//! [`RailgunSigner`] backed by a Ledger device.

use std::sync::Arc;

use ruint::aliases::U256;
use thiserror::Error;
use tracing::info;

use railgun::{
    account::{
        address::RailgunAddress,
        chain::ChainId,
        signer::{RailgunSigner, RailgunSignerError},
    },
    crypto::keys::{SpendingPublicKey, SpendingSignature, ViewingKey},
};

use crate::{
    protocol::{self, ProtocolError},
    transport::Exchange,
};

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("device shows address {device}, host derives {host}")]
    AddressMismatch { device: String, host: String },
}

/// A Railgun signer whose spending key lives on a Ledger device.
///
/// [`LedgerSigner::connect`] fetches the public material once — the spending public key and
/// the viewing seed — so address derivation, note scanning and gas estimation never touch
/// the device again. Only [`RailgunSigner::sign`] does, and each call is a blind-signing
/// review on the device.
pub struct LedgerSigner<E> {
    // Not derived Debug: E is a device handle, and Debug on the cached keys would invite
    // logging the viewing key.
    device: E,
    account_index: u32,
    chain_id: ChainId,
    spending_pubkey: SpendingPublicKey,
    viewing_key: ViewingKey,
}

impl<E: Exchange> LedgerSigner<E> {
    /// Connects with no host-side cache: exports the viewing key and fetches the
    /// spending public key (two device approvals). See [`Self::connect_cached`] to
    /// skip the spending-pubkey prompt when the host already holds it.
    pub async fn connect(
        device: E,
        chain_id: ChainId,
        account_index: u32,
    ) -> Result<Arc<Self>, LedgerError> {
        Self::connect_cached(device, chain_id, account_index, None).await
    }

    /// Connects reusing cached *public* material (spending pubkey + 0zk address) the
    /// host persisted from a previous session.
    ///
    /// The viewing key is always exported from the device (one approval) — it is the
    /// scanning secret and is never cached. Its public key is then compared against the
    /// cached address's viewing pubkey: on a match the cached spending pubkey still
    /// belongs to this device/seed and is reused with no further prompt; on a mismatch
    /// (first run, different account, or a changed passphrase seed) the spending pubkey
    /// is fetched from the device (a second approval) so the caller can refresh its cache
    /// from [`RailgunSigner::spending_public_key`] and [`RailgunSigner::address`].
    pub async fn connect_cached(
        device: E,
        chain_id: ChainId,
        account_index: u32,
        cached: Option<(SpendingPublicKey, RailgunAddress)>,
    ) -> Result<Arc<Self>, LedgerError> {
        let version = protocol::get_version(&device).await?;
        let viewing_key = protocol::export_viewing_key(&device, account_index).await?;

        let spending_pubkey = match cached {
            Some((spending_pubkey, address))
                if address.viewing_pubkey() == viewing_key.public_key() =>
            {
                spending_pubkey
            }
            _ => protocol::get_spending_public_key(&device, account_index).await?,
        };

        info!(
            app_version = format!("{}.{}.{}", version.0, version.1, version.2),
            account_index, "connected to Ledger Railgun app"
        );

        Ok(Arc::new(Self {
            device,
            account_index,
            chain_id,
            spending_pubkey,
            viewing_key,
        }))
    }

    /// Address verification: the device displays its canonical `0zk1…` string, which must
    /// match the host-derived address of the cached public material.
    ///
    /// The device renders the chain-agnostic form, so the comparison uses [`ChainId::All`]
    /// regardless of this signer's chain.
    pub async fn verify_address_on_device(&self) -> Result<String, LedgerError> {
        let device = protocol::get_railgun_address(&self.device, self.account_index).await?;
        let host = self.address().with_chain(ChainId::All).to_string();
        if device != host {
            return Err(LedgerError::AddressMismatch { device, host });
        }
        Ok(device)
    }
}

#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
impl<E: Exchange> RailgunSigner for LedgerSigner<E> {
    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    fn viewing_key(&self) -> ViewingKey {
        self.viewing_key
    }

    fn spending_public_key(&self) -> SpendingPublicKey {
        self.spending_pubkey
    }

    async fn sign(&self, inputs: U256) -> Result<SpendingSignature, RailgunSignerError> {
        let signature = match protocol::sign_hash(&self.device, self.account_index, inputs).await {
            // A stale handle, not a device answer: a Ledger re-enumerates on USB whenever
            // an app opens/closes or the device locks. Reconnect and retry once. Status
            // errors (user denial, locked) are answers and are not retried.
            Err(ProtocolError::Transport(first)) => {
                self.device.reconnect().await.map_err(|e| {
                    RailgunSignerError::new(format!(
                        "Ledger unreachable ({first}); reconnect failed: {e} — is the device \
                         plugged in and unlocked, with the RAILGUN app open?"
                    ))
                })?;
                protocol::sign_hash(&self.device, self.account_index, inputs).await
            }
            other => other,
        }
        .map_err(RailgunSignerError::new)?;

        // The signature authenticates the signer: verifying against the pubkey cached at
        // connect guarantees the reconnected device holds the same account.
        if !self.spending_pubkey.verify(inputs, &signature) {
            return Err(RailgunSignerError::new(
                "device signature does not verify against the connected account — different \
                 device or account since the wallet was opened?",
            ));
        }
        Ok(signature)
    }
}
