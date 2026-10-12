use std::{fmt::Debug, sync::Arc};

use ruint::aliases::U256;
use thiserror::Error;

use crate::{
    account::{address::RailgunAddress, chain::ChainId},
    crypto::keys::{
        MasterPublicKey, SpendingKey, SpendingPublicKey, SpendingSignature, ViewingKey,
    },
};

use crate::common::MaybeSend;

/// A railgun signer which can sign transactions and provide the associated 0xzk address.
///
/// The spending private key never crosses this interface, so it can be implemented by a
/// signer that does not hold the key in memory, such as a hardware wallet. The viewing key
/// does cross it: note scanning is an ECDH per encrypted note, unworkable over a device
/// round-trip. This is the usual split for privacy protocols: hardware protects spending,
/// view keys are exportable.
///
/// `sign` is async and fallible: on a hardware signer it is a transport round-trip plus a
/// user confirmation, either of which can fail or be declined.
#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
pub trait RailgunSigner: MaybeSend {
    fn chain_id(&self) -> ChainId;
    fn viewing_key(&self) -> ViewingKey;
    fn spending_public_key(&self) -> SpendingPublicKey;
    async fn sign(&self, inputs: U256) -> Result<SpendingSignature, RailgunSignerError>;

    fn master_public_key(&self) -> MasterPublicKey {
        MasterPublicKey::new(
            self.spending_public_key(),
            self.viewing_key().nullifying_key(),
        )
    }

    fn address(&self) -> RailgunAddress {
        RailgunAddress::from_public_keys(
            self.master_public_key(),
            self.viewing_key().public_key(),
            self.chain_id(),
        )
    }
}

/// An implementation of RailgunSigner that holds the spending and viewing private keys in memory.
pub struct PrivateKeySigner {
    spending_key: SpendingKey,
    viewing_key: ViewingKey,
    chain_id: ChainId,
}

#[derive(Debug, Error)]
#[error("Signing error: {0}")]
pub struct RailgunSignerError(#[source] Box<dyn std::error::Error + Send + Sync>);

impl RailgunSignerError {
    pub fn new(source: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self(source.into())
    }
}

impl PrivateKeySigner {
    pub fn new(spending_key: SpendingKey, viewing_key: ViewingKey, chain_id: ChainId) -> Arc<Self> {
        Arc::new(Self {
            spending_key,
            viewing_key,
            chain_id,
        })
    }

    /// Helper for creating an EVM signer with a simple u64 chain ID.
    pub fn new_evm(spending_key: SpendingKey, viewing_key: ViewingKey, chain_id: u64) -> Arc<Self> {
        Self::new(spending_key, viewing_key, ChainId::evm(chain_id))
    }
}

#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
impl RailgunSigner for PrivateKeySigner {
    fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    fn spending_public_key(&self) -> SpendingPublicKey {
        self.spending_key.public_key()
    }

    fn viewing_key(&self) -> ViewingKey {
        self.viewing_key
    }

    async fn sign(&self, inputs: U256) -> Result<SpendingSignature, RailgunSignerError> {
        Ok(self.spending_key.sign(inputs))
    }
}

impl Debug for dyn RailgunSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signer(address: {})", self.address())
    }
}

/// BIP-32 derivation paths for railgun spending keys.
///
/// <https://github.com/Railgun-Community/engine/blob/e2913b39e13f82f43556d23705fa20d2ece2e8ab/src/key-derivation/wallet-node.ts#L17>
pub fn spending_key_path(index: u32) -> String {
    format!("m/44'/1984'/0'/0'/{}'", index)
}

/// BIP-32 derivation paths for railgun viewing keys.
///
///  <https://github.com/Railgun-Community/engine/blob/e2913b39e13f82f43556d23705fa20d2ece2e8ab/src/key-derivation/wallet-node.ts#L17>
pub fn viewing_key_path(index: u32) -> String {
    format!("m/420'/1984'/0'/0'/{}'", index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::HexKey;

    #[test]
    fn test_address() {
        let spending_key = SpendingKey::from_hex(
            "039b3b11110e49d7340cbe7171791972e3c0d94ef31b18d6ab93d7ace62d278a",
        )
        .unwrap();
        let viewing_key = ViewingKey::from_hex(
            "d345b2cc2f414aa93413b9572fa2b26e0e869e9274b006415a8d62ab1fa2dcb1",
        )
        .unwrap();

        let signer = PrivateKeySigner::new(spending_key, viewing_key, ChainId::All);
        let address = signer.address();
        assert_eq!(
            address.to_string(),
            "0zk1qynw6pq3nvntq90sts0khgs8ndqxzsrza88cd553dqwt28mskxlxtrv7j6fe3z53l7lczqdhfmfffxa8cps4hw7nprhx3hv3ykx097l8p7gjh2xla365qacrwu2"
        );
        assert_eq!(
            address,
            RailgunAddress::from_private_keys(spending_key, viewing_key, ChainId::All)
        );
    }

    #[tokio::test]
    async fn signatures_verify_against_the_signer_public_key_only() {
        let signer = PrivateKeySigner::new(
            SpendingKey::from_hex(
                "039b3b11110e49d7340cbe7171791972e3c0d94ef31b18d6ab93d7ace62d278a",
            )
            .unwrap(),
            ViewingKey::from_hex(
                "d345b2cc2f414aa93413b9572fa2b26e0e869e9274b006415a8d62ab1fa2dcb1",
            )
            .unwrap(),
            ChainId::All,
        );
        let message = U256::from(42u64);
        let signature = signer.sign(message).await.unwrap();
        let public_key = signer.spending_public_key();

        assert!(public_key.verify(message, &signature));
        assert!(!public_key.verify(message + U256::from(1u64), &signature));

        let other = SpendingKey::from_hex(&hex::encode([7u8; 32])).unwrap();
        assert!(!other.public_key().verify(message, &signature));
    }
}
