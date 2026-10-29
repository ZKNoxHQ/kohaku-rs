use std::{collections::HashMap, sync::Arc};

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::{DynProvider, Provider},
    rpc::types::TransactionRequest,
    sol_types::SolCall,
    transports::{RpcError, TransportErrorKind},
};
use kohaku_userop_kit::{
    builder::UserOperationBuilder,
    bundler::{Bundler, BundlerError, BundlerExt},
    signable_user_operation::SignableUserOperation,
    smart_account::SmartAccount,
    user_operation::UserOperationGasEstimate,
};
use rand::CryptoRng;
use serde::Serialize;
use thiserror::Error;
use tracing::info;

use crate::{
    account::{address::RailgunAddress, chain::ChainId, signer::RailgunSigner},
    adapter_data::{encode_paymaster_data, encode_railgun_adapter_data, paymaster_railgun_address},
    caip::AssetId,
    chain_config::ChainConfig,
    circuit::groth16_prover::Groth16Prover,
    crypto::keys::ViewingPublicKey,
    indexer::utxo_indexer::{UtxoIndexer, UtxoIndexerError},
    note::Note,
    poi::{
        provider::{PoiProvider, PoiProviderError},
        types::{BlindedCommitmentType, PoiStatus},
    },
    transact::{
        AmountError, AmountIntents, ShieldBuilder, Spend, SpendError, attach_fee, prove_operations,
        proved_transaction::{ProvedOperation, ProvedTx},
        verifier_override::verifier_state_override,
    },
};

/// Fee of the first dummy UserOperation of [`RailgunProvider::simulate_gas_limits`], before the
/// bundler has said anything about gas. Its only effect is on which notes get selected.
const SEED_FEE: u128 = 100_000_000;

#[derive(Debug, Serialize)]
pub struct BalanceEntry {
    pub asset: AssetId,
    /// If POI is enabled, the spendability status from the local list copy.
    /// `Unavailable` means that list is not caught up. It is never `Missing`.
    /// None when POI is disabled.
    #[serde(rename = "poiStatus")]
    pub poi_status: Option<PoiStatus>,
    pub amount: u128,
}

#[derive(Debug, Serialize)]
pub struct NoteEntry {
    pub asset: AssetId,
    /// If POI is enabled, the spendability status from the local list copy.
    /// `Unavailable` means that list is not caught up. It is never `Missing`.
    /// None when POI is disabled.
    #[serde(rename = "poiStatus")]
    pub poi_status: Option<PoiStatus>,
    pub amount: u128,
    #[serde(rename = "treeNumber")]
    pub tree_number: u32,
    #[serde(rename = "leafIndex")]
    pub leaf_index: u32,
    #[serde(rename = "blindedCommitment")]
    pub blinded_commitment: String,
    #[serde(rename = "commitmentType")]
    pub commitment_type: BlindedCommitmentType,
    pub memo: String,
}

impl NoteEntry {
    fn from_note(note: UtxoNote, poi_status: Option<PoiStatus>) -> Self {
        Self {
            asset: note.asset(),
            poi_status,
            amount: note.value(),
            tree_number: note.tree_number,
            leaf_index: note.leaf_index,
            blinded_commitment: format!("0x{:064x}", note.blinded_commitment),
            commitment_type: note.commitment_type,
            memo: note.memo,
        }
    }
}

/// An unspent note plus the POI status `balance` and spends read.
///
/// This is the note the amount helpers select from and that [`RailgunProvider::spend`] takes.
#[derive(Debug, Clone)]
pub struct AnnotatedNote {
    pub note: UtxoNote,
    pub poi_status: Option<PoiStatus>,
}

/// What [`RailgunProvider::prepare_userop_single_proof`] did, for logs and UIs.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SingleProofReport {
    pub total_gas_limit: u128,
    pub max_fee_per_gas: u128,
    pub fee: u128,
    /// Paymaster verification gas measured on the real proof, against the limit committed to.
    pub paymaster_verification_measured: u128,
    pub paymaster_verification_limit: u128,
}

/// `tx.origin` for which the Railgun verifier skips the SNARK check (`VERIFICATION_BYPASS` in the
/// contracts). Only meaningful as the `from` of an `eth_estimateGas` on a dummy-proof transaction.
pub const VERIFICATION_BYPASS: Address =
    alloy::primitives::address!("0x000000000000000000000000000000000000dEaD");

// Types of the read API, for crates that do not reach into the indexer modules.
pub use crate::{
    indexer::{indexed_account::IndexedAccountState, syncer::Operation},
    note::{
        sent::SentNote,
        utxo::{UtxoNote, blinded_commitment},
    },
    poi::types::BlindedCommitmentType as CommitmentKind,
};

fn txid_hex(txid: crate::crypto::railgun_txid::Txid) -> String {
    let raw: U256 = txid.into();
    format!("0x{raw:064x}")
}

/// Interfaces with the RAILGUN protocol.
pub struct RailgunProvider {
    chain: ChainConfig,
    provider: DynProvider,
    utxo_indexer: UtxoIndexer,
    prover: Groth16Prover,
    poi_provider: Option<PoiProvider>,
}

/// Unspent notes a build may spend, plus accounts whose POI status was not observed.
struct SpendableNotes {
    notes: Vec<UtxoNote>,
    unavailable: Vec<(ViewingPublicKey, AssetId)>,
}

impl SpendableNotes {
    fn from_unspent(poi_enabled: bool, in_notes: Vec<AnnotatedNote>) -> Self {
        let unavailable = in_notes
            .iter()
            .filter(|note| note.poi_status == Some(PoiStatus::Unavailable))
            .map(|note| (note.note.viewing_pubkey, note.note.asset))
            .collect();
        let notes = if poi_enabled {
            in_notes
                .into_iter()
                .filter(|note| note.poi_status == Some(PoiStatus::Valid))
                .map(|note| note.note)
                .collect()
        } else {
            in_notes.into_iter().map(|note| note.note).collect()
        };
        Self { notes, unavailable }
    }

    /// An insufficient balance is an observation failure when this account and asset
    /// still has notes whose POI status could not be read. Valid notes are already
    /// the only inputs, so a covered amount does not take this path.
    fn explain(
        &self,
        result: Result<Vec<Spend>, AmountError>,
    ) -> Result<Vec<Spend>, RailgunProviderError> {
        match result {
            Err(AmountError::InsufficientBalance { from, asset, .. })
                if self.unavailable.contains(&(from.viewing_pubkey(), asset)) =>
            {
                Err(RailgunProviderError::PoiStatusUnavailable)
            }
            result => result.map_err(Into::into),
        }
    }
}

#[derive(Debug, Error)]
pub enum RailgunProviderError {
    #[error("Utxo indexer error: {0}")]
    UtxoIndexer(#[from] UtxoIndexerError),
    #[error("Spend error: {0}")]
    Spend(#[from] SpendError),
    #[error("Amount error: {0}")]
    Amount(#[from] AmountError),
    #[error("POI provider error: {0}")]
    PoiProvider(#[from] PoiProviderError),
    #[error("Unable to construct valid note configuration for fee payment")]
    FeeNoteNotFound,
    #[error("POI status unavailable; refresh observation before building a transaction")]
    PoiStatusUnavailable,
    #[error("Signer Error: {0}")]
    Signer(#[from] alloy::signers::Error),
    #[error("Bundler error: {0}")]
    Bundler(#[from] BundlerError),
    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError<TransportErrorKind>),
    #[error(
        "gas limits fixed before proving are too low: {what} needs {needed}, limit is {limit}. \
         Nothing was sent"
    )]
    LimitsTooLow {
        what: &'static str,
        needed: u128,
        limit: u128,
    },
    #[error("Privacy Paymaster not configured for chain: {0}")]
    PrivacyPaymasterNotConfigured(u64),
    #[error("Other: {0}")]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl RailgunProvider {
    pub(crate) async fn new(
        chain: ChainConfig,
        provider: DynProvider,
        utxo_indexer: UtxoIndexer,
        prover: Groth16Prover,
        poi_provider: Option<PoiProvider>,
    ) -> Result<Self, RailgunProviderError> {
        Ok(Self {
            chain,
            provider,
            utxo_indexer,
            prover,
            poi_provider,
        })
    }

    /// Last block the UTXO indexer has been synced to.
    pub fn synced_block(&self) -> u64 {
        self.utxo_indexer.synced_block()
    }

    /// Whether POI support is enabled on this provider.
    pub fn poi_enabled(&self) -> bool {
        self.poi_provider.is_some()
    }

    /// POI list keys this provider proves against (their wire strings), empty when POI is off.
    pub fn poi_list_keys(&self) -> Vec<String> {
        self.poi_provider
            .as_ref()
            .map(|p| {
                p.list_keys()
                    .iter()
                    .map(crate::poi::provider::list_key_string)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Full state of a registered account: unspent, spent and sent notes.
    pub fn account_state(&self, address: RailgunAddress) -> Option<IndexedAccountState> {
        self.utxo_indexer.account_state(address)
    }

    /// The account's own on-chain operations as kept by the txid indexer (POI enabled only),
    /// keyed by railgun txid as `0x` + 64 hex digits.
    pub fn own_operations(&self) -> Vec<(String, Operation)> {
        self.poi_provider
            .as_ref()
            .map(|p| {
                p.own_operations()
                    .into_iter()
                    .map(|(txid, op)| (txid_hex(txid), op))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// POI status of a blinded commitment on each list (list key wire string, status), read
    /// from the local list copies: no request names the commitment. Empty when POI is off.
    /// For an unshield, the blinded commitment is the railgun txid.
    pub fn poi_status_per_list(&self, blinded_commitment: U256) -> Vec<(String, PoiStatus)> {
        self.poi_provider
            .as_ref()
            .map(|p| {
                p.status_per_list(blinded_commitment.into())
                    .into_iter()
                    .map(|(list, status)| (crate::poi::provider::list_key_string(&list), status))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Summaries of the POI proofs still waiting to be generated and submitted.
    pub fn poi_pending(&self) -> Vec<crate::poi::PendingPoiSummary> {
        self.poi_provider
            .as_ref()
            .map(|p| p.pending_summaries())
            .unwrap_or_default()
    }

    /// Railgun txids (`0x` + 64 hex digits) of past operations whose POI the recovery pass
    /// found `Valid`.
    pub fn poi_recovered_valid(&self) -> Vec<String> {
        self.poi_provider
            .as_ref()
            .map(|p| p.recovered_valid().into_iter().map(txid_hex).collect())
            .unwrap_or_default()
    }

    /// Register a signer with the provider. The provider will index and track
    /// UTXOs for the associated address.
    pub async fn register(
        &mut self,
        signer: Arc<dyn RailgunSigner>,
    ) -> Result<(), RailgunProviderError> {
        self.utxo_indexer.register(signer).await?;
        Ok(())
    }

    /// Syncs the provider to the latest block and processes pending POI proofs.
    /// With POI enabled, this may generate and submit proofs to the POI service.
    ///
    /// # Errors
    /// Returns synchronization or persistence errors. Individual POI processing
    /// failures retain the existing best-effort behavior.
    pub async fn sync(&mut self) -> Result<(), RailgunProviderError> {
        self.sync_to(u64::MAX).await
    }

    /// Syncs the provider to the specified block and processes pending POI proofs.
    /// Use [`Self::sync_to_without_poi_submission`] to defer proof submission.
    ///
    /// # Errors
    /// Returns synchronization or persistence errors. Individual POI processing
    /// failures retain the existing best-effort behavior.
    pub async fn sync_to(&mut self, to_block: u64) -> Result<(), RailgunProviderError> {
        self.sync_to_without_poi_submission(to_block).await?;
        self.process_pending_poi().await
    }

    /// Syncs to the latest block without generating or submitting POI proofs.
    /// This still copies POI lists and checks txid roots. List reads name leaf
    /// ranges, not the wallet's commitments.
    ///
    /// # Errors
    /// Returns an error if synchronization, validation or persistence fails.
    pub async fn sync_without_poi_submission(&mut self) -> Result<(), RailgunProviderError> {
        self.sync_to_without_poi_submission(u64::MAX).await
    }

    /// Syncs to the specified block without generating or submitting POI proofs.
    /// Pending POI work is retained for [`Self::process_pending_poi`]. This is
    /// not a no-disclosure scan: list pages and txid roots are still read.
    ///
    /// # Errors
    /// Returns an error if synchronization, validation or persistence fails.
    pub async fn sync_to_without_poi_submission(
        &mut self,
        to_block: u64,
    ) -> Result<(), RailgunProviderError> {
        self.utxo_indexer.sync_to(to_block).await?;

        if let Some(poi_provider) = &mut self.poi_provider {
            // The account history lets the POI provider rebuild proofs for
            // operations it did not build itself.
            let accounts = self.utxo_indexer.recovery_accounts();
            poi_provider.sync_to(to_block, &accounts).await?;
        }

        Ok(())
    }

    /// Explicitly generates and submits pending POI proofs when POI is enabled.
    /// Processing is best effort: individual proof/service failures remain
    /// queued and are logged; `Ok` is not proof acceptance. Observe the local
    /// list copy separately before spending. This processes the whole queue and
    /// provides no per-proof review or durable send-attempt journal.
    ///
    /// # Errors
    /// Returns an error if queue persistence fails. Individual processing errors
    /// are logged and their entries remain pending.
    pub async fn process_pending_poi(&mut self) -> Result<(), RailgunProviderError> {
        if let Some(poi_provider) = &mut self.poi_provider {
            poi_provider.process_pending(&self.prover).await?;
        }
        Ok(())
    }

    /// Unspent notes for `address`, each with its POI status.
    ///
    /// This is the list [`Self::spend`] and the amount helpers read. [`Self::balance`]
    /// is the sum of these notes grouped by asset and POI status.
    #[allow(clippy::unused_async)]
    pub async fn unspent_notes(&mut self, address: RailgunAddress) -> Vec<AnnotatedNote> {
        let notes = self.utxo_indexer.unspent(address);
        let Some(poi_provider) = &self.poi_provider else {
            return notes
                .into_iter()
                .map(|note| AnnotatedNote {
                    note,
                    poi_status: None,
                })
                .collect();
        };

        notes
            .into_iter()
            .map(|note| {
                let poi_status =
                    poi_provider.status(note.blinded_commitment.into(), note.commitment_type);
                AnnotatedNote {
                    note,
                    poi_status: Some(poi_status),
                }
            })
            .collect()
    }

    /// Returns all unspent notes for the given address, as a display record.
    pub async fn notes(&mut self, address: RailgunAddress) -> Vec<NoteEntry> {
        self.unspent_notes(address)
            .await
            .into_iter()
            .map(|annotated| NoteEntry::from_note(annotated.note, annotated.poi_status))
            .collect()
    }

    /// Sum of [`Self::unspent_notes`], grouped by asset and POI status.
    ///
    /// If POI is enabled, only `Valid` is spendable. `Unavailable` means the local
    /// list is not caught up, not that a proof is missing.
    pub async fn balance(&mut self, address: RailgunAddress) -> Vec<BalanceEntry> {
        let mut balance_map = HashMap::new();
        for annotated in self.unspent_notes(address).await {
            *balance_map
                .entry((annotated.note.asset(), annotated.poi_status))
                .or_insert(0) += annotated.note.value();
        }

        balance_map
            .into_iter()
            .map(|((asset, poi_status), amount)| BalanceEntry {
                asset,
                poi_status,
                amount,
            })
            .collect()
    }

    /// Helper to create a shield builder.
    pub fn shield(&self) -> ShieldBuilder {
        ShieldBuilder::new(self.chain.clone())
    }

    /// Start a spend of these notes. They must share a tree, an asset, and the signer's
    /// viewing key. This does not select notes, check POI, or ask the signer to sign.
    pub fn spend(
        &self,
        signer: Arc<dyn RailgunSigner>,
        inputs: Vec<UtxoNote>,
    ) -> Result<Spend, SpendError> {
        Spend::try_new(signer, inputs)
    }

    /// Select notes for one transfer and return the spends that cover it.
    ///
    /// A transfer that does not fit on one tree comes back as several spends, one per
    /// tree, each of which is one spending signature at [`Self::prove`].
    pub async fn transfer_amount(
        &mut self,
        from: Arc<dyn RailgunSigner>,
        to: RailgunAddress,
        asset: AssetId,
        value: u128,
        memo: &str,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<Spend>, RailgunProviderError> {
        self.resolve_amounts(
            AmountIntents::new().transfer(from, to, asset, value, memo),
            rng,
        )
        .await
    }

    /// Select notes for one unshield and return the spends that cover it.
    ///
    /// See [`Self::transfer_amount`] for how a value that spans trees is split.
    pub async fn unshield_amount(
        &mut self,
        from: Arc<dyn RailgunSigner>,
        to: Address,
        asset: AssetId,
        value: u128,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<Spend>, RailgunProviderError> {
        self.resolve_amounts(AmountIntents::new().unshield(from, to, asset, value)?, rng)
            .await
    }

    /// Resolve several amount intents in one selection.
    ///
    /// Intents for the same signer and asset are fitted together, smallest first, onto
    /// the oldest tree that can hold each one. The result is the note-level spends
    /// [`Self::prove`] accepts.
    pub async fn resolve_amounts(
        &mut self,
        intents: AmountIntents,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<Spend>, RailgunProviderError> {
        let spendable = self.spendable_notes().await;
        let resolved = intents.resolve(&spendable.notes, rng);
        spendable.explain(resolved)
    }

    /// Forgets the pending POI proofs of operations that never reached the chain, for instance
    /// after the submitter did not answer. Returns how many entries were dropped. Entries of
    /// operations that are never mined are also dropped automatically during sync, once the
    /// grace period has passed.
    pub async fn discard_pending_poi(
        &mut self,
        operations: &[ProvedOperation],
    ) -> Result<usize, RailgunProviderError> {
        match &mut self.poi_provider {
            Some(p) => Ok(p.discard_ops(operations).await?),
            None => Ok(0),
        }
    }

    /// Builds the transaction with an all-zero proof, for gas estimation only.
    ///
    /// Call `eth_estimateGas` on the result with `from` set to [`VERIFICATION_BYPASS`]: the
    /// Railgun verifier skips the SNARK check for that origin. Nothing is registered with the
    /// POI provider, no proof is generated, and the spending signer is not asked to sign.
    /// Not usable on the ERC-4337 path, where the bundler simulates with its own origin.
    pub async fn prove_dummy(
        &mut self,
        spends: &[Spend],
        rng: &mut impl CryptoRng,
    ) -> Result<ProvedTx, RailgunProviderError> {
        let operations = self.prove_spends(spends, rng, false).await?;
        Ok(ProvedTx::new(self.chain.railgun_smart_wallet, operations))
    }

    /// Prove spends into one Railgun transaction.
    ///
    /// Each spend is one spending signature. POI, when enabled, is checked per input
    /// note before any signature is requested. Valid spends are registered for POI.
    pub async fn prove(
        &mut self,
        spends: &[Spend],
        rng: &mut impl CryptoRng,
    ) -> Result<ProvedTx, RailgunProviderError> {
        let operations = self.prove_spends(spends, rng, true).await?;
        if let Some(poi_provider) = &mut self.poi_provider {
            poi_provider.register_ops(&operations).await?;
        }
        Ok(ProvedTx::new(self.chain.railgun_smart_wallet, operations))
    }

    /// The UserOperation [`Self::prepare_userop`] would build, with a dummy proof: same
    /// calldata, same paymaster data, nothing proved and the spending signer never asked.
    ///
    /// It cannot be sent. It exists to be simulated, with the verifier told to accept the dummy
    /// proof ([`crate::transact::verifier_override`]), so that the gas limits, hence the fee,
    /// are known before the one real proof.
    pub async fn dummy_userop<S: SmartAccount>(
        &mut self,
        spends: &[Spend],
        sender: &S,
        fee_payer: Arc<dyn RailgunSigner>,
        fee_token: Address,
        calldata: &S::Call,
        fee: u128,
        gas: UserOperationGasEstimate,
        rng: &mut impl CryptoRng,
    ) -> Result<SignableUserOperation, RailgunProviderError> {
        let (userop, _) = self
            .dummy_userop_with_operations(
                spends, sender, fee_payer, fee_token, calldata, fee, gas, rng,
            )
            .await?;
        Ok(userop)
    }

    /// [`Self::dummy_userop`] with the operations it wraps, whose circuit sizes decide which
    /// verifying keys the estimate must override.
    #[allow(clippy::too_many_arguments)]
    async fn dummy_userop_with_operations<S: SmartAccount>(
        &mut self,
        spends: &[Spend],
        sender: &S,
        fee_payer: Arc<dyn RailgunSigner>,
        fee_token: Address,
        calldata: &S::Call,
        fee: u128,
        gas: UserOperationGasEstimate,
        rng: &mut impl CryptoRng,
    ) -> Result<(SignableUserOperation, Vec<ProvedOperation>), RailgunProviderError> {
        let (privacy_paymaster, railgun_fee_adapter) = self.paymaster_contracts(fee_token)?;
        let with_fee = self
            .spends_with_fee(
                spends,
                fee_payer,
                fee_token,
                fee,
                railgun_fee_adapter,
                *sender.address().into_word(),
                rng,
            )
            .await?;
        // Unsigned circuit inputs: a gas estimate must not ask the spending signer.
        let operations = self.prove_spends(&with_fee, rng, false).await?;
        let userop = self
            .userop_from(
                &operations,
                sender,
                calldata,
                privacy_paymaster,
                railgun_fee_adapter,
                fee_token,
                fee,
                gas,
            )
            .await?;
        Ok((userop, operations))
    }

    /// Same result as [`Self::prepare_userop`] with exactly one proof, hence one spending
    /// signature per operation, instead of one per round of the fee convergence loop.
    ///
    /// The loop exists because the fee depends on the gas, which the bundler only estimates by
    /// simulating a UserOperation carrying a valid proof, itself bound to the fee. Here the
    /// caller fixes `gas` beforehand, typically from a simulation of [`Self::dummy_userop`].
    /// The fee is `total gas limit x maxFeePerGas`, as the privacy paymaster computes it, so
    /// its check passes by construction.
    ///
    /// After proving, the paymaster verification gas is measured on the real proof and the
    /// bundler is asked for its own estimate. If either exceeds a limit the call fails before
    /// anything is sent: that costs a second signature, never funds.
    pub async fn prepare_userop_single_proof<S: SmartAccount>(
        &mut self,
        spends: &[Spend],
        bundler: &dyn Bundler,
        sender: &S,
        fee_payer: Arc<dyn RailgunSigner>,
        fee_token: Address,
        calldata: S::Call,
        gas: UserOperationGasEstimate,
        rng: &mut impl CryptoRng,
    ) -> Result<(SignableUserOperation, SingleProofReport), RailgunProviderError> {
        let (privacy_paymaster, railgun_fee_adapter) = self.paymaster_contracts(fee_token)?;
        let total_gas = total_gas_limit(&gas);
        let fee = total_gas * gas.max_fee_per_gas;

        // The one proof. This is the only place the spending signer is used.
        let with_fee = self
            .spends_with_fee(
                spends,
                fee_payer,
                fee_token,
                fee,
                railgun_fee_adapter,
                *sender.address().into_word(),
                rng,
            )
            .await?;
        let operations = self.prove_spends(&with_fee, rng, true).await?;
        let signable = self
            .userop_from(
                &operations,
                sender,
                &calldata,
                privacy_paymaster,
                railgun_fee_adapter,
                fee_token,
                fee,
                gas,
            )
            .await?;

        // Check the limits against the real proof before anything leaves.
        let pmv_limit = gas.paymaster_verification_gas_limit.unwrap_or(0);
        let pmv_measured =
            estimate_paymaster_verification_gas_limit(&self.provider, &signable).await?;
        if pmv_measured > pmv_limit {
            return Err(RailgunProviderError::LimitsTooLow {
                what: "paymaster verification",
                needed: pmv_measured,
                limit: pmv_limit,
            });
        }
        let bundler_view = bundler.estimate_gas(&signable, None).await?;
        for (what, needed, limit) in [
            (
                "pre-verification",
                bundler_view.pre_verification_gas,
                gas.pre_verification_gas,
            ),
            (
                "account verification",
                bundler_view.verification_gas_limit,
                gas.verification_gas_limit,
            ),
            // Without execution calldata the call limit constrains nothing: a bundler's default
            // there is not a requirement.
            (
                "call",
                if signable.user_op.call_data.is_empty() {
                    0
                } else {
                    bundler_view.call_gas_limit
                },
                gas.call_gas_limit,
            ),
        ] {
            if needed > limit {
                return Err(RailgunProviderError::LimitsTooLow {
                    what,
                    needed,
                    limit,
                });
            }
        }

        if let Some(poi_provider) = &mut self.poi_provider {
            poi_provider.register_ops(&operations).await?;
        }
        let report = SingleProofReport {
            total_gas_limit: total_gas,
            max_fee_per_gas: gas.max_fee_per_gas,
            fee,
            paymaster_verification_measured: pmv_measured,
            paymaster_verification_limit: pmv_limit,
        };
        Ok((signable, report))
    }

    /// Estimates the ERC-4337 gas limits before proving, so the fee is fixed with one proof
    /// (hence one spending signature) via [`Self::prepare_userop_single_proof`], instead of
    /// the iterative re-proving [`Self::prepare_userop`] does.
    ///
    /// The bundler estimates a dummy-proof UserOperation ([`Self::dummy_userop`]) with a state
    /// override under which the Railgun verifier accepts the dummy proof
    /// ([`crate::transact::verifier_override`]), at the gas cost of a real one. Two rounds,
    /// because the fee is an output note whose value can change which notes are spent: the
    /// second uses the fee the first round's estimate implies. The bundler must support state
    /// overrides on `eth_estimateUserOperationGas`.
    pub async fn simulate_gas_limits<S: SmartAccount>(
        &mut self,
        spends: &[Spend],
        bundler: &dyn Bundler,
        sender: &S,
        fee_payer: Arc<dyn RailgunSigner>,
        fee_token: Address,
        calldata: &S::Call,
        rng: &mut impl CryptoRng,
    ) -> Result<UserOperationGasEstimate, RailgunProviderError> {
        let mut fee = SEED_FEE;
        let mut estimate = None;
        for _round in 0..2 {
            // Gas and prices left at zero: the bundler sets its own for the simulation.
            let (dummy, operations) = self
                .dummy_userop_with_operations(
                    spends,
                    sender,
                    fee_payer.clone(),
                    fee_token,
                    calldata,
                    fee,
                    UserOperationGasEstimate {
                        pre_verification_gas: 0,
                        verification_gas_limit: 0,
                        call_gas_limit: 0,
                        paymaster_verification_gas_limit: Some(0),
                        paymaster_post_op_gas_limit: Some(0),
                        max_fee_per_gas: 0,
                        max_priority_fee_per_gas: 0,
                    },
                    rng,
                )
                .await?;
            let circuits = operations.iter().map(|op| {
                (
                    op.transaction.nullifiers.len(),
                    op.transaction.commitments.len(),
                )
            });
            let overrides = verifier_state_override(self.chain.railgun_smart_wallet, circuits);
            let gas = bundler.estimate_gas(&dummy, Some(&overrides)).await?;
            fee = total_gas_limit(&gas) * gas.max_fee_per_gas;
            estimate = Some(gas);
        }
        Ok(estimate.expect("two rounds ran"))
    }

    /// Fixes the fee by estimation ([`Self::simulate_gas_limits`]) then proves exactly once
    /// ([`Self::prepare_userop_single_proof`]): one spending signature, no iterative re-proving.
    /// Falls back to nothing: if the estimate fails, the error is returned and nothing is signed.
    pub async fn prepare_userop_single<S: SmartAccount>(
        &mut self,
        spends: &[Spend],
        bundler: &dyn Bundler,
        sender: &S,
        fee_payer: Arc<dyn RailgunSigner>,
        fee_token: Address,
        calldata: S::Call,
        rng: &mut impl CryptoRng,
    ) -> Result<SignableUserOperation, RailgunProviderError> {
        let gas = self
            .simulate_gas_limits(
                spends,
                bundler,
                sender,
                fee_payer.clone(),
                fee_token,
                &calldata,
                rng,
            )
            .await?;
        info!(
            "Estimated before signing: pre-verification {}, account verification {}, call {}, paymaster verification {}, post-op {}; total {} gas at {} wei/gas",
            gas.pre_verification_gas,
            gas.verification_gas_limit,
            gas.call_gas_limit,
            gas.paymaster_verification_gas_limit.unwrap_or(0),
            gas.paymaster_post_op_gas_limit.unwrap_or(0),
            total_gas_limit(&gas),
            gas.max_fee_per_gas,
        );
        let (signable, _report) = self
            .prepare_userop_single_proof(
                spends, bundler, sender, fee_payer, fee_token, calldata, gas, rng,
            )
            .await?;
        Ok(signable)
    }

    fn paymaster_contracts(
        &self,
        fee_token: Address,
    ) -> Result<(Address, Address), RailgunProviderError> {
        let privacy_paymaster = self.chain.privacy_paymaster.ok_or(
            RailgunProviderError::PrivacyPaymasterNotConfigured(self.chain.id),
        )?;
        let railgun_fee_adapter = self.chain.railgun_fee_adapter.ok_or(
            RailgunProviderError::PrivacyPaymasterNotConfigured(self.chain.id),
        )?;
        if fee_token != self.chain.wrapped_base_token {
            return Err(RailgunProviderError::Other(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Currently only the wrapped base token is supported for fee payment",
            ))));
        }
        Ok((privacy_paymaster, railgun_fee_adapter))
    }

    /// UserOperation around already built operations, with the given gas figures.
    #[allow(clippy::too_many_arguments, clippy::ptr_arg)]
    async fn userop_from<S: SmartAccount>(
        &self,
        // `&Vec` because `get_fee_operation` takes one.
        operations: &Vec<ProvedOperation>,
        sender: &S,
        calldata: &S::Call,
        privacy_paymaster: Address,
        railgun_fee_adapter: Address,
        fee_token: Address,
        fee: u128,
        gas: UserOperationGasEstimate,
    ) -> Result<SignableUserOperation, RailgunProviderError> {
        let fee_asset = AssetId::Erc20(fee_token);
        let fee_operation = get_fee_operation(operations, fee_asset, fee)?;
        let fee_note = get_fee_note(fee_operation, fee_asset, fee)?;
        let transactions = operations.iter().map(|op| op.transaction.clone()).collect();
        let paymaster_data = encode_paymaster_data(
            railgun_fee_adapter,
            encode_railgun_adapter_data(fee_note.random(), fee_token, fee, transactions),
        );
        Ok(UserOperationBuilder::new_with_smart_account(sender)
            .await
            .map_err(|e| RailgunProviderError::Other(Box::new(e)))?
            .with_call(calldata)
            .with_paymaster_and_data(privacy_paymaster, Bytes::from(paymaster_data))
            .with_gas(gas)
            .build())
    }

    /// Build spends into a broadcastable 7702 UserOperation.
    ///
    /// Constructs a UserOperation sent from the `delegator_address` that executes the provided
    /// transaction, with an additional fee note transfer to cover the bundler fees. The
    /// `fee_payer` is the signer that will authorize the fee note transfer to the bundler's
    /// address for the estimated fee amount in `fee_token`.
    pub async fn prepare_userop<S: SmartAccount>(
        &mut self,
        spends: &[Spend],
        bundler: &dyn Bundler,
        sender: &S,
        fee_payer: Arc<dyn RailgunSigner>,
        fee_token: Address,
        calldata: S::Call,
        rng: &mut impl CryptoRng,
    ) -> Result<SignableUserOperation, RailgunProviderError> {
        let (privacy_paymaster, railgun_fee_adapter) = self.paymaster_contracts(fee_token)?;
        let fee_asset = AssetId::Erc20(fee_token);

        // Initial arbitrary estimation of fee note value.
        // IMPORTANT: Needs to be high enough to not cause a revert. Most
        // bundlers seem to use a fixed maxCost value for estimation (IE 27_000_000
        // for pimlico). Setting this too low causes an unrecoverable estimation
        // failure.
        let mut fee_value = 100_000_000;

        info!("Iteratively building UserOperation to converge on accurate fee estimate");
        for _ in 0..5 {
            info!(
                "Building broadcast transaction with fee value: {}",
                fee_value
            );
            let with_fee = self
                .spends_with_fee(
                    spends,
                    fee_payer.clone(),
                    fee_token,
                    fee_value,
                    railgun_fee_adapter,
                    *sender.address().into_word(),
                    rng,
                )
                .await?;
            let operations = self.prove_spends(&with_fee, rng, true).await?;

            // Get the fee operation & note so the decrypted commitment data can be sent to the
            // paymaster.
            let fee_operation = get_fee_operation(&operations, fee_asset, fee_value)?;
            let fee_note = get_fee_note(fee_operation, fee_asset, fee_value)?;

            let random = fee_note.random();
            let asset = fee_token;
            let value = fee_value;
            let transactions = operations.iter().map(|op| op.transaction.clone()).collect();

            let paymaster_data = encode_paymaster_data(
                railgun_fee_adapter,
                encode_railgun_adapter_data(random, asset, value, transactions),
            );

            // Construct UserOperation
            let mut signable = UserOperationBuilder::new_with_smart_account(sender)
                .await
                .map_err(|e| RailgunProviderError::Other(Box::new(e)))?
                .with_call(&calldata)
                .with_paymaster_and_data(privacy_paymaster, Bytes::from(paymaster_data))
                .with_gas_estimate(bundler, None)
                .await?
                .build();

            // Recalculate fee and check for convergence.
            info!("Prepared broadcast transaction: {:?}", signable);
            let estimated_paymaster_verification_gas_limit =
                estimate_paymaster_verification_gas_limit(&self.provider, &signable).await?;
            info!(
                "Estimated paymaster verification gas limit: {}",
                estimated_paymaster_verification_gas_limit
            );
            signable.user_op.paymaster_verification_gas_limit =
                Some(estimated_paymaster_verification_gas_limit);
            let total_gas = signable.total_gas_limit();
            let new_fee = total_gas * signable.user_op.max_fee_per_gas;
            info!("Estimated total gas: {}", total_gas);
            info!(
                "Estimated max fee per gas: {}",
                signable.user_op.max_fee_per_gas
            );

            //? Return once the fee converges within 1% of the previous estimate.
            if new_fee <= fee_value && new_fee.abs_diff(fee_value) <= fee_value / 100 {
                info!("Fee converged at {}, total gas: {}", new_fee, total_gas);
                if let Some(poi_provider) = &mut self.poi_provider {
                    poi_provider.register_ops(&operations).await?;
                }
                return Ok(signable);
            }
            fee_value = new_fee;
            info!("Fee updated to {}", new_fee);
        }

        return Err(RailgunProviderError::Other(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Failed to converge on fee estimate",
        ))));
    }

    async fn all_unspent(&mut self) -> Vec<AnnotatedNote> {
        let addresses = self.utxo_indexer.registered();
        let mut all_notes = Vec::new();
        for address in addresses {
            all_notes.extend(self.unspent_notes(address).await);
        }
        all_notes
    }

    /// Attach the fee, then prove. `real` asks the spending signer; a dummy proof does not.
    async fn prove_spends(
        &mut self,
        spends: &[Spend],
        rng: &mut impl CryptoRng,
        real: bool,
    ) -> Result<Vec<ProvedOperation>, RailgunProviderError> {
        self.ensure_notes_valid(spends)?;
        let operations = spends
            .iter()
            .cloned()
            .map(Spend::into_operation)
            .collect::<Result<Vec<_>, _>>()?;
        let prover = real.then_some(&self.prover);
        Ok(prove_operations(
            prover,
            &self.utxo_indexer.utxo_trees,
            self.chain.id,
            &operations,
            rng,
        )
        .await?)
    }

    fn ensure_notes_valid(&self, spends: &[Spend]) -> Result<(), SpendError> {
        let Some(poi) = &self.poi_provider else {
            return Ok(());
        };
        for spend in spends {
            for note in spend.inputs() {
                let status = poi.status(note.blinded_commitment.into(), note.commitment_type);
                if status != PoiStatus::Valid {
                    return Err(SpendError::NoteNotValid {
                        blinded_commitment: note.blinded_commitment,
                        status,
                    });
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn spends_with_fee(
        &mut self,
        spends: &[Spend],
        fee_payer: Arc<dyn RailgunSigner>,
        fee_token: Address,
        fee: u128,
        adapt_contract: Address,
        adapt_params: [u8; 32],
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<Spend>, RailgunProviderError> {
        let spendable = self.spendable_notes().await;
        let with_fee = attach_fee(
            spends,
            fee_payer,
            paymaster_railgun_address(ChainId::evm(self.chain.id)),
            AssetId::Erc20(fee_token),
            fee,
            &spendable.notes,
            adapt_contract,
            adapt_params,
            rng,
        );
        spendable.explain(with_fee)
    }

    /// Notes usable as inputs, and the account/asset pairs that could not be observed.
    ///
    /// When POI is on, only `Valid` notes are inputs. `Unavailable` is not an input,
    /// but every build reports it when that is what made the balance look short.
    async fn spendable_notes(&mut self) -> SpendableNotes {
        SpendableNotes::from_unspent(self.poi_provider.is_some(), self.all_unspent().await)
    }
}

/// The sum of the limits, what the privacy paymaster multiplies by `maxFeePerGas` for the fee.
fn total_gas_limit(gas: &UserOperationGasEstimate) -> u128 {
    gas.pre_verification_gas
        + gas.verification_gas_limit
        + gas.call_gas_limit
        + gas.paymaster_verification_gas_limit.unwrap_or(0)
        + gas.paymaster_post_op_gas_limit.unwrap_or(0)
}

/// Gets the operation containing the fee note
fn get_fee_operation<'a>(
    operations: &'a Vec<ProvedOperation>,
    fee_asset: AssetId,
    fee_value: u128,
) -> Result<&'a ProvedOperation, RailgunProviderError> {
    let Some(fee_note_pos) = operations.iter().position(|o| {
        o.inner
            .out_notes()
            .iter()
            .any(|n| is_fee_note(n, fee_asset, fee_value))
    }) else {
        return Err(RailgunProviderError::FeeNoteNotFound);
    };
    Ok(&operations[fee_note_pos])
}

/// Gets the fee note from the operation
fn get_fee_note(
    operation: &ProvedOperation,
    fee_asset: AssetId,
    fee_value: u128,
) -> Result<Box<dyn Note>, RailgunProviderError> {
    operation
        .inner
        .out_notes()
        .into_iter()
        .find(|n| is_fee_note(n, fee_asset, fee_value))
        .ok_or(RailgunProviderError::FeeNoteNotFound)
}

fn is_fee_note(note: &Box<dyn Note>, fee_asset: AssetId, fee_value: u128) -> bool {
    note.asset() == fee_asset && note.value() == fee_value && note.memo() == "fee"
}

async fn estimate_paymaster_verification_gas_limit(
    provider: &DynProvider,
    user_op: &SignableUserOperation,
) -> Result<u128, RailgunProviderError> {
    let entry_point = user_op.entry_point;
    let Some(paymaster) = user_op.user_op.paymaster else {
        return Ok(0);
    };
    let user_op = user_op.user_op.into_packed();
    let data: Bytes = abi::PrivacyPaymaster::validatePaymasterUserOpCall {
        userOp: abi::PrivacyPaymaster::PackedUserOperation {
            sender: user_op.sender,
            nonce: user_op.nonce,
            initCode: user_op.initCode,
            callData: user_op.callData,
            accountGasLimits: user_op.accountGasLimits,
            preVerificationGas: user_op.preVerificationGas,
            gasFees: user_op.gasFees,
            paymasterAndData: user_op.paymasterAndData,
            signature: Bytes::new(),
        },
        userOpHash: B256::ZERO,
        maxCost: U256::ZERO,
    }
    .abi_encode()
    .into();

    let request = TransactionRequest::default()
        .from(entry_point)
        .to(paymaster)
        .input(data.into());
    Ok(provider.estimate_gas(request).await? as u128)
}

mod abi {
    use alloy::sol;

    sol!(
        contract PrivacyPaymaster {
            function validatePaymasterUserOp(
                PackedUserOperation calldata userOp,
                bytes32 userOpHash,
                uint256 maxCost
            ) external returns (bytes memory context, uint256 validationData);

            struct PackedUserOperation {
                address sender;
                uint256 nonce;
                bytes initCode;
                bytes callData;
                bytes32 accountGasLimits;
                uint256 preVerificationGas;
                bytes32 gasFees;
                bytes paymasterAndData;
                bytes signature;
            }
        }
    );
}

#[cfg(all(test, native))]
mod poi_availability_tests {
    use alloy::providers::Provider;
    use tokio::{
        net::TcpListener,
        time::{Duration, timeout},
    };

    use super::*;
    use crate::{
        account::signer::PrivateKeySigner,
        builder::RailgunBuilder,
        crypto::keys::{ByteKey, SpendingKey, ViewingKey},
        indexer::{
            indexed_account::IndexedAccountState,
            syncer::{SyncEvent, SyncerError, UtxoSyncer},
        },
        railgun_database::RailgunDB,
        state::RailgunState,
        transact::SpendError,
    };

    const LIST: &str = "public-fixture-list";

    struct NoSync;
    #[async_trait::async_trait]
    impl UtxoSyncer for NoSync {
        async fn latest_block(&self) -> Result<u64, SyncerError> {
            panic!("no sync expected")
        }
        async fn sync(&self, _: u64, _: u64) -> Result<Vec<SyncEvent>, SyncerError> {
            panic!("no sync expected")
        }
    }

    async fn fixture(url: &str, poi: bool) -> (RailgunProvider, Arc<dyn RailgunSigner>, AssetId) {
        fixture_with_notes(url, poi, 1).await
    }

    async fn fixture_with_notes(
        url: &str,
        poi: bool,
        count: u32,
    ) -> (RailgunProvider, Arc<dyn RailgunSigner>, AssetId) {
        // Public, never-funded keys. This seeds local state; it is not a scan test.
        let signer = PrivateKeySigner::new_evm(
            SpendingKey::from_bytes([1; 32]),
            ViewingKey::from_bytes([2; 32]),
            11_155_111,
        );
        let asset = AssetId::erc20(Address::repeat_byte(0x11));
        let db = RailgunState::default();
        db.set_account(
            &signer.address(),
            &IndexedAccountState {
                notes: (0..count)
                    .map(|leaf| {
                        UtxoNote::new(
                            0,
                            leaf,
                            signer.clone(),
                            asset,
                            10,
                            [5; 16],
                            "public fixture",
                            BlindedCommitmentType::Transact,
                        )
                    })
                    .collect(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let mut chain = ChainConfig::sepolia();
        chain.poi_endpoint = url.to_owned();
        chain.subsquid_endpoint = url.to_owned();
        chain.list_keys = vec![LIST.into()];
        let rpc = alloy::providers::ProviderBuilder::new()
            .connect_http(url.parse().unwrap())
            .erased();
        let builder = RailgunBuilder::new(chain, rpc)
            .with_state(db)
            .with_utxo_syncer(Arc::new(NoSync));
        // The built-in prover's artifact loader is not injectable yet. A failed
        // status must stop build before that loader can be reached.
        let mut provider = if poi { builder.with_poi() } else { builder }
            .build()
            .await
            .unwrap();
        provider.register(signer.clone()).await.unwrap();
        (provider, signer, asset)
    }

    #[tokio::test]
    async fn unsynced_notes_are_unavailable_and_cannot_spend() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (mut provider, signer, asset) = fixture(&url, true).await;
        let notes = timeout(Duration::from_secs(5), provider.notes(signer.address()))
            .await
            .unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].poi_status, Some(PoiStatus::Unavailable));
        assert_eq!(
            serde_json::to_value(&notes[0]).unwrap()["poiStatus"],
            "Unavailable"
        );
        let balance = timeout(Duration::from_secs(5), provider.balance(signer.address()))
            .await
            .unwrap();
        assert_eq!(balance.len(), 1);
        assert_eq!(balance[0].amount, 10);
        assert_eq!(balance[0].poi_status, Some(PoiStatus::Unavailable));
        let result = timeout(
            Duration::from_secs(5),
            provider.transfer_amount(
                signer.clone(),
                signer.address(),
                asset,
                1,
                "",
                &mut rand::rng(),
            ),
        )
        .await
        .unwrap();
        assert!(matches!(
            result,
            Err(RailgunProviderError::PoiStatusUnavailable)
        ));
        let notes = timeout(
            Duration::from_secs(5),
            provider.unspent_notes(signer.address()),
        )
        .await
        .unwrap();
        let explicit = provider
            .spend(signer.clone(), vec![notes[0].note.clone()])
            .unwrap()
            .transfer(signer.address(), 1, "")
            .unwrap()
            .with_change(&mut rand::rng())
            .unwrap();
        let explicit = timeout(
            Duration::from_secs(5),
            provider.prove(&[explicit], &mut rand::rng()),
        )
        .await
        .unwrap();
        assert!(matches!(
            explicit,
            Err(RailgunProviderError::Spend(SpendError::NoteNotValid { .. }))
        ));
        assert!(
            timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn unavailable_notes_of_another_asset_do_not_mask_insufficient_balance() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (mut provider, signer, _) = fixture(&url, true).await;
        assert!(matches!(
            timeout(
                Duration::from_secs(5),
                provider.transfer_amount(
                    signer.clone(),
                    signer.address(),
                    AssetId::erc20(Address::repeat_byte(0x22)),
                    1,
                    "",
                    &mut rand::rng(),
                )
            )
            .await
            .unwrap(),
            Err(RailgunProviderError::Amount(
                AmountError::InsufficientBalance { .. }
            ))
        ));
        assert!(
            timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn disabled_poi_remains_none_without_a_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (mut provider, signer, _) = fixture(&url, false).await;
        assert_eq!(
            timeout(Duration::from_secs(5), provider.notes(signer.address()))
                .await
                .unwrap()[0]
                .poi_status,
            None
        );
        assert_eq!(
            timeout(Duration::from_secs(5), provider.balance(signer.address()))
                .await
                .unwrap()[0]
                .poi_status,
            None
        );
        assert!(
            timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[test]
    fn unavailable_round_trips_locally_but_not_as_a_node_status() {
        assert_eq!(PoiStatus::Unavailable.to_string(), "Unavailable");
        assert_eq!(
            serde_json::to_value(PoiStatus::Unavailable).unwrap(),
            "Unavailable"
        );
        assert_eq!(
            serde_json::from_str::<PoiStatus>("\"Unavailable\"").unwrap(),
            PoiStatus::Unavailable
        );
        assert_eq!(
            "Unavailable".parse::<PoiStatus>().unwrap(),
            PoiStatus::Unavailable
        );
        assert_eq!(
            PoiStatus::from(crate::poi::types::PoiNodeStatus::Missing),
            PoiStatus::Missing
        );
        assert!(
            serde_json::from_str::<crate::poi::types::PoiNodeStatus>("\"Unavailable\"").is_err()
        );
    }
}

#[cfg(all(test, native))]
mod spendable_notes_tests {
    use alloy::primitives::Address;

    use super::*;
    use crate::{
        account::signer::{PrivateKeySigner, RailgunSigner},
        caip::AssetId,
        crypto::keys::{ByteKey, SpendingKey, ViewingKey},
        note::utxo::UtxoNote,
        poi::types::BlindedCommitmentType,
        transact::AmountError,
    };

    fn signer() -> std::sync::Arc<PrivateKeySigner> {
        PrivateKeySigner::new_evm(
            SpendingKey::from_bytes([1; 32]),
            ViewingKey::from_bytes([2; 32]),
            11_155_111,
        )
    }

    fn note(signer: std::sync::Arc<PrivateKeySigner>, asset: AssetId, value: u128) -> UtxoNote {
        UtxoNote::new(
            0,
            0,
            signer,
            asset,
            value,
            [5; 16],
            "public fixture",
            BlindedCommitmentType::Transact,
        )
    }

    #[test]
    fn a_valid_note_stays_spendable_beside_an_unavailable_one() {
        let signer = signer();
        let asset = AssetId::erc20(Address::repeat_byte(0x11));
        let valid = note(signer.clone(), asset, 7);
        let unavailable = note(signer, asset, 10);
        let selected = SpendableNotes::from_unspent(
            true,
            vec![
                AnnotatedNote {
                    note: valid,
                    poi_status: Some(PoiStatus::Valid),
                },
                AnnotatedNote {
                    note: unavailable,
                    poi_status: Some(PoiStatus::Unavailable),
                },
            ],
        );
        assert_eq!(selected.notes.len(), 1);
        assert_eq!(selected.notes[0].value, 7);
        assert!(selected.explain(Ok(vec![])).is_ok());
    }

    #[test]
    fn missing_is_not_an_availability_error() {
        let signer = signer();
        let asset = AssetId::erc20(Address::repeat_byte(0x11));
        let missing = note(signer.clone(), asset, 10);
        let selected = SpendableNotes::from_unspent(
            true,
            vec![AnnotatedNote {
                note: missing,
                poi_status: Some(PoiStatus::Missing),
            }],
        );
        assert!(selected.notes.is_empty());
        let err = selected.explain(Err(AmountError::InsufficientBalance {
            from: signer.address(),
            asset,
            value: 1,
        }));
        assert!(matches!(
            err,
            Err(RailgunProviderError::Amount(
                AmountError::InsufficientBalance { .. }
            ))
        ));
    }

    #[test]
    fn unavailable_on_another_asset_does_not_mask_a_shortfall() {
        let signer = signer();
        let wanted = AssetId::erc20(Address::repeat_byte(0x11));
        let other = AssetId::erc20(Address::repeat_byte(0x22));
        let unavailable = note(signer.clone(), other, 10);
        let selected = SpendableNotes::from_unspent(
            true,
            vec![AnnotatedNote {
                note: unavailable,
                poi_status: Some(PoiStatus::Unavailable),
            }],
        );
        let err = selected.explain(Err(AmountError::InsufficientBalance {
            from: signer.address(),
            asset: wanted,
            value: 1,
        }));
        assert!(matches!(
            err,
            Err(RailgunProviderError::Amount(
                AmountError::InsufficientBalance { .. }
            ))
        ));
    }

    #[test]
    fn a_shortfall_on_an_unobserved_asset_is_unavailable() {
        let signer = signer();
        let asset = AssetId::erc20(Address::repeat_byte(0x11));
        let unavailable = note(signer.clone(), asset, 10);
        let selected = SpendableNotes::from_unspent(
            true,
            vec![AnnotatedNote {
                note: unavailable,
                poi_status: Some(PoiStatus::Unavailable),
            }],
        );
        let err = selected.explain(Err(AmountError::InsufficientBalance {
            from: signer.address(),
            asset,
            value: 1,
        }));
        assert!(matches!(
            err,
            Err(RailgunProviderError::PoiStatusUnavailable)
        ));
    }
}
