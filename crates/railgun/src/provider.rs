use std::{collections::HashMap, sync::Arc};

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    sol_types::SolCall,
};
use kohaku_eip_1193::provider::{AccountStateOverride, Eip1193Error, Eip1193Provider};
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
        NoteEncryption, ShieldBuilder, TransactionBuilder, TransactionBuilderError,
        proved_transaction::{ProvedOperation, ProvedTx},
    },
};

/// Gas limits are rounded up to a multiple of this, so small measurement noise between the
/// simulation and the real UserOperation does not push a limit below what is needed.
const GAS_BUCKET: u128 = 10_000;

/// What [`RailgunProvider::simulate_gas_limits`] measured, for logging/inspection.
#[derive(Debug, Clone)]
pub struct GasSimulationDetails {
    pub account_validation: u128,
    pub paymaster_validation: u128,
    pub call: u128,
    pub call_limit: u128,
    pub post_op: u128,
    pub pre_verification: u128,
    pub total: u128,
    pub margin_percent: u32,
}

#[derive(Debug, Serialize)]
#[cfg_attr(js, derive(tsify::Tsify))]
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
#[cfg_attr(js, derive(tsify::Tsify))]
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
    #[cfg_attr(js, tsify(type = "`0x${string}`"))]
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
    provider: Arc<dyn Eip1193Provider>,
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
    fn from_unspent(poi_enabled: bool, in_notes: Vec<(UtxoNote, Option<PoiStatus>)>) -> Self {
        let unavailable = in_notes
            .iter()
            .filter(|(_, status)| *status == Some(PoiStatus::Unavailable))
            .map(|(note, _)| (note.viewing_pubkey, note.asset))
            .collect();
        let notes = if poi_enabled {
            in_notes
                .into_iter()
                .filter(|(_, status)| *status == Some(PoiStatus::Valid))
                .map(|(note, _)| note)
                .collect()
        } else {
            in_notes.into_iter().map(|(note, _)| note).collect()
        };
        Self { notes, unavailable }
    }

    /// An insufficient balance is an observation failure when this account and asset
    /// still has notes whose POI status could not be read. Valid notes are already
    /// the only inputs, so a covered amount does not take this path.
    fn explain(
        &self,
        result: Result<Vec<ProvedOperation>, TransactionBuilderError>,
    ) -> Result<Vec<ProvedOperation>, RailgunProviderError> {
        match result {
            Err(TransactionBuilderError::InsufficientBalance { from, asset, .. })
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
    #[error("Build error: {0}")]
    Build(#[from] TransactionBuilderError),
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
    Rpc(#[from] Eip1193Error),
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
        provider: Arc<dyn Eip1193Provider>,
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

    /// Returns all unspent notes for the given address.
    pub async fn notes(&mut self, address: RailgunAddress) -> Vec<NoteEntry> {
        self.unspent(address)
            .await
            .into_iter()
            .map(|(note, poi_status)| NoteEntry::from_note(note, poi_status))
            .collect()
    }

    /// Returns the balance for the given address.
    ///
    /// If POI is enabled, groups balances by observed POI status. Only `Valid`
    /// is spendable. `Unavailable` means the local list is not caught up, not
    /// that a proof is missing.
    pub async fn balance(&mut self, address: RailgunAddress) -> Vec<BalanceEntry> {
        let mut balance_map = HashMap::new();
        for note in self.notes(address).await {
            *balance_map
                .entry((note.asset, note.poi_status))
                .or_insert(0) += note.amount;
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

    /// Helper to create a transaction builder.
    pub fn transact(&self) -> TransactionBuilder {
        TransactionBuilder::new()
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
    /// POI provider and no proof is generated, so this is cheap enough to run before every quote.
    /// Not usable on the ERC-4337 path, where the bundler simulates with its own origin.
    pub async fn build_dummy(
        &mut self,
        builder: TransactionBuilder,
        rng: &mut impl CryptoRng,
    ) -> Result<ProvedTx, RailgunProviderError> {
        let spendable = self.spendable_notes().await;
        let built = builder
            .build_dummy(
                self.chain.id,
                &spendable.notes,
                &self.utxo_indexer.utxo_trees,
                rng,
            )
            .await;
        let operations = spendable.explain(built)?;
        Ok(ProvedTx::new(self.chain.railgun_smart_wallet, operations))
    }

    /// Build a transaction builder into a proved, signable transaction.
    pub async fn build(
        &mut self,
        builder: TransactionBuilder,
        rng: &mut impl CryptoRng,
    ) -> Result<ProvedTx, RailgunProviderError> {
        let operations = self.build_operation(builder, rng).await?;
        if let Some(poi_provider) = &mut self.poi_provider {
            poi_provider.register_ops(&operations).await?;
        }

        let proved_tx = ProvedTx::new(self.chain.railgun_smart_wallet, operations);
        Ok(proved_tx)
    }

    /// The UserOperation [`Self::prepare_userop`] would build, with a dummy proof: same
    /// calldata, same paymaster data, nothing proved and the spending signer never asked.
    ///
    /// It cannot be sent. It exists to be simulated from the verification bypass origin
    /// ([`VERIFICATION_BYPASS`]), for instance with `kohaku_userop_kit::validation_probe`, so that
    /// the gas limits, hence the fee, are known before the one real proof.
    pub async fn dummy_userop<S: SmartAccount>(
        &mut self,
        builder: TransactionBuilder,
        sender: &S,
        fee_payer: Arc<dyn RailgunSigner>,
        fee_token: Address,
        calldata: &S::Call,
        fee: u128,
        gas: UserOperationGasEstimate,
        rng: &mut impl CryptoRng,
    ) -> Result<SignableUserOperation, RailgunProviderError> {
        let (privacy_paymaster, railgun_fee_adapter) = self.paymaster_contracts(fee_token)?;
        let fee_asset = AssetId::Erc20(fee_token);
        let adapted = builder
            .adapt(railgun_fee_adapter, *sender.address().into_word())
            // The paymaster checks the fee from `paymasterData`, it has no use for the sender:
            // hidden, so that opening the fee note does not tell which account paid.
            .transfer_with(
                fee_payer,
                paymaster_railgun_address(ChainId::evm(self.chain.id)),
                fee_asset,
                fee,
                "fee",
                NoteEncryption::Legacy,
                true,
            );
        let spendable = self.spendable_notes().await;
        let built = adapted
            .build_dummy(
                self.chain.id,
                &spendable.notes,
                &self.utxo_indexer.utxo_trees,
                rng,
            )
            .await;
        let operations = spendable.explain(built)?;
        self.userop_from(
            &operations,
            sender,
            calldata,
            privacy_paymaster,
            railgun_fee_adapter,
            fee_token,
            fee,
            gas,
        )
        .await
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
        builder: TransactionBuilder,
        bundler: &dyn Bundler,
        sender: &S,
        fee_payer: Arc<dyn RailgunSigner>,
        fee_token: Address,
        calldata: S::Call,
        gas: UserOperationGasEstimate,
        rng: &mut impl CryptoRng,
    ) -> Result<(SignableUserOperation, SingleProofReport), RailgunProviderError> {
        let (privacy_paymaster, railgun_fee_adapter) = self.paymaster_contracts(fee_token)?;
        let fee_asset = AssetId::Erc20(fee_token);
        let total_gas = gas.pre_verification_gas
            + gas.verification_gas_limit
            + gas.call_gas_limit
            + gas.paymaster_verification_gas_limit.unwrap_or(0)
            + gas.paymaster_post_op_gas_limit.unwrap_or(0);
        let fee = total_gas * gas.max_fee_per_gas;

        // The one proof. This is the only place the spending signer is used.
        let adapted = builder
            .adapt(railgun_fee_adapter, *sender.address().into_word())
            // The paymaster checks the fee from `paymasterData`, it has no use for the sender:
            // hidden, so that opening the fee note does not tell which account paid.
            .transfer_with(
                fee_payer,
                paymaster_railgun_address(ChainId::evm(self.chain.id)),
                fee_asset,
                fee,
                "fee",
                NoteEncryption::Legacy,
                true,
            );
        let operations = self.build_operation(adapted, rng).await?;
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
            estimate_paymaster_verification_gas_limit(self.provider.as_ref(), &signable).await?;
        if pmv_measured > pmv_limit {
            return Err(RailgunProviderError::LimitsTooLow {
                what: "paymaster verification",
                needed: pmv_measured,
                limit: pmv_limit,
            });
        }
        let bundler_view = bundler.estimate_gas(&signable).await?;
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

    /// Simulate the ERC-4337 gas limits before proving, so the fee is fixed with one proof (hence
    /// one spending signature) via [`Self::prepare_userop_single_proof`], instead of the iterative
    /// re-proving [`Self::prepare_userop`] does.
    ///
    /// Runs the `userop_kit` validation probe at the EntryPoint from the verification-bypass
    /// origin, over a dummy (zero-proof) UserOperation, using `eth_call` with state overrides. Two
    /// rounds: the second uses what the first measured. The RPC must support state overrides.
    #[allow(clippy::too_many_arguments)]
    pub async fn simulate_gas_limits<S: SmartAccount>(
        &mut self,
        builder: &TransactionBuilder,
        bundler: &dyn Bundler,
        sender: &S,
        fee_payer: Arc<dyn RailgunSigner>,
        fee_token: Address,
        calldata: &S::Call,
        has_call: bool,
        margin_percent: u32,
        rng: &mut impl CryptoRng,
    ) -> Result<(UserOperationGasEstimate, GasSimulationDetails), RailgunProviderError> {
        use kohaku_userop_kit::validation_probe::{self as probe, alto::AltoPolicy, pad_gas};

        let price = bundler.gas_price().await?.ok_or_else(|| {
            RailgunProviderError::Other(Box::new(std::io::Error::other(
                "the bundler gives no gas price outside of a simulation",
            )))
        })?;

        // The probe does not enforce limits: they only enter through `maxCost`, against which the
        // paymaster checks the fee. Round one starts from plausible figures; round two uses what
        // round one measured.
        let mut gas = UserOperationGasEstimate {
            pre_verification_gas: 150_000,
            verification_gas_limit: 100_000,
            call_gas_limit: if has_call { 150_000 } else { 20_000 },
            paymaster_verification_gas_limit: Some(1_200_000),
            paymaster_post_op_gas_limit: Some(50_000),
            max_fee_per_gas: price.max_fee_per_gas,
            max_priority_fee_per_gas: price.max_priority_fee_per_gas,
        };
        let total_of = |g: &UserOperationGasEstimate| {
            g.pre_verification_gas
                + g.verification_gas_limit
                + g.call_gas_limit
                + g.paymaster_verification_gas_limit.unwrap_or(0)
                + g.paymaster_post_op_gas_limit.unwrap_or(0)
        };

        let mut measured = None;
        for _round in 1..=2 {
            let fee = total_of(&gas) * price.max_fee_per_gas;
            let dummy = self
                .dummy_userop(
                    builder.clone(),
                    sender,
                    fee_payer.clone(),
                    fee_token,
                    calldata,
                    fee,
                    gas,
                    rng,
                )
                .await?;
            let max_cost = U256::from(dummy.total_gas_limit()) * U256::from(price.max_fee_per_gas);
            let request = probe::request(&dummy, max_cost);

            let mut overrides: Vec<AccountStateOverride> = request
                .code_overrides
                .iter()
                .map(|(address, code)| AccountStateOverride {
                    address: *address,
                    code: Some(code.clone()),
                    balance: None,
                })
                .collect();
            if let Some((from, to)) = request.copy_code_from {
                // The 7702 delegation of the fresh sender is not on-chain yet: give it the code
                // it will delegate to.
                let code = self.provider.get_code(from).await?;
                overrides.push(AccountStateOverride {
                    address: to,
                    code: Some(code),
                    balance: None,
                });
            }
            overrides.push(AccountStateOverride {
                address: VERIFICATION_BYPASS,
                code: None,
                balance: Some(U256::from(10u128.pow(24))),
            });

            let answer = self
                .provider
                .eth_call_overrides(
                    VERIFICATION_BYPASS,
                    request.to,
                    request.data.clone(),
                    25_000_000,
                    overrides,
                )
                .await?;

            let phases = probe::decode(&answer, has_call).map_err(|e| {
                RailgunProviderError::Other(Box::new(std::io::Error::other(e.to_string())))
            })?;

            // The bundler prices paymaster data and signature as all non-zero bytes: take its way
            // of counting, which is the higher one, and the usual margin.
            let pre_verification =
                probe::pre_verification_gas(&dummy).max(probe::alto::pre_verification_gas(&dummy));
            gas.pre_verification_gas = pad_gas(pre_verification, margin_percent, GAS_BUCKET);
            // The EntryPoint charges its own pre-validation work to this limit (AA26), which the
            // probe cannot see: see `ENTRY_POINT_VALIDATION_OVERHEAD`.
            gas.verification_gas_limit = pad_gas(
                phases.account_validation + probe::ENTRY_POINT_VALIDATION_OVERHEAD,
                margin_percent,
                GAS_BUCKET,
            );
            // Execution calls: size from the bundler's own prediction, with half the margin. The
            // one limit whose shortfall would strand funds on the ephemeral sender.
            gas.call_gas_limit = if has_call {
                pad_gas(
                    AltoPolicy::PIMLICO_PUBLIC.call_gas_limit(phases.call_limit),
                    margin_percent / 2,
                    GAS_BUCKET,
                )
            } else {
                30_000
            };
            gas.paymaster_verification_gas_limit = Some(pad_gas(
                phases.paymaster_validation,
                margin_percent,
                GAS_BUCKET,
            ));
            gas.paymaster_post_op_gas_limit = Some(if phases.post_op_called {
                pad_gas(phases.post_op, margin_percent, GAS_BUCKET).max(10_000)
            } else {
                10_000
            });
            let total = total_of(&gas);
            measured = Some((phases, pre_verification, total));
        }

        let (phases, pre_verification, total) = measured.expect("two rounds ran");
        Ok((
            gas,
            GasSimulationDetails {
                account_validation: phases.account_validation,
                paymaster_validation: phases.paymaster_validation,
                call: phases.call,
                call_limit: phases.call_limit,
                post_op: phases.post_op,
                pre_verification,
                total,
                margin_percent,
            },
        ))
    }

    /// Fixes the fee by simulation ([`Self::simulate_gas_limits`]) then proves exactly once
    /// ([`Self::prepare_userop_single_proof`]): one spending signature, no iterative re-proving.
    /// Falls back to nothing — if the simulation fails, the error is returned and nothing is
    /// signed. `has_call` says whether `calldata` carries execution calls.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_userop_single<S: SmartAccount>(
        &mut self,
        builder: TransactionBuilder,
        bundler: &dyn Bundler,
        sender: &S,
        fee_payer: Arc<dyn RailgunSigner>,
        fee_token: Address,
        calldata: S::Call,
        has_call: bool,
        margin_percent: u32,
        rng: &mut impl CryptoRng,
    ) -> Result<SignableUserOperation, RailgunProviderError> {
        let (gas, details) = self
            .simulate_gas_limits(
                &builder,
                bundler,
                sender,
                fee_payer.clone(),
                fee_token,
                &calldata,
                has_call,
                margin_percent,
                rng,
            )
            .await?;
        info!(
            "Simulated before signing: account {}, paymaster {}, call {} used / {} limit, post-op {}, pre-verification {}; total {} gas with {}% margin",
            details.account_validation,
            details.paymaster_validation,
            details.call,
            details.call_limit,
            details.post_op,
            details.pre_verification,
            details.total,
            details.margin_percent,
        );
        let (signable, _report) = self
            .prepare_userop_single_proof(
                builder, bundler, sender, fee_payer, fee_token, calldata, gas, rng,
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

    /// Build a transaction builder into a broadcastable 7702 UserOperation.
    ///
    /// Constructs a UserOperation sent from the `delegator_address` that executes the provided
    /// transaction, with an additional fee note transfer to cover the bundler fees. The
    /// `fee_payer` is the signer that will authorize the fee note transfer to the bundler's
    /// address for the estimated fee amount in `fee_token`.
    pub async fn prepare_userop<S: SmartAccount>(
        &mut self,
        builder: TransactionBuilder,
        bundler: &dyn Bundler,
        sender: &S,
        fee_payer: Arc<dyn RailgunSigner>,
        fee_token: Address,
        calldata: S::Call,
        rng: &mut impl CryptoRng,
    ) -> Result<SignableUserOperation, RailgunProviderError> {
        let (privacy_paymaster, railgun_fee_adapter) = self.paymaster_contracts(fee_token)?;

        let paymaster_railgun_address = paymaster_railgun_address(ChainId::evm(self.chain.id));
        let fee_asset = AssetId::Erc20(fee_token);

        //? Initial arbitrary estimation of fee note value.
        //? IMPORTANT: Needs to be high enough to not cause a revert. Most
        //? bundlers seem to use a fixed maxCost value for estimation (IE 27_000_000
        //? for pimlico). Setting this too low causes an unrecoverable estimation
        //? failure.
        let mut fee_value = 100_000_000;

        let builder = builder.adapt(railgun_fee_adapter, *sender.address().into_word());

        info!("Iteratively building UserOperation to converge on accurate fee estimate");
        for _ in 0..5 {
            let broadcast_builder = builder.clone().transfer_with(
                fee_payer.clone(),
                paymaster_railgun_address,
                fee_asset,
                fee_value,
                "fee",
                NoteEncryption::Legacy,
                true,
            );

            info!(
                "Building broadcast transaction with fee value: {}",
                fee_value
            );
            let operations = self.build_operation(broadcast_builder, rng).await?;

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
                .with_gas_estimate(bundler)
                .await?
                .build();

            // Recalculate fee and check for convergence.
            info!("Prepared broadcast transaction: {:?}", signable);
            let estimated_paymaster_verification_gas_limit =
                estimate_paymaster_verification_gas_limit(self.provider.as_ref(), &signable)
                    .await?;
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

    async fn all_unspent(&mut self) -> Vec<(UtxoNote, Option<PoiStatus>)> {
        let addresses = self.utxo_indexer.registered();
        let mut all_notes = Vec::new();

        for address in addresses {
            let mut notes = self.unspent(address).await;
            all_notes.append(&mut notes);
        }
        all_notes
    }

    async fn unspent(&mut self, address: RailgunAddress) -> Vec<(UtxoNote, Option<PoiStatus>)> {
        let notes = self.utxo_indexer.unspent(address);

        let Some(poi_provider) = &mut self.poi_provider else {
            return notes.into_iter().map(|note| (note, None)).collect();
        };

        let mut annotated_notes = Vec::new();
        for note in notes {
            let status = poi_provider.status(note.blinded_commitment.into(), note.commitment_type);
            annotated_notes.push((note, Some(status)));
        }

        annotated_notes
    }

    async fn build_operation(
        &mut self,
        builder: TransactionBuilder,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<ProvedOperation>, RailgunProviderError> {
        let spendable = self.spendable_notes().await;
        let built = builder
            .build(
                &self.prover,
                self.chain.id,
                &spendable.notes,
                &self.utxo_indexer.utxo_trees,
                rng,
            )
            .await;
        spendable.explain(built)
    }

    /// Notes usable as inputs, and the account/asset pairs that could not be observed.
    ///
    /// When POI is on, only `Valid` notes are inputs. `Unavailable` is not an input,
    /// but every build reports it when that is what made the balance look short.
    async fn spendable_notes(&mut self) -> SpendableNotes {
        SpendableNotes::from_unspent(self.poi_provider.is_some(), self.all_unspent().await)
    }
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
    provider: &dyn Eip1193Provider,
    user_op: &SignableUserOperation,
) -> Result<u128, RailgunProviderError> {
    let entry_point = user_op.entry_point;
    let Some(paymaster) = user_op.user_op.paymaster else {
        return Ok(0);
    };
    let user_op = user_op.user_op.into_packed();
    let data = abi::PrivacyPaymaster::validatePaymasterUserOpCall {
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

    Ok(provider
        .estimate_gas(paymaster, data, Some(entry_point))
        .await? as u128)
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
    };
    use alloy::providers::Provider;
    use kohaku_kv_store::Store;
    use tokio::{
        net::TcpListener,
        time::{Duration, timeout},
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
        let db = Store::create();
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
            .with_database(db)
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
        let builder = provider
            .transact()
            .transfer(signer.clone(), signer.address(), asset, 1, "");
        let result = timeout(
            Duration::from_secs(5),
            provider.build(builder, &mut rand::rng()),
        )
        .await
        .unwrap();
        assert!(matches!(
            result,
            Err(RailgunProviderError::PoiStatusUnavailable)
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
        let builder = provider.transact().transfer(
            signer.clone(),
            signer.address(),
            AssetId::erc20(Address::repeat_byte(0x22)),
            1,
            "",
        );
        assert!(matches!(
            timeout(
                Duration::from_secs(5),
                provider.build(builder, &mut rand::rng())
            )
            .await
            .unwrap(),
            Err(RailgunProviderError::Build(
                TransactionBuilderError::InsufficientBalance { .. }
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
        transact::TransactionBuilderError,
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
                (valid, Some(PoiStatus::Valid)),
                (unavailable, Some(PoiStatus::Unavailable)),
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
        let selected =
            SpendableNotes::from_unspent(true, vec![(missing, Some(PoiStatus::Missing))]);
        assert!(selected.notes.is_empty());
        let err = selected.explain(Err(TransactionBuilderError::InsufficientBalance {
            from: signer.address(),
            asset,
            value: 1,
        }));
        assert!(matches!(
            err,
            Err(RailgunProviderError::Build(
                TransactionBuilderError::InsufficientBalance { .. }
            ))
        ));
    }

    #[test]
    fn unavailable_on_another_asset_does_not_mask_a_shortfall() {
        let signer = signer();
        let wanted = AssetId::erc20(Address::repeat_byte(0x11));
        let other = AssetId::erc20(Address::repeat_byte(0x22));
        let unavailable = note(signer.clone(), other, 10);
        let selected =
            SpendableNotes::from_unspent(true, vec![(unavailable, Some(PoiStatus::Unavailable))]);
        let err = selected.explain(Err(TransactionBuilderError::InsufficientBalance {
            from: signer.address(),
            asset: wanted,
            value: 1,
        }));
        assert!(matches!(
            err,
            Err(RailgunProviderError::Build(
                TransactionBuilderError::InsufficientBalance { .. }
            ))
        ));
    }

    #[test]
    fn a_shortfall_on_an_unobserved_asset_is_unavailable() {
        let signer = signer();
        let asset = AssetId::erc20(Address::repeat_byte(0x11));
        let unavailable = note(signer.clone(), asset, 10);
        let selected =
            SpendableNotes::from_unspent(true, vec![(unavailable, Some(PoiStatus::Unavailable))]);
        let err = selected.explain(Err(TransactionBuilderError::InsufficientBalance {
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
