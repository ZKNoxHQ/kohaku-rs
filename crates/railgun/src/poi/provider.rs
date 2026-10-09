use std::{collections::HashMap, sync::Arc};

use alloy::primitives::ChainId;
use kohaku_kv_store::Store;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::{
    circuit::{
        groth16_prover::Groth16Prover,
        inputs::poi_inputs::{PoiCircuitInputs, PoiCircuitInputsError},
    },
    crypto::{
        keys::{NullifyingKey, SpendingPublicKey},
        railgun_txid::Txid,
    },
    indexer::{
        syncer::{Operation, TxidSyncer},
        txid_indexer::{TxidIndexer, TxidIndexerError},
    },
    merkle_tree::{MerkleProof, TOTAL_LEAVES, TxidLeafHash, TxidMerkleTree, UtxoTreeIndex},
    note::utxo::{self, UtxoNote},
    poi::{
        client::{PoiClient, PoiClientError, PoiNodeClient},
        note::PoiNote,
        recovery::RecoveryAccount,
        types::{
            BlindedCommitment, BlindedCommitmentType, ListKey, PoiStatus, PreTransactionPoi,
            PreTransactionPois, TransactProofData,
        },
    },
    railgun_database::{DatabaseError, RailgunDB},
    transact::proved_transaction::ProvedOperation,
};

pub struct PoiProvider {
    inner: PoiProviderState,
    db: Store,
    poi_client: PoiClient,
    txid_indexer: TxidIndexer,
    /// Statuses and txid tree only, never generate or submit proofs. Required for
    /// view-only signers, which cannot produce valid POI inputs.
    read_only: bool,
}

#[derive(Serialize, Deserialize, Default)]
pub(crate) struct PoiProviderState {
    pub pending: Vec<PendingPoiEntry>,
    pub pois: HashMap<BlindedCommitment, HashMap<ListKey, PoiInfo>>,
    /// Past operations already seen as `Valid`, not probed again.
    #[serde(default)]
    pub recovered_valid: std::collections::HashSet<Txid>,
}

#[derive(Debug, Error)]
pub enum PoiProviderError {
    #[error("Txid indexer error: {0}")]
    TxidIndexer(#[from] TxidIndexerError),
    #[error("POI Client error: {0}")]
    PoiClient(#[from] PoiClientError),
    #[error("Merkle proof not found for blinded commitment {0} and list key {1}")]
    ProofNotFound(BlindedCommitment, ListKey),
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("Pre-transaction POI error: {0}")]
    PreTransaction(Box<dyn std::error::Error + Send + Sync>),
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct PoiInfo {
    status: Option<PoiStatus>,
    proof: Option<MerkleProof>,
}

/// Serializable snapshot needed to re-prove and submit a post-transaction POI
/// proof to the POI aggregator.
///
/// TODO: Consider privacy / security implications of storing this data on disk.
#[derive(Clone, Serialize, Deserialize)]
pub struct PendingPoiEntry {
    pub txid: Txid,
    pub spending_pubkey: SpendingPublicKey,
    pub nullifying_key: NullifyingKey,
    pub utxo_tree_in: u32,
    pub bound_params_hash: U256,
    /// Input UTXO notes. Fresh POI proofs are re-fetched at process time.
    pub in_notes: Vec<UtxoNote>,
    pub out_commitments: Vec<U256>,
    pub out_npks: Vec<U256>,
    pub out_values: Vec<U256>,
    pub token_hash: U256,
    pub has_unshield: bool,
    pub list_keys: Vec<ListKey>,
    /// Seconds since the epoch when the entry was queued, 0 for entries written
    /// before the field existed. Used to tell an operation still in flight from one that never
    /// reached the chain.
    #[serde(default)]
    pub created_at: u64,
}

/// How long a proved operation may stay unmined before its pending POI is dropped.
/// Relayer quotes last a few minutes; past this, a transaction whose inputs are still unspent
/// was not sent.
const UNMINED_GRACE_SECS: u64 = 15 * 60;

fn now_secs() -> u64 {
    web_time::SystemTime::now()
        .duration_since(web_time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Non-sensitive view of a [`PendingPoiEntry`] for UIs.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingPoiSummary {
    pub txid: String,
    pub utxo_tree_in: u32,
    pub inputs: usize,
    pub outputs: usize,
    pub has_unshield: bool,
    pub list_keys: Vec<String>,
}

#[derive(Debug, Error)]
enum PendingPoiError {
    #[error("POI client error: {0}")]
    PoiClient(#[from] PoiClientError),
    #[error("Circuit inputs error: {0}")]
    CircuitInputs(#[from] PoiCircuitInputsError),
    #[error("Prover error: {0}")]
    Prover(Box<dyn std::error::Error + Send + Sync>),
    #[error("Missing txid position for txid {0:?}")]
    MissingTxid(Txid),
    #[error("Missing UTXO tree {0}")]
    MissingUtxoTree(u32),
    #[error("Missing TXID tree {0}")]
    MissingTxidTree(u32),
}

impl PoiProvider {
    pub async fn new(
        chain_id: ChainId,
        db: Store,
        txid_syncer: Arc<dyn TxidSyncer>,
        poi_endpoint: impl Into<String>,
        list_keys: Vec<ListKey>,
    ) -> Result<Self, PoiProviderError> {
        let inner = db.get_poi_provider().await?;
        let txid_indexer = TxidIndexer::new(db.clone(), txid_syncer).await?;
        let poi_client = PoiClient::new(chain_id, poi_endpoint, list_keys);

        Ok(Self {
            inner,
            db,
            poi_client,
            txid_indexer,
            read_only: false,
        })
    }

    /// Disables proof generation, recovery and submission.
    pub fn set_read_only(&mut self, read_only: bool) {
        self.read_only = read_only;
    }

    pub async fn sync_to(
        &mut self,
        prover: &Groth16Prover,
        to_block: u64,
        accounts: &[RecoveryAccount],
    ) -> Result<(), PoiProviderError> {
        // Keep the full record of the operations spending our notes.
        self.txid_indexer.watch_nullifiers(
            accounts
                .iter()
                .flat_map(|a| a.spent.iter().map(|n| n.nullifier))
                .collect(),
        );

        let poi_client = self.poi_client.clone();
        self.txid_indexer.sync_to(to_block, &poi_client).await?;

        let dropped = self.prune_unmined(accounts);
        if dropped > 0 {
            info!(
                "Dropped {dropped} pending POI entr{} of operations that never reached the chain",
                if dropped == 1 { "y" } else { "ies" }
            );
        }

        if self.read_only {
            self.save().await?;
            return Ok(());
        }

        let recovered = self.recover_missing(accounts).await;
        if recovered > 0 {
            info!("Queued {recovered} past operation(s) for POI proof generation");
        }

        self.submit_pending(prover).await;
        self.save().await?;
        Ok(())
    }

    /// Status per list of one blinded commitment, asked to the POI node now.
    /// `status()` folds the lists into the worst status; this keeps them apart. A list that
    /// cannot be reached yields `None`.
    pub async fn statuses_per_list(
        &mut self,
        blinded_commitment: BlindedCommitment,
        commitment_type: BlindedCommitmentType,
    ) -> Vec<(String, Option<PoiStatus>)> {
        let mut out = Vec::new();
        for list_key in self.list_keys() {
            let name = serde_json::to_value(&list_key)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_else(|| list_key.to_string());
            let status = match self
                .poi_client
                .poi_status(&list_key, blinded_commitment, commitment_type)
                .await
            {
                Ok(s) => Some(s),
                Err(e) => {
                    debug!("POI status probe failed for {blinded_commitment} ({list_key}): {e}");
                    None
                }
            };
            out.push((name, status));
        }
        out
    }

    /// Past operations whose POI the recovery pass saw as `Valid` on the node.
    pub fn recovered_valid(&self) -> Vec<Txid> {
        self.inner.recovered_valid.iter().copied().collect()
    }

    /// Operations of the registered accounts that the txid indexer keeps in full.
    pub fn own_operations(&self) -> Vec<(Txid, crate::indexer::syncer::Operation)> {
        self.txid_indexer
            .own_ops()
            .map(|(txid, op)| (txid.clone(), op.clone()))
            .collect()
    }

    /// Last known status per list of every blinded commitment probed so far,
    /// keyed by the blinded commitment as `0x` + 64 hex digits.
    pub fn statuses(&self) -> Vec<(String, Vec<(String, Option<PoiStatus>)>)> {
        self.inner
            .pois
            .iter()
            .map(|(commitment, per_list)| {
                // Display is `BlindedCommitment(0x…)`, not zero-padded.
                let raw = commitment.to_string();
                let hex = raw
                    .trim_start_matches("BlindedCommitment(")
                    .trim_end_matches(')')
                    .trim_start_matches("0x");
                let key = format!("0x{:0>64}", hex);
                let lists = per_list
                    .iter()
                    .map(|(list, info)| {
                        let name = serde_json::to_value(list)
                            .ok()
                            .and_then(|v| v.as_str().map(str::to_owned))
                            .unwrap_or_else(|| list.to_string());
                        (name, info.status.clone())
                    })
                    .collect();
                (key, lists)
            })
            .collect()
    }

    pub async fn register_ops(
        &mut self,
        operations: &[ProvedOperation],
    ) -> Result<(), PoiProviderError> {
        let list_keys = self.poi_client.list_keys();
        for op in operations {
            self.register(op, list_keys.clone());
        }
        self.save().await?;
        Ok(())
    }

    /// Drops the pending entries of operations that were proved but never reached
    /// the chain (a relayer that did not answer). Their txid will never be validated, so they
    /// would be retried, and fail, at every sync. Should the transaction land later after all,
    /// `recover_missing` rebuilds the entry from chain data.
    pub async fn discard_ops(
        &mut self,
        operations: &[ProvedOperation],
    ) -> Result<usize, PoiProviderError> {
        let txids: Vec<Txid> = operations.iter().map(Txid::from_operation).collect();
        let before = self.inner.pending.len();
        self.inner.pending.retain(|e| !txids.contains(&e.txid));
        let removed = before - self.inner.pending.len();
        if removed > 0 {
            self.save().await?;
        }
        Ok(removed)
    }

    /// Summaries of pending POI submissions.
    pub fn pending_summaries(&self) -> Vec<PendingPoiSummary> {
        self.inner
            .pending
            .iter()
            .map(|e| PendingPoiSummary {
                txid: format!("{:?}", e.txid),
                utxo_tree_in: e.utxo_tree_in,
                inputs: e.in_notes.len(),
                outputs: e.out_commitments.len(),
                has_unshield: e.has_unshield,
                list_keys: e
                    .list_keys
                    .iter()
                    .filter_map(|k| serde_json::to_value(k).ok()?.as_str().map(str::to_owned))
                    .collect(),
            })
            .collect()
    }

    pub fn list_keys(&self) -> Vec<ListKey> {
        self.poi_client.list_keys()
    }

    /// Returns the worst-case POI status across all configured list keys.
    pub async fn status(
        &mut self,
        blinded_commitment: BlindedCommitment,
        commitment_type: BlindedCommitmentType,
    ) -> Result<PoiStatus, PoiProviderError> {
        let mut worst = PoiStatus::Valid;
        for list_key in self.list_keys() {
            let status = self
                .poi_client
                .poi_status(&list_key, blinded_commitment, commitment_type)
                .await?;
            debug!(
                "POI status for {} ({list_key}): {status:?}",
                blinded_commitment
            );
            worst = worst.max(status);
        }
        Ok(worst)
    }

    /// Drops pending entries of operations that were proved but never mined.
    ///
    /// A mined operation nullifies every one of its inputs. So, once the UTXO indexer is synced,
    /// an entry with an input still unspent is not on-chain; past the grace period it will not
    /// be, because the relayer's quote has expired. And an entry whose inputs were spent by an
    /// operation with another txid (the retry) can never be mined at all. Such an entry can never be submitted (its
    /// txid is in no tree) and would be retried at every sync. The POI node never saw it: nothing
    /// is sent before the txid is validated, so there is nothing to clean up remotely. If the
    /// transaction does land later, `recover_missing` rebuilds the entry from chain data.
    fn prune_unmined(&mut self, accounts: &[RecoveryAccount]) -> usize {
        let now = now_secs();
        let before = self.inner.pending.len();
        let own_ops: Vec<(Txid, Vec<U256>)> = self
            .txid_indexer
            .own_ops()
            .map(|(txid, op)| (*txid, op.nullifiers.clone()))
            .collect();
        self.inner
            .pending
            .retain(|entry| !never_mined(entry, accounts, &own_ops, now));
        before - self.inner.pending.len()
    }

    /// Queues a POI proof for every past operation of `accounts` whose outputs
    /// the POI node does not know yet.
    ///
    /// `register_ops` only covers operations built by this process. A wallet restored from its
    /// keys, or one whose pending entries were lost, has change notes stuck in `Missing`: the
    /// proof is rebuilt here from chain data (spent inputs, decrypted outputs, operation record).
    /// Returns the number of entries queued. Never fails: a note that cannot be recovered is
    /// logged and left as is.
    async fn recover_missing(&mut self, accounts: &[RecoveryAccount]) -> usize {
        let list_keys = self.poi_client.list_keys();
        let own_ops: Vec<(Txid, Operation)> = self
            .txid_indexer
            .own_ops()
            .map(|(t, o)| (*t, o.clone()))
            .collect();

        let mut queued: Vec<(u64, PendingPoiEntry)> = Vec::new();
        for (txid, op) in own_ops {
            if self.inner.pending.iter().any(|e| e.txid == txid)
                || self.inner.recovered_valid.contains(&txid)
            {
                continue;
            }
            let Some(entry) = accounts
                .iter()
                .find_map(|account| recovery_entry(account, txid, &op, &list_keys))
            else {
                debug!("Own operation {txid:?} is not fully known locally, skipping POI recovery");
                continue;
            };

            // All outputs of an operation share one proof: probing the first one is enough.
            let Some(probe) = blinded_commitments(
                &entry,
                op.utxo_tree_out,
                op.utxo_out_start_index,
            )
            .into_iter()
            .next() else {
                continue;
            };
            match self.status(probe, BlindedCommitmentType::Transact).await {
                Ok(PoiStatus::Missing) => {
                    info!("POI missing for past operation {txid:?}, rebuilding its proof");
                    queued.push((op.block_number, entry));
                }
                Ok(PoiStatus::Valid) => {
                    self.inner.recovered_valid.insert(txid);
                }
                Ok(status) => debug!("Past operation {txid:?} has POI status {status:?}"),
                Err(e) => warn!("Could not read POI status of past operation {txid:?}: {e}"),
            }
        }

        // `submit_pending` walks the list backwards: newest first here means oldest submitted
        // first, which matters when an operation spends the change of a previous one.
        queued.sort_by(|a, b| b.0.cmp(&a.0));
        let count = queued.len();
        self.inner.pending.extend(queued.into_iter().map(|(_, e)| e));
        count
    }

    fn register(&mut self, op: &ProvedOperation, list_keys: Vec<ListKey>) {
        info!(
            "Registered POI for {:?}",
            op.circuit_inputs.bound_params_hash
        );
        self.inner.pending.push(entry_from_op(op, list_keys));
    }

    /// Generates, for every operation and list key, the pre-transaction POI a broadcaster asks
    /// for before relaying. Same circuit as the post-transaction proof, with the pre-inclusion
    /// UTXO position and a dummy txid inclusion proof, since the txid is in no tree yet.
    pub async fn pre_transaction_pois(
        &self,
        prover: &Groth16Prover,
        operations: &[ProvedOperation],
    ) -> Result<PreTransactionPois, PoiProviderError> {
        let list_keys = self.poi_client.list_keys();
        let mut result: PreTransactionPois = HashMap::new();

        for op in operations {
            let entry = entry_from_op(op, list_keys.clone());
            let utxo_tree_out = UtxoTreeIndex::pre_inclusion();
            let leaf = TxidLeafHash::new(entry.txid, entry.utxo_tree_in, utxo_tree_out);
            let leaf_key = format!("{:064x}", <U256 as From<_>>::from(leaf));

            for list_key in &list_keys {
                let mut in_notes = Vec::new();
                for note in entry.in_notes.clone() {
                    let proof = self
                        .poi_client
                        .merkle_proof(list_key, note.blinded_commitment.into())
                        .await?;
                    in_notes.push(PoiNote::new(
                        note,
                        HashMap::from([(list_key.clone(), proof)]),
                    ));
                }

                let inputs = PoiCircuitInputs::from_inputs_with_txid_proof(
                    entry.spending_pubkey,
                    entry.nullifying_key,
                    entry.utxo_tree_in,
                    entry.bound_params_hash,
                    &in_notes,
                    &entry.out_commitments,
                    &entry.out_npks,
                    &entry.out_values,
                    entry.token_hash,
                    entry.has_unshield,
                    list_key.clone(),
                    utxo_tree_out,
                    leaf.dummy_proof(),
                )
                .map_err(|e| PoiProviderError::PreTransaction(Box::new(e)))?;

                let proof = prover
                    .prove_poi(&inputs)
                    .await
                    .map_err(|e| PoiProviderError::PreTransaction(Box::new(e)))?;

                result.entry(list_key.clone()).or_default().insert(
                    leaf_key.clone(),
                    PreTransactionPoi {
                        proof,
                        txid_merkleroot: inputs.railgun_txid_merkleroot_after_transaction,
                        poi_merkleroots: inputs.poi_merkleroots,
                        blinded_commitments_out: blinded_commitments(
                            &entry,
                            PRE_INCLUSION_POSITION,
                            PRE_INCLUSION_POSITION,
                        ),
                        railgun_txid_if_has_unshield: inputs.railgun_txid_if_has_unshield,
                    },
                );
            }
        }
        Ok(result)
    }

    async fn submit_pending(&mut self, prover: &Groth16Prover) {
        for i in (0..self.inner.pending.len()).rev() {
            let entry = self.inner.pending[i].clone();
            match self.submit_poi(prover, &entry).await {
                Ok(_) => {
                    info!("Submitted POI for {:?}", entry.txid);
                    self.inner.pending.remove(i);
                }
                Err(PendingPoiError::MissingTxid(_)) => {
                    info!("Waiting for txid to be indexed: {:?}", entry.txid);
                }
                Err(e) => {
                    warn!("Failed to submit POI for pending entry: {:?}", e);
                }
            }
        }
    }

    async fn submit_poi(
        &self,
        prover: &Groth16Prover,
        entry: &PendingPoiEntry,
    ) -> Result<(), PendingPoiError> {
        let txid_tree_number = match self.txid_indexer.txid_position(&entry.txid) {
            Some((tree_number, _)) => tree_number,
            None => return Err(PendingPoiError::MissingTxid(entry.txid)),
        };

        let (utxo_tree_number, utxo_leaf_index) = match self.txid_indexer.utxo_position(&entry.txid)
        {
            Some((tree_number, leaf_index)) => (tree_number, leaf_index),
            None => return Err(PendingPoiError::MissingUtxoTree(entry.utxo_tree_in)),
        };

        let txid_tree = match self.txid_indexer.tree(txid_tree_number) {
            Some(tree) => tree,
            None => return Err(PendingPoiError::MissingTxidTree(txid_tree_number)),
        };

        let utxo_tree_out = UtxoTreeIndex::included(utxo_tree_number, utxo_leaf_index);

        let proof_data = self
            .create_proof(
                prover,
                entry,
                txid_tree_number,
                utxo_tree_number,
                utxo_leaf_index,
                txid_tree,
                utxo_tree_out,
            )
            .await?;

        self.poi_client.submit_proof(proof_data).await?;
        Ok(())
    }

    async fn create_proof(
        &self,
        prover: &Groth16Prover,
        entry: &PendingPoiEntry,
        txid_tree_number: u32,
        utxo_tree_number: u32,
        utxo_leaf_index: u32,
        txid_tree: &TxidMerkleTree,
        utxo_tree_out: UtxoTreeIndex,
    ) -> Result<HashMap<ListKey, TransactProofData>, PendingPoiError> {
        let mut proof_data = HashMap::new();

        for list_key in &entry.list_keys {
            let mut in_notes = Vec::new();
            for note in entry.in_notes.clone() {
                let proof = self
                    .poi_client
                    .merkle_proof(list_key, note.blinded_commitment.into())
                    .await?;
                in_notes.push(PoiNote::new(
                    note,
                    HashMap::from([(list_key.clone(), proof)]),
                ));
            }

            let inputs = PoiCircuitInputs::from_inputs(
                entry.spending_pubkey,
                entry.nullifying_key,
                entry.utxo_tree_in,
                entry.bound_params_hash,
                &in_notes,
                &entry.out_commitments,
                &entry.out_npks,
                &entry.out_values,
                entry.token_hash,
                entry.has_unshield,
                list_key.clone(),
                utxo_tree_out,
                txid_tree,
            )?;

            let proof = prover
                .prove_poi(&inputs)
                .await
                .map_err(|e| PendingPoiError::Prover(Box::new(e)))?;
            let blinded_commitments_out =
                blinded_commitments(entry, utxo_tree_number, utxo_leaf_index);

            let txid_merkleroot_index =
                txid_tree_number as u64 * TOTAL_LEAVES as u64 + (txid_tree.leaves_len() as u64 - 1);

            proof_data.insert(
                list_key.clone(),
                TransactProofData {
                    proof,
                    poi_merkleroots: inputs.poi_merkleroots,
                    txid_merkleroot: inputs.railgun_txid_merkleroot_after_transaction,
                    txid_merkleroot_index,
                    blinded_commitments_out,
                    railgun_txid_if_has_unshield: inputs.railgun_txid_if_has_unshield,
                },
            );
        }
        Ok(proof_data)
    }

    async fn save(&self) -> Result<(), PoiProviderError> {
        self.db.set_poi_provider(&self.inner).await?;
        Ok(())
    }
}

/// Tree number and leaf index the Railgun engine uses for outputs that are not on-chain yet.
const PRE_INCLUSION_POSITION: u32 = 199_999;

/// Snapshot of a freshly built operation, enough to prove its POI later.
fn entry_from_op(op: &ProvedOperation, list_keys: Vec<ListKey>) -> PendingPoiEntry {
    let out_notes = op.inner.out_notes();
    let encryptable_notes = op.inner.out_encryptable_notes();
    PendingPoiEntry {
        txid: Txid::from_operation(op),
        spending_pubkey: op.inner.from.spending_public_key(),
        nullifying_key: op.inner.from.viewing_key().nullifying_key(),
        utxo_tree_in: op.inner.utxo_tree_number,
        bound_params_hash: op.circuit_inputs.bound_params_hash,
        in_notes: op.inner.in_notes().to_vec(),
        out_commitments: out_notes.iter().map(|n| n.hash().into()).collect(),
        out_npks: encryptable_notes
            .iter()
            .map(|n| n.note_public_key())
            .collect(),
        out_values: encryptable_notes
            .iter()
            .map(|n| U256::from(n.value()))
            .collect(),
        token_hash: op.inner.asset.hash(),
        has_unshield: op.inner.unshield_note().is_some(),
        list_keys,
        created_at: now_secs(),
    }
}

/// See `PoiProvider::prune_unmined`. `own_ops` are the on-chain operations that
/// spend a nullifier of ours, as `(txid, nullifiers)`.
fn never_mined(
    entry: &PendingPoiEntry,
    accounts: &[RecoveryAccount],
    own_ops: &[(Txid, Vec<U256>)],
    now: u64,
) -> bool {
    if now.saturating_sub(entry.created_at) < UNMINED_GRACE_SECS {
        return false;
    }
    // On-chain under this very txid: mined, the proof is due.
    if own_ops.iter().any(|(txid, _)| *txid == entry.txid) {
        return false;
    }
    // Only judge entries of an account we track: its notes are the evidence.
    let Some(account) = accounts
        .iter()
        .find(|a| a.spending_pubkey == entry.spending_pubkey)
    else {
        return false;
    };
    // A mined operation nullifies all its inputs: one still unspent means it was not sent.
    let an_input_is_unspent = entry.in_notes.iter().any(|input| {
        account
            .unspent
            .iter()
            .any(|n| n.tree_number == input.tree_number && n.leaf_index == input.leaf_index)
    });
    if an_input_is_unspent {
        return true;
    }
    // All inputs are spent, but not by this operation: another one took them (typically the
    // retry after a relayer that did not answer), so this one can never be mined. Requires the
    // spending operation to be known, otherwise the txid indexer may just be behind.
    entry.in_notes.iter().any(|input| {
        own_ops
            .iter()
            .any(|(txid, nullifiers)| *txid != entry.txid && nullifiers.contains(&input.nullifier))
    })
}

/// Rebuilds the pending entry of `op` if `account` owns every input and every
/// output is known (received, or sent and decrypted as sender).
fn recovery_entry(
    account: &RecoveryAccount,
    txid: Txid,
    op: &Operation,
    list_keys: &[ListKey],
) -> Option<PendingPoiEntry> {
    // Inputs, in on-chain nullifier order: the txid commits to that order.
    let in_notes = op
        .nullifiers
        .iter()
        .map(|nullifier| {
            account
                .spent
                .iter()
                .find(|n| n.tree_number == op.utxo_tree_in && n.nullifier == *nullifier)
                .cloned()
        })
        .collect::<Option<Vec<_>>>()?;
    let token_hash = in_notes.first()?.asset.hash();

    // An unshield is the last commitment hash and has no UTXO leaf.
    let leaf_outputs = op
        .commitment_hashes
        .len()
        .checked_sub(usize::from(op.has_unshield))?;
    let mut out_npks = Vec::with_capacity(leaf_outputs);
    let mut out_values = Vec::with_capacity(leaf_outputs);
    for (i, hash) in op.commitment_hashes.iter().take(leaf_outputs).enumerate() {
        let leaf = op.utxo_out_start_index.checked_add(i as u32)?;
        let at = |t: u32, l: u32| t == op.utxo_tree_out && l == leaf;
        let received = account
            .unspent
            .iter()
            .chain(account.spent.iter())
            .find(|n| at(n.tree_number, n.leaf_index) && <U256 as From<_>>::from(n.hash) == *hash)
            .map(|n| (n.note_public_key, U256::from(n.value)));
        let sent = || {
            account
                .sent
                .iter()
                .find(|n| at(n.tree_number, n.leaf_index) && n.hash == *hash)
                .map(|n| (n.note_public_key, U256::from(n.value)))
        };
        let (npk, value) = received.or_else(sent)?;
        out_npks.push(npk);
        out_values.push(value);
    }

    Some(PendingPoiEntry {
        txid,
        spending_pubkey: account.spending_pubkey,
        nullifying_key: account.nullifying_key,
        utxo_tree_in: op.utxo_tree_in,
        bound_params_hash: op.bound_params_hash,
        in_notes,
        out_commitments: op.commitment_hashes.clone(),
        out_npks,
        out_values,
        token_hash,
        has_unshield: op.has_unshield,
        list_keys: list_keys.to_vec(),
        created_at: now_secs(),
    })
}

fn blinded_commitments(
    entry: &PendingPoiEntry,
    utxo_tree_number: u32,
    utxo_leaf_index: u32,
) -> Vec<BlindedCommitment> {
    let mut blinded_commitments_out = Vec::new();
    for (i, (commitment, npk)) in entry
        .out_commitments
        .iter()
        .zip(entry.out_npks.iter())
        .enumerate()
    {
        let blinded_commitment = utxo::blinded_commitment(
            commitment.clone(),
            npk.clone(),
            utxo_tree_number,
            utxo_leaf_index + i as u32,
        )
        .into();
        blinded_commitments_out.push(blinded_commitment);
    }
    blinded_commitments_out
}


#[cfg(test)]
mod prune_tests {
    use alloy::primitives::address;
    use rand::random;

    use super::*;
    use crate::{
        account::signer::{PrivateKeySigner, RailgunSigner},
        caip::AssetId,
        poi::types::BlindedCommitmentType,
    };

    #[test]
    fn an_entry_with_an_unspent_input_was_never_mined() {
        let signer = PrivateKeySigner::new_evm(random(), random(), 1);
        let asset = AssetId::erc20(address!("0xDEADDEADDEADDEADDEADDEADDEADDEADDEADDEAD"));
        let note = |leaf| {
            UtxoNote::new(0, leaf, signer.clone(), asset, 10, random(), "", BlindedCommitmentType::Shield)
        };
        let entry = |created_at| PendingPoiEntry {
            txid: Txid::new(&[], &[], U256::ZERO),
            spending_pubkey: signer.spending_public_key(),
            nullifying_key: signer.viewing_key().nullifying_key(),
            utxo_tree_in: 0,
            bound_params_hash: U256::ZERO,
            in_notes: vec![note(4), note(5)],
            out_commitments: vec![],
            out_npks: vec![],
            out_values: vec![],
            token_hash: U256::ZERO,
            has_unshield: false,
            list_keys: vec![],
            created_at,
        };
        let account = |unspent: Vec<UtxoNote>| RecoveryAccount {
            spending_pubkey: signer.spending_public_key(),
            nullifying_key: signer.viewing_key().nullifying_key(),
            unspent,
            spent: vec![],
            sent: vec![],
        };
        let now = 10_000_000;
        let old = now - UNMINED_GRACE_SECS - 1;

        // One input still unspent, long after the proof: never sent.
        assert!(never_mined(&entry(old), &[account(vec![note(5), note(9)])], &[], now));
        // Entries written before the timestamp existed count as old.
        assert!(never_mined(&entry(0), &[account(vec![note(4)])], &[], now));
        // Both inputs gone and the spender unknown yet (txid indexer behind): wait.
        assert!(!never_mined(&entry(old), &[account(vec![note(9)])], &[], now));
        // Both inputs gone, spent by this very operation: mined, the proof is due.
        let e = entry(old);
        let nullifiers: Vec<U256> = e.in_notes.iter().map(|n| n.nullifier).collect();
        let mined = vec![(e.txid, nullifiers.clone())];
        assert!(!never_mined(&e, &[account(vec![note(9)])], &mined, now));
        // Both inputs gone, spent by another operation (the retry): this one is dead.
        let retry = vec![(Txid::new(&nullifiers, &[U256::from(1u8)], U256::ZERO), nullifiers)];
        assert!(never_mined(&e, &[account(vec![note(9)])], &retry, now));
        // Just proved, maybe in a relayer's hands: wait.
        assert!(!never_mined(&entry(now - 60), &[account(vec![note(4), note(5)])], &[], now));
        // Not one of our accounts: no evidence, keep.
        let stranger = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = RecoveryAccount {
            spending_pubkey: stranger.spending_public_key(),
            nullifying_key: stranger.viewing_key().nullifying_key(),
            unspent: vec![note(4)],
            spent: vec![],
            sent: vec![],
        };
        assert!(!never_mined(&entry(old), &[other], &[], now));
    }
}
