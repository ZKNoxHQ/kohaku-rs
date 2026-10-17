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
    merkle_tree::{MerkleProof, TOTAL_LEAVES, TxidMerkleTree, UtxoTreeIndex},
    note::utxo::{self, UtxoNote},
    poi::{
        client::{PoiClient, PoiClientError, PoiNodeClient},
        note::PoiNote,
        recovery::RecoveryAccount,
        types::{BlindedCommitment, BlindedCommitmentType, ListKey, PoiStatus, TransactProofData},
    },
    railgun_database::{DatabaseError, RailgunDB},
    transact::proved_transaction::ProvedOperation,
};

pub struct PoiProvider {
    inner: PoiProviderState,
    db: Store,
    poi_client: PoiClient,
    txid_indexer: TxidIndexer,
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
        })
    }

    pub async fn sync_to(
        &mut self,
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

        let recovered = self.recover_missing(accounts).await;
        if recovered > 0 {
            info!("Queued {recovered} past operation(s) for POI proof generation");
        }

        self.save().await?;
        Ok(())
    }

    /// Best-effort processing is separate from synchronization so callers can
    /// authorize proof generation and submission explicitly.
    pub async fn process_pending(
        &mut self,
        prover: &Groth16Prover,
    ) -> Result<(), PoiProviderError> {
        self.submit_pending(prover).await;
        self.save().await?;
        Ok(())
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
    /// operation with another txid (the retry) can never be mined at all. Such an entry can
    /// never be submitted (its txid is in no tree) and would be retried at every sync. The POI
    /// node never saw it: nothing is sent before the txid is validated, so there is nothing to
    /// clean up remotely. If the transaction does land later, `recover_missing` rebuilds the
    /// entry from chain data.
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
            UtxoNote::new(
                0,
                leaf,
                signer.clone(),
                asset,
                10,
                random(),
                "",
                BlindedCommitmentType::Shield,
            )
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
        assert!(never_mined(
            &entry(old),
            &[account(vec![note(5), note(9)])],
            &[],
            now
        ));
        // Entries written before the timestamp existed count as old.
        assert!(never_mined(&entry(0), &[account(vec![note(4)])], &[], now));
        // Both inputs gone and the spender unknown yet (txid indexer behind): wait.
        assert!(!never_mined(
            &entry(old),
            &[account(vec![note(9)])],
            &[],
            now
        ));
        // Both inputs gone, spent by this very operation: mined, the proof is due.
        let e = entry(old);
        let nullifiers: Vec<U256> = e.in_notes.iter().map(|n| n.nullifier).collect();
        let mined = vec![(e.txid, nullifiers.clone())];
        assert!(!never_mined(&e, &[account(vec![note(9)])], &mined, now));
        // Both inputs gone, spent by another operation (the retry): this one is dead.
        let retry = vec![(
            Txid::new(&nullifiers, &[U256::from(1u8)], U256::ZERO),
            nullifiers,
        )];
        assert!(never_mined(&e, &[account(vec![note(9)])], &retry, now));
        // Just proved, maybe in a relayer's hands: wait.
        assert!(!never_mined(
            &entry(now - 60),
            &[account(vec![note(4), note(5)])],
            &[],
            now
        ));
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

#[cfg(all(test, native))]
mod submission_control_tests {
    use super::*;
    use crate::{
        account::signer::{PrivateKeySigner, RailgunSigner},
        caip::AssetId,
        crypto::keys::{ByteKey, SpendingKey, ViewingKey},
        indexer::syncer::{SyncEvent, SyncerError, UtxoSyncer},
    };
    use alloy::primitives::address;
    use std::sync::Mutex;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
        time::{Duration, timeout},
    };

    const FIXTURE_CHAIN_ID: u64 = 11_155_111;

    struct FixtureIndexer(Operation);
    #[async_trait::async_trait]
    impl TxidSyncer for FixtureIndexer {
        async fn latest_block(&self) -> Result<u64, SyncerError> {
            Ok(1)
        }
        async fn sync(&self, from: u64, to: u64) -> Result<Vec<Operation>, SyncerError> {
            Ok(if from <= to {
                vec![self.0.clone()]
            } else {
                vec![]
            })
        }
    }

    struct EmptyUtxo;
    #[async_trait::async_trait]
    impl UtxoSyncer for EmptyUtxo {
        async fn latest_block(&self) -> Result<u64, SyncerError> {
            Ok(1)
        }
        async fn sync(&self, _: u64, _: u64) -> Result<Vec<SyncEvent>, SyncerError> {
            Ok(vec![])
        }
    }

    // The fixture serves only index/root reads. A membership request is recorded
    // and rejected before proving, so no artifact acquisition or proof submission can occur.
    async fn service() -> (
        String,
        Arc<Mutex<Vec<String>>>,
        oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let methods = Arc::new(Mutex::new(Vec::new()));
        let recorded = methods.clone();
        let (stop, mut stopping) = oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = tokio::select! {
                    _ = &mut stopping => break,
                    result = listener.accept() => result.unwrap(),
                };
                let mut request = Vec::new();
                let mut buffer = [0; 1024];
                let value: serde_json::Value = loop {
                    let n = timeout(Duration::from_secs(5), socket.read(&mut buffer))
                        .await
                        .unwrap()
                        .unwrap();
                    assert!(n > 0 && request.len() + n <= 4096);
                    request.extend_from_slice(&buffer[..n]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&request[..end]).unwrap();
                        let length: usize = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse().unwrap())
                            })
                            .unwrap();
                        if request.len() >= end + 4 + length {
                            break serde_json::from_slice(&request[end + 4..]).unwrap();
                        }
                    }
                };
                let method = value["method"].as_str().unwrap();
                assert_eq!(value["params"]["chainID"], FIXTURE_CHAIN_ID.to_string());
                recorded.lock().unwrap().push(method.to_owned());
                let mut body = serde_json::json!({"jsonrpc": "2.0", "id": value["id"]});
                match method {
                    "ppoi_validated_txid" => {
                        body["result"] = serde_json::json!({"validatedTxidIndex": 0});
                    }
                    "ppoi_validate_txid_merkleroot" => body["result"] = serde_json::json!(true),
                    _ => {
                        body["error"] = serde_json::json!({"code": -32602, "message": "Fixture refuses membership and submission"});
                    }
                }
                let body = body.to_string();
                let wire = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                timeout(Duration::from_secs(5), socket.write_all(wire.as_bytes()))
                    .await
                    .unwrap()
                    .unwrap();
            }
        });
        (url, methods, stop, task)
    }

    fn pending_fixture() -> (Operation, PendingPoiEntry) {
        let operation = Operation {
            block_number: 1,
            nullifiers: vec![U256::from(1)],
            commitment_hashes: vec![U256::from(2)],
            bound_params_hash: U256::from(3),
            utxo_tree_in: 0,
            utxo_tree_out: 0,
            utxo_out_start_index: 0,
            has_unshield: false,
        };
        let txid = Txid::new(
            &operation.nullifiers,
            &operation.commitment_hashes,
            operation.bound_params_hash,
        );
        let signer = PrivateKeySigner::new_evm(
            SpendingKey::from_bytes([1; 32]),
            ViewingKey::from_bytes([2; 32]),
            FIXTURE_CHAIN_ID,
        );
        let note = UtxoNote::new(
            0,
            0,
            signer.clone(),
            AssetId::erc20(address!("0xDEADDEADDEADDEADDEADDEADDEADDEADDEADDEAD")),
            10,
            [5; 16],
            "public fixture",
            BlindedCommitmentType::Shield,
        );
        let entry = PendingPoiEntry {
            txid,
            spending_pubkey: signer.spending_public_key(),
            nullifying_key: signer.viewing_key().nullifying_key(),
            utxo_tree_in: 0,
            bound_params_hash: U256::from(3),
            in_notes: vec![note],
            out_commitments: vec![U256::from(2)],
            out_npks: vec![U256::from(11)],
            out_values: vec![U256::from(10)],
            token_hash: U256::ZERO,
            has_unshield: false,
            list_keys: vec!["public-fixture-list".into()],
            created_at: 0,
        };
        (operation, entry)
    }

    #[tokio::test]
    async fn sync_retains_pending_work_until_explicit_processing() {
        let (url, methods, stop, task) = service().await;
        let db = Store::create();
        let (operation, entry) = pending_fixture();
        let txid = entry.txid;
        let mut provider = PoiProvider::new(
            FIXTURE_CHAIN_ID,
            db.clone(),
            Arc::new(FixtureIndexer(operation)),
            url.clone(),
            vec!["public-fixture-list".into()],
        )
        .await
        .unwrap();
        provider.inner.pending.push(entry);

        let rpc = Arc::new(kohaku_eip_1193::alloy::Alloy::new(
            alloy::providers::ProviderBuilder::new().connect_http(url.parse().unwrap()),
        ));
        let chain = crate::chain_config::ChainConfig::sepolia();
        let utxo = crate::indexer::utxo_indexer::UtxoIndexer::new(
            db.clone(),
            Arc::new(EmptyUtxo),
            Arc::new(crate::merkle_tree::SmartWalletUtxoVerifier::new(
                chain.railgun_smart_wallet,
                rpc.clone(),
            )),
        )
        .await
        .unwrap();
        let mut runtime = crate::provider::RailgunProvider::new(
            chain,
            rpc,
            utxo,
            Groth16Prover::new(),
            Some(provider),
        )
        .await
        .unwrap();
        timeout(
            Duration::from_secs(10),
            runtime.sync_to_without_poi_submission(1),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            *methods.lock().unwrap(),
            vec!["ppoi_validated_txid", "ppoi_validate_txid_merkleroot"]
        );
        assert_eq!(db.get_poi_provider().await.unwrap().pending.len(), 1);
        assert_eq!(db.get_poi_provider().await.unwrap().pending[0].txid, txid);

        // Explicit processing reaches membership. The fixture refuses it before
        // any prover/artifact request, and the existing best-effort semantics
        // keep the entry pending rather than treating Ok as acceptance.
        timeout(Duration::from_secs(10), runtime.process_pending_poi())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            *methods.lock().unwrap(),
            vec![
                "ppoi_validated_txid",
                "ppoi_validate_txid_merkleroot",
                "ppoi_merkle_proofs"
            ]
        );
        assert_eq!(db.get_poi_provider().await.unwrap().pending.len(), 1);
        // Existing automatic convenience sync still processes the queue.
        timeout(Duration::from_secs(10), runtime.sync_to(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            *methods.lock().unwrap(),
            vec![
                "ppoi_validated_txid",
                "ppoi_validate_txid_merkleroot",
                "ppoi_merkle_proofs",
                "ppoi_validated_txid",
                "ppoi_merkle_proofs",
            ]
        );
        assert_eq!(db.get_poi_provider().await.unwrap().pending.len(), 1);
        stop.send(()).unwrap();
        task.await.unwrap();
    }
}
