use std::{collections::HashMap, sync::Arc};

use kohaku_kv_store::Store;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, warn};

use crate::{
    crypto::railgun_txid::Txid,
    indexer::syncer::{Operation, SyncerError, TxidSyncer},
    merkle_tree::{TOTAL_LEAVES, TxidLeafHash, TxidMerkleTree, UtxoTreeIndex},
    poi::client::{PoiClientError, PoiNodeClient},
    railgun_database::{DatabaseError, RailgunDB, write_txid_snapshot},
};

pub struct TxidIndexer {
    trees: HashMap<u32, TxidMerkleTree>,
    inner: TxidIndexerState,
    /// Nullifiers of the registered accounts. Operations spending one of them are
    /// kept in full in `inner.own_ops`, the others are reduced to a txid leaf as before.
    watched: std::collections::HashSet<U256>,

    db: Store,
    txid_syncer: Arc<dyn TxidSyncer>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub(crate) struct TxidIndexerState {
    pub synced_block: u64,
    pub trees: Vec<u32>,
    pub pending: Vec<Operation>,
    pub txid_to_utxo_position: HashMap<Txid, (u32, u32)>,
    pub txid_to_txid_position: HashMap<Txid, (u32, u32)>,
    /// Operations that spend a watched nullifier.
    #[serde(default)]
    pub own_ops: HashMap<Txid, Operation>,
}

#[derive(Debug, Error)]
pub enum TxidIndexerError {
    #[error("Syncer error: {0}")]
    SyncerError(#[from] SyncerError),
    #[error("POI client error: {0}")]
    PoiClient(#[from] PoiClientError),
    #[error("TXID tree root mismatch for tree {tree_number}")]
    RootMismatch { tree_number: u32 },
    #[error("Database error: {0}")]
    DatabaseError(#[from] DatabaseError),
}

impl TxidIndexer {
    pub async fn new(
        db: Store,
        txid_syncer: Arc<dyn TxidSyncer>,
    ) -> Result<Self, TxidIndexerError> {
        let inner = db.get_txid_indexer().await?;

        let mut txid_trees = HashMap::new();
        for number in inner.trees.clone() {
            let tree_state = db.get_txid_tree(number).await?;
            if let Some(tree_state) = tree_state {
                txid_trees.insert(number, TxidMerkleTree::from_state(tree_state));
            }
        }

        info!(
            "Loaded Txid indexer state: synced_block={}, trees={:?}, pending_ops={}",
            inner.synced_block,
            inner.trees,
            inner.pending.len()
        );
        Ok(TxidIndexer {
            inner,
            trees: txid_trees,
            watched: Default::default(),
            db,
            txid_syncer,
        })
    }

    /// Sets the nullifiers whose operations must be retained.
    pub fn watch_nullifiers(&mut self, nullifiers: std::collections::HashSet<U256>) {
        self.watched = nullifiers;
    }

    /// Retained operations of the registered accounts.
    pub fn own_ops(&self) -> impl Iterator<Item = (&Txid, &Operation)> {
        self.inner.own_ops.iter()
    }

    fn retain_own(&mut self, op: &Operation) {
        if op.nullifiers.iter().any(|n| self.watched.contains(n)) {
            let txid = Txid::new(&op.nullifiers, &op.commitment_hashes, op.bound_params_hash);
            self.inner.own_ops.entry(txid).or_insert_with(|| op.clone());
        }
    }

    pub fn tree(&self, tree_number: u32) -> Option<&TxidMerkleTree> {
        self.trees.get(&tree_number)
    }

    pub fn txid_position(&self, txid: &Txid) -> Option<(u32, u32)> {
        self.inner.txid_to_txid_position.get(txid).cloned()
    }

    pub fn utxo_position(&self, txid: &Txid) -> Option<(u32, u32)> {
        self.inner.txid_to_utxo_position.get(txid).cloned()
    }

    #[tracing::instrument(name = "txid_sync", skip_all)]
    pub async fn sync_to(
        &mut self,
        to_block: u64,
        poi_client: &impl PoiNodeClient,
    ) -> Result<(), TxidIndexerError> {
        let from_block = self.inner.synced_block + 1;

        let syncer = self.txid_syncer.clone();
        let latest_block = syncer.latest_block().await?;
        let to_block = to_block.min(latest_block);
        // A lagging source must not rewind the checkpoint or receive an inverted
        // range. Already-fetched pending operations can still become validated.
        let ops = if from_block > to_block {
            Vec::new()
        } else {
            syncer.sync(from_block, to_block).await?
        };
        info!("Fetched {} operations from syncer", ops.len());
        // Validation and saving can fail or be cancelled. Keep the live indexer
        // unchanged until one fully validated snapshot is committed.
        let mut staged = Self {
            trees: self
                .trees
                .iter()
                .map(|(number, tree)| (*number, TxidMerkleTree::from_state(tree.state())))
                .collect(),
            inner: self.inner.clone(),
            watched: self.watched.clone(),
            db: self.db.clone(),
            txid_syncer: self.txid_syncer.clone(),
        };
        // Operations fetched by an earlier sync and still waiting for validation.
        for op in staged.inner.pending.clone() {
            staged.retain_own(&op);
        }
        for op in ops {
            staged.retain_own(&op);
            staged.inner.pending.push(op);
        }
        staged.inner.synced_block = self.inner.synced_block.max(to_block);

        staged.update(poi_client).await?;
        staged.save().await?;
        *self = staged;
        Ok(())
    }

    #[tracing::instrument(name = "txid_update", skip_all)]
    async fn update(&mut self, poi_client: &impl PoiNodeClient) -> Result<(), TxidIndexerError> {
        let validated = poi_client.validated_txid().await?;
        info!(
            "Latest validated txid index from POI: tree {}, leaf {}",
            validated.tree(),
            validated.leaf_index()
        );

        let current_total = self.trees.values().map(|t| t.leaves_len() as u32).sum();
        let target_total = validated.tree() * TOTAL_LEAVES + validated.leaf_index() + 1;

        let to_drain = target_total.saturating_sub(current_total) as usize;
        if to_drain == 0 {
            return Ok(());
        }

        let drain_count = to_drain.min(self.inner.pending.len());
        let drained: Vec<_> = self.inner.pending.drain(..drain_count).collect();

        let mut total = current_total;
        let mut tree_leaves: HashMap<u32, Vec<(u32, TxidLeafHash)>> = HashMap::new();
        for op in drained {
            let txid = Txid::new(&op.nullifiers, &op.commitment_hashes, op.bound_params_hash);

            if let Some(&existing_pos) = self.inner.txid_to_txid_position.get(&txid) {
                warn!(
                    "Skipping duplicate operation: txid {:?} already at tree {}, leaf {}",
                    txid, existing_pos.0, existing_pos.1
                );
                continue;
            }

            let included = UtxoTreeIndex::included(op.utxo_tree_out, op.utxo_out_start_index);
            let leaf = TxidLeafHash::new(txid, op.utxo_tree_in, included);

            let tree_number = total / TOTAL_LEAVES;
            let leaf_index = total % TOTAL_LEAVES;

            tree_leaves
                .entry(tree_number)
                .or_default()
                .push((leaf_index as u32, leaf));

            self.inner
                .txid_to_txid_position
                .insert(txid, (tree_number, leaf_index as u32));
            self.inner
                .txid_to_utxo_position
                .insert(txid, (op.utxo_tree_out, op.utxo_out_start_index));

            if total % 10000 == 0 {
                info!(
                    "Draining operation {}/{}",
                    total - current_total,
                    target_total
                );
            }
            total += 1;
        }

        info!("Inserting leaves into TXID trees");
        for (tree_number, mut leaves) in tree_leaves {
            leaves.sort_by_key(|(idx, _)| *idx);
            let start = leaves[0].0;
            let hashes: Vec<_> = leaves.into_iter().map(|(_, hash)| hash).collect();
            self.trees
                .entry(tree_number)
                .or_insert_with(|| TxidMerkleTree::new(tree_number))
                .insert_leaves(&hashes, start as usize);
        }
        info!("Drained {} operations", drain_count);

        info!("Validating TXID trees");
        for (tree_number, tree) in self.trees.iter() {
            let index = tree.leaves_len() as u32 - 1;
            let merkleroot = tree.root();
            let validated = poi_client
                .validate_txid_merkleroot(*tree_number, index, merkleroot)
                .await?;

            if !validated {
                return Err(TxidIndexerError::RootMismatch {
                    tree_number: *tree_number,
                });
            }

            info!(
                "Validated TXID tree up to tree {}, leaf {} (total {})",
                tree_number,
                index,
                total - 1
            );
        }

        Ok(())
    }

    /// Persist trees, mappings, pending operations and checkpoint as one atomic snapshot.
    /// Custom backends must honor `Store::put_batch`'s all-or-nothing contract.
    async fn save(&self) -> Result<(), DatabaseError> {
        let state = TxidIndexerState {
            synced_block: self.inner.synced_block,
            trees: self.trees.keys().cloned().collect(),
            pending: self.inner.pending.clone(),
            txid_to_utxo_position: self.inner.txid_to_utxo_position.clone(),
            txid_to_txid_position: self.inner.txid_to_txid_position.clone(),
            own_ops: self.inner.own_ops.clone(),
        };
        let trees: Vec<_> = self
            .trees
            .iter()
            .map(|(number, tree)| (*number, tree.state()))
            .collect();
        write_txid_snapshot(&self.db, &state, &trees).await?;

        Ok(())
    }
}

#[cfg(all(test, native))]
mod snapshot_tests {
    use super::*;
    use crate::{
        merkle_tree::{MerkleProof, MerkleRoot},
        poi::types::{
            BlindedCommitment, BlindedCommitmentType, ListKey, PoiStatus, TransactProofData,
            ValidatedRailgunTxidStatus,
        },
    };
    use kohaku_kv_store::{
        backend::{KvStoreBackend, StoreError},
        memory::MemoryStore,
    };
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    #[derive(Clone)]
    struct FailCheckpoint {
        inner: Arc<MemoryStore>,
        fail: Arc<AtomicBool>,
        after_commit: Arc<AtomicBool>,
        committed: Arc<Mutex<Option<Arc<tokio::sync::Notify>>>>,
    }
    #[async_trait::async_trait]
    impl KvStoreBackend for FailCheckpoint {
        async fn get_batch(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
            self.inner.get_batch(keys).await
        }
        async fn put_batch(&self, items: &[(&[u8], &[u8])]) -> Result<(), StoreError> {
            if self.fail.load(Ordering::SeqCst)
                && items.iter().any(|(key, _)| *key == b"txid_indexer")
            {
                if self.after_commit.load(Ordering::SeqCst) {
                    self.inner.put_batch(items).await?;
                }
                return Err(StoreError::from(Box::new(std::io::Error::other(
                    "injected checkpoint write failure",
                ))
                    as Box<dyn std::error::Error + Send + Sync>));
            }
            self.inner.put_batch(items).await?;
            let committed = self.committed.lock().unwrap().clone();
            if let Some(committed) = committed
                && items.iter().any(|(key, _)| *key == b"txid_indexer")
            {
                committed.notify_one();
                std::future::pending::<()>().await;
            }
            Ok(())
        }
        async fn delete_batch(&self, keys: &[&[u8]]) -> Result<(), StoreError> {
            self.inner.delete_batch(keys).await
        }
    }

    struct TwoOperations;
    fn op(block: u64, output: u32) -> Operation {
        Operation {
            block_number: block,
            nullifiers: vec![U256::from(block)],
            commitment_hashes: vec![U256::from(block + 1)],
            bound_params_hash: U256::from(7),
            utxo_tree_in: 0,
            utxo_tree_out: 0,
            utxo_out_start_index: output,
            has_unshield: false,
        }
    }
    #[async_trait::async_trait]
    impl TxidSyncer for TwoOperations {
        async fn latest_block(&self) -> Result<u64, SyncerError> {
            Ok(20)
        }
        async fn sync(&self, from: u64, to: u64) -> Result<Vec<Operation>, SyncerError> {
            Ok([op(10, 0), op(20, 1)]
                .into_iter()
                .filter(|operation| (from..=to).contains(&operation.block_number))
                .collect())
        }
    }

    struct Node {
        index: Mutex<u32>,
        verdict: Mutex<Result<bool, &'static str>>,
        reads: AtomicUsize,
    }
    impl Node {
        fn new(index: u32) -> Self {
            Self {
                index: Mutex::new(index),
                verdict: Mutex::new(Ok(true)),
                reads: AtomicUsize::new(0),
            }
        }
    }
    #[async_trait::async_trait]
    impl PoiNodeClient for Node {
        fn list_keys(&self) -> Vec<ListKey> {
            vec![]
        }
        async fn poi_status(
            &self,
            _: &ListKey,
            _: BlindedCommitment,
            _: BlindedCommitmentType,
        ) -> Result<PoiStatus, PoiClientError> {
            panic!("no owned reads")
        }
        async fn merkle_proof(
            &self,
            _: &ListKey,
            _: BlindedCommitment,
        ) -> Result<MerkleProof, PoiClientError> {
            panic!("no membership reads")
        }
        async fn submit_proof(
            &self,
            _: HashMap<ListKey, TransactProofData>,
        ) -> Result<(), PoiClientError> {
            panic!("no proof submission")
        }
        async fn validated_txid(&self) -> Result<ValidatedRailgunTxidStatus, PoiClientError> {
            Ok(ValidatedRailgunTxidStatus {
                index: *self.index.lock().unwrap(),
            })
        }
        async fn validate_txid_merkleroot(
            &self,
            _: u32,
            _: u32,
            _: MerkleRoot,
        ) -> Result<bool, PoiClientError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.verdict
                .lock()
                .unwrap()
                .map_err(|message| PoiClientError::UnexpectedResponse(message.to_owned()))
        }
    }

    #[tokio::test]
    async fn a_failed_checkpoint_write_cannot_split_trees_from_position_maps() {
        let backend = FailCheckpoint {
            inner: Arc::new(MemoryStore::new()),
            fail: Arc::new(AtomicBool::new(false)),
            after_commit: Arc::new(AtomicBool::new(false)),
            committed: Arc::new(Mutex::new(None)),
        };
        let store = Store::new(backend.clone());
        let node = Node::new(0);
        let mut first = TxidIndexer::new(store.clone(), Arc::new(TwoOperations))
            .await
            .unwrap();
        first.sync_to(10, &node).await.unwrap();
        let before = store.get(b"txid_indexer").await.unwrap();

        backend.fail.store(true, Ordering::SeqCst);
        *node.index.lock().unwrap() = 1;
        assert!(matches!(
            first.sync_to(20, &node).await,
            Err(TxidIndexerError::DatabaseError(_))
        ));
        assert_eq!(store.get(b"txid_indexer").await.unwrap(), before);
        // A tree written ahead of the position map makes the restored indexer
        // count an unindexed operation as already validated and skip its mapping.

        drop(first);
        backend.fail.store(false, Ordering::SeqCst);
        let mut restored = TxidIndexer::new(store.clone(), Arc::new(TwoOperations))
            .await
            .unwrap();
        restored.sync_to(20, &node).await.unwrap();
        assert_eq!(restored.tree(0).unwrap().leaves_len(), 2);
        for (operation, position) in [(op(10, 0), 0), (op(20, 1), 1)] {
            let id = Txid::new(
                &operation.nullifiers,
                &operation.commitment_hashes,
                operation.bound_params_hash,
            );
            assert_eq!(restored.txid_position(&id), Some((0, position)));
            assert_eq!(restored.utxo_position(&id), Some((0, position)));
        }
        assert_eq!(store.get_txid_indexer().await.unwrap().synced_block, 20);
    }

    #[tokio::test]
    async fn a_lost_save_reply_restores_the_complete_committed_snapshot() {
        let backend = FailCheckpoint {
            inner: Arc::new(MemoryStore::new()),
            fail: Arc::new(AtomicBool::new(true)),
            after_commit: Arc::new(AtomicBool::new(true)),
            committed: Arc::new(Mutex::new(None)),
        };
        let store = Store::new(backend.clone());
        let node = Node::new(1);
        let mut writer = TxidIndexer::new(store.clone(), Arc::new(TwoOperations))
            .await
            .unwrap();
        assert!(writer.sync_to(20, &node).await.is_err());
        drop(writer);
        let restored = TxidIndexer::new(store.clone(), Arc::new(TwoOperations))
            .await
            .unwrap();
        assert_eq!(store.get_txid_indexer().await.unwrap().synced_block, 20);
        assert_eq!(restored.tree(0).unwrap().leaves_len(), 2);
        let last = op(20, 1);
        let id = Txid::new(
            &last.nullifiers,
            &last.commitment_hashes,
            last.bound_params_hash,
        );
        assert_eq!(restored.txid_position(&id), Some((0, 1)));
        assert_eq!(restored.utxo_position(&id), Some((0, 1)));
    }

    #[tokio::test]
    async fn cancellation_after_the_atomic_commit_preserves_every_mapping() {
        let committed = Arc::new(tokio::sync::Notify::new());
        let backend = FailCheckpoint {
            inner: Arc::new(MemoryStore::new()),
            fail: Arc::new(AtomicBool::new(false)),
            after_commit: Arc::new(AtomicBool::new(false)),
            committed: Arc::new(Mutex::new(Some(committed.clone()))),
        };
        let store = Store::new(backend.clone());
        let node = Node::new(1);
        let mut writer = TxidIndexer::new(store.clone(), Arc::new(TwoOperations))
            .await
            .unwrap();
        {
            let future = writer.sync_to(20, &node);
            tokio::pin!(future);
            tokio::select! {
                result = &mut future => panic!("unexpected completion: {result:?}"),
                result = tokio::time::timeout(std::time::Duration::from_secs(5), committed.notified()) => result.unwrap(),
            }
        }
        drop(writer);
        let restored = TxidIndexer::new(store.clone(), Arc::new(TwoOperations))
            .await
            .unwrap();
        assert_eq!(store.get_txid_indexer().await.unwrap().synced_block, 20);
        assert_eq!(restored.tree(0).unwrap().leaves_len(), 2);
        let last = op(20, 1);
        let id = Txid::new(
            &last.nullifiers,
            &last.commitment_hashes,
            last.bound_params_hash,
        );
        assert_eq!(restored.txid_position(&id), Some((0, 1)));
        assert_eq!(restored.utxo_position(&id), Some((0, 1)));
    }

    #[tokio::test]
    async fn retry_on_the_same_instance_cannot_skip_failed_root_validation() {
        let store = Store::create();
        let node = Node::new(1);
        let mut indexer = TxidIndexer::new(store.clone(), Arc::new(TwoOperations))
            .await
            .unwrap();
        *node.verdict.lock().unwrap() = Err("injected root outage");
        assert!(matches!(
            indexer.sync_to(20, &node).await,
            Err(TxidIndexerError::PoiClient(_))
        ));
        assert!(indexer.tree(0).is_none());
        assert_eq!(indexer.inner.synced_block, 0);
        *node.verdict.lock().unwrap() = Ok(false);
        assert!(matches!(
            indexer.sync_to(20, &node).await,
            Err(TxidIndexerError::RootMismatch { tree_number: 0 })
        ));
        assert_eq!(node.reads.load(Ordering::SeqCst), 2);
        assert_eq!(store.get_txid_indexer().await.unwrap().synced_block, 0);
        assert!(store.get_txid_tree(0).await.unwrap().is_none());
        *node.verdict.lock().unwrap() = Ok(true);
        indexer.sync_to(20, &node).await.unwrap();
        assert_eq!(node.reads.load(Ordering::SeqCst), 3);
        assert_eq!(indexer.tree(0).unwrap().leaves_len(), 2);
        assert_eq!(store.get_txid_indexer().await.unwrap().synced_block, 20);
    }

    #[tokio::test]
    async fn an_older_target_cannot_regress_the_checkpoint() {
        let store = Store::create();
        let node = Node::new(1);
        let mut indexer = TxidIndexer::new(store.clone(), Arc::new(TwoOperations))
            .await
            .unwrap();
        indexer.sync_to(20, &node).await.unwrap();
        let before = store.get(b"txid_indexer").await.unwrap();
        indexer.sync_to(10, &node).await.unwrap();
        assert_eq!(indexer.inner.synced_block, 20);
        assert_eq!(store.get(b"txid_indexer").await.unwrap(), before);
        assert_eq!(node.reads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_older_target_still_processes_previously_fetched_pending_operations() {
        let store = Store::create();
        let node = Node::new(0);
        let mut indexer = TxidIndexer::new(store.clone(), Arc::new(TwoOperations))
            .await
            .unwrap();
        indexer.sync_to(20, &node).await.unwrap();
        assert_eq!(indexer.inner.pending.len(), 1);
        *node.index.lock().unwrap() = 1;
        indexer.sync_to(10, &node).await.unwrap();
        assert_eq!(indexer.inner.synced_block, 20);
        assert!(indexer.inner.pending.is_empty());
        assert_eq!(indexer.tree(0).unwrap().leaves_len(), 2);
        assert_eq!(store.get_txid_indexer().await.unwrap().synced_block, 20);
        assert_eq!(node.reads.load(Ordering::SeqCst), 2);
    }
}
