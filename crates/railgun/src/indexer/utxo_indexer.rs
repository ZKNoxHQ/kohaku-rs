use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
    u64,
};

use kohaku_kv_store::Store;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

use crate::{
    account::{address::RailgunAddress, signer::RailgunSigner},
    indexer::{
        indexed_account::IndexedAccount,
        syncer::{self, SyncEvent, SyncerError, UtxoSyncer},
    },
    merkle_tree::{MerkleTreeVerifier, UtxoLeafHash, UtxoMerkleTree},
    note::utxo::{NoteError, UtxoNote},
    railgun_database::{DatabaseError, RailgunDB},
};

/// Utxo indexer that maintains the set of UTXO merkle trees and tracks accounts
/// and account notes / balances.
pub struct UtxoIndexer {
    synced_block: u64,
    pub utxo_trees: BTreeMap<u32, UtxoMerkleTree>,
    accounts: Vec<IndexedAccount>,

    db: Store,
    utxo_syncer: Arc<dyn UtxoSyncer>,
    utxo_verifier: Arc<dyn MerkleTreeVerifier>,
}

#[derive(Serialize, Deserialize, Default)]
pub(crate) struct UtxoIndexerState {
    pub synced_block: u64,
    pub trees: Vec<u32>,
}

#[derive(Debug, Error)]
pub enum UtxoIndexerError {
    #[error("Syncer error: {0}")]
    SyncerError(#[from] SyncerError),
    #[error("Verification error: {0}")]
    VerificationError(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("Note error: {0}")]
    NoteError(#[from] NoteError),
    #[error("Database error: {0}")]
    DatabaseError(#[from] DatabaseError),
    #[error("Timed out waiting for commitments")]
    Timeout,
}

impl UtxoIndexer {
    pub async fn new(
        db: Store,
        utxo_syncer: Arc<dyn UtxoSyncer>,
        utxo_verifier: Arc<dyn MerkleTreeVerifier>,
    ) -> Result<Self, UtxoIndexerError> {
        let state = db.get_utxo_indexer().await?;

        let mut utxo_trees = BTreeMap::new();
        for number in state.trees.clone() {
            let tree_state = db.get_utxo_tree(number).await?;
            if let Some(tree_state) = tree_state {
                utxo_trees.insert(number, UtxoMerkleTree::from_state(tree_state));
            }
        }

        info!(
            "Loaded UTXO indexer state: synced_block={}, trees={:?}",
            state.synced_block, state.trees
        );
        Ok(UtxoIndexer {
            synced_block: state.synced_block,
            utxo_trees,
            accounts: vec![],
            db,
            utxo_syncer,
            utxo_verifier,
        })
    }

    /// Returns the latest synced block
    pub fn synced_block(&self) -> u64 {
        let mut min_synced = self.synced_block;
        for account in self.accounts.iter() {
            min_synced = min_synced.min(account.synced_block());
        }
        min_synced
    }

    /// Registers a signer with the indexer. The indexer will track UTXOs for the associated
    /// address.
    pub async fn register(
        &mut self,
        signer: Arc<dyn RailgunSigner>,
    ) -> Result<(), UtxoIndexerError> {
        let addr = signer.address();
        let state = self.db.get_account(&addr).await?;

        let account = IndexedAccount::from_state(signer, state);
        self.accounts.push(account);
        Ok(())
    }

    /// Lists all registered accounts
    /// What the POI provider needs to rebuild proofs for past operations.
    pub fn recovery_accounts(&self) -> Vec<crate::poi::recovery::RecoveryAccount> {
        self.accounts
            .iter()
            .map(|a| {
                let signer = a.signer();
                crate::poi::recovery::RecoveryAccount {
                    spending_pubkey: signer.spending_key().public_key(),
                    nullifying_key: signer.viewing_key().nullifying_key(),
                    unspent: a.unspent(),
                    spent: a.spent(),
                    sent: a.sent(),
                }
            })
            .collect()
    }

    pub fn registered(&self) -> Vec<RailgunAddress> {
        self.accounts.iter().map(|a| a.address()).collect()
    }

    /// Lists all unspent notes for a given address. Returns an empty list if the address is not
    /// registered.
    pub fn unspent(&self, address: RailgunAddress) -> Vec<UtxoNote> {
        for account in self.accounts.iter() {
            if account.address() == address {
                return account.unspent();
            }
        }

        vec![]
    }

    /// Syncs the indexer to a specific block. If the indexer is already synced past that block,
    /// this is a no-op.
    #[tracing::instrument(name = "utxo_sync", skip_all)]
    pub async fn sync_to(&mut self, to_block: u64) -> Result<(), UtxoIndexerError> {
        let from_block = self.synced_block() + 1;

        let latest_block = self.utxo_syncer.latest_block().await?;
        let to_block = to_block.min(latest_block);

        if from_block > to_block {
            return Ok(());
        }

        // Sync
        let events = self.utxo_syncer.sync(from_block, to_block).await?;
        info!("Fetched {} events from syncer", events.len());

        let mut tree_leaves: HashMap<u32, Vec<(u32, UtxoLeafHash)>> = HashMap::new();
        for (i, event) in events.iter().enumerate() {
            if i % 20000 == 0 {
                info!("Processing event {}/{}", i, events.len());
            }
            self.handle_event(&event, &mut tree_leaves)?;
        }

        info!("Inserting leaves into UTXO trees");
        for (tree_number, mut leaves) in tree_leaves {
            leaves.sort_by_key(|(idx, _)| *idx);
            let start = leaves[0].0;
            let hashes: Vec<_> = leaves.into_iter().map(|(_, hash)| hash).collect();

            self.utxo_trees
                .entry(tree_number)
                .or_insert(UtxoMerkleTree::new(tree_number))
                .insert_leaves(&hashes, start as usize);
        }

        // Verify
        info!("Verifying UTXO trees");
        self.verify().await?;

        info!("Synced to block {}", to_block);
        self.synced_block = to_block;
        for account in self.accounts.iter_mut() {
            account.set_synced_block(to_block);
        }

        // Save
        self.save().await?;

        Ok(())
    }

    fn handle_event(
        &mut self,
        event: &SyncEvent,
        tree_leaves: &mut HashMap<u32, Vec<(u32, UtxoLeafHash)>>,
    ) -> Result<(), UtxoIndexerError> {
        match event {
            SyncEvent::Shield(shield, _) => self.handle_shield(shield, tree_leaves)?,
            SyncEvent::Transact(transact, _) => self.handle_transact(transact, tree_leaves)?,
            SyncEvent::Nullified(nullified, ts) => self.handle_nullified(nullified, *ts),
            SyncEvent::Legacy(legacy, _) => self.handle_legacy(legacy, tree_leaves),
        };

        Ok(())
    }

    fn handle_shield(
        &mut self,
        event: &syncer::Shield,
        tree_leaves: &mut HashMap<u32, Vec<(u32, UtxoLeafHash)>>,
    ) -> Result<(), UtxoIndexerError> {
        tree_leaves
            .entry(event.tree_number)
            .or_default()
            .push((event.leaf_index, event.hash()));

        for account in self.accounts.iter_mut() {
            account.handle_shield_event(event)?;
        }

        Ok(())
    }

    fn handle_transact(
        &mut self,
        event: &syncer::Transact,
        tree_leaves: &mut HashMap<u32, Vec<(u32, UtxoLeafHash)>>,
    ) -> Result<(), UtxoIndexerError> {
        tree_leaves
            .entry(event.tree_number)
            .or_default()
            .push((event.leaf_index, event.hash.into()));

        for account in self.accounts.iter_mut() {
            account.handle_transact_event(event)?;
        }

        Ok(())
    }

    fn handle_nullified(&mut self, event: &syncer::Nullified, timestamp: u64) {
        for account in self.accounts.iter_mut() {
            account.handle_nullified_event(event, timestamp);
        }
    }

    fn handle_legacy(
        &mut self,
        _event: &syncer::LegacyCommitment,
        tree_leaves: &mut HashMap<u32, Vec<(u32, UtxoLeafHash)>>,
    ) {
        tree_leaves
            .entry(_event.tree_number)
            .or_default()
            .push((_event.leaf_index, _event.hash.into()));

        // TODO: Forward legacy to accounts
    }

    async fn verify(&self) -> Result<(), UtxoIndexerError> {
        for tree in self.utxo_trees.values() {
            if tree.leaves_len() == 0 {
                continue;
            }

            let known = self
                .utxo_verifier
                .verify_root(tree.number(), tree.leaves_len() as u32 - 1, tree.root())
                .await
                .map_err(|e| UtxoIndexerError::VerificationError(e))?;
            // A root the chain never had means the local tree is missing or has wrong leaves:
            // every proof built on it would revert ("Invalid Merkle Root"). Refuse to go on.
            if !known {
                return Err(UtxoIndexerError::VerificationError(
                    format!(
                        "local UTXO tree {} ({} leaves) has a root the chain never had: the \
                         local database is inconsistent, clear it and sync again",
                        tree.number(),
                        tree.leaves_len()
                    )
                    .into(),
                ));
            }
        }
        Ok(())
    }

    /// Saves the current state of the indexer to the database.
    ///
    /// Trees are written before the synced block: if the process stops in between, the next run
    /// resumes from the older block and re-inserts the same leaves (idempotent), instead of
    /// believing it is synced while the saved tree lacks them.
    async fn save(&self) -> Result<(), DatabaseError> {
        for (tree_number, tree) in self.utxo_trees.iter() {
            self.db.set_utxo_tree(*tree_number, tree.state()).await?;
        }

        let state = UtxoIndexerState {
            synced_block: self.synced_block,
            trees: self.utxo_trees.keys().cloned().collect(),
        };
        self.db.set_utxo_indexer(&state).await?;

        for account in self.accounts.iter() {
            self.db
                .set_account(&account.address(), &account.state())
                .await?;
        }

        Ok(())
    }
}

#[cfg(all(test, native))]
mod tests {
    use std::sync::{Arc, Mutex};

    use kohaku_kv_store::{
        Store,
        backend::{KvStoreBackend, StoreError},
        memory::MemoryStore,
    };
    use ruint::aliases::U256;

    use super::*;
    use crate::{
        indexer::syncer::{LegacyCommitment, SyncEvent, SyncerError, UtxoSyncer},
        merkle_tree::MerkleRoot,
    };

    /// One commitment at block 5 of a 10-block chain.
    struct OneLeaf;

    #[async_trait::async_trait]
    impl UtxoSyncer for OneLeaf {
        async fn latest_block(&self) -> Result<u64, SyncerError> {
            Ok(10)
        }

        async fn sync(&self, from: u64, to: u64) -> Result<Vec<SyncEvent>, SyncerError> {
            let leaf = LegacyCommitment { hash: U256::from(1), tree_number: 0, leaf_index: 0 };
            Ok(if (from..=to).contains(&5) {
                vec![SyncEvent::Legacy(leaf, 5)]
            } else {
                vec![]
            })
        }
    }

    /// Answers every root with the same verdict.
    struct Verifier(bool);

    #[async_trait::async_trait]
    impl MerkleTreeVerifier for Verifier {
        async fn verify_root(
            &self,
            _tree_number: u32,
            _tree_index: u32,
            _root: MerkleRoot,
        ) -> Result<bool, Box<dyn std::error::Error + Send + Sync + 'static>> {
            Ok(self.0)
        }
    }

    /// In-memory backend that can be told to fail every write of one key: a process stopping
    /// in the middle of a save.
    #[derive(Clone)]
    struct Faulty {
        inner: Arc<MemoryStore>,
        fail_on: Arc<Mutex<Option<Vec<u8>>>>,
    }

    impl Faulty {
        fn new() -> Self {
            Self { inner: Arc::new(MemoryStore::new()), fail_on: Arc::new(Mutex::new(None)) }
        }
    }

    #[async_trait::async_trait]
    impl KvStoreBackend for Faulty {
        async fn get_batch(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
            self.inner.get_batch(keys).await
        }

        async fn put_batch(&self, items: &[(&[u8], &[u8])]) -> Result<(), StoreError> {
            if let Some(key) = self.fail_on.lock().unwrap().as_deref() {
                if items.iter().any(|(k, _)| *k == key) {
                    return Err(StoreError::from(Box::<dyn std::error::Error + Send + Sync>::from(
                        "simulated interruption",
                    )));
                }
            }
            self.inner.put_batch(items).await
        }

        async fn delete_batch(&self, keys: &[&[u8]]) -> Result<(), StoreError> {
            self.inner.delete_batch(keys).await
        }
    }

    #[tokio::test]
    async fn a_root_the_chain_never_had_stops_the_sync() {
        let mut indexer = UtxoIndexer::new(
            Store::new(MemoryStore::new()),
            Arc::new(OneLeaf),
            Arc::new(Verifier(false)),
        )
        .await
        .unwrap();

        let err = indexer.sync_to(10).await.unwrap_err();
        assert!(err.to_string().contains("root the chain never had"), "got: {err}");
        assert_eq!(indexer.synced_block(), 0, "a rejected tree must not advance the sync");
    }

    #[tokio::test]
    async fn an_interrupted_save_never_claims_unsaved_leaves() {
        let backend = Faulty::new();
        *backend.fail_on.lock().unwrap() = Some(b"utxo_tree:0".to_vec());

        let mut indexer =
            UtxoIndexer::new(Store::new(backend.clone()), Arc::new(OneLeaf), Arc::new(Verifier(true)))
                .await
                .unwrap();
        assert!(indexer.sync_to(10).await.is_err(), "the tree write was made to fail");

        // Next run: the saved synced block must not be ahead of the saved tree.
        *backend.fail_on.lock().unwrap() = None;
        let mut reloaded =
            UtxoIndexer::new(Store::new(backend.clone()), Arc::new(OneLeaf), Arc::new(Verifier(true)))
                .await
                .unwrap();
        assert_eq!(reloaded.synced_block(), 0, "blocks claimed whose leaves were never saved");

        // And it recovers: the leaf is fetched again.
        reloaded.sync_to(10).await.unwrap();
        assert_eq!(reloaded.synced_block(), 10);
        assert_eq!(reloaded.utxo_trees.get(&0).map(|t| t.leaves_len()), Some(1));
    }
}
