use kohaku_kv_store::Store;
use thiserror::Error;
use tracing::info;

use crate::{
    indexer::{
        indexer_store::IndexerStoreExt,
        syncer::{SyncEvent, Syncer, SyncerError},
        verifier::{Verifier, VerifierError},
    },
    merkle_tree::MsMerkleTree,
    pool::Pool,
};

mod indexer_store;
pub mod rpc;
pub mod syncer;
pub mod verifier;

const REORG_MARGIN: u64 = 32;

#[derive(Clone)]
pub struct Indexer {
    pool: Pool,
    store: Store,
    syncer: Syncer,
    verifier: Verifier,
}

#[derive(Debug, Error)]
pub enum IndexerError {
    #[error(transparent)]
    Syncer(#[from] SyncerError),
    #[error(transparent)]
    Verifier(#[from] VerifierError),
    #[error(transparent)]
    Merkle(#[from] kohaku_merkle_tree::MerkleTreeError),
}

impl Indexer {
    #[must_use]
    pub fn new(pool: Pool, store: Store, syncer: Syncer, verifier: Verifier) -> Self {
        Self {
            pool,
            store,
            syncer,
            verifier,
        }
    }

    #[must_use]
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    #[must_use]
    pub fn tree(&self) -> MsMerkleTree {
        let epoch_store = self.store.scope(b"epoch-tree");
        MsMerkleTree::new(epoch_store)
    }

    pub async fn epoch(&self) -> u64 {
        self.store.epoch().await
    }

    pub async fn sync(&self) -> Result<(), IndexerError> {
        let latest = self.syncer.latest_block(&self.pool).await?;
        self.sync_to(latest).await
    }

    async fn sync_to(&self, to_block: u64) -> Result<(), IndexerError> {
        let latest = self.store.latest_block().await;
        let from = latest
            .saturating_sub(REORG_MARGIN)
            .max(self.pool.deployed_block);
        if from >= to_block {
            info!("already synced to {latest}");
            self.verifier
                .verify(&self.pool, self.tree().root().await?)
                .await?;
            return Ok(());
        }
        let events = self.syncer.sync(&self.pool, from..to_block).await?;
        let mut epoch = self.store.epoch().await;
        let tree = self.tree();
        for event in events {
            match event {
                SyncEvent::EpochRolled { new_epoch, .. } => {
                    epoch = new_epoch;
                }
                SyncEvent::LeafAppended {
                    cm,
                    index,
                    epoch: ev_epoch,
                    ..
                } => {
                    epoch = ev_epoch;
                    tree.insert(index as usize, cm).await?;
                }
                SyncEvent::NoteSpent { .. } | SyncEvent::RootPublished { .. } => {}
            }
        }
        // Verify before committing height so a bad sync cannot stick the wallet
        // past a recoverable reorg window.
        self.verifier
            .verify(&self.pool, tree.root().await?)
            .await?;
        self.store.commit(to_block, epoch).await;
        Ok(())
    }
}
