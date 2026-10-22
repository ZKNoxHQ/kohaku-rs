//! Public encrypted dummy notes; no RPC, private wallet, or transaction submission.
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use kohaku_kv_store::{
    backend::{KvStoreBackend, StoreError},
    memory::MemoryStore,
};
use ruint::aliases::U256;
use tokio::sync::Notify;

use super::*;
use crate::{
    account::signer::PrivateKeySigner,
    caip::AssetId,
    crypto::keys::{ByteKey, SpendingKey, ViewingKey},
    merkle_tree::MerkleRoot,
    note::encrypt::encrypt_shield,
};

struct ShieldSyncer(syncer::Shield);
#[async_trait::async_trait]
impl UtxoSyncer for ShieldSyncer {
    async fn latest_block(&self) -> Result<u64, SyncerError> {
        Ok(10)
    }
    async fn sync(&self, from: u64, to: u64) -> Result<Vec<SyncEvent>, SyncerError> {
        Ok(if (from..=to).contains(&5) {
            vec![SyncEvent::Shield(self.0.clone(), 5)]
        } else {
            vec![]
        })
    }
}

struct Gate {
    accepted: AtomicBool,
    paused: AtomicBool,
    entered: Notify,
}
impl Gate {
    fn new() -> Self {
        Self {
            accepted: AtomicBool::new(true),
            paused: AtomicBool::new(false),
            entered: Notify::new(),
        }
    }
}
#[async_trait::async_trait]
impl MerkleTreeVerifier for Gate {
    async fn verify_root(
        &self,
        _: u32,
        _: u32,
        _: MerkleRoot,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        if self.paused.load(Ordering::Relaxed) {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(self.accepted.load(Ordering::Relaxed))
    }
}

async fn fixture(
    db: Store,
    gate: Arc<Gate>,
) -> (UtxoIndexer, Arc<dyn RailgunSigner>, Arc<ShieldSyncer>) {
    let signer = PrivateKeySigner::new_evm(
        SpendingKey::from_bytes([1; 32]),
        ViewingKey::from_bytes([2; 32]),
        1,
    );
    let asset = AssetId::erc20(alloy::primitives::address!(
        "1234567890123456789012345678901234567890"
    ));
    let request = encrypt_shield(signer.address(), asset, 100, &mut rand::rng()).unwrap();
    let syncer = Arc::new(ShieldSyncer(syncer::Shield {
        tree_number: 0,
        leaf_index: 0,
        npk: request.preimage.npk.into(),
        token: asset,
        value: U256::from(100),
        ciphertext: request.ciphertext.clone().into(),
        shield_key: *request.ciphertext.shieldKey,
        hash: None,
    }));
    let mut indexer = UtxoIndexer::new(db, syncer.clone(), gate).await.unwrap();
    indexer.register(signer.clone()).await.unwrap();
    (indexer, signer, syncer)
}

fn assert_unpublished(indexer: &UtxoIndexer, signer: &dyn RailgunSigner) {
    assert_eq!(indexer.synced_block(), 0);
    assert!(indexer.utxo_trees.is_empty());
    assert!(indexer.unspent(signer.address()).is_empty());
}

async fn assert_saved_once(db: &Store, signer: &dyn RailgunSigner) {
    assert_eq!(db.get_utxo_indexer().await.unwrap().synced_block, 10);
    assert_eq!(
        UtxoMerkleTree::from_state(db.get_utxo_tree(0).await.unwrap().unwrap()).leaves_len(),
        1
    );
    let state = db.get_account(&signer.address()).await.unwrap();
    assert_eq!(state.synced_block, 10);
    assert_eq!(state.notes.len(), 1);
    assert_eq!(state.notes[0].value, 100);
}

#[tokio::test]
async fn rejected_root_then_retry_never_exposes_or_duplicates_notes() {
    let db = Store::create();
    let gate = Arc::new(Gate::new());
    let (mut indexer, signer, syncer) = fixture(db.clone(), gate.clone()).await;
    gate.accepted.store(false, Ordering::Relaxed);
    assert!(indexer.sync_to(10).await.is_err());
    assert_unpublished(&indexer, signer.as_ref());
    assert!(
        db.get_account(&signer.address())
            .await
            .unwrap()
            .notes
            .is_empty()
    );
    gate.accepted.store(true, Ordering::Relaxed);
    indexer.sync_to(10).await.unwrap();
    assert_eq!(indexer.unspent(signer.address()).len(), 1);
    assert_saved_once(&db, signer.as_ref()).await;
    let mut reopened = UtxoIndexer::new(db, syncer, gate).await.unwrap();
    reopened.register(signer.clone()).await.unwrap();
    assert_eq!(reopened.unspent(signer.address()).len(), 1);
}

#[tokio::test]
async fn cancellation_during_root_validation_keeps_the_published_snapshot() {
    let db = Store::create();
    let gate = Arc::new(Gate::new());
    let (mut indexer, signer, _) = fixture(db.clone(), gate.clone()).await;
    gate.paused.store(true, Ordering::Relaxed);
    let mut sync = Box::pin(indexer.sync_to(10));
    tokio::select! {
        result = &mut sync => panic!("validation must block: {result:?}"),
        () = gate.entered.notified() => {},
    }
    drop(sync);
    assert_unpublished(&indexer, signer.as_ref());
    gate.paused.store(false, Ordering::Relaxed);
    indexer.sync_to(10).await.unwrap();
    assert_saved_once(&db, signer.as_ref()).await;
}

struct Writes {
    inner: Arc<MemoryStore>,
    failed_key: Option<Vec<u8>>,
    paused: Arc<AtomicBool>,
    entered: Arc<Notify>,
    after_commit: bool,
}
#[async_trait::async_trait]
impl KvStoreBackend for Writes {
    async fn get_batch(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
        self.inner.get_batch(keys).await
    }
    async fn put_batch(&self, items: &[(&[u8], &[u8])]) -> Result<(), StoreError> {
        if self
            .failed_key
            .as_ref()
            .is_some_and(|key| items.iter().any(|(k, _)| *k == key))
        {
            return Err(StoreError::from(
                Box::<dyn std::error::Error + Send + Sync>::from("injected snapshot failure"),
            ));
        }
        if self.after_commit {
            self.inner.put_batch(items).await?;
        }
        if self.paused.load(Ordering::Relaxed) {
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        if !self.after_commit {
            self.inner.put_batch(items).await?;
        }
        Ok(())
    }
    async fn delete_batch(&self, keys: &[&[u8]]) -> Result<(), StoreError> {
        self.inner.delete_batch(keys).await
    }
}

#[tokio::test]
async fn any_snapshot_key_failure_keeps_trees_accounts_and_cursors_together() {
    // Failing the last account write used to leave the tree and global cursor committed.
    let signer = PrivateKeySigner::new_evm(
        SpendingKey::from_bytes([1; 32]),
        ViewingKey::from_bytes([2; 32]),
        1,
    );
    for key in [
        b"utxo_tree:0".to_vec(),
        b"utxo_indexer".to_vec(),
        format!("account:{}", signer.address()).into_bytes(),
    ] {
        let inner = Arc::new(MemoryStore::new());
        let db = Store::new(Writes {
            inner: inner.clone(),
            failed_key: Some(key),
            paused: Arc::new(AtomicBool::new(false)),
            entered: Arc::new(Notify::new()),
            after_commit: false,
        });
        let (mut indexer, signer, syncer) = fixture(db.clone(), Arc::new(Gate::new())).await;
        assert!(indexer.sync_to(10).await.is_err());
        assert_unpublished(&indexer, signer.as_ref());
        assert_eq!(db.get_utxo_indexer().await.unwrap().synced_block, 0);
        assert!(db.get_utxo_tree(0).await.unwrap().is_none());
        assert!(
            db.get_account(&signer.address())
                .await
                .unwrap()
                .notes
                .is_empty()
        );
        let clean = Store::new(Writes {
            inner,
            failed_key: None,
            paused: Arc::new(AtomicBool::new(false)),
            entered: Arc::new(Notify::new()),
            after_commit: false,
        });
        let mut reopened = UtxoIndexer::new(clean.clone(), syncer, Arc::new(Gate::new()))
            .await
            .unwrap();
        reopened.register(signer.clone()).await.unwrap();
        reopened.sync_to(10).await.unwrap();
        assert_saved_once(&clean, signer.as_ref()).await;
    }
}

async fn cancel_save(after_commit: bool) {
    let paused = Arc::new(AtomicBool::new(true));
    let entered = Arc::new(Notify::new());
    let db = Store::new(Writes {
        inner: Arc::new(MemoryStore::new()),
        failed_key: None,
        paused: paused.clone(),
        entered: entered.clone(),
        after_commit,
    });
    let (mut indexer, signer, syncer) = fixture(db.clone(), Arc::new(Gate::new())).await;
    let mut sync = Box::pin(indexer.sync_to(10));
    tokio::select! {
        result = &mut sync => panic!("save must block: {result:?}"),
        () = entered.notified() => {},
    }
    drop(sync);
    assert_unpublished(&indexer, signer.as_ref());
    assert_eq!(
        db.get_utxo_indexer().await.unwrap().synced_block,
        if after_commit { 10 } else { 0 }
    );
    let mut reopened = UtxoIndexer::new(db.clone(), syncer, Arc::new(Gate::new()))
        .await
        .unwrap();
    reopened.register(signer.clone()).await.unwrap();
    assert_eq!(
        reopened.unspent(signer.address()).len(),
        usize::from(after_commit)
    );
    paused.store(false, Ordering::Relaxed);
    indexer.sync_to(10).await.unwrap();
    assert_eq!(indexer.unspent(signer.address()).len(), 1);
    assert_saved_once(&db, signer.as_ref()).await;
}

#[tokio::test]
async fn cancellation_before_save_preserves_the_previous_snapshot() {
    cancel_save(false).await;
}
#[tokio::test]
async fn lost_save_ack_keeps_a_consistent_cold_snapshot_and_allows_replay() {
    cancel_save(true).await;
}

#[tokio::test]
async fn a_new_account_rescan_does_not_duplicate_an_existing_account() {
    let db = Store::create();
    let (mut indexer, signer, _) = fixture(db.clone(), Arc::new(Gate::new())).await;
    indexer.sync_to(10).await.unwrap();
    let bob = PrivateKeySigner::new_evm(
        SpendingKey::from_bytes([3; 32]),
        ViewingKey::from_bytes([4; 32]),
        1,
    );
    indexer.register(bob.clone()).await.unwrap();
    assert_eq!(indexer.synced_block(), 0);
    indexer.sync_to(10).await.unwrap();
    assert_eq!(indexer.unspent(signer.address()).len(), 1);
    assert!(indexer.unspent(bob.address()).is_empty());
    assert_saved_once(&db, signer.as_ref()).await;
}
