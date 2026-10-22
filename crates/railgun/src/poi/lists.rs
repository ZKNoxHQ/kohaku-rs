use std::{collections::HashMap, future::Future};

use kohaku_kv_store::Store;
use ruint::aliases::U256;
use thiserror::Error;
use tracing::{info, warn};

use crate::{
    common::sleep,
    merkle_tree::{
        MerkleRoot, PoiMerkleProof, PoiMerkleTree, PoiMerkleTreeState, TOTAL_LEAVES,
        is_poi_empty_leaf,
    },
    poi::{
        client::{PoiClientError, PoiNodeClient},
        types::{BlindedCommitment, ListKey},
    },
    railgun_database::{DatabaseError, RailgunDB, write_poi_snapshot},
};

/// One request, matching the node's cap on `ppoi_poi_merkletree_leaves`.
const LEAF_PAGE: u64 = 100;
/// Pages applied, validated and saved together. A save writes each touched tree whole (up to
/// 65,536 leaves and every level above them), so saving after each page made the first copy of
/// a long list slow down as each tree filled. A failed batch costs at most this many pages again.
const BATCH_PAGES: u64 = 20;
/// Leaf requests in flight while a batch is fetched.
const PARALLEL_FETCHES: usize = 4;
/// Extra attempts after the first failure, same budget as the Subsquid syncer.
const MAX_RETRIES: usize = 3;

/// Every configured POI list, stored locally and queried by leaf index.
pub struct PoiLists {
    db: Store,
    lists: HashMap<ListKey, PoiList>,
}

struct PoiList {
    trees: HashMap<u32, PoiMerkleTree>,
    /// Blinded commitment to its position. Built from the trees, not stored.
    index: HashMap<BlindedCommitment, (u32, u32)>,
    next_index: u64,
    /// True only after this process has copied through the zero leaf. Not stored:
    /// a restart has not re-checked the tail, so absence is not yet `Missing`.
    caught_up: bool,
}

#[derive(Debug, Error)]
pub enum PoiSyncError {
    #[error("POI client error: {0}")]
    Client(#[from] PoiClientError),
    #[error("Database error: {0}")]
    Database(#[from] DatabaseError),
    #[error("POI node rejected merkle roots for list {list_key}")]
    RootRejected { list_key: ListKey },
    /// The node owes a full page, or a shorter one that ends in the POI zero.
    #[error("POI list {list_key} returned {got} leaves for {start}..{end} with no zero leaf")]
    ShortPage {
        list_key: ListKey,
        start: u64,
        end: u64,
        got: usize,
    },
}

impl PoiLists {
    pub async fn load(db: Store, list_keys: &[ListKey]) -> Result<Self, DatabaseError> {
        let mut lists = HashMap::new();
        for list_key in list_keys {
            lists.insert(list_key.clone(), PoiList::load(&db, list_key).await?);
        }
        Ok(Self { db, lists })
    }

    pub fn contains(&self, list_key: &ListKey, commitment: BlindedCommitment) -> bool {
        self.lists
            .get(list_key)
            .is_some_and(|list| list.index.contains_key(&commitment))
    }

    pub fn proof(
        &self,
        list_key: &ListKey,
        commitment: BlindedCommitment,
    ) -> Option<PoiMerkleProof> {
        let list = self.lists.get(list_key)?;
        let (tree_number, leaf_index) = list.index.get(&commitment).copied()?;
        let tree = list.trees.get(&tree_number)?;
        match tree.generate_proof_at(leaf_index as usize) {
            Ok(proof) => Some(proof),
            Err(err) => {
                warn!("POI proof for list {list_key} failed: {err}");
                None
            }
        }
    }

    pub fn next_index(&self, list_key: &ListKey) -> u64 {
        self.lists
            .get(list_key)
            .map(|list| list.next_index)
            .unwrap_or(0)
    }

    /// Whether the latest sync of this list reached its zero leaf.
    pub fn caught_up(&self, list_key: &ListKey) -> bool {
        self.lists.get(list_key).is_some_and(|list| list.caught_up)
    }

    /// Copies each list forward from its saved cursor. One request at a time.
    pub async fn sync(&mut self, client: &impl PoiNodeClient) -> Result<(), PoiSyncError> {
        let list_keys: Vec<ListKey> = self.lists.keys().cloned().collect();
        for list_key in list_keys {
            self.sync_list(client, &list_key).await?;
        }
        Ok(())
    }

    async fn sync_list(
        &mut self,
        client: &impl PoiNodeClient,
        list_key: &ListKey,
    ) -> Result<(), PoiSyncError> {
        use futures::StreamExt;

        if let Some(list) = self.lists.get_mut(list_key) {
            list.caught_up = false;
        }
        // The first batch is one page, so a list that is already caught up costs one request.
        // After a rejected batch, one page at a time keeps the prefix the node accepts.
        let mut batch_pages = 1;
        let mut narrowed = false;
        loop {
            let start = self.next_index(list_key);
            let ranges: Vec<(u64, u64)> = (0..batch_pages)
                .map_while(|i| {
                    let page_start = start.checked_add(i * LEAF_PAGE)?;
                    Some((page_start, page_start.checked_add(LEAF_PAGE)?))
                })
                .collect();
            let Some(&(_, span_end)) = ranges.last() else {
                return Ok(());
            };
            let mut pages = futures::stream::iter(ranges.iter().map(|&(page_start, page_end)| {
                async move {
                    let page =
                        retry(|| client.merkletree_leaves(list_key, page_start, page_end)).await;
                    (page_start, page_end, page)
                }
            }))
            .buffered(PARALLEL_FETCHES);

            // Applied in order; the first page that is not full ends the batch.
            let snapshots = self.snapshot(list_key, start, (span_end - start) as usize);
            let mut previous = Vec::new();
            let mut roots = Vec::new();
            let mut cursor = start;
            let mut pages_applied = 0;
            let mut stopped = None;
            let mut end_reached = false;
            while let Some((page_start, page_end, page)) = pages.next().await {
                let page = match page {
                    Ok(page) => page,
                    Err(err) => {
                        stopped = Some(PoiSyncError::from(err));
                        break;
                    }
                };
                let expected = (page_end - page_start) as usize;
                let zero_at = page.iter().position(|leaf| is_poi_empty_leaf(*leaf));
                if page.len() < expected && zero_at.is_none() {
                    stopped = Some(PoiSyncError::ShortPage {
                        list_key: list_key.clone(),
                        start: page_start,
                        end: page_end,
                        got: page.len(),
                    });
                    break;
                }
                let real_len = zero_at.unwrap_or(page.len());
                let real = &page[..real_len];
                if real.is_empty() {
                    end_reached = true;
                    break;
                }

                previous.extend(self.previous_positions(list_key, real));
                self.lists
                    .get_mut(list_key)
                    .expect("POI list loaded at startup")
                    .insert_range(page_start, real);
                // Every page's roots, as when the pages were checked one by one.
                roots.extend(self.roots(list_key, &touched_trees(page_start, real_len)));
                cursor = page_start + real_len as u64;
                pages_applied += 1;
                if real_len < page.len() {
                    end_reached = true;
                    break;
                }
            }
            drop(pages);

            if pages_applied == 0 {
                if let Some(err) = stopped {
                    return Err(err);
                }
                if end_reached {
                    self.lists
                        .get_mut(list_key)
                        .expect("POI list loaded at startup")
                        .caught_up = true;
                    info!("POI list {list_key} is synced at leaf {start}");
                }
                return Ok(());
            }

            let accepted = match retry(|| client.validate_poi_merkleroots(list_key, &roots)).await {
                Ok(accepted) => accepted,
                Err(err) => {
                    self.restore(list_key, snapshots, previous);
                    return Err(err.into());
                }
            };
            if !accepted {
                self.restore(list_key, snapshots, previous);
                if pages_applied > 1 {
                    batch_pages = 1;
                    narrowed = true;
                    continue;
                }
                return Err(PoiSyncError::RootRejected {
                    list_key: list_key.clone(),
                });
            }

            self.lists
                .get_mut(list_key)
                .expect("POI list loaded at startup")
                .next_index = cursor;
            let tree_numbers = touched_trees(start, (cursor - start) as usize);
            if let Err(err) = self.persist(list_key, &tree_numbers).await {
                self.restore(list_key, snapshots, previous);
                self.lists
                    .get_mut(list_key)
                    .expect("POI list loaded at startup")
                    .next_index = start;
                return Err(err);
            }
            info!("Synced POI list {list_key} through leaf {cursor}");

            if let Some(err) = stopped {
                return Err(err);
            }
            if end_reached {
                self.lists
                    .get_mut(list_key)
                    .expect("POI list loaded at startup")
                    .caught_up = true;
                return Ok(());
            }
            if !narrowed {
                batch_pages = BATCH_PAGES;
            }
        }
    }

    fn snapshot(
        &self,
        list_key: &ListKey,
        start: u64,
        count: usize,
    ) -> Vec<(u32, Option<PoiMerkleTreeState>)> {
        let list = &self.lists[list_key];
        touched_trees(start, count)
            .into_iter()
            .map(|number| (number, list.trees.get(&number).map(|tree| tree.state())))
            .collect()
    }

    fn previous_positions(
        &self,
        list_key: &ListKey,
        leaves: &[U256],
    ) -> Vec<(BlindedCommitment, Option<(u32, u32)>)> {
        let list = &self.lists[list_key];
        leaves
            .iter()
            .map(|leaf| {
                let commitment = BlindedCommitment::from(*leaf);
                (commitment, list.index.get(&commitment).copied())
            })
            .collect()
    }

    fn roots(&self, list_key: &ListKey, tree_numbers: &[u32]) -> Vec<MerkleRoot> {
        let list = &self.lists[list_key];
        tree_numbers
            .iter()
            .filter_map(|number| list.trees.get(number).map(|tree| tree.root()))
            .collect()
    }

    fn restore(
        &mut self,
        list_key: &ListKey,
        snapshots: Vec<(u32, Option<PoiMerkleTreeState>)>,
        previous: Vec<(BlindedCommitment, Option<(u32, u32)>)>,
    ) {
        let list = self
            .lists
            .get_mut(list_key)
            .expect("POI list loaded at startup");
        // Newest first: a commitment seen twice in one batch ends at its position before both.
        for (commitment, position) in previous.into_iter().rev() {
            match position {
                Some(position) => {
                    list.index.insert(commitment, position);
                }
                None => {
                    list.index.remove(&commitment);
                }
            }
        }
        for (number, state) in snapshots {
            match state {
                Some(state) => {
                    list.trees.insert(number, PoiMerkleTree::from_state(state));
                }
                None => {
                    list.trees.remove(&number);
                }
            }
        }
    }

    async fn persist(&self, list_key: &ListKey, tree_numbers: &[u32]) -> Result<(), PoiSyncError> {
        let list = &self.lists[list_key];
        let states: Vec<(u32, PoiMerkleTreeState)> = tree_numbers
            .iter()
            .map(|number| {
                (
                    *number,
                    list.trees.get(number).expect("touched POI tree").state(),
                )
            })
            .collect();
        let next_index = list.next_index;
        write_poi_snapshot(&self.db, list_key, next_index, &states).await?;
        Ok(())
    }
}

impl PoiList {
    async fn load(db: &Store, list_key: &ListKey) -> Result<Self, DatabaseError> {
        let next_index = db.get_poi_sync(list_key).await?.next_index;
        let mut trees = HashMap::new();
        let mut index = HashMap::new();
        let mut tree_number = 0u32;
        loop {
            let Some(state) = db.get_poi_tree(list_key, tree_number).await? else {
                break;
            };
            let tree = PoiMerkleTree::from_state(state);
            for (leaf_index, leaf) in tree.leaves().iter().copied().enumerate() {
                index.insert(
                    BlindedCommitment::from(leaf),
                    (tree_number, leaf_index as u32),
                );
            }
            trees.insert(tree_number, tree);
            tree_number = match tree_number.checked_add(1) {
                Some(next) => next,
                None => break,
            };
        }
        Ok(Self {
            trees,
            index,
            next_index,
            caught_up: false,
        })
    }

    fn insert_range(&mut self, start: u64, leaves: &[U256]) {
        let mut offset = 0usize;
        while offset < leaves.len() {
            let global = start + offset as u64;
            let tree_number = (global / TOTAL_LEAVES as u64) as u32;
            let leaf_index = (global % TOTAL_LEAVES as u64) as u32;
            let room = (TOTAL_LEAVES - leaf_index) as usize;
            let count = (leaves.len() - offset).min(room);
            let chunk = &leaves[offset..offset + count];
            let tree = self
                .trees
                .entry(tree_number)
                .or_insert_with(|| PoiMerkleTree::new(tree_number));
            tree.insert_leaves(chunk, leaf_index as usize);
            for (i, leaf) in chunk.iter().copied().enumerate() {
                self.index.insert(
                    BlindedCommitment::from(leaf),
                    (tree_number, leaf_index + i as u32),
                );
            }
            offset += count;
        }
    }
}

fn touched_trees(start: u64, count: usize) -> Vec<u32> {
    if count == 0 {
        return Vec::new();
    }
    let last = start + count as u64 - 1;
    let first_tree = (start / TOTAL_LEAVES as u64) as u32;
    let last_tree = (last / TOTAL_LEAVES as u64) as u32;
    (first_tree..=last_tree).collect()
}

async fn retry<T, F, Fut>(mut op: F) -> Result<T, PoiClientError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, PoiClientError>>,
{
    let mut attempt = 0;
    loop {
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) => {
                attempt += 1;
                if attempt > MAX_RETRIES {
                    return Err(err);
                }
                warn!("POI request failed (attempt {attempt}/{MAX_RETRIES}): {err}");
                sleep(web_time::Duration::from_secs(1)).await;
            }
        }
    }
}

#[cfg(all(test, native))]
mod tests {
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use super::*;
    use crate::poi::types::TransactProofData;
    use kohaku_kv_store::{
        backend::{KvStoreBackend, StoreError},
        memory::MemoryStore,
    };

    #[derive(Clone, Copy)]
    enum LeafPages {
        /// Full requested range, POI zero past the stored leaves.
        Padded,
        Empty,
        /// Stored leaves only, no zero padding.
        Exact,
    }

    struct FakeNode {
        leaves: Mutex<Vec<U256>>,
        accept_roots: AtomicBool,
        /// Accept this many root checks, then reject. `None` follows `accept_roots`.
        accept_prefix: Mutex<Option<usize>>,
        /// Roots the node has published, as a real node: a check passes when all are in it.
        /// `None` follows `accept_prefix` and `accept_roots`.
        published: Mutex<Option<Vec<MerkleRoot>>>,
        root_checks: AtomicUsize,
        pages: LeafPages,
    }

    impl FakeNode {
        fn new(leaves: Vec<U256>, accept_roots: bool) -> Self {
            Self::with_pages(leaves, accept_roots, LeafPages::Padded)
        }

        fn empty() -> Self {
            Self::with_pages(Vec::new(), true, LeafPages::Empty)
        }

        fn exact(leaves: Vec<U256>) -> Self {
            Self::with_pages(leaves, true, LeafPages::Exact)
        }

        fn with_pages(leaves: Vec<U256>, accept_roots: bool, pages: LeafPages) -> Self {
            Self {
                leaves: Mutex::new(leaves),
                accept_roots: AtomicBool::new(accept_roots),
                accept_prefix: Mutex::new(None),
                published: Mutex::new(None),
                root_checks: AtomicUsize::new(0),
                pages,
            }
        }

        fn reject_after(&self, accepted: usize) {
            *self.accept_prefix.lock().unwrap() = Some(accepted);
        }

        /// Publishes the root after each of the first `count` leaves (all in tree 0).
        fn publish_through(&self, count: usize) {
            let leaves = self.leaves.lock().unwrap();
            let mut tree = PoiMerkleTree::new(0);
            let roots = leaves[..count]
                .iter()
                .enumerate()
                .map(|(i, leaf)| {
                    tree.insert_leaves(&[*leaf], i);
                    tree.root()
                })
                .collect();
            *self.published.lock().unwrap() = Some(roots);
        }

        fn set_leaves(&self, leaves: Vec<U256>) {
            *self.leaves.lock().unwrap() = leaves;
        }
    }

    #[cfg_attr(native, async_trait::async_trait)]
    impl PoiNodeClient for FakeNode {
        fn list_keys(&self) -> Vec<ListKey> {
            vec![ListKey::from("list")]
        }

        async fn merkletree_leaves(
            &self,
            _list_key: &ListKey,
            start_index: u64,
            end_index: u64,
        ) -> Result<Vec<U256>, PoiClientError> {
            match self.pages {
                LeafPages::Empty => Ok(Vec::new()),
                LeafPages::Exact => {
                    let leaves = self.leaves.lock().unwrap();
                    let start = start_index as usize;
                    let end = (end_index as usize).min(leaves.len());
                    if start >= end {
                        Ok(Vec::new())
                    } else {
                        Ok(leaves[start..end].to_vec())
                    }
                }
                LeafPages::Padded => {
                    let leaves = self.leaves.lock().unwrap();
                    let zero = PoiMerkleTree::zero();
                    Ok((start_index..end_index)
                        .map(|index| leaves.get(index as usize).copied().unwrap_or(zero))
                        .collect())
                }
            }
        }

        async fn validate_poi_merkleroots(
            &self,
            _list_key: &ListKey,
            roots: &[MerkleRoot],
        ) -> Result<bool, PoiClientError> {
            let n = self.root_checks.fetch_add(1, Ordering::Relaxed);
            if let Some(published) = &*self.published.lock().unwrap() {
                return Ok(roots.iter().all(|root| published.contains(root)));
            }
            if let Some(prefix) = *self.accept_prefix.lock().unwrap() {
                return Ok(n < prefix);
            }
            Ok(self.accept_roots.load(Ordering::Relaxed))
        }

        async fn submit_proof(
            &self,
            _proof_data: HashMap<ListKey, TransactProofData>,
        ) -> Result<(), PoiClientError> {
            unimplemented!()
        }

        async fn validated_txid(
            &self,
        ) -> Result<crate::poi::types::ValidatedRailgunTxidStatus, PoiClientError> {
            unimplemented!()
        }

        async fn validate_txid_merkleroot(
            &self,
            _tree: u32,
            _index: u32,
            _merkleroot: MerkleRoot,
        ) -> Result<bool, PoiClientError> {
            unimplemented!()
        }
    }

    fn list_key() -> ListKey {
        ListKey::from("list")
    }

    #[tokio::test]
    async fn sync_stops_at_the_zero_leaf_and_resumes() {
        let db = Store::create();
        let key = list_key();
        let mut leaves: Vec<U256> = (1..=101u32).map(U256::from).collect();
        let node = FakeNode::new(leaves.clone(), true);
        let mut lists = PoiLists::load(db.clone(), &[key.clone()]).await.unwrap();

        lists.sync(&node).await.unwrap();
        assert_eq!(lists.next_index(&key), 101);
        assert!(lists.caught_up(&key));
        let commitment = BlindedCommitment::from(U256::from(2u8));
        let proof = lists.proof(&key, commitment).unwrap();
        assert!(proof.verify());

        let reloaded = PoiLists::load(db.clone(), &[key.clone()]).await.unwrap();
        assert_eq!(reloaded.next_index(&key), 101);
        assert!(!reloaded.caught_up(&key));
        assert!(reloaded.proof(&key, commitment).unwrap().verify());

        leaves.push(U256::from(102u32));
        leaves.push(U256::from(103u32));
        node.set_leaves(leaves);
        lists.sync(&node).await.unwrap();
        assert_eq!(lists.next_index(&key), 103);
        assert!(lists.contains(&key, BlindedCommitment::from(U256::from(103u32))));
    }

    #[tokio::test]
    async fn rejected_root_does_not_advance_the_cursor() {
        let db = Store::create();
        let key = list_key();
        let node = FakeNode::new((1..=3u32).map(U256::from).collect(), false);
        let mut lists = PoiLists::load(db.clone(), &[key.clone()]).await.unwrap();

        let err = lists.sync(&node).await.unwrap_err();
        assert!(matches!(err, PoiSyncError::RootRejected { .. }));
        assert_eq!(lists.next_index(&key), 0);
        assert!(!lists.caught_up(&key));
        assert!(
            lists
                .proof(&key, BlindedCommitment::from(U256::from(1u8)))
                .is_none()
        );

        let reloaded = PoiLists::load(db, &[key.clone()]).await.unwrap();
        assert_eq!(reloaded.next_index(&key), 0);
        assert!(!reloaded.contains(&key, BlindedCommitment::from(U256::from(1u8))));
    }

    #[tokio::test]
    async fn a_rejected_later_page_keeps_the_prefix_but_not_caught_up() {
        let db = Store::create();
        let key = list_key();
        let node = FakeNode::new((1..=101u32).map(U256::from).collect(), true);
        node.reject_after(1);
        let mut lists = PoiLists::load(db, &[key.clone()]).await.unwrap();

        let err = lists.sync(&node).await.unwrap_err();
        assert!(matches!(err, PoiSyncError::RootRejected { .. }));
        assert_eq!(lists.next_index(&key), 100);
        assert!(!lists.caught_up(&key));
        assert!(lists.contains(&key, BlindedCommitment::from(U256::from(1u8))));
        assert!(!lists.contains(&key, BlindedCommitment::from(U256::from(101u32))));
    }

    #[tokio::test]
    async fn an_empty_page_is_not_the_end_of_the_list() {
        let db = Store::create();
        let key = list_key();
        let node = FakeNode::empty();
        let mut lists = PoiLists::load(db, &[key.clone()]).await.unwrap();

        let err = lists.sync(&node).await.unwrap_err();
        assert!(matches!(err, PoiSyncError::ShortPage { got: 0, .. }));
        assert_eq!(lists.next_index(&key), 0);
        assert!(!lists.caught_up(&key));
    }

    #[tokio::test]
    async fn a_short_page_without_a_zero_is_not_applied() {
        let db = Store::create();
        let key = list_key();
        let node = FakeNode::exact((1..=3u32).map(U256::from).collect());
        let mut lists = PoiLists::load(db, &[key.clone()]).await.unwrap();

        let err = lists.sync(&node).await.unwrap_err();
        assert!(matches!(err, PoiSyncError::ShortPage { got: 3, .. }));
        assert_eq!(lists.next_index(&key), 0);
        assert!(!lists.caught_up(&key));
        assert!(!lists.contains(&key, BlindedCommitment::from(U256::from(1u8))));
    }

    fn leaves(count: u32) -> Vec<U256> {
        (1..=count).map(U256::from).collect()
    }

    /// Counts snapshot saves.
    struct CountWrites {
        inner: MemoryStore,
        writes: std::sync::Arc<AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl KvStoreBackend for CountWrites {
        async fn get_batch(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
            self.inner.get_batch(keys).await
        }
        async fn put_batch(&self, entries: &[(&[u8], &[u8])]) -> Result<(), StoreError> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            self.inner.put_batch(entries).await
        }
        async fn delete_batch(&self, keys: &[&[u8]]) -> Result<(), StoreError> {
            self.inner.delete_batch(keys).await
        }
    }

    /// 4,250 leaves: one page, then batches of 20 pages. Four root checks and four saves where
    /// page by page took 43 of each, and the same tree.
    #[tokio::test]
    async fn a_long_list_is_copied_in_batches() {
        let writes = std::sync::Arc::new(AtomicUsize::new(0));
        let db = Store::new(CountWrites {
            inner: MemoryStore::new(),
            writes: writes.clone(),
        });
        let key = list_key();
        let all = leaves(4_250);
        let node = FakeNode::new(all.clone(), true);
        node.publish_through(all.len());
        let mut lists = PoiLists::load(db.clone(), &[key.clone()]).await.unwrap();

        lists.sync(&node).await.unwrap();
        assert_eq!(lists.next_index(&key), 4_250);
        assert!(lists.caught_up(&key));
        assert_eq!(node.root_checks.load(Ordering::Relaxed), 4);
        assert_eq!(writes.load(Ordering::Relaxed), 4);

        let mut expected = PoiMerkleTree::new(0);
        expected.insert_leaves(&all, 0);
        let reloaded = PoiLists::load(db, &[key.clone()]).await.unwrap();
        assert_eq!(reloaded.next_index(&key), 4_250);
        for leaf in [1u32, 2_100, 4_250] {
            let proof = reloaded
                .proof(&key, BlindedCommitment::from(U256::from(leaf)))
                .unwrap();
            assert!(proof.verify());
            assert_eq!(proof.root, expected.root());
        }

        // Caught up: one more request and nothing to check.
        lists.sync(&node).await.unwrap();
        assert_eq!(node.root_checks.load(Ordering::Relaxed), 4);
    }

    /// The node has published roots through leaf 1,300 only: the batch from 100 is rejected,
    /// then retried page by page, which keeps everything up to 1,300.
    #[tokio::test]
    async fn a_rejected_batch_keeps_the_accepted_pages() {
        let db = Store::create();
        let key = list_key();
        let node = FakeNode::new(leaves(2_500), true);
        node.publish_through(1_300);
        let mut lists = PoiLists::load(db.clone(), &[key.clone()]).await.unwrap();

        let err = lists.sync(&node).await.unwrap_err();
        assert!(matches!(err, PoiSyncError::RootRejected { .. }));
        assert_eq!(lists.next_index(&key), 1_300);
        assert!(!lists.caught_up(&key));
        assert!(lists.contains(&key, BlindedCommitment::from(U256::from(1_300u32))));
        assert!(!lists.contains(&key, BlindedCommitment::from(U256::from(1_301u32))));

        let reloaded = PoiLists::load(db, &[key.clone()]).await.unwrap();
        assert_eq!(reloaded.next_index(&key), 1_300);
        assert!(
            reloaded
                .proof(&key, BlindedCommitment::from(U256::from(1_300u32)))
                .unwrap()
                .verify()
        );
    }

    /// A commitment present twice in a rejected batch is gone after the rollback, as it was
    /// before the batch.
    #[tokio::test]
    async fn a_rollback_forgets_a_commitment_repeated_in_the_batch() {
        let db = Store::create();
        let key = list_key();
        let mut all = leaves(400);
        let repeated = U256::from(9_999u32);
        all[150] = repeated;
        all[250] = repeated;
        let node = FakeNode::new(all, true);
        node.reject_after(1);
        let mut lists = PoiLists::load(db, &[key.clone()]).await.unwrap();

        let err = lists.sync(&node).await.unwrap_err();
        assert!(matches!(err, PoiSyncError::RootRejected { .. }));
        assert_eq!(lists.next_index(&key), 100);
        assert!(!lists.contains(&key, BlindedCommitment::from(repeated)));
    }

    struct FailWrites {
        inner: MemoryStore,
    }
    #[async_trait::async_trait]
    impl KvStoreBackend for FailWrites {
        async fn get_batch(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, StoreError> {
            self.inner.get_batch(keys).await
        }
        async fn put_batch(&self, _: &[(&[u8], &[u8])]) -> Result<(), StoreError> {
            Err(StoreError::from(
                Box::new(std::io::Error::other("injected POI snapshot failure"))
                    as Box<dyn std::error::Error + Send + Sync>,
            ))
        }
        async fn delete_batch(&self, keys: &[&[u8]]) -> Result<(), StoreError> {
            self.inner.delete_batch(keys).await
        }
    }

    #[tokio::test]
    async fn a_failed_save_rolls_the_page_back() {
        let db = Store::new(FailWrites {
            inner: MemoryStore::new(),
        });
        let kept = db.clone();
        let key = list_key();
        let node = FakeNode::new((1..=3u32).map(U256::from).collect(), true);
        let mut lists = PoiLists::load(db, &[key.clone()]).await.unwrap();

        let err = lists.sync(&node).await.unwrap_err();
        assert!(matches!(err, PoiSyncError::Database(_)));
        assert_eq!(lists.next_index(&key), 0);
        assert!(!lists.caught_up(&key));
        assert!(!lists.contains(&key, BlindedCommitment::from(U256::from(1u8))));

        let reloaded = PoiLists::load(kept, &[key.clone()]).await.unwrap();
        assert_eq!(reloaded.next_index(&key), 0);
        assert!(!reloaded.contains(&key, BlindedCommitment::from(U256::from(1u8))));
    }
}
