use std::sync::Arc;

use crate::indexer::syncer::{SyncEvent, SyncerError, UtxoSyncer};

/// Helper syncer that chains multiple UTXO syncers together.
///
/// Syncers are queried in the order they are added, and the sync range is adjusted based on the
/// latest block of each syncer.
#[derive(Default)]
pub struct ChainedSyncer {
    syncers: Vec<Arc<dyn UtxoSyncer>>,
}

impl ChainedSyncer {
    pub fn new() -> Self {
        Self {
            syncers: Vec::new(),
        }
    }

    /// Adds a syncer to the chain. Syncers are queried in the order they are added.
    pub fn then<S: UtxoSyncer + 'static>(mut self, syncer: S) -> Self {
        self.syncers.push(Arc::new(syncer));
        self
    }

    /// Adds a syncer to the chain. Syncers are queried in the order they are added.
    pub fn then_arc(mut self, syncer: Arc<dyn UtxoSyncer>) -> Self {
        self.syncers.push(syncer);
        self
    }
}

#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
impl UtxoSyncer for ChainedSyncer {
    async fn latest_block(&self) -> Result<u64, SyncerError> {
        let mut max_block = 0u64;
        for syncer in &self.syncers {
            if let Ok(block) = syncer.latest_block().await {
                max_block = max_block.max(block);
            }
        }
        Ok(max_block)
    }

    /// Syncs `from_block..=to_block`, each syncer taking the blocks it has. A syncer that fails
    /// leaves its range to the next one; a range no syncer covered is an error, never a gap the
    /// indexer would mark as synced (its commitments would be missing for good, and the next
    /// leaves would land past the end of the tree).
    async fn sync(&self, from_block: u64, to_block: u64) -> Result<Vec<SyncEvent>, SyncerError> {
        let mut current_from = from_block;
        let mut last_error = None;

        let mut all_events = Vec::new();
        for (i, syncer) in self.syncers.iter().enumerate() {
            if current_from > to_block {
                break;
            }

            let syncer_latest = match syncer.latest_block().await {
                Ok(block) => block,
                Err(e) => {
                    tracing::warn!("Syncer {} failed: {}", i, e);
                    last_error = Some(e);
                    continue;
                }
            };
            if syncer_latest < current_from {
                continue;
            }

            let range_end = syncer_latest.min(to_block);
            match syncer.sync(current_from, range_end).await {
                Ok(events) => {
                    all_events.extend(events);
                    current_from = range_end + 1;
                }
                Err(e) => {
                    tracing::warn!("Syncer {} failed: {}", i, e);
                    last_error = Some(e);
                }
            }
        }

        if current_from <= to_block {
            return Err(last_error.unwrap_or_else(|| {
                SyncerError::new(Uncovered {
                    from: current_from,
                    to: to_block,
                })
            }));
        }
        Ok(all_events)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("no syncer covers blocks {from}..={to}")]
struct Uncovered {
    from: u64,
    to: u64,
}

#[cfg(all(test, native))]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("unreachable")]
    struct Down;

    /// A syncer that has blocks up to `latest`, records the ranges asked of it, and fails them
    /// when `down`.
    struct Fake {
        latest: u64,
        down: bool,
        calls: Arc<Mutex<Vec<(u64, u64)>>>,
    }

    impl Fake {
        fn new(latest: u64, down: bool) -> (Self, Arc<Mutex<Vec<(u64, u64)>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    latest,
                    down,
                    calls: calls.clone(),
                },
                calls,
            )
        }
    }

    #[async_trait::async_trait]
    impl UtxoSyncer for Fake {
        async fn latest_block(&self) -> Result<u64, SyncerError> {
            Ok(self.latest)
        }

        async fn sync(&self, from: u64, to: u64) -> Result<Vec<SyncEvent>, SyncerError> {
            self.calls.lock().unwrap().push((from, to));
            if self.down {
                Err(SyncerError::new(Down))
            } else {
                Ok(Vec::new())
            }
        }
    }

    #[tokio::test]
    async fn the_next_syncer_takes_up_where_the_first_stops() {
        let (squid, squid_calls) = Fake::new(100, false);
        let (rpc, rpc_calls) = Fake::new(150, false);
        let chained = ChainedSyncer::new().then(squid).then(rpc);

        chained.sync(50, 150).await.unwrap();
        assert_eq!(*squid_calls.lock().unwrap(), vec![(50, 100)]);
        assert_eq!(*rpc_calls.lock().unwrap(), vec![(101, 150)]);
    }

    #[tokio::test]
    async fn a_failed_range_goes_to_the_next_syncer() {
        let (squid, _) = Fake::new(100, true);
        let (rpc, rpc_calls) = Fake::new(150, false);
        let chained = ChainedSyncer::new().then(squid).then(rpc);

        chained.sync(50, 150).await.unwrap();
        assert_eq!(*rpc_calls.lock().unwrap(), vec![(50, 150)]);
    }

    #[tokio::test]
    async fn a_range_no_syncer_covered_is_an_error() {
        let (squid, _) = Fake::new(100, false);
        let (rpc, _) = Fake::new(150, true);
        let chained = ChainedSyncer::new().then(squid).then(rpc);

        // Blocks 101..=150 are only on the RPC, which fails: not a silent gap.
        assert!(chained.sync(50, 150).await.is_err());
    }
}
