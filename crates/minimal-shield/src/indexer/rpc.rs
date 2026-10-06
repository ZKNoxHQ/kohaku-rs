use std::{sync::Arc, time::Duration};

use alloy::{primitives::B256, providers::Provider, rpc::types::Filter, sol_types::SolEvent};
use ruint::aliases::U256;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::{
    abis::ShieldedPool::{self, EpochRolled, LeafAppended, NoteSpent, RootPublished},
    indexer::{
        syncer::{SyncEvent, SyncerBackend, SyncerError},
        verifier::{VerifierBackend, VerifierError},
    },
    pool::Pool,
};

#[derive(Clone)]
pub struct RpcSyncer<P: Provider> {
    provider: P,
    batch_size: u64,
    batch_delay: Duration,
    progress: Option<Arc<dyn Fn(u64, u64) + Send + Sync>>,
}

impl<P: Provider> RpcSyncer<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            batch_size: logs_block_range(),
            batch_delay: logs_batch_delay(),
            progress: None,
        }
    }

    /// `progress(done, total)` is the blocks walked in this sync.
    #[must_use]
    pub fn with_progress(mut self, progress: impl Fn(u64, u64) + Send + Sync + 'static) -> Self {
        self.progress = Some(Arc::new(progress));
        self
    }
}

#[async_trait::async_trait]
impl<P: Provider> SyncerBackend for RpcSyncer<P> {
    async fn latest_block(&self, _pool: &Pool) -> Result<u64, SyncerError> {
        self.provider
            .get_block_number()
            .await
            .map_err(SyncerError::other)
    }

    async fn sync(
        &self,
        pool: &Pool,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<SyncEvent>, SyncerError> {
        Ok(self
            .fetch(pool, from_block, to_block)
            .await?
            .into_iter()
            .map(|logged| logged.event)
            .collect())
    }
}

/// One pool log, with the block it was mined in.
#[derive(Debug, Clone)]
pub struct LoggedEvent {
    pub block: u64,
    pub event: SyncEvent,
}

impl<P: Provider> RpcSyncer<P> {
    /// Logs in `from_block..=to_block`. `to_block` is included, matching [`SyncerBackend::sync`].
    pub async fn fetch(
        &self,
        pool: &Pool,
        from_block: u64,
        to_block: u64,
    ) -> Result<Vec<LoggedEvent>, SyncerError> {
        let from_block = from_block.max(pool.deployed_block);
        let span = to_block.saturating_sub(from_block).max(1);
        self.report(0, span);
        let mut all = Vec::new();
        let mut current = from_block;
        while current <= to_block {
            let end = to_block.min(current + self.batch_size - 1);
            let filter = Filter::new()
                .address(pool.address)
                .from_block(current)
                .to_block(end);
            let logs = self
                .provider
                .get_logs(&filter)
                .await
                .map_err(SyncerError::other)?;
            sleep(self.batch_delay).await;
            for log in &logs {
                let block = log.block_number.unwrap_or(end);
                match decode(log) {
                    Ok(evs) => all.extend(evs.into_iter().map(|event| LoggedEvent { block, event })),
                    Err(e) => warn!("skip log: {e}"),
                }
            }
            info!("{end}/{to_block} ({} events)", all.len());
            if end == to_block {
                break;
            }
            current = end + 1;
            self.report(current.saturating_sub(from_block).min(span), span);
        }
        self.report(span, span);
        Ok(all)
    }
}

fn logs_block_range() -> u64 {
    // Sparse pools finish faster with a wide range; override with RPC_LOGS_BLOCKRANGE.
    const DEFAULT: u64 = 50_000;
    match std::env::var("RPC_LOGS_BLOCKRANGE") {
        Ok(raw) => match raw.parse::<u64>() {
            Ok(n) if n > 0 => n,
            _ => {
                warn!("RPC_LOGS_BLOCKRANGE={raw} is not a positive integer; using {DEFAULT}");
                DEFAULT
            }
        },
        Err(_) => DEFAULT,
    }
}

fn logs_batch_delay() -> Duration {
    match std::env::var("RPC_LOGS_BATCH_DELAY_MS") {
        Ok(raw) => match raw.parse::<u64>() {
            Ok(0) => Duration::from_millis(0),
            Ok(n) => Duration::from_millis(n),
            _ => Duration::from_millis(0),
        },
        // Hegota's pool is sparse; the old 200ms pause dominated first sync.
        Err(_) => Duration::from_millis(0),
    }
}

impl<P: Provider> RpcSyncer<P> {
    fn report(&self, done: u64, total: u64) {
        if let Some(progress) = &self.progress {
            progress(done, total);
        }
    }
}

#[async_trait::async_trait]
impl<P: Provider> VerifierBackend for RpcSyncer<P> {
    async fn verify(&self, pool: &Pool, root: U256) -> Result<(), VerifierError> {
        let instance = ShieldedPool::new(pool.address, &self.provider);
        let onchain: B256 = instance
            .currentRoot()
            .call()
            .await
            .map_err(VerifierError::other)?;
        let onchain = U256::from_be_bytes(onchain.0);
        if onchain == root {
            Ok(())
        } else {
            Err(VerifierError::InvalidRoot { root })
        }
    }
}

fn decode(log: &alloy::rpc::types::Log) -> Result<Vec<SyncEvent>, alloy::sol_types::Error> {
    let topic = log.topics().first().copied();
    if topic == Some(LeafAppended::SIGNATURE_HASH) {
        let ev = LeafAppended::decode_log(&log.inner)?.data;
        return Ok(vec![SyncEvent::LeafAppended {
            cm: u256(ev.cm),
            epoch: ev.epoch,
            index: ev.index,
            new_root: u256(ev.newRoot),
        }]);
    }
    if topic == Some(EpochRolled::SIGNATURE_HASH) {
        let ev = EpochRolled::decode_log(&log.inner)?.data;
        return Ok(vec![SyncEvent::EpochRolled {
            closed: ev.closedEpoch,
            new_epoch: ev.newEpoch,
        }]);
    }
    if topic == Some(NoteSpent::SIGNATURE_HASH) {
        let ev = NoteSpent::decode_log(&log.inner)?.data;
        return Ok(vec![SyncEvent::NoteSpent { nf: u256(ev.nf) }]);
    }
    if topic == Some(RootPublished::SIGNATURE_HASH) {
        let ev = RootPublished::decode_log(&log.inner)?.data;
        return Ok(vec![SyncEvent::RootPublished { epoch: ev.epoch }]);
    }
    Ok(vec![])
}

fn u256(h: alloy::primitives::FixedBytes<32>) -> U256 {
    U256::from_be_bytes(h.0)
}
