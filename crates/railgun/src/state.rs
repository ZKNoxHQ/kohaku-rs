//! In-memory Railgun state and caller-owned persistence snapshots.
//!
//! Clone the handle before passing it to `RailgunBuilder::with_state`. Export a
//! snapshot after each completed operation that changes state, and save it using
//! the application's persistence layer. Restore it before rebuilding the provider.
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use serde::{Deserialize, Serialize};

/// A complete, versioned checkpoint of Railgun's in-memory state.
///
/// Serialize this value with serde and save it atomically as one document. It
/// includes unencrypted notes; applications are responsible for protecting it.
/// Keep separate snapshots for each chain and wallet. Private keys are excluded.
#[derive(Clone, Serialize, Deserialize)]
pub struct RailgunSnapshot {
    version: u32,
    // A sequence keeps binary keys compatible with JSON and other serde formats.
    entries: Vec<(Vec<u8>, Vec<u8>)>,
}

/// Shared in-memory state. Clones refer to the same state; restored snapshots are
/// independent. Each validated tree/account/cursor batch is published atomically.
///
/// This type performs no disk or network I/O. Only complete snapshots are exposed
/// publicly, so applications cannot accidentally persist half of a batch.
#[derive(Clone, Default)]
pub struct RailgunState {
    entries: Arc<RwLock<BTreeMap<Vec<u8>, Vec<u8>>>>,
    #[cfg(test)]
    backend: Option<Arc<dyn test_support::backend::StateBackend>>,
}

#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error("Unsupported Railgun snapshot version: {0}")]
    UnsupportedVersion(u32),
    #[error("Railgun state lock poisoned")]
    Poisoned,
    #[cfg(test)]
    #[error(transparent)]
    Injected(#[from] test_support::backend::StateWriteError),
    #[cfg(test)]
    #[error("Snapshots are not supported by injected test backends")]
    TestBackendSnapshot,
}

impl RailgunState {
    /// Restores an independent state handle from a previously exported snapshot.
    pub fn from_snapshot(snapshot: RailgunSnapshot) -> Result<Self, StateError> {
        if snapshot.version != 1 {
            return Err(StateError::UnsupportedVersion(snapshot.version));
        }
        Ok(Self {
            entries: Arc::new(RwLock::new(snapshot.entries.into_iter().collect())),
            #[cfg(test)]
            backend: None,
        })
    }

    /// Exports all committed state under one read lock. Save the resulting value
    /// atomically; a partial external write must not replace the last checkpoint.
    pub fn snapshot(&self) -> Result<RailgunSnapshot, StateError> {
        #[cfg(test)]
        if self.backend.is_some() {
            return Err(StateError::TestBackendSnapshot);
        }
        let entries = self.entries.read().map_err(|_| StateError::Poisoned)?;
        Ok(RailgunSnapshot {
            version: 1,
            entries: entries
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        })
    }

    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_async,
            reason = "Async shape supports test failure and cancellation injection"
        )
    )]
    pub(crate) async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StateError> {
        #[cfg(test)]
        if let Some(backend) = &self.backend {
            return Ok(backend
                .get_batch(&[key])
                .await?
                .into_iter()
                .next()
                .flatten());
        }
        Ok(self
            .entries
            .read()
            .map_err(|_| StateError::Poisoned)?
            .get(key)
            .cloned())
    }

    pub(crate) async fn put(&self, key: &[u8], value: &[u8]) -> Result<(), StateError> {
        self.put_batch(vec![(key.to_vec(), value.to_vec())]).await
    }

    #[cfg_attr(
        not(test),
        expect(
            clippy::unused_async,
            reason = "Async shape supports test failure and cancellation injection"
        )
    )]
    pub(crate) async fn put_batch(
        &self,
        entries: Vec<(Vec<u8>, Vec<u8>)>,
    ) -> Result<(), StateError> {
        #[cfg(test)]
        if let Some(backend) = &self.backend {
            let refs: Vec<_> = entries
                .iter()
                .map(|(k, v)| (k.as_slice(), v.as_slice()))
                .collect();
            return Ok(backend.put_batch(&refs).await?);
        }
        // No await inside the write lock: cancellation cannot split publication.
        self.entries
            .write()
            .map_err(|_| StateError::Poisoned)?
            .extend(entries);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn new(backend: impl test_support::backend::StateBackend + 'static) -> Self {
        Self {
            backend: Some(Arc::new(backend)),
            ..Self::default()
        }
    }
}

// Failure/cancellation injection belongs to tests, not the public persistence API.
#[cfg(test)]
pub(crate) mod test_support {
    pub mod backend {
        #[async_trait::async_trait]
        pub trait StateBackend: Send + Sync {
            async fn get_batch(
                &self,
                keys: &[&[u8]],
            ) -> Result<Vec<Option<Vec<u8>>>, StateWriteError>;
            async fn put_batch(&self, entries: &[(&[u8], &[u8])]) -> Result<(), StateWriteError>;
        }
        #[derive(Debug, thiserror::Error)]
        #[error(transparent)]
        pub struct StateWriteError(#[from] Box<dyn std::error::Error + Send + Sync>);
    }
    pub mod memory {
        use std::{collections::BTreeMap, sync::Mutex};

        use super::backend::{StateBackend, StateWriteError};
        #[derive(Default)]
        pub struct MemoryState(Mutex<BTreeMap<Vec<u8>, Vec<u8>>>);
        impl MemoryState {
            pub fn new() -> Self {
                Self::default()
            }
        }
        #[async_trait::async_trait]
        impl StateBackend for MemoryState {
            async fn get_batch(
                &self,
                keys: &[&[u8]],
            ) -> Result<Vec<Option<Vec<u8>>>, StateWriteError> {
                let entries = self.0.lock().unwrap();
                Ok(keys.iter().map(|k| entries.get(*k).cloned()).collect())
            }
            async fn put_batch(&self, entries: &[(&[u8], &[u8])]) -> Result<(), StateWriteError> {
                self.0
                    .lock()
                    .unwrap()
                    .extend(entries.iter().map(|(k, v)| (k.to_vec(), v.to_vec())));
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn serialized_snapshot_restores_whole_batches_independently() {
        let state = RailgunState::default();
        let handle = state.clone();
        state
            .put_batch(vec![
                (b"tree".to_vec(), b"leaves".to_vec()),
                (b"cursor".to_vec(), b"10".to_vec()),
            ])
            .await
            .unwrap();
        let bytes = serde_json::to_vec(&handle.snapshot().unwrap()).unwrap();
        let restored =
            RailgunState::from_snapshot(serde_json::from_slice(&bytes).unwrap()).unwrap();
        assert_eq!(
            restored.get(b"tree").await.unwrap(),
            Some(b"leaves".to_vec())
        );
        assert_eq!(restored.get(b"cursor").await.unwrap(), Some(b"10".to_vec()));
        state.put(b"cursor", b"20").await.unwrap();
        assert_eq!(handle.get(b"cursor").await.unwrap(), Some(b"20".to_vec()));
        assert_eq!(restored.get(b"cursor").await.unwrap(), Some(b"10".to_vec()));
    }

    #[test]
    fn rejects_unknown_snapshot_version() {
        let snapshot = RailgunSnapshot {
            version: 2,
            entries: vec![],
        };
        assert!(matches!(
            RailgunState::from_snapshot(snapshot),
            Err(StateError::UnsupportedVersion(2))
        ));
    }
}
