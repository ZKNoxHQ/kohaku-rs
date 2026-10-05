use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use crate::PirProviderError;

/// Blocking key lookup used by the router (wrapped in `spawn_blocking`).
///
/// Live PIR is a `LookupBackend` you provide (typically wrapping
/// `pir_client::PirClient` from inspire-gpu-serving). This crate does not
/// depend on that repo, so kohaku-rs CI stays self-contained.
pub trait LookupBackend: Send + Sync {
    /// Return the raw value bytes for `key`, or `None` if the key is absent.
    ///
    /// # Errors
    ///
    /// Returns [`PirProviderError::Client`] when the lookup fails.
    fn lookup(&self, key: &[u8]) -> Result<Option<Vec<u8>>, PirProviderError>;

    /// Look up many keys. Default loops [`lookup`](Self::lookup); backends that
    /// can amortize round-trips should override this.
    ///
    /// # Errors
    ///
    /// Returns [`PirProviderError::Client`] when the batch lookup fails.
    fn lookup_batch(
        &self,
        keys: &[Vec<u8>],
    ) -> Result<Vec<Option<Vec<u8>>>, PirProviderError> {
        keys.iter().map(|k| self.lookup(k)).collect()
    }
}

/// In-memory lookup for tests.
#[derive(Default)]
pub struct MapLookup {
    /// Raw PIR key → value bytes.
    pub entries: Mutex<HashMap<Vec<u8>, Vec<u8>>>,
}

impl MapLookup {
    /// Insert a key/value pair.
    pub fn insert(&self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.as_ref().to_vec(), value.as_ref().to_vec());
    }
}

impl LookupBackend for MapLookup {
    fn lookup(&self, key: &[u8]) -> Result<Option<Vec<u8>>, PirProviderError> {
        Ok(self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned())
    }
}
