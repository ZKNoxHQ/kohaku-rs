use kohaku_kv_store::{Store, backend::StoreError};
use serde::{Deserialize, Serialize};

use crate::{
    account::address::RailgunAddress,
    indexer::{
        indexed_account::IndexedAccountState, txid_indexer::TxidIndexerState,
        utxo_indexer::UtxoIndexerState,
    },
    merkle_tree::{MerkleTreeState, PoiMerkleTreeState, PoiSyncState},
    poi::{provider::PoiProviderState, types::ListKey},
};

/// Errors from Railgun typed database helpers.
#[derive(Debug, thiserror::Error)]
pub enum DatabaseError {
    #[error("Unsupported version: {0}")]
    UnsupportedVersion(u32),
    #[error("Storage error: {0}")]
    Storage(#[from] StoreError),
    #[error("Other error: {0}")]
    Other(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl DatabaseError {
    pub fn other(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        DatabaseError::Other(Box::new(e))
    }
}

/// Railgun-specific typed persistence helpers over [`Store`].
#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
pub trait RailgunDB: crate::common::MaybeSend {
    async fn get_utxo_indexer(&self) -> Result<UtxoIndexerState, DatabaseError>;
    async fn get_account(
        &self,
        addr: &RailgunAddress,
    ) -> Result<IndexedAccountState, DatabaseError>;
    #[cfg(test)]
    async fn set_account(
        &self,
        addr: &RailgunAddress,
        state: &IndexedAccountState,
    ) -> Result<(), DatabaseError>;
    async fn get_utxo_tree(
        &self,
        tree_number: u32,
    ) -> Result<Option<MerkleTreeState>, DatabaseError>;
    async fn get_txid_indexer(&self) -> Result<TxidIndexerState, DatabaseError>;
    async fn get_txid_tree(
        &self,
        tree_number: u32,
    ) -> Result<Option<MerkleTreeState>, DatabaseError>;
    async fn get_poi_provider(&self) -> Result<PoiProviderState, DatabaseError>;
    async fn set_poi_provider(&self, state: &PoiProviderState) -> Result<(), DatabaseError>;
    async fn get_poi_tree(
        &self,
        list_key: &ListKey,
        tree_number: u32,
    ) -> Result<Option<PoiMerkleTreeState>, DatabaseError>;
    async fn get_poi_sync(&self, list_key: &ListKey) -> Result<PoiSyncState, DatabaseError>;
}

#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
impl RailgunDB for Store {
    async fn get_utxo_indexer(&self) -> Result<UtxoIndexerState, DatabaseError> {
        let key = utxo_indexer_key();
        let Some(bytes) = self.get(&key).await? else {
            return Ok(Default::default());
        };

        deserialize_envelope(&bytes, 1)
    }

    async fn get_account(
        &self,
        addr: &RailgunAddress,
    ) -> Result<IndexedAccountState, DatabaseError> {
        let key = account_key(addr);
        let Some(bytes) = self.get(&key).await? else {
            return Ok(Default::default());
        };

        deserialize_envelope(&bytes, 1)
    }

    #[cfg(test)]
    async fn set_account(
        &self,
        addr: &RailgunAddress,
        state: &IndexedAccountState,
    ) -> Result<(), DatabaseError> {
        write_envelope(self, &account_key(addr), 1, state).await
    }

    async fn get_utxo_tree(
        &self,
        tree_number: u32,
    ) -> Result<Option<MerkleTreeState>, DatabaseError> {
        let key = utxo_tree_key(tree_number);
        let Some(bytes) = self.get(&key).await? else {
            return Ok(None);
        };

        deserialize_envelope(&bytes, 1).map(Some)
    }

    async fn get_txid_indexer(&self) -> Result<TxidIndexerState, DatabaseError> {
        let key = txid_indexer_key();
        let Some(bytes) = self.get(&key).await? else {
            return Ok(Default::default());
        };

        deserialize_envelope(&bytes, 1)
    }

    async fn get_txid_tree(
        &self,
        tree_number: u32,
    ) -> Result<Option<MerkleTreeState>, DatabaseError> {
        let key = txid_tree_key(tree_number);
        let Some(bytes) = self.get(&key).await? else {
            return Ok(None);
        };

        deserialize_envelope(&bytes, 1).map(Some)
    }

    async fn get_poi_provider(&self) -> Result<PoiProviderState, DatabaseError> {
        let key = poi_provider_key();
        let Some(bytes) = self.get(&key).await? else {
            return Ok(Default::default());
        };

        deserialize_envelope(&bytes, 1)
    }

    async fn set_poi_provider(&self, state: &PoiProviderState) -> Result<(), DatabaseError> {
        write_envelope(self, &poi_provider_key(), 1, state).await
    }

    async fn get_poi_tree(
        &self,
        list_key: &ListKey,
        tree_number: u32,
    ) -> Result<Option<PoiMerkleTreeState>, DatabaseError> {
        let key = poi_tree_key(list_key, tree_number);
        let Some(bytes) = self.get(&key).await? else {
            return Ok(None);
        };

        deserialize_envelope(&bytes, 1).map(Some)
    }

    async fn get_poi_sync(&self, list_key: &ListKey) -> Result<PoiSyncState, DatabaseError> {
        let key = poi_sync_key(list_key);
        let Some(bytes) = self.get(&key).await? else {
            return Ok(PoiSyncState::default());
        };

        deserialize_envelope(&bytes, 1)
    }
}

async fn write_envelope<S: Serialize>(
    store: &Store,
    key: &[u8],
    version: u32,
    data: &S,
) -> Result<(), DatabaseError> {
    let bytes = serialize_envelope(version, data)?;
    store.put(key, &bytes).await?;
    Ok(())
}

/// Position maps and trees describe one TXID snapshot. Writing trees first can
/// leave extra leaves with no position mappings if the final checkpoint write
/// fails. The store's atomic batch commits all existing version-1 envelopes together.
pub(crate) async fn write_txid_snapshot(
    store: &Store,
    state: &TxidIndexerState,
    trees: &[(u32, MerkleTreeState)],
) -> Result<(), DatabaseError> {
    let mut writes = Vec::with_capacity(trees.len() + 1);
    for (number, tree) in trees {
        writes.push((txid_tree_key(*number), serialize_envelope(1, tree)?));
    }
    writes.push((txid_indexer_key(), serialize_envelope(1, state)?));
    store.put_batch(writes).await?;
    Ok(())
}

/// One verified UTXO snapshot, including account notes and every cursor. The existing
/// version-1 keys/envelopes are unchanged; `Store::put_batch` requires atomicity.
pub(crate) async fn write_utxo_snapshot(
    store: &Store,
    state: &UtxoIndexerState,
    trees: &[(u32, MerkleTreeState)],
    accounts: &[(RailgunAddress, IndexedAccountState)],
) -> Result<(), DatabaseError> {
    let mut writes = Vec::with_capacity(trees.len() + accounts.len() + 1);
    for (number, tree) in trees {
        writes.push((utxo_tree_key(*number), serialize_envelope(1, tree)?));
    }
    for (address, account) in accounts {
        writes.push((account_key(address), serialize_envelope(1, account)?));
    }
    writes.push((utxo_indexer_key(), serialize_envelope(1, state)?));
    store.put_batch(writes).await?;
    Ok(())
}

/// One copied POI page. Trees and the cursor commit together, matching
/// [`write_txid_snapshot`]: a crash cannot leave new leaves behind an old cursor.
pub(crate) async fn write_poi_snapshot(
    store: &Store,
    list_key: &ListKey,
    next_index: u64,
    trees: &[(u32, PoiMerkleTreeState)],
) -> Result<(), DatabaseError> {
    let mut writes = Vec::with_capacity(trees.len() + 1);
    for (number, tree) in trees {
        writes.push((
            poi_tree_key(list_key, *number),
            serialize_envelope(1, tree)?,
        ));
    }
    writes.push((
        poi_sync_key(list_key),
        serialize_envelope(1, &PoiSyncState { next_index })?,
    ));
    store.put_batch(writes).await?;
    Ok(())
}

/// Stored layout: `{"v": <version>, "data": <state>}`.
///
/// Written and read straight to and from `T`, never through `serde_json::Value`, which cannot
/// hold an integer above `u64::MAX`: a note worth more than 18.44 units of an 18-decimal token
/// made every account save fail with "number out of range" (the sync then stopped, and the synced
/// block was never persisted). Same bytes on disk as before for values that fit.
#[derive(Serialize)]
struct EnvelopeRef<'a, T> {
    v: u32,
    data: &'a T,
}

#[derive(Deserialize)]
struct EnvelopeVersion {
    v: u32,
}

#[derive(Deserialize)]
struct Envelope<T> {
    data: T,
}

fn serialize_envelope<T: Serialize>(version: u32, data: &T) -> Result<Vec<u8>, DatabaseError> {
    serde_json::to_vec(&EnvelopeRef { v: version, data }).map_err(DatabaseError::other)
}

fn deserialize_envelope<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    version: u32,
) -> Result<T, DatabaseError> {
    let EnvelopeVersion { v } = serde_json::from_slice(bytes).map_err(DatabaseError::other)?;
    if v != version {
        return Err(DatabaseError::UnsupportedVersion(v));
    }
    let envelope: Envelope<T> = serde_json::from_slice(bytes).map_err(DatabaseError::other)?;
    Ok(envelope.data)
}

fn utxo_indexer_key() -> Vec<u8> {
    b"utxo_indexer".to_vec()
}

fn account_key(addr: &RailgunAddress) -> Vec<u8> {
    format!("account:{}", addr).into_bytes()
}

fn utxo_tree_key(tree_number: u32) -> Vec<u8> {
    format!("utxo_tree:{}", tree_number).into_bytes()
}

fn txid_indexer_key() -> Vec<u8> {
    b"txid_indexer".to_vec()
}

fn txid_tree_key(tree_number: u32) -> Vec<u8> {
    format!("txid_tree:{}", tree_number).into_bytes()
}

fn poi_provider_key() -> Vec<u8> {
    b"poi_provider".to_vec()
}

fn poi_tree_key(list_key: &ListKey, tree_number: u32) -> Vec<u8> {
    let list_key = String::from(list_key.clone());
    format!("poi_tree:{list_key}:{tree_number}").into_bytes()
}

fn poi_sync_key(list_key: &ListKey) -> Vec<u8> {
    let list_key = String::from(list_key.clone());
    format!("poi_sync:{list_key}").into_bytes()
}

#[cfg(test)]
mod envelope_tests {
    use super::*;

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Note {
        value: u128,
        tree: u32,
    }

    /// 56.5 WETH in wei is above `u64::MAX`: the envelope must keep it exactly.
    #[test]
    fn large_note_values_round_trip() {
        let note = Note {
            value: 56_502_370_000_000_000_000,
            tree: 1,
        };
        let bytes = serialize_envelope(1, &note).unwrap();
        assert_eq!(deserialize_envelope::<Note>(&bytes, 1).unwrap(), note);
        assert!(matches!(
            deserialize_envelope::<Note>(&bytes, 2),
            Err(DatabaseError::UnsupportedVersion(1))
        ));
        // Data written by earlier versions (through serde_json::Value) still reads.
        let old = br#"{"v":1,"data":{"value":1000,"tree":0}}"#;
        assert_eq!(
            deserialize_envelope::<Note>(old, 1).unwrap(),
            Note {
                value: 1000,
                tree: 0
            }
        );
    }
}
