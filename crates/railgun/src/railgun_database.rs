use kohaku_kv_store::{Store, backend::StoreError};
use serde::{Deserialize, Serialize};

use crate::{
    account::address::RailgunAddress,
    indexer::{
        indexed_account::IndexedAccountState, txid_indexer::TxidIndexerState,
        utxo_indexer::UtxoIndexerState,
    },
    merkle_tree::MerkleTreeState,
    poi::provider::PoiProviderState,
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
    async fn set_utxo_indexer(&self, state: &UtxoIndexerState) -> Result<(), DatabaseError>;
    async fn get_account(
        &self,
        addr: &RailgunAddress,
    ) -> Result<IndexedAccountState, DatabaseError>;
    async fn set_account(
        &self,
        addr: &RailgunAddress,
        state: &IndexedAccountState,
    ) -> Result<(), DatabaseError>;
    async fn get_utxo_tree(
        &self,
        tree_number: u32,
    ) -> Result<Option<MerkleTreeState>, DatabaseError>;
    async fn set_utxo_tree(
        &self,
        tree_number: u32,
        state: MerkleTreeState,
    ) -> Result<(), DatabaseError>;
    async fn get_txid_indexer(&self) -> Result<TxidIndexerState, DatabaseError>;
    async fn set_txid_indexer(&self, state: &TxidIndexerState) -> Result<(), DatabaseError>;
    async fn get_txid_tree(
        &self,
        tree_number: u32,
    ) -> Result<Option<MerkleTreeState>, DatabaseError>;
    async fn set_txid_tree(
        &self,
        tree_number: u32,
        state: MerkleTreeState,
    ) -> Result<(), DatabaseError>;
    async fn get_poi_provider(&self) -> Result<PoiProviderState, DatabaseError>;
    async fn set_poi_provider(&self, state: &PoiProviderState) -> Result<(), DatabaseError>;
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

    async fn set_utxo_indexer(&self, state: &UtxoIndexerState) -> Result<(), DatabaseError> {
        write_envelope(self, &utxo_indexer_key(), 1, state).await
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

    async fn set_utxo_tree(
        &self,
        tree_number: u32,
        state: MerkleTreeState,
    ) -> Result<(), DatabaseError> {
        write_envelope(self, &utxo_tree_key(tree_number), 1, &state)
            .await
    }

    async fn get_txid_indexer(&self) -> Result<TxidIndexerState, DatabaseError> {
        let key = txid_indexer_key();
        let Some(bytes) = self.get(&key).await? else {
            return Ok(Default::default());
        };

        deserialize_envelope(&bytes, 1)
    }

    async fn set_txid_indexer(&self, state: &TxidIndexerState) -> Result<(), DatabaseError> {
        write_envelope(self, &txid_indexer_key(), 1, state).await
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

    async fn set_txid_tree(
        &self,
        tree_number: u32,
        state: MerkleTreeState,
    ) -> Result<(), DatabaseError> {
        write_envelope(self, &txid_tree_key(tree_number), 1, &state)
            .await
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
