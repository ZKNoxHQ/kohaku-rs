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

        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(DatabaseError::other)?;
        match envelope.v {
            1 => Ok(serde_json::from_value(envelope.data).map_err(DatabaseError::other)?),
            v => Err(DatabaseError::UnsupportedVersion(v)),
        }
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

        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(DatabaseError::other)?;
        match envelope.v {
            1 => Ok(serde_json::from_value(envelope.data).map_err(DatabaseError::other)?),
            v => Err(DatabaseError::UnsupportedVersion(v)),
        }
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

        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(DatabaseError::other)?;
        match envelope.v {
            1 => Ok(Some(
                serde_json::from_value(envelope.data).map_err(DatabaseError::other)?,
            )),
            v => Err(DatabaseError::UnsupportedVersion(v)),
        }
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

        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(DatabaseError::other)?;
        match envelope.v {
            1 => Ok(serde_json::from_value(envelope.data).map_err(DatabaseError::other)?),
            v => Err(DatabaseError::UnsupportedVersion(v)),
        }
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

        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(DatabaseError::other)?;
        match envelope.v {
            1 => Ok(Some(
                serde_json::from_value(envelope.data).map_err(DatabaseError::other)?,
            )),
            v => Err(DatabaseError::UnsupportedVersion(v)),
        }
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

        let envelope: Envelope = serde_json::from_slice(&bytes).map_err(DatabaseError::other)?;
        match envelope.v {
            1 => Ok(serde_json::from_value(envelope.data).map_err(DatabaseError::other)?),
            v => Err(DatabaseError::UnsupportedVersion(v)),
        }
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

#[derive(Serialize, Deserialize)]
struct Envelope {
    pub v: u32,
    pub data: serde_json::Value,
}

fn serialize_envelope<T: Serialize>(version: u32, data: &T) -> Result<Vec<u8>, DatabaseError> {
    let envelope = Envelope {
        v: version,
        data: serde_json::to_value(data).map_err(DatabaseError::other)?,
    };
    Ok(serde_json::to_vec(&envelope).map_err(DatabaseError::other)?)
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
