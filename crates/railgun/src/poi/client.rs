use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use alloy::primitives::ChainId;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

use crate::{
    merkle_tree::{MerkleProof, MerkleRoot, MerkleTreeVerifier},
    poi::types::{
        BlindedCommitment, BlindedCommitmentData, BlindedCommitmentType, ChainParams,
        GetMerkleProofsParams, GetPoisPerListParams, ListKey, PoiStatus, PoisPerListMap,
        SubmitTransactProofParams, TransactProofData, TxidVersion, ValidateTxidMerklerootParams,
        ValidatedRailgunTxidStatus,
    },
};

#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
pub trait PoiNodeClient {
    fn list_keys(&self) -> Vec<ListKey>;
    async fn poi_status(
        &self,
        list_key: &ListKey,
        blinded_commitment: BlindedCommitment,
        commitment_type: BlindedCommitmentType,
    ) -> Result<PoiStatus, PoiClientError>;
    async fn merkle_proof(
        &self,
        list_key: &ListKey,
        blinded_commitment: BlindedCommitment,
    ) -> Result<MerkleProof, PoiClientError>;
    async fn submit_proof(
        &self,
        proof_data: HashMap<ListKey, TransactProofData>,
    ) -> Result<(), PoiClientError>;
    async fn validated_txid(&self) -> Result<ValidatedRailgunTxidStatus, PoiClientError>;
    async fn validate_txid_merkleroot(
        &self,
        tree: u32,
        index: u32,
        merkleroot: MerkleRoot,
    ) -> Result<bool, PoiClientError>;
}

#[derive(Clone)]
pub struct PoiClient {
    inner: Arc<PoiClientInner>,
    list_keys: Vec<ListKey>,
}

pub struct PoiClientInner {
    http: reqwest::Client,
    url: String,
    next_id: AtomicU64,

    chain: ChainId,
}

#[derive(Debug, Error)]
pub enum PoiClientError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON-RPC error: {0}")]
    Rpc(JsonRpcError),
    #[error("Null result from RPC")]
    NullResult,
    #[error("Unexpected response: {0}")]
    UnexpectedResponse(String),
    #[error("Invalid POI Merkle root for list key {0:?}: {1}")]
    InvalidPoiMerkleRoot(ListKey, MerkleRoot),
    #[error("Proof not found for blinded commitment {1:?} and list key {0:?}")]
    ProofNotFound(ListKey, BlindedCommitment),
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest<P: Serialize> {
    jsonrpc: &'static str,
    method: &'static str,
    id: u64,
    params: P,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse<R> {
    jsonrpc: String,
    id: u64,
    result: Option<R>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<serde_json::Value>,
}

impl PoiClient {
    pub fn new(chain: ChainId, url: impl Into<String>, list_keys: Vec<ListKey>) -> Self {
        let next_id = AtomicU64::new(1);
        let http = reqwest::Client::new();
        let url = url.into();

        Self {
            inner: Arc::new(PoiClientInner {
                http,
                url,
                next_id,
                chain,
            }),
            list_keys,
        }
    }

    fn chain(&self) -> ChainParams {
        ChainParams {
            chain_type: 0.to_string(), // EVM
            chain_id: self.inner.chain.to_string(),
            txid_version: TxidVersion::V2PoseidonMerkle,
        }
    }
}

#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
impl PoiNodeClient for PoiClient {
    fn list_keys(&self) -> Vec<ListKey> {
        self.list_keys.clone()
    }

    /// Returns the POI status for a given list key and blinded commitment.
    ///  
    /// NOTE: Fetches a single status rather than batching many blinded commitments
    /// because I don't know how the POI node handles partial failures in a batch.
    async fn poi_status(
        &self,
        list_key: &ListKey,
        blinded_commitment: BlindedCommitment,
        commitment_type: BlindedCommitmentType,
    ) -> Result<PoiStatus, PoiClientError> {
        let mut pois_per_list: PoisPerListMap = self
            .call(
                "ppoi_pois_per_list",
                GetPoisPerListParams {
                    chain: self.chain(),
                    list_keys: vec![list_key.clone()],
                    blinded_commitment_datas: vec![BlindedCommitmentData {
                        blinded_commitment,
                        commitment_type,
                    }],
                },
            )
            .await?;

        let mut list_key_map = pois_per_list
            .remove(&blinded_commitment)
            .ok_or_else(|| PoiClientError::ProofNotFound(list_key.clone(), blinded_commitment))?;

        let poi_status = list_key_map
            .remove(list_key)
            .ok_or_else(|| PoiClientError::ProofNotFound(list_key.clone(), blinded_commitment))?;
        Ok(poi_status.into())
    }

    /// Returns the Merkle proof for a given list key and blinded commitment.
    ///
    /// NOTE: Fetches a single proof rather than batching many blinded commitments
    /// because I don't know how the POI node handles partial failures in a batch.
    async fn merkle_proof(
        &self,
        list_key: &ListKey,
        blinded_commitment: BlindedCommitment,
    ) -> Result<MerkleProof, PoiClientError> {
        let proofs: Vec<MerkleProof> = self
            .call(
                "ppoi_merkle_proofs",
                GetMerkleProofsParams {
                    chain: self.chain(),
                    list_key: list_key.clone(),
                    blinded_commitments: vec![blinded_commitment],
                },
            )
            .await?;

        let proof = proofs
            .into_iter()
            .next()
            .ok_or_else(|| PoiClientError::ProofNotFound(list_key.clone(), blinded_commitment))?;

        Ok(proof)
    }

    /// Submits a proved transaction to the POI node.
    async fn submit_proof(
        &self,
        proof_data: HashMap<ListKey, TransactProofData>,
    ) -> Result<(), PoiClientError> {
        for (list_key, proof_data) in proof_data {
            let resp: Result<(), PoiClientError> = self
                .call(
                    "ppoi_submit_transact_proof",
                    SubmitTransactProofParams {
                        chain: self.chain(),
                        list_key: list_key.clone(),
                        transact_proof_data: proof_data,
                    },
                )
                .await;

            match resp {
                Ok(_) => {}
                Err(PoiClientError::NullResult) => {}
                Err(e) => {
                    return Err(e);
                }
            }
        }

        Ok(())
    }

    /// Returns the current validated txid status from the POI node.
    async fn validated_txid(&self) -> Result<ValidatedRailgunTxidStatus, PoiClientError> {
        self.call("ppoi_validated_txid", self.chain()).await
    }

    /// Validates a txid merkle root against the POI node.
    async fn validate_txid_merkleroot(
        &self,
        tree: u32,
        index: u32,
        merkleroot: MerkleRoot,
    ) -> Result<bool, PoiClientError> {
        self.call(
            "ppoi_validate_txid_merkleroot",
            ValidateTxidMerklerootParams {
                chain: self.chain(),
                tree,
                index,
                merkleroot,
            },
        )
        .await
    }
}

#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
impl MerkleTreeVerifier for PoiClient {
    async fn verify_root(
        &self,
        tree_number: u32,
        tree_index: u32,
        root: MerkleRoot,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(self
            .validate_txid_merkleroot(tree_number, tree_index, root)
            .await?)
    }
}

impl PoiClient {
    async fn call<P: Serialize, R: DeserializeOwned>(
        &self,
        method: &'static str,
        params: P,
    ) -> Result<R, PoiClientError> {
        call(
            &self.inner.next_id,
            &self.inner.http,
            &self.inner.url,
            method,
            params,
        )
        .await
    }
}

async fn call<P: Serialize, R: DeserializeOwned>(
    next_id: &AtomicU64,
    http: &reqwest::Client,
    url: &str,
    method: &'static str,
    params: P,
) -> Result<R, PoiClientError> {
    let id = next_id.fetch_add(1, Ordering::Relaxed);
    let req = JsonRpcRequest {
        jsonrpc: "2.0",
        method,
        id,
        params,
    };

    // let req_json = serde_json::to_string(&req).unwrap();
    // info!("Sending JSON-RPC request: {}", req_json);

    let resp: JsonRpcResponse<R> = http.post(url).json(&req).send().await?.json().await?;
    if resp.jsonrpc != "2.0" || resp.id != id {
        return Err(PoiClientError::UnexpectedResponse(
            "JSON-RPC version or request id mismatch".to_owned(),
        ));
    }
    if let Some(err) = resp.error {
        return Err(PoiClientError::Rpc(err));
    }
    resp.result.ok_or(PoiClientError::NullResult)
}

impl std::fmt::Display for JsonRpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RPC error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for JsonRpcError {}

#[cfg(all(test, native))]
mod response_tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::{Duration, timeout},
    };

    /// One bounded loopback exchange. No live service, profile or owned data.
    async fn exchange<R: DeserializeOwned>(
        method: &'static str,
        body: serde_json::Value,
    ) -> Result<R, PoiClientError> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = timeout(Duration::from_secs(5), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            loop {
                let n = timeout(Duration::from_secs(5), socket.read(&mut buffer))
                    .await
                    .unwrap()
                    .unwrap();
                assert!(n > 0 && request.len() + n <= 4096);
                request.extend_from_slice(&buffer[..n]);
                if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&request[..end]).unwrap();
                    let length: usize = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse().unwrap())
                        })
                        .unwrap();
                    if request.len() >= end + 4 + length {
                        let sent: serde_json::Value =
                            serde_json::from_slice(&request[end + 4..]).unwrap();
                        assert_eq!(sent["id"], 1);
                        assert_eq!(sent["method"], method);
                        break;
                    }
                }
            }
            let body = body.to_string();
            let wire = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(wire.as_bytes()).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let result = call(&AtomicU64::new(1), &client, &url, method, ()).await;
        server.await.unwrap();
        result
    }

    async fn response(
        body: serde_json::Value,
    ) -> Result<ValidatedRailgunTxidStatus, PoiClientError> {
        exchange("ppoi_validated_txid", body).await
    }

    #[tokio::test]
    async fn matched_response_is_accepted() {
        let result = response(
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"validatedTxidIndex": 42}}),
        )
        .await
        .unwrap();
        assert_eq!(result.index, 42);
    }

    #[tokio::test]
    async fn unrelated_response_id_is_refused() {
        let result = response(
            serde_json::json!({"jsonrpc": "2.0", "id": 2, "result": {"validatedTxidIndex": 42}}),
        )
        .await;
        assert!(matches!(result, Err(PoiClientError::UnexpectedResponse(_))));
    }

    #[tokio::test]
    async fn wrong_jsonrpc_version_is_refused() {
        let result = response(
            serde_json::json!({"jsonrpc": "1.0", "id": 1, "result": {"validatedTxidIndex": 42}}),
        )
        .await;
        assert!(matches!(result, Err(PoiClientError::UnexpectedResponse(_))));
    }

    #[tokio::test]
    async fn matched_rpc_error_is_preserved() {
        let result = response(serde_json::json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "Invalid params"}})).await;
        assert!(matches!(
            result,
            Err(PoiClientError::Rpc(JsonRpcError { code: -32602, .. }))
        ));
    }

    #[tokio::test]
    async fn unrelated_rpc_error_is_refused() {
        let result = response(serde_json::json!({"jsonrpc": "2.0", "id": 2, "error": {"code": -32602, "message": "Invalid params"}})).await;
        assert!(matches!(result, Err(PoiClientError::UnexpectedResponse(_))));
    }

    #[tokio::test]
    async fn matched_void_submit_response_keeps_null_result_semantics() {
        let result = exchange::<()>(
            "ppoi_submit_transact_proof",
            serde_json::json!({"jsonrpc": "2.0", "id": 1}),
        )
        .await;
        // submit_proof maps this existing outcome to success. This is not a POI
        // acceptance verdict; owned status must be observed separately.
        assert!(matches!(result, Err(PoiClientError::NullResult)));
    }

    #[tokio::test]
    async fn void_response_is_not_a_validated_txid() {
        let result = response(serde_json::json!({"jsonrpc": "2.0", "id": 1})).await;
        assert!(matches!(result, Err(PoiClientError::NullResult)));
    }
}
