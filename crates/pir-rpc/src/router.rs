use std::sync::Arc;

use serde_json::Value;
use tracing::debug;

use crate::{
    DatasetManifest, FallbackRpc, LookupBackend, MapFallback, MapLookup, PirDecode, PirOp,
    PirProviderError, PlannedOp, Route, RouteTable,
    routes::{encode_bytes, encode_qty, encode_uint256, encode_zero, parse_address_param},
};

/// Hybrid router: PIR allowlist + JSON-RPC fallback.
pub struct PirRouter {
    lookup: Arc<dyn LookupBackend>,
    fallback: Arc<dyn FallbackRpc>,
    routes: RouteTable,
}

impl PirRouter {
    /// Wrap a lookup backend with HTTP JSON-RPC fallback.
    ///
    /// `lookup` is how PIR bytes are fetched (remote `pir-client` wrapper, or
    /// a test map). `rpc_url` is the ordinary Ethereum node.
    ///
    /// # Errors
    ///
    /// Returns [`PirProviderError::InvalidUrl`] if `rpc_url` is not a valid HTTP URL.
    pub fn with_rpc(
        lookup: Arc<dyn LookupBackend>,
        rpc_url: &str,
        datasets: Vec<DatasetManifest>,
    ) -> Result<Self, PirProviderError> {
        Ok(Self::from_parts(
            lookup,
            Arc::new(crate::HttpFallback::new(rpc_url)?),
            datasets,
        ))
    }

    /// Build a router from injected backends (tests, custom transports).
    #[must_use]
    pub fn from_parts(
        lookup: Arc<dyn LookupBackend>,
        fallback: Arc<dyn FallbackRpc>,
        datasets: Vec<DatasetManifest>,
    ) -> Self {
        Self {
            lookup,
            fallback,
            routes: RouteTable::from_datasets(datasets),
        }
    }

    /// Convenience constructor for in-memory tests.
    #[must_use]
    pub fn mock(lookup: MapLookup, fallback: MapFallback, datasets: Vec<DatasetManifest>) -> Self {
        Self::from_parts(Arc::new(lookup), Arc::new(fallback), datasets)
    }

    /// Routing table used for this router.
    #[must_use]
    pub const fn routes(&self) -> &RouteTable {
        &self.routes
    }

    /// Classify one JSON-RPC method into a PIR op or fallback.
    ///
    /// # Errors
    ///
    /// Returns [`PirProviderError::InvalidParams`] when a PIR-routed method has
    /// a malformed address / key.
    pub fn plan_request(&self, method: &str, params: &Value) -> Result<PlannedOp, PirProviderError> {
        let params = normalize_params(params);
        match self.routes.classify(method, &params) {
            Route::AccountBalance => {
                let key = parse_address_param(&params)?.to_vec();
                Ok(PlannedOp::Pir(PirOp {
                    key,
                    decode: PirDecode::AccountBalance,
                }))
            }
            Route::AccountNonce => {
                let key = parse_address_param(&params)?.to_vec();
                Ok(PlannedOp::Pir(PirOp {
                    key,
                    decode: PirDecode::AccountNonce,
                }))
            }
            Route::Call(m) => Ok(PlannedOp::Pir(PirOp {
                key: m.key,
                decode: PirDecode::Call {
                    value_encoding: m.value_encoding,
                },
            })),
            Route::Fallback => Ok(PlannedOp::Fallback),
        }
    }

    /// Classify many requests (same order as input).
    pub fn plan_requests<S: AsRef<str>>(
        &self,
        items: &[(S, Value)],
    ) -> Vec<Result<PlannedOp, PirProviderError>> {
        items
            .iter()
            .map(|(method, params)| self.plan_request(method.as_ref(), params))
            .collect()
    }

    /// Execute PIR ops via one [`LookupBackend::lookup_batch`], then decode.
    ///
    /// A PIR miss is **not** an error: account methods return `0x0`.
    ///
    /// # Errors
    ///
    /// Returns when the batch lookup worker fails. Per-item decode failures are
    /// returned inside the `Vec`.
    pub async fn execute_pir(
        &self,
        ops: &[PirOp],
    ) -> Result<Vec<Result<Value, PirProviderError>>, PirProviderError> {
        if ops.is_empty() {
            return Ok(Vec::new());
        }
        let keys: Vec<Vec<u8>> = ops.iter().map(|op| op.key.clone()).collect();
        let values = self.lookup_batch_blocking(keys).await?;
        Ok(ops
            .iter()
            .zip(values)
            .map(|(op, raw)| decode_pir(op, raw))
            .collect())
    }

    /// Dispatch one JSON-RPC method.
    ///
    /// # Errors
    ///
    /// Returns [`PirProviderError`] on PIR failure, invalid params, or fallback
    /// RPC/HTTP errors. A PIR miss is **not** an error: account methods return
    /// `0x0`.
    pub async fn request(&self, method: &str, params: Value) -> Result<Value, PirProviderError> {
        let params = normalize_params(&params);
        match self.plan_request(method, &params)? {
            PlannedOp::Pir(op) => {
                let mut out = self.execute_pir(std::slice::from_ref(&op)).await?;
                out.pop().unwrap_or_else(|| Ok(encode_qty(0)))
            }
            PlannedOp::Fallback => {
                debug!(method, "fallback RPC");
                self.fallback.request(method, params).await
            }
        }
    }

    async fn lookup_batch_blocking(
        &self,
        keys: Vec<Vec<u8>>,
    ) -> Result<Vec<Option<Vec<u8>>>, PirProviderError> {
        let lookup = Arc::clone(&self.lookup);
        tokio::task::spawn_blocking(move || lookup.lookup_batch(&keys)).await?
    }
}

fn normalize_params(params: &Value) -> Value {
    if params.is_null() {
        Value::Array(Vec::new())
    } else {
        params.clone()
    }
}

/// Decode raw PIR bytes for one planned op into a JSON-RPC result value.
///
/// A miss (`None`) yields the zero encoding for that op (never an error).
///
/// # Errors
///
/// Returns [`PirProviderError::Client`] when account blobs are the wrong size.
pub fn decode_pir(op: &PirOp, value: Option<Vec<u8>>) -> Result<Value, PirProviderError> {
    match (&op.decode, value) {
        (PirDecode::AccountBalance, Some(raw)) => {
            let acct = parse_account_bytes(&raw).ok_or_else(|| {
                PirProviderError::Client("account value is not 40 bytes".into())
            })?;
            Ok(encode_qty(acct.balance))
        }
        (PirDecode::AccountNonce, Some(raw)) => {
            let acct = parse_account_bytes(&raw).ok_or_else(|| {
                PirProviderError::Client("account value is not 40 bytes".into())
            })?;
            Ok(encode_qty(u128::from(acct.nonce)))
        }
        (PirDecode::AccountBalance | PirDecode::AccountNonce, None) => Ok(encode_qty(0)),
        (PirDecode::Call { value_encoding }, Some(raw)) => Ok(match value_encoding.as_str() {
            "bytes" | "account" => encode_bytes(&raw),
            _ => encode_uint256(&raw),
        }),
        (PirDecode::Call { value_encoding }, None) => Ok(encode_zero(value_encoding)),
    }
}

fn parse_account_bytes(v: &[u8]) -> Option<AccountView> {
    if v.len() != 40 {
        return None;
    }
    Some(AccountView {
        balance: u128::from_be_bytes(v[16..32].try_into().ok()?),
        nonce: u64::from_be_bytes(v[32..40].try_into().ok()?),
    })
}

struct AccountView {
    balance: u128,
    nonce: u64,
}

#[cfg(test)]
mod tests {
    use crate::DatasetManifest;
    use serde_json::json;

    use super::*;
    use crate::routes::encode_uint256;

    fn account_bytes(balance: u128, nonce: u64) -> Vec<u8> {
        let mut v = vec![0u8; 40];
        v[16..32].copy_from_slice(&balance.to_be_bytes());
        v[32..40].copy_from_slice(&nonce.to_be_bytes());
        v
    }

    fn addr(n: u8) -> [u8; 20] {
        let mut a = [0u8; 20];
        a[19] = n;
        a
    }

    fn addr_hex(n: u8) -> String {
        format!("0x{}", hex::encode(addr(n)))
    }

    #[tokio::test]
    async fn get_balance_uses_pir_not_fallback() {
        let lookup = MapLookup::default();
        lookup.insert(addr(1), account_bytes(0x0163_4578_5d8a_0000, 7));
        let fallback = MapFallback::default();
        fallback.set("eth_getBalance", json!("0xdead"));
        let router = PirRouter::mock(lookup, fallback, Vec::new());

        let got = router
            .request("eth_getBalance", json!([addr_hex(1), "latest"]))
            .await
            .unwrap();
        assert_eq!(got, json!("0x16345785d8a0000"));
    }

    #[tokio::test]
    async fn get_nonce_uses_pir() {
        let lookup = MapLookup::default();
        lookup.insert(addr(1), account_bytes(1, 9));
        let router = PirRouter::mock(lookup, MapFallback::default(), Vec::new());
        let got = router
            .request("eth_getTransactionCount", json!([addr_hex(1)]))
            .await
            .unwrap();
        assert_eq!(got, json!("0x9"));
    }

    #[tokio::test]
    async fn missing_account_is_zero_not_fallback() {
        let fallback = MapFallback::default();
        fallback.set("eth_getBalance", json!("0xdead"));
        let router = PirRouter::mock(MapLookup::default(), fallback, Vec::new());
        let got = router
            .request("eth_getBalance", json!([addr_hex(9), "latest"]))
            .await
            .unwrap();
        assert_eq!(got, json!("0x0"));
    }

    #[tokio::test]
    async fn get_logs_uses_fallback() {
        let fallback = MapFallback::default();
        fallback.set("eth_getLogs", json!([]));
        let router = PirRouter::mock(MapLookup::default(), fallback, Vec::new());
        let got = router.request("eth_getLogs", json!([{}])).await.unwrap();
        assert_eq!(got, json!([]));
    }

    #[tokio::test]
    async fn unknown_eth_call_uses_fallback() {
        let fallback = MapFallback::default();
        fallback.set("eth_call", json!("0x01"));
        let router = PirRouter::mock(MapLookup::default(), fallback, Vec::new());
        let params = json!([{
            "to": addr_hex(3),
            "data": "0xdeadbeef"
        }, "latest"]);
        let got = router.request("eth_call", params).await.unwrap();
        assert_eq!(got, json!("0x01"));
    }

    #[tokio::test]
    async fn matched_eth_call_uses_pir() {
        let to = addr(8);
        let holder = addr(2);
        let mut packed = Vec::from(to);
        packed.extend_from_slice(&holder);
        let key = alloy::primitives::keccak256(&packed);

        let lookup = MapLookup::default();
        lookup.insert(key.as_slice(), 42u128.to_be_bytes());

        let datasets = vec![DatasetManifest {
            id: "erc20_balances".into(),
            selectors: vec!["0x70a08231".into()],
            contracts: vec![addr_hex(8)],
            key_scheme: "token_holder".into(),
            value_encoding: "uint256".into(),
            ..DatasetManifest::default()
        }];
        let fallback = MapFallback::default();
        fallback.set("eth_call", json!("0xdead"));
        let router = PirRouter::mock(lookup, fallback, datasets);

        let data = format!("0x70a08231{:0>64}", hex::encode(holder));
        let params = json!([{ "to": addr_hex(8), "data": data }, "latest"]);
        let got = router.request("eth_call", params).await.unwrap();
        assert_eq!(got, encode_uint256(&42u128.to_be_bytes()));
    }

    #[tokio::test]
    async fn historical_get_balance_uses_fallback() {
        let fallback = MapFallback::default();
        fallback.set("eth_getBalance", json!("0xabc"));
        let lookup = MapLookup::default();
        lookup.insert(addr(1), account_bytes(1, 0));
        let router = PirRouter::mock(lookup, fallback, Vec::new());
        let got = router
            .request("eth_getBalance", json!([addr_hex(1), "0x10"]))
            .await
            .unwrap();
        assert_eq!(got, json!("0xabc"));
    }

    #[tokio::test]
    async fn execute_pir_batches_lookups() {
        let lookup = MapLookup::default();
        lookup.insert(addr(1), account_bytes(10, 1));
        lookup.insert(addr(2), account_bytes(20, 2));
        let router = PirRouter::mock(lookup, MapFallback::default(), Vec::new());
        let ops = vec![
            PirOp {
                key: addr(1).to_vec(),
                decode: PirDecode::AccountBalance,
            },
            PirOp {
                key: addr(2).to_vec(),
                decode: PirDecode::AccountNonce,
            },
        ];
        let out = router.execute_pir(&ops).await.unwrap();
        assert_eq!(out[0].as_ref().unwrap(), &json!("0xa"));
        assert_eq!(out[1].as_ref().unwrap(), &json!("0x2"));
    }

    #[test]
    fn plan_request_splits_pir_and_fallback() {
        let router = PirRouter::mock(MapLookup::default(), MapFallback::default(), Vec::new());
        match router
            .plan_request("eth_getBalance", &json!([addr_hex(1), "latest"]))
            .unwrap()
        {
            PlannedOp::Pir(op) => assert_eq!(op.key, addr(1)),
            PlannedOp::Fallback => panic!("expected PIR"),
        }
        assert!(matches!(
            router.plan_request("eth_getLogs", &json!([{}])).unwrap(),
            PlannedOp::Fallback
        ));
    }
}
