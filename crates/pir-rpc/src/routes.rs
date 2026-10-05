use alloy::primitives::keccak256;
use serde_json::Value;

use crate::DatasetManifest;

/// Where a JSON-RPC method should be answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route {
    /// `eth_getBalance` against the accounts dataset.
    AccountBalance,
    /// `eth_getTransactionCount` against the accounts dataset.
    AccountNonce,
    /// `eth_call` matched to a manifest dataset.
    Call(CallMatch),
    /// Forward to the fallback Ethereum node.
    Fallback,
}

/// A successful `eth_call` match against a dataset advertisement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallMatch {
    /// Dataset id from the manifest.
    pub dataset_id: String,
    /// Derived PIR lookup key.
    pub key: Vec<u8>,
    /// `account`, `bytes`, or `uint256`.
    pub value_encoding: String,
}

/// Method table: Phase-1 account routes plus manifest-driven `eth_call` matchers.
#[derive(Clone, Debug, Default)]
pub struct RouteTable {
    datasets: Vec<DatasetManifest>,
}

impl RouteTable {
    /// Build from `/manifest` `datasets`. Account balance/nonce are always
    /// PIR-routed (Phase 1), independent of this list.
    #[must_use]
    pub fn from_datasets(datasets: Vec<DatasetManifest>) -> Self {
        Self { datasets }
    }

    /// Datasets used for `eth_call` matching.
    #[must_use]
    pub fn datasets(&self) -> &[DatasetManifest] {
        &self.datasets
    }

    /// Classify `method` + `params`. Non-`latest` block tags always fall back.
    #[must_use]
    pub fn classify(&self, method: &str, params: &Value) -> Route {
        if !block_tag_is_latest(params) {
            return Route::Fallback;
        }
        match method {
            "eth_getBalance" => Route::AccountBalance,
            "eth_getTransactionCount" => Route::AccountNonce,
            "eth_call" => self
                .classify_call(params)
                .map_or(Route::Fallback, Route::Call),
            _ => Route::Fallback,
        }
    }

    fn classify_call(&self, params: &Value) -> Option<CallMatch> {
        let obj = params.as_array()?.first()?;
        let to = parse_address_value(obj.get("to")?)?;
        let data = parse_hex_bytes(obj.get("data").or_else(|| obj.get("input"))?)?;
        if data.len() < 4 {
            return None;
        }
        let selector = &data[..4];
        for ds in &self.datasets {
            if ds.selectors.is_empty() {
                continue;
            }
            if !ds.selectors.iter().any(|s| selector_eq(s, selector)) {
                continue;
            }
            if !ds.contracts.is_empty() && !ds.contracts.iter().any(|c| address_eq(c, &to)) {
                continue;
            }
            let scheme = if ds.key_scheme.is_empty() {
                "token_holder"
            } else {
                ds.key_scheme.as_str()
            };
            let key = derive_key(scheme, &to, &data)?;
            let value_encoding = if ds.value_encoding.is_empty() {
                "uint256".to_string()
            } else {
                ds.value_encoding.clone()
            };
            return Some(CallMatch {
                dataset_id: ds.id.clone(),
                key,
                value_encoding,
            });
        }
        None
    }
}

fn block_tag_is_latest(params: &Value) -> bool {
    let Some(arr) = params.as_array() else {
        return true;
    };
    match arr.get(1) {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.is_empty() || s.eq_ignore_ascii_case("latest"),
        _ => false,
    }
}

fn selector_eq(spec: &str, got: &[u8]) -> bool {
    parse_hex_str(spec).is_some_and(|bytes| bytes == got)
}

fn address_eq(spec: &str, got: &[u8; 20]) -> bool {
    parse_address_str(spec).is_some_and(|addr| &addr == got)
}

fn derive_key(scheme: &str, to: &[u8; 20], data: &[u8]) -> Option<Vec<u8>> {
    match scheme {
        "address" => Some(to.to_vec()),
        "token_holder" => {
            let holder = call_arg0_address(data)?;
            let mut packed = Vec::with_capacity(40);
            packed.extend_from_slice(to);
            packed.extend_from_slice(&holder);
            Some(keccak256(&packed).to_vec())
        }
        "arg0" => Some(call_arg0_word(data)?.to_vec()),
        _ => None,
    }
}

fn call_arg0_word(data: &[u8]) -> Option<[u8; 32]> {
    if data.len() < 36 {
        return None;
    }
    data[4..36].try_into().ok()
}

fn call_arg0_address(data: &[u8]) -> Option<[u8; 20]> {
    let word = call_arg0_word(data)?;
    word[12..32].try_into().ok()
}

fn parse_address_value(v: &Value) -> Option<[u8; 20]> {
    parse_address_str(v.as_str()?)
}

fn parse_address_str(s: &str) -> Option<[u8; 20]> {
    let bytes = parse_hex_str(s)?;
    bytes.try_into().ok()
}

fn parse_hex_bytes(v: &Value) -> Option<Vec<u8>> {
    parse_hex_str(v.as_str()?)
}

pub(crate) fn parse_hex_str(s: &str) -> Option<Vec<u8>> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    hex::decode(s).ok()
}

pub(crate) fn parse_address_param(params: &Value) -> Result<[u8; 20], crate::PirProviderError> {
    let s = params
        .as_array()
        .and_then(|a| a.first())
        .and_then(Value::as_str)
        .ok_or_else(|| {
            crate::PirProviderError::InvalidParams("expected address as first param".into())
        })?;
    let bytes = parse_hex_str(s)
        .ok_or_else(|| crate::PirProviderError::InvalidParams("address is not valid hex".into()))?;
    bytes
        .try_into()
        .map_err(|_| crate::PirProviderError::InvalidParams("address must be 20 bytes".into()))
}

pub(crate) fn encode_qty(n: u128) -> Value {
    if n == 0 {
        Value::String("0x0".into())
    } else {
        Value::String(format!("0x{n:x}"))
    }
}

pub(crate) fn encode_bytes(bytes: &[u8]) -> Value {
    Value::String(format!("0x{}", hex::encode(bytes)))
}

pub(crate) fn encode_uint256(bytes: &[u8]) -> Value {
    let mut word = [0u8; 32];
    if bytes.len() >= 32 {
        word.copy_from_slice(&bytes[bytes.len() - 32..]);
    } else {
        word[32 - bytes.len()..].copy_from_slice(bytes);
    }
    encode_bytes(&word)
}

pub(crate) fn encode_zero(encoding: &str) -> Value {
    match encoding {
        "bytes" => encode_bytes(&[]),
        _ => encode_uint256(&[]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn historical_block_falls_back() {
        let table = RouteTable::default();
        assert_eq!(
            table.classify("eth_getBalance", &json!(["0x00", "0x1"])),
            Route::Fallback
        );
        assert_eq!(
            table.classify("eth_getBalance", &json!(["0x00", "latest"])),
            Route::AccountBalance
        );
    }

    #[test]
    fn unknown_call_falls_back() {
        let table = RouteTable::default();
        let params = json!([{
            "to": "0x0000000000000000000000000000000000000001",
            "data": "0x70a082310000000000000000000000000000000000000000000000000000000000000002"
        }, "latest"]);
        assert_eq!(table.classify("eth_call", &params), Route::Fallback);
    }

    #[test]
    fn matched_balance_of_routes_to_pir() {
        let table = RouteTable::from_datasets(vec![DatasetManifest {
            id: "erc20_balances".into(),
            selectors: vec!["0x70a08231".into()],
            key_scheme: "token_holder".into(),
            value_encoding: "uint256".into(),
            ..DatasetManifest::default()
        }]);
        let to = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
        let holder = "0x0000000000000000000000000000000000000002";
        let data = format!("0x70a08231{:0>64}", holder.trim_start_matches("0x"));
        let params = json!([{ "to": to, "data": data }, "latest"]);
        match table.classify("eth_call", &params) {
            Route::Call(m) => {
                assert_eq!(m.dataset_id, "erc20_balances");
                assert_eq!(m.key.len(), 32);
            }
            other => panic!("expected Call, got {other:?}"),
        }
    }
}
