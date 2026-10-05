#![cfg(test)]

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;
use alloy::rpc::json_rpc::{
    Id, Request, RequestPacket, Response, ResponsePacket, ResponsePayload, SerializedRequest,
};
use alloy::transports::{TransportError, TransportErrorKind};
use serde_json::{Value, json};
use url::Url;

use crate::TorRpcBackend;

#[derive(Default)]
pub struct MockTorRpc {
    pub shared_batches: Mutex<Vec<Vec<String>>>,
    pub isolated_batches: Mutex<Vec<Vec<String>>>,
    pub http_posts: Mutex<Vec<(String, Vec<u8>)>>,
    /// method → result for JSON-RPC
    pub results: Mutex<HashMap<String, Value>>,
    /// PIR key hex (no 0x) → value bytes for `/lookup` over Tor HTTP
    pub pir_entries: Mutex<HashMap<String, Vec<u8>>>,
}

impl MockTorRpc {
    pub fn set(&self, method: impl Into<String>, result: Value) {
        self.results
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(method.into(), result);
    }

    pub fn set_pir(&self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
        self.pir_entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(hex::encode(key.as_ref()), value.as_ref().to_vec());
    }

    pub fn shared_batches(&self) -> Vec<Vec<String>> {
        self.shared_batches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn isolated_batches(&self) -> Vec<Vec<String>> {
        self.isolated_batches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn http_post_count(&self) -> usize {
        self.http_posts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    pub fn http_post_urls(&self) -> Vec<String> {
        self.http_posts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(u, _)| u.clone())
            .collect()
    }

    async fn answer(&self, packet: RequestPacket) -> Result<ResponsePacket, TransportError> {
        let reqs: Vec<SerializedRequest> = match packet {
            RequestPacket::Single(r) => vec![r],
            RequestPacket::Batch(rs) => rs,
        };
        let mut out = Vec::with_capacity(reqs.len());
        for req in reqs {
            let method = req.method().to_string();
            let id = req.id().clone();
            let value = self
                .results
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&method)
                .cloned()
                .unwrap_or_else(|| json!("0xmock"));
            let raw = serde_json::value::to_raw_value(&value).map_err(TransportErrorKind::custom)?;
            out.push(Response {
                id,
                payload: ResponsePayload::Success(raw),
            });
        }
        if out.len() == 1 {
            Ok(ResponsePacket::Single(out.pop().expect("len")))
        } else {
            Ok(ResponsePacket::Batch(out))
        }
    }

    fn answer_pir_lookup(&self, body: &[u8]) -> Result<Vec<u8>, String> {
        let req: Value = serde_json::from_slice(body).map_err(|e| e.to_string())?;
        let keys = req
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| "missing keys".to_string())?;
        let entries = self
            .pir_entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let values: Vec<Value> = keys
            .iter()
            .map(|k| {
                let s = k.as_str().unwrap_or("");
                let raw = s
                    .strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .unwrap_or(s);
                match entries.get(raw) {
                    Some(v) => Value::String(format!("0x{}", hex::encode(v))),
                    None => Value::Null,
                }
            })
            .collect();
        serde_json::to_vec(&json!({ "values": values })).map_err(|e| e.to_string())
    }
}

#[async_trait]
impl TorRpcBackend for MockTorRpc {
    async fn send_shared(
        &self,
        _url: Url,
        packet: RequestPacket,
    ) -> Result<ResponsePacket, TransportError> {
        let methods: Vec<String> = packet
            .requests()
            .iter()
            .map(|r| r.method().to_string())
            .collect();
        self.shared_batches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(methods);
        self.answer(packet).await
    }

    async fn send_isolated(
        &self,
        _url: Url,
        packet: RequestPacket,
    ) -> Result<ResponsePacket, TransportError> {
        let methods: Vec<String> = packet
            .requests()
            .iter()
            .map(|r| r.method().to_string())
            .collect();
        self.isolated_batches
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(methods);
        self.answer(packet).await
    }

    async fn http_post(
        &self,
        url: &Url,
        _headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.http_posts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((url.to_string(), body.to_vec()));
        if url.path().ends_with("/lookup") {
            return self.answer_pir_lookup(body);
        }
        Ok(Vec::new())
    }
}

pub fn serialize_req(method: &'static str, id: u64, params: Value) -> SerializedRequest {
    Request::new(method, Id::Number(id), params)
        .serialize()
        .expect("serialize request")
}

pub fn account_bytes(balance: u128, nonce: u64) -> Vec<u8> {
    let mut v = vec![0u8; 40];
    v[16..32].copy_from_slice(&balance.to_be_bytes());
    v[32..40].copy_from_slice(&nonce.to_be_bytes());
    v
}

pub fn addr(n: u8) -> [u8; 20] {
    let mut a = [0u8; 20];
    a[19] = n;
    a
}

pub fn addr_hex(n: u8) -> String {
    format!("0x{}", hex::encode(addr(n)))
}
