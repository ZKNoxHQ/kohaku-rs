use std::sync::Arc;

use async_trait::async_trait;
use kohaku_pir_rpc::{LookupBackend, PirProviderError};
use serde_json::{Value, json};
use url::Url;

use crate::TorRpcBackend;

/// Async PIR key lookup used by the privacy orchestrator.
///
/// Unlike [`LookupBackend`] (sync / `spawn_blocking`), this is async so Tor HTTP
/// can drive the PIR server without blocking the runtime.
#[async_trait]
pub trait AsyncLookupBackend: Send + Sync {
    /// Look up many PIR keys (order-preserving).
    async fn lookup_batch(
        &self,
        keys: &[Vec<u8>],
    ) -> Result<Vec<Option<Vec<u8>>>, PirProviderError>;
}

/// Bridge a sync [`LookupBackend`] into [`AsyncLookupBackend`] via `spawn_blocking`.
///
/// Useful for in-memory tests (`MapLookup`). Does **not** send traffic over Tor.
pub struct SyncLookupAdapter {
    inner: Arc<dyn LookupBackend>,
}

impl SyncLookupAdapter {
    /// Wrap a sync lookup backend.
    #[must_use]
    pub fn new(inner: Arc<dyn LookupBackend>) -> Self {
        Self { inner }
    }
}

#[async_trait]
impl AsyncLookupBackend for SyncLookupAdapter {
    async fn lookup_batch(
        &self,
        keys: &[Vec<u8>],
    ) -> Result<Vec<Option<Vec<u8>>>, PirProviderError> {
        let inner = Arc::clone(&self.inner);
        let keys = keys.to_vec();
        tokio::task::spawn_blocking(move || inner.lookup_batch(&keys)).await?
    }
}

/// PIR lookups over **shared** Tor HTTP (no circuit isolation).
///
/// Posts a JSON batch to `{pir_base}/lookup`:
///
/// ```json
/// {"keys":["0x…","0x…"]}
/// ```
///
/// Expects:
///
/// ```json
/// {"values":[null,"0x…"]}
/// ```
///
/// This is the Tor underlay seam for PIR. Production wallets should replace the
/// body codec with inspire-gpu-serving `pir-client` crypto while keeping Tor as
/// the HTTP transport (`http_post` / shared circuits only).
pub struct TorPirLookup {
    tor: Arc<dyn TorRpcBackend>,
    lookup_url: Url,
}

impl TorPirLookup {
    /// Build a lookup client targeting `pir_base` (e.g. `https://pir.example`).
    ///
    /// # Errors
    ///
    /// Returns when `pir_base` is not a valid URL.
    pub fn new(tor: Arc<dyn TorRpcBackend>, pir_base: &str) -> Result<Self, crate::PrivacyError> {
        let mut lookup_url =
            Url::parse(pir_base).map_err(|e| crate::PrivacyError::InvalidUrl(e.to_string()))?;
        let path = lookup_url.path().trim_end_matches('/');
        let path = if path.is_empty() || path == "/" {
            "/lookup".to_string()
        } else {
            format!("{path}/lookup")
        };
        lookup_url.set_path(&path);
        Ok(Self { tor, lookup_url })
    }

    /// Endpoint used for batch lookups (including `/lookup`).
    #[must_use]
    pub const fn lookup_url(&self) -> &Url {
        &self.lookup_url
    }
}

#[async_trait]
impl AsyncLookupBackend for TorPirLookup {
    async fn lookup_batch(
        &self,
        keys: &[Vec<u8>],
    ) -> Result<Vec<Option<Vec<u8>>>, PirProviderError> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let body = json!({
            "keys": keys.iter().map(|k| format!("0x{}", hex::encode(k))).collect::<Vec<_>>(),
        });
        let bytes =
            serde_json::to_vec(&body).map_err(|e| PirProviderError::Client(e.to_string()))?;
        let headers = vec![("content-type".into(), "application/json".into())];
        let resp = self
            .tor
            .http_post(&self.lookup_url, &headers, &bytes)
            .await
            .map_err(PirProviderError::Client)?;
        parse_lookup_response(&resp, keys.len())
    }
}

fn parse_lookup_response(
    body: &[u8],
    expected: usize,
) -> Result<Vec<Option<Vec<u8>>>, PirProviderError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|e| PirProviderError::Client(e.to_string()))?;
    let values = value
        .get("values")
        .and_then(Value::as_array)
        .ok_or_else(|| PirProviderError::Client("PIR response missing values[]".into()))?;
    if values.len() != expected {
        return Err(PirProviderError::Client(format!(
            "PIR response length {} != request length {expected}",
            values.len()
        )));
    }
    values
        .iter()
        .map(|v| match v {
            Value::Null => Ok(None),
            Value::String(s) => {
                let raw = s
                    .strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .unwrap_or(s);
                let bytes = hex::decode(raw)
                    .map_err(|e| PirProviderError::Client(format!("PIR value hex: {e}")))?;
                Ok(Some(bytes))
            }
            other => Err(PirProviderError::Client(format!(
                "PIR value must be hex string or null, got {other}"
            ))),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_url_appends_path() {
        let tor: Arc<dyn TorRpcBackend> = Arc::new(crate::mock::MockTorRpc::default());
        let lookup = TorPirLookup::new(tor, "https://pir.example").unwrap();
        assert_eq!(lookup.lookup_url().as_str(), "https://pir.example/lookup");
    }

    #[test]
    fn parses_batch_response() {
        let body = br#"{"values":[null,"0x0102"]}"#;
        let out = parse_lookup_response(body, 2).unwrap();
        assert_eq!(out[0], None);
        assert_eq!(out[1], Some(vec![1, 2]));
    }
}
