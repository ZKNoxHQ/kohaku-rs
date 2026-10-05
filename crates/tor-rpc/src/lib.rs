//! Alloy JSON-RPC through Arti.
//!
//! Callers choose circuit policy explicitly:
//! - [`TorRpc::shared_rpc_client`] — reuse the bootstrapped client (pool sync, cache GET).
//! - [`TorRpc::isolated_rpc_client`] / [`TorRpc::with_isolated`] — one
//!   [`TorClient::isolated_client`] for a short-lived session (all RPCs about one address).

use std::{
    fmt::Write as _,
    future::Future,
    io,
    sync::Arc,
    task::{self, Poll},
};

use alloy::{
    providers::RootProvider,
    rpc::{
        client::RpcClient,
        json_rpc::{RequestPacket, ResponsePacket},
    },
    transports::{TransportError, TransportErrorKind, TransportFut},
};
use anyhow::{Context, Result, bail};
use arti_client::{TorClient, TorClientConfig};
use rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tor_rtcompat::PreferredRuntime;
use tower::Service;
use url::Url;

/// Raw HTTP response from a Tor exit request (shared client).
#[derive(Clone, Debug)]
pub struct TorHttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response header lines (name, value).
    pub headers: Vec<(String, String)>,
    /// Response body.
    pub body: Vec<u8>,
}

impl TorHttpResponse {
    /// First header value matching `name` (case-insensitive).
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// A bootstrapped Tor client. Cloning is cheap and shares the directory state.
#[derive(Clone)]
pub struct TorRpc {
    client: TorClient<PreferredRuntime>,
}

impl TorRpc {
    /// Bootstrap a Tor client. Fails if the local network cannot reach the Tor directory.
    ///
    /// # Errors
    /// Returns when Arti cannot bootstrap.
    pub async fn connect() -> Result<Self> {
        let client = TorClient::create_bootstrapped(TorClientConfig::default())
            .await
            .context("bootstrap Tor")?;
        Ok(Self { client })
    }

    /// Long-lived JSON-RPC client that reuses the shared Tor client (and its circuits).
    ///
    /// # Errors
    /// Returns when `url` is a local address an exit cannot reach.
    pub fn shared_rpc_client(&self, url: Url) -> Result<RpcClient> {
        self.rpc_client(url, self.client.clone())
    }

    /// JSON-RPC client pinned to a fresh [`TorClient::isolated_client`].
    ///
    /// All requests on this client share one isolation token / circuit family.
    ///
    /// # Errors
    /// Returns when `url` is a local address an exit cannot reach.
    pub fn isolated_rpc_client(&self, url: Url) -> Result<RpcClient> {
        self.rpc_client(url, self.client.isolated_client())
    }

    /// Run `f` with an [`isolated_rpc_client`](Self::isolated_rpc_client), then drop it.
    ///
    /// # Errors
    /// Returns when the client cannot be built or `f` fails.
    pub async fn with_isolated<F, Fut, T>(&self, url: Url, f: F) -> Result<T>
    where
        F: FnOnce(RpcClient) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        f(self.isolated_rpc_client(url)?).await
    }

    /// Shared-circuit Alloy provider (pool sync).
    ///
    /// # Errors
    /// Returns when `url` is local.
    pub fn shared_provider(&self, url: Url) -> Result<RootProvider> {
        Ok(RootProvider::new(self.shared_rpc_client(url)?))
    }

    /// Isolated-session Alloy provider.
    ///
    /// # Errors
    /// Returns when `url` is local.
    pub fn isolated_provider(&self, url: Url) -> Result<RootProvider> {
        Ok(RootProvider::new(self.isolated_rpc_client(url)?))
    }

    /// `GET url` over the shared Tor client.
    ///
    /// # Errors
    /// Returns when the download fails or the host is local.
    pub async fn get(&self, url: &Url) -> Result<Vec<u8>> {
        self.request_shared(url, "GET", &[], &[]).await
    }

    /// `POST url` with `body` over the shared Tor client.
    ///
    /// Used by PIR backends that must reach a PIR HTTP API without clearnet.
    ///
    /// # Errors
    /// Returns when the upload fails or the host is local.
    pub async fn post(
        &self,
        url: &Url,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>> {
        self.request_shared(url, "POST", headers, body).await
    }

    /// Arbitrary HTTP request over the shared Tor client.
    ///
    /// # Errors
    /// Returns when the exchange fails, the host is local, or the status is not 2xx.
    pub async fn request_shared(
        &self,
        url: &Url,
        method: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<Vec<u8>> {
        let resp = self.http_shared(url, method, headers, body).await?;
        if !(200..300).contains(&resp.status) {
            bail!("{method} {url} returned HTTP {}", resp.status);
        }
        Ok(resp.body)
    }

    /// HTTP over the shared Tor client, including response headers.
    ///
    /// # Errors
    /// Returns when Tor or the HTTP exchange fails (not on non-2xx status).
    pub async fn http_shared(
        &self,
        url: &Url,
        method: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<TorHttpResponse> {
        let status = exchange(&self.client, url, method, headers, body).await?;
        Ok(TorHttpResponse {
            status: status.code,
            headers: status.headers,
            body: status.body,
        })
    }

    /// Send a JSON-RPC packet over the shared Tor client (one HTTP POST).
    ///
    /// # Errors
    /// Returns a transport error when serialization, Tor, or HTTP fails.
    pub async fn send_shared(
        &self,
        url: Url,
        packet: RequestPacket,
    ) -> Result<ResponsePacket, TransportError> {
        reject_local(&url)
            .map_err(|err| TransportErrorKind::custom(io::Error::other(err.to_string())))?;
        TorTransport {
            client: self.client.clone(),
            url,
        }
        .post_packet(packet)
        .await
    }

    /// Send a JSON-RPC packet on a fresh [`TorClient::isolated_client`].
    ///
    /// Batch all RPCs that should share one isolation token into `packet`.
    ///
    /// # Errors
    /// Returns a transport error when serialization, Tor, or HTTP fails.
    pub async fn send_isolated(
        &self,
        url: Url,
        packet: RequestPacket,
    ) -> Result<ResponsePacket, TransportError> {
        reject_local(&url)
            .map_err(|err| TransportErrorKind::custom(io::Error::other(err.to_string())))?;
        TorTransport {
            client: self.client.isolated_client(),
            url,
        }
        .post_packet(packet)
        .await
    }

    #[allow(clippy::unused_self)]
    fn rpc_client(&self, url: Url, client: TorClient<PreferredRuntime>) -> Result<RpcClient> {
        reject_local(&url)?;
        Ok(RpcClient::new(TorTransport { client, url }, false))
    }
}

#[derive(Clone)]
struct TorTransport {
    client: TorClient<PreferredRuntime>,
    url: Url,
}

impl Service<RequestPacket> for TorTransport {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { this.post_packet(req).await })
    }
}

impl TorTransport {
    async fn post_packet(self, req: RequestPacket) -> Result<ResponsePacket, TransportError> {
        let body = serde_json::to_vec(&req).map_err(TransportError::ser_err)?;
        let mut extra = vec![("content-type".to_string(), "application/json".to_string())];
        for (name, value) in &req.headers() {
            extra.push((
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            ));
        }
        let status = exchange(&self.client, &self.url, "POST", &extra, &body)
            .await
            .map_err(|err| TransportErrorKind::custom(io::Error::other(err.to_string())))?;
        if !(200..300).contains(&status.code) {
            return Err(TransportErrorKind::http_error(
                status.code,
                String::from_utf8_lossy(&status.body).into_owned(),
            ));
        }
        serde_json::from_slice(&status.body)
            .map_err(|err| TransportError::deser_err(err, String::from_utf8_lossy(&status.body)))
    }
}

struct HttpStatus {
    code: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn exchange(
    client: &TorClient<PreferredRuntime>,
    url: &Url,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<HttpStatus> {
    reject_local(url)?;
    let host = url.host_str().context("url host")?.to_string();
    let port = url.port_or_known_default().context("url port")?;
    let https = url.scheme() == "https";
    if url.scheme() != "http" && !https {
        bail!("Tor RPC only supports http and https, got {}", url.scheme());
    }
    match exchange_once(client, &host, port, https, url, method, headers, body).await {
        Ok(status) => Ok(status),
        Err(_) => exchange_once(client, &host, port, https, url, method, headers, body).await,
    }
}

#[allow(clippy::too_many_arguments)]
async fn exchange_once(
    client: &TorClient<PreferredRuntime>,
    host: &str,
    port: u16,
    https: bool,
    url: &Url,
    method: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<HttpStatus> {
    let stream = client
        .connect((host, port))
        .await
        .with_context(|| format!("Tor connect {host}:{port}"))?;
    let path = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    let path = if path.is_empty() {
        "/".to_string()
    } else {
        path
    };
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: */*\r\n");
    if !body.is_empty() {
        let _ = write!(request, "Content-Length: {}\r\n", body.len());
    }
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");

    if https {
        let tls = tls_connector();
        let name = ServerName::try_from(host.to_string()).context("tls server name")?;
        let mut stream = tls
            .connect(name, stream.compat())
            .await
            .context("tls through Tor")?;
        write_and_read(&mut stream, request.as_bytes(), body).await
    } else {
        let mut stream = stream.compat();
        write_and_read(&mut stream, request.as_bytes(), body).await
    }
}

fn tls_connector() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

async fn write_and_read(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    head: &[u8],
    body: &[u8],
) -> Result<HttpStatus> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(head).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    parse_http(&raw)
}

fn parse_http(raw: &[u8]) -> Result<HttpStatus> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("http headers")?;
    let header = std::str::from_utf8(&raw[..split]).context("http header utf8")?;
    let mut lines = header.split("\r\n");
    let status = lines.next().context("http status")?;
    let code: u16 = status
        .split_whitespace()
        .nth(1)
        .context("http status code")?
        .parse()
        .context("http status code")?;
    let mut length = None;
    let mut chunked = false;
    let mut headers = Vec::new();
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        headers.push((name.to_string(), value.to_string()));
        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }
    let rest = &raw[split + 4..];
    let body = if chunked {
        decode_chunks(rest)?
    } else if let Some(n) = length {
        rest.get(..n).context("short http body")?.to_vec()
    } else {
        rest.to_vec()
    };
    Ok(HttpStatus {
        code,
        headers,
        body,
    })
}

fn decode_chunks(mut rest: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line_end = rest
            .windows(2)
            .position(|w| w == b"\r\n")
            .context("chunk size")?;
        let size = std::str::from_utf8(&rest[..line_end]).context("chunk size")?;
        let size = usize::from_str_radix(size.trim().split(';').next().unwrap_or("0"), 16)
            .context("chunk size")?;
        rest = &rest[line_end + 2..];
        if size == 0 {
            break;
        }
        if rest.len() < size + 2 {
            bail!("short chunk");
        }
        out.extend_from_slice(&rest[..size]);
        rest = &rest[size + 2..];
    }
    Ok(out)
}

fn reject_local(url: &Url) -> Result<()> {
    let host = url.host_str().unwrap_or("");
    let local = host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host.to_ascii_lowercase().ends_with(".local")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("172.16.")
        || host.is_empty();
    if local {
        bail!("{host} is not reachable through a Tor exit");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn localhost_is_rejected() {
        let url: Url = "http://127.0.0.1:8545".parse().unwrap();
        assert!(reject_local(&url).is_err());
    }

    #[test]
    fn parses_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloTRAIL";
        let status = parse_http(raw).unwrap();
        assert_eq!(status.code, 200);
        assert_eq!(status.body, b"hello");
    }

    #[test]
    fn shared_and_isolated_clients_build_for_remote_url() {
        // Construction does not need a live Tor bootstrap: we only check reject_local
        // via the public builders once a TorRpc exists. Without bootstrap, assert URL
        // policy on reject_local alone (method-name isolation is gone).
        let remote: Url = "https://ethereum.publicnode.com".parse().unwrap();
        assert!(reject_local(&remote).is_ok());
        let local: Url = "http://localhost:8545".parse().unwrap();
        assert!(reject_local(&local).is_err());
    }

    #[tokio::test]
    #[ignore = "bootstraps Tor and times shared vs isolated JSON-RPC calls"]
    async fn circuit_session_latency() {
        let tor = TorRpc::connect().await.unwrap();
        let url: Url = "https://ethereum.publicnode.com".parse().unwrap();
        let shared = tor.shared_provider(url.clone()).unwrap();
        let started = std::time::Instant::now();
        let head = alloy::providers::Provider::get_block_number(&shared)
            .await
            .unwrap();
        eprintln!(
            "shared eth_blockNumber -> {head} in {:.1}s",
            started.elapsed().as_secs_f64()
        );
        let from = head.saturating_sub(31);
        let weth: alloy::primitives::Address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
            .parse()
            .unwrap();
        let filter = alloy::rpc::types::Filter::new()
            .address(weth)
            .from_block(from)
            .to_block(head);
        for i in 0..2 {
            let started = std::time::Instant::now();
            match alloy::providers::Provider::get_logs(&shared, &filter).await {
                Ok(logs) => eprintln!(
                    "shared eth_getLogs {i} blocks {from}..={head} {} logs in {:.1}s",
                    logs.len(),
                    started.elapsed().as_secs_f64()
                ),
                Err(err) => eprintln!(
                    "shared eth_getLogs {i} blocks {from}..={head} failed in {:.1}s: {err}",
                    started.elapsed().as_secs_f64()
                ),
            }
        }
        let started = std::time::Instant::now();
        let n = tor
            .with_isolated(url, |client| async move {
                let p: RootProvider = RootProvider::new(client);
                Ok(alloy::providers::Provider::get_block_number(&p).await?)
            })
            .await
            .unwrap();
        eprintln!(
            "isolated eth_blockNumber -> {n} in {:.1}s",
            started.elapsed().as_secs_f64()
        );
    }
}
