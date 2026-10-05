use std::sync::Arc;

use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use kohaku_pir_rpc::{DatasetManifest, MapFallback, MapLookup, PirRouter};
use kohaku_tor_rpc::TorRpc;
use url::Url;

use crate::{
    AsyncLookupBackend, DefaultIsolationPolicy, IsolationPolicy, LiveTorRpc, PrivacyConnect,
    PrivacyError, PrivacyTransport, StateVerifier, SyncLookupAdapter, TorPirLookup, TorRpcBackend,
};

/// Mix-and-match builder for the privacy orchestrator.
///
/// `TorPIR` preset: `.tor(...).pir_over_tor(pir_url, datasets).connect()`.
/// Future Helios+Tor: `.tor(...).verifier(helios).connect()` without PIR.
pub struct PrivacyBuilder {
    rpc_url: Url,
    tor: Option<Arc<dyn TorRpcBackend>>,
    async_lookup: Option<Arc<dyn AsyncLookupBackend>>,
    /// When set, build [`TorPirLookup`] at `build_transport` time (needs tor).
    pir_over_tor_url: Option<String>,
    datasets: Vec<DatasetManifest>,
    isolation: Arc<dyn IsolationPolicy>,
    verifier: Option<Arc<dyn StateVerifier>>,
}

impl PrivacyBuilder {
    /// Start a builder targeting `rpc_url` for fallback Ethereum JSON-RPC.
    ///
    /// # Errors
    ///
    /// Returns [`PrivacyError::InvalidUrl`] when the URL cannot be parsed.
    pub fn new(rpc_url: &str) -> Result<Self, PrivacyError> {
        let rpc_url = Url::parse(rpc_url).map_err(|e| PrivacyError::InvalidUrl(e.to_string()))?;
        Ok(Self {
            rpc_url,
            tor: None,
            async_lookup: None,
            pir_over_tor_url: None,
            datasets: Vec::new(),
            isolation: Arc::new(DefaultIsolationPolicy),
            verifier: None,
        })
    }

    /// Use a live [`TorRpc`] for all egress.
    #[must_use]
    pub fn tor(mut self, tor: TorRpc) -> Self {
        self.tor = Some(Arc::new(LiveTorRpc::new(tor)));
        self
    }

    /// Inject a custom Tor backend (tests, alternate transports).
    #[must_use]
    pub fn tor_backend(mut self, tor: Arc<dyn TorRpcBackend>) -> Self {
        self.tor = Some(tor);
        self
    }

    /// Enable PIR over **shared Tor** to `pir_url` (no circuit isolation).
    ///
    /// Builds a [`TorPirLookup`] that POSTs batch keys to `{pir_url}/lookup`
    /// through [`TorRpcBackend::http_post`].
    #[must_use]
    pub fn pir_over_tor(mut self, pir_url: &str, datasets: Vec<DatasetManifest>) -> Self {
        self.pir_over_tor_url = Some(pir_url.to_string());
        self.async_lookup = None;
        self.datasets = datasets;
        self
    }

    /// Enable PIR with a custom async lookup (e.g. tests, custom codecs).
    #[must_use]
    pub fn pir_lookup(
        mut self,
        lookup: Arc<dyn AsyncLookupBackend>,
        datasets: Vec<DatasetManifest>,
    ) -> Self {
        self.async_lookup = Some(lookup);
        self.pir_over_tor_url = None;
        self.datasets = datasets;
        self
    }

    /// Override the default shared / isolated-by-EOA policy.
    #[must_use]
    pub fn isolation_policy(mut self, policy: Arc<dyn IsolationPolicy>) -> Self {
        self.isolation = policy;
        self
    }

    /// Attach an optional lightclient verifier (Helios / Colibri later).
    #[must_use]
    pub fn verifier(mut self, verifier: Arc<dyn StateVerifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Build the [`PrivacyTransport`].
    ///
    /// # Errors
    ///
    /// Returns when Tor was not configured, or `pir_over_tor` URL is invalid.
    pub fn build_transport(self) -> Result<PrivacyTransport, PrivacyError> {
        let tor = self
            .tor
            .ok_or_else(|| PrivacyError::Builder("tor backend is required".into()))?;

        let async_lookup = if let Some(pir_url) = self.pir_over_tor_url {
            Some(Arc::new(TorPirLookup::new(Arc::clone(&tor), &pir_url)?)
                as Arc<dyn AsyncLookupBackend>)
        } else {
            self.async_lookup
        };

        // Router is used for plan/classify only; its sync LookupBackend is inert.
        let router = Arc::new(PirRouter::from_parts(
            Arc::new(MapLookup::default()),
            Arc::new(MapFallback::default()),
            self.datasets,
        ));
        Ok(PrivacyTransport::new(
            router,
            async_lookup,
            tor,
            self.rpc_url,
            self.isolation,
            self.verifier,
        ))
    }

    /// Build a type-erased Alloy provider.
    ///
    /// # Errors
    ///
    /// Returns when the transport cannot be built or Alloy connect fails.
    pub async fn connect(self) -> Result<DynProvider, PrivacyError> {
        let transport = self.build_transport()?;
        ProviderBuilder::default()
            .connect_with(&PrivacyConnect::new(transport))
            .await
            .map(Provider::erased)
            .map_err(|e| PrivacyError::Transport(e.to_string()))
    }
}

/// Convenience: Tor + PIR-over-Tor → [`DynProvider`].
///
/// Doc alias for the `TorPIR` provider composition.
///
/// # Errors
///
/// Returns when a URL is invalid or Alloy connect fails.
pub async fn connect_tor_pir(
    tor: TorRpc,
    pir_url: &str,
    rpc_url: &str,
    datasets: Vec<DatasetManifest>,
) -> Result<DynProvider, PrivacyError> {
    PrivacyBuilder::new(rpc_url)?
        .tor(tor)
        .pir_over_tor(pir_url, datasets)
        .connect()
        .await
}

/// Test helper: sync [`MapLookup`](kohaku_pir_rpc::MapLookup) as async PIR (no Tor HTTP).
#[must_use]
pub fn sync_pir_lookup(lookup: Arc<dyn kohaku_pir_rpc::LookupBackend>) -> Arc<dyn AsyncLookupBackend> {
    Arc::new(SyncLookupAdapter::new(lookup))
}
