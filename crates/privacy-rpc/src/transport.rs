use std::{
    borrow::Cow,
    collections::HashMap,
    sync::Arc,
    task,
};

use alloy::{
    rpc::json_rpc::{
        ErrorPayload, Id, RequestPacket, Response, ResponsePacket, ResponsePayload,
        SerializedRequest,
    },
    transports::{
        BoxTransport, TransportConnect, TransportError, TransportErrorKind, TransportFut,
    },
};
use futures::future::try_join_all;
use kohaku_pir_rpc::{PirOp, PirProviderError, PirRouter, PlannedOp, decode_pir};
use serde_json::{Value, value::RawValue};
use tower::Service;
use tracing::debug;
use url::Url;

use crate::{
    AsyncLookupBackend, CircuitChoice, IsolationPolicy, PrivacyError, StateVerifier, TorRpcBackend,
};

/// Batch-aware privacy orchestrator: PIR over Tor, fallback RPC over Tor with
/// selective circuit isolation.
#[derive(Clone)]
pub struct PrivacyTransport {
    router: Arc<PirRouter>,
    /// When set, allowlisted methods go through this async PIR lookup (Tor-backed in `TorPIR`).
    async_lookup: Option<Arc<dyn AsyncLookupBackend>>,
    tor: Arc<dyn TorRpcBackend>,
    rpc_url: Url,
    isolation: Arc<dyn IsolationPolicy>,
    verifier: Option<Arc<dyn StateVerifier>>,
}

impl PrivacyTransport {
    /// Construct from already-wired parts.
    #[must_use]
    pub fn new(
        router: Arc<PirRouter>,
        async_lookup: Option<Arc<dyn AsyncLookupBackend>>,
        tor: Arc<dyn TorRpcBackend>,
        rpc_url: Url,
        isolation: Arc<dyn IsolationPolicy>,
        verifier: Option<Arc<dyn StateVerifier>>,
    ) -> Self {
        Self {
            router,
            async_lookup,
            tor,
            rpc_url,
            isolation,
            verifier,
        }
    }

    /// PIR routing table (for logging / debugging).
    #[must_use]
    pub fn router(&self) -> &PirRouter {
        &self.router
    }

    async fn handle(self, req: RequestPacket) -> Result<ResponsePacket, TransportError> {
        let reqs: Vec<SerializedRequest> = match req {
            RequestPacket::Single(r) => vec![r],
            RequestPacket::Batch(rs) => rs,
        };
        let responses = self.dispatch(reqs).await?;
        if responses.len() == 1 {
            Ok(ResponsePacket::Single(
                responses.into_iter().next().expect("len checked"),
            ))
        } else {
            Ok(ResponsePacket::Batch(responses))
        }
    }

    async fn dispatch(
        &self,
        reqs: Vec<SerializedRequest>,
    ) -> Result<Vec<Response>, TransportError> {
        let n = reqs.len();
        let mut pir_jobs: Vec<(usize, Id, PirOp)> = Vec::new();
        let mut fallback_jobs: Vec<(usize, SerializedRequest, String, Value)> = Vec::new();
        let mut early: HashMap<usize, Response> = HashMap::new();
        let mut meta: HashMap<usize, (String, Value)> = HashMap::new();
        let pir_enabled = self.async_lookup.is_some();

        for (idx, req) in reqs.into_iter().enumerate() {
            let method = req.method().to_string();
            let params = req
                .params()
                .map(|raw| serde_json::from_str(raw.get()))
                .transpose()
                .map_err(TransportErrorKind::custom)?
                .unwrap_or(Value::Array(Vec::new()));
            let id = req.id().clone();
            meta.insert(idx, (method.clone(), params.clone()));
            if !pir_enabled {
                fallback_jobs.push((idx, req, method, params));
                continue;
            }
            match self.router.plan_request(&method, &params) {
                Ok(PlannedOp::Pir(op)) => pir_jobs.push((idx, id, op)),
                Ok(PlannedOp::Fallback) => {
                    fallback_jobs.push((idx, req, method, params));
                }
                Err(e) => {
                    early.insert(idx, failure_response(id, &e));
                }
            }
        }

        let (pir_results, rpc_results) = tokio::try_join!(
            self.run_pir(&pir_jobs),
            self.run_fallback_rpc(&fallback_jobs)
        )?;

        let mut slots: Vec<Option<Response>> = (0..n).map(|_| None).collect();
        for (idx, resp) in early {
            slots[idx] = Some(resp);
        }
        for (idx, resp) in pir_results {
            slots[idx] = Some(resp);
        }
        for (idx, resp) in rpc_results {
            slots[idx] = Some(resp);
        }

        let mut out = Vec::with_capacity(n);
        for (idx, slot) in slots.into_iter().enumerate() {
            out.push(slot.ok_or_else(|| {
                TransportErrorKind::custom(PrivacyError::Transport(format!(
                    "missing response for index {idx}"
                )))
            })?);
        }

        if let Some(verifier) = &self.verifier {
            for (idx, resp) in out.iter_mut().enumerate() {
                let ResponsePayload::Success(raw) = &resp.payload else {
                    continue;
                };
                let (method, params) = meta.get(&idx).cloned().unwrap_or_default();
                let value: Value =
                    serde_json::from_str(raw.get()).map_err(TransportErrorKind::custom)?;
                match verifier.verify(&method, &params, value).await {
                    Ok(v) => {
                        resp.payload = ResponsePayload::Success(to_raw(&v)?);
                    }
                    Err(e) => {
                        *resp = Response {
                            id: resp.id.clone(),
                            payload: ResponsePayload::Failure(ErrorPayload {
                                code: e.rpc_code(),
                                message: Cow::Owned(e.to_string()),
                                data: None,
                            }),
                        };
                    }
                }
            }
        }

        Ok(out)
    }

    async fn run_pir(
        &self,
        jobs: &[(usize, Id, PirOp)],
    ) -> Result<Vec<(usize, Response)>, TransportError> {
        if jobs.is_empty() {
            return Ok(Vec::new());
        }
        let lookup = self.async_lookup.as_ref().ok_or_else(|| {
            TransportErrorKind::custom(PrivacyError::Transport(
                "PIR jobs planned but no async lookup configured".into(),
            ))
        })?;
        debug!(count = jobs.len(), "PIR lane over Tor-backed lookup");
        let keys: Vec<Vec<u8>> = jobs.iter().map(|(_, _, op)| op.key.clone()).collect();
        let values = lookup
            .lookup_batch(&keys)
            .await
            .map_err(TransportError::from)?;
        let mut out = Vec::with_capacity(jobs.len());
        for ((idx, id, op), raw) in jobs.iter().zip(values) {
            out.push((
                *idx,
                match decode_pir(op, raw) {
                    Ok(value) => success_response(id.clone(), &value)?,
                    Err(e) => failure_response(id.clone(), &e),
                },
            ));
        }
        Ok(out)
    }

    async fn run_fallback_rpc(
        &self,
        jobs: &[(usize, SerializedRequest, String, Value)],
    ) -> Result<Vec<(usize, Response)>, TransportError> {
        if jobs.is_empty() {
            return Ok(Vec::new());
        }

        let mut groups: HashMap<CircuitChoice, Vec<(usize, SerializedRequest)>> = HashMap::new();
        for (idx, req, method, params) in jobs {
            let choice = self.isolation.circuit_for(method, params);
            groups.entry(choice).or_default().push((*idx, req.clone()));
        }

        let futs = groups.into_iter().map(|(choice, items)| {
            let tor = Arc::clone(&self.tor);
            let url = self.rpc_url.clone();
            async move {
                let indices: Vec<usize> = items.iter().map(|(i, _)| *i).collect();
                let packet = if items.len() == 1 {
                    RequestPacket::Single(items.into_iter().next().expect("len").1)
                } else {
                    RequestPacket::Batch(items.into_iter().map(|(_, r)| r).collect())
                };
                debug!(?choice, count = indices.len(), "fallback RPC Tor lane");
                let resp_packet = match choice {
                    CircuitChoice::Shared => tor.send_shared(url, packet).await?,
                    CircuitChoice::Isolated { .. } => tor.send_isolated(url, packet).await?,
                };
                let responses = match resp_packet {
                    ResponsePacket::Single(r) => vec![r],
                    ResponsePacket::Batch(rs) => rs,
                };
                if responses.len() != indices.len() {
                    return Err(TransportErrorKind::custom(PrivacyError::Transport(format!(
                        "RPC returned {} responses for {} requests",
                        responses.len(),
                        indices.len()
                    ))));
                }
                Ok(indices.into_iter().zip(responses).collect::<Vec<_>>())
            }
        });

        let nested = try_join_all(futs).await?;
        Ok(nested.into_iter().flatten().collect())
    }
}

fn success_response(id: Id, value: &Value) -> Result<Response, TransportError> {
    Ok(Response {
        id,
        payload: ResponsePayload::Success(to_raw(value)?),
    })
}

fn failure_response(id: Id, err: &PirProviderError) -> Response {
    Response {
        id,
        payload: ResponsePayload::Failure(ErrorPayload {
            code: err.rpc_code(),
            message: Cow::Owned(err.to_string()),
            data: None,
        }),
    }
}

fn to_raw(value: &Value) -> Result<Box<RawValue>, TransportError> {
    let s = serde_json::to_string(value).map_err(TransportErrorKind::custom)?;
    RawValue::from_string(s).map_err(TransportErrorKind::custom)
}

impl Service<RequestPacket> for PrivacyTransport {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> task::Poll<Result<(), Self::Error>> {
        task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        Box::pin(self.clone().handle(req))
    }
}

/// [`TransportConnect`] for [`PrivacyTransport`].
#[derive(Clone)]
pub struct PrivacyConnect {
    transport: PrivacyTransport,
}

impl PrivacyConnect {
    /// Wrap a transport.
    #[must_use]
    pub const fn new(transport: PrivacyTransport) -> Self {
        Self { transport }
    }
}

impl TransportConnect for PrivacyConnect {
    fn is_local(&self) -> bool {
        false
    }

    async fn get_transport(&self) -> Result<BoxTransport, TransportError> {
        Ok(BoxTransport::new(self.transport.clone()))
    }
}
