use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
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
use kohaku_pir_rpc::{
    PIR_TOKENS, PirLane, PirOp, PirProviderError, PirRouter, PlannedOp, decode_pir, dedupe_keys,
    token_balance_op,
};
use serde_json::{Value, value::RawValue};
use tower::Service;
use tracing::debug;
use url::Url;

use crate::{
    AsyncLookupBackend, CircuitChoice, IsolationPolicy, PrivacyError, StateVerifier, TorRpcBackend,
    multicall::{FallbackJob, pack_circuit_group},
};

/// Batch-aware privacy orchestrator: PIR over Tor, fallback RPC over Tor with
/// selective circuit isolation and Multicall3 packing.
#[derive(Clone)]
pub struct PrivacyTransport {
    router: Arc<PirRouter>,
    /// Account-table PIR (required when PIR is enabled).
    accounts_lookup: Option<Arc<dyn AsyncLookupBackend>>,
    /// Token-storage PIR (optional; without it, token `balanceOf` falls back).
    tokens_lookup: Option<Arc<dyn AsyncLookupBackend>>,
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
        accounts_lookup: Option<Arc<dyn AsyncLookupBackend>>,
        tokens_lookup: Option<Arc<dyn AsyncLookupBackend>>,
        tor: Arc<dyn TorRpcBackend>,
        rpc_url: Url,
        isolation: Arc<dyn IsolationPolicy>,
        verifier: Option<Arc<dyn StateVerifier>>,
    ) -> Self {
        Self {
            router,
            accounts_lookup,
            tokens_lookup,
            tor,
            rpc_url,
            isolation,
            verifier,
        }
    }

    /// Backward-compatible constructor: one lookup for all PIR lanes.
    #[must_use]
    pub fn new_single_lookup(
        router: Arc<PirRouter>,
        async_lookup: Option<Arc<dyn AsyncLookupBackend>>,
        tor: Arc<dyn TorRpcBackend>,
        rpc_url: Url,
        isolation: Arc<dyn IsolationPolicy>,
        verifier: Option<Arc<dyn StateVerifier>>,
    ) -> Self {
        Self::new(
            router,
            async_lookup.clone(),
            async_lookup,
            tor,
            rpc_url,
            isolation,
            verifier,
        )
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
        let mut fallback_jobs: Vec<FallbackJob> = Vec::new();
        let mut early: HashMap<usize, Response> = HashMap::new();
        let mut meta: HashMap<usize, (String, Value)> = HashMap::new();
        let pir_enabled = self.accounts_lookup.is_some();

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
                fallback_jobs.push(FallbackJob {
                    idx,
                    req,
                    method,
                    params,
                });
                continue;
            }
            match self.router.plan_request(&method, &params) {
                Ok(PlannedOp::Pir(op)) => {
                    // Token PIR without a tokens backend → fallback RPC.
                    if op.lane == PirLane::TokenStorage && self.tokens_lookup.is_none() {
                        fallback_jobs.push(FallbackJob {
                            idx,
                            req,
                            method,
                            params,
                        });
                    } else {
                        pir_jobs.push((idx, id, op));
                    }
                }
                Ok(PlannedOp::Fallback) => {
                    fallback_jobs.push(FallbackJob {
                        idx,
                        req,
                        method,
                        params,
                    });
                }
                Err(e) => {
                    early.insert(idx, failure_response(id, &e));
                }
            }
        }

        // Privacy pad: any holder with ≥1 of the four tokens → look up all four.
        let pad_ops = pad_token_lookups(&pir_jobs);

        let (pir_results, rpc_results) = tokio::try_join!(
            self.run_pir(&pir_jobs, &pad_ops),
            self.run_fallback_rpc(fallback_jobs)
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
        pad_ops: &[PirOp],
    ) -> Result<Vec<(usize, Response)>, TransportError> {
        if jobs.is_empty() && pad_ops.is_empty() {
            return Ok(Vec::new());
        }

        // Physical lookups = client jobs + padding (padding has no response index).
        let mut all_ops: Vec<PirOp> = jobs.iter().map(|(_, _, op)| op.clone()).collect();
        all_ops.extend(pad_ops.iter().cloned());

        let mut account_ops = Vec::new();
        let mut token_ops = Vec::new();
        let mut account_job_map = Vec::new(); // all_ops index
        let mut token_job_map = Vec::new();

        for (i, op) in all_ops.iter().enumerate() {
            match op.lane {
                PirLane::Account => {
                    account_job_map.push(i);
                    account_ops.push(op.clone());
                }
                PirLane::TokenStorage => {
                    token_job_map.push(i);
                    token_ops.push(op.clone());
                }
            }
        }

        let (account_values, token_values) = tokio::try_join!(
            self.lookup_lane(self.accounts_lookup.as_ref(), &account_ops, "account"),
            self.lookup_lane(self.tokens_lookup.as_ref(), &token_ops, "token"),
        )?;

        let mut raw_by_all: Vec<Option<Vec<u8>>> = vec![None; all_ops.len()];
        for (j, &i) in account_job_map.iter().enumerate() {
            raw_by_all[i] = account_values[j].clone();
        }
        for (j, &i) in token_job_map.iter().enumerate() {
            raw_by_all[i] = token_values[j].clone();
        }

        // Only emit responses for client jobs (first `jobs.len()` entries of all_ops).
        let mut out = Vec::with_capacity(jobs.len());
        for (job_i, (idx, id, op)) in jobs.iter().enumerate() {
            out.push((
                *idx,
                match decode_pir(op, raw_by_all[job_i].clone()) {
                    Ok(value) => success_response(id.clone(), &value)?,
                    Err(e) => failure_response(id.clone(), &e),
                },
            ));
        }
        Ok(out)
    }

    async fn lookup_lane(
        &self,
        lookup: Option<&Arc<dyn AsyncLookupBackend>>,
        ops: &[PirOp],
        label: &str,
    ) -> Result<Vec<Option<Vec<u8>>>, TransportError> {
        if ops.is_empty() {
            return Ok(Vec::new());
        }
        let lookup = lookup.ok_or_else(|| {
            TransportErrorKind::custom(PrivacyError::Transport(format!(
                "PIR {label} jobs planned but no lookup configured"
            )))
        })?;
        let (unique_keys, remap) = dedupe_keys(ops);
        debug!(
            lane = label,
            ops = ops.len(),
            unique = unique_keys.len(),
            "PIR lane over Tor-backed lookup"
        );
        let values = lookup
            .lookup_batch(&unique_keys)
            .await
            .map_err(TransportError::from)?;
        Ok(remap.into_iter().map(|i| values[i].clone()).collect())
    }

    async fn run_fallback_rpc(
        &self,
        jobs: Vec<FallbackJob>,
    ) -> Result<Vec<(usize, Response)>, TransportError> {
        if jobs.is_empty() {
            return Ok(Vec::new());
        }

        let mut groups: HashMap<CircuitChoice, Vec<FallbackJob>> = HashMap::new();
        for job in jobs {
            let choice = self.isolation.circuit_for(&job.method, &job.params);
            groups.entry(choice).or_default().push(job);
        }

        let futs = groups.into_iter().map(|(choice, items)| {
            let tor = Arc::clone(&self.tor);
            let url = self.rpc_url.clone();
            async move {
                let count = items.len();
                let (packet, packed) = pack_circuit_group(items)?;
                debug!(?choice, jobs = count, "fallback RPC Tor lane (multicall-packed)");
                let resp_packet = match choice {
                    CircuitChoice::Shared => tor.send_shared(url, packet).await?,
                    CircuitChoice::Isolated { .. } => tor.send_isolated(url, packet).await?,
                };
                packed.unpack(resp_packet)
            }
        });

        let nested = try_join_all(futs).await?;
        Ok(nested.into_iter().flatten().collect())
    }
}

/// For each holder that already has ≥1 PIR token job, add missing tokens as pad ops.
fn pad_token_lookups(jobs: &[(usize, Id, PirOp)]) -> Vec<PirOp> {
    let mut present: HashMap<[u8; 20], HashSet<usize>> = HashMap::new();
    for (_, _, op) in jobs {
        if op.lane != PirLane::TokenStorage {
            continue;
        }
        let (Some(holder), Some(ti)) = (op.holder, op.token_index) else {
            continue;
        };
        present.entry(holder).or_default().insert(ti);
    }

    let mut pad = Vec::new();
    for (holder, have) in present {
        for (ti, token) in PIR_TOKENS.iter().enumerate() {
            if !have.contains(&ti) {
                pad.push(token_balance_op(token, &holder));
            }
        }
    }
    pad
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
