# kohaku-privacy-rpc

Batch-aware privacy orchestrator that composes **Tor** (`kohaku-tor-rpc`) and
**PIR** (`kohaku-pir-rpc`) into one Alloy JSON-RPC transport.

## Privacy stack

1. **Tor underlay** — PIR server calls and Ethereum RPC both egress through Arti.
2. **Prefer PIR** — allowlisted latest reads (`eth_getBalance`,
   `eth_getTransactionCount`, matched `eth_call`) go to
   [`TorPirLookup`](crate::TorPirLookup) over **shared** Tor HTTP (no isolation).
3. **Fallback clear RPC** — everything else is plaintext JSON-RPC to the node,
   still over Tor.
4. **Selective isolation** — bulk/metadata methods share a Tor circuit;
   address-bearing fallbacks are grouped by EOA onto isolated circuits.

## Construction

Standalone pieces still work on their own:

- Tor-only: `TorRpc::shared_provider` / `with_isolated`
- PIR-only: `PirRouter::with_rpc` + `PirConnect` (clearnet fallback; tests/local)

Composed `TorPIR` (doc alias for this builder preset):

```rust,ignore
use kohaku_privacy_rpc::{PrivacyBuilder, connect_tor_pir};
use kohaku_tor_rpc::TorRpc;

let tor = TorRpc::connect().await?;
let provider = PrivacyBuilder::new("https://eth.example")?
    .tor(tor.clone())
    .pir_over_tor("https://pir.example", datasets)
    .connect()
    .await?;

// or
let provider = connect_tor_pir(tor, "https://pir.example", "https://eth.example", datasets).await?;
```

`pir_over_tor` posts a JSON key batch to `{pir_url}/lookup` via shared Tor
(`TorRpcBackend::http_post`). Replace the body codec later with inspire
`pir-client` crypto; keep Tor as the HTTP transport.

Tor-only / future Helios+Tor (no PIR): omit `.pir_over_tor(...)`. Optional
`.verifier(helios)` and `.isolation_policy(custom)` slots avoid combinatorial
provider types.

## Isolation policy

[`DefaultIsolationPolicy`](crate::DefaultIsolationPolicy) sends `eth_getLogs`
and chain metadata on the shared client; other fallbacks are
`Isolated { key: address }` (or `"_anon"`). Override with
[`PrivacyBuilder::isolation_policy`](crate::PrivacyBuilder::isolation_policy).

PIR traffic always uses the **shared** Tor client (query privacy is provided by
PIR; Tor anonymizes the client IP).

## Batch planning

One Alloy `RequestPacket` (single or batch) is classified once. PIR keys run
through one shared-Tor `lookup_batch` POST. Fallback RPCs are coalesced into the
fewest Tor POSTs possible (one shared batch + one isolated batch per EOA group)
and executed concurrently with the PIR lane.
