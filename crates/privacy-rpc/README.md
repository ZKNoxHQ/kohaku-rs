# kohaku-privacy-rpc

Batch-aware privacy orchestrator that composes **Tor** (`kohaku-tor-rpc`) and
**PIR** (`kohaku-pir-rpc`) into one Alloy JSON-RPC transport.

## Privacy stack

1. **Tor underlay** — PIR server calls and Ethereum RPC both egress through Arti.
2. **Prefer PIR** — allowlisted latest reads go over **shared** Tor HTTP:
   - Account table (`:18090`): `eth_getBalance`, `eth_getTransactionCount`
   - Token storage table (`:18091`): `balanceOf` for USDC / USDT / DAI / WETH
3. **Fallback clear RPC** — everything else (including `eth_getCode` until
   account blobs grow) is plaintext JSON-RPC to the node, still over Tor.
4. **Selective isolation** — bulk/metadata methods share a Tor circuit;
   address-bearing fallbacks are grouped by EOA onto isolated circuits.
5. **Multicall3 packing** — within each circuit group, eligible `eth_call` /
   `eth_getBalance` calls become one Multicall3 `aggregate3`; siblings
   (`eth_getLogs`, `eth_getCode`, …) ride in the same Tor JSON-RPC POST.

## Construction

```rust,ignore
use kohaku_privacy_rpc::{PrivacyBuilder, connect_tor_pir};
use kohaku_tor_rpc::TorRpc;

let tor = TorRpc::connect().await?;
let provider = PrivacyBuilder::new("https://eth.example")?
    .tor(tor.clone())
    .pir_over_tor(
        "http://pir.example:18090",
        Some("http://pir.example:18091"),
        datasets,
    )
    .connect()
    .await?;
```

`pir_lookup(accounts, tokens, datasets)` accepts custom inspire crypto pools
(see `local-pir-rpc`). Omit `tokens` to leave ERC-20 `balanceOf` on fallback RPC
(still Multicall-packed).

## Batch planning

One Alloy `RequestPacket` (single or batch) is classified once:

1. **Account PIR** — unique keys only; `eth_getBalance` + `eth_getTransactionCount`
   for the same EOA share one lookup and decode two fields.
2. **Token PIR** — if a holder asks for any of the four default tokens, the
   orchestrator pads to **all four** PIR lookups (privacy). Extra tokens stay on
   fallback Multicall. `local-pir-rpc` wraps Tor PIR backends in a short TTL
   cache so sequential per-token HTTP calls reuse the padded results instead of
   re-fetching four Tor PIR lookups each time.
3. **Fallback** — group by isolation policy; each group is one Tor POST with
   Multicall3 + sibling RPCs. Groups run concurrently with both PIR lanes.

`eth_getLogs` is never folded into Multicall3; callers still chunk historical
ranges. Multiple already-chunked `eth_getLogs` can share one Shared Tor POST.

## Isolation policy

[`DefaultIsolationPolicy`](crate::DefaultIsolationPolicy) sends `eth_getLogs`
and chain metadata on the shared client; other fallbacks are
`Isolated { key: address }` (or `"_anon"`). Override with
[`PrivacyBuilder::isolation_policy`](crate::PrivacyBuilder::isolation_policy).

PIR traffic always uses the **shared** Tor client (query privacy is provided by
PIR; Tor anonymizes the client IP).
