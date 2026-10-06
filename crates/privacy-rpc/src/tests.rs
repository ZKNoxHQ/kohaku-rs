#![cfg(test)]

use std::sync::Arc;

use alloy::rpc::json_rpc::{RequestPacket, ResponsePacket, ResponsePayload};
use kohaku_pir_rpc::{
    MapFallback, MapLookup, PIR_TOKENS, PirRouter, balance_of_data_hex,
};
use serde_json::{Value, json};
use tower::Service;
use url::Url;

use crate::mock::{MockTorRpc, account_bytes, addr, addr_hex, serialize_req, storage_cell};
use crate::{
    DefaultIsolationPolicy, PrivacyBuilder, PrivacyTransport, SyncLookupAdapter, TorPirLookup,
};

fn router() -> Arc<PirRouter> {
    Arc::new(PirRouter::mock(
        MapLookup::default(),
        MapFallback::default(),
        Vec::new(),
    ))
}

fn transport_with_sync_pir(lookup: MapLookup, tor: Arc<MockTorRpc>) -> PrivacyTransport {
    let async_lookup = Arc::new(SyncLookupAdapter::new(Arc::new(lookup)));
    PrivacyTransport::new(
        router(),
        Some(async_lookup.clone()),
        Some(async_lookup),
        tor,
        Url::parse("https://eth.example").unwrap(),
        Arc::new(DefaultIsolationPolicy),
        None,
    )
}

fn transport_with_dual_sync(
    accounts: MapLookup,
    tokens: MapLookup,
    tor: Arc<MockTorRpc>,
) -> PrivacyTransport {
    PrivacyTransport::new(
        router(),
        Some(Arc::new(SyncLookupAdapter::new(Arc::new(accounts)))),
        Some(Arc::new(SyncLookupAdapter::new(Arc::new(tokens)))),
        tor,
        Url::parse("https://eth.example").unwrap(),
        Arc::new(DefaultIsolationPolicy),
        None,
    )
}

fn transport_with_tor_pir(tor: Arc<MockTorRpc>) -> PrivacyTransport {
    let lookup = Arc::new(TorPirLookup::new(Arc::clone(&tor) as _, "https://pir.example").unwrap());
    PrivacyTransport::new(
        router(),
        Some(lookup.clone()),
        Some(lookup),
        tor,
        Url::parse("https://eth.example").unwrap(),
        Arc::new(DefaultIsolationPolicy),
        None,
    )
}

async fn call(mut t: PrivacyTransport, packet: RequestPacket) -> ResponsePacket {
    Service::call(&mut t, packet).await.unwrap()
}

fn success_values(packet: ResponsePacket) -> Vec<Value> {
    let resps = match packet {
        ResponsePacket::Single(r) => vec![r],
        ResponsePacket::Batch(rs) => rs,
    };
    resps
        .into_iter()
        .map(|r| match r.payload {
            ResponsePayload::Success(raw) => serde_json::from_str(raw.get()).unwrap(),
            ResponsePayload::Failure(err) => panic!("rpc failure: {err:?}"),
        })
        .collect()
}

#[tokio::test]
async fn pir_items_never_hit_ethereum_tor_rpc() {
    let lookup = MapLookup::default();
    lookup.insert(addr(1), account_bytes(99, 1));
    let tor = Arc::new(MockTorRpc::default());
    tor.set("eth_getBalance", json!("0xdead"));
    let t = transport_with_sync_pir(lookup, Arc::clone(&tor));
    let packet = RequestPacket::Single(serialize_req(
        "eth_getBalance",
        1,
        json!([addr_hex(1), "latest"]),
    ));
    let values = success_values(call(t, packet).await);
    assert_eq!(values[0], json!("0x63"));
    assert!(tor.shared_batches().is_empty());
    assert!(tor.isolated_batches().is_empty());
}

#[tokio::test]
async fn pir_over_tor_uses_shared_http_post() {
    let tor = Arc::new(MockTorRpc::default());
    tor.set_pir(addr(1), account_bytes(99, 1));
    tor.set("eth_getBalance", json!("0xdead"));
    let t = transport_with_tor_pir(Arc::clone(&tor));
    let packet = RequestPacket::Single(serialize_req(
        "eth_getBalance",
        1,
        json!([addr_hex(1), "latest"]),
    ));
    let values = success_values(call(t, packet).await);
    assert_eq!(values[0], json!("0x63"));
    assert_eq!(tor.http_post_count(), 1);
    assert!(
        tor.http_post_urls()[0].ends_with("/lookup"),
        "posts go to PIR /lookup"
    );
    assert!(tor.shared_batches().is_empty());
    assert!(tor.isolated_batches().is_empty());
}

#[tokio::test]
async fn account_balance_and_nonce_dedupe_one_lookup() {
    let lookup = MapLookup::default();
    lookup.insert(addr(1), account_bytes(10, 3));
    let tor = Arc::new(MockTorRpc::default());
    let t = transport_with_sync_pir(lookup, Arc::clone(&tor));
    let packet = RequestPacket::Batch(vec![
        serialize_req(
            "eth_getBalance",
            1,
            json!([addr_hex(1), "latest"]),
        ),
        serialize_req(
            "eth_getTransactionCount",
            2,
            json!([addr_hex(1), "latest"]),
        ),
    ]);
    let values = success_values(call(t, packet).await);
    assert_eq!(values[0], json!("0xa"));
    assert_eq!(values[1], json!("0x3"));
}

#[tokio::test]
async fn pir_over_tor_batches_keys_in_one_post() {
    let tor = Arc::new(MockTorRpc::default());
    tor.set_pir(addr(1), account_bytes(10, 1));
    tor.set_pir(addr(2), account_bytes(20, 2));
    let t = transport_with_tor_pir(Arc::clone(&tor));
    let packet = RequestPacket::Batch(vec![
        serialize_req(
            "eth_getBalance",
            1,
            json!([addr_hex(1), "latest"]),
        ),
        serialize_req(
            "eth_getTransactionCount",
            2,
            json!([addr_hex(2), "latest"]),
        ),
    ]);
    let values = success_values(call(t, packet).await);
    assert_eq!(values[0], json!("0xa"));
    assert_eq!(values[1], json!("0x2"));
    assert_eq!(tor.http_post_count(), 1, "one shared Tor POST for the batch");
}

#[tokio::test]
async fn builder_pir_over_tor_wires_lookup() {
    let tor = Arc::new(MockTorRpc::default());
    tor.set_pir(addr(3), account_bytes(7, 0));
    let transport = PrivacyBuilder::new("https://eth.example")
        .unwrap()
        .tor_backend(Arc::clone(&tor) as _)
        .pir_over_tor("https://pir.example", None, Vec::new())
        .build_transport()
        .unwrap();
    let packet = RequestPacket::Single(serialize_req(
        "eth_getBalance",
        1,
        json!([addr_hex(3), "latest"]),
    ));
    let values = success_values(call(transport, packet).await);
    assert_eq!(values[0], json!("0x7"));
    assert_eq!(tor.http_post_count(), 1);
}

#[tokio::test]
async fn shared_fallbacks_coalesce_to_one_batch() {
    let tor = Arc::new(MockTorRpc::default());
    tor.set("eth_blockNumber", json!("0x10"));
    tor.set("eth_chainId", json!("0x1"));
    let t = transport_with_sync_pir(MapLookup::default(), Arc::clone(&tor));
    let packet = RequestPacket::Batch(vec![
        serialize_req("eth_blockNumber", 1, json!([])),
        serialize_req("eth_chainId", 2, json!([])),
    ]);
    let values = success_values(call(t, packet).await);
    assert_eq!(values, vec![json!("0x10"), json!("0x1")]);
    let shared = tor.shared_batches();
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0].len(), 2);
    assert!(tor.isolated_batches().is_empty());
}

#[tokio::test]
async fn two_eoas_get_two_isolated_multicalls() {
    let tor = Arc::new(MockTorRpc::default());
    tor.set("eth_call", json!("0x01"));
    let t = transport_with_sync_pir(MapLookup::default(), Arc::clone(&tor));
    let packet = RequestPacket::Batch(vec![
        serialize_req(
            "eth_call",
            1,
            json!([{ "to": addr_hex(1), "data": "0xdeadbeef" }, "latest"]),
        ),
        serialize_req(
            "eth_call",
            2,
            json!([{ "to": addr_hex(2), "data": "0xdeadbeef" }, "latest"]),
        ),
    ]);
    let values = success_values(call(t, packet).await);
    assert_eq!(values[0], json!("0x01"));
    assert_eq!(values[1], json!("0x01"));
    assert!(tor.shared_batches().is_empty());
    assert_eq!(tor.isolated_batches().len(), 2);
    for batch in tor.isolated_batches() {
        assert_eq!(batch, vec!["eth_call".to_string()]);
    }
}

#[tokio::test]
async fn mixed_batch_preserves_order_with_tor_pir() {
    let tor = Arc::new(MockTorRpc::default());
    tor.set_pir(addr(7), account_bytes(5, 0));
    tor.set("eth_getLogs", json!([]));
    tor.set("eth_call", json!("0xabcdef"));
    let t = transport_with_tor_pir(Arc::clone(&tor));
    let packet = RequestPacket::Batch(vec![
        serialize_req(
            "eth_getBalance",
            1,
            json!([addr_hex(7), "latest"]),
        ),
        serialize_req("eth_getLogs", 2, json!([{}])),
        serialize_req(
            "eth_call",
            3,
            json!([{ "to": addr_hex(9), "data": "0x00" }, "latest"]),
        ),
    ]);
    let values = success_values(call(t, packet).await);
    assert_eq!(values[0], json!("0x5"));
    assert_eq!(values[1], json!([]));
    assert_eq!(values[2], json!("0xabcdef"));
    assert_eq!(tor.http_post_count(), 1);
    assert_eq!(tor.shared_batches().len(), 1);
    assert_eq!(tor.isolated_batches().len(), 1);
}

#[tokio::test]
async fn without_pir_all_methods_use_tor_rpc() {
    let tor = Arc::new(MockTorRpc::default());
    tor.set("eth_getBalance", json!("0xabc"));
    let t = PrivacyTransport::new(
        router(),
        None,
        None,
        Arc::clone(&tor) as Arc<dyn crate::TorRpcBackend>,
        Url::parse("https://eth.example").unwrap(),
        Arc::new(DefaultIsolationPolicy),
        None,
    );
    let packet = RequestPacket::Single(serialize_req(
        "eth_getBalance",
        1,
        json!([addr_hex(1), "latest"]),
    ));
    let values = success_values(call(t, packet).await);
    assert_eq!(values[0], json!("0xabc"));
    // eth_getBalance packs into Multicall3 eth_call on isolated circuit
    assert_eq!(tor.isolated_batches().len(), 1);
    assert_eq!(tor.isolated_batches()[0], vec!["eth_call".to_string()]);
    assert_eq!(tor.http_post_count(), 0);
}

#[tokio::test]
async fn usdc_balance_of_uses_token_pir_and_pads_four() {
    let holder = addr(5);
    let accounts = MapLookup::default();
    let tokens = MapLookup::default();
    let mut word = [0u8; 32];
    word[31] = 7;
    for token in &PIR_TOKENS {
        tokens.insert(token.balance_key(&holder).as_slice(), storage_cell(word));
    }
    let tor = Arc::new(MockTorRpc::default());
    tor.set("eth_call", json!("0xdead"));
    let t = transport_with_dual_sync(accounts, tokens, Arc::clone(&tor));

    let data = balance_of_data_hex(&holder);
    let packet = RequestPacket::Single(serialize_req(
        "eth_call",
        1,
        json!([{ "to": PIR_TOKENS[0].address, "data": data }, "latest"]),
    ));
    let values = success_values(call(t, packet).await);
    let mut expected = [0u8; 32];
    expected[31] = 7;
    assert_eq!(
        values[0],
        json!(format!("0x{}", hex::encode(expected)))
    );
    // No fallback Tor RPC — padding stays on PIR
    assert!(tor.isolated_batches().is_empty());
    assert!(tor.shared_batches().is_empty());
}

#[tokio::test]
async fn get_code_stays_on_fallback() {
    let tor = Arc::new(MockTorRpc::default());
    tor.set("eth_getCode", json!("0x6080"));
    let t = transport_with_sync_pir(MapLookup::default(), Arc::clone(&tor));
    let packet = RequestPacket::Single(serialize_req(
        "eth_getCode",
        1,
        json!([addr_hex(1), "latest"]),
    ));
    let values = success_values(call(t, packet).await);
    assert_eq!(values[0], json!("0x6080"));
    assert_eq!(tor.isolated_batches().len(), 1);
    assert_eq!(tor.isolated_batches()[0], vec!["eth_getCode".to_string()]);
}
