//! Offline conformance fixture, not a list provider or a live-chain qualification.
//! Real Groth16 verification; synthetic roots/status transitions and no artifact downloads.

use std::{
    collections::HashSet,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
};

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_groth16::{Groth16, PreparedVerifyingKey, VerifyingKey, prepare_verifying_key};
use kohaku_kv_store::{Store, file::FileStore};
use ruint::aliases::U256;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{Notify, oneshot},
    time::{Duration, timeout},
};

use super::{
    client::{PoiClient, PoiClientError, PoiNodeClient},
    types::{BlindedCommitment, ListKey, SubmitTransactProofParams, TransactProofData},
};
use crate::{
    crypto::railgun_txid::Txid,
    indexer::{
        syncer::{Operation, SyncerError, TxidSyncer},
        txid_indexer::{TxidIndexer, TxidIndexerError},
    },
    merkle_tree::{MerkleTree, TxidLeafHash, TxidMerkleTree, UtxoTreeIndex},
    railgun_database::RailgunDB,
};

const LIST: &str = "public-fixture-list";
const CHAIN: u64 = 11_155_111;
const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/poi-conformance/"
);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    input_count: usize,
    output_count: usize,
    proof_data: TransactProofData,
    public_signals: Vec<String>,
}

fn fixture(name: &str) -> Fixture {
    serde_json::from_slice(&std::fs::read(format!("{FIXTURES}{name}.json")).unwrap()).unwrap()
}

#[derive(Deserialize)]
struct KeyJson {
    protocol: String,
    curve: String,
    #[serde(rename = "nPublic")]
    n_public: usize,
    vk_alpha_1: [String; 3],
    vk_beta_2: [[String; 2]; 3],
    vk_gamma_2: [[String; 2]; 3],
    vk_delta_2: [[String; 2]; 3],
    #[serde(rename = "IC")]
    ic: Vec<[String; 3]>,
}

// Reject noncanonical fields instead of reducing malformed proof coordinates modulo p.
fn field<F: PrimeField<BigInt = ark_ff::BigInt<4>>>(value: U256) -> Result<F, &'static str> {
    if value >= U256::from_limbs(F::MODULUS.0) {
        return Err("out-of-field value");
    }
    Ok(F::from_be_bytes_mod_order(&value.to_be_bytes::<32>()))
}

fn decimal(value: &str) -> U256 {
    U256::from_str(value).unwrap()
}

fn g1(x: U256, y: U256) -> Result<G1Affine, &'static str> {
    let point = G1Affine::new_unchecked(field(x)?, field(y)?);
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err("invalid G1");
    }
    Ok(point)
}

fn g2(x: [U256; 2], y: [U256; 2]) -> Result<G2Affine, &'static str> {
    // snarkjs and kohaku's Proof use Fq2 c0,c1 order, with no Solidity swap.
    let point = G2Affine::new_unchecked(
        Fq2::new(field(x[0])?, field(x[1])?),
        Fq2::new(field(y[0])?, field(y[1])?),
    );
    if !point.is_on_curve() || !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err("invalid G2");
    }
    Ok(point)
}

fn key(name: &str) -> PreparedVerifyingKey<Bn254> {
    let json: KeyJson =
        serde_json::from_slice(&std::fs::read(format!("{FIXTURES}{name}-vkey.json")).unwrap())
            .unwrap();
    assert_eq!(json.protocol, "groth16");
    assert_eq!(json.curve, "bn128");
    assert_eq!(json.ic.len(), json.n_public + 1);
    let g1_json = |value: &[String; 3]| {
        assert_eq!(value[2], "1");
        g1(decimal(&value[0]), decimal(&value[1])).unwrap()
    };
    let g2_json = |value: &[[String; 2]; 3]| {
        assert_eq!(value[2], ["1", "0"]);
        g2(
            [decimal(&value[0][0]), decimal(&value[0][1])],
            [decimal(&value[1][0]), decimal(&value[1][1])],
        )
        .unwrap()
    };
    prepare_verifying_key(&VerifyingKey {
        alpha_g1: g1_json(&json.vk_alpha_1),
        beta_g2: g2_json(&json.vk_beta_2),
        gamma_g2: g2_json(&json.vk_gamma_2),
        delta_g2: g2_json(&json.vk_delta_2),
        gamma_abc_g1: json.ic.iter().map(g1_json).collect(),
    })
}

fn signals(data: &TransactProofData, size: usize) -> Vec<U256> {
    assert!(data.blinded_commitments_out.len() <= size && data.poi_merkleroots.len() <= size);
    let mut signals: Vec<U256> = data
        .blinded_commitments_out
        .iter()
        .map(|value| (*value).into())
        .collect();
    signals.resize(size, U256::ZERO);
    signals.push(data.txid_merkleroot.into());
    signals.push(data.railgun_txid_if_has_unshield.into());
    signals.extend(
        data.poi_merkleroots
            .iter()
            .map(|root| <U256 as From<_>>::from(*root)),
    );
    signals.resize(size * 2 + 2, MerkleTree::zero());
    signals
}

fn verify(
    data: &TransactProofData,
    key: &PreparedVerifyingKey<Bn254>,
) -> Result<bool, &'static str> {
    let proof = &data.proof;
    let proof = ark_groth16::Proof {
        a: g1(proof.a.x, proof.a.y)?,
        b: g2(proof.b.x, proof.b.y)?,
        c: g1(proof.c.x, proof.c.y)?,
    };
    let size = (key.vk.gamma_abc_g1.len() - 3) / 2;
    let public = signals(data, size)
        .into_iter()
        .map(field::<Fr>)
        .collect::<Result<Vec<_>, _>>()?;
    Groth16::<Bn254>::verify_proof(key, &proof, &public).map_err(|_| "verification failed")
}

#[test]
fn retained_keys_and_public_fixtures_are_pinned() {
    for (file, digest) in [
        (
            "current-3x3-vkey.json",
            "e6ac836dcabb1d70f3924f172d8edd52e09269f87a0d5b977650c63a8070bd31",
        ),
        (
            "current-13x13-vkey.json",
            "b939fbc34c9ba9cc294a8b5c1e72ddc4088e559d351dc4fab7b71234d34bbb17",
        ),
        (
            "retired-3x3-vkey.json",
            "92120a7dfda25cc56c79ce7047f2ff8596f4d96e95dcdc2ff4d599a5cdcf5c56",
        ),
        (
            "current-3x3.json",
            "8fca4b56dda834463916e281c4f286c8f2bdc6536791ab371520610405f6bf5e",
        ),
        (
            "current-13x13-unshield.json",
            "a1064270bbe255cab85106209a42a0a8b0666cb404f7f7bb481d47c3c8926dcc",
        ),
        (
            "retired-3x3.json",
            "6a2dc9544779612070413021d9018c7f55f443d7315626c3080ec9853a4f07a4",
        ),
    ] {
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(std::fs::read(format!("{FIXTURES}{file}")).unwrap())
            ),
            digest,
            "{file}"
        );
    }
}

#[test]
fn current_and_retired_proofs_are_not_interchangeable() {
    let current = key("current-3x3");
    let retired = key("retired-3x3");
    for (name, accepts, rejects) in [
        ("current-3x3", &current, &retired),
        ("retired-3x3", &retired, &current),
    ] {
        let fixture = fixture(name);
        assert_eq!((fixture.input_count, fixture.output_count), (1, 1));
        assert_eq!(
            signals(&fixture.proof_data, 3),
            fixture
                .public_signals
                .iter()
                .map(|s| decimal(s))
                .collect::<Vec<_>>()
        );
        assert!(verify(&fixture.proof_data, accepts).unwrap());
        assert!(!verify(&fixture.proof_data, rejects).unwrap());
        let mut changed = fixture.proof_data.clone();
        changed.txid_merkleroot =
            (<U256 as From<_>>::from(changed.txid_merkleroot) + U256::from(1)).into();
        assert!(!verify(&changed, accepts).unwrap());
    }
}

#[test]
fn unshield_boundary_uses_the_full_circuit() {
    let fixture = fixture("current-13x13-unshield");
    assert_eq!((fixture.input_count, fixture.output_count), (1, 4));
    assert_eq!(fixture.proof_data.blinded_commitments_out.len(), 3);
    assert_ne!(
        Into::<U256>::into(fixture.proof_data.railgun_txid_if_has_unshield),
        U256::ZERO
    );
    assert_eq!(
        signals(&fixture.proof_data, 13),
        fixture
            .public_signals
            .iter()
            .map(|s| decimal(s))
            .collect::<Vec<_>>()
    );
    assert!(verify(&fixture.proof_data, &key("current-13x13")).unwrap());
    assert!(!verify(&fixture.proof_data, &key("current-3x3")).unwrap());
}

#[test]
fn changed_payload_and_malformed_points_are_rejected() {
    let data = fixture("current-3x3").proof_data;
    let key = key("current-3x3");
    for category in 0..4 {
        let mut changed = data.clone();
        match category {
            0 => {
                changed.blinded_commitments_out[0] =
                    (<U256 as From<_>>::from(changed.blinded_commitments_out[0]) + U256::from(1))
                        .into();
            }
            1 => {
                changed.poi_merkleroots[0] =
                    (<U256 as From<_>>::from(changed.poi_merkleroots[0]) + U256::from(1)).into();
            }
            2 => changed.railgun_txid_if_has_unshield = U256::from(1).into(),
            _ => {
                changed.txid_merkleroot =
                    (<U256 as From<_>>::from(changed.txid_merkleroot) + U256::from(1)).into();
            }
        }
        assert!(!verify(&changed, &key).unwrap());
    }
    let mut changed = data.clone();
    changed.proof.a.x = U256::from(1);
    changed.proof.a.y = U256::from(3);
    assert!(verify(&changed, &key).is_err());
    changed.proof.a.x = U256::from_limbs(Fq::MODULUS.0);
    assert!(verify(&changed, &key).is_err());
    changed = data;
    changed.proof.b.x.swap(0, 1);
    changed.proof.b.y.swap(0, 1);
    assert!(verify(&changed, &key).is_err());
}

#[derive(Default)]
struct ServiceState {
    accepted: HashSet<BlindedCommitment>,
    methods: Vec<String>,
    drop_next_submit: bool,
    fail_root: bool,
    root_reads: usize,
    fail_root_at: Option<usize>,
    latest_index: u32,
}

struct Service {
    url: String,
    state: Arc<Mutex<ServiceState>>,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

fn assert_submission_wire(params: &Value) {
    assert_eq!(params["chainType"], "0");
    assert_eq!(params["txidVersion"], "V2_PoseidonMerkle");
    let data = &params["transactProofData"];
    let fields: HashSet<_> = data
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        fields,
        HashSet::from([
            "snarkProof",
            "poiMerkleroots",
            "txidMerkleroot",
            "txidMerklerootIndex",
            "blindedCommitmentsOut",
            "railgunTxidIfHasUnshield"
        ])
    );
    let hex = |value: &Value, prefix: bool| {
        let string = value.as_str().unwrap();
        let digits = if prefix {
            string.strip_prefix("0x").unwrap()
        } else {
            string
        };
        assert_eq!(digits.len(), 64);
        assert!(
            digits
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    };
    hex(&data["txidMerkleroot"], false);
    for value in data["poiMerkleroots"].as_array().unwrap() {
        hex(value, false);
    }
    for value in data["blindedCommitmentsOut"].as_array().unwrap() {
        hex(value, true);
    }
    // Kohaku uses a full-width zero, while the SDK uses 0x00. The public node
    // tests this marker numerically; do not mistake this normalization for a new wire rule.
    hex(&data["railgunTxidIfHasUnshield"], true);
    assert!(data["txidMerklerootIndex"].is_u64());
    let decimal = |value: &Value| {
        let value = value.as_str().unwrap();
        assert!(!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()));
    };
    let proof = &data["snarkProof"];
    assert_eq!(
        proof
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<HashSet<_>>(),
        HashSet::from(["pi_a", "pi_b", "pi_c"])
    );
    for name in ["pi_a", "pi_c"] {
        assert_eq!(proof[name].as_array().unwrap().len(), 2);
        for value in proof[name].as_array().unwrap() {
            decimal(value);
        }
    }
    assert_eq!(proof["pi_b"].as_array().unwrap().len(), 2);
    for pair in proof["pi_b"].as_array().unwrap() {
        assert_eq!(pair.as_array().unwrap().len(), 2);
        for value in pair.as_array().unwrap() {
            decimal(value);
        }
    }
}

fn accept_proof(
    state: &mut ServiceState,
    data: &TransactProofData,
    mini: &PreparedVerifyingKey<Bn254>,
    full: &PreparedVerifyingKey<Bn254>,
) -> bool {
    let valid = (data.poi_merkleroots.len() <= 3
        && data.blinded_commitments_out.len() <= 3
        && verify(data, mini).unwrap_or(false))
        || verify(data, full).unwrap_or(false);
    if valid {
        state
            .accepted
            .extend(data.blinded_commitments_out.iter().copied());
    }
    valid
}

impl Service {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(ServiceState::default()));
        let inner = state.clone();
        let (stop, mut stopping) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mini = key("current-3x3");
            let full = key("current-13x13");
            loop {
                let (mut socket, _) = tokio::select! {
                    _ = &mut stopping => break,
                    accepted = listener.accept() => accepted.unwrap(),
                };
                let request = timeout(Duration::from_secs(5), read_request(&mut socket))
                    .await
                    .unwrap();
                assert_eq!(request["jsonrpc"], "2.0");
                assert_eq!(request["params"]["chainID"], CHAIN.to_string());
                let method = request["method"].as_str().unwrap();
                let mut response = json!({"jsonrpc": "2.0", "id": request["id"]});
                let mut status = "200 OK";
                let drop_response = {
                    let mut state = inner.lock().unwrap();
                    state.methods.push(method.to_owned());
                    assert!(state.methods.len() <= 32, "bounded fixture request count");
                    let mut drop_response = false;
                    match method {
                        "ppoi_submit_transact_proof" => {
                            assert_submission_wire(&request["params"]);
                            let params: SubmitTransactProofParams =
                                serde_json::from_value(request["params"].clone()).unwrap();
                            assert_eq!(params.list_key, ListKey::from(LIST));
                            let data = &params.transact_proof_data;
                            // The fixture tries 3x3 then 13x13; root/list acceptance is synthetic.
                            if accept_proof(&mut state, data, &mini, &full) {
                                // Deliberately void: public node handlers can omit result.
                                drop_response = std::mem::take(&mut state.drop_next_submit);
                            } else {
                                status = "400 Bad Request";
                                response["error"] =
                                    json!({"code": -32602, "message": "Invalid proof"});
                            }
                        }
                        "ppoi_validated_txid" => {
                            response["result"] = json!({"validatedTxidIndex": state.latest_index});
                        }
                        "ppoi_validate_txid_merkleroot" => {
                            state.root_reads += 1;
                            if state.fail_root_at == Some(state.root_reads) {
                                response["error"] =
                                    json!({"code": -32000, "message": "Injected root outage"});
                            } else {
                                response["result"] = json!(!state.fail_root);
                            }
                        }
                        _ => panic!("unexpected fixture request"),
                    }
                    drop_response
                };
                if drop_response {
                    continue;
                }
                let body = response.to_string();
                let wire = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                timeout(Duration::from_secs(5), socket.write_all(wire.as_bytes()))
                    .await
                    .unwrap()
                    .unwrap();
            }
        });
        Self {
            url,
            state,
            stop,
            task,
        }
    }

    fn client(&self) -> PoiClient {
        PoiClient::new(CHAIN, self.url.clone(), vec![LIST.into()])
    }

    async fn close(self) {
        self.stop.send(()).unwrap();
        self.task.await.unwrap();
    }
}

async fn read_request(socket: &mut tokio::net::TcpStream) -> Value {
    let mut bytes = Vec::new();
    let mut buffer = [0; 1024];
    loop {
        let n = socket.read(&mut buffer).await.unwrap();
        assert!(n > 0 && bytes.len() + n <= 16_384);
        bytes.extend_from_slice(&buffer[..n]);
        if let Some(end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
            let headers = std::str::from_utf8(&bytes[..end]).unwrap();
            let len: usize = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().unwrap())
                })
                .unwrap();
            assert!(end + 4 + len <= 16_384);
            if bytes.len() >= end + 4 + len {
                return serde_json::from_slice(&bytes[end + 4..end + 4 + len]).unwrap();
            }
        }
    }
}

#[tokio::test]
async fn real_client_submits_current_proofs_and_retired_proofs_stay_missing() {
    let service = Service::new().await;
    let client = service.client();
    let retired = fixture("retired-3x3").proof_data;
    let refused = timeout(
        Duration::from_secs(5),
        client.submit_proof([(LIST.into(), retired)].into()),
    )
    .await
    .unwrap();
    assert!(
        matches!(refused, Err(PoiClientError::Rpc(error)) if error.code == -32602 && error.message == "Invalid proof")
    );
    assert!(service.state.lock().unwrap().accepted.is_empty());
    for name in ["current-3x3", "current-13x13-unshield"] {
        let current = fixture(name).proof_data;
        let output = current.blinded_commitments_out[0];
        timeout(
            Duration::from_secs(5),
            client.submit_proof([(LIST.into(), current)].into()),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(service.state.lock().unwrap().accepted.contains(&output));
    }
    assert_eq!(
        *service.state.lock().unwrap().methods,
        vec![
            "ppoi_submit_transact_proof",
            "ppoi_submit_transact_proof",
            "ppoi_submit_transact_proof",
        ]
    );
    service.close().await;
}

#[tokio::test]
async fn lost_submit_response_is_not_followed_by_another_post() {
    let service = Service::new().await;
    service.state.lock().unwrap().drop_next_submit = true;
    let data = fixture("current-3x3").proof_data;
    let output = data.blinded_commitments_out[0];
    let result = timeout(
        Duration::from_secs(5),
        service.client().submit_proof([(LIST.into(), data)].into()),
    )
    .await
    .unwrap();
    assert!(matches!(result, Err(PoiClientError::Http(_))));
    // The node accepted the proof. The client does not retry the POST and does
    // not ask about this commitment; the local list copy is how that shows up.
    let state = service.state.lock().unwrap();
    assert!(state.accepted.contains(&output));
    assert_eq!(*state.methods, vec!["ppoi_submit_transact_proof"]);
    drop(state);
    service.close().await;
}

fn scratch_store() -> PathBuf {
    // Retain scratch files; public synthetic data only.
    std::env::temp_dir().join(format!(
        "kohaku-poi-conformance-{}-{}.redb",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn operation(block: u64, output: u32) -> Operation {
    Operation {
        block_number: block,
        nullifiers: vec![U256::from(block)],
        commitment_hashes: vec![U256::from(block + 1)],
        bound_params_hash: U256::from(7),
        utxo_tree_in: 0,
        utxo_tree_out: 0,
        utxo_out_start_index: output,
        has_unshield: false,
    }
}

fn txid(op: &Operation) -> Txid {
    Txid::new(&op.nullifiers, &op.commitment_hashes, op.bound_params_hash)
}

struct FixtureSyncer {
    operations: Vec<Operation>,
    entered: Option<Arc<Notify>>,
}
#[async_trait::async_trait]
impl TxidSyncer for FixtureSyncer {
    async fn latest_block(&self) -> Result<u64, SyncerError> {
        Ok(20)
    }
    async fn sync(&self, from: u64, to: u64) -> Result<Vec<Operation>, SyncerError> {
        if let Some(entered) = &self.entered {
            entered.notify_one();
            std::future::pending::<()>().await;
        }
        Ok(self
            .operations
            .iter()
            .filter(|op| (from..=to).contains(&op.block_number))
            .cloned()
            .collect())
    }
}

async fn indexer(store: Store, entered: Option<Arc<Notify>>) -> TxidIndexer {
    TxidIndexer::new(
        store,
        Arc::new(FixtureSyncer {
            operations: vec![operation(10, 0), operation(20, 1)],
            entered,
        }),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn root_outage_then_reopen_preserves_checkpoint_and_replays_without_duplicates() {
    let service = Service::new().await;
    let path = scratch_store();
    {
        let store = Store::new(FileStore::open(&path).unwrap());
        let mut indexer = indexer(store.clone(), None).await;
        timeout(
            Duration::from_secs(5),
            indexer.sync_to(10, &service.client()),
        )
        .await
        .unwrap()
        .unwrap();
        let before = store.get(b"txid_indexer").await.unwrap();
        let tree_before = store.get(b"txid_tree:0").await.unwrap();
        service.state.lock().unwrap().latest_index = 1;
        service.state.lock().unwrap().fail_root_at = Some(2);
        assert!(matches!(
            timeout(
                Duration::from_secs(5),
                indexer.sync_to(20, &service.client())
            )
            .await
            .unwrap(),
            Err(TxidIndexerError::PoiClient(_))
        ));
        assert_eq!(store.get(b"txid_indexer").await.unwrap(), before);
        assert_eq!(store.get(b"txid_tree:0").await.unwrap(), tree_before);
    }
    {
        let store = Store::new(FileStore::open(&path).unwrap());
        assert_eq!(store.get_txid_indexer().await.unwrap().synced_block, 10);
        let mut restored = indexer(store.clone(), None).await;
        assert_eq!(restored.tree(0).unwrap().leaves_len(), 1);
        timeout(
            Duration::from_secs(5),
            restored.sync_to(20, &service.client()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(store.get_txid_indexer().await.unwrap().synced_block, 20);
        assert_eq!(restored.tree(0).unwrap().leaves_len(), 2);
        assert_eq!(
            restored.txid_position(&txid(&operation(10, 0))),
            Some((0, 0))
        );
        assert_eq!(
            restored.txid_position(&txid(&operation(20, 1))),
            Some((0, 1))
        );
        let mut expected = TxidMerkleTree::new(0);
        expected.insert_leaves(
            &[
                TxidLeafHash::new(txid(&operation(10, 0)), 0, UtxoTreeIndex::included(0, 0)),
                TxidLeafHash::new(txid(&operation(20, 1)), 0, UtxoTreeIndex::included(0, 1)),
            ],
            0,
        );
        assert_eq!(restored.tree(0).unwrap().root(), expected.root());
    }
    service.close().await;
}

#[tokio::test]
async fn cancellation_during_acquisition_preserves_the_saved_checkpoint() {
    let service = Service::new().await;
    let path = scratch_store();
    {
        let store = Store::new(FileStore::open(&path).unwrap());
        let mut initial = indexer(store.clone(), None).await;
        timeout(
            Duration::from_secs(5),
            initial.sync_to(10, &service.client()),
        )
        .await
        .unwrap()
        .unwrap();
        drop(initial);
        let entered = Arc::new(Notify::new());
        let mut interrupted = indexer(store.clone(), Some(entered.clone())).await;
        let client = service.client();
        {
            let future = interrupted.sync_to(20, &client);
            tokio::pin!(future);
            tokio::select! {
                result = &mut future => panic!("unexpected completion: {result:?}"),
                result = timeout(Duration::from_secs(5), entered.notified()) => result.unwrap()
            }
        }
        assert_eq!(store.get_txid_indexer().await.unwrap().synced_block, 10);
    }
    {
        let store = Store::new(FileStore::open(&path).unwrap());
        let mut restored = indexer(store.clone(), None).await;
        assert_eq!(restored.tree(0).unwrap().leaves_len(), 1);
        service.state.lock().unwrap().latest_index = 1;
        timeout(
            Duration::from_secs(5),
            restored.sync_to(20, &service.client()),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(store.get_txid_indexer().await.unwrap().synced_block, 20);
        assert_eq!(restored.tree(0).unwrap().leaves_len(), 2);
    }
    service.close().await;
}

/// Independently check a freshly generated payload, then exercise the real client wire path.
pub(super) async fn assert_fresh_submission(data: TransactProofData) {
    assert!(verify(&data, &key("current-3x3")).unwrap());
    assert!(!verify(&data, &key("retired-3x3")).unwrap());
    let mut changed = data.clone();
    changed.txid_merkleroot =
        (<U256 as From<_>>::from(data.txid_merkleroot) + U256::from(1)).into();
    assert!(!verify(&changed, &key("current-3x3")).unwrap());

    let service = Service::new().await;
    let client = service.client();
    let output = data.blinded_commitments_out[0];
    let refused = timeout(
        Duration::from_secs(5),
        client.submit_proof([(LIST.into(), changed)].into()),
    )
    .await
    .unwrap();
    assert!(matches!(refused, Err(PoiClientError::Rpc(error)) if error.code == -32602));
    assert!(service.state.lock().unwrap().accepted.is_empty());
    timeout(
        Duration::from_secs(5),
        client.submit_proof([(LIST.into(), data)].into()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        service.state.lock().unwrap().accepted,
        HashSet::from([output])
    );
    assert_eq!(service.state.lock().unwrap().methods.len(), 2);
    service.close().await;
}
