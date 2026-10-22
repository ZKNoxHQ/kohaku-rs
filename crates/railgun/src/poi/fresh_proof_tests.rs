//! Opt-in native proving test: public dummy notes, pinned provisioned artifacts, loopback only.

use std::{collections::HashMap, path::Path, sync::Arc};

use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::{Duration, timeout},
};

use super::*;
use crate::{
    account::signer::PrivateKeySigner,
    caip::AssetId,
    crypto::{
        keys::{ByteKey, SpendingKey, ViewingKey},
        railgun_txid::Txid,
    },
    indexer::syncer::{Operation, SyncerError},
    merkle_tree::{PoiMerkleTree, TxidLeafHash},
    poi::conformance_tests::assert_fresh_submission,
    railgun_database::write_poi_snapshot,
};

// Compressed files in the production loader's pinned artifact commit 98e6a5255ae4a12bcc1fdaa8ba3bfcf2e805166d.
const ARTIFACTS: [(&str, &str); 3] = [
    (
        "proving_key.bin.br",
        "dcb2f6e793fe47a8e32ba457085834dc11aebaab3336783fb9af592b7455b7c9",
    ),
    (
        "matrices.bin.br",
        "0d306640d3e6783921facfb60bc01dfe20da5b86fc15258c07d85de0407da347",
    ),
    (
        "wasm.br",
        "ff916dc7a95e593b70d0bdf6626bcba1104a22f33298fc1a2a64936325197493",
    ),
];

fn checked_artifact(bytes: &[u8], digest: &str) -> bool {
    hex::encode(Sha256::digest(bytes)) == digest
}

fn load_artifacts(directory: &Path) -> std::io::Result<HashMap<String, Vec<u8>>> {
    ARTIFACTS
        .into_iter()
        .map(|(file, digest)| {
            let bytes = std::fs::read(directory.join(file))?;
            if !checked_artifact(&bytes, digest) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("artifact digest mismatch: {file}"),
                ));
            }
            Ok((format!("/railgun/poi/03x03/{file}"), bytes))
        })
        .collect()
}

#[test]
fn altered_or_missing_artifacts_cannot_start_the_fixture() {
    let directory = std::env::temp_dir().join(format!(
        "kohaku-proof-artifact-negative-{}-{}",
        std::process::id(),
        web_time::SystemTime::now()
            .duration_since(web_time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    assert_eq!(
        load_artifacts(&directory).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(directory.join(ARTIFACTS[0].0), b"altered artifact").unwrap();
    assert_eq!(
        load_artifacts(&directory).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
}

struct Artifacts {
    url: String,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Vec<String>>,
}

impl Artifacts {
    async fn serve(directory: &Path) -> Self {
        // Read and authenticate everything before opening the listener. No download fallback.
        let files = load_artifacts(directory).expect("provision all pinned 03x03 artifacts first");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (stop, mut stopping) = oneshot::channel();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            loop {
                let (mut socket, _) = tokio::select! {
                    _ = &mut stopping => break,
                    accepted = listener.accept() => accepted.unwrap(),
                };
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                timeout(Duration::from_secs(5), async {
                    while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                        let n = socket.read(&mut buffer).await.unwrap();
                        assert!(n > 0 && request.len() + n <= 8192);
                        request.extend_from_slice(&buffer[..n]);
                    }
                })
                .await
                .unwrap();
                let request = std::str::from_utf8(&request).unwrap();
                let line = request.lines().next().unwrap();
                let path = line
                    .strip_prefix("GET ")
                    .unwrap()
                    .strip_suffix(" HTTP/1.1")
                    .unwrap();
                let data = files
                    .get(path)
                    .expect("only the pinned 03x03 files are served");
                requests.push(path.to_owned());
                assert!(requests.len() <= 3, "unexpected artifact request or retry");
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    data.len()
                );
                timeout(Duration::from_secs(10), async {
                    socket.write_all(header.as_bytes()).await.unwrap();
                    socket.write_all(data).await.unwrap();
                })
                .await
                .unwrap();
            }
            requests
        });
        Self { url, stop, task }
    }

    async fn close(self) {
        self.stop.send(()).unwrap();
        let requests = self.task.await.unwrap();
        assert_eq!(
            requests,
            ARTIFACTS.map(|(file, _)| format!("/railgun/poi/03x03/{file}"))
        );
    }
}

struct NoSync;
#[async_trait::async_trait]
impl TxidSyncer for NoSync {
    async fn latest_block(&self) -> Result<u64, SyncerError> {
        panic!("no external sync in fixture")
    }
    async fn sync(&self, _: u64, _: u64) -> Result<Vec<Operation>, SyncerError> {
        panic!("no external sync in fixture")
    }
}

#[tokio::test]
#[ignore = "expensive native proof; provision pinned artifacts and set KOHAKU_POI_3X3_ARTIFACTS"]
async fn fresh_native_poi_proof_passes_the_independent_service() {
    fresh_case(false).await;
}

#[tokio::test]
#[ignore = "expensive native proof; provision pinned artifacts and set KOHAKU_POI_3X3_ARTIFACTS"]
async fn fresh_native_poi_with_unshield_passes_the_independent_service() {
    fresh_case(true).await;
}

async fn fresh_case(has_unshield: bool) {
    let directory = std::env::var_os("KOHAKU_POI_3X3_ARTIFACTS")
        .expect("set KOHAKU_POI_3X3_ARTIFACTS to the provisioned 03x03 directory");
    let artifacts = Artifacts::serve(Path::new(&directory)).await;
    let prover = Groth16Prover::with_test_artifacts(&artifacts.url);
    let (entry, input, output) = public_entry(has_unshield);
    let txid = entry.txid;
    let mut poi_tree = PoiMerkleTree::new(0);
    poi_tree.insert_leaves(&[U256::from(1), U256::from(2), input.blinded_commitment], 0);
    let store = Store::create();
    write_poi_snapshot(&store, &entry.list_keys[0], 3, &[(0, poi_tree.state())])
        .await
        .unwrap();
    let provider = PoiProvider::new(
        11_155_111,
        store,
        Arc::new(NoSync),
        "http://127.0.0.1:1",
        entry.list_keys.clone(),
    )
    .await
    .unwrap();
    let mut txid_tree = TxidMerkleTree::new(3);
    let index = UtxoTreeIndex::included(output.tree_number, output.leaf_index);
    txid_tree.insert_leaves(
        &[
            U256::from(1).into(),
            TxidLeafHash::new(txid, input.tree_number, index),
        ],
        0,
    );
    // Exercise the production cache membership -> inputs -> witness -> prover -> wire-data path.
    let mut proofs = provider
        .create_proof(
            &prover,
            &entry,
            3,
            output.tree_number,
            output.leaf_index,
            &txid_tree,
            index,
        )
        .await
        .unwrap();
    let data = proofs.remove(&entry.list_keys[0]).unwrap();
    assert!(proofs.is_empty());
    assert_eq!(
        data.blinded_commitments_out,
        vec![output.blinded_commitment.into()]
    );
    assert_eq!(data.txid_merkleroot, txid_tree.root());
    assert_eq!(data.txid_merkleroot_index, 3 * 65_536 + 1);
    assert_eq!(
        data.railgun_txid_if_has_unshield,
        if has_unshield {
            txid
        } else {
            U256::ZERO.into()
        }
    );
    assert_fresh_submission(data).await;
    artifacts.close().await;
}

fn public_entry(has_unshield: bool) -> (PendingPoiEntry, UtxoNote, UtxoNote) {
    let alice = PrivateKeySigner::new_evm(
        SpendingKey::from_bytes([1; 32]),
        ViewingKey::from_bytes([2; 32]),
        11_155_111,
    );
    let bob = PrivateKeySigner::new_evm(
        SpendingKey::from_bytes([3; 32]),
        ViewingKey::from_bytes([4; 32]),
        11_155_111,
    );
    let asset = AssetId::Erc20(alloy::primitives::address!(
        "1234567890123456789012345678901234567890"
    ));
    let input = UtxoNote::new(
        1,
        7,
        alice,
        asset,
        100,
        [5; 16],
        "",
        BlindedCommitmentType::Shield,
    );
    let output = UtxoNote::new(
        2,
        11,
        bob,
        asset,
        if has_unshield { 60 } else { 100 },
        [6; 16],
        "",
        BlindedCommitmentType::Transact,
    );
    let bound_params_hash = U256::from(17);
    let mut out_commitments = vec![output.hash.into()];
    if has_unshield {
        // As in a real partial unshield, the public-address commitment is last and has no UTXO leaf.
        out_commitments.push(
            kohaku_crypto::poseidon_hash(&[U256::from(42), asset.hash(), U256::from(40)]).unwrap(),
        );
    }
    let txid = Txid::new(&[input.nullifier], &out_commitments, bound_params_hash);
    let entry = PendingPoiEntry {
        txid,
        spending_pubkey: input.spending_pubkey,
        nullifying_key: input.nullifying_key,
        utxo_tree_in: input.tree_number,
        bound_params_hash,
        in_notes: vec![input.clone()],
        out_commitments,
        out_npks: vec![output.note_public_key],
        out_values: vec![U256::from(output.value)],
        token_hash: asset.hash(),
        has_unshield,
        list_keys: vec!["public-fixture-list".into()],
        created_at: 0,
    };
    (entry, input, output)
}
