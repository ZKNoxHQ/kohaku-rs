//! Utility to convert circuit artifacts from their original snark-js .zkey format
//! into circom-friendly proving keys and matrices.
//!
//! Conversion step takes upward of 3 seconds in release mode, so we want to do this
//! once.
//!
//! Usage:
//!   main                                              # legacy: transact 01x01..05x05 from the
//!                                                     # original Railgun release, into ./
//!   main <ipfs-base> <out-dir> <circuit> [circuit…]   # any release, e.g. the POI circuits:
//!   main https://ipfs-lb.com/ipfs/QmZ2My…new artifacts/railgun/poi 03x03 13x13
//!
//! The release layout is `{base}/circuits/{name}/zkey.br` and
//! `{base}/prover/snarkjs/{name}.wasm.br`. When the release also publishes
//! `{base}/circuits/{name}/vkey.json` (snarkjs format), the verifying key embedded in the
//! converted proving key is checked against it field by field: a mismatch aborts. Each output
//! file's SHA-256 is printed, for pinning.

use std::io::Cursor;

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_circom::read_zkey;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use kohaku_railgun::crypto::serializable_np_index::SerializableNpIndex;
use num_bigint::BigUint;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::info;

const LEGACY_IPFS_BASE: &str =
    "https://ipfs-lb.com/ipfs/QmUsmnK4PFc7zDp2cmC4wBZxYLjNyRgWfs5GNcJJ2uLcpU";

pub async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--check-vk") {
        // main --check-vk <proving_key.bin.br> <vkey.json path or URL>
        let (pk_path, vkey_src) = (&args[1], &args[2]);
        let mut raw = Vec::new();
        brotli::BrotliDecompress(&mut std::fs::read(pk_path).unwrap().as_slice(), &mut raw)
            .unwrap();
        let pk = ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut Cursor::new(raw))
            .expect("Failed to deserialize proving key");
        let vkey: Value = if vkey_src.starts_with("http") {
            serde_json::from_slice(&fetch(vkey_src).await).unwrap()
        } else {
            serde_json::from_slice(&std::fs::read(vkey_src).unwrap()).unwrap()
        };
        check_vkey(&pk.vk, &vkey, pk_path);
        println!("MATCH {pk_path}");
        return;
    }
    if args.is_empty() {
        for i in 1..6 {
            for j in 1..6 {
                let circuit_name = format!("0{}x0{}", i, j);
                convert_artifacts(LEGACY_IPFS_BASE, ".", &circuit_name).await;
            }
        }
        return;
    }
    if args.len() < 3 {
        eprintln!("usage: main <ipfs-base> <out-dir> <circuit> [circuit…]");
        std::process::exit(2);
    }
    let base = args[0].trim_end_matches('/');
    let out_dir = &args[1];
    for circuit_name in &args[2..] {
        convert_artifacts(base, out_dir, circuit_name).await;
    }
}

async fn fetch(url: &str) -> Vec<u8> {
    info!("Downloading {}", url);
    let resp = reqwest::get(url).await.unwrap();
    assert!(resp.status().is_success(), "{url}: HTTP {}", resp.status());
    resp.bytes().await.unwrap().to_vec()
}

async fn convert_artifacts(base: &str, out_dir: &str, circuit_name: &str) {
    info!("Converting artifacts for circuit: {}", circuit_name);

    let compressed = fetch(&format!("{}/circuits/{}/zkey.br", base, circuit_name)).await;
    let mut zkey = Vec::new();
    brotli::BrotliDecompress(&mut compressed.as_slice(), &mut zkey).unwrap();

    info!("Parsing .zkey file");
    let mut cursor = Cursor::new(zkey);
    let (proving_key, matrices) = read_zkey(&mut cursor).unwrap();
    let matrices: SerializableNpIndex<_> = matrices.into();

    // Cross-check against the release's own verifying key, when it publishes one.
    let vkey_url = format!("{}/circuits/{}/vkey.json", base, circuit_name);
    match reqwest::get(&vkey_url).await {
        Ok(resp) if resp.status().is_success() => {
            let vkey: Value = resp.json().await.unwrap();
            check_vkey(&proving_key.vk, &vkey, circuit_name);
            info!("{circuit_name}: verifying key matches the release's vkey.json");
        }
        _ => info!("{circuit_name}: no vkey.json in this release, cross-check skipped"),
    }

    let dir = format!("{}/{}", out_dir, circuit_name);
    std::fs::create_dir_all(&dir).unwrap();
    let wasm_path = format!("{}/wasm.br", dir);
    let proving_key_path = format!("{}/proving_key.bin.br", dir);
    let matrices_path = format!("{}/matrices.bin.br", dir);

    let wasm_bytes = fetch(&format!("{}/prover/snarkjs/{}.wasm.br", base, circuit_name)).await;
    std::fs::write(&wasm_path, &wasm_bytes).unwrap();

    let params = brotli::enc::BrotliEncoderParams::default();

    info!("Serializing proving key and matrices to disk");
    let mut proving_key_bytes = Vec::new();
    proving_key
        .serialize_uncompressed(&mut proving_key_bytes)
        .unwrap();
    let mut proving_key_file = std::fs::File::create(&proving_key_path).unwrap();
    brotli::BrotliCompress(
        &mut proving_key_bytes.as_slice(),
        &mut proving_key_file,
        &params,
    )
    .unwrap();
    proving_key_file.sync_all().unwrap();

    let mut matrices_bytes = Vec::new();
    matrices
        .serialize_uncompressed(&mut matrices_bytes)
        .unwrap();
    let mut matrices_file = std::fs::File::create(&matrices_path).unwrap();
    brotli::BrotliCompress(&mut matrices_bytes.as_slice(), &mut matrices_file, &params).unwrap();
    matrices_file.sync_all().unwrap();

    info!("Artifacts converted and saved to disk. Verifying...");

    let mut proving_key_disk = Vec::new();
    brotli::BrotliDecompress(
        &mut std::fs::read(&proving_key_path).unwrap().as_slice(),
        &mut proving_key_disk,
    )
    .unwrap();
    let proving_key_read_back =
        ProvingKey::<Bn254>::deserialize_uncompressed_unchecked(&mut Cursor::new(proving_key_disk))
            .expect("Failed to deserialize proving key");
    assert_eq!(proving_key, proving_key_read_back);

    let mut matrices_disk = Vec::new();
    brotli::BrotliDecompress(
        &mut std::fs::read(&matrices_path).unwrap().as_slice(),
        &mut matrices_disk,
    )
    .unwrap();
    let matrices_read_back = SerializableNpIndex::<Fr>::deserialize_uncompressed_unchecked(
        &mut Cursor::new(matrices_disk),
    )
    .expect("Failed to deserialize matrices");
    assert_eq!(matrices, matrices_read_back);

    for path in [&wasm_path, &proving_key_path, &matrices_path] {
        let digest = Sha256::digest(std::fs::read(path).unwrap());
        println!("sha256 {}  {}", hex::encode(digest), path);
    }

    info!(
        "Conversion complete. WASM saved to {}, proving key saved to {}, matrices saved to {}",
        wasm_path, proving_key_path, matrices_path
    );
}

fn dec(f: Fq) -> String {
    BigUint::from_bytes_le(&f.into_bigint().to_bytes_le()).to_string()
}

fn json_str(v: &Value) -> &str {
    v.as_str()
        .expect("vkey.json: field elements are decimal strings")
}

/// snarkjs G1: `[x, y, "1"]`.
fn check_g1(what: &str, p: &G1Affine, v: &Value) {
    assert_eq!(dec(p.x), json_str(&v[0]), "{what}.x");
    assert_eq!(dec(p.y), json_str(&v[1]), "{what}.y");
}

/// snarkjs G2: `[[x.c0, x.c1], [y.c0, y.c1], ["1", "0"]]`.
fn check_g2(what: &str, p: &G2Affine, v: &Value) {
    let pair = |f: Fq2| (dec(f.c0), dec(f.c1));
    let (x0, x1) = pair(p.x);
    let (y0, y1) = pair(p.y);
    assert_eq!(x0, json_str(&v[0][0]), "{what}.x.c0");
    assert_eq!(x1, json_str(&v[0][1]), "{what}.x.c1");
    assert_eq!(y0, json_str(&v[1][0]), "{what}.y.c0");
    assert_eq!(y1, json_str(&v[1][1]), "{what}.y.c1");
}

fn check_vkey(vk: &VerifyingKey<Bn254>, json: &Value, circuit: &str) {
    assert_eq!(
        json["protocol"], "groth16",
        "{circuit}: vkey.json is not groth16"
    );
    assert_eq!(
        json["curve"], "bn128",
        "{circuit}: vkey.json is not on bn128"
    );
    check_g1("vk_alpha_1", &vk.alpha_g1, &json["vk_alpha_1"]);
    check_g2("vk_beta_2", &vk.beta_g2, &json["vk_beta_2"]);
    check_g2("vk_gamma_2", &vk.gamma_g2, &json["vk_gamma_2"]);
    check_g2("vk_delta_2", &vk.delta_g2, &json["vk_delta_2"]);
    let ic = json["IC"].as_array().expect("vkey.json: IC array");
    assert_eq!(ic.len(), vk.gamma_abc_g1.len(), "{circuit}: IC length");
    for (i, (p, v)) in vk.gamma_abc_g1.iter().zip(ic).enumerate() {
        check_g1(&format!("IC[{i}]"), p, v);
    }
    assert_eq!(
        json["nPublic"].as_u64().unwrap_or(u64::MAX) as usize + 1,
        vk.gamma_abc_g1.len(),
        "{circuit}: nPublic"
    );
}
