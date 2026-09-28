//! The APDU protocol of the ZKNOX Railgun Ledger app.
//!
//! This module is the single source of truth for the host side of the wire format; it
//! mirrors the app's instruction table. Every instruction addresses an account by a 4-byte
//! big-endian index; the derivation paths are pinned in the firmware:
//! `m/44'/1984'/account'/0'/0'` for the BabyJubJub spending key and
//! `m/420'/1984'/account'/0'/0'` for the ed25519 viewing key. Note the account sits at the
//! third component, unlike the Railgun engine's `m/44'/1984'/0'/0'/index'`: account 0
//! coincides with the engine's index 0, accounts >= 1 are a different key space.
//!
//! ## Instructions used by this host
//!
//! | INS | Name | P1 | Data | Response on approve |
//! |-----|------|----|------|---------------------|
//! | `0x01` | SPENDING_PUBKEY | `0x01` (display; silent is debug-only) | account(4 BE) | 64 bytes: BabyJubJub X ‖ Y, 32-byte big-endian each |
//! | `0x03` | GET_VERSION | 0 | empty | 3 bytes: major, minor, patch |
//! | `0x04` | GET_APP_NAME | 0 | empty | ASCII app name |
//! | `0x10` | VIEWING_PUBKEY | `0x01` (display; prod requires it) | account(4 BE) | 32 bytes: ed25519 public key, RFC 8032 compressed |
//! | `0x12` | BLIND_SIGN | curve: `0x00` BabyJubJub (default), `0x01` Bandersnatch, `0x02` BabyJubJub | account(4 BE) ‖ msg(32, **little-endian**: circomlib's leInt2Buff convention) | 129 bytes: sigLen(1, = 96) ‖ R8x ‖ R8y ‖ S (32 B big-endian each) ‖ echoed msg(32); the echo is checked against what was sent |
//! | `0x13` | VIEWING_PRIVKEY | 0 | account(4 BE) | 32 bytes: the ed25519 viewing private key; user approval on device |
//! | `0x14` | RAILGUN_ADDRESS | `0x01` | account(4 BE) | 127 ASCII bytes: the `0zk1…` string, not NUL-terminated; user approval on device |
//!
//! Instructions the host does not use yet: `0x07`/`0x08`/`0x09` (secp256k1 7702 sub-tree
//! and one-shot tx-hash signing), `0x11` CLEAR_SIGN (the stateful review session — the
//! upgrade path from blind signing).
//!
//! For BLIND_SIGN the message is the already-poseidon-hashed transaction digest
//! (`poseidon(merkleroot, boundParamsHash, nullifiers…, commitments…)`), computed host-side.
//! The signature must verify under circomlib's `EdDSAPoseidonVerifier`, i.e. match the
//! deterministic Poseidon-EdDSA of the reference software implementation.

use ruint::aliases::U256;
use thiserror::Error;

use railgun::crypto::keys::{HexKey, SpendingPublicKey, SpendingSignature, ViewingKey};

use crate::transport::{Apdu, Exchange, TransportError};

pub const CLA: u8 = 0xE0;

pub const INS_SPENDING_PUBKEY: u8 = 0x01;
pub const INS_GET_VERSION: u8 = 0x03;
pub const INS_GET_APP_NAME: u8 = 0x04;
pub const INS_VIEWING_PUBKEY: u8 = 0x10;
pub const INS_BLIND_SIGN: u8 = 0x12;
pub const INS_VIEWING_PRIVKEY: u8 = 0x13;
pub const INS_RAILGUN_ADDRESS: u8 = 0x14;

/// Display-and-confirm on the device. Required in production for the pubkey and address
/// instructions; the silent form (`0x00`) is debug-only firmware.
pub const P1_DISPLAY: u8 = 0x01;

/// BLIND_SIGN curve selector: BabyJubJub, the default.
pub const P1_CURVE_BABYJUBJUB: u8 = 0x00;

pub const STATUS_OK: u16 = 0x9000;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("device status {status:#06x}: {}", status_name(*status))]
    Status { status: u16 },
    #[error("unexpected response length: expected {expected}, got {got}")]
    ResponseLength { expected: usize, got: usize },
    #[error("invalid key material in response: {0}")]
    Key(String),
    #[error("viewing key export does not match the device's viewing public key")]
    ViewingKeyMismatch,
    #[error("device signed a different message than requested")]
    SignedHashMismatch,
}

fn status_name(status: u16) -> &'static str {
    match status {
        0x5515 => "device locked",
        0x6985 => "denied by user",
        0x6a86 => "wrong P1/P2",
        0x6a87 => "wrong data length",
        0x6d00 => "instruction not supported (wrong app?)",
        0x6e00 => "class not supported (wrong app?)",
        _ => "unknown status",
    }
}

/// One APDU round-trip; checks the status word, and the payload length when expected.
async fn call<E: Exchange>(
    device: &E,
    ins: u8,
    p1: u8,
    data: Vec<u8>,
    expected_len: Option<usize>,
) -> Result<Vec<u8>, ProtocolError> {
    let response = device
        .exchange(&Apdu {
            cla: CLA,
            ins,
            p1,
            p2: 0,
            data,
        })
        .await?;
    if response.status != STATUS_OK {
        return Err(ProtocolError::Status {
            status: response.status,
        });
    }
    if let Some(expected) = expected_len
        && response.data.len() != expected
    {
        return Err(ProtocolError::ResponseLength {
            expected,
            got: response.data.len(),
        });
    }
    Ok(response.data)
}

/// The app version, `(major, minor, patch)`.
pub async fn get_version<E: Exchange>(device: &E) -> Result<(u8, u8, u8), ProtocolError> {
    let data = call(device, INS_GET_VERSION, 0, Vec::new(), Some(3)).await?;
    Ok((data[0], data[1], data[2]))
}

/// The app name, for a wrong-app check before anything sensitive.
pub async fn get_app_name<E: Exchange>(device: &E) -> Result<String, ProtocolError> {
    let data = call(device, INS_GET_APP_NAME, 0, Vec::new(), None).await?;
    Ok(String::from_utf8_lossy(&data).into_owned())
}

/// SPENDING_PUBKEY: the BabyJubJub spending public key of the account, reviewed and
/// approved on the device (production firmware requires the display form).
pub async fn get_spending_public_key<E: Exchange>(
    device: &E,
    account: u32,
) -> Result<SpendingPublicKey, ProtocolError> {
    let data = account.to_be_bytes().to_vec();
    let data = call(device, INS_SPENDING_PUBKEY, P1_DISPLAY, data, Some(64)).await?;

    let x: [u8; 32] = data[..32].try_into().expect("length checked");
    let y: [u8; 32] = data[32..].try_into().expect("length checked");
    Ok(SpendingPublicKey::new(x, y))
}

/// VIEWING_PUBKEY: the ed25519 viewing public key of the account, reviewed and approved on
/// the device (production firmware requires the display form).
pub async fn get_viewing_public_key<E: Exchange>(
    device: &E,
    account: u32,
) -> Result<[u8; 32], ProtocolError> {
    let data = account.to_be_bytes().to_vec();
    let data = call(device, INS_VIEWING_PUBKEY, P1_DISPLAY, data, Some(32)).await?;
    Ok(data.try_into().expect("length checked"))
}

/// VIEWING_PRIVKEY: export the ed25519 viewing private key of the account. Mandatory user
/// approval on the device.
///
/// The host requires the raw 32-byte seed: it is used as an ed25519 seed for the viewing
/// public key, hashed-and-clamped for note-decryption ECDH, and as the poseidon preimage
/// of the nullifying key. An export with other semantics (e.g. the clamped scalar) fails
/// the cross-check against VIEWING_PUBKEY at connect.
pub async fn export_viewing_key<E: Exchange>(
    device: &E,
    account: u32,
) -> Result<ViewingKey, ProtocolError> {
    let data = account.to_be_bytes().to_vec();
    let data = call(device, INS_VIEWING_PRIVKEY, 0, data, Some(32)).await?;
    ViewingKey::from_hex(&hex::encode(&data)).map_err(|e| ProtocolError::Key(e.to_string()))
}

/// BLIND_SIGN: Poseidon-EdDSA over BabyJubJub on an already-hashed message.
///
/// One call is one blind-signing review on the device, showing the account index and the
/// message hash. The response echoes the signed hash, which is checked against the request.
pub async fn sign_hash<E: Exchange>(
    device: &E,
    account: u32,
    hash: U256,
) -> Result<SpendingSignature, ProtocolError> {
    // The wire message is little-endian: the firmware mirrors circomlib's signPoseidon,
    // which serializes the message with leInt2Buff (nonce over the raw LE bytes, challenge
    // over the byte-reversed value).
    let hash_bytes = hash.to_le_bytes::<32>();
    let mut data = account.to_be_bytes().to_vec();
    data.extend_from_slice(&hash_bytes);
    let response = call(device, INS_BLIND_SIGN, P1_CURVE_BABYJUBJUB, data, Some(129)).await?;

    if response[0] != 96 {
        return Err(ProtocolError::Key(format!(
            "unexpected signature length marker {}",
            response[0]
        )));
    }
    if response[97..129] != hash_bytes {
        return Err(ProtocolError::SignedHashMismatch);
    }

    Ok(SpendingSignature {
        r8_x: U256::from_be_slice(&response[1..33]),
        r8_y: U256::from_be_slice(&response[33..65]),
        s: U256::from_be_slice(&response[65..97]),
    })
}

/// RAILGUN_ADDRESS: the canonical `0zk1…` string of the account, reviewed and approved on
/// the trusted screen — the strong form of address verification.
///
/// The device derives both keys itself and bech32m-encodes on device; the response is the
/// 127 ASCII bytes of the all-chains address.
pub async fn get_railgun_address<E: Exchange>(
    device: &E,
    account: u32,
) -> Result<String, ProtocolError> {
    let data = account.to_be_bytes().to_vec();
    let response = call(device, INS_RAILGUN_ADDRESS, P1_DISPLAY, data, Some(127)).await?;
    Ok(String::from_utf8_lossy(&response).into_owned())
}
