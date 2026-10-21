//! Hybrid post-quantum note encryption: Railgun V2's ECDH on blinded viewing keys, combined
//! with ML-KEM-768 to the receiver's encapsulation key.
//!
//! ```text
//! r = sha512(sharedRandom ⊕ senderRandom)        V'_S = [r]V_S      V'_R = [r]V_R
//! K_ecdh = SHA256([v_S]·V'_R) = SHA256([v_R]·V'_S)
//! (kemCt, K_kem) = ML-KEM-768.Encaps(ek_R)
//! session = SHA256("RAILGUN-PQ-V1-NOTE" || K_ecdh || K_kem || kemCt || V'_S)
//!
//! note      = AES-GCM(session, V2 plaintext)                           ciphertext[4] + memo
//! key blob  = AES-GCM(SHA256("…-BLOB" || K_kem), V'_S)                 the two bytes32 key fields
//! sender    = AES-GCM(SHA256("…-SENDER" || v_S), K_kem || V'_R || V'_S || meta)
//! annotationData = "RGPQ" || 0x01 || kemCt || sender blob
//! ```
//!
//! No curve point is on-chain in the clear: the receiver reaches `V'_S` through ML-KEM, the
//! sender reaches everything through a key derived from its viewing seed. Opening a note takes
//! `K_kem` and a viewing scalar, so it needs both ML-KEM and Curve25519 broken classically, and
//! ML-KEM broken by a quantum attacker (Shor yields the viewing scalars, not the seeds, which
//! are hashed into them). Every AES-GCM has the version tag and `kemCt` as associated data.
//!
//! The contract is unchanged: the receiver tells this format from the legacy one by the
//! annotation data. Legacy wallets ignore these notes.

use rand::{CryptoRng, RngExt};
use sha2::{Digest, Sha256};

use crate::{
    abis::railgun::CommitmentCiphertext,
    account::{address::RailgunAddress, signer::RailgunSigner},
    caip::AssetId,
    crypto::{
        aes::{Ciphertext, decrypt_gcm_aad, encrypt_gcm_aad},
        kem::{self, KemCiphertext, KemEncapsulationKey},
        keys::{BlindedKey, ByteKey, ViewingKey},
        railgun_base_37,
    },
    indexer::syncer,
    note::encrypt::{DecryptError, EncryptError, NotePlaintext, blind_viewing_keys, concat_arrays},
};

const MAGIC: &[u8; 4] = b"RGPQ";
const VERSION: u8 = 1;
const HEADER_SIZE: usize = MAGIC.len() + 1;
/// `K_kem (32) || V'_R (32) || V'_S (32) || meta (32)`, meta being
/// `outputType (1) || senderRandom (15) || applicationIdentifier (16)` as in V2.
const SENDER_PAYLOAD_SIZE: usize = 128;
const SENDER_BLOB_SIZE: usize = 16 + 16 + SENDER_PAYLOAD_SIZE;
const ANNOTATION_SIZE: usize = HEADER_SIZE + kem::CIPHERTEXT_SIZE + SENDER_BLOB_SIZE;

const NOTE_LABEL: &[u8] = b"RAILGUN-PQ-V1-NOTE";
const BLOB_LABEL: &[u8] = b"RAILGUN-PQ-V1-BLOB";
const SENDER_LABEL: &[u8] = b"RAILGUN-PQ-V1-SENDER";

/// Whether a transact output uses this format.
pub(super) fn is_hybrid(transact: &syncer::Transact) -> bool {
    let data = &transact.annotation_data;
    data.len() == ANNOTATION_SIZE && &data[..4] == MAGIC && data[4] == VERSION
}

#[allow(clippy::too_many_arguments)]
pub(super) fn encrypt(
    receiver_kem_key: &KemEncapsulationKey,
    receiver: &RailgunAddress,
    shared_random: &[u8; 16],
    value: u128,
    asset: &AssetId,
    memo: &str,
    viewing_key: ViewingKey,
    blind: bool,
    rng: &mut dyn CryptoRng,
) -> Result<CommitmentCiphertext, EncryptError> {
    let output_type = 0u8;
    let application_identifier = railgun_base_37::encode("railgun rs")?;
    let sender_random: [u8; 15] = if blind { rng.random() } else { [0u8; 15] };

    let (blinded_sender, blinded_receiver) = blind_viewing_keys(
        viewing_key.public_key(),
        receiver.viewing_pubkey(),
        &concat_arrays(shared_random, &[0u8; 16]),
        &concat_arrays(&sender_random, &[0u8; 17]),
    )?;

    let k_ecdh = viewing_key.derive_shared_key_blinded(blinded_receiver)?;
    let (kem_ciphertext, k_kem) = receiver_kem_key.encapsulate(rng.random());
    let aad = associated_data(&kem_ciphertext);

    let session = session_key(k_ecdh.as_bytes(), &k_kem, &kem_ciphertext, &blinded_sender);
    let note = encrypt_gcm_aad(
        &[
            receiver.master_key().as_bytes(),
            &asset.hash().to_be_bytes_vec(),
            &concat_arrays::<16, 16, 32>(shared_random, &value.to_be_bytes()),
            memo.as_bytes(),
        ],
        &session,
        &rng.random(),
        &aad,
    )?;

    let key_blob = encrypt_gcm_aad(
        &[blinded_sender.as_bytes()],
        &labelled(BLOB_LABEL, &[&k_kem]),
        &rng.random(),
        &aad,
    )?;

    let meta: [u8; 32] = concat_arrays(
        &concat_arrays::<1, 15, 16>(&[output_type], &sender_random),
        &application_identifier,
    );
    let sender_blob = encrypt_gcm_aad(
        &[
            &k_kem,
            blinded_receiver.as_bytes(),
            blinded_sender.as_bytes(),
            &meta,
        ],
        &sender_key(&viewing_key),
        &rng.random(),
        &aad,
    )?;

    let mut annotation = Vec::with_capacity(ANNOTATION_SIZE);
    annotation.extend_from_slice(MAGIC);
    annotation.push(VERSION);
    annotation.extend_from_slice(kem_ciphertext.as_bytes());
    annotation.extend_from_slice(&sender_blob.iv);
    annotation.extend_from_slice(&sender_blob.tag);
    for block in &sender_blob.data {
        annotation.extend_from_slice(block);
    }
    debug_assert_eq!(annotation.len(), ANNOTATION_SIZE);

    let bundle_1: [u8; 32] = note.data[0].clone().try_into().unwrap();
    let bundle_2: [u8; 32] = note.data[1].clone().try_into().unwrap();
    let bundle_3: [u8; 32] = note.data[2].clone().try_into().unwrap();
    let key_blob_ciphertext: [u8; 32] = key_blob.data[0].clone().try_into().unwrap();

    Ok(CommitmentCiphertext {
        // V2 layout: iv (16) | tag (16), master public key, token hash, random | value
        ciphertext: [
            concat_arrays(&note.iv, &note.tag).into(),
            bundle_1.into(),
            bundle_2.into(),
            bundle_3.into(),
        ],
        // The blinded sender key, encrypted under the KEM secret: iv | tag, then ciphertext.
        blindedSenderViewingKey: concat_arrays::<16, 16, 32>(&key_blob.iv, &key_blob.tag).into(),
        blindedReceiverViewingKey: key_blob_ciphertext.into(),
        annotationData: annotation.into(),
        memo: note.data[3].clone().into(),
    })
}

pub(super) fn decrypt_as_receiver(
    signer: &dyn RailgunSigner,
    transact: &syncer::Transact,
) -> Result<NotePlaintext, DecryptError> {
    let Some(kem_key_pair) = signer.kem_key_pair() else {
        return Err(DecryptError::NoKemKey);
    };
    let (kem_ciphertext, _) = parse_annotation(transact)?;
    let aad = associated_data(&kem_ciphertext);
    let k_kem = kem_key_pair.decapsulate(&kem_ciphertext);

    let key_blob = Ciphertext {
        iv: transact.blinded_sender_viewing_key[..16]
            .try_into()
            .unwrap(),
        tag: transact.blinded_sender_viewing_key[16..]
            .try_into()
            .unwrap(),
        data: vec![transact.blinded_receiver_viewing_key.to_vec()],
    };
    let blinded_sender = decrypt_gcm_aad(&key_blob, &labelled(BLOB_LABEL, &[&k_kem]), &aad)?;
    let blinded_sender = BlindedKey::from_bytes(
        blinded_sender[0]
            .as_slice()
            .try_into()
            .map_err(|_| DecryptError::Malformed)?,
    );

    let k_ecdh = signer
        .viewing_key()
        .derive_shared_key_blinded(blinded_sender)?;
    let session = session_key(k_ecdh.as_bytes(), &k_kem, &kem_ciphertext, &blinded_sender);
    NotePlaintext::from_bundle(decrypt_gcm_aad(&transact.ciphertext, &session, &aad)?)
}

pub(super) fn decrypt_as_sender(
    signer: &dyn RailgunSigner,
    transact: &syncer::Transact,
) -> Result<NotePlaintext, DecryptError> {
    let (kem_ciphertext, sender_blob) = parse_annotation(transact)?;
    let aad = associated_data(&kem_ciphertext);
    let viewing_key = signer.viewing_key();
    let payload = decrypt_gcm_aad(&sender_blob, &sender_key(&viewing_key), &aad)?;
    let [k_kem, blinded_receiver, blinded_sender, _meta] = payload.as_slice() else {
        return Err(DecryptError::Malformed);
    };
    let as_key = |bytes: &Vec<u8>| -> Result<[u8; 32], DecryptError> {
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| DecryptError::Malformed)
    };
    let k_kem = as_key(k_kem)?;
    let blinded_receiver = BlindedKey::from_bytes(as_key(blinded_receiver)?);
    let blinded_sender = BlindedKey::from_bytes(as_key(blinded_sender)?);

    let k_ecdh = viewing_key.derive_shared_key_blinded(blinded_receiver)?;
    let session = session_key(k_ecdh.as_bytes(), &k_kem, &kem_ciphertext, &blinded_sender);
    NotePlaintext::from_bundle(decrypt_gcm_aad(&transact.ciphertext, &session, &aad)?)
}

/// The KEM ciphertext and the sender blob of a hybrid note.
fn parse_annotation(
    transact: &syncer::Transact,
) -> Result<(KemCiphertext, Ciphertext), DecryptError> {
    if !is_hybrid(transact) {
        return Err(DecryptError::Malformed);
    }
    let data = &transact.annotation_data;
    let kem_ciphertext =
        KemCiphertext::from_slice(&data[HEADER_SIZE..HEADER_SIZE + kem::CIPHERTEXT_SIZE])
            .map_err(|_| DecryptError::Malformed)?;
    let blob = &data[HEADER_SIZE + kem::CIPHERTEXT_SIZE..];
    let sender_blob = Ciphertext {
        iv: blob[..16].try_into().unwrap(),
        tag: blob[16..32].try_into().unwrap(),
        data: vec![
            blob[32..64].to_vec(),
            blob[64..96].to_vec(),
            blob[96..128].to_vec(),
            blob[128..160].to_vec(),
        ],
    };
    Ok((kem_ciphertext, sender_blob))
}

/// `SHA256(label || parts…)`, every part of a size fixed by the label.
fn labelled(label: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new().chain_update(label);
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn session_key(
    k_ecdh: &[u8; 32],
    k_kem: &[u8; 32],
    kem_ciphertext: &KemCiphertext,
    blinded_sender: &BlindedKey,
) -> [u8; 32] {
    labelled(
        NOTE_LABEL,
        &[
            k_ecdh,
            k_kem,
            kem_ciphertext.as_bytes(),
            blinded_sender.as_bytes(),
        ],
    )
}

/// The sender's recovery key, from its viewing seed: the seed is hashed into the viewing
/// scalar, so the scalar (and hence Shor) does not give it.
fn sender_key(viewing_key: &ViewingKey) -> [u8; 32] {
    labelled(SENDER_LABEL, &[viewing_key.as_bytes()])
}

fn associated_data(kem_ciphertext: &KemCiphertext) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_SIZE + kem::CIPHERTEXT_SIZE);
    aad.extend_from_slice(MAGIC);
    aad.push(VERSION);
    aad.extend_from_slice(kem_ciphertext.as_bytes());
    aad
}

#[cfg(test)]
pub(super) const TEST_ANNOTATION_SIZE: usize = ANNOTATION_SIZE;
