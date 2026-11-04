//! Hybrid post-quantum note encryption: Railgun V2's ECDH on blinded viewing keys, combined
//! with ML-KEM-768 to the receiver's encapsulation key.
//!
//! Format 2, written by [`encrypt`]:
//!
//! ```text
//! r = sha512(sharedRandom ⊕ senderRandom)        V'_S = [r]V_S      V'_R = [r]V_R
//! K_ecdh = SHA256([v_S]·V'_R) = SHA256([v_R]·V'_S)
//! e random, E = [e]B
//! k_mask = SHA256("…-V2-MASK" || SHA256([e]·V_R) || E || V_R)          receiver: [v_R]·E
//! (kemCt, K_kem) = ML-KEM-768.Encaps(ek_R), again until Kemeleon encodes kemCt
//! kemCt* = Kemeleon(kemCt) ⊕ AES-256-CTR(k_mask, iv 0)                 1252 bytes, no tag
//! session = SHA256("…-V2-NOTE" || K_ecdh || K_kem || E || kemCt* || V'_S)
//!
//! note      = AES-GCM(session, V2 plaintext)                           ciphertext[4] + memo
//! key blob  = AES-GCM(SHA256("…-V2-BLOB" || K_kem || k_mask), V'_S)    the two bytes32 key fields
//! sender    = AES-GCM(SHA256("…-V2-SENDER" || v_S), K_kem || V'_R || V'_S || meta)
//! annotationData = "RGPQ" || 0x02 || E || kemCt* || sender blob        1449 bytes
//! ```
//!
//! Every AES-GCM has `"RGPQ" || 0x02 || E || kemCt*` as associated data.
//!
//! **Confidentiality.** No curve point is on-chain in the clear except `E`, which does not
//! depend on the receiver. The receiver reaches `V'_S` through ML-KEM, the sender reaches
//! everything through a key derived from its viewing seed. Opening a note takes `K_kem` and a
//! viewing scalar: both ML-KEM and Curve25519 broken classically, or ML-KEM broken by a quantum
//! attacker (Shor yields the viewing scalars, not the seeds, which are hashed into them).
//!
//! **Recipient anonymity.** The bytes that depend on the receiver are `kemCt*` and the key
//! blob, and both need `k_mask`, a Diffie-Hellman secret, on top of `K_kem`. A classical
//! attacker must break both CDH on Curve25519 and MLWE to tell who a note is for. A quantum
//! attacker removes the mask for every candidate and then faces Kemeleon-encoded ciphertexts,
//! uniform under MLWE, and ML-KEM's anonymity. Kemeleon is what makes the mask safe: a raw
//! ML-KEM ciphertext is not uniform, and the candidate whose unmasked bytes look like one would
//! be the receiver.
//!
//! Format 1, read only: `annotationData = "RGPQ" || 0x01 || kemCt || sender blob` (1253 bytes),
//! labels `…-V1-…`, no `E`, no mask, the raw `kemCt` in the clear, the key blob under
//! `SHA256("…-V1-BLOB" || K_kem)`. Its recipient anonymity rests on ML-KEM alone: a
//! decapsulation key, from MLWE broken even classically, confirms the receiver.
//!
//! In both formats the associated data is the annotation up to the sender blob, and the session
//! key binds the same bytes after the header.
//!
//! The contract is unchanged: the receiver tells these formats from the legacy one by the
//! annotation data. Legacy wallets ignore these notes.

use aes::{
    Aes256,
    cipher::{KeyIvInit, StreamCipher},
};
use rand::{CryptoRng, RngExt};
use sha2::{Digest, Sha256};

use crate::{
    abis::railgun::CommitmentCiphertext,
    account::{address::RailgunAddress, signer::RailgunSigner},
    caip::AssetId,
    crypto::{
        aes::{Ciphertext, decrypt_gcm_aad, encrypt_gcm_aad},
        kem::{self, KemCiphertext, KemEncapsulationKey, KemKeyPair},
        keys::{BlindedKey, ByteKey, ViewingKey, ViewingPublicKey},
        railgun_base_37,
    },
    indexer::syncer,
    note::encrypt::{DecryptError, EncryptError, NotePlaintext, blind_viewing_keys, concat_arrays},
};

const MAGIC: &[u8; 4] = b"RGPQ";
const HEADER_SIZE: usize = MAGIC.len() + 1;
const EPHEMERAL_SIZE: usize = 32;
/// `K_kem (32) || V'_R (32) || V'_S (32) || meta (32)`, meta being
/// `outputType (1) || senderRandom (15) || applicationIdentifier (16)` as in V2.
const SENDER_PAYLOAD_SIZE: usize = 128;
const SENDER_BLOB_SIZE: usize = 16 + 16 + SENDER_PAYLOAD_SIZE;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    /// Raw KEM ciphertext, anonymity from ML-KEM alone. Read only.
    V1,
    /// Ephemeral point and masked, Kemeleon-encoded KEM ciphertext.
    V2,
}

impl Format {
    const fn version(self) -> u8 {
        match self {
            Format::V1 => 1,
            Format::V2 => 2,
        }
    }

    /// Bytes between the header and the sender blob.
    const fn body_size(self) -> usize {
        match self {
            Format::V1 => kem::CIPHERTEXT_SIZE,
            Format::V2 => EPHEMERAL_SIZE + kem::UNIFORM_CIPHERTEXT_SIZE,
        }
    }

    const fn annotation_size(self) -> usize {
        HEADER_SIZE + self.body_size() + SENDER_BLOB_SIZE
    }

    const fn note_label(self) -> &'static [u8] {
        match self {
            Format::V1 => b"RAILGUN-PQ-V1-NOTE",
            Format::V2 => b"RAILGUN-PQ-V2-NOTE",
        }
    }

    const fn blob_label(self) -> &'static [u8] {
        match self {
            Format::V1 => b"RAILGUN-PQ-V1-BLOB",
            Format::V2 => b"RAILGUN-PQ-V2-BLOB",
        }
    }

    const fn sender_label(self) -> &'static [u8] {
        match self {
            Format::V1 => b"RAILGUN-PQ-V1-SENDER",
            Format::V2 => b"RAILGUN-PQ-V2-SENDER",
        }
    }

    fn of(data: &[u8]) -> Option<Self> {
        [Format::V1, Format::V2].into_iter().find(|format| {
            data.len() == format.annotation_size()
                && &data[..MAGIC.len()] == MAGIC
                && data[MAGIC.len()] == format.version()
        })
    }
}

const MASK_LABEL: &[u8] = b"RAILGUN-PQ-V2-MASK";

/// A hybrid note's annotation data, split.
struct Annotation<'a> {
    format: Format,
    /// The header and body: the associated data of every AES-GCM.
    aad: &'a [u8],
    /// `kemCt` (format 1) or `E || kemCt*` (format 2): what the session key binds.
    body: &'a [u8],
    sender_blob: Ciphertext,
}

/// Whether a transact output uses one of these formats.
pub(super) fn is_hybrid(transact: &syncer::Transact) -> bool {
    Format::of(&transact.annotation_data).is_some()
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
    let format = Format::V2;
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

    let ephemeral: ViewingKey = rng.random();
    let ephemeral_public = ephemeral.public_key();
    let k_mask = mask_key(
        ephemeral
            .derive_shared_key(receiver.viewing_pubkey())?
            .as_bytes(),
        &ephemeral_public,
        &receiver.viewing_pubkey(),
    );

    let (mut kem_ciphertext, k_kem) = receiver_kem_key.encapsulate_uniform(rng);
    apply_mask(&k_mask, &mut kem_ciphertext);

    let mut annotation = Vec::with_capacity(format.annotation_size());
    annotation.extend_from_slice(MAGIC);
    annotation.push(format.version());
    annotation.extend_from_slice(ephemeral_public.as_bytes());
    annotation.extend_from_slice(&kem_ciphertext);
    let aad = annotation.clone();
    let body = &aad[HEADER_SIZE..];

    let session = session_key(format, k_ecdh.as_bytes(), &k_kem, body, &blinded_sender);
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
        &labelled(format.blob_label(), &[&k_kem, &k_mask]),
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
        &sender_key(format, &viewing_key),
        &rng.random(),
        &aad,
    )?;

    annotation.extend_from_slice(&sender_blob.iv);
    annotation.extend_from_slice(&sender_blob.tag);
    for block in &sender_blob.data {
        annotation.extend_from_slice(block);
    }
    debug_assert_eq!(annotation.len(), format.annotation_size());

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
    let annotation = parse_annotation(transact)?;
    let viewing_key = signer.viewing_key();
    let (k_kem, blob_key) = receiver_kem_secret(&annotation, kem_key_pair, &viewing_key)?;

    let key_blob = Ciphertext {
        iv: transact.blinded_sender_viewing_key[..16]
            .try_into()
            .unwrap(),
        tag: transact.blinded_sender_viewing_key[16..]
            .try_into()
            .unwrap(),
        data: vec![transact.blinded_receiver_viewing_key.to_vec()],
    };
    let blinded_sender = decrypt_gcm_aad(&key_blob, &blob_key, annotation.aad)?;
    let blinded_sender = BlindedKey::from_bytes(
        blinded_sender[0]
            .as_slice()
            .try_into()
            .map_err(|_| DecryptError::Malformed)?,
    );

    let k_ecdh = viewing_key.derive_shared_key_blinded(blinded_sender)?;
    let session = session_key(
        annotation.format,
        k_ecdh.as_bytes(),
        &k_kem,
        annotation.body,
        &blinded_sender,
    );
    NotePlaintext::from_bundle(decrypt_gcm_aad(
        &transact.ciphertext,
        &session,
        annotation.aad,
    )?)
}

pub(super) fn decrypt_as_sender(
    signer: &dyn RailgunSigner,
    transact: &syncer::Transact,
) -> Result<NotePlaintext, DecryptError> {
    let annotation = parse_annotation(transact)?;
    let viewing_key = signer.viewing_key();
    let payload = decrypt_gcm_aad(
        &annotation.sender_blob,
        &sender_key(annotation.format, &viewing_key),
        annotation.aad,
    )?;
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
    let session = session_key(
        annotation.format,
        k_ecdh.as_bytes(),
        &k_kem,
        annotation.body,
        &blinded_sender,
    );
    NotePlaintext::from_bundle(decrypt_gcm_aad(
        &transact.ciphertext,
        &session,
        annotation.aad,
    )?)
}

/// `K_kem` and the key blob's key, as the receiver derives them.
fn receiver_kem_secret(
    annotation: &Annotation<'_>,
    kem_key_pair: &KemKeyPair,
    viewing_key: &ViewingKey,
) -> Result<([u8; 32], [u8; 32]), DecryptError> {
    match annotation.format {
        Format::V1 => {
            let kem_ciphertext =
                KemCiphertext::from_slice(annotation.body).map_err(|_| DecryptError::Malformed)?;
            let k_kem = kem_key_pair.decapsulate(&kem_ciphertext);
            Ok((k_kem, labelled(Format::V1.blob_label(), &[&k_kem])))
        }
        Format::V2 => {
            let (ephemeral, masked) = annotation.body.split_at(EPHEMERAL_SIZE);
            let ephemeral = ViewingPublicKey::from_bytes(ephemeral.try_into().unwrap());
            let k_mask = mask_key(
                viewing_key.derive_shared_key(ephemeral)?.as_bytes(),
                &ephemeral,
                &viewing_key.public_key(),
            );
            let mut encoded: [u8; kem::UNIFORM_CIPHERTEXT_SIZE] = masked.try_into().unwrap();
            apply_mask(&k_mask, &mut encoded);
            let k_kem = kem_key_pair.decapsulate_uniform(&encoded);
            Ok((k_kem, labelled(Format::V2.blob_label(), &[&k_kem, &k_mask])))
        }
    }
}

fn parse_annotation(transact: &syncer::Transact) -> Result<Annotation<'_>, DecryptError> {
    let data = transact.annotation_data.as_slice();
    let format = Format::of(data).ok_or(DecryptError::Malformed)?;
    let (aad, blob) = data.split_at(HEADER_SIZE + format.body_size());
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
    Ok(Annotation {
        format,
        aad,
        body: &aad[HEADER_SIZE..],
        sender_blob,
    })
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
    format: Format,
    k_ecdh: &[u8; 32],
    k_kem: &[u8; 32],
    body: &[u8],
    blinded_sender: &BlindedKey,
) -> [u8; 32] {
    labelled(
        format.note_label(),
        &[k_ecdh, k_kem, body, blinded_sender.as_bytes()],
    )
}

/// The mask on the KEM ciphertext, from the ephemeral Diffie-Hellman with the receiver's
/// viewing key, bound to both public keys.
fn mask_key(dh: &[u8; 32], ephemeral: &ViewingPublicKey, receiver: &ViewingPublicKey) -> [u8; 32] {
    labelled(MASK_LABEL, &[dh, ephemeral.as_bytes(), receiver.as_bytes()])
}

/// XORs the AES-256-CTR keystream of `k_mask` into `data`. Unauthenticated on purpose: a tag
/// would let whoever recovers `e` test each candidate receiver. One key per note, so a fixed IV.
fn apply_mask(k_mask: &[u8; 32], data: &mut [u8]) {
    Aes256Ctr::new(k_mask.into(), &[0u8; 16].into()).apply_keystream(data);
}

/// The sender's recovery key, from its viewing seed: the seed is hashed into the viewing
/// scalar, so the scalar (and hence Shor) does not give it.
fn sender_key(format: Format, viewing_key: &ViewingKey) -> [u8; 32] {
    labelled(format.sender_label(), &[viewing_key.as_bytes()])
}

#[cfg(test)]
pub(super) const TEST_ANNOTATION_SIZE: usize = Format::V2.annotation_size();

#[cfg(all(test, native))]
mod tests {
    use std::sync::Arc;

    use alloy::primitives::{Bytes, FixedBytes, address};
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use ruint::aliases::U256;

    use super::*;
    use crate::{
        account::{
            chain::ChainId,
            signer::{PrivateKeySigner, RailgunSigner},
        },
        crypto::keys::SpendingKey,
        note::encrypt::{
            NoteEncryption, decrypt_transact_as_receiver, decrypt_transact_as_sender,
            encrypt_transact,
        },
    };

    fn on_chain(encrypted: &CommitmentCiphertext) -> syncer::Transact {
        syncer::Transact {
            tree_number: 0,
            leaf_index: 0,
            hash: U256::ZERO,
            blinded_sender_viewing_key: encrypted.blindedSenderViewingKey.0,
            blinded_receiver_viewing_key: encrypted.blindedReceiverViewingKey.0,
            annotation_data: encrypted.annotationData.to_vec(),
            ciphertext: Ciphertext::from(encrypted.clone()),
        }
    }

    fn sender() -> Arc<PrivateKeySigner> {
        PrivateKeySigner::new_evm(
            SpendingKey::from_bytes([1u8; 32]),
            ViewingKey::from_bytes([2u8; 32]),
            1,
        )
    }

    fn receiver() -> Arc<PrivateKeySigner> {
        PrivateKeySigner::new_with_kem(
            SpendingKey::from_bytes([3u8; 32]),
            ViewingKey::from_bytes([4u8; 32]),
            KemKeyPair::derive(b"receiver"),
            ChainId::evm(1),
        )
    }

    fn asset() -> AssetId {
        AssetId::Erc20(address!("0x1234567890123456789012345678901234567890"))
    }

    /// A format-1 note written by the code before format 2 (zknox/dev-pq 34d929d).
    fn format_1_note() -> CommitmentCiphertext {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/rgpq/format1_note.json"
        ))
        .unwrap();
        let bytes = |key: &str| hex::decode(fixture[key].as_str().unwrap()).unwrap();
        let word = |hex_word: &serde_json::Value| {
            FixedBytes::<32>::from_slice(&hex::decode(hex_word.as_str().unwrap()).unwrap())
        };
        let words = fixture["ciphertext"].as_array().unwrap();
        CommitmentCiphertext {
            ciphertext: [
                word(&words[0]),
                word(&words[1]),
                word(&words[2]),
                word(&words[3]),
            ],
            blindedSenderViewingKey: FixedBytes::from_slice(&bytes("blindedSenderViewingKey")),
            blindedReceiverViewingKey: FixedBytes::from_slice(&bytes("blindedReceiverViewingKey")),
            annotationData: Bytes::from(bytes("annotationData")),
            memo: Bytes::from(bytes("memo")),
        }
    }

    fn format_2_note(rng: &mut ChaChaRng) -> CommitmentCiphertext {
        let receiver = receiver();
        encrypt_transact(
            &NoteEncryption::HybridPq {
                receiver_kem_key: receiver.kem_key_pair().unwrap().encapsulation_key().clone(),
            },
            &receiver.address(),
            &[5u8; 16],
            1000,
            &asset(),
            "format 2 note",
            sender().viewing_key(),
            true,
            rng,
        )
        .unwrap()
    }

    #[test]
    fn sizes() {
        assert_eq!(Format::V1.annotation_size(), 1253);
        assert_eq!(Format::V2.annotation_size(), 1449);
    }

    #[test]
    fn format_1_notes_stay_readable() {
        let note = on_chain(&format_1_note());
        assert!(is_hybrid(&note));
        let expected = NotePlaintext {
            encoded_master_key: *receiver().address().master_key().as_bytes(),
            token_hash: asset().hash().to_be_bytes(),
            random: [5u8; 16],
            value: 1000,
            memo: b"format 1 note".to_vec(),
        };
        assert_eq!(
            decrypt_transact_as_receiver(receiver().as_ref(), &note).unwrap(),
            expected
        );
        assert_eq!(
            decrypt_transact_as_sender(sender().as_ref(), &note).unwrap(),
            expected
        );
    }

    #[test]
    fn new_notes_use_format_2() {
        let mut rng = ChaChaRng::seed_from_u64(9);
        let encrypted = format_2_note(&mut rng);
        assert_eq!(&encrypted.annotationData[..HEADER_SIZE], b"RGPQ\x02");
        assert_eq!(encrypted.annotationData.len(), Format::V2.annotation_size());
        let note = on_chain(&encrypted);
        assert_eq!(
            decrypt_transact_as_receiver(receiver().as_ref(), &note)
                .unwrap()
                .memo,
            b"format 2 note"
        );
        assert_eq!(
            decrypt_transact_as_sender(sender().as_ref(), &note)
                .unwrap()
                .memo,
            b"format 2 note"
        );
    }

    /// Whether the key blob opens with `key`: a candidate receiver confirmed.
    fn key_blob_opens(note: &syncer::Transact, key: &[u8; 32]) -> bool {
        let annotation = parse_annotation(note).unwrap();
        let key_blob = Ciphertext {
            iv: note.blinded_sender_viewing_key[..16].try_into().unwrap(),
            tag: note.blinded_sender_viewing_key[16..].try_into().unwrap(),
            data: vec![note.blinded_receiver_viewing_key.to_vec()],
        };
        decrypt_gcm_aad(&key_blob, key, annotation.aad).is_ok()
    }

    /// The point of format 2. An attacker who has the receiver's decapsulation key, from MLWE
    /// broken, but not its viewing key: format 1 confirms the receiver, format 2 does not
    /// without the Diffie-Hellman secret behind the mask.
    #[test]
    fn a_decapsulation_key_alone_no_longer_confirms_the_receiver() {
        let kem = KemKeyPair::derive(b"receiver");

        let note = on_chain(&format_1_note());
        let body = parse_annotation(&note).unwrap().body.to_vec();
        let k_kem = kem.decapsulate(&KemCiphertext::from_slice(&body).unwrap());
        assert!(key_blob_opens(
            &note,
            &labelled(Format::V1.blob_label(), &[&k_kem])
        ));

        let mut rng = ChaChaRng::seed_from_u64(10);
        let note = on_chain(&format_2_note(&mut rng));
        let body = parse_annotation(&note).unwrap().body.to_vec();
        let (ephemeral, masked) = body.split_at(EPHEMERAL_SIZE);
        let masked: [u8; kem::UNIFORM_CIPHERTEXT_SIZE] = masked.try_into().unwrap();

        // Without the mask key: the decoded bytes are not the ciphertext.
        let k_kem = kem.decapsulate_uniform(&masked);
        assert!(!key_blob_opens(
            &note,
            &labelled(Format::V1.blob_label(), &[&k_kem])
        ));
        for k_mask in [[0u8; 32], rng.random()] {
            assert!(!key_blob_opens(
                &note,
                &labelled(Format::V2.blob_label(), &[&k_kem, &k_mask])
            ));
        }

        // With it (here from the viewing key), the same decapsulation key confirms.
        let viewing = ViewingKey::from_bytes([4u8; 32]);
        let ephemeral = ViewingPublicKey::from_bytes(ephemeral.try_into().unwrap());
        let k_mask = mask_key(
            viewing.derive_shared_key(ephemeral).unwrap().as_bytes(),
            &ephemeral,
            &viewing.public_key(),
        );
        let mut encoded = masked;
        apply_mask(&k_mask, &mut encoded);
        let k_kem = kem.decapsulate_uniform(&encoded);
        assert!(key_blob_opens(
            &note,
            &labelled(Format::V2.blob_label(), &[&k_kem, &k_mask])
        ));
    }

    /// The viewing key alone (a quantum attacker's view: Shor gives the scalar) does not open
    /// the note either: a wrong KEM key decapsulates to an unrelated secret.
    #[test]
    fn the_viewing_key_alone_does_not_open_format_2() {
        let mut rng = ChaChaRng::seed_from_u64(11);
        let note = on_chain(&format_2_note(&mut rng));
        let wrong_kem = PrivateKeySigner::new_with_kem(
            SpendingKey::from_bytes([3u8; 32]),
            ViewingKey::from_bytes([4u8; 32]),
            KemKeyPair::derive(b"other"),
            ChainId::evm(1),
        );
        assert!(matches!(
            decrypt_transact_as_receiver(wrong_kem.as_ref(), &note),
            Err(DecryptError::Aes(_))
        ));
    }

    /// Every byte of the ephemeral point and of the masked ciphertext is bound: a flip breaks
    /// the note for receiver and sender alike.
    #[test]
    fn format_2_tampering_fails() {
        let mut rng = ChaChaRng::seed_from_u64(12);
        let encrypted = format_2_note(&mut rng);
        for offset in [
            HEADER_SIZE,
            HEADER_SIZE + EPHEMERAL_SIZE - 1,
            HEADER_SIZE + EPHEMERAL_SIZE,
            HEADER_SIZE + EPHEMERAL_SIZE + kem::UNIFORM_CIPHERTEXT_SIZE - 1,
        ] {
            let mut tampered = encrypted.clone();
            let mut data = tampered.annotationData.to_vec();
            data[offset] ^= 1;
            tampered.annotationData = data.into();
            let tampered = on_chain(&tampered);
            assert!(
                decrypt_transact_as_receiver(receiver().as_ref(), &tampered).is_err(),
                "receiver, offset {offset}"
            );
            assert!(
                decrypt_transact_as_sender(sender().as_ref(), &tampered).is_err(),
                "sender, offset {offset}"
            );
        }
    }

    /// Two notes to the same receiver share no public byte that could link them: fresh `E`,
    /// fresh mask, fresh KEM ciphertext.
    #[test]
    fn notes_to_the_same_receiver_look_unrelated() {
        let mut rng = ChaChaRng::seed_from_u64(13);
        let a = format_2_note(&mut rng).annotationData;
        let b = format_2_note(&mut rng).annotationData;
        let body = HEADER_SIZE..HEADER_SIZE + Format::V2.body_size();
        let equal = a[body.clone()]
            .iter()
            .zip(&b[body.clone()])
            .filter(|(x, y)| x == y)
            .count();
        // About 1/256 of the bytes match by chance.
        assert!(equal < body.len() / 64, "{equal} equal bytes");
    }
}
