//! Encryption of the data a note carries on-chain.
//!
//! Shields use one scheme, Railgun V2's ECDH + AES-GCM ([`encrypt_shield`]). Transact outputs
//! can use several: the sender picks a [`NoteEncryption`] per note, and the receiver tells the
//! schemes apart from the on-chain data ([`decrypt_transact_as_receiver`]). Every scheme fills
//! the V2 contract's `CommitmentCiphertext` and keeps the V2 plaintext layout, so what a wallet
//! learns from a note does not depend on how it was encrypted.

use curve25519_dalek::{Scalar, edwards::CompressedEdwardsY};
use kohaku_crypto::poseidon_hash;
use rand::{CryptoRng, RngExt};
use ruint::{Uint, aliases::U256};
use sha2::{Digest, Sha512};
use thiserror::Error;

use crate::{
    abis::railgun::{CommitmentCiphertext, CommitmentPreimage, ShieldCiphertext, ShieldRequest},
    account::{address::RailgunAddress, signer::RailgunSigner},
    caip::AssetId,
    crypto::{
        aes::AesError,
        keys::{BlindedKey, ByteKey, KeyError, U256Key, ViewingKey, ViewingPublicKey},
        railgun_base_37,
    },
    indexer::syncer,
};

pub mod legacy;

#[derive(Debug, Error)]
pub enum EncryptError {
    #[error("Railgun base37 encoding error: {0}")]
    RailgunBase37(#[from] railgun_base_37::EncodingError),
    #[error("AES encryption error: {0}")]
    Aes(#[from] AesError),
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
}

#[derive(Debug, Error)]
pub enum DecryptError {
    #[error("AES decryption error: {0}")]
    Aes(#[from] AesError),
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
    #[error("Note plaintext does not have the V2 layout")]
    Malformed,
}

/// How a transact output is encrypted for its receiver, and for its sender to read back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoteEncryption {
    /// Railgun V2: ed25519 ECDH on blinded viewing keys and AES-256-GCM. Readable by every
    /// Railgun wallet.
    #[default]
    Legacy,
}

/// What a transact output encrypts, in Railgun V2's layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotePlaintext {
    /// The receiver's master public key, as is (kohaku) or XOR the sender's (the Railgun engine).
    pub encoded_master_key: [u8; 32],
    pub token_hash: [u8; 32],
    pub random: [u8; 16],
    pub value: u128,
    pub memo: Vec<u8>,
}

/// Encrypts a transact output with the scheme the sender chose.
#[allow(clippy::too_many_arguments)]
pub fn encrypt_transact(
    encryption: &NoteEncryption,
    receiver: &RailgunAddress,
    shared_random: &[u8; 16],
    value: u128,
    asset: &AssetId,
    memo: &str,
    viewing_key: ViewingKey,
    blind: bool,
    rng: &mut dyn CryptoRng,
) -> Result<CommitmentCiphertext, EncryptError> {
    match encryption {
        NoteEncryption::Legacy => legacy::encrypt(
            receiver,
            shared_random,
            value,
            asset,
            memo,
            viewing_key,
            blind,
            rng,
        ),
    }
}

/// Decrypts a transact output addressed to `signer`, whatever scheme the sender used.
pub fn decrypt_transact_as_receiver(
    signer: &dyn RailgunSigner,
    transact: &syncer::Transact,
) -> Result<NotePlaintext, DecryptError> {
    // Only the legacy format exists so far.
    legacy::decrypt_as_receiver(signer, transact)
}

/// Decrypts a transact output `signer` sent, from the material each scheme leaves for the
/// sender.
pub fn decrypt_transact_as_sender(
    signer: &dyn RailgunSigner,
    transact: &syncer::Transact,
) -> Result<NotePlaintext, DecryptError> {
    legacy::decrypt_as_sender(signer, transact)
}

pub fn encrypt_shield(
    recipient: RailgunAddress,
    asset: AssetId,
    value: u128,
    rng: &mut impl CryptoRng,
) -> Result<ShieldRequest, EncryptError> {
    let shield_private_key: ViewingKey = rng.random();
    let shared_key = shield_private_key
        .derive_shared_key(recipient.viewing_pubkey())
        .unwrap();

    let random_seed: [u8; 16] = rng.random();
    let mut npk: [u8; 32] = poseidon_hash(&[
        recipient.master_key().to_u256(),
        U256::from_be_slice(&random_seed),
    ])
    .unwrap()
    .to_le_bytes();
    npk.reverse();

    let gcm = shared_key
        .encrypt_gcm(&[&random_seed], &rng.random())
        .unwrap();
    let ctr =
        shield_private_key.encrypt_ctr(&[recipient.viewing_pubkey().as_bytes()], &rng.random());

    let gcm_random: [u8; 16] = gcm.data[0].clone().try_into().unwrap();
    let ctr_key: [u8; 32] = ctr.data[0].clone().try_into().unwrap();

    Ok(ShieldRequest {
        preimage: CommitmentPreimage {
            npk: npk.into(),
            token: asset.into(),
            value: Uint::from(value),
        },
        ciphertext: ShieldCiphertext {
            // iv (16) | tag (16)
            // random (16) | ctr iv (16)
            // receiver_viewing_key (32)
            encryptedBundle: [
                concat_arrays(&gcm.iv, &gcm.tag).into(),
                concat_arrays(&gcm_random, &ctr.iv).into(),
                ctr_key.into(),
            ],
            shieldKey: shield_private_key.public_key().to_u256().into(),
        },
    })
}

pub(crate) fn blind_viewing_keys(
    sender: ViewingPublicKey,
    receiver: ViewingPublicKey,
    shared_random: &[u8; 32],
    sender_random: &[u8; 32],
) -> Result<(BlindedKey, BlindedKey), KeyError> {
    let sender_point = CompressedEdwardsY(*sender.as_bytes())
        .decompress()
        .ok_or(KeyError::DecompressionFailed)?;
    let receiver_point = CompressedEdwardsY(*receiver.as_bytes())
        .decompress()
        .ok_or(KeyError::DecompressionFailed)?;

    let mut final_random = [0u8; 32];
    for i in 0..32 {
        final_random[i] = shared_random[i] ^ sender_random[i];
    }

    let hash = Sha512::digest(final_random);
    let mut hash_bytes: [u8; 64] = hash.into();
    hash_bytes.reverse();
    let scalar = Scalar::from_bytes_mod_order_wide(&hash_bytes);

    Ok((
        BlindedKey::from_bytes((sender_point * scalar).compress().to_bytes()),
        BlindedKey::from_bytes((receiver_point * scalar).compress().to_bytes()),
    ))
}

/// Concatenates two sized arrays into a new sized array. The output size must be the sum of the
/// input sizes.
fn concat_arrays<const A: usize, const B: usize, const C: usize>(
    a: &[u8; A],
    b: &[u8; B],
) -> [u8; C] {
    assert_eq!(A + B, C);
    let mut out = [0u8; C];
    out[..A].copy_from_slice(a);
    out[A..].copy_from_slice(b);
    out
}

#[cfg(all(test, native))]
mod tests {
    use alloy::primitives::{Address, address};
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use tracing_test::traced_test;

    use super::*;
    use crate::{
        account::{
            chain::ChainId,
            signer::{PrivateKeySigner, RailgunSigner},
        },
        crypto::{
            aes::Ciphertext,
            keys::{HexKey, SpendingKey},
        },
    };

    #[test]
    fn test_encrypt_snap() {
        let mut rand = ChaChaRng::seed_from_u64(0);
        let chain_id = 1;

        // Sender keys
        let sender_viewing_key = ViewingKey::from_bytes([2u8; 32]);

        // Receiver keys
        let receiver_spending_key = SpendingKey::from_bytes([3u8; 32]);
        let receiver_viewing_key = ViewingKey::from_bytes([4u8; 32]);
        let receiver =
            PrivateKeySigner::new_evm(receiver_spending_key, receiver_viewing_key, chain_id)
                .address();

        let shared_random = [5u8; 16];
        let value = 1000u128;
        let asset = AssetId::Erc20(address!("0x1234567890123456789012345678901234567890"));
        let memo = "test memo";

        let encrypted = encrypt_transact(
            &NoteEncryption::Legacy,
            &receiver,
            &shared_random,
            value,
            &asset,
            memo,
            sender_viewing_key,
            false,
            &mut rand,
        )
        .unwrap();

        insta::assert_debug_snapshot!(encrypted);
    }

    /// What the sender encrypts is what both the receiver and the sender decrypt, through the
    /// scheme-agnostic entry points, for every scheme.
    #[test]
    fn transact_round_trip() {
        let mut rng = ChaChaRng::seed_from_u64(1);
        let sender = PrivateKeySigner::new_evm(
            SpendingKey::from_bytes([1u8; 32]),
            ViewingKey::from_bytes([2u8; 32]),
            1,
        );
        let receiver = PrivateKeySigner::new_evm(
            SpendingKey::from_bytes([3u8; 32]),
            ViewingKey::from_bytes([4u8; 32]),
            1,
        );
        let asset = AssetId::Erc20(address!("0x1234567890123456789012345678901234567890"));
        let shared_random = [5u8; 16];

        for encryption in [NoteEncryption::Legacy] {
            let encrypted = encrypt_transact(
                &encryption,
                &receiver.address(),
                &shared_random,
                1000,
                &asset,
                "test memo",
                sender.viewing_key(),
                false,
                &mut rng,
            )
            .unwrap();
            let on_chain = syncer::Transact {
                tree_number: 0,
                leaf_index: 0,
                hash: U256::ZERO,
                blinded_sender_viewing_key: encrypted.blindedSenderViewingKey.0,
                blinded_receiver_viewing_key: encrypted.blindedReceiverViewingKey.0,
                annotation_data: encrypted.annotationData.to_vec(),
                ciphertext: Ciphertext::from(encrypted),
            };

            let expected = NotePlaintext {
                encoded_master_key: *receiver.address().master_key().as_bytes(),
                token_hash: asset.hash().to_be_bytes(),
                random: shared_random,
                value: 1000,
                memo: b"test memo".to_vec(),
            };
            let as_receiver = decrypt_transact_as_receiver(receiver.as_ref(), &on_chain).unwrap();
            let as_sender = decrypt_transact_as_sender(sender.as_ref(), &on_chain).unwrap();
            assert_eq!(as_receiver, expected, "{encryption:?}");
            assert_eq!(as_sender, expected, "{encryption:?}");

            // Not for a third party.
            let other = PrivateKeySigner::new_evm(
                SpendingKey::from_bytes([7u8; 32]),
                ViewingKey::from_bytes([8u8; 32]),
                1,
            );
            assert!(decrypt_transact_as_receiver(other.as_ref(), &on_chain).is_err());
            assert!(decrypt_transact_as_sender(other.as_ref(), &on_chain).is_err());
        }
    }

    #[test]
    #[traced_test]
    fn test_encrypt_shield_snap() {
        let mut rng = ChaChaRng::seed_from_u64(0);

        let spending_key: SpendingKey = rng.random();
        let viewing_key: ViewingKey = rng.random();

        let recipient =
            RailgunAddress::from_private_keys(spending_key, viewing_key, ChainId::evm(1));
        let asset: AssetId = AssetId::Erc20(Address::from([0u8; 20]));
        let value: u128 = 1_000_000;

        let shield_request = encrypt_shield(recipient, asset, value, &mut rng).unwrap();
        insta::assert_debug_snapshot!(shield_request);
    }

    #[test]
    #[traced_test]
    fn test_blinded_key() {
        let viewing_key = ViewingKey::from_bytes([2u8; 32]);
        let their_viewing = ViewingKey::from_bytes([3u8; 32]);
        let shared_random = [4u8; 32];
        let sender_random = [5u8; 32];

        let (blinded, their_blinded) = blind_viewing_keys(
            viewing_key.public_key(),
            their_viewing.public_key(),
            &shared_random,
            &sender_random,
        )
        .unwrap();

        let expected_blinded = "2ed993356db2b8b5e573da394c2317942c9a1a72eb9a8dfd02705cc56cb1423b";
        let expected_their_blinded =
            "90878634485e306dc7f31840362fc43532313cea73c9006a19b0718e298ffcce";

        assert_eq!(expected_blinded, blinded.to_hex());
        assert_eq!(expected_their_blinded, their_blinded.to_hex());
    }

    #[test]
    #[traced_test]
    fn test_shared_blinded_key() {
        let viewing_key = ViewingKey::from_bytes([2u8; 32]);
        let their_viewing = ViewingKey::from_bytes([3u8; 32]);
        let shared_random = [4u8; 32];
        let sender_random = [5u8; 32];

        let (blinded, their_blinded) = blind_viewing_keys(
            viewing_key.public_key(),
            their_viewing.public_key(),
            &shared_random,
            &sender_random,
        )
        .unwrap();

        let shared_key_ab = viewing_key
            .derive_shared_key_blinded(their_blinded)
            .unwrap();
        let shared_key_ba = their_viewing.derive_shared_key_blinded(blinded).unwrap();

        let expected_shared_key =
            "2d33b7ea38413dfd631149f00dd0745f06dc06cd8112a6a174c73fa97af8d5a0";

        assert_eq!(shared_key_ab.to_hex(), shared_key_ba.to_hex());
        assert_eq!(expected_shared_key, shared_key_ab.to_hex());
    }
}
