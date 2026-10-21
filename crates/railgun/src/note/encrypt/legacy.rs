//! Railgun V2 note encryption: ed25519 ECDH on blinded viewing keys, AES-256-GCM for the note,
//! AES-256-CTR under the sender's viewing key for the annotation data. Readable by every Railgun
//! wallet.

use rand::{CryptoRng, RngExt};

use crate::{
    abis::railgun::CommitmentCiphertext,
    account::{address::RailgunAddress, signer::RailgunSigner},
    caip::AssetId,
    crypto::{
        keys::{BlindedKey, ByteKey, U256Key, ViewingKey},
        railgun_base_37,
    },
    indexer::syncer,
    note::encrypt::{DecryptError, EncryptError, NotePlaintext, blind_viewing_keys, concat_arrays},
};

/// Encrypts a note into a CommitmentCiphertext
///
/// TODO: Add details on blind
#[allow(clippy::too_many_arguments)]
pub(super) fn encrypt(
    receiver: &RailgunAddress,
    shared_random: &[u8; 16],
    value: u128,
    asset: &AssetId,
    memo: &str,
    viewing_key: ViewingKey,
    blind: bool,
    rng: &mut dyn CryptoRng,
) -> Result<CommitmentCiphertext, EncryptError> {
    let output_type = 0;
    let application_identifier = railgun_base_37::encode("railgun rs")?;
    let sender_random: [u8; 15] = if blind { rng.random() } else { [0u8; 15] };

    let (blinded_sender, blinded_receiver) = blind_viewing_keys(
        viewing_key.public_key(),
        receiver.viewing_pubkey(),
        &concat_arrays(shared_random, &[0u8; 16]),
        &concat_arrays(&sender_random, &[0u8; 17]),
    )?;

    let shared_key = viewing_key.derive_shared_key_blinded(blinded_receiver)?;
    let gcm = shared_key.encrypt_gcm(
        &[
            receiver.master_key().as_bytes(),
            &asset.hash().to_be_bytes_vec(),
            &concat_arrays::<16, 16, 32>(shared_random, &value.to_be_bytes()),
            memo.as_bytes(),
        ],
        &rng.random(),
    )?;

    let ctr0: [u8; 16] = concat_arrays(&[output_type], &sender_random);
    let ctr1 = [0u8; 16];
    let ctr2 = application_identifier;
    let ctr = viewing_key.encrypt_ctr(&[&ctr0, &ctr1, &ctr2], &rng.random());

    let bundle_1: [u8; 32] = gcm.data[0].clone().try_into().unwrap();
    let bundle_2: [u8; 32] = gcm.data[1].clone().try_into().unwrap();
    let bundle_3: [u8; 32] = gcm.data[2].clone().try_into().unwrap();

    Ok(CommitmentCiphertext {
        // iv (16) | tag (16)
        // master_public_key (32)
        // token_hash (32)
        // random (16) | value (16)
        ciphertext: [
            concat_arrays(&gcm.iv, &gcm.tag).into(),
            bundle_1.into(),
            bundle_2.into(),
            bundle_3.into(),
        ],
        blindedSenderViewingKey: blinded_sender.to_u256().into(),
        blindedReceiverViewingKey: blinded_receiver.to_u256().into(),
        // ctr_iv (16) | outputType (1) | senderRandom (15) | padding (16) | applicationIdentifier
        // (16)
        annotationData: [ctr.iv.as_slice(), &ctr.data[0], &ctr.data[1], &ctr.data[2]]
            .concat()
            .into(),
        memo: gcm.data[3].clone().into(),
    })
}

/// The receiver's shared key comes from the blinded sender key.
pub(super) fn decrypt_as_receiver(
    signer: &dyn RailgunSigner,
    transact: &syncer::Transact,
) -> Result<NotePlaintext, DecryptError> {
    let blinded_sender = BlindedKey::from_bytes(transact.blinded_sender_viewing_key);
    let shared_key = signer
        .viewing_key()
        .derive_shared_key_blinded(blinded_sender)?;
    NotePlaintext::from_bundle(shared_key.decrypt_gcm(&transact.ciphertext)?)
}

/// The sender's shared key comes from the blinded receiver key.
pub(super) fn decrypt_as_sender(
    signer: &dyn RailgunSigner,
    transact: &syncer::Transact,
) -> Result<NotePlaintext, DecryptError> {
    let blinded_receiver = BlindedKey::from_bytes(transact.blinded_receiver_viewing_key);
    let shared_key = signer
        .viewing_key()
        .derive_shared_key_blinded(blinded_receiver)?;
    NotePlaintext::from_bundle(shared_key.decrypt_gcm(&transact.ciphertext)?)
}
