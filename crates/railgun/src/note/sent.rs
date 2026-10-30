//! Sender-side view of a transact output.
//!
//! A post-transaction POI proof needs the note public key and value of every output, including
//! the ones sent to somebody else. When the operation was built by this process they come from
//! the builder; when the wallet is restored from its keys they have to be recovered from chain
//! data, which the sender can do with the shared key derived from the blinded receiver key.

use std::sync::Arc;

use alloy::primitives::U256;
use kohaku_crypto::poseidon_hash;
use serde::{Deserialize, Serialize};

use crate::{
    account::signer::RailgunSigner,
    crypto::keys::U256Key,
    indexer::syncer,
    note::{
        encrypt::{DecryptError, decrypt_transact_as_sender},
        utxo::NoteError,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentNote {
    pub tree_number: u32,
    pub leaf_index: u32,
    pub hash: U256,
    pub note_public_key: U256,
    pub value: u128,
    pub token_hash: U256,
}

impl SentNote {
    /// Decrypts a transact commitment as its sender.
    ///
    /// Returns `Ok(None)` when the ciphertext opens but no receiver master key candidate
    /// reproduces the on-chain commitment hash.
    pub fn decrypt(
        signer: &Arc<dyn RailgunSigner>,
        transact: &syncer::Transact,
    ) -> Result<Option<Self>, NoteError> {
        let plaintext = match decrypt_transact_as_sender(signer.as_ref(), transact) {
            Ok(plaintext) => plaintext,
            Err(DecryptError::Malformed) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let encoded_mpk = U256::from_be_slice(&plaintext.encoded_master_key);
        let token_hash = U256::from_be_slice(&plaintext.token_hash);
        let random = U256::from_be_slice(&plaintext.random);
        let value = plaintext.value;

        // The Railgun engine stores receiver XOR sender unless the sender is hidden; kohaku
        // stores the receiver key as is. The commitment hash tells which one applies.
        let sender_mpk = signer.address().master_key().to_u256();
        for receiver_mpk in [encoded_mpk, encoded_mpk ^ sender_mpk] {
            let Ok(npk) = poseidon_hash(&[receiver_mpk, random]) else {
                continue;
            };
            let Ok(hash) = poseidon_hash(&[npk, token_hash, U256::from(value)]) else {
                continue;
            };
            if hash == transact.hash {
                return Ok(Some(SentNote {
                    tree_number: transact.tree_number,
                    leaf_index: transact.leaf_index,
                    hash,
                    note_public_key: npk,
                    value,
                    token_hash,
                }));
            }
        }
        Ok(None)
    }
}
