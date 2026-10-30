use std::{
    fmt::{Debug, Display},
    sync::Arc,
};

use alloy::primitives::U256;
use kohaku_crypto::poseidon_hash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    abis::railgun::{TokenData, TokenDataError},
    account::signer::RailgunSigner,
    caip::AssetId,
    crypto::{
        aes::AesError,
        keys::{
            ByteKey, KeyError, MasterPublicKey, NullifyingKey, SpendingPublicKey, U256Key,
            ViewingPublicKey,
        },
    },
    indexer::syncer,
    merkle_tree::UtxoLeafHash,
    note::{
        Note,
        encrypt::{DecryptError, decrypt_transact_as_receiver},
    },
    poi::types::BlindedCommitmentType,
};

/// Railgun UTXO note
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct UtxoNote {
    pub tree_number: u32,
    pub leaf_index: u32,
    pub spending_pubkey: SpendingPublicKey,
    pub viewing_pubkey: ViewingPublicKey,

    pub random: [u8; 16],
    pub value: u128,
    pub asset: AssetId,
    pub memo: String,

    pub hash: UtxoLeafHash,
    pub nullifier: U256,
    pub note_public_key: U256,
    #[allow(private_interfaces)]
    pub nullifying_key: NullifyingKey,
    pub blinded_commitment: U256,
    pub commitment_type: BlindedCommitmentType,
}

#[derive(Debug, Error)]
pub enum NoteError {
    #[error("AES error: {0}")]
    Aes(#[from] AesError),
    #[error("TokenData error: {0}")]
    TokenData(#[from] TokenDataError),
    #[error("Key error: {0}")]
    Key(#[from] KeyError),
    #[error("Decryption error: {0}")]
    Decrypt(#[from] DecryptError),
}

impl UtxoNote {
    pub fn new(
        tree_number: u32,
        leaf_index: u32,
        signer: Arc<dyn RailgunSigner>,
        asset: AssetId,
        value: u128,
        random: [u8; 16],
        memo: &str,
        commitment_type: BlindedCommitmentType,
    ) -> Self {
        let spending_pubkey = signer.spending_public_key();
        let viewing_pubkey = signer.viewing_key().public_key();
        let nullifying_key = signer.viewing_key().nullifying_key();
        let nullifier = poseidon_hash(&[nullifying_key.to_u256(), U256::from(leaf_index)]).unwrap();
        // Through the signer's master key rather than rebuilt from its spending public key: equal
        // for a full signer (the trait default), and correct for a view-only signer that knows
        // the master key from the 0zk address but not the spending public key.
        let npk = note_public_key(signer.master_public_key(), &random);
        let hash = note_hash(npk, asset, value);
        let blinded_commitment = blinded_commitment(hash.into(), npk, tree_number, leaf_index);

        UtxoNote {
            tree_number,
            leaf_index,
            spending_pubkey,
            viewing_pubkey,
            asset,
            value,
            random,
            memo: memo.to_string(),
            hash,
            note_public_key: npk,
            nullifying_key,
            nullifier,
            blinded_commitment,
            commitment_type,
        }
    }

    /// Decrypt a transact note into a Note
    pub fn decrypt_transact(
        signer: Arc<dyn RailgunSigner>,
        transact: &syncer::Transact,
    ) -> Result<Self, NoteError> {
        let plaintext = decrypt_transact_as_receiver(signer.as_ref(), transact)?;
        let token_data = TokenData::from_hash(&plaintext.token_hash)?;
        let asset_id = AssetId::from(token_data);
        let memo = std::str::from_utf8(&plaintext.memo).unwrap_or("");

        Ok(UtxoNote::new(
            transact.tree_number,
            transact.leaf_index,
            signer,
            asset_id,
            plaintext.value,
            plaintext.random,
            memo,
            BlindedCommitmentType::Transact,
        ))
    }

    /// Decrypts a shield note into a Note
    pub fn decrypt_shield(
        signer: Arc<dyn RailgunSigner>,
        shield: &syncer::Shield,
    ) -> Result<Self, NoteError> {
        let shield_key = ViewingPublicKey::from_bytes(shield.shield_key);
        let shared_key = signer.viewing_key().derive_shared_key(shield_key)?;

        let decrypted = shared_key.decrypt_gcm(&shield.ciphertext)?;
        let asset_id = shield.token;
        let value = shield.value;

        let mut random = [0u8; 16];
        random.copy_from_slice(&decrypted[0][..16]);

        Ok(UtxoNote::new(
            shield.tree_number,
            shield.leaf_index,
            signer,
            asset_id,
            value.saturating_to(),
            random,
            "",
            BlindedCommitmentType::Shield,
        ))
    }
}

impl Note for UtxoNote {
    fn asset(&self) -> AssetId {
        self.asset
    }

    fn value(&self) -> u128 {
        self.value
    }

    fn memo(&self) -> String {
        self.memo.clone()
    }

    fn random(&self) -> [u8; 16] {
        self.random
    }

    fn hash(&self) -> UtxoLeafHash {
        self.hash
    }

    fn note_public_key(&self) -> U256 {
        self.note_public_key
    }
}

impl Display for UtxoNote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UtxoNote {{ tree_number: {}, leaf_index: {}, asset: {}, value: {}, memo: {}, type: {:?} }}",
            self.tree_number,
            self.leaf_index,
            self.asset,
            self.value,
            self.memo,
            self.commitment_type
        )
    }
}

fn note_hash(note_public_key: U256, asset: AssetId, value: u128) -> UtxoLeafHash {
    poseidon_hash(&[note_public_key, asset.hash(), U256::from(value)])
        .unwrap()
        .into()
}

/// `npk = poseidon(masterPublicKey, random)`.
fn note_public_key(master_key: MasterPublicKey, random: &[u8; 16]) -> U256 {
    poseidon_hash(&[master_key.to_u256(), U256::from_be_slice(random)]).unwrap()
}

pub fn blinded_commitment(hash: U256, npk: U256, tree_number: u32, leaf_index: u32) -> U256 {
    poseidon_hash(&[
        hash,
        npk,
        U256::from((tree_number as u128) * 65536 + (leaf_index as u128)),
    ])
    .unwrap()
}

#[cfg(all(test, native))]
pub fn test_note() -> UtxoNote {
    use crate::{
        account::signer::PrivateKeySigner,
        crypto::keys::{SpendingKey, ViewingKey},
    };

    let signer = PrivateKeySigner::new_evm(
        SpendingKey::from_bytes([1u8; 32]),
        ViewingKey::from_bytes([2u8; 32]),
        1,
    );
    UtxoNote::new(
        1,
        0,
        signer,
        AssetId::Erc20(alloy::primitives::address!(
            "0x1234567890123456789012345678901234567890"
        )),
        100u128,
        [3u8; 16],
        "test memo",
        BlindedCommitmentType::Transact,
    )
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use tracing_test::traced_test;

    use super::*;

    #[test]
    #[traced_test]
    fn test_note_hash() {
        let note = test_note();
        let hash: U256 = note.hash().into();

        insta::assert_debug_snapshot!(hash);
    }

    #[test]
    #[traced_test]
    fn test_note_spending_pubkey() {
        let note = test_note();
        let pub_key = note.spending_pubkey;

        insta::assert_debug_snapshot!(pub_key);
    }

    #[test]
    #[traced_test]
    fn test_note_nullifier() {
        let note = test_note();
        let nullifier = note.nullifier;

        insta::assert_debug_snapshot!(nullifier);
    }

    #[test]
    #[traced_test]
    fn test_note_nullifying_key() {
        let note = test_note();
        let nullifying_key = note.nullifying_key;

        insta::assert_debug_snapshot!(nullifying_key);
    }

    #[test]
    #[traced_test]
    fn test_note_public_key() {
        let note = test_note();
        let pub_key = note.note_public_key;

        insta::assert_debug_snapshot!(pub_key);
    }

    /// A signer that knows the viewing key and the master public key (as decoded from a 0zk
    /// address) but not the spending public key: it returns an unrelated one.
    struct ViewOnlySigner {
        viewing: crate::crypto::keys::ViewingKey,
        master: MasterPublicKey,
        placeholder: SpendingPublicKey,
    }

    #[async_trait::async_trait]
    impl RailgunSigner for ViewOnlySigner {
        fn chain_id(&self) -> crate::account::chain::ChainId {
            crate::account::chain::ChainId::evm(1)
        }
        fn viewing_key(&self) -> crate::crypto::keys::ViewingKey {
            self.viewing
        }
        fn spending_public_key(&self) -> SpendingPublicKey {
            self.placeholder
        }
        fn master_public_key(&self) -> MasterPublicKey {
            self.master
        }
        async fn sign(
            &self,
            _inputs: U256,
        ) -> Result<
            crate::crypto::keys::SpendingSignature,
            crate::account::signer::RailgunSignerError,
        > {
            Err(crate::account::signer::RailgunSignerError::new("view-only"))
        }
    }

    /// A view-only signer rebuilds the same note as the full signer: note public key, hash,
    /// blinded commitment and nullifier only depend on the master key and the viewing key.
    #[test]
    fn view_only_signer_rebuilds_the_same_note() {
        use crate::{
            account::signer::PrivateKeySigner,
            crypto::keys::{SpendingKey, ViewingKey},
        };

        let full = PrivateKeySigner::new_evm(
            SpendingKey::from_bytes([1u8; 32]),
            ViewingKey::from_bytes([2u8; 32]),
            1,
        );
        let view_only: Arc<dyn RailgunSigner> = Arc::new(ViewOnlySigner {
            viewing: full.viewing_key(),
            master: full.master_public_key(),
            placeholder: SpendingKey::from_bytes([9u8; 32]).public_key(),
        });
        assert_ne!(view_only.spending_public_key(), full.spending_public_key());
        assert_eq!(view_only.address(), full.address());

        let asset = AssetId::Erc20(alloy::primitives::address!(
            "0x1234567890123456789012345678901234567890"
        ));
        let build = |signer: Arc<dyn RailgunSigner>| {
            UtxoNote::new(
                1,
                7,
                signer,
                asset,
                100,
                [3u8; 16],
                "",
                BlindedCommitmentType::Transact,
            )
        };
        let (a, b) = (build(full), build(view_only));
        assert_eq!(a.note_public_key, b.note_public_key);
        assert_eq!(a.hash, b.hash);
        assert_eq!(a.blinded_commitment, b.blinded_commitment);
        assert_eq!(a.nullifier, b.nullifier);
    }
}
