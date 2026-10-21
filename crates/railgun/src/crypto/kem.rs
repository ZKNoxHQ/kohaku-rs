//! ML-KEM-768 (FIPS 203), the post-quantum half of
//! [`crate::note::encrypt::NoteEncryption::HybridPq`].
//!
//! The key pair is derived from a secret rather than generated, so a wallet restores it from
//! its seed like the viewing key. Encapsulation randomness is drawn by the caller.

use std::fmt;

use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768PrivateKey, MlKem768PublicKey};
use sha2::{Digest, Sha512};
use thiserror::Error;

pub const ENCAPSULATION_KEY_SIZE: usize = 1184;
pub const DECAPSULATION_KEY_SIZE: usize = 2400;
pub const CIPHERTEXT_SIZE: usize = 1088;
pub const SHARED_SECRET_SIZE: usize = 32;
const SEED_SIZE: usize = 64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KemError {
    #[error("ML-KEM encapsulation key is not {ENCAPSULATION_KEY_SIZE} valid bytes")]
    InvalidEncapsulationKey,
    #[error("ML-KEM ciphertext is not {CIPHERTEXT_SIZE} bytes")]
    InvalidCiphertext,
}

/// The public key a sender encapsulates to. Published by the receiver.
#[derive(Clone, PartialEq, Eq)]
pub struct KemEncapsulationKey([u8; ENCAPSULATION_KEY_SIZE]);

/// The receiver's key pair.
#[derive(Clone)]
pub struct KemKeyPair {
    encapsulation_key: KemEncapsulationKey,
    decapsulation_key: [u8; DECAPSULATION_KEY_SIZE],
}

#[derive(Clone, PartialEq, Eq)]
pub struct KemCiphertext([u8; CIPHERTEXT_SIZE]);

impl KemKeyPair {
    /// Deterministic key pair from a 64-byte seed (`d || z` of FIPS 203).
    pub fn from_seed(seed: [u8; SEED_SIZE]) -> Self {
        let pair = mlkem768::generate_key_pair(seed);
        Self {
            encapsulation_key: KemEncapsulationKey(*pair.pk()),
            decapsulation_key: *pair.sk(),
        }
    }

    /// Key pair from a wallet secret of any length, such as a BIP-32 key at [`kem_key_path`]:
    /// the seed is `SHA-512("RAILGUN-PQ-V1-KEM" || secret)`.
    pub fn derive(secret: &[u8]) -> Self {
        let seed = Sha512::new()
            .chain_update(b"RAILGUN-PQ-V1-KEM")
            .chain_update(secret)
            .finalize();
        Self::from_seed(seed.into())
    }

    pub fn encapsulation_key(&self) -> &KemEncapsulationKey {
        &self.encapsulation_key
    }

    /// The shared secret of `ciphertext`. A ciphertext for another key yields an unrelated,
    /// pseudo-random secret (implicit rejection), never an error.
    pub fn decapsulate(&self, ciphertext: &KemCiphertext) -> [u8; SHARED_SECRET_SIZE] {
        let private_key = MlKem768PrivateKey::from(self.decapsulation_key);
        mlkem768::decapsulate(&private_key, &MlKem768Ciphertext::from(ciphertext.0))
    }
}

impl KemEncapsulationKey {
    pub fn from_bytes(bytes: [u8; ENCAPSULATION_KEY_SIZE]) -> Result<Self, KemError> {
        let key = MlKem768PublicKey::from(bytes);
        if !mlkem768::validate_public_key(&key) {
            return Err(KemError::InvalidEncapsulationKey);
        }
        Ok(Self(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, KemError> {
        let bytes: [u8; ENCAPSULATION_KEY_SIZE] = bytes
            .try_into()
            .map_err(|_| KemError::InvalidEncapsulationKey)?;
        Self::from_bytes(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; ENCAPSULATION_KEY_SIZE] {
        &self.0
    }

    /// A fresh shared secret and the ciphertext that carries it to the key's owner.
    pub fn encapsulate(
        &self,
        randomness: [u8; SHARED_SECRET_SIZE],
    ) -> (KemCiphertext, [u8; SHARED_SECRET_SIZE]) {
        let (ciphertext, shared_secret) =
            mlkem768::encapsulate(&MlKem768PublicKey::from(self.0), randomness);
        (KemCiphertext(*ciphertext.as_slice()), shared_secret)
    }
}

impl KemCiphertext {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, KemError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| KemError::InvalidCiphertext)
    }

    pub fn as_bytes(&self) -> &[u8; CIPHERTEXT_SIZE] {
        &self.0
    }
}

impl fmt::Debug for KemEncapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemEncapsulationKey({}…)", hex::encode(&self.0[..8]))
    }
}

impl fmt::Debug for KemKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemKeyPair({:?})", self.encapsulation_key)
    }
}

impl fmt::Debug for KemCiphertext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KemCiphertext({}…)", hex::encode(&self.0[..8]))
    }
}

/// BIP-32 derivation path for the ML-KEM key of a Railgun account. A kohaku convention: 203 for
/// FIPS 203, then Railgun's 1984, like the viewing key path.
pub fn kem_key_path(index: u32) -> String {
    format!("m/203'/1984'/0'/0'/{}'", index)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_pair_is_deterministic_and_round_trips() {
        let a = KemKeyPair::derive(b"secret");
        let b = KemKeyPair::derive(b"secret");
        assert_eq!(a.encapsulation_key(), b.encapsulation_key());
        assert_ne!(
            a.encapsulation_key(),
            KemKeyPair::derive(b"other").encapsulation_key()
        );

        let (ciphertext, secret) = a.encapsulation_key().encapsulate([7u8; 32]);
        assert_eq!(a.decapsulate(&ciphertext), secret);
        assert_eq!(b.decapsulate(&ciphertext), secret);
        // Implicit rejection: another key gets a different secret, not an error.
        assert_ne!(
            KemKeyPair::derive(b"other").decapsulate(&ciphertext),
            secret
        );

        let reparsed = KemEncapsulationKey::from_slice(a.encapsulation_key().as_bytes()).unwrap();
        assert_eq!(&reparsed, a.encapsulation_key());
        assert_eq!(
            KemEncapsulationKey::from_slice(&[0u8; 10]),
            Err(KemError::InvalidEncapsulationKey)
        );
        assert_eq!(
            KemCiphertext::from_slice(&[0u8; 10]),
            Err(KemError::InvalidCiphertext)
        );
    }
}
