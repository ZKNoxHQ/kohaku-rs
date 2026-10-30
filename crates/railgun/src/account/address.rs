use std::{fmt::Display, str::FromStr};

use bech32::{
    Bech32m, Fe32, Hrp,
    primitives::{
        checksum::{Checksum, Engine},
        decode::UncheckedHrpstring,
        encode::Encoder,
        iter::{ByteIterExt, Fe32IterExt},
    },
};
use serde::{self, Deserialize, Serialize};
use thiserror::Error;

use crate::{
    account::chain::{ChainId, ChainIdError},
    crypto::{
        kem::{self, KemEncapsulationKey, KemError},
        keys::{ByteKey, KeyError, MasterPublicKey, SpendingKey, ViewingKey, ViewingPublicKey},
    },
    note::encrypt::NoteEncryption,
};

/// Railgun address
///
/// Railgun addresses are the primary identifiers for users within the Railgun protocol, encoding
/// the public key material required to send transactions to the addressed account, as well as an
/// optional advisory chain ID.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct RailgunAddress {
    master_key: MasterPublicKey,
    viewing_pubkey: ViewingPublicKey,
    chain_id: ChainId,
}

#[derive(Debug, Error)]
pub enum RailgunAddressError {
    #[error("Bech32 decoding error: {0}")]
    Bech32Decode(#[from] bech32::DecodeError),
    #[error("Invalid Prefix: {0}")]
    InvalidPrefix(String),
    #[error("ParseInt Error: {0}")]
    ParseInt(#[from] std::num::ParseIntError),
    #[error("Key Error: {0}")]
    Key(#[from] KeyError),
    #[error("Invalid ChainId: {0}")]
    InvalidChainId(u8),
    #[error("Invalid Version: {0}")]
    InvalidVersion(u8),
    #[error("Invalid payload length: expected 73 bytes, got {0}")]
    InvalidPayloadLength(usize),
    #[error("Invalid ML-KEM key: {0}")]
    Kem(#[from] KemError),
    #[error("Invalid Bech32m string: {0}")]
    InvalidBech32m(&'static str),
    #[error("Invalid payload padding: {0}")]
    InvalidPadding(#[from] bech32::primitives::decode::PaddingError),
    #[error("Hex decoding error: {0}")]
    HexDecode(#[from] hex::FromHexError),
    #[error("Chain ID parsing error: {0}")]
    ChainId(#[from] ChainIdError),
}

const PREFIX: Hrp = Hrp::parse_unchecked("0zk");
const ADDRESS_VERSION: u8 = 1;
const PAYLOAD_LENGTH: usize = 73;
/// Version 2: the version 1 payload followed by the ML-KEM-768 encapsulation key.
const ADDRESS_VERSION_PQ: u8 = 2;
const PAYLOAD_LENGTH_PQ: usize = PAYLOAD_LENGTH + kem::ENCAPSULATION_KEY_SIZE;

impl RailgunAddress {
    pub fn from_public_keys(
        master_key: MasterPublicKey,
        viewing_pubkey: ViewingPublicKey,
        chain_id: ChainId,
    ) -> Self {
        RailgunAddress {
            master_key,
            viewing_pubkey,
            chain_id,
        }
    }

    pub fn from_private_keys(
        spending_key: SpendingKey,
        viewing_key: ViewingKey,
        chain_id: ChainId,
    ) -> Self {
        let master_key =
            MasterPublicKey::new(spending_key.public_key(), viewing_key.nullifying_key());

        RailgunAddress::from_public_keys(master_key, viewing_key.public_key(), chain_id)
    }

    pub fn master_key(&self) -> MasterPublicKey {
        self.master_key
    }

    pub fn viewing_pubkey(&self) -> ViewingPublicKey {
        self.viewing_pubkey
    }

    pub fn chain(&self) -> ChainId {
        self.chain_id
    }

    /// The same keys under another advisory chain ID, e.g. the chain-agnostic form.
    pub fn with_chain(mut self, chain_id: ChainId) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// The address with the account's ML-KEM key, for post-quantum encrypted notes.
    pub fn with_kem_key(self, kem_key: KemEncapsulationKey) -> PqRailgunAddress {
        PqRailgunAddress::new(self, kem_key)
    }

    /// Master public key (32), network ID (8), viewing public key (32).
    fn payload_body(&self) -> Vec<u8> {
        let network_id_hex = xor_network_id(&self.chain_id.to_string());
        let network_id = hex::decode(network_id_hex).unwrap();

        let mut body = Vec::with_capacity(PAYLOAD_LENGTH - 1);
        body.extend_from_slice(self.master_key.as_bytes());
        body.extend_from_slice(&network_id);
        body.extend_from_slice(self.viewing_pubkey.as_bytes());
        body
    }

    fn from_payload_body(body: &[u8]) -> Result<Self, RailgunAddressError> {
        let master_key = MasterPublicKey::from_bytes(body[..32].try_into().unwrap());
        let network_id = xor_network_id(&hex::encode(&body[32..40]));
        let chain_id = ChainId::from_str(&network_id)?;
        let viewing_pubkey = ViewingPublicKey::from_bytes(body[40..72].try_into().unwrap());

        Ok(RailgunAddress {
            master_key,
            viewing_pubkey,
            chain_id,
        })
    }
}

impl Display for RailgunAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut payload = Vec::with_capacity(PAYLOAD_LENGTH);
        payload.push(ADDRESS_VERSION);
        payload.extend_from_slice(&self.payload_body());

        let encoded = bech32::encode::<bech32::Bech32m>(PREFIX, &payload).unwrap();
        write!(f, "{}", encoded)
    }
}

impl FromStr for RailgunAddress {
    type Err = RailgunAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let payload = decode_payload(s)?;

        if payload.len() != PAYLOAD_LENGTH {
            return Err(RailgunAddressError::InvalidPayloadLength(payload.len()));
        }

        let version = payload[0];
        if version != ADDRESS_VERSION {
            return Err(RailgunAddressError::InvalidVersion(version));
        }

        Self::from_payload_body(&payload[1..])
    }
}

/// A Railgun address together with the account's ML-KEM-768 encapsulation key: what a sender
/// needs to encrypt a note with [`NoteEncryption::HybridPq`].
///
/// Encoded like a [`RailgunAddress`] with version byte 2 and the key after the version 1
/// payload, about 2,000 characters. Legacy wallets refuse the version rather than misread it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PqRailgunAddress {
    address: RailgunAddress,
    kem_key: KemEncapsulationKey,
}

impl PqRailgunAddress {
    pub fn new(address: RailgunAddress, kem_key: KemEncapsulationKey) -> Self {
        Self { address, kem_key }
    }

    pub fn address(&self) -> RailgunAddress {
        self.address
    }

    pub fn kem_key(&self) -> &KemEncapsulationKey {
        &self.kem_key
    }

    /// The scheme that encrypts a note to this address.
    pub fn encryption(&self) -> NoteEncryption {
        NoteEncryption::HybridPq {
            receiver_kem_key: self.kem_key.clone(),
        }
    }
}

impl Display for PqRailgunAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut payload = Vec::with_capacity(PAYLOAD_LENGTH_PQ);
        payload.push(ADDRESS_VERSION_PQ);
        payload.extend_from_slice(&self.address.payload_body());
        payload.extend_from_slice(self.kem_key.as_bytes());

        // Past the Bech32m code length, which `bech32::encode` refuses: the checksum still
        // detects errors, only its guaranteed detection bound no longer applies.
        let encoder = Encoder::<_, Bech32m>::new(payload.iter().copied().bytes_to_fes(), &PREFIX);
        for c in encoder.chars() {
            write!(f, "{c}")?;
        }
        Ok(())
    }
}

impl FromStr for PqRailgunAddress {
    type Err = RailgunAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let payload = decode_long_payload(s)?;

        if payload.len() != PAYLOAD_LENGTH_PQ {
            return Err(RailgunAddressError::InvalidPayloadLength(payload.len()));
        }

        let version = payload[0];
        if version != ADDRESS_VERSION_PQ {
            return Err(RailgunAddressError::InvalidVersion(version));
        }

        let address = RailgunAddress::from_payload_body(&payload[1..PAYLOAD_LENGTH])?;
        let kem_key = KemEncapsulationKey::from_slice(&payload[PAYLOAD_LENGTH..])?;
        Ok(Self { address, kem_key })
    }
}

impl TryFrom<String> for PqRailgunAddress {
    type Error = RailgunAddressError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<PqRailgunAddress> for String {
    fn from(address: PqRailgunAddress) -> Self {
        address.to_string()
    }
}

/// [`decode_payload`] for strings past the Bech32m code length, which the crate's decoder
/// refuses. Same checks: one case, valid characters, the checksum, zero padding bits.
fn decode_long_payload(s: &str) -> Result<Vec<u8>, RailgunAddressError> {
    let invalid = RailgunAddressError::InvalidBech32m;
    if s.bytes().any(|b| b.is_ascii_uppercase()) && s.bytes().any(|b| b.is_ascii_lowercase()) {
        return Err(invalid("mixed case"));
    }
    let lower = s.to_ascii_lowercase();
    let Some((hrp, data)) = lower.rsplit_once('1') else {
        return Err(invalid("no separator"));
    };
    if hrp != PREFIX.to_string() {
        return Err(RailgunAddressError::InvalidPrefix(hrp.to_string()));
    }
    let fes: Vec<Fe32> = data
        .chars()
        .map(Fe32::from_char)
        .collect::<Result<_, _>>()
        .map_err(|_| invalid("invalid character"))?;
    if fes.len() <= Bech32m::CHECKSUM_LENGTH {
        return Err(invalid("too short"));
    }

    let mut engine = Engine::<Bech32m>::new();
    engine.input_hrp(PREFIX);
    for fe in &fes {
        engine.input_fe(*fe);
    }
    if *engine.residue() != Bech32m::TARGET_RESIDUE {
        return Err(invalid("checksum"));
    }

    let data = &fes[..fes.len() - Bech32m::CHECKSUM_LENGTH];
    let padding_bits = (data.len() * 5) % 8;
    let padding_is_zero = data
        .last()
        .is_none_or(|last| last.to_u8() & ((1u8 << padding_bits) - 1) == 0);
    if padding_bits >= 5 || !padding_is_zero {
        return Err(invalid("padding"));
    }
    Ok(data.iter().copied().fes_to_bytes().collect())
}

/// The bytes of a `0zk` Bech32m string, with its version byte first.
fn decode_payload(s: &str) -> Result<Vec<u8>, RailgunAddressError> {
    // The generic decoder also accepts the legacy Bech32 checksum. Railgun
    // addresses use Bech32m exclusively, as in the published engine.
    let unchecked = UncheckedHrpstring::new(s).map_err(bech32::DecodeError::Parse)?;
    unchecked
        .validate_checksum::<bech32::Bech32m>()
        .map_err(bech32::DecodeError::Checksum)?;
    let checked = unchecked.remove_checksum::<bech32::Bech32m>();
    // byte_iter drops trailing bits; validate them before decoding bytes.
    checked.validate_segwit_padding()?;
    let hrp = checked.hrp();
    if hrp != PREFIX {
        return Err(RailgunAddressError::InvalidPrefix(hrp.to_string()));
    }
    Ok(checked.byte_iter().collect())
}

//? Redundant with FromStr, but required for serde's try_from
impl TryFrom<String> for RailgunAddress {
    type Error = RailgunAddressError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

//? Redundant with Display, but required for serde's into
impl From<RailgunAddress> for String {
    fn from(address: RailgunAddress) -> Self {
        address.to_string()
    }
}

fn xor_network_id(network_id: &str) -> String {
    let bytes = hex::decode(network_id).expect("valid hex");
    let key = b"railgun\x00"; // 8-byte key
    let xored: Vec<u8> = bytes.iter().zip(key.iter()).map(|(a, b)| a ^ b).collect();
    hex::encode(xored)
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use tracing_test::traced_test;

    use super::*;
    use crate::crypto::keys::ByteKey;

    #[test]
    #[traced_test]
    fn test_railgun_address_to_from_string() {
        let master_key = MasterPublicKey::from_bytes([1u8; 32]);
        let viewing_pubkey = ViewingPublicKey::from_bytes([2u8; 32]);
        let chain = 1;
        let railgun_address =
            RailgunAddress::from_public_keys(master_key, viewing_pubkey, ChainId::evm(chain));

        let address_string = railgun_address.to_string();
        let expected_address_string = "0zk1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszunpd9kxwatwqypqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqy3t4umn";
        assert_eq!(address_string, expected_address_string);

        let parsed: RailgunAddress = address_string.parse().unwrap();
        assert_eq!(parsed, railgun_address);
    }

    #[test]
    #[traced_test]
    fn test_railgun_address_all_chains() {
        let address = "0zk1qykqj8ed50tfm8a4ezl2qekk3aqxuq37pgv88pv6s9phk0vj3lv7erv7j6fe3z53la8hh9taj9xq34y835wrscryymjf8qqrasmm2vxrm68y0qsxtcvzj6paxpy";
        let parsed: RailgunAddress = address.parse().unwrap();
        assert_eq!(parsed.chain(), ChainId::All);

        let address_string = parsed.to_string();
        assert_eq!(address_string, address);
    }

    /// Version 2 carries the KEM key; each version refuses the other's string.
    #[test]
    fn pq_address_round_trips_and_versions_do_not_mix() {
        use crate::crypto::kem::KemKeyPair;

        let address = RailgunAddress::from_public_keys(
            MasterPublicKey::from_bytes([1u8; 32]),
            ViewingPublicKey::from_bytes([2u8; 32]),
            ChainId::evm(1),
        );
        let kem = KemKeyPair::derive(b"receiver");
        let pq = address.with_kem_key(kem.encapsulation_key().clone());

        let encoded = pq.to_string();
        assert!(encoded.starts_with("0zk1"));
        assert_eq!(encoded.len(), 2022);
        let parsed: PqRailgunAddress = encoded.parse().unwrap();
        assert_eq!(
            encoded
                .to_ascii_uppercase()
                .parse::<PqRailgunAddress>()
                .unwrap(),
            pq
        );
        let mut flipped = encoded.clone();
        flipped.replace_range(100..101, if &encoded[100..101] == "q" { "p" } else { "q" });
        assert!(matches!(
            flipped.parse::<PqRailgunAddress>(),
            Err(RailgunAddressError::InvalidBech32m("checksum"))
        ));
        assert_eq!(parsed, pq);
        assert_eq!(parsed.address(), address);
        assert_eq!(parsed.kem_key(), kem.encapsulation_key());
        assert_eq!(
            serde_json::from_value::<PqRailgunAddress>(serde_json::json!(encoded)).unwrap(),
            pq
        );

        // A version 1 parser refuses the string (the crate's decoder, at its length limit).
        assert!(encoded.parse::<RailgunAddress>().is_err());
        assert!(matches!(
            address.to_string().parse::<PqRailgunAddress>(),
            Err(RailgunAddressError::InvalidPayloadLength(_))
        ));

        // The version byte alone is not enough: a version 1 payload tagged 2, and vice versa.
        let (_, mut payload) = bech32::decode(&address.to_string()).unwrap();
        payload[0] = ADDRESS_VERSION_PQ;
        let tagged = bech32::encode::<bech32::Bech32m>(PREFIX, &payload).unwrap();
        assert!(tagged.parse::<PqRailgunAddress>().is_err());
        assert!(tagged.parse::<RailgunAddress>().is_err());

        // A corrupted key is refused by ML-KEM's key validation.
        let mut payload = vec![ADDRESS_VERSION_PQ];
        payload.extend_from_slice(&address.payload_body());
        payload.extend_from_slice(&[0xffu8; kem::ENCAPSULATION_KEY_SIZE]);
        let encoder = Encoder::<_, Bech32m>::new(payload.iter().copied().bytes_to_fes(), &PREFIX);
        let corrupted: String = encoder.chars().collect();
        assert!(matches!(
            corrupted.parse::<PqRailgunAddress>(),
            Err(RailgunAddressError::Kem(_))
        ));
    }

    #[test]
    fn test_invalid_payload_lengths_return_errors() {
        let address = RailgunAddress::from_public_keys(
            MasterPublicKey::from_bytes([1u8; 32]),
            ViewingPublicKey::from_bytes([2u8; 32]),
            ChainId::evm(1),
        );
        let (_, payload) = bech32::decode(&address.to_string()).unwrap();
        for length in 0..payload.len() {
            let encoded = bech32::encode::<bech32::Bech32m>(PREFIX, &payload[..length]).unwrap();
            let result = std::panic::catch_unwind(|| encoded.parse::<RailgunAddress>());
            assert!(result.is_ok(), "payload length {length} must not panic");
            assert!(
                result.unwrap().is_err(),
                "payload length {length} must refuse"
            );
        }
        let mut oversized = payload;
        oversized.push(0);
        let encoded = bech32::encode::<bech32::Bech32m>(PREFIX, &oversized).unwrap();
        assert!(encoded.parse::<RailgunAddress>().is_err());
        assert!(serde_json::from_value::<RailgunAddress>(serde_json::json!(encoded)).is_err());
    }

    #[test]
    fn test_legacy_bech32_checksum_is_refused() {
        let address = RailgunAddress::from_public_keys(
            MasterPublicKey::from_bytes([1u8; 32]),
            ViewingPublicKey::from_bytes([2u8; 32]),
            ChainId::evm(1),
        );
        let (_, payload) = bech32::decode(&address.to_string()).unwrap();
        let encoded = bech32::encode::<bech32::Bech32>(PREFIX, &payload).unwrap();
        assert!(encoded.parse::<RailgunAddress>().is_err());
        assert!(address.to_string().parse::<RailgunAddress>().is_ok());
    }

    #[test]
    fn test_noncanonical_padding_is_refused() {
        // Valid Bech32m checksums, but a nonzero padding bit or an extra group.
        // The published engine rejects both rather than aliasing one address.
        for encoded in [
            "0zk1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszunpd9kxwatwqypqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq9vapfxp",
            "0zk1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszunpd9kxwatwqypqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqdnz56e",
        ] {
            assert!(matches!(
                encoded.parse::<RailgunAddress>(),
                Err(RailgunAddressError::InvalidPadding(_))
            ));
        }
    }
}
