//! Offline interoperability vectors from the published Railgun engine 9.6.0.
//! All keys come from the well-known public test mnemonic; never fund them.

use std::{
    io,
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use crate::{
    account::{
        address::RailgunAddress,
        chain::ChainId,
        signer::{RailgunSigner, RailgunSignerError},
    },
    crypto::{
        keys::{HexKey, SpendingKey, SpendingPublicKey, SpendingSignature, ViewingKey},
        railgun_txid::Txid,
    },
};
use ruint::aliases::U256;
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    accounts: Vec<Account>,
    operations: Vec<Operation>,
}

#[derive(Deserialize)]
struct Account {
    index: u32,
    spending_key: String,
    viewing_key: String,
    spending_public_key: [String; 2],
    viewing_public_key: String,
    master_public_key: String,
    addresses: Vec<Address>,
    signatures: Vec<Signature>,
}

#[derive(Deserialize)]
struct Address {
    chain_id: Option<u64>,
    address: String,
}

#[derive(Deserialize)]
struct Signature {
    message: String,
    r8_x: String,
    r8_y: String,
    s: String,
}

impl Signature {
    fn signature(&self) -> SpendingSignature {
        SpendingSignature {
            r8_x: decimal(&self.r8_x),
            r8_y: decimal(&self.r8_y),
            s: decimal(&self.s),
        }
    }
}

#[derive(Deserialize)]
struct Operation {
    name: String,
    nullifiers: Vec<String>,
    commitments: Vec<String>,
    bound_params_hash: String,
    txid: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(include_str!(
        "../tests/fixtures/engine-interoperability/vectors.json"
    ))
    .unwrap()
}

fn decimal(value: &str) -> U256 {
    U256::from_str_radix(value, 10).unwrap()
}

fn chain(id: Option<u64>) -> ChainId {
    id.map_or(ChainId::All, ChainId::evm)
}

#[test]
fn engine_keys_and_addresses_match() {
    for account in vectors().accounts {
        let spending = SpendingKey::from_hex(&account.spending_key).unwrap();
        let viewing = ViewingKey::from_hex(&account.viewing_key).unwrap();
        let public = spending.public_key();
        assert_eq!(public.x_u256(), decimal(&account.spending_public_key[0]));
        assert_eq!(public.y_u256(), decimal(&account.spending_public_key[1]));
        assert_eq!(viewing.public_key().to_hex(), account.viewing_public_key);
        for address in account.addresses {
            let actual =
                RailgunAddress::from_private_keys(spending, viewing, chain(address.chain_id));
            assert_eq!(actual.master_key().to_hex(), account.master_public_key);
            assert_eq!(
                actual.to_string(),
                address.address,
                "account {}",
                account.index
            );
            assert_eq!(RailgunAddress::from_str(&address.address).unwrap(), actual);
        }
    }
}

#[test]
fn engine_signatures_match_and_verify() {
    let accounts = vectors().accounts;
    for (position, account) in accounts.iter().enumerate() {
        let spending = SpendingKey::from_hex(&account.spending_key).unwrap();
        let public = spending.public_key();
        let other_public =
            SpendingKey::from_hex(&accounts[(position + 1) % accounts.len()].spending_key)
                .unwrap()
                .public_key();
        for expected in &account.signatures {
            let message = decimal(&expected.message);
            let reference = expected.signature();
            let actual = spending.sign(message);
            assert_eq!(
                (actual.r8_x, actual.r8_y, actual.s),
                (reference.r8_x, reference.r8_y, reference.s)
            );
            assert!(public.verify(message, &reference));
            assert!(!public.verify(message + U256::from(1), &reference));
            assert!(!other_public.verify(message, &reference));
        }
    }
}

/// Models a signer whose spending key stays outside the Railgun runtime.
/// It owns only public key material, the exportable viewing key and public fixture signatures.
struct ExternalSigner {
    public: SpendingPublicKey,
    viewing: ViewingKey,
    signatures: Vec<Signature>,
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl RailgunSigner for ExternalSigner {
    fn chain_id(&self) -> ChainId {
        ChainId::All
    }
    fn viewing_key(&self) -> ViewingKey {
        self.viewing
    }
    fn spending_public_key(&self) -> SpendingPublicKey {
        self.public
    }
    async fn sign(&self, inputs: U256) -> Result<SpendingSignature, RailgunSignerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.signatures
            .iter()
            .find(|s| decimal(&s.message) == inputs)
            .map(Signature::signature)
            .ok_or_else(|| RailgunSignerError::new(io::Error::other("Fixture signer declined")))
    }
}

#[tokio::test]
async fn external_signer_uses_reference_signatures_without_a_spending_key() {
    for account in vectors().accounts {
        let expected_address = &account.addresses[0].address;
        let signer = Arc::new(ExternalSigner {
            public: SpendingPublicKey::new(
                decimal(&account.spending_public_key[0]).to_be_bytes(),
                decimal(&account.spending_public_key[1]).to_be_bytes(),
            ),
            viewing: ViewingKey::from_hex(&account.viewing_key).unwrap(),
            signatures: account.signatures,
            calls: AtomicUsize::new(0),
        });
        let port: Arc<dyn RailgunSigner> = signer.clone();
        assert_eq!(port.address().to_string(), *expected_address);
        for signature in &signer.signatures {
            let message = decimal(&signature.message);
            assert!(
                port.spending_public_key()
                    .verify(message, &port.sign(message).await.unwrap())
            );
        }
        assert!(port.sign(U256::from(1_234_567)).await.is_err());
        assert_eq!(
            signer.calls.load(Ordering::SeqCst),
            signer.signatures.len() + 1
        );
    }
}

#[test]
fn engine_txids_match_padding_order_and_bound_parameters() {
    for operation in vectors().operations {
        let nullifiers: Vec<_> = operation.nullifiers.iter().map(|s| decimal(s)).collect();
        let commitments: Vec<_> = operation.commitments.iter().map(|s| decimal(s)).collect();
        let bound = decimal(&operation.bound_params_hash);
        let actual = Txid::new(&nullifiers, &commitments, bound);
        assert_eq!(
            serde_json::to_value(actual).unwrap(),
            operation.txid,
            "{}",
            operation.name
        );
        assert_ne!(
            actual,
            Txid::new(&nullifiers, &commitments, bound + U256::from(1))
        );
        if nullifiers.len() > 1 {
            let mut reordered = nullifiers.clone();
            reordered.swap(0, 1);
            assert_ne!(actual, Txid::new(&reordered, &commitments, bound));
        }
        if commitments.len() > 1 {
            let mut reordered = commitments;
            reordered.swap(0, 1);
            assert_ne!(actual, Txid::new(&nullifiers, &reordered, bound));
        }
    }
}
