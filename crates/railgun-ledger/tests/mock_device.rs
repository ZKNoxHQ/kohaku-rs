//! End-to-end test of the signer over a mock device that implements the ZKNOX APDU
//! protocol in software. Proves the wire format round-trips: a `LedgerSigner` must be
//! indistinguishable from a `PrivateKeySigner` holding the same keys.

use async_trait::async_trait;
use ruint::aliases::U256;

use kohaku_railgun_ledger::{
    Apdu, ApduResponse, Exchange, LedgerSigner, TransportError,
    protocol::{
        CLA, INS_BLIND_SIGN, INS_GET_VERSION, INS_RAILGUN_ADDRESS, INS_SPENDING_PUBKEY,
        INS_VIEWING_PRIVKEY, INS_VIEWING_PUBKEY, P1_CURVE_BABYJUBJUB, P1_DISPLAY,
    },
};
use railgun::{
    account::{
        chain::ChainId,
        signer::{PrivateKeySigner, RailgunSigner},
    },
    crypto::keys::{HexKey, SpendingKey, ViewingKey},
};

const SPENDING_HEX: &str = "039b3b11110e49d7340cbe7171791972e3c0d94ef31b18d6ab93d7ace62d278a";
const VIEWING_HEX: &str = "d345b2cc2f414aa93413b9572fa2b26e0e869e9274b006415a8d62ab1fa2dcb1";
const ACCOUNT_INDEX: u32 = 0;

/// A software model of the device app: checks the APDU framing byte-for-byte and answers
/// with the same key material a real device would hold.
struct MockDevice {
    spending: SpendingKey,
    viewing: ViewingKey,
    deny_signing: bool,
    corrupt_viewing_export: bool,
    sign_with_wrong_key: bool,
}

impl MockDevice {
    fn new() -> Self {
        Self {
            spending: SpendingKey::from_hex(SPENDING_HEX).unwrap(),
            viewing: ViewingKey::from_hex(VIEWING_HEX).unwrap(),
            deny_signing: false,
            corrupt_viewing_export: false,
            sign_with_wrong_key: false,
        }
    }
}

#[async_trait]
impl Exchange for MockDevice {
    async fn exchange(&self, apdu: &Apdu) -> Result<ApduResponse, TransportError> {
        assert_eq!(apdu.cla, CLA);
        assert_eq!(apdu.p2, 0);

        let ok = |data: Vec<u8>| {
            Ok(ApduResponse {
                data,
                status: 0x9000,
            })
        };
        match apdu.ins {
            INS_GET_VERSION => {
                assert!(apdu.data.is_empty());
                ok(vec![0, 1, 0])
            }
            INS_SPENDING_PUBKEY => {
                // The silent form is debug-only in the app: the host must display.
                assert_eq!(apdu.p1, P1_DISPLAY);
                assert_eq!(apdu.data, ACCOUNT_INDEX.to_be_bytes());
                let pubkey = self.spending.public_key();
                let mut data = pubkey.x_u256().to_be_bytes::<32>().to_vec();
                data.extend_from_slice(&pubkey.y_u256().to_be_bytes::<32>());
                ok(data)
            }
            INS_VIEWING_PUBKEY => {
                // Production firmware requires display-and-confirm here too.
                assert_eq!(apdu.p1, P1_DISPLAY);
                assert_eq!(apdu.data, ACCOUNT_INDEX.to_be_bytes());
                ok(hex::decode(self.viewing.public_key().to_hex()).unwrap())
            }
            INS_VIEWING_PRIVKEY => {
                assert_eq!(apdu.p1, 0);
                assert_eq!(apdu.data, ACCOUNT_INDEX.to_be_bytes());
                let mut seed = hex::decode(self.viewing.to_hex()).unwrap();
                if self.corrupt_viewing_export {
                    seed[0] ^= 0xFF;
                }
                ok(seed)
            }
            INS_BLIND_SIGN => {
                assert_eq!(apdu.p1, P1_CURVE_BABYJUBJUB);
                if self.deny_signing {
                    return Ok(ApduResponse {
                        data: Vec::new(),
                        status: 0x6985,
                    });
                }
                assert_eq!(apdu.data.len(), 36);
                assert_eq!(&apdu.data[..4], ACCOUNT_INDEX.to_be_bytes());
                // The wire message is little-endian, as the real firmware consumes it.
                let hash = U256::from_le_slice(&apdu.data[4..]);
                let key = if self.sign_with_wrong_key {
                    SpendingKey::from_hex(&hex::encode([7u8; 32])).unwrap()
                } else {
                    self.spending
                };
                let signature = key.sign(hash);
                // Firmware layout: sigLen(1) || R8x || R8y || S || echoed msg_hash(32).
                let mut data = vec![96u8];
                data.extend_from_slice(&signature.r8_x.to_be_bytes::<32>());
                data.extend_from_slice(&signature.r8_y.to_be_bytes::<32>());
                data.extend_from_slice(&signature.s.to_be_bytes::<32>());
                data.extend_from_slice(&apdu.data[4..]);
                ok(data)
            }
            INS_RAILGUN_ADDRESS => {
                assert_eq!(apdu.p1, P1_DISPLAY);
                assert_eq!(apdu.data, ACCOUNT_INDEX.to_be_bytes());
                let address = PrivateKeySigner::new(self.spending, self.viewing, ChainId::All)
                    .address()
                    .to_string();
                assert_eq!(address.len(), 127);
                ok(address.into_bytes())
            }
            ins => panic!("unexpected instruction {ins:#04x}"),
        }
    }
}

fn software_signer() -> std::sync::Arc<PrivateKeySigner> {
    PrivateKeySigner::new(
        SpendingKey::from_hex(SPENDING_HEX).unwrap(),
        ViewingKey::from_hex(VIEWING_HEX).unwrap(),
        ChainId::All,
    )
}

#[tokio::test]
async fn ledger_signer_matches_software_signer() {
    let ledger = LedgerSigner::connect(MockDevice::new(), ChainId::All, ACCOUNT_INDEX)
        .await
        .unwrap();
    let software = software_signer();

    // Same address, hence same master and viewing public keys.
    assert_eq!(ledger.address(), software.address());

    // The device's displayed 0zk string matches the host derivation.
    let shown = ledger.verify_address_on_device().await.unwrap();
    assert_eq!(shown, software.address().to_string());

    // Deterministic EdDSA: the signature through the APDU layer is bit-identical.
    let message = U256::from(42u64);
    let from_device = ledger.sign(message).await.unwrap();
    let from_software = software.sign(message).await.unwrap();
    assert_eq!(from_device.r8_x, from_software.r8_x);
    assert_eq!(from_device.r8_y, from_software.r8_y);
    assert_eq!(from_device.s, from_software.s);
}

#[tokio::test]
async fn user_denial_is_an_error_not_a_panic() {
    let mut device = MockDevice::new();
    device.deny_signing = true;
    let ledger = LedgerSigner::connect(device, ChainId::All, ACCOUNT_INDEX)
        .await
        .unwrap();

    let err = ledger.sign(U256::from(1u64)).await.unwrap_err();
    assert!(err.to_string().contains("denied by user"), "got: {err}");
}

#[tokio::test]
async fn wrong_key_signature_is_rejected() {
    let mut device = MockDevice::new();
    device.sign_with_wrong_key = true;
    let ledger = LedgerSigner::connect(device, ChainId::All, ACCOUNT_INDEX)
        .await
        .unwrap();

    let err = ledger.sign(U256::from(1u64)).await.unwrap_err();
    assert!(err.to_string().contains("does not verify"), "got: {err}");
}

#[tokio::test]
async fn corrupted_viewing_export_is_rejected_at_connect() {
    let mut device = MockDevice::new();
    device.corrupt_viewing_export = true;

    let Err(err) = LedgerSigner::connect(device, ChainId::All, ACCOUNT_INDEX).await else {
        panic!("corrupted seed export must not connect");
    };
    assert!(err.to_string().contains("does not match"), "got: {err}");
}
