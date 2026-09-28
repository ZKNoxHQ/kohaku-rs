//! Hardware smoke test against a real Ledger running the ZKNOX Railgun app.
//!
//! Run with the device plugged in, unlocked, app open:
//!
//! ```sh
//! cargo run -p railgun-ledger --features usb --example smoke
//! ```
//!
//! Device approvals, in order: spending pubkey, viewing key export, viewing pubkey
//! (connect), the 0zk address (verification), one blind-sign. Five in total.

use ark_ff::PrimeField;
use num_bigint::{BigInt, Sign};
use ruint::aliases::U256;

use kohaku_railgun_ledger::{LedgerSigner, protocol, transport::usb::UsbLedger};
use railgun::account::{chain::ChainId, signer::RailgunSigner};

const ACCOUNT: u32 = 0;

fn big(u: U256) -> BigInt {
    BigInt::from_bytes_be(Sign::Plus, &u.to_be_bytes::<32>())
}

fn fr(u: U256) -> ark_bn254::Fr {
    ark_bn254::Fr::from_be_bytes_mod_order(&u.to_be_bytes::<32>())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("connecting over USB HID…");
    let device = UsbLedger::init().await?;

    let name = protocol::get_app_name(&device).await?;
    let (major, minor, patch) = protocol::get_version(&device).await?;
    println!("app: {name} v{major}.{minor}.{patch}");

    println!("\n[1/3] connect: approve spending pubkey, viewing key export, viewing pubkey…");
    let signer = LedgerSigner::connect(device, ChainId::All, ACCOUNT).await?;
    println!("      connected; viewing-seed cross-check passed");
    println!("      host-derived address: {}", signer.address());

    println!("\n[2/3] address verification: approve the 0zk address on the device…");
    let shown = signer.verify_address_on_device().await?;
    println!("      device shows the same address: {shown}");

    println!("\n[3/3] blind-sign of test hash 42: approve on the device…");
    let message = U256::from(42u64);
    let signature = signer.sign(message).await?;
    println!("      r8_x = {:#066x}", signature.r8_x);
    println!("      r8_y = {:#066x}", signature.r8_y);
    println!("      s    = {:#066x}", signature.s);

    // Verify the circomlib EdDSA-Poseidon equation host-side:
    //   s·B8 == R8 + (8·hm)·A,  hm = poseidon(R8.x, R8.y, A.x, A.y, msg)
    let pubkey = signer.spending_public_key();
    let (ax, ay) = (pubkey.x_u256(), pubkey.y_u256());
    let hm = crypto::poseidon_hash(&[signature.r8_x, signature.r8_y, ax, ay, message])?;

    let a = crypto::babyjubjub::Point {
        x: fr(ax),
        y: fr(ay),
    };
    let r8 = crypto::babyjubjub::Point {
        x: fr(signature.r8_x),
        y: fr(signature.r8_y),
    };

    let left = crypto::babyjubjub::b8().mul_scalar(&big(signature.s));
    let right = r8
        .projective()
        .add(&a.mul_scalar(&(big(hm) * 8)).projective())
        .affine();

    if left.x == right.x && left.y == right.y {
        println!("      signature VERIFIES against the device's spending pubkey");
        println!("\nall checks passed — the device is a working Railgun signer");
        Ok(())
    } else {
        Err("signature does NOT verify: s·B8 != R8 + 8·hm·A".into())
    }
}
