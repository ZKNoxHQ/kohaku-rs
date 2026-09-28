//! Hardware signing for Railgun with a Ledger device running the ZKNOX BabyJubJub app.
//!
//! The spending private key never leaves the device: the host fetches the spending *public*
//! key once at connection, and every spending signature is an APDU round-trip plus a user
//! confirmation. The viewing key is exported to the host at connection — note scanning is an
//! ECDH per encrypted note, which cannot round-trip through a device; this is the usual split
//! for privacy protocols (hardware protects spending, view keys are exportable).
//!
//! Layering, bottom to top:
//!
//! - [`transport::Exchange`] — one method, `exchange(apdu) -> response`. Everything above is
//!   transport-agnostic; everything below is swappable (USB today, BLE or WebHID later).
//! - [`transport::usb`] (feature `usb`, native only) — [`Exchange`] over USB HID via
//!   `coins-ledger`, the transport maintained by the alloy ecosystem.
//! - [`protocol`] — the APDU protocol of the ZKNOX app: instruction bytes, BIP-32 path
//!   framing, response layouts, status words. The single source of truth the device app
//!   must match.
//! - [`signer::LedgerSigner`] — implements `railgun`'s `RailgunSigner` on top of the above.

pub mod protocol;
pub mod signer;
pub mod transport;

pub use signer::{LedgerError, LedgerSigner};
pub use transport::{Apdu, ApduResponse, Exchange, TransportError};

#[cfg(all(native, feature = "ble"))]
pub use transport::ble::BleLedger;

#[cfg(all(wasm, feature = "webusb"))]
pub use transport::webusb::WebUsbLedger;

#[cfg(all(wasm, feature = "webble"))]
pub use transport::webble::WebBleLedger;
