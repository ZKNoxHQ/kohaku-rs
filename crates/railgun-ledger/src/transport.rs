//! Transport abstraction: anything that can exchange APDUs with a Ledger device.

use common::MaybeSend;
use thiserror::Error;

/// A raw APDU command, transport-agnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Apdu {
    pub cla: u8,
    pub ins: u8,
    pub p1: u8,
    pub p2: u8,
    pub data: Vec<u8>,
}

/// A raw APDU response: payload plus the trailing status word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApduResponse {
    pub data: Vec<u8>,
    pub status: u16,
}

#[derive(Debug, Error)]
#[error("Ledger transport error: {0}")]
pub struct TransportError(pub String);

/// A duplex channel to a Ledger device.
///
/// The only integration point a transport has to provide. Implementations exist for USB HID
/// (feature `usb`); BLE or browser WebHID transports slot in here without touching the
/// protocol or signer layers.
#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
pub trait Exchange: MaybeSend {
    async fn exchange(&self, apdu: &Apdu) -> Result<ApduResponse, TransportError>;

    /// Re-establish the channel after it went stale. A Ledger re-enumerates on USB whenever
    /// an app is opened or closed (and on lock), which invalidates any open handle; callers
    /// retry a failed exchange once after a successful reconnect.
    async fn reconnect(&self) -> Result<(), TransportError> {
        Err(TransportError(
            "transport does not support reconnection".into(),
        ))
    }
}

/// USB HID transport over `coins-ledger`.
#[cfg(all(native, feature = "usb"))]
pub mod usb {
    use coins_ledger::{
        common::{APDUCommand, APDUData},
        transports::{Ledger, LedgerAsync},
    };

    use super::{Apdu, ApduResponse, Exchange, TransportError};

    /// A USB-connected Ledger. [`UsbLedger::init`] picks the first device found.
    ///
    /// The handle sits behind a mutex so [`Exchange::reconnect`] can replace it in place:
    /// a Ledger re-enumerates on USB whenever an app opens or closes, killing old handles.
    pub struct UsbLedger(tokio::sync::Mutex<Ledger>);

    impl UsbLedger {
        pub async fn init() -> Result<Self, TransportError> {
            let ledger = Ledger::init()
                .await
                .map_err(|e| TransportError(e.to_string()))?;
            Ok(Self(tokio::sync::Mutex::new(ledger)))
        }
    }

    #[async_trait::async_trait]
    impl Exchange for UsbLedger {
        async fn exchange(&self, apdu: &Apdu) -> Result<ApduResponse, TransportError> {
            let command = APDUCommand {
                cla: apdu.cla,
                ins: apdu.ins,
                p1: apdu.p1,
                p2: apdu.p2,
                data: APDUData::new(&apdu.data),
                response_len: None,
            };
            let answer = self
                .0
                .lock()
                .await
                .exchange(&command)
                .await
                .map_err(|e| TransportError(e.to_string()))?;
            Ok(ApduResponse {
                status: answer.retcode(),
                data: answer.data().unwrap_or_default().to_vec(),
            })
        }

        async fn reconnect(&self) -> Result<(), TransportError> {
            let fresh = Ledger::init()
                .await
                .map_err(|e| TransportError(e.to_string()))?;
            *self.0.lock().await = fresh;
            Ok(())
        }
    }
}

/// Bluetooth LE transport over `btleplug`, for Flex / Stax / Nano X.
///
/// Implements Ledger's APDU-over-BLE framing (the same protocol as the JS
/// `@ledgerhq/devices` BLE transport): a 5-byte MTU handshake, then APDUs
/// chunked into `0x05`-tagged frames across a GATT write characteristic, with
/// the response reassembled from notify-characteristic frames.
#[cfg(all(native, feature = "ble"))]
pub mod ble {
    use std::pin::Pin;
    use std::time::Duration;

    use btleplug::api::{
        Central, CharPropFlags, Characteristic, Manager as _, Peripheral as _, ScanFilter,
        ValueNotification, WriteType,
    };
    use btleplug::platform::{Adapter, Manager, Peripheral};
    use futures::{FutureExt, Stream, StreamExt};
    use tokio::sync::Mutex;
    use tokio::time::{sleep, timeout};
    use uuid::Uuid;

    use super::{Apdu, ApduResponse, Exchange, TransportError};

    const TAG_APDU: u8 = 0x05;
    const TAG_MTU: u8 = 0x08;
    const DEFAULT_MTU: usize = 23;

    /// Ledger BLE GATT service UUIDs. Flex/Stax/Nano X share the same framing;
    /// only the third group's high nibble differs per model.
    fn ledger_services() -> [Uuid; 3] {
        [
            Uuid::from_u128(0x13d63400_2c97_3004_0000_4c6564676572), // Flex
            Uuid::from_u128(0x13d63400_2c97_6004_0000_4c6564676572), // Stax
            Uuid::from_u128(0x13d63400_2c97_0004_0000_4c6564676572), // Nano X
        ]
    }

    fn err(e: impl std::fmt::Display) -> TransportError {
        TransportError(e.to_string())
    }

    type NotifyStream = Pin<Box<dyn Stream<Item = ValueNotification> + Send>>;

    /// A Bluetooth-connected Ledger. [`BleLedger::connect`] scans, connects and
    /// negotiates the MTU. One APDU exchange holds the notification stream for
    /// the duration of the request/response so frames are not interleaved.
    pub struct BleLedger {
        peripheral: Peripheral,
        write_char: Characteristic,
        write_type: WriteType,
        notify_uuid: Uuid,
        mtu: usize,
        notifications: Mutex<NotifyStream>,
    }

    impl BleLedger {
        /// Scan for a Ledger (Flex/Stax/Nano X), connect, and negotiate MTU.
        pub async fn connect() -> Result<Self, TransportError> {
            Self::connect_timeout(Duration::from_secs(20)).await
        }

        pub async fn connect_timeout(scan_timeout: Duration) -> Result<Self, TransportError> {
            let manager = Manager::new().await.map_err(err)?;
            let adapter = manager
                .adapters()
                .await
                .map_err(err)?
                .into_iter()
                .next()
                .ok_or_else(|| TransportError("no Bluetooth adapter found".into()))?;

            let services = ledger_services().to_vec();
            adapter
                .start_scan(ScanFilter {
                    services: services.clone(),
                })
                .await
                .map_err(err)?;

            let peripheral = timeout(scan_timeout, find_ledger(&adapter, &services))
                .await
                .map_err(|_| {
                    TransportError(
                        "no Ledger found over BLE (device unlocked, Bluetooth on, app open?)"
                            .into(),
                    )
                })??;
            let _ = adapter.stop_scan().await;

            peripheral.connect().await.map_err(err)?;
            peripheral.discover_services().await.map_err(err)?;

            let chars = peripheral.characteristics();
            let notify = chars
                .iter()
                .find(|c| {
                    services.contains(&c.service_uuid)
                        && c.properties.contains(CharPropFlags::NOTIFY)
                })
                .cloned()
                .ok_or_else(|| {
                    TransportError("Ledger BLE notify characteristic not found".into())
                })?;
            let write_char = chars
                .iter()
                .find(|c| {
                    services.contains(&c.service_uuid)
                        && c.properties.contains(CharPropFlags::WRITE)
                })
                .cloned()
                .ok_or_else(|| {
                    TransportError("Ledger BLE write characteristic not found".into())
                })?;

            peripheral.subscribe(&notify).await.map_err(err)?;
            let notifications = peripheral.notifications().await.map_err(err)?;

            let mut me = Self {
                peripheral,
                write_char,
                write_type: WriteType::WithResponse,
                notify_uuid: notify.uuid,
                mtu: DEFAULT_MTU,
                notifications: Mutex::new(notifications),
            };
            me.negotiate_mtu().await?;
            Ok(me)
        }

        /// Ledger MTU handshake: write `[0x08,0,0,0,0]`, read the `0x08` reply
        /// whose byte 5 is the frame MTU. Skips any stray frame before it so
        /// the reply is never left in the buffer for the first APDU to trip on.
        async fn negotiate_mtu(&mut self) -> Result<(), TransportError> {
            let mut stream = self.notifications.lock().await;
            self.peripheral
                .write(&self.write_char, &[TAG_MTU, 0, 0, 0, 0], self.write_type)
                .await
                .map_err(err)?;
            for _ in 0..8 {
                let frame = next_frame(&mut stream, self.notify_uuid).await?;
                if frame.first() == Some(&TAG_MTU) {
                    if frame.len() >= 6 {
                        self.mtu = (frame[5] as usize).max(DEFAULT_MTU);
                    }
                    return Ok(());
                }
                // Not the MTU reply (a spurious/keepalive frame): keep looking.
            }
            // No 0x08 reply seen; keep the conservative default MTU.
            Ok(())
        }

        async fn write_apdu(&self, raw: &[u8]) -> Result<(), TransportError> {
            let mut seq: u16 = 0;
            let mut offset = 0;
            while offset < raw.len() {
                let header_len = if seq == 0 { 5 } else { 3 };
                let chunk_len = self.mtu.saturating_sub(header_len).min(raw.len() - offset);
                if chunk_len == 0 {
                    return Err(TransportError("BLE MTU too small to frame APDU".into()));
                }
                let mut frame = Vec::with_capacity(header_len + chunk_len);
                frame.push(TAG_APDU);
                frame.extend_from_slice(&seq.to_be_bytes());
                if seq == 0 {
                    frame.extend_from_slice(&(raw.len() as u16).to_be_bytes());
                }
                frame.extend_from_slice(&raw[offset..offset + chunk_len]);
                self.peripheral
                    .write(&self.write_char, &frame, self.write_type)
                    .await
                    .map_err(err)?;
                offset += chunk_len;
                seq += 1;
            }
            Ok(())
        }

        async fn read_apdu(&self, stream: &mut NotifyStream) -> Result<Vec<u8>, TransportError> {
            // First (header) frame: seq 0, tag 0x05, 2-byte total length. Tolerate
            // a bounded number of stray leading frames (e.g. a late 0x08 MTU reply
            // or a keepalive) before it rather than failing outright.
            let mut header = None;
            let mut skipped: Vec<String> = Vec::new();
            for _ in 0..8 {
                let frame = next_frame(stream, self.notify_uuid).await?;
                if frame.first() == Some(&TAG_APDU) {
                    header = Some(frame);
                    break;
                }
                skipped.push(hex::encode(&frame));
            }
            let header = header.ok_or_else(|| {
                TransportError(format!(
                    "no BLE APDU frame received; got only: [{}]",
                    skipped.join(", ")
                ))
            })?;
            if header.len() < 5 {
                return Err(TransportError(format!(
                    "short BLE header frame: {}",
                    hex::encode(&header)
                )));
            }
            if u16::from_be_bytes([header[1], header[2]]) != 0 {
                return Err(TransportError("first BLE frame is not sequence 0".into()));
            }
            let total = u16::from_be_bytes([header[3], header[4]]) as usize;
            let mut data: Vec<u8> = header[5..].to_vec();

            // Continuation frames: strict tag/sequence checking.
            let mut expected_seq: u16 = 1;
            while data.len() < total {
                let frame = next_frame(stream, self.notify_uuid).await?;
                if frame.first() != Some(&TAG_APDU) || frame.len() < 3 {
                    return Err(TransportError(format!(
                        "malformed BLE continuation frame: {}",
                        hex::encode(&frame)
                    )));
                }
                let seq = u16::from_be_bytes([frame[1], frame[2]]);
                if seq != expected_seq {
                    return Err(TransportError(format!(
                        "BLE frame out of sequence: expected {expected_seq}, got {seq}"
                    )));
                }
                data.extend_from_slice(&frame[3..]);
                expected_seq = expected_seq.wrapping_add(1);
            }
            data.truncate(total);
            Ok(data)
        }
    }

    /// Poll the adapter until a peripheral advertising a Ledger service appears.
    async fn find_ledger(
        adapter: &Adapter,
        services: &[Uuid],
    ) -> Result<Peripheral, TransportError> {
        loop {
            for p in adapter.peripherals().await.map_err(err)? {
                if let Ok(Some(props)) = p.properties().await {
                    if props.services.iter().any(|s| services.contains(s)) {
                        return Ok(p);
                    }
                }
            }
            sleep(Duration::from_millis(300)).await;
        }
    }

    /// Next notification value on the notify characteristic, skipping others.
    async fn next_frame(
        stream: &mut NotifyStream,
        notify_uuid: Uuid,
    ) -> Result<Vec<u8>, TransportError> {
        loop {
            let n = stream
                .next()
                .await
                .ok_or_else(|| TransportError("BLE notification stream ended".into()))?;
            // Ignore notifications on other characteristics and spurious empty
            // frames some BLE stacks deliver on subscribe.
            if n.uuid == notify_uuid && !n.value.is_empty() {
                return Ok(n.value);
            }
        }
    }

    #[async_trait::async_trait]
    impl Exchange for BleLedger {
        async fn exchange(&self, apdu: &Apdu) -> Result<ApduResponse, TransportError> {
            // Raw APDU: CLA INS P1 P2 Lc data (1-byte Lc, as Ledger uses).
            let mut raw = Vec::with_capacity(5 + apdu.data.len());
            raw.extend_from_slice(&[apdu.cla, apdu.ins, apdu.p1, apdu.p2, apdu.data.len() as u8]);
            raw.extend_from_slice(&apdu.data);

            // Hold the notification stream for the whole request/response so a
            // concurrent exchange cannot steal our response frames.
            let mut stream = self.notifications.lock().await;

            // Drain frames buffered before this request: MTU keepalives the
            // device emits between exchanges, and duplicate response frames the
            // bluez stack can re-deliver on a re-paired link. Such an echo can
            // arrive a beat *after* the previous response, so settle briefly
            // first, then drain. This is safe: any frame present before we write
            // the current command is by definition stale — the real response
            // only arrives after the write below.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            while stream.next().now_or_never().flatten().is_some() {}

            self.write_apdu(&raw).await?;
            let resp = self.read_apdu(&mut stream).await?;
            if resp.len() < 2 {
                return Err(TransportError(
                    "BLE response shorter than status word".into(),
                ));
            }
            let split = resp.len() - 2;
            let status = u16::from_be_bytes([resp[split], resp[split + 1]]);
            Ok(ApduResponse {
                data: resp[..split].to_vec(),
                status,
            })
        }
    }
}

/// Ledger USB (HID-style) APDU framing, shared by any USB-based transport.
///
/// Pure — no platform APIs — so it is unit-tested off-device. The wire format:
/// the data stream is `len(2 BE) || apdu`, split into `PACKET_SIZE - 5`-byte
/// chunks; each 64-byte packet is `channel(2 BE) || 0x05 || seq(2 BE) || chunk`,
/// the last zero-padded.
#[cfg(any(feature = "webusb", test))]
mod usb_framing {
    pub const PACKET_SIZE: usize = 64;
    const TAG: u8 = 0x05;
    const HEADER: usize = 5; // channel(2) + tag(1) + seq(2)

    /// Split a raw APDU into 64-byte USB packets.
    pub fn pack(channel: u16, apdu: &[u8]) -> Vec<[u8; PACKET_SIZE]> {
        let mut data = Vec::with_capacity(2 + apdu.len());
        data.extend_from_slice(&(apdu.len() as u16).to_be_bytes());
        data.extend_from_slice(apdu);

        let chunk = PACKET_SIZE - HEADER;
        let mut packets = Vec::new();
        let mut seq: u16 = 0;
        let mut off = 0;
        loop {
            let mut pkt = [0u8; PACKET_SIZE];
            pkt[0..2].copy_from_slice(&channel.to_be_bytes());
            pkt[2] = TAG;
            pkt[3..5].copy_from_slice(&seq.to_be_bytes());
            let n = chunk.min(data.len() - off);
            pkt[HEADER..HEADER + n].copy_from_slice(&data[off..off + n]);
            packets.push(pkt);
            off += n;
            seq = seq.wrapping_add(1);
            if off >= data.len() {
                break;
            }
        }
        packets
    }

    /// Reassembles response packets into the APDU (payload + status word).
    pub struct Reassembler {
        channel: u16,
        expected_seq: u16,
        total: Option<usize>,
        data: Vec<u8>,
    }

    impl Reassembler {
        pub fn new(channel: u16) -> Self {
            Self {
                channel,
                expected_seq: 0,
                total: None,
                data: Vec::new(),
            }
        }

        /// Feed one packet; returns `Some(apdu)` once the full response is in.
        pub fn feed(&mut self, pkt: &[u8]) -> Result<Option<Vec<u8>>, String> {
            if pkt.len() < HEADER {
                return Err(format!("short USB packet ({} bytes)", pkt.len()));
            }
            let channel = u16::from_be_bytes([pkt[0], pkt[1]]);
            if channel != self.channel {
                return Err(format!("wrong USB channel {channel:#06x}"));
            }
            if pkt[2] != TAG {
                return Err(format!("wrong USB tag {:#04x}", pkt[2]));
            }
            let seq = u16::from_be_bytes([pkt[3], pkt[4]]);
            if seq != self.expected_seq {
                return Err(format!(
                    "out-of-sequence USB packet: expected {}, got {seq}",
                    self.expected_seq
                ));
            }
            let mut body = &pkt[HEADER..];
            if self.total.is_none() {
                if body.len() < 2 {
                    return Err("first USB packet too short for length".into());
                }
                self.total = Some(u16::from_be_bytes([body[0], body[1]]) as usize);
                body = &body[2..];
            }
            let total = self.total.unwrap_or(0);
            let take = (total - self.data.len()).min(body.len());
            self.data.extend_from_slice(&body[..take]);
            self.expected_seq = self.expected_seq.wrapping_add(1);
            if self.data.len() >= total {
                Ok(Some(std::mem::take(&mut self.data)))
            } else {
                Ok(None)
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn roundtrip(apdu: &[u8]) {
            let channel = 0x0101;
            let packets = pack(channel, apdu);
            assert!(packets.iter().all(|p| p.len() == PACKET_SIZE));
            let mut re = Reassembler::new(channel);
            let mut out = None;
            for p in &packets {
                if let Some(r) = re.feed(p).unwrap() {
                    out = Some(r);
                }
            }
            assert_eq!(out.as_deref(), Some(apdu));
        }

        #[test]
        fn framing_roundtrip() {
            roundtrip(&[0xE0, 0x04, 0, 0, 0]); // short: get app name
            roundtrip(&[0xE0, 0x12, 0, 0, 0x24]); // blind-sign header
            roundtrip(&(0..200u32).map(|i| i as u8).collect::<Vec<u8>>()); // multi-packet
            roundtrip(&[7u8; 59 - 2]); // exactly fills packet 0 (59 - 2-byte len prefix)
            roundtrip(&[9u8; 59 - 2 + 1]); // spills into packet 1
        }

        #[test]
        fn rejects_wrong_channel() {
            let mut re = Reassembler::new(0x0101);
            let bad = pack(0x0202, &[1, 2, 3]);
            assert!(re.feed(&bad[0]).is_err());
        }
    }
}

/// Browser WebUSB transport (wasm32), for Chrome/Chromium on desktop or Android.
///
/// Pure Rust over `web-sys`: only the auto-generated `wasm-bindgen` shim touches
/// `navigator.usb`; the Ledger USB framing and APDU protocol are the same Rust as
/// the native transports. Requires `--cfg web_sys_unstable_apis` (set for the
/// wasm target in `.cargo/config.toml`).
#[cfg(all(wasm, feature = "webusb"))]
pub mod webusb {
    use js_sys::{Array, Object, Reflect, Uint8Array};
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{
        UsbConfiguration, UsbDevice, UsbDeviceRequestOptions, UsbDirection, UsbInTransferResult,
        UsbInterface,
    };

    use super::usb_framing::{self, PACKET_SIZE};
    use super::{Apdu, ApduResponse, Exchange, TransportError};

    const LEDGER_VENDOR_ID: u32 = 0x2c97;
    const CHANNEL: u16 = 0x0101;

    fn err(context: &str, e: impl std::fmt::Debug) -> TransportError {
        TransportError(format!("{context}: {e:?}"))
    }

    /// A WebUSB-connected Ledger. [`WebUsbLedger::connect`] shows the browser's
    /// device picker (filtered to Ledger), opens the device and claims the pipe.
    pub struct WebUsbLedger {
        device: UsbDevice,
        endpoint_in: u8,
        endpoint_out: u8,
    }

    /// `navigator.usb`, from the page or from a dedicated worker (Chromium exposes WebUSB in
    /// workers; only the permission picker `requestDevice` is main-thread-only).
    fn usb_handle() -> Result<web_sys::Usb, TransportError> {
        if let Some(win) = web_sys::window() {
            return Ok(win.navigator().usb());
        }
        let scope: web_sys::WorkerGlobalScope = js_sys::global()
            .dyn_into()
            .map_err(|_| TransportError("no browser window and not a worker scope".into()))?;
        Ok(scope.navigator().usb())
    }

    impl WebUsbLedger {
        pub async fn connect() -> Result<Self, TransportError> {
            let usb = usb_handle()?;

            // Build { filters: [{ vendorId: 0x2c97 }] } without depending on the
            // web-sys dictionary setter API (which shifts between versions).
            let filter = Object::new();
            Reflect::set(
                &filter,
                &"vendorId".into(),
                &JsValue::from(LEDGER_VENDOR_ID),
            )
            .map_err(|e| err("build filter", e))?;
            let opts = Object::new();
            Reflect::set(&opts, &"filters".into(), &Array::of1(&filter))
                .map_err(|e| err("build options", e))?;
            let opts: UsbDeviceRequestOptions = opts.unchecked_into();

            let device: UsbDevice = JsFuture::from(usb.request_device(&opts))
                .await
                .map_err(|e| err("requestDevice (cancelled or no device?)", e))?
                .unchecked_into();

            Self::open_device(device).await
        }

        /// Opens a Ledger this origin is already authorized for, without the picker — the page
        /// must have called `navigator.usb.requestDevice()` before (main thread, user gesture).
        /// This is the worker-side entry: `getDevices()` works in a dedicated worker, where
        /// `requestDevice()` does not exist.
        pub async fn connect_existing() -> Result<Self, TransportError> {
            let usb = usb_handle()?;
            let devices: Array = JsFuture::from(usb.get_devices())
                .await
                .map_err(|e| err("getDevices", e))?
                .unchecked_into();
            let device = devices
                .iter()
                .map(|d| d.unchecked_into::<UsbDevice>())
                .find(|d| u32::from(d.vendor_id()) == LEDGER_VENDOR_ID)
                .ok_or_else(|| {
                    TransportError(
                        "no authorized Ledger: grant USB access from the page first".into(),
                    )
                })?;
            Self::open_device(device).await
        }

        async fn open_device(device: UsbDevice) -> Result<Self, TransportError> {
            JsFuture::from(device.open())
                .await
                .map_err(|e| err("open", e))?;
            if device.configuration().is_none() {
                JsFuture::from(device.select_configuration(1))
                    .await
                    .map_err(|e| err("selectConfiguration", e))?;
            }
            let config = device
                .configuration()
                .ok_or_else(|| TransportError("device has no USB configuration".into()))?;

            let (interface_number, endpoint_in, endpoint_out) = find_pipe(&config)
                .ok_or_else(|| TransportError("no Ledger APDU interface on device".into()))?;

            JsFuture::from(device.claim_interface(interface_number))
                .await
                .map_err(|e| err("claimInterface", e))?;

            Ok(Self {
                device,
                endpoint_in,
                endpoint_out,
            })
        }
    }

    /// The Ledger APDU pipe: the first interface exposing both an IN and OUT
    /// endpoint. Returns (interface_number, endpoint_in, endpoint_out).
    fn find_pipe(config: &UsbConfiguration) -> Option<(u8, u8, u8)> {
        let interfaces = config.interfaces();
        for i in 0..interfaces.length() {
            let iface: UsbInterface = interfaces.get(i).dyn_into().ok()?;
            let alt = iface.alternate();
            // Ledger exposes both a HID interface (class 0x03) and a
            // vendor-specific WebUSB interface (class 0xFF). Browsers refuse to
            // claim protected classes like HID, so only the 0xFF one works.
            if alt.interface_class() != 0xFF {
                continue;
            }
            let endpoints = alt.endpoints();
            let mut ep_in = None;
            let mut ep_out = None;
            for j in 0..endpoints.length() {
                let ep: web_sys::UsbEndpoint = endpoints.get(j).dyn_into().ok()?;
                match ep.direction() {
                    UsbDirection::In => ep_in = Some(ep.endpoint_number()),
                    UsbDirection::Out => ep_out = Some(ep.endpoint_number()),
                    _ => {}
                }
            }
            if let (Some(ep_in), Some(ep_out)) = (ep_in, ep_out) {
                return Some((iface.interface_number(), ep_in, ep_out));
            }
        }
        None
    }

    #[async_trait::async_trait(?Send)]
    impl Exchange for WebUsbLedger {
        async fn exchange(&self, apdu: &Apdu) -> Result<ApduResponse, TransportError> {
            let mut raw = Vec::with_capacity(5 + apdu.data.len());
            raw.extend_from_slice(&[apdu.cla, apdu.ins, apdu.p1, apdu.p2, apdu.data.len() as u8]);
            raw.extend_from_slice(&apdu.data);

            for pkt in usb_framing::pack(CHANNEL, &raw) {
                let mut buf = pkt;
                let promise = self
                    .device
                    .transfer_out_with_u8_slice(self.endpoint_out, &mut buf[..])
                    .map_err(|e| err("transferOut call", e))?;
                JsFuture::from(promise)
                    .await
                    .map_err(|e| err("transferOut", e))?;
            }

            let mut re = usb_framing::Reassembler::new(CHANNEL);
            let response = loop {
                let result: UsbInTransferResult = JsFuture::from(
                    self.device
                        .transfer_in(self.endpoint_in, PACKET_SIZE as u32),
                )
                .await
                .map_err(|e| err("transferIn", e))?
                .unchecked_into();
                let view = result
                    .data()
                    .ok_or_else(|| TransportError("empty USB IN transfer".into()))?;
                let bytes = Uint8Array::new_with_byte_offset_and_length(
                    &view.buffer(),
                    view.byte_offset() as u32,
                    view.byte_length() as u32,
                )
                .to_vec();
                if let Some(r) = re.feed(&bytes).map_err(TransportError)? {
                    break r;
                }
            };

            if response.len() < 2 {
                return Err(TransportError(
                    "USB response shorter than status word".into(),
                ));
            }
            let split = response.len() - 2;
            let status = u16::from_be_bytes([response[split], response[split + 1]]);
            Ok(ApduResponse {
                data: response[..split].to_vec(),
                status,
            })
        }
    }
}

/// Ledger BLE APDU framing, shared by the native (btleplug) and browser
/// (Web Bluetooth) transports. Pure — no platform APIs — so it is unit-tested
/// off-device. Same protocol as the JS `@ledgerhq/devices` BLE transport.
#[cfg(any(feature = "webble", test))]
pub mod ble_framing {
    pub const TAG_APDU: u8 = 0x05;
    pub const TAG_MTU: u8 = 0x08;
    pub const DEFAULT_MTU: usize = 23;

    /// The 5-byte MTU-negotiation request.
    pub fn mtu_request() -> [u8; 5] {
        [TAG_MTU, 0, 0, 0, 0]
    }

    /// MTU from a `0x08` reply frame (byte 5), clamped to at least the default.
    pub fn parse_mtu(frame: &[u8]) -> Option<usize> {
        if frame.first() == Some(&TAG_MTU) && frame.len() >= 6 {
            Some((frame[5] as usize).max(DEFAULT_MTU))
        } else {
            None
        }
    }

    /// Split a raw APDU into `0x05` frames: frame 0 is
    /// `0x05 || seq(2 BE) || len(2 BE) || data(mtu-5)`, later frames are
    /// `0x05 || seq(2 BE) || data(mtu-3)`.
    pub fn frames(mtu: usize, apdu: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut seq: u16 = 0;
        let mut off = 0;
        while off < apdu.len() {
            let header = if seq == 0 { 5 } else { 3 };
            let chunk = mtu.saturating_sub(header).min(apdu.len() - off);
            let mut f = Vec::with_capacity(header + chunk);
            f.push(TAG_APDU);
            f.extend_from_slice(&seq.to_be_bytes());
            if seq == 0 {
                f.extend_from_slice(&(apdu.len() as u16).to_be_bytes());
            }
            f.extend_from_slice(&apdu[off..off + chunk]);
            out.push(f);
            off += chunk;
            seq = seq.wrapping_add(1);
        }
        out
    }

    /// Reassembles response frames into the APDU (payload + status word).
    pub struct Reassembler {
        expected_seq: u16,
        total: Option<usize>,
        data: Vec<u8>,
    }

    impl Reassembler {
        pub fn new() -> Self {
            Self {
                expected_seq: 0,
                total: None,
                data: Vec::new(),
            }
        }

        /// Feed one frame; returns `Some(apdu)` once the full response is in.
        pub fn feed(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, String> {
            if frame.first() != Some(&TAG_APDU) || frame.len() < 3 {
                return Err(format!("malformed BLE frame ({} bytes)", frame.len()));
            }
            let seq = u16::from_be_bytes([frame[1], frame[2]]);
            if seq != self.expected_seq {
                return Err(format!(
                    "out-of-sequence BLE frame: expected {}, got {seq}",
                    self.expected_seq
                ));
            }
            let body = if self.total.is_none() {
                if frame.len() < 5 {
                    return Err("short BLE header frame".into());
                }
                self.total = Some(u16::from_be_bytes([frame[3], frame[4]]) as usize);
                &frame[5..]
            } else {
                &frame[3..]
            };
            let total = self.total.unwrap_or(0);
            let take = (total - self.data.len()).min(body.len());
            self.data.extend_from_slice(&body[..take]);
            self.expected_seq = self.expected_seq.wrapping_add(1);
            if self.data.len() >= total {
                Ok(Some(std::mem::take(&mut self.data)))
            } else {
                Ok(None)
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn roundtrip(mtu: usize, apdu: &[u8]) {
            let mut re = Reassembler::new();
            let mut out = None;
            for f in frames(mtu, apdu) {
                if let Some(r) = re.feed(&f).unwrap() {
                    out = Some(r);
                }
            }
            assert_eq!(out.as_deref(), Some(apdu));
        }

        #[test]
        fn framing_roundtrip() {
            roundtrip(153, &[0xE0, 0x04, 0, 0, 0]);
            roundtrip(153, &(0..300u32).map(|i| i as u8).collect::<Vec<u8>>());
            roundtrip(23, &[7u8; 100]); // small MTU, many frames
        }

        #[test]
        fn mtu_reply() {
            assert_eq!(parse_mtu(&[0x08, 0, 0, 0x99, 0x01, 0x99]), Some(153));
            assert_eq!(parse_mtu(&[0x05, 0, 0, 0, 0, 20]), None);
        }
    }
}

/// Browser Web Bluetooth transport (wasm32), the cable-free path for
/// Flex/Stax/Nano X on Android/desktop Chromium.
///
/// Pure Rust over `web-sys`: GATT calls and the notification event bridge go
/// through the auto-generated `wasm-bindgen` shim, while the Ledger BLE framing
/// and APDU protocol are the same Rust as the native/BLE transports. Requires
/// `--cfg web_sys_unstable_apis`.
#[cfg(all(wasm, feature = "webble"))]
pub mod webble {
    use futures::channel::mpsc::{UnboundedReceiver, unbounded};
    use futures::lock::Mutex;
    use futures::{FutureExt, StreamExt};
    use js_sys::{Array, Object, Reflect, Uint8Array};
    use wasm_bindgen::closure::Closure;
    use wasm_bindgen::{JsCast, JsValue};
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{
        BluetoothRemoteGattCharacteristic, BluetoothRemoteGattServer, Event, RequestDeviceOptions,
    };

    use super::ble_framing::{self, DEFAULT_MTU};
    use super::{Apdu, ApduResponse, Exchange, TransportError};

    /// (service, notify characteristic, write characteristic) per device model.
    const MODELS: &[(&str, &str, &str)] = &[
        (
            "13d63400-2c97-3004-0000-4c6564676572",
            "13d63400-2c97-3004-0001-4c6564676572",
            "13d63400-2c97-3004-0002-4c6564676572",
        ), // Flex
        (
            "13d63400-2c97-6004-0000-4c6564676572",
            "13d63400-2c97-6004-0001-4c6564676572",
            "13d63400-2c97-6004-0002-4c6564676572",
        ), // Stax
        (
            "13d63400-2c97-0004-0000-4c6564676572",
            "13d63400-2c97-0004-0001-4c6564676572",
            "13d63400-2c97-0004-0002-4c6564676572",
        ), // Nano X
    ];

    fn err(context: &str, e: impl std::fmt::Debug) -> TransportError {
        TransportError(format!("{context}: {e:?}"))
    }

    /// A Web-Bluetooth-connected Ledger. Notifications arrive as JS events; a
    /// closure funnels their bytes into a channel the exchange reads from.
    pub struct WebBleLedger {
        write_char: BluetoothRemoteGattCharacteristic,
        mtu: usize,
        rx: Mutex<UnboundedReceiver<Vec<u8>>>,
        _on_notify: Closure<dyn FnMut(Event)>,
    }

    fn view_to_vec(view: &js_sys::DataView) -> Vec<u8> {
        Uint8Array::new_with_byte_offset_and_length(
            &view.buffer(),
            view.byte_offset() as u32,
            view.byte_length() as u32,
        )
        .to_vec()
    }

    async fn write_frame(
        write_char: &BluetoothRemoteGattCharacteristic,
        frame: &[u8],
    ) -> Result<(), TransportError> {
        let mut buf = frame.to_vec();
        let promise = write_char
            .write_value_with_u8_slice(&mut buf)
            .map_err(|e| err("writeValue call", e))?;
        JsFuture::from(promise)
            .await
            .map_err(|e| err("writeValue", e))?;
        Ok(())
    }

    impl WebBleLedger {
        pub async fn connect() -> Result<Self, TransportError> {
            let bluetooth = web_sys::window()
                .ok_or_else(|| TransportError("no browser window".into()))?
                .navigator()
                .bluetooth()
                .ok_or_else(|| TransportError("Web Bluetooth unavailable".into()))?;

            // { filters: [{ services: [svc] }, ...] } — one filter per model so
            // any Ledger matches.
            let filters = Array::new();
            for (svc, _, _) in MODELS {
                let f = Object::new();
                Reflect::set(&f, &"services".into(), &Array::of1(&JsValue::from_str(svc)))
                    .map_err(|e| err("build filter", e))?;
                filters.push(&f);
            }
            let opts = Object::new();
            Reflect::set(&opts, &"filters".into(), &filters)
                .map_err(|e| err("build options", e))?;
            let opts: RequestDeviceOptions = opts.unchecked_into();

            let device: web_sys::BluetoothDevice = JsFuture::from(bluetooth.request_device(&opts))
                .await
                .map_err(|e| err("requestDevice (cancelled or no device?)", e))?
                .unchecked_into();

            let server: BluetoothRemoteGattServer = device
                .gatt()
                .ok_or_else(|| TransportError("device has no GATT".into()))?;
            JsFuture::from(server.connect())
                .await
                .map_err(|e| err("gatt connect", e))?;

            // Find which model's service the device exposes.
            let mut chosen = None;
            for (svc, notify, write) in MODELS {
                if let Ok(service) = JsFuture::from(server.get_primary_service_with_str(svc)).await
                {
                    let service: web_sys::BluetoothRemoteGattService = service.unchecked_into();
                    let notify_char: BluetoothRemoteGattCharacteristic =
                        JsFuture::from(service.get_characteristic_with_str(notify))
                            .await
                            .map_err(|e| err("get notify characteristic", e))?
                            .unchecked_into();
                    let write_char: BluetoothRemoteGattCharacteristic =
                        JsFuture::from(service.get_characteristic_with_str(write))
                            .await
                            .map_err(|e| err("get write characteristic", e))?
                            .unchecked_into();
                    chosen = Some((notify_char, write_char));
                    break;
                }
            }
            let (notify_char, write_char) =
                chosen.ok_or_else(|| TransportError("no Ledger GATT service on device".into()))?;

            // Bridge notification events into a channel.
            let (tx, mut rx) = unbounded::<Vec<u8>>();
            let notify_for_cb = notify_char.clone();
            let on_notify = Closure::<dyn FnMut(Event)>::new(move |_e: Event| {
                if let Some(view) = notify_for_cb.value() {
                    let _ = tx.unbounded_send(view_to_vec(&view));
                }
            });
            notify_char
                .add_event_listener_with_callback(
                    "characteristicvaluechanged",
                    on_notify.as_ref().unchecked_ref(),
                )
                .map_err(|e| err("addEventListener", e))?;
            JsFuture::from(notify_char.start_notifications())
                .await
                .map_err(|e| err("startNotifications", e))?;

            // MTU handshake: write 0x08, read the 0x08 reply.
            write_frame(&write_char, &ble_framing::mtu_request()).await?;
            let mut mtu = DEFAULT_MTU;
            for _ in 0..8 {
                match rx.next().await {
                    Some(frame) => {
                        if let Some(m) = ble_framing::parse_mtu(&frame) {
                            mtu = m;
                            break;
                        }
                    }
                    None => break,
                }
            }

            Ok(Self {
                write_char,
                mtu,
                rx: Mutex::new(rx),
                _on_notify: on_notify,
            })
        }
    }

    #[async_trait::async_trait(?Send)]
    impl Exchange for WebBleLedger {
        async fn exchange(&self, apdu: &Apdu) -> Result<ApduResponse, TransportError> {
            let mut raw = Vec::with_capacity(5 + apdu.data.len());
            raw.extend_from_slice(&[apdu.cla, apdu.ins, apdu.p1, apdu.p2, apdu.data.len() as u8]);
            raw.extend_from_slice(&apdu.data);

            let mut rx = self.rx.lock().await;
            // Discard stale/echo frames buffered before this request.
            while rx.next().now_or_never().flatten().is_some() {}

            for frame in ble_framing::frames(self.mtu, &raw) {
                write_frame(&self.write_char, &frame).await?;
            }

            let mut re = ble_framing::Reassembler::new();
            let response = loop {
                let frame = rx
                    .next()
                    .await
                    .ok_or_else(|| TransportError("BLE notification channel closed".into()))?;
                if let Some(r) = re.feed(&frame).map_err(TransportError)? {
                    break r;
                }
            };

            if response.len() < 2 {
                return Err(TransportError(
                    "BLE response shorter than status word".into(),
                ));
            }
            let split = response.len() - 2;
            let status = u16::from_be_bytes([response[split], response[split + 1]]);
            Ok(ApduResponse {
                data: response[..split].to_vec(),
                status,
            })
        }
    }
}
