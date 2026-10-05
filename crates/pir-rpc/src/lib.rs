//! Hybrid Ethereum JSON-RPC provider: PIR for private account reads, fallback
//! RPC for everything else.

#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

mod dataset;
mod error;
mod fallback;
mod lookup;
mod plan;
mod router;
mod routes;
mod transport;

pub use dataset::DatasetManifest;
pub use error::PirProviderError;
pub use fallback::{FallbackRpc, HttpFallback, MapFallback};
pub use lookup::{LookupBackend, MapLookup};
pub use plan::{PirDecode, PirOp, PlannedOp};
pub use router::{PirRouter, decode_pir};
pub use routes::{CallMatch, Route, RouteTable};
pub use transport::{PirConnect, PirTransport, connect_provider};
