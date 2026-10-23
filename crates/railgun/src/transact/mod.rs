mod amount;
pub mod proved_transaction;
mod shield_builder;
mod spend;

pub(crate) use amount::attach_fee;
pub use amount::{AmountError, AmountIntents};
pub use proved_transaction::{ProvedOperation, ProvedTx};
pub use shield_builder::{ShieldBuilder, ShieldError};
pub(crate) use spend::prove_operations;
pub use spend::{Spend, SpendError};
