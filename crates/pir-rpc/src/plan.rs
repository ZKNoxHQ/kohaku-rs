/// How to decode PIR value bytes into a JSON-RPC result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PirDecode {
    /// 40-byte account blob → balance quantity hex.
    AccountBalance,
    /// 40-byte account blob → nonce quantity hex.
    AccountNonce,
    /// Dataset value → `value_encoding` (`account` / `bytes` / `uint256`).
    Call {
        /// Encoding from the dataset manifest.
        value_encoding: String,
    },
}

/// A PIR lookup the orchestrator should run (never silent-fallback to RPC).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PirOp {
    /// Derived PIR key.
    pub key: Vec<u8>,
    /// Decode rule for the returned bytes.
    pub decode: PirDecode,
}

/// Result of classifying one JSON-RPC method against the PIR allowlist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlannedOp {
    /// Answer via PIR lookup.
    Pir(PirOp),
    /// Forward to the fallback Ethereum JSON-RPC endpoint.
    Fallback,
}
