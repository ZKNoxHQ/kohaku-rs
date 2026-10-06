/// Which PIR server / key space an op targets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PirLane {
    /// Account table (`eth_getBalance` / `eth_getTransactionCount`).
    Account,
    /// Contract storage table (ERC-20 `balanceOf` for PIR tokens).
    TokenStorage,
}

/// How to decode PIR value bytes into a JSON-RPC result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PirDecode {
    /// 40-byte account blob → balance quantity hex.
    AccountBalance,
    /// 40-byte account blob → nonce quantity hex.
    AccountNonce,
    /// Reserved: account blob → code (not served by PIR yet).
    #[allow(dead_code)]
    AccountCode,
    /// 40-byte storage cell → ABI `uint256` (optional top-bit clear).
    TokenBalance {
        /// Clear bit 255 of the storage word (USDC blacklist).
        flag_in_top_bit: bool,
    },
    /// Dataset value → `value_encoding` (`account` / `bytes` / `uint256`).
    Call {
        /// Encoding from the dataset manifest.
        value_encoding: String,
    },
}

/// A PIR lookup the orchestrator should run (never silent-fallback to RPC).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PirOp {
    /// Accounts vs token-storage PIR server.
    pub lane: PirLane,
    /// Derived PIR key.
    pub key: Vec<u8>,
    /// Decode rule for the returned bytes.
    pub decode: PirDecode,
    /// Holder address when this is a token `balanceOf` (for four-token padding).
    pub holder: Option<[u8; 20]>,
    /// Index into [`crate::PIR_TOKENS`] when this is a hardcoded token balance.
    pub token_index: Option<usize>,
}

/// Result of classifying one JSON-RPC method against the PIR allowlist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlannedOp {
    /// Answer via PIR lookup.
    Pir(PirOp),
    /// Forward to the fallback Ethereum JSON-RPC endpoint.
    Fallback,
}
