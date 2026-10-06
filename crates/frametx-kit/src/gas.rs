//! Pinned gas limits from MSP HEAD [`gas_profile.py`].

pub const RECENT_ROOT_FRAME_GAS: u64 = 8_000;
pub const RECENT_ROOT_TUPLE_BYTES: usize = 72;
pub const VERIFY_FRAME_GAS: u64 = 225_000;
pub const VERIFY_FRAME_STATE_GAS: u64 = 195_840;
pub const SETTLE_FRAME_GAS: u64 = 2_000_000;
pub const SETTLE_FRAME_STATE_GAS: u64 = 550_000;
pub const CLAIM_FRAME_GAS: u64 = 100_000;
pub const CLAIM_FRAME_STATE_GAS: u64 = 183_600;
pub const EIP7825_TX_GAS_CAP: u64 = 1 << 24;
pub const ETHEX_MEMPOOL_MAX_BYTES: usize = 128 * 1024;
pub const WILD_FRAME_GAS: u64 = 500_000;
pub const WILD_FRAME_STATE_GAS: u64 = 100_000;
pub const SHIELD_VERIFY_GAS: u64 = 80_000;
pub const SIGNATURE_GAS_SECP256K1: u64 = 2_800;
pub const CLAIM_WITHDRAWAL_CALLDATA: usize = 36;
pub const TX_VALUE_COST: u64 = 6_000;
pub const FRAME_TX_INTRINSIC: u64 = 12_000;
pub const PER_FRAME_GAS: u64 = 475;
pub const RECENT_ROOT_WINDOW: u64 = 8192;
pub const HEGOTA_CHAIN_ID: u64 = 8141;
pub const RECENT_ROOT_ADDRESS: alloy::primitives::Address =
    alloy::primitives::address!("0x0000000000000000000000000000000000008272");

pub const FRAME_MODE_DEFAULT: u8 = 0;
pub const FRAME_MODE_VERIFY: u8 = 1;
pub const FRAME_MODE_SENDER: u8 = 2;
pub const APPROVE_EXECUTION_AND_PAYMENT: u8 = 0x03;
/// Consecutive `SENDER` frames except the last carry this flag. Batch members
/// must not set approval-scope bits.
pub const ATOMIC_BATCH_FLAG: u8 = 0x04;
pub const SIG_SCHEME_SECP256K1: u8 = 1;

/// EIP-8037 cost-per-state-byte used by Hegotá / MSP `gas_profile.py`.
pub const CPSB: u64 = 1_530;
pub const STATE_BYTES_PER_STORAGE_SET: u64 = 64;
/// First-use SSTORE (nonce `0 → 1` on a fresh `FrameAccount`).
pub const KEYED_NONCE_FIRST_USE_STATE_GAS: u64 = STATE_BYTES_PER_STORAGE_SET * CPSB;
pub const MULTICALL3_OVERHEAD_EXEC: u64 = 30_000;
pub const EXECUTE_BATCH_EXEC: u64 = 50_000;
pub const CREATE2_NOOP_EXEC: u64 = 8_000;
pub const WARM_CLAIM_STATE_GAS: u64 = 40_000;
pub const WARM_NONCE_STATE_GAS: u64 = 5_000;
/// Applied to the summed tail budget so a live Hegotá tick cannot OOG the DEFAULT.
pub const TAIL_GAS_PAD_BPS: u64 = 1_500;
/// Used when `deploy-accounts` has not yet measured CREATE2 on Hegotá.
/// FrameAccount code deposit is ~200 gas/byte; 400k OOGs a 2–3 KiB create.
pub const CREATE2_EXEC_FALLBACK: u64 = 1_500_000;
pub const CREATE2_STATE_FALLBACK: u64 = 4_000_000;
/// First successful Multicall tail: prefer these floors over a tight estimate.
pub const TAIL_FIRST_DEPLOY_EXEC_FLOOR: u64 = 2_000_000;
pub const TAIL_FIRST_DEPLOY_STATE_FLOOR: u64 = 4_500_000;
/// Generous SENDER pins for a direct `createAccount` frame.
/// Hegotá charges code deposit as state (~1,530/byte). FrameAccount runtime is
/// ~2 KiB, so 3M state halts the deploy with execution gas left over.
pub const CREATE2_MEASURE_EXEC: u64 = 2_000_000;
/// Measured deploy used ~4.18M state; keep headroom without a 10M reserve.
pub const CREATE2_MEASURE_STATE: u64 = 5_500_000;
/// Extra tail budget for `ecrecover`, the nonce write, and one value call.
pub const EXECUTE_BATCH_PAD_EXEC: u64 = 100_000;
pub const EXECUTE_BATCH_PAD_STATE: u64 = 100_000;

/// Execution and state limits for a `FrameAccount` leftover.
///
/// `include_claim` is the withdraw path (create, claim, execute). A gas-only
/// spend sets it false: create runs only when `account_empty`, otherwise the
/// leftover is `executeBatch` alone. The result is padded 15%. A first deploy
/// is also raised to the floors so the pin cannot sit under code deposit.
#[must_use]
pub fn estimate_frame_account_tail_gas(
    account_empty: bool,
    dest_empty: bool,
    include_claim: bool,
    create2_exec: u64,
    create2_state: u64,
) -> (u64, u64) {
    let claim_exec = if include_claim { CLAIM_FRAME_GAS } else { 0 };
    let claim_state = if !include_claim {
        0
    } else if account_empty {
        CLAIM_FRAME_STATE_GAS
    } else {
        WARM_CLAIM_STATE_GAS
    };
    let include_create = include_claim || account_empty;
    let (factory_exec, factory_state) = if !include_create {
        (0, 0)
    } else if account_empty {
        (create2_exec, create2_state)
    } else {
        (CREATE2_NOOP_EXEC, 0)
    };
    let overhead = if include_create {
        MULTICALL3_OVERHEAD_EXEC
    } else {
        0
    };
    let exec_batch_state = if account_empty {
        KEYED_NONCE_FIRST_USE_STATE_GAS
    } else {
        WARM_NONCE_STATE_GAS
    };
    let dest_state = if dest_empty { CLAIM_FRAME_STATE_GAS } else { 0 };
    let mut exec = pad_tail_gas(claim_exec + factory_exec + EXECUTE_BATCH_EXEC + overhead);
    let mut state = pad_tail_gas(claim_state + factory_state + exec_batch_state + dest_state);
    if account_empty {
        exec = exec.max(TAIL_FIRST_DEPLOY_EXEC_FLOOR);
        state = state.max(TAIL_FIRST_DEPLOY_STATE_FLOOR);
    }
    (exec, state)
}

/// Increase `n` by [`TAIL_GAS_PAD_BPS`] (15%).
#[must_use]
pub fn pad_tail_gas(n: u64) -> u64 {
    n.saturating_add(n.saturating_mul(TAIL_GAS_PAD_BPS) / 10_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_deploy_includes_create2_and_new_eoa_state() {
        let (exec, state) = estimate_frame_account_tail_gas(true, true, true, 100_000, 500_000);
        assert_eq!(exec, TAIL_FIRST_DEPLOY_EXEC_FLOOR);
        assert_eq!(state, TAIL_FIRST_DEPLOY_STATE_FLOOR);
    }

    #[test]
    fn warm_account_drops_create2_and_dest_surcharge() {
        let (exec, state) = estimate_frame_account_tail_gas(false, false, true, 400_000, 2_000_000);
        let raw_exec =
            CLAIM_FRAME_GAS + CREATE2_NOOP_EXEC + EXECUTE_BATCH_EXEC + MULTICALL3_OVERHEAD_EXEC;
        let raw_state = WARM_CLAIM_STATE_GAS + WARM_NONCE_STATE_GAS;
        assert_eq!(exec, pad_tail_gas(raw_exec));
        assert_eq!(state, pad_tail_gas(raw_state));
        assert!(exec < 250_000);
        assert!(state < 60_000);
    }

    #[test]
    fn gas_only_warm_account_is_execute_batch_alone() {
        let (exec, state) =
            estimate_frame_account_tail_gas(false, false, false, 2_000_000, 8_000_000);
        assert_eq!(exec, pad_tail_gas(EXECUTE_BATCH_EXEC));
        assert_eq!(state, pad_tail_gas(WARM_NONCE_STATE_GAS));
    }
}
