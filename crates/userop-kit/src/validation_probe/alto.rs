//! What the alto bundler (Pimlico) will answer to `eth_estimateUserOperationGas`, computed
//! beforehand.
//!
//! A caller that fixes its gas limits before proving has to end up at or above the bundler's own
//! estimate, which it can only ask for once the proof exists. That estimate is not the gas the
//! chain needs: alto searches the minimal limit on a fixed ladder of midpoints, then scales it.
//! Both steps are reproduced here from alto's source (`binarySearchGasLimit` in
//! `EntryPointSimulations.sol`, `getGasEstimates` in `eth_estimateUserOperationGas.ts`, commit
//! 9652959 of 2026-09-16).
//!
//! The multipliers are deployment settings. alto's defaults are 100% for the call limit and 130%
//! for the verification limit; Pimlico's public endpoint was observed at 220% and 135%:
//!
//! * call phase needing 25,312 gas: ladder value 30,971, times 220% = 68,136, the figure the
//!   endpoint returned on two different transactions;
//! * verification needing between 31,000 and 38,250: ladder value 38,295, times 135% = 51,698,
//!   the figure it returned.
//!
//! Exact matches, but two of them: if Pimlico changes its settings the prediction is off, which
//! is why the comparison with the bundler's real estimate after the proof must stay.

use alloy::sol_types::SolValue;

use super::ProbedUserOperation;
use crate::{signable_user_operation::SignableUserOperation, user_operation::Authorization};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AltoPolicy {
    /// `initialMinGas` of the binary search.
    pub search_floor: u128,
    /// `binary-search-gas-allowance`.
    pub search_allowance: u128,
    /// `binary-search-tolerance-delta`.
    pub search_tolerance: u128,
    /// `v7-call-gas-limit-multiplier`, percent.
    pub call_multiplier_percent: u128,
    /// `v7-verification-gas-limit-multiplier`, percent.
    pub verification_multiplier_percent: u128,
}

impl AltoPolicy {
    /// Settings inferred for `public.pimlico.io` on Sepolia, 2026-09-20.
    pub const PIMLICO_PUBLIC: Self = Self {
        search_floor: 9_000,
        search_allowance: 30_000_000,
        search_tolerance: 10_000,
        call_multiplier_percent: 220,
        // 135% when calibrated on 2026-09-20; 175% observed on 2026-10-07 (an account
        // verification estimate of 220,825 = ladder 126,186 x 175%, the only exact fit).
        verification_multiplier_percent: 175,
    };

    /// Value alto's search returns when the smallest limit that works is `minimal`: the lowest
    /// successful midpoint of a bisection that stops once the interval is under the tolerance.
    /// Up to about 7,300 above `minimal`, and the same for every `minimal` in a bucket.
    pub fn ladder(&self, minimal: u128) -> u128 {
        let (mut low, mut high) = (self.search_floor, self.search_floor + self.search_allowance);
        let mut best = high;
        while high - low >= self.search_tolerance {
            let mid = (low + high) / 2;
            if mid >= minimal {
                best = mid;
                high = mid - 1;
            } else {
                low = mid + 1;
            }
        }
        best
    }

    /// Predicted `callGasLimit` for an execution phase whose minimal limit is `minimal`.
    ///
    /// `minimal` comes from a simulation of our own, which may differ from alto's by a few
    /// hundred gas; near the edge of a bucket that moves the answer by a whole step. The
    /// prediction is therefore taken for a slightly larger need as well, and the larger kept.
    pub fn call_gas_limit(&self, minimal: u128) -> u128 {
        let nudged = minimal + minimal / 10 + 1_000;
        self.ladder(minimal).max(self.ladder(nudged)) * self.call_multiplier_percent / 100
    }

    /// Predicted `verificationGasLimit`, same construction.
    pub fn verification_gas_limit(&self, minimal: u128) -> u128 {
        let nudged = minimal + minimal / 10 + 1_000;
        self.ladder(minimal).max(self.ladder(nudged)) * self.verification_multiplier_percent / 100
    }
}

/// `preVerificationGas` as alto estimates it (`calcExecutionPvgComponent`, L1 chains): alto prices
/// the UserOperation with its gas fields at their maximum and `paymasterAndData` and the
/// signature filled with `0xff`, that is every such byte as non-zero, whatever the real bytes
/// are. For a Railgun UserOperation, whose paymaster data is several kilobytes with many zero
/// bytes, this is well above a count over the real encoding.
pub fn pre_verification_gas(op: &SignableUserOperation) -> u128 {
    const ZERO_BYTE: u128 = 4;
    const NON_ZERO_BYTE: u128 = 16;
    const TRANSACTION_STIPEND: u128 = 21_000;
    const FIXED_OVERHEAD: u128 = 9_830;
    const PER_USER_OP: u128 = 7_260;
    const EIP7702_AUTHORIZATION: u128 = 25_000;
    /// Per word of `callData`, in thousandths of gas.
    const PER_CALLDATA_WORD_MILLI: u128 = 9_200;

    let packed = op.user_op.into_packed();
    let filled = ProbedUserOperation {
        sender: packed.sender,
        nonce: packed.nonce,
        initCode: packed.initCode,
        callData: packed.callData.clone(),
        accountGasLimits: [0xff; 32].into(),
        preVerificationGas: alloy::primitives::U256::MAX,
        gasFees: [0xff; 32].into(),
        paymasterAndData: vec![0xff; packed.paymasterAndData.len()].into(),
        signature: vec![0xff; op.user_op.signature.len()].into(),
    };
    let calldata_cost: u128 = filled
        .abi_encode()
        .iter()
        .map(|b| if *b == 0 { ZERO_BYTE } else { NON_ZERO_BYTE })
        .sum();
    let calldata_words = (packed.callData.len() as u128).div_ceil(32);
    let authorization = match op.user_op.authorization {
        Authorization::None => 0,
        _ => EIP7702_AUTHORIZATION,
    };
    calldata_cost
        + TRANSACTION_STIPEND
        + FIXED_OVERHEAD
        + PER_USER_OP
        + authorization
        + calldata_words * PER_CALLDATA_WORD_MILLI / 1_000
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two figures Pimlico's public endpoint returned on Sepolia, reproduced to the unit.
    #[test]
    fn reproduces_the_observed_estimates() {
        let alto = AltoPolicy::PIMLICO_PUBLIC;
        // Unwrap + send: our probe found a minimal call limit of 25,312; the bundler said 68,136.
        assert_eq!(alto.ladder(25_312), 30_971);
        assert_eq!(alto.ladder(25_312) * 220 / 100, 68_136);
        assert_eq!(alto.call_gas_limit(25_312), 68_136);
        // Account verification: the bundler said 51,698 = 38,295 x 135%.
        assert_eq!(alto.ladder(35_000) * 135 / 100, 51_698);
    }

    #[test]
    fn ladder_is_a_step_function_above_the_need() {
        let alto = AltoPolicy::PIMLICO_PUBLIC;
        for minimal in [9_000u128, 16_300, 23_650, 30_950, 31_000, 120_000, 1_400_000] {
            let value = alto.ladder(minimal);
            assert!(value >= minimal, "{minimal} -> {value}");
            assert!(value - minimal < 7_400, "{minimal} -> {value}");
        }
        assert_eq!(alto.ladder(23_650), alto.ladder(30_950));
        assert!(alto.ladder(31_000) > alto.ladder(30_950));
    }

    /// Just under a bucket edge, the prediction already takes the next step: our measure of the
    /// need and alto's may fall on either side.
    #[test]
    fn prediction_covers_the_next_bucket_near_an_edge() {
        let alto = AltoPolicy::PIMLICO_PUBLIC;
        assert_eq!(alto.call_gas_limit(30_900), alto.ladder(31_000) * 220 / 100);
    }
}
