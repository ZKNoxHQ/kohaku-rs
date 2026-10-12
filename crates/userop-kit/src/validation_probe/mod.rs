//! Gas of every phase of a UserOperation, measured by an `eth_call` of the caller's own.
//!
//! A bundler's `eth_estimateUserOperationGas` answers the same question, but from an origin the
//! bundler chooses. Some contracts behave differently for a designated estimation origin (the
//! Railgun verifier accepts any proof when `tx.origin` is its bypass address): with the bundler,
//! such a UserOperation can only be estimated once it carries a valid proof, and the proof binds
//! the fee that the estimate is needed for. Hence a loop, and one signature per round.
//!
//! The probe breaks the circle. A state override puts [`PROBE_RUNTIME_CODE`] at the EntryPoint
//! address, so the account and the paymaster see the caller they require, and the call is sent
//! from the origin the application needs. Nothing is configured or learned: the figures come from
//! executing the exact UserOperation against the current state.
//!
//! The module only builds the request and decodes the answer; the caller performs the
//! `eth_call` with whatever provider it has, which must support state overrides.

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    sol,
    sol_types::{SolCall, SolValue},
};

use crate::{signable_user_operation::SignableUserOperation, user_operation::Authorization};

pub mod alto;

/// Runtime bytecode of `ValidationProbe.sol` (solc 0.8.28, optimizer 200 runs, via-IR, cancun).
/// Rebuild with solc after any change to the source, and keep the two files in step: the test
/// below only checks the selector.
/// No constructor, no immutable, no storage: valid as overridden code at any address.
pub const PROBE_RUNTIME_CODE: &str = include_str!("ValidationProbe.bin-runtime");

sol! {
    struct ProbedUserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        bytes paymasterAndData;
        bytes signature;
    }

    struct ProbeResult {
        uint256 accountValidationGas;
        uint256 paymasterValidationGas;
        uint256 callGas;
        uint256 postOpGas;
        bool accountValidated;
        bool paymasterValidated;
        bool callSucceeded;
        bool postOpCalled;
        bytes paymasterError;
        bytes callError;
        uint256 callGasLimit;
    }

    function probe(ProbedUserOperation op, bytes32 userOpHash, uint256 maxCost)
        external
        returns (ProbeResult r);
}

/// What to send: `eth_call { from, to, data }` with `code_overrides` applied.
#[derive(Debug, Clone)]
pub struct ProbeRequest {
    /// The EntryPoint address, whose code is overridden by the probe.
    pub to: Address,
    pub data: Bytes,
    /// `(address, code)` pairs. Always the probe at the EntryPoint; plus the account, when it is
    /// an EIP-7702 account whose delegation is not on-chain yet.
    pub code_overrides: Vec<(Address, Bytes)>,
    /// Account whose code must be read and installed at `sender` before the call, for a 7702
    /// authorization still to be applied. Copying the code rather than a delegation designator
    /// keeps the request independent of how a node treats overridden designators.
    pub copy_code_from: Option<(Address, Address)>,
}

/// Gas used by each phase. Limits must leave room above these: the EntryPoint forwards at most
/// 63/64 of a limit to nested calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeGas {
    pub account_validation: u128,
    pub paymaster_validation: u128,
    /// Gas the execution call used. Informative: use [`Self::call_limit`] to size the limit.
    pub call: u128,
    /// Smallest `callGasLimit` with which the execution call succeeds, found by the probe by
    /// trial (each trial reverted) to within 1000 gas. Well above the gas used whenever value
    /// moves: a transfer must have 9000 gas at hand, 34000 towards a new account, and hands most
    /// of it back. 0 without execution calldata.
    pub call_limit: u128,
    pub post_op: u128,
    pub post_op_called: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("probe answer could not be decoded: {0}")]
    Decode(String),
    #[error("account validation reverted in the probe, its gas cannot be trusted")]
    AccountValidation,
    #[error("paymaster validation reverted in the probe: {0}")]
    PaymasterValidation(String),
    #[error("the execution phase reverted in the probe: {0}")]
    Call(String),
    #[error("the probe found no gas limit under which the execution phase succeeds")]
    CallLimit,
}

/// Builds the probe request for an unsigned UserOperation (its dummy signature is used).
pub fn request(op: &SignableUserOperation, max_cost: U256) -> ProbeRequest {
    let packed = op.user_op.into_packed();
    let probed = ProbedUserOperation {
        sender: packed.sender,
        nonce: packed.nonce,
        initCode: packed.initCode,
        callData: packed.callData,
        accountGasLimits: packed.accountGasLimits,
        preVerificationGas: packed.preVerificationGas,
        gasFees: packed.gasFees,
        paymasterAndData: packed.paymasterAndData,
        signature: op.user_op.signature.clone(),
    };
    let data = probeCall {
        op: probed,
        // Accounts and paymasters that check the hash do so against a signature, which a probe
        // does not have. The value does not change the gas.
        userOpHash: B256::ZERO,
        maxCost: max_cost,
    }
    .abi_encode()
    .into();

    let probe_code: Bytes = PROBE_RUNTIME_CODE
        .trim()
        .parse()
        .expect("embedded probe bytecode is valid hex");
    let copy_code_from = match &op.user_op.authorization {
        Authorization::Eip7702(auth) => Some((auth.address, op.user_op.sender)),
        Authorization::SignedEip7702(auth) => Some((auth.address, op.user_op.sender)),
        Authorization::None => None,
    };
    ProbeRequest {
        to: op.entry_point,
        data,
        code_overrides: vec![(op.entry_point, probe_code)],
        copy_code_from,
    }
}

/// Decodes the `eth_call` answer. A phase that reverted makes its gas figure meaningless, so it
/// is an error rather than a number.
pub fn decode(answer: &[u8], has_call: bool) -> Result<ProbeGas, ProbeError> {
    let r = ProbeResult::abi_decode(answer).map_err(|e| ProbeError::Decode(e.to_string()))?;
    if !r.accountValidated {
        return Err(ProbeError::AccountValidation);
    }
    if !r.paymasterValidated {
        return Err(ProbeError::PaymasterValidation(revert_text(&r.paymasterError)));
    }
    if has_call && !r.callSucceeded {
        return Err(ProbeError::Call(revert_text(&r.callError)));
    }
    if has_call && r.callGasLimit.is_zero() {
        return Err(ProbeError::CallLimit);
    }
    let gas = |v: U256| u128::try_from(v).unwrap_or(u128::MAX);
    Ok(ProbeGas {
        account_validation: gas(r.accountValidationGas),
        paymaster_validation: gas(r.paymasterValidationGas),
        call: gas(r.callGas),
        call_limit: gas(r.callGasLimit),
        post_op: gas(r.postOpGas),
        post_op_called: r.postOpCalled,
    })
}

/// `Error(string)` text when there is one, the selector otherwise.
fn revert_text(data: &[u8]) -> String {
    if data.len() >= 4 && data[..4] == [0x08, 0xc3, 0x79, 0xa0] {
        if let Ok(text) = String::abi_decode(&data[4..]) {
            return text;
        }
    }
    match data.len() {
        0 => "no revert data".into(),
        n if n >= 4 => format!("custom error 0x{}", alloy::hex::encode(&data[..4])),
        _ => format!("0x{}", alloy::hex::encode(data)),
    }
}

/// `preVerificationGas` by the reference formula of the ERC-4337 bundler spec (L1 chains):
/// calldata cost of the packed UserOperation, the bundle's fixed cost, a per-operation and a
/// per-word overhead, plus the intrinsic cost of an EIP-7702 authorization when there is one.
///
/// This is the one figure no simulation can give: it is the bundler's pricing of inclusion, not
/// execution. Bundlers may ask for more (EIP-7623 floor pricing, their own overheads), so pad it
/// generously; the bundler's estimate on the final UserOperation remains the check.
pub fn pre_verification_gas(op: &SignableUserOperation) -> u128 {
    const FIXED: u128 = 21_000;
    const PER_USER_OP: u128 = 18_300;
    const PER_WORD: u128 = 4;
    const ZERO_BYTE: u128 = 4;
    const NON_ZERO_BYTE: u128 = 16;
    const EIP7702_AUTHORIZATION: u128 = 25_000;

    let packed = op.user_op.into_packed();
    let probed = ProbedUserOperation {
        sender: packed.sender,
        nonce: packed.nonce,
        initCode: packed.initCode,
        callData: packed.callData,
        accountGasLimits: packed.accountGasLimits,
        preVerificationGas: packed.preVerificationGas,
        gasFees: packed.gasFees,
        paymasterAndData: packed.paymasterAndData,
        signature: op.user_op.signature.clone(),
    };
    let bytes = probed.abi_encode();
    let calldata: u128 = bytes
        .iter()
        .map(|b| if *b == 0 { ZERO_BYTE } else { NON_ZERO_BYTE })
        .sum();
    let words = (bytes.len() as u128).div_ceil(32);
    let authorization = match op.user_op.authorization {
        Authorization::None => 0,
        _ => EIP7702_AUTHORIZATION,
    };
    calldata + FIXED + PER_USER_OP + PER_WORD * words + authorization
}

/// Gas the EntryPoint itself spends inside the window it charges to `verificationGasLimit`.
///
/// EntryPoint v0.7 and v0.8 do not apply that limit to the account's `validateUserOp` alone:
/// they revert with `AA26 over verificationGasLimit` when the gas used since the start of
/// `_validatePrepayment` exceeds it, which also covers copying the UserOperation to memory, the
/// prefund computation, sender creation (the EIP-7702 path reads the delegate's code) and nonce
/// validation. The probe stands in for the EntryPoint and cannot measure the EntryPoint's own
/// work, so [`ProbeGas::account_validation`] is only the account's share.
///
/// Measured on Sepolia (v0.8, Simple7702Account, privacy paymaster data of about 4 kB): the
/// account used 9.5k and the bundler required 51.7k, its own buffer included. This allowance
/// covers that with room for larger paymaster data, whose copy cost grows by a few gas per word.
/// It is a property of the EntryPoint version, not of the chain or of the transaction.
pub const ENTRY_POINT_VALIDATION_OVERHEAD: u128 = 60_000;

/// `value` plus `margin_percent`, rounded up to a multiple of `bucket`.
pub fn pad_gas(value: u128, margin_percent: u32, bucket: u128) -> u128 {
    let padded = value + value * u128::from(margin_percent) / 100;
    let bucket = bucket.max(1);
    padded.div_ceil(bucket) * bucket
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_bytecode_is_the_probe() {
        let code: Bytes = PROBE_RUNTIME_CODE.trim().parse().unwrap();
        assert!(code.len() > 1_000);
        // The only external function is probe(...): its selector must be in the dispatcher.
        let selector = probeCall::SELECTOR;
        assert!(code.windows(4).any(|w| w == selector));
        // Solidity's own ABI for the same signature, from the compiler output.
        assert_eq!(alloy::hex::encode(selector), "f03e34c4");
    }

    #[test]
    fn decode_reports_reverted_phases() {
        let ok = ProbeResult {
            accountValidationGas: U256::from(41_000u64),
            paymasterValidationGas: U256::from(900_000u64),
            callGas: U256::ZERO,
            postOpGas: U256::ZERO,
            accountValidated: true,
            paymasterValidated: true,
            callSucceeded: true,
            postOpCalled: false,
            paymasterError: Bytes::new(),
            callError: Bytes::new(),
            callGasLimit: U256::ZERO,
        };
        let gas = decode(&ok.abi_encode(), false).unwrap();
        // With execution calldata, a search that found nothing is an error, not a zero limit.
        assert!(matches!(decode(&ok.abi_encode(), true), Err(ProbeError::CallLimit)));
        assert_eq!(gas.paymaster_validation, 900_000);
        assert!(!gas.post_op_called);

        let mut bad = ok.clone();
        bad.paymasterValidated = false;
        bad.paymasterError = {
            let mut e = vec![0x08, 0xc3, 0x79, 0xa0];
            e.extend("Gas price too low".to_string().abi_encode());
            e.into()
        };
        match decode(&bad.abi_encode(), false) {
            Err(ProbeError::PaymasterValidation(text)) => assert_eq!(text, "Gas price too low"),
            other => panic!("{other:?}"),
        }

        let mut no_account = ok;
        no_account.accountValidated = false;
        assert!(matches!(
            decode(&no_account.abi_encode(), false),
            Err(ProbeError::AccountValidation)
        ));
    }

    #[test]
    fn padding() {
        assert_eq!(pad_gas(100_000, 25, 10_000), 130_000);
        assert_eq!(pad_gas(104_001, 25, 10_000), 140_000);
        assert_eq!(pad_gas(100, 10, 0), 110);
    }
}
