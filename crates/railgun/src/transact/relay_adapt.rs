//! Post-transaction actions through the RelayAdapt contract.
//!
//! A Railgun transaction can hand its unshielded tokens to the RelayAdapt contract and have it
//! run a list of calls in the same EVM transaction: unwrap the wrapped base token and forward
//! the native currency, for instance. `RelayAdapt.relay(transactions, actionData)` executes
//! `RailgunSmartWallet.transact` then the calls. The calls are bound into every proof through
//! `boundParams.adaptParams = keccak256(abi.encode(nullifiers, transactions.length, actionData))`
//! and `boundParams.adaptContract = RelayAdapt`, so whoever submits the transaction (a
//! broadcaster) can neither change the recipient nor drop a call. This mirrors
//! `RelayAdaptHelper.getRelayAdaptParams` of the Railgun community engine.

use alloy::{
    primitives::{Address, B256, Bytes, FixedBytes, U256, keccak256},
    sol_types::{SolCall, SolValue},
};
use rand::CryptoRng;

use crate::abis::railgun::{RelayAdapt, TokenData, TokenType, Transaction};

/// The calls RelayAdapt runs after the transaction, and the parameters bound into the proofs.
#[derive(Debug, Clone)]
pub struct RelayAction {
    /// RelayAdapt contract of the chain: the adapt contract and the target of every call.
    pub relay_adapt: Address,
    /// 31 bytes of salt, so two identical actions never share an `adaptParams`.
    pub random: [u8; 31],
    /// When true the whole transaction reverts if a call fails (`sendWithPublicWallet` in the
    /// community engine); broadcaster submissions use false so the Railgun transaction itself
    /// lands even if a call reverts (the contract then emits `CallError`).
    pub require_success: bool,
    /// Minimum gas the relay call must have left before running the calls; 0 for no check.
    pub min_gas_limit: U256,
    /// Calls in execution order, all targeting `relay_adapt` for the built-in actions.
    pub calls: Vec<RelayAdapt::Call>,
}

impl RelayAction {
    /// Unshield the wrapped base token to `to` as native currency: the transaction unshields
    /// to the RelayAdapt contract, which unwraps its whole balance and transfers it. Amounts
    /// of 0 mean "everything the contract holds", exactly as the community engine populates
    /// `unshieldBaseToken`.
    pub fn unshield_base_token(relay_adapt: Address, to: Address, rng: &mut impl CryptoRng) -> Self {
        let mut random = [0u8; 31];
        rng.fill_bytes(&mut random);
        let base_token = TokenData {
            tokenType: TokenType::ERC20,
            tokenAddress: Address::ZERO,
            tokenSubID: U256::ZERO,
        };
        let calls = vec![
            RelayAdapt::Call {
                to: relay_adapt,
                data: RelayAdapt::unwrapBaseCall { _amount: U256::ZERO }.abi_encode().into(),
                value: U256::ZERO,
            },
            RelayAdapt::Call {
                to: relay_adapt,
                data: RelayAdapt::transferCall {
                    _transfers: vec![RelayAdapt::TokenTransfer {
                        token: base_token,
                        to,
                        value: U256::ZERO,
                    }],
                }
                .abi_encode()
                .into(),
                value: U256::ZERO,
            },
        ];
        Self {
            relay_adapt,
            random,
            require_success: false,
            min_gas_limit: U256::ZERO,
            calls,
        }
    }

    /// Arbitrary calls after the transaction (cross-contract calls).
    pub fn calls(
        relay_adapt: Address,
        calls: Vec<RelayAdapt::Call>,
        require_success: bool,
        min_gas_limit: U256,
        rng: &mut impl CryptoRng,
    ) -> Self {
        let mut random = [0u8; 31];
        rng.fill_bytes(&mut random);
        Self {
            relay_adapt,
            random,
            require_success,
            min_gas_limit,
            calls,
        }
    }

    pub fn action_data(&self) -> RelayAdapt::ActionData {
        RelayAdapt::ActionData {
            random: FixedBytes::<31>::from(self.random),
            requireSuccess: self.require_success,
            minGasLimit: self.min_gas_limit,
            calls: self.calls.clone(),
        }
    }

    /// `adaptParams` for a set of transactions, from their nullifiers in transaction order:
    /// `keccak256(abi.encode(bytes32[][] nullifiers, uint256 transactionsLength, ActionData))`.
    /// RelayAdapt recomputes it in `relay` and rejects a transaction whose bound params differ.
    pub fn adapt_params(&self, nullifiers: &[Vec<B256>]) -> [u8; 32] {
        // abi.encode(a, b, c): the tuple is the parameter list, not one tuple-typed parameter.
        let preimage = (
            nullifiers.to_vec(),
            U256::from(nullifiers.len()),
            self.action_data(),
        )
            .abi_encode_params();
        debug_assert_eq!(preimage.len() % 32, 0);
        keccak256(preimage).0
    }

    /// Calldata of `RelayAdapt.relay(transactions, actionData)`.
    pub fn relay_calldata(&self, transactions: Vec<Transaction>) -> Bytes {
        RelayAdapt::relayCall {
            _transactions: transactions,
            _actionData: self.action_data(),
        }
        .abi_encode()
        .into()
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{address, b256, hex};

    use super::*;

    // Vectors produced with the community engine's ABI (RelayAdapt.json, V2) through ethers:
    // `RelayAdaptHelper.getRelayAdaptParams` preimage layout and the two call encodings.
    const RELAY: Address = address!("4025ee6512DBbda97049Bcf5AA5D38C54aF6bE8a");
    const TO: Address = address!("000000000000000000000000000000000000dEaD");
    /// `relay([], actionData)` as ethers encodes it with the fixed salt.
    const RELAY_EMPTY: &str = "28223a7700000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000011111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001000000000000000000000000004025ee6512dbbda97049bcf5aa5d38c54af6be8a000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000024d5774a280000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004025ee6512dbbda97049bcf5aa5d38c54af6be8a0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000e4c2e9ffd800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000dead000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

    fn fixed_action() -> RelayAction {
        let mut a = RelayAction::unshield_base_token(RELAY, TO, &mut rand::rng());
        a.random = [0x11; 31];
        a
    }

    #[test]
    fn unshield_base_token_calls_match_the_engine() {
        let a = fixed_action();
        assert_eq!(a.calls.len(), 2);
        assert_eq!(
            hex::encode(&a.calls[0].data),
            "d5774a280000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            hex::encode(&a.calls[1].data),
            "c2e9ffd800000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000dead0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert!(a.calls.iter().all(|c| c.to == RELAY && c.value.is_zero()));
    }

    #[test]
    fn adapt_params_match_relay_adapt_helper() {
        let a = fixed_action();
        let nullifiers = vec![
            vec![
                b256!("0101010101010101010101010101010101010101010101010101010101010101"),
                b256!("0202020202020202020202020202020202020202020202020202020202020202"),
            ],
            vec![b256!("0303030303030303030303030303030303030303030303030303030303030303")],
        ];
        assert_eq!(
            hex::encode(a.adapt_params(&nullifiers)),
            "abc633ee814bf8acd95c94c99858fb9aa8be4de2069fe3a713f1548f064c0323"
        );
        // the community preimage for these inputs is 1152 bytes
        let preimage = (nullifiers.clone(), U256::from(2), a.action_data()).abi_encode_params();
        assert_eq!(preimage.len(), 1152);
        // any change to the salt, the calls or the nullifier set changes the binding
        let mut b = a.clone();
        b.random[0] ^= 1;
        assert_ne!(b.adapt_params(&nullifiers), a.adapt_params(&nullifiers));
        assert_ne!(a.adapt_params(&nullifiers[..1]), a.adapt_params(&nullifiers));
    }

    #[test]
    fn relay_calldata_matches_the_engine() {
        let a = fixed_action();
        let data = a.relay_calldata(Vec::new());
        assert_eq!(&data[..4], &hex!("28223a77"));
        assert_eq!(data.len(), 900);
        assert_eq!(keccak256(&data), keccak256(hex::decode(RELAY_EMPTY).unwrap()));
    }
}
