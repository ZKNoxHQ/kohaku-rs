//! A state override under which Railgun's verifier accepts a dummy proof.
//!
//! Railgun only skips the SNARK check for `tx.origin == VERIFICATION_BYPASS`, and a bundler
//! simulates from its own origin, so estimating a UserOperation's gas normally takes a real
//! proof, hence a spending signature. Instead, the estimate call can carry a state override
//! that zeroes the G2 elements (`beta2`, `gamma2`, `delta2`) of the verifying keys in use. Every
//! factor of the pairing check becomes `e(·, O) = 1`, so `verify` returns true for the dummy
//! proof of [`crate::circuit::proof::Proof::dummy`] while running exactly the code and precompiles
//! of a real verification: `alpha1` and `ic` are left in place (`verify` requires
//! `alpha1.x != 0`), and the gas of the ec operations and of the pairing precompile does not
//! depend on the values.
//!
//! The one coupling is the storage layout of `RailgunSmartWallet`, see
//! [`VERIFICATION_KEYS_SLOT`].

use alloy::{
    primitives::{Address, B256, U256, keccak256},
    rpc::types::state::{StateOverride, StateOverridesBuilder},
    sol_types::SolValue,
};

/// Storage slot of `Verifier.verificationKeys` (`mapping(nullifiers => mapping(commitments =>
/// VerifyingKey))`) in RailgunSmartWallet V2, whose layout is RailgunLogic's: Initializable,
/// OwnableUpgradeable, Commitments, TokenBlocklist, then Verifier. Located on the Sepolia
/// deployment by matching `alpha1.x` of the 1×2 key, and the same for every deployment of that
/// bytecode. A new contract version may move it: the override then leaves the keys intact and
/// the estimate fails on the proof, nothing is sent.
pub const VERIFICATION_KEYS_SLOT: u64 = 199;

/// Slot offsets of the G2 elements inside `VerifyingKey`: `string artifactsIPFSHash` (1 slot),
/// `G1Point alpha1` (2), then `beta2`, `gamma2`, `delta2` (4 each), then `G1Point[] ic`.
const G2_FIRST_OFFSET: u64 = 3;
const G2_SLOTS: u64 = 12;

/// Base slot of the verifying key for `nullifiers` × `commitments`.
pub fn verifying_key_slot(nullifiers: usize, commitments: usize) -> U256 {
    let inner =
        keccak256((U256::from(nullifiers), U256::from(VERIFICATION_KEYS_SLOT)).abi_encode());
    U256::from_be_bytes(keccak256((U256::from(commitments), inner).abi_encode()).0)
}

/// The slots of the G2 elements of that key, i.e. what to zero.
pub fn g2_slots(nullifiers: usize, commitments: usize) -> impl Iterator<Item = B256> {
    let base = verifying_key_slot(nullifiers, commitments);
    (G2_FIRST_OFFSET..G2_FIRST_OFFSET + G2_SLOTS)
        .map(move |offset| (base + U256::from(offset)).into())
}

/// The override that makes `railgun_smart_wallet` accept dummy proofs for the circuits of the
/// given sizes (`(nullifiers, commitments)` per operation).
pub fn verifier_state_override(
    railgun_smart_wallet: Address,
    circuits: impl IntoIterator<Item = (usize, usize)>,
) -> StateOverride {
    let mut sizes: Vec<(usize, usize)> = circuits.into_iter().collect();
    sizes.sort_unstable();
    sizes.dedup();
    let zeroed = sizes
        .into_iter()
        .flat_map(|(nullifiers, commitments)| g2_slots(nullifiers, commitments))
        .map(|slot| (slot, B256::ZERO));
    StateOverridesBuilder::default()
        .with_state_diff(railgun_smart_wallet, zeroed)
        .build()
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{address, b256};

    use super::*;

    /// `alpha1.x` of the 1×2 key sits at this base + 1 on Sepolia's RailgunSmartWallet
    /// (`0xeCFC…3fea`), as read with `eth_getStorageAt` and compared with
    /// `getVerificationKey(1, 2)`.
    #[test]
    fn slot_matches_the_sepolia_deployment() {
        assert_eq!(
            verifying_key_slot(1, 2),
            U256::from_be_bytes(
                b256!("0xf5f1dd9ce555de26dd247c9863c8d24a96a342583c4bebe2403ea9b4c3f7c396").0
            )
        );
    }

    #[test]
    fn override_zeroes_twelve_slots_per_circuit_once() {
        let wallet = address!("0xeCFCf3b4eC647c4Ca6D49108b311b7a7C9543fea");
        let overrides = verifier_state_override(wallet, [(1, 2), (2, 3), (1, 2)]);
        let diff = overrides[&wallet].state_diff.as_ref().unwrap();
        assert_eq!(diff.len(), 24);
        assert!(diff.values().all(|v| *v == B256::ZERO));
        let base = verifying_key_slot(1, 2);
        for offset in 3..15u64 {
            assert!(diff.contains_key(&B256::from(base + U256::from(offset))));
        }
        assert!(
            !diff.contains_key(&B256::from(base + U256::from(1))),
            "alpha1 is kept"
        );
        assert!(
            !diff.contains_key(&B256::from(base + U256::from(15))),
            "ic is kept"
        );
    }
}

/// Against a fork of Sepolia: `verify` accepts the dummy proof under the override and refuses
/// it without. Needs `RPC_URL_SEPOLIA` and anvil, skipped otherwise.
#[cfg(all(test, native))]
mod fork_tests {
    use alloy::{
        network::TransactionBuilder,
        node_bindings::Anvil,
        primitives::{Bytes, FixedBytes, U256},
        providers::{Provider, ProviderBuilder},
        rpc::types::TransactionRequest,
        sol_types::SolCall,
    };

    use super::*;
    use crate::{
        abis::railgun::{
            BoundParams, CommitmentCiphertext, CommitmentPreimage, RailgunSmartWallet, Transaction,
            UnshieldType,
        },
        chain_config::ChainConfig,
        circuit::proof::Proof,
    };

    #[tokio::test]
    async fn verifier_accepts_the_dummy_proof_only_under_the_override() {
        let Ok(rpc) = std::env::var("RPC_URL_SEPOLIA") else {
            eprintln!("RPC_URL_SEPOLIA not set, skipping");
            return;
        };
        let anvil = Anvil::new().fork(rpc).try_spawn().unwrap();
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
        let chain = ChainConfig::sepolia();

        // One nullifier, two commitments: the 1×2 circuit. Small public inputs keep them in
        // the scalar field, which `verify` checks before the pairing.
        let ciphertext = || CommitmentCiphertext {
            ciphertext: [FixedBytes::ZERO; 4],
            blindedSenderViewingKey: FixedBytes::ZERO,
            blindedReceiverViewingKey: FixedBytes::ZERO,
            annotationData: Bytes::new(),
            memo: Bytes::new(),
        };
        let transaction = Transaction::new(
            Proof::dummy().into(),
            FixedBytes::from(U256::from(1u8)),
            vec![FixedBytes::from(U256::from(2u8))],
            vec![
                FixedBytes::from(U256::from(3u8)),
                FixedBytes::from(U256::from(4u8)),
            ],
            BoundParams::new(
                0,
                0,
                UnshieldType::NONE,
                chain.id,
                Address::ZERO,
                &[0u8; 32],
                vec![ciphertext(), ciphertext()],
            ),
            CommitmentPreimage::default(),
        );
        let call = RailgunSmartWallet::verifyCall {
            _transaction: transaction,
        };
        let request = TransactionRequest::default()
            .with_to(chain.railgun_smart_wallet)
            .with_input(call.abi_encode());

        let plain = provider.call(request.clone()).await.unwrap();
        let plain = RailgunSmartWallet::verifyCall::abi_decode_returns(&plain).unwrap();
        assert!(!plain, "a dummy proof must not verify on its own");

        let overrides = verifier_state_override(chain.railgun_smart_wallet, [(1, 2)]);
        let overridden = provider.call(request).overrides(overrides).await.unwrap();
        let overridden = RailgunSmartWallet::verifyCall::abi_decode_returns(&overridden).unwrap();
        assert!(overridden, "the override must make the verifier accept it");
    }
}
