//! The validation probe against a real EVM. Needs anvil: set `ANVIL=/path/to/anvil`, otherwise
//! the test is skipped. The account and paymaster are mocks (tests/fixtures/Mocks.sol) with the
//! two properties that matter: they only accept the EntryPoint as caller, and the paymaster only
//! accepts a "proof" when tx.origin is the bypass address, as the Railgun verifier does.

use std::{process::Stdio, time::Duration};

use alloy::{
    network::TransactionBuilder,
    primitives::{Address, Bytes, U256, address},
    providers::{Provider, ProviderBuilder},
    rpc::types::{
        TransactionRequest,
        state::{AccountOverride, StateOverride},
    },
    sol,
    sol_types::{SolCall, eip712_domain},
};
use kohaku_userop_kit::{
    builder::UserOperationBuilder,
    entry_point::ENTRY_POINT_08,
    user_operation::UserOperationGasEstimate,
    validation_probe::{self as probe, ProbeError},
};

const BYPASS: Address = address!("0x000000000000000000000000000000000000dEaD");

sol! {
    function run(address paymaster, address to) external;
}

async fn deploy(provider: &impl Provider, from: Address, hex_code: &str) -> Address {
    let code: Bytes = hex_code.trim().parse().unwrap();
    let receipt = provider
        .send_transaction(TransactionRequest::default().from(from).with_deploy_code(code))
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();
    receipt.contract_address.unwrap()
}

#[tokio::test]
async fn probe_measures_each_phase_from_the_bypass_origin() {
    let Ok(anvil) = std::env::var("ANVIL") else {
        eprintln!("ANVIL not set, skipping");
        return;
    };
    let port = 18_545;
    let mut node = std::process::Command::new(anvil)
        .args(["--port", &port.to_string(), "--silent"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;

    let provider = ProviderBuilder::new()
        .connect(&format!("http://127.0.0.1:{port}"))
        .await
        .unwrap();
    let deployer = provider.get_accounts().await.unwrap()[0];
    let account = deploy(&provider, deployer, include_str!("fixtures/MockAccount.bin")).await;
    let paymaster = deploy(&provider, deployer, include_str!("fixtures/MockPaymaster.bin")).await;

    let fresh = address!("0x00000000000000000000000000000000000f4e54"); // never seen on this chain
    let user_op = |with_call: bool| {
        let mut builder = UserOperationBuilder::<()>::new(
            account,
            ENTRY_POINT_08,
            eip712_domain! { name: "ERC4337", version: "1", chain_id: 31337, verifying_contract: ENTRY_POINT_08, },
        )
        .with_paymaster_and_data(paymaster, vec![1, 2, 3].into())
        .with_gas(UserOperationGasEstimate {
            pre_verification_gas: 1,
            verification_gas_limit: 1,
            call_gas_limit: 1,
            paymaster_verification_gas_limit: Some(1),
            paymaster_post_op_gas_limit: Some(1),
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
        });
        if with_call {
            builder = builder.with_calldata(runCall { paymaster, to: fresh }.abi_encode().into());
        }
        builder.build()
    };

    let run = |op: kohaku_userop_kit::signable_user_operation::SignableUserOperation,
               max_cost: u64,
               origin: Address| {
        let provider = &provider;
        async move {
            let request = probe::request(&op, U256::from(max_cost));
            assert!(request.copy_code_from.is_none());
            let mut overrides = StateOverride::default();
            for (address, code) in request.code_overrides {
                overrides.insert(address, AccountOverride::default().with_code(code));
            }
            // The mock account forwards 1 wei.
            overrides.insert(account, AccountOverride::default().with_balance(U256::from(10u64)));
            let answer = provider
                .call(
                    TransactionRequest::default()
                        .from(origin)
                        .to(request.to)
                        .input(request.data.into()),
                )
                .overrides(overrides)
                .await
                .unwrap();
            probe::decode(&answer, !op.user_op.call_data.is_empty())
        }
    };

    // All four phases run, in order: the account's call needs the paymaster's state change.
    let gas = run(user_op(true), 1_000, BYPASS).await.unwrap();
    assert!(gas.account_validation > 5_000, "{gas:?}");
    assert!(gas.paymaster_validation > gas.account_validation * 4, "{gas:?}");
    eprintln!("probe on anvil: {gas:?}");
    assert!(gas.call > 500, "{gas:?}");
    // The value transfer to a new account needs 34000 gas at hand: the limit found by trial is
    // well above the gas used, which is what a bundler reports too.
    assert!(gas.call_limit >= 34_000, "{gas:?}");
    assert!(gas.call_limit > gas.call, "{gas:?}");
    assert!(gas.call_limit < gas.call * 4, "{gas:?}");
    assert!(gas.post_op_called && gas.post_op > 20_000, "{gas:?}");

    // No execution calldata, and a paymaster that returns no context: nothing else is called.
    let gas = run(user_op(false), 1, BYPASS).await.unwrap();
    assert_eq!((gas.call, gas.call_limit, gas.post_op, gas.post_op_called), (0, 0, 0, false));

    // From any other origin the paymaster rejects the dummy proof: the probe says why.
    match run(user_op(false), 1_000, deployer).await {
        Err(ProbeError::PaymasterValidation(reason)) => assert_eq!(reason, "paymaster: proof rejected"),
        other => panic!("{other:?}"),
    }
    match run(user_op(false), 666, BYPASS).await {
        Err(ProbeError::PaymasterValidation(reason)) => assert_eq!(reason, "paymaster: insufficient fee"),
        other => panic!("{other:?}"),
    }

    // The probe is an eth_call: nothing it did is on-chain.
    sol! { function paid() external view returns (bool); }
    let paid = provider
        .call(TransactionRequest::default().to(paymaster).input(paidCall {}.abi_encode().into()))
        .await
        .unwrap();
    assert_eq!(U256::from_be_slice(&paid), U256::ZERO);

    node.kill().ok();
}
