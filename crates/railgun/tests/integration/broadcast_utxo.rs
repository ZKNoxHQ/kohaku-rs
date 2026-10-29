use std::{sync::Arc, time::Duration};

use alloy::{
    node_bindings::Anvil,
    primitives::{Address, U256, b256},
    providers::{Provider, ProviderBuilder},
    sol,
};
use kohaku_fork_kit::{
    alto::AltoBuilder,
    entry_point::deploy_entry_point,
    paymaster::{deploy_paymaster, deploy_railgun_fee_adapter},
    railgun::deploy_railgun,
    simple_account::{SIMPLE_7702_ACCOUNT_IMPLEMENTATION_V08, deploy_simple_account},
};
use kohaku_railgun::{
    account::signer::{PrivateKeySigner, RailgunSigner},
    builder::RailgunBuilder,
    caip::AssetId,
    indexer::syncer::RpcSyncer,
};
use kohaku_userop_kit::{
    bundler::Bundler,
    smart_account::simple_smart_account::{self, SimpleSmartAccount},
};
use tracing_subscriber::EnvFilter;

sol! {
    #[sol(rpc)]
    contract WETH {
        function balanceOf(address account) external view returns (uint256);
        function withdraw(uint256 amount) external;
    }
}

const SHIELD_AMOUNT: u128 = 10_u128.pow(18);
const UNSHIELD_AMOUNT: u128 = 10_u128.pow(15);
const UNWRAP_AMOUNT: u128 = 6 * 10_u128.pow(14);
const PAYMASTER_MASTER_PUBLIC_KEY: alloy::primitives::B256 =
    b256!("19acdde26147205d58fd7768be7c011f08a147ef86e6b70968d09c81cef74b13");

#[tokio::test]
#[ignore = "requires anvil, alto and release-mode proving"]
#[expect(clippy::too_many_lines, reason = "keep integration setup inline")]
async fn test_broadcast_utxo() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_test_writer()
        .try_init()
        .ok();

    let anvil = Anvil::new().try_spawn()?;
    let provider = ProviderBuilder::new()
        .wallet(anvil.wallet().expect("anvil supplies a disposable wallet"))
        .connect_http(anvil.endpoint_url())
        .erased();
    let entrypoint = deploy_entry_point(&provider).await?;
    deploy_simple_account(&provider).await?;
    let mut chain = deploy_railgun(provider.clone()).await?;
    let paymaster = deploy_paymaster(
        provider.clone(),
        entrypoint,
        Address::ZERO,
        chain.wrapped_base_token,
    )
    .await?;
    let adapter = deploy_railgun_fee_adapter(
        provider.clone(),
        paymaster,
        chain.railgun_smart_wallet,
        PAYMASTER_MASTER_PUBLIC_KEY,
    )
    .await?;
    chain.privacy_paymaster = Some(paymaster);
    chain.railgun_fee_adapter = Some(adapter);

    let executor = alloy::signers::local::PrivateKeySigner::random();
    let utility = alloy::signers::local::PrivateKeySigner::random();
    let alto = AltoBuilder::new(
        anvil.endpoint(),
        entrypoint,
        format!("{:#x}", executor.to_bytes()),
        format!("{:#x}", utility.to_bytes()),
    )
    .prefund(&provider)
    .await?
    .spawn()
    .await?;

    let syncer = Arc::new(
        RpcSyncer::new(chain.clone(), provider.clone())
            .with_batch_size(1000)
            .with_batch_delay(Duration::ZERO),
    );
    let mut railgun = RailgunBuilder::new(chain.clone(), provider.clone())
        .with_utxo_syncer(syncer)
        .build()
        .await?;
    let railgun_signer = PrivateKeySigner::new_evm(rand::random(), rand::random(), chain.id);
    railgun.register(railgun_signer.clone()).await?;
    for tx in railgun
        .shield()
        .shield_native(railgun_signer.address(), SHIELD_AMOUNT)
        .build(&mut rand::rng())?
    {
        assert!(
            provider
                .send_transaction(tx)
                .await?
                .get_receipt()
                .await?
                .status()
        );
    }
    railgun.sync().await?;
    let weth = AssetId::Erc20(chain.wrapped_base_token);
    let initial_private = railgun
        .balance(railgun_signer.address())
        .await
        .into_iter()
        .find(|entry| entry.asset == weth)
        .expect("shielded WETH")
        .amount;
    assert_eq!(initial_private, SHIELD_AMOUNT - SHIELD_AMOUNT * 25 / 10_000);

    // The recipient starts without gas ETH: the private fee note pays the paymaster.
    let owner = alloy::signers::local::PrivateKeySigner::random();
    let smart_account =
        SimpleSmartAccount::new(owner.address(), chain.id, Arc::new(provider.clone()));
    let weth_contract = WETH::new(chain.wrapped_base_token, provider.clone());
    let native_before = provider.get_balance(owner.address()).await?;
    let tokens_before = weth_contract.balanceOf(owner.address()).call().await?;
    assert_eq!(native_before, U256::ZERO);
    assert_eq!(tokens_before, U256::ZERO);
    let spends = railgun
        .unshield_amount(
            railgun_signer.clone(),
            owner.address(),
            weth,
            UNSHIELD_AMOUNT,
            &mut rand::rng(),
        )
        .await?;
    let calls = vec![simple_smart_account::Call {
        target: chain.wrapped_base_token,
        value: U256::ZERO,
        data: weth_contract
            .withdraw(U256::from(UNWRAP_AMOUNT))
            .calldata()
            .clone(),
    }];
    // Estimate dummy proofs with temporary state overrides, then generate one genuine proof.
    let gas = railgun
        .simulate_gas_limits(
            &spends,
            &*alto,
            &smart_account,
            railgun_signer.clone(),
            chain.wrapped_base_token,
            &calls,
            &mut rand::rng(),
        )
        .await?;
    let (signable, report) = railgun
        .prepare_userop_single_proof(
            &spends,
            &*alto,
            &smart_account,
            railgun_signer.clone(),
            chain.wrapped_base_token,
            calls,
            gas,
            &mut rand::rng(),
        )
        .await?;
    assert!(report.fee > 0 && report.fee < initial_private - UNSHIELD_AMOUNT);
    assert_eq!(signable.user_op.paymaster, Some(paymaster));
    assert_eq!(
        signable.total_gas_limit() * signable.user_op.max_fee_per_gas,
        report.fee
    );

    let signed = signable.sign(&owner).await?;
    let hash = alto.send_user_operation(&signed).await?;
    let receipt = alto.wait_for_receipt(hash).await?;
    assert!(receipt.success);

    railgun.sync().await?;
    let final_private = railgun
        .balance(railgun_signer.address())
        .await
        .into_iter()
        .find(|entry| entry.asset == weth)
        .expect("private change")
        .amount;
    assert_eq!(
        final_private + UNSHIELD_AMOUNT + report.fee,
        initial_private
    );
    let net_unshield =
        UNSHIELD_AMOUNT - UNSHIELD_AMOUNT * u128::from(chain.unshield_fee_bps) / 10_000;
    assert_eq!(
        weth_contract.balanceOf(owner.address()).call().await?,
        tokens_before + U256::from(net_unshield - UNWRAP_AMOUNT)
    );
    assert_eq!(
        provider.get_balance(owner.address()).await?,
        native_before + U256::from(UNWRAP_AMOUNT)
    );
    let code = provider.get_code_at(owner.address()).await?;
    assert_eq!(code.len(), 23, "7702 delegation was not installed");
    assert_eq!(&code[..3], &[0xef, 0x01, 0x00]);
    assert_eq!(
        &code[3..],
        SIMPLE_7702_ACCOUNT_IMPLEMENTATION_V08.as_slice()
    );
    Ok(())
}
