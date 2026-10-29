//! 4337 [PrivacyPaymaster](https://github.com/Robert-MacWha/privacy-paymaster) deployment and configuration.

use alloy::{
    primitives::{Address, B256, U256},
    providers::DynProvider,
};

mod sol {
    use alloy::sol;

    sol!(
        #[sol(rpc)]
        PrivacyPaymaster,
        "fixtures/privacy_paymaster.json"
    );
    sol!(
        #[sol(rpc)]
        TornadoFeeAdapter,
        "fixtures/tornado_fee_adapter.json"
    );
    // https://etherscan.io/address/0xD73A1dE75B1D4A3aF1D9f664fBcFA327bD2Cd59d#code
    sol!(
        #[sol(rpc)]
        RailgunFeeAdapter,
        "fixtures/railgun/fee_adapter.json"
    );
}

const PAYMASTER_STAKE_WEI: u128 = 10_u128.pow(17); // 0.1 ETH
const PAYMASTER_DEPOSIT_WEI: u128 = 10_u128.pow(17); // 0.1 ETH
const PAYMASTER_UNSTAKE_DELAY_SEC: u32 = 3600;
const PAYMASTER_TWAP_PERIOD_SEC: u32 = 3600;

/// Deploys and stakes a new `PrivacyPaymaster`.
///
/// Returns the address of the deployed paymaster.
///
/// # Errors
/// Returns an error if the deploy, deposit, or stake transactions fail.
pub async fn deploy_paymaster(
    provider: DynProvider,
    entrypoint: Address,
    factory: Address,
    weth: Address,
) -> Result<Address, anyhow::Error> {
    let paymaster = sol::PrivacyPaymaster::deploy(
        &provider,
        entrypoint,
        factory,
        weth,
        PAYMASTER_TWAP_PERIOD_SEC,
    )
    .await?;

    paymaster
        .deposit()
        .value(U256::from(PAYMASTER_DEPOSIT_WEI))
        .send()
        .await?
        .get_receipt()
        .await?;
    paymaster
        .addStake(PAYMASTER_UNSTAKE_DELAY_SEC)
        .value(U256::from(PAYMASTER_STAKE_WEI))
        .send()
        .await?
        .get_receipt()
        .await?;

    Ok(*paymaster.address())
}

/// Deploys a new `TornadoFeeAdapter` for `pool_address`.
///
/// Automatically approves on `paymaster`. Returns the adapter's address.
///
/// # Errors
/// Returns an error if the deploy or approval transactions fail.
pub async fn deploy_fee_adapter(
    provider: DynProvider,
    paymaster: Address,
    pool_address: Address,
) -> Result<Address, anyhow::Error> {
    let adapter = sol::TornadoFeeAdapter::deploy(&provider, pool_address).await?;
    sol::PrivacyPaymaster::new(paymaster, &provider)
        .setApprovedAdapter(*adapter.address(), true)
        .send()
        .await?
        .get_receipt()
        .await?;

    Ok(*adapter.address())
}

/// Deploys and approves a `RailgunFeeAdapter` for a local smart wallet and paymaster key.
///
/// # Errors
/// Returns an error if deployment or paymaster approval fails.
pub async fn deploy_railgun_fee_adapter(
    provider: DynProvider,
    paymaster: Address,
    smart_wallet: Address,
    master_public_key: B256,
) -> Result<Address, anyhow::Error> {
    let adapter =
        sol::RailgunFeeAdapter::deploy(&provider, smart_wallet, master_public_key).await?;
    sol::PrivacyPaymaster::new(paymaster, &provider)
        .setApprovedAdapter(*adapter.address(), true)
        .send()
        .await?
        .get_receipt()
        .await?;
    Ok(*adapter.address())
}
