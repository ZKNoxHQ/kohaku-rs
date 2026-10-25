//! Railgun deployment.

use alloy::{
    primitives::{Address, Bytes, U256, address},
    providers::{DynProvider, Provider, ext::AnvilApi},
};
use kohaku_railgun::chain_config::ChainConfig;
use serde::Deserialize;

mod sol {
    #![allow(clippy::all)]
    #![allow(clippy::pedantic)]

    use alloy::sol;

    sol!(
        #[sol(rpc, extra_derives(serde::Deserialize))]
        RailgunSmartWallet,
        "fixtures/railgun/smart_wallet.json"
    );
    sol!(
        #[sol(rpc)]
        RelayAdapt,
        "fixtures/railgun/relay_adapt.json"
    );
    sol!(
        #[sol(rpc)]
        WETH9,
        "fixtures/railgun/weth9.json"
    );
}

// The smart wallet bytecode is the mainnet implementation
// (0xD662C4B1F22AcEb0BEaCdf3A493De6f478686A0C), which is linked against the mainnet Poseidon
// libraries. Their runtime code is placed at the same addresses rather than relinking.
const POSEIDON_T3: Address = address!("0xf5fe83643dd42d408c19b938866fa441c6c52563");
const POSEIDON_T4: Address = address!("0xafd3fc0396f793b35e433bbe0e1160329bf0abd3");
const POSEIDON_T3_RUNTIME: &str = include_str!("../fixtures/railgun/poseidon_t3.runtime.hex");
const POSEIDON_T4_RUNTIME: &str = include_str!("../fixtures/railgun/poseidon_t4.runtime.hex");

// Verification keys read from the mainnet smart wallet's `getVerificationKey`.
const VKEYS: &str = include_str!("../fixtures/railgun/vkeys.json");

const FEE_BPS: u16 = 25;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct VKeyFixture {
    nullifiers: u8,
    commitments: u8,
    contract_v_key: sol::RailgunSmartWallet::VerifyingKey,
}

/// Deploys a fresh Railgun smart wallet, relay adapt, and WETH9 to an anvil node.
///
/// Returns a [`ChainConfig`] pointing at the deployed contracts.
///
/// # Errors
/// Returns an error if any contract fails to deploy or initialize.
pub async fn deploy_railgun(provider: DynProvider) -> Result<ChainConfig, anyhow::Error> {
    provider
        .anvil_set_code(POSEIDON_T3, POSEIDON_T3_RUNTIME.trim().parse::<Bytes>()?)
        .await?;
    provider
        .anvil_set_code(POSEIDON_T4, POSEIDON_T4_RUNTIME.trim().parse::<Bytes>()?)
        .await?;

    let receipt = sol::RailgunSmartWallet::deploy_builder(&provider)
        .send()
        .await?
        .get_receipt()
        .await?;
    let deployer = receipt.from;
    let wallet_address = receipt
        .contract_address
        .ok_or_else(|| anyhow::anyhow!("smart wallet deploy returned no contract address"))?;
    let wallet = sol::RailgunSmartWallet::new(wallet_address, &provider);

    wallet
        .initializeRailgunLogic(
            deployer,
            FEE_BPS.try_into()?,
            FEE_BPS.try_into()?,
            U256::from(FEE_BPS),
            deployer,
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    set_verification_keys(&wallet).await?;

    let weth = sol::WETH9::deploy(&provider).await?;
    let relay_adapt = sol::RelayAdapt::deploy(&provider, wallet_address, *weth.address()).await?;

    Ok(ChainConfig::new(
        provider.get_chain_id().await?,
        wallet_address,
        FEE_BPS,
        *relay_adapt.address(),
        *weth.address(),
        0,
        0,
        "",
        "",
        Vec::<String>::new(),
        None,
        None,
    ))
}

async fn set_verification_keys(
    wallet: &sol::RailgunSmartWallet::RailgunSmartWalletInstance<&DynProvider>,
) -> Result<(), anyhow::Error> {
    let vkeys: Vec<VKeyFixture> = serde_json::from_str(VKEYS)?;
    for vkey in vkeys {
        wallet
            .setVerificationKey(
                U256::from(vkey.nullifiers),
                U256::from(vkey.commitments),
                vkey.contract_v_key,
            )
            .send()
            .await?
            .get_receipt()
            .await?;
    }
    Ok(())
}
