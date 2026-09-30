#![doc = include_str!("../README.md")]

pub mod alto;
pub mod anvil;
pub mod entry_point;
pub mod paymaster;
pub mod pool;
pub mod relayer;
pub mod simple_account;

use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ext::AnvilApi},
    signers::local::PrivateKeySigner,
};

pub async fn set_balances(provider: &impl Provider, addresses: &[Address], value: U256) {
    for addr in addresses {
        provider.anvil_set_balance(*addr, value).await.unwrap();
    }
}

pub async fn set_pk_balances(provider: &impl Provider, private_keys: &[&str], value: U256) {
    let addresses: Vec<Address> = private_keys
        .iter()
        .map(|pk| pk.parse::<PrivateKeySigner>().map(|s| s.address()))
        .collect::<Result<_, _>>()
        .unwrap();
    set_balances(provider, &addresses, value).await
}
