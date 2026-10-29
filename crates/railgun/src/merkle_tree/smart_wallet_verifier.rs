use alloy::{
    primitives::{Address, U256},
    providers::{DynProvider, Provider},
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};

use crate::{
    abis::railgun::RailgunSmartWallet,
    merkle_tree::{MerkleRoot, verifier::MerkleTreeVerifier},
};

/// Verifies UTXO Merkle roots against the deployed `RailgunSmartWallet` contract.
pub struct SmartWalletUtxoVerifier {
    address: Address,
    provider: DynProvider,
}

impl SmartWalletUtxoVerifier {
    pub fn new(address: Address, provider: DynProvider) -> Self {
        Self { address, provider }
    }
}

#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
impl MerkleTreeVerifier for SmartWalletUtxoVerifier {
    async fn verify_root(
        &self,
        tree_number: u32,
        _tree_index: u32,
        root: MerkleRoot,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync + 'static>> {
        let root: U256 = root.into();
        let call = RailgunSmartWallet::rootHistoryCall {
            treeNumber: U256::from(tree_number),
            root: root.into(),
        };
        let request = TransactionRequest::default()
            .to(self.address)
            .input(call.abi_encode().into());
        let returned = self.provider.call(request).await?;
        Ok(RailgunSmartWallet::rootHistoryCall::abi_decode_returns(
            &returned,
        )?)
    }
}
