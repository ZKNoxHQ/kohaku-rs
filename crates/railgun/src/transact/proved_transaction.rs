use alloy::{
    primitives::{Address, U256},
    sol_types::SolCall,
};
use kohaku_eip_1193::tx_data::TxData;

use crate::{
    abis::{self, railgun::RailgunSmartWallet},
    circuit::inputs::transact_inputs::TransactCircuitInputs,
    note::operation::Operation,
    transact::relay_adapt::RelayAction,
};

/// A transaction that has been proven for railgun.
pub struct ProvedTx {
    /// Transaction data to execute this transaction on-chain in railgun.
    pub tx_data: TxData,
    /// The operations included in this transaction alongside their proof data.
    pub proved_operations: Vec<ProvedOperation>,
    /// Set when `tx_data` calls `RelayAdapt.relay` instead of `RailgunSmartWallet.transact`.
    pub relay: Option<RelayAction>,
}

/// A single proved operation.
#[derive(Clone)]
pub struct ProvedOperation {
    pub inner: Operation,
    pub circuit_inputs: TransactCircuitInputs,
    pub transaction: abis::railgun::Transaction,
}

impl ProvedTx {
    pub fn new(railgun_smart_wallet: Address, operations: Vec<ProvedOperation>) -> Self {
        let transactions = operations.iter().map(|op| op.transaction.clone()).collect();
        let calldata = RailgunSmartWallet::transactCall {
            _transactions: transactions,
        }
        .abi_encode();
        let tx_data = TxData::new(railgun_smart_wallet, calldata.into(), U256::ZERO);
        Self {
            tx_data,
            proved_operations: operations,
            relay: None,
        }
    }

    /// Packages operations built with [`super::TransactionBuilder::relay`] as a call to
    /// `RelayAdapt.relay(transactions, actionData)`. The operations must carry the adapt params
    /// of `action`, which the builder guarantees.
    pub fn relay(operations: Vec<ProvedOperation>, action: RelayAction) -> Self {
        let transactions = operations.iter().map(|op| op.transaction.clone()).collect();
        let calldata = action.relay_calldata(transactions);
        let tx_data = TxData::new(action.relay_adapt, calldata, U256::ZERO);
        Self {
            tx_data,
            proved_operations: operations,
            relay: Some(action),
        }
    }
}

impl ProvedOperation {
    pub fn new(
        operation: Operation,
        circuit_inputs: TransactCircuitInputs,
        transaction: abis::railgun::Transaction,
    ) -> Self {
        Self {
            inner: operation,
            circuit_inputs,
            transaction,
        }
    }
}
