//! Because Railgun's transaction-within-transaction language is confusing, I'm
//! setting some ground rules.
//!
//! A "Note" is an already-on-chain note, which can be used as an input to an Operation.
//!
//! A "Operation" means a single railgun transaction (IE `RailgunSmartWallet.Transaction` object).
//!  - An operation can have many input notes, but they must all be on the same tree and held by the
//!    same address.
//!  - An operation may have many output notes, which can be to different addresses and on different
//!    trees.
//!  - An operation may only have one unshield note, since the `RailgunSmartWallet.Transaction`
//!    struct only
//!
//! A "Transaction" means an EVM transaction.
//!  - A transaction can have many operations across many trees and addresses.

use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use alloy::primitives::{Address, B256, U256};
use rand::{CryptoRng, RngExt};
use thiserror::Error;
use tracing::info;

use crate::{
    abis,
    account::{address::RailgunAddress, signer::RailgunSigner},
    caip::AssetId,
    circuit::{
        groth16_prover::Groth16Prover,
        inputs::transact_inputs::{TransactCircuitInputs, TransactCircuitInputsError},
        proof::Proof,
    },
    merkle_tree::UtxoMerkleTree,
    note::{
        Note,
        encrypt::{EncryptError, NoteEncryption},
        operation::{Operation, OperationVerificationError},
        transfer::TransferNote,
        unshield::UnshieldNote,
        utxo::UtxoNote,
    },
    transact::proved_transaction::ProvedOperation,
};

/// Derives the adapt params from the nullifiers of the built operations, one list per
/// operation in transaction order. See [`TransactionBuilder::adapt_with`].
pub type AdaptParamsFn = Arc<dyn Fn(&[Vec<B256>]) -> [u8; 32] + Send + Sync>;

/// Basic builder for constructing railgun transactions. Transactions are sets
/// of shielded operations (transfers and unshield) that are proved together
/// and can be executed in a single on-chain transaction.
#[derive(Clone, Default)]
pub struct TransactionBuilder {
    intents: Vec<Intent>,

    //? Used to track unshield intents to ensure we don't have multiple unshields
    //? for the same from / asset.
    unshields: HashSet<(RailgunAddress, AssetId)>,

    adapt_contract: Option<Address>,
    adapt_params: Option<[u8; 32]>,
    /// Adapt contract with params derived from the built operations, see [`Self::adapt_with`].
    adapt_with: Option<(Address, AdaptParamsFn)>,
    min_gas_price: u128,
    /// Change notes go back to their signer under [`NoteEncryption::HybridPq`] with its own
    /// KEM key even when no transfer is hybrid, see [`Self::with_hybrid_change`].
    hybrid_change: bool,
}

#[derive(Debug, Error)]
pub enum TransactionBuilderError {
    #[error(
        "Multiple unshield operations from the same address and asset are not supported: from {from}, asset {asset}"
    )]
    MultipleUnshields {
        from: RailgunAddress,
        asset: AssetId,
    },
    #[error("Insufficient balance for intent with from {from}, asset {asset}, value {value}")]
    InsufficientBalance {
        from: RailgunAddress,
        asset: AssetId,
        value: u128,
    },
    #[error("adapt() and adapt_with() both set the adapt contract; use one of them")]
    ConflictingAdapt,
    #[error("A transaction can only carry one broadcaster fee")]
    MultipleBroadcasterFees,
    #[error(
        "The broadcaster fee of {value} cannot be paid from a single UTXO tree, it must be one note"
    )]
    BroadcasterFeeSplit { value: u128 },
    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptError),
    #[error("Prover error: {0}")]
    Prover(Box<dyn std::error::Error + Send + Sync>),
    #[error("Missing tree for number {0}")]
    MissingTree(u32),
    #[error("No input notes")]
    NoInputNotes,
    #[error("Transact circuit input error: {0}")]
    TransactCircuitInput(#[from] TransactCircuitInputsError),
    #[error("Operation verification error: {0}")]
    OperationVerification(#[from] OperationVerificationError),
    #[error("Hybrid change notes were requested, but the signer of {from} has no ML-KEM key")]
    ChangeNeedsKemKey { from: RailgunAddress },
}

#[derive(Clone)]
struct Intent {
    pub from: Arc<dyn RailgunSigner>,
    pub asset: AssetId,
    pub value: u128,
    pub kind: IntentKind,
    /// The note of this intent must be the first commitment of the first operation.
    pub pinned_first: bool,
}

#[derive(Clone)]
enum IntentKind {
    Transfer {
        to: RailgunAddress,
        memo: String,
        encryption: NoteEncryption,
        hide_sender: bool,
    },
    Unshield {
        to: Address,
    },
}

impl TransactionBuilder {
    pub fn new() -> Self {
        Self {
            intents: Vec::new(),
            unshields: HashSet::new(),
            adapt_contract: None,
            adapt_params: None,
            adapt_with: None,
            min_gas_price: 0,
            hybrid_change: false,
        }
    }
}

impl TransactionBuilder {
    /// Adds a transfer operation to this transaction, encrypted the way every Railgun wallet
    /// reads ([`NoteEncryption::Legacy`]).
    pub fn transfer(
        self,
        from: Arc<dyn RailgunSigner>,
        to: RailgunAddress,
        asset: AssetId,
        value: u128,
        memo: &str,
    ) -> Self {
        self.transfer_with_encryption(from, to, asset, value, memo, NoteEncryption::Legacy)
    }

    /// Adds a transfer operation whose note is encrypted with `encryption`, for instance
    /// [`NoteEncryption::HybridPq`] with the receiver's published KEM key.
    pub fn transfer_with_encryption(
        self,
        from: Arc<dyn RailgunSigner>,
        to: RailgunAddress,
        asset: AssetId,
        value: u128,
        memo: &str,
        encryption: NoteEncryption,
    ) -> Self {
        self.transfer_with(from, to, asset, value, memo, encryption, false)
    }

    /// Adds a transfer operation with every option: the encryption scheme, and whether the
    /// sender is hidden from whoever opens the note ([`TransferNote::hide_sender`]).
    #[allow(clippy::too_many_arguments)]
    pub fn transfer_with(
        mut self,
        from: Arc<dyn RailgunSigner>,
        to: RailgunAddress,
        asset: AssetId,
        value: u128,
        memo: &str,
        encryption: NoteEncryption,
        hide_sender: bool,
    ) -> Self {
        self.intents.push(Intent {
            from,
            asset,
            value,
            kind: IntentKind::Transfer {
                to,
                memo: memo.to_string(),
                encryption,
                hide_sender,
            },
            pinned_first: false,
        });
        self
    }

    /// Adds the fee note of a Railgun broadcaster.
    ///
    /// Broadcasters only look at `transactions[0].commitments[0]`, so unlike [`Self::transfer`]
    /// this note is guaranteed to come first whatever the other intents are. The fee has to fit
    /// in the notes of a single UTXO tree.
    pub fn broadcaster_fee(
        mut self,
        from: Arc<dyn RailgunSigner>,
        to: RailgunAddress,
        asset: AssetId,
        value: u128,
    ) -> Result<Self, TransactionBuilderError> {
        if self.intents.iter().any(|i| i.pinned_first) {
            return Err(TransactionBuilderError::MultipleBroadcasterFees);
        }
        self.intents.push(Intent {
            from,
            asset,
            value,
            kind: IntentKind::Transfer {
                to,
                memo: String::new(),
                encryption: NoteEncryption::Legacy,
                // Broadcasters verify the fee note, they have no use for who paid it.
                hide_sender: true,
            },
            pinned_first: true,
        });
        Ok(self)
    }

    /// Sets `BoundParams.minGasPrice`. The Railgun contract rejects the transaction when
    /// `tx.gasprice` is lower, which is how a broadcaster is held to the price the fee was
    /// computed for. Leave at 0 (the default) for any other submitter, in particular ERC-4337
    /// bundlers, whose gas price is not known when the proof is made.
    pub fn min_gas_price(mut self, wei: u128) -> Self {
        self.min_gas_price = wei;
        self
    }

    /// Encrypts the change notes with [`NoteEncryption::HybridPq`] to their signer's own KEM
    /// key even when no transfer is hybrid. Off by default, so that wallets without the key
    /// (legacy wallets on the same seed) keep seeing the change of legacy transactions.
    ///
    /// Change notes are hybrid regardless whenever a transfer of the transaction is: a legacy
    /// change note next to a hybrid output would let a quantum attacker unblind its receiver,
    /// the sender, and so deanonymise the whole transaction. In both cases building fails if a
    /// signer has no KEM key: the choice is never downgraded silently.
    pub fn with_hybrid_change(mut self) -> Self {
        self.hybrid_change = true;
        self
    }

    /// Adds an unshield operation to this transaction.
    pub fn unshield(
        mut self,
        from: Arc<dyn RailgunSigner>,
        to: Address,
        asset: AssetId,
        value: u128,
    ) -> Result<Self, TransactionBuilderError> {
        if self.unshields.contains(&(from.address(), asset)) {
            return Err(TransactionBuilderError::MultipleUnshields {
                from: from.address(),
                asset,
            });
        }
        self.unshields.insert((from.address(), asset));

        self.intents.push(Intent {
            from,
            asset,
            value,
            kind: IntentKind::Unshield { to },
            pinned_first: false,
        });
        Ok(self)
    }

    /// Sets the adapt contract and parameters for this transaction.
    pub fn adapt(mut self, contract: Address, params: [u8; 32]) -> Self {
        self.adapt_contract = Some(contract);
        self.adapt_params = Some(params);
        self
    }

    /// Sets the adapt contract, with adapt params computed from the nullifiers of the
    /// operations once their input notes are chosen, before proving.
    ///
    /// For adapt contracts that bind the transaction they run in, such as Railgun's RelayAdapt
    /// (`adaptParams = keccak256(abi.encode(nullifiers, transactions.length, actionData))`):
    /// the nullifiers are only known at build time, so [`Self::adapt`] cannot be used there.
    pub fn adapt_with(
        mut self,
        contract: Address,
        params: impl Fn(&[Vec<B256>]) -> [u8; 32] + Send + Sync + 'static,
    ) -> Self {
        self.adapt_with = Some((contract, Arc::new(params)));
        self
    }

    /// Builds and proves a set of operations for railgun, without packaging into a transaction.
    pub(crate) async fn build(
        &self,
        prover: &Groth16Prover,
        chain_id: u64,
        in_notes: &[UtxoNote],
        utxo_trees: &BTreeMap<u32, UtxoMerkleTree>,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<ProvedOperation>, TransactionBuilderError> {
        let operations = self.operations(in_notes, rng)?;
        let proved = prove_operations(Some(prover), utxo_trees, chain_id, &operations, rng).await?;
        Ok(proved)
    }

    /// Same as [`Self::build`] with an all-zero proof instead of a real one.
    ///
    /// The result has the exact calldata shape of the real transaction and is only good for gas
    /// estimation with `from` (or `tx.origin`) set to the Railgun verification bypass address.
    /// The signer is never asked to sign. Note randomness differs from a later [`Self::build`],
    /// which does not change the gas used.
    pub(crate) async fn build_dummy(
        &self,
        chain_id: u64,
        in_notes: &[UtxoNote],
        utxo_trees: &BTreeMap<u32, UtxoMerkleTree>,
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<ProvedOperation>, TransactionBuilderError> {
        let operations = self.operations(in_notes, rng)?;
        prove_operations(None, utxo_trees, chain_id, &operations, rng).await
    }

    fn operations(
        &self,
        in_notes: &[UtxoNote],
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<Operation>, TransactionBuilderError> {
        let hybrid_change = self.hybrid_change
            || self.intents.iter().any(|intent| {
                matches!(
                    intent.kind,
                    IntentKind::Transfer {
                        encryption: NoteEncryption::HybridPq { .. },
                        ..
                    }
                )
            });
        let groups = self.group_intents();
        let mut operations = build_groups(in_notes, groups, hybrid_change, rng)?;

        let (adapt_contract, adapt_params) = match &self.adapt_with {
            Some((contract, params)) => {
                if self.adapt_contract.is_some() || self.adapt_params.is_some() {
                    return Err(TransactionBuilderError::ConflictingAdapt);
                }
                // Nullifiers are fixed once the input notes are chosen, before proving, so the
                // params bound here are exactly what the adapt contract can recompute on-chain.
                let nullifiers: Vec<Vec<B256>> = operations
                    .iter()
                    .map(|op| op.in_notes().iter().map(|n| n.nullifier.into()).collect())
                    .collect();
                (Some(*contract), Some(params(&nullifiers)))
            }
            None => (self.adapt_contract, self.adapt_params),
        };

        for op in &mut operations {
            op.adapt_contract = adapt_contract;
            op.adapt_params = adapt_params;
            op.min_gas_price = self.min_gas_price;
            op.verify()?;
        }
        Ok(operations)
    }

    /// Group intents with the following rules:
    ///
    /// 1. Each group has a single asset.
    /// 2. Each group has a single signer.
    /// 3. Each group has at most one unshield.
    fn group_intents(&self) -> BTreeMap<(RailgunAddress, AssetId), Vec<Intent>> {
        let mut groups = BTreeMap::new();
        for intent in &self.intents {
            groups
                .entry((intent.from.address(), intent.asset))
                .or_insert_with(Vec::new)
                .push(intent.clone());
        }

        groups
    }
}

/// Build the operations for each group of intents.
fn build_groups(
    in_notes: &[UtxoNote],
    groups: BTreeMap<(RailgunAddress, AssetId), Vec<Intent>>,
    hybrid_change: bool,
    rng: &mut impl CryptoRng,
) -> Result<Vec<Operation>, TransactionBuilderError> {
    let mut operations = Vec::new();
    for ((from, asset), intents) in groups {
        let pinned = intents.iter().any(|i| i.pinned_first);
        let ops = build_group(in_notes, from, asset, intents, hybrid_change, rng)?;
        if pinned {
            // The group paying the broadcaster fee goes first, its fee operation leading.
            operations.splice(0..0, ops);
        } else {
            operations.extend(ops);
        }
    }
    Ok(operations)
}

/// Build the operations for a single group of intents.
fn build_group(
    in_notes: &[UtxoNote],
    from: RailgunAddress,
    asset: AssetId,
    mut intents: Vec<Intent>,
    hybrid_change: bool,
    rng: &mut impl CryptoRng,
) -> Result<Vec<Operation>, TransactionBuilderError> {
    // Sort intents smallest to largest. Helps to ensure small intents don't
    // ever need to span across multiple trees.
    // A pinned intent (broadcaster fee) goes first so its note is the first commitment. The sort
    // is stable and the key is constant without a pinned intent, so the default order is
    // unchanged.
    intents.sort_by(|a, b| (!a.pinned_first, a.value).cmp(&(!b.pinned_first, b.value)));

    // Filter notes for this asset and signer, and group by tree number.
    let tree_number = in_notes
        .iter()
        .filter(|n| n.asset == asset && n.viewing_pubkey == from.viewing_pubkey())
        .fold(BTreeMap::new(), |mut acc, n| {
            acc.entry(n.tree_number).or_insert_with(Vec::new).push(n);
            acc
        });

    let mut balances: BTreeMap<u32, u128> = tree_number
        .iter()
        .map(|(tree_number, notes)| {
            let balance = notes.iter().map(|n| n.value()).sum();
            (*tree_number, balance)
        })
        .collect();

    // Fit intents to trees.
    let mut operations = BTreeMap::new();
    let mut pinned_tree = None;
    for intent in intents {
        //? Try single tree first (oldest sufficient).
        let single = balances
            .iter()
            .find(|&(_, bal)| bal >= &intent.value)
            .map(|(&t, _)| t);

        if let Some(tree) = single {
            *balances.get_mut(&tree).unwrap() -= intent.value;
            if intent.pinned_first {
                pinned_tree = Some(tree);
            }
            insert_operation(&mut operations, tree, intent, rng);
            continue;
        }

        if intent.pinned_first {
            return Err(TransactionBuilderError::BroadcasterFeeSplit {
                value: intent.value,
            });
        }

        split_intent(from, asset, intent, &mut balances, &mut operations, rng)?;
    }

    // Add in notes to operations
    for (tree, op) in operations.iter_mut() {
        let Some(notes) = tree_number.get(tree) else {
            debug_assert!(false, "Tree {} should exist in tree_number", tree);
            continue;
        };

        let selected = select_notes(notes, op.out_value());
        for note in selected {
            op.add_in_note(note.clone());
        }
        add_change_note(op, asset, hybrid_change, rng)?;
    }

    let mut operations: Vec<Operation> = operations.into_values().collect();
    if let Some(tree) = pinned_tree {
        // Stable: only the operation holding the pinned note moves, to the front.
        operations.sort_by_key(|op| op.utxo_tree_number != tree);
    }
    Ok(operations)
}

/// Helper for fitting an intent to multiple trees when it can't fit on a single tree.
fn split_intent(
    from: RailgunAddress,
    asset: AssetId,
    intent: Intent,
    balances: &mut BTreeMap<u32, u128>,
    operations: &mut BTreeMap<u32, Operation>,
    rng: &mut impl CryptoRng,
) -> Result<(), TransactionBuilderError> {
    let mut remaining = intent.value;
    let trees: Vec<u32> = balances.keys().copied().collect();
    for tree in trees {
        if remaining == 0 {
            break;
        }

        let available = *balances.get(&tree).unwrap();
        if available == 0 {
            continue;
        }

        let take = remaining.min(available);
        *balances.get_mut(&tree).unwrap() -= take;

        let mut partial = intent.clone();
        partial.value = take;
        insert_operation(operations, tree, partial, rng);

        remaining -= take;
    }

    if remaining > 0 {
        return Err(TransactionBuilderError::InsufficientBalance {
            from,
            asset,
            value: intent.value,
        });
    }
    Ok(())
}

/// Helper to insert an intent into an operation, creating the operation if it
/// doesn't exist.
fn insert_operation(
    operations: &mut BTreeMap<u32, Operation>,
    tree: u32,
    intent: Intent,
    rng: &mut impl CryptoRng,
) {
    let from = intent.from.clone();
    let asset = intent.asset;
    let op = operations
        .entry(tree)
        .or_insert(Operation::new_empty(tree, from, asset));

    match intent.kind {
        IntentKind::Transfer {
            to,
            memo,
            encryption,
            hide_sender,
        } => {
            let note = TransferNote::new(
                intent.from.viewing_key(),
                to,
                intent.asset,
                intent.value,
                rng.random(),
                &memo,
            )
            .with_encryption(encryption);
            op.add_out_note(if hide_sender {
                note.with_hidden_sender()
            } else {
                note
            })
        }
        IntentKind::Unshield { to } => {
            op.set_unshield_note(UnshieldNote::new(to, intent.asset, intent.value))
        }
    }
}

/// TODO: Improve selection algorithm to minimize the number of notes used while
/// avoiding creating many dust notes.
///
/// Probably best is some target # of notes to use, then selecting the smallest
/// notes that meet the target value.  This way dust notes are gradually consolidated
/// while avoiding wasting gas.
fn select_notes<'a>(notes: &'a [&UtxoNote], value: u128) -> Vec<&'a UtxoNote> {
    let mut selected: Vec<&UtxoNote> = Vec::new();
    let mut total = 0;
    for note in notes {
        selected.push(note);
        total += note.value();
        if total >= value {
            break;
        }
    }
    selected
}

/// Helper to add a change note to an operation if there is excess value.
fn add_change_note(
    operation: &mut Operation,
    asset: AssetId,
    hybrid_change: bool,
    rng: &mut impl CryptoRng,
) -> Result<(), TransactionBuilderError> {
    let signer = operation.from.clone();
    let change = operation.in_value().saturating_sub(operation.out_value());
    if change > 0 {
        let encryption = if hybrid_change {
            let Some(kem) = signer.kem_key_pair() else {
                return Err(TransactionBuilderError::ChangeNeedsKemKey {
                    from: signer.address(),
                });
            };
            NoteEncryption::HybridPq {
                receiver_kem_key: kem.encapsulation_key().clone(),
            }
        } else {
            NoteEncryption::Legacy
        };
        let change_note = TransferNote::new(
            signer.viewing_key(),
            signer.address(),
            asset,
            change,
            rng.random(),
            "change",
        )
        .with_encryption(encryption);
        operation.add_out_note(change_note);
    }
    Ok(())
}

async fn prove_operations(
    prover: Option<&Groth16Prover>,
    utxo_trees: &BTreeMap<u32, UtxoMerkleTree>,
    chain_id: u64,
    operations: &[Operation],
    rng: &mut impl CryptoRng,
) -> Result<Vec<ProvedOperation>, TransactionBuilderError> {
    let mut proved = Vec::new();
    for op in operations {
        let tree = op.utxo_tree_number;
        let Some(utxo_tree) = utxo_trees.get(&tree) else {
            return Err(TransactionBuilderError::MissingTree(tree));
        };
        let proved_op = prove_operation(prover, utxo_tree, chain_id, op, rng).await?;
        proved.push(proved_op);
    }
    Ok(proved)
}

async fn prove_operation(
    prover: Option<&Groth16Prover>,
    utxo_tree: &UtxoMerkleTree,
    chain_id: u64,
    operation: &Operation,
    rng: &mut impl CryptoRng,
) -> Result<ProvedOperation, TransactionBuilderError> {
    info!("Constructing circuit inputs");
    let unshield_note = operation.unshield_note();
    let unshield_type = unshield_note.map(|n| n.unshield_type()).unwrap_or_default();
    let unshield_preimage = unshield_note.map(|n| n.preimage()).unwrap_or_default();

    let commitment_ciphertexts: Vec<abis::railgun::CommitmentCiphertext> = operation
        .out_encryptable_notes()
        .iter()
        .map(|n| n.encrypt(rng))
        .collect::<Result<_, _>>()?;

    //? min_gas_price, adapt_contract and adapt_params are bound into the proof and checked by
    //? the Railgun contract (`tx.gasprice >= minGasPrice`, `adaptContract == msg.sender`).
    let bound_params = abis::railgun::BoundParams::new(
        utxo_tree.number() as u16,
        operation.min_gas_price,
        unshield_type,
        chain_id,
        operation.adapt_contract.unwrap_or(Address::ZERO),
        &operation.adapt_params.unwrap_or([0u8; 32]),
        commitment_ciphertexts,
    );

    // A dummy build (no prover) must not reach the signer: see `from_inputs_unsigned`.
    let inputs = if prover.is_some() {
        TransactCircuitInputs::from_inputs(
            utxo_tree,
            bound_params.hash(),
            operation.from.clone(),
            operation.asset,
            operation.in_notes(),
            &operation.out_notes(),
        )
        .await?
    } else {
        TransactCircuitInputs::from_inputs_unsigned(
            utxo_tree,
            bound_params.hash(),
            operation.from.clone(),
            operation.asset,
            operation.in_notes(),
            &operation.out_notes(),
        )
        .await?
    };
    let proof = match prover {
        Some(prover) => prover
            .prove_transact(&inputs)
            .await
            .map_err(|e| TransactionBuilderError::Prover(Box::new(e)))?,
        None => Proof::zero(),
    };

    let merkleroot: U256 = inputs.merkleroot.into();
    let transaction = abis::railgun::Transaction::new(
        proof.into(),
        merkleroot.into(),
        inputs.nullifiers.iter().map(|n| n.clone().into()).collect(),
        inputs
            .commitments_out
            .iter()
            .map(|c| c.clone().into())
            .collect(),
        bound_params,
        unshield_preimage,
    );

    Ok(ProvedOperation::new(operation.clone(), inputs, transaction))
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;
    use rand::random;

    use super::*;
    use crate::{account::signer::PrivateKeySigner, poi::types::BlindedCommitmentType};

    const WETH: AssetId = AssetId::Erc20(address!("0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14"));
    const USDC: AssetId = AssetId::Erc20(address!("0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238"));

    fn note(
        signer: &Arc<PrivateKeySigner>,
        tree: u32,
        leaf: u32,
        asset: AssetId,
        value: u128,
    ) -> UtxoNote {
        UtxoNote::new(
            tree,
            leaf,
            signer.clone(),
            asset,
            value,
            random(),
            "",
            BlindedCommitmentType::Shield,
        )
    }

    fn tree_with(notes: &[UtxoNote], number: u32) -> BTreeMap<u32, UtxoMerkleTree> {
        let mut tree = UtxoMerkleTree::new(number);
        let mut leaves: Vec<_> = notes.iter().filter(|n| n.tree_number == number).collect();
        leaves.sort_by_key(|n| n.leaf_index);
        let hashes: Vec<_> = leaves.iter().map(|n| n.hash).collect();
        tree.insert_leaves(&hashes, 0);
        BTreeMap::from([(number, tree)])
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// Stands for a hardware or threshold signer: counts how often it is asked to sign.
    struct CountingSigner {
        inner: Arc<PrivateKeySigner>,
        signatures: std::sync::atomic::AtomicUsize,
    }

    #[cfg_attr(native, async_trait::async_trait)]
    #[cfg_attr(wasm, async_trait::async_trait(?Send))]
    impl RailgunSigner for CountingSigner {
        async fn sign(
            &self,
            inputs: U256,
        ) -> Result<
            crate::crypto::keys::SpendingSignature,
            crate::account::signer::RailgunSignerError,
        > {
            self.signatures
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.sign(inputs).await
        }
        fn spending_public_key(&self) -> crate::crypto::keys::SpendingPublicKey {
            self.inner.spending_public_key()
        }
        fn viewing_key(&self) -> crate::crypto::keys::ViewingKey {
            self.inner.viewing_key()
        }
        fn chain_id(&self) -> crate::account::chain::ChainId {
            self.inner.chain_id()
        }
    }

    /// A gas estimate must not cost a confirmation on a hardware wallet, or a threshold
    /// signing ceremony.
    /// The scheme is chosen per transfer. Change notes are legacy in an all-legacy
    /// transaction unless asked otherwise, and hybrid as soon as one transfer is, taking the
    /// signer's own KEM key or failing.
    #[test]
    fn encryption_is_chosen_per_note() {
        use crate::{
            account::chain::ChainId,
            crypto::{kem::KemKeyPair, keys::ByteKey},
        };

        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let other_kem = KemKeyPair::derive(b"other");
        let notes = [note(&me, 0, 0, WETH, 100)];
        let hybrid = NoteEncryption::HybridPq {
            receiver_kem_key: other_kem.encapsulation_key().clone(),
        };

        // All legacy: the change is legacy too, and the sender visible everywhere.
        let ops = TransactionBuilder::new()
            .transfer(me.clone(), other.address(), WETH, 10, "legacy")
            .operations(&notes, &mut rand::rng())
            .unwrap();
        assert!(
            ops[0]
                .transfer_notes()
                .iter()
                .all(|n| n.encryption == NoteEncryption::Legacy && !n.hide_sender)
        );

        // One hybrid transfer forces hybrid change, which this signer cannot produce.
        let err = TransactionBuilder::new()
            .transfer(me.clone(), other.address(), WETH, 10, "legacy")
            .transfer_with_encryption(me.clone(), other.address(), WETH, 20, "pq", hybrid.clone())
            .operations(&notes, &mut rand::rng())
            .unwrap_err();
        assert!(matches!(
            err,
            TransactionBuilderError::ChangeNeedsKemKey { .. }
        ));

        let my_kem = KemKeyPair::derive(b"me");
        let me_pq = PrivateKeySigner::new_with_kem(
            crate::crypto::keys::SpendingKey::from_bytes([1u8; 32]),
            crate::crypto::keys::ViewingKey::from_bytes([2u8; 32]),
            my_kem.clone(),
            ChainId::evm(1),
        );
        let pq_notes = [note(&me_pq, 0, 0, WETH, 100)];
        let ops = TransactionBuilder::new()
            .transfer(me_pq.clone(), other.address(), WETH, 10, "legacy")
            .transfer_with_encryption(
                me_pq.clone(),
                other.address(),
                WETH,
                20,
                "pq",
                hybrid.clone(),
            )
            .operations(&pq_notes, &mut rand::rng())
            .unwrap();
        let by_memo = |memo: &str| {
            ops[0]
                .transfer_notes()
                .iter()
                .find(|n| n.memo == memo)
                .unwrap()
                .encryption
                .clone()
        };
        assert_eq!(by_memo("legacy"), NoteEncryption::Legacy);
        assert_eq!(by_memo("pq"), hybrid);
        assert_eq!(
            by_memo("change"),
            NoteEncryption::HybridPq {
                receiver_kem_key: my_kem.encapsulation_key().clone()
            }
        );

        let ops = TransactionBuilder::new()
            .transfer_with(
                me.clone(),
                other.address(),
                WETH,
                10,
                "fee",
                NoteEncryption::Legacy,
                true,
            )
            .operations(&notes, &mut rand::rng())
            .unwrap();
        let fee = ops[0]
            .transfer_notes()
            .iter()
            .find(|n| n.memo == "fee")
            .unwrap();
        assert!(fee.hide_sender);

        // Hybrid change on request, in an all-legacy transaction: needs the signer's own key.
        let err = TransactionBuilder::new()
            .transfer(me.clone(), other.address(), WETH, 10, "")
            .with_hybrid_change()
            .operations(&notes, &mut rand::rng())
            .unwrap_err();
        assert!(matches!(
            err,
            TransactionBuilderError::ChangeNeedsKemKey { .. }
        ));

        let ops = TransactionBuilder::new()
            .transfer(me_pq.clone(), other.address(), WETH, 10, "")
            .with_hybrid_change()
            .operations(&pq_notes, &mut rand::rng())
            .unwrap();
        let change = ops[0]
            .transfer_notes()
            .iter()
            .find(|n| n.memo == "change")
            .unwrap();
        assert_eq!(
            change.encryption,
            NoteEncryption::HybridPq {
                receiver_kem_key: my_kem.encapsulation_key().clone()
            }
        );
    }

    #[test]
    fn dummy_build_never_asks_the_signer() {
        let key = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let me = Arc::new(CountingSigner {
            inner: key.clone(),
            signatures: Default::default(),
        });
        // Notes are owned by the same keys, whoever signs.
        let notes = [note(&key, 0, 0, WETH, 100), note(&key, 0, 1, USDC, 1_000)];
        let trees = tree_with(&notes, 0);

        let builder = TransactionBuilder::new()
            .transfer(me.clone(), other.address(), USDC, 500, "")
            .transfer(me.clone(), other.address(), WETH, 25, "");
        let dummy = block_on(builder.build_dummy(1, &notes, &trees, &mut rand::rng())).unwrap();

        assert_eq!(dummy.len(), 2);
        assert_eq!(me.signatures.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    /// The dummy build has the calldata shape of a real one, with an all-zero proof.
    #[test]
    fn dummy_build_has_a_zero_proof_and_the_real_shape() {
        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let notes = [note(&me, 0, 0, WETH, 100)];
        let trees = tree_with(&notes, 0);

        let builder = TransactionBuilder::new().transfer(me.clone(), other.address(), WETH, 30, "");
        let dummy = block_on(builder.build_dummy(1, &notes, &trees, &mut rand::rng())).unwrap();

        let tx = &dummy[0].transaction;
        assert_eq!(tx.proof.a.x, U256::ZERO);
        assert_eq!(tx.proof.b.x, [U256::ZERO; 2]);
        assert_eq!(tx.nullifiers.len(), 1);
        assert_eq!(tx.commitments.len(), 2);
        assert_eq!(tx.boundParams.commitmentCiphertext.len(), 2);
    }

    /// Without a pinned intent the layout is the historical one: groups in `(address, asset)`
    /// order, notes by ascending value, change last. The ERC-4337 path relies on nothing else,
    /// but it must not move when the broadcaster features are unused.
    #[test]
    fn default_layout_is_unchanged() {
        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let notes = [note(&me, 0, 0, WETH, 100)];

        let builder = TransactionBuilder::new()
            .transfer(me.clone(), other.address(), WETH, 30, "")
            .transfer(me.clone(), other.address(), WETH, 10, "fee")
            .transfer(me.clone(), other.address(), WETH, 20, "");
        let ops = builder.operations(&notes, &mut rand::rng()).unwrap();

        assert_eq!(ops.len(), 1);
        assert_eq!(out_values(&ops[0]), vec![10, 20, 30, 40]);
        assert_eq!(ops[0].min_gas_price, 0);
    }

    #[test]
    fn broadcaster_fee_is_first_commitment_of_first_operation() {
        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let broadcaster = PrivateKeySigner::new_evm(random(), random(), 1);
        let notes = [note(&me, 0, 0, WETH, 100), note(&me, 0, 1, USDC, 1_000)];

        // USDC sorts before WETH in the group map and 5 < 25: both orderings would bury the fee.
        assert!(USDC < WETH);
        let builder = TransactionBuilder::new()
            .transfer(me.clone(), other.address(), USDC, 500, "")
            .transfer(me.clone(), other.address(), WETH, 5, "")
            .broadcaster_fee(me.clone(), broadcaster.address(), WETH, 25)
            .unwrap()
            .min_gas_price(7);
        let ops = builder.operations(&notes, &mut rand::rng()).unwrap();

        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].asset, WETH);
        assert_eq!(out_values(&ops[0]), vec![25, 5, 70]);
        assert_eq!(ops[1].asset, USDC);
        assert!(ops.iter().all(|op| op.min_gas_price == 7));
    }

    #[test]
    fn broadcaster_fee_moves_its_tree_operation_first() {
        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let broadcaster = PrivateKeySigner::new_evm(random(), random(), 1);
        // Tree 0 cannot pay the fee, tree 1 can: the fee operation is the tree 1 one.
        let notes = [note(&me, 0, 0, WETH, 10), note(&me, 1, 0, WETH, 100)];

        let builder = TransactionBuilder::new()
            .transfer(me.clone(), other.address(), WETH, 8, "")
            .broadcaster_fee(me.clone(), broadcaster.address(), WETH, 25)
            .unwrap();
        let ops = builder.operations(&notes, &mut rand::rng()).unwrap();

        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].utxo_tree_number, 1);
        assert_eq!(out_values(&ops[0])[0], 25);
    }

    #[test]
    fn broadcaster_fee_rules() {
        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let broadcaster = PrivateKeySigner::new_evm(random(), random(), 1);

        let twice = TransactionBuilder::new()
            .broadcaster_fee(me.clone(), broadcaster.address(), WETH, 1)
            .unwrap()
            .broadcaster_fee(me.clone(), broadcaster.address(), WETH, 1);
        assert!(matches!(
            twice,
            Err(TransactionBuilderError::MultipleBroadcasterFees)
        ));

        // 15 is only reachable by combining two trees: refused, the fee must be one note.
        let notes = [note(&me, 0, 0, WETH, 10), note(&me, 1, 0, WETH, 10)];
        let split = TransactionBuilder::new()
            .broadcaster_fee(me.clone(), broadcaster.address(), WETH, 15)
            .unwrap()
            .operations(&notes, &mut rand::rng());
        assert!(matches!(
            split,
            Err(TransactionBuilderError::BroadcasterFeeSplit { value: 15 })
        ));
    }

    /// `minGasPrice` is part of the proven bound params: 0 by default, and the dummy build has
    /// the calldata shape of a real one with an all-zero proof.
    #[test]
    fn min_gas_price_is_bound_and_dummy_proof_is_zero() {
        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let notes = [note(&me, 0, 0, WETH, 100)];
        let trees = tree_with(&notes, 0);

        let base = TransactionBuilder::new().transfer(me.clone(), other.address(), WETH, 30, "");
        let default = block_on(
            base.clone()
                .build_dummy(1, &notes, &trees, &mut rand::rng()),
        )
        .unwrap();
        let priced = block_on(base.min_gas_price(1_000_000_000).build_dummy(
            1,
            &notes,
            &trees,
            &mut rand::rng(),
        ))
        .unwrap();

        let tx = &default[0].transaction;
        assert_eq!(tx.boundParams.minGasPrice.to::<u128>(), 0);
        assert_eq!(
            priced[0].transaction.boundParams.minGasPrice.to::<u128>(),
            1_000_000_000
        );
        assert_eq!(tx.proof.a.x, U256::ZERO);
        assert_eq!(tx.proof.b.x, [U256::ZERO; 2]);
        assert_eq!(tx.nullifiers.len(), 1);
        assert_eq!(tx.commitments.len(), 2);
        assert_eq!(tx.boundParams.commitmentCiphertext.len(), 2);
    }

    fn out_values(op: &Operation) -> Vec<u128> {
        op.out_notes().iter().map(|n| n.value()).collect()
    }

    /// `adapt_with`: the params are computed from the nullifiers of the operations actually
    /// built and bound into each of them; combining it with `adapt()` is refused.
    #[test]
    fn adapt_with_binds_params_derived_from_the_built_nullifiers() {
        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let contract = address!("0x7e3d929EbD5bDC84d02Bd3205c777578f33A214D");
        let notes = [note(&me, 0, 0, WETH, 100), note(&me, 0, 1, WETH, 50)];
        let derive =
            |nullifiers: &[Vec<B256>]| alloy::primitives::keccak256(nullifiers.concat().concat()).0;

        let builder = TransactionBuilder::new()
            .unshield(me.clone(), contract, WETH, 120)
            .unwrap()
            .transfer(me.clone(), other.address(), WETH, 5, "")
            .adapt_with(contract, derive);
        let ops = builder.operations(&notes, &mut rand::rng()).unwrap();

        let nullifiers: Vec<Vec<B256>> = ops
            .iter()
            .map(|op| op.in_notes().iter().map(|n| n.nullifier.into()).collect())
            .collect();
        assert_eq!(nullifiers[0].len(), 2);
        for op in &ops {
            assert_eq!(op.adapt_contract, Some(contract));
            assert_eq!(op.adapt_params, Some(derive(&nullifiers)));
        }

        let both = TransactionBuilder::new()
            .unshield(me.clone(), contract, WETH, 10)
            .unwrap()
            .adapt(contract, [0u8; 32])
            .adapt_with(contract, derive)
            .operations(&notes, &mut rand::rng());
        assert!(matches!(
            both,
            Err(TransactionBuilderError::ConflictingAdapt)
        ));
    }
}
