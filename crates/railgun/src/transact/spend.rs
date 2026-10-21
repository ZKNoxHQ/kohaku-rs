//! A spend is one Railgun operation: the input notes you named, the outputs you
//! named, and one signer. Proving it is separate, and that is the only step that
//! asks the signer for a spending signature.

use std::{collections::BTreeMap, sync::Arc};

use alloy::primitives::{Address, U256};
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
    poi::types::PoiStatus,
    transact::proved_transaction::ProvedOperation,
};

/// One shielded operation. Inputs are fixed when the spend is created; outputs
/// are added with [`Self::transfer`] and [`Self::unshield`], then [`Self::with_change`]
/// balances it. Nothing here asks the spending signer to sign.
#[derive(Clone, Debug)]
pub struct Spend {
    signer: Arc<dyn RailgunSigner>,
    inputs: Vec<UtxoNote>,
    pending: Vec<PendingTransfer>,
    outputs: Vec<TransferNote>,
    unshield: Option<UnshieldNote>,
    change: Option<TransferNote>,
    change_to: RailgunAddress,
    finalized: bool,
    adapt_contract: Option<Address>,
    adapt_params: Option<[u8; 32]>,
    /// The change note goes back to its signer under [`NoteEncryption::HybridPq`] with its own
    /// KEM key even when no transfer is hybrid, see [`Self::with_hybrid_change`].
    hybrid_change: bool,
}

#[derive(Clone, Debug)]
struct PendingTransfer {
    to: RailgunAddress,
    value: u128,
    memo: String,
    encryption: NoteEncryption,
    hide_sender: bool,
}

#[derive(Debug, Error)]
pub enum SpendError {
    #[error("a spend needs at least one input note")]
    EmptyInputs,
    #[error("input notes are from more than one tree")]
    MixedTree,
    #[error("input notes are for more than one asset")]
    MixedAsset,
    #[error("an input note is not held by this signer")]
    SignerMismatch,
    #[error("too many input notes: {0} > 13")]
    TooManyInputs(usize),
    #[error("a spend can only unshield once")]
    MultipleUnshields,
    #[error("outputs are fixed once change is added")]
    AlreadyFinalized,
    #[error("call with_change before proving")]
    NotFinalized,
    #[error("outputs {outputs} exceed inputs {inputs}")]
    OutputsExceedInputs { inputs: u128, outputs: u128 },
    #[error("note {blinded_commitment} is not POI valid ({status})")]
    NoteNotValid {
        blinded_commitment: U256,
        status: PoiStatus,
    },
    #[error("Encryption error: {0}")]
    Encryption(#[from] EncryptError),
    #[error("Prover error: {0}")]
    Prover(Box<dyn std::error::Error + Send + Sync>),
    #[error("Missing tree for number {0}")]
    MissingTree(u32),
    #[error("Transact circuit input error: {0}")]
    TransactCircuitInput(#[from] TransactCircuitInputsError),
    #[error("Operation verification error: {0}")]
    OperationVerification(#[from] OperationVerificationError),
    #[error("A hybrid change note was requested, but the signer of {from} has no ML-KEM key")]
    ChangeNeedsKemKey { from: RailgunAddress },
}

impl Spend {
    pub(crate) fn try_new(
        signer: Arc<dyn RailgunSigner>,
        inputs: Vec<UtxoNote>,
    ) -> Result<Self, SpendError> {
        if inputs.is_empty() {
            return Err(SpendError::EmptyInputs);
        }
        if inputs.len() > 13 {
            return Err(SpendError::TooManyInputs(inputs.len()));
        }
        let tree = inputs[0].tree_number;
        let asset = inputs[0].asset;
        let viewing = signer.viewing_key().public_key();
        for note in &inputs {
            if note.tree_number != tree {
                return Err(SpendError::MixedTree);
            }
            if note.asset != asset {
                return Err(SpendError::MixedAsset);
            }
            if note.viewing_pubkey != viewing {
                return Err(SpendError::SignerMismatch);
            }
        }
        Ok(Self {
            change_to: signer.address(),
            signer,
            inputs,
            pending: Vec::new(),
            outputs: Vec::new(),
            unshield: None,
            change: None,
            finalized: false,
            adapt_contract: None,
            adapt_params: None,
            hybrid_change: false,
        })
    }

    /// Spend `value` of this spend's asset to another Railgun address, encrypted the way
    /// every Railgun wallet reads ([`NoteEncryption::Legacy`]).
    pub fn transfer(self, to: RailgunAddress, value: u128, memo: &str) -> Result<Self, SpendError> {
        self.transfer_with_encryption(to, value, memo, NoteEncryption::Legacy)
    }

    /// Spend `value` of this spend's asset to another Railgun address, with the note encrypted
    /// by `encryption`, for instance [`NoteEncryption::HybridPq`] with the receiver's published
    /// KEM key.
    pub fn transfer_with_encryption(
        self,
        to: RailgunAddress,
        value: u128,
        memo: &str,
        encryption: NoteEncryption,
    ) -> Result<Self, SpendError> {
        self.transfer_with(to, value, memo, encryption, false)
    }

    /// A transfer with every option: the encryption scheme, and whether the sender is hidden
    /// from whoever opens the note ([`TransferNote::hide_sender`]).
    pub fn transfer_with(
        mut self,
        to: RailgunAddress,
        value: u128,
        memo: &str,
        encryption: NoteEncryption,
        hide_sender: bool,
    ) -> Result<Self, SpendError> {
        self.ensure_open()?;
        self.pending.push(PendingTransfer {
            to,
            value,
            memo: memo.to_string(),
            encryption,
            hide_sender,
        });
        Ok(self)
    }

    /// Encrypts the change note with [`NoteEncryption::HybridPq`] to the signer's own KEM
    /// key even when no transfer is hybrid. Off by default, so that wallets without the key
    /// (legacy wallets on the same seed) keep seeing the change of legacy transactions.
    ///
    /// The change note is hybrid regardless whenever a transfer of the spend is: a legacy
    /// change note next to a hybrid output would let a quantum attacker unblind its receiver,
    /// the sender, and so deanonymise the whole transaction. In both cases building fails if
    /// the signer has no KEM key: the choice is never downgraded silently.
    pub fn with_hybrid_change(mut self) -> Self {
        self.hybrid_change = true;
        self
    }

    /// Unshield `value` of this spend's asset to an external address.
    pub fn unshield(mut self, to: Address, value: u128) -> Result<Self, SpendError> {
        self.ensure_open()?;
        if self.unshield.is_some() {
            return Err(SpendError::MultipleUnshields);
        }
        self.unshield = Some(UnshieldNote::new(to, self.asset(), value));
        Ok(self)
    }

    /// Send the remainder to `to` instead of back to the signer. Call before [`Self::with_change`].
    pub fn change_to(mut self, to: RailgunAddress) -> Self {
        if !self.finalized {
            self.change_to = to;
        }
        self
    }

    /// Sets the adapt contract and parameters copied into the bound parameters.
    pub fn adapt(mut self, contract: Address, params: [u8; 32]) -> Self {
        self.adapt_contract = Some(contract);
        self.adapt_params = Some(params);
        self
    }

    /// Materialize output notes and add a change note for any remainder.
    ///
    /// The spending signer is not asked to sign. A remainder of zero adds no change note.
    /// Outputs that already exceed the inputs are an error: change is never invented later.
    pub fn with_change(mut self, rng: &mut impl CryptoRng) -> Result<Self, SpendError> {
        if self.finalized {
            return Ok(self);
        }
        let asset = self.asset();
        let viewing = self.signer.viewing_key();
        for pending in self.pending.drain(..) {
            let note = TransferNote::new(
                viewing,
                pending.to,
                asset,
                pending.value,
                rng.random(),
                &pending.memo,
            )
            .with_encryption(pending.encryption);
            self.outputs.push(if pending.hide_sender {
                note.with_hidden_sender()
            } else {
                note
            });
        }
        self.rebuild_change(rng)?;
        self.finalized = true;
        self.clone().into_operation()?;
        Ok(self)
    }

    pub fn inputs(&self) -> &[UtxoNote] {
        &self.inputs
    }

    /// Transfer outputs, not including change. Empty until [`Self::with_change`].
    pub fn transfers(&self) -> &[TransferNote] {
        &self.outputs
    }

    pub fn change_note(&self) -> Option<&TransferNote> {
        self.change.as_ref()
    }

    pub fn unshield_note(&self) -> Option<UnshieldNote> {
        self.unshield
    }

    pub fn tree(&self) -> u32 {
        self.inputs[0].tree_number
    }

    pub fn asset(&self) -> AssetId {
        self.inputs[0].asset
    }

    pub fn signer(&self) -> Arc<dyn RailgunSigner> {
        self.signer.clone()
    }

    /// A spend over already selected inputs, balanced by a change note to the signer.
    pub(crate) fn from_selected(
        signer: Arc<dyn RailgunSigner>,
        inputs: Vec<UtxoNote>,
        outputs: Vec<TransferNote>,
        unshield: Option<UnshieldNote>,
        adapt: Option<(Address, [u8; 32])>,
        hybrid_change: bool,
        rng: &mut impl CryptoRng,
    ) -> Result<Self, SpendError> {
        let mut spend = Self::try_new(signer, inputs)?;
        spend.outputs = outputs;
        spend.unshield = unshield;
        spend.hybrid_change = hybrid_change;
        spend.rebuild_change(rng)?;
        spend.finalized = true;
        if let Some((contract, params)) = adapt {
            spend.adapt_contract = Some(contract);
            spend.adapt_params = Some(params);
        }
        spend.clone().into_operation()?;
        Ok(spend)
    }

    pub(crate) fn hybrid_change(&self) -> bool {
        self.hybrid_change
    }

    pub(crate) fn set_adapt(&mut self, contract: Address, params: [u8; 32]) {
        self.adapt_contract = Some(contract);
        self.adapt_params = Some(params);
    }

    pub(crate) fn change_value(&self) -> u128 {
        self.change.as_ref().map_or(0, Note::value)
    }

    pub(crate) fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Add extra inputs and one transfer, then rebuild change so the spend still balances.
    pub(crate) fn absorb(
        &mut self,
        extra_inputs: Vec<UtxoNote>,
        transfer: TransferNote,
        rng: &mut impl CryptoRng,
    ) -> Result<(), SpendError> {
        if !self.finalized {
            return Err(SpendError::NotFinalized);
        }
        let viewing = self.signer.viewing_key().public_key();
        for note in &extra_inputs {
            if note.tree_number != self.tree() {
                return Err(SpendError::MixedTree);
            }
            if note.asset != self.asset() {
                return Err(SpendError::MixedAsset);
            }
            if note.viewing_pubkey != viewing {
                return Err(SpendError::SignerMismatch);
            }
        }
        self.inputs.extend(extra_inputs);
        if self.inputs.len() > 13 {
            return Err(SpendError::TooManyInputs(self.inputs.len()));
        }
        self.outputs.push(transfer);
        self.rebuild_change(rng)?;
        self.clone().into_operation()?;
        Ok(())
    }

    pub(crate) fn into_operation(self) -> Result<Operation, SpendError> {
        if !self.finalized {
            return Err(SpendError::NotFinalized);
        }
        let asset = self.asset();
        let tree = self.tree();
        let mut outputs = self.outputs;
        if let Some(change) = self.change {
            outputs.push(change);
        }
        let mut operation = Operation::new(
            tree,
            self.signer,
            asset,
            self.inputs,
            outputs,
            self.unshield,
        );
        operation.adapt_contract = self.adapt_contract;
        operation.adapt_params = self.adapt_params;
        operation.verify()?;
        Ok(operation)
    }

    fn ensure_open(&self) -> Result<(), SpendError> {
        if self.finalized {
            Err(SpendError::AlreadyFinalized)
        } else {
            Ok(())
        }
    }

    fn rebuild_change(&mut self, rng: &mut impl CryptoRng) -> Result<(), SpendError> {
        let inputs = self.inputs.iter().map(Note::value).sum();
        let outputs = self.outputs.iter().map(Note::value).sum::<u128>()
            + self.unshield.as_ref().map_or(0, Note::value);
        if outputs > inputs {
            return Err(SpendError::OutputsExceedInputs { inputs, outputs });
        }
        let change = inputs - outputs;
        self.change = if change > 0 {
            let hybrid = self.hybrid_change
                || self
                    .outputs
                    .iter()
                    .any(|note| matches!(note.encryption, NoteEncryption::HybridPq { .. }));
            let encryption = if hybrid {
                let Some(kem) = self.signer.kem_key_pair() else {
                    return Err(SpendError::ChangeNeedsKemKey {
                        from: self.signer.address(),
                    });
                };
                NoteEncryption::HybridPq {
                    receiver_kem_key: kem.encapsulation_key().clone(),
                }
            } else {
                NoteEncryption::Legacy
            };
            Some(
                TransferNote::new(
                    self.signer.viewing_key(),
                    self.change_to,
                    self.asset(),
                    change,
                    rng.random(),
                    "change",
                )
                .with_encryption(encryption),
            )
        } else {
            None
        };
        Ok(())
    }
}

pub(crate) async fn prove_operations(
    prover: Option<&Groth16Prover>,
    utxo_trees: &BTreeMap<u32, UtxoMerkleTree>,
    chain_id: u64,
    operations: &[Operation],
    rng: &mut impl CryptoRng,
) -> Result<Vec<ProvedOperation>, SpendError> {
    let mut proved_ops = Vec::new();
    for operation in operations {
        let tree = operation.utxo_tree_number;
        let Some(utxo_tree) = utxo_trees.get(&tree) else {
            return Err(SpendError::MissingTree(tree));
        };
        proved_ops.push(prove_operation(prover, utxo_tree, chain_id, operation, rng).await?);
    }
    Ok(proved_ops)
}

async fn prove_operation(
    prover: Option<&Groth16Prover>,
    utxo_tree: &UtxoMerkleTree,
    chain_id: u64,
    operation: &Operation,
    rng: &mut impl CryptoRng,
) -> Result<ProvedOperation, SpendError> {
    info!("Constructing circuit inputs");
    let unshield_note = operation.unshield_note();
    let unshield_type = unshield_note.map(|n| n.unshield_type()).unwrap_or_default();
    let unshield_preimage = unshield_note.map(|n| n.preimage()).unwrap_or_default();

    let commitment_ciphertexts: Vec<abis::railgun::CommitmentCiphertext> = operation
        .out_encryptable_notes()
        .iter()
        .map(|n| n.encrypt(rng))
        .collect::<Result<_, _>>()?;

    // min_gas_price, adapt_contract, and adapt_input are vestigial fields for railgun relayers.
    let bound_params = abis::railgun::BoundParams::new(
        utxo_tree.number() as u16,
        0,
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
            .map_err(|e| SpendError::Prover(Box::new(e)))?,
        None => Proof::dummy(),
    };

    let merkleroot: U256 = inputs.merkleroot.into();
    let transaction = abis::railgun::Transaction::new(
        proof.into(),
        merkleroot.into(),
        inputs
            .nullifiers
            .iter()
            .map(|nullifier| (*nullifier).into())
            .collect(),
        inputs
            .commitments_out
            .iter()
            .map(|commitment| (*commitment).into())
            .collect(),
        bound_params,
        unshield_preimage,
    );

    Ok(ProvedOperation::new(operation.clone(), inputs, transaction))
}

#[cfg(all(test, native))]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use alloy::primitives::address;
    use rand::random;

    use super::*;
    use crate::{
        account::{chain::ChainId, signer::PrivateKeySigner},
        crypto::keys::{SpendingPublicKey, SpendingSignature, ViewingKey},
        poi::types::BlindedCommitmentType,
    };

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
        tree.insert_leaves(&hashes, 0).unwrap();
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
        signatures: AtomicUsize,
    }

    #[cfg_attr(native, async_trait::async_trait)]
    #[cfg_attr(wasm, async_trait::async_trait(?Send))]
    impl RailgunSigner for CountingSigner {
        async fn sign(
            &self,
            inputs: U256,
        ) -> Result<SpendingSignature, crate::account::signer::RailgunSignerError> {
            self.signatures.fetch_add(1, Ordering::SeqCst);
            self.inner.sign(inputs).await
        }
        fn spending_public_key(&self) -> SpendingPublicKey {
            self.inner.spending_public_key()
        }
        fn viewing_key(&self) -> ViewingKey {
            self.inner.viewing_key()
        }
        fn chain_id(&self) -> ChainId {
            self.inner.chain_id()
        }
    }

    #[test]
    fn spend_rejects_mixed_trees_assets_and_signers() {
        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let weth = note(&me, 0, 0, WETH, 100);
        let other_tree = note(&me, 1, 0, WETH, 100);
        let usdc = note(&me, 0, 1, USDC, 100);
        let theirs = note(&other, 0, 2, WETH, 100);

        assert!(matches!(
            Spend::try_new(me.clone(), vec![weth.clone(), other_tree]),
            Err(SpendError::MixedTree)
        ));
        assert!(matches!(
            Spend::try_new(me.clone(), vec![weth.clone(), usdc]),
            Err(SpendError::MixedAsset)
        ));
        assert!(matches!(
            Spend::try_new(me.clone(), vec![theirs]),
            Err(SpendError::SignerMismatch)
        ));
        assert!(matches!(
            Spend::try_new(me, vec![]),
            Err(SpendError::EmptyInputs)
        ));
    }

    #[test]
    fn a_second_unshield_is_rejected_and_change_balances() {
        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let input = note(&me, 0, 0, WETH, 100);
        let external = address!("0x00000000000000000000000000000000000000aa");

        let twice = Spend::try_new(me.clone(), vec![input.clone()])
            .unwrap()
            .unshield(external, 10)
            .unwrap()
            .unshield(external, 1);
        assert!(matches!(twice, Err(SpendError::MultipleUnshields)));

        let spend = Spend::try_new(me, vec![input])
            .unwrap()
            .transfer(other.address(), 30, "memo")
            .unwrap()
            .with_change(&mut rand::rng())
            .unwrap();
        assert_eq!(spend.transfers().len(), 1);
        assert_eq!(spend.transfers()[0].value(), 30);
        assert_eq!(spend.transfers()[0].memo(), "memo");
        assert_eq!(spend.change_note().unwrap().value(), 70);
        assert_eq!(spend.change_note().unwrap().memo(), "change");
        let inputs = spend.inputs().iter().map(Note::value).sum::<u128>();
        let outputs = spend.transfers().iter().map(Note::value).sum::<u128>()
            + spend.change_note().map_or(0, Note::value);
        assert_eq!(inputs, outputs);
    }

    #[test]
    fn outputs_past_the_inputs_do_not_invent_change() {
        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let input = note(&me, 0, 0, WETH, 100);
        let spend = Spend::try_new(me, vec![input])
            .unwrap()
            .transfer(other.address(), 150, "")
            .unwrap()
            .with_change(&mut rand::rng());
        assert!(matches!(spend, Err(SpendError::OutputsExceedInputs { .. })));
    }

    /// The scheme is chosen per transfer. The change note is legacy in an all-legacy spend
    /// unless asked otherwise, and hybrid as soon as one transfer is, taking the signer's own
    /// KEM key or failing.
    #[test]
    fn encryption_is_chosen_per_note() {
        use crate::crypto::{
            kem::KemKeyPair,
            keys::{ByteKey, SpendingKey},
        };

        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let other_kem = KemKeyPair::derive(b"other");
        let hybrid = NoteEncryption::HybridPq {
            receiver_kem_key: other_kem.encapsulation_key().clone(),
        };
        let mut rng = rand::rng();

        // All legacy: the change is legacy too, and the sender visible everywhere.
        let spend = Spend::try_new(me.clone(), vec![note(&me, 0, 0, WETH, 100)])
            .unwrap()
            .transfer(other.address(), 10, "legacy")
            .unwrap()
            .with_change(&mut rng)
            .unwrap();
        assert!(
            spend
                .transfers()
                .iter()
                .chain(spend.change_note())
                .all(|n| n.encryption == NoteEncryption::Legacy && !n.hide_sender)
        );

        // One hybrid transfer forces hybrid change, which this signer cannot produce.
        let err = Spend::try_new(me.clone(), vec![note(&me, 0, 0, WETH, 100)])
            .unwrap()
            .transfer(other.address(), 10, "legacy")
            .unwrap()
            .transfer_with_encryption(other.address(), 20, "pq", hybrid.clone())
            .unwrap()
            .with_change(&mut rng)
            .unwrap_err();
        assert!(matches!(err, SpendError::ChangeNeedsKemKey { .. }));

        let my_kem = KemKeyPair::derive(b"me");
        let me_pq = PrivateKeySigner::new_with_kem(
            SpendingKey::from_bytes([1u8; 32]),
            ViewingKey::from_bytes([2u8; 32]),
            my_kem.clone(),
            ChainId::evm(1),
        );
        let spend = Spend::try_new(me_pq.clone(), vec![note(&me_pq, 0, 0, WETH, 100)])
            .unwrap()
            .transfer(other.address(), 10, "legacy")
            .unwrap()
            .transfer_with_encryption(other.address(), 20, "pq", hybrid.clone())
            .unwrap()
            .with_change(&mut rng)
            .unwrap();
        let by_memo = |memo: &str| {
            spend
                .transfers()
                .iter()
                .chain(spend.change_note())
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

        let spend = Spend::try_new(me.clone(), vec![note(&me, 0, 0, WETH, 100)])
            .unwrap()
            .transfer_with(other.address(), 10, "fee", NoteEncryption::Legacy, true)
            .unwrap()
            .with_change(&mut rng)
            .unwrap();
        assert!(spend.transfers()[0].hide_sender);
        assert!(!spend.change_note().unwrap().hide_sender);

        // Hybrid change on request, in an all-legacy spend: needs the signer's own key.
        let err = Spend::try_new(me.clone(), vec![note(&me, 0, 0, WETH, 100)])
            .unwrap()
            .transfer(other.address(), 10, "")
            .unwrap()
            .with_hybrid_change()
            .with_change(&mut rng)
            .unwrap_err();
        assert!(matches!(err, SpendError::ChangeNeedsKemKey { .. }));

        let spend = Spend::try_new(me_pq.clone(), vec![note(&me_pq, 0, 0, WETH, 100)])
            .unwrap()
            .transfer(other.address(), 10, "")
            .unwrap()
            .with_hybrid_change()
            .with_change(&mut rng)
            .unwrap();
        assert_eq!(
            spend.change_note().unwrap().encryption,
            NoteEncryption::HybridPq {
                receiver_kem_key: my_kem.encapsulation_key().clone()
            }
        );
    }

    /// A gas estimate must not cost a confirmation on a hardware wallet, or a threshold
    /// signing ceremony.
    #[test]
    fn dummy_build_never_asks_the_signer() {
        let key = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let me = Arc::new(CountingSigner {
            inner: key.clone(),
            signatures: AtomicUsize::new(0),
        });
        let notes = [note(&key, 0, 0, WETH, 100), note(&key, 0, 1, USDC, 1_000)];
        let trees = tree_with(&notes, 0);
        let mut rng = rand::rng();
        let weth = Spend::try_new(me.clone(), vec![notes[0].clone()])
            .unwrap()
            .transfer(other.address(), 25, "")
            .unwrap()
            .with_change(&mut rng)
            .unwrap();
        let usdc = Spend::try_new(me.clone(), vec![notes[1].clone()])
            .unwrap()
            .transfer(other.address(), 500, "")
            .unwrap()
            .with_change(&mut rng)
            .unwrap();
        let operations = vec![
            weth.into_operation().unwrap(),
            usdc.into_operation().unwrap(),
        ];
        let dummy = block_on(prove_operations(None, &trees, 1, &operations, &mut rng)).unwrap();

        assert_eq!(dummy.len(), 2);
        assert_eq!(me.signatures.load(Ordering::SeqCst), 0);
    }

    /// The dummy build has the calldata shape of a real one, with an all-zero proof.
    #[test]
    fn dummy_build_has_a_dummy_proof_and_the_real_shape() {
        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let notes = [note(&me, 0, 0, WETH, 100)];
        let trees = tree_with(&notes, 0);
        let mut rng = rand::rng();
        let spend = Spend::try_new(me, notes.to_vec())
            .unwrap()
            .transfer(other.address(), 30, "")
            .unwrap()
            .with_change(&mut rng)
            .unwrap();
        let operation = spend.into_operation().unwrap();
        let dummy = block_on(prove_operations(None, &trees, 1, &[operation], &mut rng)).unwrap();

        let tx = &dummy[0].transaction;
        assert_eq!(tx.proof.a.x, U256::from(1u8));
        assert_eq!(tx.proof.a.y, U256::from(2u8));
        assert_eq!(tx.proof.b.x, [U256::ZERO; 2]);
        assert_eq!(tx.proof.c.x, U256::ZERO);
        assert_eq!(tx.nullifiers.len(), 1);
        assert_eq!(tx.commitments.len(), 2);
        assert_eq!(tx.boundParams.commitmentCiphertext.len(), 2);
    }
}
