//! Amount spends are a wrapper: they select input notes, then return [`Spend`]s.
//! Proving those spends is unchanged.

use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use alloy::primitives::Address;
use rand::{CryptoRng, RngExt};
use thiserror::Error;

use crate::{
    account::{address::RailgunAddress, signer::RailgunSigner},
    caip::AssetId,
    note::{
        Note, encrypt::NoteEncryption, transfer::TransferNote, unshield::UnshieldNote,
        utxo::UtxoNote,
    },
    transact::spend::{Spend, SpendError},
};

/// Several amount intents resolved together, so one selection can cover more
/// than one output. [`RailgunProvider::transfer_amount`](crate::provider::RailgunProvider::transfer_amount)
/// is the one-intent form.
#[derive(Clone, Default)]
pub struct AmountIntents {
    intents: Vec<Intent>,
    unshields: HashSet<(RailgunAddress, AssetId)>,
    adapt_contract: Option<Address>,
    adapt_params: Option<[u8; 32]>,
    hybrid_change: bool,
}

#[derive(Debug, Error)]
pub enum AmountError {
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
    #[error(transparent)]
    Spend(#[from] SpendError),
}

#[derive(Clone)]
struct Intent {
    from: Arc<dyn RailgunSigner>,
    asset: AssetId,
    value: u128,
    kind: IntentKind,
}

#[derive(Clone)]
enum IntentKind {
    Transfer {
        to: RailgunAddress,
        memo: String,
        encryption: NoteEncryption,
    },
    Unshield {
        to: Address,
    },
}

struct Draft {
    signer: Arc<dyn RailgunSigner>,
    outputs: Vec<TransferNote>,
    unshield: Option<UnshieldNote>,
}

impl Draft {
    fn out_value(&self) -> u128 {
        self.outputs.iter().map(Note::value).sum::<u128>()
            + self.unshield.as_ref().map_or(0, Note::value)
    }
}

impl AmountIntents {
    pub fn new() -> Self {
        Self::default()
    }

    /// A transfer encrypted the way every Railgun wallet reads ([`NoteEncryption::Legacy`]).
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

    /// A transfer whose note is encrypted with `encryption`, for instance
    /// [`NoteEncryption::HybridPq`] with the receiver's published KEM key.
    pub fn transfer_with_encryption(
        mut self,
        from: Arc<dyn RailgunSigner>,
        to: RailgunAddress,
        asset: AssetId,
        value: u128,
        memo: &str,
        encryption: NoteEncryption,
    ) -> Self {
        self.intents.push(Intent {
            from,
            asset,
            value,
            kind: IntentKind::Transfer {
                to,
                memo: memo.to_string(),
                encryption,
            },
        });
        self
    }

    /// Encrypts the change notes with [`NoteEncryption::HybridPq`] to their signer's own KEM
    /// key, see [`Spend::with_hybrid_change`].
    pub fn with_hybrid_change(mut self) -> Self {
        self.hybrid_change = true;
        self
    }

    pub fn unshield(
        mut self,
        from: Arc<dyn RailgunSigner>,
        to: Address,
        asset: AssetId,
        value: u128,
    ) -> Result<Self, AmountError> {
        if self.unshields.contains(&(from.address(), asset)) {
            return Err(AmountError::MultipleUnshields {
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
        });
        Ok(self)
    }

    pub fn adapt(mut self, contract: Address, params: [u8; 32]) -> Self {
        self.adapt_contract = Some(contract);
        self.adapt_params = Some(params);
        self
    }

    pub(crate) fn resolve(
        self,
        notes: &[UtxoNote],
        rng: &mut impl CryptoRng,
    ) -> Result<Vec<Spend>, AmountError> {
        let adapt = self
            .adapt_contract
            .map(|contract| (contract, self.adapt_params.unwrap_or([0u8; 32])));
        let mut groups: BTreeMap<(RailgunAddress, AssetId), Vec<Intent>> = BTreeMap::new();
        for intent in self.intents {
            groups
                .entry((intent.from.address(), intent.asset))
                .or_default()
                .push(intent);
        }

        let mut spends = Vec::new();
        for ((from, asset), intents) in groups {
            spends.extend(build_group(
                notes,
                from,
                asset,
                intents,
                adapt,
                self.hybrid_change,
                rng,
            )?);
        }
        Ok(spends)
    }
}

/// Add a fee output to an existing batch of spends.
///
/// The fee stays one output of exactly `fee`. It is merged into the spend on the
/// oldest tree whose remaining value (change, plus notes not already spent) covers
/// it. A tree that does not already have a spend gets a new one. Adapting the
/// batch applies to every spend, including ones the fee does not touch.
#[allow(clippy::too_many_arguments)]
pub(crate) fn attach_fee(
    spends: &[Spend],
    fee_payer: Arc<dyn RailgunSigner>,
    fee_to: RailgunAddress,
    fee_asset: AssetId,
    fee: u128,
    available: &[UtxoNote],
    adapt_contract: Address,
    adapt_params: [u8; 32],
    rng: &mut impl CryptoRng,
) -> Result<Vec<Spend>, AmountError> {
    let mut spends = spends.to_vec();
    for spend in &mut spends {
        if !spend.is_finalized() {
            return Err(SpendError::NotFinalized.into());
        }
        spend.set_adapt(adapt_contract, adapt_params);
    }
    // A fee spend opened on another tree follows the batch's choice for its change note.
    let hybrid_change = spends.iter().any(Spend::hybrid_change);

    let viewing = fee_payer.viewing_key().public_key();
    let used: HashSet<(u32, u32)> = spends
        .iter()
        .flat_map(|spend| {
            spend
                .inputs()
                .iter()
                .map(|note| (note.tree_number, note.leaf_index))
        })
        .collect();

    let mut unused: BTreeMap<u32, Vec<&UtxoNote>> = BTreeMap::new();
    for note in available {
        if note.asset != fee_asset || note.viewing_pubkey != viewing {
            continue;
        }
        if used.contains(&(note.tree_number, note.leaf_index)) {
            continue;
        }
        unused.entry(note.tree_number).or_default().push(note);
    }
    for spend in &spends {
        if spend.asset() == fee_asset && spend.signer().address() == fee_payer.address() {
            unused.entry(spend.tree()).or_default();
        }
    }

    let available_on = |tree: u32, spends: &[Spend], unused: &BTreeMap<u32, Vec<&UtxoNote>>| {
        let change: u128 = spends
            .iter()
            .filter(|spend| {
                spend.tree() == tree
                    && spend.asset() == fee_asset
                    && spend.signer().address() == fee_payer.address()
            })
            .map(Spend::change_value)
            .sum();
        let extra: u128 = unused
            .get(&tree)
            .map_or(0, |notes| notes.iter().map(|note| note.value()).sum());
        change + extra
    };

    let Some(tree) = unused
        .keys()
        .copied()
        .find(|tree| available_on(*tree, &spends, &unused) >= fee)
    else {
        return Err(AmountError::InsufficientBalance {
            from: fee_payer.address(),
            asset: fee_asset,
            value: fee,
        });
    };

    // The paymaster checks the fee from `paymasterData`, it has no use for the sender: hidden,
    // so that opening the fee note does not tell which account paid.
    let fee_note = TransferNote::new(
        fee_payer.viewing_key(),
        fee_to,
        fee_asset,
        fee,
        rng.random(),
        "fee",
    )
    .with_hidden_sender();

    if let Some(spend) = spends.iter_mut().find(|spend| {
        spend.tree() == tree
            && spend.asset() == fee_asset
            && spend.signer().address() == fee_payer.address()
    }) {
        let need = fee.saturating_sub(spend.change_value());
        let extra = select_notes(slice_at(&unused, tree), need)
            .into_iter()
            .cloned()
            .collect();
        spend.absorb(extra, fee_note, rng)?;
    } else {
        spends.push(open_fee_spend(
            fee_payer,
            fee_asset,
            fee,
            fee_note,
            slice_at(&unused, tree),
            (adapt_contract, adapt_params),
            hybrid_change,
            rng,
        )?);
    }

    Ok(spends)
}

fn build_group(
    in_notes: &[UtxoNote],
    from: RailgunAddress,
    asset: AssetId,
    mut intents: Vec<Intent>,
    adapt: Option<(Address, [u8; 32])>,
    hybrid_change: bool,
    rng: &mut impl CryptoRng,
) -> Result<Vec<Spend>, AmountError> {
    // Smallest first, so a small intent does not get pushed onto a later tree
    // by a larger one that could have used that later tree itself.
    intents.sort_by_key(|intent| intent.value);

    let tree_notes = in_notes
        .iter()
        .filter(|note| note.asset == asset && note.viewing_pubkey == from.viewing_pubkey())
        .fold(BTreeMap::new(), |mut acc, note| {
            acc.entry(note.tree_number)
                .or_insert_with(Vec::new)
                .push(note);
            acc
        });
    let mut balances: BTreeMap<u32, u128> = tree_notes
        .iter()
        .map(|(tree, notes)| (*tree, notes.iter().map(|note| note.value()).sum()))
        .collect();

    let mut drafts: BTreeMap<u32, Draft> = BTreeMap::new();
    for intent in intents {
        let single = balances
            .iter()
            .find(|(_, balance)| **balance >= intent.value)
            .map(|(tree, _)| *tree);
        if let Some(tree) = single {
            *balances.get_mut(&tree).unwrap() -= intent.value;
            insert_draft(&mut drafts, tree, &intent, rng);
            continue;
        }
        split_intent(from, asset, &intent, &mut balances, &mut drafts, rng)?;
    }

    let mut spends = Vec::new();
    for (tree, draft) in drafts {
        let notes = tree_notes.get(&tree).expect("draft tree has notes");
        let selected = select_notes(notes, draft.out_value());
        let inputs: Vec<UtxoNote> = selected.into_iter().cloned().collect();
        spends.push(Spend::from_selected(
            draft.signer,
            inputs,
            draft.outputs,
            draft.unshield,
            adapt,
            hybrid_change,
            rng,
        )?);
    }
    Ok(spends)
}

fn slice_at<'a, 'b>(notes: &'b BTreeMap<u32, Vec<&'a UtxoNote>>, tree: u32) -> &'b [&'a UtxoNote] {
    notes.get(&tree).map_or(&[], Vec::as_slice)
}

fn open_fee_spend(
    fee_payer: Arc<dyn RailgunSigner>,
    fee_asset: AssetId,
    fee: u128,
    fee_note: TransferNote,
    notes: &[&UtxoNote],
    adapt: (Address, [u8; 32]),
    hybrid_change: bool,
    rng: &mut impl CryptoRng,
) -> Result<Spend, AmountError> {
    let inputs: Vec<UtxoNote> = select_notes(notes, fee).into_iter().cloned().collect();
    let input_value: u128 = inputs.iter().map(Note::value).sum();
    if input_value < fee {
        return Err(AmountError::InsufficientBalance {
            from: fee_payer.address(),
            asset: fee_asset,
            value: fee,
        });
    }
    Spend::from_selected(
        fee_payer,
        inputs,
        vec![fee_note],
        None,
        Some(adapt),
        hybrid_change,
        rng,
    )
    .map_err(Into::into)
}

fn split_intent(
    from: RailgunAddress,
    asset: AssetId,
    intent: &Intent,
    balances: &mut BTreeMap<u32, u128>,
    drafts: &mut BTreeMap<u32, Draft>,
    rng: &mut impl CryptoRng,
) -> Result<(), AmountError> {
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
        insert_draft(drafts, tree, &partial, rng);
        remaining -= take;
    }
    if remaining > 0 {
        return Err(AmountError::InsufficientBalance {
            from,
            asset,
            value: intent.value,
        });
    }
    Ok(())
}

fn insert_draft(
    drafts: &mut BTreeMap<u32, Draft>,
    tree: u32,
    intent: &Intent,
    rng: &mut impl CryptoRng,
) {
    let draft = drafts.entry(tree).or_insert_with(|| Draft {
        signer: intent.from.clone(),
        outputs: Vec::new(),
        unshield: None,
    });
    match &intent.kind {
        IntentKind::Transfer {
            to,
            memo,
            encryption,
        } => draft.outputs.push(
            TransferNote::new(
                intent.from.viewing_key(),
                *to,
                intent.asset,
                intent.value,
                rng.random(),
                memo,
            )
            .with_encryption(encryption.clone()),
        ),
        IntentKind::Unshield { to } => {
            draft.unshield = Some(UnshieldNote::new(*to, intent.asset, intent.value));
        }
    }
}

/// Oldest notes first, until their sum covers `value`.
///
/// A zero `value` selects nothing. A fee that already fits in change must not pull another note.
fn select_notes<'a>(notes: &'a [&UtxoNote], value: u128) -> Vec<&'a UtxoNote> {
    let mut selected = Vec::new();
    let mut total = 0;
    for note in notes {
        if value == 0 {
            break;
        }
        selected.push(*note);
        total += note.value();
        if total >= value {
            break;
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;
    use rand::random;

    use super::*;
    use crate::{account::signer::PrivateKeySigner, poi::types::BlindedCommitmentType};

    const WETH: AssetId = AssetId::Erc20(address!("0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14"));

    fn note(signer: &Arc<PrivateKeySigner>, tree: u32, leaf: u32, value: u128) -> UtxoNote {
        UtxoNote::new(
            tree,
            leaf,
            signer.clone(),
            WETH,
            value,
            random(),
            "",
            BlindedCommitmentType::Shield,
        )
    }

    #[test]
    fn selection_takes_oldest_notes_until_the_sum_covers_the_value() {
        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let notes = [note(&me, 0, 0, 40), note(&me, 0, 1, 70)];
        let spends = AmountIntents::new()
            .transfer(me.clone(), other.address(), WETH, 50, "pay")
            .resolve(&notes, &mut rand::rng())
            .unwrap();
        assert_eq!(spends.len(), 1);
        assert_eq!(spends[0].inputs().len(), 2);
        assert_eq!(spends[0].inputs()[0].value(), 40);
        assert_eq!(spends[0].inputs()[1].value(), 70);
        assert_eq!(spends[0].transfers()[0].value(), 50);
        assert_eq!(spends[0].transfers()[0].memo(), "pay");
        assert_eq!(spends[0].change_note().unwrap().value(), 60);
        assert_eq!(spends[0].change_note().unwrap().memo(), "change");

        let reversed = [note(&me, 0, 0, 70), note(&me, 0, 1, 40)];
        let spends = AmountIntents::new()
            .transfer(me, other.address(), WETH, 50, "")
            .resolve(&reversed, &mut rand::rng())
            .unwrap();
        assert_eq!(spends[0].inputs().len(), 1);
        assert_eq!(spends[0].inputs()[0].value(), 70);
        assert_eq!(spends[0].change_note().unwrap().value(), 20);
    }

    #[test]
    fn the_smaller_intent_takes_the_older_tree() {
        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let notes = [note(&me, 0, 0, 50), note(&me, 1, 0, 50)];
        let spends = AmountIntents::new()
            .transfer(me.clone(), other.address(), WETH, 40, "big")
            .transfer(me, other.address(), WETH, 30, "small")
            .resolve(&notes, &mut rand::rng())
            .unwrap();
        assert_eq!(spends.len(), 2);
        let tree0 = spends.iter().find(|spend| spend.tree() == 0).unwrap();
        let tree1 = spends.iter().find(|spend| spend.tree() == 1).unwrap();
        assert_eq!(tree0.transfers()[0].value(), 30);
        assert_eq!(tree0.change_note().unwrap().value(), 20);
        assert_eq!(tree1.transfers()[0].value(), 40);
        assert_eq!(tree1.change_note().unwrap().value(), 10);
    }

    #[test]
    fn an_amount_that_fits_no_single_tree_is_split() {
        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let notes = [note(&me, 0, 0, 40), note(&me, 1, 0, 30)];
        let spends = AmountIntents::new()
            .transfer(me, other.address(), WETH, 50, "")
            .resolve(&notes, &mut rand::rng())
            .unwrap();
        assert_eq!(spends.len(), 2);
        let tree0 = spends.iter().find(|spend| spend.tree() == 0).unwrap();
        let tree1 = spends.iter().find(|spend| spend.tree() == 1).unwrap();
        assert_eq!(tree0.transfers()[0].value(), 40);
        assert!(tree0.change_note().is_none());
        assert_eq!(tree1.transfers()[0].value(), 10);
        assert_eq!(tree1.change_note().unwrap().value(), 20);
    }

    #[test]
    fn a_fee_merges_into_change_or_opens_an_older_tree() {
        let me = PrivateKeySigner::new_evm(random(), random(), 1);
        let other = PrivateKeySigner::new_evm(random(), random(), 1);
        let paymaster = PrivateKeySigner::new_evm(random(), random(), 1);
        let notes = [note(&me, 0, 0, 100)];
        let spend = AmountIntents::new()
            .transfer(me.clone(), other.address(), WETH, 30, "")
            .resolve(&notes, &mut rand::rng())
            .unwrap();
        let with_fee = attach_fee(
            &spend,
            me.clone(),
            paymaster.address(),
            WETH,
            10,
            &notes,
            Address::repeat_byte(0x11),
            [1u8; 32],
            &mut rand::rng(),
        )
        .unwrap();
        assert_eq!(with_fee.len(), 1);
        assert_eq!(with_fee[0].inputs().len(), 1);
        assert_eq!(with_fee[0].transfers().len(), 2);
        assert!(
            with_fee[0]
                .transfers()
                .iter()
                .any(|note| note.memo() == "fee" && note.value() == 10 && note.hide_sender)
        );
        assert_eq!(with_fee[0].change_note().unwrap().value(), 60);

        let tree0 = note(&me, 0, 0, 40);
        let tree1 = note(&me, 1, 0, 100);
        let notes = [tree0.clone(), tree1];
        let spend = Spend::try_new(me.clone(), vec![notes[1].clone()])
            .unwrap()
            .unshield(address!("0x00000000000000000000000000000000000000aa"), 50)
            .unwrap()
            .with_change(&mut rand::rng())
            .unwrap();
        let with_fee = attach_fee(
            &[spend],
            me,
            paymaster.address(),
            WETH,
            10,
            &notes,
            Address::repeat_byte(0x11),
            [2u8; 32],
            &mut rand::rng(),
        )
        .unwrap();
        assert_eq!(with_fee.len(), 2);
        let fee_spend = with_fee.iter().find(|spend| spend.tree() == 0).unwrap();
        assert_eq!(fee_spend.transfers().len(), 1);
        assert_eq!(fee_spend.transfers()[0].value(), 10);
        assert_eq!(fee_spend.transfers()[0].memo(), "fee");
        assert_eq!(fee_spend.change_note().unwrap().value(), 30);
        assert!(
            with_fee
                .iter()
                .any(|spend| spend.tree() == 1 && spend.unshield_note().is_some())
        );
    }
}
