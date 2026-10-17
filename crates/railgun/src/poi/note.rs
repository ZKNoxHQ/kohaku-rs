use std::collections::HashMap;

use crate::{merkle_tree::PoiMerkleProof, note::utxo::UtxoNote, poi::types::ListKey};

#[derive(Clone)]
pub struct PoiNote {
    pub inner: UtxoNote,
    pub pois: HashMap<ListKey, PoiMerkleProof>,
}

impl PoiNote {
    pub fn new(note: UtxoNote, pois: HashMap<ListKey, PoiMerkleProof>) -> Self {
        Self { inner: note, pois }
    }
}
