use kohaku_crypto::{merkle_tree::MerkleConfig, poseidon_hash};
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::merkle_tree::TREE_DEPTH;

/// POI list accumulator. Same depth and Poseidon hash as the Railgun UTXO tree.
/// The zero is the PPOI node's constant, kept separate so the list follows the
/// node if the UTXO zero ever changes. Today the two integers are equal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoiMerkleConfig;

impl MerkleConfig for PoiMerkleConfig {
    const DEPTH: usize = TREE_DEPTH;

    fn hash(left: U256, right: U256) -> U256 {
        poseidon_hash(&[left, right]).unwrap()
    }

    fn zero() -> U256 {
        // `POIMerkletree.MERKLE_ZERO_VALUE` in the PPOI node. The node copied the
        // Railgun engine zero, so this integer matches the UTXO tree zero today.
        // It stays its own constant: the list must follow the node, not our tree.
        U256::from_be_bytes([
            0x04, 0x88, 0xf8, 0x9b, 0x25, 0xbc, 0x70, 0x11, 0xea, 0xf6, 0xa5, 0xed, 0xce, 0x71,
            0xae, 0xaf, 0xb9, 0xfe, 0x70, 0x6f, 0xaa, 0x3c, 0x0a, 0x5c, 0xd9, 0xcb, 0xe8, 0x68,
            0xae, 0x3b, 0x9f, 0xfc,
        ])
    }
}

pub type PoiMerkleTree = kohaku_crypto::merkle_tree::MerkleTree<PoiMerkleConfig>;
pub type PoiMerkleProof = kohaku_crypto::merkle_tree::MerkleProof<PoiMerkleConfig>;
pub type PoiMerkleTreeState = kohaku_crypto::merkle_tree::MerkleTreeState<PoiMerkleConfig>;

/// How far a list has been copied locally. The next fetch starts at `next_index`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PoiSyncState {
    pub next_index: u64,
}

/// A missing leaf in a `ppoi_poi_merkletree_leaves` page. The node pads past the
/// end of the list with this value, so it is never inserted.
pub fn is_poi_empty_leaf(leaf: U256) -> bool {
    leaf == PoiMerkleConfig::zero()
}

#[cfg(all(test, native))]
mod tests {
    use super::*;
    use crate::crypto::railgun_zero::SNARK_PRIME;

    #[test]
    fn poi_zero_matches_the_node_constant() {
        let zero = PoiMerkleConfig::zero();
        let expected = U256::from_str_radix(
            "0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc",
            16,
        )
        .unwrap();
        assert_eq!(zero, expected);
        assert!(zero < SNARK_PRIME);
    }

    #[test]
    fn inserted_leaf_has_a_valid_inclusion_proof() {
        let mut tree = PoiMerkleTree::new(0);
        let leaves = [U256::from(1u8), U256::from(2u8), U256::from(3u8)];
        tree.insert_leaves(&leaves, 0);

        assert_eq!(tree.leaves(), &leaves);
        let proof = tree.generate_proof_at(1).unwrap();
        assert!(proof.verify());
        assert_eq!(proof.element, U256::from(2u8));
        assert!(tree.generate_proof(U256::from(4u8)).is_err());
    }
}
