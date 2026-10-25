use kohaku_crypto::poseidon_hash;
use kohaku_merkle_tree::hasher::Hasher;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::merkle_tree::merkle_tree::NumberedMerkleTree;

/// POI list accumulator. Same depth and Poseidon hash as the Railgun UTXO tree.
/// The zero is the PPOI node's constant, kept separate so the list follows the
/// node if the UTXO zero ever changes. Today the two integers are equal.
#[derive(Debug, Clone, Copy)]
pub struct PoiHasher;

impl Hasher<2, U256> for PoiHasher {
    fn hash(children: [U256; 2]) -> U256 {
        poseidon_hash(&children).unwrap()
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

pub type PoiMerkleTree = NumberedMerkleTree<PoiHasher>;

/// How far a list has been copied locally. The next fetch starts at `next_index`.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct PoiSyncState {
    pub next_index: u64,
}

/// A missing leaf in a `ppoi_poi_merkletree_leaves` page. The node pads past the
/// end of the list with this value, so it is never inserted.
pub fn is_poi_empty_leaf(leaf: U256) -> bool {
    leaf == PoiHasher::zero()
}

#[cfg(all(test, native))]
mod tests {
    use super::*;
    use crate::crypto::railgun_zero::SNARK_PRIME;

    #[test]
    fn poi_zero_matches_the_node_constant() {
        let zero = PoiHasher::zero();
        let expected = U256::from_str_radix(
            "0488f89b25bc7011eaf6a5edce71aeafb9fe706faa3c0a5cd9cbe868ae3b9ffc",
            16,
        )
        .unwrap();
        assert_eq!(zero, expected);
        assert!(zero < SNARK_PRIME);
    }
}
