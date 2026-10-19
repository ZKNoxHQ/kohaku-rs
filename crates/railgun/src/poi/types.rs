//! Types for the POI client
//!
//! <https://github.com/Railgun-Community/private-proof-of-innocence/blob/4b1eaf6ef19099dbfd6b43b1ca78d2ce0132a752/packages/node/src/api/README.md>

use std::{fmt::Display, str::FromStr};

use ruint::aliases::U256;
use serde::{Deserialize, Serialize};

use crate::{circuit::proof::Proof, crypto::railgun_txid::Txid, merkle_tree::MerkleRoot};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(js, derive(tsify::Tsify))]
#[cfg_attr(js, tsify(into_wasm_abi, from_wasm_abi, type = "string"))]
pub struct ListKey(String);

#[derive(Debug, Copy, Clone, PartialEq, Deserialize, Eq, Hash)]
pub struct BlindedCommitment(U256);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TxidVersion {
    #[serde(rename = "V2_PoseidonMerkle")]
    V2PoseidonMerkle,
    #[serde(rename = "V3_PoseidonMerkle")]
    V3PoseidonMerkle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(js, derive(tsify::Tsify))]
#[cfg_attr(js, tsify(into_wasm_abi, from_wasm_abi))]
pub enum BlindedCommitmentType {
    Shield,
    Transact,
    Unshield,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[cfg_attr(js, derive(tsify::Tsify))]
#[cfg_attr(js, tsify(into_wasm_abi, from_wasm_abi))]
pub enum PoiStatus {
    Valid,
    ProofSubmitted,
    Missing,
    ShieldBlocked,
    /// Local observation failure, not a status reported by a POI node.
    /// Does not establish absence and must not authorize proof submission.
    Unavailable,
}

// The node reports only protocol statuses. Keep local observation failures out
// of its wire vocabulary while allowing public/cached statuses to round-trip.
#[cfg(test)]
#[derive(Debug, Clone, Copy, Deserialize)]
pub(crate) enum PoiNodeStatus {
    Valid,
    ProofSubmitted,
    Missing,
    ShieldBlocked,
}

#[cfg(test)]
impl From<PoiNodeStatus> for PoiStatus {
    fn from(value: PoiNodeStatus) -> Self {
        match value {
            PoiNodeStatus::Valid => Self::Valid,
            PoiNodeStatus::ProofSubmitted => Self::ProofSubmitted,
            PoiNodeStatus::Missing => Self::Missing,
            PoiNodeStatus::ShieldBlocked => Self::ShieldBlocked,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainParams {
    pub chain_type: String,
    #[serde(rename = "chainID")]
    pub chain_id: String,
    pub txid_version: TxidVersion,
}

/// Range of POI list leaves. `end_index` is exclusive. The node returns at most
/// 100 leaves and pads past the end of the list with the POI zero.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPoiMerkletreeLeavesParams {
    #[serde(flatten)]
    pub chain: ChainParams,
    pub list_key: ListKey,
    pub start_index: u64,
    pub end_index: u64,
}

/// Asks whether these POI roots have been published. Carries no commitments.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatePoiMerklerootsParams {
    #[serde(flatten)]
    pub chain: ChainParams,
    pub list_key: ListKey,
    pub poi_merkleroots: Vec<MerkleRoot>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ValidatedRailgunTxidStatus {
    #[serde(rename = "validatedTxidIndex")]
    pub index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidateTxidMerklerootParams {
    #[serde(flatten)]
    pub chain: ChainParams,
    pub tree: u32,
    pub index: u32,
    pub merkleroot: MerkleRoot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubmitTransactProofParams {
    #[serde(flatten)]
    pub chain: ChainParams,
    pub list_key: ListKey,
    pub transact_proof_data: TransactProofData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactProofData {
    #[serde(rename = "snarkProof")]
    pub proof: Proof,
    pub poi_merkleroots: Vec<MerkleRoot>,
    /// Merkle root of the txid tree the inclusion proof was generated with
    pub txid_merkleroot: MerkleRoot,
    /// Index of the txid tree the inclusion proof was generated with
    ///
    /// NOT the leaf index of the txid, but the index for the merkleroot of the
    /// txid tree. If a single railgun transaction had multiple txids, this
    /// would be the same for all of them since they're all being proven against
    /// the same snapshot of the txid tree.
    pub txid_merkleroot_index: u64,
    pub blinded_commitments_out: Vec<BlindedCommitment>,
    pub railgun_txid_if_has_unshield: Txid,
}

/// POI proof of one operation for one list, with the public values a POI node or a broadcaster
/// checks it against. See `RailgunProvider::prove_operation_pois`.
#[derive(Debug, Clone)]
pub struct OperationPoi {
    pub proof: Proof,
    /// Root of the txid inclusion proof the proof was made with.
    pub txid_merkleroot: MerkleRoot,
    pub poi_merkleroots: Vec<MerkleRoot>,
    /// Blinded commitments of the outputs at the position the proof was made for.
    pub blinded_commitments_out: Vec<BlindedCommitment>,
    pub railgun_txid_if_has_unshield: Txid,
}

impl ValidatedRailgunTxidStatus {
    pub fn tree(&self) -> u32 {
        (self.index >> 16) as u32
    }

    pub fn leaf_index(&self) -> u32 {
        self.index & 0xFFFF
    }
}

impl Display for ListKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ListKey({})", self.0)
    }
}

impl Display for BlindedCommitment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlindedCommitment({:#x})", self.0)
    }
}

impl From<String> for ListKey {
    fn from(value: String) -> Self {
        ListKey(value)
    }
}

impl From<ListKey> for String {
    fn from(value: ListKey) -> Self {
        value.0
    }
}

impl From<&str> for ListKey {
    fn from(value: &str) -> Self {
        ListKey(value.to_string())
    }
}

impl From<U256> for BlindedCommitment {
    fn from(value: U256) -> Self {
        BlindedCommitment(value)
    }
}

impl From<BlindedCommitment> for U256 {
    fn from(value: BlindedCommitment) -> Self {
        value.0
    }
}

impl Serialize for BlindedCommitment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let hex_string = format!("0x{:064x}", self.0);
        serializer.serialize_str(&hex_string)
    }
}

impl Display for PoiStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            PoiStatus::Valid => "Valid",
            PoiStatus::ShieldBlocked => "ShieldBlocked",
            PoiStatus::ProofSubmitted => "ProofSubmitted",
            PoiStatus::Missing => "Missing",
            PoiStatus::Unavailable => "Unavailable",
        };
        write!(f, "{}", s)
    }
}

impl FromStr for PoiStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "valid" => Ok(PoiStatus::Valid),
            "shieldblocked" => Ok(PoiStatus::ShieldBlocked),
            "proofsubmitted" => Ok(PoiStatus::ProofSubmitted),
            "missing" => Ok(PoiStatus::Missing),
            "unavailable" => Ok(PoiStatus::Unavailable),
            _ => Err(()),
        }
    }
}

impl FromStr for ListKey {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(ListKey(s.to_string()))
    }
}
