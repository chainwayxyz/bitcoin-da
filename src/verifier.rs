use bitcoin::hashes::Hash;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{DaSpec, DaVerifier};
use sov_rollup_interface::digest::Digest;
use sov_rollup_interface::zk::ValidityCondition;
use thiserror::Error;

use crate::helpers::parsers::parse_transaction;
use crate::spec::merkletree::BitcoinMerkleTree;
use crate::spec::BitcoinSpec;

pub struct BitcoinVerifier {
    pub rollup_name: String,
}

// TODO: custom errors based on our implementation
#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ValidationError {
    InvalidTx,
    InvalidProof,
    InvalidBlock,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Hash,
    BorshDeserialize,
    BorshSerialize,
)]
/// A validity condition expressing that a chain of DA layer blocks is contiguous and canonical
pub struct ChainValidityCondition {
    pub prev_hash: [u8; 32],
    pub block_hash: [u8; 32],
}
#[derive(Error, Debug)]
pub enum ValidityConditionError {
    #[error("conditions for validity can only be combined if the blocks are consecutive")]
    BlocksNotConsecutive,
}

impl ValidityCondition for ChainValidityCondition {
    type Error = ValidityConditionError;
    fn combine<H: Digest>(&self, rhs: Self) -> Result<Self, Self::Error> {
        if self.block_hash != rhs.prev_hash {
            return Err(ValidityConditionError::BlocksNotConsecutive);
        }
        Ok(rhs)
    }
}

impl DaVerifier for BitcoinVerifier {
    type Spec = BitcoinSpec;

    type Error = ValidationError;

    fn new(params: <Self::Spec as DaSpec>::ChainParams) -> Self {
        Self {
            rollup_name: params.rollup_name,
        }
    }

    // Verify that the given list of blob transactions is complete and correct.
    fn verify_relevant_tx_list<H: Digest>(
        &self,
        block_header: &<Self::Spec as sov_rollup_interface::da::DaSpec>::BlockHeader,
        txs: &[<Self::Spec as sov_rollup_interface::da::DaSpec>::BlobTransaction],
        inclusion_proof: <Self::Spec as sov_rollup_interface::da::DaSpec>::InclusionMultiProof,
        completeness_proof: <Self::Spec as sov_rollup_interface::da::DaSpec>::CompletenessProof,
    ) -> Result<<Self::Spec as DaSpec>::ValidityCondition, Self::Error> {
        let validity_condition = ChainValidityCondition {
            prev_hash: block_header.header.prev_blockhash.as_hash().into_inner(),
            block_hash: block_header.header.block_hash().as_hash().into_inner(),
        };

        let tx_root = block_header.header.merkle_root.as_hash().into_inner();

        if txs.is_empty() {
            return Ok(validity_condition);
        }

        // Inclusion proof is all the txs in the block.
        let tree_from_inclusion = BitcoinMerkleTree::from_leaves(inclusion_proof.txs.clone());
        let root_from_inclusion = tree_from_inclusion.get_root().unwrap();

        txs.iter().for_each(|tx| {
            assert!(inclusion_proof.txs.contains(&tx.hash));
        });

        assert_eq!(root_from_inclusion, tx_root);

        // Completeness proof is all the txs in the block.
        // 1. Generate merkle tree and assert roots are the same
        // 2. Go over all txs and assert txs outside relevant_txs don't have specific script
        let tx_ids = completeness_proof
            .iter()
            .map(|tx| tx.transaction.txid().as_hash().into_inner())
            .collect::<Vec<_>>();

        let tree_from_completeness = BitcoinMerkleTree::from_leaves(tx_ids);
        let root_from_completeness = tree_from_completeness.get_root().unwrap();

        assert_eq!(root_from_completeness, tx_root);

        let relevant_txs = txs
            .iter()
            .map(|tx| (tx.hash, true))
            .collect::<std::collections::HashMap<_, _>>();

        // get non-included txs
        let irrelevant_txs = completeness_proof
            .iter()
            .filter(|tx| !relevant_txs.contains_key(&tx.transaction.txid().as_hash().into_inner()))
            .collect::<Vec<_>>();

        for irrelevant_tx in irrelevant_txs {
            // assert no relevant script in tx
            assert!(parse_transaction(&irrelevant_tx.transaction, &self.rollup_name).is_err());
        }

        Ok(validity_condition)
    }
}
