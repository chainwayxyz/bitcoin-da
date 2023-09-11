use std::collections::HashSet;

use bitcoin::hashes::Hash;
use bitcoin::{merkle_tree, Txid};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{DaSpec, DaVerifier};
use sov_rollup_interface::digest::Digest;
use sov_rollup_interface::zk::ValidityCondition;
use thiserror::Error;

use crate::helpers::parsers::parse_transaction;
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
            prev_hash: block_header
                .header
                .prev_blockhash
                .to_raw_hash()
                .to_byte_array(),
            block_hash: block_header
                .header
                .block_hash()
                .to_raw_hash()
                .to_byte_array(),
        };

        // completeness proof

        // create hash set of txs
        let mut txs_to_check = txs
            .iter()
            .map(|blob| blob.hash)
            .collect::<HashSet<_>>();

        // Check every 00 bytes tx that parsed correctly is in txs
        let mut completeness_tx_hashes = completeness_proof.iter().map(|tx| {
            let tx_hash = tx.txid().to_raw_hash().to_byte_array();

            // it must parsed correctly
            let parsed_tx = parse_transaction(tx, &self.rollup_name);
            if parsed_tx.is_ok() {
                let blob = parsed_tx.unwrap().body;
                let blob_hash: [u8; 32] = bitcoin::hashes::sha256d::Hash::hash(&blob).to_byte_array();
                // it must be in txs
                assert!(txs_to_check.remove(&blob_hash));
            }

            tx_hash
        })
        .collect::<HashSet<_>>();
        

        // assert no extra txs than the ones in the completeness proof are left
        assert!(txs_to_check.is_empty());

        // no 00 bytes left behind completeness proof
        inclusion_proof.txs.iter().for_each(|tx_hash| {
            if tx_hash[0..2] == [0, 0] {
                assert!(completeness_tx_hashes.remove(tx_hash));
            }
        });

        // assert all transactions are included in block
        assert!(completeness_tx_hashes.is_empty());   

        let tx_root = block_header
            .header
            .merkle_root
            .to_raw_hash()
            .to_byte_array();

        // Inclusion proof is all the txs in the block.
        let tx_hashes = inclusion_proof
            .txs
            .iter()
            .map(|tx| Txid::from_slice(tx).unwrap())
            .collect::<Vec<_>>();

        let root_from_inclusion = merkle_tree::calculate_root(tx_hashes.into_iter())
            .unwrap()
            .to_raw_hash()
            .to_byte_array();

        // Check that the tx root in the block header matches the tx root in the inclusion proof.
        assert_eq!(root_from_inclusion, tx_root);

        Ok(validity_condition)
    }
}

#[cfg(test)]
mod tests {

    use core::str::FromStr;
    use hex;
    use bitcoin::{block::{Header, Version}, BlockHash, hash_types::TxMerkleNode, CompactTarget, string::FromHexStr, Transaction, consensus::Decodable, hashes::Hash};
    use sov_rollup_interface::da::{DaVerifier, DaSpec};

    use crate::{spec::{header::HeaderWrapper, blob::BlobWithSender, proof::InclusionMultiProof, transaction::ExtendedTransaction}, helpers::{parsers::{parse_transaction, recover_sender_and_hash_from_tx}, builders::decompress_blob}};

    use super::BitcoinVerifier;

    fn get_mock_txs() -> Vec<Transaction> {
        // relevant txs are on 6, 8, 10, 12 indices
        let txs = std::fs::read_to_string("test_data/mock_txs.txt").unwrap();

        txs.lines().map(|tx| {
            Transaction::consensus_decode(&mut &hex::decode(tx).unwrap()[..]).unwrap()
        }).collect()
    }

    fn get_blob_with_sender(tx: &Transaction) -> BlobWithSender {
        let (sender, blob_hash) = recover_sender_and_hash_from_tx(tx, "sov-btc").unwrap();

        let tx = ExtendedTransaction {
            transaction: tx.clone(),
            sender: Some(sender),
            blob_hash: Some(blob_hash)
        };

        let parsed_inscription = parse_transaction(&tx.transaction, "sov-btc").unwrap();

        let blob = parsed_inscription.body;

        // Decompress the blob
        let decompressed_blob = decompress_blob(&blob);

        BlobWithSender::new(
            decompressed_blob,
            tx.sender.clone(),
            tx.blob_hash,
        )
    }

    fn get_mock_data() -> (
        <<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::BlockHeader, // block header
        <<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::InclusionMultiProof, // inclusion proof
        <<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::CompletenessProof, // completeness proof
        Vec<<<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::BlobTransaction> // txs
    ) {

        // let secp = Secp256k1::new();
        // let key = SecretKey::from_str("E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262").unwrap();
        // let public_key = PublicKey::from_secret_key(&secp, &key);

        let header = HeaderWrapper {
            header: Header {
                version: Version::from_consensus(536870912),
                prev_blockhash: BlockHash::from_str("6b15a2e4b17b0aabbd418634ae9410b46feaabf693eea4c8621ffe71435d24b0").unwrap(),
                merkle_root: TxMerkleNode::from_str("7750076b3b5498aad3e2e7da55618c66394d1368dc08f19f0b13d1e5b83ae056").unwrap(),
                time: 1694177029,
                bits: CompactTarget::from_hex_str_no_prefix("207fffff").unwrap(),
                nonce: 0,
            },
            tx_count: 13,
        };

        let block_txs = get_mock_txs();

        // relevant txs are on 6, 8, 10, 12 indices
        let completeness_proof = vec![
            block_txs[6].clone(),
            block_txs[8].clone(),
            block_txs[10].clone(),
            block_txs[12].clone(),
        ];

        let inclusion_proof = InclusionMultiProof {
            txs: block_txs.iter().map(|t| t.txid().to_raw_hash().to_byte_array()).collect()
        };

        let txs: Vec<BlobWithSender>= vec![
            get_blob_with_sender(&block_txs[6]),
            get_blob_with_sender(&block_txs[8]),
            get_blob_with_sender(&block_txs[10]),
            get_blob_with_sender(&block_txs[12])
        ];

        (header, inclusion_proof, completeness_proof, txs)


    }

    #[test]
    fn test_inclusion_proof () {

        let (
            block_header,
            inclusion_proof,
            completeness_proof,
            txs
        ) = get_mock_data();


        // Put non-existing tx in inclusion proof

        // Don't put a tx in the inclusion proof

        // Empty inclusion proof

        // Break order of txs

    }

    #[test]
    fn test_completeness_proof () {
        // Omit relevant tx from completeness proof

        // Empty completeness proof
    }
}