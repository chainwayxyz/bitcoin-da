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
    use bitcoin::{block::{Header, Version}, BlockHash, hash_types::TxMerkleNode, CompactTarget, string::FromHexStr, secp256k1::{Secp256k1, SecretKey, PublicKey}, Transaction, consensus::Decodable};
    use sov_rollup_interface::da::{DaVerifier, DaSpec};

    use crate::spec::{header::HeaderWrapper, blob::BlobWithSender, address::AddressWrapper, proof::InclusionMultiProof};

    use super::BitcoinVerifier;
    
    fn mock_blob_with_sender(pub_key: &PublicKey, tx_id: &str) -> BlobWithSender {

        let mut out = hex::decode("aba902b2da4f900385da48b104439a22e590ab1cc85b9e43ec7b457b4a5c0000").unwrap();
        out.reverse();

        let x = out.as_slice();

        BlobWithSender::new(Vec::new(), AddressWrapper(pub_key.serialize().to_vec()), x.try_into().unwrap())
    }

    fn get_mock_data() -> (
        <<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::BlockHeader, // block header
        <<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::InclusionMultiProof, // inclusion proof
        <<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::CompletenessProof, // completeness proof
        Vec<<<BitcoinVerifier as DaVerifier>::Spec as DaSpec>::BlobTransaction> // txs
    ) {

        let secp = Secp256k1::new();
        let key = SecretKey::from_str("E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262").unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &key);

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

        let txs = vec![
            mock_blob_with_sender(&public_key, "5edf0ea353646d5bcba20a5f4e22036d348e864164c5b3f8fcfd62aa12c50000"),
            mock_blob_with_sender(&public_key, "0703a2686783ee57ff0cfac76df0d8997e1196a80cf7e67d0e8c893d27000000"),
            mock_blob_with_sender(&public_key, "aba902b2da4f900385da48b104439a22e590ab1cc85b9e43ec7b457b4a5c0000"),
            mock_blob_with_sender(&public_key, "3007598a6d61d3e7493d3435d986d05b14065641ac65aa93a707245833e40000")
        ];


        let mut completeness_proof = Vec::with_capacity(13);

        completeness_proof.push(Transaction::consensus_decode(&mut &hex::decode("01000000000101af49f3ced4752417ef844dd486a37df1b0b5eb5b4c6a52ad69caf0fc9cc7ea330000000000fdffffff012202000000000000160014371b02d451081c0cf541aa6b96552aa435ce789103405158341c234d131e629202e78dc1463a18fc5eb8a9fdeadbb0ace07080904686104b0670b64ce61aef9a08db7b66d2cb4abbb92d03235e5f40d1c32242f62feffd63012071a2477d43a5701e5b4f009ef2d920c2969ef9dd47f1524ff36b5dfa087a5a1dac0063010107736f762d627463010240cc4b23d2cb3e22b2c57a59f24088764f39f7b789847e983b9ee9ce7682578c2b7dbdf4384e230c942b91ae5ce6b1ba33587f549fedee4d19e54ff3a8e54601e801032102588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc90104038c0403004cc41b7b01f845c786b10e90638b5cd88023081823b06c20b90040401052860738a7c6cd60c7358f581158bbf7e6bc92c7391efe57ed40c593d8a2e09839969526a688dd6cdf3e13965aeca8592c53b7e8bbce8f89ea5492b146f243b3e5a5035eae51c7ebe6b8bc3cab03487b71a7990116d8b5afdc53370e95bb16a7c0adbd8489749b96ad15ae448c2be3bb332f7dc39b6d967b026f9f591af96f3669f1f7c9cc7b1dd047a2c392bbd145daf11142776253e420f5eccc169afb55693d0febc27f0db159036821c171a2477d43a5701e5b4f009ef2d920c2969ef9dd47f1524ff36b5dfa087a5a1d00000000").unwrap()[..]).unwrap());
        completeness_proof.push(Transaction::consensus_decode(&mut &hex::decode("010000000001013a931993d889efacf67ec6e98b4739c4d02af1a118de31dfab9331b9af7d121b0000000000fdffffff012202000000000000160014371b02d451081c0cf541aa6b96552aa435ce78910340ba74d48b5eee94276fa436baa74d3f6286220f5130db45f67f4990823d8be7453402e72fad80990566d643f4a1d2a0472258d742a95245435b8263493d958c68fd58012010dd634819823f9857759dceb16ed8c3977f8b2949972b0cc83d83bd55fbc98aac0063010107736f762d6274630102405ced8a43ccf97fe5aea00eff641c4ffd38dec00ec7b277bddaf48241e5e55feb69fe5281113209d1708beeba7ce8dcd821e9000674c1c8ef28c79a0e7bbc352b01032102588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9010403458000004cb91b6401f845c786b10e90638b5cd88023081823b06c10b9004040105286ab9c53e366b0e39a47ac08acdd7b735ec9e31c0fffab76a0e2496c5170cc1ccb4a1353c46eb66f9f094b2d76d42c96a95b942d2f1df0728d3a5e37c7e5e5591d40da8b3bcd0cb0c0ae7de59eba71a8dcb538056eed254ca4dbb46cad7025625c19df9d79e91bde6cb3dc1378fbccd2c87fb3498bbf4f66deeb803e121d96dc8d2ed28e8f10ba139b2207a96767b6d0dcaf4aeb795817fe6b88cd1a006821c110dd634819823f9857759dceb16ed8c3977f8b2949972b0cc83d83bd55fbc98a00000000").unwrap()[..]).unwrap());
        completeness_proof.push(Transaction::consensus_decode(&mut &hex::decode("010000000001012913ec7a7ba8a24c4ef3cea5a355ef11cfc98fac26c6d599b2d1ecc4bcae68600000000000fdffffff012202000000000000160014371b02d451081c0cf541aa6b96552aa435ce78910340d0644c8a26d02fad3139c8b72513c23184577c54a63706deb4946cc51bb62055f0129153763f006147fbd6ac837cacbc10e4cfc8187d0e6983f7621bfad5d24cfd5b012080c217aaa568136042683a4cfce040b51cd5b697eea59caddbb39c5bdc45a432ac0063010107736f762d6274630102407ba452bda72ead6ee34d52d28b4ac9b1a47e0481c0cd426b8d8eff6131e7e5292125e090e5af52e980fd522e787200d164819ec704be693a53a2f28fe69798eb01032102588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc9010402d047004cbd1b6a01f845c786b10e90638b5cd880130e9823b06c10b9004040105286cbc48ac0dabd37e7953ccef1f0bf6a072a9ec41605c7ccb1ac343145ec66fbf699b0d46247cd6299ba45df757e4c54a7928c35921f9a2d2f1df0728d3a5e37c7e5e5591d40da8b3bcd0cb0c0ae7de59eba71a8dcb538056eed254ca4dbb46cad7025625c19df9d79e91bde6cb3dc1378fbccd2c87fb3498bbf4f66deeb803e121d96dc8d2ed28e8f10ba139b2207a96767b6d0dcaf4aeb795817fe6b88cd1a006821c180c217aaa568136042683a4cfce040b51cd5b697eea59caddbb39c5bdc45a43200000000").unwrap()[..]).unwrap());
        completeness_proof.push(Transaction::consensus_decode(&mut &hex::decode("01000000000101db75e1e9b22f92e2e03c1305a36290de0f2adee6bd16dd18127e7e793d01a6530000000000fdffffff012202000000000000160014371b02d451081c0cf541aa6b96552aa435ce78910340f64562ba7e3c6c90cfd44aa657d3c5be5d9417e10ead079d7851a9000fa499bfa22dffffbc1e876429668d3865030c6d33b3e31635d40da8d48632952cd1433bfd2c01203348c52c55bf875b73d9fab83ee4af35f09c20eed1ca9cf386e502e891650466ac0063010107736f762d62746301024050bc15fbbad1c3fad49c3abaac9731939428b2b87c19d07e7b60b6fc0c29234166cf0984f5ddddc7b4b8445e69caaf8165eaccf17cb9063e59a05ff60a0e51a201032102588d202afcc1ee4ab5254c7847ec25b9a135bbda0f2bc69ee1a714749fd77dc901040399da00004c8d1b0f01f845c786b18e23608bdcde6013b582540020200829c361cea97133d8718d123f04d64e75ce2b799c43f1ff7b1da850892d0a8e99635969628ad8cdf6ed3361a9c5ce330b0000dda665bf0a7f448c2be3bb33afa7c39b6d967b026f9f591af93a9bb4f8ab32a3da017d246f587237bae8757c84d09dd81439e87976660bcdfdaab41ec5baf05f436cd6006821c13348c52c55bf875b73d9fab83ee4af35f09c20eed1ca9cf386e502e89165046600000000").unwrap()[..]).unwrap());


        let inclusion_proof = InclusionMultiProof { txs: txs.iter().map(|t| t.hash.clone()).collect() };

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