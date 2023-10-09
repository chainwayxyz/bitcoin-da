use core::result::Result::Ok;
use core::str::FromStr;
use core::time::Duration;
use std::sync::{Arc, Mutex};

use alloc::collections::VecDeque;
use async_trait::async_trait;
use bitcoin::address::NetworkUnchecked;
use bitcoin::consensus::encode;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::secp256k1::{ecdsa, Message, Secp256k1};
use bitcoin::{secp256k1, Address};
use hex::ToHex;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::services::da::DaService;
use tracing::info;

use crate::helpers::builders::{
    compress_blob, create_inscription_transactions, decompress_blob, sign_blob_with_private_key,
    write_reveal_tx,
};
use crate::helpers::parsers::parse_transaction;
use crate::rpc::{BitcoinNode, RPCError};
use crate::spec::blob::BlobWithSender;
use crate::spec::block::BitcoinBlock;
use crate::spec::proof::InclusionMultiProof;
use crate::spec::utxo::UTXO;
use crate::spec::{BitcoinSpec, RollupParams};
use crate::verifier::BitcoinVerifier;

/// A service that provides data and data availability proofs for Bitcoin
#[derive(Debug, Clone)]
pub struct BitcoinService {
    client: BitcoinNode,
    rollup_name: String,
    network: bitcoin::Network,
    address: Address<NetworkUnchecked>,
    sequencer_da_private_key: String,
    last_fee_rates: Arc<Mutex<VecDeque<f64>>>,
    fee_rates_to_avg: usize,
}

/// Runtime configuration for the DA service
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DaServiceConfig {
    /// The URL of the Bitcoin node to connect to
    pub node_url: String,
    pub node_username: String,
    pub node_password: String,

    // network of the bitcoin node
    pub network: String,

    // taproot address that holds the funds of the sequencer
    pub address: String,

    // da private key of the sequencer
    pub sequencer_da_private_key: Option<String>,

    // number of last paid fee rates to average if estimation fails
    pub fee_rates_to_avg: usize,
}

const FINALITY_DEPTH: u64 = 4; // blocks
const POLLING_INTERVAL: u64 = 10; // seconds

impl BitcoinService {
    // Create a new instance of the DA service from the given configuration.
    pub fn new(config: DaServiceConfig, chain_params: RollupParams) -> Self {
        let network =
            bitcoin::Network::from_str(&config.network).unwrap_or(bitcoin::Network::Regtest); // default to regtest (?)

        let client = BitcoinNode::new(
            config.node_url,
            config.node_username,
            config.node_password,
            network,
        );

        let address = Address::from_str(&config.address).expect("Invalid bitcoin address");

        Self::with_client(
            client,
            chain_params.rollup_name,
            network,
            address,
            config.sequencer_da_private_key.unwrap_or("".to_owned()),
            config.fee_rates_to_avg,
        )
    }

    pub fn with_client(
        client: BitcoinNode,
        rollup_name: String,
        network: bitcoin::Network,
        address: Address<NetworkUnchecked>,
        sequencer_da_private_key: String,
        fee_rates_to_avg: usize,
    ) -> Self {
        Self {
            client,
            rollup_name,
            network,
            address,
            sequencer_da_private_key,
            last_fee_rates: Arc::new(Mutex::new(VecDeque::new())),
            fee_rates_to_avg,
        }
    }
}

#[async_trait]
impl DaService for BitcoinService {
    type Spec = BitcoinSpec;

    type Verifier = BitcoinVerifier;

    type FilteredBlock = BitcoinBlock;

    type Error = anyhow::Error;

    // Make an RPC call to the node to get the finalized block at the given height, if one exists.
    // If no such block exists, block until one does.
    async fn get_finalized_at(&self, height: u64) -> Result<Self::FilteredBlock, Self::Error> {
        let client = self.client.clone();
        info!("Getting finalized block at height {}", height);
        loop {
            let block_count = client.get_block_count().await?;

            // if at least `FINALITY_DEPTH` blocks are mined, we can be sure that the block is finalized
            if block_count >= height + FINALITY_DEPTH {
                break;
            }

            info!("Block not finalized, waiting");
            tokio::time::sleep(Duration::from_secs(POLLING_INTERVAL)).await;
        }

        let block_hash = client.get_block_hash(height).await?;
        let block: BitcoinBlock = client.get_block(block_hash).await?;

        Ok(block)
    }

    // Make an RPC call to the node to get the block at the given height
    // If no such block exists, block until one does.
    async fn get_block_at(&self, height: u64) -> Result<Self::FilteredBlock, Self::Error> {
        let client = self.client.clone();
        info!("Getting block at height {}", height);

        let block_hash;
        loop {
            block_hash = match client.get_block_hash(height).await {
                Ok(block_hash_response) => block_hash_response,
                Err(error) => {
                    match error.downcast_ref::<RPCError>() {
                        Some(error) => {
                            if error.code == -8 {
                                info!("Block not found, waiting");
                                tokio::time::sleep(Duration::from_secs(POLLING_INTERVAL)).await;
                                continue;
                            } else {
                                // other error, return message
                                return Err(anyhow::anyhow!(error.message.clone()));
                            }
                        }
                        None => {
                            return Err(anyhow::anyhow!(error));
                        }
                    }
                }
            };

            break;
        }
        let block = client.get_block(block_hash).await?;

        Ok(block)
    }

    // Extract the blob transactions relevant to a particular rollup from a block.
    fn extract_relevant_txs(
        &self,
        block: &Self::FilteredBlock,
    ) -> Vec<<Self::Spec as sov_rollup_interface::da::DaSpec>::BlobTransaction> {
        let mut txs = Vec::new();

        info!(
            "Extracting relevant txs from block {:?}",
            block.header.block_hash()
        );

        // iterate over all transactions in the block
        for tx in block.txdata.iter() {
            if !tx.txid().to_byte_array().as_slice().starts_with(&[0, 0]) {
                continue;
            }

            // check if the inscription in script is relevant to the rollup
            let parsed_inscription = parse_transaction(&tx, &self.rollup_name);

            if let Ok(inscription) = parsed_inscription {
                let public_key = secp256k1::PublicKey::from_slice(&inscription.public_key).unwrap();
                let signature = ecdsa::Signature::from_compact(&inscription.signature).unwrap();
                let message = Message::from_hashed_data::<sha256d::Hash>(&inscription.body);

                let secp = Secp256k1::new();
                if secp.verify_ecdsa(&message, &signature, &public_key).is_ok() {
                    // Decompress the blob
                    let decompressed_blob = decompress_blob(&inscription.body);

                    let relevant_tx = BlobWithSender::new(
                        decompressed_blob,
                        inscription.public_key,
                        sha256d::Hash::hash(&inscription.body).to_byte_array(),
                    );

                    txs.push(relevant_tx);
                }
            }
        }
        txs
    }

    async fn get_extraction_proof(
        &self,
        block: &Self::FilteredBlock,
        _blobs: &[<Self::Spec as sov_rollup_interface::da::DaSpec>::BlobTransaction],
    ) -> (
        <Self::Spec as sov_rollup_interface::da::DaSpec>::InclusionMultiProof,
        <Self::Spec as sov_rollup_interface::da::DaSpec>::CompletenessProof,
    ) {
        info!(
            "Getting extraction proof for block {:?}",
            block.header.block_hash()
        );

        let mut completeness_proof = Vec::with_capacity(block.txdata.len());

        let block_txs = block
            .txdata
            .iter()
            .map(|tx| {
                let tx_hash = tx.txid().to_raw_hash().to_byte_array();

                // if tx_hash has two leading zeros, it is in the completeness proof
                if tx_hash[0..2] == [0, 0] {
                    completeness_proof.push(tx.clone());
                }

                tx_hash
            })
            .collect::<Vec<_>>();

        let inclusion_proof = InclusionMultiProof { txs: block_txs };

        (inclusion_proof, completeness_proof)
    }

    // Extract the list blob transactions relevant to a particular rollup from a block, along with inclusion and
    // completeness proofs for that set of transactions. The output of this method will be passed to the verifier.
    async fn extract_relevant_txs_with_proof(
        &self,
        block: &Self::FilteredBlock,
    ) -> (
        Vec<<Self::Spec as sov_rollup_interface::da::DaSpec>::BlobTransaction>,
        <Self::Spec as sov_rollup_interface::da::DaSpec>::InclusionMultiProof,
        <Self::Spec as sov_rollup_interface::da::DaSpec>::CompletenessProof,
    ) {
        info!(
            "Extracting relevant txs with proof from block {:?}",
            block.header.block_hash()
        );

        let txs = self.extract_relevant_txs(block);
        let (inclusion_proof, completeness_proof) =
            self.get_extraction_proof(block, txs.as_slice()).await;

        (txs, inclusion_proof, completeness_proof)
    }

    async fn send_transaction(&self, blob: &[u8]) -> Result<(), Self::Error> {
        let client = self.client.clone();

        let blob = blob.to_vec();
        let network = self.network;
        let address = self
            .address
            .clone()
            .require_network(network)
            .expect("Invalid network for address");
        let rollup_name = self.rollup_name.clone();
        let sequencer_da_private_key = self.sequencer_da_private_key.clone();

        // Compress the blob
        let blob = compress_blob(&blob);

        // get all available utxos
        let utxos: Vec<UTXO> = client.get_utxos().await?;

        // sign the blob for authentication of the sequencer
        let (signature, public_key) = sign_blob_with_private_key(&blob, &sequencer_da_private_key)
            .expect("Sequencer sign the blob");

        // get fee rate from node
        // if fail to get fee use avg of MAX_COUNT_OF_FEES_TO_AVG last used fees
        let fee_sat_per_vbyte = match client.estimate_smart_fee().await {
            Ok(fee) => {
                let shared = self.last_fee_rates.clone();

                let mut last_fee_rates = shared.lock().unwrap();
                last_fee_rates.push_back(fee);

                if last_fee_rates.len() > self.fee_rates_to_avg {
                    last_fee_rates.pop_front();
                }

                fee
            }
            Err(_) => {
                let shared = self.last_fee_rates.clone();

                let last_fee_rates = shared.lock().unwrap();

                let mut sum = 0.0;
                for fee in last_fee_rates.iter() {
                    sum += fee;
                }

                let len = last_fee_rates.len();
                let average = if len > 0 { sum / len as f64 } else { 12.0 };

                average
            }
        };

        // create inscribe transactions
        let (unsigned_commit_tx, reveal_tx) = create_inscription_transactions(
            &rollup_name,
            blob,
            signature,
            public_key,
            utxos,
            address,
            fee_sat_per_vbyte,
            fee_sat_per_vbyte,
            network,
        )?;

        // sign inscribe transactions
        let serialized_unsigned_commit_tx = &encode::serialize(&unsigned_commit_tx);
        let signed_raw_commit_tx = client
            .sign_raw_transaction_with_wallet(serialized_unsigned_commit_tx.encode_hex())
            .await?;

        // send inscribe transactions
        client.send_raw_transaction(signed_raw_commit_tx).await?;

        // serialize reveal tx
        let serialized_reveal_tx = &encode::serialize(&reveal_tx);

        // write reveal tx to file, it can be used to continue revealing blob if something goes wrong
        write_reveal_tx(
            serialized_reveal_tx,
            unsigned_commit_tx.txid().to_raw_hash().to_string(),
        );

        // send reveal tx
        let reveal_tx_hash = client
            .send_raw_transaction(serialized_reveal_tx.encode_hex())
            .await?;

        info!("Blob inscribe tx sent. Hash: {}", reveal_tx_hash);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use core::str::FromStr;
    use std::collections::HashSet;

    use bitcoin::hashes::{sha256d, Hash};
    use bitcoin::secp256k1::{KeyPair, SecretKey};
    use bitcoin::{merkle_tree, Address, Txid};
    use sov_rollup_interface::services::da::DaService;

    use super::BitcoinService;
    use crate::helpers::parsers::parse_transaction;
    use crate::rpc::BitcoinNode;
    use crate::service::DaServiceConfig;
    use crate::spec::RollupParams;

    fn get_service() -> BitcoinService {
        let runtime_config = DaServiceConfig {
            node_url: "http://localhost:38332".to_string(),
            node_username: "chainway".to_string(),
            node_password: "topsecret".to_string(),
            network: "regtest".to_string(),
            address: "bcrt1qxuds94z3pqwqea2p4f4ev4f25s6uu7y3avljrl".to_string(),
            sequencer_da_private_key: Some(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262".to_string(), // Test key, safe to publish
            ),
            fee_rates_to_avg: 2, // small to speed up tests
        };

        BitcoinService::new(
            runtime_config,
            RollupParams {
                rollup_name: "sov-btc".to_string(),
            },
        )
    }

    #[tokio::test]
    async fn get_finalized_at() {
        let da_service = get_service();

        da_service
            .get_finalized_at(132)
            .await
            .expect("Failed to get block");
    }

    #[tokio::test]
    async fn get_block_at() {
        let da_service = get_service();

        da_service
            .get_block_at(132)
            .await
            .expect("Failed to get block");
    }

    #[tokio::test]
    async fn extract_relevant_txs() {
        let da_service = get_service();

        let block = da_service
            .get_block_at(132)
            .await
            .expect("Failed to get block");
        // panic!();

        let txs = da_service.extract_relevant_txs(&block);

        for tx in txs {
            println!("blob: {:?}", tx.blob);
        }
    }

    #[tokio::test]
    async fn extract_relevant_txs_with_proof() {
        let da_service = get_service();

        let block = da_service
            .get_block_at(142)
            .await
            .expect("Failed to get block");

        let (txs, inclusion_proof, completeness_proof) =
            da_service.extract_relevant_txs_with_proof(&block).await;

        // completeness proof

        // create hash set of txs
        let mut txs_to_check = txs.iter().map(|blob| blob.hash).collect::<HashSet<_>>();

        // Check every 00 bytes tx that parsed correctly is in txs
        let mut completeness_tx_hashes = completeness_proof
            .iter()
            .map(|tx| {
                let tx_hash = tx.txid().to_raw_hash().to_byte_array();

                // it must parsed correctly
                let parsed_tx = parse_transaction(tx, &da_service.rollup_name);
                if parsed_tx.is_ok() {
                    let blob = parsed_tx.unwrap().body;
                    let blob_hash: [u8; 32] = sha256d::Hash::hash(&blob).to_byte_array();
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

        println!("\n--- Completeness proof verified ---\n");

        let tx_root = block.header.merkle_root().to_raw_hash().to_byte_array();

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

        println!("\n--- Inclusion proof verified ---\n");

        println!("\n--- Extracted #{:?} txs ---\n", txs.len());
    }

    #[tokio::test]
    async fn send_transaction() {
        let da_service = get_service();

        let blob = "01000000b60000002adbd76606f2bd4125080e6f44df7ba2d728409955c80b8438eb1828ddf23e3c12188eeac7ecf6323be0ed5668e21cc354fca90d8bca513d6c0a240c26afa7007b758bf2e7670fafaf6bf0015ce0ff5aa802306fc7e3f45762853ffc37180fe64a0000000001fea6ac5b8751120fb62fff67b54d2eac66aef307c7dde1d394dea1e09e43dd44c800000000000000135d23aee8cb15c890831ff36db170157acaac31df9bba6cd40e7329e608eabd0000000000000000";
        da_service
            .send_transaction(blob.as_bytes())
            .await
            .expect("Failed to send transaction");
    }

    #[tokio::test]
    async fn fee_rates() {
        let da_service = get_service();
        let fee = da_service
            .client
            .estimate_smart_fee()
            .await
            .expect("Failed to get fee");

        let blob = "01000000b60000002adbd76606f2bd4125080e6f44df7ba2d728409955c80b8438eb1828ddf23e3c12188eeac7ecf6323be0ed5668e21cc354fca90d8bca513d6c0a240c26afa7007b758bf2e7670fafaf6bf0015ce0ff5aa802306fc7e3f45762853ffc37180fe64a0000000001fea6ac5b8751120fb62fff67b54d2eac66aef307c7dde1d394dea1e09e43dd44c800000000000000135d23aee8cb15c890831ff36db170157acaac31df9bba6cd40e7329e608eabd0000000000000000";

        for i in 0..3 {
            println!("Sending tx #{}", i);
            da_service
                .send_transaction(blob.as_bytes())
                .await
                .expect("Failed to send transaction");
        }

        {
            let shared = da_service.last_fee_rates.clone();

            let mut last_fee_rates = shared.lock().unwrap();

            let mut fees: Vec<f64> = vec![];
            for _ in 0..da_service.fee_rates_to_avg {
                fees.push(fee);
            }

            assert_eq!(last_fee_rates.make_contiguous(), fees.as_slice());
        }
    }

    #[tokio::test]
    async fn check_signature() {
        let rpc = BitcoinNode::new(
            "http://localhost:38332".to_string(),
            "chainway".to_string(),
            "topsecret".to_string(),
            bitcoin::Network::Regtest,
        );

        // empty regtest mempool
        rpc.generate_to_address(
            Address::from_str("bcrt1qxuds94z3pqwqea2p4f4ev4f25s6uu7y3avljrl")
                .unwrap()
                .require_network(bitcoin::Network::Regtest)
                .unwrap(),
            5,
        )
        .await
        .unwrap();

        let da_service = get_service();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let da_pubkey = KeyPair::from_secret_key(
            &secp,
            &SecretKey::from_str(&da_service.sequencer_da_private_key).unwrap(),
        )
        .public_key()
        .serialize()
        .to_vec();

        // incorrect private key

        let blob = "01000000b60000002adbd76606f2bd4125080e6f44df7ba2d728409955c80b8438eb1828ddf23e3c12188eeac7ecf6323be0ed5668e21cc354fca90d8bca513d6c0a240c26afa7007b758bf2e7670fafaf6bf0015ce0ff5aa802306fc7e3f45762853ffc37180fe64a0000000001fea6ac5b8751120fb62fff67b54d2eac66aef307c7dde1d394dea1e09e43dd44c800000000000000135d23aee8cb15c890831ff36db170157acaac31df9bba6cd40e7329e608eabd0000000000000000";
        da_service
            .send_transaction(blob.as_bytes())
            .await
            .expect("Failed to send transaction");

        let hashes = rpc
            .generate_to_address(
                Address::from_str("bcrt1qxuds94z3pqwqea2p4f4ev4f25s6uu7y3avljrl")
                    .unwrap()
                    .require_network(bitcoin::Network::Regtest)
                    .unwrap(),
                1,
            )
            .await
            .unwrap();

        let block_hash = hashes[0];

        let block = rpc.get_block(block_hash.to_string()).await.unwrap();

        let block = da_service.get_block_at(block.header.height).await.unwrap();

        let txs = da_service.extract_relevant_txs(&block);

        assert_eq!(
            txs.get(0).unwrap().sender.0,
            da_pubkey,
            "Publickey recovered incorrectly!"
        );
    }
}
