use core::result::Result::Ok;
use core::str::FromStr;
use core::time::Duration;

use async_trait::async_trait;
use bitcoin::consensus::encode;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::Hash;
use bitcoin::Address;
use ord::SatPoint;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::services::da::DaService;
use tracing::info;

use crate::helpers::builders::{
    create_inscription_transactions, get_satpoint_to_inscribe, sign_blob_with_private_key,
    write_reveal_tx,
};
use crate::helpers::parsers::parse_transaction;
use crate::rpc::{BitcoinNode, RPCError};
use crate::spec::address::AddressWrapper;
use crate::spec::blob::BlobWithSender;
use crate::spec::block::BitcoinBlock;
use crate::spec::proof::InclusionMultiProof;
use crate::spec::utxo::UTXO;
use crate::spec::{BitcoinSpec, RollupParams};

/// A service that provides data and data availability proofs for Bitcoin
#[derive(Debug, Clone)]
pub struct BitcoinService {
    client: BitcoinNode,
    rollup_name: String,
    network: bitcoin::Network,
    address: String,
    sequencer_da_private_key: String,
}
impl BitcoinService {
    pub fn with_client(
        client: BitcoinNode,
        rollup_name: String,
        network: bitcoin::Network,
        address: String,
        sequencer_da_private_key: String,
    ) -> Self {
        Self {
            client,
            rollup_name,
            network,
            address,
            sequencer_da_private_key,
        }
    }
}

/// Runtime configuration for the DA service
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct DaServiceConfig {
    /// The URL of the Bitcoin node to connect to
    pub node_url: String,
    pub node_username: String,
    pub node_password: String,

    // network of the bitcoin node
    pub network: Option<String>,

    // taproot address that holds the funds of the sequencer
    pub address: Option<String>,

    // da private key of the sequencer
    pub sequencer_da_private_key: Option<String>,
}

const FINALITY_DEPTH: u64 = 4; // blocks
const POLLING_INTERVAL: u64 = 1; // seconds

impl BitcoinService {
    // Create a new instance of the DA service from the given configuration.
    pub fn new(config: DaServiceConfig, chain_params: RollupParams) -> Self {
        let client = BitcoinNode::new(config.node_url, config.node_username, config.node_password);

        Self::with_client(
            client,
            chain_params.rollup_name,
            bitcoin::Network::from_str(&config.network.unwrap_or("regtest".to_owned())).unwrap(), // default to regtest (?)
            config.address.unwrap_or("".to_owned()),
            config.sequencer_da_private_key.unwrap_or("".to_owned()),
        )
    }
}

#[async_trait]
impl DaService for BitcoinService {
    type Spec = BitcoinSpec;

    type FilteredBlock = BitcoinBlock;

    type Error = anyhow::Error;

    // Make an RPC call to the node to get the finalized block at the given height, if one exists.
    // If no such block exists, block until one does.
    async fn get_finalized_at(&self, height: u64) -> Result<Self::FilteredBlock, Self::Error> {
        let client = self.client.clone();
        let rollup_name = self.rollup_name.clone();
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
        let block: BitcoinBlock = client.get_block(block_hash, &rollup_name).await?;

        Ok(block)
    }

    // Make an RPC call to the node to get the block at the given height
    // If no such block exists, block until one does.
    async fn get_block_at(&self, height: u64) -> Result<Self::FilteredBlock, Self::Error> {
        let client = self.client.clone();
        let rollup_name = self.rollup_name.clone();
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
        let block = client.get_block(block_hash, &rollup_name).await?;

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
            block.header.header.block_hash()
        );

        // iterate over all transactions in the block
        for tx in block.txdata.iter() {
            // check if the inscription in script is relevant to the rollup
            let parsed_inscription = parse_transaction(&tx.transaction, &self.rollup_name);

            if let Ok(inscription) = parsed_inscription {
                let blob = inscription.body;

                // TODO: Decompress the blob after implementing compression
                // Issue: https://github.com/chainwayxyz/bitcoin-da/issues/4

                let relevant_tx = BlobWithSender::new(
                    blob,
                    AddressWrapper(tx.sender.clone()),
                    tx.transaction.txid().as_hash().into_inner(),
                );

                txs.push(relevant_tx);
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
            block.header.header.block_hash()
        );

        let block_txs = block
            .txdata
            .iter()
            .map(|tx| tx.transaction.txid().as_hash().into_inner())
            .collect::<Vec<_>>();

        let inclusion_proof = InclusionMultiProof { txs: block_txs };

        let completeness_proof = block.txdata.clone();

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
            block.header.header.block_hash()
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
        let address = self.address.clone();
        let rollup_name = self.rollup_name.clone();
        let sequencer_da_private_key = self.sequencer_da_private_key.clone();

        // TODO: Pick a compression algorithm and compress the blob
        // Issue: https://github.com/chainwayxyz/bitcoin-da/issues/4

        // get two change addresses that are necessary for the inscribe transaction
        let change_addresses: [Address; 2] = client.get_change_addresses().await?;

        // get all available utxos
        let utxos: Vec<UTXO> = client.get_utxos().await?;

        let satpoint: SatPoint = get_satpoint_to_inscribe(&utxos[0]);

        // return funds to sequencer address
        let destination_address = Address::from_str(&address.clone())?;

        // sign the blob for authentication of the sequencer
        let (signature, public_key) = sign_blob_with_private_key(&blob, &sequencer_da_private_key)
            .expect("Sequencer sign the blob");

        // get fee rate from node
        let fee_sat_per_vbyte: f64 = client.estimate_smart_fee().await?;

        // create inscribe transactions
        let (unsigned_commit_tx, reveal_tx) = create_inscription_transactions(
            &rollup_name,
            blob,
            signature,
            public_key,
            satpoint,
            utxos,
            change_addresses,
            destination_address,
            fee_sat_per_vbyte,
            fee_sat_per_vbyte,
            network,
        )?;

        // sign inscribe transactions
        let serialized_unsigned_commit_tx = &encode::serialize(&unsigned_commit_tx);
        let signed_raw_commit_tx = client
            .sign_raw_transaction_with_wallet(serialized_unsigned_commit_tx.to_hex())
            .await?;

        // send inscribe transactions
        client.send_raw_transaction(signed_raw_commit_tx).await?;

        // serialize reveal tx
        let serialized_reveal_tx = &encode::serialize(&reveal_tx);

        // write reveal tx to file, it can be used to continue revealing blob if something goes wrong
        write_reveal_tx(
            serialized_reveal_tx,
            unsigned_commit_tx.txid().as_hash().to_string(),
        );

        // send reveal tx
        let reveal_tx_hash = client
            .send_raw_transaction(serialized_reveal_tx.to_hex())
            .await?;

        info!("Blob inscribe tx sent. Hash: {}", reveal_tx_hash);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use sov_rollup_interface::services::da::DaService;

    use super::BitcoinService;
    use crate::helpers::parsers::parse_transaction;
    use crate::service::DaServiceConfig;
    use crate::spec::merkletree::BitcoinMerkleTree;
    use crate::spec::RollupParams;

    async fn get_service() -> BitcoinService {
        let runtime_config = DaServiceConfig {
            node_url: "http://localhost:38332".to_string(),
            node_username: "chainway".to_string(),
            node_password: "topsecret".to_string(),
            network: Some("regtest".to_string()),
            address: Some("bcrt1qyxexhcc7vcgvzlg5dncqg383frkeawp39eag4k".to_string()),
            sequencer_da_private_key: Some(
                "E9873D79C6D87DC0FB6A5778633389F4453213303DA61F20BD67FC233AA33262".to_string(), // Test key, safe to publish
            ),
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
        let da_service = get_service().await;

        da_service
            .get_finalized_at(131)
            .await
            .expect("Failed to get block");
    }

    #[tokio::test]
    async fn get_block_at() {
        let da_service = get_service().await;

        da_service
            .get_block_at(131)
            .await
            .expect("Failed to get block");
    }

    #[tokio::test]
    async fn extract_relevant_txs() {
        let da_service = get_service().await;

        let block = da_service
            .get_block_at(131)
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
        let da_service = get_service().await;

        let block = da_service
            .get_block_at(131)
            .await
            .expect("Failed to get block");

        let (txs, inclusion_proof, completeness_proof) =
            da_service.extract_relevant_txs_with_proof(&block).await;

        if txs.is_empty() {
            println!("No relevant txs found");
            return;
        }

        let tx_root = block.header.header.merkle_root.as_hash().into_inner();

        println!();

        let tree_from_inclusion = BitcoinMerkleTree::from_leaves(inclusion_proof.txs.clone());
        let root_from_inclusion = tree_from_inclusion.get_root().unwrap();

        // Assert all blob hashes (tx_hashes) are included in the block txs
        txs.iter().for_each(|tx| {
            assert!(inclusion_proof.txs.contains(&tx.hash));
        });

        // Assert root from inclusion proof is equal to the root from the block header
        assert_eq!(root_from_inclusion, tx_root);

        println!("\n--- Inclusion proof verified ---");

        // completeness proof
        let tx_ids = completeness_proof
            .iter()
            .map(|tx| tx.transaction.txid().as_hash().into_inner())
            .collect::<Vec<_>>();

        let tree_from_completeness = BitcoinMerkleTree::from_leaves(tx_ids);

        assert_eq!(tree_from_completeness.get_root().unwrap(), tx_root);
        println!("\n--- Root from completeness proof verified ---");

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
            assert!(
                parse_transaction(&irrelevant_tx.transaction, &da_service.rollup_name).is_err()
            );
        }

        println!("\n--- Completeness proof verified ---\n");
    }

    #[tokio::test]
    async fn send_transaction() {
        let da_service = get_service().await;

        let blob = "01000000b60000002adbd76606f2bd4125080e6f44df7ba2d728409955c80b8438eb1828ddf23e3c12188eeac7ecf6323be0ed5668e21cc354fca90d8bca513d6c0a240c26afa7007b758bf2e7670fafaf6bf0015ce0ff5aa802306fc7e3f45762853ffc37180fe64a0000000001fea6ac5b8751120fb62fff67b54d2eac66aef307c7dde1d394dea1e09e43dd44c800000000000000135d23aee8cb15c890831ff36db170157acaac31df9bba6cd40e7329e608eabd0000000000000000";
        da_service
            .send_transaction(blob.as_bytes())
            .await
            .expect("Failed to send transaction");
    }
}
