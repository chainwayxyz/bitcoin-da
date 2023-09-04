use bitcoin::hashes::Hash;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::BlockHeaderTrait;
use sov_rollup_interface::services::da::SlotData;

use super::header::HeaderWrapper;
use super::transaction::ExtendedTransaction;
use crate::verifier::ChainValidityCondition;

// BitcoinBlock is a wrapper around Block to remove unnecessary fields and implement SlotData
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BitcoinBlock {
    pub header: HeaderWrapper,
    pub txdata: Vec<ExtendedTransaction>,
}

impl SlotData for BitcoinBlock {
    type BlockHeader = HeaderWrapper;
    type Cond = ChainValidityCondition;

    fn hash(&self) -> [u8; 32] {
        self.header().hash().as_ref().try_into().unwrap()
    }

    fn header(&self) -> &Self::BlockHeader {
        &self.header
    }

    fn validity_condition(&self) -> Self::Cond {
        ChainValidityCondition {
            prev_hash: self
                .header
                .header
                .prev_blockhash
                .clone()
                .as_raw_hash()
                .to_byte_array(),
            block_hash: self.header.hash().as_ref().try_into().unwrap(),
        }
    }
}
