use bitcoin::BlockHeader;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::BlockHeaderTrait;

use super::block_hash::BlockHashWrapper;

// BlockHashWrapper is a wrapper around BlockHash to implement BlockHashTrait
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HeaderWrapper {
    pub header: BlockHeader,
    pub tx_count: u32,
}

impl BlockHeaderTrait for HeaderWrapper {
    type Hash = BlockHashWrapper;

    fn prev_hash(&self) -> Self::Hash {
        BlockHashWrapper(self.header.prev_blockhash)
    }

    fn hash(&self) -> Self::Hash {
        BlockHashWrapper(self.header.block_hash())
    }
}
