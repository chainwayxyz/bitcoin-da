use bitcoin::BlockHash;
use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::BlockHashTrait;

// BlockHashWrapper is a wrapper around BlockHash to implement BlockHashTrait
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlockHashWrapper(pub BlockHash);

impl BlockHashTrait for BlockHashWrapper {}

impl AsRef<[u8]> for BlockHashWrapper {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}