use bitcoin::Transaction;
use serde::{Deserialize, Serialize};

// ExtendedTransaction is a wrapper around Transaction to add sender recovered from signature in inscription
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExtendedTransaction {
    pub transaction: Transaction,
    pub sender: Vec<u8>,
    pub blob_hash: [u8; 32],
}
