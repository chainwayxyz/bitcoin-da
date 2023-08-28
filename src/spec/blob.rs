use serde::{Deserialize, Serialize};
use sov_rollup_interface::da::{BlobReaderTrait, CountedBufReader};
use sov_rollup_interface::Buf;

use super::address::AddressWrapper;

// BlobBuf is a wrapper around Vec<u8> to implement Buf
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlobBuf {
    pub data: Vec<u8>,

    pub offset: usize,
}

impl BlobWithSender {
    pub fn new(blob: Vec<u8>, sender: AddressWrapper, hash: [u8; 32]) -> Self {
        Self {
            blob: CountedBufReader::new(BlobBuf {
                data: blob,
                offset: 0,
            }),
            sender,
            hash,
        }
    }
}

impl Buf for BlobBuf {
    fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    fn chunk(&self) -> &[u8] {
        &self.data[self.offset..]
    }

    fn advance(&mut self, cnt: usize) {
        self.offset += cnt;
    }
}

// BlobWithSender is a wrapper around BlobBuf to implement BlobReaderTrait
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BlobWithSender {
    pub hash: [u8; 32], // txid is used as hash

    pub sender: AddressWrapper,

    pub blob: CountedBufReader<BlobBuf>,
}

impl BlobReaderTrait for BlobWithSender {
    type Data = BlobBuf;

    type Address = AddressWrapper;

    fn sender(&self) -> Self::Address {
        self.sender.clone()
    }

    fn data(&self) -> &sov_rollup_interface::da::CountedBufReader<Self::Data> {
        &self.blob
    }

    fn data_mut(&mut self) -> &mut sov_rollup_interface::da::CountedBufReader<Self::Data> {
        &mut self.blob
    }

    fn hash(&self) -> [u8; 32] {
        self.hash
    }
}
