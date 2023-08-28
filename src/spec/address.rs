use core::fmt::{Display, Formatter};
use core::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sov_rollup_interface::BasicAddress;

// AddressWrapper is a wrapper around Vec<u8> to implement AddressTrait
#[derive(
    Debug, PartialEq, Clone, Eq, Serialize, Deserialize, BorshDeserialize, BorshSerialize, Hash,
)]
pub struct AddressWrapper(pub Vec<u8>);

impl BasicAddress for AddressWrapper {}

impl FromStr for AddressWrapper {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(hex::decode(s)?))
    }
}

impl Display for AddressWrapper {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        let hash = hex::encode(&self.0);
        write!(f, "{hash}")
    }
}

impl AsRef<[u8]> for AddressWrapper {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<[u8; 32]> for AddressWrapper {
    fn from(value: [u8; 32]) -> Self {
        Self(value.to_vec())
    }
}

impl<'a> TryFrom<&'a [u8]> for AddressWrapper {
    type Error = anyhow::Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.to_vec()))
    }
}
