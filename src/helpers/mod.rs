// Tags that are used to seperate the different parts of the script
const ROLLUP_NAME_TAG: &[u8] = &[1];
const SIGNATURE_TAG: &[u8] = &[2];
const PUBLICKEY_TAG: &[u8] = &[3];
const BODY_TAG: &[u8] = &[];

pub mod builders;
pub mod parsers;
