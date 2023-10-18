#![cfg_attr(not(feature = "native"), no_std)]
mod helpers;
mod rpc;
pub mod spec;

#[cfg(feature = "native")]
pub mod service;
pub mod verifier;
extern crate alloc;

const REVEAL_OUTPUT_AMOUNT: u64 = 546;
const DEFAULT_FEE_RATES_TO_AVG_CNT: usize = 10;
