//! Content-blind ordered-log and access-consumption primitives.
//! Hash-chain verification is not original-author or account verification.
#![forbid(unsafe_code)]

mod access;
mod log;
pub use access::*;
pub use log::*;
