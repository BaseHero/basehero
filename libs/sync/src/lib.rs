//! Content-blind ordered-log and access-consumption primitives.
//! Hash-chain verification is not original-author or account verification.
#![forbid(unsafe_code)]

mod access;
pub mod canonical;
pub mod evidence;
pub mod home_objects;
mod log;
pub mod permit;
pub mod receipt;
pub mod wire;
pub use access::*;
pub use canonical::{OrderState, RawControlHead};
pub use log::*;
