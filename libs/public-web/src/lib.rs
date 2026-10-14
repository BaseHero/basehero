//! Public-only page reading. All returned content is untrusted.
//! Service entry points must disable dependency logging: parsers and HTTP stacks
//! can log content. This library does not install a logger or tracing subscriber.
#![forbid(unsafe_code)]

pub mod evidence;
pub mod extract;
pub mod fetch;
#[cfg(test)]
mod network_tests;
pub mod policy;
pub mod provenance;
mod resolve;
pub mod search;

pub use fetch::{FetchError, Limits, Reader};
pub use provenance::{JobSources, ReadPermit};
