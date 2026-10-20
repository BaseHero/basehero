//! The app's native host for accounts, sync and pairing, callable without a
//! GUI. The app's windows reach it through thin commands that only name the
//! calling window; headless tests call the same operations, authority checks
//! and durable state.
//!
//! - `accounts`: the account registry, its one owner per container, signup,
//!   startup, joining and lending a ready account's owner to native work.
//! - `sync`: one sync client per ready account, its signer over that owner,
//!   and the status its windows are told.
//! - `pairing`: showing a code and approving a device; joining by a code.
//! - `confirm`: one confirmation covering a pairing addition and its copy,
//!   on a key store whose control confirmation the app enforces.
//! - `endpoint`: the build's fixed sync endpoint file.
#![forbid(unsafe_code)]

pub mod accounts;
pub mod confirm;
pub mod endpoint;
pub mod pairing;
pub mod sync;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
