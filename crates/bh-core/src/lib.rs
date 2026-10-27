//! BaseHero's core: keys, accounts, local stores and sync. The CLI and apps
//! only call this API.

mod account;
pub mod approval;
mod base;
mod client;
mod clock;
mod core;
mod envelope;
mod error;
pub mod hero;
#[allow(dead_code, reason = "used by the hidden account operations, next")]
mod hidden;
mod keys;
pub mod models;
mod note;
mod objects;
mod query;
mod search;
mod secrets;
mod store;
mod strength;
mod sync;
mod types;

pub use crate::core::{Core, CoreConfig, PendingSignIn, SignIn, SignUp};
pub use account::{
    Account, AccountEvent, AccountSummary, AppCredentials, AppGrant, AppRequest, AppSummary,
    BaseGrantRequest, DeviceKind, DeviceSummary,
};
pub use approval::{Approval, ApprovalRequest, OpenRequest, protocol::Digits};
pub use base::{Base, BaseSummary, Mode};
pub use bh_proto::{AccountId, ApprovalId, BaseId, DeviceId, ObjectId};
pub use clock::{Clock, ManualClock};
pub use error::{EndReason, Error};
pub use keys::RecoveryKit;
pub use note::{NoteDoc, NoteUpdate};
pub use objects::{NewObject, ObjectSummary};
pub use query::{Filter, Op, Order, Query};
pub use search::SearchHit;
pub use secrets::{FileSecretStore, SealedFileSecretStore, SecretStore};
pub use strength::{PasswordStrength, password_strength};
pub use sync::{BaseEvent, SyncState};
pub use types::{FieldDef, FieldKind, TypeDef, TypeRef};
pub use url::Url;

/// Hooks for bh-testkit; never enabled in apps.
#[cfg(feature = "test-support")]
pub mod test_support {
    pub use crate::client::{Fault, set_test_bypass};

    /// Number of extra-password derivations attempted in this process.
    pub fn argon2_calls() -> u64 {
        crate::hidden::argon2_calls()
    }

    /// The login key for `password` with the default parameters, for raw protocol tests.
    pub fn login_key(password: &str, salt: &[u8; 16]) -> Result<[u8; 32], crate::Error> {
        Ok(
            crate::keys::PasswordSecret::derive(password, salt, crate::keys::DEFAULT_KDF)?
                .login_key(),
        )
    }
}
