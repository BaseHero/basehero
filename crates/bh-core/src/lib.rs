//! BaseHero's core for accounts, encrypted local bases, typed records and sync.
//!
//! An app opens one [`Core`], installs credentials it already has, opens a granted
//! [`Base`], defines its record type, then writes and queries local records. Sync
//! runs in the background; only installing credentials in this example needs the
//! network. See the [app guide](https://github.com/BaseHero/basehero/blob/main/docs/build-an-app.md)
//! for setup and connection instructions.
//!
//! ```no_run
//! use bh_core::{AppCredentials, BaseGrantRequest, Core, CoreConfig, FieldDef, FieldKind,
//!     NewObject, Query, TypeDef, TypeRef};
//! use serde_json::{Map, json};
//!
//! async fn use_app(config: CoreConfig, credentials: AppCredentials) -> Result<(), bh_core::Error> {
//!     let core = Core::open(config)?;
//!     let base_id = credentials.bases[0];
//!     let account = core.install_app(credentials).await?;
//!     let base = account.base(base_id)?;
//!     base.define_type(TypeDef {
//!         name: "sample.reading".into(), version: 1, doc: "A reading".into(),
//!         title_field: None,
//!         fields: vec![FieldDef { name: "value".into(), kind: FieldKind::Number,
//!             required: true, unit: None, doc: "Measured value".into() }],
//!     })?;
//!     let mut fields = Map::new();
//!     fields.insert("value".into(), json!(42));
//!     base.create(NewObject { ty: TypeRef::new("sample.reading", 1),
//!         parent: None, after: None, fields })?;
//!     let _readings = base.query(&Query { ty: "sample.reading".into(),
//!         filters: vec![], order_by: None, limit: None })?;
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(rustdoc::broken_intra_doc_links, rustdoc::private_intra_doc_links)]

mod account;
/// The full-device approval and app connection exchanges and their protocol types.
pub mod approval;
mod base;
mod client;
mod clock;
mod core;
mod envelope;
mod error;
mod export;
mod files;
/// Persisted chats and Hero's account controller.
pub mod hero;
#[allow(dead_code, reason = "used by the hidden account operations, next")]
mod hidden;
mod keys;
mod markdown;
/// Model request and response types, and the account's configured model.
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
mod usage;
/// Device-local version policy and its background checks.
pub mod versions;

pub use crate::core::{Core, CoreConfig, PendingSignIn, SignIn, SignUp};
pub use account::{
    Account, AccountEvent, AccountSummary, AccountUsage, AppCredentials, AppGrant, AppRequest,
    AppSummary, BaseGrantRequest, DeviceKind, DeviceSummary, KitStatus,
};
pub use approval::connect::{
    AppChoice, AppIdentity, AppOffer, DEFAULT_APP_CAP_MICRO_USD, OldConnection, OpenAppRequest,
    PendingConnection,
};
pub use approval::{Approval, ApprovalRequest, OpenRequest, RequestKind, protocol::Digits};
pub use base::{Base, BaseSummary, Mode};
pub use bh_proto::{AccountId, ApprovalId, BaseId, DeviceId, ObjectId};
pub use clock::{Clock, ManualClock};
pub use error::{EndReason, Error};
pub use export::ExportSummary;
pub use files::{FILE_MAX, FILE_PART, FileInfo, FileStatus, Image, NewFile, sniff_image};
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
pub use usage::UsageRow;
pub use versions::ObjectVersion;

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
