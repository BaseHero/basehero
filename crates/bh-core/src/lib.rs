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
mod backup;
mod base;
mod basekeys;
mod client;
mod clock;
mod core;
mod envelope;
mod error;
mod export;
mod files;
mod grants;
/// Persisted chats and Hero's account controller.
pub mod hero;
#[allow(dead_code, reason = "used by the hidden account operations, next")]
mod hidden;
mod keys;
mod markdown;
/// Model request and response types, and the account's configured model.
pub mod models;
mod mounts;
mod moves;
mod note;
mod objects;
mod query;
mod rotation;
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
    AppSummary, BaseGrantRequest, DeviceKind, DeviceSummary, KitStatus, Removal, RemovalOutcome,
};
pub use approval::connect::{
    AppChoice, AppIdentity, AppOffer, DEFAULT_APP_CAP_MICRO_USD, OldConnection, OpenAppRequest,
    PendingConnection,
};
pub use approval::{Approval, ApprovalRequest, OpenRequest, RequestKind, protocol::Digits};
pub use backup::{
    BackupFolder, BackupListing, BackupLocation, BackupProblem, BackupRun, BackupSchedule,
    BackupStatus, BaseCheck, CheckReport, DocumentFolders, FolderEntry, FolderError, LocalFolder,
    OpenedBackup, RestorableBase, RestoreSummary, list_backups,
};
pub use base::{Base, BaseSummary, Mode};
pub use bh_proto::{AccountId, ApprovalId, BaseId, DeviceId, ObjectId};
pub use clock::{Clock, ManualClock};
pub use error::{EndReason, Error};
pub use export::ExportSummary;
pub use files::{FILE_MAX, FILE_PART, FileInfo, FileStatus, Image, NewFile, sniff_image};
pub use keys::RecoveryKit;
pub use mounts::{Mount, TreeItem};
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

    /// Decodes a record file in a backup folder, refusing incomplete or damaged files.
    pub fn backup_records(
        folder: &dyn crate::BackupFolder,
        path: &str,
    ) -> Result<Vec<Vec<u8>>, crate::Error> {
        let kind = if path.ends_with(".bhk") {
            crate::backup::format::FileKind::Keys
        } else if path.ends_with(".bhs") {
            crate::backup::format::FileKind::Snapshot
        } else if path.ends_with(".bhl") {
            crate::backup::format::FileKind::Log
        } else {
            return Err(crate::Error::invalid("backup record path"));
        };
        let bytes = folder
            .read(path)
            .map_err(|e| crate::Error::Storage(format!("{e:?}")))?;
        crate::backup::format::decode(kind, &bytes)
            .map(|records| records.into_iter().map(Vec::from).collect())
            .map_err(|e| crate::Error::Storage(format!("{e:?}")))
    }

    /// Number of extra-password derivations attempted in this process.
    pub fn argon2_calls() -> u64 {
        crate::hidden::argon2_calls()
    }

    /// Seals an account-key envelope with the supplied password, salt and kit for protocol tests.
    pub fn seal_envelope(
        key: &[u8; 32],
        salt: &[u8; 16],
        password: &str,
        kit: &crate::RecoveryKit,
        account: bh_proto::AccountId,
    ) -> Result<Vec<u8>, crate::Error> {
        let secret = crate::keys::PasswordSecret::derive(password, salt, crate::keys::DEFAULT_KDF)?;
        Ok(crate::envelope::seal(
            &secret.wrap_key(kit),
            &crate::keys::account_key_aad(&account, 1),
            key,
        ))
    }

    /// Opens an account-key envelope with the supplied password, salt and kit.
    pub fn open_envelope(
        envelope: &[u8],
        salt: &[u8; 16],
        password: &str,
        kit: &crate::RecoveryKit,
        account: bh_proto::AccountId,
    ) -> Result<[u8; 32], crate::Error> {
        let secret = crate::keys::PasswordSecret::derive(password, salt, crate::keys::DEFAULT_KDF)?;
        let opened = crate::envelope::open(
            &secret.wrap_key(kit),
            &crate::keys::account_key_aad(
                &account,
                crate::envelope::epoch(envelope).ok_or(crate::Error::Crypto)?,
            ),
            envelope,
        )?;
        opened
            .as_slice()
            .try_into()
            .map_err(|_| crate::Error::Crypto)
    }

    /// Try to open a base wrapper using an app key retained before rotation.
    pub fn open_app_wrapper(
        wrapper: &[u8],
        key: &[u8; 32],
        base: crate::BaseId,
        device: crate::DeviceId,
    ) -> Result<Vec<u8>, crate::Error> {
        let epoch = crate::envelope::epoch(wrapper).ok_or(crate::Error::Crypto)?;
        crate::envelope::open(
            &bh_crypto::kdf(&bh_crypto::Secret::<32>::from_slice(key)?, b"bhbasew1", 1),
            &crate::keys::app_wrapper_aad(&base, &device, epoch),
            wrapper,
        )
        .map(|opened| opened.to_vec())
    }

    /// The login key for `password` with the default parameters, for raw protocol tests.
    pub fn login_key(password: &str, salt: &[u8; 16]) -> Result<[u8; 32], crate::Error> {
        Ok(
            crate::keys::PasswordSecret::derive(password, salt, crate::keys::DEFAULT_KDF)?
                .login_key(),
        )
    }
}
