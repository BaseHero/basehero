//! Held base roots in the container's local keyring: each sealed to the
//! account's accepted personal key and bound to its account, base, purpose and
//! committed id. Opening re-derives that id; rows are never exported.
use crate::{ContainerId, Owner, OwnerError, own_base::OwnBaseError};
use bh_account::{
    AccountId,
    local_seal::{self, LocalKeyContext, LocalKeyPurpose},
    personal::PersonalKey,
};
use bh_crypto::Secret;
use bh_event::key_id;
use bh_storage::{EpochKeyRow, StoreError, sync_state::LOG_BASE};
use bh_sync::BaseId;

/// `root` sealed to `to` under its committed id.
pub(crate) fn sealed(
    account: AccountId,
    base: [u8; 32],
    purpose: LocalKeyPurpose,
    root: &Secret<32>,
    to: &PersonalKey,
) -> Result<EpochKeyRow, OwnBaseError> {
    let context = LocalKeyContext {
        account,
        base,
        purpose,
        key_id: key_id(root),
    };
    Ok(EpochKeyRow {
        base,
        epoch_id: context.key_id,
        purpose: purpose as i64,
        seal: local_seal::seal(&context, &to.public(), root).map_err(|_| OwnBaseError::Invalid)?,
    })
}

/// The held root committing to `key_id`, if a row holds it. A row that does
/// not open to exactly that root is refused, never skipped.
pub(crate) fn held(
    rows: &[EpochKeyRow],
    account: AccountId,
    base: [u8; 32],
    purpose: LocalKeyPurpose,
    key_id: [u8; 32],
    personal: &PersonalKey,
) -> Result<Option<Secret<32>>, OwnBaseError> {
    let Some(row) = rows
        .iter()
        .find(|r| r.base == base && r.epoch_id == key_id && r.purpose == purpose as i64)
    else {
        return Ok(None);
    };
    let context = LocalKeyContext {
        account,
        base,
        purpose,
        key_id,
    };
    local_seal::open(&context, personal, &row.seal)
        .map(Some)
        .map_err(|_| OwnBaseError::Invalid)
}

/// Whether `base` has the rows acceptance requires: a metadata and a content root.
pub(crate) fn complete(rows: &[EpochKeyRow], base: [u8; 32]) -> bool {
    [LocalKeyPurpose::Metadata, LocalKeyPurpose::Content]
        .iter()
        .all(|p| {
            rows.iter()
                .any(|r| r.base == base && r.purpose == *p as i64)
        })
}

impl Owner {
    /// Scoped use of the base's verified metadata key M and the held content
    /// key K of `epoch_id`, opened from this container's keyring with the
    /// account's accepted `personal` key. An epoch whose key is not held is
    /// `Unavailable`; no other key stands in for it. A held row that does not
    /// open to its committed root is invalid (`CorruptSecurity`), never
    /// reported as missing.
    pub fn with_epoch_key<R>(
        &self,
        id: ContainerId,
        base: BaseId,
        epoch_id: [u8; 32],
        personal: &PersonalKey,
        use_keys: impl FnOnce(&Secret<32>, &Secret<32>) -> R,
    ) -> Result<R, OwnerError> {
        let account = self
            .registry
            .lock()
            .expect("owner registry lock")
            .containers
            .get(&id)
            .ok_or(OwnerError::UnknownContainer)?
            .anchor
            .ok_or(OwnerError::Unbound)?;
        let database = self.shared_database(id)?;
        let (metadata_id, rows) = {
            let db = database.lock().expect("container writer lock");
            let progress = db
                .log_progress(LOG_BASE, base.0)?
                .ok_or(OwnerError::NotRegistered)?;
            (
                progress.metadata_id.ok_or(OwnerError::NotRegistered)?,
                db.epoch_keys(base.0)?,
            )
        };
        let open = |purpose, key_id| {
            held(&rows, AccountId(account), base.0, purpose, key_id, personal)
                .map_err(|_| OwnerError::Store(StoreError::CorruptSecurity))?
                .ok_or(OwnerError::Unavailable)
        };
        let metadata = open(LocalKeyPurpose::Metadata, metadata_id)?;
        let content = open(LocalKeyPurpose::Content, epoch_id)?;
        Ok(use_keys(&metadata, &content))
    }
}
