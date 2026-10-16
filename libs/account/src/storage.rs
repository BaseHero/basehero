//! `AccountJournal` over the device-local SQLite database. Storage keeps opaque
//! rows; this adapter maps them to account types and never adds verification.

use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard, Weak},
};

use crate::history::indexed::{HistoryIndex, KeyUse, receiving_hash};
use crate::history::{DeviceId, Error, MAX_EVENT_LEN};
use bh_storage::ReadPool;
use bh_storage::account::{
    AccountHistoryCursor, DeviceIdentityRecord, PendingSetupRow, StagedAdmissionRow,
};
use bh_storage::{DeviceDatabase, StoreError};

use crate::history::{AccountEvent, AccountId, DevicePublicKeys, Head, VerifiedAccount};
use crate::journal::{
    AccountJournal, HistoryCursor, HistoryPage, JournalError, JournaledAccount, JournaledDevice,
    JournaledProjection, PendingSetupRecord, SetupStage, StagedAdmission,
};
use crate::platform::{ControlKeyPolicy, DeviceKeyStoreKind, KeyHandle};

/// Account journal using the container's connection and writer guard. Each
/// synchronous journal operation takes one guard; native key work never does.
pub struct DeviceJournal {
    database: Arc<Mutex<DeviceDatabase>>,
}

impl DeviceJournal {
    /// Standalone journal for tests or a caller that owns its own connection.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        DeviceDatabase::open(path)
            .map(|database| Self::from_shared(Arc::new(Mutex::new(database))))
            .map_err(|_| JournalError::Storage)
    }

    pub fn from_shared(database: Arc<Mutex<DeviceDatabase>>) -> Self {
        Self { database }
    }

    fn database(&self) -> Result<MutexGuard<'_, DeviceDatabase>, JournalError> {
        self.database.lock().map_err(|_| JournalError::Storage)
    }
}

fn policy_code(policy: ControlKeyPolicy) -> u8 {
    match policy {
        ControlKeyPolicy::CurrentBiometricsOnly => 0,
        ControlKeyPolicy::DevicePasscodeWithoutBiometrics => 1,
        ControlKeyPolicy::AppEnforcedOwnerConfirmation => 2,
    }
}

fn policy_from_code(code: u8) -> Option<ControlKeyPolicy> {
    match code {
        0 => Some(ControlKeyPolicy::CurrentBiometricsOnly),
        1 => Some(ControlKeyPolicy::DevicePasscodeWithoutBiometrics),
        2 => Some(ControlKeyPolicy::AppEnforcedOwnerConfirmation),
        _ => None,
    }
}

fn kind_code(kind: DeviceKeyStoreKind) -> u8 {
    match kind {
        DeviceKeyStoreKind::MacLoginKeychainV1 => 0,
        DeviceKeyStoreKind::MacDataProtectionKeychainV1 => 1,
        DeviceKeyStoreKind::AndroidKeystoreV1 => 2,
    }
}

fn kind_from_code(code: u8) -> Option<DeviceKeyStoreKind> {
    match code {
        0 => Some(DeviceKeyStoreKind::MacLoginKeychainV1),
        1 => Some(DeviceKeyStoreKind::MacDataProtectionKeychainV1),
        2 => Some(DeviceKeyStoreKind::AndroidKeystoreV1),
        _ => None,
    }
}

fn staged_row(row: &StagedAdmission) -> StagedAdmissionRow {
    StagedAdmissionRow {
        position: row.position,
        previous: row.previous,
        event: row.event.clone(),
        delivery: row.delivery.clone(),
    }
}
fn staged_error(error: StoreError) -> JournalError {
    match error {
        StoreError::StagedAdmissionExists => JournalError::StagedAdmissionExists,
        StoreError::StagedAdmissionChanged => JournalError::StagedAdmissionChanged,
        StoreError::CorruptStagedAdmission => JournalError::Corrupt,
        _ => JournalError::Storage,
    }
}

fn index_error(error: StoreError) -> JournalError {
    if bh_storage::account::is_account_corruption(&error) {
        JournalError::Corrupt
    } else {
        JournalError::Storage
    }
}
struct SqliteIndex {
    pool: Weak<ReadPool>,
    anchor: AccountId,
    epoch: u64,
}
impl HistoryIndex for SqliteIndex {
    fn event_matches(&self, cut: Head, position: u64, bytes: &[u8]) -> Result<bool, Error> {
        let pool = self.pool.upgrade().ok_or(Error::Unavailable)?;
        let stored = pool
            .account_event_bytes(
                self.anchor.0,
                self.epoch,
                cut.position,
                position,
                MAX_EVENT_LEN,
            )
            .map_err(|_| Error::Unavailable)?;
        Ok(stored.is_some_and(|stored| stored == bytes))
    }
    fn device_seen(&self, cut: Head, id: &DeviceId) -> Result<bool, Error> {
        self.pool
            .upgrade()
            .ok_or(Error::Unavailable)?
            .account_device_seen(self.anchor.0, self.epoch, cut.position, &id.0)
            .map_err(|_| Error::Unavailable)
    }
    fn key_used(&self, cut: Head, key: KeyUse<'_>) -> Result<bool, Error> {
        let (space, key) = match key {
            KeyUse::Signing(key) => (0, *key),
            KeyUse::Receiving(key) => (1, receiving_hash(key)),
        };
        self.pool
            .upgrade()
            .ok_or(Error::Unavailable)?
            .account_key_used(self.anchor.0, self.epoch, cut.position, space, &key)
            .map_err(|_| Error::Unavailable)
    }
}

impl AccountJournal for DeviceJournal {
    fn load_projection(&self) -> Result<Option<JournaledProjection>, JournalError> {
        let mut db = self.database()?;
        let Some(state) = db.account_state().map_err(index_error)? else {
            return Ok(None);
        };
        // Only ephemeral in-memory journals lack a reader pool.
        let Some(pool) = db.read_pool() else {
            return Ok(None);
        };
        for attempt in 0..2 {
            let result = (|| {
                let view = db
                    .account_projection_view(MAX_EVENT_LEN)
                    .map_err(index_error)?
                    .ok_or(JournalError::Corrupt)?;
                let anchor = AccountId(view.state.anchor);
                let target = Head {
                    position: view.state.head_position,
                    hash: view.state.head_hash,
                };
                if AccountEvent::decode(&view.first)
                    .ok()
                    .and_then(|e| AccountId::of_genesis(&e).ok())
                    != Some(anchor)
                {
                    return Err(JournalError::Corrupt);
                }
                let p = view.projection.ok_or(JournalError::Corrupt)?;
                let index: Arc<dyn HistoryIndex> = Arc::new(SqliteIndex {
                    pool: Arc::downgrade(&pool),
                    anchor,
                    epoch: p.epoch,
                });
                let account = if p.through_position == 0 {
                    if p.through_hash != [0; 32] || !p.summary.is_empty() {
                        return Err(JournalError::Corrupt);
                    }
                    VerifiedAccount::from_genesis(anchor, &view.first)
                        .map_err(|_| JournalError::Corrupt)?
                        .pin_empty(p.epoch, index)
                } else {
                    let through = Head {
                        position: p.through_position,
                        hash: p.through_hash,
                    };
                    if view
                        .through
                        .as_ref()
                        .is_none_or(|bytes| crate::crypto::hash(bytes) != through.hash)
                    {
                        return Err(JournalError::Corrupt);
                    }
                    VerifiedAccount::from_index(
                        anchor,
                        through,
                        &p.summary,
                        view.active,
                        p.epoch,
                        index,
                    )
                    .map_err(|_| JournalError::Corrupt)?
                };
                Ok(JournaledProjection {
                    account,
                    stopped: view.state.stopped,
                    target,
                })
            })();
            match result {
                Ok(p) => {
                    // Genesis is verified but not yet checkpointed on a new epoch.
                    if p.account.delta().expected.0 == 0 {
                        db.advance_account_projection(
                            p.account.id().0,
                            &p.account.delta(),
                            MAX_EVENT_LEN,
                        )
                        .map_err(index_error)?;
                        let epoch = db
                            .account_projection()
                            .map_err(index_error)?
                            .ok_or(JournalError::Corrupt)?
                            .epoch;
                        let index = Arc::new(SqliteIndex {
                            pool: Arc::downgrade(&pool),
                            anchor: p.account.id(),
                            epoch,
                        });
                        return Ok(Some(JournaledProjection {
                            account: p.account.rebase(epoch, index),
                            ..p
                        }));
                    }
                    db.cleanup_account_projection().map_err(index_error)?;
                    return Ok(Some(p));
                }
                Err(JournalError::Corrupt) if attempt == 0 => {
                    db.reset_account_projection(state.anchor)
                        .map_err(index_error)?;
                }
                Err(e) => return Err(e),
            }
        }
        Err(JournalError::Corrupt)
    }
    fn advance_projection(&mut self, account: &VerifiedAccount) -> Result<(), JournalError> {
        self.database()?
            .advance_account_projection(account.id().0, &account.delta(), MAX_EVENT_LEN)
            .map_err(index_error)
    }
    fn rebase_projection(&self, account: VerifiedAccount) -> Result<VerifiedAccount, JournalError> {
        let db = self.database()?;
        let Some(pool) = db.read_pool() else {
            return Ok(account);
        };
        let p = db
            .account_projection()
            .map_err(index_error)?
            .ok_or(JournalError::Corrupt)?;
        if p.anchor != account.id().0
            || (p.through_position, p.through_hash)
                != (account.head().position, account.head().hash)
        {
            return Err(JournalError::Corrupt);
        }
        let index = Arc::new(SqliteIndex {
            pool: Arc::downgrade(&pool),
            anchor: account.id(),
            epoch: p.epoch,
        });
        Ok(account.rebase(p.epoch, index))
    }
    fn has_account(&self) -> Result<bool, JournalError> {
        Ok(self
            .database()?
            .account_state()
            .map_err(index_error)?
            .is_some())
    }
    fn history_prefix(
        &self,
        cursor: Option<HistoryCursor>,
        limit: usize,
    ) -> Result<Option<HistoryPage>, JournalError> {
        let cursor = cursor.map(|c| AccountHistoryCursor {
            anchor: c.anchor.0,
            cut: (c.cut.position, c.cut.hash),
            next_position: c.next_position,
        });
        Ok(self
            .database()?
            .account_history_page(cursor, limit, MAX_EVENT_LEN)
            .map_err(index_error)?
            .map(|p| {
                let c = HistoryCursor {
                    anchor: AccountId(p.cursor.anchor),
                    cut: Head {
                        position: p.cursor.cut.0,
                        hash: p.cursor.cut.1,
                    },
                    next_position: p.cursor.next_position,
                };
                HistoryPage {
                    anchor: c.anchor,
                    cut: c.cut,
                    first_position: c.next_position,
                    events: p.events,
                    next: p
                        .next_position
                        .map(|next_position| HistoryCursor { next_position, ..c }),
                }
            }))
    }

    fn load(&self) -> Result<Option<JournaledAccount>, JournalError> {
        let database = self.database()?;
        let Some(state) = database
            .account_state()
            .map_err(|_| JournalError::Storage)?
        else {
            return Ok(None);
        };
        let history = database
            .account_history()
            .map_err(|_| JournalError::Storage)?;
        Ok(Some(JournaledAccount {
            anchor: AccountId(state.anchor),
            history,
            head: Head {
                position: state.head_position,
                hash: state.head_hash,
            },
            stopped: state.stopped,
        }))
    }

    fn commit_verified(
        &mut self,
        anchor: AccountId,
        events: &[&[u8]],
        head: Head,
        stopped: bool,
    ) -> Result<(), JournalError> {
        self.database()?
            .commit_account_verified(anchor.0, events, head.position, head.hash, stopped)
            .map_err(|_| JournalError::Storage)
    }

    fn fence(&self, action: impl FnOnce()) -> Result<(), JournalError> {
        match self.database.lock() {
            Ok(_guard) => {
                action();
                Ok(())
            }
            Err(poisoned) => {
                // A poisoned mutex still provides exclusion. Fence stale
                // capabilities before reporting storage failure.
                let _guard = poisoned.into_inner();
                action();
                Err(JournalError::Storage)
            }
        }
    }

    fn commit_verified_fenced(
        &mut self,
        anchor: AccountId,
        events: &[&[u8]],
        head: Head,
        stopped: bool,
        fence: impl FnOnce(bool),
    ) -> Result<(), JournalError> {
        let mut database = match self.database.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                let _guard = poisoned.into_inner();
                fence(false);
                return Err(JournalError::Storage);
            }
        };
        let result = database
            .commit_account_verified(anchor.0, events, head.position, head.hash, stopped)
            .map_err(|_| JournalError::Storage);
        fence(result.is_ok());
        result
    }

    fn commit_projected_fenced(
        &mut self,
        anchor: AccountId,
        events: &[&[u8]],
        head: Head,
        stopped: bool,
        projection: Option<&VerifiedAccount>,
        fence: impl FnOnce(bool),
    ) -> Result<(), JournalError> {
        let mut database = match self.database.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                let _guard = poisoned.into_inner();
                fence(false);
                return Err(JournalError::Storage);
            }
        };
        // Without a reader pool activation uses replay, with no indexed epoch
        // continuation. Persist no projection on that path either.
        let delta = if database.read_pool().is_some() {
            projection.map(VerifiedAccount::delta)
        } else {
            None
        };
        let result = database
            .commit_account_verified_projected(
                anchor.0,
                events,
                head.position,
                head.hash,
                stopped,
                delta.as_ref(),
            )
            .map_err(|_| JournalError::Storage);
        fence(result.is_ok());
        result
    }

    fn device(&self) -> Result<Option<JournaledDevice>, JournalError> {
        let Some(record) = self
            .database()?
            .device_identity()
            .map_err(|_| JournalError::Storage)?
        else {
            return Ok(None);
        };
        let keys = DevicePublicKeys::new(record.signing, record.control, record.receiving)
            .map_err(|_| JournalError::Corrupt)?;
        Ok(Some(JournaledDevice {
            handle: KeyHandle(record.handle),
            keys,
            policy: policy_from_code(record.policy).ok_or(JournalError::Corrupt)?,
            kind: kind_from_code(record.kind).ok_or(JournalError::Corrupt)?,
        }))
    }

    fn commit_device(&mut self, device: &JournaledDevice) -> Result<(), JournalError> {
        let record = DeviceIdentityRecord {
            handle: device.handle.0,
            signing: *device.keys.signing(),
            control: *device.keys.control(),
            receiving: *device.keys.receiving(),
            policy: policy_code(device.policy),
            kind: kind_code(device.kind),
        };
        self.database()?
            .commit_device_identity(&record)
            .map_err(|_| JournalError::Storage)
    }

    fn initial_bootstrap(
        &self,
    ) -> Result<Option<crate::journal::InitialBootstrapRecord>, JournalError> {
        Ok(self
            .database()?
            .initial_bootstrap()
            .map_err(|_| JournalError::Storage)?
            .map(|r| crate::journal::InitialBootstrapRecord {
                anchor: AccountId(r.anchor),
                head: Head {
                    position: r.head_position,
                    hash: r.head_hash,
                },
                recovery_record: r.recovery_record,
                device_seal: r.device_seal,
                recovery_seal: r.recovery_seal,
            }))
    }

    fn retain_initial_bootstrap(
        &mut self,
        r: &crate::journal::InitialBootstrapRecord,
        clear_pending: bool,
    ) -> Result<(), JournalError> {
        self.database()?
            .retain_initial_bootstrap(
                &bh_storage::account::InitialBootstrapRecord {
                    anchor: r.anchor.0,
                    head_position: r.head.position,
                    head_hash: r.head.hash,
                    recovery_record: r.recovery_record.clone(),
                    device_seal: r.device_seal.clone(),
                    recovery_seal: r.recovery_seal.clone(),
                },
                clear_pending,
            )
            .map_err(|_| JournalError::Storage)
    }

    fn pending_setup(&self) -> Result<Option<PendingSetupRecord>, JournalError> {
        let Some(row) = self
            .database()?
            .pending_setup()
            .map_err(|_| JournalError::Storage)?
        else {
            return Ok(None);
        };
        Ok(Some(PendingSetupRecord {
            version: row.version,
            stage: SetupStage::from_code(row.stage).ok_or(JournalError::Corrupt)?,
            kit_saved: row.kit_saved,
            blob: row.blob,
        }))
    }

    fn commit_pending_setup(&mut self, setup: &PendingSetupRecord) -> Result<(), JournalError> {
        let row = PendingSetupRow {
            version: setup.version,
            stage: setup.stage.code(),
            kit_saved: setup.kit_saved,
            blob: setup.blob.clone(),
        };
        self.database()?
            .commit_pending_setup(&row)
            .map_err(|_| JournalError::Storage)
    }

    fn clear_pending_setup(&mut self) -> Result<(), JournalError> {
        self.database()?
            .clear_pending_setup()
            .map_err(|_| JournalError::Storage)
    }

    fn staged_admission(&self) -> Result<Option<StagedAdmission>, JournalError> {
        self.database()?
            .staged_admission()
            .map_err(staged_error)
            .map(|row| {
                row.map(|row| StagedAdmission {
                    position: row.position,
                    previous: row.previous,
                    event: row.event,
                    delivery: row.delivery,
                })
            })
    }

    fn insert_staged_admission(&mut self, row: &StagedAdmission) -> Result<(), JournalError> {
        i64::try_from(row.position).map_err(|_| JournalError::Corrupt)?;
        self.database()?
            .insert_staged_admission(&staged_row(row))
            .map_err(staged_error)
    }

    fn clear_staged_admission(&mut self, expected: &StagedAdmission) -> Result<(), JournalError> {
        self.database()?
            .clear_staged_admission(&staged_row(expected))
            .map_err(staged_error)
    }
}

#[cfg(test)]
mod kind_tests {
    use super::*;

    #[test]
    fn android_lineage_round_trips_without_becoming_a_mac_store() {
        let android = DeviceKeyStoreKind::AndroidKeystoreV1;
        assert_eq!(kind_code(android), 2);
        assert_eq!(kind_from_code(2), Some(android));
        assert_eq!(
            kind_from_code(0),
            Some(DeviceKeyStoreKind::MacLoginKeychainV1)
        );
        assert_eq!(
            kind_from_code(1),
            Some(DeviceKeyStoreKind::MacDataProtectionKeychainV1)
        );
        assert_eq!(kind_from_code(3), None);
    }
}
