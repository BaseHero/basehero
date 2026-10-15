//! `AccountJournal` over the device-local SQLite database. Storage keeps opaque
//! rows; this adapter maps them to account types and never adds verification.

use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

use bh_storage::account::{DeviceIdentityRecord, PendingSetupRow, StagedAdmissionRow};
use bh_storage::{DeviceDatabase, StoreError};

use crate::history::{AccountId, DevicePublicKeys, Head};
use crate::journal::{
    AccountJournal, JournalError, JournaledAccount, JournaledDevice, PendingSetupRecord,
    SetupStage, StagedAdmission,
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

impl AccountJournal for DeviceJournal {
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
