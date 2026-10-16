//! Scanner identity is native and journaled once, never regenerated on a QR retry.
#[path = "support/indexed_journal.rs"]
mod indexed_journal;
#[path = "support/store.rs"]
mod store;
use bh_account::{
    AccountEvent, AccountId, Head, RecoveryPublicKeys, VerifiedAccount,
    crypto::{KemKey, SigningKey},
    journal::{
        AccountJournal, JournalError, JournaledAccount, JournaledDevice, JournaledProjection,
        PendingSetupRecord, StagedAdmission,
    },
    owner::AccountGeneration,
    pairing::{PairError, ScannerStatus, scanner_identity, scanner_status},
    platform::{ControlKeyPolicy, KeyStoreError},
    storage::DeviceJournal,
};
use store::FakeStore;

fn ready<F: std::future::Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => panic!("unexpected native async suspension"),
    }
}

#[derive(Default)]
struct Journal {
    device: Option<JournaledDevice>,
    account: Option<JournaledAccount>,
    staged: Option<StagedAdmission>,
}
impl AccountJournal for Journal {
    fn load(&self) -> Result<Option<JournaledAccount>, JournalError> {
        Ok(self.account.clone())
    }
    fn commit_verified(
        &mut self,
        _anchor: AccountId,
        _events: &[&[u8]],
        _head: Head,
        _stopped: bool,
    ) -> Result<(), JournalError> {
        unreachable!()
    }
    fn device(&self) -> Result<Option<JournaledDevice>, JournalError> {
        Ok(self.device.clone())
    }
    fn commit_device(&mut self, device: &JournaledDevice) -> Result<(), JournalError> {
        self.device = Some(device.clone());
        Ok(())
    }
    fn pending_setup(&self) -> Result<Option<PendingSetupRecord>, JournalError> {
        Ok(None)
    }
    fn commit_pending_setup(&mut self, _: &PendingSetupRecord) -> Result<(), JournalError> {
        unreachable!()
    }
    fn clear_pending_setup(&mut self) -> Result<(), JournalError> {
        unreachable!()
    }
    fn staged_admission(&self) -> Result<Option<StagedAdmission>, JournalError> {
        Ok(self.staged.clone())
    }
    fn insert_staged_admission(&mut self, row: &StagedAdmission) -> Result<(), JournalError> {
        if self.staged.is_some() {
            return Err(JournalError::StagedAdmissionExists);
        }
        self.staged = Some(row.clone());
        Ok(())
    }
    fn clear_staged_admission(&mut self, expected: &StagedAdmission) -> Result<(), JournalError> {
        if self.staged.as_ref().is_some_and(|row| row != expected) {
            return Err(JournalError::StagedAdmissionChanged);
        }
        self.staged = None;
        Ok(())
    }
}

#[test]
fn retries_reuse_the_same_native_identity_and_missing_key_is_not_replaced() {
    let generation = AccountGeneration::new();
    let mut native = FakeStore::new(generation);
    let mut journal = Journal::default();
    let first = ready(scanner_identity(
        &mut journal,
        &mut native,
        ControlKeyPolicy::AppEnforcedOwnerConfirmation,
    ))
    .unwrap();
    assert_eq!(scanner_status(&journal).unwrap(), ScannerStatus::Pending);
    for _ in 0..3 {
        let again = ready(scanner_identity(
            &mut journal,
            &mut native,
            ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        ))
        .unwrap();
        assert_eq!(again.keys, first.keys);
        assert!(again.handle == first.handle);
    }
    assert_eq!(native.state().create_calls, 1);
    native.state_mut().fail_load = true;
    assert_eq!(
        ready(scanner_identity(
            &mut journal,
            &mut native,
            ControlKeyPolicy::AppEnforcedOwnerConfirmation
        ))
        .err(),
        Some(PairError::Device(KeyStoreError::Unavailable))
    );
    assert_eq!(native.state().create_calls, 1);
    assert_eq!(journal.device().unwrap().unwrap().keys, first.keys);
}

#[test]
fn existing_account_without_journaled_identity_does_not_create_new_scanner() {
    let mut journal = Journal {
        account: Some(JournaledAccount {
            anchor: AccountId([9; 32]),
            history: vec![],
            head: Head {
                position: 1,
                hash: [1; 32],
            },
            stopped: false,
        }),
        ..Journal::default()
    };
    let mut native = FakeStore::new(AccountGeneration::new());
    assert_eq!(
        ready(scanner_identity(
            &mut journal,
            &mut native,
            ControlKeyPolicy::AppEnforcedOwnerConfirmation
        ))
        .err(),
        Some(PairError::WrongContext)
    );
    assert_eq!(native.state().create_calls, 0);
}

// Native journal load is deliberately unreachable on these paths; its indexed
// projection and existence probe are the only local authority consumed here.
fn native_journal(path: &std::path::Path) -> indexed_journal::HookJournal {
    indexed_journal::HookJournal {
        inner: DeviceJournal::open(path).unwrap(),
        after_advance: Box::new(|_| {}),
        pages: Default::default(),
    }
}

// Capture an authentic native view before interrupting its indexed evidence.
// The status path must consume that same view, not load a fresh projection.
struct CapturedView<'a> {
    journal: &'a mut indexed_journal::HookJournal,
    view: JournaledProjection,
}
impl AccountJournal for CapturedView<'_> {
    fn load(&self) -> Result<Option<JournaledAccount>, JournalError> {
        panic!("no full load")
    }
    fn load_projection(&self) -> Result<Option<JournaledProjection>, JournalError> {
        Ok(Some(JournaledProjection {
            account: self.view.account.clone(),
            stopped: self.view.stopped,
            target: self.view.target,
        }))
    }
    fn has_account(&self) -> Result<bool, JournalError> {
        self.journal.has_account()
    }
    fn device(&self) -> Result<Option<JournaledDevice>, JournalError> {
        self.journal.device()
    }
    fn commit_verified(
        &mut self,
        _: AccountId,
        _: &[&[u8]],
        _: Head,
        _: bool,
    ) -> Result<(), JournalError> {
        unreachable!()
    }
    fn commit_device(&mut self, _: &JournaledDevice) -> Result<(), JournalError> {
        unreachable!()
    }
    fn pending_setup(&self) -> Result<Option<PendingSetupRecord>, JournalError> {
        unreachable!()
    }
    fn commit_pending_setup(&mut self, _: &PendingSetupRecord) -> Result<(), JournalError> {
        unreachable!()
    }
    fn clear_pending_setup(&mut self) -> Result<(), JournalError> {
        unreachable!()
    }
    fn staged_admission(&self) -> Result<Option<StagedAdmission>, JournalError> {
        unreachable!()
    }
    fn insert_staged_admission(&mut self, _: &StagedAdmission) -> Result<(), JournalError> {
        unreachable!()
    }
    fn clear_staged_admission(&mut self, _: &StagedAdmission) -> Result<(), JournalError> {
        unreachable!()
    }
}

fn signed_genesis(
    keys: bh_account::DevicePublicKeys,
    control: &SigningKey,
) -> (AccountId, Vec<u8>) {
    let request = AccountEvent::genesis(
        keys,
        RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public()),
    );
    let event = request
        .finish(control.sign(request.signing_bytes()))
        .unwrap();
    let id = AccountId::of_genesis(&event).unwrap();
    (id, event.as_bytes().to_vec())
}

#[test]
fn native_scanner_identity_uses_existence_without_loading_history() {
    let dir = tempfile::tempdir().unwrap();
    let mut journal = native_journal(&dir.path().join("account.sqlite"));
    let mut native = FakeStore::new(AccountGeneration::new());
    ready(scanner_identity(
        &mut journal,
        &mut native,
        ControlKeyPolicy::AppEnforcedOwnerConfirmation,
    ))
    .unwrap();
    assert_eq!(scanner_status(&journal), Ok(ScannerStatus::Pending));
    let control = SigningKey::generate();
    let (id, genesis) = signed_genesis(
        bh_account::DevicePublicKeys::new(
            SigningKey::generate().public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap(),
        &control,
    );
    journal
        .commit_verified(
            id,
            &[&genesis],
            Head {
                position: 1,
                hash: id.0,
            },
            false,
        )
        .unwrap();
    assert_eq!(scanner_status(&journal), Ok(ScannerStatus::Pending));
    let existing = journal.device().unwrap().unwrap();
    assert_eq!(
        ready(scanner_identity(
            &mut journal,
            &mut native,
            ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        ))
        .unwrap()
        .keys,
        existing.keys,
    );
    let mut no_device = native_journal(&dir.path().join("other.sqlite"));
    no_device
        .commit_verified(
            id,
            &[&genesis],
            Head {
                position: 1,
                hash: id.0,
            },
            false,
        )
        .unwrap();
    assert_eq!(
        ready(scanner_identity(
            &mut no_device,
            &mut native,
            ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        ))
        .err(),
        Some(PairError::WrongContext),
    );
}

#[test]
fn native_indexed_seen_failure_is_unavailable_not_already_added_or_history() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let mut journal = native_journal(&path);
    let mut native = FakeStore::new(AccountGeneration::new());
    ready(scanner_identity(
        &mut journal,
        &mut native,
        ControlKeyPolicy::AppEnforcedOwnerConfirmation,
    ))
    .unwrap();
    let control = SigningKey::generate();
    let (id, genesis) = signed_genesis(
        bh_account::DevicePublicKeys::new(
            SigningKey::generate().public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap(),
        &control,
    );
    journal
        .commit_verified(
            id,
            &[&genesis],
            Head {
                position: 1,
                hash: id.0,
            },
            false,
        )
        .unwrap();
    assert_eq!(scanner_status(&journal), Ok(ScannerStatus::Pending));
    let view = journal.load_projection().unwrap().unwrap();
    let mut captured = CapturedView {
        journal: &mut journal,
        view,
    };
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute("ALTER TABLE account_devices RENAME TO hidden_devices", [])
        .unwrap();
    assert_eq!(scanner_status(&captured), Err(PairError::Unavailable));
    assert_eq!(
        ready(scanner_identity(
            &mut captured,
            &mut native,
            ControlKeyPolicy::AppEnforcedOwnerConfirmation
        ))
        .err(),
        Some(PairError::Unavailable),
    );
    raw.execute("ALTER TABLE hidden_devices RENAME TO account_devices", [])
        .unwrap();
    assert_eq!(scanner_status(&captured), Ok(ScannerStatus::Pending));
}

#[test]
fn malformed_or_stopped_memory_history_remains_history_error() {
    let mut journal = Journal::default();
    let mut native = FakeStore::new(AccountGeneration::new());
    ready(scanner_identity(
        &mut journal,
        &mut native,
        ControlKeyPolicy::AppEnforcedOwnerConfirmation,
    ))
    .unwrap();
    journal.account = Some(JournaledAccount {
        anchor: AccountId([4; 32]),
        history: vec![vec![1, 2, 3]],
        head: Head {
            position: 1,
            hash: [4; 32],
        },
        stopped: false,
    });
    assert_eq!(scanner_status(&journal), Err(PairError::History));
    journal.account.as_mut().unwrap().stopped = true;
    assert_eq!(scanner_status(&journal), Err(PairError::History));
}

#[test]
fn native_partial_projection_does_not_publish_scanner_status() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let mut journal = native_journal(&path);
    let control = SigningKey::generate();
    let keys = bh_account::DevicePublicKeys::new(
        SigningKey::generate().public(),
        control.public(),
        KemKey::generate().public(),
    )
    .unwrap();
    let (id, genesis) = signed_genesis(keys.clone(), &control);
    let second = bh_account::DevicePublicKeys::new(
        SigningKey::generate().public(),
        SigningKey::generate().public(),
        KemKey::generate().public(),
    )
    .unwrap();
    let state = VerifiedAccount::from_genesis(id, &genesis).unwrap();
    let request = state.add_device(keys.id(), second).unwrap();
    let event = request
        .finish(control.sign(request.signing_bytes()))
        .unwrap();
    journal
        .commit_verified(
            id,
            &[&genesis],
            Head {
                position: 1,
                hash: id.0,
            },
            false,
        )
        .unwrap();
    journal
        .commit_verified(id, &[event.as_bytes()], event.head(), false)
        .unwrap();
    journal
        .commit_device(&JournaledDevice {
            handle: bh_account::platform::KeyHandle([1; 32]),
            keys,
            policy: ControlKeyPolicy::AppEnforcedOwnerConfirmation,
            kind: bh_account::platform::DeviceKeyStoreKind::AndroidKeystoreV1,
        })
        .unwrap();
    // No replay on status: a newly reset projection only contains genesis.
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute("DELETE FROM account_projection", [])
        .unwrap();
    assert_eq!(scanner_status(&journal), Err(PairError::Unavailable));
    let partial = journal.load_projection().unwrap().unwrap();
    assert_eq!(partial.account.head().position, 1);
    let completed = partial.account.applied_batch(&[event.as_bytes()]).unwrap();
    journal.advance_projection(&completed).unwrap();
    assert_eq!(scanner_status(&journal), Ok(ScannerStatus::Added));
}
