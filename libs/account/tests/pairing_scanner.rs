//! Scanner identity is native and journaled once, never regenerated on a QR retry.
#[path = "support/store.rs"]
mod store;
use bh_account::{
    AccountId, Head,
    journal::{
        AccountJournal, JournalError, JournaledAccount, JournaledDevice, PendingSetupRecord,
        StagedAdmission,
    },
    owner::AccountGeneration,
    pairing::{PairError, ScannerStatus, scanner_identity, scanner_status},
    platform::{ControlKeyPolicy, KeyStoreError},
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
