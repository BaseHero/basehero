use std::future::Future;
use std::path::PathBuf;

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => panic!("synthetic adapter unexpectedly pending"),
    }
}

#[path = "support/protector.rs"]
mod protector;
#[path = "support/store.rs"]
mod store;

use bh_account::journal::{AccountJournal, JournaledAccount, SetupStage};
use bh_account::owner::{
    AccountCapability, AccountGeneration, AccountLoad, AdmissionReason, Authority, OwnerError,
    SetupError, SetupStatus,
};
use bh_account::platform::{ControlKeyPolicy, KeyStoreError};
use bh_account::recovery::Password;
use bh_account::storage::DeviceJournal;
use bh_account::{AccountEvent, Head};
use protector::PlainProtector;
use rusqlite::{Connection, params};
use store::FakeStore;

type Owner = bh_account::owner::AccountOwner<DeviceJournal, FakeStore, PlainProtector>;

/// One temp database path plus shared native-key state across "restarts".
struct Harness {
    dir: tempfile::TempDir,
    path: PathBuf,
    generation: AccountGeneration,
    store: FakeStore,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("account.sqlite");
        let generation = AccountGeneration::new();
        let store = FakeStore::new(generation.clone());
        Self {
            dir,
            path,
            generation,
            store,
        }
    }

    fn owner(&self) -> Owner {
        let journal = DeviceJournal::open(&self.path).expect("open device journal");
        bh_account::owner::AccountOwner::new(
            journal,
            self.store.clone(),
            PlainProtector,
            self.generation.clone(),
        )
    }

    fn journal(&self) -> DeviceJournal {
        DeviceJournal::open(&self.path).expect("open device journal")
    }

    fn raw(&self) -> Connection {
        Connection::open(&self.path).unwrap()
    }

    fn stored(&self) -> JournaledAccount {
        self.journal().load().unwrap().expect("journaled account")
    }
}

fn password() -> Password {
    Password::new("correct horse battery staple").unwrap()
}

fn begin(owner: &mut Owner) -> SetupStatus {
    ready(owner.begin_first_device(ControlKeyPolicy::AppEnforcedOwnerConfirmation, &password()))
        .expect("first device setup")
}

/// A complete, kit-saved first device, returned at rest.
fn complete(h: &Harness) -> SetupStatus {
    let mut owner = h.owner();
    let status = begin(&mut owner);
    owner
        .confirm_home_ordered(status.head)
        .expect("home ordered");
    owner.confirm_kit_saved().expect("kit saved");
    status
}

fn activate(owner: &mut Owner) -> AccountCapability {
    match ready(owner.activate()).expect("journal load") {
        AccountLoad::Active(capability) => capability,
        other => panic!("expected active account, got {other:?}"),
    }
}

#[test]
fn setup_resumes_at_each_stage_without_duplicate_genesis() {
    let h = Harness::new();
    let mut owner = h.owner();
    assert!(matches!(
        ready(owner.activate()).unwrap(),
        AccountLoad::Uninitialized
    ));

    let status = begin(&mut owner);
    assert_eq!(status.stage, SetupStage::Prepared);
    assert!(!status.kit_saved);
    assert_eq!(status.submission.len(), 3, "genesis + record + publication");
    let genesis = status.submission[0].clone();
    let code = owner.pending_kit_code().expect("pending code");
    assert!(
        h.journal().load().unwrap().is_none(),
        "not yet home-ordered"
    );
    assert_eq!(h.store.state().create_calls, 1);

    // Restart at Prepared: exact genesis and code survive, nothing regenerates.
    drop(owner);
    let mut owner = h.owner();
    let resumed = owner.setup_status().expect("resume").expect("setup");
    assert_eq!(resumed.stage, SetupStage::Prepared);
    assert_eq!(resumed.submission[0], genesis);
    assert!(resumed.anchor == status.anchor);
    assert_eq!(owner.pending_kit_code().unwrap().expose(), code.expose());
    assert_eq!(h.store.state().create_calls, 1, "no second genesis");

    // A retry while setup is pending must not start over.
    assert!(matches!(
        ready(
            owner.begin_first_device(ControlKeyPolicy::AppEnforcedOwnerConfirmation, &password())
        ),
        Err(SetupError::AlreadyStarted)
    ));
    assert_eq!(h.store.state().create_calls, 1);

    // Restart at HomePending, then confirm the exact head.
    owner.mark_home_pending().expect("submitted");
    drop(owner);
    let mut owner = h.owner();
    assert_eq!(
        owner.setup_status().unwrap().unwrap().stage,
        SetupStage::HomePending
    );
    assert!(h.journal().load().unwrap().is_none());
    owner
        .confirm_home_ordered(status.head)
        .expect("home ordered");
    assert_eq!(h.stored().head, status.head);

    // Restart, then finish only on explicit save confirmation.
    drop(owner);
    let mut owner = h.owner();
    assert!(owner.setup_status().unwrap().is_some(), "kit not saved yet");
    owner.confirm_kit_saved().expect("kit saved");
    drop(owner);
    let mut owner = h.owner();
    assert!(owner.setup_status().unwrap().is_none());
    assert!(h.journal().pending_setup().unwrap().is_none());
    assert!(
        h.journal().load().unwrap().is_some(),
        "account survives setup"
    );
    let capability = activate(&mut owner);
    assert!(capability.account_id() == status.anchor);
}

#[test]
fn home_order_is_idempotent_over_real_storage() {
    let h = Harness::new();
    let mut owner = h.owner();
    let status = begin(&mut owner);
    owner.mark_home_pending().unwrap();
    owner
        .confirm_home_ordered(status.head)
        .expect("home ordered");
    // A resumed/retried confirmation must not append the same bytes twice.
    owner
        .confirm_home_ordered(status.head)
        .expect("idempotent retry");
    let stored = h.stored();
    assert_eq!(stored.history.len(), 3, "no duplicate events");
    assert_eq!(stored.head, status.head);
}

#[test]
fn kit_saved_before_ordering_survives_restart_and_deletes_after_ordering() {
    let h = Harness::new();
    let mut owner = h.owner();
    let status = begin(&mut owner);
    let code = owner.pending_kit_code().unwrap().expose().to_owned();

    // The person confirms the kit while the home has not ordered yet.
    owner
        .confirm_kit_saved()
        .expect("confirmed before ordering");
    let resumed = owner.setup_status().unwrap().unwrap();
    assert!(resumed.kit_saved);
    assert_eq!(owner.pending_kit_code().unwrap().expose(), &code);
    assert!(
        h.journal().pending_setup().unwrap().is_some(),
        "code retained until ordering"
    );

    // The confirmation survives a restart, and ordering then deletes the blob.
    drop(owner);
    let mut owner = h.owner();
    assert!(owner.setup_status().unwrap().unwrap().kit_saved);
    owner
        .confirm_home_ordered(status.head)
        .expect("home ordered");
    assert!(owner.setup_status().unwrap().is_none());
    assert!(h.journal().pending_setup().unwrap().is_none());
    assert!(matches!(
        owner.pending_kit_code(),
        Err(SetupError::NotStarted)
    ));
    assert!(h.journal().load().unwrap().is_some());
}

#[test]
fn kit_confirmation_is_explicit_and_order_alone_keeps_the_code() {
    let h = Harness::new();
    let mut owner = h.owner();
    let status = begin(&mut owner);
    let code = owner.pending_kit_code().unwrap().expose().to_owned();

    // Ordering alone deletes nothing: the person has not confirmed a save.
    owner
        .confirm_home_ordered(status.head)
        .expect("home ordered");
    assert!(h.journal().pending_setup().unwrap().is_some());
    let status = owner.setup_status().unwrap().unwrap();
    assert!(!status.kit_saved);
    assert_eq!(owner.pending_kit_code().unwrap().expose(), &code);

    owner.confirm_kit_saved().expect("explicit save");
    assert!(owner.setup_status().unwrap().is_none());
    assert!(matches!(
        owner.pending_kit_code(),
        Err(SetupError::NotStarted)
    ));
}

#[test]
fn begin_after_setup_is_refused_without_touching_the_device() {
    let h = Harness::new();
    let status = complete(&h);
    let creates = h.store.state().create_calls;
    let stored = h.stored();

    let mut owner = h.owner();
    assert!(matches!(
        ready(
            owner.begin_first_device(ControlKeyPolicy::AppEnforcedOwnerConfirmation, &password())
        ),
        Err(SetupError::AlreadyStarted)
    ));
    assert_eq!(h.store.state().create_calls, creates, "no second device");
    assert!(h.stored().anchor == stored.anchor);
    assert_eq!(h.stored().head, stored.head);
    // The existing account still activates.
    match ready(owner.activate()).unwrap() {
        AccountLoad::Active(capability) => assert!(capability.account_id() == status.anchor),
        other => panic!("expected active account, got {other:?}"),
    }
}

#[test]
fn uncertain_home_head_does_not_advance_or_bless_bytes() {
    let h = Harness::new();
    let mut owner = h.owner();
    let status = begin(&mut owner);
    let wrong = Head {
        position: status.head.position + 7,
        hash: [9; 32],
    };
    assert!(matches!(
        owner.confirm_home_ordered(wrong),
        Err(SetupError::HomeMismatch)
    ));
    assert_eq!(
        owner.setup_status().unwrap().unwrap().stage,
        SetupStage::Prepared
    );
    assert!(
        h.journal().load().unwrap().is_none(),
        "an uncertain head is never a verified head"
    );

    owner.mark_home_pending().unwrap();
    assert!(matches!(
        owner.confirm_home_ordered(wrong),
        Err(SetupError::HomeMismatch)
    ));
    assert_eq!(
        owner.setup_status().unwrap().unwrap().stage,
        SetupStage::HomePending
    );
    assert!(h.journal().load().unwrap().is_none());
}

#[test]
fn invalid_incoming_history_persists_stop_with_unchanged_head() {
    let h = Harness::new();
    let _ = complete(&h);
    let mut owner = h.owner();
    let _capability = activate(&mut owner);
    let before = h.stored();

    assert!(matches!(
        owner.apply_incoming(&[b"not an account event"]),
        Err(OwnerError::Invalid(_))
    ));
    let after = h.stored();
    assert!(after.stopped, "invalid input must sticky-stop");
    assert_eq!(after.head, before.head);
    assert_eq!(after.history, before.history, "no unverified bytes stored");

    // The stop is sticky: more input never revives the account or moves the head.
    assert!(matches!(
        owner.apply_incoming(&[b"more"]),
        Err(OwnerError::Stopped)
    ));
    assert_eq!(h.stored().head, before.head);
}

#[test]
fn sticky_stop_survives_restart_and_keeps_remembered_head() {
    let h = Harness::new();
    let _ = complete(&h);
    let mut owner = h.owner();
    let _ = activate(&mut owner);
    let before = h.stored().head;
    assert!(owner.apply_incoming(&[b"bad"]).is_err());

    drop(owner);
    let mut owner = h.owner();
    assert!(matches!(
        ready(owner.activate()).unwrap(),
        AccountLoad::Stopped
    ));
    let stored = h.stored();
    assert!(stored.stopped);
    assert_eq!(stored.head, before);
}

#[test]
fn replay_rollback_and_fork_are_refused() {
    let h = Harness::new();
    let _ = complete(&h);
    let mut owner = h.owner();
    let _ = activate(&mut owner);
    let original = h.stored();

    // Rollback: the remembered head points past the stored history.
    h.raw()
        .execute("UPDATE account_state SET head_position=4 WHERE id=1", [])
        .unwrap();
    let rolled_back = h.stored();
    match ready(owner.activate()).unwrap() {
        AccountLoad::AdmissionRequired(AdmissionReason::CorruptHistory) => {}
        other => panic!("expected corrupt history, got {other:?}"),
    }
    assert_eq!(
        h.stored().head,
        rolled_back.head,
        "a refused replay must not clear or replace the remembered head"
    );
    assert_eq!(h.stored().history, rolled_back.history);

    // Fork: different bytes at a remembered position.
    h.raw()
        .execute(
            "UPDATE account_state SET head_position=3, head_hash=?1 WHERE id=1",
            params![original.head.hash.as_slice()],
        )
        .unwrap();
    let mut forked = original.history[2].clone();
    forked[0] ^= 1;
    h.raw()
        .execute(
            "UPDATE account_events SET bytes=?1 WHERE id=3",
            params![forked.as_slice()],
        )
        .unwrap();
    match ready(owner.activate()).unwrap() {
        AccountLoad::AdmissionRequired(AdmissionReason::CorruptHistory) => {}
        other => panic!("expected corrupt history, got {other:?}"),
    }
}

#[test]
fn missing_or_wrong_native_key_requires_fresh_admission() {
    let h = Harness::new();
    let _ = complete(&h);
    let before = h.stored();
    let creates = h.store.state().create_calls;

    h.store.state_mut().fail_load = true;
    let mut owner = h.owner();
    match ready(owner.activate()).unwrap() {
        AccountLoad::AdmissionRequired(AdmissionReason::KeyUnavailable) => {}
        other => panic!("expected key unavailable, got {other:?}"),
    }
    assert_eq!(h.store.state().create_calls, creates, "never regenerate");
    assert_eq!(h.stored().head, before.head);
    assert_eq!(h.stored().history, before.history);

    h.store.state_mut().fail_load = false;
    h.store.state_mut().wrong_public = true;
    let mut owner = h.owner();
    match ready(owner.activate()).unwrap() {
        AccountLoad::AdmissionRequired(AdmissionReason::KeyUnavailable) => {}
        other => panic!("expected key mismatch, got {other:?}"),
    }
}

#[test]
fn transient_store_failure_is_not_a_lost_key() {
    let h = Harness::new();
    let _ = complete(&h);
    let before = h.stored();

    for error in [
        KeyStoreError::AuthenticationCancelled,
        KeyStoreError::StorageFailure,
    ] {
        h.store.state_mut().load_error = Some(error);
        let mut owner = h.owner();
        assert!(matches!(
            ready(owner.activate()),
            Err(OwnerError::Device(reported)) if reported == error
        ));
        assert_eq!(
            h.stored().head,
            before.head,
            "a cancelled prompt is not a reset"
        );
    }
    h.store.state_mut().load_error = Some(KeyStoreError::Unavailable);
    let mut owner = h.owner();
    assert!(matches!(
        ready(owner.activate()).unwrap(),
        AccountLoad::AdmissionRequired(AdmissionReason::KeyUnavailable)
    ));
}

#[test]
fn activate_rejects_a_generation_change_during_the_native_load() {
    let h = Harness::new();
    let _ = complete(&h);

    h.store.state_mut().advance_generation_on_load = true;
    let mut owner = h.owner();
    assert!(matches!(ready(owner.activate()), Err(OwnerError::Stale)));
    // A fresh generation can activate normally.
    h.store.state_mut().advance_generation_on_load = false;
    let mut owner = h.owner();
    let _ = activate(&mut owner);
}

#[test]
fn activation_requires_ready_materials() {
    for events in 1..=2 {
        let h = Harness::new();
        let mut setup = h.owner();
        let status = begin(&mut setup);
        drop(setup);

        // Keep only the device identity and the first `events` signed events.
        let mut journal = h.journal();
        journal.clear_pending_setup().unwrap();
        let head = AccountEvent::decode(&status.submission[events - 1])
            .unwrap()
            .head();
        let committed: Vec<&[u8]> = status.submission[..events]
            .iter()
            .map(Vec::as_slice)
            .collect();
        journal
            .commit_verified(status.anchor, &committed, head, false)
            .unwrap();
        drop(journal);

        let mut owner = h.owner();
        match ready(owner.activate()).unwrap() {
            AccountLoad::AdmissionRequired(AdmissionReason::IncompleteMaterials) => {}
            other => panic!("expected incomplete materials for {events} events, got {other:?}"),
        }
    }
}

#[test]
fn a_failed_stop_write_still_stops_the_session() {
    let h = Harness::new();
    let _ = complete(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    // The durable stop write fails after the in-memory stop is set.
    h.raw()
        .execute_batch(
            "CREATE TRIGGER fail_stop BEFORE UPDATE ON account_state \
             BEGIN SELECT RAISE(FAIL, 'no space'); END;",
        )
        .unwrap();
    assert!(matches!(
        owner.apply_incoming(&[b"bad"]),
        Err(OwnerError::Journal(_))
    ));
    assert!(matches!(
        owner.prepare_remove_self(&capability),
        Err(OwnerError::Stopped)
    ));
}

#[test]
fn removed_device_denies_the_old_capability() {
    let h = Harness::new();
    let _ = complete(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    let request = owner.prepare_remove_self(&capability).unwrap();
    let event = ready(owner.sign_control(&capability, &request)).unwrap();
    let head = owner.apply_incoming(&[event.as_bytes()]).unwrap();
    assert_eq!(head, event.head());

    assert!(ready(owner.sign_control(&capability, &request)).is_err());
    drop(owner);
    let mut owner = h.owner();
    match ready(owner.activate()).unwrap() {
        AccountLoad::AdmissionRequired(AdmissionReason::DeviceNotActive) => {}
        other => panic!("expected removed device, got {other:?}"),
    }
}

#[test]
fn stale_generation_after_await_is_rejected() {
    let h = Harness::new();
    let _ = complete(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    let request = owner.prepare_remove_self(&capability).unwrap();

    h.store.state_mut().advance_generation_on_sign = true;
    assert!(matches!(
        ready(owner.sign_control(&capability, &request)),
        Err(OwnerError::Stale)
    ));
    h.store.state_mut().advance_generation_on_sign = false;

    let capability = activate(&mut owner);
    ready(owner.sign_control(&capability, &request)).unwrap();
}

#[test]
fn lock_invalidates_the_generation_and_the_capability() {
    let h = Harness::new();
    let _ = complete(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    assert_eq!(capability.authority(), Authority::OfflineLastVerified);
    let request = owner.prepare_remove_self(&capability).unwrap();
    owner.lock();
    assert!(matches!(
        ready(owner.sign_control(&capability, &request)),
        Err(OwnerError::NotActive)
    ));
    let _ = activate(&mut owner);
    let _ = &h.dir;
}
