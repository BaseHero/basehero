use bh_device::{ContainerId, Owner, OwnerError};
use bh_storage::{
    DeviceDatabase, OpenError,
    account::{DeviceIdentityRecord, PendingSetupRow, StagedAdmissionRow},
};
use std::{fs, fs::OpenOptions};

#[test]
fn bad_container_does_not_strand_good_ones() {
    let dir = tempfile::tempdir().unwrap();
    let seed = Owner::default();
    seed.create_container(dir.path()).unwrap();
    seed.create_container(dir.path()).unwrap();
    drop(seed);
    let bad = "abcdef0123456789abcdef0123456789";
    let path = dir.path().join("accounts").join(format!("{bad}.sqlite"));
    let db = rusqlite::Connection::open(path).unwrap();
    db.pragma_update(None, "user_version", 999).unwrap();
    drop(db);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let (owner, files) = loop {
        let owner = Owner::default();
        let files = owner.open_containers(dir.path()).unwrap();
        if files.iter().filter(|(_, result)| result.is_ok()).count() == 2 {
            break (owner, files);
        }
        assert!(
            std::time::Instant::now() < deadline,
            "good containers stayed Busy"
        );
        drop(owner);
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert_eq!(files.len(), 3);
    assert!(matches!(
        files.iter().find(|(stem, _)| stem == bad).unwrap().1,
        Err(OwnerError::Open(OpenError::NewerData { .. }))
    ));
    assert_eq!(files.iter().filter(|(_, id)| id.is_ok()).count(), 2);
    let again = owner.open_containers(dir.path()).unwrap();
    assert_eq!(
        again
            .iter()
            .filter(|(_, result)| matches!(result, Err(OwnerError::Busy)))
            .count(),
        2
    );
    assert_eq!(again.iter().filter(|(_, result)| result.is_ok()).count(), 0);
}

#[test]
fn external_lock_prevents_any_sqlite_initialization() {
    let dir = tempfile::tempdir().unwrap();
    let accounts = dir.path().join("accounts");
    fs::create_dir(&accounts).unwrap();
    let path = accounts.join("abcdef0123456789abcdef0123456789.sqlite");
    fs::write(&path, []).unwrap();
    let lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.with_extension("lock"))
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    let result = Owner::default().open_containers(dir.path()).unwrap();
    assert_eq!(result.len(), 1);
    assert!(matches!(result[0].1, Err(OwnerError::Busy)));
    assert_eq!(fs::metadata(&path).unwrap().len(), 0);
    assert!(!path.with_extension("sqlite-wal").exists());
    assert!(!path.with_extension("sqlite-shm").exists());
}

#[test]
fn general_open_cannot_bypass_live_container() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Owner::default();
    owner.create_container(dir.path()).unwrap();
    let path = fs::read_dir(dir.path().join("accounts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "sqlite"))
        .unwrap();
    assert!(matches!(DeviceDatabase::open(path), Err(OpenError::Busy)));
}

#[test]
fn unanchored_container_with_pending_note_work_is_not_empty() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Owner::default();
    let id = owner.create_container(dir.path()).unwrap();
    let key = bh_storage::NoteKey {
        base: [1; 32],
        audience: [2; 32],
        note: [3; 32],
    };
    owner
        .shared_database(id)
        .unwrap()
        .lock()
        .unwrap()
        .apply_local_update(
            key,
            [4; 16],
            &bh_core::note::Note::new().append_paragraph("unsent"),
        )
        .unwrap();
    assert!(
        !owner.is_empty(id).unwrap(),
        "reusing this container could mix another account with pending writing"
    );
}

#[test]
fn empty_container_may_be_reused_after_crash() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Owner::default();
    let id = owner.create_container(dir.path()).unwrap();
    assert!(owner.is_empty(id).unwrap());
    assert!(matches!(
        owner.is_empty(ContainerId::default()),
        Err(OwnerError::UnknownContainer)
    ));
    drop(owner);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let (reopened, id) = loop {
        let reopened = Owner::default();
        let result = reopened.open_containers(dir.path()).unwrap().remove(0).1;
        match result {
            Ok(id) => break (reopened, id),
            Err(OwnerError::Busy) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            other => panic!("reopen: {other:?}"),
        }
    };
    assert!(reopened.is_empty(id).unwrap());
    let db = reopened.shared_database(id).unwrap();
    db.lock()
        .unwrap()
        .commit_pending_setup(&PendingSetupRow {
            version: 1,
            stage: 1,
            kit_saved: false,
            blob: vec![42],
        })
        .unwrap();
    assert!(!reopened.is_empty(id).unwrap());
    db.lock().unwrap().clear_pending_setup().unwrap();
    assert!(reopened.is_empty(id).unwrap());
    let staged = StagedAdmissionRow {
        position: 2,
        previous: [1; 32],
        event: vec![2],
        delivery: vec![3],
    };
    db.lock().unwrap().insert_staged_admission(&staged).unwrap();
    assert!(!reopened.is_empty(id).unwrap());
    db.lock().unwrap().clear_staged_admission(&staged).unwrap();
    assert!(reopened.is_empty(id).unwrap());
    db.lock()
        .unwrap()
        .commit_device_identity(&DeviceIdentityRecord {
            handle: [1; 32],
            signing: [2; 32],
            control: [3; 32],
            receiving: [4; 1216],
            policy: 0,
            kind: 0,
        })
        .unwrap();
    assert!(!reopened.is_empty(id).unwrap());
    // An account row means this container is no longer a reusable setup slot.
    let signing = bh_account::crypto::SigningKey::generate();
    let control = bh_account::crypto::SigningKey::generate();
    let device = bh_account::DevicePublicKeys::new(
        signing.public(),
        control.public(),
        bh_account::crypto::KemKey::generate().public(),
    )
    .unwrap();
    let recovery = bh_account::RecoveryPublicKeys::new(
        bh_account::crypto::SigningKey::generate().public(),
        bh_account::crypto::KemKey::generate().public(),
    );
    let draft = bh_account::AccountEvent::genesis(device, recovery);
    let event = draft.finish(control.sign(draft.signing_bytes())).unwrap();
    let verified = bh_account::VerifiedAccount::from_genesis(
        bh_account::AccountId::of_genesis(&event).unwrap(),
        event.as_bytes(),
    )
    .unwrap();
    db.lock()
        .unwrap()
        .commit_account_verified(
            verified.id().0,
            &[event.as_bytes()],
            verified.head().position,
            verified.head().hash,
            false,
        )
        .unwrap();
    assert!(!reopened.is_empty(id).unwrap());
}
