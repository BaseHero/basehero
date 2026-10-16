use bh_account::{
    AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount,
    crypto::{KemKey, SigningKey},
};
use bh_device::{Owner, OwnerError};
use std::{fs, process::Command};

fn account() -> (VerifiedAccount, Vec<u8>) {
    let signing = SigningKey::generate();
    let control = SigningKey::generate();
    let device = DevicePublicKeys::new(
        signing.public(),
        control.public(),
        KemKey::generate().public(),
    )
    .unwrap();
    let recovery =
        RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public());
    let draft = AccountEvent::genesis(device, recovery);
    let event = draft.finish(control.sign(draft.signing_bytes())).unwrap();
    (
        VerifiedAccount::from_genesis(AccountId::of_genesis(&event).unwrap(), event.as_bytes())
            .unwrap(),
        event.as_bytes().to_vec(),
    )
}

#[test]
fn create_reopen_stored_account_and_anchor_once() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Owner::default();
    let first = owner.create_container(dir.path()).unwrap();
    let (account, bytes) = account();
    owner
        .shared_database(first)
        .unwrap()
        .lock()
        .unwrap()
        .commit_account_verified(
            account.id().0,
            &[&bytes],
            account.head().position,
            account.head().hash,
            false,
        )
        .unwrap();
    let paths: Vec<_> = fs::read_dir(dir.path().join("accounts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "sqlite"))
        .collect();
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0].file_stem().unwrap().len(), 32);
    drop(owner);
    let reopened = Owner::default();
    let ids = reopen_after_background_release(&reopened, dir.path());
    assert_eq!(ids.len(), 1);
    assert!(!reopened.is_empty(ids[0]).unwrap());
    reopened.anchor(ids[0], &account).unwrap();
    assert!(!reopened.is_empty(ids[0]).unwrap());
    let other = reopened.create_container(dir.path()).unwrap();
    reopened
        .shared_database(other)
        .unwrap()
        .lock()
        .unwrap()
        .commit_account_verified(
            account.id().0,
            &[&bytes],
            account.head().position,
            account.head().hash,
            false,
        )
        .unwrap();
    assert!(matches!(
        reopened.anchor(other, &account),
        Err(OwnerError::DuplicateAnchor)
    ));
}

#[test]
fn stray_files_and_locked_container_do_not_prevent_free_open() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Owner::default();
    let locked = owner.create_container(dir.path()).unwrap();
    let _free = owner.create_container(dir.path()).unwrap();
    let held = owner.shared_database(locked).unwrap();
    drop(owner);
    fs::write(
        dir.path().join("accounts").join("unfinished.tmp"),
        b"partial",
    )
    .unwrap();
    fs::write(dir.path().join("accounts").join("readme"), b"stray").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let second = loop {
        let second = Owner::default();
        let files = second.open_containers(dir.path()).unwrap();
        if files.iter().filter(|(_, result)| result.is_ok()).count() == 1 {
            break second;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "free container stayed Busy"
        );
        drop(second);
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    drop(held);
    drop(second);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        let reopened = Owner::default();
        match reopened.open_containers(dir.path()) {
            Ok(files) if files.len() == 2 && files.iter().all(|(_, id)| id.is_ok()) => break,
            Ok(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            result => panic!("two unlocked containers: {result:?}"),
        }
    }
}

fn reopen_after_background_release(
    owner: &Owner,
    path: &std::path::Path,
) -> Vec<bh_device::ContainerId> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        match owner.open_containers(path) {
            Ok(files) if files.iter().all(|(_, result)| result.is_ok()) => {
                return files
                    .into_iter()
                    .map(|(_, result)| result.unwrap())
                    .collect();
            }
            Ok(_) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10))
            }
            result => panic!("reopen: {result:?}"),
        }
    }
}

#[test]
fn shared_handle_retains_process_lock() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Owner::default();
    let id = owner.create_container(dir.path()).unwrap();
    let database = owner.shared_database(id).unwrap();
    drop(owner);
    assert!(matches!(
        Owner::default().open_containers(dir.path()).unwrap()[0].1,
        Err(OwnerError::Busy)
    ));
    drop(database);
    assert_eq!(
        reopen_after_background_release(&Owner::default(), dir.path()).len(),
        1
    );
}

#[test]
fn independent_accounts_do_not_share_writer_guard() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Owner::default();
    let first = owner.create_container(dir.path()).unwrap();
    let second = owner.create_container(dir.path()).unwrap();
    let held = owner.shared_database(first).unwrap();
    let other = owner.shared_database(second).unwrap();
    let guard = held.lock().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        let db = other.lock().unwrap();
        tx.send(db.data_version()).unwrap();
    });
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap(),
        bh_core::LOCAL_DATA_VERSION
    );
    drop(guard);
    worker.join().unwrap();
}

#[test]
fn borrowed_read_pool_keeps_lock_until_connections_close() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Owner::default();
    let id = owner.create_container(dir.path()).unwrap();
    let shared = owner.shared_database(id).unwrap();
    let pool = shared.lock().unwrap().read_pool().unwrap();
    drop(shared);
    drop(owner);
    assert!(matches!(
        Owner::default().open_containers(dir.path()).unwrap()[0].1,
        Err(OwnerError::Busy)
    ));
    drop(pool);
    assert_eq!(
        reopen_after_background_release(&Owner::default(), dir.path()).len(),
        1
    );
}

#[test]
fn subprocess_cannot_take_live_container_lock() {
    if let Ok(path) = std::env::var("BH_TEST_CONTAINER_DIR") {
        let owner = Owner::default();
        assert!(matches!(
            owner.open_containers(std::path::Path::new(&path)).unwrap()[0].1,
            Err(OwnerError::Busy)
        ));
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let owner = Owner::default();
    let id = owner.create_container(dir.path()).unwrap();
    let handle = owner.shared_database(id).unwrap();
    drop(owner);
    let result = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("subprocess_cannot_take_live_container_lock")
        .arg("--nocapture")
        .env("BH_TEST_CONTAINER_DIR", dir.path())
        .status()
        .unwrap();
    assert!(result.success());
    drop(handle);
    assert_eq!(
        reopen_after_background_release(&Owner::default(), dir.path()).len(),
        1
    );
}
