//! Storage-only account journal operations. These check atomic persistence of
//! opaque rows; verification lives in `bh-account`.
use bh_storage::DeviceDatabase;
use bh_storage::StoreError;
use bh_storage::account::{DeviceIdentityRecord, PendingSetupRow, StagedAdmissionRow};
use rusqlite::Connection;

fn database() -> (tempfile::TempDir, DeviceDatabase) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let database = DeviceDatabase::open(&path).unwrap();
    (dir, database)
}

fn identity() -> DeviceIdentityRecord {
    DeviceIdentityRecord {
        handle: [7; 32],
        signing: [1; 32],
        control: [2; 32],
        receiving: [3; 1216],
        policy: 2,
        kind: 0,
    }
}

#[test]
fn verified_commit_and_stop_share_one_transaction() {
    let (_dir, mut database) = database();
    assert!(database.account_state().unwrap().is_none());

    database
        .commit_account_verified([9; 32], &[b"genesis", b"record"], 2, [4; 32], false)
        .unwrap();
    let state = database.account_state().unwrap().unwrap();
    assert_eq!(state.anchor, [9; 32]);
    assert_eq!(state.head_position, 2);
    assert_eq!(state.head_hash, [4; 32]);
    assert!(!state.stopped);
    assert_eq!(
        database.account_history().unwrap(),
        vec![b"genesis".to_vec(), b"record".to_vec()]
    );

    // A stop carries no new bytes and keeps the last head and history.
    database
        .commit_account_verified([9; 32], &[], 2, [4; 32], true)
        .unwrap();
    let state = database.account_state().unwrap().unwrap();
    assert!(state.stopped);
    assert_eq!(state.head_position, 2);
    assert_eq!(state.head_hash, [4; 32]);
    assert_eq!(database.account_history().unwrap().len(), 2);
}

#[test]
fn head_without_matching_bytes_is_rejected_and_changes_nothing() {
    let (_dir, mut database) = database();
    database
        .commit_account_verified([9; 32], &[b"genesis"], 1, [4; 32], false)
        .unwrap();

    let result = database.commit_account_verified([9; 32], &[b"record"], 5, [5; 32], false);
    assert!(matches!(result, Err(StoreError::HeadWithoutBytes)));
    let state = database.account_state().unwrap().unwrap();
    assert_eq!(state.head_position, 1);
    assert_eq!(state.head_hash, [4; 32]);
    assert_eq!(
        database.account_history().unwrap(),
        vec![b"genesis".to_vec()]
    );
}

#[test]
fn a_different_anchor_is_refused_for_the_same_journal() {
    let (_dir, mut database) = database();
    database
        .commit_account_verified([9; 32], &[b"genesis"], 1, [4; 32], false)
        .unwrap();
    assert!(matches!(
        database.commit_account_verified([8; 32], &[b"other"], 2, [5; 32], false),
        Err(StoreError::CorruptAccount)
    ));
    assert_eq!(database.account_history().unwrap().len(), 1);
}

#[test]
fn device_identity_and_pending_setup_round_trip() {
    let (_dir, mut database) = database();
    assert!(database.device_identity().unwrap().is_none());
    assert!(database.pending_setup().unwrap().is_none());

    let record = identity();
    database.commit_device_identity(&record).unwrap();
    assert_eq!(database.device_identity().unwrap().unwrap(), record);

    let setup = PendingSetupRow {
        version: 1,
        stage: 1,
        kit_saved: false,
        blob: vec![0xaa; 32],
    };
    database.commit_pending_setup(&setup).unwrap();
    assert_eq!(database.pending_setup().unwrap().unwrap(), setup);

    // A later commit cannot clear an already-recorded kit confirmation.
    database
        .commit_pending_setup(&PendingSetupRow {
            kit_saved: true,
            ..setup.clone()
        })
        .unwrap();
    database.commit_pending_setup(&setup).unwrap();
    assert!(database.pending_setup().unwrap().unwrap().kit_saved);

    database.clear_pending_setup().unwrap();
    assert!(database.pending_setup().unwrap().is_none());
    // Clearing setup never clears the device identity or account state.
    assert_eq!(database.device_identity().unwrap().unwrap(), record);
}

#[test]
fn a_write_refusal_rolls_back_events_and_state_together() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("atomic.sqlite");
    let mut database = DeviceDatabase::open(&path).unwrap();
    // A second connection refuses the state upsert after the event inserts in
    // the same transaction.
    let other = Connection::open(&path).unwrap();
    other
        .execute_batch(
            "CREATE TRIGGER fail_state BEFORE INSERT ON account_state \
             BEGIN SELECT RAISE(FAIL, 'no space'); END;",
        )
        .unwrap();
    assert!(matches!(
        database.commit_account_verified([9; 32], &[b"genesis", b"record"], 2, [4; 32], false),
        Err(StoreError::Database(_))
    ));
    assert!(
        database.account_history().unwrap().is_empty(),
        "event bytes must not land without the head"
    );
    assert!(
        database.account_state().unwrap().is_none(),
        "the head must not land without the bytes"
    );

    other.execute_batch("DROP TRIGGER fail_state").unwrap();
    database
        .commit_account_verified([9; 32], &[b"genesis", b"record"], 2, [4; 32], false)
        .unwrap();
    assert_eq!(database.account_history().unwrap().len(), 2);
    assert_eq!(database.account_state().unwrap().unwrap().head_position, 2);
}

#[test]
fn storage_never_clears_a_stop() {
    let (_dir, mut database) = database();
    database
        .commit_account_verified([9; 32], &[b"genesis"], 1, [4; 32], true)
        .unwrap();
    // A later not-stopped commit cannot revive the journal row.
    database
        .commit_account_verified([9; 32], &[], 1, [4; 32], false)
        .unwrap();
    assert!(database.account_state().unwrap().unwrap().stopped);
}

#[test]
fn a_first_commit_without_bytes_is_refused() {
    let (_dir, mut database) = database();
    assert!(matches!(
        database.commit_account_verified([9; 32], &[], 0, [4; 32], false),
        Err(StoreError::HeadWithoutBytes)
    ));
    assert!(database.account_state().unwrap().is_none());
}

fn staged() -> StagedAdmissionRow {
    StagedAdmissionRow {
        position: 4,
        previous: [7; 32],
        event: b"signed add".to_vec(),
        delivery: b"signed seal".to_vec(),
    }
}

#[test]
fn staged_insert_is_atomic_and_never_overwrites_a_previous_row() {
    let (dir, mut db) = database();
    let first = staged();
    db.insert_staged_admission(&first).unwrap();
    assert!(matches!(
        db.insert_staged_admission(&first),
        Err(StoreError::StagedAdmissionExists)
    ));
    assert_eq!(db.staged_admission().unwrap(), Some(first.clone()));
    let mut second = staged();
    second.event = b"different signed add".to_vec();
    assert!(matches!(
        db.insert_staged_admission(&second),
        Err(StoreError::StagedAdmissionExists)
    ));
    let reopened = DeviceDatabase::open(dir.path().join("account.sqlite")).unwrap();
    assert_eq!(reopened.staged_admission().unwrap(), Some(first));
}

#[test]
fn stale_completion_cannot_delete_a_replacement_staged_row() {
    let (_dir, mut db) = database();
    let first = staged();
    db.insert_staged_admission(&first).unwrap();
    db.clear_staged_admission(&first).unwrap();
    let mut second = staged();
    second.event = b"replacement signed add".to_vec();
    db.insert_staged_admission(&second).unwrap();
    assert!(matches!(
        db.clear_staged_admission(&first),
        Err(StoreError::StagedAdmissionChanged)
    ));
    assert_eq!(db.staged_admission().unwrap(), Some(second.clone()));
    db.clear_staged_admission(&second).unwrap();
    db.clear_staged_admission(&second).unwrap(); // missing is idempotent
    assert_eq!(db.staged_admission().unwrap(), None);
}

#[test]
fn malformed_staged_row_is_refused_instead_of_truncated() {
    let (dir, mut db) = database();
    assert!(matches!(
        db.insert_staged_admission(&StagedAdmissionRow {
            position: u64::MAX,
            ..staged()
        }),
        Err(StoreError::CorruptStagedAdmission)
    ));
    let other = Connection::open(dir.path().join("account.sqlite")).unwrap();
    other.execute("INSERT INTO account_staged_admission(id,position,previous,event,delivery) VALUES (1,4,?1,?2,?3)", rusqlite::params![[7u8; 32].as_slice(), b"add", b"seal"]).unwrap();
    other.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE account_staged_admission SET previous=x'01'; PRAGMA ignore_check_constraints=OFF;").unwrap();
    assert!(matches!(
        db.staged_admission(),
        Err(StoreError::CorruptStagedAdmission)
    ));
}

#[test]
fn staged_load_refuses_invalid_positions_and_empty_payloads_independently() {
    for (position, event, delivery) in [
        (0i64, b"add".as_slice(), b"seal".as_slice()),
        (1, b"add", b"seal"),
        (4, b"", b"seal"),
        (4, b"add", b""),
    ] {
        let (dir, db) = database();
        let other = Connection::open(dir.path().join("account.sqlite")).unwrap();
        other
            .execute_batch("PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        other.execute(
            "INSERT INTO account_staged_admission(id,position,previous,event,delivery) VALUES (1,?1,?2,?3,?4)",
            rusqlite::params![position, [7u8; 32].as_slice(), event, delivery],
        ).unwrap();
        other
            .execute_batch("PRAGMA ignore_check_constraints=OFF;")
            .unwrap();
        assert!(
            matches!(
                db.staged_admission(),
                Err(StoreError::CorruptStagedAdmission)
            ),
            "invalid row position={position}, event length={}, delivery length={}",
            event.len(),
            delivery.len()
        );
    }
}
