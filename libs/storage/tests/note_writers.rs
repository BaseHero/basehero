use bh_storage::{
    DeviceDatabase, NoteKey, PackagePreparation,
    note_writers::{BaseWriterPhase, WriterSlot},
    own_base::OwnBaseRecord,
};
fn key() -> NoteKey {
    NoteKey {
        base: [2; 32],
        audience: [0; 32],
        note: [3; 32],
    }
}
fn slot() -> WriterSlot {
    WriterSlot {
        key: key(),
        account: [1; 32],
        device: [4; 32],
        slot: 0,
        nonce: [5; 32],
        client_id: 42,
        retired: false,
    }
}
fn setup(db: &mut DeviceDatabase) {
    db.commit_account_verified([1; 32], &[b"original"], 1, [6; 32], false)
        .unwrap();
    db.create_own_base_if_absent(
        &OwnBaseRecord {
            account: [1; 32],
            base: [2; 32],
            genesis_descriptor: vec![1],
            genesis_body: vec![2],
            initial_key_package: vec![3],
        },
        || true,
    )
    .unwrap();
}
#[test]
fn own_base_phase_is_atomic_and_missing_legacy_phase_never_becomes_unregistered() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.base_writer_phase([2; 32]).unwrap(), None);
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute_batch("CREATE TRIGGER fail_phase BEFORE INSERT ON base_writer_phase BEGIN SELECT RAISE(ABORT,'phase'); END;").unwrap();
    db.commit_account_verified([1; 32], &[b"original"], 1, [6; 32], false)
        .unwrap();
    let record = OwnBaseRecord {
        account: [1; 32],
        base: [2; 32],
        genesis_descriptor: vec![1],
        genesis_body: vec![2],
        initial_key_package: vec![3],
    };
    assert!(db.create_own_base_if_absent(&record, || true).is_err());
    assert!(db.own_base().unwrap().is_none());
    raw.execute_batch("DROP TRIGGER fail_phase;").unwrap();
    db.create_own_base_if_absent(&record, || true).unwrap();
    assert_eq!(
        db.base_writer_phase([2; 32]).unwrap(),
        Some(BaseWriterPhase::Unregistered)
    );
    drop(db);
    let mut db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(
        db.base_writer_phase([2; 32]).unwrap(),
        Some(BaseWriterPhase::Unregistered)
    );
    raw.execute("DELETE FROM base_writer_phase", []).unwrap();
    db.create_own_base_if_absent(&record, || true).unwrap();
    assert_eq!(db.base_writer_phase([2; 32]).unwrap(), None);
    assert_eq!(db.own_base().unwrap(), Some(record));
}
#[test]
fn v9_upgrade_preserves_own_base_and_proofless_work_without_granting_phase() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    setup(&mut db);
    let original = db.own_base().unwrap();
    db.commit_working_update(key(), 0, [1; 32], [1; 16], &[0, 0])
        .unwrap();
    drop(db);
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute_batch("DROP TABLE note_outbox_members; DROP TABLE joined_device; DROP TABLE base_control_outbox; DROP TABLE registration; DROP TABLE sync_alarm; DROP TABLE note_outbox_progress; DROP TABLE writer_binding; DROP TABLE accepted_note_tail; DROP TABLE accepted_note; DROP TABLE log_floor; DROP TABLE log_account_change; DROP TABLE log_event_id; DROP TABLE log_seen; DROP TABLE log_progress; DROP TABLE note_update_writer; DROP TABLE note_writer_slots; DROP TABLE base_writer_phase; PRAGMA user_version=9;").unwrap();
    let db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.data_version(), bh_core::LOCAL_DATA_VERSION);
    assert_eq!(db.own_base().unwrap(), original);
    assert_eq!(db.base_writer_phase([2; 32]).unwrap(), None);
    let pending = db.pending_note_updates().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].writer, None);
    assert_eq!(pending[0].bytes, [0, 0]);
}
#[test]
fn deferred_commit_failure_leaves_no_delta_catalogue_or_proof() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    setup(&mut db);
    db.insert_writer_slot(&slot()).unwrap();
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute_batch("CREATE TABLE parent(id INTEGER PRIMARY KEY);
      CREATE TABLE fail_commit(id INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);
      CREATE TRIGGER fail_at_commit AFTER INSERT ON note_update_writer BEGIN INSERT INTO fail_commit VALUES(1); END;").unwrap();
    assert!(
        db.commit_writer_update(0, [1; 32], [8; 16], &[0, 0], &slot())
            .is_err()
    );
    for table in [
        "note_updates",
        "note_update_writer",
        "pending_note_work",
        "pending_scope",
        "notes",
    ] {
        assert_eq!(
            raw.query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r
                .get::<_, u32>(0))
                .unwrap(),
            0
        );
    }
    assert_eq!(db.local_frontier(key()).unwrap(), 0);
    assert!(
        db.committed_request(key(), [8; 16], &[0, 0])
            .unwrap()
            .is_none()
    );
}
#[test]
fn slot_and_pending_proof_survive_restart_and_failed_commit_leaves_no_link() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    setup(&mut db);
    db.insert_writer_slot(&slot()).unwrap();
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute_batch("CREATE TRIGGER fail_link BEFORE INSERT ON note_update_writer BEGIN SELECT RAISE(ABORT,'link'); END;").unwrap();
    assert!(
        db.commit_writer_update(0, [1; 32], [8; 16], &[0, 0], &slot())
            .is_err()
    );
    assert!(db.pending_note_updates().unwrap().is_empty());
    assert_eq!(db.local_frontier(key()).unwrap(), 0);
    raw.execute_batch("DROP TRIGGER fail_link;").unwrap();
    let commit = db
        .commit_writer_update(0, [1; 32], [8; 16], &[0, 0], &slot())
        .unwrap();
    assert!(
        db.commit_writer_update(0, [1; 32], [8; 16], &[0, 0], &slot())
            .unwrap()
            .replayed
    );
    drop(db);
    let db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(
        db.writer_slots(key(), [1; 32], [4; 32]).unwrap(),
        vec![slot()]
    );
    let PackagePreparation::Candidate(c) = db.prepare_note_package(commit.update_id).unwrap()
    else {
        panic!()
    };
    assert_eq!(c.pending.writer, Some(slot()));
    assert!(
        raw.execute("UPDATE note_writer_slots SET nonce=?1", [[9u8; 32]])
            .is_err()
    );
    assert!(
        raw.execute("UPDATE note_writer_slots SET client_id=43", [])
            .is_err()
    );
}
#[test]
fn titled_writer_commit_shares_one_commit_and_retry_never_retitles() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    setup(&mut db);
    let note = db.create_note([2; 32], [0; 32]).unwrap();
    let slot = WriterSlot {
        key: NoteKey { note, ..key() },
        ..slot()
    };
    db.insert_writer_slot(&slot).unwrap();
    let listed = |db: &DeviceDatabase| db.list_notes([2; 32], [0; 32], None, 50).unwrap();
    let before = listed(&db);
    let raw = rusqlite::Connection::open(&path).unwrap();
    raw.execute_batch("CREATE TRIGGER fail_title BEFORE UPDATE OF title ON notes BEGIN SELECT RAISE(ABORT,'title'); END;").unwrap();
    assert!(
        db.commit_writer_update_with_title(0, [1; 32], [8; 16], &[0, 0], &slot, "first")
            .is_err()
    );
    assert_eq!(listed(&db), before);
    assert!(db.pending_note_updates().unwrap().is_empty());
    raw.execute_batch("DROP TRIGGER fail_title;").unwrap();
    assert!(matches!(
        db.commit_writer_update_with_title(0, [1; 32], [8; 16], &[0, 0], &slot, &"x".repeat(81)),
        Err(bh_storage::StoreError::InvalidNoteTitle)
    ));
    assert!(db.pending_note_updates().unwrap().is_empty());
    let commit = db
        .commit_writer_update_with_title(0, [1; 32], [8; 16], &[0, 0], &slot, "first")
        .unwrap();
    assert!(!commit.replayed);
    let titled = listed(&db);
    assert_eq!(titled[0].title, "first");
    assert!(titled[0].touched > before[0].touched);
    assert_eq!(db.pending_note_updates().unwrap()[0].writer, Some(slot));
    // An exact retry is the original request: no new touch or title.
    assert!(
        db.commit_writer_update_with_title(0, [1; 32], [8; 16], &[0, 0], &slot, "changed")
            .unwrap()
            .replayed
    );
    assert_eq!(listed(&db), titled);
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
}
