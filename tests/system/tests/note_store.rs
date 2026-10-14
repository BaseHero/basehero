use bh_storage::{DeviceDatabase, NoteKey, OpenError, StoreError};
use rusqlite::Connection;
use std::{path::Path, time::Duration};
use yrs::{Doc, Transact, WriteTxn, XmlElementPrelim, XmlFragment};

fn scoped_key(base: u8, audience: u8, note: u8) -> NoteKey {
    NoteKey {
        base: [base; 32],
        audience: [audience; 32],
        note: [note; 32],
    }
}
fn key(audience: u8, note: u8) -> NoteKey {
    scoped_key(1, audience, note)
}
fn update(text: &str) -> Vec<u8> {
    let d = Doc::new();
    let mut txn = d.transact_mut();
    let f = txn.get_or_insert_xml_fragment("default");
    let p = f.insert(&mut txn, 0, XmlElementPrelim::empty("paragraph"));
    p.insert(&mut txn, 0, yrs::XmlTextPrelim::new(text));
    txn.encode_update_v1()
}

#[test]
fn committed_work_reopens_and_retries_exactly_once() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("notes.db");
    let bytes = update("kept");
    let mut db = DeviceDatabase::open(&path).unwrap();
    let first = db.apply_local_update(key(2, 3), [9; 16], &bytes).unwrap();
    let state = db.note_state(key(2, 3)).unwrap();
    assert!(!first.replayed);
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    let retry = db.apply_local_update(key(2, 3), [9; 16], &bytes).unwrap();
    assert_eq!(retry.update_id, first.update_id);
    assert!(retry.replayed);
    assert_eq!(db.note_state(key(2, 3)).unwrap(), state);
    assert!(matches!(
        db.apply_local_update(key(2, 3), [9; 16], &update("other")),
        Err(StoreError::RequestConflict)
    ));
    drop(db);
    let mut reopened = DeviceDatabase::open(&path).unwrap();
    assert_eq!(reopened.note_state(key(2, 3)).unwrap(), state);
    let pending = reopened.pending_note_updates().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].bytes, bytes);
    assert_eq!(pending[0].update_id, first.update_id);
    assert_eq!(pending[0].key, key(2, 3));
}

#[test]
fn note_and_audience_never_share_state() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    let scopes = [
        scoped_key(1, 2, 3),
        scoped_key(4, 2, 3), // another base
        scoped_key(1, 5, 3), // another audience
        scoped_key(1, 2, 6), // another note
    ];
    for (index, scope) in scopes.into_iter().enumerate() {
        for other in scopes.iter().skip(index + 1) {
            assert_eq!(
                db.note_state(scope).unwrap(),
                db.note_state(*other).unwrap()
            );
        }
        db.apply_local_update(
            scope,
            [index as u8 + 1; 16],
            &update(&format!("scope {index}")),
        )
        .unwrap();
        for other in scopes.iter().skip(index + 1) {
            assert_ne!(
                db.note_state(scope).unwrap(),
                db.note_state(*other).unwrap()
            );
        }
    }
    let pending = db.pending_note_updates().unwrap();
    assert_eq!(pending.len(), scopes.len());
    for (row, scope) in pending.iter().zip(scopes) {
        assert_eq!(row.key, scope);
    }
}

#[test]
fn invalid_update_is_not_stored_and_later_valid_update_commits() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    let scope = key(2, 3);
    db.apply_local_update(scope, [1; 16], &update("before"))
        .unwrap();
    let state = db.note_state(scope).unwrap();
    assert!(matches!(
        db.apply_local_update(scope, [2; 16], &[1, 2, 3]),
        Err(StoreError::InvalidUpdate)
    ));
    assert_eq!(db.note_state(scope).unwrap(), state);
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    db.apply_local_update(scope, [2; 16], &update("after"))
        .unwrap();
    assert_ne!(db.note_state(scope).unwrap(), state);
    assert_eq!(db.pending_note_updates().unwrap().len(), 2);
}

#[test]
fn sql_write_failure_does_not_poison_cache_or_ack() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("notes.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    db.apply_local_update(key(2, 3), [1; 16], &update("first"))
        .unwrap();
    let before = db.note_state(key(2, 3)).unwrap();
    // The other connection installs a real SQLite refusal after the first commit.
    let other = Connection::open(&path).unwrap();
    other.execute_batch("CREATE TRIGGER fail_note BEFORE INSERT ON note_updates BEGIN SELECT RAISE(FAIL, 'no space'); END;").unwrap();
    assert!(matches!(
        db.apply_local_update(key(2, 3), [2; 16], &update("second")),
        Err(StoreError::Database(_))
    ));
    assert_eq!(db.note_state(key(2, 3)).unwrap(), before);
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    other.execute_batch("DROP TRIGGER fail_note").unwrap();
    let commit = db
        .apply_local_update(key(2, 3), [2; 16], &update("second"))
        .unwrap();
    assert!(!commit.replayed);
    assert_eq!(db.pending_note_updates().unwrap().len(), 2);
}

#[test]
fn commit_failure_discards_transient_state_and_retry_is_single() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("notes.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    let before = db.note_state(key(2, 3)).unwrap();
    // DEFERRED FK checks occur at COMMIT, not at either INSERT.
    let other = Connection::open(&path).unwrap();
    let ddl: String = other
        .query_row(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='pending_note_work'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        ddl.contains("DEFERRABLE INITIALLY DEFERRED"),
        "COMMIT-failure test requires deferred FK"
    );
    other.execute_batch("CREATE TRIGGER fail_commit AFTER INSERT ON pending_note_work BEGIN INSERT INTO pending_note_work(update_id) VALUES(-1); END;").unwrap();
    let failed = db.apply_local_update(key(2, 3), [1; 16], &update("not saved"));
    assert!(
        matches!(failed, Err(StoreError::Database(rusqlite::Error::SqliteFailure(e, _)))
        if e.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY),
        "deferred FK must fail at COMMIT"
    );
    assert_eq!(db.note_state(key(2, 3)).unwrap(), before);
    assert!(db.pending_note_updates().unwrap().is_empty());
    other.execute_batch("DROP TRIGGER fail_commit").unwrap();
    db.apply_local_update(key(2, 3), [1; 16], &update("not saved"))
        .unwrap();
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
}

#[test]
fn migration_failure_keeps_v1_while_newer_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("v1.db");
    let c = Connection::open(&path).unwrap();
    c.execute_batch("PRAGMA user_version=1; CREATE TABLE pending_note_work (wrong INTEGER);")
        .unwrap();
    drop(c);
    assert!(DeviceDatabase::open(&path).is_err());
    let c = Connection::open(&path).unwrap();
    let version: u32 = c
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 1);
    let created: i64 = c
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name='note_updates'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        created, 0,
        "earlier CREATE TABLE rolled back with failed migration"
    );
    c.execute_batch("DROP TABLE pending_note_work; PRAGMA user_version=999;")
        .unwrap();
    drop(c);
    assert!(matches!(
        DeviceDatabase::open(&path),
        Err(OpenError::NewerData { found: 999, .. })
    ));
}

#[test]
fn separate_process_kill_preserves_committed_work() {
    if let Ok(path) = std::env::var("BH_NOTE_KILL_CHILD") {
        let mut db = DeviceDatabase::open(Path::new(&path)).unwrap();
        db.apply_local_update(key(2, 3), [5; 16], &update("before kill"))
            .unwrap();
        std::fs::write(format!("{path}.ready"), b"ready").unwrap();
        std::thread::sleep(Duration::from_secs(20));
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("killed.db");
    let exe = std::env::current_exe().unwrap();
    let mut child = std::process::Command::new(exe)
        .args([
            "--exact",
            "separate_process_kill_preserves_committed_work",
            "--nocapture",
        ])
        .env("BH_NOTE_KILL_CHILD", &path)
        .spawn()
        .unwrap();
    let ready = format!("{}.ready", path.display());
    let start = std::time::Instant::now();
    while !Path::new(&ready).exists() && start.elapsed() < Duration::from_secs(5) {
        assert!(
            child.try_wait().unwrap().is_none(),
            "writer exited before commit"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(Path::new(&ready).exists(), "writer never committed");
    child.kill().unwrap();
    child.wait().unwrap();
    let mut reopened = DeviceDatabase::open(&path).unwrap();
    assert_ne!(
        reopened.note_state(key(2, 3)).unwrap(),
        reopened.note_state(key(2, 4)).unwrap()
    );
    assert!(
        reopened.pending_note_updates().unwrap()[0]
            .bytes
            .windows(b"before kill".len())
            .any(|s| s == b"before kill")
    );
}
