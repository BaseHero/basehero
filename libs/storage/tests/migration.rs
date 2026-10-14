//! Ordered device-local migrations: fresh, from the note-only v2 layout, a
//! rolled-back failed step, and newer-version refusal. Storage-only; no
//! verification lives here.
use bh_core::LOCAL_DATA_VERSION;
use bh_storage::{DeviceDatabase, OpenError};
use rusqlite::{Connection, TransactionBehavior, params};

fn version(connection: &Connection) -> u32 {
    connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap()
}

fn table_exists(connection: &Connection, name: &str) -> bool {
    connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            [name],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
        > 0
}

/// Write the pre-account v2 layout and marker, as shipped before this change.
fn write_v2(path: &std::path::Path) {
    let mut connection = Connection::open(path).unwrap();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    transaction
        .execute_batch(
            "CREATE TABLE note_updates (
                id INTEGER PRIMARY KEY,
                base BLOB NOT NULL CHECK(length(base)=32),
                audience BLOB NOT NULL CHECK(length(audience)=32),
                note BLOB NOT NULL CHECK(length(note)=32),
                request BLOB NOT NULL CHECK(length(request)=16),
                delta BLOB NOT NULL,
                UNIQUE(base,audience,note,request)
            );
            CREATE INDEX note_updates_scope ON note_updates(base,audience,note,id);
            CREATE TABLE pending_note_work (
                update_id INTEGER PRIMARY KEY REFERENCES note_updates(id) DEFERRABLE INITIALLY DEFERRED
            );",
        )
        .unwrap();
    transaction
        .pragma_update(None, "user_version", 2u32)
        .unwrap();
    transaction.commit().unwrap();
}

#[test]
fn fresh_open_applies_every_migration_step() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fresh.sqlite");
    let database = DeviceDatabase::open(&path).unwrap();
    assert_eq!(database.data_version(), LOCAL_DATA_VERSION);
    let connection = Connection::open(&path).unwrap();
    assert_eq!(version(&connection), LOCAL_DATA_VERSION);
    for table in [
        "note_updates",
        "pending_note_work",
        "account_state",
        "account_events",
        "account_device",
        "account_pending_setup",
        "note_outbox",
    ] {
        assert!(table_exists(&connection, table), "missing {table}");
    }
}

#[test]
fn opens_v2_with_existing_notes_and_adds_account_tables() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v2.sqlite");
    write_v2(&path);
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .execute(
                "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
                params![
                    [1u8; 32].as_slice(),
                    [2u8; 32].as_slice(),
                    [3u8; 32].as_slice(),
                    [4u8; 16].as_slice(),
                    b"delta".as_slice()
                ],
            )
            .unwrap();
        connection
            .execute("INSERT INTO pending_note_work(update_id) VALUES (1)", [])
            .unwrap();
    }

    let database = DeviceDatabase::open(&path).unwrap();
    let pending = database.pending_note_updates().unwrap();
    assert_eq!(pending.len(), 1, "existing note work preserved");
    assert_eq!(pending[0].bytes, b"delta");

    let connection = Connection::open(&path).unwrap();
    assert_eq!(version(&connection), LOCAL_DATA_VERSION);
    assert!(table_exists(&connection, "account_state"));
    assert!(table_exists(&connection, "account_events"));
}

#[test]
fn v3_to_v4_preserves_pending_notes_and_account_journal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v3.sqlite");
    {
        let mut db = DeviceDatabase::open(&path).unwrap();
        let mut note = bh_core::note::Note::new();
        let delta = note.append_paragraph("existing");
        let key = bh_storage::NoteKey {
            base: [1; 32],
            audience: [2; 32],
            note: [3; 32],
        };
        db.apply_local_update(key, [4; 16], &delta).unwrap();
        db.commit_account_verified([9; 32], &[b"genesis"], 1, [5; 32], false)
            .unwrap();
    }
    // Recreate the previously shipped v3 layout exactly: the only v4 schema
    // addition is note_outbox. Keep the actual note and account rows untouched.
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("DROP TABLE note_outbox; PRAGMA user_version=3")
        .unwrap();
    drop(conn);
    let db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    assert_eq!(db.account_history().unwrap(), vec![b"genesis".to_vec()]);
    assert_eq!(db.account_state().unwrap().unwrap().head_position, 1);
    assert_eq!(version(&Connection::open(&path).unwrap()), 4);
}

#[test]
fn failed_v4_migration_rolls_back_marker_and_keeps_v3_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v3-failed.sqlite");
    drop(DeviceDatabase::open(&path).unwrap());
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "DROP TABLE note_outbox; PRAGMA user_version=3; CREATE TABLE note_outbox (bogus INTEGER)",
    )
    .unwrap();
    drop(conn);
    assert!(DeviceDatabase::open(&path).is_err());
    let conn = Connection::open(&path).unwrap();
    assert_eq!(version(&conn), 3);
    assert!(table_exists(&conn, "account_state"));
    assert!(table_exists(&conn, "note_updates"));
}

#[test]
fn failed_account_migration_leaves_v2_layout_and_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("conflict.sqlite");
    write_v2(&path);
    // Conflict on the *last* table so the step has already created the others
    // inside the transaction when it fails.
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE account_pending_setup (bogus INTEGER);")
        .unwrap();

    assert!(DeviceDatabase::open(&path).is_err());
    let connection = Connection::open(&path).unwrap();
    assert_eq!(version(&connection), 2, "marker rolled back");
    assert!(table_exists(&connection, "note_updates"));
    assert!(
        !table_exists(&connection, "account_state"),
        "earlier CREATE TABLE rolled back with the failed step"
    );
    assert!(!table_exists(&connection, "account_events"));
    assert!(!table_exists(&connection, "account_device"));
    assert!(table_exists(&connection, "account_pending_setup"));
}

#[test]
fn newer_version_is_refused_before_any_change() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("newer.sqlite");
    {
        let connection = Connection::open(&path).unwrap();
        connection
            .pragma_update(None, "user_version", (LOCAL_DATA_VERSION + 1) as i64)
            .unwrap();
    }
    assert!(matches!(
        DeviceDatabase::open(&path),
        Err(OpenError::NewerData { found, .. }) if found == LOCAL_DATA_VERSION + 1
    ));
    let connection = Connection::open(&path).unwrap();
    assert_eq!(version(&connection), LOCAL_DATA_VERSION + 1);
}
