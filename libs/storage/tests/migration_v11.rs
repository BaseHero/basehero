//! The v10→v11 step adds incoming-sync state only: every v10 row, including
//! pending local work, checkpoints, writer reservations and the account
//! journal, survives exactly, and a failed step leaves v10 as it was.
use bh_core::LOCAL_DATA_VERSION;
use bh_storage::{DeviceDatabase, NoteKey, note_writers::WriterSlot};
use rusqlite::{Connection, types::Value};

const V11_TABLES: [&str; 14] = [
    "held_note_event",
    "log_progress",
    "log_seen",
    "log_event_id",
    "log_account_change",
    "log_floor",
    "accepted_note",
    "accepted_note_tail",
    "writer_binding",
    "note_outbox_progress",
    "sync_alarm",
    "registration",
    "base_control_outbox",
    "joined_device",
];
const V10_TABLES: [&str; 9] = [
    "note_updates",
    "pending_note_work",
    "pending_scope",
    "note_checkpoints",
    "note_writer_slots",
    "note_update_writer",
    "base_writer_phase",
    "account_state",
    "notes",
];

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
fn dump(connection: &Connection, table: &str) -> Vec<Vec<Value>> {
    let mut stmt = connection
        .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
        .unwrap();
    let columns = stmt.column_count();
    stmt.query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

/// A v10 container with pending work, a checkpoint, a writer reservation
/// and an anchored account row, built by the shipped steps up to v10.
fn write_v10(path: &std::path::Path) -> NoteKey {
    let key = NoteKey {
        base: [1; 32],
        audience: [0; 32],
        note: [3; 32],
    };
    {
        let mut db = DeviceDatabase::open(path).unwrap();
        let mut author = bh_core::note::Note::new().unwrap();
        db.apply_local_update(key, [1; 16], &author.append_paragraph("first").unwrap())
            .unwrap();
        db.apply_local_update(key, [2; 16], &author.append_paragraph("second").unwrap())
            .unwrap();
        db.insert_writer_slot(&WriterSlot {
            key,
            account: [4; 32],
            device: [5; 32],
            slot: 0,
            nonce: [6; 32],
            client_id: 77,
            retired: false,
        })
        .unwrap();
    }
    let raw = Connection::open(path).unwrap();
    raw.execute_batch(
        "INSERT INTO account_state(id,anchor,head_position,head_hash,stopped)
           VALUES (1,zeroblob(32),3,zeroblob(32),0);
         INSERT INTO base_writer_phase(base,phase) VALUES (zeroblob(32),0);",
    )
    .unwrap();
    raw.execute(
        "INSERT INTO note_checkpoints(base,audience,note,generation,local_frontier,encoded_yjs)
           VALUES (?1,?2,?3,1,1,?4)",
        rusqlite::params![
            key.base.as_slice(),
            key.audience.as_slice(),
            key.note.as_slice(),
            b"BHOS1\0\0\0\0".as_slice()
        ],
    )
    .unwrap();
    // Remove later additions before reconstructing the shipped v10 layout.
    raw.execute_batch("DROP TABLE note_outbox_members").unwrap();
    // Remove exactly what the v11 step adds; the rest is the shipped v10.
    for table in V11_TABLES {
        raw.execute_batch(&format!("DROP TABLE {table};")).unwrap();
    }
    raw.pragma_update(None, "user_version", 10u32).unwrap();
    key
}

#[test]
fn migration_v10_to_v11_preserves_pending_and_checkpoints() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v10.sqlite");
    let key = write_v10(&path);
    let raw = Connection::open(&path).unwrap();
    assert_eq!(version(&raw), 10);
    let before: Vec<_> = V10_TABLES.iter().map(|t| dump(&raw, t)).collect();

    let db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.data_version(), LOCAL_DATA_VERSION);
    assert_eq!(version(&raw), LOCAL_DATA_VERSION);
    let after: Vec<_> = V10_TABLES.iter().map(|t| dump(&raw, t)).collect();
    assert_eq!(before, after, "every v10 row survives byte for byte");
    for table in V11_TABLES {
        assert!(table_exists(&raw, table), "{table}");
        assert!(dump(&raw, table).is_empty(), "{table} starts empty");
    }
    let pending = db.pending_note_updates().unwrap();
    assert_eq!(pending.len(), 2);
    assert!(pending.iter().all(|p| p.key == key));
    assert_eq!(db.writer_reservations(key).unwrap().len(), 1);
    // A v10 base without a registration row is not registered by migration.
    assert_eq!(db.registration([1; 32]).unwrap(), None);
}

#[test]
fn earlier_v11_layout_gains_holds_without_losing_existing_outcomes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("earlier.sqlite");
    let key = write_v10(&path);
    drop(DeviceDatabase::open(&path).unwrap());
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch("DROP TABLE held_note_event;
        DROP TABLE note_outbox_progress;
        CREATE TABLE note_outbox_progress (
            update_id INTEGER PRIMARY KEY REFERENCES note_outbox(update_id),
            staged INTEGER NOT NULL DEFAULT 0 CHECK(staged IN (0,1)),
            acked_position INTEGER CHECK(acked_position IS NULL OR acked_position>0),
            outcome INTEGER CHECK(outcome IS NULL OR outcome BETWEEN 1 AND 5),
            refusal INTEGER CHECK(refusal IS NULL OR (outcome=3 AND refusal BETWEEN 1 AND 255)),
            CHECK(outcome!=3 OR refusal IS NOT NULL));
        INSERT INTO note_outbox(update_id,event_id,descriptor,body) VALUES (1,zeroblob(32),x'00',x'00');
        INSERT INTO note_outbox_progress(update_id,staged,acked_position,outcome) VALUES (1,1,2,1);").unwrap();
    let before = dump(&raw, "note_outbox_progress");
    let db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(version(&raw), LOCAL_DATA_VERSION);
    assert_eq!(dump(&raw, "note_outbox_progress"), before);
    assert_eq!(db.pending_count(key).unwrap(), 2);
    assert!(!db.has_held_notes().unwrap());
    raw.execute(
        "UPDATE note_outbox_progress SET outcome=6 WHERE update_id=1",
        [],
    )
    .unwrap();
    assert_eq!(
        db.package_progress(1).unwrap().unwrap().outcome,
        Some(bh_storage::sync_state::PackageOutcome::Held)
    );
}

#[test]
fn failed_v11_migration_keeps_v10_layout_and_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v10.sqlite");
    write_v10(&path);
    let raw = Connection::open(&path).unwrap();
    raw.execute_batch("CREATE TABLE registration (bogus INTEGER);")
        .unwrap();
    let before: Vec<_> = V10_TABLES.iter().map(|t| dump(&raw, t)).collect();
    assert!(DeviceDatabase::open(&path).is_err());
    assert_eq!(version(&raw), 10);
    assert!(!table_exists(&raw, "log_progress"));
    let after: Vec<_> = V10_TABLES.iter().map(|t| dump(&raw, t)).collect();
    assert_eq!(before, after);
}
