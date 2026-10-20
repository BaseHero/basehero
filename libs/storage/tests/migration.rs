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

/// Build the shipped v4/v5 tables directly, never by downgrading v6 markers.
fn write_v4(path: &std::path::Path) {
    write_v2(path);
    Connection::open(path).unwrap().execute_batch(
        "CREATE TABLE account_state (
            id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),anchor BLOB NOT NULL CHECK(length(anchor)=32),
            head_position INTEGER NOT NULL CHECK(head_position>=0),head_hash BLOB NOT NULL CHECK(length(head_hash)=32),
            stopped INTEGER NOT NULL CHECK(stopped IN (0,1))
        );
        CREATE TABLE account_events (id INTEGER PRIMARY KEY NOT NULL,bytes BLOB NOT NULL);
        CREATE TABLE account_device (id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),handle BLOB NOT NULL CHECK(length(handle)=32),
            signing BLOB NOT NULL CHECK(length(signing)=32),control BLOB NOT NULL CHECK(length(control)=32),
            receiving BLOB NOT NULL CHECK(length(receiving)=1216),policy INTEGER NOT NULL CHECK(policy BETWEEN 0 AND 255),
            kind INTEGER NOT NULL CHECK(kind BETWEEN 0 AND 255));
        CREATE TABLE account_pending_setup (id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),version INTEGER NOT NULL CHECK(version BETWEEN 0 AND 65535),
            stage INTEGER NOT NULL CHECK(stage BETWEEN 0 AND 255),kit_saved INTEGER NOT NULL CHECK(kit_saved IN (0,1)),blob BLOB NOT NULL);
        CREATE TABLE note_outbox (update_id INTEGER PRIMARY KEY REFERENCES note_updates(id),event_id BLOB NOT NULL UNIQUE CHECK(length(event_id)=32),descriptor BLOB NOT NULL,body BLOB NOT NULL,ack BLOB);
        PRAGMA user_version=4;"
    ).unwrap();
}
fn write_v5(path: &std::path::Path) {
    write_v4(path);
    Connection::open(path).unwrap().execute_batch(
        "CREATE TABLE account_staged_admission (id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),position INTEGER NOT NULL CHECK(position>1),previous BLOB NOT NULL CHECK(length(previous)=32),event BLOB NOT NULL CHECK(length(event)>0),delivery BLOB NOT NULL CHECK(length(delivery)>0));
        PRAGMA user_version=5;"
    ).unwrap();
}
/// A shipped v6 file, including its extra audience index. Keep this fixture
/// independent of the current open path so v7 tests exercise a real upgrade.
fn write_v6(path: &std::path::Path) {
    write_v5(path);
    Connection::open(path).unwrap().execute_batch(
        "CREATE TABLE note_checkpoints (
            base BLOB NOT NULL CHECK(length(base)=32), audience BLOB NOT NULL CHECK(length(audience)=32),
            note BLOB NOT NULL CHECK(length(note)=32), generation INTEGER NOT NULL CHECK(generation>0),
            local_frontier INTEGER NOT NULL CHECK(local_frontier>=0),
            materialization_frontier INTEGER NOT NULL DEFAULT 0 CHECK(materialization_frontier>=0),
            encoded_yjs BLOB NOT NULL, PRIMARY KEY(base,audience,note));
         CREATE INDEX note_updates_audience_id ON note_updates(base,audience,id);
         CREATE TABLE pending_scope (update_id INTEGER PRIMARY KEY REFERENCES note_updates(id),
            base BLOB NOT NULL CHECK(length(base)=32), audience BLOB NOT NULL CHECK(length(audience)=32),
            note BLOB NOT NULL CHECK(length(note)=32));
         CREATE INDEX pending_scope_audience ON pending_scope(base,audience,update_id);
         CREATE INDEX pending_scope_note ON pending_scope(base,audience,note,update_id);
         CREATE TABLE pending_scope_backfill (id INTEGER PRIMARY KEY NOT NULL CHECK(id=1),
            last_id INTEGER NOT NULL DEFAULT 0 CHECK(last_id>=0),
            complete INTEGER NOT NULL DEFAULT 0 CHECK(complete IN (0,1)));
         INSERT INTO pending_scope_backfill(id) VALUES (1);
         PRAGMA user_version=6;"
    ).unwrap();
}

#[test]
fn v7_to_current_retains_pending_work_and_rejects_newer_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v7.sqlite");
    write_v6(&path);
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("DROP INDEX note_updates_audience_id; PRAGMA user_version=7;")
        .unwrap();
    conn.execute(
        "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
        params![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 16], b"unsent"],
    )
    .unwrap();
    conn.execute("INSERT INTO pending_note_work(update_id) VALUES (1)", [])
        .unwrap();
    conn.execute(
        "INSERT INTO pending_scope(update_id,base,audience,note) VALUES (1,?1,?2,?3)",
        params![[1u8; 32], [2u8; 32], [3u8; 32]],
    )
    .unwrap();
    drop(conn);
    let mut db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.data_version(), LOCAL_DATA_VERSION);
    assert_eq!(db.pending_note_updates().unwrap()[0].bytes, b"unsent");
    assert!(
        !db.pending_page([1; 32], [2; 32], Some([3; 32]), 0, 10, 4096)
            .unwrap()
            .rows
            .is_empty()
    );
    let note = db.create_note([1; 32], [2; 32]).unwrap();
    assert_eq!(
        db.list_notes([1; 32], [2; 32], None, 50).unwrap()[0].note,
        note
    );
    drop(db);
    let conn = Connection::open(&path).unwrap();
    conn.pragma_update(None, "user_version", LOCAL_DATA_VERSION + 1)
        .unwrap();
    drop(conn);
    assert!(matches!(
        DeviceDatabase::open(&path),
        Err(OpenError::NewerData {found,supported}) if found==LOCAL_DATA_VERSION+1 && supported==LOCAL_DATA_VERSION
    ));
    let conn = Connection::open(&path).unwrap();
    assert_eq!(version(&conn), LOCAL_DATA_VERSION + 1);
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM pending_note_work", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn failed_v8_to_v9_rolls_back_projection_and_preserves_pending_work() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v8.sqlite");
    drop(DeviceDatabase::open(&path).unwrap());
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
        params![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 16], b"unsent"],
    )
    .unwrap();
    conn.execute("INSERT INTO pending_note_work(update_id) VALUES (1)", [])
        .unwrap();
    conn.execute_batch("DROP TABLE note_outbox_members; DROP TABLE joined_device; DROP TABLE base_control_outbox; DROP TABLE registration; DROP TABLE sync_alarm; DROP TABLE note_outbox_progress; DROP TABLE writer_binding; DROP TABLE accepted_note_tail; DROP TABLE accepted_note; DROP TABLE log_floor; DROP TABLE log_account_change; DROP TABLE log_event_id; DROP TABLE log_seen; DROP TABLE log_progress; DROP TABLE note_update_writer; DROP TABLE note_writer_slots; DROP TABLE base_writer_phase; DROP TABLE account_devices; DROP TABLE account_key_use; DROP TABLE account_projection; DROP TABLE account_initial_bootstrap; DROP TABLE own_base; PRAGMA user_version=8; CREATE TABLE own_base(bogus INTEGER);").unwrap();
    drop(conn);
    assert!(DeviceDatabase::open(&path).is_err());
    let conn = Connection::open(&path).unwrap();
    assert_eq!(version(&conn), 8);
    assert!(!table_exists(&conn, "account_projection"));
    assert!(!table_exists(&conn, "account_initial_bootstrap"));
    assert_eq!(
        conn.query_row("SELECT delta FROM note_updates WHERE id=1", [], |r| r
            .get::<_, Vec<u8>>(0))
            .unwrap(),
        b"unsent"
    );
    conn.execute_batch("DROP TABLE own_base;").unwrap();
    drop(conn);
    let db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.data_version(), LOCAL_DATA_VERSION);
    assert_eq!(db.pending_note_updates().unwrap()[0].bytes, b"unsent");
}

#[test]
fn v6_to_v7_removes_only_unused_index_and_preserves_rows_and_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v6.sqlite");
    write_v6(&path);
    let conn = Connection::open(&path).unwrap();
    let delta = bh_core::note::Note::new()
        .unwrap()
        .append_paragraph("retained")
        .unwrap();
    conn.execute(
        "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
        params![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 16], delta.as_slice()],
    )
    .unwrap();
    conn.execute("INSERT INTO pending_note_work(update_id) VALUES (1)", [])
        .unwrap();
    conn.execute(
        "INSERT INTO note_outbox(update_id,event_id,descriptor,body) VALUES (1,?1,?2,?3)",
        params![[5u8; 32], b"descriptor", b"body"],
    )
    .unwrap();
    conn.execute("INSERT INTO note_checkpoints(base,audience,note,generation,local_frontier,encoded_yjs) VALUES (?1,?2,?3,1,1,?4)",
        params![[1u8;32], [2u8;32], [3u8;32], delta.as_slice()]).unwrap();
    drop(conn);
    let db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.pending_note_updates().unwrap()[0].bytes, delta);
    drop(db);
    let conn = Connection::open(&path).unwrap();
    assert_eq!(version(&conn), LOCAL_DATA_VERSION);
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='note_updates_audience_id'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        conn.query_row("SELECT body FROM note_outbox WHERE update_id=1", [], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .unwrap(),
        b"body"
    );
    assert_eq!(
        conn.query_row(
            "SELECT encoded_yjs FROM note_checkpoints WHERE base=?1",
            [[1u8; 32].as_slice()],
            |r| r.get::<_, Vec<u8>>(0)
        )
        .unwrap(),
        delta
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM pending_note_work", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
}

#[test]
fn failed_v7_drop_rolls_back_version_and_keeps_v6_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v6-missing-index.sqlite");
    write_v6(&path);
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
        params![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 16], b"untouched"],
    )
    .unwrap();
    conn.execute_batch("DROP INDEX note_updates_audience_id")
        .unwrap();
    drop(conn);
    assert!(DeviceDatabase::open(&path).is_err());
    let conn = Connection::open(&path).unwrap();
    assert_eq!(version(&conn), 6);
    assert_eq!(
        conn.query_row("SELECT delta FROM note_updates WHERE id=1", [], |r| r
            .get::<_, Vec<u8>>(0))
            .unwrap(),
        b"untouched"
    );
    assert!(table_exists(&conn, "pending_scope"));
}

#[test]
fn v5_backfill_pages_empty_scopes_then_dual_maintains_new_pending_writes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v5-backfill.db");
    write_v5(&path);
    let mut conn = Connection::open(&path).unwrap();
    let tx = conn.transaction().unwrap();
    for n in 0..310u16 {
        let request = n.to_be_bytes();
        let base = if n < 300 { [2u8; 32] } else { [1u8; 32] };
        tx.execute(
            "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
            params![
                base.as_slice(),
                [2u8; 32].as_slice(),
                [3u8; 32].as_slice(),
                [request.as_slice(), &[0; 14]].concat(),
                b"old"
            ],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO pending_note_work(update_id) VALUES (?1)",
            [n as i64 + 1],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    drop(conn);
    let mut db = DeviceDatabase::open(&path).unwrap();
    let first = db
        .pending_page([1; 32], [2; 32], None, 0, 10, 4096)
        .unwrap();
    assert!(first.rows.is_empty());
    assert!(
        first.next.is_some(),
        "legacy empty scoped scan must advance"
    );
    let mut after = first.next.unwrap();
    loop {
        let page = db
            .pending_page([1; 32], [2; 32], None, after, 10, 4096)
            .unwrap();
        if page.rows.len() == 10 {
            break;
        }
        after = page
            .next
            .expect("advance even across empty scoped legacy pages");
    }
    let mut steps = 0;
    while !db.backfill_pending_scope(256).unwrap() {
        steps += 1;
        assert!(steps < 10);
    }
    assert!(steps > 0);
    let indexed = db
        .pending_page([1; 32], [2; 32], None, 0, 10, 4096)
        .unwrap();
    assert_eq!(indexed.rows.len(), 10);
    let mut note = bh_core::note::Note::new().unwrap();
    let delta = note.append_paragraph("new").unwrap();
    let newest = db
        .apply_local_update(
            bh_storage::NoteKey {
                base: [1; 32],
                audience: [2; 32],
                note: [7; 32],
            },
            [99; 16],
            &delta,
        )
        .unwrap()
        .update_id;
    let conn = Connection::open(&path).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT base FROM pending_scope WHERE update_id=?1",
            [newest],
            |r| r.get::<_, Vec<u8>>(0)
        )
        .unwrap(),
        vec![1; 32]
    );
}

#[test]
fn v5_to_v6_keeps_exact_old_rows_and_failed_migration_rolls_back() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v5.sqlite");
    write_v5(&path);
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
        params![
            [1u8; 32].as_slice(),
            [2u8; 32].as_slice(),
            [3u8; 32].as_slice(),
            [4u8; 16].as_slice(),
            b"legacy"
        ],
    )
    .unwrap();
    conn.execute("INSERT INTO pending_note_work(update_id) VALUES (1)", [])
        .unwrap();
    conn.execute(
        "INSERT INTO note_outbox(update_id,event_id,descriptor,body) VALUES (1,?1,?2,?3)",
        params![[5u8; 32].as_slice(), b"descriptor", b"body"],
    )
    .unwrap();
    drop(conn);
    let db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.pending_note_updates().unwrap()[0].bytes, b"legacy");
    drop(db);
    let conn = Connection::open(&path).unwrap();
    assert_eq!(version(&conn), LOCAL_DATA_VERSION);
    assert!(table_exists(&conn, "note_checkpoints"));
    assert_eq!(
        conn.query_row("SELECT body FROM note_outbox WHERE update_id=1", [], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .unwrap(),
        b"body"
    );
    drop(conn);
    let failed = dir.path().join("failed-v5.sqlite");
    write_v5(&failed);
    let conn = Connection::open(&failed).unwrap();
    conn.execute_batch("CREATE TABLE note_checkpoints(bogus INTEGER)")
        .unwrap();
    drop(conn);
    assert!(DeviceDatabase::open(&failed).is_err());
    let conn = Connection::open(&failed).unwrap();
    assert_eq!(version(&conn), 5);
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='note_updates_audience_id'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
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
        "account_staged_admission",
        "note_checkpoints",
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
        let mut note = bh_core::note::Note::new().unwrap();
        let delta = note.append_paragraph("existing").unwrap();
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
    conn.execute_batch(
        "DROP TABLE note_outbox_members; DROP TABLE joined_device; DROP TABLE base_control_outbox; DROP TABLE registration; DROP TABLE sync_alarm; DROP TABLE note_outbox_progress; DROP TABLE writer_binding; DROP TABLE accepted_note_tail; DROP TABLE accepted_note; DROP TABLE log_floor; DROP TABLE log_account_change; DROP TABLE log_event_id; DROP TABLE log_seen; DROP TABLE log_progress; DROP TABLE note_update_writer; DROP TABLE note_writer_slots; DROP TABLE base_writer_phase; DROP TABLE account_initial_bootstrap; DROP TABLE own_base; DROP TABLE account_devices; DROP TABLE account_key_use; DROP TABLE account_projection; DROP TABLE view_records; DROP TABLE notes; DROP TABLE note_counter; DROP TABLE pending_scope_backfill; DROP TABLE pending_scope; DROP TABLE note_checkpoints; DROP INDEX IF EXISTS note_updates_audience_id; DROP TABLE account_staged_admission; DROP TABLE note_outbox; PRAGMA user_version=3",
    )
    .unwrap();
    drop(conn);
    let db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    assert_eq!(db.account_history().unwrap(), vec![b"genesis".to_vec()]);
    assert_eq!(db.account_state().unwrap().unwrap().head_position, 1);
    assert_eq!(
        version(&Connection::open(&path).unwrap()),
        LOCAL_DATA_VERSION
    );
}

#[test]
fn failed_v4_migration_rolls_back_marker_and_keeps_v3_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v3-failed.sqlite");
    drop(DeviceDatabase::open(&path).unwrap());
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch(
        "DROP TABLE view_records; DROP TABLE notes; DROP TABLE note_counter; DROP TABLE note_outbox; PRAGMA user_version=3; CREATE TABLE note_outbox (bogus INTEGER)",
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
fn v4_to_v5_preserves_existing_note_and_outbox_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v4.sqlite");
    write_v4(&path);
    let conn = Connection::open(&path).unwrap();
    let delta = bh_core::note::Note::new()
        .unwrap()
        .append_paragraph("existing")
        .unwrap();
    conn.execute(
        "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
        params![
            [1u8; 32].as_slice(),
            [2u8; 32].as_slice(),
            [3u8; 32].as_slice(),
            [4u8; 16].as_slice(),
            delta
        ],
    )
    .unwrap();
    conn.execute("INSERT INTO pending_note_work(update_id) VALUES (1)", [])
        .unwrap();
    conn.execute(
        "INSERT INTO note_outbox(update_id,event_id,descriptor,body) VALUES (1,?1,?2,?3)",
        params![[8u8; 32].as_slice(), b"descriptor", b"body"],
    )
    .unwrap();
    drop(conn);
    let db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    let conn = Connection::open(&path).unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT event_id,descriptor,body FROM note_outbox WHERE update_id=1",
            [],
            |r| Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?
            ))
        )
        .unwrap(),
        (vec![8; 32], b"descriptor".to_vec(), b"body".to_vec())
    );
    assert_eq!(version(&conn), LOCAL_DATA_VERSION);
    assert!(table_exists(&conn, "account_staged_admission"));
}

#[test]
fn failed_v5_migration_keeps_v4_layout_and_version() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v4-conflict.sqlite");
    write_v4(&path);
    let conn = Connection::open(&path).unwrap();
    let delta = bh_core::note::Note::new()
        .unwrap()
        .append_paragraph("retained")
        .unwrap();
    conn.execute(
        "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
        params![
            [1u8; 32].as_slice(),
            [2u8; 32].as_slice(),
            [3u8; 32].as_slice(),
            [4u8; 16].as_slice(),
            delta
        ],
    )
    .unwrap();
    conn.execute("INSERT INTO pending_note_work(update_id) VALUES (1)", [])
        .unwrap();
    conn.execute(
        "INSERT INTO note_outbox(update_id,event_id,descriptor,body) VALUES (1,?1,?2,?3)",
        params![[8u8; 32].as_slice(), b"descriptor", b"body"],
    )
    .unwrap();
    conn.execute_batch("CREATE TABLE account_staged_admission (bogus INTEGER)")
        .unwrap();
    drop(conn);
    assert!(DeviceDatabase::open(&path).is_err());
    let conn = Connection::open(&path).unwrap();
    assert_eq!(version(&conn), 4);
    assert!(table_exists(&conn, "note_outbox"));
    assert!(table_exists(&conn, "note_updates"));
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM note_updates", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM note_outbox", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
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
