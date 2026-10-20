//! Count the actual writer's plain Note save, with real populated indexes.
use super::*;
use rusqlite::trace::{TraceEvent, TraceEventCodes};
use std::cell::Cell;

thread_local! { static STATEMENTS: Cell<usize> = const { Cell::new(0) }; }
fn count(event: TraceEvent<'_>) {
    if matches!(event, TraceEvent::Profile(_, _)) {
        STATEMENTS.with(|n| n.set(n.get() + 1));
    }
}

#[test]
fn inline_checkpoint_caps_a_burst_without_a_maintenance_worker() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("burst.sqlite");
    let db = DeviceDatabase::open(&path).unwrap();
    db.connection
        .execute_batch("CREATE TABLE burst(value BLOB)")
        .unwrap();
    for _ in 0..125 {
        db.connection
            .execute("INSERT INTO burst(value) VALUES(zeroblob(200000))", [])
            .unwrap();
    }
    let bytes = std::fs::metadata(path.with_extension("sqlite-wal"))
        .unwrap()
        .len();
    let page_size: i64 = db
        .connection
        .pragma_query_value(None, "page_size", |r| r.get(0))
        .unwrap();
    let frames = (bytes - 32) / (page_size as u64 + 24);
    let inline: u32 = db
        .connection
        .pragma_query_value(None, "wal_autocheckpoint", |r| r.get(0))
        .unwrap();
    assert_eq!(inline, INLINE_WAL_FRAMES);
    assert!(frames > 1000, "fixture must grow a WAL burst: {frames}");
    assert!(frames <= 4100, "inline WAL cap exceeded: {frames}");
}

#[test]
fn quiet_checkpoint_resets_large_wal_before_the_next_small_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reset.sqlite");
    let db = DeviceDatabase::open(&path).unwrap();
    db.connection
        .execute_batch("CREATE TABLE burst(value BLOB)")
        .unwrap();
    for _ in 0..12 {
        db.connection
            .execute("INSERT INTO burst(value) VALUES(zeroblob(200000))", [])
            .unwrap();
    }
    assert!(db.checkpoint_wal_if_needed().unwrap() > 0);
    db.connection
        .execute("INSERT INTO burst(value) VALUES(zeroblob(100))", [])
        .unwrap();
    let page_size: i64 = db
        .connection
        .pragma_query_value(None, "page_size", |r| r.get(0))
        .unwrap();
    let limit = 32 + QUIET_WAL_FRAMES * (page_size as u64 + 24);
    let wal_size = std::fs::metadata(path.with_extension("sqlite-wal"))
        .unwrap()
        .len();
    assert!(wal_size <= limit, "reset WAL: {wal_size} > {limit}");
    assert_eq!(db.checkpoint_wal_if_needed().unwrap(), 0);
}

#[test]
fn projected_note_save_keeps_frames_and_statements_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.sqlite");
    let mut db = DeviceDatabase::open(&path).unwrap();
    db.commit_account_verified([4; 32], &[b"genesis"], 1, [5; 32], false)
        .unwrap();
    let mut notes = Vec::new();
    for _ in 0..180 {
        notes.push(db.create_note([2; 32], [0; 32]).unwrap());
    }
    // A checkpoint outside the measured commit gives exact appended WAL frames.
    db.connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
        .unwrap();
    let note = notes[0];
    let mut body = bh_core::note::Note::new().unwrap();
    let delta = body.append_paragraph("new title").unwrap();
    STATEMENTS.with(|n| n.set(0));
    db.connection
        .trace_v2(TraceEventCodes::SQLITE_TRACE_PROFILE, Some(count));
    db.commit_working_update_with_title(
        NoteKey {
            base: [2; 32],
            audience: [0; 32],
            note,
        },
        0,
        [4; 32],
        [9; 16],
        &delta,
        "new title",
    )
    .unwrap();
    db.connection.trace_v2(TraceEventCodes::empty(), None);
    let statements = STATEMENTS.with(Cell::get);
    let bytes = std::fs::metadata(path.with_extension("sqlite-wal"))
        .unwrap()
        .len();
    let page_size: i64 = db
        .connection
        .pragma_query_value(None, "page_size", |r| r.get(0))
        .unwrap();
    let page_size = page_size as u64;
    let frames = (bytes - 32) / (page_size + 24);
    println!("projection_save frames={frames} statements={statements}");
    assert!(frames <= 29, "{frames} WAL frames, expected at most 29");
    assert!(
        statements <= 29,
        "{statements} statements, expected at most 29"
    );
}
