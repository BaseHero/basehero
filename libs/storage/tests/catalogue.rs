use bh_core::note::Note;
use bh_storage::{DeviceDatabase, NoteKey, StoreError};
use rusqlite::{Connection, params};

const BASE: [u8; 32] = [7; 32];
const AUDIENCE: [u8; 32] = [0; 32];
fn key(note: [u8; 32]) -> NoteKey {
    NoteKey {
        base: BASE,
        audience: AUDIENCE,
        note,
    }
}

#[test]
fn home_creation_is_idempotent_and_scope_is_full_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    let home = db.home_note(BASE, AUDIENCE).unwrap();
    assert_eq!(db.home_note(BASE, AUDIENCE).unwrap(), home);
    assert!(db.note_exists(key(home)).unwrap());
    assert!(
        !db.note_exists(NoteKey {
            base: [8; 32],
            ..key(home)
        })
        .unwrap()
    );
    assert!(
        !db.note_exists(NoteKey {
            audience: [9; 32],
            ..key(home)
        })
        .unwrap()
    );
    let created = db.create_note(BASE, AUDIENCE).unwrap();
    assert_ne!(home, created);
    assert_eq!(db.list_notes(BASE, AUDIENCE, None, 50).unwrap().len(), 2);
    drop(db);
    assert_eq!(
        DeviceDatabase::open(&path)
            .unwrap()
            .home_note(BASE, AUDIENCE)
            .unwrap(),
        created
    );
}

#[test]
fn legacy_local_commit_indexes_created_note_without_loading_document() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    let note = db.create_note(BASE, AUDIENCE).unwrap();
    let key = key(note);
    db.commit_account_verified([4; 32], &[b"genesis"], 1, [5; 32], false)
        .unwrap();
    let initial = db.list_notes(BASE, AUDIENCE, None, 1).unwrap()[0].touched;
    let delta = Note::new().unwrap().append_paragraph("saved").unwrap();
    db.commit_working_update(key, 0, [4; 32], [1; 16], &delta)
        .unwrap();
    let saved = db.list_notes(BASE, AUDIENCE, None, 1).unwrap();
    assert_eq!(saved[0].note, note);
    assert_eq!(saved[0].title, "");
    assert!(saved[0].touched > initial);
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    assert!(
        db.commit_working_update(key, 0, [4; 32], [1; 16], &delta)
            .unwrap()
            .replayed
    );
    assert_eq!(db.list_notes(BASE, AUDIENCE, None, 1).unwrap(), saved);
}

#[test]
fn direct_local_update_indexes_note_in_same_commit() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    let key = key([29; 32]);
    let delta = Note::new().unwrap().append_paragraph("direct").unwrap();
    db.apply_local_update(key, [2; 16], &delta).unwrap();
    assert!(db.note_exists(key).unwrap());
    assert_eq!(
        db.list_notes(BASE, AUDIENCE, None, 50).unwrap()[0].title,
        ""
    );
}

#[test]
fn title_and_touched_share_commit_and_replay_never_reorders() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    db.commit_account_verified([4; 32], &[b"genesis"], 1, [5; 32], false)
        .unwrap();
    let a = key(db.create_note(BASE, AUDIENCE).unwrap());
    let b = key(db.create_note(BASE, AUDIENCE).unwrap());
    let mut note = Note::new().unwrap();
    let delta = note.append_paragraph("one").unwrap();
    assert!(
        !db.commit_working_update_with_title(a, 0, [4; 32], [1; 16], &delta, "one")
            .unwrap()
            .replayed
    );
    let first = db.list_notes(BASE, AUDIENCE, None, 50).unwrap();
    assert_eq!(first[0].note, a.note);
    assert_eq!(first[0].title, "one");
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    let counter = Connection::open(&path)
        .unwrap()
        .query_row("SELECT value FROM note_counter WHERE id=1", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
    assert!(
        db.commit_working_update_with_title(a, 0, [4; 32], [1; 16], &delta, "changed")
            .unwrap()
            .replayed
    );
    assert_eq!(
        Connection::open(&path)
            .unwrap()
            .query_row("SELECT value FROM note_counter WHERE id=1", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        counter
    );
    assert_eq!(db.list_notes(BASE, AUDIENCE, None, 50).unwrap(), first);
    let conn = Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER refuse_touch BEFORE UPDATE OF touched ON notes BEGIN SELECT RAISE(ABORT, 'test-only rollback'); END;").unwrap();
    assert!(matches!(
        db.commit_working_update_with_title(a, 1, [4; 32], [2; 16], &delta, "other"),
        Err(StoreError::Database(_))
    ));
    conn.execute_batch("DROP TRIGGER refuse_touch").unwrap();
    assert_eq!(db.list_notes(BASE, AUDIENCE, None, 50).unwrap(), first);
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    assert_eq!(
        Connection::open(&path)
            .unwrap()
            .query_row("SELECT value FROM note_counter WHERE id=1", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        counter
    );
    assert!(matches!(
        db.commit_working_update_with_title(key([99; 32]), 0, [4; 32], [9; 16], &delta, "missing"),
        Err(StoreError::MissingNote)
    ));
    assert_eq!(db.pending_note_updates().unwrap().len(), 1);
    assert!(matches!(
        db.list_notes(BASE, AUDIENCE, None, 51),
        Err(StoreError::InvalidNotePage)
    ));
    let mut second = Note::new().unwrap();
    let second_delta = second.append_paragraph("two").unwrap();
    db.commit_working_update_with_title(b, 0, [4; 32], [3; 16], &second_delta, "two")
        .unwrap();
    let page = db.list_notes(BASE, AUDIENCE, None, 1).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].note, b.note);
    assert_eq!(
        db.list_notes(BASE, AUDIENCE, Some((page[0].touched, page[0].note)), 50)
            .unwrap()[0]
            .note,
        a.note
    );
    drop(db);
    assert_eq!(
        DeviceDatabase::open(&path)
            .unwrap()
            .list_notes(BASE, AUDIENCE, None, 50)
            .unwrap()[0]
            .title,
        "two"
    );
}

#[test]
fn simultaneous_first_home_calls_commit_only_one_row() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("concurrent.sqlite");
    drop(DeviceDatabase::open(&path).unwrap());
    let gate = std::sync::Arc::new(std::sync::Barrier::new(3));
    let workers: Vec<_> = (0..2)
        .map(|_| {
            let path = path.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                let mut db = DeviceDatabase::open(path).unwrap();
                gate.wait();
                db.home_note(BASE, AUDIENCE).unwrap()
            })
        })
        .collect();
    gate.wait();
    let ids: Vec<_> = workers.into_iter().map(|w| w.join().unwrap()).collect();
    assert_eq!(ids[0], ids[1]);
    assert_eq!(
        DeviceDatabase::open(&path)
            .unwrap()
            .list_notes(BASE, AUDIENCE, None, 50)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn catalogue_page_reads_no_documents() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    let note = db.create_note(BASE, AUDIENCE).unwrap();
    let pool = db.read_pool().unwrap();
    let conn = Connection::open(&path).unwrap();
    conn.execute(
        "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,x'ff')",
        params![BASE, AUDIENCE, note, [1u8; 16]],
    )
    .unwrap();
    let page = pool.list_notes(BASE, AUDIENCE, None, 1).unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].note, note);
    assert_eq!(
        pool.replayed_rows(),
        0,
        "catalogue must not reconstruct note content"
    );
    assert!(
        pool.note_state(key(note)).is_err(),
        "fixture must fail if content is loaded"
    );
}

#[test]
fn hundred_thousand_rows_use_indexed_search_for_first_and_cursor_page() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.db");
    let db = DeviceDatabase::open(&path).unwrap();
    let pool = db.read_pool().unwrap();
    let mut conn = Connection::open(&path).unwrap();
    let tx = conn.transaction().unwrap();
    {
        let mut insert = tx
            .prepare("INSERT INTO notes(base,audience,note,touched,title) VALUES (?1,?2,?3,?4,'')")
            .unwrap();
        for i in 0u32..100_000 {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&i.to_be_bytes());
            insert
                .execute(params![
                    BASE.as_slice(),
                    AUDIENCE.as_slice(),
                    id.as_slice(),
                    i + 1
                ])
                .unwrap();
        }
    }
    tx.commit().unwrap();
    for after in [
        None,
        Some((99_951, {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&99_950u32.to_be_bytes());
            id
        })),
    ] {
        let start = std::time::Instant::now();
        let page = pool.list_notes(BASE, AUDIENCE, after, 50).unwrap();
        assert_eq!(page.len(), 50);
        eprintln!("100k catalogue page: {:?}", start.elapsed());
    }
    for after in [false, true] {
        let sql = if after {
            "EXPLAIN QUERY PLAN SELECT note FROM notes WHERE base=?1 AND audience=?2 AND (touched,note)<(?3,?4) ORDER BY touched DESC,note DESC LIMIT 50"
        } else {
            "EXPLAIN QUERY PLAN SELECT note FROM notes WHERE base=?1 AND audience=?2 ORDER BY touched DESC,note DESC LIMIT 50"
        };
        let mut stmt = conn.prepare(sql).unwrap();
        let args: &[&dyn rusqlite::ToSql] = if after {
            &[
                &BASE.as_slice(),
                &AUDIENCE.as_slice(),
                &99_951i64,
                &[0u8; 32].as_slice(),
            ]
        } else {
            &[&BASE.as_slice(), &AUDIENCE.as_slice()]
        };
        let plan: Vec<String> = stmt
            .query_map(args, |r| r.get(3))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(
            plan.iter()
                .any(|s| s.contains("SEARCH") && s.contains("notes_recent")),
            "{plan:?}"
        );
        assert!(
            !plan
                .iter()
                .any(|s| s.contains("SCAN") || s.contains("TEMP B-TREE")),
            "{plan:?}"
        );
    }
}
