use bh_core::{contained::with_fuel, note::Note};
use bh_storage::{DeviceDatabase, NoteKey, StoreError};
#[path = "support/note_rows.rs"]
mod note_rows;

fn key() -> NoteKey {
    NoteKey {
        base: [1; 32],
        audience: [2; 32],
        note: [3; 32],
    }
}

#[test]
fn failed_cached_read_retries_from_durable_state() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.sqlite");
    let mut db = DeviceDatabase::open(&path).unwrap();
    let update = Note::with_writer(102)
        .unwrap()
        .append_paragraph("keep the cached note")
        .unwrap();
    db.apply_local_update(key(), [1; 16], &update).unwrap();
    let expected = db.note_state(key()).unwrap();
    assert!(matches!(
        with_fuel(0, || db.note_state(key())),
        Err(StoreError::NoteUnavailable)
    ));
    assert_eq!(db.note_state(key()).unwrap(), expected);
}

#[test]
fn unavailable_save_keeps_all_durable_rows_and_exact_retry() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.sqlite");
    let mut db = DeviceDatabase::open(&path).unwrap();
    let raw = rusqlite::Connection::open(&path).unwrap();
    let mut author = Note::with_writer(100).unwrap();
    let first = author.append_paragraph("accepted").unwrap();
    let queued = author
        .append_paragraph("retain this exact attempted save")
        .unwrap();
    db.apply_local_update(key(), [1; 16], &first).unwrap();
    let before_state = db.note_state(key()).unwrap();
    let before = note_rows::snapshot(&raw);
    let failed = with_fuel(0, || db.apply_local_update(key(), [2; 16], &queued));
    assert!(
        matches!(failed, Err(StoreError::NoteUnavailable)),
        "{failed:?}"
    );
    assert_eq!(note_rows::snapshot(&raw), before);
    assert_eq!(db.note_state(key()).unwrap(), before_state);
    let saved = db.apply_local_update(key(), [2; 16], &queued).unwrap();
    assert!(!saved.replayed);
    assert!(
        db.apply_local_update(key(), [2; 16], &queued)
            .unwrap()
            .replayed
    );
    assert_eq!(db.pending_note_updates().unwrap()[1].bytes, queued);
}

#[test]
fn unavailable_checkpoint_finish_publishes_nothing_and_retries_from_durable_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("notes.sqlite");
    let mut db = DeviceDatabase::open(&path).unwrap();
    let raw = rusqlite::Connection::open(&path).unwrap();
    let mut author = Note::with_writer(101).unwrap();
    let load_job = |db: &DeviceDatabase| {
        let mut job = db
            .begin_checkpoint(key())
            .unwrap()
            .unwrap()
            .start()
            .unwrap();
        loop {
            let page = db.checkpoint_page(&job, 256).unwrap();
            if page.is_empty() {
                break;
            }
            job.apply_page(&page).unwrap();
        }
        job
    };
    db.apply_local_update(
        key(),
        [1; 16],
        &author.append_paragraph("prior checkpoint").unwrap(),
    )
    .unwrap();
    let first = load_job(&db).finish().unwrap().unwrap();
    db.publish_checkpoint(&first).unwrap();
    let tail = author.append_paragraph("exact tail").unwrap();
    db.apply_local_update(key(), [2; 16], &tail).unwrap();
    let job = load_job(&db);
    let before_state = db.note_state(key()).unwrap();
    let before = note_rows::snapshot(&raw);
    let result = with_fuel(0, || job.finish());
    assert!(matches!(result, Err(StoreError::NoteUnavailable)));
    assert_eq!(note_rows::snapshot(&raw), before);
    drop(db);
    let mut db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.note_state(key()).unwrap(), before_state);
    let retry = load_job(&db).finish().unwrap().unwrap();
    assert!(db.publish_checkpoint(&retry).unwrap());
    assert_eq!(db.note_state(key()).unwrap(), before_state);
    assert_eq!(db.pending_note_updates().unwrap()[1].bytes, tail);
}
