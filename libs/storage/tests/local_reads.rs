use bh_core::note::Note;
use bh_storage::{DeviceDatabase, NoteKey};
use yrs::{Doc, Transact, WriteTxn, XmlElementPrelim, XmlFragment};

fn key(base: u8, note: u8) -> NoteKey {
    NoteKey {
        base: [base; 32],
        audience: [1; 32],
        note: [note; 32],
    }
}
fn edit(db: &mut DeviceDatabase, key: NoteKey, request: u8) -> i64 {
    db.apply_local_update(
        key,
        [request; 16],
        &Note::new().unwrap().append_paragraph("local").unwrap(),
    )
    .unwrap()
    .update_id
}
/// Reproduce with: cargo test -p bh-storage --test local_reads growth_run -- --ignored --nocapture
/// Opt into 1M with BH_LOCAL_GROWTH_MILLION=1. The repeated real Yjs update
/// measures local row/keyset costs, not growing-document CRDT encoding costs.
#[test]
#[ignore = "explicit performance run; not an affected-check cost"]
fn growth_run_open_rows_bytes_and_checkpoint_output() {
    use std::time::Instant;
    let dir = tempfile::tempdir().unwrap();
    let target = key(1, 1);
    let delta = Note::new()
        .unwrap()
        .append_paragraph(&"x".repeat(1024))
        .unwrap();
    let levels = if std::env::var_os("BH_LOCAL_GROWTH_MILLION").is_some() {
        vec![1000, 10000, 100000, 1000000]
    } else {
        vec![1000, 10000, 100000]
    };
    for count in levels {
        let path = dir.path().join(format!("growth-{count}.db"));
        let mut db = DeviceDatabase::open(&path).unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        let mut written = 0u64;
        let started = Instant::now();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        while written < count {
            let request = written.to_be_bytes();
            conn.execute("INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",rusqlite::params![target.base.as_slice(),target.audience.as_slice(),target.note.as_slice(),[request.as_slice(),&[0;8]].concat(),delta.as_slice()]).unwrap();
            conn.execute(
                "INSERT INTO pending_note_work(update_id) VALUES (?1)",
                [written as i64 + 1],
            )
            .unwrap();
            written += 1;
        }
        conn.execute_batch("COMMIT").unwrap();
        let inserted = started.elapsed();
        let backfill_started = Instant::now();
        while !db.backfill_pending_scope(256).unwrap() {}
        let backfill = backfill_started.elapsed();
        let pending_started = Instant::now();
        let mut pages = 0;
        let mut cursor = 0;
        let mut pending_bytes = 0usize;
        let mut pending_rows = 0;
        loop {
            let page = db
                .pending_page(
                    target.base,
                    target.audience,
                    Some(target.note),
                    cursor,
                    256,
                    256 * 1024,
                )
                .unwrap();
            if page.rows.is_empty() {
                break;
            }
            pending_rows += page.rows.len();
            pending_bytes += page.rows.iter().map(|r| r.bytes.len()).sum::<usize>();
            pages += 1;
            if let Some(next) = page.next {
                cursor = next;
            } else {
                break;
            }
        }
        let pending_time = pending_started.elapsed();
        assert_eq!(pending_rows, count as usize);
        let pool = db.read_pool().unwrap();
        let started = Instant::now();
        let raw = pool.note_state(target).unwrap();
        let cold = started.elapsed();
        let mut job = db
            .begin_checkpoint(target)
            .unwrap()
            .unwrap()
            .start()
            .unwrap();
        let started = Instant::now();
        let mut checkpoint_rows = 0;
        loop {
            let page = db.checkpoint_page(&job, 256).unwrap();
            if page.is_empty() {
                break;
            }
            checkpoint_rows += page.len();
            job.apply_page(&page).unwrap();
        }
        let encoded = job.finish().unwrap().unwrap();
        let compact = started.elapsed();
        let checkpoint_bytes = encoded.encoded_bytes();
        assert!(db.publish_checkpoint(&encoded).unwrap());
        let started = Instant::now();
        let fast = pool.note_state(target).unwrap();
        let healthy = started.elapsed();
        assert_eq!(raw.state, fast.state);
        eprintln!(
            "growth rows={count} insert={inserted:?} backfill={backfill:?} pending_pages={pages} pending_time={pending_time:?} pending_rows={pending_rows} pending_bytes={pending_bytes} cold_open={cold:?} cold_rows={} cold_bytes={} compact={compact:?} compact_rows={checkpoint_rows} checkpoint_bytes={checkpoint_bytes} healthy_open={healthy:?} healthy_rows={} healthy_bytes={}",
            raw.rows, raw.bytes, fast.rows, fast.bytes
        );
        assert_eq!(raw.rows, count as usize);
        assert_eq!(fast.rows, 0);
    }
}

#[test]
fn clean_durably_committed_unsent_notes_are_lru_evictable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    db.set_note_cache_budget(256);
    for i in 1..=24u8 {
        edit(&mut db, key(1, i), i);
    }
    assert!(
        db.cached_note_count() < 24,
        "offline unsent work must not pin every visited note"
    );
    let retained = db.pending_note_updates().unwrap();
    assert_eq!(retained.len(), 24);
    let first = db.note_state(key(1, 1)).unwrap();
    drop(db);
    assert_eq!(
        DeviceDatabase::open(&path)
            .unwrap()
            .note_state(key(1, 1))
            .unwrap(),
        first
    );
}

#[test]
fn pending_pages_are_keyset_scoped_and_bounded_by_rows_and_bytes() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    for i in 1..6 {
        edit(&mut db, key(1, 1), i);
        edit(&mut db, key(2, 1), i + 20);
    }
    let mut after = 0;
    let mut collected = Vec::new();
    loop {
        let page = db
            .pending_page([1; 32], [1; 32], Some([1; 32]), after, 2, 160)
            .unwrap();
        assert!(page.rows.len() <= 2);
        assert!(page.rows.iter().all(|r| r.key == key(1, 1)));
        if page.rows.is_empty() {
            assert!(page.next.is_none());
            break;
        }
        collected.extend(page.rows.iter().map(|r| r.update_id));
        if let Some(next) = page.next {
            assert!(next > after);
            after = next;
        } else {
            break;
        }
    }
    assert_eq!(collected.len(), 5);
    collected.sort();
    collected.dedup();
    assert_eq!(collected.len(), 5);
}
#[test]
fn working_note_commit_is_scoped_cas_and_rollback_leaves_only_durable_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("work.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    db.commit_account_verified([9; 32], &[b"test-only anchor"], 1, [8; 32], false)
        .unwrap();
    let a = key(1, 1);
    let b = key(2, 1);
    let mut candidate = Note::new().unwrap();
    let delta = candidate.append_paragraph("mine").unwrap();
    let before = db.local_frontier(a).unwrap();
    edit(&mut db, b, 77); // unrelated note cannot invalidate A
    let committed = db
        .commit_working_update(a, before, [9; 32], [1; 16], &delta)
        .unwrap();
    assert!(!committed.replayed);
    assert!(matches!(
        db.commit_working_update(a, before, [9; 32], [2; 16], &delta),
        Err(bh_storage::StoreError::StaleNote)
    ));
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER refuse_edit BEFORE INSERT ON note_updates WHEN NEW.base=x'0101010101010101010101010101010101010101010101010101010101010101' BEGIN SELECT RAISE(ABORT,'failure'); END").unwrap();
    let mut next = Note::new().unwrap();
    let attempted = next.append_paragraph("failed").unwrap();
    assert!(
        db.commit_working_update(a, committed.update_id, [9; 32], [3; 16], &attempted)
            .is_err()
    );
    drop(db);
    let mut reopened = DeviceDatabase::open(&path).unwrap();
    let mut expected = Note::new().unwrap();
    expected.apply_update(&delta).unwrap();
    assert_eq!(reopened.note_state(a).unwrap(), expected.state().unwrap());
    assert_eq!(
        reopened
            .pending_page(a.base, a.audience, Some(a.note), 0, 10, 8192)
            .unwrap()
            .rows
            .len(),
        1
    );
}

#[test]
fn stale_cached_note_is_discarded_before_working_cas() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stale-cache.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    db.commit_account_verified([9; 32], &[b"test-only anchor"], 1, [8; 32], false)
        .unwrap();
    let key = key(1, 1);
    let first = Note::new().unwrap().append_paragraph("cached").unwrap();
    let committed = db
        .commit_working_update(key, 0, [9; 32], [1; 16], &first)
        .unwrap();
    let mut cached = Note::new().unwrap();
    cached.apply_update(&first).unwrap();
    db.return_committed_note(key, cached, committed.update_id, first.len());
    let second = Note::new()
        .unwrap()
        .append_paragraph("outside writer")
        .unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
        rusqlite::params![
            key.base.as_slice(),
            key.audience.as_slice(),
            key.note.as_slice(),
            [2u8; 16].as_slice(),
            second
        ],
    )
    .unwrap();
    let frontier = db.local_frontier(key).unwrap();
    assert!(frontier > committed.update_id);
    assert!(
        db.take_cached_note(key, frontier).is_none(),
        "cache must name its own committed frontier"
    );
    let rebuilt = db.read_pool().unwrap().load_note(key).unwrap();
    assert_eq!(rebuilt.frontier, frontier);
    let mut expected = Note::new().unwrap();
    expected.apply_update(&first).unwrap();
    expected.apply_update(&second).unwrap();
    assert_eq!(
        rebuilt.note.state().unwrap(),
        expected.state().unwrap(),
        "rebuilt projection includes the out-of-band row"
    );
    let third = Note::new().unwrap().append_paragraph("new").unwrap();
    db.commit_working_update(key, rebuilt.frontier, [9; 32], [3; 16], &third)
        .unwrap();
}

#[test]
fn tiny_cached_guests_do_not_fit_a_sixteen_kib_budget() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    db.set_note_cache_budget(16 * 1024);
    for n in 0..100u8 {
        let key = NoteKey {
            base: [n; 32],
            audience: [1; 32],
            note: [2; 32],
        };
        db.return_committed_note(key, Note::new().unwrap(), 0, 1);
    }
    assert_eq!(
        db.cached_note_count(),
        0,
        "even a tiny guest exceeds 16 KiB"
    );
}

#[test]
fn paused_base_a_read_does_not_hold_writer_for_base_b_local_typing() {
    use std::{
        sync::{Arc, Mutex, mpsc},
        thread,
        time::Duration,
    };
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("two-bases.db");
    let db = Arc::new(Mutex::new(DeviceDatabase::open(&path).unwrap()));
    let a = key(1, 1);
    let b = key(2, 1);
    let delta = Note::new().unwrap().append_paragraph("read page").unwrap();
    let mut conn = rusqlite::Connection::open(&path).unwrap();
    let tx = conn.transaction().unwrap();
    for n in 0..600u16 {
        tx.execute(
            "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![
                a.base.as_slice(),
                a.audience.as_slice(),
                a.note.as_slice(),
                [n.to_be_bytes().as_slice(), &[0; 14]].concat(),
                delta.as_slice()
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let pool = db.lock().unwrap().read_pool().unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut first = true;
        pool.note_state_with_progress(a, || {
            if first {
                first = false;
                started_tx.send(()).unwrap();
                resume_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            }
        })
        .unwrap()
    });
    started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let (saved_tx, saved_rx) = mpsc::channel();
    let writer = Arc::clone(&db);
    thread::spawn(move || {
        saved_tx
            .send(writer.lock().unwrap().apply_local_update(
                b,
                [1; 16],
                &Note::new().unwrap().append_paragraph("typing").unwrap(),
            ))
            .unwrap()
    });
    assert!(
        saved_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .is_ok(),
        "base B cannot wait for base A's paused reconstruction"
    );
    resume_tx.send(()).unwrap();
    assert_eq!(reader.join().unwrap().rows, 600);
}

#[test]
fn checkpoint_pages_are_bounded_by_bytes_as_well_as_rows() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    let target = key(1, 1);
    for id in [1, 2] {
        edit_raw(
            &mut db,
            target,
            id,
            &Note::new()
                .unwrap()
                .append_paragraph(&"x".repeat(140 * 1024))
                .unwrap(),
        );
    }
    let mut job = db
        .begin_checkpoint(target)
        .unwrap()
        .unwrap()
        .start()
        .unwrap();
    let first = db.checkpoint_page(&job, 256).unwrap();
    assert_eq!(
        first.len(),
        1,
        "two large deltas must not share a 256-KiB page"
    );
    job.apply_page(&first).unwrap();
    assert_eq!(db.checkpoint_page(&job, 256).unwrap().len(), 1);
}

#[test]
fn failed_sqlite_checkpoint_and_restart_keep_dependent_and_unknown_yjs_content() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("failed.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    let target = key(1, 1);
    let mut source = Note::new().unwrap();
    let first = source.append_paragraph("first").unwrap();
    let dependent = source.append_paragraph("later").unwrap();
    let foreign = Doc::new();
    let unknown = {
        let mut txn = foreign.transact_mut();
        txn.get_or_insert_xml_fragment("default").insert(
            &mut txn,
            0,
            XmlElementPrelim::empty("future-widget"),
        );
        txn.encode_update_v1()
    };
    edit_raw(&mut db, target, 1, &dependent);
    edit_raw(&mut db, target, 2, &unknown);
    let mut job = db
        .begin_checkpoint(target)
        .unwrap()
        .unwrap()
        .start()
        .unwrap();
    loop {
        let page = db.checkpoint_page(&job, 1).unwrap();
        if page.is_empty() {
            break;
        }
        job.apply_page(&page).unwrap();
    }
    let prepared = job.finish().unwrap().unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER refuse_checkpoint BEFORE INSERT ON note_checkpoints BEGIN SELECT RAISE(ABORT,'write refused'); END").unwrap();
    assert!(db.publish_checkpoint(&prepared).is_err());
    drop(db);
    let mut reopened = DeviceDatabase::open(&path).unwrap();
    edit_raw(&mut reopened, target, 3, &first);
    let mut expected = Note::new().unwrap();
    expected.apply_update(&dependent).unwrap();
    expected.apply_update(&unknown).unwrap();
    expected.apply_update(&first).unwrap();
    assert_eq!(
        reopened.note_state(target).unwrap(),
        expected.state().unwrap(),
        "dependency and unsupported structure must survive failure/restart"
    );
    conn.execute_batch("DROP TRIGGER refuse_checkpoint")
        .unwrap();
    assert!(
        reopened.publish_checkpoint(&prepared).unwrap(),
        "captured prefix can publish after later writes"
    );
    drop(reopened);
    assert_eq!(
        DeviceDatabase::open(&path)
            .unwrap()
            .note_state(target)
            .unwrap(),
        expected.state().unwrap()
    );
}
fn edit_raw(db: &mut DeviceDatabase, key: NoteKey, request: u8, bytes: &[u8]) {
    db.apply_local_update(key, [request; 16], bytes).unwrap();
}

#[test]
fn hundreds_of_same_note_saves_continue_while_a_checkpoint_is_delayed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("busy.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    let target = key(1, 1);
    for i in 0..256u16 {
        let mut request = [0u8; 16];
        request[..2].copy_from_slice(&i.to_be_bytes());
        request[2] = 11;
        db.apply_local_update(
            target,
            request,
            &Note::new().unwrap().append_paragraph("warmup").unwrap(),
        )
        .unwrap();
    }
    let mut job = db
        .begin_checkpoint(target)
        .unwrap()
        .unwrap()
        .start()
        .unwrap();
    loop {
        let page = db.checkpoint_page(&job, 32).unwrap();
        if page.is_empty() {
            break;
        }
        job.apply_page(&page).unwrap();
    }
    // The expensive whole-state encoding and stalled publication do not own
    // SQLite. Use unique request IDs in a second batch of 200 foreground saves.
    for i in 0..200u16 {
        let mut request = [0u8; 16];
        request[..2].copy_from_slice(&i.to_be_bytes());
        request[2] = 77;
        db.apply_local_update(
            target,
            request,
            &Note::new()
                .unwrap()
                .append_paragraph("during compaction")
                .unwrap(),
        )
        .unwrap();
    }
    let prepared = job.finish().unwrap().unwrap();
    assert!(db.publish_checkpoint(&prepared).unwrap());
    assert_eq!(db.checkpoint_tail(target).unwrap().0, 200);
    let saved = db.note_state(target).unwrap();
    drop(db);
    assert_eq!(
        DeviceDatabase::open(&path)
            .unwrap()
            .note_state(target)
            .unwrap(),
        saved
    );
}

#[test]
fn checkpoint_prefix_cas_preserves_later_writes_and_failed_publish_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    let target = key(1, 1);
    for i in 1..5 {
        edit(&mut db, target, i);
    }
    let mut capture = db
        .begin_checkpoint(target)
        .unwrap()
        .unwrap()
        .start()
        .unwrap();
    let mut later = 7;
    loop {
        let page = db.checkpoint_page(&capture, 2).unwrap();
        if page.is_empty() {
            break;
        }
        capture.apply_page(&page).unwrap();
        edit(&mut db, target, later); // saves continue while immutable prefix encodes
        later += 1;
    }
    let encoded = capture.finish().unwrap().unwrap();
    assert!(db.publish_checkpoint(&encoded).unwrap());
    assert!(
        !db.publish_checkpoint(&encoded).unwrap(),
        "generation CAS rejects stale publication"
    );
    let before = db.note_state(target).unwrap();
    drop(db);
    let mut reopened = DeviceDatabase::open(&path).unwrap();
    assert_eq!(reopened.note_state(target).unwrap(), before);
    assert_eq!(reopened.pending_note_updates().unwrap().len(), 6);
    assert_eq!(reopened.checkpoint_tail(target).unwrap().0, 2);
}

/// Yjs updates in log order; the third names a left origin in the first and
/// a right origin in the second that are not adjacent.
const K2: [&[u8]; 4] = [
    &[
        1, 3, 2, 0, 7, 1, 7, 100, 101, 102, 97, 117, 108, 116, 3, 9, 112, 97, 114, 97, 103, 114,
        97, 112, 104, 7, 0, 2, 0, 6, 4, 0, 2, 1, 5, 104, 101, 108, 108, 111, 0,
    ],
    &[1, 1, 1, 0, 132, 2, 6, 2, 72, 76, 0],
    &[1, 1, 50, 0, 196, 2, 4, 1, 1, 4, 97, 98, 99, 100, 0],
    &[1, 1, 107, 0, 132, 2, 6, 6, 32, 119, 111, 114, 108, 100, 0],
];

#[test]
fn checkpoint_and_reopen_keep_the_integrated_structure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ordered.db");
    let target = key(1, 1);
    let mut live = Note::new().unwrap();
    let mut db = DeviceDatabase::open(&path).unwrap();
    for (n, update) in K2.iter().enumerate() {
        db.apply_local_update(target, [n as u8; 16], update)
            .unwrap();
        live.apply_update(update).unwrap();
    }
    assert_eq!(live.title_preview().unwrap(), "helloH worldabcdL");
    let mut job = db
        .begin_checkpoint(target)
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
    assert!(
        db.publish_checkpoint(&job.finish().unwrap().unwrap())
            .unwrap()
    );
    // A later row after the checkpoint, then every load path.
    let later = Note::new().unwrap().append_paragraph("later").unwrap();
    db.apply_local_update(target, [9; 16], &later).unwrap();
    live.apply_update(&later).unwrap();
    drop(db);
    let mut reopened = DeviceDatabase::open(&path).unwrap();
    let ordered = reopened.note_ordered(target).unwrap();
    let pool = reopened.read_pool().unwrap();
    let (pooled, frontier) = pool.note_ordered(target).unwrap();
    assert_eq!(pooled, ordered);
    assert_eq!(frontier, reopened.local_frontier(target).unwrap());
    let loaded = pool.load_note(target).unwrap();
    assert_eq!(loaded.rows, 1, "the checkpoint covered the first rows");
    for note in [Note::from_ordered(&ordered).unwrap(), loaded.note] {
        assert_eq!(note.digest().unwrap(), live.digest().unwrap());
        assert_eq!(note.title_preview().unwrap(), "helloH worldabcdL");
    }
    // The writer's own cache rebuilds from the same ordered rows.
    reopened.note_state(target).unwrap();
    let cached = reopened
        .take_cached_note(target, frontier)
        .expect("cached after a read");
    assert_eq!(cached.0.digest().unwrap(), live.digest().unwrap());

    // A second compaction from the ordered checkpoint keeps it too.
    let mut job = reopened
        .begin_checkpoint(target)
        .unwrap()
        .unwrap()
        .start()
        .unwrap();
    job.apply_page(&reopened.checkpoint_page(&job, 256).unwrap())
        .unwrap();
    assert!(
        reopened
            .publish_checkpoint(&job.finish().unwrap().unwrap())
            .unwrap()
    );
    let again = Note::from_ordered(&reopened.note_ordered(target).unwrap()).unwrap();
    assert_eq!(again.digest().unwrap(), live.digest().unwrap());
}

#[test]
fn a_legacy_single_state_checkpoint_still_loads() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    let target = key(1, 1);
    let mut db = DeviceDatabase::open(&path).unwrap();
    let first = Note::new().unwrap().append_paragraph("legacy").unwrap();
    let id = edit(&mut db, target, 1);
    let mut expected = Note::new().unwrap();
    expected
        .apply_update(&Note::new().unwrap().append_paragraph("local").unwrap())
        .unwrap();
    // Legacy encoding used one merged state without the ordered encoding.
    let legacy = expected.state().unwrap();
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "INSERT INTO note_checkpoints(base,audience,note,generation,local_frontier,encoded_yjs) VALUES (?1,?2,?3,1,?4,?5)",
            rusqlite::params![target.base.as_slice(), target.audience.as_slice(), target.note.as_slice(), id, legacy],
        )
        .unwrap();
    db.apply_local_update(target, [2; 16], &first).unwrap();
    expected.apply_update(&first).unwrap();
    drop(db);
    let reopened = DeviceDatabase::open(&path).unwrap();
    let ordered = reopened.note_ordered(target).unwrap();
    assert_eq!(ordered.segments(), [legacy, first]);
    assert_eq!(
        Note::from_ordered(&ordered).unwrap().digest().unwrap(),
        expected.digest().unwrap()
    );
}
