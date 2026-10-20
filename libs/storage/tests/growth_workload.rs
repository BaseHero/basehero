//! Opt-in, reproducible REAL growing/churned Yjs workload; never in affected
//! checks. `cargo test -p bh-storage --test growth_workload -- --ignored --nocapture`.
//! Set BH_LOCAL_GROWTH_MILLION=1 to include a one-million-update case.
use bh_core::note::FRAGMENT;
use bh_storage::{DeviceDatabase, NoteKey};
use rusqlite::{Connection, params};
use std::{path::Path, time::Instant};
use yrs::{Doc, Text, Transact, WriteTxn, XmlElementPrelim, XmlFragment, XmlTextPrelim};

fn rss_bytes() -> Option<usize> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|line| line.starts_with("VmRSS:"))?;
    let kib = line.split_whitespace().nth(1)?.parse::<usize>().ok()?;
    Some(kib * 1024)
}
fn scope() -> NoteKey {
    NoteKey {
        base: [1; 32],
        audience: [2; 32],
        note: [3; 32],
    }
}
fn run(path: &Path, shape: &str, updates: usize) {
    let rss_start = rss_bytes();
    let mut db = DeviceDatabase::open(path).unwrap();
    let conn = Connection::open(path).unwrap();
    let key = scope();
    let source = Doc::new();
    let initial = "x".repeat(1024 * 1024);
    let (text, first) = {
        let mut txn = source.transact_mut();
        let fragment = txn.get_or_insert_xml_fragment(FRAGMENT);
        let large = fragment.insert(&mut txn, 0, XmlElementPrelim::empty("paragraph"));
        large.insert(&mut txn, 0, XmlTextPrelim::new(&initial));
        // Keep the note itself ~1 MiB while updates touch a small second
        // paragraph. Editing inside the 1-MiB text would benchmark the Yrs
        // cursor's linear scan, not the local-storage checkpoint path.
        let changing = fragment.insert(&mut txn, 1, XmlElementPrelim::empty("paragraph"));
        let text = changing.insert(&mut txn, 0, XmlTextPrelim::new(""));
        let bytes = txn.encode_update_v1();
        (text, bytes)
    };
    let mut written_bytes = 0usize;
    let insert = Instant::now();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut record = |id: usize, delta: Vec<u8>| {
        let request = (id as u64).to_be_bytes();
        written_bytes += delta.len();
        conn.execute(
            "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
            params![
                key.base.as_slice(),
                key.audience.as_slice(),
                key.note.as_slice(),
                [request.as_slice(), &[0; 8]].concat(),
                delta
            ],
        )
        .unwrap();
    };
    record(0, first);
    for n in 0..updates {
        let delta = {
            let mut txn = source.transact_mut();
            let len = text.len(&txn);
            if shape == "grow" || n % 2 == 0 {
                text.insert(&mut txn, len, "a");
            } else {
                text.remove_range(&mut txn, len - 1, 1);
            }
            txn.encode_update_v1()
        };
        record(n + 1, delta);
    }
    conn.execute_batch("COMMIT").unwrap();
    let inserted = insert.elapsed();
    let pool = db.read_pool().unwrap();
    let before_rss = rss_bytes();
    let started = Instant::now();
    let cold = pool.note_state(key).unwrap();
    let cold_time = started.elapsed();
    let after_rss = rss_bytes();
    let seed = db.begin_checkpoint(key).unwrap().unwrap();
    let mut job = seed.start().unwrap();
    let encode = Instant::now();
    let mut visited = 0;
    loop {
        let page = db.checkpoint_page(&job, 256).unwrap();
        if page.is_empty() {
            break;
        }
        visited += page.len();
        job.apply_page(&page).unwrap();
    }
    let checkpoint = job.finish().unwrap().unwrap();
    let compact_time = encode.elapsed();
    let checkpoint_bytes = checkpoint.encoded_bytes();
    let rss_after_checkpoint = rss_bytes();
    assert!(db.publish_checkpoint(&checkpoint).unwrap());
    let started = Instant::now();
    let healthy = pool.note_state(key).unwrap();
    let healthy_time = started.elapsed();
    assert_eq!(
        cold.state, healthy.state,
        "checkpoint must reproduce the actual growing/churned document"
    );
    assert_eq!(cold.rows, updates + 1);
    assert_eq!(healthy.rows, 0);
    eprintln!(
        "real-yjs shape={shape} updates={updates} written_delta_bytes={written_bytes} insert={inserted:?} cold_open={cold_time:?} cold_rows={} cold_bytes={} checkpoint_encode={compact_time:?} compact_rows={visited} checkpoint_bytes={checkpoint_bytes} healthy_open={healthy_time:?} healthy_rows={} healthy_bytes={} rss_start={rss_start:?} rss_before_cold={before_rss:?} rss_after_cold={after_rss:?} rss_after_checkpoint={rss_after_checkpoint:?}",
        cold.rows, cold.bytes, healthy.rows, healthy.bytes
    );
}
#[test]
#[ignore = "opt-in large pending list and local backfill measurement"]
fn ten_thousand_offline_edited_notes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("offline.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    let conn = Connection::open(&path).unwrap();
    let delta = bh_core::note::Note::new()
        .unwrap()
        .append_paragraph("offline draft")
        .unwrap();
    let scope = scope();
    let started = Instant::now();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    for id in 0..10_000u64 {
        let mut note = [0u8; 32];
        note[..8].copy_from_slice(&id.to_be_bytes());
        let request = id.to_be_bytes();
        conn.execute(
            "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
            params![
                scope.base.as_slice(),
                scope.audience.as_slice(),
                note.as_slice(),
                [request.as_slice(), &[0; 8]].concat(),
                delta.as_slice()
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO pending_note_work(update_id) VALUES (?1)",
            [(id + 1) as i64],
        )
        .unwrap();
    }
    conn.execute_batch("COMMIT").unwrap();
    let inserted = started.elapsed();
    let started = Instant::now();
    let mut batches = 0;
    loop {
        batches += 1;
        if db.backfill_pending_scope(256).unwrap() {
            break;
        }
    }
    let backfill = started.elapsed();
    let started = Instant::now();
    let (mut after, mut pages, mut visited) = (0i64, 0usize, 0usize);
    loop {
        let page = db
            .pending_page(scope.base, scope.audience, None, after, 256, 256 * 1024)
            .unwrap();
        if page.rows.is_empty() {
            break;
        }
        visited += page.rows.len();
        pages += 1;
        if let Some(next) = page.next {
            after = next;
        } else {
            break;
        }
    }
    let enumeration = started.elapsed();
    assert_eq!(visited, 10_000);
    let mut note = [0u8; 32];
    note[..8].copy_from_slice(&9_999u64.to_be_bytes());
    let opened = db
        .read_pool()
        .unwrap()
        .note_state(NoteKey { note, ..scope })
        .unwrap();
    assert_eq!(opened.rows, 1);
    eprintln!(
        "offline_notes=10000 rows=10000 delta_bytes={} insert={inserted:?} backfill={backfill:?} backfill_batches={batches} pending_pages={pages} pending_enumeration={enumeration:?} last_note_open_rows={} rss={:?}",
        delta.len(),
        opened.rows,
        rss_bytes()
    );
}
#[test]
#[ignore = "explicit scale run; expensive real Yjs growth/churn"]
fn real_mib_growth_and_churn() {
    let dir = tempfile::tempdir().unwrap();
    let counts = if std::env::var_os("BH_LOCAL_GROWTH_MILLION").is_some() {
        vec![1000, 10000, 100000, 1000000]
    } else {
        vec![1000, 10000, 100000]
    };
    let max = std::env::var("BH_LOCAL_GROWTH_MAX")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(usize::MAX);
    let only = std::env::var("BH_LOCAL_GROWTH_ONLY")
        .ok()
        .and_then(|v| v.parse::<usize>().ok());
    let only_shape = std::env::var("BH_LOCAL_GROWTH_SHAPE").ok();
    for count in counts
        .into_iter()
        .filter(|count| *count <= max && only.is_none_or(|only| *count == only))
    {
        for shape in ["grow", "churn"]
            .into_iter()
            .filter(|shape| only_shape.as_deref().is_none_or(|only| *shape == only))
        {
            run(
                &dir.path().join(format!("{shape}-{count}.db")),
                shape,
                count,
            );
        }
    }
}
