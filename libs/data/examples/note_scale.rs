//! Typed Note projection/extraction fixture, no real writer/transport proof.
//! Synthetic bodies live in BodyText, never in record JSON or an output file.
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
    sync::mpsc,
    time::Instant,
};

use bh_data::{
    DataError, FieldPath, KeyRef, Position, RecordId, Scope, TypeId,
    catalogue::Shipped,
    note,
    query::{self, Budget, Completeness, Page, Query, QueryError, SortKey, TextMatch, TypeSelect},
    store::{coverage, records},
    text::{self, BodyText},
};
use rusqlite::Connection;

const SCOPE: Scope = Scope {
    base: [42; 32],
    audience: [0; 32],
};
const SAMPLES: usize = 120;
const STEP_VM: u64 = 3_000;
const STEP_JOBS: usize = 4;

fn id(n: usize) -> RecordId {
    let mut bytes = [7; 32];
    bytes[..8].copy_from_slice(&(n as u64).to_be_bytes());
    RecordId(bytes)
}
fn number(id: RecordId) -> usize {
    usize::try_from(u64::from_be_bytes(id.0[..8].try_into().unwrap())).unwrap()
}
struct Bodies {
    count: usize,
    fixtures: Vec<String>,
    unavailable: Option<usize>,
}
impl Bodies {
    fn new(count: usize) -> Self {
        // A shared set of four independent allocations: 16, 32, 64, 256 KiB.
        // Only the last SAMPLES notes use non-empty bodies; this is NOT a
        // simulation of 100k separately materialised canonical Yjs documents.
        let fixtures = [16, 32, 64, 256]
            .into_iter()
            .map(|kib| {
                let mut s = format!("fixturetoken{kib} ");
                s.push_str(&"x".repeat(kib * 1024 - s.len()));
                s
            })
            .collect();
        Self {
            count,
            fixtures,
            unavailable: None,
        }
    }
}
impl BodyText for Bodies {
    fn body_text(&self, scope: Scope, record: RecordId) -> Result<Option<String>, DataError> {
        assert_eq!(scope, SCOPE);
        let n = number(record);
        if self.unavailable == Some(n) {
            return Ok(None);
        }
        if n >= self.count - SAMPLES {
            Ok(Some(self.fixtures[n % 4].clone()))
        } else {
            Ok(Some(String::new()))
        }
    }
}
fn recent_query() -> Query {
    Query {
        select: TypeSelect::Family(TypeId::core("note")),
        filter: None,
        sort: vec![SortKey {
            key: KeyRef::Changed,
            desc: true,
        }],
        fields: vec![FieldPath::parse("/title").unwrap()],
        follow: vec![],
        text: None,
        limit: 50,
        after: None,
    }
}
fn search_query(rev: u64) -> Query {
    Query {
        sort: vec![], // FTS-driven search, not a full-library sorted text page.
        text: Some(TextMatch {
            terms: "fixturetoken256".into(),
            on: None,
            require_revision: Some(rev),
        }),
        ..recent_query()
    }
}
fn percentile(values: &mut [u128], pct: usize) -> u128 {
    values.sort_unstable();
    values[(values.len() - 1) * pct / 100]
}
fn stats(values: &mut [u128]) -> String {
    assert!(values.len() >= 60, "at least 60 measurements required");
    format!(
        "{}/{}/{}",
        percentile(values, 50),
        percentile(values, 95),
        values.last().unwrap()
    )
}
fn pragmas(conn: &Connection) -> Result<String, Box<dyn std::error::Error>> {
    let journal: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    let sync: i64 = conn.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    let page: i64 = conn.query_row("PRAGMA page_size", [], |r| r.get(0))?;
    Ok(format!(
        "journal_mode={journal}; synchronous={sync} (FULL=2); page_size={page}"
    ))
}
fn disk(path: &Path) -> io::Result<u64> {
    let mut bytes = fs::metadata(path)?.len(); // The main database is required.
    for sidecar in [
        path.with_extension("sqlite-wal"),
        path.with_extension("sqlite-shm"),
    ] {
        match fs::metadata(sidecar) {
            Ok(meta) => bytes += meta.len(),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(bytes)
}
fn assert_recent_page(page: &Page, expected: &[RecordId]) {
    assert_eq!(page.completeness, Completeness::Complete);
    let actual: Vec<_> = page.rows.iter().map(|row| row.record).collect();
    assert_eq!(actual, expected, "newest Note IDs in descending recency");
}
fn jobs(conn: &Connection) -> rusqlite::Result<i64> {
    conn.query_row("SELECT count(*) FROM data_text_job", [], |r| r.get(0))
}
fn seed(conn: &mut Connection, count: usize) -> Result<(), Box<dyn std::error::Error>> {
    for start in (0..count).step_by(250) {
        let tx = conn.transaction()?;
        for n in start..(start + 250).min(count) {
            note::upsert_projection(&tx, SCOPE, id(n), &format!("Note {n:08}"))?;
        }
        tx.commit()?;
        if start % 10_000 == 0 {
            eprintln!("seed {start}/{count}");
        }
    }
    Ok(())
}
fn drain(
    conn: &mut Connection,
    body: &Bodies,
    target: i64,
) -> Result<(Vec<u128>, usize), Box<dyn std::error::Error>> {
    let mut holds = vec![];
    let mut completed = 0;
    // One bounded turn followed by a yield: no high-priority spin over an
    // unavailable source. Caller ensures progress / caps retries.
    while jobs(conn)? > target {
        let start = Instant::now();
        let done = text::extract_step_bounded(conn, body, 32, 30_000)?;
        holds.push(start.elapsed().as_micros());
        completed += done;
        if done == 0 {
            return Err("no progress draining available bodies".into());
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Ok((holds, completed))
}
fn run(count: usize, out: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    if count < SAMPLES + 50 {
        return Err("--records must be at least 170".into());
    }
    if out.exists() {
        if !out.is_dir() || fs::read_dir(&out)?.next().is_some() {
            return Err("output directory is not empty; use a disposable directory".into());
        }
    } else {
        fs::create_dir(&out)?;
    }
    let db = out.join("note.sqlite");
    let mut conn = Connection::open(&db)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000",
    )?;
    let tx = conn.transaction()?;
    bh_data::store::migrate(&tx)?;
    tx.commit()?;
    let config = pragmas(&conn)?;
    let bodies = Bodies::new(count);
    let start = Instant::now();
    seed(&mut conn, count)?;
    // Synthetic *complete* fixture: assume authenticated coverage of this
    // entire scope after seeding. Projection writes alone cannot establish it;
    // this is not login, sync transport, or a verified ordered log.
    let tx = conn.transaction()?;
    let sid = records::lookup_scope(&tx, SCOPE)?.ok_or("seeded scope missing")?;
    coverage::set(&tx, sid, Position(0), true)?;
    tx.commit()?;
    let seed_time = start.elapsed().as_secs_f64();
    let setup_bytes = disk(&db)?;
    let queued_seed = jobs(&conn)?;
    assert_eq!(queued_seed, count as i64);
    let baseline_start = Instant::now();
    let (initial_holds, initial_done) = drain(&mut conn, &bodies, 0)?;
    let baseline_seconds = baseline_start.elapsed().as_secs_f64();
    assert_eq!(initial_done, count);
    let after_extract_bytes = disk(&db)?;
    let title_json_bytes: i64 =
        conn.query_row("SELECT sum(length(accepted)) FROM data_record", [], |r| {
            r.get(0)
        })?;

    let query = recent_query();
    let expected_recent: Vec<_> = (count - 50..count).rev().map(id).collect();
    let mut pages = vec![];
    for _ in 0..60 {
        let start = Instant::now();
        let result = query::run(
            &conn,
            SCOPE,
            &[SCOPE],
            &Shipped,
            &query,
            Budget::INTERACTIVE,
        )
        .map_err(|e| format!("{e:?}"))?;
        let elapsed_us = start.elapsed().as_micros();
        assert_recent_page(&result, &expected_recent);
        pages.push(elapsed_us);
    }
    let mut projections = vec![];
    let mut body_edits = vec![];
    let mut revisions = vec![];
    // A separate measured projection update and three synthetic body-only
    // notifications per distinct Note, leaving the projected title unchanged.
    for n in count - SAMPLES..count {
        let start = Instant::now();
        let tx = conn.transaction()?;
        note::upsert_projection(&tx, SCOPE, id(n), &format!("Updated {n:08}"))?;
        tx.commit()?;
        projections.push(start.elapsed().as_micros());
        let sid = records::lookup_scope(&conn, SCOPE)?.ok_or("missing scope")?;
        for _ in 0..3 {
            let start = Instant::now();
            let tx = conn.transaction()?;
            let row = records::get(&tx, sid, id(n))?.ok_or("missing note")?;
            assert_eq!(
                row.accepted.as_ref().unwrap()["title"],
                format!("Updated {n:08}")
            );
            revisions.push(text::body_changed(&tx, &row)?);
            tx.commit()?;
            body_edits.push(start.elapsed().as_micros());
        }
    }
    let required = *revisions.last().unwrap();
    let burst_jobs = jobs(&conn)?;
    assert_eq!(burst_jobs, SAMPLES as i64, "one coalesced job per Note");
    let behind = text::watermark(&conn, SCOPE)?;
    assert!(behind.complete_through < required);
    assert!(matches!(
        query::run(
            &conn,
            SCOPE,
            &[SCOPE],
            &Shipped,
            &search_query(required),
            Budget::INTERACTIVE
        ),
        Err(QueryError::TextBehind { .. })
    ));
    // A fetched job becomes obsolete after a second body notification.
    let obsolete = text::next_jobs(&conn, 1)?.remove(0);
    let sid = records::lookup_scope(&conn, SCOPE)?.ok_or("missing scope")?;
    let tx = conn.transaction()?;
    let row = records::get(&tx, sid, obsolete.record)?.ok_or("obsolete note missing")?;
    text::body_changed(&tx, &row)?;
    tx.commit()?;
    let tx = conn.transaction()?;
    assert!(!text::store_extracted(&tx, &obsolete, "obsoletefixture")?);
    tx.commit()?;
    assert_eq!(jobs(&conn)?, burst_jobs);
    // Missing body is retried after reopening; persisted cursor lets later
    // jobs progress. No tight loop when the only outstanding body is missing.
    let missing = count - 2;
    let unavailable = Bodies {
        unavailable: Some(missing),
        ..bodies
    };
    drop(conn);
    let reopen_start = Instant::now();
    let mut conn = Connection::open(&db)?;
    conn.execute_batch("PRAGMA busy_timeout=5000")?;
    let reopened = query::run(
        &conn,
        SCOPE,
        &[SCOPE],
        &Shipped,
        &query,
        Budget::INTERACTIVE,
    )
    .map_err(|e| format!("{e:?}"))?;
    let reopen_us = reopen_start.elapsed().as_micros();
    assert_recent_page(&reopened, &expected_recent);
    assert_eq!(jobs(&conn)?, burst_jobs);
    let mut step_times = vec![];
    let mut waits = vec![];
    let mut completed = 0;
    let (requests, received) = mpsc::channel::<(usize, Instant)>();
    let (ack, acknowledgements) = mpsc::channel::<()>();
    requests.send((0, Instant::now()))?;
    let producer = std::thread::spawn(move || {
        for n in 1..60 {
            if acknowledgements.recv().is_err() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
            if requests.send((n, Instant::now())).is_err() {
                break;
            }
        }
    });
    let catchup_start = Instant::now();
    // A producer enqueues foreground edits while a single writer connection
    // runs bounded extraction turns. The writer serves one waiting edit after
    // each turn; no competing writer transaction or busy-snapshot retry loop.
    for step in 0..SAMPLES * 3 {
        let start = Instant::now();
        let done = text::extract_step_bounded(&mut conn, &unavailable, STEP_JOBS, STEP_VM)
            .map_err(|e| format!("extraction step {step}: {e}"))?;
        step_times.push(start.elapsed().as_micros());
        completed += done;
        if let Ok((n, queued)) = received.try_recv() {
            let tx = conn.transaction()?;
            note::upsert_projection(&tx, SCOPE, id(n), &format!("Foreground {n:08}"))?;
            tx.commit()?;
            waits.push(queued.elapsed().as_micros());
            let _ = ack.send(()); // final acknowledgement may outlive the producer
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
        if jobs(&conn)? == 1 && completed >= SAMPLES - 1 && waits.len() == 60 {
            break;
        }
    }
    let lag_unavailable = catchup_start.elapsed().as_millis();
    drop(ack);
    producer
        .join()
        .map_err(|_| "foreground producer panicked")?;
    assert_eq!(waits.len(), 60);
    assert_eq!(jobs(&conn)?, 1);
    assert_eq!(completed, SAMPLES - 1 + 60);
    assert!(text::watermark(&conn, SCOPE)?.complete_through < required);
    assert!(matches!(
        query::run(
            &conn,
            SCOPE,
            &[SCOPE],
            &Shipped,
            &search_query(required),
            Budget::INTERACTIVE
        ),
        Err(QueryError::TextBehind { .. })
    ));
    let available = Bodies::new(count);
    let start = Instant::now();
    assert_eq!(
        text::extract_step_bounded(&mut conn, &available, STEP_JOBS, STEP_VM)?,
        1
    );
    let recovered_us = start.elapsed().as_micros();
    assert_eq!(jobs(&conn)?, 0);
    let fresh = text::watermark(&conn, SCOPE)?;
    assert!(fresh.complete_through >= required);
    let matched = query::run(
        &conn,
        SCOPE,
        &[SCOPE],
        &Shipped,
        &search_query(required),
        Budget::INTERACTIVE,
    )
    .map_err(|e| format!("{e:?}"))?;
    assert_eq!(matched.rows.len(), 30); // One of four fixture sizes among 120 Notes.
    assert_eq!(matched.completeness, Completeness::Complete);
    // The same selective matches must support recent ordering at the unchanged
    // interactive budget; compare identities, not the two different sort orders.
    let sorted_search = Query {
        sort: recent_query().sort,
        ..search_query(required)
    };
    let sorted = query::run(
        &conn,
        SCOPE,
        &[SCOPE],
        &Shipped,
        &sorted_search,
        Budget::INTERACTIVE,
    )
    .map_err(|e| format!("sorted selective search: {e:?}"))?;
    assert_eq!(sorted.completeness, Completeness::Complete);
    let mut unsorted_ids: Vec<_> = matched.rows.iter().map(|row| row.record).collect();
    let mut sorted_ids: Vec<_> = sorted.rows.iter().map(|row| row.record).collect();
    unsorted_ids.sort_unstable();
    sorted_ids.sort_unstable();
    assert_eq!(sorted_ids, unsorted_ids, "sorted and unsorted Note matches");
    let expected_ids: Vec<_> = (count - SAMPLES..count)
        .filter(|n| n % 4 == 3)
        .map(id)
        .collect();
    assert_eq!(sorted_ids, expected_ids, "the 30 fixturetoken256 Notes");
    let sorted_status = format!("{} matching IDs, Complete", sorted_ids.len());
    let storage = disk(&db)?;
    let load = Command::new("uptime")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unavailable".into());
    let cpu = fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find(|s| s.starts_with("model name") || s.starts_with("Hardware"))
        .unwrap_or("not exposed")
        .to_owned();
    let report = format!(
        "# Typed Note projection/extraction fixture, no real writer/transport proof\n\nHost: {} {}; CPU: {cpu}; load at report: {load}; profile: {}; SQLite: {config}.\n\nRecords: {count} lightweight Note projections; body fixtures: 4 shared in-memory plain-text templates of 16/32/64/256 KiB for the last {SAMPLES} Notes; remaining bodies empty. Synthetic complete fixture: after seeding, scope coverage is explicitly set assuming authenticated full-fixture coverage; this is not real login, ordered-log verification or transport. Not Yjs, not canonical Note store, not a real Note writer, sync or device measurement. Titles only in JSON; no body in record JSON. File-backed WAL/FULL.\n\nSetup seed: {seed_time:.3} s; DB+WAL+SHM: {setup_bytes} bytes ({:.1} bytes/record, {:.2}x stored title JSON); initially queued: {queued_seed}; first bounded extraction: {baseline_seconds:.3} s, {initial_done} completions, {} steps; DB+WAL+SHM after: {after_extract_bytes} bytes ({:.1} bytes/record); final: {storage} bytes. WAL sizes include uncheckpointed and reusable pages, not just live payload.\n\n| Metric (µs unless stated) | p50/p95/max | Samples |\n|---|---:|---:|\n| 50-row recent Note page | {} | {} |\n| projection update (title) | {} | {} |\n| body-only notification (title unchanged) | {} | {} |\n| bounded extraction turn wall-time (writer-hold upper bound, includes BodyText and seek) | {} | {} |\n| FIFO foreground enqueue → committed edit (includes extraction turn wait) | {} | {} |\n\nBurst: {SAMPLES} distinct Notes, 3 body notifications per Note + one projection update; {burst_jobs} coalesced jobs (360 body notifications); required content_rev {required}; before extraction watermark {:?}; search at required revision returned TextBehind. Stale extracted job rejected after newer revision; 1 unavailable body persisted through restart and extraction turns, while {} bodies progressed (119 burst + 60 interleaved foreground jobs); still TextBehind at {lag_unavailable} ms. After availability: one step {recovered_us} µs, watermark {:?}, search at required revision matched {} Note bodies (expected 30). Reopen mid-queue plus first page: {reopen_us} µs, no log/history replay. Sorted text + recent order with the unchanged interactive budget: {sorted_status}, the same 30 IDs as fresh unsorted search; both queries returned Complete. This is separate from the historical pre-fix sorted TooCostly evidence. Catch-up lag includes 1 ms per-turn yield; progress is bounded by {STEP_JOBS} attempts and {STEP_VM} SQLite VM write steps per turn. Initial extraction (32 attempts, 30,000 VM cap, 1 ms yield) per-turn wall p50/p95/max {} µs over {} steps.\n\nLimit: per-step wall is only an upper bound on SQLite writer hold; extraction API does not expose transaction timing. Foreground request timing includes one serialized extraction turn, scheduling, edit and commit, not a separately measured lock wait. An attempted simultaneous two-connection smoke failed with SQLite busy-snapshot; see evidence concern. No real writer, transport, independent 100k Note bodies, physical phone, or acceptance-budget assertion.\n",
        env::consts::OS,
        env::consts::ARCH,
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        setup_bytes as f64 / count as f64,
        setup_bytes as f64 / title_json_bytes as f64,
        initial_holds.len(),
        after_extract_bytes as f64 / count as f64,
        stats(&mut pages),
        pages.len(),
        stats(&mut projections),
        projections.len(),
        stats(&mut body_edits),
        body_edits.len(),
        stats(&mut step_times),
        step_times.len(),
        stats(&mut waits),
        waits.len(),
        behind,
        completed,
        fresh,
        matched.rows.len(),
        if initial_holds.len() >= 60 {
            stats(&mut initial_holds.clone())
        } else {
            "n/a (smoke: fewer than 60 steps)".into()
        },
        initial_holds.len()
    );
    fs::write(out.join("note_scale.md"), &report)?;
    println!("{report}");
    Ok(())
}
fn main() {
    let mut count = 100_000;
    let mut out = None;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--records" => {
                count = args
                    .next()
                    .expect("--records value")
                    .parse()
                    .expect("numeric records")
            }
            "--out" => out = Some(PathBuf::from(args.next().expect("--out value"))),
            _ => {
                eprintln!("unknown option {arg}");
                std::process::exit(2);
            }
        }
    }
    if let Err(error) = run(count, out.expect("--out required")) {
        eprintln!("note_scale failed: {error}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn small_fixture_restart_obsolete_and_freshness() {
        let dir = tempfile::tempdir().unwrap();
        run(180, dir.path().join("smoke")).unwrap();
    }
    #[test]
    fn disk_requires_main_database_but_not_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("note.sqlite");
        assert_eq!(disk(&db).unwrap_err().kind(), io::ErrorKind::NotFound);
        fs::write(&db, b"main").unwrap();
        assert_eq!(disk(&db).unwrap(), 4);
        fs::write(db.with_extension("sqlite-wal"), b"wal").unwrap();
        assert_eq!(disk(&db).unwrap(), 7);
    }
    #[cfg(unix)]
    #[test]
    fn disk_propagates_unexpected_sidecar_metadata_error() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("note.sqlite");
        fs::write(&db, b"main").unwrap();
        let wal = db.with_extension("sqlite-wal");
        symlink(&wal, &wal).unwrap(); // ELOOP is not an absent optional sidecar.
        assert_ne!(disk(&db).unwrap_err().kind(), io::ErrorKind::NotFound);
    }
    #[test]
    fn body_sizes_and_no_record_payload() {
        let b = Bodies::new(180);
        for (i, expected) in [16, 32, 64, 256].iter().enumerate() {
            assert_eq!(
                b.body_text(SCOPE, id(60 + i)).unwrap().unwrap().len(),
                expected * 1024
            );
        }
    }
}
