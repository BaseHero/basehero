//! Opt-in Note projection measurements; never part of affected checks.
//!
//! `cargo run --release -p bh-storage --features testkit --example note_projection_bench`
//! prints paired same-run baseline/projection commit p95s and a 100k-note
//! v13 step time, write-ahead log peak and database growth. `--notes N` and
//! `--paired-notes N` change the sizes, so `--paired-notes 100000` runs the
//! commit comparison on the same B-tree depth as the upgrade. It makes no
//! acceptance claim.
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use bh_core::note::Note;
use bh_storage::{DeviceDatabase, NoteKey};
use rusqlite::Connection;

const BASE: [u8; 32] = [2; 32];
const AUDIENCE: [u8; 32] = [0; 32];
const ANCHOR: [u8; 32] = [4; 32];
const DEFAULT_PAIRED: usize = 400;
const DEFAULT_UPGRADE: usize = 100_000;
const WARMUP: usize = 40;

fn p95(values: &mut [u128]) -> u128 {
    values.sort_unstable();
    values[(values.len() - 1) * 95 / 100]
}

fn file_bytes(path: &Path) -> u64 {
    std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
}

fn wal_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push("-wal");
    PathBuf::from(name)
}

/// Samples the write-ahead log while a step runs, so its peak is reported
/// rather than only its resting size.
struct WalPeak {
    stop: Arc<AtomicBool>,
    peak: Arc<AtomicU64>,
    sampler: Option<thread::JoinHandle<()>>,
}

impl WalPeak {
    fn start(wal: PathBuf) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU64::new(file_bytes(&wal)));
        let sampler = {
            let stop = stop.clone();
            let peak = peak.clone();
            thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    peak.fetch_max(file_bytes(&wal), Ordering::Relaxed);
                    thread::sleep(Duration::from_micros(200));
                }
            })
        };
        Self {
            stop,
            peak,
            sampler: Some(sampler),
        }
    }

    fn finish(mut self) -> u64 {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(sampler) = self.sampler.take() {
            sampler.join().ok();
        }
        self.peak.load(Ordering::Relaxed)
    }
}

fn paired_commit(path: &Path, notes: usize) {
    let mut db = DeviceDatabase::open(path).unwrap();
    db.commit_account_verified(ANCHOR, &[b"genesis"], 1, [5; 32], false)
        .unwrap();
    let mut keys = Vec::with_capacity(notes);
    for _ in 0..notes {
        let note = db.create_note(BASE, AUDIENCE).unwrap();
        keys.push(NoteKey {
            base: BASE,
            audience: AUDIENCE,
            note,
        });
    }
    let warmup = WARMUP.min(notes / 10);
    let (mut baseline, mut projection) = (Vec::new(), Vec::new());
    for (index, key) in keys.into_iter().enumerate() {
        let delta = Note::new()
            .unwrap()
            .append_paragraph(&format!("sample {index}"))
            .unwrap();
        let started = Instant::now();
        if index % 2 == 0 {
            db.commit_working_update_with_title_baseline(
                key,
                0,
                ANCHOR,
                [index as u8; 16],
                &delta,
                "sample",
            )
            .unwrap();
            let elapsed = started.elapsed().as_micros();
            if index >= warmup {
                baseline.push(elapsed);
            }
        } else {
            db.commit_working_update_with_title(
                key,
                0,
                ANCHOR,
                [index as u8; 16],
                &delta,
                "sample",
            )
            .unwrap();
            let elapsed = started.elapsed().as_micros();
            if index >= warmup {
                projection.push(elapsed);
            }
        }
    }
    let (baseline, projection) = (p95(&mut baseline), p95(&mut projection));
    println!(
        "{{\"kind\":\"paired-note-commit\",\"notes\":{},\"samples\":{},\"baseline_p95_us\":{},\"projection_p95_us\":{},\"ratio\":{:.6}}}",
        notes,
        notes - warmup,
        baseline,
        projection,
        projection as f64 / baseline as f64
    );
}

fn drop_typed_layout(conn: &Connection) {
    conn.execute_batch(
        "DROP TABLE IF EXISTS data_fts; DROP TABLE IF EXISTS note_projection_repair;",
    )
    .unwrap();
    loop {
        let names: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'data_%' ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        if names.is_empty() {
            break;
        }
        for name in names {
            conn.execute_batch(&format!("DROP TABLE IF EXISTS \"{name}\""))
                .unwrap();
        }
    }
    if conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='sqlite_sequence')",
            [],
            |r| r.get::<_, bool>(0),
        )
        .unwrap()
    {
        conn.execute("DELETE FROM sqlite_sequence", []).unwrap();
    }
}

fn v13_step(path: &Path, notes: usize) {
    drop(DeviceDatabase::open(path).unwrap());
    let mut conn = Connection::open(path).unwrap();
    conn.execute(
        "UPDATE note_counter SET value=?1 WHERE id=1",
        [notes as i64],
    )
    .unwrap();
    {
        let tx = conn.transaction().unwrap();
        {
            let mut insert = tx
                .prepare(
                    "INSERT INTO notes(base,audience,note,touched,title) VALUES(?1,?2,?3,?4,?5)",
                )
                .unwrap();
            for n in 0..notes {
                let mut note = [0u8; 32];
                note[..8].copy_from_slice(&(n as u64).to_be_bytes());
                insert
                    .execute(rusqlite::params![
                        BASE.as_slice(),
                        AUDIENCE.as_slice(),
                        note.as_slice(),
                        (n + 1) as i64,
                        format!("note {n}")
                    ])
                    .unwrap();
            }
        }
        tx.commit().unwrap();
    }
    drop_typed_layout(&conn);
    conn.pragma_update(None, "user_version", 12u32).unwrap();
    drop(conn);

    // A closed connection leaves a checkpointed database, so the sizes below
    // separate the derived layout the step adds from what was already there.
    let db_before = file_bytes(path);
    let peak = WalPeak::start(wal_path(path));
    let started = Instant::now();
    let db = DeviceDatabase::open(path).unwrap();
    let first_open = started.elapsed().as_micros();
    assert_eq!(db.data_version(), 13);
    drop(db);
    let wal_peak = peak.finish();
    let db_after = file_bytes(path);
    let started = Instant::now();
    drop(DeviceDatabase::open(path).unwrap());
    let reopen = started.elapsed().as_micros();
    println!(
        "{{\"kind\":\"v13-step\",\"notes\":{},\"first_open_us\":{},\"ordinary_reopen_us\":{},\"db_before_bytes\":{},\"db_after_bytes\":{},\"db_growth_bytes\":{},\"wal_peak_bytes\":{}}}",
        notes,
        first_open,
        reopen,
        db_before,
        db_after,
        db_after.saturating_sub(db_before),
        wal_peak
    );
    let raw = Connection::open(path).unwrap();
    let seeded: i64 = raw
        .query_row("SELECT count(*) FROM data_record", [], |r| r.get(0))
        .unwrap();
    assert_eq!(seeded, notes as i64);
}

fn usage() -> ! {
    eprintln!("usage: note_projection_bench [--notes N] [--paired-notes N]");
    std::process::exit(2);
}

#[cfg(feature = "testkit")]
fn main() {
    let mut upgrade_notes = DEFAULT_UPGRADE;
    let mut paired_notes = DEFAULT_PAIRED;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--notes" => {
                upgrade_notes = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--paired-notes" => {
                paired_notes = args
                    .next()
                    .and_then(|value| value.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            _ => usage(),
        }
    }
    let dir = tempfile::tempdir().unwrap();
    paired_commit(&dir.path().join("paired.sqlite"), paired_notes);
    v13_step(&dir.path().join("upgrade.sqlite"), upgrade_notes);
}

#[cfg(not(feature = "testkit"))]
fn main() {
    eprintln!("run with --features testkit");
    std::process::exit(2);
}
