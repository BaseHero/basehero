//! Release-mode budgets for encrypted folder backups and offline checking.
#![cfg(not(debug_assertions))]

use bh_core::{
    Account, BackupLocation, Base, Clock, Core, FileStatus, LocalFolder, ManualClock, ObjectId,
    list_backups,
};
use bh_testkit::{
    TEST_PASSWORD, append_text, device, device_with_clock, folder::MemoryFolder, generate,
    new_signup,
};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const DAY: Duration = Duration::from_secs(86_400);
const NOTES: usize = 300;
const SESSIONS: usize = 50_000;
const FILES: usize = 1_000;
const FILE_SIZE: usize = 64 * 1024;

fn load() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .unwrap_or_else(|_| "unavailable".into())
        .split_whitespace()
        .take(3)
        .collect::<Vec<_>>()
        .join("/")
}

struct Year {
    core: Core,
    account: Account,
    base: Base,
    notes: Vec<ObjectId>,
    kit: String,
    folder: Arc<LocalFolder>,
    _dir: tempfile::TempDir,
}

static YEAR: tokio::sync::OnceCell<Year> = tokio::sync::OnceCell::const_new();
static FIRST: tokio::sync::OnceCell<Duration> = tokio::sync::OnceCell::const_new();

async fn year() -> &'static Year {
    YEAR.get_or_init(|| async {
        let core = device("backup-scale");
        let (account, kit) = core.sign_up(new_signup()).await.unwrap();
        let base = account.create_base("Year").await.unwrap();
        let notes = generate::year_of_editing(&base, NOTES, SESSIONS).await;
        let files = generate::files(&base, None, FILES, FILE_SIZE);
        assert_eq!(files.len(), FILES);
        // File uploads update object state asynchronously; settle them before
        // measuring a backup that is supposed to contain exactly one new edit.
        tokio::time::timeout(Duration::from_secs(60), async {
            while !files.iter().all(|&id| {
                base.file(id)
                    .unwrap()
                    .is_some_and(|file| file.status == FileStatus::Here)
            }) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("file uploads finished");
        base.flush().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let folder = Arc::new(LocalFolder::new(dir.path().to_path_buf()));
        account
            .set_backup(Some(BackupLocation::Path {
                path: dir.path().to_path_buf(),
                label: "Backup".into(),
            }))
            .unwrap();
        Year {
            core,
            account,
            base,
            notes,
            kit: kit.display(),
            folder,
            _dir: dir,
        }
    })
    .await
}

async fn first_backup() -> (&'static Year, Duration) {
    let fixture = year().await;
    let elapsed = *FIRST.get_or_init(|| async {
        let start = Instant::now();
        let run = fixture.account.backup_now().await.unwrap();
        let elapsed = start.elapsed();
        assert_eq!(run.snapshots, 1, "{run:?}");
        assert_eq!(run.objects, NOTES + FILES + 1, "{run:?}");
        assert_eq!(run.parts, FILES, "{run:?}");
        println!("first backup: {elapsed:?} for {NOTES} notes / {SESSIONS} sessions / {FILES} files of {FILE_SIZE} bytes (budget 30s), load={}", load());
        elapsed
    }).await;
    (fixture, elapsed)
}

#[tokio::test]
async fn a_first_backup_of_a_year_of_editing_and_1000_files_takes_under_30_s() {
    let (_, elapsed) = first_backup().await;
    assert!(
        elapsed < Duration::from_secs(30),
        "first backup: {elapsed:?}"
    );
}

#[tokio::test]
async fn a_run_after_one_edit_takes_under_250_ms() {
    let (fixture, _) = first_backup().await;
    let note = fixture.base.note(fixture.notes[0]).unwrap();
    note.apply(5, &append_text(&note.state(), "one more edit"))
        .unwrap();
    let start = Instant::now();
    let run = fixture.account.backup_now().await.unwrap();
    let elapsed = start.elapsed();
    println!(
        "backup after one edit: {elapsed:?} (budget 250ms), load={}",
        load()
    );
    assert_eq!(
        (run.objects, run.snapshots, run.parts),
        (1, 0, 0),
        "{run:?}"
    );
    assert!(
        elapsed < Duration::from_millis(250),
        "one-edit run: {elapsed:?}"
    );
}

#[tokio::test]
async fn restoring_a_year_of_editing_takes_under_15_s() {
    let (fixture, _) = first_backup().await;
    let start = Instant::now();
    let listing = list_backups(&*fixture.folder).unwrap();
    assert_eq!(listing.len(), 1);
    let opened = fixture
        .core
        .open_backup(
            fixture.folder.clone(),
            &listing[0],
            Zeroizing::new(TEST_PASSWORD.into()),
            &fixture.kit,
        )
        .await
        .unwrap();
    let point = opened.points()[0];
    let report = opened.check(point).await.unwrap();
    let elapsed = start.elapsed();
    println!(
        "offline open + check: {elapsed:?} for {NOTES} notes / {SESSIONS} sessions / {FILES} files (budget 15s), load={}",
        load()
    );
    assert_eq!(report.locked, 0, "{report:?}");
    assert_eq!(report.missing, 0, "{report:?}");
    assert!(report.ignored_files.is_empty(), "{report:?}");
    assert_eq!(report.bases.len(), 1, "{report:?}");
    assert_eq!(report.bases[0].id, fixture.base.id());
    assert_eq!(report.bases[0].objects, NOTES + FILES + 1, "{report:?}");
    assert_eq!(report.bases[0].unreadable, 0, "{report:?}");
    assert!(report.bases[0].missing_files.is_empty(), "{report:?}");
    assert!(
        elapsed < Duration::from_secs(15),
        "offline check: {elapsed:?}"
    );
}

#[tokio::test]
async fn a_month_of_daily_runs_keeps_the_folder_under_its_files_plus_six_snapshots() {
    let (clock, manual): (Clock, ManualClock) = Clock::manual();
    let core = device_with_clock("backup-month", &clock);
    let (account, _) = core.sign_up(new_signup()).await.unwrap();
    let base = account.create_base("Month").await.unwrap();
    let notes = generate::notes(&base, NOTES);
    let files = generate::files(&base, None, 10, FILE_SIZE);
    assert_eq!(files.len(), 10);
    tokio::time::timeout(Duration::from_secs(60), async {
        while !files.iter().all(|&id| {
            base.file(id)
                .unwrap()
                .is_some_and(|file| file.status == FileStatus::Here)
        }) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("file uploads finished");
    base.flush().await.unwrap();
    let folder = Arc::new(MemoryFolder::default());
    core.set_document_folders(folder.clone());
    account
        .set_backup(Some(BackupLocation::Document {
            uri: "memory".into(),
            label: "Backup".into(),
        }))
        .unwrap();
    let first = account.backup_now().await.unwrap();
    assert!(first.run.is_some(), "{first:?}");
    assert_eq!(first.objects, NOTES + files.len() + 1, "{first:?}");
    assert_eq!(first.parts, files.len(), "{first:?}");
    let start = Instant::now();
    for day in 0..30 {
        manual.advance(DAY);
        let edited: Vec<_> = (0..3).map(|edit| notes[(day * 3 + edit) % NOTES]).collect();
        for (edit, &id) in edited.iter().enumerate() {
            let note = base.note(id).unwrap();
            note.apply(
                5,
                &append_text(&note.state(), &format!("day {day} edit {edit}")),
            )
            .unwrap();
        }
        let run = account.backup_now().await.unwrap();
        assert!(run.run.is_some(), "day {day}: {run:?}");
        assert_eq!(run.parts, 0, "day {day}: {run:?}");
        if run.snapshots == 0 {
            let logs: Vec<_> = folder
                .files()
                .into_keys()
                .filter(|path| path.ends_with(".bhl"))
                .collect();
            let log = logs.iter().max().expect("daily run has a log");
            let records = bh_core::test_support::backup_records(&*folder, log).unwrap();
            let mut actual: Vec<_> = records
                .iter()
                .map(|record| {
                    assert_eq!(record[0], 0);
                    record[17..33].to_vec()
                })
                .collect();
            actual.sort();
            let mut expected: Vec<_> = edited.iter().map(|id| id.0.to_vec()).collect();
            expected.sort();
            assert_eq!(actual, expected, "day {day}");
        }
        assert_eq!(
            run.objects,
            if run.snapshots == 0 {
                3
            } else {
                NOTES + files.len() + 1
            },
            "day {day}: {run:?}"
        );
    }
    let elapsed = start.elapsed();
    let state_bytes = base.test_backup_state_bytes();
    let files = folder.files();
    let file_parts: u64 = files
        .iter()
        .filter(|(path, _)| path.contains("/files/"))
        .map(|(_, bytes)| bytes.len() as u64)
        .sum();
    let stored: u64 = files.values().map(|bytes| bytes.len() as u64).sum();
    let snapshots: Vec<_> = files
        .iter()
        .filter(|(path, _)| path.contains("/snapshots/"))
        .collect();
    let snapshot_bytes: u64 = snapshots.iter().map(|(_, bytes)| bytes.len() as u64).sum();
    let newest_snapshot_bytes = snapshots
        .iter()
        .max_by_key(|(path, _)| *path)
        .expect("month has a snapshot")
        .1
        .len() as u64;
    let limit = file_parts + 6 * newest_snapshot_bytes;
    println!(
        "30 daily runs: {elapsed:?}, folder={stored} bytes, state bytes={state_bytes}, sealed part bytes={file_parts}, snapshots={} ({snapshot_bytes} bytes), newest snapshot={newest_snapshot_bytes} bytes, other={} bytes, limit={limit} bytes, load={}",
        snapshots.len(),
        stored - file_parts - snapshot_bytes,
        load()
    );
    assert!(state_bytes > 0);
    assert!(file_parts > 0);
    assert_eq!(account.backup_estimate().unwrap(), state_bytes + file_parts);
    assert!(
        stored < limit,
        "folder {stored} >= file parts {file_parts} + six newest sealed snapshots {newest_snapshot_bytes} × 6"
    );
}
