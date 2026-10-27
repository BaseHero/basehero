//! Release-mode budgets against real local bases and the loopback Worker.
#![cfg(not(debug_assertions))]

use bh_core::{Account, Base, BaseId, FileStatus, NewFile, ObjectId};
use bh_testkit::{LocalServer, b64, generate, new_signup, raw_device, wait_for_base};
use serde_json::json;
use std::path::Path;
use std::time::{Duration, Instant};

fn load() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .unwrap_or_else(|_| "unavailable".into())
        .split_whitespace()
        .take(3)
        .collect::<Vec<_>>()
        .join("/")
}

fn persisted_sqlite_bytes(root: &Path) -> u64 {
    let mut dirs = vec![root.to_path_buf()];
    let mut size = 0;
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                dirs.push(entry.path());
            } else if entry.file_name().to_string_lossy().contains(".sqlite") {
                size += entry.metadata().unwrap().len();
            }
        }
    }
    size
}

async fn new_reader(account: &Account, base: BaseId, kit: &str) -> (Account, Base) {
    let reader = bh_testkit::device("scale-reader")
        .sign_in(bh_testkit::signin_for(account))
        .await
        .unwrap()
        .with_kit(kit)
        .await
        .unwrap();
    reader.refresh().await.unwrap();
    let opened = reader.base(base).unwrap();
    (reader, opened)
}

fn all_here(base: &Base, ids: &[ObjectId]) -> bool {
    ids.iter().all(|&id| {
        base.file(id)
            .unwrap()
            .is_some_and(|file| file.status == FileStatus::Here)
    })
}

#[tokio::test]
async fn a_100_mib_file_reaches_another_full_device_in_under_30_s() {
    let (account, kit) = bh_testkit::device("scale-writer")
        .sign_up(new_signup())
        .await
        .unwrap();
    let base = account.create_base("Large file").await.unwrap();
    base.flush().await.unwrap();
    let (_reader, other) = new_reader(&account, base.id(), &kit.display()).await;
    let content = bh_testkit::random(100 * 1024 * 1024);
    let start = Instant::now();
    let id = base
        .add_file(
            NewFile {
                parent: None,
                name: "large.bin".into(),
                mime: "application/octet-stream".into(),
            },
            &content,
        )
        .unwrap();
    base.flush().await.unwrap();
    let arrived = tokio::time::timeout(Duration::from_secs(30), async {
        while !all_here(&other, &[id]) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let elapsed = start.elapsed();
    println!(
        "100 MiB to second full device: {elapsed:?} (budget 30s), writer={:?}, reader={:?}, load={}",
        base.file(id).unwrap().map(|f| f.status),
        other.file(id).unwrap().map(|f| f.status),
        load()
    );
    assert!(
        arrived.is_ok(),
        "file did not arrive within the 30s safety deadline"
    );
    assert_eq!(other.file_bytes(id).await.unwrap(), content);
    assert!(elapsed < Duration::from_secs(30));
}

#[tokio::test]
async fn a_base_with_1000_files_opens_within_the_open_budget() {
    let (account, kit) = bh_testkit::device("scale-writer")
        .sign_up(new_signup())
        .await
        .unwrap();
    let base = account.create_base("Files and notes").await.unwrap();
    let notes = generate::notes(&base, 300);
    let files = generate::files(&base, None, 1_000, 64 * 1024);
    base.flush().await.unwrap();
    let start = Instant::now();
    let (_reader, other) = new_reader(&account, base.id(), &kit.display()).await;
    let notes_ready = tokio::time::timeout(Duration::from_secs(30), async {
        while !notes.iter().all(|&id| {
            other
                .note(id)
                .is_ok_and(|note| note.text().contains("project meeting notes"))
        }) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let notes_elapsed = start.elapsed();
    let count = notes.iter().filter(|&&id| other.note(id).is_ok()).count();
    println!(
        "new device: {count}/300 notes with text, 1000 files: {notes_elapsed:?} (budget 5s), load={}",
        load()
    );
    assert!(notes_ready.is_ok(), "notes did not arrive within 30s");
    assert!(notes_elapsed < Duration::from_secs(5));
    let files_ready = tokio::time::timeout(Duration::from_secs(30), async {
        while !all_here(&base, &files) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        base.flush().await.unwrap(); // All uploaded flags must reach the new device.
        while !all_here(&other, &files) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    let files_elapsed = start.elapsed();
    let count = files
        .iter()
        .filter(|&&id| {
            other
                .file(id)
                .unwrap()
                .is_some_and(|f| f.status == FileStatus::Here)
        })
        .count();
    let writer_ready = files
        .iter()
        .filter(|&&id| {
            base.file(id)
                .unwrap()
                .is_some_and(|f| f.status == FileStatus::Here)
        })
        .count();
    let waiting = files
        .iter()
        .filter(|&&id| {
            matches!(
                other.file(id).unwrap().map(|f| f.status),
                Some(FileStatus::Waiting)
            )
        })
        .count();
    let fetching = files
        .iter()
        .filter(|&&id| {
            matches!(
                other.file(id).unwrap().map(|f| f.status),
                Some(FileStatus::Fetching { .. })
            )
        })
        .count();
    println!(
        "new device: {count}/1000 files Here (writer {writer_ready}, waiting {waiting}, fetching {fetching}, writer outbox {}): {files_elapsed:?} (budget 30s), load={}",
        base.test_outbox().len(),
        load()
    );
    assert!(files_ready.is_ok(), "files did not arrive within 30s");
    assert!(files_elapsed < Duration::from_secs(30));
}

// The raw workload's bodies are deliberately opaque; put valid sealed states at
// both ends so restore exercises a real historical note and a valid latest state.
async fn storage_bytes(raw: &bh_testkit::RawDevice, base: BaseId) -> u64 {
    let (status, reply) = raw.get("/v1/usage", json!({})).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{reply}");
    reply["months"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["service"] == "storage" && row["base"] == base.to_string())
        .and_then(|row| row["storedBytes"].as_u64())
        .expect("base storage usage")
}

async fn version_fixture(server: &mut LocalServer) -> (Account, Base, ObjectId, u64, u64, u64) {
    let (account, _) =
        bh_testkit::device_on_server("scale-versions", &bh_core::Clock::system(), server)
            .sign_up(new_signup())
            .await
            .unwrap();
    let base = account.create_base("Versions").await.unwrap();
    let id = bh_testkit::note_with_text(&base, "before the year");
    base.flush().await.unwrap();
    server.restart();
    let raw = raw_device(&account);
    let before = storage_bytes(&raw, base.id()).await;
    let post_valid = |body: Vec<u8>, covers: u64| {
        json!({
            "changes": [{"changeId": bh_testkit::random_id(), "objectId": id,
                "kind": "state", "covers": covers, "keep": true, "body": b64(&body)}]
        })
    };
    let first_body = base.test_seal_state(id, &base.note(id).unwrap().state());
    let first_len = first_body.len() as u64;
    let first_covers = base.test_confirmed_seq(id);
    let (status, result) = raw
        .post(
            &format!("/v1/bases/{}/changes", base.id()),
            post_valid(first_body, first_covers),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{result}");
    let oldest = result["results"][0]["seq"].as_u64().unwrap();
    let note = base.note(id).unwrap();
    note.apply(5, &bh_testkit::append_text(&note.state(), "after the year"))
        .unwrap();
    base.flush().await.unwrap();
    let latest_body = base.test_seal_state(id, &base.note(id).unwrap().state());
    let latest_len = latest_body.len() as u64;
    let latest_covers = base.test_confirmed_seq(id);
    base.test_pause_sync();
    generate::kept_versions(&raw, base.id(), id, 2_920, 20 * 1024).await;
    let (status, result) = raw
        .post(
            &format!("/v1/bases/{}/changes", base.id()),
            post_valid(latest_body, latest_covers),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{result}");
    assert_eq!(result["results"][0]["stale"], false);
    let after = storage_bytes(&raw, base.id()).await;
    // Miniflare's metadata.sqlite under persist_dir() does not expose its
    // live DO database size. /v1/usage reports the DO's sql.databaseSize;
    // subtract exact R2 body lengths to isolate the billed SQLite growth.
    let r2 = first_len
        + latest_len
        + (0..2_920u64)
            .map(|i| 2_048 + i * (2 * 20 * 1024 - 2_048) / 2_920)
            .sum::<u64>();
    assert!(
        after >= before + r2,
        "storage usage must include all kept R2 bodies"
    );
    let sqlite_growth = after - before - r2;
    println!(
        "persist_dir SQLite metadata: {} bytes; DO databaseSize delta: {sqlite_growth} bytes, R2 bodies: {r2} bytes, load={}",
        persisted_sqlite_bytes(server.persist_dir()),
        load()
    );
    base.test_resume_sync();
    base.flush().await.unwrap();
    (account, base, id, oldest, before, sqlite_growth)
}

static VERSIONS: tokio::sync::OnceCell<(LocalServer, Account, Base, ObjectId, u64, u64, u64)> =
    tokio::sync::OnceCell::const_new();
async fn year_versions() -> &'static (LocalServer, Account, Base, ObjectId, u64, u64, u64) {
    VERSIONS
        .get_or_init(|| async {
            let mut server = LocalServer::start();
            let (account, base, id, oldest, before, after) = version_fixture(&mut server).await;
            (server, account, base, id, oldest, before, after)
        })
        .await
}

#[tokio::test]
async fn a_year_of_hourly_versions_lists_in_under_300_ms_and_restores_in_under_1_s() {
    let (_, _, base, id, oldest, _, _) = year_versions().await;
    let start = Instant::now();
    let (versions, more) = base.versions(*id, None, 50).await.unwrap();
    let listed = start.elapsed();
    println!(
        "2920 versions, list 50: {listed:?} (budget 300ms), load={}",
        load()
    );
    assert_eq!(versions.len(), 50);
    assert!(more && versions[0].seq > *oldest);
    assert!(listed < Duration::from_millis(300));
    let start = Instant::now();
    base.restore_version(*id, *oldest).await.unwrap();
    let restored = start.elapsed();
    println!(
        "2920 versions, restore oldest: {restored:?} (budget 1s), load={}",
        load()
    );
    assert_eq!(base.note(*id).unwrap().text(), "before the year");
    assert!(restored < Duration::from_secs(1));
}

#[tokio::test]
async fn each_kept_version_adds_under_1_kib_to_base_storage() {
    let (_, account, base, id, _, before, after) = year_versions().await;
    let raw = raw_device(account);
    let path = format!("/v1/bases/{}/objects/{id}/versions?limit=1", base.id());
    let (status, reply) = raw.get(&path, json!({})).await;
    assert_eq!(status, reqwest::StatusCode::OK, "{reply}");
    assert!(reply["versions"].as_array().unwrap().len() == 1);
    let bytes_per_version = *after as f64 / 2_920.;
    println!(
        "kept-version DO SQLite: baseline={before}, delta={after}, {bytes_per_version:.1} bytes/version (budget <1024), load={}",
        load()
    );
    assert!(
        *before > 0 && *after > 0,
        "must measure actual SQLite storage growth"
    );
    assert!(bytes_per_version < 1024.);
}

#[tokio::test]
async fn a_year_of_editing_with_every_latest_state_kept_still_opens_in_under_5_s() {
    let (account, kit) = bh_testkit::device("scale-year")
        .sign_up(new_signup())
        .await
        .unwrap();
    let base = account.create_base("Year").await.unwrap();
    let ids = generate::year_of_editing(&base, 300, 50_000).await;
    let raw = raw_device(&account);
    let changes: Vec<_> = ids
        .iter()
        .map(|&id| {
            let body = base.test_seal_state(id, &base.note(id).unwrap().state());
            json!({"changeId": bh_testkit::random_id(), "objectId": id,
            "kind": "state", "covers": base.test_confirmed_seq(id), "keep": true,
            "body": b64(&body)})
        })
        .collect();
    for batch in changes.chunks(10) {
        let (status, reply) = raw
            .post(
                &format!("/v1/bases/{}/changes", base.id()),
                json!({"changes": batch}),
            )
            .await;
        assert_eq!(status, reqwest::StatusCode::OK, "{reply}");
        assert_eq!(reply["results"].as_array().unwrap().len(), batch.len());
        assert!(
            reply["results"]
                .as_array()
                .unwrap()
                .iter()
                .all(|r| r["stale"] == false)
        );
    }
    let expected: Vec<_> = ids
        .iter()
        .map(|&id| base.note(id).unwrap().text())
        .collect();
    let start = Instant::now();
    let (_reader, other) = new_reader(&account, base.id(), &kit.display()).await;
    wait_for_base(&other, || {
        ids.iter()
            .zip(&expected)
            .all(|(&id, text)| other.note(id).is_ok_and(|note| note.text() == *text))
    })
    .await;
    let elapsed = start.elapsed();
    println!(
        "new device: year of editing + 300 kept states: {elapsed:?} (budget 5s), load={}",
        load()
    );
    assert!(elapsed < Duration::from_secs(5));
}

#[tokio::test]
async fn exporting_10k_notes_and_100_files_takes_under_20_s() {
    let local = tempfile::tempdir().unwrap();
    let base = Base::open_local(local.path(), [7; 32]).unwrap();
    let notes = generate::notes(&base, 10_000);
    let files = generate::files(&base, None, 100, 1024 * 1024);
    assert_eq!(notes.len(), 10_000);
    assert_eq!(base.file_bytes(files[0]).await.unwrap().len(), 1024 * 1024);
    let out = tempfile::tempdir().unwrap();
    let start = Instant::now();
    let summary = base.export(&out.path().join("copy")).await.unwrap();
    let elapsed = start.elapsed();
    println!(
        "export 10000 notes + 100 MiB files: {elapsed:?} (budget 20s), load={}",
        load()
    );
    assert_eq!((summary.notes, summary.files), (10_000, 100));
    assert!(summary.missing_files.is_empty());
    assert!(elapsed < Duration::from_secs(20));
}
