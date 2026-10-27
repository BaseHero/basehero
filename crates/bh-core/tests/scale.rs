//! Performance budgets against the real local store and local Worker.
//! Only the release scale stage runs these budgets; the debug workspace suite
//! must not run the same expensive fixtures concurrently or time debug code.
#![cfg(not(debug_assertions))]
use bh_core::{Account, Base, Clock, NewObject, ObjectId, Query, SignIn, SignUp, TypeRef};
use bh_testkit::{DelayProxy, LocalServer, TEST_PASSWORD, generate, invite, wait_for_base};
use serde_json::Map;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// Full-size fixtures use test-only bulk writes; measurements use real core APIs.
const NOTES: usize = 300;
const SESSIONS: usize = 50_000;
const SEARCH_NOTES: usize = 100_000;
const FOLDER_CHILDREN: usize = 10_000;
const RECORDS: usize = 100_000;
const LIVE_EDITS: usize = 200;

type HeavyBase = (Account, Base, String, Vec<ObjectId>);
static HEAVY: tokio::sync::OnceCell<HeavyBase> = tokio::sync::OnceCell::const_new();

async fn heavy() -> &'static HeavyBase {
    HEAVY
        .get_or_init(|| async {
            let (account, kit) = bh_testkit::device("writer")
                .sign_up(bh_testkit::new_signup())
                .await
                .unwrap();
            let base = account.create_base("Year").await.unwrap();
            let ids = generate::year_of_editing(&base, NOTES, SESSIONS).await;
            (account, base, kit.display(), ids)
        })
        .await
}

fn local() -> (tempfile::TempDir, Base) {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::open_local(dir.path(), [7; 32]).unwrap();
    (dir, base)
}

struct LocalFixture {
    dir: tempfile::TempDir,
    base: Base,
    notes: Vec<ObjectId>,
    folder: ObjectId,
    children: Vec<ObjectId>,
    records: Vec<ObjectId>,
}

fn large_local() -> &'static LocalFixture {
    static FIXTURE: OnceLock<LocalFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let start = Instant::now();
        let (dir, base) = local();
        let notes = generate::notes(&base, SEARCH_NOTES);
        let folder = base
            .create(NewObject {
                ty: TypeRef::new("core.folder", 1),
                parent: None,
                after: None,
                fields: Map::new(),
            })
            .unwrap();
        let children = generate::children(&base, folder, FOLDER_CHILDREN);
        let records = generate::records(&base, "scale.item", RECORDS);
        println!(
            "local fixture: {} searchable notes, {} folder children, {} records in {:?}, load={}",
            notes.len(),
            children.len(),
            records.len(),
            start.elapsed(),
            load()
        );
        LocalFixture {
            dir,
            base,
            notes,
            folder,
            children,
            records,
        }
    })
}

fn load() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .unwrap_or_else(|_| "unavailable".into())
        .split_whitespace()
        .take(3)
        .collect::<Vec<_>>()
        .join("/")
}

fn percentile(mut samples: Vec<Duration>) -> Duration {
    samples.sort_unstable();
    samples[(samples.len() * 95).div_ceil(100) - 1]
}

#[test]
fn bulk_fixture_matches_the_real_note_and_rolls_back_on_error() {
    let (_dir, base) = local();
    let original = bh_testkit::note_with_text(&base, "marker7 project meeting notes");
    let bulk = base
        .test_bulk_create([(
            bh_testkit::note(),
            Some(bh_testkit::insert_text("marker7 project meeting notes")),
        )])
        .unwrap()[0];
    assert_eq!(
        base.note(bulk).unwrap().text(),
        base.note(original).unwrap().text()
    );
    assert_eq!(
        base.get(bulk).unwrap().unwrap().title,
        base.get(original).unwrap().unwrap().title
    );
    assert_eq!(base.search("marker7", 10).unwrap().len(), 2);
    let before = base.children(None).unwrap().len();
    let failed = base.test_bulk_create([
        (bh_testkit::note(), None),
        (
            NewObject {
                ty: TypeRef::new("unknown.type", 1),
                ..bh_testkit::note()
            },
            None,
        ),
    ]);
    assert!(failed.is_err());
    assert_eq!(base.children(None).unwrap().len(), before);
}

#[tokio::test]
async fn edited_base_opens_on_a_new_device_in_under_5_s() {
    let (account, base, kit, ids) = heavy().await;
    let fresh = bh_testkit::device("reader")
        .sign_in(bh_testkit::signin_for(account))
        .await
        .unwrap()
        .with_kit(kit)
        .await
        .unwrap();
    let start = Instant::now();
    fresh.refresh().await.unwrap();
    let other = fresh.base(base.id()).unwrap();
    let expected: Vec<_> = ids
        .iter()
        .map(|&id| base.note(id).unwrap().text())
        .collect();
    wait_for_base(&other, || {
        ids.iter()
            .zip(&expected)
            .all(|(&id, text)| other.note(id).is_ok_and(|note| note.text() == *text))
    })
    .await;
    let elapsed = start.elapsed();
    println!(
        "new device: {elapsed:?} for {} notes, {SESSIONS} edit sessions (budget 5s), load={}",
        ids.len(),
        load()
    );
    assert!(elapsed < Duration::from_secs(5));
    let mut observed_words = 0;
    for &id in ids {
        let text = other.note(id).unwrap().text();
        observed_words += text.matches("edited ").count();
    }
    let expected_words: usize = (0..SESSIONS)
        .map(|i| {
            if i % 10 == 0 {
                180 + i % 21
            } else {
                3 + i % 15
            }
        })
        .sum();
    assert_eq!(
        observed_words, expected_words,
        "no generated session may be lost"
    );
}

async fn live_lane(
    base: Base,
    other: Base,
    id: ObjectId,
    lane: usize,
    run: usize,
) -> Vec<Duration> {
    let mut samples = Vec::with_capacity(LIVE_EDITS / 4);
    for i in 0..LIVE_EDITS / 4 {
        let text = format!("edit {run}/{lane}/{i}");
        let doc = base.note(id).unwrap();
        let start = Instant::now();
        doc.apply(5, &bh_testkit::append_text(&doc.state(), &text))
            .unwrap();
        wait_for_base(&other, || other.note(id).unwrap().text().contains(&text)).await;
        samples.push(start.elapsed());
        tokio::time::sleep(Duration::from_millis(150 + (i % 4) as u64 * 150)).await;
    }
    samples
}

async fn live_sample(base: &Base, other: &Base, ids: &[ObjectId; 4], run: usize) -> Duration {
    let (a, b, c, d) = tokio::join!(
        live_lane(base.clone(), other.clone(), ids[0], 0, run),
        live_lane(base.clone(), other.clone(), ids[1], 1, run),
        live_lane(base.clone(), other.clone(), ids[2], 2, run),
        live_lane(base.clone(), other.clone(), ids[3], 3, run),
    );
    percentile(a.into_iter().chain(b).chain(c).chain(d).collect())
}

#[tokio::test]
async fn an_edit_shows_on_another_device_within_1_s_at_p95_with_100_ms_rtt() {
    let server = LocalServer::shared();
    let proxy = DelayProxy::start(server.url(), Duration::from_millis(100));
    // The background sender's 500 ms per-object interval follows this clock.
    let clock = Clock::system();
    let a = bh_testkit::device_on_server("a", &clock, server);
    let (a, kit) = a
        .sign_up(SignUp {
            server: proxy.url(),
            invite: invite(server),
            email: format!("{}@example.test", bh_testkit::random_id()),
            password: TEST_PASSWORD.to_string().into(),
            device_name: String::new(),
        })
        .await
        .unwrap();
    let b = bh_testkit::device_on_server("b", &clock, server)
        .sign_in(SignIn {
            server: proxy.url(),
            email: a.email(),
            password: TEST_PASSWORD.to_string().into(),
            device_name: String::new(),
        })
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    let base = a.create_base("Live").await.unwrap();
    base.flush().await.unwrap();
    b.refresh().await.unwrap();
    let other = b.base(base.id()).unwrap();
    let ids = std::array::from_fn(|_| base.create(bh_testkit::note()).unwrap());
    base.flush().await.unwrap();
    wait_for_base(&other, || ids.iter().all(|&id| other.note(id).is_ok())).await;
    let first = live_sample(&base, &other, &ids, 0).await;
    println!(
        "live p95 first: {first:?} for {LIVE_EDITS} edits with 100ms RTT (budget 1s), load={}",
        load()
    );
    if first >= Duration::from_secs(1) {
        let second = live_sample(&base, &other, &ids, 1).await;
        println!("live p95 second: {second:?} (budget 1s), load={}", load());
        assert!(
            second < Duration::from_secs(1),
            "both live samples missed 1s: {first:?}, {second:?}"
        );
    }
}

#[test]
fn local_search_p95_takes_under_200_ms() {
    let fixture = large_local();
    let base = &fixture.base;
    let mut samples = Vec::new();
    for i in 0..50 {
        let start = Instant::now();
        let hits = base.search(&format!("marker{i}"), 20).unwrap();
        samples.push(start.elapsed());
        assert!(!hits.is_empty());
    }
    assert_eq!(fixture.notes.len(), SEARCH_NOTES);
    let p95 = percentile(samples);
    println!(
        "search p95: {p95:?} over {} searchable notes (budget 200ms), load={}",
        fixture.notes.len(),
        load()
    );
    assert!(p95 < Duration::from_millis(200));
}

#[test]
fn folder_and_record_base_open_within_5_s() {
    let fixture = large_local();
    let start = Instant::now();
    let reopened = Base::open_local(fixture.dir.path(), [7; 32]).unwrap();
    assert_eq!(
        reopened.children(Some(fixture.folder)).unwrap().len(),
        fixture.children.len()
    );
    assert_eq!(
        reopened
            .get(fixture.records[RECORDS - 1])
            .unwrap()
            .unwrap()
            .title,
        format!("Record {}", RECORDS - 1)
    );
    assert_eq!(
        reopened
            .query(&Query {
                ty: "scale.item".into(),
                filters: vec![],
                order_by: None,
                limit: Some(1),
            })
            .unwrap()
            .len(),
        1
    );
    let elapsed = start.elapsed();
    println!(
        "folder + records open: {elapsed:?} for {} children / {RECORDS} records (budget 5s), load={}",
        fixture.children.len(),
        load()
    );
    assert!(elapsed < Duration::from_secs(5));
}

#[tokio::test]
async fn edited_base_storage_stays_under_1_gb() {
    let server = LocalServer::shared();
    let (account, base, _, ids) = heavy().await;
    let raw = bh_testkit::raw_device(account);
    let (status, head) = raw
        .get(
            &format!("/v1/bases/{}/since?after=0", base.id()),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{head}");
    assert!(
        head["head"].as_u64().unwrap() >= SESSIONS as u64,
        "the server must hold a distinct change for each edit session: {head}"
    );
    let (status, stored) = raw
        .get(
            &format!("/v1/bases/{}/stored?object={}", base.id(), ids[0]),
            serde_json::json!({}),
        )
        .await;
    assert_eq!(status, reqwest::StatusCode::OK, "{stored}");
    assert!(
        stored["changes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["kind"] == "state"),
        "hot note must have compacted"
    );
    let mut dirs = vec![server.persist_dir().to_path_buf()];
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
    println!(
        "server SQLite storage: {size} bytes for {NOTES} notes / {SESSIONS} sessions (budget 1GB), load={}",
        load()
    );
    assert!(
        size > 0,
        "must measure persisted SQLite, not an empty directory"
    );
    assert!(size < 1_000_000_000);
}
