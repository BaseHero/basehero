use std::{collections::HashMap, process::Command, time::Instant};

use bh_core::note::Note;
use bh_device::coordinator::{AuthoritySource, Coordinator, HostError, Scope};
use bh_storage::{DeviceDatabase, NoteKey};

const KEY: NoteKey = NoteKey {
    base: [1; 32],
    audience: [2; 32],
    note: [3; 32],
};
const SCOPE: Scope = Scope {
    account: [4; 32],
    key: KEY,
};

#[derive(Default)]
struct Fixture(HashMap<String, Scope>);
impl AuthoritySource for Fixture {
    fn bound_scope(&self, window: &str) -> Option<Scope> {
        self.0.get(window).copied()
    }
}
fn fixture(db: DeviceDatabase) -> Coordinator<Fixture> {
    let mut source = Fixture::default();
    source.0.insert("one".into(), SCOPE);
    source.0.insert("two".into(), SCOPE);
    Coordinator::new(db, source)
}
fn update(text: &str) -> Vec<u8> {
    Note::new().append_paragraph(text)
}

#[test]
fn busy_base_b_never_retries_base_a_snapshot_token() {
    let mut host = fixture(DeviceDatabase::open(":memory:").unwrap());
    let mut other = SCOPE;
    other.key.base = [8; 32];
    host.authority_mut().0.insert("two".into(), other);
    let a = host.open("one", KEY.note).unwrap();
    let b = host.open("two", KEY.note).unwrap();
    let revision = host.note_revision(KEY);
    for n in 0..10 {
        host.commit("two", b.generation, [n; 16], &update("busy"), |_| {})
            .unwrap();
        assert_eq!(
            host.note_revision(KEY),
            revision,
            "unrelated base must not invalidate prepared note A"
        );
    }
    let ready = host
        .open_with_state("one", KEY.note, a.generation + 100, revision, a.state)
        .unwrap();
    assert_eq!(ready.state, host.open("one", KEY.note).unwrap().state);
}

#[test]
fn fanout_only_reaches_current_authorized_scope() {
    let mut host = fixture(DeviceDatabase::open(":memory:").unwrap());
    let mut other_scope = SCOPE;
    other_scope.key.audience = [9; 32];
    host.authority_mut().0.insert("third".into(), other_scope);
    let a = host.open("one", KEY.note).unwrap();
    host.open("two", KEY.note).unwrap();
    host.open("third", KEY.note).unwrap();
    let mut seen = vec![];
    host.commit("one", a.generation, [1; 16], &update("first"), |d| {
        seen.push(d.window)
    })
    .unwrap();
    assert_eq!(seen, ["two"]);

    // A binding is not enduring read authority: removal must stop delivery.
    host.authority_mut().0.remove("two");
    seen.clear();
    host.commit("one", a.generation, [2; 16], &update("second"), |d| {
        seen.push(d.window)
    })
    .unwrap();
    assert!(seen.is_empty());
}

#[test]
fn old_page_close_cannot_unbind_reopened_generation() {
    let mut host = fixture(DeviceDatabase::open(":memory:").unwrap());
    let old = host.open("one", KEY.note).unwrap();
    let current = host.open("one", KEY.note).unwrap();
    assert_ne!(old.generation, current.generation);
    host.close_generation("one", old.generation);
    host.commit("one", current.generation, [3; 16], &update("kept"), |_| {})
        .unwrap();
    host.close_generation("one", current.generation);
    assert!(matches!(
        host.commit("one", current.generation, [4; 16], &update("gone"), |_| {}),
        Err(HostError::Unbound)
    ));
}

#[test]
fn two_windows_commit_once_no_echo_and_retry_does_not_duplicate_work() {
    let mut host = fixture(DeviceDatabase::open(":memory:").unwrap());
    let a = host.open("one", KEY.note).unwrap();
    let b = host.open("two", KEY.note).unwrap();
    let bytes = update("Hello");
    let mut seen = vec![];
    let started = Instant::now();
    let ack = host
        .commit("one", a.generation, [8; 16], &bytes, |delivery| {
            seen.push(delivery)
        })
        .unwrap();
    eprintln!(
        "ordinary SQLite FULL commit (in-memory): {:?}",
        started.elapsed()
    );
    assert_eq!(ack.request_id, [8; 16]);
    assert!(!ack.replayed);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].window, "two");
    assert_eq!(seen[0].generation, b.generation);
    assert_eq!(seen[0].update, bytes);
    assert!(seen[0].sequence > b.sequence);
    let again = host
        .commit("one", a.generation, [8; 16], &bytes, |delivery| {
            seen.push(delivery)
        })
        .unwrap();
    assert!(again.replayed);
    assert_eq!(seen.len(), 1);
    assert_eq!(host.database().pending_note_updates().unwrap().len(), 1);
    assert_eq!(
        host.open("one", KEY.note).unwrap().state,
        host.open("two", KEY.note).unwrap().state
    );
}

#[test]
fn stale_wrong_window_revoked_scope_and_close_are_refused() {
    let mut host = fixture(DeviceDatabase::open(":memory:").unwrap());
    let a = host.open("one", KEY.note).unwrap();
    assert!(matches!(
        host.commit("two", a.generation, [1; 16], &update("x"), |_| {}),
        Err(HostError::Unbound)
    ));
    let b = host.open("two", KEY.note).unwrap();
    host.close("one");
    assert!(matches!(
        host.commit("one", a.generation, [1; 16], &update("x"), |_| {}),
        Err(HostError::Unbound)
    ));
    let reopened = host.open("one", KEY.note).unwrap();
    assert!(matches!(
        host.commit("one", a.generation, [1; 16], &update("x"), |_| {}),
        Err(HostError::Unbound)
    ));
    host.authority_mut().0.remove("two");
    assert!(matches!(
        host.commit("two", b.generation, [1; 16], &update("x"), |_| {}),
        Err(HostError::Unbound)
    ));
    host.commit("one", reopened.generation, [1; 16], &update("x"), |_| {})
        .unwrap();
    host.invalidate("one");
    assert!(matches!(
        host.open("one", KEY.note),
        Err(HostError::Unbound)
    ));
    assert!(matches!(
        host.commit("one", reopened.generation, [2; 16], &update("x"), |_| {}),
        Err(HostError::Unbound)
    ));
    host.allow_bound_window("one");
    assert_ne!(
        host.open("one", KEY.note).unwrap().generation,
        reopened.generation
    );
    assert!(matches!(
        host.open("two", KEY.note),
        Err(HostError::Unbound)
    ));
    assert_eq!(host.database().pending_note_updates().unwrap().len(), 1);
}

#[test]
fn failed_commit_has_no_ack_or_fanout_and_does_not_poison_cached_note() {
    let mut host = fixture(DeviceDatabase::open(":memory:").unwrap());
    let a = host.open("one", KEY.note).unwrap();
    host.open("two", KEY.note).unwrap();
    let mut seen = vec![];
    let state = a.state;
    assert!(matches!(
        host.commit("one", a.generation, [1; 16], b"bad", |d| seen.push(d)),
        Err(HostError::Store(_))
    ));
    assert!(seen.is_empty());
    assert_eq!(host.database().pending_note_updates().unwrap().len(), 0);
    let reread = host.open("one", KEY.note).unwrap();
    assert_eq!(reread.state, state);
    host.commit("one", reread.generation, [1; 16], &update("ok"), |d| {
        seen.push(d)
    })
    .unwrap();
    assert_eq!(seen.len(), 1);
}

#[test]
fn disk_commit_latency() {
    let dir = tempfile::tempdir().unwrap();
    let mut host = fixture(DeviceDatabase::open(dir.path().join("latency.sqlite")).unwrap());
    let opened = host.open("one", KEY.note).unwrap();
    let mut times = Vec::new();
    for i in 0..12u8 {
        let started = Instant::now();
        host.commit("one", opened.generation, [i; 16], &update("typing"), |_| {})
            .unwrap();
        times.push(started.elapsed());
    }
    times.sort();
    eprintln!(
        "SQLite FULL 12 ordinary disk commits, median {:?}, max {:?}",
        times[6], times[11]
    );
}

#[test]
fn child_writer() {
    let Ok(path) = std::env::var("BH_NOTE_CHILD_DB") else {
        return;
    };
    let mut host = fixture(DeviceDatabase::open(path).unwrap());
    let a = host.open("one", KEY.note).unwrap();
    host.commit("one", a.generation, [7; 16], &update("survives"), |_| {})
        .unwrap();
    // No destructor, flush, or orderly shutdown can be relied on.
    std::process::abort();
}

#[test]
fn kill_reopen_retains_acknowledged_note() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("note.sqlite");
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "child_writer", "--nocapture"])
        .env("BH_NOTE_CHILD_DB", &path)
        .status()
        .unwrap();
    assert!(!child.success());
    let mut host = fixture(DeviceDatabase::open(path).unwrap());
    let state = host.open("one", KEY.note).unwrap().state;
    let pending = host.database().pending_note_updates().unwrap();
    assert_eq!(pending.len(), 1);
    let mut expected = Note::new();
    expected.apply_update(&pending[0].bytes).unwrap();
    assert_eq!(state, expected.state());
}
