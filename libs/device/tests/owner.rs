use bh_account::{
    AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount,
    crypto::{KemKey, SigningKey},
};
use bh_core::note::{Note, OrderedState};
use bh_data::{
    FieldPath, KeyRef, RecordId, Scope as DataScope, TypeId, index, note, store::records,
};
use bh_device::{
    ContainerId, Owner, OwnerError,
    coordinator::{AuthoritySource, Scope},
};
use bh_storage::{DeviceDatabase, NoteKey};
use rusqlite::OptionalExtension;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::Duration,
};

/// Generous bound on waiting for a worker report; it only stops a hung test.
const HANG: Duration = Duration::from_secs(60);

#[derive(Default)]
struct TestIssuer(HashMap<String, Scope>);
impl AuthoritySource for TestIssuer {
    fn bound_scope(&self, window: &str) -> Option<Scope> {
        self.0.get(window).copied()
    }
}
fn scope(account: [u8; 32], base: u8) -> Scope {
    Scope {
        account,
        key: NoteKey {
            base: [base; 32],
            audience: [3; 32],
            note: [4; 32],
        },
    }
}
fn issuer(account: [u8; 32], base: u8, window: &str) -> Box<dyn AuthoritySource + Send> {
    Box::new(TestIssuer(HashMap::from([(
        window.to_owned(),
        scope(account, base),
    )])))
}
fn test_only_verified() -> (VerifiedAccount, Vec<u8>) {
    let signing = SigningKey::generate();
    let control = SigningKey::generate();
    let device = DevicePublicKeys::new(
        signing.public(),
        control.public(),
        KemKey::generate().public(),
    )
    .unwrap();
    let recovery =
        RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public());
    let draft = AccountEvent::genesis(device, recovery);
    let event = draft.finish(control.sign(draft.signing_bytes())).unwrap();
    let state =
        VerifiedAccount::from_genesis(AccountId::of_genesis(&event).unwrap(), event.as_bytes())
            .unwrap();
    (state, event.as_bytes().to_vec())
}
fn anchored(path: &std::path::Path, verified: &VerifiedAccount, signed: &[u8]) -> DeviceDatabase {
    let mut db = DeviceDatabase::open(path).unwrap();
    db.commit_account_verified(
        verified.id().0,
        &[signed],
        verified.head().position,
        verified.head().hash,
        false,
    )
    .unwrap();
    db
}
fn pending_body_jobs(path: &std::path::Path) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row("SELECT count(*) FROM data_text_job", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn owner_commit_triggers_body_maintenance() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("commit.db");
    let (extracted, completed) = mpsc::channel();
    let (proof, signed) = test_only_verified();
    let mut key = scope(proof.id().0, 1).key;
    let mut db = anchored(&path, &proof, &signed);
    key.note = db.create_note(key.base, key.audience).unwrap();
    let owner = Owner::notifying_maintenance(extracted);
    let source = Box::new(TestIssuer(HashMap::from([(
        "writer".to_owned(),
        Scope {
            account: proof.id().0,
            key,
        },
    )])));
    let id = owner.register(db, Some(&proof), source).unwrap();
    owner.bind("writer", id).unwrap();
    assert_eq!(completed.recv().unwrap().0, id);
    let opened = owner.open("writer", key.note).unwrap();
    assert_eq!(completed.recv().unwrap().0, id);
    owner
        .commit_queued(
            "writer",
            opened.generation,
            [1; 16],
            &Note::new().unwrap().append_paragraph("indexed").unwrap(),
        )
        .unwrap();
    loop {
        let (finished, extracted) = completed.recv().unwrap();
        assert_eq!(finished, id);
        if extracted > 0 {
            break;
        }
    }
    drop(owner);
    assert_eq!(pending_body_jobs(&path), 0);
}

#[test]
fn dropping_owner_mid_index_build_resumes_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("index.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    let data_scope = DataScope {
        base: [2; 32],
        audience: [0; 32],
    };
    let ix = db
        .with_data_write(|tx| {
            for n in 0..3000u32 {
                let mut id = [0; 32];
                id[..4].copy_from_slice(&n.to_be_bytes());
                note::upsert_projection(tx, data_scope, RecordId(id), &format!("Note {n:04}"))?;
            }
            let sid = records::lookup_scope(tx, data_scope)?.unwrap();
            index::ensure_local(
                tx,
                sid,
                TypeId::core("note"),
                vec![KeyRef::Field(FieldPath::parse("/title").unwrap())],
            )
        })
        .unwrap();
    // At most one derived turn: its budget is spent before the turn reports,
    // so after that report no worker starts or requeues another.
    let (completed, turns) = mpsc::channel();
    let owner = Owner::notifying_derived_turns(completed, 1);
    let id = owner
        .register(db, None, issuer([0; 32], 2, "writer"))
        .unwrap();
    let state = || index::state(&rusqlite::Connection::open(&path).unwrap(), ix).unwrap();
    let partial = loop {
        let (turn, _) = turns.recv_timeout(HANG).expect("first derived turn");
        assert_eq!(turn, id);
        let state = state();
        if state.built > 0 {
            break state;
        }
    };
    assert_eq!(
        partial.state, "building",
        "one bounded turn leaves a persisted cursor"
    );
    assert!(partial.built < 3000);
    drop(owner);
    assert_eq!(state(), partial, "nothing ran after the acknowledged turn");
    let db = DeviceDatabase::open(&path).unwrap();
    let (completed, turns) = mpsc::channel();
    let owner = Owner::notifying_maintenance(completed);
    let reopened = owner
        .register(db, None, issuer([0; 32], 2, "writer"))
        .unwrap();
    for _ in 0..300 {
        let (turn, _) = turns.recv_timeout(HANG).expect("resumed derived turn");
        assert_eq!(turn, reopened);
        let conn = rusqlite::Connection::open(&path).unwrap();
        if index::state(&conn, ix).unwrap().state == "ready" {
            assert!(!index::has_pending(&conn).unwrap());
            return;
        }
    }
    panic!("reopened owner did not complete the persisted index build");
}

#[test]
fn owner_open_triggers_body_maintenance() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("open.db");
    let (extracted, completed) = mpsc::channel();
    let (proof, signed) = test_only_verified();
    let mut key = scope(proof.id().0, 1).key;
    let mut db = anchored(&path, &proof, &signed);
    key.note = db.create_note(key.base, key.audience).unwrap();
    let owner = Owner::notifying_maintenance(extracted);
    let source = Box::new(TestIssuer(HashMap::from([(
        "writer".to_owned(),
        Scope {
            account: proof.id().0,
            key,
        },
    )])));
    let id = owner.register(db, Some(&proof), source).unwrap();
    owner.bind("writer", id).unwrap();
    assert_eq!(completed.recv().unwrap().0, id); // registration turn is done before seeding
    let delta = Note::new()
        .unwrap()
        .append_paragraph("queued before open")
        .unwrap();
    let db = owner.shared_database(id).unwrap();
    db.lock()
        .unwrap()
        .commit_working_update_with_title(key, 0, proof.id().0, [1; 16], &delta, "queued")
        .unwrap();
    assert_eq!(pending_body_jobs(&path), 1);
    owner.open("writer", key.note).unwrap();
    loop {
        let (finished, extracted) = completed.recv().unwrap();
        assert_eq!(finished, id);
        if extracted > 0 {
            break;
        }
    }
    drop(db);
    drop(owner);
    assert_eq!(pending_body_jobs(&path), 0);
}

#[test]
fn duplicate_anchor_and_tampered_registry_cannot_create_note_authority() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Owner::default();
    let (proof, bytes) = test_only_verified();
    let first = owner
        .register(
            anchored(&dir.path().join("first.db"), &proof, &bytes),
            Some(&proof),
            issuer(proof.id().0, 1, "one"),
        )
        .unwrap();
    assert_ne!(first, ContainerId::default());
    assert!(matches!(
        owner.register(
            anchored(&dir.path().join("second.db"), &proof, &bytes),
            Some(&proof),
            issuer(proof.id().0, 2, "two")
        ),
        Err(OwnerError::DuplicateAnchor)
    ));
    let unanchored = owner
        .register(
            DeviceDatabase::open(dir.path().join("setup.db")).unwrap(),
            None,
            issuer(proof.id().0, 1, "two"),
        )
        .unwrap();
    owner.bind("one", first).unwrap();
    owner.bind("two", unanchored).unwrap();
    assert!(matches!(
        owner.open("two", [4; 32]),
        Err(OwnerError::Unbound)
    ));
    assert!(matches!(
        owner.bind("three", ContainerId([1; 16])),
        Err(OwnerError::UnknownContainer)
    ));
    let conn = rusqlite::Connection::open(dir.path().join("tampered.db")).unwrap();
    drop(conn);
    let mut tampered = anchored(&dir.path().join("tampered.db"), &proof, &bytes);
    tampered
        .commit_account_verified(proof.id().0, &[b"unsigned"], 2, [9; 32], false)
        .unwrap();
    assert!(matches!(
        owner.register(tampered, Some(&proof), issuer(proof.id().0, 1, "three")),
        Err(OwnerError::AnchorMismatch)
    ));
    let mut forged = DeviceDatabase::open(dir.path().join("forged.db")).unwrap();
    forged
        .commit_account_verified(
            proof.id().0,
            &[b"forged genesis"],
            proof.head().position,
            proof.head().hash,
            false,
        )
        .unwrap();
    assert!(
        matches!(
            owner.register(forged, Some(&proof), issuer(proof.id().0, 1, "three")),
            Err(OwnerError::AnchorMismatch)
        ),
        "matching registry row without original signed genesis must not authorize notes"
    );
    let old = owner.open("one", [4; 32]).unwrap();
    let (different, signed) = test_only_verified();
    let other = owner
        .register(
            anchored(&dir.path().join("other.db"), &different, &signed),
            Some(&different),
            issuer(different.id().0, 2, "one"),
        )
        .unwrap();
    owner.bind("one", other).unwrap();
    let current = owner.open("one", [4; 32]).unwrap();
    assert_ne!(
        old.generation, current.generation,
        "navigation must not accept an old eval even when both containers opened one note"
    );
    assert!(matches!(
        owner.commit(
            "one",
            old.generation,
            [3; 16],
            &Note::new().unwrap().append_paragraph("old").unwrap(),
            |_| {}
        ),
        Err(OwnerError::Unbound)
    ));
}
#[test]
fn setup_container_promotes_in_place_only_after_exact_verified_history() {
    let dir = tempfile::tempdir().unwrap();
    let (proof, signed) = test_only_verified();
    let owner = Owner::default();
    let id = owner
        .register(
            DeviceDatabase::open(dir.path().join("setup.db")).unwrap(),
            None,
            issuer(proof.id().0, 1, "one"),
        )
        .unwrap();
    assert!(matches!(
        owner.shared_database(ContainerId([7; 16])),
        Err(OwnerError::UnknownContainer)
    ));
    assert!(matches!(
        owner.anchor(ContainerId([7; 16]), &proof),
        Err(OwnerError::UnknownContainer)
    ));
    owner.bind("one", id).unwrap();
    assert!(matches!(
        owner.open("one", [4; 32]),
        Err(OwnerError::Unbound)
    ));
    let db = owner.shared_database(id).unwrap();
    db.lock()
        .unwrap()
        .commit_account_verified(
            proof.id().0,
            &[&signed],
            proof.head().position,
            proof.head().hash,
            false,
        )
        .unwrap();
    owner.anchor(id, &proof).unwrap();
    owner.anchor(id, &proof).unwrap(); // exact same authority revalidation
    let opened = owner.open("one", [4; 32]).unwrap();
    owner
        .commit_queued(
            "one",
            opened.generation,
            [1; 16],
            &Note::new().unwrap().append_paragraph("persisted").unwrap(),
        )
        .unwrap();
    let (different, _) = test_only_verified();
    assert!(matches!(
        owner.anchor(id, &different),
        Err(OwnerError::AnchorMismatch)
    ));
    assert_eq!(
        full(&owner.open("one", [4; 32]).unwrap().state),
        DeviceDatabase::open(dir.path().join("setup.db"))
            .unwrap()
            .note_state(scope(proof.id().0, 1).key)
            .unwrap()
    );
    // Promotion never installs a new page authority: the original issuer
    // still has to return the same proven account and note scope.
    let (other, other_bytes) = test_only_verified();
    let wrong = owner
        .register(
            DeviceDatabase::open(dir.path().join("wrong-source.db")).unwrap(),
            None,
            issuer(proof.id().0, 1, "wrong"),
        )
        .unwrap();
    owner
        .shared_database(wrong)
        .unwrap()
        .lock()
        .unwrap()
        .commit_account_verified(
            other.id().0,
            &[&other_bytes],
            other.head().position,
            other.head().hash,
            false,
        )
        .unwrap();
    owner.anchor(wrong, &other).unwrap();
    owner.bind("wrong", wrong).unwrap();
    assert!(matches!(
        owner.open("wrong", [4; 32]),
        Err(OwnerError::Unbound)
    ));
}

#[test]
fn concurrent_setup_promotions_refuse_duplicate_and_bad_history() {
    let dir = tempfile::tempdir().unwrap();
    let (proof, signed) = test_only_verified();
    let owner = Arc::new(Owner::default());
    let mut ids = Vec::new();
    for index in 0..2 {
        let path = dir.path().join(format!("{index}.db"));
        let id = owner
            .register(
                DeviceDatabase::open(&path).unwrap(),
                None,
                issuer(proof.id().0, 1, "one"),
            )
            .unwrap();
        owner
            .shared_database(id)
            .unwrap()
            .lock()
            .unwrap()
            .commit_account_verified(
                proof.id().0,
                &[&signed],
                proof.head().position,
                proof.head().hash,
                false,
            )
            .unwrap();
        ids.push(id);
    }
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let jobs: Vec<_> = ids
        .iter()
        .map(|id| {
            let owner = Arc::clone(&owner);
            let barrier = Arc::clone(&barrier);
            let proof = proof.clone();
            let id = *id;
            thread::spawn(move || {
                barrier.wait();
                owner.anchor(id, &proof)
            })
        })
        .collect();
    let results: Vec<_> = jobs.into_iter().map(|job| job.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(OwnerError::DuplicateAnchor)))
            .count(),
        1
    );

    let bad = owner
        .register(
            DeviceDatabase::open(dir.path().join("bad.db")).unwrap(),
            None,
            issuer(proof.id().0, 1, "bad"),
        )
        .unwrap();
    assert!(matches!(
        owner.anchor(bad, &proof),
        Err(OwnerError::AnchorMismatch)
    ));
    owner
        .shared_database(bad)
        .unwrap()
        .lock()
        .unwrap()
        .commit_account_verified(
            proof.id().0,
            &[b"forged genesis"],
            proof.head().position,
            proof.head().hash,
            false,
        )
        .unwrap();
    assert!(matches!(
        owner.anchor(bad, &proof),
        Err(OwnerError::AnchorMismatch)
    ));
    let conn = rusqlite::Connection::open(dir.path().join("bad.db")).unwrap();
    conn.execute("UPDATE account_events SET bytes=?1 WHERE id=1", [&signed])
        .unwrap();
    conn.execute(
        "UPDATE account_state SET head_hash=?1",
        [[9u8; 32].as_slice()],
    )
    .unwrap();
    assert!(matches!(
        owner.anchor(bad, &proof),
        Err(OwnerError::AnchorMismatch)
    ));
    conn.execute(
        "UPDATE account_state SET head_hash=?1",
        [proof.head().hash.as_slice()],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO account_events(id,bytes) VALUES (2,?1)",
        [&signed],
    )
    .unwrap();
    assert!(matches!(
        owner.anchor(bad, &proof),
        Err(OwnerError::AnchorMismatch)
    ));
    conn.execute("DELETE FROM account_events WHERE id=2", [])
        .unwrap();
    conn.execute("UPDATE account_state SET stopped=1", [])
        .unwrap();
    assert!(matches!(
        owner.anchor(bad, &proof),
        Err(OwnerError::AnchorMismatch)
    ));
}

#[test]
fn delivery_callback_cannot_hold_writer_or_owner_and_containers_progress_independently() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Arc::new(Owner::default());
    let (proof_a, bytes_a) = test_only_verified();
    let (proof_b, bytes_b) = test_only_verified();
    let listeners = TestIssuer(HashMap::from([
        ("one".into(), scope(proof_a.id().0, 1)),
        ("listener".into(), scope(proof_a.id().0, 1)),
    ]));
    let a = owner
        .register(
            anchored(&dir.path().join("a.db"), &proof_a, &bytes_a),
            Some(&proof_a),
            Box::new(listeners),
        )
        .unwrap();
    let b = owner
        .register(
            anchored(&dir.path().join("b.db"), &proof_b, &bytes_b),
            Some(&proof_b),
            issuer(proof_b.id().0, 2, "other"),
        )
        .unwrap();
    owner.bind("one", a).unwrap();
    owner.bind("listener", a).unwrap();
    owner.bind("other", b).unwrap();
    let opened = owner.open("one", [4; 32]).unwrap();
    owner.open("listener", [4; 32]).unwrap();
    let other = owner.open("other", [4; 32]).unwrap();
    let update = Note::new().unwrap().append_paragraph("editable").unwrap();
    let second = Arc::clone(&owner);
    owner
        .commit("one", opened.generation, [1; 16], &update, |_| {
            let next = Arc::clone(&second);
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                tx.send(
                    next.commit(
                        "other",
                        other.generation,
                        [2; 16],
                        &Note::new()
                            .unwrap()
                            .append_paragraph("independent")
                            .unwrap(),
                        |_| {},
                    ),
                )
                .unwrap();
            });
            assert!(
                rx.recv_timeout(Duration::from_secs(2)).unwrap().is_ok(),
                "slow delivery must never hold storage"
            );
        })
        .unwrap();
}

#[test]
fn two_authorized_windows_fan_out_once_only_after_disk_commit_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("windows.db");
    let (proof, signed) = test_only_verified();
    let owner = Owner::default();
    let issuer = TestIssuer(HashMap::from([
        ("left".into(), scope(proof.id().0, 1)),
        ("right".into(), scope(proof.id().0, 1)),
        ("elsewhere".into(), scope(proof.id().0, 2)),
    ]));
    let id = owner
        .register(
            anchored(&path, &proof, &signed),
            Some(&proof),
            Box::new(issuer),
        )
        .unwrap();
    for window in ["left", "right", "elsewhere"] {
        owner.bind(window, id).unwrap();
    }
    let left = owner.open("left", [4; 32]).unwrap();
    let right = owner.open("right", [4; 32]).unwrap();
    owner.open("elsewhere", [4; 32]).unwrap();
    let first = Note::new().unwrap().append_paragraph("from left").unwrap();
    let (ack, targets) = owner
        .commit_queued("left", left.generation, [1; 16], &first)
        .unwrap();
    assert!(!ack.replayed);
    assert_eq!(targets, ["right"]);
    let disk = DeviceDatabase::open(&path).unwrap();
    assert_eq!(
        disk.pending_note_updates().unwrap().len(),
        1,
        "an Ack or delivery must not precede the disk transaction"
    );
    let mut sent = Vec::new();
    assert!(owner.drain_surface("right", &mut |d| sent.push(d)));
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].update, first);
    assert_eq!(sent[0].generation, right.generation);
    assert!(owner.drain_surface("left", &mut |_| panic!("origin echoed")));
    assert!(owner.drain_surface("elsewhere", &mut |_| panic!("other note delivered")));
    let (retry, targets) = owner
        .commit_queued("left", left.generation, [1; 16], &first)
        .unwrap();
    assert!(retry.replayed);
    assert!(targets.is_empty());
    assert!(owner.drain_surface("right", &mut |_| panic!("retry duplicated update")));
    let second = Note::new().unwrap().append_paragraph("from right").unwrap();
    let (_, targets) = owner
        .commit_queued("right", right.generation, [2; 16], &second)
        .unwrap();
    assert_eq!(targets, ["left"]);
    let mut reverse = Vec::new();
    assert!(owner.drain_surface("left", &mut |d| reverse.push(d)));
    assert_eq!(reverse.len(), 1);
    assert_eq!(reverse[0].update, second);
    let after = DeviceDatabase::open(&path)
        .unwrap()
        .note_state(scope(proof.id().0, 1).key)
        .unwrap();
    assert_eq!(full(&owner.open("left", [4; 32]).unwrap().state), after);
    assert_eq!(full(&owner.open("right", [4; 32]).unwrap().state), after);
    assert_eq!(
        DeviceDatabase::open(&path)
            .unwrap()
            .pending_note_updates()
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn navigation_during_exclusive_work_discards_uncommitted_note_and_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cancel.db");
    let (proof, signed) = test_only_verified();
    let owner = Arc::new(Owner::default());
    let id = owner
        .register(
            anchored(&path, &proof, &signed),
            Some(&proof),
            issuer(proof.id().0, 1, "writer"),
        )
        .unwrap();
    owner.bind("writer", id).unwrap();
    let open = owner.open("writer", [4; 32]).unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let writing = Arc::clone(&owner);
    let job = thread::spawn(move || {
        writing.commit_with_work_hook(
            "writer",
            open.generation,
            [23; 16],
            &Note::new().unwrap().append_paragraph("unsaved").unwrap(),
            || {
                ready_tx.send(()).unwrap();
                resume_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            },
            |_| panic!("uncommitted fanout"),
        )
    });
    ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    owner.invalidate("writer");
    resume_tx.send(()).unwrap();
    assert!(matches!(job.join().unwrap(), Err(OwnerError::Unbound)));
    assert!(
        DeviceDatabase::open(&path)
            .unwrap()
            .pending_note_updates()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn three_same_note_open_races_return_retryable_instead_of_replaying_under_guard() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("racing.db");
    let (proof, signed) = test_only_verified();
    let owner = Owner::default();
    let issuer = TestIssuer(HashMap::from([
        ("writer".into(), scope(proof.id().0, 1)),
        ("view".into(), scope(proof.id().0, 1)),
    ]));
    let id = owner
        .register(
            anchored(&path, &proof, &signed),
            Some(&proof),
            Box::new(issuer),
        )
        .unwrap();
    owner.bind("writer", id).unwrap();
    owner.bind("view", id).unwrap();
    let writer = owner.open("writer", [4; 32]).unwrap();
    let racing = owner.open_with_snapshot_hook("view", [4; 32], |attempt| {
        let update = Note::new().unwrap().append_paragraph("arrival").unwrap();
        owner
            .commit(
                "writer",
                writer.generation,
                [attempt + 1; 16],
                &update,
                |_| {},
            )
            .unwrap();
    });
    assert!(
        matches!(racing, Err(OwnerError::Changed)),
        "a busy note must not force cold replay under the container guard"
    );
    let reopened = owner.open("view", [4; 32]).unwrap();
    assert_eq!(
        full(&reopened.state),
        DeviceDatabase::open(&path)
            .unwrap()
            .note_state(scope(proof.id().0, 1).key)
            .unwrap()
    );
}

#[test]
fn paused_same_container_note_work_does_not_block_other_base_or_publish_dirty_note() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("both.db");
    let (proof, signed) = test_only_verified();
    let owner = Arc::new(Owner::default());
    let fixture = TestIssuer(HashMap::from([
        ("a".into(), scope(proof.id().0, 1)),
        ("b".into(), scope(proof.id().0, 2)),
        ("a-view".into(), scope(proof.id().0, 1)),
    ]));
    let id = owner
        .register(
            anchored(&path, &proof, &signed),
            Some(&proof),
            Box::new(fixture),
        )
        .unwrap();
    for window in ["a", "b", "a-view"] {
        owner.bind(window, id).unwrap();
    }
    let a = owner.open("a", [4; 32]).unwrap();
    let b = owner.open("b", [4; 32]).unwrap();
    owner.open("a-view", [4; 32]).unwrap();
    let (paused_tx, paused_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel();
    let (committed_tx, committed_rx) = mpsc::channel();
    let copy = Arc::clone(&owner);
    let a_writer = thread::spawn(move || {
        let changed = Note::new()
            .unwrap()
            .append_paragraph("a committed")
            .unwrap();
        let result = copy.commit_with_work_hook(
            "a",
            a.generation,
            [51; 16],
            &changed,
            || {
                paused_tx.send(()).unwrap();
                resume_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            },
            |d| committed_tx.send(d).unwrap(),
        );
        result.unwrap();
    });
    paused_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(
        committed_rx.try_recv().is_err(),
        "uncommitted A must not fan out"
    );
    let (saved_tx, saved_rx) = mpsc::channel();
    let other = Arc::clone(&owner);
    thread::spawn(move || {
        saved_tx
            .send(other.commit(
                "b",
                b.generation,
                [52; 16],
                &Note::new().unwrap().append_paragraph("b typed").unwrap(),
                |_| {},
            ))
            .unwrap()
    });
    assert!(
        saved_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .is_ok(),
        "base B in the SAME account must save despite A paused under exclusive Note ownership"
    );
    assert!(committed_rx.try_recv().is_err());
    resume_tx.send(()).unwrap();
    a_writer.join().unwrap();
    let sent = committed_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(sent.window, "a-view");
    let mut reopened = DeviceDatabase::open(&path).unwrap();
    assert_eq!(
        reopened
            .pending_page([1; 32], [3; 32], Some([4; 32]), 0, 10, 8192)
            .unwrap()
            .rows
            .len(),
        1
    );
    assert_eq!(
        reopened
            .pending_page([2; 32], [3; 32], Some([4; 32]), 0, 10, 8192)
            .unwrap()
            .rows
            .len(),
        1
    );
    assert_eq!(
        full(&owner.open("a", [4; 32]).unwrap().state),
        reopened.note_state(scope(proof.id().0, 1).key).unwrap()
    );
}

#[test]
fn cold_open_seeds_first_save_and_checkpoint_without_replaying_legacy_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    let (proof, signed) = test_only_verified();
    let key = scope(proof.id().0, 1).key;
    let db = anchored(&path, &proof, &signed);
    let replay = db.read_pool().unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    let old = Note::new().unwrap().append_paragraph("old").unwrap();
    for n in 0..256u16 {
        conn.execute(
            "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![
                key.base,
                key.audience,
                key.note,
                [n.to_be_bytes().as_slice(), &[0; 14]].concat(),
                old
            ],
        )
        .unwrap();
    }
    let owner = Owner::without_maintenance();
    let id = owner
        .register(db, Some(&proof), issuer(proof.id().0, 1, "writer"))
        .unwrap();
    owner.bind("writer", id).unwrap();
    let opened = owner.open("writer", key.note).unwrap();
    assert_eq!(replay.replayed_rows(), 256, "exactly one cold replay pass");
    // Destroy one old projection row after loading. A second replay (whether
    // for first save or checkpoint) would now fail, while the owned Note is sound.
    conn.execute("UPDATE note_updates SET delta=x'ff' WHERE id=2", [])
        .unwrap();
    let new = Note::new().unwrap().append_paragraph("new").unwrap();
    owner
        .commit_queued("writer", opened.generation, [255; 16], &new)
        .unwrap();
    assert_eq!(
        replay.replayed_rows(),
        256,
        "first save cannot replay old history"
    );
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let covered: Option<i64> = conn
            .query_row(
                "SELECT local_frontier FROM note_checkpoints WHERE base=?1",
                [key.base.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        if covered.is_some_and(|n| n >= 256) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "cold checkpoint replayed old rows or did not publish"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        replay.replayed_rows(),
        256,
        "checkpoint used the rebuilt Note"
    );
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

fn insert_rows(conn: &rusqlite::Connection, key: NoteKey, rows: &[&[u8]]) {
    for (n, delta) in rows.iter().enumerate() {
        conn.execute(
            "INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![
                key.base,
                key.audience,
                key.note,
                [(n as u16).to_be_bytes().as_slice(), &[0; 14]].concat(),
                delta
            ],
        )
        .unwrap();
    }
}
/// The published checkpoint, once the background job has covered `rows`.
fn wait_for_checkpoint(conn: &rusqlite::Connection, key: NoteKey, rows: usize) -> OrderedState {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let checkpoint: Option<(i64, Vec<u8>)> = conn
            .query_row(
                "SELECT local_frontier,encoded_yjs FROM note_checkpoints WHERE base=?1",
                [key.base.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .unwrap();
        if let Some((covered, encoded)) = checkpoint
            && covered >= rows as i64
        {
            return OrderedState::decode(&encoded).unwrap();
        }
        assert!(
            std::time::Instant::now() < deadline,
            "background checkpoint did not publish"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn open_and_its_checkpoint_keep_the_integrated_structure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ordered.db");
    let (proof, signed) = test_only_verified();
    let key = scope(proof.id().0, 1).key;
    let db = anchored(&path, &proof, &signed);
    let conn = rusqlite::Connection::open(&path).unwrap();
    // Enough rows that a checkpoint is due at open.
    let old = Note::new().unwrap().append_paragraph("old").unwrap();
    let rows: Vec<&[u8]> = K2.iter().copied().chain([old.as_slice(); 256]).collect();
    insert_rows(&conn, key, &rows);
    let mut live = Note::new().unwrap();
    for delta in &rows {
        live.apply_update(delta).unwrap();
    }
    let owner = Owner::default();
    let id = owner
        .register(db, Some(&proof), issuer(proof.id().0, 1, "writer"))
        .unwrap();
    owner.bind("writer", id).unwrap();
    let opened = owner.open("writer", key.note).unwrap();
    // One full state reopens differently, so the view gets the stored order
    // and the background checkpoint does the compaction.
    assert_eq!(opened.state.segments().len(), rows.len());
    let view = Note::from_ordered(&opened.state).unwrap();
    assert_eq!(view.digest().unwrap(), live.digest().unwrap());
    assert!(
        view.title_preview()
            .unwrap()
            .starts_with("helloH worldabcdL")
    );
    let published = wait_for_checkpoint(&conn, key, rows.len());
    assert!(published.segments().len() < rows.len());
    assert_eq!(
        Note::from_ordered(&published).unwrap().digest().unwrap(),
        live.digest().unwrap()
    );
    drop(owner);
    let owner = Owner::default();
    let id = owner
        .register(
            DeviceDatabase::open(&path).unwrap(),
            Some(&proof),
            issuer(proof.id().0, 1, "writer"),
        )
        .unwrap();
    owner.bind("writer", id).unwrap();
    let reopened = owner.open("writer", key.note).unwrap();
    assert_eq!(reopened.state, published);
    assert_eq!(
        Note::from_ordered(&reopened.state)
            .unwrap()
            .digest()
            .unwrap(),
        live.digest().unwrap()
    );
}

#[test]
fn opening_a_hostile_million_position_note_rebuilds_at_most_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hostile.db");
    let (proof, signed) = test_only_verified();
    let key = scope(proof.id().0, 1).key;
    let db = anchored(&path, &proof, &signed);
    let conn = rusqlite::Connection::open(&path).unwrap();
    // K2, then about a million positions as one update, then 256 saves.
    let mut author = Note::with_writer(9).unwrap();
    let line = "x".repeat(98);
    for _ in 0..9_990 {
        author.append_paragraph(&line).unwrap();
    }
    let big = author.state().unwrap();
    let saves: Vec<Vec<u8>> = (0..256)
        .map(|n| author.append_paragraph(&format!("save {n}")).unwrap())
        .collect();
    let rows: Vec<&[u8]> = K2
        .iter()
        .copied()
        .chain([big.as_slice()])
        .chain(saves.iter().map(Vec::as_slice))
        .collect();
    insert_rows(&conn, key, &rows);
    let mut live = Note::new().unwrap();
    for delta in &rows {
        live.apply_update(delta).unwrap();
    }
    assert!(live.document_positions().unwrap() >= 1_000_000);
    let owner = Owner::default();
    let id = owner
        .register(db, Some(&proof), issuer(proof.id().0, 1, "writer"))
        .unwrap();
    owner.bind("writer", id).unwrap();
    // Background compaction runs on its own workers, not this thread.
    let before = bh_core::note::verification_rebuilds();
    let opened = owner.open("writer", key.note).unwrap();
    let rebuilds = bh_core::note::verification_rebuilds() - before;
    assert!(rebuilds <= 1, "{rebuilds} rebuilds on open");
    assert_eq!(
        Note::from_ordered(&opened.state).unwrap().digest().unwrap(),
        live.digest().unwrap()
    );
    let published = wait_for_checkpoint(&conn, key, rows.len());
    assert_eq!(
        Note::from_ordered(&published).unwrap().digest().unwrap(),
        live.digest().unwrap()
    );
}

#[test]
fn stale_retry_cannot_erase_new_generation_after_validation() {
    let dir = tempfile::tempdir().unwrap();
    let (proof, signed) = test_only_verified();
    let fixture = TestIssuer(HashMap::from([
        ("writer".into(), scope(proof.id().0, 1)),
        ("reader".into(), scope(proof.id().0, 1)),
    ]));
    let owner = Arc::new(Owner::default());
    let id = owner
        .register(
            anchored(&dir.path().join("retry.db"), &proof, &signed),
            Some(&proof),
            Box::new(fixture),
        )
        .unwrap();
    owner.bind("writer", id).unwrap();
    owner.bind("reader", id).unwrap();
    let writer = owner.open("writer", [4; 32]).unwrap();
    owner.open("reader", [4; 32]).unwrap();
    let delta = Note::new().unwrap().append_paragraph("first").unwrap();
    owner
        .commit_queued("writer", writer.generation, [1; 16], &delta)
        .unwrap();
    let mut first = Vec::new();
    owner.drain_surface_once("reader", &mut |item| first.push(item));
    let (ready, resume) = mpsc::channel();
    let (go, continued) = mpsc::channel();
    let old = first.pop().unwrap();
    let worker = Arc::clone(&owner);
    let job = thread::spawn(move || {
        worker.retry_delivery_with_hook(&old, || {
            ready.send(()).unwrap();
            continued.recv().unwrap();
        })
    });
    resume.recv().unwrap();
    let reopened = owner.open("reader", [4; 32]).unwrap();
    owner
        .commit_queued(
            "writer",
            writer.generation,
            [2; 16],
            &Note::new().unwrap().append_paragraph("new").unwrap(),
        )
        .unwrap();
    go.send(()).unwrap();
    job.join().unwrap();
    let mut delivered = Vec::new();
    assert!(owner.drain_surface_once("reader", &mut |item| delivered.push(item)));
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].generation, reopened.generation);
    assert!(!delivered[0].update.is_empty());
}

#[test]
fn read_only_and_failed_opens_release_idle_work_slots() {
    let dir = tempfile::tempdir().unwrap();
    let (proof, signed) = test_only_verified();
    let owner = Arc::new(Owner::default());
    let id = owner
        .register(
            anchored(&dir.path().join("readers.db"), &proof, &signed),
            Some(&proof),
            issuer(proof.id().0, 1, "reader"),
        )
        .unwrap();
    owner.bind("reader", id).unwrap();
    for _ in 0..1000 {
        let opened = owner.open("reader", [4; 32]).unwrap();
        owner.close_generation("reader", opened.generation);
    }
    assert_eq!(owner.note_work_slot_count(), 0);
    let key = scope(proof.id().0, 1).key;
    let db = owner.shared_database(id).unwrap();
    db.lock()
        .unwrap()
        .commit_working_update_timed(key, 0, proof.id().0, [8; 16], &[255])
        .unwrap();
    assert!(owner.open("reader", [4; 32]).is_err());
    assert_eq!(owner.note_work_slot_count(), 0);
}

#[test]
fn concurrent_note_work_reuses_one_slot_until_last_user_finishes() {
    let dir = tempfile::tempdir().unwrap();
    let (proof, signed) = test_only_verified();
    let owner = Arc::new(Owner::default());
    let id = owner
        .register(
            anchored(&dir.path().join("concurrent.db"), &proof, &signed),
            Some(&proof),
            issuer(proof.id().0, 1, "reader"),
        )
        .unwrap();
    owner.bind("reader", id).unwrap();
    let opened = owner.open("reader", [4; 32]).unwrap();
    let (ready, waiting) = mpsc::channel();
    let (release, resume) = mpsc::channel();
    let first = Arc::clone(&owner);
    let writer = thread::spawn(move || {
        first
            .commit_with_work_hook(
                "reader",
                opened.generation,
                [7; 16],
                &Note::new().unwrap().append_paragraph("one").unwrap(),
                || {
                    ready.send(()).unwrap();
                    resume.recv().unwrap();
                },
                |_| {},
            )
            .unwrap()
    });
    waiting.recv().unwrap();
    assert_eq!(owner.note_work_slot_count(), 1);
    let (began, begin) = mpsc::channel();
    let second = Arc::clone(&owner);
    let reader = thread::spawn(move || {
        began.send(()).unwrap();
        second
            .commit_queued(
                "reader",
                opened.generation,
                [8; 16],
                &Note::new().unwrap().append_paragraph("two").unwrap(),
            )
            .unwrap()
    });
    begin.recv().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while owner.note_work_slot_users(id, scope(proof.id().0, 1).key) < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "second user must share the first slot"
        );
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(owner.note_work_slot_count(), 1);
    release.send(()).unwrap();
    writer.join().unwrap();
    reader.join().unwrap();
    assert_eq!(owner.note_work_slot_count(), 0);
}

#[test]
fn one_unacked_native_delivery_bounds_hundreds_of_pending_updates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("slow-window.db");
    let (proof, signed) = test_only_verified();
    let fixture = TestIssuer(HashMap::from([
        ("writer".into(), scope(proof.id().0, 1)),
        ("reader".into(), scope(proof.id().0, 1)),
    ]));
    let owner = Owner::default();
    let id = owner
        .register(
            anchored(&path, &proof, &signed),
            Some(&proof),
            Box::new(fixture),
        )
        .unwrap();
    owner.bind("writer", id).unwrap();
    owner.bind("reader", id).unwrap();
    let writer = owner.open("writer", [4; 32]).unwrap();
    owner.open("reader", [4; 32]).unwrap();
    // One large repeated update exceeds the 256-KiB byte budget well
    // before 64 rows: a rows-only queue mutant must fail this test.
    let delta = Note::new()
        .unwrap()
        .append_paragraph(&"x".repeat(8192))
        .unwrap();
    owner
        .commit_queued("writer", writer.generation, [1; 16], &delta)
        .unwrap();
    let mut delivered = Vec::new();
    assert!(owner.drain_surface_once("reader", &mut |d| delivered.push(d)));
    assert_eq!(delivered.len(), 1);
    owner.retry_delivery(&delivered[0]); // eval rejected after dequeue
    assert_eq!(owner.queued_delivery_budget("reader"), (1, 0, true));
    let rejected = delivered.pop().unwrap();
    let mut resync = Vec::new();
    assert!(owner.drain_surface_once("reader", &mut |d| resync.push(d)));
    assert!(resync[0].resync, "rejection retries as durable snapshot");
    let reopened = owner.open("reader", [4; 32]).unwrap();
    owner.retry_delivery(&rejected); // callback from prior generation
    assert_eq!(owner.queued_delivery_budget("reader"), (0, 0, false));
    for n in 2..=301u16 {
        owner
            .commit_queued(
                "writer",
                writer.generation,
                n.to_be_bytes().repeat(8).try_into().unwrap(),
                &delta,
            )
            .unwrap();
    }
    let (rows, bytes, resync) = owner.queued_delivery_budget("reader");
    assert!(
        rows <= 64 && bytes <= 256 * 1024 && resync,
        "unacked WebView must not queue hundreds of unbounded updates"
    );
    let mut next = Vec::new();
    assert!(owner.drain_surface_once("reader", &mut |d| next.push(d)));
    assert_eq!(
        next.len(),
        1,
        "one eval lease schedules one evaluation only"
    );
    assert!(next[0].resync);
    assert_eq!(next[0].generation, reopened.generation);
}

/// Explicit scale probe: realistic one-writer growing Yjs paragraph deltas,
/// a retained 1-MiB paragraph, and cold open followed by two ordinary saves.
/// BH_OWNER_SCALE_ONLY=20000 or 100000 selects one case.
#[test]
#[ignore = "opt-in realistic legacy replay and owner first-save timing"]
fn realistic_legacy_owner_open_and_two_saves() {
    let counts = match std::env::var("BH_OWNER_SCALE_ONLY").ok().as_deref() {
        Some("20000") => vec![20_000],
        Some("100000") => vec![100_000],
        _ => vec![20_000, 100_000],
    };
    fn rss() -> usize {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmRSS:"))?
                    .split_whitespace()
                    .nth(1)?
                    .parse::<usize>()
                    .ok()
            })
            .unwrap_or(0)
            * 1024
    }
    for count in counts {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.db");
        let (proof, signed) = test_only_verified();
        let db = anchored(&path, &proof, &signed);
        let replay = db.read_pool().unwrap();
        let key = scope(proof.id().0, 1).key;
        let mut source = Note::new().unwrap();
        let first = source.append_paragraph(&"x".repeat(1024 * 1024)).unwrap();
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        let insert = |n: usize, delta: Vec<u8>| {
            conn.execute("INSERT INTO note_updates(base,audience,note,request,delta) VALUES (?1,?2,?3,?4,?5)",
                rusqlite::params![key.base, key.audience, key.note, (n as u128).to_be_bytes(), delta]).unwrap();
        };
        insert(0, first);
        for n in 0..count {
            insert(n + 1, source.append_paragraph("a").unwrap());
        }
        conn.execute_batch("COMMIT").unwrap();
        drop(source);
        let before_rss = rss();
        let owner = Owner::without_maintenance();
        let id = owner
            .register(db, Some(&proof), issuer(proof.id().0, 1, "writer"))
            .unwrap();
        owner.bind("writer", id).unwrap();
        let started = std::time::Instant::now();
        let opened = owner.open("writer", key.note).unwrap();
        let open_time = started.elapsed();
        let after_rss = rss();
        assert_eq!(replay.replayed_rows(), count + 1, "one replay on cold open");
        let started = std::time::Instant::now();
        owner
            .commit_queued(
                "writer",
                opened.generation,
                [1; 16],
                &Note::new().unwrap().append_paragraph("first").unwrap(),
            )
            .unwrap();
        let first_time = started.elapsed();
        let started = std::time::Instant::now();
        owner
            .commit_queued(
                "writer",
                opened.generation,
                [2; 16],
                &Note::new().unwrap().append_paragraph("second").unwrap(),
            )
            .unwrap();
        let second_time = started.elapsed();
        assert_eq!(
            replay.replayed_rows(),
            count + 1,
            "first and second saves reuse committed Note"
        );
        eprintln!(
            "owner_legacy_updates={count} open={open_time:?} first_save={first_time:?} second_save={second_time:?} replayed_rows={} state_bytes={} rss_before={before_rss} rss_after={after_rss} rss_delta={} cache_budget_estimate={} containers=1",
            replay.replayed_rows(),
            opened.state.encode().len(),
            after_rss.saturating_sub(before_rss),
            3 * opened.state.encode().len() + 4096
        );
    }
}

#[test]
fn failed_background_compaction_retries_on_next_open() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("retry.db");
    let (proof, signed) = test_only_verified();
    let owner = Owner::default();
    let id = owner
        .register(
            anchored(&path, &proof, &signed),
            Some(&proof),
            issuer(proof.id().0, 1, "writer"),
        )
        .unwrap();
    owner.bind("writer", id).unwrap();
    let opened = owner.open("writer", [4; 32]).unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER refuse_checkpoint BEFORE INSERT ON note_checkpoints BEGIN SELECT RAISE(ABORT,'temporarily unavailable'); END").unwrap();
    for n in 0..256u16 {
        let mut request = [0u8; 16];
        request[..2].copy_from_slice(&n.to_be_bytes());
        owner
            .commit_queued(
                "writer",
                opened.generation,
                request,
                &Note::new().unwrap().append_paragraph("offline").unwrap(),
            )
            .unwrap();
    }
    thread::sleep(Duration::from_millis(200)); // let the first background write meet the injected SQLite failure
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM note_checkpoints", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    conn.execute_batch("DROP TRIGGER refuse_checkpoint")
        .unwrap();
    thread::sleep(Duration::from_millis(400));
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM note_checkpoints", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0,
        "failed checkpoint must not retry forever without foreground work"
    );
    // Reopening, not a background timer, schedules the failed projection again.
    owner.open("writer", [4; 32]).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    loop {
        let covered: Option<i64> = conn
            .query_row(
                "SELECT local_frontier FROM note_checkpoints WHERE base=?1",
                [[1u8; 32].as_slice()],
                |r| r.get(0),
            )
            .optional()
            .unwrap();
        if covered.is_some_and(|value| value >= 256) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "failed job was never rescheduled after the trigger disappeared"
        );
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM pending_note_work", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        256
    );
}

#[test]
fn failed_resnapshot_stays_bounded_and_later_merges_all_committed_updates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("resync.db");
    let (proof, signed) = test_only_verified();
    let owner = Owner::default();
    let fixture = TestIssuer(HashMap::from([
        ("writer".into(), scope(proof.id().0, 1)),
        ("reader".into(), scope(proof.id().0, 1)),
    ]));
    let id = owner
        .register(
            anchored(&path, &proof, &signed),
            Some(&proof),
            Box::new(fixture),
        )
        .unwrap();
    owner.bind("writer", id).unwrap();
    owner.bind("reader", id).unwrap();
    let writer = owner.open("writer", [4; 32]).unwrap();
    owner.open("reader", [4; 32]).unwrap();
    for n in 0..82u8 {
        owner
            .commit_queued(
                "writer",
                writer.generation,
                [n; 16],
                &Note::new().unwrap().append_paragraph("committed").unwrap(),
            )
            .unwrap();
    }
    assert!(
        owner.queued_delivery_budget("reader").2,
        "overflow must be metadata, not a heap of dropped raw bytes"
    );
    assert!(owner.queued_delivery_budget("reader").0 <= 64);
    let mut seen = Vec::new();
    assert!(
        !owner.drain_surface_with_snapshot("reader", &mut |d| seen.push(d), |_| Err(
            bh_storage::StoreError::InvalidUpdate
        ))
    );
    assert!(seen.is_empty());
    assert!(owner.queued_delivery_budget("reader").0 <= 64);
    for n in 82..97u8 {
        owner
            .commit_queued(
                "writer",
                writer.generation,
                [n; 16],
                &Note::new()
                    .unwrap()
                    .append_paragraph("after failure")
                    .unwrap(),
            )
            .unwrap();
    }
    let read_pool = DeviceDatabase::open(&path).unwrap().read_pool().unwrap();
    assert!(
        !owner.drain_surface_with_snapshot("reader", &mut |d| seen.push(d), |key| {
            let (state, _) = read_pool.note_ordered(key)?;
            Ok((state, 0))
        }),
        "snapshot below the marker's covered row cannot claim its sequence"
    );
    assert!(owner.queued_delivery_budget("reader").0 <= 64);
    assert!(
        owner.drain_surface_with_snapshot("reader", &mut |d| seen.push(d), |key| {
            read_pool.note_ordered(key)
        })
    );
    assert!(seen.iter().any(|d| d.resync));
    let mut merged = Note::new().unwrap();
    for d in seen {
        // A resync carries the note's ordered updates, a delta one update.
        for update in if d.resync { d.segments } else { vec![d.update] } {
            merged.apply_update(&update).unwrap();
        }
    }
    assert_eq!(
        merged.state().unwrap(),
        full(&owner.open("reader", [4; 32]).unwrap().state)
    );
    owner
        .commit_queued(
            "writer",
            writer.generation,
            [99; 16],
            &Note::new().unwrap().append_paragraph("fenced").unwrap(),
        )
        .unwrap();
    owner.invalidate("reader");
    assert_eq!(owner.queued_delivery_budget("reader"), (0, 0, false));
    assert!(owner.drain_surface_with_snapshot(
        "reader",
        &mut |_| panic!("navigated surface"),
        |_| panic!("no snapshot")
    ));
}

#[test]
fn failed_resnapshot_during_reopen_does_not_wedge_new_generation() {
    let dir = tempfile::tempdir().unwrap();
    let (proof, signed) = test_only_verified();
    let owner = Owner::default();
    let issuer = TestIssuer(HashMap::from([
        ("writer".into(), scope(proof.id().0, 1)),
        ("reader".into(), scope(proof.id().0, 1)),
    ]));
    let id = owner
        .register(
            anchored(&dir.path().join("reopen.db"), &proof, &signed),
            Some(&proof),
            Box::new(issuer),
        )
        .unwrap();
    owner.bind("writer", id).unwrap();
    owner.bind("reader", id).unwrap();
    let writer = owner.open("writer", [4; 32]).unwrap();
    owner.open("reader", [4; 32]).unwrap();
    for n in 0..82u8 {
        owner
            .commit_queued(
                "writer",
                writer.generation,
                [n; 16],
                &Note::new().unwrap().append_paragraph("overflow").unwrap(),
            )
            .unwrap();
    }
    assert!(owner.queued_delivery_budget("reader").2);
    let mut reopened = None;
    assert!(owner.drain_surface_with_snapshot(
        "reader",
        &mut |_| panic!("failed snapshot"),
        |_| {
            reopened = Some(owner.open("reader", [4; 32]).unwrap());
            Err(bh_storage::StoreError::InvalidUpdate)
        }
    ));
    owner
        .commit_queued(
            "writer",
            writer.generation,
            [99; 16],
            &Note::new()
                .unwrap()
                .append_paragraph("new generation")
                .unwrap(),
        )
        .unwrap();
    let mut delivered = Vec::new();
    assert!(owner.drain_surface("reader", &mut |d| delivered.push(d)));
    assert!(
        delivered
            .iter()
            .any(|d| d.generation == reopened.as_ref().unwrap().generation),
        "reopened window must receive new-generation deliveries without spinning"
    );
    assert!(!owner.has_queued_delivery("reader"));
}

#[test]
fn overflow_resync_is_ordered_and_does_not_block_same_container_writes() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Arc::new(Owner::default());
    let (proof, signed) = test_only_verified();
    let listeners = TestIssuer(HashMap::from([
        ("writer".into(), scope(proof.id().0, 1)),
        ("reader".into(), scope(proof.id().0, 1)),
    ]));
    let id = owner
        .register(
            anchored(&dir.path().join("a.db"), &proof, &signed),
            Some(&proof),
            Box::new(listeners),
        )
        .unwrap();
    owner.bind("writer", id).unwrap();
    owner.bind("reader", id).unwrap();
    let opened = owner.open("writer", [4; 32]).unwrap();
    owner.open("reader", [4; 32]).unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let work = Arc::clone(&owner);
    let results = Arc::clone(&seen);
    let first = thread::spawn(move || {
        work.commit(
            "writer",
            opened.generation,
            [1; 16],
            &Note::new().unwrap().append_paragraph("first").unwrap(),
            |d| {
                if results.lock().unwrap().is_empty() {
                    started_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                }
                results.lock().unwrap().push(d);
            },
        )
        .unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    for index in 2..90u8 {
        owner
            .commit(
                "writer",
                opened.generation,
                [index; 16],
                &Note::new().unwrap().append_paragraph("later").unwrap(),
                |_| {},
            )
            .unwrap();
    }
    release_tx.send(()).unwrap();
    first.join().unwrap();
    let deliveries = seen.lock().unwrap();
    assert!(
        deliveries.iter().any(|item| item.resync),
        "overflow must replace dropped deltas with a full merge snapshot"
    );
    let mut merged = Note::new().unwrap();
    for d in deliveries.iter() {
        for update in if d.resync {
            &d.segments[..]
        } else {
            std::slice::from_ref(&d.update)
        } {
            merged.apply_update(update).unwrap();
        }
    }
    // A stale earlier update is harmless: the Yjs merge, not editor recreation,
    // retains the in-flight local edits and resolves dependencies.
    assert_eq!(
        merged.state().unwrap(),
        full(&owner.open("reader", [4; 32]).unwrap().state)
    );
}

/// The full state a view reaches after applying an open's ordered updates.
fn full(state: &OrderedState) -> Vec<u8> {
    Note::from_ordered(state).unwrap().state().unwrap()
}
