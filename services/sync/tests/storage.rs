use bh_sync::*;
use bh_sync_service::{Clock, Database, Outcome, Refusal};
use std::path::Path;

struct HostClock;
impl Clock for HostClock {
    fn window(&self) -> Result<TimeWindow, Refusal> {
        Ok(TimeWindow {
            earliest: 110,
            latest: 120,
        })
    }
}
const BINDING: Digest = Digest([6; 32]);
fn body(n: u8) -> BodyObject {
    BodyObject::new(vec![n; 1024]).unwrap()
}
/// Keep the descriptor invariant the kernel checks: the first 32 envelope bytes
/// are the detached body's commitment.
fn event_with_body(id: u8, seed: u8) -> OpaqueEvent {
    let body = body(seed);
    let mut envelope = body.commitment().0.to_vec();
    envelope.extend(vec![seed; 1024 - 32]);
    OpaqueEvent::new(EventId([id; 32]), envelope).unwrap()
}
fn event(n: u8) -> OpaqueEvent {
    event_with_body(n, n)
}
fn key() -> bh_crypto::SigningKey {
    bh_crypto::SigningKey::from_seed(&bh_crypto::Secret::from_slice(&[7; 32]).unwrap())
}
fn initial() -> GateState {
    let genesis = event(1);
    GateState {
        base: BaseId::from_genesis(&genesis),
        head: Head::EMPTY,
        incarnation: [4; 32],
        sequence: 0,
        checker_key: key().public(),
    }
}
fn grant(state: GateState, operation: &Operation) -> SignedApproval {
    let approval = Approval {
        base: state.base,
        expected_head: state.head,
        incarnation: state.incarnation,
        sequence: state.sequence + 1,
        nonce: [8; 32],
        operation: operation.digest(),
        response_binding: BINDING,
        not_before: 100,
        expires: 200,
    };
    SignedApproval {
        signature: key().sign(&approval.signing_bytes()),
        approval,
    }
}
fn new_db(path: &Path) -> Database {
    let db = Database::create(path, initial()).unwrap();
    // Seed the bodies the pre-existing append fixtures reference. Dedicated
    // body tests stage through the real approved operation instead.
    let conn = rusqlite::Connection::open(path).unwrap();
    for n in 1..=10u8 {
        conn.execute(
            "INSERT INTO bodies (base, commitment, body) VALUES (?1, ?2, ?3)",
            rusqlite::params![
                initial().base.0.as_slice(),
                body(n).commitment().0.as_slice(),
                body(n).bytes()
            ],
        )
        .unwrap();
    }
    db
}
fn count_rows(path: &Path) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap()
}
fn consume(db: &mut Database, operation: &Operation) -> Result<Outcome, Refusal> {
    db.consume(
        &grant(db.state().unwrap(), operation),
        operation,
        BINDING,
        &HostClock,
    )
}

#[test]
fn append_commit_reopen_and_lost_ack_reconcile() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    let mut db = new_db(&path);
    let op = Operation::Append(event(1));
    let signed = grant(initial(), &op);
    let original = match db.consume(&signed, &op, BINDING, &HostClock).unwrap() {
        Outcome::Ack(ack) => ack,
        _ => panic!("expected ack"),
    };
    assert_eq!(original.head().position, 1);
    assert_eq!(db.state().unwrap().sequence, 1);
    assert_eq!(db.last_outcome().unwrap().unwrap().approval, signed);
    assert_eq!(db.last_outcome().unwrap().unwrap().ack, Some(original));
    drop(db); // Response lost after commit; cold reopen is not a fresh authority proof.
    let mut db = Database::open(&path).unwrap();
    assert_eq!(db.state().unwrap().head, original.head());
    let read = Operation::read(vec![event(1).digest()]).unwrap();
    assert_eq!(
        consume(&mut db, &read).unwrap(),
        Outcome::Read(vec![event(1).encode()])
    );
    assert_eq!(
        db.consume(&signed, &op, BINDING, &HostClock),
        Err(Refusal::Access(AccessError::Stale))
    );
    consume(&mut db, &Operation::Append(event(2))).unwrap();
    let later = db.state().unwrap().head;
    let retry = consume(&mut db, &op).unwrap();
    assert_eq!(retry, Outcome::Ack(original));
    assert_eq!(db.state().unwrap().head, later);
    assert_eq!(db.state().unwrap().sequence, 4);
    assert_eq!(count_rows(&path), 2);
}

#[test]
fn exact_reads_consume_sequence_not_head_and_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = new_db(&dir.path().join("base.db"));
    for n in [1, 2] {
        consume(&mut db, &Operation::Append(event(n))).unwrap();
    }
    let before = db.state().unwrap();
    let read = Operation::read(vec![event(1).digest(), event(2).digest()]).unwrap();
    let signed = grant(before, &read);
    assert_eq!(
        db.consume(&signed, &read, Digest([9; 32]), &HostClock),
        Err(Refusal::Access(AccessError::Operation))
    );
    assert_eq!(db.state().unwrap(), before);
    assert_eq!(
        db.consume(&signed, &read, BINDING, &HostClock).unwrap(),
        Outcome::Read(vec![event(1).encode(), event(2).encode()])
    );
    assert_eq!(db.state().unwrap().head, before.head);
    assert_eq!(db.state().unwrap().sequence, before.sequence + 1);
    let before = db.state().unwrap();
    let missing = Operation::read(vec![event(1).digest(), Digest([3; 32])]).unwrap();
    assert_eq!(consume(&mut db, &missing), Err(Refusal::Unavailable));
    assert_eq!(db.state().unwrap(), before);
}

#[test]
fn conflicts_bad_signature_and_duplicate_prior_approval_do_not_mutate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    let mut first = new_db(&path);
    let mut second = Database::open(&path).unwrap();
    let op = Operation::Append(event(1));
    let prior = grant(initial(), &op);
    first.consume(&prior, &op, BINDING, &HostClock).unwrap();
    let after = first.state().unwrap();
    assert_eq!(
        second.consume(&prior, &op, BINDING, &HostClock),
        Err(Refusal::Access(AccessError::Stale))
    );
    let changed = Operation::Append(event_with_body(1, 9));
    assert_eq!(
        consume(&mut second, &changed),
        Err(Refusal::Access(AccessError::ReplayConflict))
    );
    let mut forged = grant(after, &op);
    forged.signature[0] ^= 1;
    assert_eq!(
        second.consume(&forged, &op, BINDING, &HostClock),
        Err(Refusal::Access(AccessError::Signature))
    );
    assert_eq!(second.state().unwrap(), after);
    assert_eq!(count_rows(&path), 1);
}

#[test]
fn corrupt_historical_body_commitment_or_index_blocks_replay_and_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    let mut db = new_db(&path);
    let first = Operation::Append(event(1));
    let original = match consume(&mut db, &first).unwrap() {
        Outcome::Ack(ack) => ack,
        _ => panic!("expected Ack"),
    };
    for n in [2, 3] {
        consume(&mut db, &Operation::Append(event(n))).unwrap();
    }
    assert_eq!(db.state().unwrap().head.position, 3);
    // Both exact lookups work at a later head before corruption; row 1 is
    // neither the head nor the immediate predecessor inspected by check_head.
    assert_eq!(consume(&mut db, &first), Ok(Outcome::Ack(original)));
    let read = Operation::read(vec![event(1).digest()]).unwrap();
    assert_eq!(
        consume(&mut db, &read),
        Ok(Outcome::Read(vec![event(1).encode()]))
    );
    let prior = db.state().unwrap();
    let last = db.last_outcome().unwrap();
    assert_eq!(count_rows(&path), 3);

    let conn = rusqlite::Connection::open(&path).unwrap();
    for (column, update) in [
        ("body", "UPDATE events SET body=x'00' WHERE position=1"),
        (
            "commitment",
            "UPDATE events SET commitment=x'00' WHERE position=1",
        ),
        (
            "event_id",
            "UPDATE events SET event_id=x'00' WHERE position=1",
        ),
        (
            "event_digest",
            "UPDATE events SET event_digest=x'00' WHERE position=1",
        ),
    ] {
        conn.execute(update, []).unwrap();
        assert_eq!(
            consume(&mut db, &first),
            Err(Refusal::Unavailable),
            "replay with corrupt {column}"
        );
        assert_eq!(
            consume(&mut db, &read),
            Err(Refusal::Unavailable),
            "read with corrupt {column}"
        );
        assert_eq!(db.state().unwrap(), prior, "gate changed for {column}");
        assert_eq!(
            db.last_outcome().unwrap(),
            last,
            "outcome changed for {column}"
        );
        assert_eq!(count_rows(&path), 3, "row count changed for {column}");
        conn.execute(
            "UPDATE events SET event_id=?1, event_digest=?2, commitment=?3, body=?4 WHERE position=1",
            rusqlite::params![event(1).id().0.as_slice(), event(1).digest().0.as_slice(), original.encode(), event(1).encode()],
        )
        .unwrap();
    }
}

#[test]
fn invalid_time_incarnation_and_sequence_never_consume() {
    struct Expired;
    impl Clock for Expired {
        fn window(&self) -> Result<TimeWindow, Refusal> {
            Ok(TimeWindow {
                earliest: 199,
                latest: 200,
            })
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let mut db = new_db(&dir.path().join("base.db"));
    let op = Operation::Append(event(1));
    let signed = grant(initial(), &op);
    assert_eq!(
        db.consume(&signed, &op, BINDING, &Expired),
        Err(Refusal::Access(AccessError::Time))
    );
    let mut wrong = signed;
    wrong.approval.incarnation = [3; 32];
    wrong.signature = key().sign(&wrong.approval.signing_bytes());
    assert_eq!(
        db.consume(&wrong, &op, BINDING, &HostClock),
        Err(Refusal::Access(AccessError::Stale))
    );
    wrong = signed;
    wrong.approval.sequence = 2;
    wrong.signature = key().sign(&wrong.approval.signing_bytes());
    assert_eq!(
        db.consume(&wrong, &op, BINDING, &HostClock),
        Err(Refusal::Access(AccessError::Stale))
    );
    assert_eq!(db.state().unwrap(), initial());
    assert_eq!(db.last_outcome().unwrap(), None);
}

#[test]
fn concurrent_consumers_of_one_prior_approval_commit_at_most_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    drop(new_db(&path));
    let signed = grant(initial(), &Operation::Append(event(1)));
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let jobs: Vec<_> = (0..2)
        .map(|_| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut db = Database::open(&path).unwrap();
                barrier.wait();
                db.consume(&signed, &Operation::Append(event(1)), BINDING, &HostClock)
            })
        })
        .collect();
    let results: Vec<_> = jobs.into_iter().map(|job| job.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| **result == Err(Refusal::Access(AccessError::Stale)))
            .count(),
        1
    );
    let db = Database::open(&path).unwrap();
    assert_eq!(db.state().unwrap().sequence, 1);
    assert_eq!(db.state().unwrap().head.position, 1);
    assert_eq!(count_rows(&path), 1);
}

#[test]
fn failed_insert_and_failed_compare_roll_back_without_ack() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    let mut db = new_db(&path);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_insert BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
    drop(conn);
    let op = Operation::Append(event(1));
    assert_eq!(consume(&mut db, &op), Err(Refusal::Unavailable));
    assert_eq!(db.state().unwrap(), initial());
    assert_eq!(db.last_outcome().unwrap(), None);
    assert_eq!(count_rows(&path), 0);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("DROP TRIGGER reject_insert; CREATE TRIGGER reject_compare BEFORE UPDATE ON gate BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
    drop(conn);
    assert_eq!(consume(&mut db, &op), Err(Refusal::Unavailable));
    assert_eq!(db.state().unwrap(), initial());
    assert_eq!(db.last_outcome().unwrap(), None);
    assert_eq!(count_rows(&path), 0);
}

#[test]
fn newer_schema_refuses_before_mutating() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    drop(new_db(&path));
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.pragma_update(None, "user_version", 3).unwrap();
    drop(conn);
    assert!(matches!(Database::open(&path), Err(Refusal::Unavailable)));
    let conn = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        conn.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
            .unwrap(),
        3
    );
}

fn body_rows(path: &Path) -> i64 {
    rusqlite::Connection::open(path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM bodies", [], |row| row.get(0))
        .unwrap()
}
fn initial_for(genesis: &OpaqueEvent) -> GateState {
    GateState {
        base: BaseId::from_genesis(genesis),
        head: Head::EMPTY,
        incarnation: [4; 32],
        sequence: 0,
        checker_key: key().public(),
    }
}
fn descriptor_for(body: &BodyObject) -> OpaqueEvent {
    let mut envelope = body.commitment().0.to_vec();
    envelope.extend(vec![0x22; 1024 - 32]);
    OpaqueEvent::new(EventId([1; 32]), envelope).unwrap()
}

#[test]
fn body_stage_append_and_read_survive_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    let body = BodyObject::new(vec![0x11; 4096]).unwrap();
    let descriptor = descriptor_for(&body);
    let mut db = Database::create(&path, initial_for(&descriptor)).unwrap();
    assert_eq!(
        consume(&mut db, &Operation::stage_body(body.clone())),
        Ok(Outcome::Staged(body.commitment()))
    );
    assert!(matches!(
        consume(&mut db, &Operation::Append(descriptor.clone())),
        Ok(Outcome::Ack(_))
    ));
    let read = Operation::read_bodies(vec![body.commitment()]).unwrap();
    assert_eq!(
        consume(&mut db, &read),
        Ok(Outcome::ReadBodies(vec![body.bytes().to_vec()]))
    );
    drop(db);
    let mut db = Database::open(&path).unwrap();
    assert_eq!(
        consume(&mut db, &read),
        Ok(Outcome::ReadBodies(vec![body.bytes().to_vec()]))
    );
    assert_eq!(db.state().unwrap().head.position, 1);
}

#[test]
fn append_without_the_referenced_body_is_refused_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    let body = BodyObject::new(vec![0x44; 1024]).unwrap();
    let descriptor = descriptor_for(&body);
    let mut db = Database::create(&path, initial_for(&descriptor)).unwrap();
    let before = db.state().unwrap();
    assert_eq!(
        consume(&mut db, &Operation::Append(descriptor.clone())),
        Err(Refusal::Access(AccessError::Body))
    );
    assert_eq!(db.state().unwrap(), before);
    assert_eq!(count_rows(&path), 0);
    assert_eq!(body_rows(&path), 0);
    // Stage a different body; the referenced one is still absent.
    let other = BodyObject::new(vec![0x45; 1024]).unwrap();
    assert_eq!(
        consume(&mut db, &Operation::stage_body(other.clone())),
        Ok(Outcome::Staged(other.commitment()))
    );
    assert_eq!(
        consume(&mut db, &Operation::Append(descriptor.clone())),
        Err(Refusal::Access(AccessError::Body))
    );
    assert_eq!(count_rows(&path), 0);
}

#[test]
fn wrong_size_and_mismatched_bodies_are_refused() {
    assert!(BodyObject::new(Vec::new()).is_err());
    assert!(BodyObject::new(vec![0; 1000]).is_err());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    let mismatched = BodyObject::new(vec![0x55; 1024]).unwrap();
    let descriptor = descriptor_for(&mismatched);
    let mut db = Database::create(&path, initial_for(&descriptor)).unwrap();
    // Staging the same-sized but different body cannot authorise the append.
    let other = BodyObject::new(vec![0x56; 1024]).unwrap();
    assert_eq!(
        consume(&mut db, &Operation::stage_body(other.clone())),
        Ok(Outcome::Staged(other.commitment()))
    );
    assert_eq!(
        consume(&mut db, &Operation::Append(descriptor.clone())),
        Err(Refusal::Access(AccessError::Body))
    );
    assert_eq!(count_rows(&path), 0);
}

#[test]
fn stale_replayed_or_misbound_body_approvals_never_consume() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    let mut db = new_db(&path);
    let before = db.state().unwrap();
    let stage = Operation::stage_body(body(5));
    let signed = grant(before, &stage);
    assert_eq!(
        db.consume(&signed, &stage, BINDING, &HostClock),
        Ok(Outcome::Staged(body(5).commitment()))
    );
    assert_eq!(
        db.consume(&signed, &stage, BINDING, &HostClock),
        Err(Refusal::Access(AccessError::Stale))
    );
    let after = db.state().unwrap();
    let other = Operation::stage_body(body(6));
    assert_eq!(
        db.consume(&grant(after, &stage), &other, BINDING, &HostClock),
        Err(Refusal::Access(AccessError::Operation))
    );
    assert_eq!(
        db.consume(&grant(after, &stage), &stage, Digest([9; 32]), &HostClock),
        Err(Refusal::Access(AccessError::Operation))
    );
    assert_eq!(db.state().unwrap(), after);
}

#[test]
fn staging_the_same_body_twice_is_idempotent_and_does_not_fork() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    let mut db = new_db(&path);
    let unique = BodyObject::new(vec![0x99; 4096]).unwrap();
    let stage = Operation::stage_body(unique.clone());
    assert_eq!(
        consume(&mut db, &stage),
        Ok(Outcome::Staged(unique.commitment()))
    );
    assert_eq!(body_rows(&path), 11);
    assert_eq!(
        consume(&mut db, &stage),
        Ok(Outcome::Staged(unique.commitment()))
    );
    assert_eq!(body_rows(&path), 11);
    assert_eq!(db.state().unwrap().sequence, 2);
    assert_eq!(count_rows(&path), 0);
}

#[test]
fn restaging_over_a_corrupt_stored_body_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    let mut db = new_db(&path);
    let unique = BodyObject::new(vec![0x99; 4096]).unwrap();
    let stage = Operation::stage_body(unique.clone());
    assert_eq!(
        consume(&mut db, &stage),
        Ok(Outcome::Staged(unique.commitment()))
    );
    let after = db.state().unwrap();
    // Same-size corruption: only the stored-commitment re-check can catch it.
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute(
        "UPDATE bodies SET body=zeroblob(4096) WHERE base=?1 AND commitment=?2",
        rusqlite::params![
            initial().base.0.as_slice(),
            unique.commitment().0.as_slice()
        ],
    )
    .unwrap();
    drop(conn);
    assert_eq!(consume(&mut db, &stage), Err(Refusal::Unavailable));
    assert_eq!(db.state().unwrap(), after);
}

#[test]
fn a_body_read_requires_its_own_approval() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    let mut db = new_db(&path);
    let body_read = Operation::read_bodies(vec![body(3).commitment()]).unwrap();
    // The same 32-byte object read through the event domain must still refuse:
    // if the domains were shared, this grant would authorise the body read.
    let event_read = Operation::read(vec![body(3).commitment()]).unwrap();
    let state = db.state().unwrap();
    assert_eq!(
        db.consume(&grant(state, &event_read), &body_read, BINDING, &HostClock),
        Err(Refusal::Access(AccessError::Operation))
    );
    assert_eq!(
        db.consume(&grant(state, &body_read), &body_read, BINDING, &HostClock),
        Ok(Outcome::ReadBodies(vec![body(3).bytes().to_vec()]))
    );
}

#[test]
fn corrupt_stored_body_is_refused_on_read_and_append() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    let mut db = Database::create(
        &path,
        initial_for(&descriptor_for(&BodyObject::new(vec![0x77; 1024]).unwrap())),
    )
    .unwrap();
    let body = BodyObject::new(vec![0x77; 1024]).unwrap();
    let descriptor = descriptor_for(&body);
    assert_eq!(
        consume(&mut db, &Operation::stage_body(body.clone())),
        Ok(Outcome::Staged(body.commitment()))
    );
    let read = Operation::read_bodies(vec![body.commitment()]).unwrap();
    assert_eq!(
        consume(&mut db, &read),
        Ok(Outcome::ReadBodies(vec![body.bytes().to_vec()]))
    );
    let before = db.state().unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute("UPDATE bodies SET body=zeroblob(1024)", [])
        .unwrap();
    drop(conn);
    assert_eq!(consume(&mut db, &read), Err(Refusal::Unavailable));
    assert_eq!(
        consume(&mut db, &Operation::Append(descriptor)),
        Err(Refusal::Unavailable)
    );
    assert_eq!(db.state().unwrap(), before);
    assert_eq!(count_rows(&path), 0);
}

#[test]
fn version_one_database_is_refused_without_mutating() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    let genesis = event(1);
    let base = BaseId::from_genesis(&genesis);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE gate (
            singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
            base BLOB NOT NULL, position INTEGER NOT NULL, chain_hash BLOB NOT NULL,
            incarnation BLOB NOT NULL, sequence INTEGER NOT NULL, checker_key BLOB NOT NULL,
            last_approval BLOB, last_ack BLOB
        );
        CREATE TABLE events (
            base BLOB NOT NULL, event_id BLOB NOT NULL, position INTEGER NOT NULL UNIQUE,
            event_digest BLOB NOT NULL UNIQUE, commitment BLOB NOT NULL, body BLOB NOT NULL,
            PRIMARY KEY(base, event_id)
        );
        PRAGMA user_version = 1;",
    )
    .unwrap();
    conn.execute(
        "INSERT INTO gate VALUES (1, ?1, 0, ?2, ?3, 0, ?4, NULL, NULL)",
        rusqlite::params![
            base.0.as_slice(),
            Head::EMPTY.hash.0.as_slice(),
            [4u8; 32].as_slice(),
            key().public().as_slice()
        ],
    )
    .unwrap();
    drop(conn);
    // A body-less v1 file is refused, not silently upgraded into dangling state.
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(Database::open(&path), Err(Refusal::Unavailable)));
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn real_event_sealed_body_reference_matches_and_stages() {
    use bh_account::{AccountId, DeviceId, Head as AccountHead};
    use bh_crypto::{Secret, SigningKey};
    let metadata = Secret::from_slice(&[5; 32]).unwrap();
    let content = Secret::from_slice(&[6; 32]).unwrap();
    let signer = SigningKey::from_seed(&Secret::from_slice(&[7; 32]).unwrap());
    let signed = bh_event::Binding {
        version: 2,
        highest: 2,
        mode: 0,
        base: [1; 32],
        audience: [2; 32],
        epoch: [3; 32],
        event_id: EventId([9; 32]),
        account: AccountId([4; 32]),
        device: DeviceId([5; 32]),
        account_head: AccountHead {
            position: 0,
            hash: [0; 32],
        },
        seen: Head::EMPTY,
        seen_control: [0; 32],
        class: bh_event::CLASS_CONTENT,
        padded: 0,
        commitment: [0; 32],
        // Packaging only: the hosted store never opens the binding.
        seen_receipt: [0; bh_sync::receipt::RECEIPT_LEN],
    };
    let encoded = bh_event::seal(
        signed,
        bh_event::Payload {
            kind: bh_event::NOTE,
            data: &[0x33; 40],
        },
        &signer,
        &metadata,
        Some(&content),
    )
    .unwrap();
    let staged = BodyObject::new(encoded.body.clone()).unwrap();
    assert_eq!(
        referenced_body(&encoded.descriptor).unwrap(),
        staged.commitment(),
        "the real codec's first descriptor bytes must be the kernel body commitment"
    );

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.db");
    let mut db = Database::create(&path, initial_for(&encoded.descriptor)).unwrap();
    assert_eq!(
        consume(&mut db, &Operation::stage_body(staged.clone())),
        Ok(Outcome::Staged(staged.commitment()))
    );
    assert!(matches!(
        consume(&mut db, &Operation::Append(encoded.descriptor.clone())),
        Ok(Outcome::Ack(_))
    ));
    let read = Operation::read_bodies(vec![staged.commitment()]).unwrap();
    assert_eq!(
        consume(&mut db, &read),
        Ok(Outcome::ReadBodies(vec![encoded.body.clone()]))
    );
}
