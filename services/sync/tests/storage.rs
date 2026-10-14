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
fn event(n: u8) -> OpaqueEvent {
    OpaqueEvent::new(EventId([n; 32]), vec![n; 1024]).unwrap()
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
    Database::create(path, initial()).unwrap()
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
    let changed = Operation::Append(OpaqueEvent::new(event(1).id(), vec![9; 1024]).unwrap());
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
    conn.pragma_update(None, "user_version", 2).unwrap();
    drop(conn);
    assert!(matches!(Database::open(&path), Err(Refusal::Unavailable)));
    let conn = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        conn.pragma_query_value(None, "user_version", |row| row.get::<_, u32>(0))
            .unwrap(),
        2
    );
}
