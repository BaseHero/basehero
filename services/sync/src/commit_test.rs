use super::*;

struct TestClock;
impl Clock for TestClock {
    fn window(&self) -> Result<TimeWindow, Refusal> {
        Ok(TimeWindow {
            earliest: 100,
            latest: 101,
        })
    }
}

#[test]
fn sqlite_commit_failure_releases_no_ack_and_rolls_back_insert_and_gate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("commit.db");
    let event = OpaqueEvent::new(EventId([5; 32]), vec![7; 1024]).unwrap();
    let seed = bh_crypto::Secret::from_slice(&[8; 32]).unwrap();
    let key = bh_crypto::SigningKey::from_seed(&seed);
    let initial = GateState {
        base: BaseId::from_genesis(&event),
        head: Head::EMPTY,
        incarnation: [1; 32],
        sequence: 0,
        checker_key: key.public(),
    };
    let mut db = Database::create(&path, initial).unwrap();
    db.connection.execute_batch("CREATE TABLE parent(id INTEGER PRIMARY KEY);
        CREATE TABLE fail_commit(parent INTEGER REFERENCES parent(id) DEFERRABLE INITIALLY DEFERRED);").unwrap();
    let operation = Operation::Append(event);
    let approval = bh_sync::Approval {
        base: initial.base,
        expected_head: initial.head,
        incarnation: initial.incarnation,
        sequence: 1,
        nonce: [3; 32],
        operation: operation.digest(),
        response_binding: Digest([6; 32]),
        not_before: 100,
        expires: 200,
    };
    let signed = SignedApproval {
        signature: key.sign(&approval.signing_bytes()),
        approval,
    };
    db.fail_commit = true;
    assert_eq!(
        db.consume(&signed, &operation, Digest([6; 32]), &TestClock),
        Err(Refusal::Unavailable)
    );
    drop(db);
    let db = Database::open(&path).unwrap();
    assert_eq!(db.state().unwrap(), initial);
    assert_eq!(db.last_outcome().unwrap(), None);
    assert_eq!(
        db.connection
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
}
