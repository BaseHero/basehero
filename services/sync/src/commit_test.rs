use super::*;
use bh_sync::OrderState;

fn approval(
    state: GateState,
    operation: &Operation,
    key: &bh_crypto::SigningKey,
) -> SignedApproval {
    let approval = bh_sync::Approval {
        base: state.base,
        expected_head: state.head,
        incarnation: state.incarnation,
        sequence: state.sequence + 1,
        nonce: [3; 32],
        operation: operation.digest(),
        response_binding: Digest([6; 32]),
        not_before: 100,
        expires: 200,
    };
    SignedApproval {
        signature: key.sign(&approval.signing_bytes()),
        approval,
    }
}
fn append(db: &mut Database, event: &OpaqueEvent, key: &bh_crypto::SigningKey) -> Commitment {
    let body = BodyObject::new(vec![7; 1024]).unwrap();
    let stage = Operation::StageBody(body);
    let grant = approval(db.state().unwrap(), &stage, key);
    assert!(matches!(
        db.consume(&grant, &stage, Digest([6; 32]), &TestClock),
        Ok(Outcome::Staged(_))
    ));
    let op = Operation::Append(event.clone());
    let grant = approval(db.state().unwrap(), &op, key);
    match db
        .consume(&grant, &op, Digest([6; 32]), &TestClock)
        .unwrap()
    {
        Outcome::Ack(ack) => ack,
        other => panic!("unexpected outcome: {other:?}"),
    }
}

#[test]
fn canonical_restart_preserves_opening_and_genesis_retry_after_content() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("order.db");
    let key = bh_crypto::SigningKey::from_seed(&bh_crypto::Secret::from_slice(&[8; 32]).unwrap());
    let mut bytes = BodyObject::new(vec![7; 1024])
        .unwrap()
        .commitment()
        .0
        .to_vec();
    bytes.extend([9; 992]);
    let genesis = OpaqueEvent::new(EventId([1; 32]), bytes.clone()).unwrap();
    let content = OpaqueEvent::new(EventId([2; 32]), bytes).unwrap();
    let initial = GateState {
        base: BaseId::from_genesis(&genesis),
        order: OrderState::EMPTY,
        head: Head::EMPTY,
        incarnation: [1; 32],
        sequence: 0,
        checker_key: key.public(),
    };
    let mut db = Database::create(&path, initial).unwrap();
    let first = append(&mut db, &genesis, &key);
    let second = append(&mut db, &content, &key);
    assert_eq!(db.state().unwrap().order, second.after());
    drop(db);
    let mut db = Database::open(&path).unwrap();
    assert_eq!(db.state().unwrap().order, second.after());
    let retry = append(&mut db, &genesis, &key);
    assert_eq!(retry.encode(), first.encode());
    assert_eq!(
        retry.event_id(),
        genesis.publication_id(bh_sync::Route::Control)
    );
    assert_eq!(db.state().unwrap().head, second.head());
}

#[test]
fn markerless_and_mismatched_order_gate_refuse_without_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("order.db");
    let key = bh_crypto::SigningKey::from_seed(&bh_crypto::Secret::from_slice(&[8; 32]).unwrap());
    let mut bytes = BodyObject::new(vec![7; 1024])
        .unwrap()
        .commitment()
        .0
        .to_vec();
    bytes.extend([9; 992]);
    let genesis = OpaqueEvent::new(EventId([1; 32]), bytes).unwrap();
    let initial = GateState {
        base: BaseId::from_genesis(&genesis),
        order: OrderState::EMPTY,
        head: Head::EMPTY,
        incarnation: [1; 32],
        sequence: 0,
        checker_key: key.public(),
    };
    let mut db = Database::create(&path, initial).unwrap();
    append(&mut db, &genesis, &key);
    db.connection
        .execute("UPDATE gate SET order_format=NULL", [])
        .unwrap();
    drop(db);
    assert!(matches!(Database::open(&path), Err(Refusal::Unavailable)));
    let conn = Connection::open(&path).unwrap();
    let marker: Option<i64> = conn
        .query_row("SELECT order_format FROM gate", [], |r| r.get(0))
        .unwrap();
    assert_eq!(marker, None);
    conn.execute(
        "UPDATE gate SET order_format=2, opening=?1",
        [OrderState::EMPTY.encode().to_vec()],
    )
    .unwrap();
    drop(conn);
    assert!(matches!(Database::open(&path), Err(Refusal::Unavailable)));
}

#[test]
fn actual_tail_not_just_gate_row_is_required_on_open_state_and_stage() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("order.db");
    let key = bh_crypto::SigningKey::from_seed(&bh_crypto::Secret::from_slice(&[8; 32]).unwrap());
    let mut bytes = BodyObject::new(vec![7; 1024])
        .unwrap()
        .commitment()
        .0
        .to_vec();
    bytes.extend([9; 992]);
    let genesis = OpaqueEvent::new(EventId([1; 32]), bytes.clone()).unwrap();
    let content = OpaqueEvent::new(EventId([2; 32]), bytes).unwrap();
    let initial = GateState {
        base: BaseId::from_genesis(&genesis),
        head: Head::EMPTY,
        order: OrderState::EMPTY,
        incarnation: [1; 32],
        sequence: 0,
        checker_key: key.public(),
    };
    let mut db = Database::create(&path, initial).unwrap();
    append(&mut db, &genesis, &key);
    let first = db.state().unwrap();
    append(&mut db, &content, &key);
    let count = |db: &Database| {
        db.connection
            .query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))
            .unwrap()
    };
    assert_eq!(count(&db), 2);
    db.connection
        .execute(
            "UPDATE gate SET position=?1,chain_hash=?2,opening=?3,sequence=?4",
            params![
                number(first.head.position).unwrap(),
                first.head.hash.0.as_slice(),
                first.order.encode().as_slice(),
                number(first.sequence).unwrap()
            ],
        )
        .unwrap();
    let staged = Operation::StageBody(BodyObject::new(vec![7; 1024]).unwrap());
    let grant = approval(first, &staged, &key);
    assert!(matches!(db.state(), Err(Refusal::Unavailable)));
    assert!(matches!(
        db.consume(&grant, &staged, Digest([6; 32]), &TestClock),
        Err(Refusal::Unavailable)
    ));
    assert_eq!(count(&db), 2);
    drop(db);
    assert!(matches!(Database::open(&path), Err(Refusal::Unavailable)));
}

#[test]
fn empty_gate_refuses_a_stray_actual_tail() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("order.db");
    let key = bh_crypto::SigningKey::from_seed(&bh_crypto::Secret::from_slice(&[8; 32]).unwrap());
    let mut bytes = BodyObject::new(vec![7; 1024])
        .unwrap()
        .commitment()
        .0
        .to_vec();
    bytes.extend([9; 992]);
    let genesis = OpaqueEvent::new(EventId([1; 32]), bytes).unwrap();
    let initial = GateState {
        base: BaseId::from_genesis(&genesis),
        head: Head::EMPTY,
        order: OrderState::EMPTY,
        incarnation: [1; 32],
        sequence: 0,
        checker_key: key.public(),
    };
    let mut db = Database::create(&path, initial).unwrap();
    append(&mut db, &genesis, &key);
    db.connection
        .execute(
            "UPDATE gate SET position=0,chain_hash=zeroblob(32),opening=?1,sequence=0",
            [OrderState::EMPTY.encode().as_slice()],
        )
        .unwrap();
    assert!(matches!(db.state(), Err(Refusal::Unavailable)));
    drop(db);
    assert!(matches!(Database::open(&path), Err(Refusal::Unavailable)));
}

#[test]
fn missing_or_corrupt_actual_tail_refuses_before_any_operation() {
    for damaged in ["missing", "corrupt"] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("order.db");
        let key =
            bh_crypto::SigningKey::from_seed(&bh_crypto::Secret::from_slice(&[8; 32]).unwrap());
        let mut bytes = BodyObject::new(vec![7; 1024])
            .unwrap()
            .commitment()
            .0
            .to_vec();
        bytes.extend([9; 992]);
        let genesis = OpaqueEvent::new(EventId([1; 32]), bytes).unwrap();
        let initial = GateState {
            base: BaseId::from_genesis(&genesis),
            head: Head::EMPTY,
            order: OrderState::EMPTY,
            incarnation: [1; 32],
            sequence: 0,
            checker_key: key.public(),
        };
        let mut db = Database::create(&path, initial).unwrap();
        append(&mut db, &genesis, &key);
        if damaged == "missing" {
            db.connection
                .execute("DELETE FROM events WHERE position=1", [])
                .unwrap();
        } else {
            db.connection
                .execute(
                    "UPDATE events SET commitment=zeroblob(149) WHERE position=1",
                    [],
                )
                .unwrap();
        }
        assert!(matches!(db.state(), Err(Refusal::Unavailable)), "{damaged}");
        drop(db);
        assert!(
            matches!(Database::open(&path), Err(Refusal::Unavailable)),
            "{damaged}"
        );
    }
}

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
    // The descriptor's first 32 envelope bytes are the detached body commitment.
    let staged = BodyObject::new(vec![7; 1024]).unwrap();
    let mut envelope = staged.commitment().0.to_vec();
    envelope.extend(vec![9; 1024 - 32]);
    let event = OpaqueEvent::new(EventId([5; 32]), envelope).unwrap();
    let seed = bh_crypto::Secret::from_slice(&[8; 32]).unwrap();
    let key = bh_crypto::SigningKey::from_seed(&seed);
    let initial = GateState {
        base: BaseId::from_genesis(&event),
        head: Head::EMPTY,
        order: bh_sync::OrderState::EMPTY,
        incarnation: [1; 32],
        sequence: 0,
        checker_key: key.public(),
    };
    let mut db = Database::create(&path, initial).unwrap();
    // The referenced body must be durably staged before the descriptor append.
    db.connection
        .execute(
            "INSERT INTO bodies (base, commitment, body) VALUES (?1, ?2, ?3)",
            rusqlite::params![
                initial.base.0.as_slice(),
                staged.commitment().0.as_slice(),
                staged.bytes()
            ],
        )
        .unwrap();
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
