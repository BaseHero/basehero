//! An index becoming ready queues a durable replay pass instead of replaying
//! its whole backlog in the readiness transaction. Each bounded page commits
//! its verdicts, the own packages it decides and its cursor together.
use bh_crypto::{Secret, SigningKey};
use bh_data::{
    Actor, AppId, DataError, MutationId, Position, RecordId, RevisionId, Scope, Wait,
    admission::{Confirmation, HostAdmission, PriorRules, Unavailable},
    catalogue::Shipped,
    mutation::{
        apply::{Outcome, apply_payload_with_admission},
        ops::Operation,
        pending::{self, SubmitError},
    },
};
use bh_event::{Binding, CLASS_CONTENT, Encoded, Payload, TYPED_DATA, key_id, seal};
use bh_storage::{
    DeviceDatabase,
    sync_state::PackageOutcome,
    typed_outbox::{TypedEcho, TypedPackagePreparation},
};
use bh_sync::{BaseId, Commitment, EventId, Head, OpaqueEvent, Route};
use rusqlite::OptionalExtension;
use serde_json::{Value, json};

const APP: AppId = AppId([2; 32]);
const ARTICLE: &[u8] = include_bytes!("../../data/tests/fixtures/types/Article.json");
/// More parked rows than one replay page settles.
const OTHERS: u8 = 20;

fn genesis() -> OpaqueEvent {
    OpaqueEvent::new(EventId([0x11; 32]), vec![0x22; 1024]).unwrap()
}
fn base() -> [u8; 32] {
    BaseId::from_genesis(&genesis()).0
}
fn scope() -> Scope {
    Scope {
        base: base(),
        audience: [0; 32],
    }
}
fn own() -> Actor {
    Actor::Device {
        account: [6; 32],
        device: [7; 32],
    }
}
fn other() -> Actor {
    Actor::Device {
        account: [8; 32],
        device: [9; 32],
    }
}

/// Test-only admission confirming device rule changes.
struct Confirmed;
impl HostAdmission for Confirmed {
    fn confirms(&self, request: &Confirmation, _at: Option<Position>) -> Result<bool, DataError> {
        Ok(matches!(request.actor, Actor::Device { .. }))
    }
}

fn sealed(id: EventId, payload: &[u8]) -> Encoded {
    seal(
        Binding {
            version: 2,
            highest: 2,
            mode: 0,
            base: base(),
            audience: [0; 32],
            epoch: key_id(&Secret::from_slice(&[5; 32]).unwrap()),
            event_id: id,
            account: bh_account::AccountId([6; 32]),
            device: bh_account::DeviceId([7; 32]),
            account_head: bh_account::Head {
                position: 0,
                hash: [0; 32],
            },
            seen: Head::EMPTY,
            seen_control: [0; 32],
            class: CLASS_CONTENT,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: [0; bh_sync::receipt::RECEIPT_LEN],
        },
        Payload {
            kind: TYPED_DATA,
            data: payload,
        },
        &SigningKey::generate(),
        &Secret::from_slice(&[4; 32]).unwrap(),
        Some(&Secret::from_slice(&[5; 32]).unwrap()),
    )
    .unwrap()
}

/// The exact prior rules a device approval would sign for `op` now.
fn prior(tx: &rusqlite::Transaction<'_>, op: &Operation) -> PriorRules {
    tx.execute_batch("SAVEPOINT dry_run").unwrap();
    let result =
        pending::submit_with_admission(tx, &Shipped, scope(), &own(), op.clone(), &Unavailable);
    tx.execute_batch("ROLLBACK TO dry_run; RELEASE dry_run")
        .unwrap();
    match result {
        Err(SubmitError::ConfirmationRequired(request)) => request.prior,
        other => panic!("{other:?}"),
    }
}

fn ordered(
    tx: &rusqlite::Transaction<'_>,
    position: u64,
    actor: &Actor,
    op: &Operation,
    prior: Option<PriorRules>,
) -> Outcome {
    let bytes =
        bh_data::payload::encode_with_confirmation(MutationId::random(), op, prior).unwrap();
    apply_payload_with_admission(
        tx,
        &Shipped,
        scope(),
        Position(position),
        actor,
        &bytes,
        &Confirmed,
    )
    .unwrap()
}

fn create(n: u8, revision: RevisionId, url: &str) -> Operation {
    Operation::Create {
        record: RecordId([n; 32]),
        type_id: bh_data::definition::parse(ARTICLE).unwrap().type_id,
        revision,
        doc: json!({"title": "Title", "url": url}),
    }
}

fn parked(raw: &rusqlite::Connection) -> i64 {
    raw.query_row("SELECT count(*) FROM data_parked", [], |r| r.get(0))
        .unwrap()
}
fn cursor(raw: &rusqlite::Connection) -> Option<i64> {
    raw.query_row("SELECT cursor FROM data_replay", [], |r| r.get(0))
        .optional()
        .unwrap()
}
fn outcome(db: &DeviceDatabase, package: i64) -> Option<PackageOutcome> {
    db.typed_package_progress(package).unwrap().unwrap().outcome
}
fn index_ready(db: &DeviceDatabase) -> bool {
    db.with_data_read(|conn| {
        Ok(conn
            .query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM data_index WHERE state!='ready')",
                [],
                |r| r.get(0),
            )
            .unwrap())
    })
    .unwrap()
}

/// Articles exist before their source becomes unique, so the unique index
/// builds. This device's own create claiming an existing source, then other
/// members' fresh creates, park on uniqueness at their ordered positions.
fn backlog(path: &std::path::Path) -> (DeviceDatabase, i64) {
    let mut db = DeviceDatabase::open(path).unwrap();
    let mut loose: Value = serde_json::from_slice(ARTICLE).unwrap();
    loose["unique"] = json!([]);
    loose["description"] = json!("Articles before the source became unique");
    let loose = serde_json::to_vec(&loose).unwrap();
    db.with_data_write(|tx| {
        let sid = bh_data::store::records::scope_id(tx, scope(), &Shipped)?;
        bh_data::store::coverage::set(tx, sid, Position(0), true)?;
        let app = Operation::DefineApp {
            app: APP,
            name: "Articles".into(),
        };
        assert!(matches!(
            ordered(tx, 1, &own(), &app, None),
            Outcome::Accepted { .. }
        ));
        let define = Operation::DefineType {
            bytes: loose.clone(),
        };
        assert!(matches!(
            ordered(tx, 2, &own(), &define, None),
            Outcome::Accepted { .. }
        ));
        for n in 1..=3 {
            let op = create(
                n,
                RevisionId::of(&loose),
                &format!("https://example.test/{n}"),
            );
            assert!(matches!(
                ordered(tx, 2 + n as u64, &other(), &op, None),
                Outcome::Accepted { .. }
            ));
        }
        let unique = Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        };
        let rules = prior(tx, &unique);
        assert!(matches!(
            ordered(tx, 6, &own(), &unique, Some(rules)),
            Outcome::Accepted { .. }
        ));
        Ok(())
    })
    .unwrap();
    assert!(!index_ready(&db));
    // This device's create claims record 1's source while uniqueness is unknown.
    let package = db
        .submit_typed(
            &Shipped,
            scope(),
            &own(),
            create(10, RevisionId::of(ARTICLE), "https://example.test/1"),
            &Confirmed,
        )
        .unwrap()
        .package;
    let candidate = match db.prepare_typed_package(package).unwrap() {
        TypedPackagePreparation::Candidate(candidate) => candidate,
        TypedPackagePreparation::Existing(_) => panic!("already sealed"),
    };
    let encoded = sealed(candidate.event_id, &candidate.payload);
    let descriptor = encoded.descriptor.clone();
    let stored = db
        .publish_typed_package(
            candidate,
            descriptor,
            bh_sync::BodyObject::new(encoded.body).unwrap(),
        )
        .unwrap();
    // Ordered at position 7: the genesis, five other events, then this one.
    let mut order = Commitment::order(
        BaseId(base()),
        bh_sync::OrderState::EMPTY,
        &genesis(),
        Route::Control,
    )
    .unwrap()
    .after();
    for _ in 2..7 {
        let filler = sealed(EventId(bh_crypto::random()), b"filler");
        order = Commitment::order(BaseId(base()), order, &filler.descriptor, Route::Content)
            .unwrap()
            .after();
    }
    let at = Commitment::order(BaseId(base()), order, &stored.descriptor, Route::Content).unwrap();
    assert_eq!(at.head().position, 7);
    let payload: Vec<u8> = db
        .with_data_read(|conn| {
            Ok(conn.query_row(
                "SELECT payload FROM data_pending WHERE mutation=(SELECT mutation FROM typed_outbox WHERE id=?1)",
                [package],
                |r| r.get(0),
            )
            .unwrap())
        })
        .unwrap();
    db.with_data_write(|tx| {
        let outcome = apply_payload_with_admission(
            tx,
            &Shipped,
            scope(),
            Position(7),
            &own(),
            &payload,
            &Confirmed,
        )?;
        assert_eq!(outcome, Outcome::Waiting(Wait::UniquenessUnknown(scope())));
        for n in 0..OTHERS {
            let op = create(
                20 + n,
                RevisionId::of(ARTICLE),
                &format!("https://f.test/{n}"),
            );
            assert!(matches!(
                ordered(tx, 8 + n as u64, &other(), &op, None),
                Outcome::Waiting(_)
            ));
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(
        db.record_typed_echo(
            base(),
            &TypedEcho {
                event_id: stored.event_id.0,
                ordered: at,
                outcome: None,
                publishing_stopped: false,
            },
        )
        .unwrap(),
        Some(package)
    );
    (db, package)
}

#[test]
fn readiness_queues_a_paged_replay_that_settles_own_packages_per_page() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("typed.db");
    let (mut db, package) = backlog(&path);
    let raw = rusqlite::Connection::open(&path).unwrap();
    let waiting = parked(&raw);
    assert_eq!(waiting, 1 + OTHERS as i64);
    let mut steps = 0;
    while !index_ready(&db) {
        db.derived_index_step(u64::MAX).unwrap();
        steps += 1;
        assert!(steps < 10);
    }
    // Readiness replays nothing itself: it leaves a durable pass marker, and
    // the own package's verdict waits for the page that decides it.
    assert_eq!(parked(&raw), waiting, "readiness replayed the backlog");
    assert_eq!(cursor(&raw), Some(-1));
    assert!(db.derived_pending().unwrap());
    assert_eq!(outcome(&db, package), None);

    // A page that cannot settle its own package rolls back with its verdicts
    // and cursor.
    raw.execute_batch(
        "CREATE TRIGGER fail_settle BEFORE UPDATE ON typed_outbox BEGIN SELECT RAISE(ABORT,'settle'); END;",
    )
    .unwrap();
    assert!(db.derived_replay_step(u64::MAX).is_err());
    assert_eq!(parked(&raw), waiting);
    assert_eq!(cursor(&raw), Some(-1));
    assert_eq!(outcome(&db, package), None);
    raw.execute_batch("DROP TRIGGER fail_settle").unwrap();

    // The first page decides the own create and settles it in its commit,
    // leaving the rest of the backlog for later pages.
    db.derived_replay_step(u64::MAX).unwrap();
    assert!(matches!(
        outcome(&db, package),
        Some(PackageOutcome::Rejected)
    ));
    let left = parked(&raw);
    assert!(left > 0 && left < waiting, "{left} of {waiting} parked");
    assert!(cursor(&raw).unwrap() >= 7);

    // A restart between pages resumes from the durable cursor.
    drop(db);
    let mut db = DeviceDatabase::open(&path).unwrap();
    assert!(db.derived_pending().unwrap());
    let mut pages = 0;
    while db.derived_pending().unwrap() {
        db.derived_replay_step(u64::MAX).unwrap();
        pages += 1;
        assert!(pages < 10, "the pass must end");
    }
    assert_eq!(parked(&raw), 0);
    assert_eq!(cursor(&raw), None);
    assert!(matches!(
        outcome(&db, package),
        Some(PackageOutcome::Rejected)
    ));
}

#[test]
fn a_non_unique_index_becoming_ready_queues_no_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("typed.db");
    let (mut db, _package) = backlog(&path);
    let raw = rusqlite::Connection::open(&path).unwrap();
    let waiting = parked(&raw);
    while !index_ready(&db) {
        db.derived_index_step(u64::MAX).unwrap();
    }
    // Stand in for a pass that already ended while rows still wait.
    raw.execute("DELETE FROM data_replay", []).unwrap();
    assert_eq!(cursor(&raw), None);
    // Only a unique index can release parked work: a plain local index over
    // the same populated family becomes ready without queuing a pass.
    db.with_data_write(|tx| {
        let sid = bh_data::store::records::scope_id(tx, scope(), &Shipped)?;
        let family = bh_data::definition::parse(ARTICLE).unwrap().type_id;
        bh_data::index::ensure_local(
            tx,
            sid,
            family,
            vec![bh_data::model::KeyRef::Field(
                bh_data::FieldPath::parse("/title").unwrap(),
            )],
        )?;
        Ok(())
    })
    .unwrap();
    assert!(!index_ready(&db));
    while !index_ready(&db) {
        db.derived_index_step(u64::MAX).unwrap();
    }
    assert_eq!(cursor(&raw), None, "a plain index queued a replay pass");
    assert_eq!(parked(&raw), waiting);
}
