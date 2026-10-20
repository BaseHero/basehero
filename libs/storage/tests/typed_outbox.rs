//! Typed work through this device's outbox: one immutable sealed package per
//! pending mutation, exact retransmission, Acks that record only a position,
//! and the same alarms note packages raise.
use bh_account::{AccountId, DeviceId, Head as AccountHead};
use bh_crypto::{Secret, SigningKey};
use bh_data::{
    Actor, AppId, DataError, FieldPath, MutationId, Position, RecordId, RevisionId, Scope,
    admission::{Confirmation, HostAdmission},
    catalogue::Shipped,
    mutation::{
        apply::{Ordered, Outcome, apply_ordered_with_admission, apply_payload},
        ops::{FieldChange, Operation},
    },
};
use bh_event::{Binding, CLASS_CONTENT, Encoded, Payload, TYPED_DATA, key_id, seal};
use bh_storage::{
    DeviceDatabase, NoteKey,
    sync_state::{IncomingCommit, LOG_BASE, PackageOutcome, SeenRow, SyncAlarm, VerifiedRecord},
    typed_outbox::{OutboxCandidate, OutboxOrder, TypedEcho, TypedPackagePreparation},
};
use bh_sync::{BaseId, Commitment, EventId, Head, OpaqueEvent, Route};
use std::path::PathBuf;

const APP: AppId = AppId([2; 32]);
const ARTICLE: &[u8] = include_bytes!("../../data/tests/fixtures/types/Article.json");

/// A self-consistent first event: the base id is its descriptor digest, as a
/// genesis's is. Storage never verifies the chain, so a test may order content
/// after it instead of provisioning a real account.
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
fn genesis_order() -> Commitment {
    Commitment::order(BaseId(base()), Head::EMPTY, &genesis(), Route::Control).unwrap()
}

/// A host that confirms this device's rule changes: test-only admission, never
/// compiled into a product path.
struct Confirmed;
impl HostAdmission for Confirmed {
    fn confirms(&self, request: &Confirmation, _at: Option<Position>) -> Result<bool, DataError> {
        Ok(matches!(request.actor, Actor::Device { .. }))
    }
}

fn actor() -> Actor {
    Actor::Device {
        account: [6; 32],
        device: [7; 32],
    }
}

fn app(name: &str) -> Operation {
    Operation::DefineApp {
        app: APP,
        name: name.to_owned(),
    }
}

struct Store {
    dir: tempfile::TempDir,
    db: DeviceDatabase,
}
impl Store {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = DeviceDatabase::open(path(&dir)).unwrap();
        // The scope holds its whole identity set, as a bootstrapped replica
        // does; otherwise a new app's absence cannot be checked here and the
        // save is held as waiting.
        {
            let raw = rusqlite::Connection::open(path(&dir)).unwrap();
            let tx = raw.unchecked_transaction().unwrap();
            let sid = bh_data::store::records::scope_id(&tx, scope(), &Shipped).unwrap();
            tx.execute(
                "INSERT INTO data_coverage(scope,through,complete) VALUES(?1,0,1)
                 ON CONFLICT(scope) DO UPDATE SET complete=1",
                [sid],
            )
            .unwrap();
            tx.commit().unwrap();
        }
        Self { dir, db }
    }
    /// Reopen the same container, as a restart does.
    fn reopen(dir: tempfile::TempDir) -> Self {
        let db = DeviceDatabase::open(path(&dir)).unwrap();
        Self { dir, db }
    }
    fn raw(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(path(&self.dir)).unwrap()
    }
    fn queue(&mut self, name: &str) -> i64 {
        self.queue_op(app(name))
    }
    fn queue_op(&mut self, op: Operation) -> i64 {
        self.db
            .submit_typed(&Shipped, scope(), &actor(), op, &Confirmed)
            .unwrap()
            .package
    }
    fn with_article() -> Self {
        let store = Self::new();
        let mut raw = store.raw();
        let tx = raw.transaction().unwrap();
        for (position, op) in [
            Operation::DefineApp {
                app: APP,
                name: "Articles".into(),
            },
            Operation::DefineType {
                bytes: ARTICLE.to_vec(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            let outcome = apply_ordered_with_admission(
                &tx,
                &Shipped,
                &Ordered {
                    scope: scope(),
                    position: Position(position as u64 + 1),
                    actor: &actor(),
                    mutation: MutationId::random(),
                    op: &op,
                },
                &Confirmed,
            )
            .unwrap();
            assert!(matches!(outcome, Outcome::Accepted { .. }), "{outcome:?}");
        }
        tx.commit().unwrap();
        store
    }
    /// Seal and persist `package`, returning its exact stored bytes.
    fn publish(&mut self, package: i64) -> Sealed {
        let candidate = match self.db.prepare_typed_package(package).unwrap() {
            TypedPackagePreparation::Candidate(candidate) => candidate,
            TypedPackagePreparation::Existing(_) => panic!("not sealed yet"),
        };
        let encoded = sealed(candidate.event_id, &candidate.payload);
        let descriptor = encoded.descriptor.clone();
        let body = bh_sync::BodyObject::new(encoded.body).unwrap();
        let stored = self
            .db
            .publish_typed_package(candidate, descriptor, body)
            .unwrap();
        Sealed {
            event_id: stored.event_id,
            descriptor: stored.descriptor,
            body: stored.body,
        }
    }
    fn echo(&mut self, echo: TypedEcho) -> Option<i64> {
        self.db.record_typed_echo(base(), &echo).unwrap()
    }
}

fn path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("typed.db")
}

struct Sealed {
    event_id: EventId,
    descriptor: OpaqueEvent,
    body: Vec<u8>,
}
impl Sealed {
    /// Its position after the first event.
    fn ordered(&self) -> Commitment {
        Commitment::order(
            BaseId(base()),
            genesis_order().head(),
            &self.descriptor,
            Route::Content,
        )
        .unwrap()
    }
    /// Its position after `earlier`, to model the same bytes ordered elsewhere.
    fn ordered_after(&self, earlier: &Commitment) -> Commitment {
        Commitment::order(
            BaseId(base()),
            earlier.head(),
            &self.descriptor,
            Route::Content,
        )
        .unwrap()
    }
}

/// A sealed typed event for `payload`, structurally valid for this store.
fn sealed(id: EventId, payload: &[u8]) -> Encoded {
    let metadata = Secret::from_slice(&[4; 32]).unwrap();
    let content = Secret::from_slice(&[5; 32]).unwrap();
    let signer = SigningKey::generate();
    seal(
        Binding {
            version: 2,
            highest: 2,
            mode: 0,
            base: base(),
            audience: [0; 32],
            epoch: key_id(&content),
            event_id: id,
            account: AccountId([6; 32]),
            device: DeviceId([7; 32]),
            account_head: AccountHead {
                position: 0,
                hash: [0; 32],
            },
            seen: Head::EMPTY,
            seen_control: [0; 32],
            class: CLASS_CONTENT,
            padded: 0,
            commitment: [0; 32],
            // Packaging only: the outbox never verifies the receipt.
            seen_receipt: [0; bh_sync::receipt::RECEIPT_LEN],
        },
        Payload {
            kind: TYPED_DATA,
            data: payload,
        },
        &signer,
        &metadata,
        Some(&content),
    )
    .unwrap()
}

fn pending_state(conn: &rusqlite::Connection) -> String {
    conn.query_row("SELECT state FROM data_pending", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn typed_work_is_queued_sealed_once_and_retried_byte_for_byte() {
    let mut store = Store::new();
    let package = store.queue("Memos");
    assert!(matches!(
        store
            .db
            .outbox_candidates(OutboxOrder::START, None, 16)
            .unwrap()
            .as_slice(),
        [OutboxCandidate::Typed(head)] if head.id == package
    ));
    let sealed = store.publish(package);
    // A sealed package is a retry: the exact same bytes, never a reseal.
    match store.db.prepare_typed_package(package).unwrap() {
        TypedPackagePreparation::Existing(stored) => {
            assert_eq!(stored.event_id, sealed.event_id);
            assert_eq!(stored.descriptor.encode(), sealed.descriptor.encode());
            assert_eq!(stored.body, sealed.body);
        }
        TypedPackagePreparation::Candidate(_) => panic!("resealed"),
    }
    // The work it publishes is exactly the payload the data layer saved.
    assert_eq!(pending_state(&store.raw()), "pending");
    // No note update, writer declaration or note outbox row was manufactured.
    let manufactured: i64 = store
        .raw()
        .query_row(
            "SELECT (SELECT COUNT(*) FROM note_updates) + (SELECT COUNT(*) FROM note_outbox)
               + (SELECT COUNT(*) FROM note_update_writer)",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(manufactured, 0);
}

#[test]
fn an_ack_records_the_position_only_and_the_work_stays_pending() {
    let mut store = Store::new();
    let package = store.queue("Memos");
    let sealed = store.publish(package);
    let ack = sealed.ordered();
    assert!(store.db.acknowledge_typed_package(package, &ack).unwrap());
    // A duplicate Ack is idempotent; a different one is a conflict.
    assert!(!store.db.acknowledge_typed_package(package, &ack).unwrap());
    let progress = store.db.typed_package_progress(package).unwrap().unwrap();
    assert_eq!(progress.payload_position, Some(ack.head().position));
    assert_eq!(progress.outcome, Some(PackageOutcome::Acked));
    // Ordering is not acceptance: the saved work is still there, pending.
    assert_eq!(pending_state(&store.raw()), "pending");
    // The acknowledged package is not offered again, and nothing follows it.
    assert!(
        store
            .db
            .outbox_candidates(OutboxOrder::START, None, 16)
            .unwrap()
            .is_empty()
    );
    let summary = store.db.outbox_summary().unwrap();
    assert_eq!(summary.unaccepted_typed, 1);
    assert_eq!(summary.not_accepted_typed, 0);
}

#[test]
fn reopen_between_seal_and_ack_resends_the_same_package() {
    let mut store = Store::new();
    let package = store.queue("Memos");
    let sealed = store.publish(package);
    let dir = store.dir;
    drop(store.db);
    let store = Store::reopen(dir);
    match store.db.prepare_typed_package(package).unwrap() {
        TypedPackagePreparation::Existing(stored) => {
            assert_eq!(stored.event_id, sealed.event_id);
            assert_eq!(stored.descriptor.encode(), sealed.descriptor.encode());
            assert_eq!(stored.body, sealed.body);
        }
        TypedPackagePreparation::Candidate(_) => panic!("resealed after reopen"),
    }
    assert_eq!(
        store
            .db
            .typed_package_progress(package)
            .unwrap()
            .unwrap()
            .outcome,
        None
    );
    // Still the next candidate: a reopen resumes the same package.
    assert!(matches!(
        store
            .db
            .outbox_candidates(OutboxOrder::START, None, 16)
            .unwrap()
            .as_slice(),
        [OutboxCandidate::Typed(head)] if head.id == package
    ));
}

#[test]
fn reopen_between_ack_and_echo_keeps_the_package_and_never_reseals() {
    let mut store = Store::new();
    let first = store.queue("Memos");
    let sealed = store.publish(first);
    let ack = sealed.ordered();
    assert!(store.db.acknowledge_typed_package(first, &ack).unwrap());
    let dir = store.dir;
    drop(store.db);
    let mut store = Store::reopen(dir);
    // The exact bytes are still there, at the same Ack position.
    match store.db.prepare_typed_package(first).unwrap() {
        TypedPackagePreparation::Existing(stored) => {
            assert_eq!(stored.ack.unwrap().encode(), ack.encode());
        }
        TypedPackagePreparation::Candidate(_) => panic!("resealed after reopen"),
    }
    // Not republished while its echo is outstanding, and not lost.
    assert!(
        store
            .db
            .outbox_candidates(OutboxOrder::START, None, 16)
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.db.outbox_summary().unwrap().unaccepted_typed, 1);
    // Later work takes the acknowledged item's place.
    let second = store.queue("Second");
    let next = store.publish(second);
    assert!(matches!(
        store
            .db
            .outbox_candidates(OutboxOrder::START, None, 16)
            .unwrap()
            .as_slice(),
        [OutboxCandidate::Typed(head)] if head.id == second
    ));
    // The verified echo settles it, keeping the position it ordered it at.
    let echo = TypedEcho {
        event_id: next.event_id.0,
        ordered: next.ordered(),
        outcome: Some(PackageOutcome::Accepted),
        publishing_stopped: false,
    };
    assert_eq!(store.echo(echo), Some(second));
    let progress = store.db.typed_package_progress(second).unwrap().unwrap();
    assert_eq!(progress.outcome, Some(PackageOutcome::Accepted));
    assert_eq!(progress.payload_position, Some(2));
}

#[test]
fn waiting_saved_work_is_offered_for_ordered_judgment() {
    let mut store = Store::new();
    let raw = store.raw();
    raw.execute("UPDATE data_coverage SET complete=0", [])
        .unwrap();
    let package = store.queue("Memos");
    assert_eq!(pending_state(&raw), "waiting");
    assert!(matches!(
        store.db.outbox_candidates(OutboxOrder::START, None, 16).unwrap().as_slice(),
        [OutboxCandidate::Typed(head)] if head.id == package
    ));
    let sealed = store.publish(package);
    assert_eq!(pending_state(&raw), "waiting");
    assert!(
        store
            .db
            .acknowledge_typed_package(package, &sealed.ordered())
            .unwrap()
    );
    assert!(
        store
            .db
            .outbox_candidates(OutboxOrder::START, None, 16)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_waiting_verified_echo_without_an_ack_releases_the_next_scope_head() {
    let mut store = Store::with_article();
    let raw = store.raw();
    raw.execute("UPDATE data_coverage SET complete=0", [])
        .unwrap();
    let revision = RevisionId::of(ARTICLE);
    let type_id = bh_data::definition::parse(ARTICLE).unwrap().type_id;
    let first = store.queue_op(Operation::Create {
        record: RecordId([8; 32]),
        revision,
        type_id,
        doc: serde_json::json!({"title":"First","url":"https://example.test/first"}),
    });
    assert_eq!(pending_state(&raw), "waiting");
    // The status line must not report Synced while a save is waiting for
    // ordered judgment, even after its verified echo arrives without an Ack.
    let summary = store.db.outbox_summary().unwrap();
    assert_eq!(summary.unaccepted_typed, 1);
    assert_eq!(summary.unaccepted, 1);

    let second = store.queue_op(Operation::Create {
        record: RecordId([9; 32]),
        revision,
        type_id,
        doc: serde_json::json!({"title":"Second","url":"https://example.test/second"}),
    });
    let first_sealed = store.publish(first);
    let ack: Option<Vec<u8>> = raw
        .query_row("SELECT ack FROM typed_outbox WHERE id=?1", [first], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(ack, None, "the verified echo must arrive without an Ack");
    let filler = sealed(EventId(bh_crypto::random()), b"filler");
    let filler_order = Commitment::order(
        BaseId(base()),
        genesis_order().head(),
        &filler.descriptor,
        Route::Content,
    )
    .unwrap();
    let ordered = first_sealed.ordered_after(&filler_order);
    let payload: Vec<u8> = raw
        .query_row(
            "SELECT payload FROM data_pending WHERE mutation=(SELECT mutation FROM typed_outbox WHERE id=?1)",
            [first],
            |r| r.get(0),
        )
        .unwrap();
    let tx = raw.unchecked_transaction().unwrap();
    assert!(matches!(
        apply_payload(
            &tx,
            &Shipped,
            scope(),
            Position(ordered.head().position),
            &actor(),
            &payload
        )
        .unwrap(),
        Outcome::Waiting(_)
    ));
    tx.commit().unwrap();
    assert_eq!(
        store.echo(TypedEcho {
            event_id: first_sealed.event_id.0,
            ordered,
            outcome: None,
            publishing_stopped: false,
        }),
        Some(first)
    );
    let progress = store.db.typed_package_progress(first).unwrap().unwrap();
    assert_eq!(progress.payload_position, Some(3));
    assert_eq!(progress.outcome, None);
    let position: Option<i64> = raw
        .query_row(
            "SELECT ordered_position FROM typed_outbox WHERE id=?1",
            [first],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(position, Some(3));
    assert!(matches!(
        store.db.outbox_candidates(OutboxOrder::START, None, 16).unwrap().as_slice(),
        [OutboxCandidate::Typed(head)] if head.id == second
    ));
    let summary = store.db.outbox_summary().unwrap();
    assert_eq!(summary.unaccepted_typed, 2);
    assert_eq!(summary.unaccepted, 2);
    assert_eq!(
        summary.unacknowledged, 1,
        "only the next, unordered save remains unacknowledged"
    );

    // Supplying full scope coverage in the next verified batch replays the
    // parked payload and settles the exact ordered position, not the next head.
    raw.execute(
        "INSERT INTO log_progress(log_kind,log_id,position,head_hash,receipt,control_digest,stopped_reason,hosting_root,account_position,account_hash,metadata_id,epoch_id,floor)
         VALUES(1,?1,0,?2,NULL,zeroblob(32),NULL,?3,NULL,NULL,NULL,NULL,1)",
        rusqlite::params![base().as_slice(), [7u8; 32].as_slice(), [8u8; 32].as_slice()],
    )
    .unwrap();
    store
        .db
        .commit_incoming(
            &IncomingCommit {
                log_kind: LOG_BASE,
                log_id: base(),
                hosting_root: [8; 32],
                after: (0, [7; 32]),
                receipt: [0; bh_sync::receipt::RECEIPT_LEN],
                records: vec![VerifiedRecord {
                    seen: SeenRow {
                        position: 4,
                        head_hash: [9; 32],
                        control_digest: [0; 32],
                        account_position: 1,
                        account_hash: [0; 32],
                    },
                    event_id: [10; 32],
                    digest: [11; 32],
                    account_change: None,
                    judged_floor: 1,
                    floor: 1,
                }],
                metadata_id: [0; 32],
                epoch_id: None,
                notes: vec![],
                steps: vec![],
                own: vec![],
                held: vec![],
            },
            |_| Ok(()),
        )
        .unwrap();
    assert_eq!(
        store
            .db
            .typed_package_progress(first)
            .unwrap()
            .unwrap()
            .outcome,
        Some(PackageOutcome::Accepted)
    );
    assert!(matches!(
        store.db.outbox_candidates(OutboxOrder::START, None, 16).unwrap().as_slice(),
        [OutboxCandidate::Typed(head)] if head.id == second
    ));
    let next = store.db.typed_package_progress(second).unwrap();
    assert_eq!(
        next, None,
        "settling the first must not seal or judge the second"
    );
    assert_eq!(store.db.outbox_summary().unwrap().unaccepted_typed, 1);
}

#[test]
fn the_verified_echo_wins_over_a_stored_ack_and_alarms_it() {
    let mut store = Store::new();
    let package = store.queue("Memos");
    let package_sealed = store.publish(package);
    // A filler event ordered first puts this package's genuine position at 3,
    // while the stored Ack names position 2: both verify the same bytes.
    let filler = sealed(EventId(bh_crypto::random()), b"filler");
    let filler_order = Commitment::order(
        BaseId(base()),
        genesis_order().head(),
        &filler.descriptor,
        Route::Content,
    )
    .unwrap();
    let genuine = package_sealed.ordered_after(&filler_order);
    let wrong = package_sealed.ordered();
    assert!(store.db.acknowledge_typed_package(package, &wrong).unwrap());
    let echo = TypedEcho {
        event_id: package_sealed.event_id.0,
        ordered: genuine,
        outcome: Some(PackageOutcome::Accepted),
        publishing_stopped: false,
    };
    assert_eq!(store.echo(echo), Some(package));
    assert_eq!(
        store.db.sync_alarms().unwrap(),
        vec![SyncAlarm::TypedAckMismatch {
            package,
            position: genuine.head().position
        }]
    );
    let progress = store.db.typed_package_progress(package).unwrap().unwrap();
    assert_eq!(progress.payload_position, Some(genuine.head().position));
    assert_eq!(progress.outcome, Some(PackageOutcome::Accepted));
}

#[test]
fn a_publishing_stop_alarm_covers_typed_packages_and_stops_note_work_too() {
    let mut store = Store::new();
    let package = store.queue("Memos");
    let sealed = store.publish(package);
    let echo = TypedEcho {
        event_id: sealed.event_id.0,
        ordered: sealed.ordered(),
        outcome: Some(PackageOutcome::Refused(3)),
        publishing_stopped: true,
    };
    assert_eq!(store.echo(echo), Some(package));
    assert!(store.db.publishing_stopped().unwrap());
    assert_eq!(
        store.db.sync_alarms().unwrap(),
        vec![SyncAlarm::TypedPublishingStopped { package }]
    );
    // The stop covers every package this container would publish.
    assert_eq!(
        store
            .db
            .prepare_typed_package(package)
            .unwrap_err()
            .to_string(),
        "publishing is stopped by a local alarm"
    );
    let next = store.queue("Later");
    assert_eq!(
        store
            .db
            .prepare_typed_package(next)
            .unwrap_err()
            .to_string(),
        "publishing is stopped by a local alarm"
    );
    assert_eq!(store.db.outbox_summary().unwrap().not_accepted_typed, 1);
}

#[test]
fn note_and_typed_work_are_offered_in_local_commit_order() {
    let mut store = Store::new();
    // One note's local commit, then typed work, then another note commit,
    // then more typed work: the order both kinds were committed in.
    let key = NoteKey {
        base: base(),
        audience: [0; 32],
        note: [9; 32],
    };
    let mut note = bh_core::note::Note::new().unwrap();
    let first = store
        .db
        .apply_local_update(key, [1; 16], &note.append_paragraph("first").unwrap())
        .unwrap()
        .update_id;
    let typed_one = store.queue("One");
    let second = store
        .db
        .apply_local_update(key, [2; 16], &note.append_paragraph("second").unwrap())
        .unwrap()
        .update_id;
    store.queue("Two");
    let order: Vec<OutboxOrder> = store
        .db
        .outbox_candidates(OutboxOrder::START, None, 16)
        .unwrap()
        .iter()
        .map(OutboxCandidate::order)
        .collect();
    // The note's next package covers its whole pending run, so it appears
    // once, at its first unsent update; typed work keeps its own place.
    // The second mutation of the same scope must not leapfrog the first.
    assert_eq!(
        order,
        vec![
            OutboxOrder {
                clock: first,
                kind: 0,
                tie: 0
            },
            OutboxOrder {
                clock: first,
                kind: 1,
                tie: typed_one
            },
        ]
    );
    // The wrap pass includes a note head at its starting cursor.
    let wrapped = store
        .db
        .outbox_candidates(OutboxOrder::START, Some(order[0]), 16)
        .unwrap();
    assert!(matches!(wrapped.as_slice(), [OutboxCandidate::Note(head)] if head.first == first));
    // The merged page can be walked with the keyset alone, without repeats.
    let rest = store.db.outbox_candidates(order[0], None, 16).unwrap();
    assert_eq!(
        rest.iter().map(OutboxCandidate::order).collect::<Vec<_>>(),
        order[1..]
    );
    // Sealing and acknowledging the first typed package advances past it.
    let sealed = store.publish(typed_one);
    assert!(
        store
            .db
            .acknowledge_typed_package(typed_one, &sealed.ordered())
            .unwrap()
    );
    let after: Vec<OutboxOrder> = store
        .db
        .outbox_candidates(OutboxOrder::START, None, 16)
        .unwrap()
        .iter()
        .map(OutboxCandidate::order)
        .collect();
    assert_eq!(after.len(), 2);
    assert_eq!(after[0], order[0]);
    assert_eq!(after[1].clock, second);
    assert_eq!(after[1].kind, 1);
    assert!(after[1].tie > typed_one);
    let summary = store.db.outbox_summary().unwrap();
    assert_eq!(summary.unaccepted_notes, 1);
    // Acknowledged typed work is still unaccepted: the echo decides that.
    assert_eq!(
        summary.unaccepted, 4,
        "two note updates and two typed items"
    );
    assert_eq!(summary.unaccepted_typed, 2);
}

#[test]
fn a_held_field_edit_blocks_later_edit_until_its_ack() {
    let mut store = Store::with_article();
    let record = RecordId([8; 32]);
    let revision = RevisionId::of(ARTICLE);
    let mut raw = store.raw();
    let tx = raw.transaction().unwrap();
    let create = Operation::Create {
        record,
        revision,
        type_id: bh_data::definition::parse(ARTICLE).unwrap().type_id,
        doc: serde_json::json!({"title":"Created","url":"https://example.test/held"}),
    };
    let outcome = apply_ordered_with_admission(
        &tx,
        &Shipped,
        &Ordered {
            scope: scope(),
            position: Position(3),
            actor: &actor(),
            mutation: MutationId::random(),
            op: &create,
        },
        &Confirmed,
    )
    .unwrap();
    assert!(matches!(outcome, Outcome::Accepted { .. }), "{outcome:?}");
    tx.commit().unwrap();
    let edit = |name| Operation::Edit {
        record,
        revision,
        changes: vec![FieldChange {
            path: FieldPath::parse("/title").unwrap(),
            value: Some(serde_json::json!(name)),
        }],
    };
    let first = store.queue_op(edit("First"));
    let second = store.queue_op(edit("Second"));
    store
        .raw()
        .execute(
            "UPDATE data_pending SET state='waiting' WHERE seq=(SELECT MIN(seq) FROM data_pending)",
            [],
        )
        .unwrap();
    assert!(
        matches!(store.db.outbox_candidates(OutboxOrder::START, None, 16).unwrap().as_slice(), [OutboxCandidate::Typed(h)] if h.id == first)
    );
    let ack = store.publish(first).ordered();
    assert!(store.db.acknowledge_typed_package(first, &ack).unwrap());
    assert!(
        matches!(store.db.outbox_candidates(OutboxOrder::START, None, 16).unwrap().as_slice(), [OutboxCandidate::Typed(h)] if h.id == second)
    );
}

#[test]
fn create_then_two_edits_to_one_record_field_advance_one_ack_at_a_time() {
    let mut store = Store::with_article();
    let record = RecordId([9; 32]);
    let revision = RevisionId::of(ARTICLE);
    let type_id = bh_data::definition::parse(ARTICLE).unwrap().type_id;
    let create = store.queue_op(Operation::Create {
        record,
        type_id,
        revision,
        doc: serde_json::json!({"title":"Created","url":"https://example.test/article"}),
    });
    let title = FieldPath::parse("/title").unwrap();
    let edit = store.queue_op(Operation::Edit {
        record,
        revision,
        changes: vec![FieldChange {
            path: title.clone(),
            value: Some(serde_json::json!("Renamed")),
        }],
    });
    let last = store.queue_op(Operation::Edit {
        record,
        revision,
        changes: vec![FieldChange {
            path: title,
            value: Some(serde_json::json!("Final")),
        }],
    });
    for (head, next) in [(create, Some(edit)), (edit, Some(last)), (last, None)] {
        assert!(
            matches!(store.db.outbox_candidates(OutboxOrder::START, None, 16).unwrap().as_slice(), [OutboxCandidate::Typed(h)] if h.id == head)
        );
        let ack = store.publish(head).ordered();
        store.db.acknowledge_typed_package(head, &ack).unwrap();
        if let Some(next) = next {
            assert!(
                matches!(store.db.outbox_candidates(OutboxOrder::START, None, 16).unwrap().as_slice(), [OutboxCandidate::Typed(h)] if h.id == next)
            );
        } else {
            assert!(
                store
                    .db
                    .outbox_candidates(OutboxOrder::START, None, 16)
                    .unwrap()
                    .is_empty()
            );
        }
    }
}

#[test]
fn scope_heads_keep_cursor_order_across_audiences() {
    let mut store = Store::new();
    let first = store.queue("First");
    let other_scope = Scope {
        base: base(),
        audience: [3; 32],
    };
    let second = store
        .db
        .submit_typed(&Shipped, other_scope, &actor(), app("Other"), &Confirmed)
        .unwrap()
        .package;
    let third = store.queue("Third");
    let heads = store
        .db
        .outbox_candidates(OutboxOrder::START, None, 16)
        .unwrap();
    assert!(
        matches!(heads.as_slice(), [OutboxCandidate::Typed(a), OutboxCandidate::Typed(b)] if a.id == first && b.id == second)
    );
    assert!(matches!(
        store.db.outbox_candidates(heads[0].order(), None, 16).unwrap().as_slice(),
        [OutboxCandidate::Typed(h)] if h.id == second
    ));
    let sealed = store.publish(first);
    store
        .db
        .acknowledge_typed_package(first, &sealed.ordered())
        .unwrap();
    let heads = store
        .db
        .outbox_candidates(OutboxOrder::START, None, 16)
        .unwrap();
    assert!(
        matches!(heads.as_slice(), [OutboxCandidate::Typed(a), OutboxCandidate::Typed(b)] if a.id == second && b.id == third)
    );
}

#[test]
fn typed_candidate_and_package_use_outbox_scope_even_if_data_scope_diverges() {
    let mut store = Store::new();
    let first = store.queue("First");
    store
        .raw()
        .execute("UPDATE data_scope SET audience=?1", [[7u8; 32].as_slice()])
        .unwrap();
    // A scope mismatch is not authority to seal for a different audience.
    assert!(
        matches!(store.db.outbox_candidates(OutboxOrder::START, None, 16).unwrap().as_slice(), [OutboxCandidate::Typed(h)] if h.id == first && h.audience == [0;32])
    );
    assert!(matches!(
        store.db.prepare_typed_package(first),
        Err(bh_storage::StoreError::RequestConflict)
    ));
}

#[test]
fn an_own_key_clash_stops_all_publishing() {
    let mut store = Store::new();
    let package = store.queue("First");
    let sealed = store.publish(package);
    assert_eq!(
        store.echo(TypedEcho {
            event_id: sealed.event_id.0,
            ordered: sealed.ordered(),
            outcome: Some(PackageOutcome::Conflicted),
            publishing_stopped: true
        }),
        Some(package)
    );
    assert!(store.db.publishing_stopped().unwrap());
    let progress = store.db.typed_package_progress(package).unwrap().unwrap();
    assert_eq!(progress.outcome, Some(PackageOutcome::Conflicted));
    assert_eq!(
        progress.payload_position, None,
        "clashing bytes are not this package's Ack"
    );
    assert_eq!(
        store.db.sync_alarms().unwrap(),
        vec![SyncAlarm::TypedPublishingStopped { package }]
    );
}

#[test]
fn a_typed_package_without_its_saved_work_is_a_conflict() {
    let mut store = Store::new();
    let package = store.queue("Memos");
    let candidate = match store.db.prepare_typed_package(package).unwrap() {
        TypedPackagePreparation::Candidate(candidate) => candidate,
        TypedPackagePreparation::Existing(_) => panic!("not sealed yet"),
    };
    // The saved work changes between preparing and publishing: the short CAS
    // refuses, so no package ever names bytes the data layer no longer holds.
    let raw = store.raw();
    raw.execute("UPDATE data_pending SET payload=x'00'", [])
        .unwrap();
    let encoded = sealed(candidate.event_id, &candidate.payload);
    let body = bh_sync::BodyObject::new(encoded.body).unwrap();
    assert!(matches!(
        store
            .db
            .publish_typed_package(candidate, encoded.descriptor, body),
        Err(bh_storage::StoreError::RequestConflict)
    ));
    // A discarded mutation is not offered either, and its entry stays idle.
    raw.execute("DELETE FROM data_pending", []).unwrap();
    assert!(
        store
            .db
            .outbox_candidates(OutboxOrder::START, None, 16)
            .unwrap()
            .is_empty()
    );
    assert!(store.db.outbox_summary().unwrap().unaccepted_typed == 0);
}

#[test]
fn a_queued_mutation_has_one_outbox_entry_even_after_reopen() {
    let mut store = Store::new();
    let queued = store
        .db
        .submit_typed(&Shipped, scope(), &actor(), app("Memos"), &Confirmed)
        .unwrap();
    assert_eq!(
        store.db.typed_package_id(queued.saved.mutation).unwrap(),
        Some(queued.package)
    );
    let dir = store.dir;
    drop(store.db);
    let store = Store::reopen(dir);
    assert_eq!(
        store.db.typed_package_id(queued.saved.mutation).unwrap(),
        Some(queued.package)
    );
    assert_eq!(
        store
            .raw()
            .query_row("SELECT COUNT(*) FROM typed_outbox", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        1
    );
}
