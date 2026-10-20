//! The core Note adapter: derived projections of real Notes, their
//! specialisation by an ordered binding, and the routes generic writes take.
use bh_data::{
    Actor, AppId, FieldPath, KeyRef, MutationId, RecordId, RejectCode, Rejection, RevisionId,
    Scope, TypeId, Wait,
    catalogue::{self, Shipped},
    mutation::{
        apply::{self, Outcome},
        history,
        ops::{FieldChange, Operation},
        pending::{self, SubmitError},
    },
    note, payload,
    query::{self, Budget, Completeness, Follow, Gap, Query, QueryError, SortKey, TypeSelect},
    session::{Authority, DataSession, Store, TypeRef},
    store::records::{self, RecordRow},
    testkit::{Delivery, OrderedLog, Replica},
    text,
};
use rusqlite::trace::{TraceEvent, TraceEventCodes};
use serde_json::{Value, json};
use std::cell::Cell;

thread_local! {
    static OLD_UPSERT: Cell<bool> = const { Cell::new(false) };
    static OLD_INDEX_INSERT: Cell<bool> = const { Cell::new(false) };
}
fn upsert_trace(event: TraceEvent<'_>) {
    if let TraceEvent::Stmt(stmt, _) = event {
        if stmt.sql().starts_with("INSERT INTO data_record(scope,record,type,revision,accepted,doc,deleted,pending,changed_at,changed,text_rev)") {
            OLD_UPSERT.with(|seen| seen.set(true));
        }
        if stmt.sql().starts_with("INSERT INTO data_index_entry(") {
            OLD_INDEX_INSERT.with(|seen| seen.set(true));
        }
    }
}
fn projected_via_original_upsert(net: &Net, note: RecordId, title: &str) {
    OLD_UPSERT.with(|seen| seen.set(false));
    OLD_INDEX_INSERT.with(|seen| seen.set(false));
    net.reps[0]
        .conn()
        .trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(upsert_trace));
    net.project(0, note, title);
    net.reps[0].conn().trace_v2(TraceEventCodes::empty(), None);
    assert!(
        OLD_UPSERT.with(Cell::get),
        "fallback must use the original full upsert"
    );
}

#[test]
fn second_plain_note_save_matches_full_upsert_record_and_changed_keys() {
    let net = Net::new(2);
    for i in 0..2 {
        net.project(i, rid(1), "first");
    }
    net.project(0, rid(1), "second");
    // A hidden Note takes the existing full-upsert and full-index-write route.
    // Restoring it returns the same accepted state as an ordinary second save.
    let fallback = net.reps[1].conn();
    fallback
        .execute(
            "UPDATE data_record SET hidden=1,deleted=1 WHERE record=?1",
            [rid(1).0.as_slice()],
        )
        .unwrap();
    OLD_UPSERT.with(|seen| seen.set(false));
    OLD_INDEX_INSERT.with(|seen| seen.set(false));
    fallback.trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(upsert_trace));
    net.project(1, rid(1), "second");
    fallback.trace_v2(TraceEventCodes::empty(), None);
    assert!(
        OLD_UPSERT.with(Cell::get),
        "restore must take the old upsert"
    );
    assert!(
        OLD_INDEX_INSERT.with(Cell::get),
        "restore must rebuild the index"
    );
    let columns = |i: usize| {
        let conn = net.reps[i].conn();
        let record = conn
            .query_row(
                "SELECT scope,record,type,revision,accepted,doc,deleted,pending,changed_at,changed,text_rev,hidden FROM data_record WHERE record=?1",
                [rid(1).0.as_slice()],
                |r| (0..12).map(|n| r.get::<_, rusqlite::types::Value>(n)).collect::<rusqlite::Result<Vec<_>>>(),
            )
            .unwrap();
        let changed = conn
            .query_row(
                "SELECT e.ix,e.k1,e.k2,e.k3,e.k4,e.rec,e.record FROM data_index_entry e JOIN data_index ix ON ix.id=e.ix WHERE e.record=?1 AND ix.keys='[\"$changed\"]'",
                [rid(1).0.as_slice()],
                |r| (0..7).map(|n| r.get::<_, rusqlite::types::Value>(n)).collect::<rusqlite::Result<Vec<_>>>(),
            )
            .unwrap();
        (record, changed)
    };
    assert_eq!(columns(0), columns(1));
}

#[test]
fn first_restore_provisional_and_specialised_notes_keep_the_full_upsert() {
    let mut net = Net::with_types(1, &[JOURNAL]);
    projected_via_original_upsert(&net, rid(1), "first");
    net.reps[0]
        .write(|tx| note::remove_projection(tx, SCOPE, rid(1)))
        .unwrap();
    projected_via_original_upsert(&net, rid(1), "restored");
    assert_eq!(
        net.row(0, rid(1)).accepted,
        Some(json!({"title":"restored"}))
    );

    net.ok(bind(rid(1), json!({"date":1,"mood":"calm"})));
    projected_via_original_upsert(&net, rid(1), "specialised");
    assert!(
        OLD_INDEX_INSERT.with(Cell::get),
        "specialised indexes keep the full write"
    );
    assert_eq!(
        net.row(0, rid(1)).accepted,
        Some(json!({"title":"specialised","date":1,"mood":"calm"}))
    );

    projected_via_original_upsert(&net, rid(2), "before proposal");
    let sid = records::lookup_scope(net.reps[0].conn(), SCOPE)
        .unwrap()
        .unwrap();
    let row = net.row(0, rid(2));
    net.reps[0].conn().execute(
        "UPDATE data_record SET type=?1, revision=?2, accepted=NULL, doc=?3, pending=1 WHERE id=?4",
        rusqlite::params![type_of(JOURNAL).0.as_slice(), rev(JOURNAL).0.as_slice(), "{\"date\":2}", row.id],
    ).unwrap();
    projected_via_original_upsert(&net, rid(2), "canonical");
    let row = records::get(net.reps[0].conn(), sid, rid(2))
        .unwrap()
        .unwrap();
    assert_eq!(row.type_id, note_type());
    assert_eq!(row.accepted, Some(json!({"title":"canonical"})));
    assert!(row.pending);
}

const JOURNAL: &[u8] = include_bytes!("fixtures/types/JournalEntry.json");
const ADDRESS: &[u8] = include_bytes!("fixtures/types/Address.json");
const RECIPE: &[u8] = include_bytes!("fixtures/types/Recipe.json");
const ARTICLE: &[u8] = include_bytes!("fixtures/types/Article.json");
const APP: AppId = AppId([2; 32]);
const SCOPE: Scope = Scope {
    base: [1; 32],
    audience: [0; 32],
};
const ROUTE: &str = "note body edit through the note writer";

fn dev() -> Actor {
    Actor::Device {
        account: [1; 32],
        device: [1; 32],
    }
}
fn rid(n: u8) -> RecordId {
    RecordId([n; 32])
}
fn nid(n: u32) -> RecordId {
    let mut id = [7; 32];
    id[..4].copy_from_slice(&n.to_be_bytes());
    RecordId(id)
}
fn path(p: &str) -> FieldPath {
    FieldPath::parse(p).unwrap()
}
fn set(p: &str, value: Value) -> FieldChange {
    FieldChange {
        path: path(p),
        value: Some(value),
    }
}
fn rev(bytes: &[u8]) -> RevisionId {
    RevisionId::of(bytes)
}
fn type_of(bytes: &[u8]) -> TypeId {
    bh_data::definition::parse(bytes).unwrap().type_id
}
fn note_type() -> TypeId {
    TypeId::core("note")
}
fn note_rev() -> RevisionId {
    catalogue::baseline_note().1
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A second Note specialisation of the same app.
fn task_note() -> Vec<u8> {
    let mut ty: Value = serde_json::from_slice(JOURNAL).unwrap();
    ty["local"] = json!("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
    ty["name"] = json!("TaskNote");
    ty["description"] = json!("A Note that tracks whether its task is done.");
    ty["fields"] = json!({"/done": {"kind": "boolean", "meaning": "Whether the task is done", "write": "direct"}});
    ty["schema"] =
        json!({"type": "object", "properties": {"done": {"type": "boolean"}}, "required": []});
    ty["indexes"] = json!([]);
    serde_json::to_vec(&ty).unwrap()
}

fn bind(note: RecordId, doc: Value) -> Operation {
    Operation::BindNote {
        note,
        type_id: type_of(JOURNAL),
        revision: rev(JOURNAL),
        doc,
    }
}
fn edit_journal(note: RecordId, changes: Vec<FieldChange>) -> Operation {
    Operation::Edit {
        record: note,
        revision: rev(JOURNAL),
        changes,
    }
}

/// Replicas fed one ordered log; each projects the Notes it holds.
struct Net {
    log: OrderedLog,
    reps: Vec<Replica>,
}

impl Net {
    fn new(n: usize) -> Self {
        let mut net = Self {
            log: OrderedLog::new(),
            reps: (0..n).map(|_| Replica::new_in_memory().unwrap()).collect(),
        };
        net.ok(Operation::DefineApp {
            app: APP,
            name: "Journal".into(),
        });
        net
    }
    fn with_types(n: usize, types: &[&[u8]]) -> Self {
        let mut net = Self::new(n);
        for bytes in types {
            net.ok(Operation::DefineType {
                bytes: bytes.to_vec(),
            });
        }
        net
    }
    /// Orders `op` and returns each replica's outcome.
    fn order_each(&mut self, op: &Operation) -> Vec<Outcome> {
        self.publish(payload::encode(MutationId::random(), op).unwrap())
    }
    fn publish(&mut self, bytes: Vec<u8>) -> Vec<Outcome> {
        self.log.append(SCOPE, &dev(), bytes);
        self.reps
            .iter_mut()
            .map(|rep| {
                let mut outcomes = rep.sync_from(&self.log, Delivery::InOrder).unwrap();
                outcomes.pop().unwrap().1
            })
            .collect()
    }
    /// Orders `op`; every replica must reach the same outcome.
    fn order(&mut self, op: Operation) -> Outcome {
        let outcomes = self.order_each(&op);
        for outcome in &outcomes[1..] {
            assert_eq!(outcome, &outcomes[0], "replicas disagree on {op:?}");
        }
        outcomes[0].clone()
    }
    fn ok(&mut self, op: Operation) {
        let outcome = self.order(op);
        assert!(
            matches!(outcome, Outcome::Accepted { .. }),
            "expected acceptance, got {outcome:?}"
        );
    }
    fn rejected(&mut self, op: Operation) -> Rejection {
        match self.order(op) {
            Outcome::Rejected(rejection) => rejection,
            other => panic!("expected rejection, got {other:?}"),
        }
    }
    fn project(&self, i: usize, note: RecordId, title: &str) -> u64 {
        self.reps[i]
            .write(|tx| note::upsert_projection(tx, SCOPE, note, title))
            .unwrap()
    }
    fn project_all(&self, note: RecordId, title: &str) {
        for i in 0..self.reps.len() {
            self.project(i, note, title);
        }
    }
    fn row(&self, i: usize, record: RecordId) -> RecordRow {
        let conn = self.reps[i].conn();
        let sid = records::lookup_scope(conn, SCOPE).unwrap().unwrap();
        records::get(conn, sid, record).unwrap().unwrap()
    }
    fn digest(&self, i: usize) -> [u8; 32] {
        self.reps[i].state_digest(SCOPE).unwrap()
    }
    fn assert_converged(&self) {
        for i in 1..self.reps.len() {
            assert_eq!(self.digest(i), self.digest(0), "replica state diverged");
        }
    }
    fn parked(&self, i: usize) -> i64 {
        self.reps[i]
            .conn()
            .query_row("SELECT count(*) FROM data_parked", [], |r| r.get(0))
            .unwrap()
    }
    fn query(&self, i: usize, q: &Query, budget: Budget) -> Result<query::Page, QueryError> {
        query::run(self.reps[i].conn(), SCOPE, &[SCOPE], &Shipped, q, budget)
    }
}

fn select(select: TypeSelect, fields: &[&str]) -> Query {
    Query {
        select,
        filter: None,
        sort: vec![],
        fields: fields.iter().map(|p| path(p)).collect(),
        follow: vec![],
        text: None,
        limit: 50,
        after: None,
    }
}

fn paths(entries: &[history::HistoryEntry]) -> Vec<String> {
    entries
        .iter()
        .map(|e| {
            e.path
                .as_ref()
                .map_or_else(String::new, FieldPath::as_pointer)
        })
        .collect()
}

#[test]
fn projection_updates_title_preserving_extension() {
    let mut net = Net::with_types(2, &[JOURNAL]);
    let first = net.project(0, rid(1), "Day one");
    net.project(1, rid(1), "Day one");
    let row = net.row(0, rid(1));
    assert_eq!(row.type_id, note_type());
    assert_eq!(row.revision, note_rev());
    assert_eq!(row.accepted, Some(json!({"title": "Day one"})));
    assert_eq!(row.text_rev, first);
    net.ok(bind(rid(1), json!({"date": 1, "mood": "calm"})));
    let bound = net.row(0, rid(1));
    assert_eq!(bound.type_id, type_of(JOURNAL));
    assert_eq!(bound.revision, rev(JOURNAL));
    let history_before = history::of(net.reps[0].conn(), SCOPE, rid(1), 50, None).unwrap();
    assert_eq!(paths(&history_before), ["/date", "/mood"]);

    let second = net.project(0, rid(1), "Day one, later");
    assert!(second > first);
    let row = net.row(0, rid(1));
    assert_eq!(
        row.accepted,
        Some(json!({"title": "Day one, later", "date": 1, "mood": "calm"}))
    );
    assert_eq!(row.type_id, type_of(JOURNAL));
    assert_eq!(row.text_rev, second);
    assert!(row.changed > bound.changed, "a projection renews recency");
    // The derived title has no history or clock of its own here.
    let history_after = history::of(net.reps[0].conn(), SCOPE, rid(1), 50, None).unwrap();
    assert_eq!(history_after, history_before);
    // One coalesced body job asks for the latest text revision.
    let jobs = text::next_jobs(net.reps[0].conn(), 10).unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!((jobs[0].record, jobs[0].wanted), (rid(1), second));

    // Pending local work keeps its overlay, which follows the title too.
    let saved = net.reps[0]
        .submit(
            SCOPE,
            &dev(),
            edit_journal(rid(1), vec![set("/mood", json!("tired"))]),
        )
        .unwrap();
    net.project(0, rid(1), "Third title");
    let row = net.row(0, rid(1));
    assert_eq!(
        row.accepted,
        Some(json!({"title": "Third title", "date": 1, "mood": "calm"}))
    );
    assert_eq!(
        row.doc,
        Some(json!({"title": "Third title", "date": 1, "mood": "tired"}))
    );
    let outcomes = net.publish(saved.payload);
    assert!(matches!(outcomes[0], Outcome::Accepted { .. }));
    assert_eq!(
        net.row(0, rid(1)).accepted,
        Some(json!({"title": "Third title", "date": 1, "mood": "tired"}))
    );
    // A title the Note contract cannot hold is refused before anything is written.
    let long = "x".repeat(201);
    assert!(
        net.reps[0]
            .write(|tx| note::upsert_projection(tx, SCOPE, rid(1), &long))
            .is_err()
    );
    assert_eq!(net.row(0, rid(1)).accepted.unwrap()["title"], "Third title");
}

#[test]
fn generic_edit_of_note_title_rejected_with_route() {
    let mut net = Net::with_types(2, &[JOURNAL]);
    net.project_all(rid(1), "Plain");
    net.project_all(rid(2), "Journal");
    net.ok(bind(rid(2), json!({"date": 2})));
    for (record, revision) in [(rid(1), note_rev()), (rid(2), rev(JOURNAL))] {
        let edit = Operation::Edit {
            record,
            revision,
            changes: vec![set("/title", json!("Renamed"))],
        };
        let rejection = net.rejected(edit.clone());
        assert_eq!(rejection.code, RejectCode::DerivedField);
        assert_eq!(rejection.path, Some(path("/title")));
        assert!(rejection.detail.contains(ROUTE), "{}", rejection.detail);
        match net.reps[0].submit(SCOPE, &dev(), edit) {
            Err(SubmitError::Rejected(local)) => assert_eq!(local, rejection),
            other => panic!("expected a local rejection, got {other:?}"),
        }
    }
    assert_eq!(net.row(0, rid(1)).accepted, Some(json!({"title": "Plain"})));
    // An edit that changes nothing is refused whether or not this replica
    // holds the Note, so it never marks one replica's projection as edited.
    net.project(0, rid(3), "Only on replica 0");
    let empty = net.rejected(Operation::Edit {
        record: rid(3),
        revision: note_rev(),
        changes: vec![],
    });
    assert_eq!(empty.code, RejectCode::Schema);
    net.assert_converged();
}

#[test]
fn create_note_family_via_generic_rejected() {
    let mut net = Net::with_types(2, &[JOURNAL]);
    net.project_all(rid(1), "Existing");
    let creates = [
        (rid(2), note_type(), note_rev(), json!({"title": "New"})),
        (
            rid(3),
            type_of(JOURNAL),
            rev(JOURNAL),
            json!({"title": "New", "date": 1}),
        ),
        // The verdict does not depend on whether this replica holds the Note.
        (
            rid(1),
            type_of(JOURNAL),
            rev(JOURNAL),
            json!({"title": "New", "date": 1}),
        ),
    ];
    for (record, type_id, revision, doc) in creates {
        let rejection = net.rejected(Operation::Create {
            record,
            type_id,
            revision,
            doc,
        });
        assert_eq!(rejection.code, RejectCode::DerivedField);
        assert!(
            rejection
                .detail
                .contains("create the Note through the note writer, then BindNote"),
            "{}",
            rejection.detail
        );
    }
    assert!(
        net.reps[0]
            .conn()
            .query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM data_record WHERE record IN (?1,?2))",
                [rid(2).0.as_slice(), rid(3).0.as_slice()],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
}

#[test]
fn bind_note_waits_for_projection() {
    let mut net = Net::with_types(2, &[JOURNAL]);
    // Replica 1 has not materialised the Note yet, though it holds the whole typed log.
    net.project(0, rid(1), "Day one");
    let outcomes = net.order_each(&bind(rid(1), json!({"date": 1, "mood": "calm"})));
    assert!(matches!(outcomes[0], Outcome::Accepted { .. }));
    assert_eq!(outcomes[1], Outcome::Waiting(Wait::MissingRecord(rid(1))));
    let outcomes = net.order_each(&edit_journal(rid(1), vec![set("/mood", json!("tired"))]));
    assert!(matches!(outcomes[0], Outcome::Accepted { .. }));
    assert_eq!(outcomes[1], Outcome::Waiting(Wait::Queued));
    // Other Notes are not held up.
    net.project_all(rid(2), "Another");
    net.ok(bind(rid(2), json!({"date": 2})));
    assert_eq!(net.parked(1), 2);
    // The Note arrives; the host replays the waiting work in order.
    net.project(1, rid(1), "Day one");
    assert_eq!(net.parked(1), 0);
    let row = net.row(1, rid(1));
    assert_eq!(row.type_id, type_of(JOURNAL));
    assert_eq!(
        row.accepted,
        Some(json!({"title": "Day one", "date": 1, "mood": "tired"}))
    );
    net.assert_converged();
    // A local binding of a Note this replica does not hold is refused.
    match net.reps[1].submit(SCOPE, &dev(), bind(rid(9), json!({"date": 9}))) {
        Err(SubmitError::Rejected(r)) => assert_eq!(r.code, RejectCode::NotFound),
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[test]
fn a_note_gap_waits_only_for_that_record() {
    let mut net = Net::with_types(2, &[ADDRESS, RECIPE, JOURNAL]);
    net.project_all(rid(1), "Day one");
    net.ok(bind(rid(1), json!({"date": 1})));
    // Replica 1 can no longer show Note 2's content.
    net.reps[1]
        .write(|tx| note::mark_unavailable(tx, SCOPE, rid(2)))
        .unwrap();

    // Unrelated typed work is unaffected: it applies here, at its position.
    let soup = Operation::Create {
        record: rid(50),
        type_id: type_of(RECIPE),
        revision: rev(RECIPE),
        doc: json!({"name": "Soup"}),
    };
    let outcomes = net.order_each(&soup);
    assert!(matches!(outcomes[0], Outcome::Accepted { .. }));
    assert!(
        matches!(outcomes[1], Outcome::Accepted { .. }),
        "{:?}",
        outcomes[1]
    );
    assert_eq!(net.parked(1), 0);

    // A creation of the same identity cannot prove absence either.
    let clash = Operation::Create {
        record: rid(2),
        type_id: type_of(RECIPE),
        revision: rev(RECIPE),
        doc: json!({"name": "Clash"}),
    };
    let outcomes = net.order_each(&clash);
    assert!(matches!(outcomes[1], Outcome::Waiting(Wait::MissingRecord(r)) if r == rid(2)));
    // An operation naming the gap Note is undecidable here whatever the
    // scope's coverage: it queues behind that record's wait, not refused.
    let edit = Operation::Edit {
        record: rid(2),
        revision: note_rev(),
        changes: vec![set("/title", json!("x"))],
    };
    let outcomes = net.order_each(&edit);
    assert!(matches!(outcomes[1], Outcome::Waiting(Wait::Queued)));
    assert_eq!(net.parked(1), 2);

    // With the gap cleared, replayed work is decided on what this replica has.
    net.reps[1]
        .write(|tx| {
            note::clear_unavailable(tx, SCOPE, rid(2))?;
            apply::retry_parked(tx, &Shipped, SCOPE).map(|decided| decided.len())
        })
        .unwrap();
    assert_eq!(net.parked(1), 0);
}

/// A targeted replay must also settle rows queued behind its record, in
/// position order; the whole-scope pass is the reference for their verdicts.
#[test]
fn targeted_retry_decides_queued_definitions_and_unique_creates() {
    let mut net = Net::new(3);
    for i in 1..3 {
        net.reps[i]
            .write(|tx| note::mark_unavailable(tx, SCOPE, rid(29)))
            .unwrap();
    }
    let missing = edit_journal(rid(29), vec![set("/mood", json!("waiting"))]);
    let outcomes = net.order_each(&missing);
    assert!(
        outcomes[1..]
            .iter()
            .all(|o| matches!(o, Outcome::Waiting(Wait::MissingRecord(_))))
    );
    let mut child: Value = serde_json::from_slice(&task_note()).unwrap();
    child["unique"] = json!([{"name": "one_done", "keys": ["/done"]}]);
    child["schema"]["required"] = json!(["done"]);
    let note_child = serde_json::to_vec(&child).unwrap();
    let define = Operation::DefineType {
        bytes: note_child.clone(),
    };
    let definitions = net.order_each(&define);
    assert!(
        matches!(definitions[0], Outcome::Accepted { .. }),
        "{definitions:?}"
    );
    assert_eq!(
        definitions[1..],
        [
            Outcome::Waiting(Wait::Queued),
            Outcome::Waiting(Wait::Queued)
        ]
    );
    let create = Operation::Create {
        record: rid(30),
        type_id: type_of(&note_child),
        revision: rev(&note_child),
        doc: json!({"title": "Task", "done": true}),
    };
    assert_eq!(
        net.order_each(&create)[1..],
        [
            Outcome::Waiting(Wait::Queued),
            Outcome::Waiting(Wait::Queued)
        ]
    );
    for i in 1..3 {
        let tx = net.reps[i].conn().unchecked_transaction().unwrap();
        note::clear_unavailable(&tx, SCOPE, rid(29)).unwrap();
        let decided = if i == 1 {
            bh_data::testkit::retry_parked_for(&tx, &Shipped, SCOPE, apply::Key::Record(rid(29)))
        } else {
            bh_data::testkit::retry_parked(&tx, &Shipped, SCOPE)
        }
        .unwrap();
        assert_eq!(decided.len(), 3);
        tx.commit().unwrap();
    }
    assert_eq!(net.parked(1), 0);
    assert_eq!(net.parked(2), 0);
    for i in 1..3 {
        let current: Vec<u8> = net.reps[i]
            .conn()
            .query_row(
                "SELECT current FROM data_type WHERE type=?1",
                [type_of(&note_child).0.as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(current, rev(&note_child).0);
    }
    assert!(
        net.reps[1]
            .conn()
            .query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM data_record WHERE record=?1)",
                [rid(30).0.as_slice()],
                |r| r.get::<_, bool>(0)
            )
            .unwrap()
    );
    assert_eq!(net.digest(1), net.digest(2));
}

#[test]
fn targeted_replay_ignores_a_later_parked_row_with_a_different_key() {
    let mut net = Net::new(2);
    for replica in &net.reps {
        replica
            .write(|tx| note::mark_unavailable(tx, SCOPE, rid(29)))
            .unwrap();
    }
    let waiting = net.order_each(&edit_journal(rid(29), vec![set("/mood", json!("waiting"))]));
    assert!(
        waiting
            .iter()
            .all(|o| matches!(o, Outcome::Waiting(Wait::MissingRecord(_))))
    );
    // A newer unreadable definition occupies a different key but overlaps
    // the Note. It cannot decide an earlier log position on targeted replay.
    let header = bh_data::value::canonical(&json!({"affects": {}}));
    let mut future = (payload::PAYLOAD_VERSION + 1).to_be_bytes().to_vec();
    future.extend_from_slice(&(header.len() as u32).to_be_bytes());
    future.extend_from_slice(header.as_bytes());
    let later = net.publish(future);
    assert_eq!(
        later,
        [
            Outcome::Waiting(Wait::Unsupported),
            Outcome::Waiting(Wait::Unsupported)
        ]
    );
    let parked = |replica: &Replica| -> Vec<Vec<rusqlite::types::Value>> {
        replica.conn().prepare("SELECT scope,position,affects,payload,actor,reason,mutation,type,record,uniques,app,holds,unresolved_type FROM data_parked ORDER BY position")
            .unwrap().query_map([], |r| (0..13).map(|i| r.get(i)).collect::<rusqlite::Result<Vec<_>>>())
            .unwrap().map(Result::unwrap).collect()
    };
    assert_eq!(parked(&net.reps[0]), parked(&net.reps[1]));
    let mut decided = Vec::new();
    for (i, replica) in net.reps.iter().enumerate() {
        let tx = replica.conn().unchecked_transaction().unwrap();
        note::clear_unavailable(&tx, SCOPE, rid(29)).unwrap();
        let result = if i == 0 {
            bh_data::testkit::retry_parked_for(&tx, &Shipped, SCOPE, apply::Key::Record(rid(29)))
        } else {
            bh_data::testkit::retry_parked(&tx, &Shipped, SCOPE)
        }
        .unwrap();
        decided.push(result);
        tx.commit().unwrap();
    }
    assert_eq!(decided[0], decided[1]);
    assert_eq!(decided[0].len(), 1);
    assert_eq!(net.digest(0), net.digest(1));
    assert_eq!(parked(&net.reps[0]), parked(&net.reps[1]));
}

#[test]
fn a_gapped_note_does_not_hold_unrelated_definitions_or_unique_writes() {
    let mut net = Net::new(1);
    net.reps[0]
        .write(|tx| note::mark_unavailable(tx, SCOPE, rid(29)))
        .unwrap();
    assert_eq!(
        net.order(edit_journal(rid(29), vec![set("/mood", json!("waiting"))])),
        Outcome::Waiting(Wait::MissingRecord(rid(29)))
    );
    net.ok(Operation::DefineType {
        bytes: ARTICLE.to_vec(),
    });
    net.ok(Operation::Create {
        record: rid(30),
        type_id: type_of(ARTICLE),
        revision: rev(ARTICLE),
        doc: json!({"title": "Article", "url": "https://example.test/unique"}),
    });
    assert_eq!(net.parked(0), 1);
}

#[test]
fn an_unsupported_edit_on_a_gapped_note_does_not_hold_unrelated_work() {
    let mut net = Net::new(1);
    net.reps[0]
        .write(|tx| note::mark_unavailable(tx, SCOPE, rid(29)))
        .unwrap();
    net.reps[0].without_kinds(&["edit"]);
    assert_eq!(
        net.order(edit_journal(rid(29), vec![set("/mood", json!("waiting"))])),
        Outcome::Waiting(Wait::Unsupported)
    );
    net.ok(Operation::DefineType {
        bytes: ARTICLE.to_vec(),
    });
    net.ok(Operation::Create {
        record: rid(30),
        type_id: type_of(ARTICLE),
        revision: rev(ARTICLE),
        doc: json!({"title": "Article", "url": "https://example.test/unique"}),
    });
    assert_eq!(net.parked(0), 1);
}

#[test]
fn targeted_retry_decides_a_parked_note_operation() {
    let mut net = Net::new(1);
    net.reps[0]
        .write(|tx| note::mark_unavailable(tx, SCOPE, rid(29)))
        .unwrap();
    assert_eq!(
        net.order(edit_journal(rid(29), vec![set("/mood", json!("waiting"))])),
        Outcome::Waiting(Wait::MissingRecord(rid(29)))
    );
    let decided = net.reps[0]
        .write(|tx| {
            note::clear_unavailable(tx, SCOPE, rid(29))?;
            apply::retry_parked_for(tx, &Shipped, SCOPE, apply::Key::Record(rid(29)))
        })
        .unwrap();
    assert_eq!(decided.len(), 1);
    assert_eq!(net.parked(0), 0);
}

/// Note gaps affect only results whose selected types include the Note family.
#[test]
fn a_note_gap_marks_only_note_listings_incomplete() {
    let mut net = Net::with_types(1, &[ADDRESS, RECIPE, JOURNAL]);
    net.project_all(rid(1), "Day one");
    net.ok(bind(rid(1), json!({"date": 1})));
    let notes = |net: &Net| {
        net.query(
            0,
            &select(TypeSelect::Family(note_type()), &["/title"]),
            Budget::INTERACTIVE,
        )
        .unwrap()
    };
    assert_eq!(notes(&net).completeness, Completeness::Complete);
    net.reps[0]
        .write(|tx| note::mark_unavailable(tx, SCOPE, rid(2)))
        .unwrap();
    let page = notes(&net);
    assert_eq!(
        page.completeness,
        Completeness::Incomplete(vec![Gap::NoteUnavailable])
    );
    assert_eq!(page.rows.len(), 1, "the projected Note is still listed");
    // Unrelated types are complete, and the gap never stops ordered work.
    assert_eq!(
        net.query(
            0,
            &select(TypeSelect::Exact(type_of(RECIPE)), &["/name"]),
            Budget::INTERACTIVE,
        )
        .unwrap()
        .completeness,
        Completeness::Complete
    );
    net.reps[0]
        .write(|tx| note::clear_unavailable(tx, SCOPE, rid(2)))
        .unwrap();
    assert_eq!(notes(&net).completeness, Completeness::Complete);
}

#[test]
fn bind_note_then_edit_extension_fields() {
    let mut net = Net::with_types(2, &[JOURNAL]);
    net.project_all(rid(1), "Day one");
    // Only extension fields: the Note's own fields keep the note writer.
    let refused = [
        (json!({"title": "x", "date": 1}), RejectCode::DerivedField),
        (
            json!({"date": 1, "weather": "sun"}),
            RejectCode::UnknownField,
        ),
        (json!({"date": "yesterday"}), RejectCode::Schema),
        (json!({"mood": "calm"}), RejectCode::Schema),
    ];
    for (doc, code) in refused {
        assert_eq!(net.rejected(bind(rid(1), doc)).code, code);
    }
    // A local binding stays pending: the record keeps its type until ordered.
    let saved = net.reps[0]
        .submit(
            SCOPE,
            &dev(),
            bind(rid(1), json!({"date": 1, "mood": "calm"})),
        )
        .unwrap();
    let local = net.row(0, rid(1));
    assert_eq!(local.type_id, note_type());
    assert!(local.pending);
    assert_eq!(local.accepted, Some(json!({"title": "Day one"})));
    // Re-deriving the view (here, after discarding other work) leaves it out too.
    let other = net.reps[0]
        .submit(SCOPE, &dev(), bind(rid(1), json!({"date": 3})))
        .unwrap();
    net.reps[0]
        .write(|tx| pending::discard(tx, &Shipped, other.mutation))
        .unwrap();
    let local = net.row(0, rid(1));
    assert_eq!(
        (local.type_id, local.doc, local.pending),
        (note_type(), None, true)
    );
    assert!(matches!(
        net.publish(saved.payload)[0],
        Outcome::Accepted { .. }
    ));
    let row = net.row(0, rid(1));
    assert_eq!(row.type_id, type_of(JOURNAL));
    assert!(!row.pending);

    let mood = MutationId::random();
    let op = edit_journal(rid(1), vec![set("/mood", json!("tired"))]);
    let outcomes = net.publish(payload::encode(mood, &op).unwrap());
    assert!(
        outcomes
            .iter()
            .all(|o| matches!(o, Outcome::Accepted { .. }))
    );
    // The Note contract's writers name only the Note's own fields.
    let by_note = Operation::Edit {
        record: rid(1),
        revision: note_rev(),
        changes: vec![set("/mood", json!("calm"))],
    };
    assert_eq!(net.rejected(by_note).code, RejectCode::UnknownField);
    assert_eq!(
        net.rejected(edit_journal(rid(1), vec![set("/date", json!("x"))]))
            .code,
        RejectCode::Schema
    );
    let undo = bh_data::mutation::undo::prepare(net.reps[0].conn(), SCOPE, mood).unwrap();
    net.ok(undo);
    assert_eq!(
        net.row(1, rid(1)).accepted,
        Some(json!({"title": "Day one", "date": 1, "mood": "calm"}))
    );
    net.assert_converged();
}

#[test]
fn family_query_lists_notes_and_journal_entries() {
    let mut net = Net::with_types(1, &[JOURNAL]);
    net.project_all(rid(1), "Plain note");
    net.project_all(rid(2), "Journal note");
    net.ok(bind(rid(2), json!({"date": 5, "mood": "glad"})));
    let page = net
        .query(
            0,
            &select(TypeSelect::Family(note_type()), &["/title"]),
            Budget::INTERACTIVE,
        )
        .unwrap();
    let rows: Vec<_> = page
        .rows
        .iter()
        .map(|row| (row.record, row.type_id, row.values["/title"].clone()))
        .collect();
    assert_eq!(rows.len(), 2);
    assert!(rows.contains(&(rid(1), note_type(), json!("Plain note"))));
    assert!(rows.contains(&(rid(2), type_of(JOURNAL), json!("Journal note"))));
    let exact = net
        .query(
            0,
            &select(TypeSelect::Exact(note_type()), &["/title"]),
            Budget::INTERACTIVE,
        )
        .unwrap();
    assert_eq!(exact.rows.len(), 1);
    assert_eq!(exact.rows[0].record, rid(1));
    let journal = net
        .query(
            0,
            &select(TypeSelect::Exact(type_of(JOURNAL)), &["/title", "/date"]),
            Budget::INTERACTIVE,
        )
        .unwrap();
    assert_eq!(journal.rows.len(), 1);
    assert_eq!(journal.rows[0].values["/title"], json!("Journal note"));
    assert_eq!(journal.rows[0].values["/date"], json!(5));
}

#[test]
fn old_note_consumer_edit_keeps_journal_fields() {
    let mut net = Net::with_types(2, &[JOURNAL]);
    net.project_all(rid(1), "Day one");
    // Replica 1 runs an executable that predates the binding operation.
    net.reps[1].without_kinds(&["bind_note"]);
    let outcomes = net.order_each(&bind(rid(1), json!({"date": 1, "mood": "calm"})));
    assert!(matches!(outcomes[0], Outcome::Accepted { .. }));
    assert_eq!(outcomes[1], Outcome::Waiting(Wait::Unsupported));
    let outcomes = net.order_each(&edit_journal(rid(1), vec![set("/mood", json!("tired"))]));
    assert_eq!(outcomes[1], Outcome::Waiting(Wait::Queued));
    // A consumer that knows only the Note renames it through the note writer.
    let rename = Operation::Edit {
        record: rid(1),
        revision: note_rev(),
        changes: vec![set("/title", json!("Renamed"))],
    };
    let outcomes = net.order_each(&rename);
    assert!(
        matches!(&outcomes[0], Outcome::Rejected(r) if r.code == RejectCode::DerivedField),
        "{outcomes:?}"
    );
    // The older replica holds it behind the binding it cannot read yet.
    assert_eq!(outcomes[1], Outcome::Waiting(Wait::Queued));
    net.project_all(rid(1), "Renamed");
    let row = net.row(0, rid(1));
    assert_eq!(
        row.accepted,
        Some(json!({"title": "Renamed", "date": 1, "mood": "tired"}))
    );
    assert_eq!(
        net.row(1, rid(1)).accepted,
        Some(json!({"title": "Renamed"}))
    );
    let notes = net
        .query(
            0,
            &select(TypeSelect::Family(note_type()), &["/title"]),
            Budget::INTERACTIVE,
        )
        .unwrap();
    assert_eq!(notes.rows[0].values["/title"], json!("Renamed"));
    let journal = net
        .query(
            0,
            &select(TypeSelect::Exact(type_of(JOURNAL)), &["/title", "/mood"]),
            Budget::INTERACTIVE,
        )
        .unwrap();
    assert_eq!(journal.rows[0].values["/title"], json!("Renamed"));
    assert_eq!(journal.rows[0].values["/mood"], json!("tired"));
    // Once upgraded, the older replica applies the binding with today's title.
    net.reps[1].upgrade().unwrap();
    assert_eq!(net.parked(1), 0);
    assert_eq!(net.row(1, rid(1)).accepted, row.accepted);
    net.assert_converged();
}

#[test]
fn rebind_to_other_specialisation_rejected() {
    let task = task_note();
    let mut net = Net::with_types(2, &[JOURNAL, &task, ARTICLE]);
    net.project_all(rid(1), "Day one");
    net.ok(bind(rid(1), json!({"date": 1})));
    let to = |type_id, revision, doc| Operation::BindNote {
        note: rid(1),
        type_id,
        revision,
        doc,
    };
    let other = net.rejected(to(type_of(&task), rev(&task), json!({"done": false})));
    assert_eq!(other.code, RejectCode::ConcreteTypeChange);
    let again = net.rejected(bind(rid(1), json!({"date": 2})));
    assert_eq!(again.code, RejectCode::Exists);
    // A type outside the Note family is never a binding target, held Note or not.
    let article = to(
        type_of(ARTICLE),
        rev(ARTICLE),
        json!({"url": "https://example.test/a"}),
    );
    assert_eq!(net.rejected(article).code, RejectCode::ConcreteTypeChange);
    let plain = net.rejected(to(note_type(), note_rev(), json!({})));
    assert_eq!(plain.code, RejectCode::ConcreteTypeChange);
    assert_eq!(net.row(0, rid(1)).type_id, type_of(JOURNAL));
    assert_eq!(net.row(0, rid(1)).accepted.unwrap()["date"], json!(1));
    net.assert_converged();
}

#[test]
fn recipe_references_real_note_without_copying() {
    let mut net = Net::with_types(1, &[ADDRESS, RECIPE]);
    net.project_all(rid(1), "Pancake method");
    net.ok(Operation::Create {
        record: rid(5),
        type_id: type_of(RECIPE),
        revision: rev(RECIPE),
        doc: json!({"name": "Pancakes", "instructions": {"record": hex(&rid(1).0)}}),
    });
    let mut q = select(TypeSelect::Exact(type_of(RECIPE)), &["/name"]);
    q.follow = vec![Follow {
        path: path("/instructions"),
        fields: vec![path("/title")],
    }];
    let title = |net: &Net| {
        let page = net.query(0, &q, Budget::INTERACTIVE).unwrap();
        let follow = page.rows[0].follows["/instructions"].clone().unwrap();
        assert_eq!(follow.record, rid(1));
        assert_eq!(follow.type_id, note_type());
        follow.values["/title"].clone()
    };
    assert_eq!(title(&net), json!("Pancake method"));
    net.project_all(rid(1), "Better pancake method");
    assert_eq!(title(&net), json!("Better pancake method"));
    // Neither record holds a copy of the Note's body; the recipe holds only its reference.
    assert_eq!(
        net.row(0, rid(1)).accepted,
        Some(json!({"title": "Better pancake method"}))
    );
    assert_eq!(
        net.row(0, rid(5)).accepted,
        Some(json!({"name": "Pancakes", "instructions": {"record": hex(&rid(1).0)}}))
    );
}

#[test]
fn generic_delete_of_note_rejected() {
    let mut net = Net::with_types(2, &[JOURNAL]);
    net.project_all(rid(1), "Plain");
    net.project_all(rid(2), "Journal");
    net.ok(bind(rid(2), json!({"date": 2})));
    for record in [rid(1), rid(2)] {
        let rejection = net.rejected(Operation::Delete { record });
        assert_eq!(rejection.code, RejectCode::DerivedField);
        assert!(
            rejection.detail.contains("note lifecycle"),
            "{}",
            rejection.detail
        );
    }
    net.assert_converged();
}

/// Index entries and references of `record` on replica `i`.
fn derived_rows(net: &Net, i: usize, record: RecordId) -> i64 {
    let row = net.row(i, record);
    net.reps[i]
        .conn()
        .query_row(
            "SELECT (SELECT count(*) FROM data_index_entry WHERE rec=?1)
                  + (SELECT count(*) FROM data_ref WHERE src=?1)
                  + (SELECT count(*) FROM data_text_state WHERE rec=?1)",
            [row.id],
            |r| r.get(0),
        )
        .unwrap()
}

#[test]
fn removal_timing_never_changes_ordered_verdicts() {
    let mut net = Net::with_types(2, &[JOURNAL]);
    net.project_all(rid(1), "Day one");
    net.project_all(rid(2), "Plain");
    net.ok(bind(rid(1), json!({"date": 1})));
    assert!(derived_rows(&net, 0, rid(1)) > 0);
    // Replica 0 removes the Note before a concurrent edit is ordered,
    // replica 1 after it: both reach the same verdict and state.
    net.reps[0]
        .write(|tx| note::remove_projection(tx, SCOPE, rid(1)))
        .unwrap();
    net.ok(edit_journal(rid(1), vec![set("/mood", json!("tired"))]));
    net.reps[1]
        .write(|tx| note::remove_projection(tx, SCOPE, rid(1)))
        .unwrap();
    net.assert_converged();
    for i in 0..2 {
        let row = net.row(i, rid(1));
        assert!(row.deleted);
        assert_eq!(
            row.accepted,
            Some(json!({"title": "Day one", "date": 1, "mood": "tired"}))
        );
        assert_eq!(derived_rows(&net, i, rid(1)), 0);
        let page = net
            .query(
                i,
                &select(TypeSelect::Family(note_type()), &["/title"]),
                Budget::INTERACTIVE,
            )
            .unwrap();
        let records: Vec<_> = page.rows.iter().map(|r| r.record).collect();
        assert_eq!(records, [rid(2)]);
    }
    // Only a local save sees the removal.
    match net.reps[0].submit(
        SCOPE,
        &dev(),
        edit_journal(rid(1), vec![set("/mood", json!("calm"))]),
    ) {
        Err(SubmitError::Rejected(r)) => assert_eq!(r.code, RejectCode::Deleted),
        other => panic!("expected Deleted, got {other:?}"),
    }
    // A plain Note removed on one replica only is bound everywhere.
    net.reps[0]
        .write(|tx| note::remove_projection(tx, SCOPE, rid(2)))
        .unwrap();
    match net.reps[0].submit(SCOPE, &dev(), bind(rid(2), json!({"date": 2}))) {
        Err(SubmitError::Rejected(r)) => assert_eq!(r.code, RejectCode::Deleted),
        other => panic!("expected Deleted, got {other:?}"),
    }
    net.ok(bind(rid(2), json!({"date": 2})));
    assert!(net.row(0, rid(2)).deleted);
    assert!(!net.row(1, rid(2)).deleted);
    net.assert_converged();
    // Restoring returns the same record, with its fields and history.
    let revision = net.project(0, rid(1), "Day one, restored");
    let row = net.row(0, rid(1));
    assert_eq!(row.text_rev, revision);
    let job = bh_data::text::next_jobs(net.reps[0].conn(), 10)
        .unwrap()
        .into_iter()
        .find(|j| j.record == rid(1))
        .unwrap();
    assert_eq!(job.wanted, revision);
    net.reps[0]
        .write(|tx| {
            assert!(bh_data::text::store_extracted(tx, &job, "restoredcontent")?);
            Ok(())
        })
        .unwrap();
    assert!(!row.deleted);
    assert_eq!(row.type_id, type_of(JOURNAL));
    assert_eq!(
        row.accepted,
        Some(json!({"title": "Day one, restored", "date": 1, "mood": "tired"}))
    );
    assert!(derived_rows(&net, 0, rid(1)) > 0);
    let journal = net
        .query(
            0,
            &select(TypeSelect::Exact(type_of(JOURNAL)), &["/title", "/mood"]),
            Budget::INTERACTIVE,
        )
        .unwrap();
    assert_eq!(journal.rows.len(), 1);
    assert_eq!(journal.rows[0].record, rid(1));
    assert_eq!(journal.rows[0].values["/mood"], json!("tired"));
    let history = history::of(net.reps[0].conn(), SCOPE, rid(1), 50, None).unwrap();
    assert_eq!(paths(&history), ["/mood", "/date"]);
    net.assert_converged();
}

#[test]
fn bind_note_of_non_note_record_refused() {
    let mut net = Net::with_types(2, &[JOURNAL, ARTICLE]);
    net.ok(Operation::Create {
        record: rid(5),
        type_id: type_of(ARTICLE),
        revision: rev(ARTICLE),
        doc: json!({"title": "An article", "url": "https://example.test/a"}),
    });
    let refused = net.rejected(bind(rid(5), json!({"date": 1})));
    assert_eq!(refused.code, RejectCode::ConcreteTypeChange);
    net.ok(Operation::Delete { record: rid(5) });
    // Deleted, it is still known not to be a Note: nothing waits for it.
    let refused = net.rejected(bind(rid(5), json!({"date": 1})));
    assert_eq!(refused.code, RejectCode::ConcreteTypeChange);
    assert_eq!((net.parked(0), net.parked(1)), (0, 0));
    net.assert_converged();
}

#[test]
fn plain_note_refuses_ordered_work_except_binding() {
    let mut net = Net::with_types(2, &[JOURNAL]);
    // Only replica 0 holds the Note.
    net.project(0, rid(1), "Plain");
    let ops = [
        Operation::Undo {
            target: MutationId::random(),
            record: rid(1),
            changes: vec![],
        },
        Operation::Migrate {
            record: rid(1),
            from: note_rev(),
            to: note_rev(),
            changes: vec![],
        },
        Operation::Action {
            record: rid(1),
            app: APP,
            action: "tidy".into(),
            changes: vec![],
        },
    ];
    for op in ops {
        let outcomes = net.order_each(&op);
        match &outcomes[0] {
            Outcome::Rejected(r) => {
                assert_eq!(r.code, RejectCode::DerivedField, "{op:?}");
                assert!(r.detail.contains("BindNote"), "{}", r.detail);
            }
            other => panic!("expected a refusal of {op:?}, got {other:?}"),
        }
        assert!(
            matches!(outcomes[1], Outcome::Rejected(_)),
            "{:?}",
            outcomes[1]
        );
    }
    assert_eq!(net.row(0, rid(1)).changed_at, None);
    net.assert_converged();
}

#[test]
fn note_recency_sort_uses_recent_index() {
    const NOTES: u32 = 3_000;
    let net = Net::new(1);
    net.reps[0]
        .write(|tx| {
            for n in 0..NOTES {
                note::upsert_projection(tx, SCOPE, nid(n), &format!("Note {n:04}"))?;
            }
            Ok(())
        })
        .unwrap();
    // Touch an old Note: it becomes the most recent.
    net.project(0, nid(10), "Note 0010, edited");
    let mut recent = select(TypeSelect::Family(note_type()), &["/title"]);
    recent.sort = vec![SortKey {
        key: KeyRef::Changed,
        desc: true,
    }];
    recent.limit = 3;
    // A page bounded by the recent index costs the same whatever the count.
    let tight = Budget { vm_steps: 20_000 };
    let page = net.query(0, &recent, tight).unwrap();
    let records: Vec<_> = page.rows.iter().map(|r| r.record).collect();
    assert_eq!(records, [nid(10), nid(NOTES - 1), nid(NOTES - 2)]);
    recent.after = page.next.clone();
    let next = net.query(0, &recent, tight).unwrap();
    assert_eq!(next.rows[0].record, nid(NOTES - 3));
    // The same page sorted by a key no index serves cannot stay within it.
    let mut by_title = select(TypeSelect::Family(note_type()), &["/title"]);
    by_title.sort = vec![SortKey {
        key: KeyRef::Field(path("/title")),
        desc: true,
    }];
    by_title.limit = 3;
    assert!(matches!(
        net.query(0, &by_title, tight),
        Err(QueryError::TooCostly { .. })
    ));
}

#[test]
fn projection_excluded_from_state_digest() {
    let mut net = Net::with_types(2, &[JOURNAL]);
    net.project(0, rid(1), "Seen here");
    net.project(1, rid(1), "Seen there");
    net.ok(bind(rid(1), json!({"date": 1})));
    // Titles, recency and text revisions are each replica's own projection,
    // and so is a Note only one replica has materialised.
    for title in ["Again", "And again"] {
        net.project(1, rid(1), title);
    }
    net.project(1, rid(2), "Only on replica 1");
    assert_ne!(net.row(0, rid(1)).changed, net.row(1, rid(1)).changed);
    net.assert_converged();
    // Ordered typed state still counts.
    let before = net.digest(0);
    net.ok(edit_journal(rid(1), vec![set("/mood", json!("calm"))]));
    assert_ne!(net.digest(0), before);
    net.assert_converged();
}

#[test]
fn unique_over_note_title_refused() {
    let mut ty: Value = serde_json::from_slice(JOURNAL).unwrap();
    ty["unique"] = json!([{"name": "title", "keys": ["/title"]}]);
    let mut net = Net::new(1);
    let rejection = net.rejected(Operation::DefineType {
        bytes: serde_json::to_vec(&ty).unwrap(),
    });
    assert_eq!(rejection.code, RejectCode::Schema);
    assert!(rejection.detail.contains("derived"), "{}", rejection.detail);
}

#[test]
fn schema_branch_over_note_title_refused() {
    let journal = |n: usize, schema: Value| {
        let mut ty: Value = serde_json::from_slice(JOURNAL).unwrap();
        ty["local"] = json!(format!("{:032x}", 0x0d00 + n));
        for (key, value) in schema.as_object().unwrap() {
            ty["schema"][key] = value.clone();
        }
        serde_json::to_vec(&ty).unwrap()
    };
    let mut net = Net::new(1);
    // Nothing outside the Note's own property may constrain the derived
    // title, or an ordered verdict would read this replica's projection.
    let title = json!({"properties": {"title": {"minLength": 3}}});
    let refused = [
        json!({"allOf": [title]}),
        json!({"anyOf": [title, {"required": ["date"]}]}),
        json!({"oneOf": [title, {"required": ["date"]}]}),
        json!({"$ref": "#/$defs/titled", "$defs": {"titled": title}}),
        json!({"enum": [{"title": "x", "date": 1}]}),
    ];
    for (n, schema) in refused.into_iter().enumerate() {
        let rejection = net.rejected(Operation::DefineType {
            bytes: journal(n, schema),
        });
        assert_eq!(rejection.code, RejectCode::Schema);
        assert!(
            rejection.detail.contains("unsupported root keyword"),
            "{}",
            rejection.detail
        );
    }
}

struct Local;
impl Authority for Local {
    fn actor(&self) -> Actor {
        dev()
    }
    fn reads(&self) -> Vec<Scope> {
        vec![SCOPE]
    }
    fn write(&self) -> Option<Scope> {
        Some(SCOPE)
    }
}

#[test]
fn note_types_describe_their_note_operations() {
    let net = Net::with_types(1, &[JOURNAL]);
    let session = DataSession::new(&net.reps[0], Local);
    let note = session
        .describe(SCOPE, TypeRef::Current(note_type()))
        .unwrap();
    assert_eq!(note.operations, ["note_body_edit"]);
    let journal = session
        .describe(SCOPE, TypeRef::Current(type_of(JOURNAL)))
        .unwrap();
    assert_eq!(
        journal.operations,
        ["note_body_edit", "bind_note", "edit", "undo"]
    );
}
