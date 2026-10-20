use bh_data::testkit::apply_ordered;
use bh_data::{
    Actor, AppId, FieldPath, MutationId, Position, RecordId, RejectCode, RevisionId, Scope, Wait,
    catalogue::Shipped,
    index,
    mutation::{
        apply::{Ordered, Outcome},
        history,
        ops::{FieldChange, Operation},
        pending::{self, LocalSaved},
        undo,
    },
    payload,
    store::{
        self, coverage,
        records::{self, RecordRow},
    },
};
use rusqlite::{
    Connection, StatementStatus,
    trace::{TraceEvent, TraceEventCodes},
};
use serde_json::{Value, json};
use std::cell::Cell;

thread_local! {
    // Only the measured save on this test's connection enables tracing.
    static RECORD_FETCH: Cell<(u32, i32)> = const { Cell::new((0, 0)) };
}

fn profile_record_fetch(event: TraceEvent<'_>) {
    if let TraceEvent::Profile(stmt, _) = event
        && stmt.sql().starts_with("SELECT id,type,revision,accepted,doc,deleted,pending,changed_at,changed,text_rev FROM data_record")
    {
        RECORD_FETCH.with(|count| {
            let (queries, steps) = count.get();
            count.set((queries + 1, steps + stmt.get_status(StatementStatus::VmStep)));
        });
    }
}

const ARTICLE: &[u8] = include_bytes!("fixtures/types/Article.json");
const ARTICLE_V2: &[u8] = include_bytes!("fixtures/types/Article.v2.json");
const SPECIAL: &[u8] = include_bytes!("fixtures/types/SpecialArticle.json");
const NOTE: &[u8] = include_bytes!("../core/note.v1.json");
const APP: AppId = AppId([2; 32]);

const SHARED: Scope = Scope {
    base: [1; 32],
    audience: [0; 32],
};
const PRIVATE: Scope = Scope {
    base: [1; 32],
    audience: [7; 32],
};

fn dev(n: u8) -> Actor {
    Actor::Device {
        account: [n; 32],
        device: [n; 32],
    }
}
fn job(n: u8, action: Option<&str>) -> Actor {
    Actor::Job {
        account: [n; 32],
        delegation: [9; 32],
        action: action.map(str::to_owned),
    }
}
fn rid(n: u8) -> RecordId {
    RecordId([n; 32])
}
fn path(p: &str) -> FieldPath {
    FieldPath::parse(p).unwrap()
}
fn set(p: &str, v: Value) -> FieldChange {
    FieldChange {
        path: path(p),
        value: Some(v),
    }
}
fn unset(p: &str) -> FieldChange {
    FieldChange {
        path: path(p),
        value: None,
    }
}
fn decode(bytes: &[u8]) -> (MutationId, Operation) {
    match payload::decode(bytes) {
        payload::Decoded::Op(mutation, op) | payload::Decoded::Confirmed(mutation, op, _) => {
            (mutation, op)
        }
        other => panic!("expected an operation, got {other:?}"),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn rev(bytes: &[u8]) -> RevisionId {
    RevisionId::of(bytes)
}
fn type_of(bytes: &[u8]) -> bh_data::TypeId {
    bh_data::definition::parse(bytes).unwrap().type_id
}

/// A record type with an atomic object, a container with leaf children, an
/// action-only state set by a declared action and a derived field.
fn memo_json() -> Value {
    json!({"format":"bh-type/1","local":"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "app":hex(&APP.0),"kind":"record","name":"Memo","description":"A short memo",
        "extends":null,"uses":[],
        "schema":{"type":"object","properties":{
            "text":{"type":"string","maxLength":500},
            "location":{"type":"object","properties":{
                "city":{"type":"string","maxLength":50},
                "street":{"type":"string","maxLength":50}},"additionalProperties":false},
            "status":{"type":"string","enum":["open","archived"]},
            "score":{"type":"integer"},
            "meta":{"type":"object","properties":{
                "color":{"type":"string","maxLength":20},
                "size":{"type":"integer"}}}},
            "required":["text"]},
        "fields":{
            "/text":{"meaning":"Memo text","write":"direct","kind":"string"},
            "/location":{"meaning":"Where, replaced as one value","write":"direct","kind":"atomic"},
            "/status":{"meaning":"Archive state","write":"action","kind":"enum"},
            "/score":{"meaning":"Computed score","write":"derived","kind":"integer"},
            "/meta":{"meaning":"Presentation","write":"derived","kind":"container"},
            "/meta/color":{"meaning":"Colour","write":"direct","kind":"string"},
            "/meta/size":{"meaning":"Size","write":"direct","kind":"integer"}},
        "actions":[{"name":"archive","effects":["/status"],"source":"archive.js"}],
        "indexes":[],"unique":[],"search":{"title":"/text","text":[]},"queries":[],
        "evolution":{"previous":null,"migration":"","migration_ops":[],
            "examples":{"valid":[],"invalid":[]}},
        "rationale":[]})
}
fn memo() -> Vec<u8> {
    serde_json::to_vec(&memo_json()).unwrap()
}

#[test]
fn history_interns_actor_and_limits_article_storage() {
    let mut net = Net::new(1);
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineApp {
            app: APP,
            name: "Articles".into(),
        },
    );
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        },
    );
    let type_id = type_of(ARTICLE);
    for n in 0..256u32 {
        let mut bytes = [0; 32];
        bytes[..4].copy_from_slice(&n.to_be_bytes());
        net.ok(SHARED, &dev(1), Operation::Create {
            record: RecordId(bytes), type_id, revision: rev(ARTICLE),
            doc: json!({"title":"Example headline", "url":format!("https://example.test/{n}"), "state":"new", "published":1700000000000_i64}),
        });
    }
    let db = &net.reps[0];
    let (rows, actors): (i64, i64) = db
        .query_row(
            "SELECT count(*),count(DISTINCT actor) FROM data_history",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(actors, 1);
    let bytes: i64 = db
        .query_row(
            "SELECT sum(pgsize) FROM dbstat WHERE name='data_history'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    eprintln!(
        "256 Articles: data_history={bytes} bytes, {rows} rows, {} bytes/Article",
        bytes / 256
    );
    let actor_count: i64 = db
        .query_row("SELECT count(*) FROM data_actor", [], |r| r.get(0))
        .unwrap();
    assert_eq!(actor_count, 1);
    assert!(
        bytes / 256 < 800,
        "history actor should be stored once per actor, not per field"
    );
    let entries = history::of(db, SHARED, RecordId([0; 32]), 16, None).unwrap();
    assert!(entries.iter().all(|e| e.actor == dev(1)));
}

fn replica() -> Connection {
    let mut conn = Connection::open_in_memory().unwrap();
    let tx = conn.transaction().unwrap();
    store::migrate(&tx).unwrap();
    for scope in [SHARED, PRIVATE] {
        let sid = records::scope_id(&tx, scope, &Shipped).unwrap();
        coverage::set(&tx, sid, Position(0), true).unwrap();
    }
    tx.commit().unwrap();
    conn
}

/// Replicas fed the same ordered vector; every outcome must agree.
struct Net {
    reps: Vec<Connection>,
    next: u64,
}

impl Net {
    fn new(n: usize) -> Self {
        Self {
            reps: (0..n).map(|_| replica()).collect(),
            next: 1,
        }
    }
    fn order(&mut self, scope: Scope, actor: &Actor, op: Operation) -> (MutationId, Outcome) {
        let mutation = MutationId::random();
        (mutation, self.order_as(scope, actor, mutation, &op))
    }
    fn order_as(
        &mut self,
        scope: Scope,
        actor: &Actor,
        mutation: MutationId,
        op: &Operation,
    ) -> Outcome {
        let position = Position(self.next);
        self.next += 1;
        let mut outcomes = Vec::new();
        for conn in &mut self.reps {
            outcomes.push(apply(conn, scope, position, actor, mutation, op));
        }
        for outcome in &outcomes[1..] {
            assert_eq!(outcome, &outcomes[0], "replicas disagree");
        }
        outcomes.remove(0)
    }
    fn order_saved(&mut self, scope: Scope, actor: &Actor, saved: &LocalSaved) -> Outcome {
        let (mutation, op) = decode(&saved.payload);
        assert_eq!(mutation, saved.mutation);
        self.order_as(scope, actor, mutation, &op)
    }
    fn ok(&mut self, scope: Scope, actor: &Actor, op: Operation) -> MutationId {
        let (mutation, outcome) = self.order(scope, actor, op);
        assert!(
            matches!(outcome, Outcome::Accepted { .. }),
            "expected acceptance, got {outcome:?}"
        );
        mutation
    }
    fn rejected(&mut self, scope: Scope, actor: &Actor, op: Operation) -> RejectCode {
        match self.order(scope, actor, op).1 {
            Outcome::Rejected(rejection) => rejection.code,
            other => panic!("expected rejection, got {other:?}"),
        }
    }
    fn row(&self, i: usize, scope: Scope, record: RecordId) -> Option<RecordRow> {
        let sid = records::lookup_scope(&self.reps[i], scope)
            .unwrap()
            .unwrap();
        records::get(&self.reps[i], sid, record).unwrap()
    }
    fn accepted(&self, scope: Scope, record: RecordId) -> Value {
        self.assert_converged();
        self.row(0, scope, record).unwrap().accepted.unwrap()
    }
    fn assert_converged(&self) {
        let first = digest(&self.reps[0]);
        for conn in &self.reps[1..] {
            assert_eq!(digest(conn), first, "replica state diverged");
        }
    }
    fn submit(&mut self, i: usize, scope: Scope, actor: &Actor, op: Operation) -> LocalSaved {
        let conn = &mut self.reps[i];
        let tx = conn.transaction().unwrap();
        let saved = bh_data::testkit::submit(&tx, &Shipped, scope, actor, op).unwrap();
        tx.commit().unwrap();
        saved
    }
    fn define_article(&mut self) {
        self.ok(
            SHARED,
            &dev(1),
            Operation::DefineApp {
                app: APP,
                name: "Reader".into(),
            },
        );
        self.ok(
            SHARED,
            &dev(1),
            Operation::DefineType {
                bytes: ARTICLE.to_vec(),
            },
        );
    }
    fn define_memo(&mut self) {
        self.ok(
            SHARED,
            &dev(1),
            Operation::DefineApp {
                app: APP,
                name: "Memos".into(),
            },
        );
        self.ok(SHARED, &dev(1), Operation::DefineType { bytes: memo() });
    }
}

fn apply(
    conn: &mut Connection,
    scope: Scope,
    position: Position,
    actor: &Actor,
    mutation: MutationId,
    op: &Operation,
) -> Outcome {
    let tx = conn.transaction().unwrap();
    let outcome = apply_ordered(
        &tx,
        &Shipped,
        &Ordered {
            scope,
            position,
            actor,
            mutation,
            op,
        },
    )
    .unwrap();
    tx.commit().unwrap();
    outcome
}

/// Accepted documents, deletion and field clocks: the replicated state. Rows
/// that only hold this replica's never-accepted work are local.
fn digest(conn: &Connection) -> Vec<String> {
    let mut out: Vec<String> = conn
        .prepare("SELECT hex(record),type,revision,coalesce(accepted,'-'),changed_at FROM data_record WHERE accepted IS NOT NULL OR changed_at IS NOT NULL ORDER BY record")
        .unwrap()
        .query_map([], |r| {
            Ok(format!(
                "{} {} {} {} {:?}",
                r.get::<_, String>(0)?,
                hex(&r.get::<_, Vec<u8>>(1)?),
                hex(&r.get::<_, Vec<u8>>(2)?),
                r.get::<_, String>(3)?,
                r.get::<_, Option<i64>>(4)?
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    out.extend(
        conn.prepare("SELECT hex(r.record),c.path,c.position,hex(c.mutation) FROM data_field_clock c JOIN data_record r ON r.id=c.rec ORDER BY r.record,c.path")
            .unwrap()
            .query_map([], |r| {
                Ok(format!(
                    "{} {} {} {}",
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                    r.get::<_, String>(3)?
                ))
            })
            .unwrap()
            .map(Result::unwrap),
    );
    out
}

#[test]
fn ordinary_save_fetches_record_once_and_preserves_pending_payload_and_accepted_state() {
    let mut net = Net::new(1);
    net.define_article();
    let record = rid(89);
    create_article(&mut net, record, "before", "https://example.com/before");
    let accepted = net.accepted(SHARED, record);
    let op = Operation::Edit {
        record,
        revision: rev(ARTICLE),
        changes: vec![set("/title", json!("after"))],
    };
    let conn = &mut net.reps[0];
    RECORD_FETCH.with(|count| count.set((0, 0)));
    conn.trace_v2(
        TraceEventCodes::SQLITE_TRACE_PROFILE,
        Some(profile_record_fetch),
    );
    let tx = conn.transaction().unwrap();
    let saved = bh_data::testkit::submit(&tx, &Shipped, SHARED, &dev(1), op.clone()).unwrap();
    tx.commit().unwrap();
    conn.trace_v2(TraceEventCodes::empty(), None);
    let (fetches, vm_steps) = RECORD_FETCH.with(Cell::get);
    eprintln!("ordinary save record SELECT: {fetches} executions, {vm_steps} VM steps");
    assert_eq!(
        fetches, 1,
        "the initial evaluation row can be reused for materialization"
    );
    assert!(vm_steps > 0);
    assert_eq!(decode(&saved.payload), (saved.mutation, op));
    let sid = records::lookup_scope(conn, SHARED).unwrap().unwrap();
    let row = records::get(conn, sid, record).unwrap().unwrap();
    assert_eq!(row.accepted, Some(accepted));
    assert_eq!(row.view().unwrap()["title"], "after");
    assert!(row.pending);
    let (payload, state): (Vec<u8>, String) = conn
        .query_row(
            "SELECT payload,state FROM data_pending WHERE mutation=?1",
            [saved.mutation.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(payload, saved.payload);
    assert_eq!(state, "pending");
}

fn create_article(net: &mut Net, record: RecordId, title: &str, url: &str) -> MutationId {
    net.ok(
        SHARED,
        &dev(1),
        Operation::Create {
            record,
            type_id: type_of(ARTICLE),
            revision: rev(ARTICLE),
            doc: json!({"title": title, "url": url}),
        },
    )
}
fn edit_article(changes: Vec<FieldChange>, record: RecordId) -> Operation {
    Operation::Edit {
        record,
        revision: rev(ARTICLE),
        changes,
    }
}
fn create_memo(net: &mut Net, record: RecordId, doc: Value) -> MutationId {
    net.ok(
        SHARED,
        &dev(1),
        Operation::Create {
            record,
            type_id: type_of(&memo()),
            revision: rev(&memo()),
            doc,
        },
    )
}
fn edit_memo(record: RecordId, changes: Vec<FieldChange>) -> Operation {
    Operation::Edit {
        record,
        revision: rev(&memo()),
        changes,
    }
}

#[test]
fn create_validates_post_image() {
    let mut net = Net::new(2);
    net.define_article();
    let (_, outcome) = net.order(
        SHARED,
        &dev(1),
        Operation::Create {
            record: rid(1),
            type_id: type_of(ARTICLE),
            revision: rev(ARTICLE),
            doc: json!({"title":"Hello","url":"https://example.test/1"}),
        },
    );
    assert_eq!(
        outcome,
        Outcome::Accepted {
            record: Some(rid(1)),
            skipped: vec![]
        }
    );
    assert_eq!(
        net.accepted(SHARED, rid(1)),
        json!({"title":"Hello","url":"https://example.test/1"})
    );
    let row = net.row(0, SHARED, rid(1)).unwrap();
    assert_eq!(row.revision, rev(ARTICLE));
    assert_eq!(row.changed_at, Some(Position(3)));
    assert!(row.doc.is_none() && !row.pending && !row.deleted);
}

#[test]
fn invalid_post_image_rejected_and_state_unchanged() {
    let mut net = Net::new(2);
    net.define_article();
    let code = net.rejected(
        SHARED,
        &dev(1),
        Operation::Create {
            record: rid(1),
            type_id: type_of(ARTICLE),
            revision: rev(ARTICLE),
            doc: json!({"title": 5, "url":"https://example.test/1"}),
        },
    );
    assert_eq!(code, RejectCode::Schema);
    assert!(net.row(0, SHARED, rid(1)).is_none());
    create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    let before = digest(&net.reps[0]);
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            edit_article(vec![set("/title", json!(5))], rid(1))
        ),
        RejectCode::Schema
    );
    assert_eq!(
        net.rejected(SHARED, &dev(1), edit_article(vec![unset("/url")], rid(1))),
        RejectCode::Schema
    );
    assert_eq!(digest(&net.reps[0]), before);
    net.assert_converged();
}

#[test]
fn different_fields_combine() {
    let mut net = Net::new(2);
    net.define_article();
    create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    net.ok(
        SHARED,
        &dev(1),
        edit_article(vec![set("/title", json!("New title"))], rid(1)),
    );
    net.ok(
        SHARED,
        &dev(2),
        edit_article(vec![set("/state", json!("saved"))], rid(1)),
    );
    assert_eq!(
        net.accepted(SHARED, rid(1)),
        json!({"title":"New title","url":"https://example.test/1","state":"saved"})
    );
}

#[test]
fn same_field_later_position_wins_regardless_of_submit_time() {
    let mut net = Net::new(2);
    net.define_article();
    create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    // Replica 0 saves first; replica 1 saves later but is ordered first.
    let early = net.submit(
        0,
        SHARED,
        &dev(1),
        edit_article(vec![set("/title", json!("early"))], rid(1)),
    );
    let late = net.submit(
        1,
        SHARED,
        &dev(2),
        edit_article(vec![set("/title", json!("late"))], rid(1)),
    );
    assert!(matches!(
        net.order_saved(SHARED, &dev(2), &late),
        Outcome::Accepted { .. }
    ));
    assert!(matches!(
        net.order_saved(SHARED, &dev(1), &early),
        Outcome::Accepted { .. }
    ));
    assert_eq!(net.accepted(SHARED, rid(1))["title"], json!("early"));
    for i in 0..2 {
        let row = net.row(i, SHARED, rid(1)).unwrap();
        assert!(row.doc.is_none() && !row.pending);
    }
}

#[test]
fn old_writer_preserves_newer_field() {
    let mut net = Net::new(2);
    net.define_article();
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineType {
            bytes: ARTICLE_V2.to_vec(),
        },
    );
    net.ok(
        SHARED,
        &dev(1),
        Operation::Create {
            record: rid(1),
            type_id: type_of(ARTICLE),
            revision: rev(ARTICLE_V2),
            doc: json!({"title":"Hello","url":"https://example.test/1","summary":"Short"}),
        },
    );
    net.ok(
        SHARED,
        &dev(2),
        edit_article(vec![set("/title", json!("Old client title"))], rid(1)),
    );
    assert_eq!(
        net.accepted(SHARED, rid(1)),
        json!({"title":"Old client title","url":"https://example.test/1","summary":"Short"})
    );
    assert_eq!(
        net.row(0, SHARED, rid(1)).unwrap().revision,
        rev(ARTICLE_V2)
    );
    // A v1 writer does not know the v2 field, so it cannot name it.
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(2),
            edit_article(vec![set("/summary", json!("x"))], rid(1))
        ),
        RejectCode::UnknownField
    );
}

#[test]
fn base_consumer_edits_inherited_field_of_subtype_preserving_extension() {
    let mut net = Net::new(2);
    net.define_article();
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineType {
            bytes: SPECIAL.to_vec(),
        },
    );
    net.ok(
        SHARED,
        &dev(1),
        Operation::Create {
            record: rid(1),
            type_id: type_of(SPECIAL),
            revision: rev(SPECIAL),
            doc: json!({"title":"Hello","url":"https://example.test/1","category":"science"}),
        },
    );
    net.ok(
        SHARED,
        &dev(2),
        edit_article(vec![set("/title", json!("Base consumer"))], rid(1)),
    );
    assert_eq!(
        net.accepted(SHARED, rid(1)),
        json!({"title":"Base consumer","url":"https://example.test/1","category":"science"})
    );
    let row = net.row(0, SHARED, rid(1)).unwrap();
    assert_eq!(
        (row.type_id, row.revision),
        (type_of(SPECIAL), rev(SPECIAL))
    );
    // The base revision cannot reach the extension's own field.
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(2),
            edit_article(vec![set("/category", json!("x"))], rid(1))
        ),
        RejectCode::UnknownField
    );
    // Nor can the base revision create the specialised record.
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(2),
            Operation::Create {
                record: rid(2),
                type_id: type_of(SPECIAL),
                revision: rev(ARTICLE),
                doc: json!({"title":"x","url":"https://example.test/2"}),
            }
        ),
        RejectCode::RevisionNotPermitted
    );
}

#[test]
fn undeclared_path_rejected() {
    let mut net = Net::new(2);
    net.define_article();
    create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            edit_article(vec![set("/nope", json!(1))], rid(1))
        ),
        RejectCode::UnknownField
    );
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            Operation::Create {
                record: rid(2),
                type_id: type_of(ARTICLE),
                revision: rev(ARTICLE),
                doc: json!({"title":"x","url":"https://example.test/2","extra":true}),
            }
        ),
        RejectCode::UnknownField
    );
}

#[test]
fn overlapping_paths_rejected() {
    let mut net = Net::new(2);
    net.define_memo();
    create_memo(&mut net, rid(1), json!({"text":"a"}));
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            edit_memo(
                rid(1),
                vec![set("/text", json!("b")), set("/text", json!("c"))]
            )
        ),
        RejectCode::Overlap
    );
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            edit_memo(
                rid(1),
                vec![set("/meta", json!({})), set("/meta/color", json!("red"))]
            )
        ),
        RejectCode::Overlap
    );
    net.ok(
        SHARED,
        &dev(1),
        edit_memo(
            rid(1),
            vec![
                set("/meta/color", json!("red")),
                set("/meta/size", json!(3)),
            ],
        ),
    );
    assert_eq!(
        net.accepted(SHARED, rid(1)),
        json!({"text":"a","meta":{"color":"red","size":3}})
    );
}

#[test]
fn atomic_object_replaced_whole() {
    let mut net = Net::new(2);
    net.define_memo();
    create_memo(
        &mut net,
        rid(1),
        json!({"text":"a","location":{"city":"Old","street":"Main"}}),
    );
    net.ok(
        SHARED,
        &dev(1),
        edit_memo(rid(1), vec![set("/location", json!({"city":"New"}))]),
    );
    assert_eq!(
        net.accepted(SHARED, rid(1))["location"],
        json!({"city":"New"})
    );
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            edit_memo(rid(1), vec![set("/location/city", json!("x"))])
        ),
        RejectCode::UnknownField
    );
}

#[test]
fn derived_field_rejected() {
    let mut net = Net::new(2);
    net.define_memo();
    create_memo(&mut net, rid(1), json!({"text":"a"}));
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            edit_memo(rid(1), vec![set("/score", json!(3))])
        ),
        RejectCode::DerivedField
    );
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            edit_memo(rid(1), vec![set("/meta", json!({"color":"red"}))])
        ),
        RejectCode::DerivedField
    );
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            Operation::Create {
                record: rid(2),
                type_id: type_of(&memo()),
                revision: rev(&memo()),
                doc: json!({"text":"a","score":3}),
            }
        ),
        RejectCode::DerivedField
    );
}

fn archive(record: RecordId, app: AppId, action: &str, changes: Vec<FieldChange>) -> Operation {
    Operation::Action {
        record,
        app,
        action: action.into(),
        changes,
    }
}

#[test]
fn action_only_needs_declared_action() {
    let mut net = Net::new(2);
    net.define_memo();
    create_memo(&mut net, rid(1), json!({"text":"a"}));
    let archived = || vec![set("/status", json!("archived"))];
    assert_eq!(
        net.rejected(SHARED, &dev(1), edit_memo(rid(1), archived())),
        RejectCode::ActionOnly
    );
    assert_eq!(
        net.rejected(SHARED, &dev(1), archive(rid(1), APP, "archive", archived())),
        RejectCode::ActionOnly,
        "a device does not run app actions"
    );
    assert_eq!(
        net.rejected(
            SHARED,
            &job(1, Some("other")),
            archive(rid(1), APP, "archive", archived())
        ),
        RejectCode::ActionOnly,
        "the job must be delegated this action"
    );
    assert_eq!(
        net.rejected(
            SHARED,
            &job(1, Some("purge")),
            archive(rid(1), APP, "purge", archived())
        ),
        RejectCode::ActionOnly,
        "undeclared action"
    );
    assert_eq!(
        net.rejected(
            SHARED,
            &job(1, Some("archive")),
            archive(rid(1), AppId([3; 32]), "archive", archived())
        ),
        RejectCode::AppInactive,
        "another app is not defined here"
    );
    assert_eq!(
        net.rejected(
            SHARED,
            &job(1, Some("archive")),
            archive(rid(1), APP, "archive", vec![set("/text", json!("b"))])
        ),
        RejectCode::ActionOnly,
        "outside the action's effects"
    );
    net.ok(
        SHARED,
        &job(1, Some("archive")),
        archive(rid(1), APP, "archive", archived()),
    );
    assert_eq!(net.accepted(SHARED, rid(1))["status"], json!("archived"));
}

#[test]
fn undo_cannot_revert_action_only_field() {
    let mut net = Net::new(2);
    net.define_memo();
    create_memo(&mut net, rid(1), json!({"text":"a"}));
    let target = net.ok(
        SHARED,
        &job(1, Some("archive")),
        archive(
            rid(1),
            APP,
            "archive",
            vec![set("/status", json!("archived"))],
        ),
    );
    let undo_op = undo::prepare(&net.reps[0], SHARED, target).unwrap();
    assert_eq!(
        undo_op,
        Operation::Undo {
            target,
            record: rid(1),
            changes: vec![unset("/status")]
        }
    );
    assert_eq!(
        net.rejected(SHARED, &dev(1), undo_op),
        RejectCode::ActionOnly
    );
    assert_eq!(net.accepted(SHARED, rid(1))["status"], json!("archived"));
}

#[test]
fn delete_of_action_protected_record_rejected() {
    let mut net = Net::new(2);
    net.define_memo();
    create_memo(&mut net, rid(1), json!({"text":"a"}));
    assert_eq!(
        net.rejected(SHARED, &dev(1), Operation::Delete { record: rid(1) }),
        RejectCode::ActionOnly
    );
    assert!(!net.row(0, SHARED, rid(1)).unwrap().deleted);
}

#[test]
fn create_existing_id_rejected() {
    let mut net = Net::new(2);
    net.define_article();
    create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(2),
            Operation::Create {
                record: rid(1),
                type_id: type_of(ARTICLE),
                revision: rev(ARTICLE),
                doc: json!({"title":"Other","url":"https://example.test/2"}),
            }
        ),
        RejectCode::Exists
    );
    assert_eq!(net.accepted(SHARED, rid(1))["title"], json!("Hello"));
}

#[test]
fn define_app_twice_rejected() {
    let mut net = Net::new(2);
    net.define_article();
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(2),
            Operation::DefineApp {
                app: APP,
                name: "Again".into()
            }
        ),
        RejectCode::Exists
    );
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(2),
            Operation::DefineType {
                bytes: ARTICLE.to_vec()
            }
        ),
        RejectCode::Exists
    );
}

#[test]
fn foreign_app_revision_rejected() {
    let mut net = Net::new(2);
    // The type's app is defined in another audience only.
    net.ok(
        PRIVATE,
        &dev(1),
        Operation::DefineApp {
            app: APP,
            name: "Reader".into(),
        },
    );
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            Operation::DefineType {
                bytes: ARTICLE.to_vec()
            }
        ),
        RejectCode::NotFound
    );
    net.define_article();
    net.ok(SHARED, &dev(1), Operation::DefineType { bytes: memo() });
    // A revision of another type cannot write this type's records.
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            Operation::Create {
                record: rid(1),
                type_id: type_of(ARTICLE),
                revision: rev(&memo()),
                doc: json!({"title":"x","url":"https://example.test/1"}),
            }
        ),
        RejectCode::RevisionNotPermitted
    );
    create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            edit_memo(rid(1), vec![set("/text", json!("x"))])
        ),
        RejectCode::RevisionNotPermitted
    );
}

#[test]
fn job_may_add_compatible_non_rule_revision_device_for_rule_change() {
    let mut net = Net::new(2);
    net.define_article();
    net.ok(
        SHARED,
        &job(2, None),
        Operation::DefineType {
            bytes: ARTICLE_V2.to_vec(),
        },
    );
    let sid = records::lookup_scope(&net.reps[0], SHARED)
        .unwrap()
        .unwrap();
    let current = store::registry::current(&net.reps[0], sid, type_of(ARTICLE), &Shipped).unwrap();
    assert_eq!(current.unwrap().revision, rev(ARTICLE_V2));
    let permitted =
        store::registry::permitted(&net.reps[0], sid, type_of(ARTICLE), &Shipped).unwrap();
    assert_eq!(permitted, vec![rev(ARTICLE), rev(ARTICLE_V2)]);
    // Dropping the unique constraint changes the rules for existing records.
    let mut v3: Value = serde_json::from_slice(ARTICLE_V2).unwrap();
    v3["unique"] = json!([]);
    v3["description"] = json!("Articles without a unique source");
    let v3 = serde_json::to_vec(&v3).unwrap();
    assert_eq!(
        net.rejected(
            SHARED,
            &job(2, None),
            Operation::DefineType { bytes: v3.clone() }
        ),
        RejectCode::DeviceOnly
    );
    net.ok(SHARED, &dev(1), Operation::DefineType { bytes: v3.clone() });
    let current = store::registry::current(&net.reps[1], sid, type_of(ARTICLE), &Shipped).unwrap();
    assert_eq!(current.unwrap().revision, rev(&v3));
}

#[test]
fn job_may_define_new_type() {
    let mut net = Net::new(2);
    net.ok(
        SHARED,
        &job(2, None),
        Operation::DefineApp {
            app: APP,
            name: "Agent app".into(),
        },
    );
    net.ok(
        SHARED,
        &job(2, None),
        Operation::DefineType { bytes: memo() },
    );
    create_memo(&mut net, rid(1), json!({"text":"made by an agent's app"}));
}

#[test]
fn core_type_id_reserved() {
    let mut net = Net::new(2);
    net.define_article();
    let mut fake: Value = serde_json::from_slice(ARTICLE).unwrap();
    fake["builtin"] = json!("Note");
    fake["local"] = json!("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            Operation::DefineType {
                bytes: serde_json::to_vec(&fake).unwrap()
            }
        ),
        RejectCode::ReservedType
    );
    // An explicit null is no built-in claim.
    fake["builtin"] = Value::Null;
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineType {
            bytes: serde_json::to_vec(&fake).unwrap(),
        },
    );
    assert_eq!(
        net.rejected(
            PRIVATE,
            &dev(1),
            Operation::Adopt {
                from_audience: SHARED.audience,
                revision: rev(NOTE),
                bytes: NOTE.to_vec(),
            }
        ),
        RejectCode::ReservedType
    );
    // Generic creation cannot produce a built-in Note.
    let (note, note_rev) = bh_data::catalogue::baseline_note();
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            Operation::Create {
                record: rid(1),
                type_id: note,
                revision: note_rev,
                doc: json!({"title":"x"}),
            }
        ),
        RejectCode::DerivedField
    );
}

#[test]
fn unique_rejects_later_duplicate_and_names_holder() {
    let mut net = Net::new(2);
    net.define_article();
    create_article(&mut net, rid(1), "First", "https://example.test/same");
    let (_, outcome) = net.order(
        SHARED,
        &dev(2),
        Operation::Create {
            record: rid(2),
            type_id: type_of(ARTICLE),
            revision: rev(ARTICLE),
            doc: json!({"title":"Second","url":"https://example.test/same"}),
        },
    );
    let Outcome::Rejected(rejection) = outcome else {
        panic!("expected rejection, got {outcome:?}")
    };
    assert_eq!(rejection.code, RejectCode::Unique);
    assert_eq!(rejection.path, Some(path("/url")));
    assert!(rejection.detail.contains(&hex(&rid(1).0)), "{rejection:?}");
    create_article(&mut net, rid(2), "Second", "https://example.test/other");
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(2),
            edit_article(
                vec![set("/url", json!("https://example.test/same"))],
                rid(2)
            )
        ),
        RejectCode::Unique
    );
    // A deleted holder frees its key.
    net.ok(SHARED, &dev(1), Operation::Delete { record: rid(1) });
    net.ok(
        SHARED,
        &dev(2),
        edit_article(
            vec![set("/url", json!("https://example.test/same"))],
            rid(2),
        ),
    );
    net.assert_converged();
}

#[test]
fn added_unique_keeps_existing_duplicates_rejects_new() {
    let mut net = Net::new(2);
    let mut loose: Value = serde_json::from_slice(ARTICLE).unwrap();
    loose["unique"] = json!([]);
    loose["description"] = json!("Articles before the source became unique");
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineApp {
            app: APP,
            name: "Reader".into(),
        },
    );
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineType {
            bytes: serde_json::to_vec(&loose).unwrap(),
        },
    );
    for n in [1, 2] {
        net.ok(
            SHARED,
            &dev(1),
            Operation::Create {
                record: rid(n),
                type_id: type_of(ARTICLE),
                revision: RevisionId::of(&serde_json::to_vec(&loose).unwrap()),
                doc: json!({"title":"Copy","url":"https://example.test/same"}),
            },
        );
    }
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        },
    );
    // While the new unique index builds, nobody can prove a key is free.
    let (_, building) = net.order(
        SHARED,
        &dev(1),
        Operation::Create {
            record: rid(3),
            type_id: type_of(ARTICLE),
            revision: rev(ARTICLE),
            doc: json!({"title":"Copy","url":"https://example.test/fresh"}),
        },
    );
    assert_eq!(building, Outcome::Waiting(Wait::UniquenessUnknown(SHARED)));
    for conn in &mut net.reps {
        let tx = conn.transaction().unwrap();
        for ix in index::pending_work(&tx).unwrap() {
            while !index::backfill_step(&tx, ix, 500).unwrap().ready {}
        }
        // Replaying parked work is the host's retry; this test needs only verdicts.
        tx.execute("DELETE FROM data_parked", []).unwrap();
        tx.commit().unwrap();
    }
    net.ok(
        SHARED,
        &dev(2),
        edit_article(vec![set("/title", json!("Still a duplicate"))], rid(1)),
    );
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            Operation::Create {
                record: rid(4),
                type_id: type_of(ARTICLE),
                revision: rev(ARTICLE),
                doc: json!({"title":"Copy","url":"https://example.test/same"}),
            }
        ),
        RejectCode::Unique
    );
    assert_eq!(
        net.accepted(SHARED, rid(2))["url"],
        json!("https://example.test/same")
    );
}

fn incomplete(net: &mut Net, scope: Scope) {
    for conn in &mut net.reps {
        let tx = conn.transaction().unwrap();
        let sid = records::scope_id(&tx, scope, &Shipped).unwrap();
        coverage::set(&tx, sid, Position(0), false).unwrap();
        tx.commit().unwrap();
    }
}
fn parked(conn: &Connection) -> Vec<(i64, String)> {
    conn.prepare("SELECT position,affects FROM data_parked ORDER BY position")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

#[test]
fn uniqueness_waits_without_coverage() {
    let mut net = Net::new(2);
    net.define_article();
    net.ok(SHARED, &dev(1), Operation::DefineType { bytes: memo() });
    create_memo(&mut net, rid(3), json!({"text":"unrelated type"}));
    incomplete(&mut net, SHARED);
    let (_, first) = net.order(
        SHARED,
        &dev(1),
        Operation::Create {
            record: rid(1),
            type_id: type_of(ARTICLE),
            revision: rev(ARTICLE),
            doc: json!({"title":"a","url":"https://example.test/1"}),
        },
    );
    assert_eq!(first, Outcome::Waiting(Wait::UniquenessUnknown(SHARED)));
    let (_, second) = net.order(
        SHARED,
        &dev(1),
        Operation::Create {
            record: rid(2),
            type_id: type_of(ARTICLE),
            revision: rev(ARTICLE),
            doc: json!({"title":"b","url":"https://example.test/2"}),
        },
    );
    assert_eq!(second, Outcome::Waiting(Wait::Queued));
    net.ok(
        SHARED,
        &dev(1),
        edit_memo(rid(3), vec![set("/text", json!("unrelated edit"))]),
    );
    assert!(net.row(0, SHARED, rid(1)).is_none());
    let article = hex(&type_of(ARTICLE).0);
    assert_eq!(
        parked(&net.reps[0]),
        vec![
            (5, format!("t:{article}")),
            (6, format!("r:{}", hex(&rid(2).0)))
        ]
    );
    net.assert_converged();
}

#[test]
fn parked_op_blocks_later_ops_on_same_record() {
    let mut net = Net::new(2);
    net.define_memo();
    incomplete(&mut net, SHARED);
    let (_, first) = net.order(
        SHARED,
        &dev(1),
        edit_memo(rid(1), vec![set("/text", json!("b"))]),
    );
    assert_eq!(first, Outcome::Waiting(Wait::MissingRecord(rid(1))));
    let (_, second) = net.order(
        SHARED,
        &dev(1),
        edit_memo(rid(1), vec![set("/text", json!("c"))]),
    );
    assert_eq!(second, Outcome::Waiting(Wait::Queued));
    // Even a create of that record waits behind the queue.
    let (_, third) = net.order(
        SHARED,
        &dev(1),
        Operation::Create {
            record: rid(1),
            type_id: type_of(&memo()),
            revision: rev(&memo()),
            doc: json!({"text":"a"}),
        },
    );
    assert_eq!(third, Outcome::Waiting(Wait::Queued));
    assert_eq!(parked(&net.reps[1]).len(), 3);
    net.assert_converged();
}

#[test]
fn unrelated_record_not_blocked() {
    let mut net = Net::new(2);
    net.define_memo();
    create_memo(&mut net, rid(2), json!({"text":"a"}));
    incomplete(&mut net, SHARED);
    let (_, first) = net.order(
        SHARED,
        &dev(1),
        edit_memo(rid(1), vec![set("/text", json!("b"))]),
    );
    assert_eq!(first, Outcome::Waiting(Wait::MissingRecord(rid(1))));
    net.ok(
        SHARED,
        &dev(1),
        edit_memo(rid(2), vec![set("/text", json!("b"))]),
    );
    assert_eq!(net.accepted(SHARED, rid(2)), json!({"text":"b"}));
    // Another audience of the same base is independent.
    net.ok(
        PRIVATE,
        &dev(1),
        Operation::DefineApp {
            app: APP,
            name: "Memos".into(),
        },
    );
}

/// Applies at an already used position on every replica; outcomes must agree.
fn redeliver(
    net: &mut Net,
    position: u64,
    actor: &Actor,
    mutation: MutationId,
    op: &Operation,
) -> Outcome {
    let outcomes: Vec<_> = net
        .reps
        .iter_mut()
        .map(|conn| apply(conn, SHARED, Position(position), actor, mutation, op))
        .collect();
    assert!(
        outcomes.iter().all(|o| o == &outcomes[0]),
        "replicas disagree"
    );
    outcomes[0].clone()
}

#[test]
fn redelivered_position_is_duplicate_noop() {
    let mut net = Net::new(2);
    net.define_article();
    let op = Operation::Create {
        record: rid(1),
        type_id: type_of(ARTICLE),
        revision: rev(ARTICLE),
        doc: json!({"title":"a","url":"https://example.test/1"}),
    };
    let (mutation, first) = net.order(SHARED, &dev(1), op.clone());
    assert!(matches!(first, Outcome::Accepted { .. }));
    let before = digest(&net.reps[0]);
    // The same delivery repeated at its own position.
    assert_eq!(
        redeliver(&mut net, 3, &dev(1), mutation, &op),
        Outcome::Duplicate
    );
    // Anything at an applied position is a redelivery, whatever it carries.
    let other = edit_article(vec![set("/title", json!("b"))], rid(1));
    assert_eq!(
        redeliver(&mut net, 3, &dev(2), MutationId::random(), &other),
        Outcome::Duplicate
    );
    assert_eq!(
        redeliver(&mut net, 1, &dev(1), mutation, &op),
        Outcome::Duplicate
    );
    assert_eq!(digest(&net.reps[0]), before);
    net.assert_converged();
    // A rejected position is final too.
    let bad = edit_article(vec![set("/nope", json!(1))], rid(1));
    let (bad_id, rejected) = net.order(SHARED, &dev(1), bad.clone());
    assert!(matches!(rejected, Outcome::Rejected(_)));
    assert_eq!(
        redeliver(&mut net, 4, &dev(1), bad_id, &bad),
        Outcome::Duplicate
    );
    // So is a parked one: redelivery neither re-evaluates nor parks it twice.
    incomplete(&mut net, SHARED);
    let missing = edit_article(vec![set("/title", json!("c"))], rid(9));
    let (missing_id, waiting) = net.order(SHARED, &dev(1), missing.clone());
    assert_eq!(waiting, Outcome::Waiting(Wait::MissingRecord(rid(9))));
    assert_eq!(
        redeliver(&mut net, 5, &dev(1), missing_id, &missing),
        Outcome::Duplicate
    );
    assert_eq!(parked(&net.reps[0]).len(), 1);
    net.assert_converged();
}

#[test]
fn reused_mutation_id_applies_on_merits() {
    let mut net = Net::new(2);
    net.define_article();
    let create = Operation::Create {
        record: rid(1),
        type_id: type_of(ARTICLE),
        revision: rev(ARTICLE),
        doc: json!({"title":"a","url":"https://example.test/1"}),
    };
    let (mutation, first) = net.order(SHARED, &dev(1), create.clone());
    assert!(matches!(first, Outcome::Accepted { .. }));
    // The same operation at a later position is evaluated again, and loses on its merits.
    match net.order_as(SHARED, &dev(1), mutation, &create) {
        Outcome::Rejected(rejection) => assert_eq!(rejection.code, RejectCode::Exists),
        other => panic!("expected Exists, got {other:?}"),
    }
    // A different operation reusing the id is applied like any other.
    let edit = edit_article(vec![set("/title", json!("b"))], rid(1));
    assert!(matches!(
        net.order_as(SHARED, &dev(2), mutation, &edit),
        Outcome::Accepted { .. }
    ));
    assert_eq!(net.accepted(SHARED, rid(1))["title"], json!("b"));
    // The field clock names the latest position, even though the id repeats.
    let clock: i64 = net.reps[0]
        .query_row(
            "SELECT c.position FROM data_field_clock c JOIN data_record r ON r.id=c.rec WHERE c.path='/title'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(clock, 5);
    net.assert_converged();
}

fn pending_state(conn: &Connection, mutation: MutationId) -> Option<String> {
    conn.query_row(
        "SELECT state FROM data_pending WHERE mutation=?1",
        [mutation.0.as_slice()],
        |r| r.get(0),
    )
    .ok()
}

#[test]
fn foreign_op_with_my_mutation_id_does_not_retire_my_pending() {
    let mut net = Net::new(2);
    net.define_article();
    create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    let saved = net.submit(
        0,
        SHARED,
        &dev(1),
        edit_article(vec![set("/title", json!("Local"))], rid(1)),
    );
    let (_, mine) = decode(&saved.payload);
    // Another operation with my mutation id is accepted on its merits; mine stays.
    assert!(matches!(
        net.order_as(
            SHARED,
            &dev(2),
            saved.mutation,
            &edit_article(vec![set("/state", json!("saved"))], rid(1)),
        ),
        Outcome::Accepted { .. }
    ));
    assert_eq!(
        pending_state(&net.reps[0], saved.mutation).as_deref(),
        Some("pending")
    );
    let row = net.row(0, SHARED, rid(1)).unwrap();
    assert!(row.pending);
    assert_eq!(row.view().unwrap()["title"], json!("Local"));
    // My exact operation from another actor is not mine either.
    assert!(matches!(
        net.order_as(SHARED, &dev(2), saved.mutation, &mine),
        Outcome::Accepted { .. }
    ));
    assert_eq!(
        pending_state(&net.reps[0], saved.mutation).as_deref(),
        Some("pending")
    );
    // Nor does someone else's rejection with my id mark my work rejected.
    assert!(matches!(
        net.order_as(
            SHARED,
            &dev(1),
            saved.mutation,
            &edit_article(vec![set("/nope", json!(1))], rid(1)),
        ),
        Outcome::Rejected(_)
    ));
    assert_eq!(
        pending_state(&net.reps[0], saved.mutation).as_deref(),
        Some("pending")
    );
    assert!(pending::rejected(&net.reps[0], SHARED).unwrap().is_empty());
    // My own operation, ordered, retires it.
    assert!(matches!(
        net.order_saved(SHARED, &dev(1), &saved),
        Outcome::Accepted { .. }
    ));
    assert_eq!(pending_state(&net.reps[0], saved.mutation), None);
    assert!(!net.row(0, SHARED, rid(1)).unwrap().pending);
    net.assert_converged();
}

#[test]
fn undo_of_missing_record_waits_on_that_record_only() {
    let mut net = Net::new(2);
    net.define_article();
    create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    let undo_missing = Operation::Undo {
        target: MutationId::random(),
        record: rid(9),
        changes: vec![set("/title", json!("x"))],
    };
    // With the whole scope here, the undone mutation was never applied.
    assert_eq!(
        net.rejected(SHARED, &dev(1), undo_missing.clone()),
        RejectCode::NotFound
    );
    incomplete(&mut net, SHARED);
    let (_, outcome) = net.order(SHARED, &dev(1), undo_missing);
    assert_eq!(outcome, Outcome::Waiting(Wait::Coverage(SHARED)));
    assert_eq!(
        parked(&net.reps[0]),
        vec![(5, format!("r:{}", hex(&rid(9).0)))]
    );
    // Other records are not held behind it.
    net.ok(
        SHARED,
        &dev(1),
        edit_article(vec![set("/title", json!("Still editable"))], rid(1)),
    );
    net.assert_converged();
}

#[test]
fn undo_reverses_own_fields() {
    let mut net = Net::new(2);
    net.define_article();
    create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    let edit = net.ok(
        SHARED,
        &dev(1),
        edit_article(
            vec![
                set("/title", json!("Changed")),
                set("/state", json!("saved")),
            ],
            rid(1),
        ),
    );
    let op = undo::prepare(&net.reps[0], SHARED, edit).unwrap();
    let (_, outcome) = net.order(SHARED, &dev(1), op);
    assert_eq!(
        outcome,
        Outcome::Accepted {
            record: Some(rid(1)),
            skipped: vec![]
        }
    );
    assert_eq!(
        net.accepted(SHARED, rid(1)),
        json!({"title":"Hello","url":"https://example.test/1"})
    );
}

#[test]
fn local_undo_reports_only_intervening_fields() {
    let mut net = Net::new(2);
    net.define_article();
    create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    let target = net.ok(
        SHARED,
        &dev(1),
        edit_article(
            vec![set("/title", json!("Draft")), set("/state", json!("saved"))],
            rid(1),
        ),
    );
    net.ok(
        SHARED,
        &dev(2),
        edit_article(vec![set("/state", json!("new"))], rid(1)),
    );
    let op = undo::prepare(&net.reps[0], SHARED, target).unwrap();
    let saved = net.submit(0, SHARED, &dev(1), op);
    assert_eq!(saved.skipped, vec![path("/state")]);
    assert_eq!(
        net.row(0, SHARED, rid(1)).unwrap().view().unwrap()["title"],
        "Hello"
    );
}

#[test]
fn undo_reports_intervening_edit() {
    let mut net = Net::new(2);
    net.define_article();
    create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    let a = net.ok(
        SHARED,
        &dev(1),
        edit_article(
            vec![
                set("/title", json!("A's title")),
                set("/state", json!("saved")),
            ],
            rid(1),
        ),
    );
    net.ok(
        SHARED,
        &dev(2),
        edit_article(vec![set("/title", json!("B's title"))], rid(1)),
    );
    let op = undo::prepare(&net.reps[0], SHARED, a).unwrap();
    let (_, outcome) = net.order(SHARED, &dev(1), op);
    assert_eq!(
        outcome,
        Outcome::Accepted {
            record: Some(rid(1)),
            skipped: vec![path("/title")]
        }
    );
    let doc = net.accepted(SHARED, rid(1));
    assert_eq!(doc["title"], json!("B's title"));
    assert!(doc.get("state").is_none());
    // Undoing again finds nothing still attributable to it.
    let op = undo::prepare(&net.reps[0], SHARED, a).unwrap();
    assert_eq!(net.rejected(SHARED, &dev(1), op), RejectCode::NothingToUndo);
}

#[test]
fn undo_applies_on_replica_without_history() {
    let mut net = Net::new(2);
    net.define_article();
    create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    let a = net.ok(
        SHARED,
        &dev(1),
        edit_article(
            vec![
                set("/title", json!("A's title")),
                set("/state", json!("saved")),
            ],
            rid(1),
        ),
    );
    net.ok(
        SHARED,
        &dev(2),
        edit_article(vec![set("/state", json!("new"))], rid(1)),
    );
    let op = undo::prepare(&net.reps[0], SHARED, a).unwrap();
    net.reps[1].execute("DELETE FROM data_history", []).unwrap();
    let (_, outcome) = net.order(SHARED, &dev(1), op);
    assert_eq!(
        outcome,
        Outcome::Accepted {
            record: Some(rid(1)),
            skipped: vec![path("/state")]
        }
    );
    assert_eq!(
        net.accepted(SHARED, rid(1)),
        json!({"title":"Hello","url":"https://example.test/1","state":"new"})
    );
}

#[test]
fn undo_of_create_and_delete() {
    let mut net = Net::new(2);
    net.define_article();
    let created = create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    net.ok(
        SHARED,
        &dev(1),
        edit_article(vec![set("/state", json!("saved"))], rid(1)),
    );
    let op = undo::prepare(&net.reps[0], SHARED, created).unwrap();
    assert_eq!(net.rejected(SHARED, &dev(1), op), RejectCode::NothingToUndo);
    assert_eq!(net.accepted(SHARED, rid(1))["state"], json!("saved"));
    // Deliberate removal is different from undoing the creation.
    let deleted = net.ok(SHARED, &dev(1), Operation::Delete { record: rid(1) });
    let row = net.row(0, SHARED, rid(1)).unwrap();
    assert!(row.deleted && row.accepted.is_none());
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            edit_article(vec![set("/title", json!("x"))], rid(1))
        ),
        RejectCode::Deleted
    );
    let op = undo::prepare(&net.reps[1], SHARED, deleted).unwrap();
    let Operation::Undo {
        target,
        record,
        changes,
    } = &op
    else {
        panic!("expected undo, got {op:?}")
    };
    assert_eq!(*target, deleted);
    assert_eq!(*record, rid(1));
    assert_eq!(changes.len(), 3);
    net.ok(SHARED, &dev(1), op);
    assert_eq!(
        net.accepted(SHARED, rid(1)),
        json!({"title":"Hello","url":"https://example.test/1","state":"saved"})
    );
    assert!(!net.row(1, SHARED, rid(1)).unwrap().deleted);
}

#[test]
fn adopt_shared_definition_into_private_scope() {
    let mut net = Net::new(2);
    net.define_article();
    net.ok(
        PRIVATE,
        &dev(1),
        Operation::Adopt {
            from_audience: SHARED.audience,
            revision: rev(ARTICLE),
            bytes: ARTICLE.to_vec(),
        },
    );
    net.ok(
        PRIVATE,
        &dev(1),
        Operation::DefineApp {
            app: APP,
            name: "Reader".into(),
        },
    );
    net.ok(
        PRIVATE,
        &dev(1),
        Operation::DefineType {
            bytes: SPECIAL.to_vec(),
        },
    );
    net.ok(
        PRIVATE,
        &dev(1),
        Operation::Create {
            record: rid(1),
            type_id: type_of(SPECIAL),
            revision: rev(SPECIAL),
            doc: json!({"title":"Private","url":"https://example.test/p","category":"x"}),
        },
    );
    // The source must first accept the exact subtype being adopted.
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineType {
            bytes: SPECIAL.to_vec(),
        },
    );
    // A dependency missing from an audience waits rather than being assumed.
    let (_, outcome) = net.order(
        Scope {
            base: [1; 32],
            audience: [8; 32],
        },
        &dev(1),
        Operation::Adopt {
            from_audience: SHARED.audience,
            revision: rev(SPECIAL),
            bytes: SPECIAL.to_vec(),
        },
    );
    assert_eq!(
        outcome,
        Outcome::Waiting(Wait::MissingDefinition(rev(ARTICLE)))
    );
    // A mismatched content address is refused.
    assert_eq!(
        net.rejected(
            PRIVATE,
            &dev(1),
            Operation::Adopt {
                from_audience: SHARED.audience,
                revision: rev(ARTICLE),
                bytes: ARTICLE_V2.to_vec(),
            }
        ),
        RejectCode::Schema
    );
    net.assert_converged();
}

#[test]
fn adopt_private_into_shared_rejected() {
    let mut net = Net::new(2);
    net.ok(
        PRIVATE,
        &dev(1),
        Operation::DefineApp {
            app: APP,
            name: "Reader".into(),
        },
    );
    net.ok(
        PRIVATE,
        &dev(1),
        Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        },
    );
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            Operation::Adopt {
                from_audience: PRIVATE.audience,
                revision: rev(ARTICLE),
                bytes: ARTICLE.to_vec(),
            }
        ),
        RejectCode::Unauthorized
    );
    assert_eq!(
        net.rejected(
            Scope {
                base: [1; 32],
                audience: [8; 32],
            },
            &dev(1),
            Operation::Adopt {
                from_audience: PRIVATE.audience,
                revision: rev(ARTICLE),
                bytes: ARTICLE.to_vec(),
            }
        ),
        RejectCode::Unauthorized,
        "one private audience's readers are not another's"
    );
}

#[test]
fn pending_overlay_visible_then_retired_on_accept() {
    let mut net = Net::new(2);
    net.define_article();
    create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    let saved = net.submit(
        0,
        SHARED,
        &dev(1),
        edit_article(vec![set("/title", json!("Local"))], rid(1)),
    );
    let row = net.row(0, SHARED, rid(1)).unwrap();
    assert!(row.pending);
    assert_eq!(row.view().unwrap()["title"], json!("Local"));
    assert_eq!(row.accepted.as_ref().unwrap()["title"], json!("Hello"));
    // Another device's ordered edit to a different field shows under the overlay.
    net.ok(
        SHARED,
        &dev(2),
        edit_article(vec![set("/state", json!("saved"))], rid(1)),
    );
    let row = net.row(0, SHARED, rid(1)).unwrap();
    assert_eq!(
        row.view().unwrap(),
        &json!({"title":"Local","url":"https://example.test/1","state":"saved"})
    );
    assert!(matches!(
        net.order_saved(SHARED, &dev(1), &saved),
        Outcome::Accepted { .. }
    ));
    let row = net.row(0, SHARED, rid(1)).unwrap();
    assert!(!row.pending && row.doc.is_none());
    assert_eq!(row.accepted.unwrap()["title"], json!("Local"));
    let left: i64 = net.reps[0]
        .query_row("SELECT count(*) FROM data_pending", [], |r| r.get(0))
        .unwrap();
    assert_eq!(left, 0);
    // A locally created record is visible before ordering.
    let created = net.submit(
        0,
        SHARED,
        &dev(1),
        Operation::Create {
            record: rid(2),
            type_id: type_of(ARTICLE),
            revision: rev(ARTICLE),
            doc: json!({"title":"Draft","url":"https://example.test/2"}),
        },
    );
    let row = net.row(0, SHARED, rid(2)).unwrap();
    assert!(row.pending && row.accepted.is_none() && !row.deleted);
    assert!(matches!(
        net.order_saved(SHARED, &dev(1), &created),
        Outcome::Accepted { .. }
    ));
    assert_eq!(
        net.accepted(SHARED, rid(2)),
        json!({"title":"Draft","url":"https://example.test/2"})
    );
}

#[test]
fn rejected_local_work_recoverable() {
    let mut net = Net::new(2);
    net.define_article();
    let mine = net.submit(
        1,
        SHARED,
        &dev(2),
        Operation::Create {
            record: rid(2),
            type_id: type_of(ARTICLE),
            revision: rev(ARTICLE),
            doc: json!({"title":"Mine","url":"https://example.test/same"}),
        },
    );
    // Locally the key is taken by this pending record.
    let local = {
        let conn = &mut net.reps[1];
        let tx = conn.transaction().unwrap();
        let result = pending::submit(
            &tx,
            &Shipped,
            SHARED,
            &dev(2),
            Operation::Create {
                record: rid(3),
                type_id: type_of(ARTICLE),
                revision: rev(ARTICLE),
                doc: json!({"title":"Also mine","url":"https://example.test/same"}),
            },
        );
        drop(tx);
        result
    };
    match local {
        Err(pending::SubmitError::Rejected(rejection)) => {
            assert_eq!(rejection.code, RejectCode::Unique)
        }
        other => panic!("expected a local uniqueness rejection, got {other:?}"),
    }
    create_article(&mut net, rid(1), "Theirs", "https://example.test/same");
    let Outcome::Rejected(rejection) = net.order_saved(SHARED, &dev(2), &mine) else {
        panic!("expected rejection")
    };
    assert_eq!(rejection.code, RejectCode::Unique);
    let rejected = pending::rejected(&net.reps[1], SHARED).unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].mutation, mine.mutation);
    assert_eq!(rejected[0].record, Some(rid(2)));
    assert_eq!(rejected[0].rejection, rejection);
    assert!(
        rejected[0]
            .attempted
            .contains(&set("/url", json!("https://example.test/same")))
    );
    assert!(net.row(0, SHARED, rid(2)).is_none());
    let row = net.row(1, SHARED, rid(2)).unwrap();
    assert!(row.deleted && !row.pending && row.accepted.is_none());
    assert_eq!(net.accepted(SHARED, rid(1))["title"], json!("Theirs"));
    let conn = &mut net.reps[1];
    let tx = conn.transaction().unwrap();
    pending::discard(&tx, &Shipped, mine.mutation).unwrap();
    tx.commit().unwrap();
    assert!(pending::rejected(&net.reps[1], SHARED).unwrap().is_empty());
}

#[test]
fn history_attributes_each_field() {
    let mut net = Net::new(2);
    net.define_article();
    let created = create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    let first = net.ok(
        SHARED,
        &dev(2),
        edit_article(
            vec![set("/title", json!("Two")), set("/state", json!("saved"))],
            rid(1),
        ),
    );
    let second = net.ok(SHARED, &dev(3), edit_article(vec![unset("/state")], rid(1)));
    let entries = history::of(&net.reps[1], SHARED, rid(1), 10, None).unwrap();
    let shape: Vec<_> = entries
        .iter()
        .map(|e| {
            (
                e.position.0,
                e.mutation,
                e.actor.clone(),
                e.path.as_ref().map(FieldPath::as_pointer),
                e.old.clone(),
                e.new.clone(),
            )
        })
        .collect();
    assert_eq!(
        shape,
        vec![
            (
                5,
                second,
                dev(3),
                Some("/state".into()),
                Some(json!("saved")),
                None
            ),
            (
                4,
                first,
                dev(2),
                Some("/state".into()),
                None,
                Some(json!("saved"))
            ),
            (
                4,
                first,
                dev(2),
                Some("/title".into()),
                Some(json!("Hello")),
                Some(json!("Two"))
            ),
            (3, created, dev(1), None, None, Some(json!(true))),
            (
                3,
                created,
                dev(1),
                Some("/title".into()),
                None,
                Some(json!("Hello"))
            ),
            (
                3,
                created,
                dev(1),
                Some("/url".into()),
                None,
                Some(json!("https://example.test/1"))
            ),
        ]
    );
    let older = history::of(&net.reps[1], SHARED, rid(1), 1, Some(entries[2].cursor())).unwrap();
    assert_eq!(older.len(), 1);
    assert_eq!(older[0].position, Position(3));
}

#[test]
fn crash_between_pending_and_order_keeps_work() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("replica.sqlite");
    let mut net = Net::new(1);
    net.reps[0] = Connection::open(&file).unwrap();
    {
        let conn = &mut net.reps[0];
        let tx = conn.transaction().unwrap();
        store::migrate(&tx).unwrap();
        let sid = records::scope_id(&tx, SHARED, &Shipped).unwrap();
        coverage::set(&tx, sid, Position(0), true).unwrap();
        tx.commit().unwrap();
    }
    net.define_article();
    create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    let saved = net.submit(
        0,
        SHARED,
        &dev(1),
        edit_article(vec![set("/title", json!("Saved locally"))], rid(1)),
    );
    {
        // Later work that never commits.
        let conn = &mut net.reps[0];
        let tx = conn.transaction().unwrap();
        pending::submit(
            &tx,
            &Shipped,
            SHARED,
            &dev(1),
            edit_article(vec![set("/state", json!("saved"))], rid(1)),
        )
        .unwrap();
    }
    net.reps[0] = Connection::open(&file).unwrap();
    let row = net.row(0, SHARED, rid(1)).unwrap();
    assert_eq!(row.view().unwrap()["title"], json!("Saved locally"));
    assert!(row.view().unwrap().get("state").is_none());
    let payloads: Vec<Vec<u8>> = net.reps[0]
        .prepare("SELECT payload FROM data_pending WHERE state='pending'")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(payloads, vec![saved.payload.clone()]);
    assert!(matches!(
        net.order_saved(SHARED, &dev(1), &saved),
        Outcome::Accepted { .. }
    ));
    assert_eq!(
        net.accepted(SHARED, rid(1))["title"],
        json!("Saved locally")
    );
}

#[test]
fn op_grammar_is_closed() {
    let mutation = MutationId([5; 16]);
    let op = Operation::Edit {
        record: rid(1),
        revision: rev(ARTICLE),
        changes: vec![set("/title", Value::Null), unset("/state")],
    };
    let bytes = payload::encode(mutation, &op).unwrap();
    assert_eq!(decode(&bytes), (mutation, op.clone()));
    let mut value = serde_json::to_value(&op).unwrap();
    value["surprise"] = json!(1);
    assert!(serde_json::from_value::<Operation>(value).is_err());
    let mut value = serde_json::to_value(&op).unwrap();
    value["changes"][0]["extra"] = json!(1);
    assert!(serde_json::from_value::<Operation>(value).is_err());
}

#[test]
fn local_work_behind_a_parked_queue_is_marked_waiting() {
    let mut net = Net::new(1);
    net.define_memo();
    create_memo(&mut net, rid(1), json!({"text":"a"}));
    incomplete(&mut net, SHARED);
    let (_, outcome) = net.order(
        SHARED,
        &dev(2),
        edit_memo(rid(2), vec![set("/text", json!("b"))]),
    );
    assert_eq!(outcome, Outcome::Waiting(Wait::MissingRecord(rid(2))));
    let behind = net.submit(
        0,
        SHARED,
        &dev(1),
        Operation::Create {
            record: rid(2),
            type_id: type_of(&memo()),
            revision: rev(&memo()),
            doc: json!({"text":"local"}),
        },
    );
    let clear = net.submit(
        0,
        SHARED,
        &dev(1),
        edit_memo(rid(1), vec![set("/text", json!("c"))]),
    );
    let state = |m: MutationId| -> String {
        net.reps[0]
            .query_row(
                "SELECT state FROM data_pending WHERE mutation=?1",
                [m.0.as_slice()],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(state(behind.mutation), "waiting");
    assert_eq!(state(clear.mutation), "pending");
    assert_eq!(
        net.row(0, SHARED, rid(2)).unwrap().view().unwrap(),
        &json!({"text":"local"})
    );
}

#[test]
fn validator_cache_is_bounded_and_reuses_entries() {
    use bh_data::{compose, definition, validate_cache::ValidatorCache};
    let compile = |bytes: &[u8]| {
        compose::compile(&definition::parse(bytes).unwrap(), rev(bytes), &|_, _| None).unwrap()
    };
    let (article, v2) = (compile(ARTICLE), compile(ARTICLE_V2));
    let cache = ValidatorCache::new(1);
    let first = cache.get(&article).unwrap();
    assert!(std::sync::Arc::ptr_eq(
        &first,
        &cache.get(&article).unwrap()
    ));
    cache.get(&v2).unwrap();
    assert_eq!(cache.len(), 1);
    assert!(!std::sync::Arc::ptr_eq(
        &first,
        &cache.get(&article).unwrap()
    ));
    assert!(
        cache
            .get(&article)
            .unwrap()
            .validate(&json!({"title":"t","url":"u"}))
            .is_ok()
    );
}

/// Article records with a shared URL defined before the source became unique,
/// then the unique revision: every replica's new unique index is building.
fn define_unique_over_duplicates(net: &mut Net) {
    let mut loose: Value = serde_json::from_slice(ARTICLE).unwrap();
    loose["unique"] = json!([]);
    loose["description"] = json!("Articles before the source became unique");
    let loose = serde_json::to_vec(&loose).unwrap();
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineApp {
            app: APP,
            name: "Reader".into(),
        },
    );
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineType {
            bytes: loose.clone(),
        },
    );
    for n in [1, 2] {
        net.ok(
            SHARED,
            &dev(1),
            Operation::Create {
                record: rid(n),
                type_id: type_of(ARTICLE),
                revision: rev(&loose),
                doc: json!({"title":"Copy","url":"https://example.test/same"}),
            },
        );
    }
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        },
    );
}

fn create_fresh(record: RecordId) -> Operation {
    Operation::Create {
        record,
        type_id: type_of(ARTICLE),
        revision: rev(ARTICLE),
        doc: json!({"title":"Fresh","url":"https://example.test/fresh"}),
    }
}

#[test]
fn create_parked_for_uniqueness_queues_later_ops_on_its_record() {
    let mut net = Net::new(2);
    define_unique_over_duplicates(&mut net);
    let (created, outcome) = net.order(SHARED, &dev(1), create_fresh(rid(3)));
    assert_eq!(outcome, Outcome::Waiting(Wait::UniquenessUnknown(SHARED)));
    for op in [
        edit_article(vec![set("/title", json!("Edited"))], rid(3)),
        Operation::Delete { record: rid(3) },
        Operation::Undo {
            target: created,
            record: rid(3),
            changes: vec![unset("/title")],
        },
    ] {
        assert_eq!(
            net.order(SHARED, &dev(2), op).1,
            Outcome::Waiting(Wait::Queued)
        );
    }
    let rows: Vec<Option<Vec<u8>>> = net.reps[0]
        .prepare("SELECT record FROM data_parked ORDER BY position")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(rows, vec![Some(rid(3).0.to_vec()); 4]);
    net.assert_converged();
}

#[test]
fn create_parked_on_missing_definition_queues_later_ops_on_its_record() {
    let mut net = Net::new(2);
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineApp {
            app: APP,
            name: "Memos".into(),
        },
    );
    // Without coverage the definition may simply not have arrived yet.
    incomplete(&mut net, SHARED);
    let (_, outcome) = net.order(
        SHARED,
        &dev(1),
        Operation::Create {
            record: rid(1),
            type_id: type_of(&memo()),
            revision: rev(&memo()),
            doc: json!({"text":"a"}),
        },
    );
    assert_eq!(
        outcome,
        Outcome::Waiting(Wait::MissingDefinition(rev(&memo())))
    );
    for op in [
        edit_memo(rid(1), vec![set("/text", json!("b"))]),
        Operation::Delete { record: rid(1) },
    ] {
        assert_eq!(
            net.order(SHARED, &dev(2), op).1,
            Outcome::Waiting(Wait::Queued)
        );
    }
    net.assert_converged();
}

#[test]
fn parked_record_op_blocks_unique_key_edits_in_its_family_only() {
    let mut net = Net::new(2);
    net.define_article();
    create_article(&mut net, rid(1), "One", "https://example.test/1");
    create_article(&mut net, rid(2), "Two", "https://example.test/2");
    create_article(&mut net, rid(3), "Three", "https://example.test/3");
    // Without coverage, a writer revision not seen here parks under r:<2>.
    incomplete(&mut net, SHARED);
    let unknown = RevisionId([9; 32]);
    let (_, outcome) = net.order(
        SHARED,
        &dev(1),
        Operation::Edit {
            record: rid(2),
            revision: unknown,
            changes: vec![set("/url", json!("https://example.test/x"))],
        },
    );
    assert_eq!(outcome, Outcome::Waiting(Wait::MissingDefinition(unknown)));
    // Its URL would change the answer for the same key on another record.
    assert_eq!(
        net.order(
            SHARED,
            &dev(2),
            edit_article(vec![set("/url", json!("https://example.test/x"))], rid(1)),
        )
        .1,
        Outcome::Waiting(Wait::Queued)
    );
    // Fields outside any unique key on a third record are independent.
    net.ok(
        SHARED,
        &dev(2),
        edit_article(vec![set("/title", json!("Independent"))], rid(3)),
    );
    net.assert_converged();
}

fn backfill(conn: &mut Connection) {
    let tx = conn.transaction().unwrap();
    for ix in index::pending_work(&tx).unwrap() {
        while !index::backfill_step(&tx, ix, 500).unwrap().ready {}
    }
    tx.commit().unwrap();
}

/// The production scoped replay, including the persisted actor.
fn replay(conn: &mut Connection) -> Vec<(u64, Outcome)> {
    let tx = conn.transaction().unwrap();
    let mut outcomes = Vec::new();
    for scope in [SHARED, PRIVATE] {
        outcomes.extend(
            bh_data::testkit::retry_parked(&tx, &Shipped, scope)
                .unwrap()
                .into_iter()
                .map(|(position, outcome)| (position.0, outcome)),
        );
    }
    tx.commit().unwrap();
    outcomes
}

#[test]
fn building_and_ready_replicas_converge_after_replay() {
    let mut net = Net::new(2);
    define_unique_over_duplicates(&mut net);
    // Replica 1 finishes its backfill now; replica 0 is still building.
    backfill(&mut net.reps[1]);
    let ops = [
        (MutationId::random(), create_fresh(rid(3))),
        (
            MutationId::random(),
            edit_article(vec![set("/title", json!("Edited"))], rid(3)),
        ),
        (
            MutationId::random(),
            edit_article(vec![set("/state", json!("saved"))], rid(1)),
        ),
    ];
    let mut outcomes = Vec::new();
    for (i, (mutation, op)) in ops.iter().enumerate() {
        let position = Position(net.next + i as u64);
        let mut each = Vec::new();
        for conn in &mut net.reps {
            each.push(apply(conn, SHARED, position, &dev(1), *mutation, op));
        }
        outcomes.push(each);
    }
    assert_eq!(
        outcomes[0],
        vec![
            Outcome::Waiting(Wait::UniquenessUnknown(SHARED)),
            Outcome::Accepted {
                record: Some(rid(3)),
                skipped: vec![]
            }
        ]
    );
    assert_eq!(outcomes[1][0], Outcome::Waiting(Wait::Queued));
    assert!(matches!(outcomes[1][1], Outcome::Accepted { .. }));
    backfill(&mut net.reps[0]);
    replay(&mut net.reps[0]);
    let left: i64 = net.reps[0]
        .query_row("SELECT count(*) FROM data_parked", [], |r| r.get(0))
        .unwrap();
    assert_eq!(left, 0);
    assert_eq!(
        net.accepted(SHARED, rid(3)),
        json!({"title":"Edited","url":"https://example.test/fresh"})
    );
    assert_eq!(net.accepted(SHARED, rid(1))["state"], json!("saved"));
}

#[test]
fn undo_prepare_undoes_only_the_first_application_of_an_id() {
    let mut net = Net::new(2);
    net.define_article();
    create_article(&mut net, rid(1), "One", "https://example.test/1");
    create_article(&mut net, rid(2), "Two", "https://example.test/2");
    let reused = net.ok(
        SHARED,
        &dev(1),
        edit_article(vec![set("/title", json!("Changed"))], rid(1)),
    );
    assert!(matches!(
        net.order_as(
            SHARED,
            &dev(2),
            reused,
            &edit_article(vec![set("/state", json!("saved"))], rid(2)),
        ),
        Outcome::Accepted { .. }
    ));
    assert_eq!(
        undo::prepare(&net.reps[0], SHARED, reused).unwrap(),
        Operation::Undo {
            target: reused,
            record: rid(1),
            changes: vec![set("/title", json!("One"))],
        }
    );
}

#[test]
fn definition_change_refreshes_pending_overlays() {
    let mut net = Net::new(2);
    net.define_article();
    create_article(&mut net, rid(1), "Hello", "https://example.test/1");
    let saved = net.submit(
        0,
        SHARED,
        &dev(1),
        edit_article(vec![set("/state", json!("saved"))], rid(1)),
    );
    assert_eq!(
        net.row(0, SHARED, rid(1)).unwrap().view().unwrap()["state"],
        json!("saved")
    );
    // A person's device makes the state an action-only field.
    let mut v2: Value = serde_json::from_slice(ARTICLE).unwrap();
    v2["fields"]["/state"]["write"] = json!("action");
    net.ok(
        SHARED,
        &dev(2),
        Operation::DefineType {
            bytes: serde_json::to_vec(&v2).unwrap(),
        },
    );
    let row = net.row(0, SHARED, rid(1)).unwrap();
    assert!(row.pending, "the work stays until its ordered outcome");
    assert!(row.view().unwrap().get("state").is_none(), "{row:?}");
    let Outcome::Rejected(rejection) = net.order_saved(SHARED, &dev(1), &saved) else {
        panic!("expected rejection")
    };
    assert_eq!(rejection.code, RejectCode::ActionOnly);
    assert_eq!(pending::rejected(&net.reps[0], SHARED).unwrap().len(), 1);
}

#[test]
fn rejected_create_reports_declared_leaves() {
    let mut net = Net::new(2);
    net.define_memo();
    let mine = net.submit(
        1,
        SHARED,
        &dev(2),
        Operation::Create {
            record: rid(1),
            type_id: type_of(&memo()),
            revision: rev(&memo()),
            doc: json!({"text":"mine","meta":{"color":"red"},"location":{"city":"X"}}),
        },
    );
    create_memo(&mut net, rid(1), json!({"text":"theirs"}));
    let Outcome::Rejected(rejection) = net.order_saved(SHARED, &dev(2), &mine) else {
        panic!("expected rejection")
    };
    assert_eq!(rejection.code, RejectCode::Exists);
    let mut attempted = pending::rejected(&net.reps[1], SHARED).unwrap()[0]
        .attempted
        .clone();
    attempted.sort_by(|a, b| a.path.cmp(&b.path));
    assert_eq!(
        attempted,
        vec![
            set("/location", json!({"city":"X"})),
            set("/meta/color", json!("red")),
            set("/text", json!("mine")),
        ]
    );
}

/// Orders each operation in turn on every replica, which may disagree while
/// their coverage or index state differs. Returns per-operation outcomes, one
/// per replica.
fn order_each(net: &mut Net, scope: Scope, actor: &Actor, ops: &[Operation]) -> Vec<Vec<Outcome>> {
    let mut all = Vec::new();
    for op in ops {
        let position = Position(net.next);
        net.next += 1;
        let mutation = MutationId::random();
        all.push(
            net.reps
                .iter_mut()
                .map(|conn| apply(conn, scope, position, actor, mutation, op))
                .collect(),
        );
    }
    all
}

fn cover(conn: &mut Connection, scope: Scope, complete: bool) {
    let tx = conn.transaction().unwrap();
    let sid = records::scope_id(&tx, scope, &Shipped).unwrap();
    coverage::set(&tx, sid, Position(0), complete).unwrap();
    tx.commit().unwrap();
}

fn create_memo_op(record: RecordId, text: &str) -> Operation {
    Operation::Create {
        record,
        type_id: type_of(&memo()),
        revision: rev(&memo()),
        doc: json!({ "text": text }),
    }
}

fn define_memo_app(net: &mut Net) {
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineApp {
            app: APP,
            name: "Memos".into(),
        },
    );
}

#[test]
fn create_before_define_rejected_with_complete_coverage() {
    let mut net = Net::new(2);
    define_memo_app(&mut net);
    let Outcome::Rejected(rejection) = net
        .order(SHARED, &dev(1), create_memo_op(rid(1), "early"))
        .1
    else {
        panic!("expected rejection")
    };
    assert_eq!(rejection.code, RejectCode::NotFound);
    assert!(
        rejection.detail.contains(&hex(&rev(&memo()).0)),
        "{rejection:?}"
    );
    assert!(
        rejection.detail.contains(&hex(&type_of(&memo()).0)),
        "{rejection:?}"
    );
    // Nothing parked, so the definition is not stuck behind the create.
    assert!(parked(&net.reps[0]).is_empty());
    net.ok(SHARED, &dev(1), Operation::DefineType { bytes: memo() });
    create_memo(&mut net, rid(2), json!({"text":"later"}));
    // An app revision never defined in this audience is refused too.
    let unknown = RevisionId([9; 32]);
    let Outcome::Rejected(rejection) = net
        .order(
            SHARED,
            &dev(1),
            Operation::Edit {
                record: rid(2),
                revision: unknown,
                changes: vec![set("/text", json!("x"))],
            },
        )
        .1
    else {
        panic!("expected rejection")
    };
    assert_eq!(rejection.code, RejectCode::NotFound);
    assert!(rejection.detail.contains(&hex(&unknown.0)), "{rejection:?}");
    net.assert_converged();
}

#[test]
fn create_before_define_parks_with_incomplete_coverage_and_replays_to_same_verdict() {
    let mut net = Net::new(2);
    define_memo_app(&mut net);
    // Replica 0 holds the whole scope; replica 1 holds only part of it.
    cover(&mut net.reps[1], SHARED, false);
    let ops = [
        create_memo_op(rid(1), "early"),
        Operation::DefineType { bytes: memo() },
        create_memo_op(rid(2), "later"),
        edit_memo(rid(1), vec![set("/text", json!("edited"))]),
    ];
    let first = net.next;
    let outcomes = order_each(&mut net, SHARED, &dev(1), &ops);
    let full: Vec<Outcome> = outcomes.iter().map(|each| each[0].clone()).collect();
    let partial: Vec<Outcome> = outcomes.iter().map(|each| each[1].clone()).collect();
    assert!(matches!(&full[0], Outcome::Rejected(r) if r.code == RejectCode::NotFound));
    assert!(matches!(full[1], Outcome::Accepted { .. }));
    assert!(matches!(full[2], Outcome::Accepted { .. }));
    assert!(matches!(&full[3], Outcome::Rejected(r) if r.code == RejectCode::NotFound));
    assert_eq!(
        partial,
        vec![
            Outcome::Waiting(Wait::MissingDefinition(rev(&memo()))),
            Outcome::Waiting(Wait::Queued),
            Outcome::Waiting(Wait::Queued),
            Outcome::Waiting(Wait::Queued),
        ]
    );
    // Coverage completes; replaying reaches exactly the full replica's verdicts.
    cover(&mut net.reps[1], SHARED, true);
    let replayed = replay(&mut net.reps[1]);
    let expected: Vec<(u64, Outcome)> = (first..).zip(full).collect();
    assert_eq!(replayed, expected);
    assert!(parked(&net.reps[1]).is_empty());
    net.assert_converged();
    assert!(net.row(1, SHARED, rid(1)).is_none());
    assert_eq!(net.accepted(SHARED, rid(2)), json!({"text":"later"}));
}

#[test]
fn define_type_waits_behind_record_missing_app_definition_until_coverage() {
    let mut net = Net::new(2);
    define_memo_app(&mut net);
    // Replica 0 holds the whole scope; replica 1 holds only part of it.
    cover(&mut net.reps[1], SHARED, false);
    let ops = [
        create_memo_op(rid(1), "early"),
        edit_memo(rid(1), vec![set("/text", json!("edited"))]),
        Operation::DefineType { bytes: memo() },
        create_memo_op(rid(2), "later"),
    ];
    let first = net.next;
    let outcomes = order_each(&mut net, SHARED, &dev(1), &ops);
    let full: Vec<Outcome> = outcomes.iter().map(|each| each[0].clone()).collect();
    let partial: Vec<Outcome> = outcomes.iter().map(|each| each[1].clone()).collect();
    assert!(matches!(&full[0], Outcome::Rejected(r) if r.code == RejectCode::NotFound));
    assert!(matches!(&full[1], Outcome::Rejected(r) if r.code == RejectCode::NotFound));
    assert!(matches!(full[2], Outcome::Accepted { .. }));
    // Backfill may still deliver the app's definition the create waits for,
    // so the edit queued behind it holds the definition too.
    assert_eq!(
        partial,
        vec![
            Outcome::Waiting(Wait::MissingDefinition(rev(&memo()))),
            Outcome::Waiting(Wait::Queued),
            Outcome::Waiting(Wait::Queued),
            Outcome::Waiting(Wait::Queued),
        ]
    );
    // Coverage completing ends the wait: the definition then applies in order.
    cover(&mut net.reps[1], SHARED, true);
    let replayed = replay(&mut net.reps[1]);
    let expected: Vec<(u64, Outcome)> = (first..).zip(full).collect();
    assert_eq!(replayed, expected);
    assert!(parked(&net.reps[1]).is_empty());
    net.assert_converged();
    assert_eq!(net.accepted(SHARED, rid(2)), json!({"text":"later"}));
}

#[test]
fn define_type_blocked_by_record_waiting_on_uniqueness() {
    let mut net = Net::new(2);
    net.define_article();
    net.ok(SHARED, &dev(1), Operation::DefineType { bytes: memo() });
    incomplete(&mut net, SHARED);
    assert_eq!(
        net.order(SHARED, &dev(1), create_fresh(rid(2))).1,
        Outcome::Waiting(Wait::UniquenessUnknown(SHARED))
    );
    // A new revision of that type may retire the unique index the create's
    // replay needs: it queues.
    assert_eq!(
        net.order(
            SHARED,
            &job(2, None),
            Operation::DefineType {
                bytes: ARTICLE_V2.to_vec(),
            },
        )
        .1,
        Outcome::Waiting(Wait::Queued)
    );
    // An existing unrelated type can still change without proving absence.
    let mut docs = memo_json();
    docs["description"] = json!("Updated description");
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineType {
            bytes: serde_json::to_vec(&docs).unwrap(),
        },
    );
    // ... until a record of a type not known here waits for coverage: on
    // replay it may belong to any family.
    assert_eq!(
        net.order(
            SHARED,
            &dev(1),
            edit_article(vec![set("/title", json!("x"))], rid(1))
        )
        .1,
        Outcome::Waiting(Wait::MissingRecord(rid(1)))
    );
    let mut later: Value = memo_json();
    later["description"] = json!("Memos, described again");
    assert_eq!(
        net.order(
            SHARED,
            &dev(1),
            Operation::DefineType {
                bytes: serde_json::to_vec(&later).unwrap(),
            },
        )
        .1,
        Outcome::Waiting(Wait::Queued)
    );
    // The app whose active state the create reads is held too.
    assert_eq!(
        net.order(
            SHARED,
            &dev(1),
            Operation::DefineApp {
                app: APP,
                name: "Again".into(),
            },
        )
        .1,
        Outcome::Waiting(Wait::Queued)
    );
    net.assert_converged();
    for i in 0..2 {
        cover(&mut net.reps[i], SHARED, true);
        backfill(&mut net.reps[i]);
        let replayed: Vec<Outcome> = replay(&mut net.reps[i])
            .into_iter()
            .map(|(_, outcome)| outcome)
            .collect();
        assert!(
            matches!(replayed[0], Outcome::Accepted { .. }),
            "{replayed:?}"
        );
        assert!(
            matches!(replayed[1], Outcome::Accepted { .. }),
            "{replayed:?}"
        );
        assert!(matches!(&replayed[2], Outcome::Rejected(r) if r.code == RejectCode::NotFound));
        assert!(
            matches!(replayed[3], Outcome::Accepted { .. }),
            "{replayed:?}"
        );
        assert!(matches!(&replayed[4], Outcome::Rejected(r) if r.code == RejectCode::Exists));
        assert!(parked(&net.reps[i]).is_empty());
    }
    net.assert_converged();
}

#[test]
fn unique_removed_while_create_waits_on_uniqueness_converges() {
    let mut net = Net::new(2);
    define_unique_over_duplicates(&mut net);
    // Replica 1 finishes its backfill now; replica 0 is still building.
    backfill(&mut net.reps[1]);
    let mut loose: Value = serde_json::from_slice(ARTICLE).unwrap();
    loose["unique"] = json!([]);
    let ops = [
        create_fresh(rid(3)),
        Operation::DefineType {
            bytes: serde_json::to_vec(&loose).unwrap(),
        },
    ];
    let first = net.next;
    let outcomes = order_each(&mut net, SHARED, &dev(2), &ops);
    for each in &outcomes {
        assert!(matches!(each[1], Outcome::Accepted { .. }), "{each:?}");
    }
    // Removing the unique would retire the index the create still needs.
    assert_eq!(
        outcomes[0][0],
        Outcome::Waiting(Wait::UniquenessUnknown(SHARED))
    );
    assert_eq!(outcomes[1][0], Outcome::Waiting(Wait::Queued));
    backfill(&mut net.reps[0]);
    let replayed = replay(&mut net.reps[0]);
    assert_eq!(
        replayed,
        vec![
            (first, outcomes[0][1].clone()),
            (first + 1, outcomes[1][1].clone()),
        ]
    );
    assert!(parked(&net.reps[0]).is_empty());
    assert_eq!(
        net.accepted(SHARED, rid(3)),
        json!({"title":"Fresh","url":"https://example.test/fresh"})
    );
}

/// Memo extending the core Note at a revision this executable does not ship.
fn newer_note_extension(description: &str) -> Vec<u8> {
    let (note, _) = bh_data::catalogue::baseline_note();
    let mut ty = memo_json();
    ty["local"] = json!("0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d");
    ty["name"] = json!("NoteMemo");
    ty["description"] = json!(description);
    ty["extends"] = json!({"type": hex(&note.0), "revision": hex(&[9; 32])});
    serde_json::to_vec(&ty).unwrap()
}

#[test]
fn unknown_core_revision_parks_even_with_coverage() {
    let mut net = Net::new(2);
    define_memo_app(&mut net);
    let bytes = newer_note_extension("A memo on a newer note");
    // Coverage is complete, yet a newer executable may ship this revision.
    assert_eq!(
        net.order(
            SHARED,
            &dev(1),
            Operation::DefineType {
                bytes: bytes.clone()
            }
        )
        .1,
        Outcome::Waiting(Wait::MissingDefinition(RevisionId([9; 32])))
    );
    let extension = type_of(&bytes);
    assert_eq!(
        parked(&net.reps[0]),
        vec![(net.next as i64 - 1, format!("t:{}", hex(&extension.0)))]
    );
    // Later definitions and records of that type queue behind it ...
    assert_eq!(
        net.order(
            SHARED,
            &dev(1),
            Operation::DefineType {
                bytes: newer_note_extension("A second revision")
            }
        )
        .1,
        Outcome::Waiting(Wait::Queued)
    );
    assert_eq!(
        net.order(
            SHARED,
            &dev(1),
            Operation::Create {
                record: rid(1),
                type_id: extension,
                revision: rev(&bytes),
                doc: json!({"text":"x"}),
            }
        )
        .1,
        Outcome::Waiting(Wait::Queued)
    );
    // ... while unrelated definitions proceed.
    net.ok(SHARED, &dev(1), Operation::DefineType { bytes: memo() });
    net.assert_converged();
}

#[test]
fn record_waiting_for_unknown_core_revision_does_not_hold_definitions() {
    const JOURNAL: &[u8] = include_bytes!("fixtures/types/JournalEntry.json");
    let mut net = Net::new(2);
    define_memo_app(&mut net);
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineType {
            bytes: JOURNAL.to_vec(),
        },
    );
    // Notes come from the note writer, not generic creation: store one as it would.
    for conn in &mut net.reps {
        let tx = conn.transaction().unwrap();
        let sid = records::scope_id(&tx, SHARED, &Shipped).unwrap();
        let doc = json!({"title": "Day one", "date": 1});
        records::put(
            &tx,
            &mut RecordRow {
                id: 0,
                scope: sid,
                record: rid(1),
                type_id: type_of(JOURNAL),
                revision: rev(JOURNAL),
                accepted: Some(doc),
                doc: None,
                deleted: false,
                pending: false,
                changed_at: Some(Position(1)),
                changed: 0,
                text_rev: 0,
            },
        )
        .unwrap();
        tx.commit().unwrap();
    }
    // An edit by a revision unknown here, of a lineage that includes the core
    // Note, waits even with coverage: a newer executable may ship it.
    assert_eq!(
        net.order(
            SHARED,
            &dev(1),
            Operation::Edit {
                record: rid(1),
                revision: RevisionId([9; 32]),
                changes: vec![set("/mood", json!("calm"))],
            },
        )
        .1,
        Outcome::Waiting(Wait::MissingDefinition(RevisionId([9; 32])))
    );
    assert_eq!(
        net.order(
            SHARED,
            &dev(1),
            Operation::Edit {
                record: rid(1),
                revision: rev(JOURNAL),
                changes: vec![set("/mood", json!("tired"))],
            },
        )
        .1,
        Outcome::Waiting(Wait::Queued)
    );
    // A type extending the waiting records' type is still decided at once.
    let mut sub: Value = serde_json::from_slice(JOURNAL).unwrap();
    sub["local"] = json!("0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e");
    sub["name"] = json!("TravelEntry");
    sub["extends"] = json!({"type": hex(&type_of(JOURNAL).0), "revision": hex(&rev(JOURNAL).0)});
    sub["fields"] = json!({});
    sub["schema"] = json!({"type":"object","properties":{},"required":[]});
    sub["indexes"] = json!([]);
    net.ok(
        SHARED,
        &dev(1),
        Operation::DefineType {
            bytes: serde_json::to_vec(&sub).unwrap(),
        },
    );
    net.assert_converged();
}

#[test]
fn rule_change_waits_for_an_earlier_uniqueness_wait() {
    let mut net = Net::new(2);
    define_unique_over_duplicates(&mut net);
    // Replica 1 finishes its backfill now; replica 0 is still building.
    backfill(&mut net.reps[1]);
    let mut v2: Value = serde_json::from_slice(ARTICLE).unwrap();
    v2["fields"]["/state"]["write"] = json!("action");
    let ops = [
        create_fresh(rid(3)),
        edit_article(vec![set("/state", json!("saved"))], rid(3)),
        // Queued on replica 0 behind the create's uniqueness wait.
        Operation::DefineType {
            bytes: serde_json::to_vec(&v2).unwrap(),
        },
    ];
    let first = net.next;
    let outcomes = order_each(&mut net, SHARED, &dev(2), &ops);
    assert_eq!(
        outcomes[0][0],
        Outcome::Waiting(Wait::UniquenessUnknown(SHARED))
    );
    assert_eq!(outcomes[1][0], Outcome::Waiting(Wait::Queued));
    assert_eq!(outcomes[2][0], Outcome::Waiting(Wait::Queued));
    for each in &outcomes {
        assert!(matches!(each[1], Outcome::Accepted { .. }), "{each:?}");
    }
    // The edit was made while /state was still directly writable.
    backfill(&mut net.reps[0]);
    let replayed = replay(&mut net.reps[0]);
    assert_eq!(
        replayed,
        vec![
            (first, outcomes[0][1].clone()),
            (first + 1, outcomes[1][1].clone()),
            (first + 2, outcomes[2][1].clone()),
        ]
    );
    assert_eq!(net.accepted(SHARED, rid(3))["state"], json!("saved"));
}
