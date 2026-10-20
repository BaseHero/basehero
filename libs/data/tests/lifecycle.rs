//! A base app's lifecycle and the rule changes only a person's own device
//! makes: app deactivation and reactivation, core bindings, and their place
//! in the ordered queue.
use bh_data::{
    Actor, AppId, CompiledType, CoreCatalogue, FieldPath, MutationId, Position, RecordId,
    RejectCode, RevisionId, Scope, TypeId, Wait,
    catalogue::Shipped,
    compose, definition, index,
    mutation::{
        apply::Outcome,
        ops::{FieldChange, Operation},
        pending::{self, SubmitError},
    },
    query::{self, Budget, CmpOp, Expr, Query, TypeSelect},
    store::{self, coverage, records, registry},
};
use std::sync::LazyLock;

use rusqlite::Connection;
use serde_json::{Value, json};

const ARTICLE: &[u8] = include_bytes!("fixtures/types/Article.json");
const NOTE: &[u8] = include_bytes!("../core/note.v1.json");
const APP: AppId = AppId([2; 32]);
const OTHER_APP: AppId = AppId([3; 32]);
const SHARED: Scope = Scope {
    base: [1; 32],
    audience: [0; 32],
};
const ELSEWHERE: Scope = Scope {
    base: [5; 32],
    audience: [0; 32],
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
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn rev(bytes: &[u8]) -> RevisionId {
    RevisionId::of(bytes)
}
fn type_of(bytes: &[u8]) -> TypeId {
    definition::parse(bytes).unwrap().type_id
}

/// A memo whose archive state only its app's `archive` action changes.
fn memo(app: AppId) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"format":"bh-type/1","local":"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "app":hex(&app.0),"kind":"record","name":"Memo","description":"A short memo",
        "extends":null,"uses":[],
        "schema":{"type":"object","properties":{
            "text":{"type":"string","maxLength":500},
            "status":{"type":"string","enum":["open","archived"]}},
            "required":["text"]},
        "fields":{
            "/text":{"meaning":"Memo text","write":"direct","kind":"string"},
            "/status":{"meaning":"Archive state","write":"action","kind":"enum"}},
        "actions":[{"name":"archive","effects":["/status"],"source":"archive.js"}],
        "indexes":[{"name":"by_text","keys":["/text"]}],"unique":[],
        "search":{"title":"/text","text":[]},"queries":[],
        "evolution":{"previous":null,"migration":"","migration_ops":[],
            "examples":{"valid":[],"invalid":[]}},
        "rationale":[]}),
    )
    .unwrap()
}

/// The bytes of a core contract `thing` at a given label length, and its
/// compiled form under the reserved core identity.
fn thing(max: u32) -> (Vec<u8>, CompiledType) {
    let bytes = serde_json::to_vec(
        &json!({"format":"bh-type/1","local":"0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d",
        "app":hex(&[0; 32]),"kind":"record","name":"Thing","description":"A core thing",
        "extends":null,"uses":[],
        "schema":{"type":"object","properties":{"label":{"type":"string","maxLength":max}},
            "required":["label"]},
        "fields":{"/label":{"meaning":"Its label","write":"direct","kind":"string"}},
        "actions":[],"indexes":[{"name":"by_label","keys":["/label"]}],"unique":[],
        "search":{"title":"/label","text":[]},"queries":[],
        "evolution":{"previous":null,"migration":"","migration_ops":[],
            "examples":{"valid":[],"invalid":[]}},
        "rationale":[]}),
    )
    .unwrap();
    let parsed = definition::parse(&bytes).unwrap();
    let mut ct = compose::compile(&parsed, rev(&bytes), &|_, _| None).unwrap();
    let core = TypeId::core("thing");
    ct.type_id = core;
    ct.app = None;
    ct.lineage[0].0 = core;
    for field in &mut ct.fields {
        field.declared_by = core;
    }
    for index in &mut ct.indexes {
        index.declared_by = core;
    }
    (bytes, ct)
}

static THING: LazyLock<CompiledType> = LazyLock::new(|| thing(50).1);

/// An executable that also ships the core `thing` contract at label length 50.
struct Newer;
impl CoreCatalogue for Newer {
    fn core_type(&self, id: TypeId) -> Option<CompiledType> {
        Shipped
            .core_type(id)
            .or_else(|| (id == TypeId::core("thing")).then(|| THING.clone()))
    }
}

/// An app type extending core `thing` at the revision [`Newer`] ships.
fn gadget() -> Vec<u8> {
    serde_json::to_vec(
        &json!({"format":"bh-type/1","local":"0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e",
        "app":hex(&APP.0),"kind":"record","name":"Gadget","description":"A thing with a size",
        "extends":{"type":hex(&TypeId::core("thing").0),"revision":hex(&THING.revision.0)},
        "uses":[],
        "schema":{"type":"object","properties":{"size":{"type":"integer"}}},
        "fields":{"/size":{"meaning":"How big","write":"direct","kind":"integer"}},
        "actions":[],"indexes":[],"unique":[],"search":{"text":[]},"queries":[],
        "evolution":{"previous":null,"migration":"","migration_ops":[],
            "examples":{"valid":[],"invalid":[]}},
        "rationale":[]}),
    )
    .unwrap()
}

struct Rep {
    conn: Connection,
    core: Box<dyn CoreCatalogue>,
}

fn replica(core: Box<dyn CoreCatalogue>, covered: bool) -> Rep {
    let mut conn = Connection::open_in_memory().unwrap();
    let tx = conn.transaction().unwrap();
    store::migrate(&tx).unwrap();
    for scope in [SHARED, ELSEWHERE] {
        let sid = records::scope_id(&tx, scope, core.as_ref()).unwrap();
        coverage::set(&tx, sid, Position(0), covered).unwrap();
    }
    tx.commit().unwrap();
    Rep { conn, core }
}

/// Replicas fed one ordered vector of payloads.
struct Net {
    reps: Vec<Rep>,
    next: u64,
}

impl Net {
    fn new(reps: Vec<Rep>) -> Self {
        Self { reps, next: 1 }
    }
    fn current() -> Self {
        Self::new(vec![
            replica(Box::new(Shipped), true),
            replica(Box::new(Shipped), true),
        ])
    }
    /// Every replica's outcome for `op` at the next position.
    fn each(&mut self, scope: Scope, actor: &Actor, op: &Operation) -> Vec<Outcome> {
        let bytes = {
            let first = &mut self.reps[0];
            let tx = first.conn.transaction().unwrap();
            bh_data::testkit::assumed_payload(
                &tx,
                first.core.as_ref(),
                scope,
                actor,
                MutationId::random(),
                op,
            )
            .unwrap()
        };
        let position = Position(self.next);
        self.next += 1;
        self.reps
            .iter_mut()
            .map(|rep| {
                let tx = rep.conn.transaction().unwrap();
                let outcome = bh_data::testkit::apply_payload(
                    &tx,
                    rep.core.as_ref(),
                    scope,
                    position,
                    actor,
                    &bytes,
                )
                .unwrap();
                tx.commit().unwrap();
                outcome
            })
            .collect()
    }
    fn order(&mut self, scope: Scope, actor: &Actor, op: Operation) -> Outcome {
        let mut outcomes = self.each(scope, actor, &op);
        for outcome in &outcomes[1..] {
            assert_eq!(outcome, &outcomes[0], "replicas disagree on {op:?}");
        }
        outcomes.remove(0)
    }
    fn ok(&mut self, scope: Scope, actor: &Actor, op: Operation) {
        let outcome = self.order(scope, actor, op);
        assert!(
            matches!(outcome, Outcome::Accepted { .. }),
            "expected acceptance, got {outcome:?}"
        );
    }
    fn rejected(&mut self, scope: Scope, actor: &Actor, op: Operation) -> RejectCode {
        match self.order(scope, actor, op) {
            Outcome::Rejected(rejection) => rejection.code,
            other => panic!("expected rejection, got {other:?}"),
        }
    }
    fn submit(
        &mut self,
        i: usize,
        actor: &Actor,
        op: Operation,
    ) -> Result<pending::LocalSaved, SubmitError> {
        let rep = &mut self.reps[i];
        let tx = rep.conn.transaction().unwrap();
        let saved = bh_data::testkit::submit(&tx, rep.core.as_ref(), SHARED, actor, op);
        tx.commit().unwrap();
        saved
    }
    /// Completes replica `i`'s coverage (or gives it a newer executable) and
    /// replays its parked work.
    fn catch_up(&mut self, i: usize, core: Option<Box<dyn CoreCatalogue>>) -> u64 {
        let rep = &mut self.reps[i];
        if let Some(core) = core {
            rep.core = core;
        }
        let tx = rep.conn.transaction().unwrap();
        let mut applied = 0;
        for scope in [SHARED, ELSEWHERE] {
            let sid = records::scope_id(&tx, scope, rep.core.as_ref()).unwrap();
            coverage::set(&tx, sid, Position(self.next - 1), true).unwrap();
            applied += bh_data::testkit::retry_parked(&tx, rep.core.as_ref(), scope)
                .unwrap()
                .len() as u64;
        }
        tx.commit().unwrap();
        applied
    }
    fn assert_converged(&self) {
        let first = digest(&self.reps[0].conn);
        for rep in &self.reps[1..] {
            assert_eq!(digest(&rep.conn), first, "replica state diverged");
        }
    }
    fn define_memos(&mut self) {
        self.ok(SHARED, &dev(1), define_app(APP, "Memos"));
        self.ok(SHARED, &dev(1), define(&memo(APP)));
    }
}

fn define_app(app: AppId, name: &str) -> Operation {
    Operation::DefineApp {
        app,
        name: name.into(),
    }
}
fn define(bytes: &[u8]) -> Operation {
    Operation::DefineType {
        bytes: bytes.to_vec(),
    }
}
fn deactivate(app: AppId) -> Operation {
    Operation::SetAppState { app, active: false }
}
fn activate(app: AppId) -> Operation {
    Operation::SetAppState { app, active: true }
}
fn create_memo(record: RecordId, text: &str) -> Operation {
    Operation::Create {
        record,
        type_id: type_of(&memo(APP)),
        revision: rev(&memo(APP)),
        doc: json!({"text": text}),
    }
}
fn edit_memo(record: RecordId, changes: Vec<FieldChange>) -> Operation {
    Operation::Edit {
        record,
        revision: rev(&memo(APP)),
        changes,
    }
}
fn archive(record: RecordId) -> Operation {
    Operation::Action {
        record,
        app: APP,
        action: "archive".into(),
        changes: vec![set("/status", json!("archived"))],
    }
}
fn create_thing(record: RecordId, label: &str) -> Operation {
    Operation::Create {
        record,
        type_id: TypeId::core("thing"),
        revision: THING.revision,
        doc: json!({"label": label}),
    }
}
fn create_article(record: RecordId, url: &str) -> Operation {
    Operation::Create {
        record,
        type_id: type_of(ARTICLE),
        revision: rev(ARTICLE),
        doc: json!({"title": "T", "url": url}),
    }
}

/// Accepted records and field clocks: the replicated state.
fn digest(conn: &Connection) -> Vec<String> {
    let mut out: Vec<String> = conn
        .prepare("SELECT hex(record),hex(type),hex(revision),coalesce(accepted,'-'),changed_at FROM data_record WHERE accepted IS NOT NULL OR changed_at IS NOT NULL ORDER BY scope,record")
        .unwrap()
        .query_map([], |r| {
            Ok(format!(
                "{} {} {} {} {:?}",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, Option<i64>>(4)?
            ))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect();
    out.extend(
        conn.prepare("SELECT hex(r.record),c.path,c.position,hex(c.mutation) FROM data_field_clock c JOIN data_record r ON r.id=c.rec ORDER BY r.scope,r.record,c.path")
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

fn sid(conn: &Connection, scope: Scope) -> i64 {
    records::lookup_scope(conn, scope).unwrap().unwrap()
}

/// Every column of a scope's rows in `table`, for before/after comparisons.
fn rows_of(conn: &Connection, table: &str, scope: Scope) -> Vec<Vec<rusqlite::types::Value>> {
    let mut stmt = conn
        .prepare(&format!(
            "SELECT * FROM {table} WHERE scope=?1 ORDER BY 1,2,3"
        ))
        .unwrap();
    let columns = stmt.column_count();
    stmt.query_map([sid(conn, scope)], |r| {
        (0..columns).map(|i| r.get(i)).collect()
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

fn memo_query(text: &str) -> Query {
    Query {
        select: TypeSelect::Exact(type_of(&memo(APP))),
        filter: Some(Expr::Cmp {
            path: path("/text"),
            op: CmpOp::Eq,
            value: json!(text),
        }),
        sort: vec![],
        fields: vec![path("/text"), path("/status")],
        follow: vec![],
        text: None,
        limit: 50,
        after: None,
    }
}

#[test]
fn job_cannot_transition_or_bind_core_or_deactivate() {
    let mut net = Net::current();
    net.define_memos();
    let rule_changes = [
        deactivate(APP),
        Operation::BindCore {
            type_id: TypeId::core("thing"),
            revision: THING.revision,
        },
        Operation::Transition {
            type_id: type_of(&memo(APP)),
            to: rev(&memo(APP)),
        },
    ];
    for op in rule_changes {
        assert_eq!(
            net.rejected(SHARED, &job(1, None), op.clone()),
            RejectCode::DeviceOnly
        );
        match net.submit(0, &job(1, None), op) {
            Err(SubmitError::Rejected(r)) => assert_eq!(r.code, RejectCode::DeviceOnly),
            other => panic!("{other:?}"),
        }
    }
    // A job may still create new apps and types.
    net.ok(SHARED, &job(1, None), define_app(OTHER_APP, "Other"));
    net.ok(SHARED, &job(1, None), define(&memo(OTHER_APP)));
}

#[test]
fn bind_core_on_note_needs_core_transition() {
    let mut net = Net::current();
    let note = TypeId::core("note");
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            Operation::BindCore {
                type_id: note,
                revision: rev(NOTE),
            }
        ),
        RejectCode::NeedsCoreTransition
    );
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            Operation::Transition {
                type_id: note,
                to: rev(NOTE),
            }
        ),
        RejectCode::NeedsCoreTransition
    );
    // Note v1 stays the implicit baseline.
    for rep in &net.reps {
        let s = sid(&rep.conn, SHARED);
        assert_eq!(
            registry::permitted(&rep.conn, s, note, &Shipped).unwrap(),
            vec![rev(NOTE)]
        );
    }
}

#[test]
fn bind_core_unknown_revision_waits() {
    // Replica 0 ships `thing`; replica 1 is an older executable that does not.
    let mut net = Net::new(vec![
        replica(Box::new(Newer), true),
        replica(Box::new(Shipped), true),
    ]);
    net.ok(SHARED, &dev(1), define_app(APP, "Gadgets"));
    let shipped = THING.clone();
    let thing_id = TypeId::core("thing");
    // A newer executable serves nothing unbound.
    let s = sid(&net.reps[0].conn, SHARED);
    assert!(
        registry::current(&net.reps[0].conn, s, thing_id, &Newer)
            .unwrap()
            .is_none()
    );
    let bind = Operation::BindCore {
        type_id: thing_id,
        revision: shipped.revision,
    };
    assert_eq!(
        net.each(SHARED, &dev(1), &bind),
        vec![
            Outcome::Accepted {
                record: None,
                skipped: vec![]
            },
            Outcome::Waiting(Wait::MissingDefinition(shipped.revision)),
        ]
    );
    // A revision neither executable ships waits even with coverage (on the
    // older replica, queued behind its first wait).
    let unshipped = thing(80).1.revision;
    assert_eq!(
        net.each(
            SHARED,
            &dev(1),
            &Operation::BindCore {
                type_id: thing_id,
                revision: unshipped,
            }
        ),
        vec![
            Outcome::Waiting(Wait::MissingDefinition(unshipped)),
            Outcome::Waiting(Wait::Queued),
        ]
    );
    // Its own key is held, but unrelated work goes on.
    net.ok(SHARED, &dev(1), define(ARTICLE));
    net.ok(SHARED, &dev(1), create_article(rid(1), "u1"));
    // The binding is in force on the newer replica only; the older one parks it.
    let s = sid(&net.reps[0].conn, SHARED);
    assert_eq!(
        registry::permitted(&net.reps[0].conn, s, thing_id, &Newer).unwrap(),
        vec![shipped.revision]
    );
    // Upgrading the older replica replays its parked binding; the unshipped
    // revision still waits on both.
    assert_eq!(net.catch_up(1, Some(Box::new(Newer))), 1);
    net.assert_converged();
    for rep in &net.reps {
        let parked: i64 = rep
            .conn
            .query_row("SELECT count(*) FROM data_parked", [], |r| r.get(0))
            .unwrap();
        assert_eq!(parked, 1);
        let s = sid(&rep.conn, SHARED);
        assert_eq!(
            registry::current(&rep.conn, s, thing_id, rep.core.as_ref())
                .unwrap()
                .unwrap()
                .revision,
            shipped.revision
        );
    }
}

#[test]
fn new_core_type_unusable_until_bound_and_old_executable_queues() {
    let mut net = Net::new(vec![
        replica(Box::new(Newer), true),
        replica(Box::new(Shipped), true),
    ]);
    net.ok(SHARED, &dev(1), define_app(APP, "Gadgets"));
    let thing_id = TypeId::core("thing");
    // Before any binding, the type is unusable everywhere.
    assert_eq!(
        net.rejected(SHARED, &dev(1), create_thing(rid(1), "early")),
        RejectCode::NotFound
    );
    assert_eq!(
        net.rejected(SHARED, &dev(1), define(&gadget())),
        RejectCode::NotFound
    );
    let bind = Operation::BindCore {
        type_id: thing_id,
        revision: THING.revision,
    };
    assert!(matches!(
        net.each(SHARED, &dev(1), &bind)[..],
        [
            Outcome::Accepted { .. },
            Outcome::Waiting(Wait::MissingDefinition(_))
        ]
    ));
    // After it, the older executable queues every later operation on the type.
    let accepted = Outcome::Accepted {
        record: Some(rid(2)),
        skipped: vec![],
    };
    let queued = Outcome::Waiting(Wait::Queued);
    assert_eq!(
        net.each(SHARED, &dev(1), &create_thing(rid(2), "bound")),
        vec![accepted.clone(), queued.clone()]
    );
    assert_eq!(
        net.each(
            SHARED,
            &dev(2),
            &Operation::Edit {
                record: rid(2),
                revision: THING.revision,
                changes: vec![set("/label", json!("renamed"))],
            }
        ),
        vec![accepted, queued.clone()]
    );
    assert!(matches!(
        net.each(SHARED, &dev(1), &define(&gadget()))[..],
        [Outcome::Accepted { .. }, Outcome::Waiting(Wait::Queued)]
    ));
    // The newer replica indexes and queries the bound type.
    let new = &net.reps[0].conn;
    let page = query::run(
        new,
        SHARED,
        &[SHARED],
        &Newer,
        &Query {
            select: TypeSelect::Exact(thing_id),
            filter: Some(Expr::Cmp {
                path: path("/label"),
                op: CmpOp::Eq,
                value: json!("renamed"),
            }),
            sort: vec![],
            fields: vec![path("/label")],
            follow: vec![],
            text: None,
            limit: 50,
            after: None,
        },
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(page.rows.len(), 1);
    // Once upgraded, the older replica replays them in order and converges.
    assert_eq!(net.catch_up(1, Some(Box::new(Newer))), 4);
    net.assert_converged();
}

#[test]
fn deactivate_keeps_reads_and_direct_edits() {
    let mut net = Net::current();
    net.define_memos();
    net.ok(SHARED, &dev(1), create_memo(rid(1), "keep"));
    let s = sid(&net.reps[0].conn, SHARED);
    let indexes = rows_of(&net.reps[0].conn, "data_index", SHARED);
    net.ok(SHARED, &dev(1), deactivate(APP));
    for rep in &net.reps {
        assert_eq!(
            registry::app_active(&rep.conn, sid(&rep.conn, SHARED), APP).unwrap(),
            Some(false)
        );
    }
    // Direct edits stay possible; action-only fields stay protected.
    net.ok(
        SHARED,
        &dev(2),
        edit_memo(rid(1), vec![set("/text", json!("kept"))]),
    );
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(2),
            edit_memo(rid(1), vec![set("/status", json!("archived"))])
        ),
        RejectCode::ActionOnly
    );
    let saved = net
        .submit(
            0,
            &dev(2),
            edit_memo(rid(1), vec![set("/text", json!("local"))]),
        )
        .unwrap();
    assert!(!saved.payload.is_empty());
    // Definitions and indexes stay, and still answer queries.
    let conn = &net.reps[1].conn;
    assert!(
        registry::list_types(conn, s, &Shipped)
            .unwrap()
            .iter()
            .any(|ct| ct.type_id == type_of(&memo(APP)))
    );
    assert_eq!(rows_of(&net.reps[0].conn, "data_index", SHARED), indexes);
    let page = query::run(
        conn,
        SHARED,
        &[SHARED],
        &Shipped,
        &memo_query("kept"),
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].values["/text"], json!("kept"));
    net.assert_converged();
}

#[test]
fn deactivate_blocks_create_and_actions() {
    let mut net = Net::current();
    net.define_memos();
    net.ok(SHARED, &dev(1), define_app(OTHER_APP, "Other"));
    net.ok(SHARED, &dev(1), define(&memo(OTHER_APP)));
    net.ok(SHARED, &dev(1), create_memo(rid(1), "one"));
    net.ok(SHARED, &dev(1), deactivate(APP));
    assert_eq!(
        net.rejected(SHARED, &dev(1), create_memo(rid(2), "two")),
        RejectCode::AppInactive
    );
    assert_eq!(
        net.rejected(SHARED, &job(1, Some("archive")), archive(rid(1))),
        RejectCode::AppInactive
    );
    match net.submit(0, &dev(1), create_memo(rid(3), "three")) {
        Err(SubmitError::Rejected(r)) => assert_eq!(r.code, RejectCode::AppInactive),
        other => panic!("{other:?}"),
    }
    // Another app's types are unaffected.
    net.ok(
        SHARED,
        &dev(1),
        Operation::Create {
            record: rid(4),
            type_id: type_of(&memo(OTHER_APP)),
            revision: rev(&memo(OTHER_APP)),
            doc: json!({"text": "other"}),
        },
    );
    // An app that was never defined cannot be deactivated.
    assert_eq!(
        net.rejected(SHARED, &dev(1), deactivate(AppId([8; 32]))),
        RejectCode::NotFound
    );
    net.assert_converged();
}

#[test]
fn reactivate_reuses_identities() {
    let mut net = Net::current();
    net.define_memos();
    net.ok(SHARED, &dev(1), create_memo(rid(1), "one"));
    let before = rows_of(&net.reps[0].conn, "data_index", SHARED);
    let row_id = |net: &Net| {
        let conn = &net.reps[0].conn;
        records::get(conn, sid(conn, SHARED), rid(1))
            .unwrap()
            .unwrap()
            .id
    };
    let id = row_id(&net);
    net.ok(SHARED, &dev(1), deactivate(APP));
    net.ok(SHARED, &dev(1), activate(APP));
    // The same app, types, records and indexes, not copies.
    assert_eq!(
        net.rejected(SHARED, &dev(1), define_app(APP, "Memos again")),
        RejectCode::Exists
    );
    net.ok(SHARED, &job(1, Some("archive")), archive(rid(1)));
    net.ok(SHARED, &dev(1), create_memo(rid(2), "two"));
    assert_eq!(row_id(&net), id);
    let after = rows_of(&net.reps[0].conn, "data_index", SHARED);
    assert_eq!(
        after.iter().map(|r| r[0].clone()).collect::<Vec<_>>(),
        before.iter().map(|r| r[0].clone()).collect::<Vec<_>>()
    );
    let page = query::run(
        &net.reps[1].conn,
        SHARED,
        &[SHARED],
        &Shipped,
        &memo_query("one"),
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(page.rows[0].record, rid(1));
    assert_eq!(page.rows[0].values["/status"], json!("archived"));
    net.assert_converged();
}

#[test]
fn doc_only_revision_no_index_work() {
    let mut net = Net::current();
    net.ok(SHARED, &dev(1), define_app(APP, "Reader"));
    net.ok(SHARED, &dev(1), define(ARTICLE));
    net.ok(SHARED, &dev(1), create_article(rid(1), "u1"));
    let indexes = rows_of(&net.reps[0].conn, "data_index", SHARED);
    let mut doc: Value = serde_json::from_slice(ARTICLE).unwrap();
    doc["fields"]["/title"]["meaning"] = json!("The article's headline as published");
    let doc_only = serde_json::to_vec(&doc).unwrap();
    // A documentation-only revision changes no rules, so a job may add it.
    net.ok(SHARED, &job(1, None), define(&doc_only));
    for rep in &net.reps {
        let s = sid(&rep.conn, SHARED);
        assert_eq!(
            registry::current(&rep.conn, s, type_of(ARTICLE), &Shipped)
                .unwrap()
                .unwrap()
                .revision,
            rev(&doc_only)
        );
        assert_eq!(rows_of(&rep.conn, "data_index", SHARED), indexes);
        assert!(index::pending_work(&rep.conn).unwrap().is_empty());
    }
    // A revision that declares a new index starts building it.
    doc["indexes"] = json!([{"name":"by_published","keys":["/published"]},
        {"name":"by_title","keys":["/title"]}]);
    let indexed = serde_json::to_vec(&doc).unwrap();
    net.ok(SHARED, &dev(1), define(&indexed));
    for rep in &net.reps {
        let rows = rows_of(&rep.conn, "data_index", SHARED);
        assert_eq!(rows.len(), indexes.len() + 1);
        assert_eq!(index::pending_work(&rep.conn).unwrap().len(), 1);
    }
}

#[test]
fn schema_change_in_one_scope_leaves_other_scope_untouched() {
    const V3: &[u8] = include_bytes!("fixtures/types/Article.v3.json");
    let mut net = Net::current();
    for scope in [SHARED, ELSEWHERE] {
        net.ok(scope, &dev(1), define_app(APP, "Reader"));
        net.ok(scope, &dev(1), define(ARTICLE));
        net.ok(scope, &dev(1), create_article(rid(1), "u1"));
        net.ok(scope, &dev(1), create_article(rid(2), "u2"));
    }
    let snapshot = |conn: &Connection| {
        [
            "data_index",
            "data_record",
            "data_type",
            "data_type_at",
            "data_definition",
            "data_parked",
        ]
        .map(|table| rows_of(conn, table, ELSEWHERE))
    };
    let before: Vec<_> = net.reps.iter().map(|rep| snapshot(&rep.conn)).collect();
    let mut doc: Value = serde_json::from_slice(ARTICLE).unwrap();
    doc["indexes"] = json!([{"name":"by_published","keys":["/published"]},
        {"name":"by_title","keys":["/title"]}]);
    net.ok(SHARED, &dev(1), define(&serde_json::to_vec(&doc).unwrap()));
    net.ok(SHARED, &dev(1), define(V3));
    net.ok(
        SHARED,
        &dev(1),
        Operation::Transition {
            type_id: type_of(ARTICLE),
            to: rev(V3),
        },
    );
    net.ok(SHARED, &dev(1), deactivate(APP));
    for (rep, before) in net.reps.iter().zip(&before) {
        assert_eq!(&snapshot(&rep.conn), before);
        let elsewhere = sid(&rep.conn, ELSEWHERE);
        for ix in index::pending_work(&rep.conn).unwrap() {
            assert_ne!(index::state(&rep.conn, ix).unwrap().scope, elsewhere);
        }
        assert_eq!(
            registry::app_active(&rep.conn, elsewhere, APP).unwrap(),
            Some(true)
        );
    }
    // Work in the other scope carries on under its own rules.
    net.ok(
        ELSEWHERE,
        &dev(1),
        Operation::Edit {
            record: rid(1),
            revision: rev(ARTICLE),
            changes: vec![set("/title", json!("Still v1"))],
        },
    );
    net.assert_converged();
}

#[test]
fn rule_changes_wait_behind_parked_work_they_affect() {
    // Replica 1 does not yet hold the whole scope, so it cannot prove a new
    // article's URL unique and parks the creation.
    let mut net = Net::new(vec![
        replica(Box::new(Shipped), true),
        replica(Box::new(Shipped), true),
    ]);
    net.ok(SHARED, &dev(1), define_app(APP, "Reader"));
    net.ok(SHARED, &dev(1), define(ARTICLE));
    net.ok(SHARED, &dev(1), define_app(OTHER_APP, "Other"));
    net.ok(SHARED, &dev(1), define(&memo(OTHER_APP)));
    // Registry bootstrap is verified; subsequent record coverage is not.
    let tx = net.reps[1].conn.transaction().unwrap();
    coverage::set(&tx, sid(&tx, SHARED), Position(4), false).unwrap();
    tx.commit().unwrap();
    let accepted = |record: Option<RecordId>| Outcome::Accepted {
        record,
        skipped: vec![],
    };
    let queued = Outcome::Waiting(Wait::Queued);
    let outcomes = net.each(SHARED, &dev(1), &create_article(rid(1), "u1"));
    assert_eq!(outcomes[0], accepted(Some(rid(1))));
    assert!(matches!(
        outcomes[1],
        Outcome::Waiting(Wait::UniquenessUnknown(_))
    ));
    // Deactivating the app the parked creation reads, and transitioning its
    // type, queue behind it; another app's rule change does not.
    assert_eq!(
        net.each(SHARED, &dev(1), &deactivate(APP)),
        vec![accepted(None), queued.clone()]
    );
    let v3 = include_bytes!("fixtures/types/Article.v3.json");
    assert_eq!(
        net.each(SHARED, &dev(1), &define(v3)),
        vec![accepted(None), queued.clone()]
    );
    assert_eq!(
        net.each(
            SHARED,
            &dev(1),
            &Operation::Transition {
                type_id: type_of(ARTICLE),
                to: rev(v3),
            }
        ),
        vec![accepted(None), queued.clone()]
    );
    net.ok(SHARED, &dev(1), deactivate(OTHER_APP));
    // A creation of the deactivated app's type queues too.
    assert_eq!(
        net.each(SHARED, &dev(1), &create_article(rid(2), "u2")),
        vec![
            Outcome::Rejected(bh_data::Rejection {
                code: RejectCode::AppInactive,
                path: None,
                detail: format!("app {} is not active in this audience", hex(&APP.0)),
            }),
            queued
        ]
    );
    // Once covered, replay reaches the same verdicts at the same positions.
    assert_eq!(net.catch_up(1, None), 5);
    net.assert_converged();
    let conn = &net.reps[1].conn;
    let s = sid(conn, SHARED);
    assert_eq!(registry::app_active(conn, s, APP).unwrap(), Some(false));
    assert_eq!(
        registry::permitted(conn, s, type_of(ARTICLE), &Shipped).unwrap(),
        vec![rev(v3)]
    );
}

#[test]
fn app_names_are_bounded() {
    let mut net = Net::current();
    net.ok(SHARED, &dev(1), define_app(APP, &"n".repeat(200)));
    let long = define_app(OTHER_APP, &"é".repeat(101));
    assert_eq!(
        net.rejected(SHARED, &dev(1), long.clone()),
        RejectCode::TooLarge
    );
    match net.submit(0, &dev(1), long) {
        Err(SubmitError::Rejected(r)) => assert_eq!(r.code, RejectCode::TooLarge),
        other => panic!("{other:?}"),
    }
}

#[test]
fn unknown_app_state_change_waits_without_coverage() {
    let mut net = Net::new(vec![replica(Box::new(Shipped), false)]);
    assert_eq!(
        net.order(SHARED, &dev(1), deactivate(APP)),
        Outcome::Waiting(Wait::Coverage(SHARED))
    );
    // A later definition of that app queues behind it.
    assert_eq!(
        net.order(SHARED, &dev(1), define_app(APP, "Late")),
        Outcome::Waiting(Wait::Queued)
    );
    // With the scope covered, the change is refused at its own position and
    // the definition then applies.
    assert_eq!(net.catch_up(0, None), 2);
    let conn = &net.reps[0].conn;
    assert_eq!(
        registry::app_active(conn, sid(conn, SHARED), APP).unwrap(),
        Some(true)
    );
}

#[test]
fn define_type_for_unknown_app_waits_without_coverage() {
    let mut net = Net::new(vec![
        replica(Box::new(Shipped), true),
        replica(Box::new(Shipped), false),
    ]);
    let accepted = |record: Option<RecordId>| Outcome::Accepted {
        record,
        skipped: vec![],
    };
    let queued = Outcome::Waiting(Wait::Queued);
    let early = net.each(SHARED, &dev(1), &define(&memo(APP)));
    assert!(matches!(&early[0], Outcome::Rejected(r) if r.code == RejectCode::NotFound));
    assert_eq!(early[1], Outcome::Waiting(Wait::Coverage(SHARED)));
    assert_eq!(
        net.each(SHARED, &dev(1), &define_app(APP, "Memos")),
        vec![accepted(None), queued.clone()]
    );
    assert_eq!(
        net.each(SHARED, &dev(1), &define(&memo(APP))),
        vec![accepted(None), queued.clone()]
    );
    assert_eq!(
        net.each(SHARED, &dev(1), &create_memo(rid(1), "one"))[0],
        accepted(Some(rid(1)))
    );
    // Once covered, replay reaches the full replica's verdicts.
    assert_eq!(net.catch_up(1, None), 4);
    net.assert_converged();
    for rep in &net.reps {
        let parked: i64 = rep
            .conn
            .query_row("SELECT count(*) FROM data_parked", [], |r| r.get(0))
            .unwrap();
        assert_eq!(parked, 0);
    }
}

/// A compatible revision of the memo type adding an optional tag, with the
/// given migration steps.
fn memo_v2(steps: Value) -> Vec<u8> {
    let mut doc: Value = serde_json::from_slice(&memo(APP)).unwrap();
    doc["schema"]["properties"]["tag"] = json!({"type":"string","maxLength":20});
    doc["fields"]["/tag"] = json!({"meaning":"A tag","write":"direct","kind":"string"});
    doc["evolution"]["migration_ops"] = steps;
    serde_json::to_vec(&doc).unwrap()
}

#[test]
fn job_cannot_declare_migration_of_protected_fields() {
    let mut net = Net::current();
    net.define_memos();
    // A migration step may write the fields it names, so naming an
    // action-only one is a rule change.
    let protected = memo_v2(json!([{"op":"set_constant","path":"/status","value":"archived"}]));
    assert_eq!(
        net.rejected(SHARED, &job(1, None), define(&protected)),
        RejectCode::DeviceOnly
    );
    let renamed = memo_v2(json!([{"op":"rename_field","from":"/status","to":"/tag"}]));
    assert_eq!(
        net.rejected(SHARED, &job(1, None), define(&renamed)),
        RejectCode::DeviceOnly
    );
    let direct = memo_v2(json!([{"op":"set_constant","path":"/tag","value":"new"}]));
    net.ok(SHARED, &job(1, None), define(&direct));
    net.ok(SHARED, &dev(1), define(&protected));
    for rep in &net.reps {
        let s = sid(&rep.conn, SHARED);
        assert_eq!(
            registry::permitted(&rep.conn, s, type_of(&memo(APP)), &Shipped).unwrap(),
            vec![rev(&memo(APP)), rev(&direct), rev(&protected)]
        );
    }
}

#[test]
fn bind_core_on_app_type_refused() {
    let mut net = Net::current();
    net.ok(SHARED, &dev(1), define_app(APP, "Reader"));
    net.ok(SHARED, &dev(1), define(ARTICLE));
    assert_eq!(
        net.rejected(
            SHARED,
            &dev(1),
            Operation::BindCore {
                type_id: type_of(ARTICLE),
                revision: rev(ARTICLE),
            }
        ),
        RejectCode::NotFound
    );
    // Nothing waits, so the type's later work goes on.
    let v2 = include_bytes!("fixtures/types/Article.v2.json");
    net.ok(SHARED, &dev(1), define(v2));
    net.ok(SHARED, &dev(1), create_article(rid(1), "u1"));
    net.assert_converged();
}
