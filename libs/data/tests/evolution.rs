//! Revisions of a type over time: compatible revisions keep older writers,
//! breaking ones wait for an explicit transition, and records move to the new
//! revision through ordered, resumable migrations.
use bh_data::{
    Actor, AppId, FieldPath, MutationId, Position, RecordId, RejectCode, RevisionId, Scope, TypeId,
    catalogue::Shipped,
    evolve::{self, Migration},
    mutation::{
        apply::Outcome,
        ops::{FieldChange, Operation},
        pending::{self, SubmitError},
        undo,
    },
    payload,
    query::{self, Budget, Query, TypeSelect},
    store::{records, registry},
    testkit::{Delivery, OrderedLog, Replica},
};
use serde_json::{Value, json};

const ARTICLE: &[u8] = include_bytes!("fixtures/types/Article.json");
const ARTICLE_V2: &[u8] = include_bytes!("fixtures/types/Article.v2.json");
const ARTICLE_V3: &[u8] = include_bytes!("fixtures/types/Article.v3.json");
const APP: AppId = AppId([2; 32]);
const SHARED: Scope = Scope {
    base: [1; 32],
    audience: [0; 32],
};

fn dev(n: u8) -> Actor {
    Actor::Device {
        account: [n; 32],
        device: [n; 32],
    }
}
fn job(n: u8) -> Actor {
    Actor::Job {
        account: [n; 32],
        delegation: [9; 32],
        action: None,
    }
}
fn rid(n: u16) -> RecordId {
    let mut id = [0; 32];
    id[..2].copy_from_slice(&n.to_be_bytes());
    id[31] = 1;
    RecordId(id)
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
    bh_data::definition::parse(bytes).unwrap().type_id
}

/// Task v1: a title, an open/done status and a legacy note.
fn task_v1() -> Vec<u8> {
    serde_json::to_vec(
        &json!({"format":"bh-type/1","local":"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        "app":hex(&APP.0),"kind":"record","name":"Task","description":"A task to do",
        "extends":null,"uses":[],
        "schema":{"type":"object","properties":{
            "title":{"type":"string","maxLength":200},
            "status":{"type":"string","enum":["open","done"]},
            "legacy":{"type":"string","maxLength":200},
            "owner":{"type":"string","maxLength":100}},
            "required":["title","status"]},
        "fields":{
            "/title":{"meaning":"What to do","write":"direct","kind":"string"},
            "/status":{"meaning":"Whether it is done","write":"direct","kind":"enum"},
            "/legacy":{"meaning":"A note from an older tool","write":"direct","kind":"string"},
            "/owner":{"meaning":"Who does it","write":"direct","kind":"string"}},
        "actions":[],"indexes":[{"name":"by_status","keys":["/status"]}],"unique":[],
        "search":{"title":"/title","text":[]},"queries":[],
        "evolution":{"previous":null,"migration":"","migration_ops":[],
            "examples":{"valid":[],"invalid":[]}},
        "rationale":[]}),
    )
    .unwrap()
}

/// Task v2, breaking: `/title` becomes `/name`, statuses are renamed, a
/// required priority is added and the legacy note goes.
fn task_v2() -> Vec<u8> {
    serde_json::to_vec(
        &json!({"format":"bh-type/1","local":"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
        "app":hex(&APP.0),"kind":"record","name":"Task","description":"A task to do",
        "extends":null,"uses":[],
        "schema":{"type":"object","properties":{
            "name":{"type":"string","maxLength":200},
            "status":{"type":"string","enum":["todo","complete"]},
            "priority":{"type":"string","enum":["normal","high"]},
            "owner":{"type":"string","maxLength":20}},
            "required":["name","status","priority"]},
        "fields":{
            "/name":{"meaning":"What to do","write":"direct","kind":"string"},
            "/status":{"meaning":"Whether it is done","write":"direct","kind":"enum"},
            "/priority":{"meaning":"How urgent it is","write":"direct","kind":"enum"},
            "/owner":{"meaning":"Who does it","write":"direct","kind":"string"}},
        "actions":[],"indexes":[{"name":"by_status","keys":["/status"]}],"unique":[],
        "search":{"title":"/name","text":[]},"queries":[],
        "evolution":{"previous":hex(&rev(&task_v1()).0),
            "migration":"Rename title to name and the statuses; every task starts normal",
            "migration_ops":[
                {"op":"rename_field","from":"/title","to":"/name"},
                {"op":"map_enum","path":"/status","map":{"open":"todo","done":"complete"}},
                {"op":"set_constant","path":"/priority","value":"normal"},
                {"op":"drop_field","path":"/legacy"}],
            "examples":{"valid":[],"invalid":[]}},
        "rationale":["Statuses read better as todo and complete."]}),
    )
    .unwrap()
}

fn define_app() -> Operation {
    Operation::DefineApp {
        app: APP,
        name: "Planner".into(),
    }
}
fn define(bytes: &[u8]) -> Operation {
    Operation::DefineType {
        bytes: bytes.to_vec(),
    }
}
fn create_article(record: RecordId, revision: RevisionId, doc: Value) -> Operation {
    Operation::Create {
        record,
        type_id: type_of(ARTICLE),
        revision,
        doc,
    }
}
fn create_task(record: RecordId, title: &str, status: &str) -> Operation {
    Operation::Create {
        record,
        type_id: type_of(&task_v1()),
        revision: rev(&task_v1()),
        doc: json!({"title": title, "status": status, "legacy": "old", "owner": "sam"}),
    }
}

/// Replicas that receive one ordered log; every outcome must agree.
struct World {
    log: OrderedLog,
    reps: Vec<Replica>,
}

impl World {
    fn new(n: usize) -> Self {
        Self {
            log: OrderedLog::new(),
            reps: (0..n).map(|_| Replica::new_in_memory().unwrap()).collect(),
        }
    }

    /// Orders `op` as published by `actor` elsewhere and syncs every replica.
    fn order(&mut self, actor: &Actor, op: Operation) -> Outcome {
        self.order_id(actor, op).1
    }

    fn order_id(&mut self, actor: &Actor, op: Operation) -> (MutationId, Outcome) {
        let mutation = MutationId::random();
        let payload = self.reps[0]
            .assumed_payload(SHARED, actor, mutation, &op)
            .unwrap();
        let position = self.log.append(SHARED, actor, payload);
        (mutation, self.outcome_at(position))
    }

    fn ok(&mut self, actor: &Actor, op: Operation) {
        let outcome = self.order(actor, op);
        assert!(
            matches!(outcome, Outcome::Accepted { .. }),
            "expected acceptance, got {outcome:?}"
        );
    }

    fn rejected(&mut self, actor: &Actor, op: Operation) -> RejectCode {
        match self.order(actor, op) {
            Outcome::Rejected(rejection) => rejection.code,
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    /// Syncs every replica and returns the outcome they all reached at `position`.
    fn outcome_at(&mut self, position: Position) -> Outcome {
        let mut outcomes = Vec::new();
        for replica in &mut self.reps {
            let synced = replica.sync_from(&self.log, Delivery::InOrder).unwrap();
            outcomes.push(
                synced
                    .into_iter()
                    .find(|(p, _)| *p == position)
                    .map(|(_, outcome)| outcome)
                    .expect("delivered"),
            );
        }
        for outcome in &outcomes[1..] {
            assert_eq!(outcome, &outcomes[0], "replicas disagree");
        }
        outcomes.remove(0)
    }

    fn assert_converged(&self) {
        let first = self.reps[0].state_digest(SHARED).unwrap();
        for replica in &self.reps[1..] {
            assert_eq!(replica.state_digest(SHARED).unwrap(), first, "diverged");
        }
    }

    fn define_articles(&mut self) {
        self.ok(&dev(1), define_app());
        self.ok(&dev(1), define(ARTICLE));
    }

    fn define_tasks(&mut self) {
        self.ok(&dev(1), define_app());
        self.ok(&dev(1), define(&task_v1()));
    }
}

fn sid(replica: &Replica) -> i64 {
    records::lookup_scope(replica.conn(), SHARED)
        .unwrap()
        .unwrap()
}
fn row(replica: &Replica, record: RecordId) -> records::RecordRow {
    records::get(replica.conn(), sid(replica), record)
        .unwrap()
        .unwrap()
}
fn permitted(replica: &Replica, type_id: TypeId) -> Vec<RevisionId> {
    registry::permitted(replica.conn(), sid(replica), type_id, &Shipped).unwrap()
}
fn current(replica: &Replica, type_id: TypeId) -> RevisionId {
    registry::current(replica.conn(), sid(replica), type_id, &Shipped)
        .unwrap()
        .unwrap()
        .revision
}

#[test]
fn compatible_revision_keeps_old_writers() {
    let mut world = World::new(2);
    world.define_articles();
    let article = type_of(ARTICLE);
    world.ok(
        &dev(1),
        create_article(rid(1), rev(ARTICLE), json!({"title":"One","url":"u1"})),
    );
    // A job may add a compatible revision that changes no rules.
    world.ok(&job(1), define(ARTICLE_V2));
    for replica in &world.reps {
        assert_eq!(current(replica, article), rev(ARTICLE_V2));
        assert_eq!(
            permitted(replica, article),
            vec![rev(ARTICLE), rev(ARTICLE_V2)]
        );
    }
    // A writer still on v1 edits and creates; fields only v2 knows are kept.
    world.ok(
        &dev(2),
        Operation::Edit {
            record: rid(1),
            revision: rev(ARTICLE_V2),
            changes: vec![set("/summary", json!("Short"))],
        },
    );
    world.ok(
        &dev(3),
        Operation::Edit {
            record: rid(1),
            revision: rev(ARTICLE),
            changes: vec![set("/title", json!("Uno"))],
        },
    );
    world.ok(
        &dev(3),
        create_article(rid(2), rev(ARTICLE), json!({"title":"Two","url":"u2"})),
    );
    world.assert_converged();
    let one = row(&world.reps[0], rid(1));
    assert_eq!(
        one.accepted,
        Some(json!({"title":"Uno","url":"u1","summary":"Short"}))
    );
    assert_eq!(one.revision, rev(ARTICLE_V2));
}

#[test]
fn breaking_revision_needs_transition() {
    let mut world = World::new(2);
    world.define_articles();
    let article = type_of(ARTICLE);
    world.ok(
        &dev(1),
        create_article(rid(1), rev(ARTICLE), json!({"title":"One","url":"u1"})),
    );
    // A job cannot change the rules existing records live under.
    assert_eq!(
        world.rejected(&job(1), define(ARTICLE_V3)),
        RejectCode::DeviceOnly
    );
    // A device's breaking revision is defined but not yet in force.
    world.ok(&dev(1), define(ARTICLE_V3));
    for replica in &world.reps {
        assert_eq!(current(replica, article), rev(ARTICLE));
        assert_eq!(permitted(replica, article), vec![rev(ARTICLE)]);
    }
    let v3_doc = json!({"title":"Two","url":"u2","summary":"Needed now"});
    assert_eq!(
        world.rejected(
            &dev(1),
            create_article(rid(2), rev(ARTICLE_V3), v3_doc.clone())
        ),
        RejectCode::RevisionNotPermitted
    );
    world.ok(
        &dev(1),
        Operation::Transition {
            type_id: article,
            to: rev(ARTICLE_V3),
        },
    );
    for replica in &world.reps {
        assert_eq!(current(replica, article), rev(ARTICLE_V3));
        assert_eq!(permitted(replica, article), vec![rev(ARTICLE_V3)]);
    }
    world.ok(&dev(1), create_article(rid(2), rev(ARTICLE_V3), v3_doc));
    assert_eq!(
        world.rejected(
            &dev(1),
            create_article(rid(3), rev(ARTICLE), json!({"title":"Three","url":"u3"}))
        ),
        RejectCode::RevisionNotPermitted
    );
    // A writer on the new revision still cannot change a record left on the
    // old one, even with a change the new rules would accept.
    assert_eq!(
        world.rejected(
            &dev(1),
            Operation::Edit {
                record: rid(1),
                revision: rev(ARTICLE_V3),
                changes: vec![set("/summary", json!("Late"))],
            }
        ),
        RejectCode::RevisionNotPermitted
    );
    // Transitioning to a revision nobody defined is refused.
    assert_eq!(
        world.rejected(
            &dev(1),
            Operation::Transition {
                type_id: article,
                to: RevisionId([9; 32]),
            }
        ),
        RejectCode::NotFound
    );
    world.assert_converged();
    assert_eq!(row(&world.reps[0], rid(1)).revision, rev(ARTICLE));
}

#[test]
fn old_client_write_after_transition_rejected_and_kept() {
    let mut world = World::new(2);
    world.define_articles();
    let article = type_of(ARTICLE);
    world.ok(
        &dev(1),
        create_article(rid(1), rev(ARTICLE), json!({"title":"One","url":"u1"})),
    );
    // Replica 1 is an old client: it saves a v1 edit while offline.
    let saved = world.reps[1]
        .submit(
            SHARED,
            &dev(2),
            Operation::Edit {
                record: rid(1),
                revision: rev(ARTICLE),
                changes: vec![set("/title", json!("Offline title"))],
            },
        )
        .unwrap();
    // Meanwhile a person's device moves the type to v3.
    let revised = define(ARTICLE_V3);
    let bytes = world.reps[0]
        .assumed_payload(SHARED, &dev(1), MutationId::random(), &revised)
        .unwrap();
    let v3 = world.log.append(SHARED, &dev(1), bytes);
    world.reps[0]
        .sync_from(&world.log, Delivery::InOrder)
        .unwrap();
    let move_to_v3 = Operation::Transition {
        type_id: article,
        to: rev(ARTICLE_V3),
    };
    let bytes = world.reps[0]
        .assumed_payload(SHARED, &dev(1), MutationId::random(), &move_to_v3)
        .unwrap();
    let transition = world.log.append(SHARED, &dev(1), bytes);
    // The old client's edit is ordered after the transition.
    let edit = world.log.append(SHARED, &dev(2), saved.payload.clone());
    assert!(v3 < transition && transition < edit);
    let outcome = world.outcome_at(edit);
    let Outcome::Rejected(rejection) = outcome else {
        panic!("expected rejection, got {outcome:?}");
    };
    assert_eq!(rejection.code, RejectCode::RevisionNotPermitted);
    world.assert_converged();
    // Accepted state is untouched; the old client keeps its work to recover.
    for replica in &world.reps {
        assert_eq!(
            row(replica, rid(1)).accepted,
            Some(json!({"title":"One","url":"u1"}))
        );
    }
    let old = &world.reps[1];
    assert_eq!(
        row(old, rid(1)).view(),
        Some(&json!({"title":"One","url":"u1"}))
    );
    let rejected = pending::rejected(old.conn(), SHARED).unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].mutation, saved.mutation);
    assert_eq!(rejected[0].record, Some(rid(1)));
    assert_eq!(
        rejected[0].attempted,
        vec![set("/title", json!("Offline title"))]
    );
    assert_eq!(rejected[0].rejection, rejection);
    assert!(
        pending::rejected(world.reps[0].conn(), SHARED)
            .unwrap()
            .is_empty()
    );
}

/// Plans up to `batch` Task v1 → v2 migrations on `replica`.
fn plan(replica: &Replica, batch: usize) -> evolve::Plan {
    evolve::plan(
        replica.conn(),
        SHARED,
        &Shipped,
        type_of(&task_v1()),
        rev(&task_v2()),
        batch,
    )
    .unwrap()
}

/// Publishes up to `batch` planned migrations from `replica` and syncs it;
/// returns how many it published.
fn migrate_batch(replica: &mut Replica, log: &mut OrderedLog, batch: usize) -> usize {
    let planned_now = plan(replica, batch);
    assert!(planned_now.needs_manual.is_empty());
    let ops = planned_now.ops;
    let count = ops.len();
    let mut planned = Vec::new();
    for op in ops {
        planned.extend(op.record());
        let saved = replica.submit(SHARED, &job(4), op).unwrap();
        log.append(SHARED, &job(4), saved.payload);
    }
    // Records with saved, not yet ordered migrations are not planned again.
    let next = plan(replica, batch).ops;
    assert!(
        next.iter()
            .all(|op| !planned.contains(&op.record().unwrap()))
    );
    for (_, outcome) in replica.sync_from(log, Delivery::InOrder).unwrap() {
        assert!(
            matches!(outcome, Outcome::Accepted { .. } | Outcome::Duplicate),
            "{outcome:?}"
        );
    }
    count
}

fn fast(replica: &Replica) {
    replica
        .conn()
        .execute_batch("PRAGMA synchronous=OFF")
        .unwrap();
}

#[test]
fn parked_unconfirmed_management_is_refused_after_reopen_and_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("replica.sqlite");
    let mut log = OrderedLog::new();
    log.append(
        SHARED,
        &dev(1),
        payload::encode(MutationId::random(), &define_app()).unwrap(),
    );
    let mut replica = Replica::new_file(&path).unwrap();
    replica.sync_from(&log, Delivery::InOrder).unwrap();
    replica.without_kinds(&["set_app_state"]);
    log.append(
        SHARED,
        &dev(1),
        payload::encode(
            MutationId::random(),
            &Operation::SetAppState {
                app: APP,
                active: false,
            },
        )
        .unwrap(),
    );
    let result = replica.sync_from(&log, Delivery::InOrder).unwrap();
    assert!(matches!(result.as_slice(), [(_, Outcome::Waiting(_))]));
    drop(replica);
    let mut reopened = Replica::new_file(&path).unwrap();
    reopened.sync_from(&log, Delivery::InOrder).unwrap();
    reopened.upgrade().unwrap();
    let sid = records::lookup_scope(reopened.conn(), SHARED)
        .unwrap()
        .unwrap();
    assert_eq!(
        registry::app_active(reopened.conn(), sid, APP).unwrap(),
        Some(true)
    );
    assert_eq!(
        reopened
            .conn()
            .query_row("SELECT count(*) FROM data_parked", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn migration_batches_resume_after_interruption() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("replica.sqlite");
    let mut log = OrderedLog::new();
    let task = type_of(&task_v1());
    for op in [define_app(), define(&task_v1())] {
        log.append(
            SHARED,
            &dev(1),
            payload::encode(MutationId::random(), &op).unwrap(),
        );
    }
    for n in 0..1_000u16 {
        let op = create_task(
            rid(n),
            &format!("Task {n}"),
            if n % 3 == 0 { "done" } else { "open" },
        );
        log.append(
            SHARED,
            &dev(1),
            payload::encode(MutationId::random(), &op).unwrap(),
        );
    }
    let mut fixture = Replica::new_in_memory().unwrap();
    fixture.sync_from(&log, Delivery::InOrder).unwrap();
    for op in [
        define(&task_v2()),
        Operation::Transition {
            type_id: task,
            to: rev(&task_v2()),
        },
    ] {
        let bytes = fixture
            .assumed_payload(SHARED, &dev(1), MutationId::random(), &op)
            .unwrap();
        log.append(SHARED, &dev(1), bytes);
        fixture.sync_from(&log, Delivery::InOrder).unwrap();
    }
    let mut replica = Replica::new_file(&file).unwrap();
    // Durability across a power cut is not under test, only across reopening.
    fast(&replica);
    replica.sync_from(&log, Delivery::InOrder).unwrap();
    assert_eq!(permitted(&replica, task), vec![rev(&task_v2())]);
    assert_eq!(plan(&replica, 100).ops.len(), 100);
    for _ in 0..3 {
        assert_eq!(migrate_batch(&mut replica, &mut log, 100), 100);
    }
    let on = |replica: &Replica, revision: RevisionId| -> i64 {
        replica
            .conn()
            .query_row(
                "SELECT count(*) FROM data_record WHERE revision=?1 AND accepted IS NOT NULL",
                [revision.0.as_slice()],
                |r| r.get(0),
            )
            .unwrap()
    };
    assert_eq!(on(&replica, rev(&task_v2())), 300);
    assert_eq!(on(&replica, rev(&task_v1())), 700);
    // Unmigrated records stay readable under their own revision.
    let page = query::run(
        replica.conn(),
        SHARED,
        &[SHARED],
        &Shipped,
        &Query {
            select: TypeSelect::Exact(task),
            filter: None,
            sort: vec![],
            fields: vec![path("/owner"), path("/status")],
            follow: vec![],
            text: None,
            limit: 200,
            after: Some(
                query::run(
                    replica.conn(),
                    SHARED,
                    &[SHARED],
                    &Shipped,
                    &Query {
                        select: TypeSelect::Exact(task),
                        filter: None,
                        sort: vec![],
                        fields: vec![],
                        follow: vec![],
                        text: None,
                        limit: 200,
                        after: None,
                    },
                    Budget::INTERACTIVE,
                )
                .unwrap()
                .next
                .unwrap(),
            ),
        },
        Budget::INTERACTIVE,
    )
    .unwrap();
    let revisions: Vec<_> = page.rows.iter().map(|r| r.revision).collect();
    assert!(revisions.contains(&rev(&task_v1())) && revisions.contains(&rev(&task_v2())));
    let old_row = page
        .rows
        .iter()
        .find(|r| r.revision == rev(&task_v1()))
        .unwrap();
    assert_eq!(old_row.values["/owner"], json!("sam"));

    // Interrupted: the replica closes and reopens, and the log is redelivered.
    drop(replica);
    let mut replica = Replica::new_file(&file).unwrap();
    fast(&replica);
    replica.sync_from(&log, Delivery::InOrder).unwrap();
    assert_eq!(on(&replica, rev(&task_v2())), 300);
    let mut batches = 0;
    while migrate_batch(&mut replica, &mut log, 100) > 0 {
        batches += 1;
    }
    assert_eq!(batches, 7);
    assert_eq!(on(&replica, rev(&task_v1())), 0);
    assert_eq!(on(&replica, rev(&task_v2())), 1_000);
    for n in [0u16, 1, 2, 999] {
        let row = row(&replica, rid(n));
        assert_eq!(row.revision, rev(&task_v2()));
        assert_eq!(
            row.accepted,
            Some(json!({
                "name": format!("Task {n}"),
                "status": if n % 3 == 0 { "complete" } else { "todo" },
                "priority": "normal",
                "owner": "sam",
            }))
        );
    }
    // A second replica that applies the same log reaches the same state.
    let mut other = Replica::new_in_memory().unwrap();
    other.sync_from(&log, Delivery::Duplicated).unwrap();
    assert_eq!(
        other.state_digest(SHARED).unwrap(),
        replica.state_digest(SHARED).unwrap()
    );
    // Migrated records are editable again under the new rules.
    let saved = replica
        .submit(
            SHARED,
            &dev(1),
            Operation::Edit {
                record: rid(5),
                revision: rev(&task_v2()),
                changes: vec![set("/priority", json!("high"))],
            },
        )
        .unwrap();
    log.append(SHARED, &dev(1), saved.payload);
    let synced = replica.sync_from(&log, Delivery::InOrder).unwrap();
    assert!(matches!(synced[0].1, Outcome::Accepted { .. }));
}

#[test]
fn migrate_requires_matching_from() {
    let mut world = World::new(2);
    world.define_tasks();
    let task = type_of(&task_v1());
    let (v1, v2) = (rev(&task_v1()), rev(&task_v2()));
    world.ok(&dev(1), create_task(rid(1), "One", "open"));
    world.ok(&dev(1), create_task(rid(2), "Two", "done"));
    world.ok(&dev(1), create_task(rid(3), "Three", "open"));
    world.ok(&dev(1), define(&task_v2()));
    let steps = bh_data::definition::parse(&task_v2())
        .unwrap()
        .evolution
        .migration_ops;
    assert!(matches!(
        steps[..],
        [
            Migration::RenameField { .. },
            Migration::MapEnum { .. },
            Migration::SetConstant { .. },
            Migration::DropField { .. }
        ]
    ));
    let doc = |world: &World, r: RecordId| row(&world.reps[0], r).accepted.unwrap();
    let migrate = |record: RecordId, from: RevisionId, doc: &Value| Operation::Migrate {
        record,
        from,
        to: v2,
        changes: evolve::changes(&steps, doc).unwrap(),
    };
    // Before the transition, the new revision is not permitted.
    let one = doc(&world, rid(1));
    assert_eq!(
        world.rejected(&job(4), migrate(rid(1), v1, &one)),
        RejectCode::RevisionNotPermitted
    );
    world.ok(
        &dev(1),
        Operation::Transition {
            type_id: task,
            to: v2,
        },
    );
    // `from` must be the record's revision.
    assert_eq!(
        world.rejected(&job(4), migrate(rid(1), v2, &one)),
        RejectCode::RevisionNotPermitted
    );
    // Every change the declared migration makes must be there, unaltered.
    let declared = evolve::changes(&steps, &one).unwrap();
    let forge = |changes: Vec<FieldChange>| Operation::Migrate {
        record: rid(1),
        from: v1,
        to: v2,
        changes,
    };
    let altered: Vec<_> = declared
        .iter()
        .map(|c| match c.path.as_pointer().as_str() {
            "/priority" => set("/priority", json!("high")),
            _ => c.clone(),
        })
        .collect();
    assert_eq!(world.rejected(&job(4), forge(altered)), RejectCode::Schema);
    assert_eq!(
        world.rejected(&job(4), forge(declared[1..].to_vec())),
        RejectCode::Schema
    );
    // Further changes must be declared paths.
    let mut undeclared = declared.clone();
    undeclared.push(set("/colour", json!("red")));
    assert_eq!(
        world.rejected(&job(4), forge(undeclared)),
        RejectCode::UnknownField
    );
    world.ok(&job(4), migrate(rid(1), v1, &one));
    // Migrating again: the record is no longer on `from`.
    assert_eq!(
        world.rejected(&job(4), migrate(rid(1), v1, &one)),
        RejectCode::RevisionNotPermitted
    );
    world.assert_converged();
    let migrated = row(&world.reps[0], rid(1));
    assert_eq!(migrated.revision, v2);
    assert_eq!(
        migrated.accepted,
        Some(json!({"name":"One","status":"todo","priority":"normal","owner":"sam"}))
    );
    // The other record is still on v1, readable, and refuses ordinary edits.
    assert_eq!(row(&world.reps[0], rid(2)).revision, v1);
    assert_eq!(
        world.rejected(
            &dev(1),
            Operation::Edit {
                record: rid(2),
                revision: v2,
                changes: vec![set("/owner", json!("kim"))],
            }
        ),
        RejectCode::RevisionNotPermitted
    );
    // Deleting an unmigrated record keeps its revision; undoing the deletion
    // restores it on that revision, as another record to migrate.
    let (deleted, outcome) = world.order_id(&dev(1), Operation::Delete { record: rid(3) });
    assert!(matches!(outcome, Outcome::Accepted { .. }), "{outcome:?}");
    assert_eq!(row(&world.reps[0], rid(3)).revision, v1);
    let restore = undo::prepare(world.reps[0].conn(), SHARED, deleted).unwrap();
    world.ok(&dev(1), restore);
    world.assert_converged();
    assert_eq!(row(&world.reps[0], rid(3)).revision, v1);
    let remaining = plan(&world.reps[0], 10);
    assert_eq!(
        remaining.ops,
        vec![
            migrate(rid(2), v1, &doc(&world, rid(2))),
            migrate(rid(3), v1, &doc(&world, rid(3)))
        ]
    );
    assert!(remaining.needs_manual.is_empty());
}

#[test]
fn migration_steps_are_part_of_the_definition_grammar() {
    let mut definition: Value = serde_json::from_slice(&task_v2()).unwrap();
    definition["evolution"]["migration_ops"] =
        json!([{"op":"rename","from":"/title","to":"/name"}]);
    let bytes = serde_json::to_vec(&definition).unwrap();
    assert!(bh_data::definition::parse(&bytes).is_err());
    let mut world = World::new(1);
    world.define_tasks();
    assert_eq!(world.rejected(&dev(1), define(&bytes)), RejectCode::Schema);
    // Planning needs the revision defined and transitioned to.
    let plan = |world: &World| {
        evolve::plan(
            world.reps[0].conn(),
            SHARED,
            &Shipped,
            type_of(&task_v1()),
            rev(&task_v2()),
            10,
        )
    };
    assert!(plan(&world).is_err());
    world.ok(&dev(1), define(&task_v2()));
    assert!(plan(&world).is_err());
    world.ok(
        &dev(1),
        Operation::Transition {
            type_id: type_of(&task_v1()),
            to: rev(&task_v2()),
        },
    );
    assert_eq!(
        plan(&world).unwrap(),
        evolve::Plan {
            ops: vec![],
            needs_manual: vec![]
        }
    );
    // A step that cannot apply to a document is an error, not a silent loss.
    let into_string = [Migration::RenameField {
        from: path("/title"),
        to: path("/legacy/title"),
    }];
    assert!(evolve::changes(&into_string, &json!({"title": "T", "legacy": "old"})).is_err());
    assert_eq!(
        evolve::changes(&into_string, &json!({"legacy": "old"})).unwrap(),
        vec![]
    );
}

#[test]
fn local_save_of_unmigrated_record_is_refused() {
    let mut world = World::new(1);
    world.define_tasks();
    world.ok(&dev(1), create_task(rid(1), "One", "open"));
    world.ok(&dev(1), define(&task_v2()));
    world.ok(
        &dev(1),
        Operation::Transition {
            type_id: type_of(&task_v1()),
            to: rev(&task_v2()),
        },
    );
    match world.reps[0].submit(
        SHARED,
        &dev(1),
        Operation::Edit {
            record: rid(1),
            revision: rev(&task_v2()),
            changes: vec![set("/owner", json!("kim"))],
        },
    ) {
        Err(SubmitError::Rejected(r)) => assert_eq!(r.code, RejectCode::RevisionNotPermitted),
        other => panic!("{other:?}"),
    }
}

#[test]
fn record_the_declared_steps_leave_invalid_is_reported_and_fixed_by_hand() {
    let mut world = World::new(2);
    world.define_tasks();
    let task = type_of(&task_v1());
    let (v1, v2) = (rev(&task_v1()), rev(&task_v2()));
    for n in 1..=5 {
        world.ok(&dev(1), create_task(rid(n), &format!("Task {n}"), "open"));
    }
    // v1 allows a long owner; v2 does not, and its steps leave owners alone.
    world.ok(
        &dev(1),
        Operation::Edit {
            record: rid(2),
            revision: v1,
            changes: vec![set("/owner", json!("a very long owner name"))],
        },
    );
    world.ok(&dev(1), define(&task_v2()));
    world.ok(
        &dev(1),
        Operation::Transition {
            type_id: task,
            to: v2,
        },
    );
    let planned = plan(&world.reps[0], 10);
    assert_eq!(planned.needs_manual, vec![rid(2)]);
    assert_eq!(planned.ops.len(), 4);
    for op in planned.ops {
        world.ok(&job(4), op);
    }
    // The record left behind does not stop later planning reaching others.
    let again = plan(&world.reps[0], 10);
    assert_eq!(again.ops, vec![]);
    assert_eq!(again.needs_manual, vec![rid(2)]);
    // The declared changes alone leave it invalid; with a hand fix of a
    // direct field, the same migration is accepted.
    let doc = row(&world.reps[0], rid(2)).accepted.unwrap();
    let steps = bh_data::definition::parse(&task_v2())
        .unwrap()
        .evolution
        .migration_ops;
    let mut changes = evolve::changes(&steps, &doc).unwrap();
    let migrate = |changes: Vec<FieldChange>| Operation::Migrate {
        record: rid(2),
        from: v1,
        to: v2,
        changes,
    };
    assert_eq!(
        world.rejected(&job(4), migrate(changes.clone())),
        RejectCode::Schema
    );
    changes.push(set("/owner", json!("kim")));
    world.ok(&job(4), migrate(changes));
    world.assert_converged();
    let fixed = row(&world.reps[0], rid(2));
    assert_eq!(fixed.revision, v2);
    assert_eq!(
        fixed.accepted,
        Some(json!({"name":"Task 2","status":"todo","priority":"normal","owner":"kim"}))
    );
    assert_eq!(
        plan(&world.reps[0], 10),
        evolve::Plan {
            ops: vec![],
            needs_manual: vec![]
        }
    );
}

#[test]
fn delete_uses_both_current_and_retired_record_policies() {
    // Neither the older nor the newer revision can remove the other's guard.
    for (old_policy, new_policy) in [("action", "direct"), ("direct", "action")] {
        let mut world = World::new(2);
        world.ok(&dev(1), define_app());
        let mut first: Value = serde_json::from_slice(&task_v1()).unwrap();
        first["fields"]["/status"]["write"] = json!(old_policy);
        first["schema"]["required"] = json!(["title"]);
        let first = serde_json::to_vec(&first).unwrap();
        world.ok(&dev(1), define(&first));
        // The protected status is optional here; creating a record without it
        // exercises Delete's policy even when the field has no stored value.
        let record = rid(21);
        let ty = type_of(&first);
        let v1 = rev(&first);
        world.ok(
            &dev(1),
            Operation::Create {
                record,
                type_id: ty,
                revision: v1,
                doc: json!({"title":"One", "owner":"sam"}),
            },
        );
        let mut second: Value = serde_json::from_slice(&first).unwrap();
        second["fields"]["/status"]["write"] = json!(new_policy);
        second["evolution"]["previous"] = json!(v1);
        second["schema"]["required"] = json!(["title"]);
        let second = serde_json::to_vec(&second).unwrap();
        world.ok(&dev(1), define(&second));
        world.ok(
            &dev(1),
            Operation::Transition {
                type_id: ty,
                to: rev(&second),
            },
        );
        assert_eq!(row(&world.reps[0], record).revision, v1);
        let outcome = world.order(&dev(1), Operation::Delete { record });
        assert!(
            matches!(&outcome, Outcome::Rejected(r) if r.code == RejectCode::ActionOnly),
            "{old_policy} -> {new_policy}: {outcome:?}"
        );
        world.assert_converged();
    }
}

#[test]
fn delete_uses_both_policies_when_older_revision_is_still_permitted() {
    for (old_policy, new_policy) in [("action", "direct"), ("direct", "action")] {
        let mut world = World::new(2);
        world.ok(&dev(1), define_app());
        let mut first: Value = serde_json::from_slice(&task_v1()).unwrap();
        first["schema"]["required"] = json!(["title"]);
        first["fields"]["/status"]["write"] = json!(old_policy);
        let first = serde_json::to_vec(&first).unwrap();
        world.ok(&dev(1), define(&first));
        let ty = type_of(&first);
        let record = rid(22);
        world.ok(
            &dev(1),
            Operation::Create {
                record,
                type_id: ty,
                revision: rev(&first),
                doc: json!({"title":"One"}),
            },
        );
        let mut second: Value = serde_json::from_slice(&first).unwrap();
        second["fields"]["/status"]["write"] = json!(new_policy);
        second["evolution"]["previous"] = json!(rev(&first));
        let second = serde_json::to_vec(&second).unwrap();
        world.ok(&dev(1), define(&second));
        assert_eq!(current(&world.reps[0], ty), rev(&second));
        assert_eq!(
            permitted(&world.reps[0], ty),
            vec![rev(&first), rev(&second)]
        );
        assert_eq!(row(&world.reps[0], record).revision, rev(&first));
        assert_eq!(
            world.rejected(&dev(1), Operation::Delete { record }),
            RejectCode::ActionOnly
        );
        world.assert_converged();
    }
}

#[test]
fn delete_refuses_optional_derived_field_and_allows_plain_type() {
    for derived in [false, true] {
        let mut world = World::new(2);
        world.ok(&dev(1), define_app());
        let mut def: Value = serde_json::from_slice(&task_v1()).unwrap();
        if derived {
            def["schema"]["properties"]["computed"] = json!({"type":"string","maxLength":100});
            def["fields"]["/computed"] = json!({
                "meaning":"Calculated value", "kind":"string", "write":"derived"
            });
        }
        let bytes = serde_json::to_vec(&def).unwrap();
        world.ok(&dev(1), define(&bytes));
        let record = rid(23);
        world.ok(
            &dev(1),
            Operation::Create {
                record,
                type_id: type_of(&bytes),
                revision: rev(&bytes),
                doc: json!({"title":"One", "status":"open"}),
            },
        );
        let outcome = world.order(&dev(1), Operation::Delete { record });
        if derived {
            assert!(
                matches!(&outcome, Outcome::Rejected(r) if r.code == RejectCode::DerivedField && r.path.as_ref().is_some_and(|p| p.as_pointer() == "/computed")),
                "{outcome:?}"
            );
        } else {
            assert!(matches!(&outcome, Outcome::Accepted { .. }), "{outcome:?}");
        }
        world.assert_converged();
    }
}

#[test]
fn undo_of_deletion_after_transition_restores_an_unmigrated_record() {
    let mut world = World::new(2);
    world.define_tasks();
    let task = type_of(&task_v1());
    let (v1, v2) = (rev(&task_v1()), rev(&task_v2()));
    world.ok(&dev(1), create_task(rid(1), "One", "done"));
    let (deleted, outcome) = world.order_id(&dev(1), Operation::Delete { record: rid(1) });
    assert!(matches!(outcome, Outcome::Accepted { .. }), "{outcome:?}");
    world.ok(&dev(1), define(&task_v2()));
    world.ok(
        &dev(1),
        Operation::Transition {
            type_id: task,
            to: v2,
        },
    );
    assert_eq!(plan(&world.reps[0], 10).ops, vec![]);
    let restore = undo::prepare(world.reps[0].conn(), SHARED, deleted).unwrap();
    world.ok(&dev(1), restore);
    world.assert_converged();
    // Restored as it was, on v1 and under v1's rules, then migrated like any other.
    let restored = row(&world.reps[0], rid(1));
    assert_eq!(restored.revision, v1);
    assert_eq!(
        restored.accepted,
        Some(json!({"title":"One","status":"done","legacy":"old","owner":"sam"}))
    );
    let planned = plan(&world.reps[0], 10);
    assert_eq!(planned.ops.len(), 1);
    world.ok(&job(4), planned.ops[0].clone());
    world.assert_converged();
    let migrated = row(&world.reps[0], rid(1));
    assert_eq!(migrated.revision, v2);
    assert_eq!(
        migrated.accepted,
        Some(json!({"name":"One","status":"complete","priority":"normal","owner":"sam"}))
    );
}
