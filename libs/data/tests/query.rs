use bh_data::{
    AppId, CompiledType, CoreCatalogue, FieldKind, FieldPath, FieldSpec, IndexDecl, KeyRef,
    Position, RecordId, RevisionId, Scope, SearchMap, TypeDocs, TypeId, TypeKind, WritePolicy,
    index,
    query::*,
    store::{
        self, coverage,
        records::{self, RecordRow},
        registry,
    },
};
use rusqlite::Connection;
use serde_json::json;
fn ty(n: u8) -> TypeId {
    TypeId([n; 32])
}
fn id(n: u32) -> RecordId {
    let mut v = [0; 32];
    v[..4].copy_from_slice(&n.to_be_bytes());
    RecordId(v)
}
fn path(p: &str) -> FieldPath {
    FieldPath::parse(p).unwrap()
}
fn scope(n: u8) -> Scope {
    Scope {
        base: [1; 32],
        audience: [n; 32],
    }
}
struct Core;
impl CoreCatalogue for Core {
    fn core_type(&self, _: TypeId) -> Option<CompiledType> {
        None
    }
}
fn ct(n: u8, parent: Option<u8>) -> CompiledType {
    let mut lineage = vec![(ty(n), RevisionId([n; 32]))];
    if let Some(p) = parent {
        lineage.push((ty(p), RevisionId([p; 32])));
    }
    CompiledType {
        type_id: ty(n),
        revision: RevisionId([n; 32]),
        kind: TypeKind::Record,
        app: Some(AppId([1; 32])),
        name: "test".into(),
        lineage,
        effective_schema: json!({"type":"object"}),
        resources: vec![],
        fields: vec![],
        indexes: vec![],
        uniques: vec![],
        queries: vec![],
        search: SearchMap {
            title: None,
            text: vec![],
            builtin_body: false,
        },
        actions: vec![],
        builtin: None,
        previous: None,
        docs: TypeDocs {
            description: String::new(),
            rationale: vec![],
            examples_valid: vec![],
            examples_invalid: vec![],
            migration: None,
        },
    }
}
fn field(t: &mut CompiledType, p: &str, kind: FieldKind) {
    t.fields.push(FieldSpec {
        path: path(p),
        kind,
        write: WritePolicy::Direct,
        required: false,
        nullable: true,
        declared_by: ty(1),
        meaning: p.into(),
        unit: None,
        absent: None,
    });
}
fn conn() -> Connection {
    let mut c = Connection::open_in_memory().unwrap();
    let tx = c.transaction().unwrap();
    store::migrate(&tx).unwrap();
    tx.commit().unwrap();
    c
}
fn setup(types: &[CompiledType], s: Scope) -> (Connection, i64) {
    let mut c = conn();
    let tx = c.transaction().unwrap();
    let sid = records::scope_id(&tx, s, &Core).unwrap();
    for t in types {
        registry::store_definition(&tx, sid, t, b"type", Position(1)).unwrap();
        registry::set_current(&tx, sid, t.type_id, t.revision, &[t.revision], Position(1)).unwrap();
        index::ensure(&tx, sid, t).unwrap();
    }
    coverage::set(&tx, sid, Position(1), true).unwrap();
    tx.commit().unwrap();
    (c, sid)
}
fn put(c: &mut Connection, s: i64, t: &CompiledType, n: u32, doc: serde_json::Value) {
    let tx = c.transaction().unwrap();
    let mut r = RecordRow {
        id: 0,
        scope: s,
        record: id(n),
        type_id: t.type_id,
        revision: t.revision,
        accepted: Some(doc),
        doc: None,
        deleted: false,
        pending: false,
        changed_at: None,
        changed: 0,
        text_rev: 0,
    };
    records::put(&tx, &mut r).unwrap();
    index::on_record_changed(&tx, &r, t).unwrap();
    tx.commit().unwrap();
}
fn q(select: TypeSelect) -> Query {
    Query {
        select,
        filter: None,
        sort: vec![],
        fields: vec![path("/name")],
        follow: vec![],
        text: None,
        limit: 50,
        after: None,
    }
}
#[test]
fn numeric_changed_cursor_matches_query_keyset_and_rejects_other_shapes() {
    let mut t = ct(1, None);
    t.indexes.push(IndexDecl {
        name: "recent".into(),
        keys: vec![KeyRef::Changed],
        declared_by: t.type_id,
    });
    let s = scope(0);
    let (mut c, sid) = setup(&[t.clone()], s);
    for n in 1..=3 {
        put(&mut c, sid, &t, n, json!({}));
    }
    let mut query = q(TypeSelect::Exact(t.type_id));
    query.fields.clear();
    query.sort = vec![SortKey {
        key: KeyRef::Changed,
        desc: true,
    }];
    query.limit = 1;
    let first = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
    let row = &first.rows[0];
    let cursor =
        after_changed(&c, s, &[s], &Core, &query, row.changed.unwrap(), row.record).unwrap();
    assert_eq!(Some(cursor.clone()), first.next);
    query.after = Some(cursor);
    let second = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
    assert_eq!(second.rows[0].record, id(2));
    query.after = None;
    assert!(after_changed(&c, s, &[s], &Core, &query, -1, row.record).is_err());
    query.sort = vec![SortKey {
        key: KeyRef::Changed,
        desc: false,
    }];
    assert!(after_changed(&c, s, &[s], &Core, &query, 1, row.record).is_err());
}

#[test]
fn filter_sort_page_uses_index() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    t.indexes.push(IndexDecl {
        name: "by_name".into(),
        keys: vec![KeyRef::Field(path("/name"))],
        declared_by: t.type_id,
    });
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    for n in 1..=80 {
        put(&mut c, sid, &t, n, json!({"name":format!("n{n:03}")}));
    }
    let mut query = q(TypeSelect::Exact(t.type_id));
    query.sort.push(SortKey {
        key: KeyRef::Field(path("/name")),
        desc: false,
    });
    query.limit = 20;
    let first = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
    assert_eq!(first.rows.len(), 20);
    assert!(first.next.is_some());
    query.after = first.next;
    let second = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
    assert_eq!(second.rows[0].record, id(21));
}
#[test]
fn family_query_returns_specialisations_with_concrete_type() {
    let mut p = ct(1, None);
    field(&mut p, "/name", FieldKind::String);
    let mut child = ct(2, Some(1));
    field(&mut child, "/name", FieldKind::String);
    let s = scope(2);
    let (mut c, sid) = setup(&[p.clone(), child.clone()], s);
    put(&mut c, sid, &p, 1, json!({"name":"a"}));
    put(&mut c, sid, &child, 2, json!({"name":"b"}));
    let rows = run(
        &c,
        s,
        &[s],
        &Core,
        &q(TypeSelect::Family(ty(1))),
        Budget::INTERACTIVE,
    )
    .unwrap()
    .rows;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].type_id, ty(2));
    assert_eq!(
        run(
            &c,
            s,
            &[s],
            &Core,
            &q(TypeSelect::Exact(ty(1))),
            Budget::INTERACTIVE
        )
        .unwrap()
        .rows
        .len(),
        1
    );
}
#[test]
fn type_mismatch_across_family_errors() {
    let mut a = ct(1, None);
    field(&mut a, "/name", FieldKind::String);
    let mut b = ct(2, Some(1));
    field(&mut b, "/name", FieldKind::Integer);
    let s = scope(2);
    let (c, _) = setup(&[a, b], s);
    assert!(matches!(
        run(
            &c,
            s,
            &[s],
            &Core,
            &q(TypeSelect::Family(ty(1))),
            Budget::INTERACTIVE
        ),
        Err(QueryError::TypeMismatch(_))
    ));
}
#[test]
fn small_unindexed_falls_back() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    put(&mut c, sid, &t, 1, json!({"name":"a"}));
    let mut query = q(TypeSelect::Exact(t.type_id));
    query.sort.push(SortKey {
        key: KeyRef::Field(path("/name")),
        desc: false,
    });
    assert_eq!(
        run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .rows
            .len(),
        1
    );
}
#[test]
fn parked_gaps_name_scope_type_and_page_record() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    put(&mut c, sid, &t, 1, json!({"name":"one"}));
    c.execute(
        "INSERT INTO data_parked(scope,position,affects,holds) VALUES(?1,1,NULL,1)",
        [sid],
    )
    .unwrap();
    c.execute(
        "INSERT INTO data_parked(scope,position,affects,holds) VALUES(?1,2,?2,1)",
        rusqlite::params![sid, serde_json::to_string(&ty(1)).unwrap()],
    )
    .unwrap();
    c.execute(
        "INSERT INTO data_parked(scope,position,affects,holds) VALUES(?1,3,?2,1)",
        rusqlite::params![sid, serde_json::to_string(&id(1)).unwrap()],
    )
    .unwrap();
    let page = run(
        &c,
        s,
        &[s],
        &Core,
        &q(TypeSelect::Exact(ty(1))),
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(
        page.completeness,
        Completeness::Incomplete(vec![
            Gap::WaitingScope,
            Gap::WaitingType(ty(1)),
            Gap::WaitingRecord(id(1))
        ])
    );
}
#[test]
fn old_executable_unsupported_create_makes_only_its_type_incomplete() {
    use bh_data::{
        Actor, MutationId,
        catalogue::Shipped,
        mutation::ops::Operation,
        payload,
        testkit::{Delivery, OrderedLog, Replica},
    };
    let s = scope(2);
    let bytes = include_bytes!("fixtures/types/Article.json");
    let type_id = bh_data::definition::parse(bytes).unwrap().type_id;
    let actor = Actor::Device {
        account: [1; 32],
        device: [1; 32],
    };
    let mut log = OrderedLog::new();
    for op in [
        Operation::DefineApp {
            app: AppId([2; 32]),
            name: "Reader".into(),
        },
        Operation::DefineType {
            bytes: bytes.to_vec(),
        },
    ] {
        log.append(
            s,
            &actor,
            payload::encode(MutationId::random(), &op).unwrap(),
        );
    }
    let mut replica = Replica::new_in_memory().unwrap();
    replica.sync_from(&log, Delivery::InOrder).unwrap();
    replica.without_kinds(&["create"]);
    let op = Operation::Create {
        record: id(10),
        type_id,
        revision: RevisionId::of(bytes),
        doc: json!({"title":"future", "url":"https://example.test/future"}),
    };
    log.append(
        s,
        &actor,
        payload::encode(MutationId::random(), &op).unwrap(),
    );
    replica.sync_from(&log, Delivery::InOrder).unwrap();
    let query = |type_id| Query {
        select: TypeSelect::Exact(type_id),
        filter: None,
        sort: vec![],
        fields: vec![],
        follow: vec![],
        text: None,
        limit: 50,
        after: None,
    };
    let page = run(
        replica.conn(),
        s,
        &[s],
        &Shipped,
        &query(type_id),
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert!(page.rows.is_empty());
    assert_eq!(
        page.completeness,
        Completeness::Incomplete(vec![Gap::WaitingRecord(id(10))])
    );
    assert_eq!(
        run(
            replica.conn(),
            s,
            &[s],
            &Shipped,
            &query(TypeId::core("note")),
            Budget::INTERACTIVE
        )
        .unwrap()
        .completeness,
        Completeness::Complete
    );
}
#[test]
fn uniqueness_waiting_create_makes_empty_type_page_incomplete() {
    use bh_data::{
        Actor, MutationId, Wait,
        catalogue::Shipped,
        mutation::{apply::Outcome, ops::Operation},
        payload,
        testkit::{Delivery, OrderedLog, Replica},
    };
    let s = scope(2);
    let bytes = include_bytes!("fixtures/types/Article.json");
    let type_id = bh_data::definition::parse(bytes).unwrap().type_id;
    let actor = Actor::Device {
        account: [1; 32],
        device: [1; 32],
    };
    let mut log = OrderedLog::new();
    for op in [
        Operation::DefineApp {
            app: AppId([2; 32]),
            name: "Reader".into(),
        },
        Operation::DefineType {
            bytes: bytes.to_vec(),
        },
    ] {
        log.append(
            s,
            &actor,
            payload::encode(MutationId::random(), &op).unwrap(),
        );
    }
    let mut replica = Replica::new_in_memory().unwrap();
    replica.sync_from(&log, Delivery::InOrder).unwrap();
    replica.hold_backfill();
    replica
        .conn()
        .execute("UPDATE data_index SET state='building' WHERE unique_=1", [])
        .unwrap();
    let op = Operation::Create {
        record: id(11),
        type_id,
        revision: RevisionId::of(bytes),
        doc: json!({"title":"pending","url":"https://example.test/pending"}),
    };
    log.append(
        s,
        &actor,
        payload::encode(MutationId::random(), &op).unwrap(),
    );
    let outcomes = replica.sync_from(&log, Delivery::InOrder).unwrap();
    assert!(
        matches!(
            outcomes.last(),
            Some((_, Outcome::Waiting(Wait::UniquenessUnknown(_))))
        ),
        "{outcomes:?}"
    );
    let query = |type_id| Query {
        select: TypeSelect::Exact(type_id),
        filter: None,
        sort: vec![],
        fields: vec![],
        follow: vec![],
        text: None,
        limit: 50,
        after: None,
    };
    let page = run(
        replica.conn(),
        s,
        &[s],
        &Shipped,
        &query(type_id),
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert!(page.rows.is_empty());
    assert_eq!(
        page.completeness,
        Completeness::Incomplete(vec![Gap::WaitingType(type_id)])
    );
    assert_eq!(
        run(
            replica.conn(),
            s,
            &[s],
            &Shipped,
            &query(TypeId::core("note")),
            Budget::INTERACTIVE
        )
        .unwrap()
        .completeness,
        Completeness::Complete
    );
}
#[test]
fn off_page_record_waits_affect_only_the_selected_type() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    let mut u = ct(2, None);
    field(&mut u, "/name", FieldKind::String);
    let s = scope(2);
    let (mut c, sid) = setup(&[t, u], s);
    put(&mut c, sid, &ct(1, None), 1, json!({"name":"visible"}));
    // A queued Create and an unsupported future Create both have record keys,
    // but neither record can appear on the page before replay.
    for (position, record, type_id) in [(1, id(10), Some(ty(1))), (2, id(11), Some(ty(1)))] {
        c.execute(
            "INSERT INTO data_parked(scope,position,affects,type,record,holds) VALUES(?1,?2,?3,?4,?5,1)",
            rusqlite::params![sid, position, format!("r:{record:?}"), type_id.map(|t| t.0.to_vec()), record.0.as_slice()],
        ).unwrap();
    }
    let page = run(
        &c,
        s,
        &[s],
        &Core,
        &q(TypeSelect::Exact(ty(1))),
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(
        page.completeness,
        Completeness::Incomplete(vec![Gap::WaitingRecord(id(10)), Gap::WaitingRecord(id(11))])
    );
    assert_eq!(
        run(
            &c,
            s,
            &[s],
            &Core,
            &q(TypeSelect::Exact(ty(2))),
            Budget::INTERACTIVE
        )
        .unwrap()
        .completeness,
        Completeness::Complete
    );
    c.execute("UPDATE data_parked SET type=NULL WHERE position=2", [])
        .unwrap();
    assert!(
        matches!(run(&c, s, &[s], &Core, &q(TypeSelect::Exact(ty(2))), Budget::INTERACTIVE).unwrap().completeness, Completeness::Incomplete(gaps) if gaps.contains(&Gap::WaitingRecord(id(11))))
    );
}
#[test]
#[ignore = "run with scripts/check.sh data-scale (release)"]
fn unrelated_type_stays_complete_with_many_parked_record_creates() {
    let s = scope(2);
    let (mut c, sid) = setup(&[ct(1, None), ct(2, None)], s);
    let tx = c.transaction().unwrap();
    for n in 1..=200 {
        let record = id(n);
        tx.execute("INSERT INTO data_parked(scope,position,affects,type,record,holds) VALUES(?1,?2,'r:future',?3,?4,1)", rusqlite::params![sid,n,ty(1).0.as_slice(),record.0.as_slice()]).unwrap();
    }
    tx.commit().unwrap();
    let mut query = q(TypeSelect::Exact(ty(2)));
    query.fields.clear();
    let steps = |conn: &Connection| {
        let mut budget = 1_000;
        loop {
            match run(conn, s, &[s], &Core, &query, Budget { vm_steps: budget }) {
                Ok(page) => {
                    assert_eq!(page.completeness, Completeness::Complete);
                    return budget;
                }
                Err(QueryError::TooCostly { .. }) if budget < 1_000_000 => budget *= 2,
                other => panic!("unexpected parked-query result at {budget} steps: {other:?}"),
            }
        }
    };
    let small = steps(&c);
    let tx = c.transaction().unwrap();
    for n in 201..=20_000 {
        let record = id(n);
        tx.execute("INSERT INTO data_parked(scope,position,affects,type,record,holds) VALUES(?1,?2,'r:future',?3,?4,1)", rusqlite::params![sid,n,ty(1).0.as_slice(),record.0.as_slice()]).unwrap();
    }
    tx.commit().unwrap();
    let large = steps(&c);
    assert!(
        large * 2 <= small * 3,
        "unrelated parked rows grew from {small} to {large} VM steps"
    );
}
#[test]
fn parked_type_branches_seek_by_scope_and_type() {
    let s = scope(2);
    let (c, sid) = setup(&[ct(1, None), ct(2, None)], s);
    let sql = "SELECT position,affects,type,record FROM (SELECT position,affects,type,record FROM data_parked INDEXED BY data_parked_type WHERE scope=?1 AND type IS NULL LIMIT 501) UNION ALL SELECT position,affects,type,record FROM (SELECT position,affects,type,record FROM data_parked INDEXED BY data_parked_type WHERE scope=?1 AND type IN (?2) LIMIT 501) LIMIT 501";
    let detail = c
        .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
        .unwrap()
        .query_map(rusqlite::params![sid, ty(2).0.as_slice()], |r| {
            r.get::<_, String>(3)
        })
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    assert_eq!(
        detail.iter().filter(|line| line.contains("type=?")).count(),
        2,
        "{detail:?}"
    );
}
#[test]
fn query_json_uses_default_limit_and_optional_fields() {
    let error = QueryError::NotQueryable {
        path: Some(path("/name")),
        detail: "not indexed".into(),
    };
    let json = serde_json::to_value(&error).unwrap();
    assert_eq!(
        json,
        json!({"NotQueryable":{"path":"/name","detail":"not indexed"}})
    );
    assert_eq!(serde_json::from_value::<QueryError>(json).unwrap(), error);
    let value = json!({"select":{"Exact":ty(1)}});
    let decoded: Query = serde_json::from_value(value).unwrap();
    assert_eq!(decoded.limit, 50);
    assert!(decoded.filter.is_none() && decoded.after.is_none() && decoded.text.is_none());
}
#[test]
fn unknown_field_errors() {
    let t = ct(1, None);
    let s = scope(2);
    let (c, _) = setup(std::slice::from_ref(&t), s);
    assert!(matches!(
        run(
            &c,
            s,
            &[s],
            &Core,
            &q(TypeSelect::Exact(t.type_id)),
            Budget::INTERACTIVE
        ),
        Err(QueryError::UnknownField(_))
    ));
}
#[test]
fn quoted_field_path_is_parameter_safe() {
    let mut t = ct(1, None);
    field(&mut t, "/owner's name", FieldKind::String);
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    put(&mut c, sid, &t, 1, json!({"owner's name":"normal"}));
    let mut query = q(TypeSelect::Exact(ty(1)));
    query.fields = vec![path("/owner's name")];
    query.filter = Some(Expr::Cmp {
        path: path("/owner's name"),
        op: CmpOp::Eq,
        value: json!("normal"),
    });
    assert_eq!(
        run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .rows
            .len(),
        1
    );
}
#[test]
fn keyset_paging_with_null_sort_values_and_ties() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    t.indexes.push(IndexDecl {
        name: "sort".into(),
        keys: vec![KeyRef::Field(path("/name"))],
        declared_by: t.type_id,
    });
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    for (n, doc) in [
        (5, json!({"name":"z"})),
        (4, json!({"name":"same"})),
        (3, json!({"name":"same"})),
        (2, json!({})),
        (1, json!({})),
    ] {
        put(&mut c, sid, &t, n, doc);
    }
    let mut query = q(TypeSelect::Exact(t.type_id));
    query.sort = vec![SortKey {
        key: KeyRef::Field(path("/name")),
        desc: false,
    }];
    query.limit = 1;
    let mut got = vec![];
    loop {
        let page = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
        got.extend(page.rows.iter().map(|r| r.record));
        if page.next.is_none() {
            break;
        }
        query.after = page.next;
    }
    assert_eq!(got, (1..=5).map(id).collect::<Vec<_>>());
    query.after = None;
    query.sort[0].desc = true;
    let mut got = vec![];
    loop {
        let page = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
        got.extend(page.rows.iter().map(|r| r.record));
        if page.next.is_none() {
            break;
        }
        query.after = page.next;
    }
    assert_eq!(got, [id(5), id(4), id(3), id(2), id(1)]);
    query.after = None;
    query.sort.clear();
    query.limit = 50;
    query.filter = Some(Expr::In {
        path: path("/name"),
        values: vec![serde_json::Value::Null],
    });
    assert_eq!(
        run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .rows
            .len(),
        2
    );
}
#[test]
fn keyset_paging_multiple_keys_and_null_ties() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    field(&mut t, "/amount", FieldKind::Integer);
    t.indexes.push(IndexDecl {
        name: "multi".into(),
        keys: vec![KeyRef::Field(path("/name")), KeyRef::Field(path("/amount"))],
        declared_by: t.type_id,
    });
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    for (n, doc) in [
        (5, json!({"name":"a","amount":2})),
        (4, json!({"name":"a","amount":1})),
        (3, json!({"name":"a","amount":1})),
        (2, json!({"amount":2})),
        (1, json!({"amount":1})),
    ] {
        put(&mut c, sid, &t, n, doc);
    }
    let mut query = q(TypeSelect::Exact(ty(1)));
    query.sort = vec![
        SortKey {
            key: KeyRef::Field(path("/name")),
            desc: false,
        },
        SortKey {
            key: KeyRef::Field(path("/amount")),
            desc: false,
        },
    ];
    query.limit = 1;
    let mut got = vec![];
    loop {
        let page = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
        got.extend(page.rows.iter().map(|r| r.record));
        if page.next.is_none() {
            break;
        }
        query.after = page.next;
    }
    assert_eq!(got, [id(1), id(2), id(3), id(4), id(5)]);
    query.after = None;
    query.sort[1].desc = true;
    let mut got = vec![];
    loop {
        let page = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
        got.extend(page.rows.iter().map(|r| r.record));
        if page.next.is_none() {
            break;
        }
        query.after = page.next;
    }
    assert_eq!(got, [id(2), id(1), id(5), id(3), id(4)]);
}
#[test]
fn parked_target_affects_follow_and_negative_via_and_text() {
    let mut article = ct(1, None);
    field(&mut article, "/name", FieldKind::String);
    let mut selection = ct(2, None);
    field(
        &mut selection,
        "/target",
        FieldKind::Reference(bh_data::model::RefSpec {
            targets: vec![article.type_id],
            family: false,
        }),
    );
    let s = scope(0);
    let (mut c, sid) = setup(&[article.clone(), selection.clone()], s);
    put(&mut c, sid, &article, 1, json!({"name":"old"}));
    put(
        &mut c,
        sid,
        &selection,
        2,
        json!({"target":{"record":id(1)}}),
    );
    let op = bh_data::mutation::ops::Operation::Edit {
        record: id(1),
        revision: article.revision,
        changes: vec![bh_data::mutation::ops::FieldChange {
            path: path("/name"),
            value: Some(json!("new")),
        }],
    };
    let mut bytes = bh_data::payload::encode(bh_data::MutationId::random(), &op).unwrap();
    bytes[0] = 255;
    let tx = c.transaction().unwrap();
    bh_data::mutation::apply::apply_payload(
        &tx,
        &Core,
        s,
        Position(2),
        &bh_data::Actor::Device {
            account: [1; 32],
            device: [1; 32],
        },
        &bytes,
    )
    .unwrap();
    tx.commit().unwrap();
    let mut query = q(TypeSelect::Exact(selection.type_id));
    query.fields.clear();
    query.follow = vec![Follow {
        path: path("/target"),
        fields: vec![path("/name")],
    }];
    assert!(matches!(
        run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .completeness,
        Completeness::Incomplete(_)
    ));
    query.follow.clear();
    query.filter = Some(Expr::Via {
        path: path("/target"),
        filter: Box::new(Expr::Cmp {
            path: path("/name"),
            op: CmpOp::Eq,
            value: json!("new"),
        }),
    });
    let page = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
    assert!(page.rows.is_empty());
    assert!(matches!(page.completeness, Completeness::Incomplete(_)));
    query.filter = None;
    query.text = Some(TextMatch {
        terms: "new".into(),
        on: Some(path("/target")),
        require_revision: None,
    });
    let page = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
    assert!(page.rows.is_empty());
    assert!(matches!(page.completeness, Completeness::Incomplete(_)));
}
#[test]
fn follow_returns_referenced_fields_and_none_for_missing() {
    let mut article = ct(1, None);
    field(&mut article, "/name", FieldKind::String);
    let mut selection = ct(2, None);
    field(&mut selection, "/name", FieldKind::String);
    field(
        &mut selection,
        "/article",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![article.type_id],
            family: false,
        }),
    );
    let s = scope(2);
    let (mut c, sid) = setup(&[article.clone(), selection.clone()], s);
    put(&mut c, sid, &article, 1, json!({"name":"yes"}));
    put(
        &mut c,
        sid,
        &selection,
        2,
        json!({"name":"link","article":bh_data::RecordRef{audience:None,record:id(1)}}),
    );
    put(
        &mut c,
        sid,
        &selection,
        3,
        json!({"name":"broken","article":bh_data::RecordRef{audience:None,record:id(99)}}),
    );
    let mut query = q(TypeSelect::Exact(selection.type_id));
    query.follow.push(Follow {
        path: path("/article"),
        fields: vec![path("/name")],
    });
    let rows = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE)
        .unwrap()
        .rows;
    assert_eq!(
        rows[0].follows["/article"].as_ref().unwrap().values["/name"],
        json!("yes")
    );
    assert!(rows[1].follows["/article"].is_none());
}
#[test]
fn refers_to_uses_ref_table_and_shared_scope_hides_private_backlinks() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    field(
        &mut t,
        "/link",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: false,
        }),
    );
    let shared = scope(2);
    let private = scope(3);
    let (mut c, ss) = setup(&[t.clone()], shared);
    let ps = {
        let tx = c.transaction().unwrap();
        let ps = records::scope_id(&tx, private, &Core).unwrap();
        registry::store_definition(&tx, ps, &t, b"type", Position(1)).unwrap();
        registry::set_current(&tx, ps, t.type_id, t.revision, &[t.revision], Position(1)).unwrap();
        tx.commit().unwrap();
        ps
    };
    put(
        &mut c,
        ps,
        &t,
        3,
        json!({"name":"secret","link":bh_data::RecordRef{audience:Some(shared.audience),record:id(1)}}),
    );
    let mut query = q(TypeSelect::Exact(t.type_id));
    query.filter = Some(Expr::RefersTo {
        path: path("/link"),
        target: bh_data::RecordRef {
            audience: None,
            record: id(1),
        },
    });
    assert!(
        run(&c, shared, &[shared], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .rows
            .is_empty()
    );
    let counts = aggregate(
        &c,
        shared,
        &[shared],
        &Core,
        &Aggregate {
            select: TypeSelect::Exact(ty(1)),
            filter: query.filter.clone(),
            group_by: None,
            measures: vec![Measure::Count],
            max_groups: 1000,
        },
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(counts.groups[0].values, vec![json!(0)]);
    put(
        &mut c,
        ss,
        &t,
        2,
        json!({"name":"visible","link":bh_data::RecordRef{audience:None,record:id(1)}}),
    );
    assert_eq!(
        run(&c, shared, &[shared], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .rows
            .len(),
        1
    );

    for n in [5, 4] {
        put(
            &mut c,
            ss,
            &t,
            n,
            json!({"name":"visible","link":{"record":id(1)}}),
        );
    }
    for sorted in [false, true] {
        query.sort = if sorted {
            vec![SortKey {
                key: KeyRef::Field(path("/name")),
                desc: false,
            }]
        } else {
            vec![]
        };
        query.limit = 1;
        query.after = None;
        let mut got = vec![];
        loop {
            let page = run(&c, shared, &[shared], &Core, &query, Budget::INTERACTIVE).unwrap();
            got.extend(page.rows.iter().map(|r| r.record));
            let Some(next) = page.next else { break };
            query.after = Some(next);
        }
        assert_eq!(got, vec![id(2), id(4), id(5)]);
    }
}
#[test]
fn refers_to_in_boolean_expression_preserves_result() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    field(
        &mut t,
        "/link",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: false,
        }),
    );
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    put(
        &mut c,
        sid,
        &t,
        1,
        json!({"name":"linked","link":bh_data::RecordRef{audience:None,record:id(100)}}),
    );
    put(&mut c, sid, &t, 2, json!({"name":"other"}));
    let refers = Expr::RefersTo {
        path: path("/link"),
        target: bh_data::RecordRef {
            audience: None,
            record: id(100),
        },
    };
    let mut query = q(TypeSelect::Exact(ty(1)));
    query.filter = Some(Expr::Or(vec![
        refers.clone(),
        Expr::Cmp {
            path: path("/name"),
            op: CmpOp::Eq,
            value: json!("other"),
        },
    ]));
    assert_eq!(
        run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .rows
            .len(),
        2
    );
    query.filter = Some(Expr::Not(Box::new(refers)));
    assert_eq!(
        run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .rows[0]
            .record,
        id(2)
    );
}
fn bulk(c: &mut Connection, s: i64, t: &CompiledType, from: u32, to: u32) {
    let tx = c.transaction().unwrap();
    for n in from..=to {
        let mut r = RecordRow {
            id: 0,
            scope: s,
            record: id(n),
            type_id: t.type_id,
            revision: t.revision,
            accepted: Some(json!({"name":format!("name-{n:06}"),"amount":n})),
            doc: None,
            deleted: false,
            pending: false,
            changed_at: None,
            changed: 0,
            text_rev: 0,
        };
        records::put(&tx, &mut r).unwrap();
        index::on_record_changed(&tx, &r, t).unwrap();
    }
    tx.commit().unwrap();
}
#[test]
fn pending_doc_is_visible_and_unsupported_revision_is_incomplete() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    put(&mut c, sid, &t, 1, json!({"name":"accepted"}));
    let tx = c.transaction().unwrap();
    let mut row = records::get(&tx, sid, id(1)).unwrap().unwrap();
    row.pending = true;
    row.doc = Some(json!({"name":"draft"}));
    row.revision = RevisionId([8; 32]);
    records::put(&tx, &mut row).unwrap();
    index::on_record_changed(&tx, &row, &t).unwrap();
    tx.commit().unwrap();
    let page = run(
        &c,
        s,
        &[s],
        &Core,
        &q(TypeSelect::Exact(ty(1))),
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(page.rows[0].values["/name"], json!("draft"));
    assert!(page.rows[0].pending);
    assert_eq!(
        page.completeness,
        Completeness::Incomplete(vec![Gap::UnsupportedType(ty(1))])
    );
}
#[test]
fn empty_text_terms_are_rejected_and_budget_is_enforced() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    bulk(&mut c, sid, &t, 1, 1000);
    let mut query = q(TypeSelect::Exact(ty(1)));
    query.text = Some(TextMatch {
        terms: "".into(),
        on: None,
        require_revision: None,
    });
    assert!(
        matches!(run(&c,s,&[s],&Core,&query,Budget::INTERACTIVE),Err(QueryError::NotQueryable{path:None,detail}) if detail.contains("word term"))
    );
    query.text = None;
    query.sort.push(SortKey {
        key: KeyRef::Field(path("/name")),
        desc: false,
    });
    assert!(matches!(
        run(&c, s, &[s], &Core, &query, Budget { vm_steps: 0 }),
        Err(QueryError::TooCostly { .. })
    ));
}
#[test]
fn unindexed_large_sort_is_too_costly_and_mixed_direction_rejected() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    field(&mut t, "/amount", FieldKind::Integer);
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    bulk(&mut c, sid, &t, 1, 3000);
    let mut query = q(TypeSelect::Exact(ty(1)));
    query.sort.push(SortKey {
        key: KeyRef::Field(path("/name")),
        desc: false,
    });
    assert!(matches!(
        run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE),
        Err(QueryError::TooCostly { .. } | QueryError::IndexBuilding { .. })
    ));
    query.sort.push(SortKey {
        key: KeyRef::Field(path("/amount")),
        desc: true,
    });
    assert!(matches!(
        run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE),
        Err(QueryError::NotQueryable { .. })
    ));
    query.sort.pop();
    t.indexes.push(IndexDecl {
        name: "by_name".into(),
        keys: vec![KeyRef::Field(path("/name"))],
        declared_by: t.type_id,
    });
    let tx = c.transaction().unwrap();
    let ix = index::ensure(&tx, sid, &t).unwrap()[0];
    assert_eq!(index::state(&tx, ix).unwrap().state, "building");
    tx.commit().unwrap();
    assert!(matches!(
        run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE),
        Err(QueryError::IndexBuilding { index, .. }) if index=="by_name"
    ));
}
#[test]
fn via_filter_on_referenced_field_uses_index() {
    let mut article = ct(1, None);
    field(&mut article, "/name", FieldKind::String);
    field(&mut article, "/published", FieldKind::Integer);
    article.indexes.push(IndexDecl {
        name: "published".into(),
        keys: vec![KeyRef::Field(path("/published"))],
        declared_by: article.type_id,
    });
    let mut sel = ct(2, None);
    field(&mut sel, "/name", FieldKind::String);
    field(
        &mut sel,
        "/article",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: false,
        }),
    );
    let s = scope(2);
    let (mut c, sid) = setup(&[article.clone(), sel.clone()], s);
    put(
        &mut c,
        sid,
        &article,
        1,
        json!({"name":"old","published":1}),
    );
    put(
        &mut c,
        sid,
        &article,
        2,
        json!({"name":"new","published":10}),
    );
    for n in 1..=2 {
        put(
            &mut c,
            sid,
            &sel,
            n + 10,
            json!({"name":format!("selection-{n}"),"article":bh_data::RecordRef{audience:None,record:id(n)}}),
        );
    }
    let mut query = q(TypeSelect::Exact(sel.type_id));
    query.filter = Some(Expr::Via {
        path: path("/article"),
        filter: Box::new(Expr::Cmp {
            path: path("/published"),
            op: CmpOp::Ge,
            value: json!(5),
        }),
    });
    assert_eq!(
        run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .rows[0]
            .record,
        id(12)
    );
}
#[test]
fn follow_into_unreadable_audience_is_none() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    field(
        &mut t,
        "/link",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: false,
        }),
    );
    let shared = scope(2);
    let private = scope(3);
    let (mut c, sid) = setup(&[t.clone()], shared);
    put(
        &mut c,
        sid,
        &t,
        1,
        json!({"name":"shared","link":bh_data::RecordRef{audience:Some(private.audience),record:id(2)}}),
    );
    let mut query = q(TypeSelect::Exact(ty(1)));
    query.follow.push(Follow {
        path: path("/link"),
        fields: vec![path("/name")],
    });
    let rows = run(&c, shared, &[shared], &Core, &query, Budget::INTERACTIVE)
        .unwrap()
        .rows;
    assert!(rows[0].follows["/link"].is_none());
}
#[test]
fn local_index_serves_consumer_query() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    let tx = c.transaction().unwrap();
    index::ensure_local(&tx, sid, ty(1), vec![KeyRef::Field(path("/name"))]).unwrap();
    tx.commit().unwrap();
    put(&mut c, sid, &t, 1, json!({"name":"first"}));
    let mut query = q(TypeSelect::Exact(ty(1)));
    query.sort.push(SortKey {
        key: KeyRef::Field(path("/name")),
        desc: false,
    });
    assert_eq!(
        run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .rows
            .len(),
        1
    );
}
// Sparse matches must seek, not walk unrelated records in logical-ID order.
fn sparse_fixture(composite: bool) -> (Connection, i64, CompiledType, Scope) {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    field(&mut t, "/amount", FieldKind::Integer);
    let mut keys = vec![KeyRef::Field(path("/name"))];
    if composite {
        keys.push(KeyRef::Field(path("/amount")));
    }
    t.indexes.push(IndexDecl {
        name: "sparse".into(),
        keys,
        declared_by: t.type_id,
    });
    let s = scope(2);
    let (c, sid) = setup(&[t.clone()], s);
    (c, sid, t, s)
}
fn sparse_rows(c: &mut Connection, sid: i64, t: &CompiledType, start: u32, end: u32) {
    let tx = c.transaction().unwrap();
    for n in (start..=end).rev() {
        let mut row = RecordRow {
            id: 0,
            scope: sid,
            record: id(n),
            type_id: t.type_id,
            revision: t.revision,
            accepted: Some(json!({"name": if n == 1 {"rare"} else {"common"}, "amount": n})),
            doc: None,
            deleted: false,
            pending: false,
            changed_at: None,
            changed: 0,
            text_rev: 0,
        };
        records::put(&tx, &mut row).unwrap();
        index::on_record_changed(&tx, &row, t).unwrap();
    }
    tx.commit().unwrap();
}
fn rare_filter(op: CmpOp) -> Expr {
    Expr::Cmp {
        path: path("/name"),
        op,
        value: json!("rare"),
    }
}
#[test]
#[ignore = "run with scripts/check.sh data-scale (release)"]
fn sparse_equality_page_seeks_at_2k_and_20k() {
    let (mut c, sid, t, s) = sparse_fixture(false);
    let mut query = q(TypeSelect::Exact(t.type_id));
    query.filter = Some(rare_filter(CmpOp::Eq));
    for (start, end) in [(1, 2000), (2001, 20000)] {
        sparse_rows(&mut c, sid, &t, start, end);
        let page = run(&c, s, &[s], &Core, &query, Budget { vm_steps: 5000 }).unwrap();
        assert_eq!(
            page.rows.iter().map(|r| r.record).collect::<Vec<_>>(),
            vec![id(1)]
        );
        assert!(page.next.is_none());
        assert_eq!(page.completeness, Completeness::Complete);
    }
}
#[test]
#[ignore = "run with scripts/check.sh data-scale (release)"]
fn sparse_aggregates_seek_equality_and_partial_composite_ranges() {
    for composite in [false, true] {
        let (mut c, sid, t, s) = sparse_fixture(composite);
        for (start, end) in [(1, 2000), (2001, 20000)] {
            sparse_rows(&mut c, sid, &t, start, end);
            for op in [CmpOp::Eq, CmpOp::Ge] {
                let a = Aggregate {
                    select: TypeSelect::Exact(t.type_id),
                    filter: Some(rare_filter(op)),
                    group_by: None,
                    measures: vec![Measure::Count, Measure::Sum(path("/amount"))],
                    max_groups: 1,
                };
                let result = aggregate(&c, s, &[s], &Core, &a, Budget { vm_steps: 5000 }).unwrap();
                assert_eq!(result.groups[0].values, vec![json!(1), json!(1)]);
                assert_eq!(result.completeness, Completeness::Complete);
            }
        }
    }
}
#[test]
fn equality_bound_composite_page_and_family_keep_logical_order() {
    let (mut c, sid, parent, s) = sparse_fixture(true);
    let mut child = parent.clone();
    child.type_id = ty(2);
    child.revision = RevisionId([2; 32]);
    child.lineage.insert(0, (child.type_id, child.revision));
    let tx = c.transaction().unwrap();
    registry::store_definition(&tx, sid, &child, b"child", Position(1)).unwrap();
    registry::set_current(
        &tx,
        sid,
        child.type_id,
        child.revision,
        &[child.revision],
        Position(1),
    )
    .unwrap();
    index::ensure(&tx, sid, &child).unwrap();
    tx.commit().unwrap();
    for (t, n) in [(&child, 1), (&parent, 4), (&child, 2), (&parent, 3)] {
        put(&mut c, sid, t, n, json!({"name":"rare", "amount":2}));
    }
    let mut query = q(TypeSelect::Exact(parent.type_id));
    query.filter = Some(Expr::And(vec![
        rare_filter(CmpOp::Eq),
        Expr::Cmp {
            path: path("/amount"),
            op: CmpOp::Eq,
            value: json!(2),
        },
    ]));
    query.limit = 1;
    assert_eq!(all_pages(&c, s, &query), vec![id(3), id(4)]);
    query.select = TypeSelect::Family(parent.type_id);
    assert_eq!(all_pages(&c, s, &query), vec![id(3), id(4), id(1), id(2)]);
    for (select, count, sum) in [
        (TypeSelect::Exact(parent.type_id), 2, 4),
        (TypeSelect::Family(parent.type_id), 4, 8),
    ] {
        let a = Aggregate {
            select,
            filter: Some(rare_filter(CmpOp::Eq)),
            group_by: None,
            measures: vec![Measure::Count, Measure::Sum(path("/amount"))],
            max_groups: 1,
        };
        let result = aggregate(&c, s, &[s], &Core, &a, Budget::INTERACTIVE).unwrap();
        assert_eq!(result.groups[0].values, vec![json!(count), json!(sum)]);
        assert!(matches!(
            aggregate(&c, s, &[], &Core, &a, Budget::INTERACTIVE),
            Err(QueryError::NotQueryable { .. })
        ));
        let tx = c.transaction().unwrap();
        coverage::set(&tx, sid, Position(1), false).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            aggregate(&c, s, &[s], &Core, &a, Budget::INTERACTIVE)
                .unwrap()
                .completeness,
            Completeness::Incomplete(vec![Gap::NotCovered])
        );
    }
}
#[test]
fn aggregate_rejects_unsafe_sum_before_json_rounding() {
    for values in [
        [json!(9_007_199_254_740_991i64), json!(2)],
        [json!(-9_007_199_254_740_991i64), json!(-2)],
        [json!(9_007_199_254_740_990i64), json!(1.5)],
        [json!(-9_007_199_254_740_990i64), json!(-1.5)],
    ] {
        let mut t = ct(1, None);
        field(&mut t, "/amount", FieldKind::Number);
        let s = scope(2);
        let (mut c, sid) = setup(&[t.clone()], s);
        for (i, value) in values.into_iter().enumerate() {
            let doc = json!({"amount":value});
            bh_data::value::check(&doc).unwrap();
            put(&mut c, sid, &t, i as u32, doc);
        }
        let a = Aggregate {
            select: TypeSelect::Exact(t.type_id),
            filter: None,
            group_by: None,
            measures: vec![Measure::Sum(path("/amount"))],
            max_groups: 1,
        };
        let result = aggregate(&c, s, &[s], &Core, &a, Budget::INTERACTIVE);
        assert!(
            matches!(result, Err(QueryError::NotQueryable { .. })),
            "{result:?}"
        );
    }
}
#[test]
fn aggregate_safe_boundaries_real_sums_and_empty_sum() {
    for (values, expected) in [
        (
            vec![json!(9_007_199_254_740_990i64), json!(1)],
            json!(9_007_199_254_740_991i64),
        ),
        (
            vec![json!(-9_007_199_254_740_990i64), json!(-1)],
            json!(-9_007_199_254_740_991i64),
        ),
        (vec![json!(0.25), json!(0.5)], json!(0.75)),
        (vec![], json!(null)),
    ] {
        let mut t = ct(1, None);
        field(&mut t, "/amount", FieldKind::Number);
        let s = scope(2);
        let (mut c, sid) = setup(&[t.clone()], s);
        for (i, value) in values.iter().enumerate() {
            let doc = json!({"amount":value});
            bh_data::value::check(&doc).unwrap();
            put(&mut c, sid, &t, i as u32, doc);
        }
        let a = Aggregate {
            select: TypeSelect::Exact(t.type_id),
            filter: None,
            group_by: None,
            measures: vec![Measure::Count, Measure::Sum(path("/amount"))],
            max_groups: 1,
        };
        let result = aggregate(&c, s, &[s], &Core, &a, Budget::INTERACTIVE).unwrap();
        assert_eq!(result.groups[0].values, vec![json!(values.len()), expected]);
    }
}
#[test]
fn aggregate_count_sum_group_and_uncovered_scope() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    field(&mut t, "/amount", FieldKind::Integer);
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    for (n, name, amount) in [(1, "a", 3), (2, "a", 4), (3, "b", 2)] {
        put(&mut c, sid, &t, n, json!({"name":name,"amount":amount}));
    }
    let a = Aggregate {
        select: TypeSelect::Exact(t.type_id),
        filter: None,
        group_by: Some(path("/name")),
        measures: vec![Measure::Count, Measure::Sum(path("/amount"))],
        max_groups: 1000,
    };
    let result = aggregate(&c, s, &[s], &Core, &a, Budget::INTERACTIVE).unwrap();
    assert_eq!(result.groups[0].values, vec![json!(2), json!(7)]);
    let tx = c.transaction().unwrap();
    coverage::set(&tx, sid, Position(1), false).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        run(
            &c,
            s,
            &[s],
            &Core,
            &q(TypeSelect::Exact(t.type_id)),
            Budget::INTERACTIVE
        )
        .unwrap()
        .completeness,
        Completeness::Incomplete(vec![Gap::NotCovered])
    );
}

fn linked_rows<F: Fn(u32) -> Option<RecordId>>(
    c: &mut Connection,
    s: i64,
    t: &CompiledType,
    start: u32,
    end: u32,
    field_name: &str,
    target: F,
) {
    let tx = c.transaction().unwrap();
    for n in (start..=end).rev() {
        let mut doc = json!({"name":format!("n-{n:06}")});
        if let Some(record) = target(n) {
            doc[field_name] = json!(bh_data::RecordRef {
                audience: None,
                record
            });
        }
        let mut row = RecordRow {
            id: 0,
            scope: s,
            record: id(n),
            type_id: t.type_id,
            revision: t.revision,
            accepted: Some(doc),
            doc: None,
            deleted: false,
            pending: false,
            changed_at: None,
            changed: 0,
            text_rev: 0,
        };
        records::put(&tx, &mut row).unwrap();
        index::on_record_changed(&tx, &row, t).unwrap();
    }
    tx.commit().unwrap();
}
fn page_steps(conn: &Connection, scope: Scope, query: &Query) -> u64 {
    for steps in (0..=100_000).step_by(1000) {
        match run(
            conn,
            scope,
            &[scope],
            &Core,
            query,
            Budget { vm_steps: steps },
        ) {
            Ok(page) => {
                assert_eq!(page.rows.len(), query.limit as usize);
                return steps + 1000;
            }
            Err(QueryError::TooCostly { .. }) => {}
            Err(other) => panic!("unexpected query result at {steps} steps: {other:?}"),
        }
    }
    panic!("{}-row page exceeded 100,000 VM steps", query.limit)
}
#[test]
#[ignore = "run with scripts/check.sh data-scale (release)"]
fn refers_to_page_work_is_scale_invariant() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    field(
        &mut t,
        "/link",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: false,
        }),
    );
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    linked_rows(&mut c, sid, &t, 1, 2000, "link", |n| {
        (n <= 50).then_some(id(100_000))
    });
    let mut query = q(TypeSelect::Exact(ty(1)));
    query.filter = Some(Expr::RefersTo {
        path: path("/link"),
        target: bh_data::RecordRef {
            audience: None,
            record: id(100_000),
        },
    });
    let small = page_steps(&c, s, &query);
    linked_rows(&mut c, sid, &t, 2001, 20000, "link", |_| None);
    let large = page_steps(&c, s, &query);
    assert!(
        large * 2 <= small * 3,
        "reverse-ref page grew from {small} to {large} steps"
    );
}
fn via_fixture(rows: u32) -> (Connection, Scope, i64, CompiledType, Query) {
    let mut article = ct(1, None);
    field(&mut article, "/name", FieldKind::String);
    field(&mut article, "/published", FieldKind::Integer);
    article.indexes.push(IndexDecl {
        name: "published".into(),
        keys: vec![KeyRef::Field(path("/published"))],
        declared_by: article.type_id,
    });
    let mut selection = ct(2, None);
    field(&mut selection, "/name", FieldKind::String);
    field(
        &mut selection,
        "/article",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: false,
        }),
    );
    let s = scope(2);
    let (mut c, sid) = setup(&[article.clone(), selection.clone()], s);
    put(
        &mut c,
        sid,
        &article,
        100_000,
        json!({"name":"new","published":10}),
    );
    put(
        &mut c,
        sid,
        &article,
        100_001,
        json!({"name":"old","published":0}),
    );
    linked_rows(&mut c, sid, &selection, 1, rows, "article", |n| {
        Some(id(if n <= 50 { 100_000 } else { 100_001 }))
    });
    let mut query = q(TypeSelect::Exact(ty(2)));
    query.filter = Some(Expr::Via {
        path: path("/article"),
        filter: Box::new(Expr::Cmp {
            path: path("/published"),
            op: CmpOp::Ge,
            value: json!(5),
        }),
    });
    (c, s, sid, selection, query)
}
#[test]
#[ignore = "run with scripts/check.sh data-scale (release)"]
fn selective_via_page_work_is_scale_invariant() {
    let (mut c, s, sid, selection, query) = via_fixture(2000);
    let small = page_steps(&c, s, &query);
    linked_rows(&mut c, sid, &selection, 2001, 20000, "article", |_| {
        Some(id(100_001))
    });
    let large = page_steps(&c, s, &query);
    assert!(
        large * 2 <= small * 3,
        "target-first page grew from {small} to {large} steps"
    );
}
#[test]
#[ignore = "run with scripts/check.sh data-scale (release)"]
fn broad_via_page_work_stays_flat_as_targets_and_sources_grow() {
    let mut article = ct(1, None);
    field(&mut article, "/name", FieldKind::String);
    field(&mut article, "/published", FieldKind::Integer);
    article.indexes.push(IndexDecl {
        name: "published".into(),
        keys: vec![KeyRef::Field(path("/published"))],
        declared_by: article.type_id,
    });
    let mut selection = ct(2, None);
    field(&mut selection, "/name", FieldKind::String);
    field(
        &mut selection,
        "/article",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: false,
        }),
    );
    let s = scope(2);
    let (mut c, sid) = setup(&[article.clone(), selection.clone()], s);
    let mut query = q(TypeSelect::Exact(selection.type_id));
    query.filter = Some(Expr::Via {
        path: path("/article"),
        filter: Box::new(Expr::Cmp {
            path: path("/published"),
            op: CmpOp::Ge,
            value: json!(0),
        }),
    });
    let mut measured = vec![];
    for (start, end) in [(1, 2000), (2001, 20000)] {
        let tx = c.transaction().unwrap();
        for n in start..=end {
            let mut target = RecordRow {
                id: 0,
                scope: sid,
                record: id(100_000 + n),
                type_id: article.type_id,
                revision: article.revision,
                accepted: Some(json!({"name":format!("a{n}"),"published":1})),
                doc: None,
                deleted: false,
                pending: false,
                changed_at: None,
                changed: 0,
                text_rev: 0,
            };
            records::put(&tx, &mut target).unwrap();
            index::on_record_changed(&tx, &target, &article).unwrap();
            let mut source = RecordRow {
                id: 0,
                scope: sid,
                record: id(n),
                type_id: selection.type_id,
                revision: selection.revision,
                accepted: Some(
                    json!({"name":format!("s{n}"),"article":bh_data::RecordRef{audience:None,record:target.record}}),
                ),
                doc: None,
                deleted: false,
                pending: false,
                changed_at: None,
                changed: 0,
                text_rev: 0,
            };
            records::put(&tx, &mut source).unwrap();
            index::on_record_changed(&tx, &source, &selection).unwrap();
        }
        tx.commit().unwrap();
        measured.push(page_steps(&c, s, &query));
    }
    assert!(
        measured[1] * 2 <= measured[0] * 3,
        "broad Via page grew from {} to {} VM steps",
        measured[0],
        measured[1]
    );
}
#[test]
fn broad_via_is_bounded_by_budget() {
    let (c, s, _, _, mut query) = via_fixture(5000);
    query.filter = Some(Expr::Via {
        path: path("/article"),
        filter: Box::new(Expr::Cmp {
            path: path("/published"),
            op: CmpOp::Ge,
            value: json!(0),
        }),
    });
    assert!(matches!(
        run(&c, s, &[s], &Core, &query, Budget { vm_steps: 5000 }),
        Err(QueryError::TooCostly { .. })
    ));
}
#[test]
fn via_without_ready_target_index_uses_source_fallback() {
    let mut article = ct(1, None);
    field(&mut article, "/name", FieldKind::String);
    field(&mut article, "/published", FieldKind::Integer);
    let mut selection = ct(2, None);
    field(&mut selection, "/name", FieldKind::String);
    field(
        &mut selection,
        "/article",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: false,
        }),
    );
    let s = scope(2);
    let (mut c, sid) = setup(&[article.clone(), selection.clone()], s);
    put(
        &mut c,
        sid,
        &article,
        100_000,
        json!({"name":"target","published":10}),
    );
    linked_rows(&mut c, sid, &selection, 1, 10, "article", |_| {
        Some(id(100_000))
    });
    let mut query = q(TypeSelect::Exact(ty(2)));
    query.filter = Some(Expr::Via {
        path: path("/article"),
        filter: Box::new(Expr::Cmp {
            path: path("/published"),
            op: CmpOp::Ge,
            value: json!(5),
        }),
    });
    assert_eq!(
        run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .rows
            .len(),
        10
    );
}
#[test]
fn indexed_via_into_other_audience_requires_read_authority() {
    let mut article = ct(1, None);
    field(&mut article, "/name", FieldKind::String);
    field(&mut article, "/published", FieldKind::Integer);
    article.indexes.push(IndexDecl {
        name: "published".into(),
        keys: vec![KeyRef::Field(path("/published"))],
        declared_by: article.type_id,
    });
    let mut selection = ct(2, None);
    field(&mut selection, "/name", FieldKind::String);
    field(
        &mut selection,
        "/article",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: false,
        }),
    );
    let source = scope(2);
    let dest = scope(3);
    let (mut c, ss) = setup(&[selection.clone()], source);
    let ds = {
        let tx = c.transaction().unwrap();
        let ds = records::scope_id(&tx, dest, &Core).unwrap();
        registry::store_definition(&tx, ds, &article, b"article", Position(1)).unwrap();
        registry::set_current(
            &tx,
            ds,
            article.type_id,
            article.revision,
            &[article.revision],
            Position(1),
        )
        .unwrap();
        index::ensure(&tx, ds, &article).unwrap();
        tx.commit().unwrap();
        ds
    };
    put(
        &mut c,
        ds,
        &article,
        100_000,
        json!({"name":"target","published":10}),
    );
    put(
        &mut c,
        ss,
        &selection,
        1,
        json!({"name":"source","article":bh_data::RecordRef{audience:Some(dest.audience),record:id(100_000)}}),
    );
    let mut query = q(TypeSelect::Exact(ty(2)));
    query.filter = Some(Expr::Via {
        path: path("/article"),
        filter: Box::new(Expr::Cmp {
            path: path("/published"),
            op: CmpOp::Ge,
            value: json!(5),
        }),
    });
    assert!(
        run(&c, source, &[source], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .rows
            .is_empty()
    );
    assert_eq!(
        run(
            &c,
            source,
            &[source, dest],
            &Core,
            &query,
            Budget::INTERACTIVE
        )
        .unwrap()
        .rows
        .len(),
        1
    );
}

#[test]
fn nested_paths_filter_sort_and_aggregate() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    field(&mut t, "/meta/score", FieldKind::Integer);
    field(&mut t, "/meta/group", FieldKind::String);
    t.indexes.push(IndexDecl {
        name: "score".into(),
        keys: vec![KeyRef::Field(path("/meta/score"))],
        declared_by: t.type_id,
    });
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    put(
        &mut c,
        sid,
        &t,
        1,
        json!({"name":"a","meta":{"score":1,"group":"x"}}),
    );
    put(
        &mut c,
        sid,
        &t,
        2,
        json!({"name":"b","meta":{"score":3,"group":"y"}}),
    );
    put(
        &mut c,
        sid,
        &t,
        3,
        json!({"name":"c","meta":{"score":2,"group":"y"}}),
    );
    let mut query = q(TypeSelect::Exact(ty(1)));
    query.fields.push(path("/meta/score"));
    query.filter = Some(Expr::Cmp {
        path: path("/meta/score"),
        op: CmpOp::Ge,
        value: json!(2),
    });
    query.sort.push(SortKey {
        key: KeyRef::Field(path("/meta/score")),
        desc: false,
    });
    let rows = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE)
        .unwrap()
        .rows;
    assert_eq!(
        rows.iter()
            .map(|r| r.values["/meta/score"].clone())
            .collect::<Vec<_>>(),
        vec![json!(2), json!(3)]
    );
    let result = aggregate(
        &c,
        s,
        &[s],
        &Core,
        &Aggregate {
            select: TypeSelect::Exact(ty(1)),
            filter: query.filter,
            group_by: Some(path("/meta/group")),
            measures: vec![Measure::Count, Measure::Sum(path("/meta/score"))],
            max_groups: 1000,
        },
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(result.groups[0].key, Some(json!("y")));
    assert_eq!(result.groups[0].values, vec![json!(2), json!(5)]);
}

#[test]
fn indexed_fractional_numbers_match_unindexed_equality_range_and_sort() {
    let mut indexed = ct(1, None);
    field(&mut indexed, "/name", FieldKind::String);
    field(&mut indexed, "/price", FieldKind::Number);
    indexed.indexes.push(IndexDecl {
        name: "price".into(),
        keys: vec![KeyRef::Field(path("/price"))],
        declared_by: indexed.type_id,
    });
    let mut fallback = indexed.clone();
    fallback.indexes.clear();
    let s = scope(2);
    let (mut indexed_conn, indexed_scope) = setup(&[indexed.clone()], s);
    let (mut fallback_conn, fallback_scope) = setup(&[fallback.clone()], s);
    for (n, price) in [
        (1, json!(1.5)),
        (2, json!(2.25)),
        (3, json!(2)),
        (4, json!(-10.5)),
        (5, json!(1)),
        (6, json!(10.0)),
    ] {
        let doc = json!({"name":format!("item-{n}"),"price":price});
        put(&mut indexed_conn, indexed_scope, &indexed, n, doc.clone());
        put(&mut fallback_conn, fallback_scope, &fallback, n, doc);
    }
    let mut query = q(TypeSelect::Exact(ty(1)));
    let sort = SortKey {
        key: KeyRef::Field(path("/price")),
        desc: false,
    };
    for (filter, sorted) in [
        (None, true),
        (
            Some(Expr::Cmp {
                path: path("/price"),
                op: CmpOp::Eq,
                value: json!(1.5),
            }),
            false,
        ),
        (
            Some(Expr::Cmp {
                path: path("/price"),
                op: CmpOp::Ge,
                value: json!(1.5),
            }),
            true,
        ),
    ] {
        query.sort = if sorted { vec![sort.clone()] } else { vec![] };
        query.filter = filter;
        let expected = run(&fallback_conn, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
        let actual = run(&indexed_conn, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
        assert_eq!(
            actual.rows.iter().map(|r| r.record).collect::<Vec<_>>(),
            expected.rows.iter().map(|r| r.record).collect::<Vec<_>>()
        );
    }
}

#[test]
fn unknown_follow_fields_fail_before_reading_any_rows() {
    let mut article = ct(1, None);
    field(&mut article, "/name", FieldKind::String);
    let mut source = ct(2, None);
    field(&mut source, "/name", FieldKind::String);
    field(
        &mut source,
        "/article",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: false,
        }),
    );
    let s = scope(2);
    let (c, _) = setup(&[article, source], s);
    let mut query = q(TypeSelect::Exact(ty(2)));
    query.follow.push(Follow {
        path: path("/article"),
        fields: vec![path("/misspelled")],
    });
    assert!(
        matches!(run(&c,s,&[s],&Core,&query,Budget::INTERACTIVE),Err(QueryError::UnknownField(p)) if p==path("/misspelled"))
    );
}

fn tie_rows(c: &mut Connection, s: i64, t: &CompiledType, start: u32, end: u32) {
    let tx = c.transaction().unwrap();
    for n in (start..=end).rev() {
        let mut row = RecordRow {
            id: 0,
            scope: s,
            record: id(n),
            type_id: t.type_id,
            revision: t.revision,
            accepted: Some(json!({"name":"tie"})),
            doc: None,
            deleted: false,
            pending: false,
            changed_at: None,
            changed: 0,
            text_rev: 0,
        };
        records::put(&tx, &mut row).unwrap();
        index::on_record_changed(&tx, &row, t).unwrap();
    }
    tx.commit().unwrap();
}
#[test]
#[ignore = "run with scripts/check.sh data-scale (release)"]
fn tie_heavy_indexed_page_work_is_scale_invariant_asc_and_desc() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    t.indexes.push(IndexDecl {
        name: "name".into(),
        keys: vec![KeyRef::Field(path("/name"))],
        declared_by: t.type_id,
    });
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    tie_rows(&mut c, sid, &t, 1, 2000);
    let mut query = q(TypeSelect::Exact(ty(1)));
    query.sort = vec![SortKey {
        key: KeyRef::Field(path("/name")),
        desc: false,
    }];
    let mut small = vec![];
    for desc in [false, true] {
        query.sort[0].desc = desc;
        query.after = None;
        query.after = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .next;
        small.push(page_steps(&c, s, &query));
    }
    tie_rows(&mut c, sid, &t, 2001, 20000);
    for (i, desc) in [false, true].into_iter().enumerate() {
        query.limit = 50;
        query.sort[0].desc = desc;
        query.after = None;
        query.after = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .next;
        let large = page_steps(&c, s, &query);
        assert!(
            large * 2 <= small[i] * 3,
            "desc={desc}: tie-heavy page grew from {} to {large} steps",
            small[i]
        );
        query.after = None;
        query.limit = 200;
        let first = page_steps(&c, s, &query);
        let mut seen = vec![];
        while seen.len() < 19_000 {
            let page = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
            seen.extend(page.rows.iter().map(|r| r.record));
            query.after = page.next;
        }
        let deep = page_steps(&c, s, &query);
        assert!(deep * 2 <= first * 3, "tie deep page {deep}, first {first}");
        seen.extend(all_pages(&c, s, &query));
        let mut expected: Vec<_> = (1..=20_000).map(id).collect();
        if desc {
            expected.reverse();
        }
        assert_eq!(seen, expected);
        eprintln!(
            "tie desc={desc}: 2k={} 20k={large}, first200={first}, deep19000={deep} VM steps",
            small[i]
        );
    }
}
fn family_rows(
    c: &mut Connection,
    s: i64,
    parent: &CompiledType,
    child: &CompiledType,
    start: u32,
    end: u32,
) {
    let tx = c.transaction().unwrap();
    for n in (start..=end).rev() {
        let t = if n % 2 == 0 { parent } else { child };
        let mut row = RecordRow {
            id: 0,
            scope: s,
            record: id(n),
            type_id: t.type_id,
            revision: t.revision,
            accepted: Some(json!({"name":format!("item-{n}")})),
            doc: None,
            deleted: false,
            pending: false,
            changed_at: None,
            changed: 0,
            text_rev: 0,
        };
        records::put(&tx, &mut row).unwrap();
        index::on_record_changed(&tx, &row, t).unwrap();
    }
    tx.commit().unwrap();
}
#[test]
#[ignore = "run with scripts/check.sh data-scale (release)"]
fn unsorted_family_page_work_is_scale_invariant() {
    let mut parent = ct(1, None);
    field(&mut parent, "/name", FieldKind::String);
    let mut child = ct(2, Some(1));
    field(&mut child, "/name", FieldKind::String);
    let s = scope(2);
    let (mut c, sid) = setup(&[parent.clone(), child.clone()], s);
    family_rows(&mut c, sid, &parent, &child, 1, 2000);
    let mut query = q(TypeSelect::Family(ty(1)));
    let first = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
    assert_eq!(first.rows.len(), 50);
    assert!(first.rows.iter().all(|r| r.type_id == ty(1)));
    query.after = first.next;
    let small = page_steps(&c, s, &query);
    family_rows(&mut c, sid, &parent, &child, 2001, 20000);
    query.after = run(
        &c,
        s,
        &[s],
        &Core,
        &q(TypeSelect::Family(ty(1))),
        Budget::INTERACTIVE,
    )
    .unwrap()
    .next;
    let large = page_steps(&c, s, &query);
    assert!(
        large * 2 <= small * 3,
        "family page grew from {small} to {large} steps"
    );
}
#[test]
fn cursor_rejects_different_sort_shape() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    field(&mut t, "/amount", FieldKind::Integer);
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    for n in 1..=3 {
        put(
            &mut c,
            sid,
            &t,
            n,
            json!({"name":format!("{n}"),"amount":n}),
        );
    }
    let mut query = q(TypeSelect::Exact(ty(1)));
    query.limit = 1;
    query.sort.push(SortKey {
        key: KeyRef::Field(path("/name")),
        desc: false,
    });
    query.after = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE)
        .unwrap()
        .next;
    query.sort[0].key = KeyRef::Field(path("/amount"));
    assert!(
        matches!(run(&c,s,&[s],&Core,&query,Budget::INTERACTIVE),Err(QueryError::NotQueryable{path:None,detail}) if detail.contains("cursor"))
    );
}

#[test]
fn consulted_target_coverage_reports_incomplete() {
    let mut article = ct(1, None);
    field(&mut article, "/name", FieldKind::String);
    field(&mut article, "/published", FieldKind::Integer);
    article.indexes.push(IndexDecl {
        name: "published".into(),
        keys: vec![KeyRef::Field(path("/published"))],
        declared_by: article.type_id,
    });
    let mut selection = ct(2, None);
    field(&mut selection, "/name", FieldKind::String);
    field(
        &mut selection,
        "/article",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: false,
        }),
    );
    let source = scope(2);
    let target = scope(3);
    let (mut c, source_id) = setup(&[selection.clone()], source);
    let target_id = {
        let tx = c.transaction().unwrap();
        let id = records::scope_id(&tx, target, &Core).unwrap();
        registry::store_definition(&tx, id, &article, b"article", Position(1)).unwrap();
        registry::set_current(
            &tx,
            id,
            article.type_id,
            article.revision,
            &[article.revision],
            Position(1),
        )
        .unwrap();
        index::ensure(&tx, id, &article).unwrap();
        coverage::set(&tx, id, Position(1), false).unwrap();
        tx.commit().unwrap();
        id
    };
    put(
        &mut c,
        target_id,
        &article,
        100,
        json!({"name":"target","published":1}),
    );
    put(
        &mut c,
        source_id,
        &selection,
        1,
        json!({"name":"source","article":bh_data::RecordRef{audience:Some(target.audience),record:id(100)}}),
    );
    let mut query = q(TypeSelect::Exact(ty(2)));
    query.filter = Some(Expr::Via {
        path: path("/article"),
        filter: Box::new(Expr::Cmp {
            path: path("/published"),
            op: CmpOp::Ge,
            value: json!(10),
        }),
    });
    let via = run(
        &c,
        source,
        &[source, target],
        &Core,
        &query,
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert!(via.rows.is_empty());
    assert_eq!(
        via.completeness,
        Completeness::Incomplete(vec![Gap::NotCovered])
    );
    query.filter = Some(Expr::RefersTo {
        path: path("/article"),
        target: bh_data::RecordRef {
            audience: Some(target.audience),
            record: id(999),
        },
    });
    let refers = run(
        &c,
        source,
        &[source, target],
        &Core,
        &query,
        Budget::INTERACTIVE,
    )
    .unwrap();
    // Backlinks are the source audience's own reference rows; the target
    // audience's coverage does not bound them.
    assert!(refers.rows.is_empty());
    assert_eq!(refers.completeness, Completeness::Complete);
    query.filter = None;
    query.follow.push(Follow {
        path: path("/article"),
        fields: vec![path("/name")],
    });
    let page = run(
        &c,
        source,
        &[source, target],
        &Core,
        &query,
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(
        page.completeness,
        Completeness::Incomplete(vec![Gap::NotCovered])
    );
}
#[test]
fn corrupt_via_target_definition_propagates_error() {
    let mut article = ct(1, None);
    field(&mut article, "/name", FieldKind::String);
    field(&mut article, "/published", FieldKind::Integer);
    let mut selection = ct(2, None);
    field(&mut selection, "/name", FieldKind::String);
    field(
        &mut selection,
        "/article",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: false,
        }),
    );
    let s = scope(2);
    let (c, sid) = setup(&[article.clone(), selection], s);
    c.execute(
        "UPDATE data_definition SET compiled='not json' WHERE scope=?1 AND revision=?2",
        rusqlite::params![sid, article.revision.0.as_slice()],
    )
    .unwrap();
    let mut query = q(TypeSelect::Exact(ty(2)));
    query.filter = Some(Expr::Via {
        path: path("/article"),
        filter: Box::new(Expr::Cmp {
            path: path("/published"),
            op: CmpOp::Ge,
            value: json!(1),
        }),
    });
    assert!(matches!(
        run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE),
        Err(QueryError::Storage(_))
    ));
}
#[test]
fn unknown_via_target_is_reported_incomplete() {
    let mut selection = ct(2, None);
    field(&mut selection, "/name", FieldKind::String);
    field(
        &mut selection,
        "/article",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(99)],
            family: false,
        }),
    );
    let s = scope(2);
    let (mut c, sid) = setup(&[selection.clone()], s);
    put(
        &mut c,
        sid,
        &selection,
        1,
        json!({"name":"source","article":bh_data::RecordRef{audience:None,record:id(100)}}),
    );
    let mut query = q(TypeSelect::Exact(ty(2)));
    query.filter = Some(Expr::Via {
        path: path("/article"),
        filter: Box::new(Expr::Cmp {
            path: path("/published"),
            op: CmpOp::Ge,
            value: json!(1),
        }),
    });
    let page = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
    assert!(page.rows.is_empty());
    assert_eq!(
        page.completeness,
        Completeness::Incomplete(vec![Gap::UnsupportedType(ty(99))])
    );
}
#[test]
fn follow_fields_are_checked_against_all_declared_targets() {
    let mut article = ct(1, None);
    field(&mut article, "/name", FieldKind::String);
    field(&mut article, "/title", FieldKind::String);
    let mut other = ct(3, None);
    field(&mut other, "/name", FieldKind::String);
    let mut selection = ct(2, None);
    field(&mut selection, "/name", FieldKind::String);
    field(
        &mut selection,
        "/article",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1), ty(3)],
            family: false,
        }),
    );
    let s = scope(2);
    let (c, _) = setup(&[article, other, selection], s);
    let mut query = q(TypeSelect::Exact(ty(2)));
    query.follow.push(Follow {
        path: path("/article"),
        fields: vec![path("/title")],
    });
    assert!(
        matches!(run(&c,s,&[s],&Core,&query,Budget::INTERACTIVE),Err(QueryError::UnknownField(p)) if p==path("/title"))
    );
}

#[test]
fn via_filter_is_type_checked_even_when_no_target_rows_exist() {
    let mut article = ct(1, None);
    field(&mut article, "/name", FieldKind::String);
    let mut selection = ct(2, None);
    field(&mut selection, "/name", FieldKind::String);
    field(
        &mut selection,
        "/article",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: false,
        }),
    );
    let s = scope(2);
    let (c, _) = setup(&[article, selection], s);
    let mut query = q(TypeSelect::Exact(ty(2)));
    query.filter = Some(Expr::Via {
        path: path("/article"),
        filter: Box::new(Expr::Cmp {
            path: path("/published"),
            op: CmpOp::Eq,
            value: json!(true),
        }),
    });
    assert!(
        matches!(run(&c,s,&[s],&Core,&query,Budget::INTERACTIVE),Err(QueryError::UnknownField(p)) if p==path("/published"))
    );
}
#[test]
fn follow_family_fields_are_checked_against_every_member() {
    let mut parent = ct(1, None);
    field(&mut parent, "/name", FieldKind::String);
    let mut child = ct(3, Some(1));
    field(&mut child, "/name", FieldKind::String);
    field(&mut child, "/child_only", FieldKind::Integer);
    let mut source = ct(2, None);
    field(&mut source, "/name", FieldKind::String);
    field(
        &mut source,
        "/article",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: true,
        }),
    );
    let s = scope(2);
    let (c, _) = setup(&[parent, child, source], s);
    let mut query = q(TypeSelect::Exact(ty(2)));
    query.follow.push(Follow {
        path: path("/article"),
        fields: vec![path("/child_only")],
    });
    assert!(
        matches!(run(&c,s,&[s],&Core,&query,Budget::INTERACTIVE),Err(QueryError::UnknownField(p)) if p==path("/child_only"))
    );
}
fn task_type(n: u8, parent: Option<u8>, indexes: &[&[&str]]) -> CompiledType {
    let mut t = ct(n, parent);
    field(&mut t, "/name", FieldKind::String);
    field(&mut t, "/status", FieldKind::String);
    field(&mut t, "/due", FieldKind::Integer);
    field(&mut t, "/title", FieldKind::String);
    for keys in indexes {
        t.indexes.push(IndexDecl {
            name: keys.join(","),
            keys: keys.iter().map(|k| KeyRef::Field(path(k))).collect(),
            declared_by: t.type_id,
        });
    }
    t
}
// Every 13th task has no due date; due values repeat so ties are common.
fn task_doc(n: u32) -> serde_json::Value {
    let status = if n.is_multiple_of(2) {
        "open"
    } else {
        "closed"
    };
    if n.is_multiple_of(13) {
        json!({"name":format!("task-{n}"),"status":status,"title":format!("t{:05}", 30000 - n)})
    } else {
        json!({"name":format!("task-{n}"),"status":status,"due":n % 7,"title":format!("t{:05}", 30000 - n)})
    }
}
fn tasks(c: &mut Connection, s: i64, types: &[&CompiledType], from: u32, to: u32) {
    let tx = c.transaction().unwrap();
    for n in (from..=to).rev() {
        let t = types[n as usize % types.len()];
        let mut row = RecordRow {
            id: 0,
            scope: s,
            record: id(n),
            type_id: t.type_id,
            revision: t.revision,
            accepted: Some(task_doc(n)),
            doc: None,
            deleted: false,
            pending: false,
            changed_at: None,
            changed: 0,
            text_rev: 0,
        };
        records::put(&tx, &mut row).unwrap();
        index::on_record_changed(&tx, &row, t).unwrap();
    }
    tx.commit().unwrap();
}
fn all_pages(c: &Connection, s: Scope, query: &Query) -> Vec<RecordId> {
    let mut query = query.clone();
    query.limit = 200;
    let mut got = vec![];
    loop {
        let page = run(c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
        got.extend(page.rows.iter().map(|r| r.record));
        let Some(next) = page.next else { break };
        query.after = Some(next);
    }
    got
}
// Expected order: sort keys with NULL first ascending (last descending), then
// the logical record ID, independently of insertion order.
fn expected(
    ns: impl Iterator<Item = u32>,
    key: impl Fn(u32) -> Vec<Option<String>>,
    desc: bool,
) -> Vec<RecordId> {
    let mut rows: Vec<_> = ns.map(|n| (key(n), n)).collect();
    rows.sort();
    if desc {
        rows.reverse()
    }
    rows.into_iter().map(|(_, n)| id(n)).collect()
}
#[test]
fn requested_order_is_independent_of_unused_composite_keys() {
    let s = scope(2);
    for indexes in [vec![&["/status", "/due"][..]], vec![&["/status"][..]]] {
        let t = task_type(1, None, &indexes);
        let (mut c, sid) = setup(std::slice::from_ref(&t), s);
        for (n, due) in [(3, 0), (1, 5), (2, 1)] {
            put(&mut c, sid, &t, n, json!({"status":"open","due":due}));
        }
        for desc in [false, true] {
            let mut query = q(TypeSelect::Exact(ty(1)));
            query.sort = vec![SortKey {
                key: KeyRef::Field(path("/status")),
                desc,
            }];
            let want = if desc {
                vec![id(3), id(2), id(1)]
            } else {
                vec![id(1), id(2), id(3)]
            };
            assert_eq!(all_pages(&c, s, &query), want);
        }
        let mut query = q(TypeSelect::Exact(ty(1)));
        query.filter = Some(Expr::Cmp {
            path: path("/status"),
            op: CmpOp::Eq,
            value: json!("open"),
        });
        assert_eq!(all_pages(&c, s, &query), vec![id(1), id(2), id(3)]);
        let tx = c.transaction().unwrap();
        let ix =
            index::ensure_local(&tx, sid, ty(1), vec![KeyRef::Field(path("/status"))]).unwrap();
        while !index::backfill_step(&tx, ix, 1).unwrap().ready {}
        tx.commit().unwrap();
        query.filter = None;
        query.sort = vec![SortKey {
            key: KeyRef::Field(path("/status")),
            desc: false,
        }];
        assert_eq!(all_pages(&c, s, &query), vec![id(1), id(2), id(3)]);
    }
}
#[test]
fn unused_composite_suffix_needs_an_ordering_index_for_large_types() {
    let pair = task_type(1, None, &[&["/status", "/due"]]);
    let triple = task_type(2, None, &[&["/status", "/due", "/title"]]);
    let s = scope(2);
    let (mut c, sid) = setup(&[pair.clone(), triple.clone()], s);
    tasks(&mut c, sid, &[&pair], 1, 2500);
    tasks(&mut c, sid, &[&triple], 2501, 5000);
    for (t, key, filter) in [
        (ty(1), "/status", None),
        (
            ty(2),
            "/due",
            Some(Expr::Cmp {
                path: path("/status"),
                op: CmpOp::Eq,
                value: json!("open"),
            }),
        ),
    ] {
        for desc in [false, true] {
            let mut query = q(TypeSelect::Exact(t));
            query.filter = filter.clone();
            query.sort = vec![SortKey {
                key: KeyRef::Field(path(key)),
                desc,
            }];
            assert!(matches!(
                run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE),
                Err(QueryError::TooCostly { .. })
            ));
        }
    }
    // Unsorted filtering never inherits the composite index's due/title order.
    let mut query = q(TypeSelect::Exact(ty(1)));
    query.filter = Some(Expr::Cmp {
        path: path("/status"),
        op: CmpOp::Eq,
        value: json!("open"),
    });
    assert_eq!(
        all_pages(&c, s, &query),
        (1..=2500)
            .filter(|n| n % 2 == 0)
            .map(id)
            .collect::<Vec<_>>()
    );
}
#[test]
#[ignore = "run with scripts/check.sh data-scale (release)"]
fn indexed_family_equality_page_work_is_scale_invariant() {
    let parent = task_type(1, None, &[&["/status"]]);
    let child = task_type(2, Some(1), &[]);
    let s = scope(2);
    let (mut c, sid) = setup(&[parent.clone(), child.clone()], s);
    tasks(&mut c, sid, &[&parent, &child], 1, 2000);
    let mut query = q(TypeSelect::Family(ty(1)));
    query.filter = Some(Expr::Cmp {
        path: path("/status"),
        op: CmpOp::Eq,
        value: json!("open"),
    });
    let rows = all_pages(&c, s, &query);
    assert_eq!(
        rows,
        (1..=2000)
            .filter(|n| n % 2 == 0)
            .map(id)
            .collect::<Vec<_>>()
    );
    let small = page_steps(&c, s, &query);
    tasks(&mut c, sid, &[&parent, &child], 2001, 20000);
    let large = page_steps(&c, s, &query);
    assert!(
        large * 2 <= small * 3,
        "family equality page grew from {small} to {large} steps"
    );
}
#[test]
#[ignore = "run with scripts/check.sh data-scale (release)"]
fn deep_page_work_is_flat() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    t.indexes.push(IndexDecl {
        name: "name".into(),
        keys: vec![KeyRef::Field(path("/name"))],
        declared_by: t.type_id,
    });
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    let tx = c.transaction().unwrap();
    for n in (1..=20000u32).rev() {
        // One in ten has no name; NULLs sort first ascending, last descending.
        let doc = if n % 10 == 0 {
            json!({})
        } else {
            json!({"name":format!("name-{:06}", 20000 - n)})
        };
        let mut row = RecordRow {
            id: 0,
            scope: sid,
            record: id(n),
            type_id: t.type_id,
            revision: t.revision,
            accepted: Some(doc),
            doc: None,
            deleted: false,
            pending: false,
            changed_at: None,
            changed: 0,
            text_rev: 0,
        };
        records::put(&tx, &mut row).unwrap();
        index::on_record_changed(&tx, &row, &t).unwrap();
    }
    tx.commit().unwrap();
    let name = |n: u32| (!n.is_multiple_of(10)).then(|| format!("name-{:06}", 20000 - n));
    for desc in [false, true] {
        let mut query = q(TypeSelect::Exact(ty(1)));
        query.sort = vec![SortKey {
            key: KeyRef::Field(path("/name")),
            desc,
        }];
        let first = page_steps(&c, s, &query);
        query.limit = 200;
        let mut seen = vec![];
        while seen.len() < 19000 {
            let page = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
            seen.extend(page.rows.iter().map(|r| r.record));
            query.after = page.next;
        }
        query.limit = 50;
        let deep = page_steps(&c, s, &query);
        let rest = all_pages(&c, s, &query);
        seen.extend(rest);
        assert_eq!(
            seen,
            expected(1..=20000, |n| vec![name(n)], desc),
            "desc={desc}"
        );
        eprintln!("desc={desc}: first page {first} VM steps, page at row 19,000 {deep}");
        assert!(
            deep * 2 <= first * 3,
            "desc={desc}: page at row 19,000 took {deep} steps, first page {first}"
        );
    }
}
#[test]
fn unsorted_family_deep_pages_seek_each_later_type() {
    for members in [3u8, 4] {
        let types: Vec<_> = (1..=members)
            .map(|n| task_type(n, (n > 1).then_some(1), &[]))
            .collect();
        let s = scope(2);
        let (mut c, sid) = setup(&types, s);
        // Each member type holds its own block of 10,000 records.
        for (i, t) in types.iter().enumerate() {
            let from = i as u32 * 10_000 + 1;
            linked_rows(&mut c, sid, t, from, from + 9_999, "link", |_| None);
        }
        // 200-row pages, which the guard's 1,000-step granularity resolves.
        let mut query = q(TypeSelect::Family(ty(1)));
        query.limit = 200;
        let first = page_steps(&c, s, &query);
        let mut seen = vec![];
        for row in [9_000, 15_000] {
            while seen.len() < row {
                let page = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
                seen.extend(page.rows.iter().map(|r| r.record));
                query.after = page.next;
            }
            let deep = page_steps(&c, s, &query);
            eprintln!("{members} types: first page {first} VM steps, page at row {row} {deep}");
            assert!(
                deep * 2 <= first * 3,
                "{members} types: page at row {row} took {deep} steps, first page {first}"
            );
        }
        seen.extend(all_pages(&c, s, &query));
        assert_eq!(
            seen,
            (1..=u32::from(members) * 10_000)
                .map(id)
                .collect::<Vec<_>>()
        );
    }
}
#[test]
fn unsorted_family_cursor_must_name_a_selected_type() {
    let parent = task_type(1, None, &[]);
    let child = task_type(2, Some(1), &[]);
    let other = task_type(9, None, &[]);
    let s = scope(2);
    let (mut c, sid) = setup(&[parent.clone(), child.clone(), other.clone()], s);
    tasks(&mut c, sid, &[&parent, &child, &other], 1, 30);
    let mut query = q(TypeSelect::Family(ty(1)));
    query.limit = 1;
    let next = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE)
        .unwrap()
        .next
        .unwrap();
    // The same cursor, naming a type outside the family.
    let raw: Vec<u8> = (0..next.0.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&next.0[i..i + 2], 16).unwrap())
        .collect();
    let mut state: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    state["keys"][0] = json!(vec![9u8; 32]);
    let forged = serde_json::to_vec(&state).unwrap();
    query.after = Some(Cursor(forged.iter().map(|b| format!("{b:02x}")).collect()));
    assert!(matches!(
        run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE),
        Err(QueryError::NotQueryable { .. })
    ));
}
// Records 1..=5000 hold /num in 50,001..=52,500, each value twice. Later
// records lie outside that band: below it, above it, or without /num.
fn range_num(n: u32) -> Option<i64> {
    if n <= 5000 {
        return Some(50_001 + i64::from(n % 2500));
    }
    let k = i64::from(n - 5001);
    match k % 5 {
        0 | 1 => Some(k),
        2 | 3 => Some(200_000 + k),
        _ => None,
    }
}
fn range_rows(c: &mut Connection, s: i64, t: &CompiledType, from: u32, to: u32) {
    let tx = c.transaction().unwrap();
    for n in (from..=to).rev() {
        let mut doc = json!({"name":format!("n-{n}")});
        if let Some(num) = range_num(n) {
            doc["num"] = json!(num);
        }
        let mut row = RecordRow {
            id: 0,
            scope: s,
            record: id(n),
            type_id: t.type_id,
            revision: t.revision,
            accepted: Some(doc),
            doc: None,
            deleted: false,
            pending: false,
            changed_at: None,
            changed: 0,
            text_rev: 0,
        };
        records::put(&tx, &mut row).unwrap();
        index::on_record_changed(&tx, &row, t).unwrap();
    }
    tx.commit().unwrap();
}
#[test]
fn indexed_range_pages_seek_the_range_and_the_cursor() {
    let mut t = ct(1, None);
    field(&mut t, "/name", FieldKind::String);
    field(&mut t, "/num", FieldKind::Integer);
    t.indexes.push(IndexDecl {
        name: "num".into(),
        keys: vec![KeyRef::Field(path("/num"))],
        declared_by: t.type_id,
    });
    let s = scope(2);
    let (mut c, sid) = setup(&[t.clone()], s);
    // 2,500 records outside the band, then 22,500 more.
    range_rows(&mut c, sid, &t, 1, 7_500);
    let cmp = |op: CmpOp, value: i64| Expr::Cmp {
        path: path("/num"),
        op,
        value: json!(value),
    };
    type Range = (&'static str, Expr, fn(i64) -> bool);
    let ranges: Vec<Range> = vec![
        ("> 50000", cmp(CmpOp::Gt, 50_000), |v| v > 50_000),
        (">= 50001", cmp(CmpOp::Ge, 50_001), |v| v >= 50_001),
        ("< 52501", cmp(CmpOp::Lt, 52_501), |v| v < 52_501),
        ("<= 52500", cmp(CmpOp::Le, 52_500), |v| v <= 52_500),
        (
            "> 50000 and < 52501",
            Expr::And(vec![cmp(CmpOp::Gt, 50_000), cmp(CmpOp::Lt, 52_501)]),
            |v| v > 50_000 && v < 52_501,
        ),
    ];
    let mut cases = vec![];
    for (name, filter, matches) in ranges {
        for sort in [None, Some(false), Some(true)] {
            let mut query = q(TypeSelect::Exact(ty(1)));
            query.filter = Some(filter.clone());
            query.sort = sort
                .map(|desc| SortKey {
                    key: KeyRef::Field(path("/num")),
                    desc,
                })
                .into_iter()
                .collect();
            let small = page_steps(&c, s, &query);
            cases.push((name, sort, query, matches, small));
        }
    }
    range_rows(&mut c, sid, &t, 7_501, 30_000);
    let mut slow = vec![];
    for (name, sort, mut query, matches, small) in cases {
        let first = page_steps(&c, s, &query);
        let mut expected: Vec<_> = (1..=30_000)
            .filter_map(|n| range_num(n).filter(|v| matches(*v)).map(|v| (v, n)))
            .collect();
        if sort.is_none() {
            expected.sort_by_key(|(_, n)| *n);
        } else {
            expected.sort();
        }
        if sort == Some(true) {
            expected.reverse()
        }
        let expected: Vec<_> = expected.into_iter().map(|(_, n)| id(n)).collect();
        query.limit = 200;
        let mut seen = vec![];
        while seen.len() < 4_500 {
            let page = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
            seen.extend(page.rows.iter().map(|r| r.record));
            query.after = page.next;
        }
        query.limit = 50;
        let deep = page_steps(&c, s, &query);
        seen.extend(all_pages(&c, s, &query));
        assert_eq!(seen, expected, "{name}, sort {sort:?}");
        eprintln!(
            "{name}, sort {sort:?}: first page {small} -> {first} VM steps with 10x the rows outside, page at row 4,500 {deep}"
        );
        if first * 2 > small * 3 || deep * 2 > first * 3 {
            slow.push(format!(
                "{name}, sort {sort:?}: {small} -> {first}, deep {deep}"
            ));
        }
    }
    assert!(
        slow.is_empty(),
        "pages walked rows outside the range or before the cursor: {slow:#?}"
    );
}
#[test]
fn follow_target_type_only_in_unreadable_audience_is_none() {
    let mut article = ct(1, None);
    field(&mut article, "/name", FieldKind::String);
    let mut selection = ct(2, None);
    field(&mut selection, "/name", FieldKind::String);
    field(
        &mut selection,
        "/article",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: false,
        }),
    );
    let shared = scope(2);
    let private = scope(3);
    let (mut c, sid) = setup(&[selection.clone()], shared);
    let tx = c.transaction().unwrap();
    let pid = records::scope_id(&tx, private, &Core).unwrap();
    registry::store_definition(&tx, pid, &article, b"article", Position(1)).unwrap();
    registry::set_current(
        &tx,
        pid,
        article.type_id,
        article.revision,
        &[article.revision],
        Position(1),
    )
    .unwrap();
    coverage::set(&tx, pid, Position(1), true).unwrap();
    tx.commit().unwrap();
    put(
        &mut c,
        pid,
        &article,
        100,
        json!({"name":"private article"}),
    );
    put(
        &mut c,
        sid,
        &selection,
        1,
        json!({"name":"pick","article":bh_data::RecordRef{audience:Some(private.audience),record:id(100)}}),
    );
    let mut query = q(TypeSelect::Exact(ty(2)));
    query.follow.push(Follow {
        path: path("/article"),
        fields: vec![path("/name")],
    });
    let page = run(&c, shared, &[shared], &Core, &query, Budget::INTERACTIVE).unwrap();
    assert_eq!(page.rows.len(), 1);
    assert!(page.rows[0].follows["/article"].is_none());
    assert_eq!(page.completeness, Completeness::Complete);
    // With read authority the same follow resolves, and a misspelled field on
    // the now-known target type is still rejected.
    let page = run(
        &c,
        shared,
        &[shared, private],
        &Core,
        &query,
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(
        page.rows[0].follows["/article"].as_ref().unwrap().values["/name"],
        json!("private article")
    );
    query.follow[0].fields = vec![path("/nmae")];
    assert!(matches!(
        run(&c, shared, &[shared, private], &Core, &query, Budget::INTERACTIVE),
        Err(QueryError::UnknownField(p)) if p == path("/nmae")
    ));
}
#[test]
fn follow_multi_target_with_uninstalled_type() {
    let mut article = ct(1, None);
    field(&mut article, "/name", FieldKind::String);
    let mut selection = ct(2, None);
    field(&mut selection, "/name", FieldKind::String);
    field(
        &mut selection,
        "/item",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1), ty(9)],
            family: false,
        }),
    );
    let s = scope(2);
    let (mut c, sid) = setup(&[article.clone(), selection.clone()], s);
    put(&mut c, sid, &article, 100, json!({"name":"article"}));
    // A record of the uninstalled type, as held before its definition arrives.
    let tx = c.transaction().unwrap();
    let mut video = RecordRow {
        id: 0,
        scope: sid,
        record: id(200),
        type_id: ty(9),
        revision: RevisionId([9; 32]),
        accepted: Some(json!({"name":"video"})),
        doc: None,
        deleted: false,
        pending: false,
        changed_at: None,
        changed: 0,
        text_rev: 0,
    };
    records::put(&tx, &mut video).unwrap();
    tx.commit().unwrap();
    for (n, target) in [(1, 100), (2, 200), (3, 300)] {
        put(
            &mut c,
            sid,
            &selection,
            n,
            json!({"name":format!("pick-{n}"),"item":bh_data::RecordRef{audience:None,record:id(target)}}),
        );
    }
    let mut query = q(TypeSelect::Exact(ty(2)));
    query.follow.push(Follow {
        path: path("/item"),
        fields: vec![path("/name")],
    });
    let page = run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE).unwrap();
    let follows: Vec<_> = page
        .rows
        .iter()
        .map(|r| r.follows["/item"].clone())
        .collect();
    assert_eq!(follows[0].as_ref().unwrap().record, id(100));
    assert!(follows[1].is_none() && follows[2].is_none());
    assert_eq!(
        page.completeness,
        Completeness::Incomplete(vec![Gap::UnsupportedType(ty(9))])
    );
    query.follow[0].fields = vec![path("/nmae")];
    assert!(matches!(
        run(&c, s, &[s], &Core, &query, Budget::INTERACTIVE),
        Err(QueryError::UnknownField(p)) if p == path("/nmae")
    ));
}
#[test]
fn follow_coverage_counts_only_dereferenced_audiences() {
    let mut article = ct(1, None);
    field(&mut article, "/name", FieldKind::String);
    let mut selection = ct(2, None);
    field(&mut selection, "/name", FieldKind::String);
    field(
        &mut selection,
        "/article",
        FieldKind::Reference(bh_data::RefSpec {
            targets: vec![ty(1)],
            family: false,
        }),
    );
    let s = scope(2);
    let unrelated = scope(4);
    let (mut c, sid) = setup(&[article.clone(), selection.clone()], s);
    let tx = c.transaction().unwrap();
    let uid = records::scope_id(&tx, unrelated, &Core).unwrap();
    registry::store_definition(&tx, uid, &article, b"article", Position(1)).unwrap();
    registry::set_current(
        &tx,
        uid,
        article.type_id,
        article.revision,
        &[article.revision],
        Position(1),
    )
    .unwrap();
    coverage::set(&tx, uid, Position(1), false).unwrap();
    tx.commit().unwrap();
    put(&mut c, sid, &article, 100, json!({"name":"article"}));
    put(
        &mut c,
        sid,
        &selection,
        1,
        json!({"name":"pick","article":bh_data::RecordRef{audience:None,record:id(100)}}),
    );
    let mut query = q(TypeSelect::Exact(ty(2)));
    query.follow.push(Follow {
        path: path("/article"),
        fields: vec![path("/name")],
    });
    let page = run(&c, s, &[s, unrelated], &Core, &query, Budget::INTERACTIVE).unwrap();
    assert!(page.rows[0].follows["/article"].is_some());
    assert_eq!(page.completeness, Completeness::Complete);
    // Following into the incomplete audience is reported.
    put(
        &mut c,
        sid,
        &selection,
        2,
        json!({"name":"other","article":bh_data::RecordRef{audience:Some(unrelated.audience),record:id(101)}}),
    );
    let page = run(&c, s, &[s, unrelated], &Core, &query, Budget::INTERACTIVE).unwrap();
    assert_eq!(
        page.completeness,
        Completeness::Incomplete(vec![Gap::NotCovered])
    );
}
