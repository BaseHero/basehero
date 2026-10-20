use bh_data::{
    Actor, AppId, MutationId, RecordId, RevisionId, Scope, definition,
    mutation::{
        apply::Outcome,
        ops::{FieldChange, Operation},
    },
    payload,
    testkit::{Delivery, OrderedLog, Replica},
};
use serde_json::{Value, json};
const SCOPE: Scope = Scope {
    base: [1; 32],
    audience: [0; 32],
};
const ARTICLE: &[u8] = include_bytes!("fixtures/types/Article.json");
#[test]
fn negative_creation_waits_for_coverage() {
    let (mut rep, mut log) = setup();
    let mut v: Value = serde_json::from_slice(ARTICLE).unwrap();
    v["unique"] = json!([]);
    let bytes = serde_json::to_vec(&v).unwrap();
    let d = definition::parse(&bytes).unwrap();
    assert!(matches!(
        define(&mut rep, &mut log, &v),
        Outcome::Accepted { .. }
    ));
    let tx = rep.conn().unchecked_transaction().unwrap();
    let sid = bh_data::store::records::lookup_scope(&tx, SCOPE)
        .unwrap()
        .unwrap();
    bh_data::store::coverage::set(&tx, sid, bh_data::Position(2), false).unwrap();
    let op = Operation::Create {
        record: RecordId([8; 32]),
        type_id: d.type_id,
        revision: RevisionId::of(&bytes),
        doc: json!({"title":"Duplicate","url":"url"}),
    };
    let out = bh_data::mutation::apply::apply_ordered(
        &tx,
        &bh_data::catalogue::Shipped,
        &bh_data::mutation::apply::Ordered {
            scope: SCOPE,
            position: bh_data::Position(4),
            actor: &actor(),
            mutation: MutationId::random(),
            op: &op,
        },
    )
    .unwrap();
    assert!(matches!(out, Outcome::Waiting(_)), "{out:?}");
}
#[test]
fn lifecycle_undo_rechecks_race_without_history() {
    let (mut rep, mut log) = setup();
    let v: Value = serde_json::from_slice(ARTICLE).unwrap();
    let bytes = serde_json::to_vec(&v).unwrap();
    let d = definition::parse(&bytes).unwrap();
    assert!(matches!(
        define(&mut rep, &mut log, &v),
        Outcome::Accepted { .. }
    ));
    let id = RecordId([8; 32]);
    assert!(matches!(
        order(
            &mut rep,
            &mut log,
            Operation::Create {
                record: id,
                type_id: d.type_id,
                revision: RevisionId::of(&bytes),
                doc: json!({"title":"Original","url":"url"})
            }
        ),
        Outcome::Accepted { .. }
    ));
    let target = match payload::decode(&log.entries().last().unwrap().payload) {
        payload::Decoded::Op(m, _) => m,
        _ => panic!(),
    };
    let undo = bh_data::mutation::undo::prepare(rep.conn(), SCOPE, target).unwrap();
    assert!(matches!(
        order(
            &mut rep,
            &mut log,
            Operation::Edit {
                record: id,
                revision: RevisionId::of(&bytes),
                changes: vec![FieldChange {
                    path: bh_data::FieldPath::parse("/title").unwrap(),
                    value: Some(json!("Later"))
                }]
            }
        ),
        Outcome::Accepted { .. }
    ));
    rep.conn().execute("DELETE FROM data_history", []).unwrap();
    assert!(matches!(
        order(&mut rep, &mut log, undo),
        Outcome::Rejected(bh_data::Rejection {
            code: bh_data::RejectCode::NothingToUndo,
            ..
        })
    ));
}
#[test]
fn mapping_evolution_marks_untouched_records_incomplete() {
    use bh_data::query::{self, Budget, Completeness, Query, TextMatch, TypeSelect};
    let (mut rep, mut log) = setup();
    let mut v: Value = serde_json::from_slice(ARTICLE).unwrap();
    let bytes = serde_json::to_vec(&v).unwrap();
    let d = definition::parse(&bytes).unwrap();
    assert!(matches!(
        define(&mut rep, &mut log, &v),
        Outcome::Accepted { .. }
    ));
    assert!(matches!(
        order(
            &mut rep,
            &mut log,
            Operation::Create {
                record: RecordId([8; 32]),
                type_id: d.type_id,
                revision: RevisionId::of(&bytes),
                doc: json!({"title":"Original","url":"specialsearchtoken"})
            }
        ),
        Outcome::Accepted { .. }
    ));
    assert!(matches!(
        order(
            &mut rep,
            &mut log,
            Operation::Create {
                record: RecordId([9; 32]),
                type_id: d.type_id,
                revision: RevisionId::of(&bytes),
                doc: json!({"title":"Other","url":"other"})
            }
        ),
        Outcome::Accepted { .. }
    ));
    rep.submit(
        SCOPE,
        &actor(),
        Operation::Edit {
            record: RecordId([9; 32]),
            revision: RevisionId::of(&bytes),
            changes: vec![FieldChange {
                path: bh_data::FieldPath::parse("/url").unwrap(),
                value: Some(json!("pendingsearchtoken")),
            }],
        },
    )
    .unwrap();
    v["search"]["text"] = json!(["/url"]);
    assert!(matches!(
        define(&mut rep, &mut log, &v),
        Outcome::Accepted { .. }
    ));
    let q = Query {
        select: TypeSelect::Exact(d.type_id),
        filter: None,
        sort: vec![],
        fields: vec![],
        follow: vec![],
        text: Some(TextMatch {
            terms: "specialsearchtoken".into(),
            on: None,
            require_revision: None,
        }),
        limit: 10,
        after: None,
    };
    let page = query::run(
        rep.conn(),
        SCOPE,
        &[SCOPE],
        &bh_data::catalogue::Shipped,
        &q,
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert!(
        matches!(page.completeness, Completeness::Incomplete(_)),
        "{page:?}"
    );
    v["description"] = json!("Documentation updated during reprojection");
    assert!(matches!(
        define(&mut rep, &mut log, &v),
        Outcome::Accepted { .. }
    ));
    let tx = rep.conn().unchecked_transaction().unwrap();
    assert!(!bh_data::text::reproject_step(&tx, &bh_data::catalogue::Shipped, 1, 100_000).unwrap());
    tx.commit().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("mapping.sqlite");
    rep.conn()
        .execute("VACUUM INTO ?1", [file.to_str().unwrap()])
        .unwrap();
    let rep = Replica::new_file(&file).unwrap();
    let mut pending_query = q.clone();
    pending_query.text.as_mut().unwrap().terms = "pendingsearchtoken".into();
    let pending = query::run(
        rep.conn(),
        SCOPE,
        &[SCOPE],
        &bh_data::catalogue::Shipped,
        &pending_query,
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(pending.rows.len(), 1);
    assert!(matches!(pending.completeness, Completeness::Incomplete(_)));
    let tx = rep.conn().unchecked_transaction().unwrap();
    assert!(bh_data::text::reproject_step(&tx, &bh_data::catalogue::Shipped, 1, 100_000).unwrap());
    tx.commit().unwrap();
    let page = query::run(
        rep.conn(),
        SCOPE,
        &[SCOPE],
        &bh_data::catalogue::Shipped,
        &q,
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.completeness, Completeness::Complete);
    assert_eq!(page.rows[0].revision, RevisionId::of(&bytes));
}
#[test]
fn adoption_requires_accepted_source_provenance() {
    let (rep, _log) = setup();
    let tx = rep.conn().unchecked_transaction().unwrap();
    let private = Scope {
        base: SCOPE.base,
        audience: [7; 32],
    };
    let sid =
        bh_data::store::records::scope_id(&tx, private, &bh_data::catalogue::Shipped).unwrap();
    bh_data::store::coverage::set(&tx, sid, bh_data::Position(3), true).unwrap();
    let op = Operation::Adopt {
        from_audience: SCOPE.audience,
        revision: RevisionId::of(ARTICLE),
        bytes: ARTICLE.to_vec(),
    };
    let out = bh_data::testkit::apply_ordered(
        &tx,
        &bh_data::catalogue::Shipped,
        &bh_data::mutation::apply::Ordered {
            scope: private,
            position: bh_data::Position(3),
            actor: &actor(),
            mutation: MutationId::random(),
            op: &op,
        },
    )
    .unwrap();
    assert!(matches!(out, Outcome::Rejected(_)), "{out:?}");
}
#[test]
fn restoration_undo_is_conditional_and_fresh_creation_undo_still_removes() {
    let (mut rep, mut log) = setup();
    let v: Value = serde_json::from_slice(ARTICLE).unwrap();
    let bytes = serde_json::to_vec(&v).unwrap();
    let d = definition::parse(&bytes).unwrap();
    define(&mut rep, &mut log, &v);
    let id = RecordId([21; 32]);
    order(
        &mut rep,
        &mut log,
        Operation::Create {
            record: id,
            type_id: d.type_id,
            revision: RevisionId::of(&bytes),
            doc: json!({"title":"Original","url":"url"}),
        },
    );
    let last = |log: &OrderedLog| match payload::decode(&log.entries().last().unwrap().payload) {
        payload::Decoded::Op(m, _) => m,
        _ => panic!(),
    };
    let undo = bh_data::mutation::undo::prepare(rep.conn(), SCOPE, last(&log)).unwrap();
    assert!(matches!(undo, Operation::UndoRemove { .. }));
    assert!(matches!(
        order(&mut rep, &mut log, undo),
        Outcome::Accepted { .. }
    ));
    let restore = bh_data::mutation::undo::prepare(rep.conn(), SCOPE, last(&log)).unwrap();
    assert!(matches!(
        order(&mut rep, &mut log, restore),
        Outcome::Accepted { .. }
    ));
    let undo = bh_data::mutation::undo::prepare(rep.conn(), SCOPE, last(&log)).unwrap();
    assert!(matches!(undo, Operation::UndoRemove { .. }));
    order(
        &mut rep,
        &mut log,
        Operation::Edit {
            record: id,
            revision: RevisionId::of(&bytes),
            changes: vec![FieldChange {
                path: bh_data::FieldPath::parse("/title").unwrap(),
                value: Some(json!("Later")),
            }],
        },
    );
    assert!(matches!(
        order(&mut rep, &mut log, undo),
        Outcome::Rejected(bh_data::Rejection {
            code: bh_data::RejectCode::NothingToUndo,
            ..
        })
    ));
    let malformed = Operation::UndoRemove {
        record: id,
        target: MutationId::random(),
        position: bh_data::Position(10_000_000_000_000_000_000),
    };
    assert!(matches!(
        order(&mut rep, &mut log, malformed),
        Outcome::Rejected(_)
    ));
}
#[test]
fn default_ordered_management_admission_is_closed() {
    let (rep, _) = setup();
    let tx = rep.conn().unchecked_transaction().unwrap();
    let op = Operation::SetAppState {
        app: AppId([2; 32]),
        active: false,
    };
    let out = bh_data::mutation::apply::apply_ordered(
        &tx,
        &bh_data::catalogue::Shipped,
        &bh_data::mutation::apply::Ordered {
            scope: SCOPE,
            position: bh_data::Position(2),
            actor: &actor(),
            mutation: MutationId::random(),
            op: &op,
        },
    )
    .unwrap();
    assert!(matches!(
        out,
        Outcome::Rejected(bh_data::Rejection {
            code: bh_data::RejectCode::Unauthorized,
            ..
        })
    ));
}
#[test]
fn partial_app_and_note_identity_replay_preserves_existing_identity() {
    use bh_data::{
        Position,
        catalogue::Shipped,
        mutation::apply,
        store::{coverage, records, registry},
    };
    let (rep, _) = setup();
    let tx = rep.conn().unchecked_transaction().unwrap();
    let sid = records::lookup_scope(&tx, SCOPE).unwrap().unwrap();
    coverage::set(&tx, sid, Position(1), false).unwrap();
    tx.execute("DELETE FROM data_app", []).unwrap();
    tx.execute("DELETE FROM data_app_at", []).unwrap();
    let op = Operation::DefineApp {
        app: AppId([2; 32]),
        name: "Replacement".into(),
    };
    assert!(matches!(
        apply::apply_ordered(
            &tx,
            &Shipped,
            &apply::Ordered {
                scope: SCOPE,
                position: Position(2),
                actor: &actor(),
                mutation: MutationId::random(),
                op: &op
            }
        )
        .unwrap(),
        Outcome::Waiting(_)
    ));
    registry::set_app(&tx, sid, AppId([2; 32]), "Fixtures", true, Position(1)).unwrap();
    coverage::set(&tx, sid, Position(2), true).unwrap();
    let decided = apply::retry_parked(&tx, &Shipped, SCOPE).unwrap();
    assert_eq!(decided.len(), 1);
    assert_eq!(decided[0].0, Position(2));
    assert!(matches!(&decided[0].1, Outcome::Rejected(rejection)
        if rejection.code == bh_data::RejectCode::Exists));
    let name: String = tx
        .query_row("SELECT name FROM data_app WHERE scope=?1", [sid], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(name, "Fixtures");
    tx.commit().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("identity.sqlite");
    let mut rep = Replica::new_file(&db).unwrap();
    let mut log = OrderedLog::new();
    order(
        &mut rep,
        &mut log,
        Operation::DefineApp {
            app: AppId([2; 32]),
            name: "Fixtures".into(),
        },
    );
    let mut v: Value = serde_json::from_slice(ARTICLE).unwrap();
    v["unique"] = json!([]);
    let bytes = serde_json::to_vec(&v).unwrap();
    let d = definition::parse(&bytes).unwrap();
    define(&mut rep, &mut log, &v);
    let tx = rep.conn().unchecked_transaction().unwrap();
    let sid = records::lookup_scope(&tx, SCOPE).unwrap().unwrap();
    coverage::set(&tx, sid, Position(2), false).unwrap();
    let id = RecordId([42; 32]);
    let op = Operation::Create {
        record: id,
        type_id: d.type_id,
        revision: RevisionId::of(&bytes),
        doc: json!({"title":"Replacement","url":"url"}),
    };
    let saved =
        bh_data::mutation::pending::submit(&tx, &Shipped, SCOPE, &actor(), op.clone()).unwrap();
    let state: String = tx
        .query_row(
            "SELECT state FROM data_pending WHERE mutation=?1",
            [saved.mutation.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(state, "waiting");
    assert!(matches!(
        apply::apply_ordered(
            &tx,
            &Shipped,
            &apply::Ordered {
                scope: SCOPE,
                position: Position(3),
                actor: &actor(),
                mutation: saved.mutation,
                op: &op
            }
        )
        .unwrap(),
        Outcome::Waiting(_)
    ));
    let pending_bytes: Vec<u8> = tx
        .query_row(
            "SELECT payload FROM data_pending WHERE mutation=?1",
            [saved.mutation.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let revision = bh_data::note::upsert_projection(&tx, SCOPE, id, "Canonical Note").unwrap();
    assert_eq!(
        records::get(&tx, sid, id).unwrap().unwrap().text_rev,
        revision
    );
    assert_eq!(
        bh_data::text::next_jobs(&tx, 10).unwrap()[0].wanted,
        revision
    );
    assert_eq!(
        tx.query_row(
            "SELECT payload FROM data_pending WHERE mutation=?1",
            [saved.mutation.0.as_slice()],
            |r| r.get::<_, Vec<u8>>(0)
        )
        .unwrap(),
        pending_bytes
    );
    coverage::set(&tx, sid, Position(3), true).unwrap();
    assert_eq!(apply::retry_parked(&tx, &Shipped, SCOPE).unwrap().len(), 1);
    assert_eq!(
        records::get(&tx, sid, id).unwrap().unwrap().type_id,
        bh_data::TypeId::core("note")
    );
    assert_eq!(
        bh_data::mutation::pending::rejected(&tx, SCOPE).unwrap()[0]
            .rejection
            .code,
        bh_data::RejectCode::Exists
    );
    tx.commit().unwrap();
    drop(rep);
    let mut conn = rusqlite::Connection::open(db).unwrap();
    assert_note_extracts_fresh(&mut conn, id, revision);
    let restored = {
        let tx = conn.transaction().unwrap();
        bh_data::note::remove_projection(&tx, SCOPE, id).unwrap();
        assert!(records::get(&tx, sid, id).unwrap().unwrap().deleted);
        assert!(bh_data::text::next_jobs(&tx, 10).unwrap().is_empty());
        let rev = bh_data::note::upsert_projection(&tx, SCOPE, id, "Restored Note").unwrap();
        assert_eq!(records::get(&tx, sid, id).unwrap().unwrap().text_rev, rev);
        assert_eq!(bh_data::text::next_jobs(&tx, 10).unwrap()[0].wanted, rev);
        tx.commit().unwrap();
        rev
    };
    assert_note_extracts_fresh(&mut conn, id, restored);
}
fn assert_note_extracts_fresh(conn: &mut rusqlite::Connection, id: RecordId, revision: u64) {
    use bh_data::{catalogue::Shipped, query::*, text};
    struct Available(RecordId);
    impl text::BodyText for Available {
        fn body_text(
            &self,
            scope: Scope,
            record: RecordId,
        ) -> Result<Option<String>, bh_data::DataError> {
            assert_eq!((scope, record), (SCOPE, self.0));
            Ok(Some("discoverablebody".into()))
        }
    }
    assert_eq!(text::extract_step(conn, &Available(id), 10).unwrap(), 1);
    assert!(text::next_jobs(conn, 10).unwrap().is_empty());
    let page = run(
        conn,
        SCOPE,
        &[SCOPE],
        &Shipped,
        &Query {
            select: TypeSelect::Family(bh_data::TypeId::core("note")),
            filter: None,
            sort: vec![],
            fields: vec![],
            follow: vec![],
            limit: 50,
            after: None,
            text: Some(TextMatch {
                terms: "discoverablebody".into(),
                on: None,
                require_revision: Some(revision),
            }),
        },
        Budget::INTERACTIVE,
    )
    .unwrap();
    assert_eq!(page.completeness, Completeness::Complete);
    assert_eq!(
        page.rows.iter().map(|r| r.record).collect::<Vec<_>>(),
        vec![id]
    );
}
#[test]
fn adoption_waits_for_missing_source_app_provenance() {
    use bh_data::{
        Position,
        catalogue::Shipped,
        mutation::apply,
        store::{coverage, records, registry},
    };
    let (mut rep, mut log) = setup();
    let bytes = ARTICLE.to_vec();
    assert!(matches!(
        order(
            &mut rep,
            &mut log,
            Operation::DefineType {
                bytes: bytes.clone()
            }
        ),
        Outcome::Accepted { .. }
    ));
    let tx = rep.conn().unchecked_transaction().unwrap();
    let source = records::lookup_scope(&tx, SCOPE).unwrap().unwrap();
    tx.execute("DELETE FROM data_app_at WHERE scope=?1", [source])
        .unwrap();
    coverage::set(&tx, source, Position(2), false).unwrap();
    let private = Scope {
        base: SCOPE.base,
        audience: [7; 32],
    };
    let dst = records::scope_id(&tx, private, &Shipped).unwrap();
    coverage::set(&tx, dst, Position(2), true).unwrap();
    let op = Operation::Adopt {
        from_audience: SCOPE.audience,
        revision: RevisionId::of(&bytes),
        bytes,
    };
    let out = bh_data::testkit::apply_ordered(
        &tx,
        &Shipped,
        &apply::Ordered {
            scope: private,
            position: Position(3),
            actor: &actor(),
            mutation: MutationId::random(),
            op: &op,
        },
    )
    .unwrap();
    assert!(matches!(out, Outcome::Waiting(_)), "{out:?}");
    registry::set_app(&tx, source, AppId([2; 32]), "Fixtures", true, Position(1)).unwrap();
    coverage::set(&tx, source, Position(3), true).unwrap();
    assert_eq!(
        bh_data::testkit::retry_parked(&tx, &Shipped, private)
            .unwrap()
            .len(),
        1
    );
    assert!(
        registry::compiled(&tx, dst, RevisionId::of(ARTICLE))
            .unwrap()
            .is_some()
    );
}
fn actor() -> Actor {
    Actor::Device {
        account: [1; 32],
        device: [1; 32],
    }
}
fn order(rep: &mut Replica, log: &mut OrderedLog, op: Operation) -> Outcome {
    log.append(
        SCOPE,
        &actor(),
        payload::encode(MutationId::random(), &op).unwrap(),
    );
    rep.sync_from(log, Delivery::InOrder)
        .unwrap()
        .pop()
        .unwrap()
        .1
}
fn setup() -> (Replica, OrderedLog) {
    let mut rep = Replica::new_in_memory().unwrap();
    let mut log = OrderedLog::new();
    assert!(matches!(
        order(
            &mut rep,
            &mut log,
            Operation::DefineApp {
                app: AppId([2; 32]),
                name: "Fixtures".into()
            }
        ),
        Outcome::Accepted { .. }
    ));
    (rep, log)
}
fn define(rep: &mut Replica, log: &mut OrderedLog, v: &Value) -> Outcome {
    order(
        rep,
        log,
        Operation::DefineType {
            bytes: serde_json::to_vec(v).unwrap(),
        },
    )
}
fn expansion(depth: usize) -> Value {
    let mut v: Value = serde_json::from_slice(ARTICLE).unwrap();
    v["schema"]["properties"]["x"] =
        json!({"type":"object","allOf":[{"$ref":format!("#/$defs/x{depth}")}]});
    v["fields"]["/x"] = json!({"kind":"atomic","write":"direct","meaning":"Bounded value"});
    v["schema"]["$defs"] = json!({"x0":{"type":"object"}});
    for n in 1..=depth {
        v["schema"]["$defs"][format!("x{n}")] =
            json!({"allOf":vec![json!({"$ref":format!("#/$defs/x{}",n-1)});8]});
    }
    v
}
#[test]
fn expanded_schema_rejected_at_definition_acceptance_without_validation() {
    let (mut rep, mut log) = setup();
    assert!(matches!(
        define(&mut rep, &mut log, &expansion(8)),
        Outcome::Rejected(_)
    ));
}
#[test]
fn encoded_fragment_decoys_rejected_before_record_validation() {
    for cycle in [false, true] {
        let (mut rep, mut log) = setup();
        let mut v = expansion(8);
        for n in 1..=8 {
            v["schema"]["$defs"][format!("x{n}")] =
                json!({"allOf":vec![json!({"$ref":format!("#/$defs/x%3{}", n-1)});8]});
            v["schema"]["$defs"][format!("x%3{}", n - 1)] = json!({"type":"object"});
        }
        if cycle {
            v["schema"]["$defs"]["x0"] = json!({"$ref":"#/$defs/x%30"});
        }
        let result = define(&mut rep, &mut log, &v);
        assert!(
            matches!(result, Outcome::Rejected(_)),
            "cycle={cycle}: {result:?}"
        );
    }
}
#[test]
fn literal_and_pointer_escaped_definition_names_still_validate() {
    let (mut rep, mut log) = setup();
    let mut v = expansion(0);
    v["schema"]["$defs"] = json!({"literal":{"type":"object"}, "slash/tilde~":{"type":"object"}});
    v["schema"]["properties"]["x"] = json!({"type":"object", "allOf":[
        {"$ref":"#/$defs/literal"}, {"$ref":"#/$defs/slash~1tilde~0"}
    ]});
    // Annotation objects and property names are data, not reference locations.
    v["schema"]["examples"] = json!([{"$ref":"#/$defs/x%30"}]);
    v["schema"]["properties"]["x"]["properties"] = json!({"$ref":{"const":"#/$defs/x%30"}});
    assert!(matches!(
        define(&mut rep, &mut log, &v),
        Outcome::Accepted { .. }
    ));
    let bytes = serde_json::to_vec(&v).unwrap();
    let d = definition::parse(&bytes).unwrap();
    assert!(matches!(
        order(
            &mut rep,
            &mut log,
            Operation::Create {
                record: RecordId([91; 32]),
                type_id: d.type_id,
                revision: RevisionId::of(&bytes),
                doc: json!({"title":"literal", "url":"literal", "x":{"$ref":"#/$defs/x%30"}})
            }
        ),
        Outcome::Accepted { .. }
    ));
}
#[test]
fn bounded_expansion_remains_accepted() {
    let (mut rep, mut log) = setup();
    assert!(matches!(
        define(&mut rep, &mut log, &expansion(3)),
        Outcome::Accepted { .. }
    ));
}
#[test]
fn subtype_cannot_add_unique_inherited_writable_field() {
    let (mut rep, mut log) = setup();
    let article: Value = serde_json::from_slice(ARTICLE).unwrap();
    assert!(matches!(
        define(&mut rep, &mut log, &article),
        Outcome::Accepted { .. }
    ));
    let mut sub: Value =
        serde_json::from_slice(include_bytes!("fixtures/types/SpecialArticle.json")).unwrap();
    // Pin exactly the bytes submitted above, not the fixture's whitespace.
    sub["extends"]["revision"] = json!(RevisionId::of(&serde_json::to_vec(&article).unwrap()));
    sub["unique"] = json!([{"name":"title_unique","keys":["/title"]}]);
    assert!(matches!(
        define(&mut rep, &mut log, &sub),
        Outcome::Rejected(_)
    ));
    sub["unique"] = json!([{"name":"category_unique","keys":["/category"]}]);
    sub["schema"]["required"] = json!(["category"]);
    assert!(matches!(
        define(&mut rep, &mut log, &sub),
        Outcome::Accepted { .. }
    ));
    let d = definition::parse(&serde_json::to_vec(&sub).unwrap()).unwrap();
    let sid = bh_data::store::records::lookup_scope(rep.conn(), SCOPE)
        .unwrap()
        .unwrap();
    let ct =
        bh_data::store::registry::current(rep.conn(), sid, d.type_id, &bh_data::catalogue::Shipped)
            .unwrap()
            .unwrap();
    assert_eq!(ct.uniques.len(), 2);
    assert!(ct.uniques.iter().any(|u| u.name == "url"));
}
#[test]
fn malformed_reference_is_rejected_before_hooks_and_next_event_runs() {
    let (mut rep, mut log) = setup();
    let mut v: Value =
        serde_json::from_slice(include_bytes!("fixtures/types/Recipe.json")).unwrap();
    v["uses"] = json!([]);
    v["schema"]["properties"]
        .as_object_mut()
        .unwrap()
        .remove("location");
    v["fields"].as_object_mut().unwrap().remove("/location");
    let bytes = serde_json::to_vec(&v).unwrap();
    let d = definition::parse(&bytes).unwrap();
    assert!(matches!(
        define(&mut rep, &mut log, &v),
        Outcome::Accepted { .. }
    ));
    for bad in [
        json!({"record":"z".repeat(64)}),
        json!({"record":"01".repeat(32),"audience":"z".repeat(64)}),
    ] {
        let op = Operation::Create {
            record: RecordId([9; 32]),
            type_id: d.type_id,
            revision: RevisionId::of(&bytes),
            doc: json!({"name":"Recipe","instructions":bad}),
        };
        assert!(rep.submit(SCOPE, &actor(), op.clone()).is_err());
        assert!(matches!(
            order(&mut rep, &mut log, op),
            Outcome::Rejected(_)
        ));
    }
    assert!(matches!(
        order(
            &mut rep,
            &mut log,
            Operation::Create {
                record: RecordId([9; 32]),
                type_id: d.type_id,
                revision: RevisionId::of(&bytes),
                doc: json!({"name":"Recipe","instructions":{"record":"01".repeat(32)}})
            }
        ),
        Outcome::Accepted { .. }
    ));
}
#[test]
fn note_extension_resource_verdict_does_not_depend_on_title() {
    let mut v: Value =
        serde_json::from_slice(include_bytes!("fixtures/types/JournalEntry.json")).unwrap();
    v["indexes"] = json!([]);
    v["fields"] = json!({});
    v["schema"] = json!({"type":"object","properties":{},"required":[]});
    for name in ["a", "b", "c"] {
        v["schema"]["properties"][name] = json!({"type":"string","maxLength":16384});
        v["fields"][format!("/{name}")] =
            json!({"kind":"string","write":"direct","meaning":"Extension"});
    }
    let bytes = serde_json::to_vec(&v).unwrap();
    let d = definition::parse(&bytes).unwrap();
    for title in ["x".to_owned(), "x".repeat(200)] {
        let (mut rep, mut log) = setup();
        assert!(matches!(
            define(&mut rep, &mut log, &v),
            Outcome::Accepted { .. }
        ));
        // A separate connection isn't required: testkit exposes host writes in a transaction.
        let tx = rep.conn().unchecked_transaction().unwrap();
        bh_data::note::upsert_projection(&tx, SCOPE, RecordId([7; 32]), &title).unwrap();
        tx.commit().unwrap();
        let op = Operation::BindNote {
            note: RecordId([7; 32]),
            type_id: d.type_id,
            revision: RevisionId::of(&bytes),
            doc: json!({"a":"a".repeat(16320),"b":"b".repeat(16320),"c":"c".repeat(16320)}),
        };
        assert!(matches!(
            order(&mut rep, &mut log, op),
            Outcome::Accepted { .. }
        ));
        // A delayed title repair after binding must not change later extension verdicts.
        let tx = rep.conn().unchecked_transaction().unwrap();
        bh_data::note::upsert_projection(&tx, SCOPE, RecordId([7; 32]), &"r".repeat(200)).unwrap();
        tx.commit().unwrap();
        let edit = Operation::Edit {
            record: RecordId([7; 32]),
            revision: RevisionId::of(&bytes),
            changes: vec![FieldChange {
                path: bh_data::FieldPath::parse("/a").unwrap(),
                value: Some(json!("d".repeat(16320))),
            }],
        };
        assert!(rep.submit(SCOPE, &actor(), edit.clone()).is_ok());
        assert!(matches!(
            order(&mut rep, &mut log, edit),
            Outcome::Accepted { .. }
        ));
    }
}
