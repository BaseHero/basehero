use bh_data::{
    Actor, AppId, FieldPath, MutationId, Position, RecordId, RecordRef, RevisionId, Scope, TypeId,
    catalogue::Shipped,
    definition,
    mutation::{apply, ops::Operation},
    payload,
    query::*,
    store::{records, registry},
    testkit::{Delivery, OrderedLog, Replica},
};
use serde_json::{Value, json};

const SCOPE: Scope = Scope {
    base: [1; 32],
    audience: [0; 32],
};
const ARTICLE: &[u8] = include_bytes!("fixtures/types/Article.json");
const SPECIAL: &[u8] = include_bytes!("fixtures/types/SpecialArticle.json");
const SELECTION: &[u8] = include_bytes!("fixtures/types/SourceSelection.json");
const DEST: RecordId = RecordId([80; 32]);
const SOURCE: RecordId = RecordId([81; 32]);
fn actor() -> Actor {
    Actor::Device {
        account: [1; 32],
        device: [1; 32],
    }
}
fn path(s: &str) -> FieldPath {
    FieldPath::parse(s).unwrap()
}
fn append(log: &mut OrderedLog, scope: Scope, op: Operation) {
    log.append(
        scope,
        &actor(),
        payload::encode(MutationId::random(), &op).unwrap(),
    );
}
fn setup(target_scope: Scope, family: bool) -> (Replica, OrderedLog, TypeId) {
    let mut rep = Replica::new_in_memory().unwrap();
    let mut log = OrderedLog::new();
    append(
        &mut log,
        SCOPE,
        Operation::DefineApp {
            app: AppId([2; 32]),
            name: "Fixtures".into(),
        },
    );
    append(
        &mut log,
        SCOPE,
        Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        },
    );
    if target_scope != SCOPE {
        append(
            &mut log,
            target_scope,
            Operation::DefineApp {
                app: AppId([2; 32]),
                name: "Fixtures".into(),
            },
        );
        append(
            &mut log,
            target_scope,
            Operation::DefineType {
                bytes: ARTICLE.to_vec(),
            },
        );
    }
    let mut selection: Value = serde_json::from_slice(SELECTION).unwrap();
    selection["fields"]["/article"]["ref"]["family"] = json!(family);
    let bytes = serde_json::to_vec(&selection).unwrap();
    let ty = definition::parse(&bytes).unwrap().type_id;
    append(
        &mut log,
        SCOPE,
        Operation::DefineType {
            bytes: bytes.clone(),
        },
    );
    append(
        &mut log,
        SCOPE,
        Operation::Create {
            record: SOURCE,
            type_id: ty,
            revision: RevisionId::of(&bytes),
            doc: json!({"article": RecordRef {record:DEST, audience:(target_scope != SCOPE).then_some(target_scope.audience)}}),
        },
    );
    for (_, out) in rep.sync_from(&log, Delivery::InOrder).unwrap() {
        assert!(matches!(out, apply::Outcome::Accepted { .. }), "{out:?}");
    }
    (rep, log, ty)
}
fn append_target(log: &mut OrderedLog, scope: Scope, bytes: &[u8]) {
    append(
        log,
        scope,
        Operation::DefineType {
            bytes: bytes.to_vec(),
        },
    );
    append(
        log,
        scope,
        Operation::Create {
            record: DEST,
            type_id: definition::parse(bytes).unwrap().type_id,
            revision: RevisionId::of(bytes),
            doc: json!({"title":"needle", "url":"needle"}),
        },
    );
}
fn queries(ty: TypeId) -> Vec<Query> {
    let base = Query {
        select: TypeSelect::Exact(ty),
        filter: None,
        sort: vec![],
        fields: vec![],
        follow: vec![],
        text: None,
        limit: 50,
        after: None,
    };
    let mut follow = base.clone();
    follow.follow.push(Follow {
        path: path("/article"),
        fields: vec![path("/title")],
    });
    let mut via = base.clone();
    via.filter = Some(Expr::Via {
        path: path("/article"),
        filter: Box::new(Expr::Cmp {
            path: path("/title"),
            op: CmpOp::Eq,
            value: json!("needle"),
        }),
    });
    let mut text = base;
    text.text = Some(TextMatch {
        terms: "needle".into(),
        on: Some(path("/article")),
        require_revision: None,
    });
    vec![follow, via, text]
}
fn page(rep: &Replica, q: &Query) -> Page {
    run(
        rep.conn(),
        SCOPE,
        &[SCOPE],
        &Shipped,
        q,
        Budget { vm_steps: 5_000 },
    )
    .unwrap()
}

#[test]
fn unknown_subtype_follow_is_incomplete_even_without_a_known_target_row() {
    // Exact references also need the actual destination's parked-record probe;
    // a future concrete type cannot be inferred from the declared target list.
    for family in [true, false] {
        let (mut old, mut log, ty) = setup(SCOPE, family);
        old.without_kinds(&["define_type", "create"]);
        append_target(&mut log, SCOPE, SPECIAL);
        old.sync_from(&log, Delivery::InOrder).unwrap();
        let sid = records::lookup_scope(old.conn(), SCOPE).unwrap().unwrap();
        assert!(records::get(old.conn(), sid, DEST).unwrap().is_none());
        let result = page(&old, &queries(ty)[0]);
        assert!(result.rows[0].follows["/article"].is_none());
        assert!(
            matches!(result.completeness, Completeness::Incomplete(_)),
            "family={family}: {:?}",
            result.completeness
        );
    }
}
#[test]
fn unknown_subtype_negative_via_and_referenced_text_match_supported_decoder() {
    let (mut old, mut log, ty) = setup(SCOPE, true);
    let mut supported = Replica::new_in_memory().unwrap();
    old.without_kinds(&["define_type", "create"]);
    append_target(&mut log, SCOPE, SPECIAL);
    old.sync_from(&log, Delivery::InOrder).unwrap();
    for (_, out) in supported.sync_from(&log, Delivery::InOrder).unwrap() {
        assert!(matches!(out, apply::Outcome::Accepted { .. }), "{out:?}");
    }
    for (i, q) in queries(ty).iter().enumerate() {
        let before = page(&old, q);
        let control = page(&supported, q);
        assert_eq!(control.completeness, Completeness::Complete);
        assert_eq!(control.rows.len(), 1);
        if i == 0 {
            assert_eq!(
                control.rows[0].follows["/article"].as_ref().unwrap().record,
                DEST
            );
        } else {
            assert!(before.rows.is_empty());
            assert!(
                matches!(before.completeness, Completeness::Incomplete(_)),
                "query={i}: {:?}",
                before.completeness
            );
        }
    }
    old.upgrade().unwrap();
    for q in queries(ty) {
        let result = page(&old, &q);
        assert_eq!(result.completeness, Completeness::Complete);
        assert_eq!(result.rows.len(), 1);
    }
}
#[test]
fn unknown_targets_in_unreadable_audiences_do_not_affect_answers() {
    let private = Scope {
        audience: [9; 32],
        ..SCOPE
    };
    let (mut old, mut log, ty) = setup(private, true);
    old.without_kinds(&["define_type", "create"]);
    append_target(&mut log, private, SPECIAL);
    old.sync_from(&log, Delivery::InOrder).unwrap();
    for (i, q) in queries(ty).iter().enumerate() {
        let result = page(&old, q);
        assert_eq!(result.completeness, Completeness::Complete);
        if i == 0 {
            assert!(result.rows[0].follows["/article"].is_none());
        } else {
            assert!(result.rows.is_empty());
        }
    }
}
#[test]
#[ignore = "run with scripts/check.sh data-scale (release)"]
fn unrelated_type_reclassification_and_large_known_backlog_keep_queries_bounded() {
    let (mut old, mut log, ty) = setup(SCOPE, true);
    let mut unrelated: Value = serde_json::from_slice(ARTICLE).unwrap();
    unrelated["local"] = json!("bb".repeat(16));
    unrelated["unique"] = json!([]);
    let bytes = serde_json::to_vec(&unrelated).unwrap();
    old.without_kinds(&["define_type", "create"]);
    append(
        &mut log,
        SCOPE,
        Operation::DefineType {
            bytes: bytes.clone(),
        },
    );
    let type_id = definition::parse(&bytes).unwrap().type_id;
    let revision = RevisionId::of(&bytes);
    let op = |record| Operation::Create {
        record,
        type_id,
        revision,
        doc: json!({"title":"unrelated", "url":"unrelated"}),
    };
    append(&mut log, SCOPE, op(RecordId([90; 32])));
    old.sync_from(&log, Delivery::InOrder).unwrap();
    for q in &queries(ty)[1..] {
        assert!(matches!(
            page(&old, q).completeness,
            Completeness::Incomplete(_)
        ));
    }
    // Install just the verified registry piece from a supported replica,
    // without replaying any parked row. This exercises reclassification at
    // type installation, not incidentally when a payload is parked again.
    // This is a registry-transfer fixture, not a production snapshot adapter.
    let mut supported = Replica::new_in_memory().unwrap();
    for (_, out) in supported.sync_from(&log, Delivery::InOrder).unwrap() {
        assert!(matches!(out, apply::Outcome::Accepted { .. }), "{out:?}");
    }
    let supported_sid = records::lookup_scope(supported.conn(), SCOPE)
        .unwrap()
        .unwrap();
    let ct = registry::current(supported.conn(), supported_sid, type_id, &Shipped)
        .unwrap()
        .unwrap();
    let tx = old.conn().unchecked_transaction().unwrap();
    let sid = records::lookup_scope(&tx, SCOPE).unwrap().unwrap();
    registry::store_definition(&tx, sid, &ct, &bytes, Position(5)).unwrap();
    registry::set_current(&tx, sid, type_id, revision, &[revision], Position(5)).unwrap();
    tx.commit().unwrap();
    assert_eq!(
        old.conn()
            .query_row("SELECT count(*) FROM data_parked", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        2
    );
    for q in queries(ty) {
        assert_eq!(page(&old, &q).completeness, Completeness::Complete);
    }
    let tx = old.conn().unchecked_transaction().unwrap();
    for n in 0..20_000u32 {
        let mut id = [91; 32];
        id[..4].copy_from_slice(&n.to_be_bytes());
        let mut payload = payload::encode(MutationId::random(), &op(RecordId(id))).unwrap();
        payload[0] = 255;
        assert!(matches!(
            apply::apply_payload(
                &tx,
                &Shipped,
                SCOPE,
                Position(100 + n as u64),
                &actor(),
                &payload
            )
            .unwrap(),
            apply::Outcome::Waiting(_)
        ));
    }
    tx.commit().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("reclassified.sqlite");
    old.conn()
        .execute("VACUUM INTO ?1", [db.to_str().unwrap()])
        .unwrap();
    drop(old);
    let old = Replica::new_file(&db).unwrap();
    // A fixed 5k VM budget covers each full page, including gap probes,
    // independent of the 20k parked payloads of a known unrelated type.
    for q in queries(ty) {
        assert_eq!(page(&old, &q).completeness, Completeness::Complete);
    }
}
