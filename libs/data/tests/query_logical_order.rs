use bh_data::{
    Actor, AppId, FieldPath, KeyRef, RecordId, RevisionId, Scope,
    catalogue::Shipped,
    definition,
    mutation::{apply::Outcome, ops::Operation},
    query::{self, Budget, Completeness, Query, SortKey, TypeSelect},
    testkit::{Delivery, OrderedLog, Replica},
};
use serde_json::json;

const SCOPE: Scope = Scope {
    base: [7; 32],
    audience: [8; 32],
};
const APP: AppId = AppId([9; 32]);
const ID1: RecordId = RecordId([1; 32]);
const ID2: RecordId = RecordId([2; 32]);

fn actor(n: u8) -> Actor {
    Actor::Device {
        account: [n; 32],
        device: [n; 32],
    }
}
fn definition_bytes() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "format": "bh-type/1", "local": "01010101010101010101010101010101",
        "app": "0909090909090909090909090909090909090909090909090909090909090909",
        "kind": "record", "name": "Item", "description": "A simple titled item.",
        "extends": null, "uses": [],
        "schema": {"type": "object", "properties": {"title": {"type": "string", "maxLength": 200}}, "required": ["title"]},
        "fields": {"/title": {"kind": "string", "write": "direct", "meaning": "The item's title"}},
        "actions": [], "indexes": [{"name": "by_title", "keys": ["/title"]}],
        "unique": [], "search": {"title": "/title", "text": []}, "queries": [],
        "evolution": {"previous": null, "migration": "", "migration_ops": [],
            "examples": {"valid": [{"title": "same"}], "invalid": [{"title": 5}]}},
        "rationale": ["Titles are independent and may repeat."]
    })).unwrap()
}
fn check_accepted(outcomes: Vec<(bh_data::Position, Outcome)>) {
    for (position, outcome) in outcomes {
        assert!(
            matches!(outcome, Outcome::Accepted { .. }),
            "position {position:?}: {outcome:?}"
        );
    }
}

fn query(ty: bh_data::TypeId, desc: bool, limit: u32) -> Query {
    Query {
        select: TypeSelect::Exact(ty),
        filter: None,
        sort: vec![SortKey {
            key: KeyRef::Field(FieldPath::parse("/title").unwrap()),
            desc,
        }],
        fields: vec![FieldPath::parse("/title").unwrap()],
        follow: vec![],
        text: None,
        limit,
        after: None,
    }
}
fn ordered(replica: &Replica, mut q: Query) -> Vec<RecordId> {
    let mut ids = vec![];
    loop {
        let page = query::run(
            replica.conn(),
            SCOPE,
            &[SCOPE],
            &Shipped,
            &q,
            Budget::INTERACTIVE,
        )
        .unwrap();
        assert_eq!(page.completeness, Completeness::Complete);
        assert!(
            page.rows
                .iter()
                .all(|r| r.values["/title"] == json!("same"))
        );
        ids.extend(page.rows.iter().map(|r| r.record));
        match page.next {
            Some(next) => q.after = Some(next),
            None => break,
        }
    }
    ids
}
fn assert_entries_match_records(replica: &Replica) {
    let (total, wrong): (i64, i64) = replica.conn().query_row(
        "SELECT count(*),coalesce(sum(e.record != r.record OR length(e.record) != 32),0) FROM data_index_entry e JOIN data_record r ON r.id=e.rec",
        [], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert!(total > 0);
    assert_eq!(wrong, 0);
}
fn reject_integer_and_short_identity_cursors(replica: &Replica, ty: bh_data::TypeId) {
    let mut q = query(ty, false, 1);
    let first = query::run(
        replica.conn(),
        SCOPE,
        &[SCOPE],
        &Shipped,
        &q,
        Budget::INTERACTIVE,
    )
    .unwrap();
    let cursor = first.next.unwrap();
    let raw: Vec<u8> = (0..cursor.0.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&cursor.0[i..i + 2], 16).unwrap())
        .collect();
    let state: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    for old_integer in [false, true] {
        let mut invalid = state.clone();
        if old_integer {
            invalid.as_object_mut().unwrap().remove("record");
            invalid["rec"] = json!(1);
        } else {
            invalid["record"] = json!([1; 31].to_vec());
        }
        let raw = serde_json::to_vec(&invalid).unwrap();
        q.after = Some(query::Cursor(
            raw.iter().map(|b| format!("{b:02x}")).collect(),
        ));
        assert!(matches!(
            query::run(
                replica.conn(),
                SCOPE,
                &[SCOPE],
                &Shipped,
                &q,
                Budget::INTERACTIVE
            ),
            Err(query::QueryError::NotQueryable { .. })
        ));
    }
}
#[test]
fn offline_creates_converge_in_logical_tie_order_after_sync_and_reopen() {
    for count in [2, 3] {
        let dir = tempfile::tempdir().unwrap();
        let a_path = dir.path().join("a.sqlite");
        let b_path = dir.path().join("b.sqlite");
        let mut a = Replica::new_file(&a_path).unwrap();
        let mut b = Replica::new_file(&b_path).unwrap();
        let bytes = definition_bytes();
        let ty = definition::parse(&bytes).unwrap().type_id;
        let rev = RevisionId::of(&bytes);
        let mut log = OrderedLog::new();
        for op in [
            Operation::DefineApp {
                app: APP,
                name: "Items".into(),
            },
            Operation::DefineType { bytes },
        ] {
            let saved = a.submit(SCOPE, &actor(1), op).unwrap();
            log.append(SCOPE, &actor(1), saved.payload);
            check_accepted(a.sync_from(&log, Delivery::InOrder).unwrap());
        }
        check_accepted(b.sync_from(&log, Delivery::InOrder).unwrap());
        let create = |record| Operation::Create {
            record,
            type_id: ty,
            revision: rev,
            doc: json!({"title":"same"}),
        };
        let sa = a.submit(SCOPE, &actor(1), create(ID1)).unwrap();
        let sb = b.submit(SCOPE, &actor(2), create(ID2)).unwrap();
        log.append(SCOPE, &actor(1), sa.payload);
        log.append(SCOPE, &actor(2), sb.payload);
        if count == 3 {
            let saved = b
                .submit(SCOPE, &actor(2), create(RecordId([3; 32])))
                .unwrap();
            log.append(SCOPE, &actor(2), saved.payload);
        }
        check_accepted(a.sync_from(&log, Delivery::InOrder).unwrap());
        check_accepted(b.sync_from(&log, Delivery::InOrder).unwrap());
        assert_eq!(
            a.state_digest(SCOPE).unwrap(),
            b.state_digest(SCOPE).unwrap()
        );
        // Live pending edits must retain logical IDs in rewritten entries.
        for title in ["changed", "same"] {
            let saved = b
                .submit(
                    SCOPE,
                    &actor(2),
                    Operation::Edit {
                        record: ID2,
                        revision: rev,
                        changes: vec![bh_data::mutation::ops::FieldChange {
                            path: FieldPath::parse("/title").unwrap(),
                            value: Some(json!(title)),
                        }],
                    },
                )
                .unwrap();
            assert_entries_match_records(&b);
            log.append(SCOPE, &actor(2), saved.payload);
            check_accepted(a.sync_from(&log, Delivery::InOrder).unwrap());
            check_accepted(b.sync_from(&log, Delivery::InOrder).unwrap());
        }
        assert_eq!(
            a.state_digest(SCOPE).unwrap(),
            b.state_digest(SCOPE).unwrap()
        );
        let mut continuation = query(ty, false, 1);
        continuation.after = query::run(
            a.conn(),
            SCOPE,
            &[SCOPE],
            &Shipped,
            &continuation,
            Budget::INTERACTIVE,
        )
        .unwrap()
        .next;
        for phase in 0..3 {
            if phase == 2 {
                for replica in [&a, &b] {
                    let tx = replica.conn().unchecked_transaction().unwrap();
                    bh_data::index::begin_rebuild(&tx).unwrap();
                    bh_data::index::clear_step_bounded(&tx, 1, 20_000).unwrap();
                    tx.commit().unwrap();
                }
            }
            if phase > 0 {
                drop(a);
                drop(b);
                if phase == 1 {
                    // A closed SQLite copy is a fixture snapshot, not a host's
                    // protected snapshot/admission integration.
                    let snapshot_path = dir.path().join("snapshot.sqlite");
                    std::fs::copy(&a_path, &snapshot_path).unwrap();
                    let snapshot = Replica::new_file(&snapshot_path).unwrap();
                    assert_eq!(
                        query::run(
                            snapshot.conn(),
                            SCOPE,
                            &[SCOPE],
                            &Shipped,
                            &continuation,
                            Budget::INTERACTIVE
                        )
                        .unwrap()
                        .rows[0]
                            .record,
                        ID2
                    );
                }
                a = Replica::new_file(&a_path).unwrap();
                b = Replica::new_file(&b_path).unwrap();
            }
            if phase == 2 {
                for file in [&a_path, &b_path] {
                    bh_data::index::rebuild_all(|| {
                        rusqlite::Connection::open(file)
                            .map_err(|e| bh_data::DataError::Sql(e.to_string()))
                    })
                    .unwrap();
                }
                a.release_backfill().unwrap();
                b.release_backfill().unwrap();
            }
            for replica in [&a, &b] {
                assert_entries_match_records(replica);
                reject_integer_and_short_identity_cursors(replica, ty);
                assert_eq!(
                    query::run(
                        replica.conn(),
                        SCOPE,
                        &[SCOPE],
                        &Shipped,
                        &continuation,
                        Budget::INTERACTIVE
                    )
                    .unwrap()
                    .rows[0]
                        .record,
                    ID2
                );
            }
            for desc in [false, true] {
                let mut expected = vec![ID1, ID2];
                if count == 3 {
                    expected.push(RecordId([3; 32]));
                }
                if desc {
                    expected.reverse();
                }
                for replica in [&a, &b] {
                    for limit in [1, 10] {
                        for with_text in [false, true] {
                            let mut q = query(ty, desc, limit);
                            if with_text {
                                q.text = Some(query::TextMatch {
                                    terms: "same".into(),
                                    on: None,
                                    require_revision: None,
                                });
                            }
                            assert_eq!(
                                ordered(replica, q),
                                expected,
                                "count={count}, desc={desc}, limit={limit}, phase={phase}, text={with_text}"
                            );
                        }
                    }
                }
            }
        }
    }
}
