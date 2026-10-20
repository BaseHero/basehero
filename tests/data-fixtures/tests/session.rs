use bh_data::{
    AppId, FieldPath, RecordId, RevisionId, TypeId,
    mutation::{
        history::HistoryCursor,
        ops::{FieldChange, Operation},
    },
    query::{Aggregate, Measure, Query, QueryError, TypeSelect},
    session::{DataSession, SessionError, TypeRef},
    testkit::{Delivery, OrderedLog, Replica},
    tools,
};
use bh_data_fixtures::{FixtureAuthority, job, member, scopes};
use serde_json::json;

const ARTICLE: &[u8] = include_bytes!("../../../libs/data/tests/fixtures/types/Article.json");
const ARTICLE_V2: &[u8] = include_bytes!("../../../libs/data/tests/fixtures/types/Article.v2.json");
fn v2_bytes() -> Vec<u8> {
    let mut v2: serde_json::Value = serde_json::from_slice(ARTICLE_V2).unwrap();
    v2["evolution"]["previous"] = json!(RevisionId::of(ARTICLE));
    // Loosen an existing rule so the device-only revision can become current.
    v2["schema"]["properties"]["title"]["maxLength"] = json!(300);
    serde_json::to_vec(&v2).unwrap()
}
fn rejected(error: SessionError) -> bh_data::Rejection {
    match error {
        SessionError::Rejected(rejection) => rejection,
        SessionError::Data(error) => panic!("unexpected storage error: {error}"),
        SessionError::ConfirmationRequired(p) => panic!("unexpected confirmation: {p:?}"),
    }
}
fn setup() -> (Replica, bh_data::Scope, bh_data::Scope) {
    let (shared, private) = scopes(4);
    (Replica::new_in_memory().unwrap(), shared, private)
}
fn session(replica: &Replica, scope: bh_data::Scope) -> DataSession<&Replica, FixtureAuthority> {
    DataSession::new(
        replica,
        FixtureAuthority {
            actor: member(7),
            reads: vec![scope],
            write: Some(scope),
        },
    )
}
fn query(ty: TypeId) -> Query {
    Query {
        select: TypeSelect::Exact(ty),
        filter: None,
        sort: vec![],
        fields: vec![],
        follow: vec![],
        text: None,
        limit: 50,
        after: None,
    }
}
fn tool_scope(scope: bh_data::Scope) -> serde_json::Value {
    let hex = |bytes: [u8; 32]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    json!({"base": hex(scope.base), "audience": hex(scope.audience)})
}
fn app() -> AppId {
    AppId([2; 32])
}
fn type_id() -> TypeId {
    bh_data::definition::parse(ARTICLE).unwrap().type_id
}

#[test]
fn describe_returns_meaning_examples_rationale_operations() {
    let (mut replica, shared, _) = setup();
    let mut log = OrderedLog::new();
    let saved = session(&replica, shared)
        .submit(Operation::DefineApp {
            app: app(),
            name: "Articles".into(),
        })
        .unwrap();
    log.append(shared, &member(7), saved.payload);
    replica.sync_from(&log, Delivery::InOrder).unwrap();
    let saved = session(&replica, shared)
        .submit(Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        })
        .unwrap();
    log.append(shared, &member(7), saved.payload);
    replica.sync_from(&log, Delivery::InOrder).unwrap();
    let description = session(&replica, shared)
        .describe(shared, TypeRef::Current(type_id()))
        .unwrap();
    assert!(!description.docs.description.is_empty());
    assert!(!description.docs.examples_valid.is_empty());
    assert!(!description.docs.rationale.is_empty());
    assert!(description.operations.contains(&"create".to_string()));
    assert!(
        description
            .compiled
            .fields
            .iter()
            .all(|field| !field.meaning.is_empty())
    );
}

#[test]
fn describe_lists_declared_actions() {
    let (mut replica, shared, _) = setup();
    let mut definition: serde_json::Value = serde_json::from_slice(ARTICLE).unwrap();
    definition["actions"] = json!([{"name":"refresh","effects":["/state"],"source":"refresh"}]);
    let bytes = serde_json::to_vec(&definition).unwrap();
    let mut log = OrderedLog::new();
    for op in [
        Operation::DefineApp {
            app: app(),
            name: "Articles".into(),
        },
        Operation::DefineType { bytes },
    ] {
        let saved = session(&replica, shared).submit(op).unwrap();
        log.append(shared, &member(7), saved.payload);
        replica.sync_from(&log, Delivery::InOrder).unwrap();
    }
    let description = session(&replica, shared)
        .describe(shared, TypeRef::Current(type_id()))
        .unwrap();
    assert!(
        description
            .operations
            .contains(&"action:refresh".to_string())
    );
    let bytes = include_bytes!("../../../libs/data/tests/fixtures/types/Address.json");
    let saved = session(&replica, shared)
        .submit(Operation::DefineType {
            bytes: bytes.to_vec(),
        })
        .unwrap();
    log.append(shared, &member(7), saved.payload);
    replica.sync_from(&log, Delivery::InOrder).unwrap();
    let value_type = bh_data::definition::parse(bytes).unwrap().type_id;
    assert!(
        session(&replica, shared)
            .describe(shared, TypeRef::Current(value_type))
            .unwrap()
            .operations
            .is_empty()
    );
}

#[test]
fn tool_validate_example_reports_pointer() {
    let (replica, shared, _) = setup();
    let s = session(&replica, shared);
    let output = tools::call(
        &s,
        "types.validate_example",
        json!({"scope": tool_scope(shared), "type": TypeId::core("note"), "example": {"title": 42}}),
    );
    assert_eq!(output["error"]["code"], "Schema");
    assert!(
        output["error"]["detail"]
            .as_str()
            .unwrap()
            .contains("/title")
    );
}

#[test]
fn tool_mutate_obeys_same_rules_as_session() {
    let (replica, shared, _) = setup();
    let s = session(&replica, shared);
    let op = Operation::Edit {
        record: RecordId([4; 32]),
        revision: RevisionId([8; 32]),
        changes: vec![FieldChange {
            path: FieldPath::parse("/title").unwrap(),
            value: Some(json!("text")),
        }],
    };
    let direct = s.submit(op.clone()).unwrap_err();
    let result = tools::call(&s, "records.mutate", serde_json::to_value(op).unwrap());
    assert_eq!(
        result["error"]["code"],
        format!("{:?}", rejected(direct).code)
    );
    assert_eq!(
        replica
            .conn()
            .query_row("SELECT count(*) FROM data_scope", [], |row| row
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn job_tool_prepare_change_returns_pending_proposal() {
    let (replica, shared, _) = setup();
    let s = DataSession::new(
        &replica,
        FixtureAuthority {
            actor: job(8, None),
            reads: vec![shared],
            write: Some(shared),
        },
    );
    let result = tools::call(&s, "types.prepare_change", json!({"bytes": ARTICLE}));
    assert!(
        result["ok"]["change"]["compatible"].is_boolean(),
        "{result}"
    );
    assert!(result.get("ok").is_some(), "{result}");
    assert!(result["ok"]["needs_device"].is_boolean());
    assert!(matches!(
        s.describe(shared, TypeRef::Current(type_id())),
        Err(bh_data::DataError::NotFound)
    ));
    let proposal = s.prepare_change(ARTICLE).unwrap();
    assert_eq!(
        rejected(s.approve(proposal).unwrap_err()).code,
        bh_data::RejectCode::DeviceOnly
    );
}

#[test]
fn proposal_gate_matches_job_gate_even_without_records() {
    let (mut replica, shared, _) = setup();
    let mut log = OrderedLog::new();
    for op in [
        Operation::DefineApp {
            app: app(),
            name: "Articles".into(),
        },
        Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        },
    ] {
        let saved = session(&replica, shared).submit(op).unwrap();
        log.append(shared, &member(7), saved.payload);
        replica.sync_from(&log, Delivery::InOrder).unwrap();
    }
    let s = DataSession::new(
        &replica,
        FixtureAuthority {
            actor: job(8, None),
            reads: vec![shared],
            write: Some(shared),
        },
    );
    let bytes = v2_bytes();
    let proposal = s.prepare_change(&bytes).unwrap();
    assert_eq!(proposal.affected_records, 0);
    assert!(proposal.needs_device);
    let direct = s.submit(Operation::DefineType { bytes }).unwrap_err();
    assert_eq!(rejected(direct).code, bh_data::RejectCode::DeviceOnly);
}

#[test]
fn device_approve_applies_rule_change() {
    let (mut replica, shared, _) = setup();
    let mut log = OrderedLog::new();
    for op in [
        Operation::DefineApp {
            app: app(),
            name: "Articles".into(),
        },
        Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        },
        Operation::Create {
            record: RecordId([10; 32]),
            type_id: type_id(),
            revision: RevisionId::of(ARTICLE),
            doc: json!({"title":"Hello", "url":"https://example.test/a"}),
        },
    ] {
        let saved = session(&replica, shared).submit(op).unwrap();
        log.append(shared, &member(7), saved.payload);
        replica.sync_from(&log, Delivery::InOrder).unwrap();
    }
    let bytes = v2_bytes();
    let job_session = DataSession::new(
        &replica,
        FixtureAuthority {
            actor: job(8, None),
            reads: vec![shared],
            write: Some(shared),
        },
    );
    let prepared = tools::call(
        &job_session,
        "types.prepare_change",
        json!({"bytes": bytes}),
    );
    assert_eq!(prepared["ok"]["needs_device"], true, "{prepared}");
    assert_eq!(prepared["ok"]["change"]["rule_change"], true);
    let attempt = tools::call(
        &job_session,
        "records.mutate",
        serde_json::to_value(Operation::DefineType {
            bytes: bytes.clone(),
        })
        .unwrap(),
    );
    assert_eq!(attempt["error"]["code"], "DeviceOnly", "{attempt}");
    let device = session(&replica, shared);
    let proposal = device.prepare_change(&bytes).unwrap();
    let saved = device.approve(proposal).unwrap();
    log.append(shared, &member(7), saved.payload);
    drop(device);
    let outcomes = replica.sync_from(&log, Delivery::InOrder).unwrap();
    assert!(
        matches!(
            outcomes.last(),
            Some((_, bh_data::mutation::apply::Outcome::Accepted { .. }))
        ),
        "{outcomes:?}"
    );
    let description = session(&replica, shared)
        .describe(shared, TypeRef::Current(type_id()))
        .unwrap();
    assert_eq!(description.compiled.revision, RevisionId::of(&bytes));
    assert_eq!(description.evolution, Some(RevisionId::of(ARTICLE)));
}

#[test]
fn protected_migration_proposal_matches_ordered_gate() {
    let (mut replica, shared, _) = setup();
    let mut log = OrderedLog::new();
    let mut initial: serde_json::Value = serde_json::from_slice(ARTICLE).unwrap();
    initial["fields"]["/state"]["write"] = json!("action");
    let initial = serde_json::to_vec(&initial).unwrap();
    for op in [
        Operation::DefineApp {
            app: app(),
            name: "Articles".into(),
        },
        Operation::DefineType {
            bytes: initial.clone(),
        },
    ] {
        let saved = session(&replica, shared).submit(op).unwrap();
        log.append(shared, &member(7), saved.payload);
        replica.sync_from(&log, Delivery::InOrder).unwrap();
    }
    // The current revision is Direct; the protected policy survives only in
    // an earlier accepted revision, which the migration could still affect.
    let mut middle: serde_json::Value = serde_json::from_slice(&initial).unwrap();
    middle["fields"]["/state"]["write"] = json!("direct");
    middle["evolution"]["previous"] = json!(RevisionId::of(&initial));
    let middle = serde_json::to_vec(&middle).unwrap();
    let saved = session(&replica, shared)
        .submit(Operation::DefineType {
            bytes: middle.clone(),
        })
        .unwrap();
    log.append(shared, &member(7), saved.payload);
    replica.sync_from(&log, Delivery::InOrder).unwrap();

    let mut next: serde_json::Value = serde_json::from_slice(&middle).unwrap();
    next["description"] = json!("Article with a migration for existing state");
    next["evolution"]["previous"] = json!(RevisionId::of(&middle));
    next["evolution"]["migration_ops"] =
        json!([{"op":"set_constant","path":"/state","value":"saved"}]);
    let next = serde_json::to_vec(&next).unwrap();
    let job_actor = job(8, None);
    let job_session = DataSession::new(
        &replica,
        FixtureAuthority {
            actor: job_actor.clone(),
            reads: vec![shared],
            write: Some(shared),
        },
    );
    let proposal = job_session.prepare_change(&next).unwrap();
    assert!(proposal.change.compatible, "{proposal:?}");
    assert!(proposal.change.rule_change, "{proposal:?}");
    assert!(proposal.needs_device, "{proposal:?}");
    let attempt = Operation::DefineType {
        bytes: next.clone(),
    };
    assert_eq!(
        rejected(job_session.submit(attempt.clone()).unwrap_err()).code,
        bh_data::RejectCode::DeviceOnly
    );
    let payload = bh_data::payload::encode(bh_data::MutationId::random(), &attempt).unwrap();
    log.append(shared, &job_actor, payload);
    let outcomes = replica.sync_from(&log, Delivery::InOrder).unwrap();
    assert!(
        matches!(outcomes.last(), Some((_, bh_data::mutation::apply::Outcome::Rejected(r))) if r.code == bh_data::RejectCode::DeviceOnly),
        "{outcomes:?}"
    );
    let device = session(&replica, shared);
    let saved = device
        .approve(device.prepare_change(&next).unwrap())
        .unwrap();
    log.append(shared, &member(7), saved.payload);
    let outcomes = replica.sync_from(&log, Delivery::InOrder).unwrap();
    assert!(
        matches!(
            outcomes.last(),
            Some((_, bh_data::mutation::apply::Outcome::Accepted { .. }))
        ),
        "{outcomes:?}"
    );
    assert_eq!(
        session(&replica, shared)
            .describe(shared, TypeRef::Current(type_id()))
            .unwrap()
            .compiled
            .revision,
        RevisionId::of(&next)
    );
}

#[test]
fn unreadable_scope_query_unauthorized() {
    let (replica, shared, private) = setup();
    let s = DataSession::new(
        &replica,
        FixtureAuthority {
            actor: member(7),
            reads: vec![shared],
            write: None,
        },
    );
    assert_eq!(
        s.query(private, &query(TypeId::core("note"))).unwrap_err(),
        QueryError::Unauthorized
    );
}

#[test]
fn switching_authority_changes_visible_results() {
    let (mut replica, shared, private) = setup();
    let mut log = OrderedLog::new();
    let record = RecordId([5; 32]);
    for (scope, account, title) in [(shared, 7, "Shared"), (private, 8, "Private")] {
        for op in [
            Operation::DefineApp {
                app: app(),
                name: "Articles".into(),
            },
            Operation::DefineType {
                bytes: ARTICLE.to_vec(),
            },
            Operation::Create {
                record,
                type_id: type_id(),
                revision: RevisionId::of(ARTICLE),
                doc: json!({"title":title,"url":"https://example.test/a"}),
            },
        ] {
            let authority = FixtureAuthority {
                actor: member(account),
                reads: vec![scope],
                write: Some(scope),
            };
            let saved = DataSession::new(&replica, authority).submit(op).unwrap();
            log.append(scope, &member(account), saved.payload);
            replica.sync_from(&log, Delivery::InOrder).unwrap();
        }
    }
    let a = DataSession::new(
        &replica,
        FixtureAuthority {
            actor: member(7),
            reads: vec![shared],
            write: None,
        },
    );
    let b = DataSession::new(
        &replica,
        FixtureAuthority {
            actor: member(8),
            reads: vec![private],
            write: None,
        },
    );
    assert_eq!(
        a.get(shared, record).unwrap().unwrap().view().unwrap()["title"],
        "Shared"
    );
    assert_eq!(
        b.get(private, record).unwrap().unwrap().view().unwrap()["title"],
        "Private"
    );
    let mut q = query(type_id());
    q.fields.push(FieldPath::parse("/title").unwrap());
    assert_eq!(
        a.query(shared, &q).unwrap().rows[0].values["/title"],
        "Shared"
    );
    assert_eq!(
        b.query(private, &q).unwrap().rows[0].values["/title"],
        "Private"
    );
    let aggregate = Aggregate {
        select: TypeSelect::Exact(type_id()),
        filter: None,
        group_by: Some(FieldPath::parse("/title").unwrap()),
        measures: vec![Measure::Count],
        max_groups: 10,
    };
    let a_groups = a.aggregate(shared, &aggregate).unwrap().groups;
    let b_groups = b.aggregate(private, &aggregate).unwrap().groups;
    assert_eq!(a_groups[0].key, Some(json!("Shared")));
    assert_eq!(b_groups[0].key, Some(json!("Private")));
    assert!(matches!(
        b.get(shared, record),
        Err(bh_data::DataError::Unauthorized)
    ));
}

#[test]
fn proposal_cannot_be_approved_in_another_scope() {
    let (replica, shared, private) = setup();
    let proposal = session(&replica, shared).prepare_change(ARTICLE).unwrap();
    let other = session(&replica, private);
    assert!(
        matches!(other.approve(proposal), Err(SessionError::Rejected(r)) if r.code == bh_data::RejectCode::Unauthorized)
    );
    assert!(matches!(
        session(&replica, shared).describe(shared, TypeRef::Current(type_id())),
        Err(bh_data::DataError::NotFound)
    ));
}

#[test]
fn describe_supports_revision_and_builtin_operations() {
    let (mut replica, shared, _) = setup();
    let note = session(&replica, shared)
        .describe(shared, TypeRef::Current(TypeId::core("note")))
        .unwrap();
    assert!(!note.operations.contains(&"create".to_string()));
    let mut log = OrderedLog::new();
    for op in [
        Operation::DefineApp {
            app: app(),
            name: "Articles".into(),
        },
        Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        },
    ] {
        let saved = session(&replica, shared).submit(op).unwrap();
        log.append(shared, &member(7), saved.payload);
        replica.sync_from(&log, Delivery::InOrder).unwrap();
    }
    let result = tools::call(
        &session(&replica, shared),
        "types.describe",
        json!({"scope":tool_scope(shared),"revision":RevisionId::of(ARTICLE)}),
    );
    assert_eq!(
        result["ok"]["compiled"]["revision"],
        json!(RevisionId::of(ARTICLE)),
        "{result}"
    );
}

#[test]
fn session_ensure_index_is_local() {
    let (mut replica, shared, private) = setup();
    let actor = member(7);
    let saved = session(&replica, shared)
        .submit(Operation::DefineApp {
            app: app(),
            name: "Articles".into(),
        })
        .unwrap();
    let mut log = OrderedLog::new();
    log.append(shared, &actor, saved.payload);
    replica.sync_from(&log, Delivery::InOrder).unwrap();
    let s = DataSession::new(
        &replica,
        FixtureAuthority {
            actor,
            reads: vec![shared, private],
            write: None,
        },
    );
    let state = s
        .ensure_index(shared, TypeId::core("note"), vec![bh_data::KeyRef::Changed])
        .unwrap();
    assert!(state.local_claim);
    assert!(matches!(
        s.ensure_index(
            private,
            TypeId::core("note"),
            vec![bh_data::KeyRef::Changed]
        ),
        Err(bh_data::DataError::NotFound)
    ));
    let pending = replica
        .conn()
        .query_row("SELECT count(*) FROM data_pending", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();
    assert_eq!(pending, 0);
    let scopes = replica
        .conn()
        .query_row("SELECT count(*) FROM data_scope", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();
    assert_eq!(scopes, 1);
}

#[test]
fn write_without_authority_is_unauthorized_even_when_readable() {
    let (replica, shared, _) = setup();
    let s = DataSession::new(
        &replica,
        FixtureAuthority {
            actor: member(7),
            reads: vec![shared],
            write: None,
        },
    );
    assert!(
        matches!(s.submit(Operation::DefineApp { app: app(), name: "Articles".into() }), Err(SessionError::Rejected(r)) if r.code == bh_data::RejectCode::Unauthorized)
    );
    assert!(matches!(
        s.ensure_index(shared, TypeId::core("note"), vec![bh_data::KeyRef::Changed]),
        Err(bh_data::DataError::NotFound)
    ));
    assert!(matches!(
        s.ensure_index(
            scopes(9).0,
            TypeId::core("note"),
            vec![bh_data::KeyRef::Changed]
        ),
        Err(bh_data::DataError::Unauthorized)
    ));
    assert_eq!(
        s.prepare_change(ARTICLE).unwrap_err().to_string(),
        bh_data::DataError::Unauthorized.to_string()
    );
}

#[test]
fn tool_requires_explicit_read_scope() {
    let (replica, shared, private) = setup();
    let s = session(&replica, shared);
    let q = serde_json::to_value(query(TypeId::core("note"))).unwrap();
    let mut args = q.as_object().unwrap().clone();
    assert_eq!(
        tools::call(&s, "records.query", json!(args))["error"]["code"],
        "InvalidArguments"
    );
    args.insert("scope".into(), tool_scope(private));
    assert_eq!(
        tools::call(&s, "records.query", json!(args))["error"]["code"],
        "Unauthorized"
    );
    args.insert("scope".into(), tool_scope(shared));
    assert!(
        tools::call(&s, "records.query", json!(args))
            .get("ok")
            .is_some()
    );
    let record = RecordId([5; 32]);
    assert_eq!(
        tools::call(
            &s,
            "records.get",
            json!({"scope":tool_scope(private), "record":record})
        )["error"]["code"],
        "Unauthorized"
    );
    assert_eq!(
        tools::call(
            &s,
            "records.history",
            json!({"scope":tool_scope(private), "record":record})
        )["error"]["code"],
        "Unauthorized"
    );
    assert!(
        tools::call(
            &s,
            "records.get",
            json!({"scope":tool_scope(shared), "record":record})
        )
        .get("ok")
        .is_some()
    );
}

#[test]
fn session_history_pages_all_fields_of_one_mutation() {
    let (mut replica, shared, _) = setup();
    let record = RecordId([9; 32]);
    let mut definition: serde_json::Value = serde_json::from_slice(ARTICLE).unwrap();
    definition["schema"]["properties"]["tag"] = json!({"type":"string","maxLength":100});
    definition["fields"]["/tag"] = json!({"kind":"string","meaning":"Reader tag","write":"direct"});
    let bytes = serde_json::to_vec(&definition).unwrap();
    let revision = RevisionId::of(&bytes);
    let paths = ["/published", "/state", "/tag", "/title", "/url"];
    let mut log = OrderedLog::new();
    for op in [
        Operation::DefineApp {
            app: app(),
            name: "Articles".into(),
        },
        Operation::DefineType { bytes },
        Operation::Create {
            record,
            type_id: type_id(),
            revision,
            doc: json!({"title":"First","url":"https://example.test/history"}),
        },
        Operation::Edit {
            record,
            revision,
            changes: paths
                .iter()
                .enumerate()
                .map(|(i, path)| FieldChange {
                    path: FieldPath::parse(path).unwrap(),
                    value: Some(match *path {
                        "/published" => json!(10),
                        "/state" => json!("saved"),
                        "/url" => json!("https://example.test/edited"),
                        _ => json!(format!("value-{i}")),
                    }),
                })
                .collect(),
        },
    ] {
        let saved = session(&replica, shared).submit(op).unwrap();
        log.append(shared, &member(7), saved.payload);
        replica.sync_from(&log, Delivery::InOrder).unwrap();
    }
    let s = session(&replica, shared);
    let mut before: Option<HistoryCursor> = None;
    let mut first_cursor = None;
    let mut edited = Vec::new();
    for page_number in 0..3 {
        let page = s.history(shared, record, before.clone(), 2).unwrap();
        assert_eq!(page.len(), 2);
        edited.extend(
            page.iter()
                .filter(|entry| entry.position.0 == 4)
                .map(|entry| entry.path.as_ref().unwrap().as_pointer()),
        );
        let last = page.last().unwrap();
        before = Some(last.cursor());
        if page_number == 0 {
            first_cursor = before.clone();
        }
    }
    edited.sort();
    assert_eq!(edited, paths);
    let tool = tools::call(
        &s,
        "records.history",
        json!({"scope":tool_scope(shared),"record":record,"before":first_cursor,"limit":2}),
    );
    assert_eq!(tool["ok"].as_array().unwrap().len(), 2, "{tool}");
    assert_eq!(tool["ok"][0]["position"], 4);
    assert_eq!(tool["ok"][0]["path"], "/tag");
    assert_eq!(tool["ok"][1]["path"], "/title");
}

#[test]
fn tool_undo_reports_intervening_edit_path() {
    let (mut replica, shared, _) = setup();
    let mut log = OrderedLog::new();
    let record = RecordId([42; 32]);
    for op in [
        Operation::DefineApp {
            app: app(),
            name: "Articles".into(),
        },
        Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        },
        Operation::Create {
            record,
            type_id: type_id(),
            revision: RevisionId::of(ARTICLE),
            doc: json!({"title":"First", "url":"https://example.test/undo", "state":"new"}),
        },
    ] {
        let saved = session(&replica, shared).submit(op).unwrap();
        log.append(shared, &member(7), saved.payload);
        replica.sync_from(&log, Delivery::InOrder).unwrap();
    }
    let edit = Operation::Edit {
        record,
        revision: RevisionId::of(ARTICLE),
        changes: vec![
            FieldChange {
                path: FieldPath::parse("/title").unwrap(),
                value: Some(json!("Second")),
            },
            FieldChange {
                path: FieldPath::parse("/state").unwrap(),
                value: Some(json!("saved")),
            },
        ],
    };
    let saved = session(&replica, shared).submit(edit).unwrap();
    let target = saved.mutation;
    log.append(shared, &member(7), saved.payload);
    replica.sync_from(&log, Delivery::InOrder).unwrap();
    let next = session(&replica, shared)
        .submit(Operation::Edit {
            record,
            revision: RevisionId::of(ARTICLE),
            changes: vec![FieldChange {
                path: FieldPath::parse("/title").unwrap(),
                value: Some(json!("Third")),
            }],
        })
        .unwrap();
    log.append(shared, &member(7), next.payload);
    replica.sync_from(&log, Delivery::InOrder).unwrap();
    let result = tools::call(
        &session(&replica, shared),
        "records.undo",
        json!({"scope":tool_scope(shared),"mutation":target}),
    );
    assert_eq!(result["ok"]["skipped"], json!(["/title"]), "{result}");
}

#[test]
fn tool_unknown_name_is_stable_error() {
    let (replica, shared, _) = setup();
    let s = session(&replica, shared);
    assert_eq!(
        tools::call(&s, "missing", json!({}))["error"]["code"],
        "UnknownTool"
    );
}

#[test]
fn validate_does_not_save_pending_work() {
    let (replica, shared, _) = setup();
    let s = session(&replica, shared);
    let op = Operation::DefineApp {
        app: app(),
        name: "Articles".into(),
    };
    s.validate(&op).unwrap();
    assert_eq!(
        replica
            .conn()
            .query_row("SELECT count(*) FROM data_pending", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert!(s.rejected_work(shared).unwrap().is_empty());
    assert!(s.get(shared, RecordId([5; 32])).unwrap().is_none());
}
