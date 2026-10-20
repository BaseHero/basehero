//! Compilation bounds use real parsed/compiled contracts, never fabricated dependencies.
use std::cell::Cell;

use bh_data::{
    Actor, AppId, CompiledType, DataError, MutationId, RevisionId, Scope, compose, definition,
    mutation::{apply::Outcome, ops::Operation},
    payload,
    testkit::{Delivery, OrderedLog, Replica},
    validate,
};
use serde_json::{Value, json};

const LIMIT: usize = 1_048_576;
const APP: AppId = AppId([9; 32]);
const SCOPE: Scope = Scope {
    base: [7; 32],
    audience: [8; 32],
};

fn doc(local: u8, kind: &str, annotation: usize) -> Value {
    json!({
        "format":"bh-type/1", "local":format!("{local:02x}").repeat(16), "app":APP,
        "kind":kind, "name":format!("Bound{local}"), "description":"Compilation bound fixture",
        "extends":null, "uses":[],
        "schema":{"type":"object","properties":{},"description":"x".repeat(annotation)},
        "fields":{}, "actions":[], "indexes":[], "unique":[], "search":{"text":[]},
        "queries":[], "evolution":{"previous":null,"migration":"","migration_ops":[],
        "examples":{"valid":[],"invalid":[]}}, "rationale":[]
    })
}
fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}
fn pin(ct: &CompiledType) -> Value {
    json!({"type":ct.type_id,"revision":ct.revision})
}
fn compile(value: &Value, deps: &[CompiledType]) -> Result<CompiledType, compose::ComposeError> {
    let d = definition::parse(&bytes(value)).unwrap();
    compose::compile(&d, RevisionId::of(&d.bytes), &|id, rev| {
        deps.iter()
            .find(|ct| ct.type_id == id && ct.revision == rev)
            .cloned()
    })
}
fn ordered(replica: &mut Replica, log: &mut OrderedLog, op: Operation) -> Outcome {
    let actor = Actor::Device {
        account: [1; 32],
        device: [1; 32],
    };
    log.append(
        SCOPE,
        &actor,
        payload::encode(MutationId::random(), &op).unwrap(),
    );
    replica
        .sync_from(log, Delivery::InOrder)
        .unwrap()
        .pop()
        .unwrap()
        .1
}
fn accept(replica: &mut Replica, log: &mut OrderedLog, value: &Value) {
    let result = ordered(
        replica,
        log,
        Operation::DefineType {
            bytes: bytes(value),
        },
    );
    assert!(matches!(result, Outcome::Accepted { .. }), "{result:?}");
}
fn setup() -> (Replica, OrderedLog) {
    let mut replica = Replica::new_in_memory().unwrap();
    let mut log = OrderedLog::new();
    assert!(matches!(
        ordered(
            &mut replica,
            &mut log,
            Operation::DefineApp {
                app: APP,
                name: "Bounds".into()
            }
        ),
        Outcome::Accepted { .. }
    ));
    (replica, log)
}
fn limit(result: Result<CompiledType, compose::ComposeError>) {
    assert!(
        matches!(
            result,
            Err(compose::ComposeError::Invalid(DataError::Limit(_)))
        ),
        "expected compilation byte limit"
    );
}

#[test]
fn ordered_import_bytes_reject_before_registry_writes() {
    let (mut replica, mut log) = setup();
    let mut deps = Vec::new();
    for i in 10..46 {
        let value = doc(i, "value", 30 * 1024);
        accept(&mut replica, &mut log, &value);
        deps.push(compile(&value, &[]).unwrap());
    }
    let mut modest = doc(100, "record", 0);
    modest["uses"] = json!(deps[..8].iter().map(pin).collect::<Vec<_>>());
    accept(&mut replica, &mut log, &modest);
    let mut large = doc(101, "record", 0);
    large["uses"] = json!(deps.iter().map(pin).collect::<Vec<_>>());
    let count = || {
        replica
            .conn()
            .query_row("SELECT count(*) FROM data_definition", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
    };
    let before = count();
    let result = ordered(
        &mut replica,
        &mut log,
        Operation::DefineType {
            bytes: bytes(&large),
        },
    );
    assert!(matches!(result, Outcome::Rejected(_)), "{result:?}");
    let after: i64 = replica
        .conn()
        .query_row("SELECT count(*) FROM data_definition", [], |r| r.get(0))
        .unwrap();
    assert_eq!(before, after);
    let revision = RevisionId::of(&bytes(&large));
    let stored: i64 = replica
        .conn()
        .query_row(
            "SELECT count(*) FROM data_definition WHERE revision=?1",
            [revision.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, 0);
    limit(compile(&large, &deps));
}

#[test]
fn repeated_pin_fetches_once_but_base_kind_is_still_checked() {
    let value = compile(&doc(1, "value", 30 * 1024), &[]).unwrap();
    let mut root = doc(2, "record", 0);
    root["uses"] = json!(vec![pin(&value); 80]);
    let d = definition::parse(&bytes(&root)).unwrap();
    let calls = Cell::new(0);
    let compiled = compose::compile(&d, RevisionId::of(&d.bytes), &|_, _| {
        calls.set(calls.get() + 1);
        Some(value.clone())
    })
    .unwrap();
    assert_eq!(compiled.resources, value.resources);
    assert_eq!(calls.get(), 1);
    let base = compile(&doc(3, "record", 0), &[]).unwrap();
    root["extends"] = pin(&base);
    root["uses"] = json!([pin(&base)]);
    let d = definition::parse(&bytes(&root)).unwrap();
    calls.set(0);
    let result = compose::compile(&d, RevisionId::of(&d.bytes), &|_, _| {
        calls.set(calls.get() + 1);
        Some(base.clone())
    });
    assert!(matches!(
        result,
        Err(compose::ComposeError::Invalid(DataError::Definition(_)))
    ));
    assert_eq!(
        calls.get(),
        1,
        "cached base must still fail the value-kind check"
    );
}

#[test]
fn supplied_resource_annotations_are_bounded_before_validator() {
    let root = json!({"type":"object"});
    let resources: Vec<_> = (0..36)
        .map(|n| {
            (
                format!("bh:value:{n:x}@a"),
                json!({"description":"x".repeat(30 * 1024)}),
            )
        })
        .collect();
    assert!(validate::Compiled::new(&root, &resources[..8]).is_ok());
    assert!(matches!(
        validate::Compiled::new(&root, &resources),
        Err(DataError::Limit(_))
    ));
}

#[test]
fn uri_bytes_escaped_annotations_and_exact_boundary_count() {
    let root = json!({"type":"object"});
    let schema = json!({"description":"\n\"\\".repeat(5000)});
    // 30 KiB JSON despite 15 KiB of unescaped string content.
    assert!(bytes(&schema).len() > 30_000);
    let mut resources: Vec<_> = (0..32)
        .map(|n| (format!("bh:value:{n:x}@a"), schema.clone()))
        .collect();
    let used = bytes(&root).len()
        + resources
            .iter()
            .map(|(uri, v)| serde_json::to_vec(uri).unwrap().len() + bytes(v).len())
            .sum::<usize>();
    resources[0].0.push_str(&"a".repeat(LIMIT - used));
    assert!(validate::Compiled::new(&root, &resources).is_ok());
    resources[0].0.push('a');
    assert!(matches!(
        validate::Compiled::new(&root, &resources),
        Err(DataError::Limit(_))
    ));
}

#[test]
fn distinct_dependencies_charge_shared_resources_and_stop_fetching() {
    let (mut replica, mut log) = setup();
    let mut leaves = Vec::new();
    for i in 1..9 {
        let value = doc(i, "value", 30 * 1024);
        accept(&mut replica, &mut log, &value);
        leaves.push(compile(&value, &[]).unwrap());
    }
    let mut wrappers = Vec::new();
    for i in 100..108 {
        let mut wrapper = doc(i, "value", 0);
        wrapper["uses"] = json!(leaves.iter().map(pin).collect::<Vec<_>>());
        accept(&mut replica, &mut log, &wrapper);
        wrappers.push(compile(&wrapper, &leaves).unwrap());
    }
    let mut root = doc(200, "record", 0);
    root["uses"] = json!(wrappers.iter().map(pin).collect::<Vec<_>>());
    let d = definition::parse(&bytes(&root)).unwrap();
    let calls = Cell::new(0);
    let result = compose::compile(&d, RevisionId::of(&d.bytes), &|id, rev| {
        calls.set(calls.get() + 1);
        wrappers
            .iter()
            .find(|ct| ct.type_id == id && ct.revision == rev)
            .cloned()
    });
    limit(result);
    assert_eq!(
        calls.get(),
        5,
        "stop at the first over-budget distinct input"
    );
    assert!(matches!(
        ordered(
            &mut replica,
            &mut log,
            Operation::DefineType {
                bytes: bytes(&root)
            }
        ),
        Outcome::Rejected(_)
    ));
}

#[test]
fn inherited_documentation_and_final_serialization_are_bounded() {
    let (mut replica, mut log) = setup();
    let mut base: Option<CompiledType> = None;
    for i in 1..21 {
        let mut value = doc(i, "record", 0);
        let field = format!("f{i}");
        value["schema"]["properties"][&field] = json!({"type":"integer"});
        value["fields"][format!("/{field}")] =
            json!({"kind":"integer","write":"direct","meaning":"m".repeat(50_000)});
        if let Some(ct) = &base {
            value["extends"] = pin(ct);
        }
        accept(&mut replica, &mut log, &value);
        base = Some(compile(&value, &base.into_iter().collect::<Vec<_>>()).unwrap());
    }
    let base = base.unwrap();
    assert_eq!(base.fields.len(), 20);
    assert!(base.fields.iter().all(|f| f.meaning.len() == 50_000));
    let mut child = doc(100, "record", 0);
    child["extends"] = pin(&base);
    let baseline = compile(&child, std::slice::from_ref(&base)).unwrap();
    let size = serde_json::to_vec(&baseline).unwrap().len();
    let padding = LIMIT - size;
    assert!(padding < 50_000);
    let description = child["description"].as_str().unwrap().to_owned();
    child["description"] = json!(format!("{description}{}", "d".repeat(padding)));
    let exact = compile(&child, std::slice::from_ref(&base)).unwrap();
    assert_eq!(serde_json::to_vec(&exact).unwrap().len(), LIMIT);
    accept(&mut replica, &mut log, &child);
    let stored: i64 = replica
        .conn()
        .query_row(
            "SELECT length(CAST(compiled AS BLOB)) FROM data_definition WHERE revision=?1",
            [exact.revision.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, 1_048_576);
    child["description"] = json!(format!("{}x", child["description"].as_str().unwrap()));
    limit(compile(&child, std::slice::from_ref(&base)));
    assert!(matches!(
        ordered(
            &mut replica,
            &mut log,
            Operation::DefineType {
                bytes: bytes(&child)
            }
        ),
        Outcome::Rejected(_)
    ));
    // An unresolved reference would fail graph/validator construction. The final
    // representation limit must win first, not run the validator then reject.
    child["schema"]["properties"]["unresolved"] = json!({"$ref":"bh:value:aa@bb"});
    child["fields"]["/unresolved"] =
        json!({"kind":"atomic","write":"direct","meaning":"Missing value"});
    limit(compile(&child, std::slice::from_ref(&base)));
    child["schema"]["properties"] = json!({});
    child["fields"] = json!({});
    // Field metadata grows independently of schema bytes, not just root docs.
    child["description"] = json!(description);
    child["schema"]["properties"]["extra"] = json!({"type":"integer"});
    child["fields"]["/extra"] =
        json!({"kind":"integer","write":"direct","meaning":"m".repeat(50_000)});
    limit(compile(&child, &[base]));
}

#[test]
fn duplicate_supplied_resources_do_not_spend_bytes_twice() {
    let resource = (
        "bh:value:aa@bb".to_owned(),
        json!({"description":"x".repeat(30 * 1024)}),
    );
    let resources = vec![resource; 40];
    assert!(validate::Compiled::new(&json!({"type":"object"}), &resources).is_ok());
    let mut conflicting = resources;
    conflicting[1].1 = json!({"type":"integer"});
    assert!(matches!(
        validate::Compiled::new(&json!({}), &conflicting),
        Err(DataError::Definition(_))
    ));
}
