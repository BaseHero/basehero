use bh_data::{
    Actor, AppId, DataError, MutationId, Position, RecordId, RejectCode, RevisionId, Scope, TypeId,
    Wait,
    catalogue::Shipped,
    definition::MAX_DEFINITION_BYTES,
    mutation::{
        apply::Outcome,
        ops::{FieldChange, Operation},
        pending::{self, SubmitError},
    },
    payload::{self, Affects, Decoded, MAX_PAYLOAD_BYTES, PAYLOAD_VERSION},
    query::{self, Budget, Completeness, Gap, Query, TypeSelect},
    testkit::{Delivery, OrderedLog, Replica},
};
use serde_json::{Value, json};

const ARTICLE: &[u8] = include_bytes!("fixtures/types/Article.json");
const APP: AppId = AppId([2; 32]);
const SHARED: Scope = Scope {
    base: [1; 32],
    audience: [0; 32],
};
const OTHER: Scope = Scope {
    base: [3; 32],
    audience: [0; 32],
};

fn dev(n: u8) -> Actor {
    Actor::Device {
        account: [n; 32],
        device: [n; 32],
    }
}
fn rid(n: u8) -> RecordId {
    RecordId([n; 32])
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn type_of(bytes: &[u8]) -> TypeId {
    bh_data::definition::parse(bytes).unwrap().type_id
}
fn set(p: &str, v: Value) -> FieldChange {
    FieldChange {
        path: bh_data::FieldPath::parse(p).unwrap(),
        value: Some(v),
    }
}

/// A second app type, unrelated to Article.
fn memo() -> Vec<u8> {
    serde_json::to_vec(&json!({"format":"bh-type/1","local":"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "app":hex(&APP.0),"kind":"record","name":"Memo","description":"A short memo",
        "extends":null,"uses":[],
        "schema":{"type":"object","properties":{"text":{"type":"string","maxLength":500}},"required":["text"]},
        "fields":{"/text":{"meaning":"Memo text","write":"direct","kind":"string"}},
        "actions":[],"indexes":[],"unique":[],"search":{"title":"/text","text":[]},"queries":[],
        "evolution":{"previous":null,"migration":"","migration_ops":[],"examples":{"valid":[],"invalid":[]}},
        "rationale":[]}))
    .unwrap()
}

fn create_article(record: RecordId, title: &str, url: &str) -> Operation {
    Operation::Create {
        record,
        type_id: type_of(ARTICLE),
        revision: RevisionId::of(ARTICLE),
        doc: json!({"title": title, "url": url}),
    }
}
fn create_memo(record: RecordId, text: &str) -> Operation {
    Operation::Create {
        record,
        type_id: type_of(&memo()),
        revision: RevisionId::of(&memo()),
        doc: json!({"text": text}),
    }
}
fn edit_title(record: RecordId, title: &str) -> Operation {
    Operation::Edit {
        record,
        revision: RevisionId::of(ARTICLE),
        changes: vec![set("/title", json!(title))],
    }
}

/// Orders `op` as if another replica had saved it.
fn order(log: &mut OrderedLog, scope: Scope, op: &Operation) -> Position {
    log.append(
        scope,
        &dev(1),
        payload::encode(MutationId::random(), op).unwrap(),
    )
}

/// A replica holding Article and Memo in `SHARED`, with Article records 1 and 2.
fn setup() -> (Replica, OrderedLog) {
    let mut log = OrderedLog::new();
    for op in [
        Operation::DefineApp {
            app: APP,
            name: "Reader".into(),
        },
        Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        },
        Operation::DefineType { bytes: memo() },
        create_article(rid(1), "One", "https://example.test/1"),
        create_article(rid(2), "Two", "https://example.test/2"),
    ] {
        order(&mut log, SHARED, &op);
    }
    let mut replica = Replica::new_in_memory().unwrap();
    for (_, outcome) in replica.sync_from(&log, Delivery::InOrder).unwrap() {
        assert!(matches!(outcome, Outcome::Accepted { .. }), "{outcome:?}");
    }
    (replica, log)
}

fn deliver(replica: &mut Replica, log: &OrderedLog) -> Outcome {
    let mut outcomes = replica.sync_from(log, Delivery::InOrder).unwrap();
    assert_eq!(outcomes.len(), 1);
    outcomes.remove(0).1
}

/// A payload in the given layout with a hand-written header, written canonically.
fn framed(version: u16, header: &Value, tail: &[u8]) -> Vec<u8> {
    framed_bytes(version, bh_data::value::canonical(header).as_bytes(), tail)
}

/// A payload in the given layout with exactly these header bytes.
fn framed_bytes(version: u16, header: &[u8], tail: &[u8]) -> Vec<u8> {
    let mut out = version.to_be_bytes().to_vec();
    out.extend_from_slice(&(header.len() as u32).to_be_bytes());
    out.extend_from_slice(header);
    out.extend_from_slice(tail);
    out
}

fn header_of(bytes: &[u8]) -> Value {
    let len = u32::from_be_bytes(bytes[2..6].try_into().unwrap()) as usize;
    serde_json::from_slice(&bytes[6..6 + len]).unwrap()
}

#[test]
fn signed_confirmation_header_is_canonical_and_rejects_unknown_prior_fields() {
    use bh_data::admission::PriorRules;
    let mutation = MutationId([3; 16]);
    let op = Operation::SetAppState {
        app: APP,
        active: false,
    };
    let prior = PriorRules::App {
        app: APP,
        since: Some(Position(7)),
        active: Some(true),
    };
    let bytes = payload::encode_with_confirmation(mutation, &op, Some(prior.clone())).unwrap();
    assert_eq!(
        payload::decode(&bytes),
        Decoded::Confirmed(mutation, op.clone(), prior)
    );
    let mut header = header_of(&bytes);
    header["confirmation"]["App"]["unexpected"] = json!(true);
    assert!(matches!(
        payload::decode(&framed(1, &header, &[])),
        Decoded::Malformed(_)
    ));
    header["confirmation"]["App"]
        .as_object_mut()
        .unwrap()
        .remove("unexpected");
    assert_eq!(framed(1, &header, &[]), bytes);
    header["confirmation"] = Value::Null;
    assert!(matches!(
        payload::decode(&framed(1, &header, &[])),
        Decoded::Malformed(_)
    ));
}

fn parked(replica: &Replica) -> Vec<(i64, String, String)> {
    replica
        .conn()
        .prepare("SELECT position,affects,reason FROM data_parked ORDER BY position")
        .unwrap()
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn completeness(replica: &Replica, type_id: TypeId) -> Completeness {
    let query = Query {
        select: TypeSelect::Exact(type_id),
        filter: None,
        sort: vec![],
        fields: vec![],
        follow: vec![],
        text: None,
        limit: 50,
        after: None,
    };
    query::run(
        replica.conn(),
        SHARED,
        &[SHARED],
        &Shipped,
        &query,
        Budget::INTERACTIVE,
    )
    .unwrap()
    .completeness
}

#[test]
fn payload_round_trip_all_ops() {
    let mutation = MutationId([5; 16]);
    let ops = [
        Operation::DefineApp {
            app: APP,
            name: "Reader".into(),
        },
        Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        },
        Operation::Adopt {
            from_audience: [0; 32],
            revision: RevisionId::of(ARTICLE),
            bytes: ARTICLE.to_vec(),
        },
        create_article(rid(1), "One", "https://example.test/1"),
        Operation::Edit {
            record: rid(1),
            revision: RevisionId::of(ARTICLE),
            changes: vec![
                set("/title", Value::Null),
                FieldChange {
                    path: bh_data::FieldPath::parse("/state").unwrap(),
                    value: None,
                },
                set("/published", json!(1.5)),
            ],
        },
        Operation::Delete { record: rid(1) },
        Operation::Undo {
            target: MutationId([6; 16]),
            record: rid(1),
            changes: vec![set("/title", json!("Before"))],
        },
        Operation::Action {
            record: rid(1),
            app: APP,
            action: "archive".into(),
            changes: vec![set("/state", json!("saved"))],
        },
        Operation::SetAppState {
            app: APP,
            active: false,
        },
        Operation::BindCore {
            type_id: TypeId::core("thing"),
            revision: RevisionId([8; 32]),
        },
        Operation::Transition {
            type_id: type_of(ARTICLE),
            to: RevisionId([9; 32]),
        },
        Operation::Migrate {
            record: rid(1),
            from: RevisionId::of(ARTICLE),
            to: RevisionId([9; 32]),
            changes: vec![
                set("/name", json!("One")),
                FieldChange {
                    path: bh_data::FieldPath::parse("/title").unwrap(),
                    value: None,
                },
            ],
        },
        Operation::BindNote {
            note: rid(1),
            type_id: type_of(ARTICLE),
            revision: RevisionId::of(ARTICLE),
            doc: json!({"date": 1}),
        },
    ];
    let article = Some(type_of(ARTICLE));
    for op in &ops {
        let bytes = payload::encode(mutation, op).unwrap();
        assert_eq!(&bytes[..2], &PAYLOAD_VERSION.to_be_bytes());
        let decoded = payload::decode(&bytes);
        assert_eq!(decoded, Decoded::Op(mutation, op.clone()));
        // The header is canonical: re-encoding what was decoded reproduces the bytes.
        let Decoded::Op(again, back) = decoded else {
            unreachable!()
        };
        assert_eq!(payload::encode(again, &back).unwrap(), bytes);
        let header = header_of(&bytes);
        assert_eq!(header["mutation"], json!(hex(&mutation.0)));
        assert_eq!(header["op"]["kind"], json!(op.kind()));
        let affects: Affects = serde_json::from_value(header["affects"].clone()).unwrap();
        let want = match op {
            // An app's state is read by every operation on its types.
            Operation::DefineApp { .. } | Operation::SetAppState { .. } => Affects::default(),
            Operation::DefineType { .. } | Operation::Adopt { .. } => Affects {
                type_id: article,
                record: None,
            },
            Operation::BindCore { type_id, .. } | Operation::Transition { type_id, .. } => {
                Affects {
                    type_id: Some(*type_id),
                    record: None,
                }
            }
            Operation::Create { .. } | Operation::BindNote { .. } => Affects {
                type_id: article,
                record: Some(rid(1)),
            },
            _ => Affects {
                type_id: None,
                record: Some(rid(1)),
            },
        };
        assert_eq!(affects, want, "{op:?}");
        match op {
            Operation::DefineType { .. } | Operation::Adopt { .. } => {
                assert_eq!(header["op"]["definition"], json!("tail"));
                assert!(bytes.ends_with(ARTICLE));
                assert!(!header.to_string().contains("\"bytes\""));
            }
            _ => {
                let len = u32::from_be_bytes(bytes[2..6].try_into().unwrap()) as usize;
                assert_eq!(bytes.len(), 6 + len, "no tail");
            }
        }
    }
    let adopt = header_of(&payload::encode(mutation, &ops[2]).unwrap());
    assert_eq!(adopt["op"]["from_audience"], json!(hex(&[0; 32])));
}

/// Article's definition padded with JSON whitespace to exactly `len` bytes.
fn padded_article(len: usize) -> Vec<u8> {
    let mut bytes = ARTICLE.to_vec();
    bytes.resize(len, b' ');
    bytes
}

#[test]
fn max_size_definition_fits_payload() {
    let definition = padded_article(MAX_DEFINITION_BYTES);
    assert!(bh_data::definition::parse(&definition).is_ok());
    for op in [
        Operation::DefineType {
            bytes: definition.clone(),
        },
        Operation::Adopt {
            from_audience: [0; 32],
            revision: RevisionId::of(&definition),
            bytes: definition.clone(),
        },
    ] {
        let bytes = payload::encode(MutationId::random(), &op).unwrap();
        assert!(bytes.len() <= MAX_PAYLOAD_BYTES);
        assert!(matches!(payload::decode(&bytes), Decoded::Op(_, decoded) if decoded == op));
    }
    // And it is ordered and accepted like any definition.
    let mut log = OrderedLog::new();
    let mut replica = Replica::new_in_memory().unwrap();
    for op in [
        Operation::DefineApp {
            app: APP,
            name: "Reader".into(),
        },
        Operation::DefineType { bytes: definition },
    ] {
        order(&mut log, SHARED, &op);
    }
    for (_, outcome) in replica.sync_from(&log, Delivery::InOrder).unwrap() {
        assert!(matches!(outcome, Outcome::Accepted { .. }), "{outcome:?}");
    }
}

#[test]
fn oversize_payload_refused() {
    let op = Operation::DefineType {
        bytes: padded_article(MAX_PAYLOAD_BYTES),
    };
    assert!(matches!(
        payload::encode(MutationId::random(), &op),
        Err(DataError::Limit(_))
    ));
    // A payload over the limit is malformed for every reader of this version.
    let mut bytes = payload::encode(
        MutationId::random(),
        &Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        },
    )
    .unwrap();
    bytes.resize(MAX_PAYLOAD_BYTES + 1, b' ');
    assert!(matches!(payload::decode(&bytes), Decoded::Malformed(_)));
    let (mut replica, mut log) = setup();
    log.append(SHARED, &dev(1), bytes);
    assert!(matches!(
        deliver(&mut replica, &log),
        Outcome::Rejected(r) if r.code == RejectCode::Schema
    ));
    // An edit with more changes than a payload can carry is refused too.
    let many: Vec<FieldChange> = (0..2_100)
        .map(|i| set(&format!("/n{i:05}"), json!("0123456789")))
        .collect();
    let edit = Operation::Edit {
        record: rid(1),
        revision: RevisionId::of(ARTICLE),
        changes: many,
    };
    assert!(matches!(
        payload::encode(MutationId::random(), &edit),
        Err(DataError::Limit(_))
    ));
}

#[test]
fn unknown_version_parked_and_scoped() {
    let (mut replica, mut log) = setup();
    let article = type_of(ARTICLE);
    let memo_type = type_of(&memo());
    assert_eq!(completeness(&replica, article), Completeness::Complete);
    let unknown = framed(
        PAYLOAD_VERSION + 1,
        &json!({"affects":{"type":hex(&article.0)},"anything":"a newer layout"}),
        b"\x00\x01",
    );
    let position = log.append(SHARED, &dev(1), unknown.clone());
    assert_eq!(
        deliver(&mut replica, &log),
        Outcome::Waiting(Wait::Unsupported)
    );
    assert_eq!(
        parked(&replica),
        vec![(
            position.0 as i64,
            format!("t:{}", hex(&article.0)),
            "\"Unsupported\"".into()
        )]
    );
    let stored: Vec<u8> = replica
        .conn()
        .query_row("SELECT payload FROM data_parked", [], |r| r.get(0))
        .unwrap();
    assert_eq!(stored, unknown, "the exact bytes are kept");
    assert_eq!(
        completeness(&replica, article),
        Completeness::Incomplete(vec![Gap::WaitingType(article)])
    );
    assert_eq!(completeness(&replica, memo_type), Completeness::Complete);
    // Later work on the affected type queues behind it; other types and scopes go on.
    order(&mut log, SHARED, &edit_title(rid(1), "Changed"));
    assert_eq!(deliver(&mut replica, &log), Outcome::Waiting(Wait::Queued));
    order(&mut log, SHARED, &create_memo(rid(9), "Unrelated"));
    assert!(matches!(
        deliver(&mut replica, &log),
        Outcome::Accepted { .. }
    ));
    order(
        &mut log,
        OTHER,
        &Operation::DefineApp {
            app: APP,
            name: "Elsewhere".into(),
        },
    );
    assert!(matches!(
        deliver(&mut replica, &log),
        Outcome::Accepted { .. }
    ));
    // A version with no readable header waits on the whole scope.
    log.append(SHARED, &dev(1), vec![0, 9]);
    assert_eq!(
        deliver(&mut replica, &log),
        Outcome::Waiting(Wait::Unsupported)
    );
    assert_eq!(parked(&replica).last().unwrap().1, "");
    assert_eq!(
        completeness(&replica, memo_type),
        Completeness::Incomplete(vec![Gap::WaitingScope])
    );
}

#[test]
fn unknown_op_kind_uses_affects() {
    let (mut replica, mut log) = setup();
    let unknown = |affects: Value| {
        framed(
            PAYLOAD_VERSION,
            &json!({"mutation":hex(&[4; 16]),"affects":affects,
                "op":{"kind":"increment","record":hex(&rid(1).0),"by":1}}),
            b"",
        )
    };
    log.append(SHARED, &dev(1), unknown(json!({"record": hex(&rid(1).0)})));
    assert_eq!(
        deliver(&mut replica, &log),
        Outcome::Waiting(Wait::Unsupported)
    );
    assert_eq!(
        parked(&replica)[0].1,
        format!("r:{}", hex(&rid(1).0)),
        "parked under the record its affects names"
    );
    let row_type: Vec<u8> = replica
        .conn()
        .query_row("SELECT type FROM data_parked", [], |r| r.get(0))
        .unwrap();
    assert_eq!(row_type, type_of(ARTICLE).0, "type from the local record");
    // The same record waits; another record of the type does not.
    order(&mut log, SHARED, &edit_title(rid(1), "Behind"));
    assert_eq!(deliver(&mut replica, &log), Outcome::Waiting(Wait::Queued));
    order(&mut log, SHARED, &edit_title(rid(2), "Free"));
    assert!(matches!(
        deliver(&mut replica, &log),
        Outcome::Accepted { .. }
    ));
    // Unique keys of the record's type may change: its family's unique work waits.
    order(
        &mut log,
        SHARED,
        &create_article(rid(3), "New", "https://example.test/3"),
    );
    assert_eq!(deliver(&mut replica, &log), Outcome::Waiting(Wait::Queued));
    // No affects: the whole scope.
    log.append(SHARED, &dev(1), unknown(json!({})));
    assert_eq!(
        deliver(&mut replica, &log),
        Outcome::Waiting(Wait::Unsupported)
    );
    order(&mut log, SHARED, &create_memo(rid(9), "Now waits"));
    assert_eq!(deliver(&mut replica, &log), Outcome::Waiting(Wait::Queued));
    assert_eq!(parked(&replica).len(), 5);
    // Unknown fields in affects or the header are malformed for this version.
    for header in [
        json!({"mutation":hex(&[4; 16]),"affects":{"record":hex(&rid(2).0),"app":"x"},"op":{"kind":"increment"}}),
        json!({"mutation":hex(&[4; 16]),"affects":{},"op":{"kind":"increment"},"extra":1}),
    ] {
        assert!(matches!(
            payload::decode(&framed(PAYLOAD_VERSION, &header, b"")),
            Decoded::Malformed(_)
        ));
    }
}

#[test]
fn unknown_field_in_known_kind_malformed() {
    let mutation = MutationId([5; 16]);
    let edit = edit_title(rid(1), "Edited");
    let bytes = payload::encode(mutation, &edit).unwrap();
    let header = header_of(&bytes);
    let mut cases = Vec::new();
    let mut surprise = header.clone();
    surprise["op"]["surprise"] = json!(1);
    cases.push(framed(PAYLOAD_VERSION, &surprise, b""));
    let mut nested = header.clone();
    nested["op"]["changes"][0]["extra"] = json!(1);
    cases.push(framed(PAYLOAD_VERSION, &nested, b""));
    let define = header_of(
        &payload::encode(
            mutation,
            &Operation::DefineType {
                bytes: ARTICLE.to_vec(),
            },
        )
        .unwrap(),
    );
    let mut inline = define.clone();
    inline["op"]["bytes"] = json!([1, 2, 3]);
    cases.push(framed(PAYLOAD_VERSION, &inline, ARTICLE));
    for case in cases {
        assert!(
            matches!(payload::decode(&case), Decoded::Malformed(_)),
            "{}",
            String::from_utf8_lossy(&case[6..])
        );
    }
    // The untouched header, written canonically, is the encoder's payload.
    assert_eq!(framed(PAYLOAD_VERSION, &header, b""), bytes);
    assert_eq!(payload::decode(&bytes), Decoded::Op(mutation, edit));
}

#[test]
fn noncanonical_header_malformed() {
    let mutation = MutationId([5; 16]);
    let edit = edit_title(rid(1), "Edited");
    let bytes = payload::encode(mutation, &edit).unwrap();
    let header = header_of(&bytes);
    let canonical = bh_data::value::canonical(&header);
    let mut reordered = String::from("{\"op\":");
    reordered.push_str(&bh_data::value::canonical(&header["op"]));
    reordered.push_str(&format!(
        ",\"mutation\":{},\"affects\":{}}}",
        header["mutation"], header["affects"]
    ));
    let unknown = framed(
        PAYLOAD_VERSION,
        &json!({"mutation":hex(&[4; 16]),"affects":{"record":hex(&rid(1).0)},
            "op":{"kind":"increment","record":hex(&rid(1).0)}}),
        b"",
    );
    let unknown_header = header_of(&unknown);
    for header_bytes in [
        serde_json::to_vec_pretty(&header).unwrap(),
        format!(" {canonical}").into_bytes(),
        format!("{canonical}\n").into_bytes(),
        reordered.into_bytes(),
        canonical
            .replace("\"Edited\"", "\"\\u0045dited\"")
            .into_bytes(),
        // An unknown kind is held to the same form, or old and new readers
        // could disagree on its affects.
        serde_json::to_vec_pretty(&unknown_header).unwrap(),
    ] {
        let case = framed_bytes(PAYLOAD_VERSION, &header_bytes, b"");
        assert_ne!(case, bytes);
        assert!(
            matches!(payload::decode(&case), Decoded::Malformed(_)),
            "{}",
            String::from_utf8_lossy(&header_bytes)
        );
    }
    assert!(matches!(
        payload::decode(&unknown),
        Decoded::Unsupported { .. }
    ));
}

#[test]
fn duplicate_key_header_malformed() {
    let mutation = MutationId([5; 16]);
    let bytes = payload::encode(mutation, &edit_title(rid(1), "Edited")).unwrap();
    let canonical = bh_data::value::canonical(&header_of(&bytes));
    // Last-wins would read an increment; first-wins an edit. Every reader rejects it.
    let in_op = canonical.replacen(
        "\"kind\":\"edit\"",
        "\"kind\":\"edit\",\"kind\":\"increment\"",
        1,
    );
    let top = canonical.replacen("{\"affects\":", "{\"affects\":{},\"affects\":", 1);
    let in_affects = canonical.replacen(
        "\"affects\":{",
        &format!("\"affects\":{{\"record\":\"{}\",", hex(&rid(2).0)),
        1,
    );
    for header_bytes in [in_op.clone(), top, in_affects] {
        assert_ne!(header_bytes, canonical);
        let case = framed_bytes(PAYLOAD_VERSION, header_bytes.as_bytes(), b"");
        assert!(
            matches!(payload::decode(&case), Decoded::Malformed(_)),
            "{header_bytes}"
        );
    }
    // Rejected on a replica, and never parked.
    let (mut replica, mut log) = setup();
    log.append(
        SHARED,
        &dev(1),
        framed_bytes(PAYLOAD_VERSION, in_op.as_bytes(), b""),
    );
    assert!(matches!(
        deliver(&mut replica, &log),
        Outcome::Rejected(r) if r.code == RejectCode::Schema
    ));
    assert!(parked(&replica).is_empty());
}

#[test]
fn oversize_local_save_refused_too_large() {
    let (mut replica, _log) = setup();
    let pending = |replica: &Replica| -> i64 {
        replica
            .conn()
            .query_row("SELECT count(*) FROM data_pending", [], |r| r.get(0))
            .unwrap()
    };
    let before = pending(&replica);
    for len in [MAX_DEFINITION_BYTES + 1, MAX_PAYLOAD_BYTES] {
        let op = Operation::DefineType {
            bytes: padded_article(len),
        };
        match replica.submit(SHARED, &dev(1), op) {
            Err(SubmitError::Rejected(r)) => assert_eq!(r.code, RejectCode::TooLarge),
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(pending(&replica), before, "nothing saved");
}

#[test]
fn unsupported_record_row_ignores_local_pending_type() {
    let (mut mine, mut log) = setup();
    let (mut theirs, _) = setup();
    // Only `mine` has saved R9, still pending; neither has an accepted R9.
    mine.submit(
        SHARED,
        &dev(2),
        create_article(rid(9), "Mine", "https://example.test/9"),
    )
    .unwrap();
    let unknown = framed(
        PAYLOAD_VERSION,
        &json!({"mutation":hex(&[4; 16]),"affects":{"record":hex(&rid(9).0)},
            "op":{"kind":"increment","record":hex(&rid(9).0)}}),
        b"",
    );
    log.append(SHARED, &dev(1), unknown);
    for replica in [&mut mine, &mut theirs] {
        assert_eq!(deliver(replica, &log), Outcome::Waiting(Wait::Unsupported));
    }
    let rows = |replica: &Replica| -> Vec<Vec<rusqlite::types::Value>> {
        let mut stmt = replica
            .conn()
            .prepare(
                "SELECT p.position,p.affects,p.payload,a.actor,p.reason,p.mutation,p.type,p.record,p.uniques,p.app,p.holds
                 FROM data_parked p JOIN data_actor a ON a.id=p.actor ORDER BY p.position",
            )
            .unwrap();
        stmt.query_map([], |r| (0..11).map(|i| r.get(i)).collect())
            .unwrap()
            .map(Result::unwrap)
            .collect()
    };
    let parked = rows(&mine);
    assert_eq!(parked.len(), 1);
    assert_eq!(parked, rows(&theirs), "the same row on every replica");
    assert_eq!(
        parked[0][6],
        rusqlite::types::Value::Null,
        "type unknown here"
    );
}

#[test]
fn malformed_rejected_not_parked() {
    let (mut replica, mut log) = setup();
    let mutation = MutationId([5; 16]);
    let edit = payload::encode(mutation, &edit_title(rid(1), "Edited")).unwrap();
    let header = header_of(&edit);
    let mut wrong_affects = header.clone();
    wrong_affects["affects"] = json!({"record": hex(&rid(2).0)});
    let mut too_long = edit.clone();
    too_long[2..6].copy_from_slice(&(edit.len() as u32).to_be_bytes());
    let mut tailed = edit.clone();
    tailed.push(b'x');
    let cases = [
        vec![0],
        vec![0, 1, 0, 0],
        too_long,
        tailed,
        framed(PAYLOAD_VERSION, &json!("not an object"), b""),
        framed(PAYLOAD_VERSION, &wrong_affects, b""),
        framed(
            PAYLOAD_VERSION,
            &json!({"mutation":hex(&[4; 16]),"affects":{},"op":{"record":hex(&rid(1).0)}}),
            b"",
        ),
    ];
    for case in cases {
        assert!(
            matches!(payload::decode(&case), Decoded::Malformed(_)),
            "{case:?}"
        );
        log.append(SHARED, &dev(1), case);
        match deliver(&mut replica, &log) {
            Outcome::Rejected(rejection) => assert_eq!(rejection.code, RejectCode::Schema),
            other => panic!("expected rejection, got {other:?}"),
        }
    }
    assert!(parked(&replica).is_empty());
    // Nothing queues behind rejected payloads.
    order(&mut log, SHARED, &edit_title(rid(1), "Edited"));
    assert!(matches!(
        deliver(&mut replica, &log),
        Outcome::Accepted { .. }
    ));
    assert!(
        pending::rejected(replica.conn(), SHARED)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn own_pending_work_matches_the_exact_ordered_bytes() {
    let (mut replica, mut log) = setup();
    let saved = replica
        .submit(SHARED, &dev(1), edit_title(rid(1), "Mine"))
        .unwrap();
    let state = |replica: &Replica| -> Option<String> {
        replica
            .conn()
            .query_row(
                "SELECT state FROM data_pending WHERE mutation=?1",
                [saved.mutation.0.as_slice()],
                |r| r.get(0),
            )
            .ok()
    };
    // The same operation, mutation id and actor in other bytes is not my save
    // (and, not being canonical, is malformed everywhere).
    let pretty = serde_json::to_vec_pretty(&header_of(&saved.payload)).unwrap();
    let reframed = framed_bytes(PAYLOAD_VERSION, &pretty, b"");
    assert_ne!(reframed, saved.payload);
    log.append(SHARED, &dev(1), reframed);
    assert!(matches!(
        deliver(&mut replica, &log),
        Outcome::Rejected(r) if r.code == RejectCode::Schema
    ));
    assert_eq!(state(&replica).as_deref(), Some("pending"));
    log.append(SHARED, &dev(1), saved.payload.clone());
    assert!(matches!(
        deliver(&mut replica, &log),
        Outcome::Accepted { .. }
    ));
    assert_eq!(state(&replica), None, "retired by its own ordered bytes");
}
