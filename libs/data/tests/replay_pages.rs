//! A scope's parked work replays in bounded pages and reaches the verdicts a
//! single whole-scope pass reaches, including rows that still wait.
use std::collections::BTreeMap;

use bh_data::{
    Actor, AppId, MutationId, Position, RecordId, RevisionId, Scope, Wait,
    catalogue::Shipped,
    index,
    mutation::{
        apply::{self, Outcome, ReplayLimits},
        ops::{FieldChange, Operation},
    },
    payload::{self, PAYLOAD_VERSION},
    store::records,
    testkit::{self, AssumedAdmission, Delivery, OrderedLog, Replica},
};
use serde_json::{Value, json};

const ARTICLE: &[u8] = include_bytes!("fixtures/types/Article.json");
const ADDRESS: &[u8] = include_bytes!("fixtures/types/Address.json");
const APP: AppId = AppId([2; 32]);
const SHARED: Scope = Scope {
    base: [1; 32],
    audience: [0; 32],
};
const WIDE: ReplayLimits = ReplayLimits {
    rows: 2,
    bytes: 1 << 20,
    vm_steps: u64::MAX,
};

fn dev() -> Actor {
    Actor::Device {
        account: [1; 32],
        device: [1; 32],
    }
}
fn rid(n: u8) -> RecordId {
    RecordId([n; 32])
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn create(record: RecordId, revision: RevisionId, url: &str) -> Operation {
    Operation::Create {
        record,
        type_id: bh_data::definition::parse(ARTICLE).unwrap().type_id,
        revision,
        doc: json!({"title": "Title", "url": url}),
    }
}
fn edit(record: RecordId, path: &str, value: Value) -> Operation {
    Operation::Edit {
        record,
        revision: RevisionId::of(ARTICLE),
        changes: vec![FieldChange {
            path: bh_data::FieldPath::parse(path).unwrap(),
            value: Some(value),
        }],
    }
}

/// Orders `op` with the author's assumed approval, as another replica saved it.
fn order(author: &mut Replica, log: &mut OrderedLog, op: Operation) -> Position {
    let bytes = author
        .assumed_payload(SHARED, &dev(), MutationId::random(), &op)
        .unwrap();
    let position = log.append(SHARED, &dev(), bytes);
    author.sync_from(log, Delivery::InOrder).unwrap();
    position
}

/// A payload this executable cannot read, naming one record.
fn unreadable(log: &mut OrderedLog, record: RecordId) -> Position {
    let header = json!({"affects": {"record": hex(&record.0)}, "anything": "a newer layout"});
    let header = bh_data::value::canonical(&header);
    let mut bytes = (PAYLOAD_VERSION + 1).to_be_bytes().to_vec();
    bytes.extend_from_slice(&(header.len() as u32).to_be_bytes());
    bytes.extend_from_slice(header.as_bytes());
    log.append(SHARED, &dev(), bytes)
}

/// Articles exist before the source becomes unique, so a replica whose unique
/// index is still building parks every later create on uniqueness. Later work
/// queues behind those rows, and an unreadable payload ordered after them
/// names the first create's record (and so every unique family): a page that
/// let unvisited later rows block earlier ones would leave the whole backlog
/// queued behind it.
fn backlog() -> OrderedLog {
    let mut log = OrderedLog::new();
    let mut author = Replica::new_in_memory().unwrap();
    let mut loose: Value = serde_json::from_slice(ARTICLE).unwrap();
    loose["unique"] = json!([]);
    loose["description"] = json!("Articles before the source became unique");
    let loose = serde_json::to_vec(&loose).unwrap();
    order(
        &mut author,
        &mut log,
        Operation::DefineApp {
            app: APP,
            name: "Reader".into(),
        },
    );
    order(
        &mut author,
        &mut log,
        Operation::DefineType {
            bytes: loose.clone(),
        },
    );
    for n in 1..=3 {
        order(
            &mut author,
            &mut log,
            create(
                rid(n),
                RevisionId::of(&loose),
                &format!("https://example.test/{n}"),
            ),
        );
    }
    order(
        &mut author,
        &mut log,
        Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        },
    );
    let fresh = |n: u8| {
        create(
            rid(n),
            RevisionId::of(ARTICLE),
            &format!("https://f.test/{n}"),
        )
    };
    order(&mut author, &mut log, fresh(10));
    order(&mut author, &mut log, fresh(11));
    // Claims record 1's source: rejected once uniqueness can be proven.
    order(
        &mut author,
        &mut log,
        create(rid(12), RevisionId::of(ARTICLE), "https://example.test/1"),
    );
    order(
        &mut author,
        &mut log,
        edit(rid(10), "/title", json!("Edited")),
    );
    order(
        &mut author,
        &mut log,
        edit(rid(11), "/url", json!("https://f.test/eleven")),
    );
    order(&mut author, &mut log, fresh(13));
    order(&mut author, &mut log, fresh(14));
    unreadable(&mut log, rid(10));
    // The unknown record type holds a later definition, leaving both kinds
    // of parked row for the twin comparison.
    unreadable(&mut log, rid(99));
    order(
        &mut author,
        &mut log,
        Operation::DefineType {
            bytes: ADDRESS.to_vec(),
        },
    );
    order(
        &mut author,
        &mut log,
        edit(rid(10), "/state", json!("saved")),
    );
    log
}

/// A replica that received `log` while its unique index was building, then
/// finished building without replaying: the state an index becoming ready
/// leaves behind.
fn parked_replica(replica: Replica, log: &OrderedLog) -> Replica {
    let mut replica = replica;
    replica.hold_backfill();
    for (_, outcome) in replica.sync_from(log, Delivery::InOrder).unwrap() {
        assert!(!matches!(outcome, Outcome::Rejected(_)), "{outcome:?}");
    }
    let tx = replica.conn().unchecked_transaction().unwrap();
    for ix in index::pending_work(&tx).unwrap() {
        while !index::backfill_step(&tx, ix, index::BACKFILL_BATCH)
            .unwrap()
            .ready
        {}
    }
    tx.commit().unwrap();
    replica
}

fn sid(replica: &Replica) -> i64 {
    records::lookup_scope(replica.conn(), SHARED)
        .unwrap()
        .unwrap()
}

fn whole_scope(replica: &Replica) -> Vec<(Position, Outcome)> {
    let tx = replica.conn().unchecked_transaction().unwrap();
    let decided = testkit::retry_parked(&tx, &Shipped, SHARED).unwrap();
    tx.commit().unwrap();
    decided
}

fn queue(replica: &Replica) -> bool {
    let tx = replica.conn().unchecked_transaction().unwrap();
    let queued = apply::schedule_replay(&tx, sid(replica)).unwrap();
    tx.commit().unwrap();
    queued
}

/// One committed page, or `None` once no pass is queued.
fn page(replica: &Replica, limits: ReplayLimits) -> Option<apply::ReplayPage> {
    let tx = replica.conn().unchecked_transaction().unwrap();
    let page = apply::replay_page_with_admission(&tx, &Shipped, limits, &AssumedAdmission).unwrap();
    tx.commit().unwrap();
    page
}

fn paged(replica: &Replica, limits: ReplayLimits) -> (Vec<(Position, Outcome)>, usize) {
    let mut decided = Vec::new();
    let mut pages = 0;
    while let Some(page) = page(replica, limits) {
        pages += 1;
        assert!(pages < 100, "a finite pass must end");
        assert!(page.rows >= 1 && page.rows <= limits.rows, "{page:?}");
        decided.extend(page.decided);
    }
    (decided, pages)
}

type ParkedRow = Vec<rusqlite::types::Value>;
fn parked(replica: &Replica) -> Vec<ParkedRow> {
    replica
        .conn()
        .prepare(
            "SELECT position,affects,reason,type,record,uniques,holds,payload,scope,mutation,actor,app,unresolved_type FROM data_parked ORDER BY position",
        )
        .unwrap()
        .query_map([], |r| (0..13).map(|i| r.get(i)).collect())
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn marker(replica: &Replica) -> Option<(i64, i64, bool)> {
    use rusqlite::OptionalExtension;
    replica
        .conn()
        .query_row("SELECT cursor,upper,decided FROM data_replay", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()
        .unwrap()
}

fn assert_same(paged: &Replica, whole: &Replica) {
    assert_eq!(
        paged.state_digest(SHARED).unwrap(),
        whole.state_digest(SHARED).unwrap()
    );
    assert_eq!(parked(paged), parked(whole));
    assert_eq!(marker(paged), None);
}

#[test]
fn paged_pass_reaches_the_whole_scope_verdicts() {
    let log = backlog();
    let whole = parked_replica(Replica::new_in_memory().unwrap(), &log);
    let pages = parked_replica(Replica::new_in_memory().unwrap(), &log);
    assert_eq!(parked(&whole), parked(&pages));
    let before = parked(&whole);
    assert!(before.len() > 2 * WIDE.rows, "more waits than two pages");
    assert!(before.iter().any(|row| matches!((&row[1], &row[4]),
        (rusqlite::types::Value::Text(key), rusqlite::types::Value::Null) if key.starts_with("t:")
    )), "a definition stays parked");
    assert!(
        before.iter().any(|row| matches!(
            (&row[3], &row[4], &row[12]),
            (
                rusqlite::types::Value::Null,
                rusqlite::types::Value::Blob(_),
                rusqlite::types::Value::Integer(1)
            )
        )),
        "a record with unknown type stays parked"
    );
    let expected = whole_scope(&whole);
    assert!(queue(&pages));
    let (decided, count) = paged(&pages, WIDE);
    assert!(count >= 4, "{count} pages");
    assert_eq!(decided, expected);
    assert_same(&pages, &whole);
    // The pass decided creates, edits and a duplicate claim, and left the
    // unreadable row and the work behind it parked.
    assert!(
        decided.iter().any(
            |(_, o)| matches!(o, Outcome::Rejected(r) if r.code == bh_data::RejectCode::Unique)
        )
    );
    assert_eq!(decided.len(), 7, "{decided:?}");
    let reasons: Vec<String> = parked(&pages)
        .into_iter()
        .map(|row| {
            let rusqlite::types::Value::Text(reason) = row[2].clone() else {
                panic!("reason")
            };
            reason
        })
        .collect();
    assert_eq!(
        reasons,
        [
            "\"Unsupported\"",
            "\"Unsupported\"",
            "\"Queued\"",
            "\"Queued\""
        ]
    );
}

#[test]
fn pages_respect_row_byte_and_work_bounds() {
    let log = backlog();
    let replica = parked_replica(Replica::new_in_memory().unwrap(), &log);
    let whole = parked_replica(Replica::new_in_memory().unwrap(), &log);
    whole_scope(&whole);
    queue(&replica);
    let sizes: BTreeMap<i64, usize> = parked(&replica)
        .into_iter()
        .map(|row| {
            let rusqlite::types::Value::Integer(position) = &row[0] else {
                panic!("position")
            };
            let rusqlite::types::Value::Blob(payload) = &row[7] else {
                panic!("payload")
            };
            (*position, payload.len())
        })
        .collect();
    let largest = *sizes.values().max().unwrap();
    // Bytes: a page stops before a row that would exceed the bound, unless
    // the row is the page's first.
    let bytes = ReplayLimits {
        rows: 16,
        bytes: largest + 1,
        vm_steps: u64::MAX,
    };
    let first = page(&replica, bytes).unwrap();
    assert!(first.bytes <= bytes.bytes, "{first:?}");
    assert!(first.rows < sizes.len(), "{first:?}");
    // Work: a twin at the same cursor measures what its next row costs. A
    // page given exactly that budget settles no further row (one row may
    // overrun its bound by its own evaluation; the meter is checked between
    // rows, never inside one).
    let twin = parked_replica(Replica::new_in_memory().unwrap(), &log);
    queue(&twin);
    assert_eq!(page(&twin, bytes).unwrap().rows, first.rows);
    let one = ReplayLimits {
        rows: 1,
        bytes: 1 << 20,
        vm_steps: u64::MAX,
    };
    let measured = page(&twin, one).unwrap().vm_steps;
    assert!(measured > 0);
    let work = ReplayLimits {
        rows: 16,
        bytes: 1 << 20,
        vm_steps: measured,
    };
    let spent = page(&replica, work).unwrap();
    assert_eq!((spent.rows, spent.vm_steps), (1, measured), "{spent:?}");
    paged(&replica, WIDE);
    assert_same(&replica, &whole);
}

#[test]
fn rows_that_still_wait_end_the_pass_without_spinning() {
    let log = backlog();
    let replica = parked_replica(Replica::new_in_memory().unwrap(), &log);
    // Without new dependencies, a second pass revisits every row once and
    // decides nothing, then removes its marker.
    queue(&replica);
    paged(&replica, WIDE);
    let settled = parked(&replica);
    assert!(queue(&replica));
    let rows = settled.len();
    let (decided, count) = paged(&replica, WIDE);
    assert!(decided.is_empty());
    assert_eq!(count, rows.div_ceil(WIDE.rows));
    assert_eq!(parked(&replica), settled);
    assert_eq!(marker(&replica), None);
    assert!(page(&replica, WIDE).is_none());
    assert!(!apply::replay_pending(replica.conn()).unwrap());
}

#[test]
fn a_pass_resumes_after_reopen_between_pages() {
    let log = backlog();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("paged.db");
    let replica = parked_replica(Replica::new_file(&path).unwrap(), &log);
    let whole = parked_replica(Replica::new_in_memory().unwrap(), &log);
    let expected = whole_scope(&whole);
    queue(&replica);
    let first = page(&replica, WIDE).unwrap();
    let cursor = marker(&replica).unwrap().0;
    assert!(!first.finished && cursor > 0);
    drop(replica);
    let reopened = Replica::new_file(&path).unwrap();
    assert_eq!(marker(&reopened).unwrap().0, cursor);
    let (rest, _) = paged(&reopened, WIDE);
    let decided: Vec<_> = first.decided.into_iter().chain(rest).collect();
    assert_eq!(decided, expected);
    assert_same(&reopened, &whole);
}

#[test]
fn a_failed_page_rolls_back_its_rows_and_cursor() {
    let log = backlog();
    let replica = parked_replica(Replica::new_in_memory().unwrap(), &log);
    let whole = parked_replica(Replica::new_in_memory().unwrap(), &log);
    whole_scope(&whole);
    queue(&replica);
    page(&replica, WIDE).unwrap();
    let (rows, cursor) = (parked(&replica), marker(&replica));
    replica
        .conn()
        .execute_batch(
            "CREATE TRIGGER fail_page BEFORE INSERT ON data_history BEGIN SELECT RAISE(ABORT,'page'); END;",
        )
        .unwrap();
    {
        let tx = replica.conn().unchecked_transaction().unwrap();
        assert!(apply::replay_page_with_admission(&tx, &Shipped, WIDE, &AssumedAdmission).is_err());
    }
    assert_eq!(parked(&replica), rows);
    assert_eq!(marker(&replica), cursor);
    replica
        .conn()
        .execute_batch("DROP TRIGGER fail_page")
        .unwrap();
    paged(&replica, WIDE);
    assert_same(&replica, &whole);
}

#[test]
fn a_new_dependency_restarts_the_pass_and_later_queued_work_follows_it() {
    let mut log = backlog();
    let mut whole = parked_replica(Replica::new_in_memory().unwrap(), &log);
    let mut replica = parked_replica(Replica::new_in_memory().unwrap(), &log);
    let mut verdicts: BTreeMap<u64, Outcome> = whole_scope(&whole)
        .into_iter()
        .map(|(p, o)| (p.0, o))
        .collect();
    queue(&replica);
    let mut seen: BTreeMap<u64, Outcome> = BTreeMap::new();
    let first = page(&replica, WIDE).unwrap();
    seen.extend(first.decided.into_iter().map(|(p, o)| (p.0, o)));
    // A second readiness while the pass is part-way restarts it from its
    // first row rather than being lost.
    assert!(queue(&replica));
    assert_eq!(marker(&replica).unwrap().0, -1);
    // Work ordered now queues behind a create this pass has not reached yet;
    // the pass decides that create, so it carries on over the new row.
    let edit = payload::encode(
        MutationId::random(),
        &edit(rid(14), "/title", json!("Later")),
    )
    .unwrap();
    let at = log.append(SHARED, &dev(), edit);
    let arrived = replica.sync_from(&log, Delivery::InOrder).unwrap();
    assert_eq!(arrived, [(at, Outcome::Waiting(Wait::Queued))]);
    let direct = whole.sync_from(&log, Delivery::InOrder).unwrap();
    assert!(
        matches!(direct[0].1, Outcome::Accepted { .. }),
        "{direct:?}"
    );
    verdicts.insert(at.0, direct[0].1.clone());
    let (rest, _) = paged(&replica, WIDE);
    seen.extend(rest.into_iter().map(|(p, o)| (p.0, o)));
    assert_eq!(seen, verdicts);
    assert_same(&replica, &whole);
}
