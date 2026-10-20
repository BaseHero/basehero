//! Replicas sharing one ordered log converge whatever their delivery, lag,
//! executable version or index readiness.
use std::collections::BTreeMap;

use bh_data::{
    Actor, AppId, FieldPath, Position, RecordId, RejectCode, RevisionId, Scope, TypeId, Wait,
    mutation::{
        apply::Outcome,
        ops::{FieldChange, Operation},
        pending::{self, LocalSaved, SubmitError},
        undo,
    },
    payload::{self, Decoded},
    store::records,
    testkit::{Delivery, OrderedLog, Replica},
};
use serde_json::{Value, json};

const ARTICLE: &[u8] = include_bytes!("fixtures/types/Article.json");
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
fn rid(n: u8) -> RecordId {
    RecordId([n; 32])
}
fn article() -> TypeId {
    bh_data::definition::parse(ARTICLE).unwrap().type_id
}
fn set(p: &str, v: Value) -> FieldChange {
    FieldChange {
        path: FieldPath::parse(p).unwrap(),
        value: Some(v),
    }
}
fn create(record: RecordId, revision: RevisionId, title: &str, url: &str) -> Operation {
    Operation::Create {
        record,
        type_id: article(),
        revision,
        doc: json!({"title": title, "url": url}),
    }
}
fn edit(record: RecordId, changes: Vec<FieldChange>) -> Operation {
    Operation::Edit {
        record,
        revision: RevisionId::of(ARTICLE),
        changes,
    }
}
fn define_app() -> Operation {
    Operation::DefineApp {
        app: APP,
        name: "Reader".into(),
    }
}
fn define_article() -> Operation {
    Operation::DefineType {
        bytes: ARTICLE.to_vec(),
    }
}

/// Saves `op` on `replica` and publishes it; `None` if refused locally.
fn publish(
    replica: &mut Replica,
    log: &mut OrderedLog,
    actor: &Actor,
    op: Operation,
) -> Option<(LocalSaved, Position)> {
    match replica.submit(SHARED, actor, op) {
        Ok(saved) => {
            let position = log.append(SHARED, actor, saved.payload.clone());
            Some((saved, position))
        }
        Err(SubmitError::Rejected(_)) => None,
        Err(SubmitError::Data(e)) => panic!("{e}"),
        Err(SubmitError::ConfirmationRequired(p)) => panic!("unexpected confirmation: {p:?}"),
    }
}

fn published(
    replica: &mut Replica,
    log: &mut OrderedLog,
    actor: &Actor,
    op: Operation,
) -> Position {
    publish(replica, log, actor, op)
        .expect("accepted locally")
        .1
}

fn sync(replica: &mut Replica, log: &OrderedLog) -> Vec<(Position, Outcome)> {
    replica.sync_from(log, Delivery::InOrder).unwrap()
}

fn parked(replica: &Replica) -> i64 {
    replica
        .conn()
        .query_row("SELECT count(*) FROM data_parked", [], |r| r.get(0))
        .unwrap()
}

fn accepted(replica: &Replica, record: RecordId) -> Option<Value> {
    let sid = records::lookup_scope(replica.conn(), SHARED)
        .unwrap()
        .unwrap();
    records::get(replica.conn(), sid, record)
        .unwrap()
        .and_then(|row| row.accepted)
}

fn digest(replica: &Replica) -> [u8; 32] {
    replica.state_digest(SHARED).unwrap()
}

/// The mutation ordered at `position`.
fn mutation_at(log: &OrderedLog, position: Position) -> bh_data::MutationId {
    match payload::decode(&log.entries()[position.0 as usize - 1].payload) {
        Decoded::Op(mutation, _) => mutation,
        other => panic!("{other:?}"),
    }
}

#[test]
fn unpark_replays_in_position_order_and_converges() {
    let mut log = OrderedLog::new();
    let mut old = Replica::new_in_memory().unwrap();
    let mut new = Replica::new_in_memory().unwrap();
    old.without_kinds(&["undo"]);
    for op in [
        define_app(),
        define_article(),
        create(
            rid(1),
            RevisionId::of(ARTICLE),
            "One",
            "https://example.test/1",
        ),
        create(
            rid(2),
            RevisionId::of(ARTICLE),
            "Two",
            "https://example.test/2",
        ),
        edit(rid(1), vec![set("/title", json!("Three"))]),
    ] {
        published(&mut new, &mut log, &dev(1), op);
        sync(&mut new, &log);
    }
    // p undoes the edit and p+1 undoes p; the old executable reads neither.
    // Replayed out of order, p+1 would find nothing to undo and the title
    // would end as "One".
    for _ in 0..2 {
        let last = Position(log.entries().len() as u64);
        let undo = undo::prepare(new.conn(), SHARED, mutation_at(&log, last)).unwrap();
        published(&mut new, &mut log, &dev(1), undo);
        sync(&mut new, &log);
    }
    assert_eq!(accepted(&new, rid(1)).unwrap()["title"], json!("Three"));
    // p+2 is readable but queues behind them on the same record. Another
    // record goes on (only its title: the parked work may change any of
    // record 1's fields, so new unique keys would wait), and an unrelated
    // definition makes the old replica replay its parked work, which still waits.
    for op in [
        edit(rid(1), vec![set("/state", json!("saved"))]),
        edit(rid(2), vec![set("/title", json!("Second"))]),
        Operation::DefineApp {
            app: AppId([8; 32]),
            name: "Other".into(),
        },
    ] {
        published(&mut new, &mut log, &dev(1), op);
    }
    for (_, outcome) in sync(&mut new, &log) {
        assert!(matches!(outcome, Outcome::Accepted { .. }), "{outcome:?}");
    }
    let outcomes: Vec<Outcome> = sync(&mut old, &log).into_iter().map(|(_, o)| o).collect();
    assert_eq!(
        outcomes[5..8],
        [
            Outcome::Waiting(Wait::Unsupported),
            Outcome::Waiting(Wait::Unsupported),
            Outcome::Waiting(Wait::Queued)
        ]
    );
    assert!(
        matches!(outcomes[8], Outcome::Accepted { .. }),
        "{outcomes:?}"
    );
    assert!(
        matches!(outcomes[9], Outcome::Accepted { .. }),
        "{outcomes:?}"
    );
    assert_eq!(parked(&old), 3);
    assert_eq!(accepted(&old, rid(1)).unwrap()["state"], Value::Null);
    assert_ne!(digest(&old), digest(&new));
    old.upgrade().unwrap();
    assert_eq!(parked(&old), 0);
    let one = accepted(&old, rid(1)).unwrap();
    assert_eq!(
        (&one["title"], &one["state"]),
        (&json!("Three"), &json!("saved"))
    );
    assert_eq!(digest(&old), digest(&new));
}

/// A deterministic generator (SplitMix64), so failures replay exactly.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

#[test]
fn replicas_converge_under_duplicates_and_delay() {
    const OPS: usize = 500;
    let mut rng = Rng(0x5eed_0011);
    let mut log = OrderedLog::new();
    let mut reps: Vec<Replica> = (0..3).map(|_| Replica::new_in_memory().unwrap()).collect();
    let actors = [dev(1), dev(2), dev(3)];
    // Every replica's outcome at each position, ignoring redeliveries.
    let mut seen: Vec<BTreeMap<u64, Outcome>> = vec![BTreeMap::new(); 3];
    let mut redelivered = 0;
    let mut withheld = 0;
    let mut record = |i: usize, outcomes: Vec<(Position, Outcome)>| {
        for (position, outcome) in outcomes {
            if outcome == Outcome::Duplicate {
                redelivered += 1;
            } else {
                assert!(seen[i].insert(position.0, outcome).is_none());
            }
        }
    };
    for op in [define_app(), define_article()] {
        published(&mut reps[0], &mut log, &actors[0], op);
        record(0, sync(&mut reps[0], &log));
    }
    for (i, replica) in reps.iter_mut().enumerate() {
        record(i, sync(replica, &log));
    }
    // Edits and deletions mostly reach recent records; a deleted id stays deleted.
    let mut records: Vec<RecordId> = Vec::new();
    let urls: Vec<String> = (0..16)
        .map(|n| format!("https://example.test/{n}"))
        .collect();
    let mut published_ops = 0;
    let mut undos = Vec::new();
    let mut attempts = 0;
    while published_ops < OPS {
        attempts += 1;
        assert!(attempts < OPS * 20, "generator stalled");
        let i = rng.below(3);
        let recent = &records[records.len().saturating_sub(8)..];
        let target = match recent.len() {
            0 => RecordId([0; 32]),
            n => recent[rng.below(n)],
        };
        let op = match rng.below(20) {
            0..=3 => create(
                {
                    let mut id = [0; 32];
                    id[..8].copy_from_slice(&(attempts as u64).to_be_bytes());
                    RecordId(id)
                },
                RevisionId::of(ARTICLE),
                &format!("Title {attempts}"),
                &urls[rng.below(urls.len())],
            ),
            4..=9 => edit(
                target,
                vec![set("/title", json!(format!("Edit {attempts}")))],
            ),
            10..=12 => edit(
                target,
                vec![set("/url", json!(urls[rng.below(urls.len())]))],
            ),
            13 | 14 => edit(
                target,
                vec![
                    set("/state", json!(["new", "saved"][rng.below(2)])),
                    set("/published", json!(rng.below(1_000_000))),
                ],
            ),
            15 => Operation::Delete { record: target },
            _ => {
                let entries = log.entries();
                let entry = &entries[rng.below(entries.len())];
                let Decoded::Op(mutation, _) = payload::decode(&entry.payload) else {
                    unreachable!()
                };
                match undo::prepare(reps[i].conn(), SHARED, mutation) {
                    Ok(op) => op,
                    Err(_) => continue,
                }
            }
        };
        let created = match &op {
            Operation::Create { record, .. } => Some(*record),
            _ => None,
        };
        let is_undo = matches!(op, Operation::Undo { .. });
        if let Some((_, position)) = publish(&mut reps[i], &mut log, &actors[i], op) {
            published_ops += 1;
            records.extend(created);
            if is_undo {
                undos.push(position.0);
            }
        }
        // Now and then one replica receives some of the log, in one of three
        // ways; the others work offline meanwhile.
        if rng.below(3) != 0 {
            continue;
        }
        let j = rng.below(3);
        let delivery = match rng.below(3) {
            0 => Delivery::InOrder,
            1 => Delivery::Duplicated,
            _ => {
                let len = log.entries().len();
                Delivery::Delayed(vec![len - rng.below(len.min(4))])
            }
        };
        let outcomes = reps[j].sync_from(&log, delivery).unwrap();
        if reps[j].received() < log.entries().len() {
            withheld += 1;
        }
        record(j, outcomes);
    }
    for (i, replica) in reps.iter_mut().enumerate() {
        record(i, replica.sync_from(&log, Delivery::Duplicated).unwrap());
    }
    let rejected = seen[0]
        .values()
        .filter(|o| matches!(o, Outcome::Rejected(_)))
        .count();
    let unique = seen[0]
        .values()
        .filter(|o| matches!(o, Outcome::Rejected(r) if r.code == RejectCode::Unique))
        .count();
    assert!(
        rejected >= 20 && unique >= 5,
        "conflicts: {rejected} rejected, {unique} unique"
    );
    let undone = undos
        .iter()
        .filter(|p| matches!(seen[0][p], Outcome::Accepted { .. }))
        .count();
    assert!(
        undos.len() >= 20 && undone >= 15,
        "undos: {} published, {undone} accepted",
        undos.len()
    );
    assert!(
        redelivered >= 50 && withheld >= 20,
        "{redelivered} redelivered, {withheld} withheld"
    );
    assert_eq!(seen[0].len(), log.entries().len());
    for i in 1..3 {
        assert_eq!(seen[i], seen[0], "replica {i} reached other verdicts");
        assert_eq!(digest(&reps[i]), digest(&reps[0]), "replica {i} diverged");
        assert_eq!(parked(&reps[i]), 0);
    }
}

/// Article records with a shared URL defined before the source became unique,
/// then the unique revision, so each replica's unique index has rows to build.
fn define_unique_over_duplicates(rep: &mut Replica, log: &mut OrderedLog) {
    let mut loose: Value = serde_json::from_slice(ARTICLE).unwrap();
    loose["unique"] = json!([]);
    loose["description"] = json!("Articles before the source became unique");
    let loose = serde_json::to_vec(&loose).unwrap();
    published(rep, log, &dev(1), define_app());
    sync(rep, log);
    published(
        rep,
        log,
        &dev(1),
        Operation::DefineType {
            bytes: loose.clone(),
        },
    );
    sync(rep, log);
    for n in [1, 2] {
        published(
            rep,
            log,
            &dev(1),
            create(
                rid(n),
                RevisionId::of(&loose),
                "Copy",
                "https://example.test/same",
            ),
        );
    }
    sync(rep, log);
}

#[test]
fn retry_after_backfill_converges() {
    let mut log = OrderedLog::new();
    let mut ready = Replica::new_in_memory().unwrap();
    let mut building = Replica::new_in_memory().unwrap();
    building.hold_backfill();
    define_unique_over_duplicates(&mut ready, &mut log);
    published(&mut ready, &mut log, &dev(1), define_article());
    sync(&mut ready, &log);
    published(
        &mut ready,
        &mut log,
        &dev(1),
        create(
            rid(3),
            RevisionId::of(ARTICLE),
            "Fresh",
            "https://example.test/fresh",
        ),
    );
    sync(&mut ready, &log);
    for op in [
        edit(rid(3), vec![set("/title", json!("Edited"))]),
        edit(rid(1), vec![set("/url", json!("https://example.test/one"))]),
        edit(rid(2), vec![set("/state", json!("saved"))]),
    ] {
        published(&mut ready, &mut log, &dev(1), op);
    }
    let direct: Vec<Outcome> = sync(&mut ready, &log).into_iter().map(|(_, o)| o).collect();
    assert!(direct.iter().all(|o| matches!(o, Outcome::Accepted { .. })));
    let waited: Vec<Outcome> = sync(&mut building, &log)
        .into_iter()
        .map(|(_, o)| o)
        .skip(5)
        .collect();
    // While the unique index builds, the create cannot prove its key free;
    // later work on the record or its unique family queues behind it.
    assert_eq!(
        waited,
        vec![
            Outcome::Waiting(Wait::UniquenessUnknown(SHARED)),
            Outcome::Waiting(Wait::Queued),
            Outcome::Waiting(Wait::Queued),
            Outcome::Waiting(Wait::Queued),
        ]
    );
    assert_ne!(digest(&building), digest(&ready));
    building.release_backfill().unwrap();
    assert_eq!(parked(&building), 0);
    assert_eq!(digest(&building), digest(&ready));
    assert_eq!(
        accepted(&building, rid(3)).unwrap(),
        json!({"title":"Edited","url":"https://example.test/fresh"})
    );
}

#[test]
fn submit_offline_then_converge() {
    let mut log = OrderedLog::new();
    let dir = tempfile::tempdir().unwrap();
    let mut a = Replica::new_file(&dir.path().join("a.db")).unwrap();
    let mut b = Replica::new_in_memory().unwrap();
    for op in [
        define_app(),
        define_article(),
        create(
            rid(1),
            RevisionId::of(ARTICLE),
            "One",
            "https://example.test/1",
        ),
    ] {
        published(&mut a, &mut log, &dev(1), op);
        sync(&mut a, &log);
    }
    sync(&mut b, &log);
    // Offline, both edit the same field and claim the same unique key.
    published(
        &mut a,
        &mut log,
        &dev(1),
        edit(rid(1), vec![set("/title", json!("A"))]),
    );
    published(
        &mut a,
        &mut log,
        &dev(1),
        create(
            rid(5),
            RevisionId::of(ARTICLE),
            "Mine",
            "https://example.test/taken",
        ),
    );
    let (lost, _) = publish(
        &mut b,
        &mut log,
        &dev(2),
        create(
            rid(6),
            RevisionId::of(ARTICLE),
            "Also mine",
            "https://example.test/taken",
        ),
    )
    .unwrap();
    published(
        &mut b,
        &mut log,
        &dev(2),
        edit(
            rid(1),
            vec![set("/title", json!("B")), set("/state", json!("saved"))],
        ),
    );
    // Each sees its own work before syncing.
    let sid = records::lookup_scope(b.conn(), SHARED).unwrap().unwrap();
    let view = records::get(b.conn(), sid, rid(6)).unwrap().unwrap();
    assert!(view.pending && !view.deleted);
    // A reopened file replica receives the log again; what it applied is a no-op.
    drop(a);
    let mut a = Replica::new_file(&dir.path().join("a.db")).unwrap();
    let again = sync(&mut a, &log);
    assert!(again[..3].iter().all(|(_, o)| *o == Outcome::Duplicate));
    sync(&mut b, &log);
    assert_eq!(digest(&a), digest(&b));
    let one = accepted(&a, rid(1)).unwrap();
    assert_eq!(one["title"], json!("B"), "the later ordered edit wins");
    assert_eq!(one["state"], json!("saved"));
    assert!(accepted(&a, rid(5)).is_some());
    assert!(accepted(&b, rid(6)).is_none());
    // The loser's work is kept on its replica with what it attempted.
    assert!(pending::rejected(a.conn(), SHARED).unwrap().is_empty());
    let rejected = pending::rejected(b.conn(), SHARED).unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].mutation, lost.mutation);
    assert_eq!(rejected[0].record, Some(rid(6)));
    assert_eq!(rejected[0].rejection.code, RejectCode::Unique);
    assert!(
        rejected[0]
            .attempted
            .contains(&set("/url", json!("https://example.test/taken")))
    );
    let row = records::get(b.conn(), sid, rid(6)).unwrap().unwrap();
    assert!(row.deleted && !row.pending);
    // Neither replica has pending work left.
    for replica in [&a, &b] {
        let left: i64 = replica
            .conn()
            .query_row(
                "SELECT count(*) FROM data_pending WHERE state<>'rejected'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(left, 0);
    }
}
