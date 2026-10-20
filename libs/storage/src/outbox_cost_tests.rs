//! Count SQLite work in the actual production helpers, not wall time or a
//! separately maintained copy of their queries. Fixtures and tracing are
//! thread-local; these tests can run alongside every other storage test.
use super::*;
use rusqlite::{
    StatementStatus,
    trace::{TraceEvent, TraceEventCodes},
};
use std::cell::RefCell;

thread_local! {
    static QUERIES: RefCell<Vec<(String, u64)>> = const { RefCell::new(Vec::new()) };
}
fn trace(event: TraceEvent<'_>) {
    if let TraceEvent::Profile(stmt, _) = event {
        let steps = stmt.get_status(StatementStatus::VmStep);
        assert!(steps >= 0, "VM counter overflow");
        QUERIES.with(|q| {
            q.borrow_mut()
                .push((stmt.expanded_sql().unwrap(), steps as u64))
        });
    }
}
const KEY: NoteKey = NoteKey {
    base: [1; 32],
    audience: [0; 32],
    note: [3; 32],
};
fn fixture(history: i64, pending: i64) -> DeviceDatabase {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    let tx = db.connection.transaction().unwrap();
    {
        let mut insert = tx.prepare("INSERT INTO note_updates(id,base,audience,note,request,delta) VALUES(?1,?2,?3,?4,?5,zeroblob(32))").unwrap();
        for id in 1..=history + pending {
            insert
                .execute(params![
                    id,
                    KEY.base,
                    KEY.audience,
                    KEY.note,
                    (id as u128).to_le_bytes()
                ])
                .unwrap();
        }
    }
    tx.execute(
        "INSERT INTO pending_note_work SELECT id FROM note_updates WHERE id>?1",
        [history],
    )
    .unwrap();
    tx.execute(
        "INSERT INTO pending_scope SELECT id,base,audience,note FROM note_updates WHERE id>?1",
        [history],
    )
    .unwrap();
    tx.execute("UPDATE pending_scope_backfill SET complete=1", [])
        .unwrap();
    tx.execute("INSERT INTO note_writer_slots(base,audience,note,account,device,slot,nonce,client_id) VALUES(?1,?2,?3,zeroblob(32),zeroblob(32),0,zeroblob(32),42)", params![KEY.base,KEY.audience,KEY.note]).unwrap();
    tx.execute("INSERT INTO note_update_writer SELECT id,base,audience,note,zeroblob(32),zeroblob(32),0 FROM note_updates WHERE id>?1", [history]).unwrap();
    // Substantial accepted history, including historical singleton packages,
    // with no pending references. None should be scanned to find a new run.
    tx.execute("INSERT INTO note_outbox SELECT id,CAST(printf('%032d',id) AS BLOB),x'00',x'00',NULL FROM note_updates WHERE id<=?1", [history]).unwrap();
    tx.execute(
        "INSERT INTO note_outbox_progress(update_id,outcome) SELECT update_id,2 FROM note_outbox",
        [],
    )
    .unwrap();
    tx.commit().unwrap();
    db
}
fn count(db: &DeviceDatabase, operation: impl FnOnce(), explain: bool) -> u64 {
    db.connection.flush_prepared_statement_cache();
    QUERIES.with(|q| q.borrow_mut().clear());
    db.connection
        .trace_v2(TraceEventCodes::SQLITE_TRACE_PROFILE, Some(trace));
    // A regressed query fails at a VM budget instead of turning CI into an
    // endurance test. Count all statements in the real helper together.
    let work = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    db.connection
        .progress_handler(
            1000,
            Some(move || work.fetch_add(1000, std::sync::atomic::Ordering::Relaxed) >= 5_000_000),
        )
        .unwrap();
    operation();
    db.connection
        .progress_handler(0, None::<fn() -> bool>)
        .unwrap();
    db.connection.trace_v2(TraceEventCodes::empty(), None);
    let queries = QUERIES.with(|q| std::mem::take(&mut *q.borrow_mut()));
    if explain {
        for (sql, steps) in &queries {
            let mut stmt = db
                .connection
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap();
            let plan: Vec<String> = stmt
                .query_map([], |r| r.get(3))
                .unwrap()
                .map(Result::unwrap)
                .collect();
            println!("SQL ({steps} steps): {sql}\nPLAN: {plan:?}");
        }
    }
    queries.iter().map(|(_, steps)| steps).sum()
}
fn measured(history: i64, n: i64, explain: bool) -> [u64; 3] {
    let db = fixture(history, n);
    let summary = count(
        &db,
        || {
            let summary = db.outbox_summary().unwrap();
            assert_eq!(summary.unaccepted, n as u64);
            assert_eq!(summary.unaccepted_notes, 1);
        },
        explain,
    );
    let page = count(
        &db,
        || {
            let page = db.unaccepted_packages(KEY, 0, 256).unwrap();
            assert_eq!(page.len(), 256);
            assert!(page.iter().all(|p| !p.packaged));
        },
        explain,
    );
    println!("history={history} pending={n}: summary={summary} page={page}");
    let head = count(
        &db,
        || {
            let heads = db.outbox_heads(0, 16).unwrap();
            assert_eq!(heads.len(), 1);
            assert_eq!(heads[0].first, history + 1);
        },
        explain,
    );
    println!("history={history} pending={n}: summary={summary} page={page} heads={head}");
    [summary, page, head]
}
#[test]
fn pending_helpers_have_linear_vm_work_and_do_not_walk_accepted_history() {
    let small = measured(0, 10_000, true);
    let large = measured(0, 20_000, false);
    let historical_small = measured(100_000, 10_000, false);
    let historical_large = measured(100_000, 20_000, false);
    for (index, name) in ["summary", "page", "heads"].iter().enumerate() {
        for (n, counts) in [
            (10_000, small),
            (20_000, large),
            (10_000, historical_small),
            (20_000, historical_large),
        ] {
            assert!(
                counts[index] < 200 * n + 100_000,
                "{name}: {counts:?} exceeds linear VM bound for {n} pending rows"
            );
        }
        assert!(
            large[index] * 2 < small[index] * 5,
            "{name} grows faster than 2.5x: {small:?} -> {large:?}"
        );
        assert!(
            historical_large[index] * 2 < historical_small[index] * 5,
            "{name} history growth ratio"
        );
        assert!(
            historical_small[index] <= small[index] + 10_000,
            "{name} scans accepted history: {small:?} -> {historical_small:?}"
        );
        assert!(
            historical_large[index] <= large[index] + 10_000,
            "{name} scans accepted history: {large:?} -> {historical_large:?}"
        );
    }
}

/// History and a backlog in one scope must not make the per-wake typed read expensive.
#[test]
fn typed_candidates_and_status_cost_only_open_work() {
    let measure = |history: i64, backlog: i64| {
        let db = DeviceDatabase::open(":memory:").unwrap();
        db.connection
            .execute(
                "INSERT INTO data_scope(id,base,audience) VALUES(1,zeroblob(32),zeroblob(32))",
                [],
            )
            .unwrap();
        db.connection.execute(
            "WITH RECURSIVE ids(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM ids WHERE n<?1)
             INSERT INTO typed_outbox(mutation,base,audience,after_note,event_id,descriptor,body,outcome)
             SELECT CAST(printf('%016d',n) AS BLOB),zeroblob(32),zeroblob(32),0,
                    CASE WHEN n<=?2 THEN CAST(printf('%032d',n) AS BLOB) ELSE NULL END,
                    CASE WHEN n<=?2 THEN x'00' ELSE NULL END,
                    CASE WHEN n<=?2 THEN x'00' ELSE NULL END,
                    CASE WHEN n<=?2 THEN 2 ELSE NULL END FROM ids",
            params![history + backlog, history],
        ).unwrap();
        db.connection
            .execute(
                "INSERT INTO data_pending(seq,scope,mutation,payload,state)
             SELECT id,1,mutation,x'00','pending' FROM typed_outbox WHERE outcome IS NULL",
                [],
            )
            .unwrap();
        let candidates = count(
            &db,
            || {
                let found = db.outbox_candidates(OutboxOrder::START, None, 16).unwrap();
                assert_eq!(
                    found
                        .iter()
                        .filter(|c| matches!(c, OutboxCandidate::Typed(_)))
                        .count(),
                    1
                );
            },
            false,
        );
        let status = count(
            &db,
            || {
                let s = db.outbox_summary().unwrap();
                assert_eq!(s.unaccepted_typed, backlog as u64);
            },
            false,
        );
        println!(
            "typed history={history} backlog={backlog}: candidates={candidates}, status={status}"
        );
        (candidates, status)
    };
    let small = measure(100, 3);
    let large = measure(10_000, 3);
    let short_backlog = measure(100, 100);
    let long_backlog = measure(100, 10_000);
    assert!(
        long_backlog.0 <= short_backlog.0 + 500,
        "candidate scans one scope's backlog: {short_backlog:?} -> {long_backlog:?}"
    );
    assert!(
        large.0 <= small.0 + 500,
        "candidate scans history: {small:?} -> {large:?}"
    );
    assert!(
        large.1 <= small.1 + 500,
        "status scans history: {small:?} -> {large:?}"
    );
}

/// The publisher's wake-time read is one indexed lookup: its SQLite work
/// does not grow with an unsent backlog, so a slow or offline device
/// holding thousands of rows wakes as cheaply as one holding ten.
#[test]
fn the_highest_pending_update_is_one_index_lookup() {
    let steps = |history: i64, pending: i64| {
        let db = fixture(history, pending);
        let steps = count(
            &db,
            || {
                let highest = db.highest_pending_update().unwrap();
                assert_eq!(highest, Some(history + pending));
            },
            false,
        );
        println!("history={history} pending={pending}: highest_pending_update={steps}");
        steps
    };
    // Ten rows, twenty thousand rows, and the same backlog behind a large
    // accepted history: one row read, so a handful of VM steps each.
    let small = steps(0, 10);
    let large = steps(0, 20_000);
    let historical = steps(100_000, 20_000);
    let empty = {
        let db = fixture(0, 0);
        assert_eq!(db.highest_pending_update().unwrap(), None);
        count(
            &db,
            || assert_eq!(db.highest_pending_update().unwrap(), None),
            false,
        )
    };
    for (n, counted) in [("10", small), ("20000", large), ("history", historical)] {
        assert!(
            counted <= small + 50,
            "highest_pending_update costs {counted} steps with {n} pending rows, ten cost {small}"
        );
    }
    assert!(empty <= small + 50, "empty costs {empty} steps");
}
