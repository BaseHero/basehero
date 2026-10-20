//! Sparse text must sort a bounded hit set, not probe every logical record.
use std::{
    cell::RefCell,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use bh_data::{
    Actor, AppId, CompiledType, CoreCatalogue, DataError, FieldPath, KeyRef, Position, RecordId,
    RevisionId, Scope,
    catalogue::Shipped,
    compose, definition, index,
    query::{Budget, Completeness, Query, QueryError, SortKey, TextMatch, TypeSelect},
    session::{Authority, DataSession, Store},
    store::{
        self, coverage,
        records::{self, RecordRow},
        registry,
    },
    text,
};
use rusqlite::{
    Connection, StatementStatus, Transaction,
    trace::{TraceEvent, TraceEventCodes},
};
use serde_json::json;

const SCOPE: Scope = Scope {
    base: [1; 32],
    audience: [2; 32],
};
const HIDDEN: Scope = Scope {
    base: [1; 32],
    audience: [3; 32],
};
fn rid(n: u32) -> RecordId {
    let mut id = [0; 32];
    id[..4].copy_from_slice(&n.to_be_bytes());
    RecordId(id)
}
fn path(s: &str) -> FieldPath {
    FieldPath::parse(s).unwrap()
}
struct Reader;
impl Authority for Reader {
    fn actor(&self) -> Actor {
        Actor::Device {
            account: [1; 32],
            device: [1; 32],
        }
    }
    fn reads(&self) -> Vec<Scope> {
        vec![SCOPE]
    }
    fn write(&self) -> Option<Scope> {
        None
    }
}
struct Local(Connection);
impl Store for Local {
    fn read<R>(&self, f: impl FnOnce(&Connection) -> Result<R, DataError>) -> Result<R, DataError> {
        f(&self.0)
    }
    fn write<R>(
        &self,
        _: impl FnOnce(&Transaction<'_>) -> Result<R, DataError>,
    ) -> Result<R, DataError> {
        Err(DataError::Unauthorized)
    }
    fn core(&self) -> &dyn CoreCatalogue {
        &Shipped
    }
}
fn compiled(n: u8) -> (CompiledType, Vec<u8>) {
    let bytes = serde_json::to_vec(&json!({
        "format":"bh-type/1", "local":format!("{n:02x}").repeat(16),
        "app":AppId([4;32]), "kind":"record", "name":"Item",
        "description":"Bounded searchable item", "extends":null, "uses":[],
        "schema":{"type":"object", "properties":{
            "title":{"type":"string","maxLength":200},
            "a":{"type":["integer","null"]}, "b":{"type":["integer","null"]},
            "c":{"type":["integer","null"]}, "d":{"type":["integer","null"]}
        }, "required":["title"]},
        "fields":{
            "/title":{"kind":"string","write":"direct","meaning":"Searchable title"},
            "/a":{"kind":"integer","write":"direct","meaning":"First key"},
            "/b":{"kind":"integer","write":"direct","meaning":"Second key"},
            "/c":{"kind":"integer","write":"direct","meaning":"Third key"},
            "/d":{"kind":"integer","write":"direct","meaning":"Fourth key"}
        },
        "indexes":[{"name":"four_keys","keys":["/a","/b","/c","/d"]}],
        "unique":[], "search":{"title":"/title","text":[]}, "actions":[], "queries":[],
        "evolution":{"previous":null,"migration":"","migration_ops":[],
            "examples":{"valid":[],"invalid":[]}}, "rationale":[]
    }))
    .unwrap();
    let def = definition::parse(&bytes).unwrap();
    let ty = compose::compile(&def, RevisionId::of(&def.bytes), &|_, _| None).unwrap();
    (ty, def.bytes)
}
fn install(tx: &Transaction<'_>, sid: i64, ty: &CompiledType, bytes: &[u8]) {
    registry::store_definition(tx, sid, ty, bytes, Position(1)).unwrap();
    registry::set_current(
        tx,
        sid,
        ty.type_id,
        ty.revision,
        &[ty.revision],
        Position(1),
    )
    .unwrap();
    index::ensure(tx, sid, ty).unwrap();
    coverage::set(tx, sid, Position(1), true).unwrap();
}
fn put(
    tx: &Transaction<'_>,
    sid: i64,
    ty: &CompiledType,
    validator: &bh_data::validate::Compiled,
    n: u32,
    title: String,
) {
    let doc = json!({"title":title,"a":1,"b":1,"c":1,"d":1});
    validator.validate(&doc).unwrap();
    let mut row = RecordRow {
        id: 0,
        scope: sid,
        record: rid(n),
        type_id: ty.type_id,
        revision: ty.revision,
        accepted: Some(doc),
        doc: None,
        deleted: false,
        pending: false,
        changed_at: None,
        changed: 0,
        text_rev: 0,
    };
    records::put(tx, &mut row).unwrap();
    index::on_record_changed(tx, &row, ty).unwrap();
    text::on_record_changed(tx, &row, ty).unwrap();
}
fn query(ty: &CompiledType, terms: &str) -> Query {
    Query {
        select: TypeSelect::Exact(ty.type_id),
        filter: None,
        sort: vec![],
        fields: vec![path("/title")],
        follow: vec![],
        text: Some(TextMatch {
            terms: terms.into(),
            on: None,
            require_revision: None,
        }),
        limit: 50,
        after: None,
    }
}

// Connection-local callbacks use thread-local storage, so parallel tests cannot
// mix statements. Only the probe and actual page are retained, not FTS internals.
thread_local! { static SQL: RefCell<Vec<(String, String)>> = const { RefCell::new(Vec::new()) }; }
fn trace(event: TraceEvent<'_>) {
    if let TraceEvent::Stmt(stmt, _) = event {
        let sql = stmt.expanded_sql().unwrap();
        if sql.starts_with("SELECT rowid FROM data_fts")
            || sql.starts_with("SELECT r.record,")
            || sql.starts_with("SELECT e.record,")
        {
            SQL.with(|seen| seen.borrow_mut().push((stmt.sql().into_owned(), sql)));
        }
    }
}
fn captured() -> Vec<(String, String)> {
    SQL.with(|seen| std::mem::take(&mut *seen.borrow_mut()))
}
fn evidence(conn: &Connection, statements: &[(String, String)], hits: usize, candidate: bool) {
    assert_eq!(statements.len(), 2, "probe and page");
    let work = Arc::new(AtomicU64::new(0));
    let count = work.clone();
    conn.progress_handler(
        1000,
        Some(move || {
            count.fetch_add(1000, Ordering::Relaxed) + 1000 > Budget::INTERACTIVE.vm_steps
        }),
    )
    .unwrap();
    for (i, (raw, sql)) in statements.iter().enumerate() {
        let bindings = conn.prepare(raw).unwrap().parameter_count();
        let plan = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap()
            .query_map([], |r| r.get::<_, String>(3))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .join(" | ");
        let mut stmt = conn.prepare(sql).unwrap();
        let rows = stmt
            .query_map([], |_| Ok(()))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        if i == 0 {
            assert_eq!(
                rows.len(),
                hits.min(2001),
                "probe is capped, not a corpus scan"
            );
            assert!(plan.contains("VIRTUAL TABLE"), "{plan}");
        } else if candidate {
            assert!(plan.contains("INTEGER PRIMARY KEY"), "{plan}");
            assert!(!plan.contains("data_record_logical"), "{plan}");
            assert!(
                stmt.get_status(StatementStatus::FullscanStep) <= hits as i32,
                "{plan}"
            );
        } else {
            assert!(plan.contains("data_record_logical"), "{plan}");
        }
        eprintln!(
            "hits={hits} statement={i} bindings={bindings} rows={} VM={} fullscan={} plan={plan}",
            rows.len(),
            stmt.get_status(StatementStatus::VmStep),
            stmt.get_status(StatementStatus::FullscanStep)
        );
    }
    conn.progress_handler(0, None::<fn() -> bool>).unwrap();
    let cap = if candidate && !statements[1].0.contains("UNION ALL") {
        100_000
    } else {
        Budget::INTERACTIVE.vm_steps
    };
    assert!(work.load(Ordering::Relaxed) < cap);
    eprintln!(
        "hits={hits} probe+page progress={} (includes FTS internals)",
        work.load(Ordering::Relaxed)
    );
}

#[test]
fn small_text_pages_cover_2000_and_2001_rows() {
    let (ty, bytes) = compiled(1);
    let validator = bh_data::validate::Compiled::new(&ty.effective_schema, &ty.resources).unwrap();
    let mut conn = Connection::open_in_memory().unwrap();
    let tx = conn.transaction().unwrap();
    store::migrate(&tx).unwrap();
    let sid = records::scope_id(&tx, SCOPE, &Shipped).unwrap();
    install(&tx, sid, &ty, &bytes);
    for n in (1..=2001).rev() {
        let term = if n == 2001 {
            "commonword extra"
        } else {
            "commonword"
        };
        put(&tx, sid, &ty, &validator, n, term.into());
    }
    tx.commit().unwrap();
    let store = Local(conn);
    let session = DataSession::new(&store, Reader);
    let mut q = query(&ty, "commonword");
    let first = session.query(SCOPE, &q).unwrap();
    assert_eq!(first.rows.len(), 50);
    assert_eq!(first.rows[0].record, rid(1));
    q.after = first.next;
    assert_eq!(session.query(SCOPE, &q).unwrap().rows[0].record, rid(51));
    assert_eq!(
        session.query(SCOPE, &query(&ty, "extra")).unwrap().rows[0].record,
        rid(2001)
    );
}

#[test]
fn bounded_text_candidates_do_not_multiply_cursor_bindings() {
    let (ty, bytes) = compiled(1);
    let validator = bh_data::validate::Compiled::new(&ty.effective_schema, &ty.resources).unwrap();
    let mut conn = Connection::open_in_memory().unwrap();
    let tx = conn.transaction().unwrap();
    store::migrate(&tx).unwrap();
    let sid = records::scope_id(&tx, SCOPE, &Shipped).unwrap();
    install(&tx, sid, &ty, &bytes);
    for n in (1..=2000).rev() {
        put(&tx, sid, &ty, &validator, n, "commonword".into());
    }
    tx.commit().unwrap();
    let store = Local(conn);
    let session = DataSession::new(&store, Reader);
    let mut q = query(&ty, "commonword");
    // The small-type sort fallback accepts more keys than a four-key index,
    // including redundant keys. Eight DESC keys emit seventeen branches.
    q.sort = ["/a", "/b", "/c", "/d"]
        .into_iter()
        .cycle()
        .take(8)
        .map(|p| SortKey {
            key: KeyRef::Field(path(p)),
            desc: true,
        })
        .collect();
    let page = session.query(SCOPE, &q).unwrap();
    assert_eq!(page.completeness, Completeness::Complete);
    assert_eq!(
        page.rows.iter().map(|r| r.record).collect::<Vec<_>>(),
        (1951..=2000).rev().map(rid).collect::<Vec<_>>()
    );
    q.after = page.next;
    // Seventeen repeated JSON-key sorts are still subject to the unchanged
    // work guard. Exhaustion must be TooCostly, not a SQL parameter error.
    assert!(matches!(
        session.query(SCOPE, &q),
        Err(QueryError::TooCostly { work: 1_001_000 })
    ));
}

#[test]
#[ignore = "run with scripts/check.sh data-scale (release)"]
fn sparse_text_100k_pages_and_candidate_boundaries() {
    let (ty, bytes) = compiled(1);
    let (other, other_bytes) = compiled(2);
    let validator = bh_data::validate::Compiled::new(&ty.effective_schema, &ty.resources).unwrap();
    let mut conn = Connection::open_in_memory().unwrap();
    let tx = conn.transaction().unwrap();
    store::migrate(&tx).unwrap();
    let sid = records::scope_id(&tx, SCOPE, &Shipped).unwrap();
    let hidden = records::scope_id(&tx, HIDDEN, &Shipped).unwrap();
    install(&tx, sid, &ty, &bytes);
    install(&tx, sid, &other, &other_bytes);
    install(&tx, hidden, &ty, &bytes);
    // Reverse physical order prevents a rowid page from accidentally passing.
    for n in (1..=100_000).rev() {
        let mut words = String::from("ordinary");
        for (hits, stride, term) in [
            (256, 330, "hits256"),
            (257, 330, "hits257"),
            (300, 330, "scaletoken"),
            (2000, 50, "hits2000"),
            (2001, 1, "hits2001"),
        ] {
            if n % stride == 0 && n / stride <= hits {
                words.push(' ');
                words.push_str(term);
            }
        }
        if n >= 98_000 {
            words.push_str(" sparse2001");
        }
        put(&tx, sid, &ty, &validator, n, words);
    }
    tx.commit().unwrap();
    conn.trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(trace));
    let store = Local(conn);
    let session = DataSession::new(&store, Reader);
    // First and next 50-row pages through the production authority-bound API.
    // Checking every sparse page also catches truncation/duplication at the cap.
    for (hits, stride, term) in [
        (300, 330, "scaletoken"),
        (256, 330, "hits256"),
        (257, 330, "hits257"),
        (2000, 50, "hits2000"),
        (2001, 1, "hits2001"),
        (100_000, 1, "ordinary"),
    ] {
        let mut q = query(&ty, term);
        let mut offset = 0;
        loop {
            captured();
            let page = session
                .query(SCOPE, &q)
                .unwrap_or_else(|e| panic!("{term} offset={offset}: {e:?}"));
            let statements = captured();
            assert_eq!(page.completeness, Completeness::Complete);
            let end = (offset + 50).min(hits);
            assert_eq!(
                page.rows.iter().map(|r| r.record).collect::<Vec<_>>(),
                ((offset + 1)..=end)
                    .map(|n| rid(n * stride))
                    .collect::<Vec<_>>(),
                "{term} offset={offset}"
            );
            assert_eq!(page.next.is_some(), end < hits);
            if offset < 100 {
                evidence(&store.0, &statements, hits as usize, hits <= 2000);
            }
            offset = end;
            match page.next {
                Some(next) => q.after = Some(next),
                None => break,
            }
            if hits == 100_000 && offset == 100 {
                break;
            }
            if hits == 2001 && offset == 2000 {
                // One hit remains, followed by 97,999 nonmatches. Proving EOF
                // on the guarded fallback is legitimately TooCostly.
                assert!(matches!(
                    session.query(SCOPE, &q),
                    Err(QueryError::TooCostly { work: 1_001_000 })
                ));
                break;
            }
        }
    }
    // Beyond the candidate allowance, a sparse logical-order walk can honestly
    // exhaust the same guard. No partial page may masquerade as Complete.
    assert!(matches!(
        session.query(SCOPE, &query(&ty, "sparse2001")),
        Err(QueryError::TooCostly { work: 1_001_000 })
    ));
    assert_eq!(
        session
            .query(HIDDEN, &query(&ty, "scaletoken"))
            .unwrap_err(),
        QueryError::Unauthorized
    );

    // Four DESC keys produce nine UNION branches after a non-NULL cursor.
    // At the candidate cap this exercises repeated bindings and the VM guard.
    let mut q = query(&ty, "hits2000");
    q.sort = ["/a", "/b", "/c", "/d"]
        .map(|p| SortKey {
            key: KeyRef::Field(path(p)),
            desc: true,
        })
        .to_vec();
    for offset in [0, 50] {
        captured();
        let page = session.query(SCOPE, &q).unwrap();
        let statements = captured();
        evidence(&store.0, &statements, 2000, true);
        assert_eq!(page.completeness, Completeness::Complete);
        assert_eq!(
            page.rows.iter().map(|r| r.record).collect::<Vec<_>>(),
            ((1951 - offset)..=(2000 - offset))
                .rev()
                .map(|n| rid(n * 50))
                .collect::<Vec<_>>()
        );
        q.after = page.next;
    }

    // A cursor issued for 2,001 hits must survive switching to the bounded
    // candidate path after one off-page match is deleted.
    let mut transition = query(&ty, "hits2001");
    transition.after = session.query(SCOPE, &transition).unwrap().next;

    // Same token in a different concrete type must not leak; unreadable text
    // must not even influence strategy selection in the readable audience.
    let mut conn = store.0;
    conn.trace_v2(TraceEventCodes::empty(), None);
    let tx = conn.transaction().unwrap();
    put(&tx, sid, &other, &validator, 0, "scaletoken".into());
    for n in 1..=2100 {
        put(&tx, hidden, &ty, &validator, n, "scaletoken".into());
    }
    let mut deleted = records::get(&tx, sid, rid(330)).unwrap().unwrap();
    deleted.deleted = true;
    records::put(&tx, &mut deleted).unwrap();
    index::on_record_changed(&tx, &deleted, &ty).unwrap();
    text::on_record_changed(&tx, &deleted, &ty).unwrap();
    let mut pending = records::get(&tx, sid, rid(660)).unwrap().unwrap();
    pending.pending = true;
    pending.doc = Some(
        json!({"title":"ordinary hits256 hits257 scaletoken hits2001 pending","a":1,"b":1,"c":1,"d":1}),
    );
    records::put(&tx, &mut pending).unwrap();
    index::on_record_changed(&tx, &pending, &ty).unwrap();
    text::on_record_changed(&tx, &pending, &ty).unwrap();
    tx.commit().unwrap();
    let store = Local(conn);
    let page = DataSession::new(&store, Reader)
        .query(SCOPE, &query(&ty, "scaletoken"))
        .unwrap();
    assert_eq!(page.completeness, Completeness::Complete);
    assert_eq!(
        page.rows.iter().map(|r| r.record).collect::<Vec<_>>(),
        (2..=51).map(|n| rid(n * 330)).collect::<Vec<_>>()
    );
    assert!(page.rows[0].pending);
    assert_eq!(
        page.rows[0].values["/title"],
        json!("ordinary hits256 hits257 scaletoken hits2001 pending")
    );
    let page = DataSession::new(&store, Reader)
        .query(SCOPE, &transition)
        .unwrap();
    assert_eq!(page.completeness, Completeness::Complete);
    assert_eq!(
        page.rows.iter().map(|r| r.record).collect::<Vec<_>>(),
        (51..=100).map(rid).collect::<Vec<_>>()
    );
}
