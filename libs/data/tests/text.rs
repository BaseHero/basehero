use bh_data::{
    AppId, CompiledType, CoreCatalogue, FieldKind, FieldPath, FieldSpec, Position, RecordId,
    RevisionId, Scope, SearchMap, TypeDocs, TypeId, TypeKind, WritePolicy,
    query::{self, Budget, Completeness, Gap, Query, QueryError, TextMatch, TypeSelect},
    store::{
        self, coverage,
        records::{self, RecordRow},
        registry,
    },
    text,
};
use rusqlite::{Connection, OptionalExtension};
use serde_json::json;

fn scope(n: u8) -> Scope {
    Scope {
        base: [1; 32],
        audience: [n; 32],
    }
}
fn record(n: u8) -> RecordId {
    RecordId([n; 32])
}
fn path(s: &str) -> FieldPath {
    FieldPath::parse(s).unwrap()
}
struct Core;
impl CoreCatalogue for Core {
    fn core_type(&self, _: TypeId) -> Option<CompiledType> {
        None
    }
}
fn ct(body: bool) -> CompiledType {
    let type_id = TypeId([4; 32]);
    let revision = RevisionId([4; 32]);
    CompiledType {
        type_id,
        revision,
        kind: TypeKind::Record,
        app: Some(AppId([1; 32])),
        name: "test".into(),
        lineage: vec![(type_id, revision)],
        effective_schema: json!({"type":"object"}),
        resources: vec![],
        fields: ["/title", "/body"]
            .into_iter()
            .map(|p| FieldSpec {
                path: path(p),
                kind: FieldKind::String,
                write: WritePolicy::Direct,
                required: false,
                nullable: false,
                declared_by: type_id,
                meaning: p.into(),
                unit: None,
                absent: None,
            })
            .collect(),
        indexes: vec![],
        uniques: vec![],
        queries: vec![],
        search: SearchMap {
            title: Some(path("/title")),
            text: vec![path("/body")],
            builtin_body: body,
        },
        actions: vec![],
        builtin: None,
        previous: None,
        docs: TypeDocs {
            description: String::new(),
            rationale: vec![],
            examples_valid: vec![],
            examples_invalid: vec![],
            migration: None,
        },
    }
}
fn setup(scopes: &[Scope], body: bool) -> (Connection, CompiledType, Vec<i64>) {
    setup_with(scopes, ct(body))
}
fn setup_with(scopes: &[Scope], t: CompiledType) -> (Connection, CompiledType, Vec<i64>) {
    let mut conn = Connection::open_in_memory().unwrap();
    let tx = conn.transaction().unwrap();
    store::migrate(&tx).unwrap();
    let mut ids = vec![];
    for s in scopes {
        let sid = records::scope_id(&tx, *s, &Core).unwrap();
        registry::store_definition(&tx, sid, &t, b"type", Position(1)).unwrap();
        registry::set_current(&tx, sid, t.type_id, t.revision, &[t.revision], Position(1)).unwrap();
        coverage::set(&tx, sid, Position(1), true).unwrap();
        bh_data::index::ensure(&tx, sid, &t).unwrap();
        ids.push(sid);
    }
    tx.commit().unwrap();
    (conn, t, ids)
}
fn save(
    conn: &mut Connection,
    sid: i64,
    t: &CompiledType,
    n: u8,
    title: &str,
    body: &str,
) -> RecordRow {
    let tx = conn.transaction().unwrap();
    let mut r = records::get(&tx, sid, record(n))
        .unwrap()
        .unwrap_or(RecordRow {
            id: 0,
            scope: sid,
            record: record(n),
            type_id: t.type_id,
            revision: t.revision,
            accepted: None,
            doc: None,
            deleted: false,
            pending: false,
            changed_at: None,
            changed: 0,
            text_rev: 0,
        });
    r.accepted = Some(json!({"title":title,"body":body}));
    records::put(&tx, &mut r).unwrap();
    text::on_record_changed(&tx, &r, t).unwrap();
    r.text_rev = records::get(&tx, sid, record(n)).unwrap().unwrap().text_rev;
    tx.commit().unwrap();
    r
}
fn search(
    conn: &Connection,
    s: Scope,
    reads: &[Scope],
    terms: &str,
    required: Option<u64>,
) -> Result<query::Page, QueryError> {
    let q = Query {
        select: TypeSelect::Exact(ct(false).type_id),
        filter: None,
        sort: vec![],
        fields: vec![path("/title")],
        follow: vec![],
        text: Some(TextMatch {
            terms: terms.into(),
            on: None,
            require_revision: required,
        }),
        limit: 50,
        after: None,
    };
    query::run(conn, s, reads, &Core, &q, Budget::INTERACTIVE)
}
#[test]
fn generic_text_searchable_in_same_transaction() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], false);
    let tx = c.transaction().unwrap();
    let mut r = RecordRow {
        id: 0,
        scope: ids[0],
        record: record(1),
        type_id: t.type_id,
        revision: t.revision,
        accepted: Some(json!({"title":"Garden", "body":"violet"})),
        doc: None,
        deleted: false,
        pending: false,
        changed_at: None,
        changed: 0,
        text_rev: 0,
    };
    records::put(&tx, &mut r).unwrap();
    text::on_record_changed(&tx, &r, &t).unwrap();
    assert_eq!(search(&tx, s, &[s], "violet", None).unwrap().rows.len(), 1);
}
#[test]
fn rebuild_restores_search_and_resume_keeps_search_behind() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let s = scope(2);
    let t = ct(false);
    let mut c = Connection::open(file.path()).unwrap();
    let tx = c.transaction().unwrap();
    store::migrate(&tx).unwrap();
    let sid = records::scope_id(&tx, s, &Core).unwrap();
    registry::store_definition(&tx, sid, &t, b"type", Position(1)).unwrap();
    registry::set_current(&tx, sid, t.type_id, t.revision, &[t.revision], Position(1)).unwrap();
    coverage::set(&tx, sid, Position(1), true).unwrap();
    tx.commit().unwrap();
    for n in 0..510u32 {
        let tx = c.transaction().unwrap();
        let mut row = RecordRow {
            id: 0,
            scope: sid,
            record: RecordId({
                let mut bytes = [0; 32];
                bytes[..4].copy_from_slice(&n.to_be_bytes());
                bytes
            }),
            type_id: t.type_id,
            revision: t.revision,
            accepted: Some(json!({"title":format!("garden {n}"),"body":"violet"})),
            doc: None,
            deleted: false,
            pending: false,
            changed_at: None,
            changed: 0,
            text_rev: 0,
        };
        records::put(&tx, &mut row).unwrap();
        text::on_record_changed(&tx, &row, &t).unwrap();
        tx.commit().unwrap();
    }
    let before = search(&c, s, &[s], "violet", None).unwrap();
    c.execute("DELETE FROM data_fts", []).unwrap();
    assert!(search(&c, s, &[s], "violet", None).unwrap().rows.is_empty());
    drop(c);
    let mut interrupted_build = false;
    assert!(
        bh_data::index::rebuild_all(|| {
            let conn = Connection::open(file.path())
                .map_err(|e| bh_data::DataError::Sql(e.to_string()))?;
            let cursor: Option<i64> = conn
                .query_row(
                    "SELECT cursor FROM data_text_rebuild WHERE phase='building'",
                    [],
                    |r| r.get(0),
                )
                .optional()
                .unwrap();
            if cursor.is_some_and(|cursor| cursor > 0 && cursor < 510) {
                interrupted_build = true;
                return Err(bh_data::DataError::Sql("simulated restart".into()));
            }
            Ok(conn)
        })
        .is_err()
    );
    assert!(
        interrupted_build,
        "rebuild was interrupted after a committed projection batch"
    );
    let c = Connection::open(file.path()).unwrap();
    let w = text::watermark(&c, s).unwrap();
    assert!(w.complete_through < w.current);
    assert!(matches!(
        search(&c, s, &[s], "violet", Some(w.current)),
        Err(QueryError::TextBehind { .. })
    ));
    drop(c);
    bh_data::index::rebuild_all(|| {
        Connection::open(file.path()).map_err(|e| bh_data::DataError::Sql(e.to_string()))
    })
    .unwrap();
    let c = Connection::open(file.path()).unwrap();
    let after = search(&c, s, &[s], "violet", None).unwrap();
    assert_eq!(after.rows, before.rows);
    assert_eq!(after.completeness, Completeness::Complete);
    assert!(text::watermark(&c, s).unwrap().complete_through >= w.current);
}
#[test]
fn rebuilt_builtin_body_waits_for_fresh_extraction() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let s = scope(2);
    let t = ct(true);
    let mut c = Connection::open(file.path()).unwrap();
    let tx = c.transaction().unwrap();
    store::migrate(&tx).unwrap();
    let sid = records::scope_id(&tx, s, &Core).unwrap();
    registry::store_definition(&tx, sid, &t, b"type", Position(1)).unwrap();
    registry::set_current(&tx, sid, t.type_id, t.revision, &[t.revision], Position(1)).unwrap();
    coverage::set(&tx, sid, Position(1), true).unwrap();
    tx.commit().unwrap();
    save(&mut c, sid, &t, 1, "garden", "not the built-in body");
    let job = text::next_jobs(&c, 1).unwrap().remove(0);
    let tx = c.transaction().unwrap();
    text::store_extracted(&tx, &job, "violet").unwrap();
    tx.commit().unwrap();
    assert_eq!(search(&c, s, &[s], "violet", None).unwrap().rows.len(), 1);
    c.execute(
        "INSERT INTO data_pending(seq,scope,mutation,payload,state) VALUES(1,?1,?2,?3,'pending')",
        rusqlite::params![sid, [3u8; 16].as_slice(), b"saved-work"],
    )
    .unwrap();
    drop(c);
    bh_data::index::rebuild_all(|| {
        Connection::open(file.path()).map_err(|e| bh_data::DataError::Sql(e.to_string()))
    })
    .unwrap();
    let mut c = Connection::open(file.path()).unwrap();
    assert_eq!(text::next_jobs(&c, 10).unwrap().len(), 1);
    assert!(
        matches!(search(&c, s, &[s], "violet", None).unwrap().completeness, Completeness::Incomplete(gaps) if gaps.iter().any(|g| matches!(g, Gap::TextBehind { .. })))
    );
    assert_eq!(
        c.query_row("SELECT count(*) FROM data_pending", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    let job = text::next_jobs(&c, 1).unwrap().remove(0);
    let tx = c.transaction().unwrap();
    text::store_extracted(&tx, &job, "violet").unwrap();
    tx.commit().unwrap();
    assert_eq!(search(&c, s, &[s], "violet", None).unwrap().rows.len(), 1);
    assert_eq!(
        search(&c, s, &[s], "violet", None).unwrap().completeness,
        Completeness::Complete
    );
}
#[test]
fn decomposed_combining_marks_match_precomposed_words() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], false);
    save(&mut c, ids[0], &t, 1, "na\u{69}\u{308}ve", "example");
    assert_eq!(search(&c, s, &[s], "naïve", None).unwrap().rows.len(), 1);
    assert_eq!(
        search(&c, s, &[s], "na\u{69}\u{308}ve", None)
            .unwrap()
            .rows
            .len(),
        1
    );
}
#[test]
fn body_jobs_coalesce_by_revision() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], true);
    for n in 0..5 {
        save(&mut c, ids[0], &t, 1, &format!("title {n}"), "ignored");
    }
    let jobs = text::next_jobs(&c, 10).unwrap();
    assert_eq!(jobs.len(), 1);
    assert_eq!(jobs[0].wanted, text::watermark(&c, s).unwrap().current);
    assert!(jobs[0].wanted > 1);
}
#[test]
fn coalesced_job_does_not_claim_the_earlier_revision() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], true);
    let first = save(&mut c, ids[0], &t, 1, "one", "ignored");
    let later = save(&mut c, ids[0], &t, 1, "two", "ignored");
    assert!(later.text_rev > first.text_rev);
    let watermark = text::watermark(&c, s).unwrap();
    assert!(watermark.complete_through < first.text_rev);
    assert!(matches!(
        search(&c, s, &[s], "one", Some(first.text_rev)),
        Err(QueryError::TextBehind { .. })
    ));
    let job = text::next_jobs(&c, 1).unwrap().remove(0);
    let tx = c.transaction().unwrap();
    assert!(text::store_extracted(&tx, &job, "latest body").unwrap());
    tx.commit().unwrap();
    assert!(text::watermark(&c, s).unwrap().complete_through >= later.text_rev);
    assert!(search(&c, s, &[s], "two", Some(first.text_rev)).is_ok());
}
#[test]
fn obsolete_extraction_discarded() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], true);
    save(&mut c, ids[0], &t, 1, "old", "ignored");
    let old = text::next_jobs(&c, 1).unwrap().remove(0);
    save(&mut c, ids[0], &t, 1, "new", "ignored");
    let tx = c.transaction().unwrap();
    assert!(!text::store_extracted(&tx, &old, "obsolete").unwrap());
    tx.commit().unwrap();
    assert_eq!(text::next_jobs(&c, 1).unwrap().len(), 1);
    assert!(
        search(&c, s, &[s], "obsolete", None)
            .unwrap()
            .rows
            .is_empty()
    );
}
#[test]
fn stale_search_never_labelled_complete() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], true);
    save(&mut c, ids[0], &t, 1, "Garden", "ignored");
    assert!(
        matches!(search(&c,s,&[s],"Garden",None).unwrap().completeness,
        Completeness::Incomplete(g) if g.iter().any(|x| matches!(x,Gap::TextBehind{..})))
    );
}
#[test]
fn require_revision_errors_when_behind() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], true);
    let r = save(&mut c, ids[0], &t, 1, "Garden", "ignored");
    assert!(matches!(
        search(&c, s, &[s], "Garden", Some(r.text_rev)),
        Err(QueryError::TextBehind { .. })
    ));
}
#[test]
fn multiword_search_is_order_independent_and_crosses_title_and_body() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], false);
    save(&mut c, ids[0], &t, 1, "Garden plan", "violet roses");
    assert_eq!(
        search(&c, s, &[s], "garden violet", None)
            .unwrap()
            .rows
            .len(),
        1
    );
    assert_eq!(
        search(&c, s, &[s], "roses violet", None)
            .unwrap()
            .rows
            .len(),
        1
    );
    assert_eq!(
        search(&c, s, &[s], "garden missing", None)
            .unwrap()
            .rows
            .len(),
        0
    );
}
#[test]
fn punctuation_only_is_not_a_complete_empty_answer() {
    let s = scope(2);
    let (c, _, _) = setup(&[s], false);
    assert!(
        matches!(search(&c,s,&[s]," : * \" ! ",None),Err(QueryError::NotQueryable{detail,..}) if detail.contains("term"))
    );
}
#[test]
fn fts_terms_are_not_raw_syntax() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], false);
    save(&mut c, ids[0], &t, 1, "x garden title", "ignored OR");
    assert_eq!(
        search(&c, s, &[s], "title:x OR", None).unwrap().rows.len(),
        1
    );
    assert!(search(&c, s, &[s], "\" OR body:*", None).is_ok());
}
#[test]
fn large_body_indexed_by_prefix() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], true);
    save(&mut c, ids[0], &t, 1, "title", "ignored");
    let body = format!(
        "findme {} beyondlimit",
        "a".repeat(text::MAX_INDEXED_BODY_BYTES)
    );
    let job = text::next_jobs(&c, 1).unwrap().remove(0);
    let tx = c.transaction().unwrap();
    assert!(text::store_extracted(&tx, &job, &body).unwrap());
    tx.commit().unwrap();
    assert_eq!(search(&c, s, &[s], "findme", None).unwrap().rows.len(), 1);
    assert!(
        search(&c, s, &[s], "beyondlimit", None)
            .unwrap()
            .rows
            .is_empty()
    );
}
#[test]
fn text_search_scoped_by_token() {
    let a = scope(2);
    let b = scope(3);
    let (mut c, t, ids) = setup(&[a, b], false);
    save(&mut c, ids[0], &t, 1, "sameword", "one");
    save(&mut c, ids[1], &t, 2, "sameword", "two");
    assert_eq!(
        search(&c, a, &[a, b], "sameword", None).unwrap().rows[0].record,
        record(1)
    );
    assert_eq!(
        search(&c, b, &[a, b], "sameword", None).unwrap().rows[0].record,
        record(2)
    );
}
#[test]
fn watermark_is_comparable_across_records() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], true);
    save(&mut c, ids[0], &t, 1, "one", "ignored");
    let first = text::next_jobs(&c, 1).unwrap().remove(0);
    save(&mut c, ids[0], &t, 2, "two", "ignored");
    let second = text::next_jobs(&c, 10)
        .unwrap()
        .into_iter()
        .find(|j| j.record == record(2))
        .unwrap();
    assert!(second.wanted > first.wanted);
    let tx = c.transaction().unwrap();
    text::store_extracted(&tx, &first, "one").unwrap();
    tx.commit().unwrap();
    assert_eq!(
        text::watermark(&c, s).unwrap().complete_through,
        second.wanted - 1
    );
}
#[test]
#[ignore = "run with scripts/check.sh data-scale (release)"]
fn broad_text_pages_seek_logical_ids_and_sorted_work_is_bounded() {
    fn fill(c: &mut Connection, sid: i64, t: &CompiledType, from: u32, until: u32) {
        let tx = c.transaction().unwrap();
        for n in (from..=until).rev() {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&n.to_be_bytes());
            let mut row = RecordRow {
                id: 0,
                scope: sid,
                record: RecordId(id),
                type_id: t.type_id,
                revision: t.revision,
                accepted: Some(
                    json!({"title":format!("{n:06}"),"body":if n%3000==0 {"commonword rareword"}else{"commonword"}}),
                ),
                doc: None,
                deleted: false,
                pending: false,
                changed_at: None,
                changed: 0,
                text_rev: 0,
            };
            records::put(&tx, &mut row).unwrap();
            text::on_record_changed(&tx, &row, t).unwrap();
            bh_data::index::on_record_changed(&tx, &row, t).unwrap();
        }
        tx.commit().unwrap();
    }
    fn logical_id(n: u32) -> RecordId {
        let mut id = [0; 32];
        id[..4].copy_from_slice(&n.to_be_bytes());
        RecordId(id)
    }
    fn steps(c: &Connection, s: Scope, q: &Query, first: u32) -> u64 {
        for n in (0..=100_000).step_by(1000) {
            match query::run(c, s, &[s], &Core, q, Budget { vm_steps: n }) {
                Ok(page) => {
                    assert_eq!(page.completeness, Completeness::Complete);
                    assert_eq!(
                        page.rows.iter().map(|r| r.record).collect::<Vec<_>>(),
                        (first..first + q.limit).map(logical_id).collect::<Vec<_>>()
                    );
                    return n + 1000;
                }
                Err(QueryError::TooCostly { .. }) => {}
                other => panic!("text page at {n} steps: {other:?}"),
            }
        }
        panic!("text page exceeded 100k VM steps")
    }
    let s = scope(2);
    let mut t = ct(false);
    t.indexes.push(bh_data::IndexDecl {
        name: "by_title".into(),
        keys: vec![bh_data::KeyRef::Field(path("/title"))],
        declared_by: t.type_id,
    });
    t.indexes.push(bh_data::IndexDecl {
        name: "recent".into(),
        keys: vec![bh_data::KeyRef::Changed],
        declared_by: t.type_id,
    });
    let (mut c, t, ids) = setup_with(&[s], t);
    let mut q = Query {
        select: TypeSelect::Exact(t.type_id),
        filter: None,
        sort: vec![],
        fields: vec![],
        follow: vec![],
        text: Some(TextMatch {
            terms: "commonword".into(),
            on: None,
            require_revision: None,
        }),
        limit: 200,
        after: None,
    };
    fill(&mut c, ids[0], &t, 1, 2000);
    let small = steps(&c, s, &q, 1);
    fill(&mut c, ids[0], &t, 2001, 20000);
    let large = steps(&c, s, &q, 1);
    assert!(
        large * 2 <= small * 3,
        "first text page grew {small} to {large} steps"
    );
    // Cursor to 19,000 without measuring the preceding pages.
    let mut seen = 0;
    while seen < 19_000 {
        let page = query::run(&c, s, &[s], &Core, &q, Budget::INTERACTIVE).unwrap();
        assert_eq!(page.completeness, Completeness::Complete);
        assert_eq!(
            page.rows.iter().map(|r| r.record).collect::<Vec<_>>(),
            (seen + 1..=seen + q.limit)
                .map(logical_id)
                .collect::<Vec<_>>()
        );
        seen += q.limit;
        q.after = page.next;
    }
    let deep = steps(&c, s, &q, 19_001);
    eprintln!("text page work: 2k={small}, 20k={large}, row 19000={deep} VM steps");
    assert!(
        deep * 2 <= large * 3,
        "deep text page grew {large} to {deep} steps"
    );
    q.after = None;
    q.sort.push(query::SortKey {
        key: bh_data::KeyRef::Field(path("/title")),
        desc: true,
    });
    let sorted = query::run(&c, s, &[s], &Core, &q, Budget::INTERACTIVE).unwrap();
    assert_eq!(sorted.completeness, Completeness::Complete);
    assert_eq!(
        sorted.rows.iter().map(|r| r.record).collect::<Vec<_>>(),
        (19_801..=20_000).rev().map(logical_id).collect::<Vec<_>>()
    );
    assert!(matches!(
        query::run(&c, s, &[s], &Core, &q, Budget { vm_steps: 5000 }),
        Err(QueryError::TooCostly { .. })
    ));
    // Sparse sorted matches must not walk the broad 100k-row title index.
    fill(&mut c, ids[0], &t, 20001, 100000);
    q.limit = 7;
    q.sort[0].key = bh_data::KeyRef::Changed;
    q.text.as_mut().unwrap().terms = "rareword".into();
    let mut got = Vec::new();
    loop {
        let page = query::run(&c, s, &[s], &Core, &q, Budget { vm_steps: 20_000 }).unwrap();
        assert_eq!(page.completeness, Completeness::Complete);
        got.extend(page.rows.iter().map(|r| r.record));
        if page.next.is_none() {
            break;
        }
        q.after = page.next;
    }
    // Each fill inserts in reverse ID order; the newest batch is first for
    // $changed DESC. This is deliberately not logical-ID or rowid ASC order.
    let expected: Vec<_> = (7u32..=33)
        .chain(1..=6)
        .map(|n| {
            let mut id = [0; 32];
            id[..4].copy_from_slice(&(n * 3000).to_be_bytes());
            RecordId(id)
        })
        .collect();
    assert_eq!(got, expected);
}
#[test]
fn unsorted_family_text_page_orders_by_type_then_logical_id() {
    let s = scope(2);
    let (mut c, parent, ids) = setup(&[s], false);
    let mut child = parent.clone();
    child.type_id = TypeId([5; 32]);
    child.revision = RevisionId([5; 32]);
    child.lineage = vec![
        (child.type_id, child.revision),
        (parent.type_id, parent.revision),
    ];
    let tx = c.transaction().unwrap();
    registry::store_definition(&tx, ids[0], &child, b"child", Position(2)).unwrap();
    registry::set_current(
        &tx,
        ids[0],
        child.type_id,
        child.revision,
        &[child.revision],
        Position(2),
    )
    .unwrap();
    tx.commit().unwrap();
    save(&mut c, ids[0], &child, 1, "commonword", "first");
    save(&mut c, ids[0], &parent, 2, "commonword", "second");
    let mut q = Query {
        select: TypeSelect::Family(parent.type_id),
        filter: None,
        sort: vec![],
        fields: vec![],
        follow: vec![],
        text: Some(TextMatch {
            terms: "commonword".into(),
            on: None,
            require_revision: None,
        }),
        limit: 1,
        after: None,
    };
    let first = query::run(&c, s, &[s], &Core, &q, Budget::INTERACTIVE).unwrap();
    assert_eq!(first.rows[0].record, record(2));
    q.after = first.next;
    assert_eq!(
        query::run(&c, s, &[s], &Core, &q, Budget::INTERACTIVE)
            .unwrap()
            .rows[0]
            .record,
        record(1)
    );
}
#[test]
fn text_pages_use_sort_keys_or_logical_id_not_relevance() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], false);
    save(&mut c, ids[0], &t, 2, "alpha", "violet violet violet");
    save(&mut c, ids[0], &t, 1, "zeta", "violet");
    assert_eq!(
        search(&c, s, &[s], "violet", None)
            .unwrap()
            .rows
            .iter()
            .map(|r| r.record)
            .collect::<Vec<_>>(),
        vec![record(1), record(2)]
    );
    let mut q = Query {
        select: TypeSelect::Exact(t.type_id),
        filter: None,
        sort: vec![query::SortKey {
            key: bh_data::KeyRef::Field(path("/title")),
            desc: false,
        }],
        fields: vec![],
        follow: vec![],
        text: Some(TextMatch {
            terms: "violet".into(),
            on: None,
            require_revision: None,
        }),
        limit: 1,
        after: None,
    };
    let first = query::run(&c, s, &[s], &Core, &q, Budget::INTERACTIVE).unwrap();
    assert_eq!(first.rows[0].record, record(2));
    q.after = first.next;
    assert_eq!(
        query::run(&c, s, &[s], &Core, &q, Budget::INTERACTIVE)
            .unwrap()
            .rows[0]
            .record,
        record(1)
    );
}
#[test]
fn unchanged_text_keeps_revision_and_generic_deletion_removes_match() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], false);
    let first = save(&mut c, ids[0], &t, 1, "garden", "violet");
    let second = save(&mut c, ids[0], &t, 1, "garden", "violet");
    assert_eq!(first.text_rev, second.text_rev);
    let saved_hash: Vec<u8> = c
        .query_row(
            "SELECT body FROM data_text_state WHERE rec=?1",
            [first.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(saved_hash.len(), 32);
    assert_ne!(saved_hash, b"violet".to_vec());
    let tx = c.transaction().unwrap();
    let mut r = records::get(&tx, ids[0], record(1)).unwrap().unwrap();
    r.deleted = true;
    r.accepted = None;
    records::put(&tx, &mut r).unwrap();
    text::on_record_changed(&tx, &r, &t).unwrap();
    tx.commit().unwrap();
    assert!(search(&c, s, &[s], "violet", None).unwrap().rows.is_empty());
}
#[test]
fn missing_body_does_not_block_later_jobs() {
    struct Body;
    impl text::BodyText for Body {
        fn body_text(
            &self,
            _: Scope,
            record: RecordId,
        ) -> Result<Option<String>, bh_data::DataError> {
            Ok((record != RecordId([1; 32])).then(|| "found".into()))
        }
    }
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], true);
    save(&mut c, ids[0], &t, 1, "first", "ignored");
    save(&mut c, ids[0], &t, 2, "second", "ignored");
    assert_eq!(text::extract_step(&mut c, &Body, 1).unwrap(), 0);
    assert_eq!(text::extract_step(&mut c, &Body, 1).unwrap(), 1);
    assert_eq!(text::next_jobs(&c, 10).unwrap()[0].record, record(1));
    assert_eq!(
        search(&c, s, &[s], "found", None).unwrap().rows[0].record,
        record(2)
    );
}
#[test]
fn unavailable_bodies_bound_attempts_and_do_not_starve_later_jobs() {
    use std::cell::Cell;
    struct Body(Cell<usize>);
    impl text::BodyText for Body {
        fn body_text(&self, _: Scope, id: RecordId) -> Result<Option<String>, bh_data::DataError> {
            self.0.set(self.0.get() + 1);
            Ok((id == record(12)).then(|| "available".into()))
        }
    }
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], true);
    for n in 1..=12 {
        save(&mut c, ids[0], &t, n, "title", "ignored");
    }
    let body = Body(Cell::new(0));
    let dir = tempfile::tempdir().unwrap();
    for step in 0..4 {
        let before = body.0.get();
        let done = text::extract_step_bounded(&mut c, &body, 3, u64::MAX).unwrap();
        assert!(
            body.0.get() - before <= 3,
            "attempts exceeded bound on step {step}"
        );
        assert_eq!(done, usize::from(step == 3));
        if step == 0 {
            // Continue after reopen, not just after another call on this connection.
            let file = dir.path().join("extraction.sqlite");
            c.execute("VACUUM INTO ?1", [file.to_str().unwrap()])
                .unwrap();
            c = Connection::open(file).unwrap();
        }
    }
    assert_eq!(body.0.get(), 12);
    assert_eq!(
        search(&c, s, &[s], "available", None).unwrap().rows[0].record,
        record(12)
    );
    let before = body.0.get();
    text::extract_step_bounded(&mut c, &body, 3, u64::MAX).unwrap();
    assert!(body.0.get() - before <= 3);
}
#[test]
fn extraction_work_limit_stops_between_jobs() {
    struct Body;
    impl text::BodyText for Body {
        fn body_text(&self, _: Scope, _: RecordId) -> Result<Option<String>, bh_data::DataError> {
            Ok(Some("found".into()))
        }
    }
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], true);
    save(&mut c, ids[0], &t, 1, "one", "ignored");
    save(&mut c, ids[0], &t, 2, "two", "ignored");
    assert_eq!(text::extract_step_bounded(&mut c, &Body, 10, 1).unwrap(), 1);
    assert_eq!(text::next_jobs(&c, 10).unwrap().len(), 1);
    assert_eq!(text::extract_step_bounded(&mut c, &Body, 10, 1).unwrap(), 1);
    assert!(text::next_jobs(&c, 10).unwrap().is_empty());
}
#[test]
fn body_change_without_title_queues_new_revision() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], true);
    let r = save(&mut c, ids[0], &t, 1, "title", "ignored");
    let job = text::next_jobs(&c, 1).unwrap().remove(0);
    let tx = c.transaction().unwrap();
    assert!(text::store_extracted(&tx, &job, "old").unwrap());
    tx.commit().unwrap();
    let tx = c.transaction().unwrap();
    let rev = text::body_changed(&tx, &r).unwrap();
    tx.commit().unwrap();
    assert!(rev > r.text_rev);
    assert!(text::watermark(&c, s).unwrap().complete_through < rev);
    assert!(matches!(
        search(&c, s, &[s], "old", Some(rev)),
        Err(QueryError::TextBehind { .. })
    ));
}
#[test]
fn extraction_step_reads_body_and_completes_job() {
    struct Body;
    impl text::BodyText for Body {
        fn body_text(&self, _: Scope, _: RecordId) -> Result<Option<String>, bh_data::DataError> {
            Ok(Some("extractedbody".into()))
        }
    }
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], true);
    let r = save(&mut c, ids[0], &t, 1, "garden", "ignored");
    assert_eq!(text::extract_step(&mut c, &Body, 10).unwrap(), 1);
    assert_eq!(text::watermark(&c, s).unwrap().complete_through, r.text_rev);
    assert_eq!(
        search(&c, s, &[s], "extractedbody", Some(r.text_rev))
            .unwrap()
            .rows
            .len(),
        1
    );
}
#[test]
fn text_on_reference_reads_targets_first_and_requires_readable_target() {
    let a = scope(2);
    let b = scope(3);
    let mut t = ct(false);
    t.fields.push(FieldSpec {
        path: path("/link"),
        kind: FieldKind::Reference(bh_data::RefSpec {
            targets: vec![t.type_id],
            family: false,
        }),
        write: WritePolicy::Direct,
        required: false,
        nullable: false,
        declared_by: t.type_id,
        meaning: "link".into(),
        unit: None,
        absent: None,
    });
    let (mut c, _, ids) = setup_with(&[a, b], t.clone());
    save(&mut c, ids[0], &t, 3, "unrelated", "body");
    let target = save(&mut c, ids[1], &t, 2, "targetword", "body");
    let tx = c.transaction().unwrap();
    let mut r = RecordRow {
        id: 0,
        scope: ids[0],
        record: record(1),
        type_id: t.type_id,
        revision: t.revision,
        accepted: Some(
            json!({"title":"source","link":bh_data::RecordRef {record:record(2),audience:Some(b.audience)}}),
        ),
        doc: None,
        deleted: false,
        pending: false,
        changed_at: None,
        changed: 0,
        text_rev: 0,
    };
    records::put(&tx, &mut r).unwrap();
    bh_data::index::on_record_changed(&tx, &r, &t).unwrap();
    tx.commit().unwrap();
    let query = Query {
        select: TypeSelect::Exact(t.type_id),
        filter: None,
        sort: vec![],
        fields: vec![],
        follow: vec![],
        text: Some(TextMatch {
            terms: "targetword".into(),
            on: Some(path("/link")),
            require_revision: None,
        }),
        limit: 50,
        after: None,
    };
    assert_eq!(
        query::run(&c, a, &[a, b], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .rows[0]
            .record,
        record(1)
    );
    let mut query = query;
    query.text.as_mut().unwrap().require_revision = Some(target.text_rev);
    assert_eq!(
        query::run(&c, a, &[a, b], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .rows[0]
            .record,
        record(1)
    );
    assert!(
        query::run(&c, a, &[a], &Core, &query, Budget::INTERACTIVE)
            .unwrap()
            .rows
            .is_empty()
    );
}

fn decoded(jobs: Vec<text::TextJob>, body: Option<&str>) -> Vec<text::DecodedJob> {
    jobs.into_iter()
        .map(|job| text::DecodedJob {
            job,
            body: body.map(str::to_owned),
        })
        .collect()
}

#[test]
fn batch_selection_follows_and_wraps_the_extraction_cursor() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], true);
    for n in 1..=12 {
        save(&mut c, ids[0], &t, n, "title", "ignored");
    }
    let order = |jobs: &[text::TextJob]| jobs.iter().map(|job| job.rec).collect::<Vec<_>>();
    for expected in [[1, 2, 3], [4, 5, 6], [7, 8, 9], [10, 11, 12], [1, 2, 3]] {
        let jobs = text::next_batch(&c, 3).unwrap();
        assert_eq!(order(&jobs), expected);
        let tx = c.transaction().unwrap();
        let outcome = text::store_batch_bounded(&tx, &decoded(jobs, None), u64::MAX).unwrap();
        tx.commit().unwrap();
        assert_eq!(outcome.attempted, 3);
        assert_eq!(outcome.extracted, 0, "unavailable bodies stay queued");
    }
    assert_eq!(text::next_jobs(&c, 20).unwrap().len(), 12);
}

#[test]
fn batch_store_never_saves_text_for_a_moved_revision() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], true);
    save(&mut c, ids[0], &t, 1, "title", "ignored");
    let jobs = text::next_batch(&c, 1).unwrap();
    save(&mut c, ids[0], &t, 1, "title two", "ignored");
    let tx = c.transaction().unwrap();
    let outcome = text::store_batch_bounded(&tx, &decoded(jobs, Some("old")), u64::MAX).unwrap();
    tx.commit().unwrap();
    assert_eq!(outcome.attempted, 1);
    assert_eq!(outcome.extracted, 0, "the old revision is not current");
    assert_eq!(text::next_jobs(&c, 10).unwrap().len(), 1);
    let jobs = text::next_batch(&c, 1).unwrap();
    let tx = c.transaction().unwrap();
    let outcome = text::store_batch_bounded(&tx, &decoded(jobs, Some("new")), u64::MAX).unwrap();
    tx.commit().unwrap();
    assert_eq!(outcome.extracted, 1);
    assert!(text::next_jobs(&c, 10).unwrap().is_empty());
    let found = search(&c, s, &[s], "new", None).unwrap();
    assert_eq!(found.rows[0].record, record(1));
    assert!(search(&c, s, &[s], "old", None).unwrap().rows.is_empty());
}

#[test]
fn batch_store_stops_at_the_work_limit() {
    let s = scope(2);
    let (mut c, t, ids) = setup(&[s], true);
    for n in 1..=3 {
        save(&mut c, ids[0], &t, n, "title", "ignored");
    }
    let jobs = text::next_batch(&c, 3).unwrap();
    let tx = c.transaction().unwrap();
    let outcome = text::store_batch_bounded(&tx, &decoded(jobs, Some("body")), 1).unwrap();
    tx.commit().unwrap();
    assert_eq!(outcome.attempted, 1);
    assert_eq!(outcome.extracted, 1);
    assert_eq!(text::next_jobs(&c, 10).unwrap().len(), 2);
    assert_eq!(text::next_batch(&c, 1).unwrap()[0].rec, 2);
}
