//! Readable in-process acceptance evidence, not the real account/sync path.
use bh_data::{
    AppId, RejectCode, RevisionId, Scope, TypeId,
    catalogue::Shipped,
    evolve,
    mutation::{apply::Outcome, ops::Operation},
    query::{Completeness, Page, QueryError, TextMatch, TypeSelect},
    session::{DataSession, SessionError, TypeRef},
    testkit::{Delivery, OrderedLog, Replica},
};
use bh_data_consumers::{
    Harness, SHARED, all, article, authority, journal, path, recipe, reference, rid, selection,
    session, set,
};
use bh_data_fixtures::{job, member};
use rusqlite::trace::{TraceEvent, TraceEventCodes};
use serde_json::{Value, json};
use std::cell::RefCell;
use std::fmt::Write;

const FROM: i64 = 1_699_000_000_000;
const UNTIL: i64 = 1_701_000_000_000;
const PUBLISHED: i64 = 1_700_000_000_000;

// Per-thread capture, installed only around this test's query connection.
thread_local! { static SQL: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) }; }
fn trace(event: TraceEvent<'_>) {
    if let TraceEvent::Stmt(stmt, _) = event {
        SQL.with_borrow_mut(|sql| sql.push(stmt.expanded_sql().unwrap()));
    }
}
fn selected(h: &Harness) -> Page {
    selection::for_context(
        &h.session(h.replicas.len() - 1),
        SHARED,
        reference(rid(20)),
        FROM,
        UNTIL,
    )
    .unwrap()
}
fn table(out: &mut String, page: &Page) {
    out.push_str("\n| Article | Reason | Linked Note |\n|---|---|---|\n");
    for row in &page.rows {
        writeln!(
            out,
            "| {} | {} | {} |",
            row.follows["/article"].as_ref().unwrap().values["/title"]
                .as_str()
                .unwrap(),
            row.values["/reason"].as_str().unwrap(),
            row.follows["/note"].as_ref().unwrap().values["/title"]
                .as_str()
                .unwrap()
        )
        .unwrap();
    }
}
fn doc(h: &Harness, id: u8) -> Value {
    h.session(h.replicas.len() - 1)
        .get(SHARED, rid(id))
        .unwrap()
        .unwrap()
        .accepted
        .unwrap()
}
fn refused(result: Result<bh_data::mutation::pending::LocalSaved, SessionError>, code: RejectCode) {
    assert!(
        matches!(result, Err(SessionError::Rejected(ref r)) if r.code == code),
        "{result:?}"
    );
}
fn converge(h: &mut Harness) -> Vec<Outcome> {
    // Synthetic transport receives newest-first, with retries. The host must
    // buffer by the server-assigned position: apply itself takes ordered input.
    let mut arrivals: Vec<_> = h.log.entries().iter().rev().flat_map(|e| [e, e]).collect();
    assert!(
        arrivals
            .windows(2)
            .any(|pair| pair[0].position > pair[1].position)
    );
    arrivals.sort_by_key(|entry| entry.position);
    arrivals.dedup_by_key(|entry| entry.position);
    let mut buffered = OrderedLog::new();
    for entry in arrivals {
        assert_eq!(
            buffered.append(entry.scope, &entry.actor, entry.payload.clone()),
            entry.position
        );
    }
    let mut results = Vec::new();
    for (i, r) in h.replicas.iter_mut().enumerate() {
        let log = if i == 0 { &h.log } else { &buffered };
        results.extend(
            r.sync_from(log, Delivery::Duplicated)
                .unwrap()
                .into_iter()
                .map(|(_, o)| o),
        );
    }
    assert_eq!(
        h.replicas[0].state_digest(SHARED).unwrap(),
        h.replicas[1].state_digest(SHARED).unwrap()
    );
    assert_eq!(
        h.session(0).history(SHARED, rid(1), None, 200).unwrap(),
        h.session(1).history(SHARED, rid(1), None, 200).unwrap()
    );
    results
}

#[test]
fn worked_case() {
    let dir = tempfile::tempdir().unwrap();
    let installation = dir.path().join("article.sqlite");
    let other_installation = dir.path().join("selection.sqlite");
    let mut h = Harness::new();
    h.replicas[0] = Replica::new_file(&installation).unwrap();
    h.replicas[1] = Replica::new_file(&other_installation).unwrap();
    h.install();
    let mut transcript = String::from(
        "# Shared typed records: a worked case\n\nAcceptance layer: **in-process ordered-log harness; the real account/sync path comes later**.\n\nAll names and content are synthetic. A and B are separate consumer modules; only the harness supplies sessions and transports opaque payloads. Note bodies use the host projection/body-extraction seam, not the real editor or account transport.\n",
    );

    h.project_note(rid(10), "Solar notebook", "solar cells collect light");
    h.project_note(
        rid(11),
        "Kitchen instructions",
        "knead, proof, then bake in sunshine",
    );
    let saved = article::save(
        &h.session(0),
        rid(1),
        "Solar on rooftops",
        "https://example.test/solar",
        PUBLISHED,
        reference(rid(10)),
    )
    .unwrap();
    h.accept(0, saved);
    // Nonmatching controls make text, range and context conditions independently observable.
    for (id, title, date) in [
        (2, "Wind turbines", PUBLISHED),
        (3, "Solar history", FROM - 1),
    ] {
        let saved = article::save(
            &h.session(0),
            rid(id),
            title,
            &format!("https://example.test/{id}"),
            date,
            reference(rid(10)),
        )
        .unwrap();
        h.accept(0, saved);
    }
    let description = h
        .session(1)
        .describe(SHARED, TypeRef::Current(article::type_id()))
        .unwrap();
    assert!(
        description
            .compiled
            .field(&path("/published"))
            .unwrap()
            .meaning
            .contains("not save time")
    );
    assert!(description.operations.contains(&"action:archive".into()));
    assert_eq!(
        article::recent(&h.session(0), SHARED).unwrap().rows.len(),
        3
    );
    transcript.push_str("\n## 1. A publishes Articles\nActor: member Ada, using consumer A. Action: define a documented Article contract and save three Articles with unique URLs, source publication time, read-state and a canonical content Note reference. Outcome: B can discover the same contract without importing A.\n\n| Article | Publication range | Search term |\n|---|---|---|\n| Solar on rooftops | inside | solar |\n| Wind turbines | inside | no solar |\n| Solar history | outside | solar |\n");

    h.context(rid(20), "Clean energy");
    h.context(rid(21), "Other research");
    for (id, article_id, context_id) in [(30, 1, 20), (31, 2, 20), (32, 3, 20), (33, 1, 21)] {
        let saved = selection::select(
            &h.session(1),
            rid(id),
            reference(rid(article_id)),
            reference(rid(context_id)),
            "Evidence for roof panels",
            reference(rid(10)),
        )
        .unwrap();
        h.accept(1, saved);
    }
    transcript.push_str("\n## 2. B selects evidence for a context\nActor: member Ben, using consumer B. Action: define SourceSelection in B's own app, linking Article, a Project fixture owned by the separate Workspace context app, a reason and an existing Note. Outcome: the context is a filter, not an access boundary; no Note body is copied.\n");
    table(&mut transcript, &selected(&h));

    article::prepare_view(&h.session(0), SHARED).unwrap();
    selection::prepare_view(&h.session(1), SHARED).unwrap();
    // A's sorted view must use its own typed publication index. The equal-date
    // articles have no specified tie order; the older one must follow both.
    let a_conn = h.replicas[0].conn();
    SQL.with_borrow_mut(Vec::clear);
    a_conn.trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(trace));
    let recent = article::recent(&h.session(0), SHARED).unwrap();
    a_conn.trace_v2(TraceEventCodes::empty(), None);
    assert_eq!(recent.completeness, Completeness::Complete);
    assert_eq!(recent.rows.len(), 3);
    assert!(recent.rows[..2].iter().all(|row| row.record != rid(3)));
    assert_eq!(recent.rows[2].record, rid(3));
    let a_statements = SQL.with_borrow_mut(std::mem::take);
    let mut a_plans = Vec::new();
    for sql in a_statements
        .iter()
        .filter(|s| s.contains("data_index_entry"))
    {
        let mut stmt = a_conn
            .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
            .unwrap();
        a_plans.extend(
            stmt.query_map([], |r| r.get::<_, String>(3))
                .unwrap()
                .map(Result::unwrap),
        );
    }
    assert!(
        a_plans.iter().any(|s| s.contains("data_index_entry_key")),
        "{a_plans:?}"
    );
    let conn = h.replicas[1].conn();
    SQL.with_borrow_mut(Vec::clear);
    conn.trace_v2(TraceEventCodes::SQLITE_TRACE_STMT, Some(trace));
    let page = selected(&h);
    conn.trace_v2(TraceEventCodes::empty(), None);
    assert_eq!(page.completeness, Completeness::Complete);
    assert_eq!(page.rows.len(), 1);
    assert_eq!(page.rows[0].record, rid(30));
    assert_eq!(page.rows[0].values["/reason"], "Evidence for roof panels");
    assert_eq!(
        page.rows[0].follows["/article"].as_ref().unwrap().values["/title"],
        "Solar on rooftops"
    );
    assert_eq!(
        page.rows[0].follows["/note"].as_ref().unwrap().values["/title"],
        "Solar notebook"
    );
    let statements = SQL.with_borrow_mut(std::mem::take);
    let mut plans = Vec::new();
    for sql in statements
        .iter()
        .filter(|s| s.contains("data_fts") && s.contains("data_ref"))
    {
        let mut stmt = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
        plans.extend(
            stmt.query_map([], |r| r.get::<_, String>(3))
                .unwrap()
                .map(Result::unwrap),
        );
    }
    assert!(
        plans.iter().any(|s| s.contains("data_ref_dst")),
        "{plans:?}"
    );
    assert!(
        plans.iter().any(|s| s.contains("data_ref_src")),
        "{plans:?}"
    );
    assert!(
        plans
            .iter()
            .any(|s| (s.contains("sqlite_autoindex_data_record_1")
                && s.contains("scope=? AND record=?"))
                || (s.contains("data_record_logical")
                    && s.contains("scope=? AND type=? AND record=?"))),
        "{plans:?}"
    );
    assert!(
        !plans.iter().any(|s| s.contains("SCAN data_record")
            || s.contains("SCAN r ")
            || s.contains("SCAN t ")),
        "unexpected full data_record scan: {plans:?}"
    );
    assert!(
        plans.iter().any(|s| s.contains("VIRTUAL TABLE INDEX")),
        "{plans:?}"
    );
    // The local index claim is absent from the other replica; nothing was published.
    let local = |r: &Replica| {
        r.conn()
            .query_row(
                "SELECT count(*) FROM data_index WHERE local_claim=1",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
    };
    assert_eq!(local(&h.replicas[0]), 1);
    assert_eq!(local(&h.replicas[1]), 1);
    let a_keys: String = h.replicas[0]
        .conn()
        .query_row("SELECT keys FROM data_index WHERE local_claim=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    let b_keys: String = conn
        .query_row("SELECT keys FROM data_index WHERE local_claim=1", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_ne!(a_keys, b_keys);
    transcript.push_str("\n## 3. Different views, shared records\nActor: Ben/B. Action: filter one context, follow Article publication time in the half-open range, AND search `solar` on Article; project headline, reason and Note title. Outcome: exactly one row; wrong text, date and context controls are excluded. A's publication-sorted query uses its local typed publication index; B requests a separate replica-local reason index, while this context-driven query uses the reverse-reference index, the source-reference index, a scoped target-record lookup and FTS.\n");
    table(&mut transcript, &page);
    transcript.push_str(
        "\nObserved SQLite plan (A's actual publication-sorted session query):\n```text\n",
    );
    for plan in &a_plans {
        writeln!(transcript, "{plan}").unwrap();
    }
    transcript
        .push_str("```\n\nObserved SQLite plan (B's actual combined session query):\n```text\n");
    for plan in &plans {
        writeln!(transcript, "{plan}").unwrap();
    }
    transcript.push_str("```\n");

    let v1 = RevisionId::of(article::DEFINITION);
    let a = article::edit(
        &h.session(0),
        rid(1),
        v1,
        vec![set("/title", json!("Solar roofs revised"))],
    )
    .unwrap();
    let b = article::edit(
        &h.session(1),
        rid(1),
        v1,
        vec![set("/state", json!("saved"))],
    )
    .unwrap();
    // Submitted A then B; ordered B then A. Both fields must survive.
    let withheld = h.log.append(SHARED, &member(2), b.payload);
    h.log.append(SHARED, &member(1), a.payload);
    let before = h.replicas[0].received();
    h.replicas[0]
        .sync_from(&h.log, Delivery::Delayed(vec![withheld.0 as usize]))
        .unwrap();
    assert_eq!(h.replicas[0].received(), before);
    converge(&mut h);
    assert_eq!(doc(&h, 1)["title"], "Solar roofs revised");
    assert_eq!(doc(&h, 1)["state"], "saved");
    let a = article::edit(
        &h.session(0),
        rid(1),
        v1,
        vec![set("/title", json!("Solar Ada wins by position"))],
    )
    .unwrap();
    let b = article::edit(
        &h.session(1),
        rid(1),
        v1,
        vec![set("/title", json!("Solar Ben submitted later"))],
    )
    .unwrap();
    h.log.append(SHARED, &member(2), b.payload);
    let winner = h.log.append(SHARED, &member(1), a.payload);
    converge(&mut h);
    assert_eq!(doc(&h, 1)["title"], "Solar Ada wins by position");
    let history = h.session(1).history(SHARED, rid(1), None, 200).unwrap();
    assert_eq!(history[0].position, winner);
    assert_eq!(history[0].actor, member(1));

    let first = article::save(
        &h.session(0),
        rid(4),
        "Duplicate source A",
        "https://example.test/race",
        PUBLISHED,
        reference(rid(10)),
    )
    .unwrap();
    let loser = article::save(
        &h.session(1),
        rid(5),
        "Duplicate source B",
        "https://example.test/race",
        PUBLISHED,
        reference(rid(10)),
    )
    .unwrap();
    let losing_id = loser.mutation;
    h.log.append(SHARED, &member(1), first.payload);
    h.log.append(SHARED, &member(2), loser.payload);
    let outcomes = converge(&mut h);
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o,Outcome::Rejected(r) if r.code==RejectCode::Unique))
    );
    let rejected = h.session(1).rejected_work(SHARED).unwrap();
    assert_eq!(rejected.len(), 1);
    assert_eq!(rejected[0].mutation, losing_id);
    assert_eq!(rejected[0].rejection.code, RejectCode::Unique);
    assert!(
        rejected[0]
            .attempted
            .contains(&set("/title", json!("Duplicate source B")))
    );
    assert!(
        rejected[0]
            .attempted
            .contains(&set("/url", json!("https://example.test/race")))
    );
    assert!(h.session(1).get(SHARED, rid(5)).unwrap().is_none());
    let recovered = article::save(
        &h.session(1),
        rid(6),
        "Duplicate source B",
        "https://example.test/recovered",
        PUBLISHED,
        reference(rid(10)),
    )
    .unwrap();
    h.accept(1, recovered);

    let edited = article::edit(
        &h.session(0),
        rid(1),
        v1,
        vec![
            set("/title", json!("Solar draft")),
            set("/state", json!("new")),
        ],
    )
    .unwrap();
    let target = edited.mutation;
    h.accept(0, edited);
    let intervened = article::edit(
        &h.session(1),
        rid(1),
        v1,
        vec![set("/title", json!("Solar final headline"))],
    )
    .unwrap();
    h.accept(1, intervened);
    let undo = h.session(0).undo(target).unwrap();
    h.log.append(SHARED, &member(1), undo.payload);
    let outcomes = converge(&mut h);
    assert!(
        outcomes
            .iter()
            .any(|o| matches!(o,Outcome::Accepted{skipped,..} if skipped==&vec![path("/title")]))
    );
    assert_eq!(doc(&h, 1)["title"], "Solar final headline");
    assert_eq!(doc(&h, 1)["state"], "saved");

    let mut v2: Value = serde_json::from_slice(article::DEFINITION).unwrap();
    v2["evolution"]["previous"] = json!(v1);
    v2["schema"]["properties"]["tag"] = json!({"type":"string","maxLength":80});
    v2["fields"]["/tag"] =
        json!({"kind":"string","meaning":"Optional grouping label","write":"direct"});
    let bytes = serde_json::to_vec(&v2).unwrap();
    let proposal = h.session(0).prepare_change(&bytes).unwrap();
    assert_eq!(proposal.affected_records, 5);
    let approval = h.session(0).approve(proposal).unwrap();
    h.accept(0, approval);
    let saved = article::edit(
        &h.session(1),
        rid(1),
        RevisionId::of(&bytes),
        vec![set("/tag", json!("renewables"))],
    )
    .unwrap();
    h.accept(1, saved);
    let old = article::edit(&h.session(0), rid(1), v1, vec![set("/state", json!("new"))]).unwrap();
    h.accept(0, old);
    assert_eq!(doc(&h, 1)["tag"], "renewables");
    h.project_note(
        rid(10),
        "Solar notebook — updated",
        "solar cells collect light; efficiency improved",
    );
    for i in 0..2 {
        let a = article::recent(&h.session(i), SHARED).unwrap();
        assert!(
            a.rows
                .iter()
                .all(|r| r.follows["/content"].as_ref().unwrap().values["/title"]
                    == "Solar notebook — updated")
        );
        let b =
            selection::for_context(&h.session(i), SHARED, reference(rid(20)), FROM, UNTIL).unwrap();
        assert_eq!(
            b.rows[0].follows["/note"].as_ref().unwrap().values["/title"],
            "Solar notebook — updated"
        );
    }
    transcript.push_str("\n## 4. Offline conflict, recovery and Undo\nActors: Ada/A and Ben/B. Action: edit offline; reverse submission order at ordering; delay and duplicate delivery. A test transport also receives entries newest-first with retries, then buffers by their server-assigned position before ordered application. Outcome: different fields combine; later ordered same-field edit wins (not later submission). Both replicas have identical state digests and attributed history. The losing URL creation retains its attempted title and URL and is resaved with a new URL. Undo restores read-state but reports/skips an intervening title edit. A v1 writer preserves v2's `tag = renewables`. Updating the Note projection refreshes both consumers without a body copy.\n");
    table(&mut transcript, &selected(&h));

    let saved = journal::bind(&h.session(0), rid(10), PUBLISHED, "hopeful").unwrap();
    h.accept(0, saved);
    let saved = recipe::save(&h.session(1), rid(40), reference(rid(11))).unwrap();
    h.accept(1, saved);
    let mut notes = all(TypeId::core("note"));
    notes.select = TypeSelect::Family(TypeId::core("note"));
    notes.fields = vec![path("/title")];
    let family = h.session(1).query(SHARED, &notes).unwrap();
    assert_eq!(family.rows.len(), 2);
    assert!(
        family
            .rows
            .iter()
            .any(|r| r.record == rid(10) && r.type_id == journal::type_id())
    );
    assert!(
        family
            .rows
            .iter()
            .any(|r| r.record == rid(11) && r.type_id == TypeId::core("note"))
    );
    let recipes = recipe::view(&h.session(1), SHARED).unwrap();
    assert_eq!(
        recipes.rows[0].values["/location"],
        json!({"city":"Example City","street":"12 Garden Lane"})
    );
    assert_eq!(
        recipes.rows[0].follows["/instructions"]
            .as_ref()
            .unwrap()
            .record,
        rid(11)
    );
    // A Recipe is composition, NOT a Note subtype: its instructions appear in the Note family.
    assert!(!family.rows.iter().any(|r| r.record == rid(40)));
    notes.text = Some(TextMatch {
        terms: "knead".into(),
        on: None,
        require_revision: None,
    });
    assert_eq!(
        h.session(1).query(SHARED, &notes).unwrap().rows[0].record,
        rid(11)
    );
    assert_eq!(
        doc(&h, 10),
        json!({"title":"Solar notebook — updated","date":PUBLISHED,"mood":"hopeful"})
    );
    assert_eq!(doc(&h, 11), json!({"title":"Kitchen instructions"}));
    assert_eq!(doc(&h, 40).as_object().unwrap().len(), 3);
    transcript.push_str("\n### Reuse without copying bodies\nActor: Ada binds her existing Note as JournalEntry; Ben saves a Recipe. Outcome: the Note-family query includes JournalEntry and Recipe's instructions Note, not Recipe itself. Body search `knead` finds the instructions through BodyText extraction.\n\n| Record | Shape | Body owner |\n|---|---|---|\n| Solar notebook — updated | JournalEntry: Note + date/mood | Note source |\n| Kitchen instructions | Ordinary Note, referenced by Recipe | Note source |\n| Solar oven bread | Recipe + inline Address + Note reference | No body in record |\n");

    // Explicit breaking transition and resumable one-record migration batches.
    let mut v3 = v2;
    v3["evolution"]["previous"] = json!(RevisionId::of(&bytes));
    v3["schema"]["required"] = json!(["title", "url", "tag"]);
    v3["evolution"]["migration_ops"] =
        json!([{"op":"set_constant","path":"/tag","value":"reviewed"}]);
    v3["evolution"]["examples"]["valid"] = json!([]);
    let bytes3 = serde_json::to_vec(&v3).unwrap();
    let rev3 = RevisionId::of(&bytes3);
    let saved = h.replicas[0]
        .submit(
            SHARED,
            &h.actors[0],
            Operation::DefineType { bytes: bytes3 },
        )
        .unwrap();
    h.accept(0, saved);
    let saved = h.replicas[0]
        .submit(
            SHARED,
            &h.actors[0],
            Operation::Transition {
                type_id: article::type_id(),
                to: rev3,
            },
        )
        .unwrap();
    h.accept(0, saved);
    refused(
        article::edit(
            &h.session(0),
            rid(1),
            v1,
            vec![set("/state", json!("saved"))],
        ),
        RejectCode::RevisionNotPermitted,
    );
    let mut migrated = 0;
    loop {
        let plan = evolve::plan(
            h.replicas[1].conn(),
            SHARED,
            &Shipped,
            article::type_id(),
            rev3,
            1,
        )
        .unwrap();
        assert!(plan.needs_manual.is_empty());
        if plan.ops.is_empty() {
            break;
        }
        assert_eq!(plan.ops.len(), 1);
        h.apply(1, plan.ops[0].clone());
        migrated += 1;
        if migrated == 1 {
            // Restart the migration host, then ask for a fresh plan; no in-memory cursor survives.
            drop(std::mem::replace(
                &mut h.replicas[1],
                Replica::new_in_memory().unwrap(),
            ));
            h.replicas[1] = Replica::new_file(&other_installation).unwrap();
            h.replicas[1]
                .sync_from(&h.log, Delivery::Duplicated)
                .unwrap();
        }
    }
    assert_eq!(migrated, 5);
    assert_eq!(doc(&h, 1)["tag"], "reviewed");
    converge(&mut h);
    transcript.push_str("\n### Explicit schema lifecycle\nActor: Ada approves a revision; Ben resumes authorised content migration. Outcome: optional v2 addition first; then explicit v3 transition makes tag required, old writers are refused, and five Articles migrate in one-record batches with a host restart after the first. No implicit rewrite occurs.\n\n| Check | Outcome |\n|---|---|\n| Old writer after compatible addition | Preserves new field |\n| Old writer after breaking transition | RevisionNotPermitted |\n| Resumed migration | 5/5 Articles, no manual repairs |\n");

    drop(h.replicas.remove(0));
    h.actors.remove(0);
    std::fs::remove_file(&installation).unwrap();
    assert!(!installation.exists());
    assert_eq!(selected(&h).rows.len(), 1);
    let saved = h.replicas[0]
        .submit(
            SHARED,
            &h.actors[0],
            Operation::SetAppState {
                app: article::APP,
                active: false,
            },
        )
        .unwrap();
    h.accept(0, saved);
    assert_eq!(selected(&h).rows.len(), 1);
    let saved = article::edit(
        &h.session(0),
        rid(1),
        rev3,
        vec![set("/state", json!("saved"))],
    )
    .unwrap();
    h.accept(0, saved);
    let action = Operation::Action {
        record: rid(1),
        app: article::APP,
        action: "archive".into(),
        changes: vec![set("/archived", json!(true))],
    };
    refused(
        session(&h.replicas[0], SHARED, job(2, Some("archive"))).submit(action.clone()),
        RejectCode::AppInactive,
    );
    refused(
        article::edit(
            &h.session(0),
            rid(1),
            rev3,
            vec![set("/archived", json!(true))],
        ),
        RejectCode::ActionOnly,
    );
    let saved = h.replicas[0]
        .submit(
            SHARED,
            &h.actors[0],
            Operation::SetAppState {
                app: article::APP,
                active: true,
            },
        )
        .unwrap();
    h.accept(0, saved);
    let archived = session(&h.replicas[0], SHARED, job(2, Some("archive")))
        .submit(action)
        .unwrap();
    h.log
        .append(SHARED, &job(2, Some("archive")), archived.payload);
    assert!(
        h.replicas[0]
            .sync_from(&h.log, Delivery::InOrder)
            .unwrap()
            .iter()
            .all(|(_, o)| matches!(o, Outcome::Accepted { .. }))
    );
    assert_eq!(doc(&h, 1)["archived"], true);
    assert_eq!(
        h.session(0)
            .history(SHARED, rid(1), None, 200)
            .unwrap()
            .iter()
            .find(|entry| entry.path == Some(path("/state")))
            .unwrap()
            .actor,
        member(2)
    );
    assert_eq!(
        h.session(0).get(SHARED, rid(1)).unwrap().unwrap().type_id,
        article::type_id()
    );

    let private = Scope {
        audience: [8; 32],
        ..SHARED
    };
    for op in [
        Operation::DefineApp {
            app: AppId([2; 32]),
            name: "Private reader".into(),
        },
        Operation::DefineType {
            bytes: article::DEFINITION.to_vec(),
        },
    ] {
        let saved = session(&h.replicas[0], private, member(1))
            .submit(op)
            .unwrap();
        h.log.append(private, &member(1), saved.payload);
        h.replicas[0].sync_from(&h.log, Delivery::InOrder).unwrap();
    }
    let saved = article::save(
        &session(&h.replicas[0], private, member(1)),
        rid(90),
        "Solar private source",
        "https://example.test/private",
        PUBLISHED,
        reference(rid(10)),
    )
    .unwrap();
    h.log.append(private, &member(1), saved.payload);
    h.replicas[0].sync_from(&h.log, Delivery::InOrder).unwrap();
    assert!(
        session(&h.replicas[0], private, member(1))
            .get(private, rid(90))
            .unwrap()
            .is_some()
    );
    let b = DataSession::new(&h.replicas[0], authority(member(2), vec![SHARED], None));
    assert_eq!(
        b.query(private, &all(article::type_id())),
        Err(QueryError::Unauthorized)
    );
    assert!(b.get(SHARED, rid(90)).unwrap().is_none());
    assert!(
        !article::recent(&b, SHARED)
            .unwrap()
            .rows
            .iter()
            .any(|r| r.record == rid(90))
    );
    transcript.push_str("\n## 5. Installation, app and audience are separate\nActor: Ben/B. Action: delete A's replica/file, then deactivate A's app through the ordered log. Outcome: B still reads the same Articles and changes Direct read-state. The archive job is AppInactive and a generic protected-field edit is ActionOnly. Reactivation permits archive on the same record/type IDs. B's shared-only session cannot query A's populated private audience or see its Article in the shared view.\n");
    table(&mut transcript, &selected(&h));
    let output =
        std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("worked-case/worked-case.md");
    std::fs::create_dir_all(output.parent().unwrap()).unwrap();
    std::fs::write(&output, transcript).unwrap();
    println!("Worked case transcript: {}", output.display());
}

#[test]
fn consumer_modules_are_isolated() {
    let modules = [
        ("article", include_str!("../src/article.rs")),
        ("selection", include_str!("../src/selection.rs")),
        ("journal", include_str!("../src/journal.rs")),
        ("recipe", include_str!("../src/recipe.rs")),
    ];
    for (name, source) in modules {
        for forbidden in [
            "rusqlite",
            "bh_data::store",
            "bh_data::index",
            "store::",
            "records::",
            "Connection",
        ] {
            assert!(
                !source.contains(forbidden),
                "{name} bypasses session with {forbidden}"
            );
        }
        for other in ["article", "selection", "journal", "recipe"]
            .into_iter()
            .filter(|n| *n != name)
        {
            for prefix in ["crate::", "super::", "bh_data_consumers::"] {
                assert!(
                    !source.contains(&format!("{prefix}{other}")),
                    "{name} imports {other}"
                );
            }
        }
    }
}
