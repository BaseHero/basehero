//! Real personal-account path (local stack, synthetic attestation): QR-paired
//! device processes call the same native records API as a future approval UI.
#![cfg(feature = "synthetic-attestation")]
mod support;

use bh_data::{AppId, RecordId, RevisionId, Scope, TypeId};
use serde_json::{Value, json};
use support::{Device, Pair, log, pair, reopen};

const ARTICLE: &[u8] = include_bytes!("../../data-consumers/types/Article.json");
const JOURNAL: &[u8] = include_bytes!("../../data-consumers/types/JournalEntry.json");
const SELECTION: &[u8] = include_bytes!("../../data-consumers/types/SourceSelection.json");
const APP: AppId = AppId([2; 32]);
const ACCEPTED_OUTCOME: i64 = 2;

fn operation(device: &mut Device, op: Value) -> String {
    device.call(json!({"op":"records-submit", "operation":op}))["mutation"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn approval(device: &mut Device, op: Value) -> String {
    device.call(json!({"op":"records-approve", "operation":op}))["mutation"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn accepted(device: &mut Device, mutation: &str) -> i64 {
    device.wait(180, "typed package accepted", |d| {
        d.db().typed(mutation).is_some_and(|package| {
            package.position.is_some()
                && package.outcome == Some(ACCEPTED_OUTCOME)
                && !package.pending
        })
    });
    device.db().typed(mutation).unwrap().position.unwrap()
}
fn caught_up(device: &mut Device, base: &str, at: i64) {
    let base = base.to_owned();
    device.wait(180, "verified ordered typed position", |d| {
        d.wake();
        d.db().progress(&base).0 >= at
    });
}
fn query(device: &mut Device, select: Value, fields: &[&str], follow: Value) -> Value {
    device.call(json!({"op":"records-query", "query": {
        "select": select, "fields": fields, "follow":follow
    }}))
}
fn get(device: &mut Device, record: RecordId) -> Value {
    device.call(json!({"op":"records-get", "record": record}))
}
fn assert_converged(pair: &Pair) {
    let base: [u8; 32] =
        std::array::from_fn(|i| u8::from_str_radix(&pair.base[2 * i..2 * i + 2], 16).unwrap());
    let scope = Scope {
        base,
        audience: [0; 32],
    };
    assert_eq!(
        pair.mac.db().state_digest(scope),
        pair.fold.db().state_digest(scope)
    );
}
fn check_package_once(device: &mut Device, mutation: &str) {
    let package = device.db().typed(mutation).unwrap();
    assert!(
        package.position.is_some() && package.outcome == Some(ACCEPTED_OUTCOME) && !package.pending
    );
}

#[test]
#[ignore = "needs tests/local-sync/run.sh"]
fn real_personal_account_path_local_stack_synthetic_attestation() {
    let mut p = pair("typed_acceptance");
    let article = TypeId::for_app(APP, [1; 16]);
    let journal = TypeId::for_app(APP, [8; 16]);
    let selection = TypeId::for_app(APP, [7; 16]);
    // Definition bytes are the signed contract; selection's reference target
    // points at Article, and both belong to the same app in this fixture.
    let mut selection_doc: Value = serde_json::from_slice(SELECTION).unwrap();
    selection_doc["app"] = json!(APP);
    selection_doc["fields"]["/article"]["ref"]["targets"] = json!([article]);
    let selection_bytes = serde_json::to_vec(&selection_doc).unwrap();
    let mut owned = Vec::new();
    let app = operation(
        &mut p.mac,
        json!({"kind":"define_app","app":APP,"name":"Reading"}),
    );
    let at = accepted(&mut p.mac, &app);
    owned.push(app);
    caught_up(&mut p.fold, &p.base, at);
    for bytes in [ARTICLE, &selection_bytes, JOURNAL] {
        let mutation = operation(&mut p.mac, json!({"kind":"define_type","bytes":bytes}));
        let at = accepted(&mut p.mac, &mutation);
        owned.push(mutation);
        caught_up(&mut p.fold, &p.base, at);
    }
    // Existing-rule revisions require device confirmation. Both revisions
    // are signed with Mac's real native ordinary key before use.
    let mut article_doc: Value = serde_json::from_slice(ARTICLE).unwrap();
    article_doc["evolution"]["previous"] = json!(RevisionId::of(ARTICLE));
    article_doc["schema"]["properties"]["state"]["enum"] = json!(["new", "saved", "read"]);
    let article_bytes = serde_json::to_vec(&article_doc).unwrap();
    selection_doc["evolution"]["previous"] = json!(RevisionId::of(&selection_bytes));
    selection_doc["schema"]["properties"]["reason"]["maxLength"] = json!(499);
    let selection_revision_bytes = serde_json::to_vec(&selection_doc).unwrap();
    for bytes in [&article_bytes, &selection_revision_bytes] {
        let mutation = approval(&mut p.mac, json!({"kind":"define_type","bytes":bytes}));
        let at = accepted(&mut p.mac, &mutation);
        owned.push(mutation);
        caught_up(&mut p.fold, &p.base, at);
    }
    let article_revision = RevisionId::of(&article_bytes);
    let selection_revision = RevisionId::of(&selection_revision_bytes);
    for (type_id, to) in [(article, article_revision), (selection, selection_revision)] {
        let mutation = approval(
            &mut p.mac,
            json!({"kind":"transition", "type_id":type_id,"to":to}),
        );
        let at = accepted(&mut p.mac, &mutation);
        owned.push(mutation);
        caught_up(&mut p.fold, &p.base, at);
    }
    let note: RecordId = serde_json::from_value(json!(p.note)).unwrap();
    p.mac
        .call(json!({"op":"type","window":"main","note":p.note,"text":" - edited on Mac"}));
    p.mac
        .published(180, &p.note, "from the mac - edited on Mac");
    let bind = operation(
        &mut p.mac,
        json!({"kind":"bind_note", "note":note,
        "type_id":journal,"revision":RevisionId::of(JOURNAL),
        "doc":{"date":1700000000000_i64,"mood":"curious"}}),
    );
    let at = accepted(&mut p.mac, &bind);
    owned.push(bind);
    caught_up(&mut p.fold, &p.base, at);
    let record = RecordId::random();
    let created = operation(
        &mut p.mac,
        json!({"kind":"create", "record":record,
        "type_id":article,"revision":article_revision,
        "doc":{"title":"First article","url":"https://example.test/first",
            "state":"new", "content":{"record": note}}}),
    );
    let at = accepted(&mut p.mac, &created);
    owned.push(created);
    caught_up(&mut p.fold, &p.base, at);
    let selection_record = RecordId::random();
    let linked = operation(
        &mut p.mac,
        json!({"kind":"create", "record":selection_record,
        "type_id":selection,"revision":selection_revision,
        "doc":{"article":{"record":record},"note":{"record":note},"reason":"Reading"}}),
    );
    let at = accepted(&mut p.mac, &linked);
    owned.push(linked);
    caught_up(&mut p.fold, &p.base, at);
    let article_page = query(
        &mut p.fold,
        json!({"Exact":article}),
        &["/title", "/state"],
        json!([]),
    );
    assert_eq!(article_page["rows"][0]["record"], json!(record));
    assert_eq!(article_page["rows"][0]["values"]["/title"], "First article");
    let linked_page = query(
        &mut p.fold,
        json!({"Exact":selection}),
        &["/reason"],
        json!([{"path":"/article","fields":["/title"]}]),
    );
    assert_eq!(linked_page["rows"][0]["record"], json!(selection_record));
    assert_eq!(
        linked_page["rows"][0]["follows"]["/article"]["values"]["/title"],
        "First article"
    );
    let notes = query(
        &mut p.fold,
        json!({"Family":TypeId::core("note")}),
        &["/title"],
        json!([]),
    );
    assert!(
        notes["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["record"] == json!(note)
                && row["type_id"] == json!(journal)
                && row["values"]["/title"] == "from the mac - edited on Mac")
    );
    assert!(
        p.fold
            .note("main", &p.note)
            .paragraphs
            .contains(&"from the mac - edited on Mac".to_owned())
    );
    let mac_notes = query(
        &mut p.mac,
        json!({"Family":TypeId::core("note")}),
        &["/title"],
        json!([]),
    );
    assert!(
        mac_notes["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["record"] == json!(note)
                && row["values"]["/title"] == "from the mac - edited on Mac")
    );
    // Invalid resulting state never enters the outbox or the log.
    let before = p.fold.db().typed_count();
    let bad = p.fold.try_call(json!({"op":"records-submit", "operation":{
        "kind":"edit","record":record,"revision":article_revision,
        "changes":[{"path":"/state","value":"invalid-state"}]}}));
    assert!(
        bad.is_err_and(|error| error.contains("Schema")),
        "invalid write did not fail schema validation"
    );
    assert_eq!(p.fold.db().typed_count(), before);

    // Both edit /state while disconnected. The Mac also changes /title;
    // the Fold's later accepted log position takes /state, not wall time.
    p.mac.faults(json!({"offline":true}));
    p.fold.faults(json!({"offline":true}));
    let mac_edit = operation(
        &mut p.mac,
        json!({"kind":"edit", "record":record,
        "revision":article_revision, "changes":[
            {"path":"/state","value":"saved"}, {"path":"/title","value":"Mac draft"}]}),
    );
    owned.push(mac_edit.clone());
    let fold_edit = operation(
        &mut p.fold,
        json!({"kind":"edit", "record":record,
        "revision":article_revision, "changes":[{"path":"/state","value":"read"}]}),
    );
    p.mac.faults(json!({"offline":false}));
    let first = accepted(&mut p.mac, &mac_edit);
    p.fold.faults(json!({"offline":false}));
    caught_up(&mut p.fold, &p.base, first);
    let second = accepted(&mut p.fold, &fold_edit);
    assert!(second > first);
    caught_up(&mut p.mac, &p.base, second);
    for device in [&mut p.mac, &mut p.fold] {
        let article = get(device, record);
        assert_eq!(article["accepted"]["title"], "Mac draft");
        assert_eq!(article["accepted"]["state"], "read");
    }
    assert_converged(&p);
    let mac_history = p.mac.call(json!({"op":"records-history","record":record}));
    assert!(
        mac_history["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["mutation"] == mac_edit && e["path"] == "/title")
    );
    // Undo restores only Mac's still-attributed title. The overwritten state
    // is reported as intervening if the same edit is undone again.
    let undo = p.mac.call(json!({"op":"records-undo","mutation":mac_edit}));
    assert_eq!(undo["skipped"], json!(["/state"]));
    let undo_mutation = undo["mutation"].as_str().unwrap().to_owned();
    let at = accepted(&mut p.mac, &undo_mutation);
    owned.push(undo_mutation);
    caught_up(&mut p.fold, &p.base, at);
    for device in [&mut p.mac, &mut p.fold] {
        let article = get(device, record);
        assert_eq!(article["accepted"]["title"], "First article");
        assert_eq!(article["accepted"]["state"], "read");
    }
    assert_converged(&p);
    let intervening = p
        .mac
        .try_call(json!({"op":"records-undo","mutation":mac_edit}));
    assert!(intervening.is_err_and(
        |error| error.contains("changed since by later edits") && error.contains("/state")
    ));

    // Interrupt a typed package after ordering, before its Ack/echo. A new
    // Fold process reopens its own durable package and finishes the exchange.
    p.fold.faults(json!({"hold_acks":true}));
    let interrupted = operation(
        &mut p.fold,
        json!({"kind":"create",
        "record":RecordId::random(), "type_id":selection,
        "revision":selection_revision,
        "doc":{"article":{"record":record},"reason":"Restarted Fold"}}),
    );
    p.fold.wait_event("ack-held", 120);
    let stopped = p.fold.kill();
    let interrupted_package = stopped.db().typed(&interrupted).unwrap();
    assert!(interrupted_package.position.is_none() || interrupted_package.outcome.is_none());
    p.fold = reopen(stopped);
    let at = accepted(&mut p.fold, &interrupted);
    caught_up(&mut p.mac, &p.base, at);
    assert_eq!(
        query(
            &mut p.mac,
            json!({"Exact":selection}),
            &["/reason"],
            json!([])
        )["rows"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // Device approval uses the ordinary native signer, not a test authority.
    let inactive = approval(
        &mut p.mac,
        json!({"kind":"set_app_state","app":APP,"active":false}),
    );
    let at = accepted(&mut p.mac, &inactive);
    owned.push(inactive);
    caught_up(&mut p.fold, &p.base, at);
    let before = p.fold.db().typed_count();
    let refused = p.fold.try_call(json!({"op":"records-submit", "operation":{
        "kind":"create","record":RecordId::random(),"type_id":article,
        "revision":article_revision,"doc":{"title":"After deactivation",
          "url":"https://example.test/inactive"}}}));
    assert!(
        refused.is_err_and(|error| error.contains("AppInactive")),
        "inactive app did not refuse creation"
    );
    assert_eq!(p.fold.db().typed_count(), before);
    let permitted = operation(
        &mut p.fold,
        json!({
            "kind":"edit", "record":record, "revision":article_revision,
            "changes":[{"path":"/title", "value":"Edited while inactive"}]
        }),
    );
    let at = accepted(&mut p.fold, &permitted);
    caught_up(&mut p.mac, &p.base, at);
    assert_eq!(
        get(&mut p.mac, record)["accepted"]["title"],
        "Edited while inactive"
    );
    assert_converged(&p);

    let note_edit = p.fold.save("fold-main", &p.note, "Fold after deactivation");
    let note_text = "Fold after deactivation";
    p.mac.wait(180, "mac received restarted fold note", |d| {
        d.note("main", &p.note)
            .accepted
            .iter()
            .any(|s| s == note_text)
    });
    p.fold.published(180, &p.note, note_text);
    p.mac.wait_state(180, "synced");
    p.fold.wait_state(180, "synced");
    assert_eq!(p.mac.note("main", &p.note), p.fold.note("main", &p.note));
    assert_converged(&p);
    for mutation in &owned {
        check_package_once(&mut p.mac, mutation);
    }
    for mutation in [&fold_edit, &interrupted, &permitted] {
        check_package_once(&mut p.fold, mutation);
    }
    assert_eq!(
        p.fold.db().typed(&interrupted).unwrap().outcome,
        Some(ACCEPTED_OUTCOME)
    );
    p.stack.stop_part("edge");
    let stored = p.stack.storage("inspect", &p.base_log(), json!([]));
    p.stack.start_part("edge");
    let mac_packages = p.mac.db().packages();
    let fold_packages = p.fold.db().packages();
    assert_eq!(fold_packages.len(), 1);
    for package in mac_packages.iter().chain(&fold_packages) {
        assert!(
            package.acked.is_some()
                && package.outcome == Some(ACCEPTED_OUTCOME)
                && !package.pending
        );
    }
    let events = owned
        .iter()
        .map(|mutation| p.mac.db().typed(mutation).unwrap().event.unwrap())
        .chain(
            [fold_edit.as_str(), interrupted.as_str(), permitted.as_str()]
                .into_iter()
                .map(|mutation| p.fold.db().typed(mutation).unwrap().event.unwrap()),
        )
        .chain(
            mac_packages
                .iter()
                .chain(&fold_packages)
                .map(|package| package.event_id.clone()),
        );
    for event in events {
        assert_eq!(
            stored["events"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|row| row["event_id"] == event)
                .count(),
            1,
            "one accepted event per local package: {event}"
        );
    }
    assert!(note_edit["request"].is_string());
    log(
        &p.stack.dir,
        "real personal-account path (local stack, synthetic attestation): passed",
    );
}
