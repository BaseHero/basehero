//! Two devices of one account through a private real local stack each: the
//! Worker with its log objects, R2 bodies and pairing relay in local
//! workerd, and the authorization service with labelled synthetic
//! attestation. Each device is its own process over the production host
//! APIs with its own software test keys and container; the second joins
//! only through the first's QR code. Faults are made outside the
//! production code: in a device's own connector, by killing a process, by
//! restarting a stack part, or in a stopped Worker's storage.
//!
//! Needs the built stack and device process, so ignored by default:
//! `tests/local-sync/run.sh` builds them and runs these concurrently.
#![cfg(feature = "synthetic-attestation")]

mod support;

use serde_json::{Value, json};
use support::{converged, count, entries, log, pair, reopen, sha};

#[test]
#[ignore = "needs tests/local-sync/run.sh"]
fn pair_and_bootstrap() {
    let mut p = pair("pair_and_bootstrap");
    let note = p.note.clone();
    // The joined device has the account's note from verified history: its
    // accepted state, and its progress, equal the first device's.
    let mac = p.mac.note("main", &note);
    let fold = p.fold.note("main", &note);
    assert_eq!(mac.paragraphs, ["from the mac"]);
    assert_eq!(fold.paragraphs, mac.paragraphs);
    assert_eq!(fold.accepted, mac.accepted);
    assert_eq!(fold.digest, mac.digest);
    assert_eq!(fold.accepted_digest, mac.accepted_digest);
    let base = p.base.clone();
    let (mac_at, mac_hash, mac_stop, _) = p.mac.db().progress(&base);
    let (fold_at, fold_hash, fold_stop, fold_receipt) = p.fold.db().progress(&base);
    assert_eq!((fold_at, &fold_hash), (mac_at, &mac_hash));
    assert!(mac_stop.is_none() && fold_stop.is_none());
    assert!(
        fold_receipt.is_some(),
        "progress carries its hosting receipt"
    );

    // The joined device writes; the first device's open window is woken
    // and its next read has the change. This shows delivery and the read
    // after a wake; that a wake follows its commit is the host's own
    // ordering contract, tested there, not here.
    let wakes = p.mac.status()["wakes"].as_array().unwrap().len();
    p.fold.save("fold-main", &note, "from the fold");
    p.fold.wait_state(180, "synced");
    p.mac.wait(180, "mac woken", |d| {
        d.status()["wakes"].as_array().unwrap().len() > wakes
    });
    let woken = p.mac.note("main", &note);
    assert_eq!(woken.accepted, ["from the mac", "from the fold"]);
    assert_eq!(woken.paragraphs, woken.accepted);
    p.mac.wait_state(180, "synced");
    let fold = p.fold.note("main", &note);
    assert_eq!(fold.digest, woken.digest);
    assert_eq!(fold.accepted_digest, woken.accepted_digest);
    // Exactly the fold's one package, acknowledged and accepted.
    let packages = p.fold.db().packages();
    assert_eq!(packages.len(), 1);
    assert!(packages[0].acked.is_some() && !packages[0].pending);
    assert_eq!(p.fold.db().pending(), 0);
    log(&p.stack.dir, "pair_and_bootstrap: passed");
}

#[test]
#[ignore = "needs tests/local-sync/run.sh"]
fn typed_offline_sentence_is_at_most_two_packages() {
    let mut p = pair("typed_offline_sentence_is_at_most_two_packages");
    let note = p.note.clone();
    p.mac.faults(json!({"offline": true}));
    let before = p.mac.db().packages().len();
    let sentence = "Hi, this is a test";
    for c in sentence.chars() {
        let receipt = p
            .mac
            .call(json!({"op": "type", "window": "main", "note": note, "text": c.to_string()}));
        assert_eq!(receipt["replayed"], false);
    }
    assert_eq!(p.mac.db().pending(), sentence.chars().count() as i64);
    p.mac.faults(json!({"offline": false}));
    let both = converged(&mut p, 240);
    assert_eq!(both.paragraphs, [format!("from the mac{sentence}")]);
    assert_eq!(p.mac.db().pending(), 0);
    // A running offline client can already have sealed the first key
    // before its socket fails; the remaining keys form one accumulating run.
    let packages = p.mac.db().packages().len() - before;
    assert!(
        (1..=2).contains(&packages),
        "{packages} packages for 18 saves"
    );
    log(
        &p.stack.dir,
        &format!("typed sentence: 18 local saves, {packages} packages"),
    );
}

#[test]
#[ignore = "needs tests/local-sync/run.sh"]
fn live_edits_converge() {
    let mut p = pair("live_edits_converge");
    let note = p.note.clone();
    // Both directions, one at a time, then both at once.
    p.mac.save("main", &note, "mac one");
    p.fold.save("fold-main", &note, "fold one");
    for round in 0..3 {
        p.mac.save("main", &note, &format!("mac round {round}"));
        p.fold
            .save("fold-main", &note, &format!("fold round {round}"));
    }
    let both = converged(&mut p, 240);
    let expected = [
        "from the mac",
        "mac one",
        "fold one",
        "mac round 0",
        "fold round 0",
        "mac round 1",
        "fold round 1",
        "mac round 2",
        "fold round 2",
    ];
    for text in expected {
        assert_eq!(count(&both.paragraphs, text), 1, "{text} once: {both:?}");
    }
    assert_eq!(both.paragraphs.len(), expected.len());
    // Each device's account and container reopen through the production
    // startup in a new process, with the same note.
    let mac = reopen(p.mac.quit());
    let fold = reopen(p.fold.quit());
    p.mac = mac;
    p.fold = fold;
    for device in [&mut p.mac, &mut p.fold] {
        let reopened = device.note("main", &note);
        assert_eq!(reopened.digest, both.digest, "{}", device.name);
        assert_eq!(reopened.paragraphs, both.paragraphs);
        assert_eq!(reopened.accepted_digest, both.accepted_digest);
    }
    let again = converged(&mut p, 120);
    assert_eq!(again, both, "nothing more to exchange");
    log(&p.stack.dir, "live_edits_converge: passed");
}

#[test]
#[ignore = "needs tests/local-sync/run.sh"]
fn offline_then_reconnect() {
    let mut p = pair("offline_then_reconnect");
    let note = p.note.clone();
    p.mac.faults(json!({"offline": true}));
    p.fold.faults(json!({"offline": true}));
    // Each device's local commit acknowledges the edit; nothing reaches the
    // network.
    let mut receipts = Vec::new();
    for text in ["mac offline 1", "mac offline 2"] {
        receipts.push(p.mac.save("main", &note, text));
    }
    receipts.push(p.fold.save("fold-main", &note, "fold offline 1"));
    assert!(receipts.iter().all(|r| r["replayed"] == false));
    p.mac.wait_state(60, "waiting-network");
    p.fold.wait_state(60, "waiting-network");
    assert_eq!(p.mac.db().pending(), 2);
    assert_eq!(p.fold.db().pending(), 1);
    let mac = p.mac.note("main", &note);
    assert_eq!(
        mac.paragraphs,
        ["from the mac", "mac offline 1", "mac offline 2"]
    );
    assert_eq!(
        mac.accepted,
        ["from the mac"],
        "local work is not accepted yet"
    );
    assert_eq!(
        p.fold.note("main", &note).paragraphs,
        ["from the mac", "fold offline 1"]
    );
    // Neither device sent anything while offline.
    let sent = |frames: Vec<Value>| {
        frames
            .iter()
            .filter(|f| f["out"] == "append" && f["content"] == true)
            .count()
    };
    let (mac_sent, fold_sent) = (sent(p.mac.frames()), sent(p.fold.frames()));
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert_eq!(sent(p.mac.frames()), mac_sent);
    assert_eq!(sent(p.fold.frames()), fold_sent);
    p.mac.faults(json!({"offline": false}));
    p.fold.faults(json!({"offline": false}));
    let both = converged(&mut p, 240);
    for text in [
        "from the mac",
        "mac offline 1",
        "mac offline 2",
        "fold offline 1",
    ] {
        assert_eq!(count(&both.paragraphs, text), 1, "{text} once: {both:?}");
    }
    assert_eq!(both.paragraphs.len(), 4);
    assert_eq!(p.mac.db().pending(), 0);
    assert_eq!(p.fold.db().pending(), 0);
    log(&p.stack.dir, "offline_then_reconnect: passed");
}

/// The package journal entries of `event` this device sent.
fn appends_of<'a>(frames: &'a [Value], event: &str) -> Vec<&'a Value> {
    frames
        .iter()
        .filter(|f| f["out"] == "append" && f["event_id"] == event)
        .collect()
}

#[test]
#[ignore = "needs tests/local-sync/run.sh"]
fn lost_ack_exact_retry() {
    let mut p = pair("lost_ack_exact_retry");
    let note = p.note.clone();
    for (round, resend) in [(1, true), (2, false)] {
        // The edge orders the event; its Ack never reaches the device and
        // the connection drops. With `resend`, base reads fail until the
        // device sends again, so the outbox resends before its echo can
        // settle it.
        p.mac
            .faults(json!({"drop_next_ack": true, "refuse_read_after_drop": resend}));
        let text = format!("lost ack {round}");
        p.mac.save("main", &note, &text);
        let dropped = p.mac.wait_event("ack-dropped", 120)["detail"].clone();
        let event = dropped["event_id"].as_str().unwrap().to_owned();
        let position = dropped["position"].as_i64().unwrap();
        p.mac.faults(json!({"refuse_read_after_drop": false}));
        let both = converged(&mut p, 240);
        assert_eq!(count(&both.paragraphs, &text), 1, "no duplicate text");
        let frames = p.mac.frames();
        let sends = appends_of(&frames, &event);
        if resend {
            assert!(sends.len() >= 2, "resent after the lost Ack: {sends:?}");
            // The echo was kept away, and only until the resend.
            let refused = entries(&frames, "fault", "read-refused");
            assert!(!refused.is_empty());
            assert!(
                refused
                    .iter()
                    .all(|r| r["ms"].as_u64() <= sends[1]["ms"].as_u64())
            );
        }
        // Every send is the exact signed event, under the one id.
        assert!(sends.iter().all(|s| s["bytes"] == sends[0]["bytes"]));
        assert!(sends.iter().all(|s| s["digest"] == sends[0]["digest"]));
        let acks: Vec<_> = frames
            .iter()
            .filter(|f| f["in"] == "acked" && f["event_id"] == event.as_str())
            .collect();
        assert!(acks.iter().all(|a| a["position"] == position), "{acks:?}");
        // One package, Acked at the original position, accepted once.
        let packages = p.mac.db().packages();
        let kept: Vec<_> = packages.iter().filter(|k| k.event_id == event).collect();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].acked, Some(position));
        assert!(!kept[0].pending);
        assert_eq!(
            sha(&kept[0].descriptor),
            sends[0]["bytes"].as_str().unwrap()
        );
        log(
            &p.stack.dir,
            &format!(
                "lost ack {round}: event {event} at {position}, {} sends, resend {resend}",
                sends.len()
            ),
        );
        // Drop the barrier so the next round waits for its own.
        p.mac.forget_events();
    }
    // The log holds each event exactly once.
    p.stack.stop_part("edge");
    let stored = p.stack.storage("inspect", &p.base_log(), json!([]));
    p.stack.start_part("edge");
    let events = stored["events"].as_array().unwrap();
    let mut ids: Vec<_> = events
        .iter()
        .map(|e| e["event_id"].as_str().unwrap())
        .collect();
    let total = ids.len();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), total, "no event id twice");
    log(&p.stack.dir, "lost_ack_exact_retry: passed");
}

#[test]
#[ignore = "needs tests/local-sync/run.sh"]
fn crash_restage() {
    let mut p = pair("crash_restage");
    let note = p.note.clone();
    let base = p.base_log();
    // The body is staged; the order is held back; the process is killed.
    p.mac.faults(json!({"hold_appends": true}));
    p.mac.save("main", &note, "crash restage");
    let held = p.mac.wait_event("append-held", 120)["detail"].clone();
    let event = held["event_id"].as_str().unwrap().to_owned();
    let stopped = p.mac.kill();
    let frames = stopped.frames();
    let staged: Vec<_> = frames
        .iter()
        .filter(|f| f["out"] == "stage" && f["log"] == base.as_str())
        .collect();
    let body = staged.last().unwrap()["body"].as_str().unwrap().to_owned();
    assert!(
        frames.iter().any(|f| f["in"] == "staged"),
        "staging answered"
    );
    let before = stopped.db().packages();
    let kept = before.iter().find(|k| k.event_id == event).unwrap().clone();
    assert!(kept.acked.is_none() && kept.pending);

    // With the Worker stopped, its own reclaim runs under a clock two days
    // later: the staging row is marked, the object deleted, the row dropped.
    p.stack.stop_part("edge");
    let inspect = p.stack.storage("inspect", &base, json!([]));
    let staging: Vec<_> = inspect["bodies"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|b| b["state"] == "staging")
        .cloned()
        .collect();
    assert_eq!(staging.len(), 1, "{inspect}");
    let commitment = staging[0]["commitment"].as_str().unwrap().to_owned();
    let object = p.stack.storage("r2-get", &base, json!([commitment]));
    let bytes = unhex(object["bytes"].as_str().unwrap());
    assert_eq!(sha(&bytes), body, "the staged object is the device's body");
    assert!(
        inspect["events"]
            .as_array()
            .unwrap()
            .iter()
            .all(|e| e["event_id"] != event.as_str()),
        "not ordered"
    );
    let swept = p
        .stack
        .storage("sweepAfter", &base, json!([2 * 86_400_000u64]));
    assert!(
        swept["bodies"]
            .as_array()
            .unwrap()
            .iter()
            .all(|b| b["commitment"] != commitment.as_str()),
        "reclaimed: {swept}"
    );
    assert!(p.stack.storage("r2-get", &base, json!([commitment]))["bytes"].is_null());
    p.stack.start_part("edge");

    // The next process sends the kept bytes, learns the body is gone,
    // stages the same bytes again and the event is ordered once.
    p.mac = reopen(stopped);
    let both = converged(&mut p, 240);
    assert_eq!(count(&both.paragraphs, "crash restage"), 1);
    let frames = p.mac.frames();
    let restarted: Vec<_> = frames
        .iter()
        .skip_while(|f| f["process"] != p.mac.pid)
        .collect();
    let restaged: Vec<_> = restarted
        .iter()
        .filter(|f| f["out"] == "stage" && f["log"] == base.as_str())
        .collect();
    assert!(
        restaged.iter().any(|f| f["body"] == body.as_str()),
        "same body restaged"
    );
    // Its round stages the kept body again before it appends: the
    // reclaimed object is put back from the device's exact bytes.
    let first_stage = restarted
        .iter()
        .position(|f| f["out"] == "stage" && f["body"] == body.as_str())
        .expect("restaged");
    let first_append = restarted
        .iter()
        .position(|f| f["out"] == "append" && f["event_id"] == event.as_str())
        .expect("appended again");
    assert!(first_stage < first_append);
    assert_eq!(restarted[first_stage]["commitment"], commitment.as_str());
    let sends = appends_of(&frames, &event);
    assert!(sends.iter().all(|s| s["bytes"] == held["bytes"]));
    let after = p.mac.db().packages();
    let kept = after.iter().find(|k| k.event_id == event).unwrap();
    assert_eq!(
        kept.descriptor,
        before
            .iter()
            .find(|k| k.event_id == event)
            .unwrap()
            .descriptor
    );
    assert!(kept.acked.is_some() && !kept.pending);
    p.stack.stop_part("edge");
    let stored = p.stack.storage("inspect", &base, json!([]));
    p.stack.start_part("edge");
    let ordered: Vec<_> = stored["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["event_id"] == event.as_str())
        .collect();
    assert_eq!(ordered.len(), 1);
    assert!(
        stored["bodies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["commitment"] == commitment.as_str() && b["state"] == "ordered")
    );
    log(
        &p.stack.dir,
        &format!("crash_restage: passed; event {event} reclaimed body {commitment} restaged"),
    );
}

#[test]
#[ignore = "needs tests/local-sync/run.sh"]
fn crash_after_append_before_ack_persist() {
    let mut p = pair("crash_after_append_before_ack_persist");
    let note = p.note.clone();
    // The order commits at the edge; neither its Ack nor its echo reaches
    // the device, and a later edit waits behind it (one package per note in
    // flight).
    p.mac.faults(json!({"hold_acks": true}));
    p.mac.save("main", &note, "ordered before the crash");
    let held = p.mac.wait_event("ack-held", 120)["detail"].clone();
    let event = held["event_id"].as_str().unwrap().to_owned();
    let position = held["position"].as_i64().unwrap();
    p.mac.save("main", &note, "local after the order");
    let stopped = p.mac.kill();
    let packages = stopped.db().packages();
    let kept = packages
        .iter()
        .find(|k| k.event_id == event)
        .unwrap()
        .clone();
    assert!(kept.acked.is_none() && kept.pending, "no Ack persisted");
    assert_eq!(stopped.db().pending(), 2);
    // The other device sees it ordered meanwhile.
    p.fold.wait(180, "fold has the ordered edit", |d| {
        d.wake();
        count(&d.note("main", &note).accepted, "ordered before the crash") == 1
    });
    p.mac = reopen(stopped);
    let reopened = p.mac.note("main", &note);
    assert_eq!(count(&reopened.paragraphs, "ordered before the crash"), 1);
    assert_eq!(count(&reopened.paragraphs, "local after the order"), 1);
    let both = converged(&mut p, 240);
    assert_eq!(count(&both.paragraphs, "ordered before the crash"), 1);
    assert_eq!(count(&both.paragraphs, "local after the order"), 1);
    let packages = p.mac.db().packages();
    let kept = packages.iter().find(|k| k.event_id == event).unwrap();
    assert_eq!(
        kept.acked,
        Some(position),
        "the outcome at its original position"
    );
    assert!(!kept.pending);
    assert_eq!(p.mac.db().pending(), 0);
    let frames = p.mac.frames();
    let sends = appends_of(&frames, &event);
    assert!(
        sends
            .iter()
            .all(|s| s["bytes"] == held_bytes(&frames, &event))
    );
    log(
        &p.stack.dir,
        &format!(
            "crash_after_append_before_ack_persist: passed; {} sends of {event}",
            sends.len()
        ),
    );
}

fn held_bytes(frames: &[Value], event: &str) -> Value {
    appends_of(frames, event)[0]["bytes"].clone()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[cfg(unix)]
fn inode(path: &std::path::Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).unwrap().ino()
}

#[test]
#[ignore = "needs tests/local-sync/run.sh"]
fn authz_restart() {
    let mut p = pair("authz_restart");
    let note = p.note.clone();
    let db = p.stack.stack_dir().join("authz.db");
    let (file, address) = (
        inode(&db),
        std::fs::read_to_string(p.stack.stack_dir().join("authz-address")).unwrap(),
    );
    // The service is killed on its current protected disk; devices keep
    // editing; queued work waits.
    p.stack.stop_part("authz");
    let down_ms = now_ms();
    p.mac.save("main", &note, "mac while authz is down");
    p.fold.save("fold-main", &note, "fold while authz is down");
    std::thread::sleep(std::time::Duration::from_secs(5));
    assert!(p.mac.db().pending() >= 1 && p.fold.db().pending() >= 1);
    for device in [&mut p.mac, &mut p.fold] {
        assert_ne!(device.state(), "synced", "{}: work waits", device.name);
    }
    let up_ms = now_ms();
    p.stack.start_part("authz");
    assert_eq!(inode(&db), file, "the same service database");
    assert_eq!(
        std::fs::read_to_string(p.stack.stack_dir().join("authz-address")).unwrap(),
        address
    );
    let both = converged(&mut p, 300);
    assert_eq!(count(&both.paragraphs, "mac while authz is down"), 1);
    assert_eq!(count(&both.paragraphs, "fold while authz is down"), 1);
    // Context, not a regression check (it cannot fail while the service is
    // dead): no permit was issued during the outage. The restart evidence is
    // the same database and address, and convergence.
    for device in [&p.mac, &p.fold] {
        let during: Vec<_> = device
            .frames()
            .into_iter()
            .filter(|f| f["out"] == "stage" || f["out"] == "append")
            .filter(|f| {
                f["issued_ms"]
                    .as_u64()
                    .is_some_and(|at| at > down_ms && at < up_ms)
            })
            .collect();
        assert!(during.is_empty(), "{}: {during:?}", device.name);
    }
    // And it goes on working after the restart.
    p.fold.save("fold-main", &note, "after the restart");
    let both = converged(&mut p, 240);
    assert_eq!(count(&both.paragraphs, "after the restart"), 1);
    log(&p.stack.dir, "authz_restart: passed");
}

#[test]
#[ignore = "needs tests/local-sync/run.sh"]
fn workerd_restart() {
    let mut p = pair("workerd_restart");
    let note = p.note.clone();
    let base = p.base.clone();
    let (before, _, _, _) = p.mac.db().progress(&base);
    // The Worker stops and starts again on its persisted log and body
    // storage, the same keys and the same endpoint.
    p.stack.stop_part("edge");
    p.mac.save("main", &note, "mac while the edge is down");
    p.fold
        .save("fold-main", &note, "fold while the edge is down");
    p.mac.wait_state(120, "waiting-network");
    p.stack.start_part("edge");
    let both = converged(&mut p, 300);
    assert_eq!(count(&both.paragraphs, "mac while the edge is down"), 1);
    assert_eq!(count(&both.paragraphs, "fold while the edge is down"), 1);
    let (after, _, stopped, _) = p.mac.db().progress(&base);
    assert!(
        after >= before + 2 && stopped.is_none(),
        "history continued: {before} -> {after}"
    );
    let (fold_at, _, fold_stopped, _) = p.fold.db().progress(&base);
    assert_eq!(fold_at, after);
    assert!(fold_stopped.is_none());
    log(&p.stack.dir, "workerd_restart: passed");
}

#[test]
#[ignore = "needs tests/local-sync/run.sh"]
fn current_authority_refusal() {
    let mut p = pair("current_authority_refusal");
    let note = p.note.clone();
    // A second note, so each order has its own package in flight.
    let other = p.fold.call(json!({"op": "create-note"}))["note"]
        .as_str()
        .unwrap()
        .to_owned();
    p.fold.save("other", &other, "the fold's other note");
    p.fold.wait(180, "other note published", |d| {
        d.db().pending() == 0 && d.state() == "synced"
    });
    // Two packages staged and permitted while the Fold is still a member,
    // their appends held back. Both are saved offline, so one round sends
    // them together (a round waits for every answer it asked for).
    p.fold.faults(json!({"offline": true}));
    p.fold
        .save("fold-main", &note, "content before the closure");
    p.fold.save("other", &other, "content after the closure");
    p.fold
        .faults(json!({"hold_appends": true, "offline": false}));
    let mut held: Vec<Value> = Vec::new();
    p.fold.wait(120, "both appends held", |d| {
        held.clear();
        for f in d.frames() {
            if f["barrier"] == "append-held"
                && !held
                    .iter()
                    .any(|h| h["event_id"] == f["detail"]["event_id"])
            {
                held.push(f["detail"].clone());
            }
        }
        held.len() >= 2
    });
    // The two kept packages, in local commit order.
    let pending: Vec<_> = p
        .fold
        .db()
        .packages()
        .into_iter()
        .filter(|k| k.pending)
        .collect();
    assert_eq!(pending.len(), 2);
    let held_as = |k: &support::Package| {
        held.iter()
            .find(|h| h["event_id"] == k.event_id.as_str())
            .cloned()
            .expect("its append is held")
    };
    let (before, after) = (held_as(&pending[0]), held_as(&pending[1]));
    // The Fold removes itself: signed natively, verified and ordered by the
    // service and the account log.
    let removal = p.fold.call(json!({"op": "remove-self"}));
    let removed_ms = now_ms();
    log(&p.stack.dir, &format!("removal ordered: {removal}"));
    // Its own authenticated session asks for the same ordinary base read
    // before the removal and after the removal's Ack: permitted, then
    // refused because the device is no longer active.
    let probe = &removal["probe"];
    assert_eq!(probe["before"], "permitted", "a valid read: {removal}");
    assert_eq!(
        probe["after"], "refused: NotActive",
        "no new permit for a removed device: {removal}"
    );
    // Order 1: the first append reaches the base while its copy of the
    // removal still waits for the Mac's confirmation: ordered and accepted.
    p.fold.faults(json!({"release": before["event_id"]}));
    p.mac.wait(180, "copy waits for confirmation", |d| {
        d.status()["view"]["confirm"] == true
    });
    let first_text = |d: &mut support::Device| {
        let main = d.note("main", &note);
        let side = d.note("other", &other);
        (main.accepted, side.accepted)
    };
    p.mac.wait(180, "mac accepted the earlier content", |d| {
        d.wake();
        count(&first_text(d).0, "content before the closure") == 1
    });
    // The Mac confirms the removal; its copy is ordered as a base control.
    // Wait for that copy's own Ack: the confirmation flag clears before it
    // is ordered.
    let before_at = p
        .fold
        .frames()
        .iter()
        .find(|f| f["in"] == "acked" && f["event_id"] == before["event_id"])
        .and_then(|f| f["position"].as_i64())
        .expect("the first append acknowledged");
    p.mac.call(json!({"op": "reconfirm"}));
    let base = p.base_log();
    p.mac.wait(180, "closure copy ordered", |d| {
        d.frames().iter().any(|f| {
            f["in"] == "acked"
                && f["log"] == base.as_str()
                && f["content"] == false
                && f["position"].as_i64().is_some_and(|at| at > before_at)
        })
    });
    log(
        &p.stack.dir,
        &format!("closure ordered after position {before_at}"),
    );
    // Order 2: the second append, permitted before the removal, never leaves
    // the device: it verified its own removal, so it publishes nothing.
    // Past every permit the Fold held, it still has published nothing.
    std::thread::sleep(std::time::Duration::from_secs(35));
    p.fold.wait(180, "fold verified its removal", |d| {
        d.wake();
        let view = d.status();
        view["view"]["account"] == "removed" && view["running"] == false
    });
    // The Mac's own later work goes under the new key, after the closure, with
    // no prompt; reading its echo means it has read past the closure.
    p.mac.save("main", &note, "mac after the closure");
    p.mac.published(180, &note, "mac after the closure");
    let (main, side) = first_text(&mut p.mac);
    assert_eq!(count(&main, "content before the closure"), 1);
    assert_eq!(
        count(&side, "content after the closure"),
        0,
        "the removed device's late work never reached the Mac"
    );
    let frames = p.fold.frames();
    let late = after["event_id"].as_str().unwrap();
    let kept = packages_of(&p.fold, late);
    assert!(kept.pending && kept.acked.is_none(), "kept, never ordered");
    assert!(
        appends_of(&frames, late)
            .iter()
            .all(|s| s["bytes"] == after["bytes"])
    );
    assert_eq!(
        sha(&kept.descriptor),
        after["bytes"].as_str().unwrap(),
        "the same signed bytes"
    );
    // Its local work stays in its container: read from the file, as this
    // device's own authority may have ended.
    let kept_work = p.fold.db().pending();
    assert!(kept_work >= 1, "the late update still pending");
    // It verified its removal: sync stopped, the account says removed, its
    // windows' routes ended, and its unsent work is still there.
    let removed = p.fold.status();
    assert_eq!(removed["view"]["account"], "removed");
    assert_eq!(removed["running"], false, "sync stopped");
    let ended: Vec<&str> = removed["ended"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|window| window.as_str())
        .collect();
    for window in ["main", "fold-main", "other"] {
        assert!(
            ended.contains(&window),
            "route ended for {window}: {ended:?}"
        );
    }
    log(
        &p.stack.dir,
        &format!("fold pending after its removal: {kept_work}"),
    );
    // Context: no stage or append used a permit issued after the removal.
    // (An absence; the refused read above is the service-side evidence.)
    let late_permits: Vec<_> = frames
        .iter()
        .filter(|f| f["out"] == "stage" || f["out"] == "append")
        .filter(|f| f["log"] == p.base_log().as_str())
        .filter(|f| f["issued_ms"].as_u64().is_some_and(|at| at > removed_ms))
        .collect();
    assert!(
        late_permits.is_empty(),
        "permitted after removal: {late_permits:?}"
    );
    log(
        &p.stack.dir,
        &format!(
            "current_authority_refusal: passed; mac {} fold {}",
            p.mac.status(),
            p.fold.status()
        ),
    );
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn packages_of(device: &support::Device, event: &str) -> support::Package {
    device
        .db()
        .packages()
        .into_iter()
        .find(|k| k.event_id == event)
        .expect("kept package")
}

#[test]
#[ignore = "needs tests/local-sync/run.sh"]
fn corrupted_stored_head_is_not_served() {
    let mut p = pair("corrupted_stored_head_is_not_served");
    let note = p.note.clone();
    let base = p.base_log();
    // Unauthenticated damage: a stored body's bytes changed, then missing.
    // The device waits and keeps its data; it does not stop.
    p.fold.faults(json!({"offline": true}));
    p.mac.save("main", &note, "body to damage");
    p.mac.published(180, &note, "body to damage");
    p.stack.stop_part("edge");
    let stored = p.stack.storage("inspect", &base, json!([]));
    let ordered: Vec<_> = stored["bodies"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|b| b["state"] == "ordered")
        .collect();
    let commitment = last_staged(&p.mac.frames(), &base);
    assert!(
        ordered
            .iter()
            .any(|b| b["commitment"] == commitment.as_str())
    );
    let original = p.stack.storage("r2-get", &base, json!([commitment]));
    let mut damaged = unhex(original["bytes"].as_str().unwrap());
    let middle = damaged.len() / 2;
    damaged[middle] ^= 1;
    p.stack
        .storage("r2-put", &base, json!([commitment, hex(&damaged)]));
    p.stack.start_part("edge");
    let (held_at, held_hash, _, _) = p.fold.db().progress(&p.base);
    p.fold.faults(json!({"offline": false}));
    std::thread::sleep(std::time::Duration::from_secs(10));
    let (at, hash, stopped, _) = p.fold.db().progress(&p.base);
    assert_eq!(
        (at, &hash, stopped),
        (held_at, &held_hash, None),
        "a changed body waits"
    );
    assert_ne!(p.fold.state(), "stopped");
    p.stack.stop_part("edge");
    p.stack.storage("r2-delete", &base, json!([commitment]));
    p.stack.start_part("edge");
    p.fold.wait_state(120, "history-missing");
    let (at, _, stopped, _) = p.fold.db().progress(&p.base);
    assert_eq!((at, stopped), (held_at, None), "a missing body waits");
    p.stack.stop_part("edge");
    p.stack
        .storage("r2-put", &base, json!([commitment, original["bytes"]]));
    p.stack.start_part("edge");
    let both = converged(&mut p, 240);
    assert_eq!(count(&both.paragraphs, "body to damage"), 1);
    let ordered_before = ordered.len();
    assert!(ordered_before >= 2);

    // A corrupted stored head: the service's own order gate refuses to load
    // the log, so it serves nothing new. The device waits and keeps its work;
    // it does not stop, and nothing is ordered.
    let kept = p.mac.note("main", &note);
    let (q, h, _, _) = p.mac.db().progress(&p.base);
    p.fold.faults(json!({"offline": true}));
    p.stack.stop_part("edge");
    let events_before = p.stack.storage("inspect", &base, json!([]))["events"]
        .as_array()
        .unwrap()
        .len();
    let forged = "ab".repeat(32);
    let rewrite = p.stack.storage("rewriteHead", &base, json!([forged]));
    log(&p.stack.dir, &format!("head rewritten: {rewrite}"));
    // Save while the edge is down, so its reconnect publishes the work against
    // the corrupted head rather than a background read racing the save.
    let saved_ms = now_ms();
    p.mac.save("main", &note, "after the forged head");
    p.stack.start_part("edge");
    p.mac
        .wait(180, "the append refused on the unreadable log", |d| {
            d.wake();
            d.frames().iter().any(|f| {
                f["in"] == "refused"
                    && f["kind"] == "append"
                    && f["log"] == base.as_str()
                    && f["reason"] == "Unavailable"
                    && f["ms"].as_u64().is_some_and(|ms| ms > saved_ms)
            })
        });
    assert_eq!(p.mac.state(), "waiting-authorization");
    let (at, hash, stopped, _) = p.mac.db().progress(&p.base);
    assert_eq!(
        (at, &hash, stopped),
        (q, &h, None),
        "nothing past the verified head, no stop"
    );
    p.stack.stop_part("edge");
    let events_after = p.stack.storage("inspect", &base, json!([]))["events"]
        .as_array()
        .unwrap()
        .len();
    assert_eq!(events_after, events_before, "nothing ordered");
    p.stack.start_part("edge");
    // Its local text is kept, and nothing new is accepted from the unreadable
    // log.
    let waiting = p.mac.note("main", &note);
    assert_eq!(
        count(&waiting.paragraphs, "after the forged head"),
        1,
        "kept locally"
    );
    assert_eq!(count(&waiting.paragraphs, "body to damage"), 1);
    assert_eq!(waiting.accepted, kept.accepted, "nothing accepted");
    log(&p.stack.dir, "corrupted_stored_head_is_not_served: passed");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
/// The body commitment this device last staged on the base log.
fn last_staged(frames: &[Value], base: &str) -> String {
    frames
        .iter()
        .rev()
        .find(|f| f["out"] == "stage" && f["log"] == base)
        .expect("a staged body")["commitment"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
#[ignore = "needs tests/local-sync/run.sh"]
fn hostile_k2_converges() {
    let mut p = pair("hostile_k2_converges");
    let note = p.fold.call(json!({"op": "create-note"}))["note"]
        .as_str()
        .unwrap()
        .to_owned();
    let k2 = p.fold.call(json!({"op": "k2", "note": note}));
    log(&p.stack.dir, &format!("k2: {k2}"));
    assert_eq!(
        k2["unattachable"], "refused",
        "a real writer never commits it"
    );
    let live = k2["live_digest"].as_str().unwrap().to_owned();
    p.fold.wait(240, "fold accepted its K2 updates", |d| {
        d.db().pending() == 0 && d.state() == "synced"
    });
    let fold = p.fold.note("k2", &note);
    assert_eq!(fold.accepted_digest, live, "the log-order integration");
    assert_eq!(fold.digest, live);
    p.mac.wait(240, "mac has the note", |d| {
        d.wake();
        d.try_call(json!({"op": "note", "window": "k2", "note": note}))
            .is_ok_and(|n| n["accepted_digest"] == live.as_str())
    });
    let mac = p.mac.note("k2", &note);
    assert_eq!(mac.paragraphs, fold.paragraphs);
    assert_eq!(mac.digest, live);
    let mac_device = reopen(p.mac.quit());
    p.mac = mac_device;
    let fold_device = reopen(p.fold.quit());
    p.fold = fold_device;
    for device in [&mut p.mac, &mut p.fold] {
        let reopened = device.note("k2", &note);
        assert_eq!(reopened.digest, live, "{} after reopen", device.name);
        assert_eq!(reopened.accepted_digest, live);
        assert_eq!(reopened.paragraphs, fold.paragraphs);
    }
    log(
        &p.stack.dir,
        &format!("hostile_k2_converges: passed; text {:?}", fold.paragraphs),
    );
}

#[test]
#[ignore = "needs tests/local-sync/run.sh"]
fn restart_no_lost_ack_work() {
    let mut p = pair("restart_no_lost_ack_work");
    let note = p.note.clone();
    // The Mac: one edit fully acknowledged, one ordered whose Ack is lost,
    // one only committed locally, then killed.
    p.mac.save("main", &note, "mac acked");
    p.mac.published(180, &note, "mac acked");
    p.mac.faults(json!({"hold_acks": true}));
    let mut local = Vec::new();
    let mut save = |d: &mut support::Device, window: &str, text: &'static str| {
        let receipt = d.save(window, &note, text);
        local.push((d.name.clone(), text, receipt));
    };
    save(&mut p.mac, "main", "mac ordered, ack lost");
    p.mac.wait_event("ack-held", 120);
    save(&mut p.mac, "main", "mac local only");
    let mac = p.mac.kill();
    // The Fold: one edit acknowledged, one staged but not ordered, one
    // only local, then killed.
    p.fold.save("fold-main", &note, "fold acked");
    p.fold.published(180, &note, "fold acked");
    p.fold.faults(json!({"hold_appends": true}));
    save(&mut p.fold, "fold-main", "fold staged");
    p.fold.wait_event("append-held", 120);
    save(&mut p.fold, "fold-main", "fold local only");
    let fold = p.fold.kill();
    log(&p.stack.dir, &format!("local commit receipts: {local:?}"));
    assert_eq!(mac.db().pending(), 2);
    assert_eq!(fold.db().pending(), 2);
    // Each restarts with its network refused from before its startup, so
    // what it shows comes from its own container, not from a replay.
    p.mac = support::reopen_offline(mac);
    p.fold = support::reopen_offline(fold);
    // Each local commit receipt names a kept, still pending update with
    // its edit.
    for (name, text, receipt) in &local {
        let device = if name == "mac" { &p.mac } else { &p.fold };
        assert_eq!(receipt["replayed"], false);
        let (delta, pending) = device
            .db()
            .update(receipt["request"].as_str().unwrap())
            .unwrap_or_else(|| panic!("{name}: no update for {text:?}: {receipt}"));
        assert!(pending, "{name}: {text:?} pending");
        assert!(
            delta.windows(text.len()).any(|w| w == text.as_bytes()),
            "{name}: the update for {text:?} carries it"
        );
    }
    // Every locally committed edit is there at once, before any network
    // acknowledgement.
    let texts = [
        "from the mac",
        "mac acked",
        "mac ordered, ack lost",
        "mac local only",
        "fold acked",
        "fold staged",
        "fold local only",
    ];
    let mac_now = p.mac.note("main", &note);
    for text in ["mac acked", "mac ordered, ack lost", "mac local only"] {
        assert_eq!(count(&mac_now.paragraphs, text), 1, "{text}: {mac_now:?}");
    }
    let fold_now = p.fold.note("main", &note);
    for text in ["fold acked", "fold staged", "fold local only"] {
        assert_eq!(count(&fold_now.paragraphs, text), 1, "{text}: {fold_now:?}");
    }
    for device in [&p.mac, &p.fold] {
        assert_eq!(device.db().pending(), 2, "{}: still pending", device.name);
        let sent: Vec<_> = device
            .frames()
            .into_iter()
            .skip_while(|f| f["process"] != device.pid)
            .filter(|f| f.get("out").is_some())
            .collect();
        assert!(sent.is_empty(), "{}: offline: {sent:?}", device.name);
    }
    p.mac.faults(json!({"offline": false}));
    p.fold.faults(json!({"offline": false}));
    let both = converged(&mut p, 300);
    for text in texts {
        assert_eq!(count(&both.paragraphs, text), 1, "{text} once: {both:?}");
    }
    assert_eq!(both.paragraphs.len(), texts.len());
    assert_eq!(p.mac.db().pending(), 0);
    assert_eq!(p.fold.db().pending(), 0);
    log(&p.stack.dir, "restart_no_lost_ack_work: passed");
}

#[test]
#[ignore = "needs tests/local-sync/run.sh"]
fn presence_delivers_and_appends_nothing() {
    let mut p = pair("presence_delivers_and_appends_nothing");
    let note = p.note.clone();
    converged(&mut p, 180);
    let base = p.base.clone();
    let before = (
        p.mac.db().packages().len(),
        p.fold.db().packages().len(),
        p.mac.db().progress(&base).0,
        p.fold.db().progress(&base).0,
        p.mac.frames().len(),
        p.fold.frames().len(),
    );

    // Both devices join by reporting a selection, as two open note windows do.
    let fold_at = p.fold.call(
        json!({"op": "relative", "window": "fold-main", "note": note,
        "paragraph": 0, "offset": 4}),
    );
    p.fold
        .call(json!({"op": "select", "window": "fold-main", "note": note,
        "anchor": fold_at["hex"], "head": fold_at["hex"], "label": "Fold"}));
    let first = p.mac.call(
        json!({"op": "relative", "window": "main", "note": note, "paragraph": 0, "offset": 2}),
    );
    p.mac
        .call(json!({"op": "select", "window": "main", "note": note,
        "anchor": first["hex"], "head": first["hex"], "label": "Mac"}));

    p.fold.wait(120, "mac caret visible on fold", |d| {
        let remote = d.call(json!({"op": "remote-presence"}));
        remote["entries"].as_array().unwrap().iter().any(|entry| {
            entry["note"] == json!(note)
                && entry["label"] == json!("Mac")
                && entry["anchor"] == first["hex"]
        })
    });
    p.mac.wait(120, "fold caret visible on mac", |d| {
        let remote = d.call(json!({"op": "remote-presence"}));
        remote["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["note"] == json!(note) && entry["label"] == json!("Fold"))
    });

    // A second selection moves it; a leave removes it.
    let second = p.mac.call(
        json!({"op": "relative", "window": "main", "note": note, "paragraph": 0, "offset": 7}),
    );
    p.mac
        .call(json!({"op": "select", "window": "main", "note": note,
        "anchor": second["hex"], "head": second["hex"], "label": "Mac"}));
    p.fold.wait(120, "mac caret moved", |d| {
        let remote = d.call(json!({"op": "remote-presence"}));
        remote["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["label"] == json!("Mac") && entry["anchor"] == second["hex"])
    });
    p.mac.call(json!({"op": "clear"}));
    p.fold.wait(120, "mac caret cleared", |d| {
        let remote = d.call(json!({"op": "remote-presence"}));
        !remote["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["label"] == json!("Mac"))
    });

    let mac_frames = p.mac.frames();
    let fold_frames = p.fold.frames();
    let sent = mac_frames
        .iter()
        .filter(|frame| frame["out"] == json!("presence"))
        .count();
    let joined = mac_frames
        .iter()
        .filter(|frame| frame["out"] == json!("presence-join"))
        .count();
    let received = fold_frames
        .iter()
        .filter(|frame| frame["in"] == json!("presence"))
        .count();
    assert!(sent >= 3, "mac sent {sent} presence frames");
    assert!(joined >= 1, "mac made {joined} joins");
    assert!(received >= 3, "fold received {received} presence frames");
    let appends = |frames: &[Value]| {
        frames
            .iter()
            .filter(|frame| frame["out"] == json!("append"))
            .count()
    };
    assert_eq!(
        appends(&mac_frames),
        appends(&p.mac.frames()[..before.4]),
        "presence appended on the mac"
    );
    assert_eq!(
        appends(&fold_frames),
        appends(&p.fold.frames()[..before.5]),
        "presence appended on the fold"
    );
    // No stored package or ordered position changed either.
    assert_eq!(p.mac.db().packages().len(), before.0);
    assert_eq!(p.fold.db().packages().len(), before.1);
    assert_eq!(p.mac.db().progress(&base).0, before.2);
    assert_eq!(p.fold.db().progress(&base).0, before.3);
    log(
        &p.stack.dir,
        &format!("presence: sent {sent}, received {received}, no appends"),
    );
}
