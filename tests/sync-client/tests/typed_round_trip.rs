//! The real personal-account sync path, including device-signed management
//! approvals and unconfirmed work ordered after competing rule changes.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_data::{
    AppId, FieldPath, KeyRef, RecordId, RevisionId, Scope, TypeId,
    catalogue::Shipped,
    mutation::ops::{FieldChange, Operation},
    query::{Budget, Page, Query, QueryError, SortKey, TypeSelect, run},
    session::{Authority, DataSession, SessionError},
    store::{records, registry},
    testkit::state_digest,
    text, tools,
};
use bh_storage::sync_state::PackageOutcome;
use bh_sync_client::{Signer, SyncStatus};
use serde_json::json;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use support::{
    device::{Device, until},
    fake::Hosted,
};

const ARTICLE: &[u8] = include_bytes!("../../data-consumers/types/Article.json");
const JOURNAL: &[u8] = include_bytes!("../../data-consumers/types/JournalEntry.json");
const APP: AppId = AppId([2; 32]);

fn scope(device: &Device) -> Scope {
    Scope {
        base: device.base.0,
        audience: [0; 32],
    }
}

fn path(s: &str) -> FieldPath {
    FieldPath::parse(s).unwrap()
}

fn page(device: &Device, select: TypeSelect, fields: &[&str]) -> Page {
    let scope = scope(device);
    run(
        &device.raw(),
        scope,
        &[scope],
        &Shipped,
        &Query {
            select,
            filter: None,
            sort: vec![],
            fields: fields.iter().map(|field| path(field)).collect(),
            follow: vec![],
            text: None,
            limit: 50,
            after: None,
        },
        Budget::INTERACTIVE,
    )
    .unwrap()
}

fn accepted(device: &Device, packages: &[i64]) -> bool {
    packages.iter().all(|id| {
        device.typed_progress(*id).is_some_and(|progress| {
            progress.outcome == Some(PackageOutcome::Accepted)
                && progress.payload_position.is_some()
        })
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_devices_exchange_typed_records_and_specialised_notes_after_restart() {
    let hosted = Hosted::new();
    let a = Device::new();
    let (a_client, mut a_status) = a.start(&hosted);
    let a_client = Arc::new(a_client);
    let wake_count = Arc::new(AtomicUsize::new(0));
    until(20, "first registered", || {
        a.registered() && a.progress().position >= 1
    })
    .await;
    let b = Device::join(&a, &hosted);
    until(20, "addition copied", || {
        a.progress()
            .account
            .is_some_and(|(position, _)| position == 4)
    })
    .await;
    let (b_client, _) = b.start(&hosted);
    until(20, "joined replica caught up", || {
        b.progress().position == a.progress().position
            && b.progress()
                .account
                .is_some_and(|(position, _)| position == 4)
    })
    .await;

    let records = a.owner.records(a.id).unwrap();
    // An already-open handle must see the publisher installed later.
    let weak_client = Arc::downgrade(&a_client);
    let wakes = Arc::clone(&wake_count);
    a.owner.set_records_wake(Arc::new(move |_| {
        wakes.fetch_add(1, Ordering::SeqCst);
        if let Some(client) = weak_client.upgrade() {
            client.wake();
        }
    }));
    let wakes_before_app = wake_count.load(Ordering::SeqCst);
    let app_saved = records
        .submit(Operation::DefineApp {
            app: APP,
            name: "Reading".into(),
        })
        .unwrap();
    assert_eq!(wake_count.load(Ordering::SeqCst), wakes_before_app + 1);
    let db = a.owner.shared_database(a.id).unwrap();
    let app_package = db
        .lock()
        .unwrap()
        .typed_package_id(app_saved.mutation)
        .unwrap()
        .unwrap();
    until(20, "app accepted on first device", || {
        accepted(&a, &[app_package])
    })
    .await;
    let mut a_packages = vec![app_package];
    assert!(matches!(
        a.owner.records(b.id),
        Err(bh_device::OwnerError::UnknownContainer)
    ));
    assert_eq!(records.scope(), scope(&a));
    let foreign = Scope {
        base: [9; 32],
        audience: [0; 32],
    };
    assert!(matches!(
        records.session().list_types(foreign),
        Err(bh_data::DataError::Unauthorized)
    ));
    // Even a forged in-process Authority cannot make the production store
    // admit a management change outside the private signed-approval path.
    struct ForgedAuthority {
        scope: Scope,
        actor: bh_data::Actor,
    }
    impl Authority for ForgedAuthority {
        fn actor(&self) -> bh_data::Actor {
            self.actor.clone()
        }
        fn reads(&self) -> Vec<Scope> {
            vec![self.scope]
        }
        fn write(&self) -> Option<Scope> {
            Some(self.scope)
        }
        fn confirm_rule_change(
            &self,
            _: &bh_data::admission::Confirmation,
            _: Option<bh_data::Position>,
        ) -> Result<bool, bh_data::DataError> {
            Ok(true)
        }
    }
    let forged = DataSession::new(
        &records,
        ForgedAuthority {
            scope: scope(&a),
            actor: Authority::actor(&records),
        },
    );
    assert!(matches!(
        forged.submit(Operation::SetAppState {
            app: APP,
            active: false
        }),
        Err(SessionError::ConfirmationRequired(_))
    ));
    assert!(matches!(
        records.submit(Operation::SetAppState {
            app: APP,
            active: false
        }),
        Err(SessionError::ConfirmationRequired(_))
    ));
    let forged_confirmation = json!({"kind":"set_app_state","app":APP,"active":false,
        "confirmation":{"App":{"app":APP,"since":null,"active":true}}});
    assert!(serde_json::from_value::<Operation>(forged_confirmation.clone()).is_err());
    let rejected_tool = tools::call(&records.session(), "records.mutate", forged_confirmation);
    assert!(
        rejected_tool.get("error").is_some(),
        "caller confirmation must be refused: {rejected_tool}"
    );
    let prepared = tools::call(
        &records.session(),
        "types.prepare_change",
        json!({"bytes": ARTICLE}),
    );
    assert!(
        prepared.get("ok").is_some(),
        "prepare must return a proposal: {prepared}"
    );
    assert!(
        records
            .session()
            .list_types(scope(&a))
            .unwrap()
            .iter()
            .all(|t| t.type_id != TypeId::for_app(APP, [1; 16]))
    );
    let wrong = records
        .approval_request_operation(Operation::SetAppState {
            app: APP,
            active: false,
        })
        .unwrap();
    let wrong_signature = a
        .signer
        .sign_event(b"different bytes".to_vec())
        .await
        .unwrap();
    assert!(records.approve(wrong, wrong_signature).is_err());
    let other = records
        .approval_request_operation(Operation::SetAppState {
            app: APP,
            active: false,
        })
        .unwrap();
    let other_signature = b.signer.sign_event(other.message().to_vec()).await.unwrap();
    assert!(records.approve(other, other_signature).is_err());
    for bytes in [ARTICLE, JOURNAL] {
        assert!(
            records
                .approval_request(&records.prepare_change(bytes).unwrap())
                .is_err()
        );
        let saved = records
            .submit(Operation::DefineType {
                bytes: bytes.to_vec(),
            })
            .unwrap();
        let db = a.owner.shared_database(a.id).unwrap();
        let package = db
            .lock()
            .unwrap()
            .typed_package_id(saved.mutation)
            .unwrap()
            .unwrap();
        a_packages.push(package);
    }
    a_client.wake();
    until(20, "definitions accepted on first device", || {
        accepted(&a, &a_packages)
    })
    .await;

    let (mut note, first_note_update) = a.new_note("Shared note");
    a.append(&mut note, "A writes the body");
    let record = RecordId::random();
    let article = TypeId::for_app(APP, [1; 16]);
    let journal = TypeId::for_app(APP, [8; 16]);
    let article_saved = records.submit(Operation::Create {
        record,
        type_id: article,
        revision: RevisionId::of(ARTICLE),
        doc: json!({"title":"First article", "url":"https://example.test/first", "state":"new"}),
    }).unwrap();
    let db = a.owner.shared_database(a.id).unwrap();
    let create = db
        .lock()
        .unwrap()
        .typed_package_id(article_saved.mutation)
        .unwrap()
        .unwrap();
    let bound = records
        .submit(Operation::BindNote {
            note: RecordId(note.note),
            type_id: journal,
            revision: RevisionId::of(JOURNAL),
            doc: json!({"date":1700000000000_i64,"mood":"curious"}),
        })
        .unwrap();
    let db = a.owner.shared_database(a.id).unwrap();
    let bind = db
        .lock()
        .unwrap()
        .typed_package_id(bound.mutation)
        .unwrap()
        .unwrap();
    a_packages.extend([create, bind]);
    a_client.wake();
    until(20, "first replica's work accepted", || {
        accepted(&a, &a_packages) && a.pending() == 0
    })
    .await;
    assert!(a.acked(first_note_update).is_some());
    // Retrying the same BindNote package resolves to its immutable sealed
    // original, not another mutation or a newly signed event.
    let first_bind = a.typed_package(bind).unwrap();
    let retried_bind = a.typed_package(bind).unwrap();
    assert_eq!(first_bind.event_id, retried_bind.event_id);
    assert_eq!(
        first_bind.descriptor.encode(),
        retried_bind.descriptor.encode()
    );
    assert_eq!(first_bind.body, retried_bind.body);
    assert_eq!(
        page(&a, TypeSelect::Exact(journal), &["/mood"]).rows[0].values["/mood"],
        "curious"
    );
    let before_typed_edit = a
        .owner
        .list_notes_page(a.id, None, 50)
        .unwrap()
        .rows
        .into_iter()
        .find(|row| row.note == note.note)
        .unwrap()
        .touched;
    let extension = records
        .submit(Operation::Edit {
            record: RecordId(note.note),
            revision: RevisionId::of(JOURNAL),
            changes: vec![FieldChange {
                path: path("/mood"),
                value: Some(json!("reflective")),
            }],
        })
        .unwrap();
    let db = a.owner.shared_database(a.id).unwrap();
    let extension_package = db
        .lock()
        .unwrap()
        .typed_package_id(extension.mutation)
        .unwrap()
        .unwrap();
    a_packages.push(extension_package);
    until(20, "second replica received typed and note work", || {
        accepted(&a, &[extension_package])
            && b.progress().position == hosted.edge.head(b.log()).position
            && b.inserted(note.note, "A writes the body") == 1
    })
    .await;
    let articles = page(&b, TypeSelect::Exact(article), &["/title", "/state"]);
    assert_eq!(articles.rows.len(), 1);
    assert_eq!(articles.rows[0].record, record);
    assert_eq!(articles.rows[0].values["/title"], "First article");
    let notes = page(&b, TypeSelect::Family(TypeId::core("note")), &["/title"]);
    let bound = notes
        .rows
        .iter()
        .find(|row| row.record == RecordId(note.note))
        .unwrap();
    assert_eq!(bound.type_id, journal);
    assert_eq!(bound.values["/title"], "Shared note");
    let native_notes = b.owner.list_notes_page(b.id, None, 50).unwrap();
    assert_eq!(
        native_notes.completeness,
        bh_data::query::Completeness::Complete
    );
    let native_note = native_notes
        .rows
        .iter()
        .find(|row| row.note == note.note)
        .unwrap();
    assert_eq!(native_note.title, "Shared note");
    let after_typed_edit = a
        .owner
        .list_notes_page(a.id, None, 50)
        .unwrap()
        .rows
        .into_iter()
        .find(|row| row.note == note.note)
        .unwrap()
        .touched;
    assert!(
        after_typed_edit > before_typed_edit,
        "a specialised Note's typed field edit advances its shared-query recency"
    );
    let specialised = page(&b, TypeSelect::Exact(journal), &["/mood"]);
    assert_eq!(specialised.rows[0].values["/mood"], "reflective");
    assert_eq!(
        page(&b, TypeSelect::Exact(journal), &["/mood"]).rows[0].values["/mood"],
        "reflective"
    );

    hosted.edge.freeze_reads(Some(b.progress().position));
    let b_records = b.owner.records(b.id).unwrap();
    let edit_saved = b_records
        .submit(Operation::Edit {
            record,
            revision: RevisionId::of(ARTICLE),
            changes: vec![FieldChange {
                path: path("/state"),
                value: Some(json!("saved")),
            }],
        })
        .unwrap();
    let edit_mutation = edit_saved.mutation;
    let db = b.owner.shared_database(b.id).unwrap();
    let edit = db
        .lock()
        .unwrap()
        .typed_package_id(edit_mutation)
        .unwrap()
        .unwrap();
    let mut b_note = b.writer(note.note);
    let b_note_update = b.append(&mut b_note, "B replies");
    b_client.wake();
    until(20, "second replica acked before echo", || {
        b.typed_acked(edit).is_some() && b.acked(b_note_update).is_some()
    })
    .await;
    assert_eq!(
        b.typed_progress(edit).unwrap().outcome,
        Some(PackageOutcome::Acked)
    );
    b_client.shutdown().await;
    drop(b_client);
    until(20, "second replica client released", || {
        Arc::strong_count(&b.owner) == 1 && Arc::strong_count(&b.signer) == 1
    })
    .await;
    // Restart models a full process exit; release the native records handle
    // and writer clone so neither retains the container's file lock.
    drop(b_records);
    drop(db);
    let b = b.restart();
    assert_eq!(
        b.typed_progress(edit).unwrap().outcome,
        Some(PackageOutcome::Acked)
    );
    hosted.edge.freeze_reads(None);
    let (b_client, mut b_status_after_restart) = b.start(&hosted);
    b_client.wake();
    a_client.wake();
    until(20, "both replicas settled", || {
        accepted(&b, &[edit])
            && accepted(&a, &a_packages)
            && b.typed_state(edit_mutation).is_none()
            && a.progress().position == hosted.edge.head(a.log()).position
            && b.progress().position == a.progress().position
            && a.pending() == 0
            && b.pending() == 0
    })
    .await;
    assert_eq!(
        page(&a, TypeSelect::Exact(article), &["/state"]).rows[0].values["/state"],
        "saved"
    );
    assert_eq!(a.inserted(note.note, "B replies"), 1);
    assert_eq!(b.inserted(note.note, "B replies"), 1);
    assert_eq!(
        a.raw()
            .query_row("SELECT COUNT(*) FROM data_pending", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        b.raw()
            .query_row("SELECT COUNT(*) FROM data_pending", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        state_digest(&a.raw(), scope(&a)).unwrap(),
        state_digest(&b.raw(), scope(&b)).unwrap(),
        "replicated typed state diverged"
    );
    let appends = hosted.edge.appends(a.log().id);
    for (device, packages) in [(&a, a_packages.as_slice()), (&b, &[edit][..])] {
        for id in packages {
            let sealed = device.typed_package(*id).unwrap().descriptor.encode();
            assert_eq!(appends.iter().filter(|bytes| **bytes == sealed).count(), 1);
        }
    }
    // Existing record rules require explicit approval, and the receiver must
    // decide from this device's authenticated ordered original on replay.
    let mut changed: serde_json::Value = serde_json::from_slice(ARTICLE).unwrap();
    changed["evolution"]["previous"] = serde_json::to_value(RevisionId::of(ARTICLE)).unwrap();
    changed["fields"]["/state"]["write"] = json!("action");
    let changed = serde_json::to_vec(&changed).unwrap();
    let proposal = records.prepare_change(&changed).unwrap();
    assert!(proposal.needs_device);
    assert!(matches!(
        records.submit(Operation::DefineType {
            bytes: changed.clone()
        }),
        Err(SessionError::ConfirmationRequired(_))
    ));
    let approval = records.approval_request(&proposal).unwrap();
    let signature = a
        .signer
        .sign_event(approval.message().to_vec())
        .await
        .unwrap();
    let wake_before = wake_count.load(Ordering::SeqCst);
    let saved = records.approve(approval, signature).unwrap();
    assert_eq!(wake_count.load(Ordering::SeqCst), wake_before + 1);
    assert!(
        a.owner
            .list_notes_page(a.id, None, 50)
            .unwrap()
            .rows
            .iter()
            .any(|row| row.note == note.note && row.title == "Shared note"),
        "a Note remains in the list after an actual account-signed rule approval"
    );
    let db = a.owner.shared_database(a.id).unwrap();
    let revision_package = db
        .lock()
        .unwrap()
        .typed_package_id(saved.mutation)
        .unwrap()
        .unwrap();
    b_client.wake();
    until(20, "both statuses synced", || {
        accepted(&a, &[revision_package])
            && a.typed_progress(revision_package)
                .and_then(|p| p.payload_position)
                .is_some_and(|position| b.progress().position >= position)
            && b.progress().position == a.progress().position
            && *a_status.borrow_and_update() == SyncStatus::Synced
            && *b_status_after_restart.borrow_and_update() == SyncStatus::Synced
    })
    .await;
    let db = b.raw();
    let sid = records::lookup_scope(&db, scope(&b)).unwrap().unwrap();
    assert_eq!(
        registry::current(&db, sid, article, &Shipped)
            .unwrap()
            .unwrap()
            .revision,
        RevisionId::of(&changed)
    );
    // Two independently valid edits at the same account head: a confirmation
    // for one cannot survive the other's accepted rule change.
    let mut first: serde_json::Value = serde_json::from_slice(&changed).unwrap();
    first["evolution"]["previous"] = json!(RevisionId::of(&changed));
    first["fields"]["/url"]["write"] = json!("action");
    let first = serde_json::to_vec(&first).unwrap();
    let mut second: serde_json::Value = serde_json::from_slice(&changed).unwrap();
    second["evolution"]["previous"] = json!(RevisionId::of(&changed));
    second["fields"]["/title"]["write"] = json!("action");
    let second = serde_json::to_vec(&second).unwrap();
    let stale_proposal = records.prepare_change(&second).unwrap();
    let stale_request = records.approval_request(&stale_proposal).unwrap();
    let stale_signature = a
        .signer
        .sign_event(stale_request.message().to_vec())
        .await
        .unwrap();
    let first_request = records
        .approval_request(&records.prepare_change(&first).unwrap())
        .unwrap();
    let first_signature = a
        .signer
        .sign_event(first_request.message().to_vec())
        .await
        .unwrap();
    let first_saved = records.approve(first_request, first_signature).unwrap();
    let first_package = a
        .owner
        .shared_database(a.id)
        .unwrap()
        .lock()
        .unwrap()
        .typed_package_id(first_saved.mutation)
        .unwrap()
        .unwrap();
    until(20, "first policy revision accepted", || {
        accepted(&a, &[first_package])
    })
    .await;
    let before = wake_count.load(Ordering::SeqCst);
    let db = a.raw();
    let queued: i64 = db
        .query_row("SELECT count(*) FROM typed_outbox", [], |r| r.get(0))
        .unwrap();
    let pending: i64 = db
        .query_row("SELECT count(*) FROM data_pending", [], |r| r.get(0))
        .unwrap();
    drop(db);
    assert!(
        records.approval_request(&stale_proposal).is_err(),
        "prepare/request must bind prior rules"
    );
    assert_eq!(wake_count.load(Ordering::SeqCst), before);
    assert!(
        records.approve(stale_request, stale_signature).is_err(),
        "signature/commit must bind prior rules"
    );
    assert_eq!(wake_count.load(Ordering::SeqCst), before);
    let db = a.raw();
    assert_eq!(
        db.query_row("SELECT count(*) FROM typed_outbox", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        queued
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM data_pending", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        pending
    );
    drop(db);
    let fresh_request = records
        .approval_request(&records.prepare_change(&second).unwrap())
        .unwrap();
    let fresh_signature = a
        .signer
        .sign_event(fresh_request.message().to_vec())
        .await
        .unwrap();
    let second_saved = records.approve(fresh_request, fresh_signature).unwrap();
    let second_package = a
        .owner
        .shared_database(a.id)
        .unwrap()
        .lock()
        .unwrap()
        .typed_package_id(second_saved.mutation)
        .unwrap()
        .unwrap();
    until(20, "freshly confirmed policy accepted", || {
        accepted(&a, &[second_package])
    })
    .await;

    let deactivation = records
        .approval_request_operation(Operation::SetAppState {
            app: APP,
            active: false,
        })
        .unwrap();
    let signature = a
        .signer
        .sign_event(deactivation.message().to_vec())
        .await
        .unwrap();
    let deactivated = records.approve(deactivation, signature).unwrap();
    let package = a
        .owner
        .shared_database(a.id)
        .unwrap()
        .lock()
        .unwrap()
        .typed_package_id(deactivated.mutation)
        .unwrap()
        .unwrap();
    until(20, "deactivation accepted on peer", || {
        accepted(&a, &[package]) && b.progress().position == a.progress().position
    })
    .await;
    let peer = b.raw();
    let sid = records::lookup_scope(&peer, scope(&b)).unwrap().unwrap();
    assert_eq!(registry::app_active(&peer, sid, APP).unwrap(), Some(false));
    drop(peer);

    // An otherwise valid, unsubmitted revision is invalidated by replacing
    // account authority, even when the verified account head stays unchanged.
    let mut next: serde_json::Value = serde_json::from_slice(&second).unwrap();
    next["evolution"]["previous"] = json!(RevisionId::of(&second));
    next["fields"]["/url"]["write"] = json!("action");
    let next = serde_json::to_vec(&next).unwrap();
    let proposal = records.prepare_change(&next).unwrap();
    let old_request = records.approval_request(&proposal).unwrap();
    let old_signature = a
        .signer
        .sign_event(old_request.message().to_vec())
        .await
        .unwrap();
    let other_old_request = records.approval_request(&proposal).unwrap();
    let other_old_signature = a
        .signer
        .sign_event(other_old_request.message().to_vec())
        .await
        .unwrap();
    let wakes_before_reauth = wake_count.load(Ordering::SeqCst);
    let db = a.raw();
    let pending_before: i64 = db
        .query_row("SELECT count(*) FROM data_pending", [], |r| r.get(0))
        .unwrap();
    let outbox_before: i64 = db
        .query_row("SELECT count(*) FROM typed_outbox", [], |r| r.get(0))
        .unwrap();
    drop(db);
    a.signer.relock();
    assert!(matches!(records.approve(old_request, old_signature),
        Err(bh_data::Rejection { code: bh_data::RejectCode::Unauthorized, detail, .. })
        if detail == "invalid or stale device approval"));
    a.authorize().unwrap();
    let fresh = a.owner.records(a.id).unwrap();
    assert!(
        matches!(fresh.approve(other_old_request, other_old_signature),
        Err(bh_data::Rejection { code: bh_data::RejectCode::Unauthorized, detail, .. })
        if detail == "invalid or stale device approval")
    );
    assert_eq!(wake_count.load(Ordering::SeqCst), wakes_before_reauth);
    let db = a.raw();
    assert_eq!(
        db.query_row("SELECT count(*) FROM data_pending", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        pending_before
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM typed_outbox", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        outbox_before
    );
    drop(db);
    let new_proposal = fresh.prepare_change(&next).unwrap();
    let new_request = fresh.approval_request(&new_proposal).unwrap();
    let new_signature = a
        .signer
        .sign_event(new_request.message().to_vec())
        .await
        .unwrap();
    assert!(fresh.approve(new_request, new_signature).is_ok());
    b_client.shutdown().await;
    a_client.shutdown().await;
}

async fn drive(mut ready: impl FnMut() -> bool) {
    for _ in 0..200_000 {
        if ready() {
            return;
        }
        tokio::task::yield_now().await;
    }
    assert!(
        ready(),
        "operation did not complete in bounded scheduler turns"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_documentation_revision_cannot_restore_a_new_protected_policy() {
    let hosted = Hosted::new();
    let a = Device::new();
    let (a_client, _) = a.start(&hosted);
    drive(|| a.registered() && a.progress().position >= 1).await;
    let b = Device::join(&a, &hosted);
    drive(|| {
        a.progress()
            .account
            .is_some_and(|(position, _)| position == 4)
    })
    .await;
    let (b_client, _) = b.start(&hosted);
    drive(|| b.progress().position == a.progress().position).await;
    let a_records = a.owner.records(a.id).unwrap();
    let b_records = b.owner.records(b.id).unwrap();
    let app = a_records
        .submit(Operation::DefineApp {
            app: APP,
            name: "Reading".into(),
        })
        .unwrap();
    let app_id = a
        .owner
        .shared_database(a.id)
        .unwrap()
        .lock()
        .unwrap()
        .typed_package_id(app.mutation)
        .unwrap()
        .unwrap();
    drive(|| accepted(&a, &[app_id]) && b.progress().position == a.progress().position).await;
    let base = a_records
        .submit(Operation::DefineType {
            bytes: ARTICLE.to_vec(),
        })
        .unwrap();
    let ids: Vec<_> = [app.mutation, base.mutation]
        .iter()
        .map(|mutation| {
            a.owner
                .shared_database(a.id)
                .unwrap()
                .lock()
                .unwrap()
                .typed_package_id(*mutation)
                .unwrap()
                .unwrap()
        })
        .collect();
    drive(|| accepted(&a, &ids) && b.progress().position == a.progress().position).await;
    a_client.shutdown().await;
    drop(a_client);
    drive(|| Arc::strong_count(&a.owner) == 1 && Arc::strong_count(&a.signer) == 1).await;

    let mut docs: serde_json::Value = serde_json::from_slice(ARTICLE).unwrap();
    docs["evolution"]["previous"] = json!(RevisionId::of(ARTICLE));
    docs["description"] = json!("Reworded article documentation");
    let docs = serde_json::to_vec(&docs).unwrap();
    assert!(!a_records.prepare_change(&docs).unwrap().needs_device);
    let queued = a_records
        .submit(Operation::DefineType { bytes: docs })
        .unwrap();
    let queued_package = a
        .owner
        .shared_database(a.id)
        .unwrap()
        .lock()
        .unwrap()
        .typed_package_id(queued.mutation)
        .unwrap()
        .unwrap();
    let mut protected: serde_json::Value = serde_json::from_slice(ARTICLE).unwrap();
    protected["evolution"]["previous"] = json!(RevisionId::of(ARTICLE));
    protected["fields"]["/url"]["write"] = json!("action");
    let protected = serde_json::to_vec(&protected).unwrap();
    let request = b_records
        .approval_request(&b_records.prepare_change(&protected).unwrap())
        .unwrap();
    let signature = b
        .signer
        .sign_event(request.message().to_vec())
        .await
        .unwrap();
    let policy = b_records.approve(request, signature).unwrap();
    let policy_package = b
        .owner
        .shared_database(b.id)
        .unwrap()
        .lock()
        .unwrap()
        .typed_package_id(policy.mutation)
        .unwrap()
        .unwrap();
    drive(|| accepted(&b, &[policy_package])).await;
    let (a_client, _) = a.start(&hosted);
    a_client.wake();
    b_client.wake();
    drive(|| {
        a.typed_progress(queued_package)
            .is_some_and(|p| p.outcome == Some(PackageOutcome::Rejected))
            && b.progress().position == a.progress().position
            && a.typed_state(queued.mutation).as_deref() == Some("rejected")
    })
    .await;
    for device in [&a, &b] {
        let conn = device.raw();
        let sid = records::lookup_scope(&conn, scope(device))
            .unwrap()
            .unwrap();
        assert_eq!(
            registry::current(&conn, sid, TypeId::for_app(APP, [1; 16]), &Shipped)
                .unwrap()
                .unwrap()
                .revision,
            RevisionId::of(&protected)
        );
    }
    a_client.shutdown().await;
    b_client.shutdown().await;
    drop(a_client);
    drop(b_client);
    drop(a_records);
    drop(b_records);
    drive(|| Arc::strong_count(&a.owner) == 1 && Arc::strong_count(&b.owner) == 1).await;
    let a = a.restart();
    let b = b.restart();
    assert_eq!(a.typed_state(queued.mutation).as_deref(), Some("rejected"));
    for device in [&a, &b] {
        let conn = device.raw();
        let sid = records::lookup_scope(&conn, scope(device))
            .unwrap()
            .unwrap();
        assert_eq!(
            registry::current(&conn, sid, TypeId::for_app(APP, [1; 16]), &Shipped)
                .unwrap()
                .unwrap()
                .revision,
            RevisionId::of(&protected)
        );
    }
}

// Use the published owner/transport path rather than the data-library fixture
// host: a new index must progress even if no foreground typed work follows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revised_article_index_and_search_resume_parked_work_on_two_devices() {
    let hosted = Hosted::new();
    let a = Device::new_with_maintenance(false);
    let (a_client, _) = a.start(&hosted);
    until(120, "first registered", || {
        a.registered() && a.progress().position >= 1
    })
    .await;
    let b = Device::join_with_maintenance(&a, &hosted, false);
    until(120, "addition copied", || {
        a.progress().account.is_some_and(|(p, _)| p == 4)
    })
    .await;
    let (b_client, _) = b.start(&hosted);
    until(120, "joined replica caught up", || {
        b.progress().position == a.progress().position
    })
    .await;
    let records = a.owner.records(a.id).unwrap();
    let article = TypeId::for_app(APP, [1; 16]);
    let mut initial: serde_json::Value = serde_json::from_slice(ARTICLE).unwrap();
    initial["unique"] = json!([]);
    initial["indexes"] = json!([]);
    let initial = serde_json::to_vec(&initial).unwrap();
    let package = |saved: &bh_data::mutation::pending::LocalSaved| {
        a.owner
            .shared_database(a.id)
            .unwrap()
            .lock()
            .unwrap()
            .typed_package_id(saved.mutation)
            .unwrap()
            .unwrap()
    };
    let app = package(
        &records
            .submit(Operation::DefineApp {
                app: APP,
                name: "Reading".into(),
            })
            .unwrap(),
    );
    a_client.wake();
    until(120, "app accepted", || accepted(&a, &[app])).await;
    let definition = package(
        &records
            .submit(Operation::DefineType {
                bytes: initial.clone(),
            })
            .unwrap(),
    );
    a_client.wake();
    until(120, "initial rules accepted", || {
        accepted(&a, &[definition])
    })
    .await;

    // More than the bounded sort fallback, all through the real pending and
    // encrypted publish path; each payload retains a distinct durable position.
    let mut final_create = 0;
    for n in 0..2001 {
        final_create = package(&records.submit(Operation::Create {
            record: RecordId::random(), type_id: article, revision: RevisionId::of(&initial),
            doc: json!({"title":format!("Article {n:04}"), "url":format!("https://example.test/{n}")}),
        }).unwrap());
    }
    a_client.wake();
    until(240, "both devices populated", || {
        accepted(&a, &[final_create])
            && b.progress().position == a.progress().position
            && b.raw()
                .query_row(
                    "SELECT count(*) FROM data_record WHERE type=?1",
                    [article.0.as_slice()],
                    |r| r.get::<_, i64>(0),
                )
                .unwrap()
                == 2001
    })
    .await;

    let mut changed: serde_json::Value = serde_json::from_slice(&initial).unwrap();
    changed["evolution"]["previous"] = json!(RevisionId::of(&initial));
    changed["unique"] = json!([{"name":"url", "keys":["/url"]}]);
    changed["indexes"] = json!([{"name":"by_title", "keys":["/title"]}]);
    changed["search"]["text"] = json!(["/url"]);
    let changed = serde_json::to_vec(&changed).unwrap();
    let request = records
        .approval_request(&records.prepare_change(&changed).unwrap())
        .unwrap();
    let signature = a
        .signer
        .sign_event(request.message().to_vec())
        .await
        .unwrap();
    let revision = package(&records.approve(request, signature).unwrap());
    let raced_record = RecordId::random();
    let raced = records
        .submit(Operation::Create {
            record: raced_record,
            type_id: article,
            revision: RevisionId::of(&initial),
            doc: json!({"title":"Racing article", "url":"https://example.test/0"}),
        })
        .unwrap();
    let raced_package = package(&raced);
    a_client.wake();
    b_client.wake();
    let sorted = Query {
        select: TypeSelect::Exact(article),
        filter: None,
        sort: vec![SortKey {
            key: KeyRef::Field(path("/title")),
            desc: false,
        }],
        fields: vec![path("/title")],
        follow: vec![],
        text: None,
        limit: 20,
        after: None,
    };
    until(
        240,
        "revision and racing create ordered on both devices",
        || {
            accepted(&a, &[revision])
                && a.typed_progress(raced_package)
                    .and_then(|p| p.payload_position)
                    .is_some_and(|position| {
                        a.progress().position >= position && b.progress().position >= position
                    })
                && b.progress().position == a.progress().position
        },
    )
    .await;
    // A parked typed echo retains its Acked status until replay decides it.
    let raced_progress = a.typed_progress(raced_package).unwrap();
    assert_eq!(raced_progress.outcome, Some(PackageOutcome::Acked));
    let raced_position = raced_progress.payload_position.unwrap();
    for device in [&a, &b] {
        let conn = device.raw();
        let sid = records::lookup_scope(&conn, scope(device))
            .unwrap()
            .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT state FROM data_index WHERE scope=?1 AND name='by_title'",
                [sid],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "building"
        );
        assert!(matches!(
            device
                .owner
                .records(device.id)
                .unwrap()
                .session()
                .query(scope(device), &sorted),
            Err(QueryError::IndexBuilding { .. })
        ));
        let reason: String = conn
            .query_row(
                "SELECT reason FROM data_parked WHERE scope=?1 AND position=?2 AND affects=?3",
                rusqlite::params![
                    sid,
                    raced_position as i64,
                    bh_data::mutation::apply::Key::Type(article).encode()
                ],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            reason.contains("UniquenessUnknown"),
            "unexpected wait: {reason}"
        );
        assert!(text::reprojection_pending(&conn).unwrap());
    }
    a.owner.resume_maintenance(a.id).unwrap();
    b.owner.resume_maintenance(b.id).unwrap();
    until(240, "revision and index finish on both devices", || {
        let done = a
            .typed_progress(raced_package)
            .is_some_and(|p| p.outcome == Some(PackageOutcome::Rejected))
            && b.progress().position == a.progress().position;
        done && [&a, &b].iter().all(|device| {
            let conn = device.raw();
            let sid = records::lookup_scope(&conn, scope(device))
                .unwrap()
                .unwrap();
            conn.query_row(
                "SELECT state FROM data_index WHERE scope=?1 AND name='by_title'",
                [sid],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .as_deref()
                == Some("ready")
                && !text::reprojection_pending(&conn).unwrap()
                && device
                    .owner
                    .records(device.id)
                    .unwrap()
                    .session()
                    .query(scope(device), &sorted)
                    .is_ok()
        })
    })
    .await;
    assert_eq!(
        state_digest(&a.raw(), scope(&a)).unwrap(),
        state_digest(&b.raw(), scope(&b)).unwrap()
    );
    assert_eq!(
        page(&a, TypeSelect::Exact(article), &["/title"]).rows.len(),
        50
    );
    for device in [&a, &b] {
        let conn = device.raw();
        assert_eq!(
            device
                .owner
                .records(device.id)
                .unwrap()
                .session()
                .query(scope(device), &sorted)
                .unwrap()
                .rows
                .len(),
            20
        );
        let sid = records::lookup_scope(&conn, scope(device))
            .unwrap()
            .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM data_parked WHERE scope=?1",
                [sid],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        // The author's rejected local overlay remains recoverable, but no
        // replica accepts that duplicate record into ordered state.
        assert_eq!(
            conn.query_row(
                "SELECT count(*) FROM data_record WHERE scope=?1 AND record=?2 AND accepted IS NOT NULL",
                rusqlite::params![sid, raced_record.0.as_slice()],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        let watermark = text::watermark(&conn, scope(device)).unwrap();
        assert_eq!(watermark.complete_through, watermark.current);
    }
    // One durable verdict for the author's raced package. Transport
    // redelivery of exact retries is covered by the shared retry tests.
    assert_eq!(
        a.raw()
            .query_row(
                "SELECT count(*) FROM typed_outbox WHERE id=?1 AND outcome=4",
                [raced_package],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
        1
    );
    a_client.shutdown().await;
    b_client.shutdown().await;
}
