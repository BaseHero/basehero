//! Removal settlement must count the exact locally saved work that has not
//! received an authenticated ordering acknowledgment.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_data::{AppId, mutation::ops::Operation};
use bh_sync_client::{DeviceClock, RemovalVerdict, Signer};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use support::{
    device::{Device, until},
    fake::Hosted,
};

struct LocalClock(AtomicU64);
impl LocalClock {
    fn new(at: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(at)))
    }
    fn advance_to(&self, at: u64) {
        self.0.store(at, Ordering::SeqCst);
    }
}
impl DeviceClock for LocalClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Whether the device holds a durable refused-change alert.
fn alerted(device: &Device) -> bool {
    let db = device.owner.shared_database(device.id).unwrap();
    db.lock()
        .unwrap()
        .alerts(20)
        .unwrap()
        .iter()
        .any(|alert| alert.kind == bh_storage::AlertKind::RefusedChange)
}

/// A registered device whose home confirmed it, then stopped.
async fn confirmed_and_stopped(hosted: &Arc<Hosted>, device: &Device) {
    let (client, _) = device.start(hosted);
    until(20, "registered and confirmed", || {
        device.registered() && !device.home_pending()
    })
    .await;
    client.shutdown().await;
}

/// Restart `device` and expect its own removal's evidence to be refused
/// with a durable alert, its data untouched.
async fn restart_expecting_refusal(hosted: &Arc<Hosted>, device: &Device) {
    let (client, _) = device.start(hosted);
    let verdict = client.removal_verdict();
    until(20, "evidence refused", || {
        *verdict.borrow() == RemovalVerdict::Refused
    })
    .await;
    assert!(alerted(device), "a refused change is alerted");
    assert!(device.owner.shared_database(device.id).is_ok());
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn device_clock_behind_waits_then_erases() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = mac.start(&hosted);
    until(20, "home confirmed", || {
        mac.registered() && !mac.home_pending()
    })
    .await;
    let fold = Device::join(&mac, &hosted).await;
    until(20, "addition followed", || {
        mac.signer.current_account().unwrap().head().position == 4
    })
    .await;
    let clock = LocalClock::new(hosted.edge.clock.now());
    let mut endpoint = fold.endpoint(&hosted);
    endpoint.device_clock = clock.clone();
    let (fold_client, _) = fold.start_at(&hosted, endpoint);
    until(20, "fold registered", || fold.registered()).await;
    hosted.edge.order_account(
        mac.account_log,
        &mac.signer.request_removal(fold.signer.device_id()),
    );
    fold_client.wake();
    let verdict = fold_client.removal_verdict();
    until(20, "request verified", || {
        matches!(*verdict.borrow(), RemovalVerdict::Pending { .. })
    })
    .await;
    let deadline = match *verdict.borrow() {
        RemovalVerdict::Pending { deadline_ms, by } => {
            assert!(
                by == Some(mac.signer.device_id()),
                "verified requester is shown"
            );
            deadline_ms
        }
        other => panic!("expected pending: {other:?}"),
    };

    hosted
        .edge
        .clock
        .advance(deadline - hosted.edge.clock.now() + 1);
    // The service now refuses the device; the device's own clock still has
    // not established the deadline. It must not declare erasure eligible.
    let reads_before = hosted.edge.reads(mac.account_log).len();
    fold_client.wake();
    until(20, "evidence read after home deadline", || {
        hosted.edge.reads(mac.account_log).len() > reads_before
    })
    .await;
    assert!(
        matches!(*verdict.borrow(), RemovalVerdict::Pending { .. }),
        "home time alone must not erase before the local clock"
    );
    clock.advance_to(deadline + 1);
    // No account notice and no explicit wake: the pending deadline must
    // schedule a bounded recheck when the local clock catches up.
    tokio::time::advance(std::time::Duration::from_secs(301)).await;
    until(20, "both clocks past deadline", || {
        matches!(*verdict.borrow(), RemovalVerdict::Removed { .. })
    })
    .await;
    fold_client.shutdown().await;
    mac_client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn removed_device_reads_account_evidence_verifies_and_reports_removal() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = device.start(&hosted);
    until(20, "registered and home confirmed", || {
        device.registered() && !device.home_pending()
    })
    .await;
    client.shutdown().await;
    hosted
        .edge
        .order_account(device.account_log, &device.signer.remove_self());
    let (client, _) = device.start(&hosted);
    let verdict = client.removal_verdict();
    until(20, "verified own removal", || {
        *verdict.borrow() == RemovalVerdict::Removed { unsent: 0 }
    })
    .await;
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn target_keeps_syncing_during_wait_and_sends_last_edit() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = mac.start(&hosted);
    until(20, "home confirmed", || {
        mac.registered() && !mac.home_pending()
    })
    .await;
    let fold = Device::join(&mac, &hosted).await;
    until(20, "addition followed", || {
        mac.signer.current_account().unwrap().head().position == 4
    })
    .await;
    let (fold_client, _) = fold.start(&hosted);
    until(20, "fold registered", || fold.registered()).await;
    hosted.edge.order_account(
        mac.account_log,
        &mac.signer.request_removal(fold.signer.device_id()),
    );
    fold_client.wake();
    let verdict = fold_client.removal_verdict();
    until(20, "pending removal verified", || {
        matches!(*verdict.borrow(), RemovalVerdict::Pending { .. })
    })
    .await;
    let (_, edit) = fold.new_note("last edit while still authorised");
    fold_client.wake();
    until(20, "last edit acknowledged", || fold.acked(edit).is_some()).await;
    fold_client.shutdown().await;
    mac_client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn forged_removal_with_a_bad_signature_alerts_and_erases_nothing() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = device.start(&hosted);
    until(20, "home confirmed", || {
        device.registered() && !device.home_pending()
    })
    .await;
    client.shutdown().await;
    hosted
        .edge
        .order_account(device.account_log, &device.signer.remove_self());
    hosted.corrupt_accepted_account(device.account_log, true);
    let (client, _) = device.start(&hosted);
    let verdict = client.removal_verdict();
    until(20, "refused signed evidence", || {
        *verdict.borrow() == RemovalVerdict::Refused
    })
    .await;
    let db = device.owner.shared_database(device.id).unwrap();
    assert!(
        db.lock()
            .unwrap()
            .alerts(20)
            .unwrap()
            .iter()
            .any(|alert| { alert.kind == bh_storage::AlertKind::RefusedChange })
    );
    assert!(device.owner.shared_database(device.id).is_ok());
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn device_clock_ahead_without_home_time_erases_nothing() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = mac.start(&hosted);
    until(20, "home confirmed", || {
        mac.registered() && !mac.home_pending()
    })
    .await;
    let fold = Device::join(&mac, &hosted).await;
    until(20, "addition followed", || {
        mac.signer.current_account().unwrap().head().position == 4
    })
    .await;
    // The device's own clock is far past the deadline; the home's confirmed
    // lower bound is not, so nothing may be erased.
    let clock = LocalClock::new(u64::MAX / 2);
    let mut endpoint = fold.endpoint(&hosted);
    endpoint.device_clock = clock.clone();
    let (fold_client, _) = fold.start_at(&hosted, endpoint);
    until(20, "fold registered", || fold.registered()).await;
    hosted.edge.order_account(
        mac.account_log,
        &mac.signer.request_removal(fold.signer.device_id()),
    );
    fold_client.wake();
    let verdict = fold_client.removal_verdict();
    until(20, "pending despite the local clock", || {
        matches!(*verdict.borrow(), RemovalVerdict::Pending { .. })
    })
    .await;
    assert!(fold.owner.shared_database(fold.id).is_ok());
    fold_client.shutdown().await;
    mac_client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn cancelled_removal_erases_nothing() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = mac.start(&hosted);
    until(20, "home confirmed", || {
        mac.registered() && !mac.home_pending()
    })
    .await;
    let fold = Device::join(&mac, &hosted).await;
    until(20, "addition followed", || {
        mac.signer.current_account().unwrap().head().position == 4
    })
    .await;
    let (fold_client, _) = fold.start_at(&hosted, fold.endpoint(&hosted));
    until(20, "fold registered", || fold.registered()).await;
    let request = mac.signer.request_removal(fold.signer.device_id());
    let position = hosted.edge.order_account(mac.account_log, &request);
    let cancel = mac
        .signer
        .cancel_removal(fold.signer.device_id(), position)
        .expect("cancel request");
    hosted.edge.order_account(mac.account_log, &cancel);
    fold_client.wake();
    let verdict = fold_client.removal_verdict();
    until(20, "cancelled removal is not pending", || {
        *verdict.borrow() == RemovalVerdict::Active
    })
    .await;
    assert!(fold.owner.shared_database(fold.id).is_ok());
    fold_client.shutdown().await;
    mac_client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn authenticate_not_active_without_visible_removal_keeps_account() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = device.start(&hosted);
    until(20, "registered and confirmed", || {
        device.registered() && !device.home_pending()
    })
    .await;
    client.shutdown().await;
    hosted.confirm_served_account(device.account_log);
    hosted.refuse_authenticate_not_active(true);
    let reads = hosted.edge.reads(device.account_log).len();
    let (client, _) = device.start(&hosted);
    until(20, "authenticate refused", || {
        hosted.forced_not_active_count() > 0
    })
    .await;
    until(20, "public account evidence read", || {
        hosted.edge.reads(device.account_log).len() > reads
    })
    .await;
    assert_eq!(*client.removal_verdict().borrow(), RemovalVerdict::Active);
    let db = device.owner.shared_database(device.id).unwrap();
    assert!(
        !db.lock()
            .unwrap()
            .alerts(20)
            .unwrap()
            .iter()
            .any(|alert| { alert.kind == bh_storage::AlertKind::RefusedChange })
    );
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn running_session_permits_not_active_without_removal_keeps_account() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = device.start(&hosted);
    until(20, "registered and confirmed", || {
        device.registered() && !device.home_pending()
    })
    .await;
    // Route through the fixture's attested request interceptor while the
    // real service still serves the unchanged signed account history.
    client.shutdown().await;
    hosted.confirm_served_account(device.account_log);
    let (client, _) = device.start(&hosted);
    let mut session = client.authz().await.unwrap();
    let reads = hosted.edge.reads(device.account_log).len();
    hosted.refuse_permits_not_active(true);
    let answer = session
        .ask(bh_authz::proto::ToService::Permits {
            items: vec![bh_authz::proto::Want::ReadEvents {
                log: device.log(),
                first: 1,
                last: 1,
            }],
        })
        .await
        .unwrap();
    assert!(
        matches!(
            answer,
            bh_authz::proto::FromService::Refused {
                reason: bh_authz::proto::Refusal::NotActive
            }
        ),
        "answer={answer:?}, forced={}",
        hosted.forced_not_active_count()
    );
    drop(session);
    hosted.refuse_permits_not_active(false);
    assert!(hosted.forced_not_active_count() >= 1);
    until(20, "public account evidence read", || {
        hosted.edge.reads(device.account_log).len() > reads
    })
    .await;
    assert_eq!(*client.removal_verdict().borrow(), RemovalVerdict::Active);
    let db = device.owner.shared_database(device.id).unwrap();
    assert!(
        !db.lock()
            .unwrap()
            .alerts(20)
            .unwrap()
            .iter()
            .any(|alert| { alert.kind == bh_storage::AlertKind::RefusedChange })
    );
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn altered_original_signature_cannot_authorize_erasure() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = device.start(&hosted);
    until(20, "registered and confirmed", || {
        device.registered() && !device.home_pending()
    })
    .await;
    client.shutdown().await;
    let removal = device.signer.remove_self();
    let position = hosted.edge.order_account(device.account_log, &removal);
    let mut forgery = removal;
    *forgery.last_mut().unwrap() ^= 1;
    hosted
        .edge
        .serve_account(device.account_log, position, &[forgery]);
    hosted.confirm_served_account(device.account_log);
    let (client, _) = device.start(&hosted);
    let verdict = client.removal_verdict();
    until(20, "forged original refused", || {
        *verdict.borrow() == RemovalVerdict::Refused
    })
    .await;
    let db = device.owner.shared_database(device.id).unwrap();
    assert!(
        db.lock()
            .unwrap()
            .alerts(20)
            .unwrap()
            .iter()
            .any(|alert| { alert.kind == bh_storage::AlertKind::RefusedChange })
    );
    assert!(device.owner.shared_database(device.id).is_ok());
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn unsent_count_counts_only_unacknowledged_outbox_items() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, mut status) = device.start(&hosted);
    until(20, "registered", || {
        device.registered() && device.progress().position == 1
    })
    .await;
    // Echoes are held back: only a verified ACK may settle saved work.
    hosted.edge.freeze_reads(Some(1));
    // One note's three saved edits, sealed as one coalesced package.
    let (mut writer, first) = device.new_note("coalesced one");
    device.append(&mut writer, "coalesced two");
    device.append(&mut writer, "coalesced three");
    client.wake();
    until(20, "package ack", || device.acked(first).is_some()).await;
    let members: i64 = device
        .raw()
        .query_row("SELECT COUNT(*) FROM note_outbox_members", [], |r| r.get(0))
        .unwrap();
    assert!(members >= 2, "the package has several members: {members}");
    // ACKed typed work.
    let (_, typed) = device.typed_submit(Operation::DefineApp {
        app: AppId([41; 32]),
        name: "Acknowledged app".into(),
    });
    client.wake();
    until(20, "typed ack", || device.typed_acked(typed).is_some()).await;
    // A package the service refused: it has an outcome but no ACK.
    hosted
        .edge
        .refuse_next_event(bh_sync::wire::Refusal::Conflict);
    let (_, refused) = device.new_note("refused");
    client.wake();
    until(20, "not accepted", || {
        *status.borrow_and_update() == bh_sync_client::SyncStatus::NotAccepted { notes: 1 }
    })
    .await;
    assert_eq!(device.acked(refused), None);
    client.shutdown().await;

    let (mut writer, _) = device.new_note("first unsent edit");
    device.append(&mut writer, "second unsent edit");
    device.typed_submit(Operation::DefineApp {
        app: AppId([42; 32]),
        name: "Unsent app".into(),
    });
    let db = device.owner.shared_database(device.id).unwrap();
    // The refused note, two unpackaged edits and the unsent typed work.
    assert_eq!(db.lock().unwrap().unsent_count().unwrap(), 4);
}

#[tokio::test(start_paused = true)]
async fn an_entry_past_the_answered_head_is_unavailable_not_forged() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = mac.start(&hosted);
    until(20, "home confirmed", || {
        mac.registered() && !mac.home_pending()
    })
    .await;
    let fold = Device::join(&mac, &hosted).await;
    until(20, "addition followed", || {
        mac.signer.current_account().unwrap().head().position == 4
    })
    .await;
    let clock = LocalClock::new(hosted.edge.clock.now());
    let mut endpoint = fold.endpoint(&hosted);
    endpoint.device_clock = clock;
    let (fold_client, _) = fold.start_at(&hosted, endpoint);
    until(20, "fold registered", || fold.registered()).await;
    let request = hosted.edge.order_account(
        mac.account_log,
        &mac.signer.request_removal(fold.signer.device_id()),
    );
    fold_client.wake();
    let verdict = fold_client.removal_verdict();
    until(20, "request verified", || {
        matches!(*verdict.borrow(), RemovalVerdict::Pending { .. })
    })
    .await;
    until(20, "mac followed its request", || {
        mac.signer.current_account().unwrap().head().position == request
    })
    .await;
    mac_client.shutdown().await;
    // The home answers at its head; meanwhile it orders the next entry, which
    // the edge already serves without a confirmation in that answer.
    let next = mac
        .signer
        .cancel_removal(fold.signer.device_id(), request)
        .unwrap();
    hosted
        .edge
        .serve_account(mac.account_log, request + 1, &[next]);
    let reads = hosted.edge.reads(mac.account_log).len();
    // The pending request's bounded recheck reads that page.
    tokio::time::sleep(std::time::Duration::from_secs(301)).await;
    assert!(hosted.edge.reads(mac.account_log).len() > reads);
    assert!(!alerted(&fold), "an honest race raised an alert");
    assert!(matches!(*verdict.borrow(), RemovalVerdict::Pending { .. }));
    fold_client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_missing_confirmation_at_the_answered_head_is_refused() {
    let hosted = Hosted::new();
    let device = Device::new();
    confirmed_and_stopped(&hosted, &device).await;
    let position = hosted
        .edge
        .order_account(device.account_log, &device.signer.remove_self());
    // The answer's head covers the removal, but its confirmation is withheld.
    hosted.omit_account_confirmation(device.account_log, position);
    restart_expecting_refusal(&hosted, &device).await;
}

#[tokio::test(start_paused = true)]
async fn removal_signed_by_the_wrong_signer_is_refused() {
    let hosted = Hosted::new();
    let device = Device::new();
    confirmed_and_stopped(&hosted, &device).await;
    let position = hosted
        .edge
        .order_account(device.account_log, &device.signer.remove_self());
    // The home certifies a removal the device's ordinary key signed, not the
    // control key the account names for it.
    hosted.edge.serve_account(
        device.account_log,
        position,
        &[device.signer.remove_self_signed_by_ordinary_key()],
    );
    hosted.confirm_served_account(device.account_log);
    restart_expecting_refusal(&hosted, &device).await;
}

#[tokio::test(start_paused = true)]
async fn confirmation_from_another_root_is_refused() {
    let hosted = Hosted::new();
    let device = Device::new();
    confirmed_and_stopped(&hosted, &device).await;
    hosted
        .edge
        .order_account(device.account_log, &device.signer.remove_self());
    hosted.foreign_root_account_confirmations(device.account_log);
    restart_expecting_refusal(&hosted, &device).await;
}

#[tokio::test(start_paused = true)]
async fn accepted_head_for_another_challenge_is_refused() {
    let hosted = Hosted::new();
    let device = Device::new();
    confirmed_and_stopped(&hosted, &device).await;
    hosted
        .edge
        .order_account(device.account_log, &device.signer.remove_self());
    hosted.accepted_account_head_for_other_challenge(device.account_log);
    restart_expecting_refusal(&hosted, &device).await;
}

/// A removal behind more than one full 64-entry page of account history.
async fn long_history_removal(hosted: &Arc<Hosted>, device: &Device) -> u64 {
    confirmed_and_stopped(hosted, device).await;
    let mut last = 0;
    for original in device
        .signer
        .signed_additions_then_removal(70, hosted.edge.clock.now())
    {
        last = hosted.edge.order_account(device.account_log, &original);
    }
    last
}

#[tokio::test(start_paused = true)]
async fn removal_behind_full_pages_is_verified() {
    let hosted = Hosted::new();
    let device = Device::new();
    long_history_removal(&hosted, &device).await;
    let (client, _) = device.start(&hosted);
    let verdict = client.removal_verdict();
    until(20, "verified across pages", || {
        matches!(*verdict.borrow(), RemovalVerdict::Removed { .. })
    })
    .await;
    assert!(!alerted(&device));
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn an_omitted_confirmation_in_a_full_page_is_refused() {
    let hosted = Hosted::new();
    let device = Device::new();
    long_history_removal(&hosted, &device).await;
    hosted.omit_account_confirmation(device.account_log, 30);
    restart_expecting_refusal(&hosted, &device).await;
}

#[tokio::test(start_paused = true)]
async fn a_false_ahead_claim_carried_across_pages_is_refused() {
    let hosted = Hosted::new();
    let device = Device::new();
    let head = long_history_removal(&hosted, &device).await;
    // Pages that stop short of the head carry a claim about it that the
    // final page's original contradicts.
    hosted.corrupt_ahead_account_claim(device.account_log, head, true);
    restart_expecting_refusal(&hosted, &device).await;
}

#[tokio::test(start_paused = true)]
async fn a_lapsed_removal_request_erases_nothing() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = mac.start(&hosted);
    until(20, "home confirmed", || {
        mac.registered() && !mac.home_pending()
    })
    .await;
    let fold = Device::join(&mac, &hosted).await;
    until(20, "addition followed", || {
        mac.signer.current_account().unwrap().head().position == 4
    })
    .await;
    let clock = LocalClock::new(hosted.edge.clock.now());
    let mut endpoint = fold.endpoint(&hosted);
    endpoint.device_clock = clock.clone();
    let (fold_client, _) = fold.start_at(&hosted, endpoint);
    until(20, "fold registered", || fold.registered()).await;
    hosted.edge.order_account(
        mac.account_log,
        &mac.signer.request_removal(fold.signer.device_id()),
    );
    fold_client.wake();
    let verdict = fold_client.removal_verdict();
    until(20, "request verified", || {
        matches!(*verdict.borrow(), RemovalVerdict::Pending { .. })
    })
    .await;
    let RemovalVerdict::Pending { deadline_ms, .. } = *verdict.borrow() else {
        unreachable!()
    };
    until(20, "mac followed its request", || {
        mac.signer.current_account().unwrap().head().position == 5
    })
    .await;
    // The requester leaves at once: its pending request lapses with it.
    hosted
        .edge
        .order_account(mac.account_log, &mac.signer.remove_self());
    mac_client.shutdown().await;
    hosted
        .edge
        .clock
        .advance(deadline_ms - hosted.edge.clock.now() + 1);
    clock.advance_to(deadline_ms + 1);
    fold_client.wake();
    until(20, "lapsed request leaves the device active", || {
        *verdict.borrow() == RemovalVerdict::Active
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_secs(301)).await;
    assert_eq!(*verdict.borrow(), RemovalVerdict::Active);
    assert!(fold.owner.shared_database(fold.id).is_ok());
    fold_client.shutdown().await;
}

/// A check asked for while another is under way answers for newer history:
/// the earlier one's result, read before the ask, is not published.
#[tokio::test(start_paused = true)]
async fn a_check_overtaken_by_a_newer_ask_is_not_published() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = device.start(&hosted);
    until(20, "registered and confirmed", || {
        device.registered() && !device.home_pending()
    })
    .await;
    let mut verdict = client.removal_verdict();
    verdict.borrow_and_update();
    let published = Arc::new(AtomicU64::new(0));
    let counting = tokio::spawn({
        let published = published.clone();
        async move {
            while verdict.changed().await.is_ok() {
                published.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    let hold = hosted.edge.hold_next_authz_reply();
    client.check_removal();
    hold.arrived.await.unwrap();
    // Asked again while the first check waits for its answer.
    client.check_removal();
    hold.release.send(()).unwrap();
    until(20, "answered", || published.load(Ordering::SeqCst) > 0).await;
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    assert_eq!(published.load(Ordering::SeqCst), 1, "one answer, the newer");
    assert_eq!(*client.removal_verdict().borrow(), RemovalVerdict::Active);
    client.shutdown().await;
    counting.abort();
}

/// A check the host asks for after the owner applied this device's removal
/// fails at the network: it is retried on the bounded interval until an
/// answer is published, rather than never.
#[tokio::test(start_paused = true)]
async fn an_asked_check_that_fails_at_the_network_is_retried() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = device.start(&hosted);
    until(20, "registered and confirmed", || {
        device.registered() && !device.home_pending()
    })
    .await;
    // As the host's signer: once the owner applies the removal, this device
    // can no longer authenticate, so no refusal asks for a check.
    device
        .signer
        .proofs_need_membership
        .store(true, Ordering::SeqCst);
    let verdict = client.removal_verdict();
    hosted.go_down();
    hosted
        .edge
        .order_account(device.account_log, &device.signer.remove_self());
    let removal = hosted
        .confirmed_account(device.account_log)
        .await
        .pop()
        .unwrap();
    // The owner applies it, as the account follow does, then the host asks.
    let head = device.signer.current_account().unwrap().head();
    let _ = device.signer.apply_account_timed(head, vec![removal]).await;
    let journal = bh_account::storage::DeviceJournal::from_shared(
        device.owner.shared_database(device.id).unwrap(),
    );
    assert_eq!(
        bh_account::journal::AccountJournal::load(&journal)
            .unwrap()
            .unwrap()
            .head
            .position,
        head.position + 1,
        "the owner applied this device's removal"
    );
    client.check_removal();
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    assert_eq!(
        *verdict.borrow(),
        RemovalVerdict::Active,
        "a check that failed at the network publishes nothing"
    );
    hosted.come_up();
    tokio::time::sleep(std::time::Duration::from_secs(301)).await;
    until(20, "the retried check verified the removal", || {
        matches!(*verdict.borrow(), RemovalVerdict::Removed { .. })
    })
    .await;
    client.shutdown().await;
}

/// The removal lane's evidence link belongs to one check: a completed check
/// holds no DATA socket open, the next check opens a fresh one rather than
/// reusing it, and a check whose evidence read fails at the network leaves
/// nothing behind to retry on.
#[tokio::test(start_paused = true)]
async fn the_removal_lane_holds_its_evidence_link_only_while_checking() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = device.start_named(&hosted, "removal");
    until(20, "registered and confirmed", || {
        device.registered() && !device.home_pending()
    })
    .await;
    let mut verdict = client.removal_verdict();
    verdict.borrow_and_update();
    let published = Arc::new(AtomicU64::new(0));
    let watching = tokio::spawn({
        let published = published.clone();
        async move {
            while verdict.changed().await.is_ok() {
                published.fetch_add(1, Ordering::SeqCst);
            }
        }
    });
    let live = || hosted.edge.live_evidence_links("removal");
    let links = || hosted.edge.evidence_links("removal");

    // One check: its verdict is published with no link left open.
    client.check_removal();
    until(20, "the check's verdict was published", || {
        published.load(Ordering::SeqCst) >= 1
    })
    .await;
    until(20, "the check released its link", || live() == 0).await;
    let first = links();
    assert!(!first.is_empty(), "the check read the public evidence");

    // The next check opens a link of its own.
    client.check_removal();
    until(20, "the second check released its link", || {
        live() == 0 && links().len() > first.len()
    })
    .await;
    let latest = published.load(Ordering::SeqCst);

    // A check whose evidence read the edge cannot serve fails at the
    // network: it holds no link, and the next check opens another.
    hosted.edge.refuse_next_evidence_read();
    client.check_removal();
    until(20, "the evidence read was refused", || {
        hosted.edge.evidence_refused() == 1
    })
    .await;
    until(20, "the failed check released its link", || live() == 0).await;
    assert_eq!(
        published.load(Ordering::SeqCst),
        latest,
        "a failed check publishes no verdict"
    );
    let failed = links().len();
    client.check_removal();
    until(
        20,
        "the check after the failure opened and released its link",
        || live() == 0 && links().len() > failed && published.load(Ordering::SeqCst) > latest,
    )
    .await;
    client.shutdown().await;
    watching.abort();
}

/// A later entry the home confirmed after the deadline ends the device's
/// membership by home time alone. Its own clock has not reached the
/// deadline, so the removal stays pending until it does.
#[tokio::test(start_paused = true)]
async fn a_home_confirmed_removal_waits_for_the_device_clock() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = mac.start(&hosted);
    until(20, "home confirmed", || {
        mac.registered() && !mac.home_pending()
    })
    .await;
    let fold = Device::join(&mac, &hosted).await;
    until(20, "addition followed", || {
        mac.signer.current_account().unwrap().head().position == 4
    })
    .await;
    let clock = LocalClock::new(hosted.edge.clock.now());
    let mut endpoint = fold.endpoint(&hosted);
    endpoint.device_clock = clock.clone();
    let (fold_client, _) = fold.start_at(&hosted, endpoint);
    until(20, "fold registered", || fold.registered()).await;
    hosted.edge.order_account(
        mac.account_log,
        &mac.signer.request_removal(fold.signer.device_id()),
    );
    fold_client.wake();
    let mut verdict = fold_client.removal_verdict();
    until(20, "request verified", || {
        matches!(*verdict.borrow(), RemovalVerdict::Pending { .. })
    })
    .await;
    let RemovalVerdict::Pending { deadline_ms, .. } = *verdict.borrow() else {
        unreachable!()
    };
    until(20, "mac followed its request", || {
        mac.signer.current_account().unwrap().head().position == 5
    })
    .await;
    mac_client.shutdown().await;
    // Past the deadline by home time, the home confirms another entry.
    hosted
        .edge
        .clock
        .advance(deadline_ms - hosted.edge.clock.now() + 1);
    let later = mac.signer.signed_additions(1, hosted.edge.clock.now());
    hosted.edge.order_account(mac.account_log, &later[0]);
    verdict.borrow_and_update();
    fold_client.wake();
    tokio::time::timeout(std::time::Duration::from_secs(60), verdict.changed())
        .await
        .expect("the check answered")
        .unwrap();
    assert_eq!(
        *verdict.borrow(),
        RemovalVerdict::Pending {
            deadline_ms,
            by: Some(mac.signer.device_id())
        },
        "home time alone must not erase before the device clock"
    );
    assert!(fold.owner.shared_database(fold.id).is_ok());
    clock.advance_to(deadline_ms + 1);
    tokio::time::advance(std::time::Duration::from_secs(301)).await;
    until(20, "both clocks past the deadline", || {
        matches!(*verdict.borrow(), RemovalVerdict::Removed { .. })
    })
    .await;
    fold_client.shutdown().await;
}

/// A refusal after a pending deadline wakes a verified check; neither the
/// local clock alone nor NotActive alone proves removal.
#[tokio::test(start_paused = true)]
async fn pending_deadline_not_active_checks_verified_removal() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = mac.start(&hosted);
    until(20, "home confirmed", || {
        mac.registered() && !mac.home_pending()
    })
    .await;
    let fold = Device::join(&mac, &hosted).await;
    until(20, "addition followed", || {
        mac.signer.current_account().unwrap().head().position == 4
    })
    .await;
    let clock = LocalClock::new(hosted.edge.clock.now());
    let mut endpoint = fold.endpoint(&hosted);
    endpoint.device_clock = clock.clone();
    let (fold_client, _) = fold.start_at(&hosted, endpoint);
    until(20, "fold registered", || fold.registered()).await;
    hosted.edge.order_account(
        mac.account_log,
        &mac.signer.request_removal(fold.signer.device_id()),
    );
    fold_client.wake();
    let verdict = fold_client.removal_verdict();
    until(20, "request verified", || {
        matches!(*verdict.borrow(), RemovalVerdict::Pending { .. })
    })
    .await;
    let RemovalVerdict::Pending { deadline_ms, .. } = *verdict.borrow() else {
        unreachable!()
    };
    // Hold home time just behind the deadline while fixture handshakes run.
    // The device clock advances independently; the requested check leaves
    // a pending verdict, and its deadline timer must check both clocks.
    hosted
        .edge
        .clock
        .advance(deadline_ms - hosted.edge.clock.now() - 2_000);
    hosted.edge.clock.stand_still();
    clock.advance_to(deadline_ms - 1_000);
    let reads_before = hosted.edge.reads(mac.account_log).len();
    fold_client.check_removal();
    until(20, "near-deadline check", || {
        hosted.edge.reads(mac.account_log).len() > reads_before
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let reads_before = hosted.edge.reads(mac.account_log).len();
    clock.advance_to(deadline_ms + 1);
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    until(2, "device deadline check", || {
        hosted.edge.reads(mac.account_log).len() > reads_before
    })
    .await;
    assert!(
        hosted.edge.clock.now() < deadline_ms,
        "the home must still be behind at the device deadline check"
    );
    assert!(matches!(*verdict.borrow(), RemovalVerdict::Pending { .. }));
    let mut session = fold_client.authz().await.unwrap();
    clock.advance_to(deadline_ms + 1);
    hosted.edge.clock.resume();
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    let answer = session
        .ask(bh_authz::proto::ToService::Permits {
            items: vec![bh_authz::proto::Want::ReadEvents {
                log: fold.log(),
                first: 1,
                last: 1,
            }],
        })
        .await
        .unwrap();
    assert!(
        matches!(
            answer,
            bh_authz::proto::FromService::Refused {
                reason: bh_authz::proto::Refusal::NotActive
            }
        ),
        "home={} deadline={deadline_ms} answer={answer:?}",
        hosted.edge.clock.now()
    );
    drop(session);
    until(2, "verified removal after NotActive", || {
        matches!(*verdict.borrow(), RemovalVerdict::Removed { .. })
    })
    .await;
    fold_client.shutdown().await;
    mac_client.shutdown().await;
}

/// No refusal or extra wake rescues the target: only the deadline timer
/// checks again after home time joins the already-past device clock.
#[tokio::test(start_paused = true)]
async fn pending_deadline_rechecks_when_home_catches_up_without_not_active() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = mac.start(&hosted);
    until(20, "home confirmed", || {
        mac.registered() && !mac.home_pending()
    })
    .await;
    let fold = Device::join(&mac, &hosted).await;
    until(20, "addition followed", || {
        mac.signer.current_account().unwrap().head().position == 4
    })
    .await;
    let clock = LocalClock::new(hosted.edge.clock.now());
    let mut endpoint = fold.endpoint(&hosted);
    endpoint.device_clock = clock.clone();
    let (fold_client, _) = fold.start_at(&hosted, endpoint);
    until(20, "fold registered", || fold.registered()).await;
    hosted.edge.order_account(
        mac.account_log,
        &mac.signer.request_removal(fold.signer.device_id()),
    );
    fold_client.wake();
    let mut verdict = fold_client.removal_verdict();
    until(20, "request verified", || {
        matches!(*verdict.borrow(), RemovalVerdict::Pending { .. })
    })
    .await;
    let RemovalVerdict::Pending { deadline_ms, .. } = *verdict.borrow() else {
        unreachable!()
    };

    // The fixture still handles every real public-evidence request, but
    // translates ordinary NotActive refusals into Unauthenticated, which
    // cannot trigger either of the removal lane's NotActive watches.
    hosted.mask_not_active();
    hosted
        .edge
        .clock
        .advance(deadline_ms - hosted.edge.clock.now() - 2_000);
    hosted.edge.clock.stand_still();
    clock.advance_to(deadline_ms - 1_000);
    verdict.borrow_and_update();
    fold_client.check_removal();
    until(20, "near-deadline verdict published", || {
        verdict.has_changed().unwrap()
    })
    .await;
    assert!(matches!(
        *verdict.borrow_and_update(),
        RemovalVerdict::Pending { .. }
    ));

    clock.advance_to(deadline_ms + 1);
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    until(2, "device-deadline verdict published", || {
        verdict.has_changed().unwrap()
    })
    .await;
    assert!(hosted.edge.clock.now() < deadline_ms);
    assert!(matches!(
        *verdict.borrow_and_update(),
        RemovalVerdict::Pending { .. }
    ));
    // No call to check_removal(), no user wake, and no NotActive can arrive.
    tokio::time::advance(std::time::Duration::from_secs(1)).await;
    assert!(matches!(*verdict.borrow(), RemovalVerdict::Pending { .. }));
    hosted.edge.clock.resume();
    tokio::time::advance(std::time::Duration::from_secs(2)).await;
    until(1, "timer verified removal after both clocks", || {
        matches!(*verdict.borrow(), RemovalVerdict::Removed { .. })
    })
    .await;
    assert!(hosted.edge.clock.now() >= deadline_ms);
    fold_client.shutdown().await;
    mac_client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_device_clock_ahead_rechecks_on_a_bounded_interval() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (mac_client, _) = mac.start(&hosted);
    until(20, "home confirmed", || {
        mac.registered() && !mac.home_pending()
    })
    .await;
    let fold = Device::join(&mac, &hosted).await;
    until(20, "addition followed", || {
        mac.signer.current_account().unwrap().head().position == 4
    })
    .await;
    let clock = LocalClock::new(u64::MAX / 2);
    let mut endpoint = fold.endpoint(&hosted);
    endpoint.device_clock = clock.clone();
    let (fold_client, _) = fold.start_at(&hosted, endpoint);
    until(20, "fold registered", || fold.registered()).await;
    hosted.edge.order_account(
        mac.account_log,
        &mac.signer.request_removal(fold.signer.device_id()),
    );
    fold_client.wake();
    let verdict = fold_client.removal_verdict();
    until(20, "pending despite the local clock", || {
        matches!(*verdict.borrow(), RemovalVerdict::Pending { .. })
    })
    .await;
    // An hour of a far-ahead device clock: each recheck is an attested
    // handshake and an evidence read, so they stay at the bounded interval.
    mac_client.shutdown().await;
    let before = hosted.edge.reads(mac.account_log).len();
    tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    let reads = hosted.edge.reads(mac.account_log).len() - before;
    // Measured: 24 (the five-minute recheck and the account follow's own
    // reads); a one-second recheck makes about 3600.
    assert!(reads <= 30, "{reads} evidence reads in an hour");
    assert!(matches!(*verdict.borrow(), RemovalVerdict::Pending { .. }));
    fold_client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn running_session_refused_mid_sync_checks_and_reports_removal() {
    let hosted = Hosted::new();
    let device = Device::new();
    let (client, _) = device.start(&hosted);
    until(20, "registered and confirmed", || {
        device.registered() && !device.home_pending()
    })
    .await;
    // An authenticated session is open when the home orders the removal; the
    // service refuses its next permit request.
    let mut session = client.authz().await.unwrap();
    hosted
        .edge
        .order_account(device.account_log, &device.signer.remove_self());
    let answer = session
        .ask(bh_authz::proto::ToService::Permits {
            items: vec![bh_authz::proto::Want::ReadEvents {
                log: device.log(),
                first: 1,
                last: 1,
            }],
        })
        .await
        .unwrap();
    assert!(
        matches!(
            answer,
            bh_authz::proto::FromService::Refused {
                reason: bh_authz::proto::Refusal::NotActive
            }
        ),
        "{answer:?}"
    );
    drop(session);
    let verdict = client.removal_verdict();
    until(20, "verified removal after a running refusal", || {
        matches!(*verdict.borrow(), RemovalVerdict::Removed { .. })
    })
    .await;
    client.shutdown().await;
}
