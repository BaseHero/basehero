mod common;

use basehero_app_lib::commands::{account, approval};
use basehero_app_lib::views::{AppEvent, SignInForm, SignUpForm};
use bh_core::{AccountEvent, AppIdentity, ApprovalId, RecoveryKit};
use bh_testkit::{LocalServer, TEST_PASSWORD, invite};
use common::state_at;
use std::time::Duration;

/// One generous deadline for things that should happen: Argon2id and server round
/// trips are slow on a loaded machine, and these waits never test speed.
const WAIT: Duration = Duration::from_secs(30);

async fn setup() -> (
    basehero_app_lib::state::AppState,
    common::Events,
    basehero_app_lib::state::AppState,
    common::Events,
    String,
    String,
    bh_core::AccountId,
) {
    let server = LocalServer::shared();
    let (full, events) = state_at(server.url());
    let signed = account::sign_up(
        &full,
        SignUpForm {
            invite: invite(server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: TEST_PASSWORD.into(),
            device_name: "Mac".into(),
        },
    )
    .await
    .unwrap();
    let (new, new_events) = state_at(server.url());
    let pending = account::sign_in_start(
        &new,
        SignInForm {
            email: signed.account.email,
            password: TEST_PASSWORD.into(),
            device_name: "Fold".into(),
        },
    )
    .await
    .unwrap();
    (
        full,
        events,
        new,
        new_events,
        pending,
        signed.kit.to_string(),
        signed.account.id,
    )
}

#[tokio::test]
async fn an_app_is_connected_through_the_commands() {
    let server = LocalServer::shared();
    let (full, _events) = state_at(server.url());
    let signed = account::sign_up(
        &full,
        SignUpForm {
            invite: invite(server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: TEST_PASSWORD.into(),
            device_name: "Mac".into(),
        },
    )
    .await
    .unwrap();
    let (app, _app_events) = state_at(server.url());
    let mut pending = app
        .core
        .start_connection(
            server.url(),
            &signed.account.email,
            AppIdentity {
                name: "Sample".into(),
                app_id: "app.basehero.sample".into(),
            },
        )
        .await
        .unwrap();
    let id = pending.id();
    let (opened, digits) = tokio::time::timeout(WAIT, async {
        tokio::join!(
            approval::connect_open(&full, signed.account.id, id),
            pending.digits()
        )
    })
    .await
    .unwrap();
    assert_eq!(opened.unwrap().id, id);
    let offer = approval::connect_check(&full, signed.account.id, id, &digits.unwrap().to_string())
        .await
        .unwrap();
    assert_eq!(offer.name, "Sample");
    assert!(offer.device_name.ends_with(" - Sample"));
    assert_eq!(offer.bases.len(), 1);
    let choice = approval::AppChoiceInput {
        bases: offer
            .bases
            .iter()
            .map(|grant| approval::BaseChoiceInput {
                base: Some(grant.base),
                new_name: None,
                mode: grant.mode,
            })
            .collect(),
        cap_micro_usd: offer.cap_micro_usd,
        replaces: None,
    };
    let (device, removed) = approval::connect_approve(&full, signed.account.id, id, choice)
        .await
        .unwrap();
    assert!(!removed);
    let connected = tokio::time::timeout(WAIT, pending.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(connected.device_id(), device);
    assert_eq!(connected.id(), signed.account.id);
    account::set_app_cap(&full, signed.account.id, device, 500_000)
        .await
        .unwrap();
    assert_eq!(
        account::devices(&full, signed.account.id)
            .await
            .unwrap()
            .into_iter()
            .find(|row| row.id == device)
            .unwrap()
            .cap_micro_usd,
        Some(500_000)
    );
}

#[tokio::test]
async fn a_check_with_wrong_digits_ends_the_request() {
    let server = LocalServer::shared();
    let (full, _events) = state_at(server.url());
    let signed = account::sign_up(
        &full,
        SignUpForm {
            invite: invite(server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: TEST_PASSWORD.into(),
            device_name: "Mac".into(),
        },
    )
    .await
    .unwrap();
    let (app, _app_events) = state_at(server.url());
    let mut pending = app
        .core
        .start_connection(
            server.url(),
            &signed.account.email,
            AppIdentity {
                name: "Sample".into(),
                app_id: "app.basehero.sample".into(),
            },
        )
        .await
        .unwrap();
    let id = pending.id();
    let (_, shown) = tokio::time::timeout(WAIT, async {
        tokio::join!(
            approval::connect_open(&full, signed.account.id, id),
            pending.digits()
        )
    })
    .await
    .unwrap();
    let wrong = if shown.unwrap().to_string() == "000 000" {
        "111111"
    } else {
        "000000"
    };
    assert_eq!(
        approval::connect_check(&full, signed.account.id, id, wrong)
            .await
            .unwrap_err()
            .kind,
        "ApprovalEnded"
    );
    assert_eq!(
        approval::connect_approve(
            &full,
            signed.account.id,
            id,
            approval::AppChoiceInput {
                bases: vec![],
                cap_micro_usd: 1_000_000,
                replaces: None,
            }
        )
        .await
        .unwrap_err()
        .kind,
        "NotFound"
    );
}

#[tokio::test]
async fn a_bad_kit_during_approval_can_be_retried() {
    let (_full, _events, new, _new_events, pending, kit, account) = setup().await;
    approval::approval_start(&new, &pending).await.unwrap();
    assert_eq!(
        approval::approval_use_kit(&new, &pending, &RecoveryKit::generate().display())
            .await
            .unwrap_err()
            .kind,
        "BadKit"
    );
    assert_eq!(
        approval::approval_use_kit(&new, &pending, &kit)
            .await
            .unwrap()
            .id,
        account
    );
    assert_eq!(
        approval::approval_use_kit(&new, &pending, &kit)
            .await
            .unwrap_err()
            .kind,
        "Invalid"
    );
}

#[tokio::test]
async fn failed_approval_post_keeps_the_same_pending_id_usable_for_kit() {
    let (_full, _events, new, _new_events, pending, kit, account) = setup().await;
    new.core.inject_fault(bh_core::test_support::Fault {
        method: "POST",
        path: "v1/approvals",
        lost_reply: false,
        times: 1,
    });
    assert_eq!(
        approval::approval_start(&new, &pending)
            .await
            .unwrap_err()
            .kind,
        "Network"
    );
    assert_eq!(
        approval::approval_use_kit(&new, &pending, &kit)
            .await
            .unwrap()
            .id,
        account
    );
}

#[tokio::test]
async fn kit_chosen_while_approval_post_is_pending_signs_in_on_same_id() {
    let (full, _events, new, _new_events, pending, kit, account) = setup().await;
    let (entered, release) = new.core.test_hold_approval_post();
    let (started, used) = tokio::time::timeout(WAIT, async {
        tokio::join!(approval::approval_start(&new, &pending), async {
            entered.await.expect("post never started");
            let used = approval::approval_use_kit(&new, &pending, &kit).await;
            release.send(()).unwrap();
            used
        })
    })
    .await
    .expect("post or kit stalled");
    assert_eq!(used.unwrap().id, account);
    assert_eq!(started.unwrap_err().kind, "NotFound");
    assert!(
        approval::approval_requests(&full, account)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn approval_events_use_the_app_event_channel() {
    let (full, events, new, _new_events, pending, _, account) = setup().await;
    let id: ApprovalId = approval::approval_start(&new, &pending).await.unwrap();
    events.wait_for(|event| matches!(event, AppEvent::Account { account: owner, event: AccountEvent::ApprovalRequested(request) } if *owner == account && request.id == id));
    let listed = approval::approval_requests(&full, account).await.unwrap();
    assert!(listed.iter().any(|request| request.id == id));
    approval::approval_decline(&full, account, id)
        .await
        .unwrap();
    events.wait_for(|event| matches!(event, AppEvent::Account { account: owner, event: AccountEvent::ApprovalClosed(closed) } if *owner == account && *closed == id));
}

#[tokio::test]
async fn malformed_digits_leave_the_open_request_usable() {
    let (full, _events, new, _new_events, pending, _, account) = setup().await;
    let id = approval::approval_start(&new, &pending).await.unwrap();
    let opened = async { approval::approval_open(&full, account, id).await.unwrap() };
    let shown = async { approval::approval_digits(&new, &pending).await.unwrap() };
    let (opened, shown) = tokio::time::timeout(WAIT, async { tokio::join!(opened, shown) })
        .await
        .unwrap();
    assert_eq!(opened.id, id);
    assert_eq!(shown.len(), 7);
    assert_eq!(
        approval::approval_approve(&full, account, id, "48291")
            .await
            .unwrap_err()
            .kind,
        "Invalid"
    );
    approval::approval_approve(&full, account, id, &shown)
        .await
        .unwrap();
    assert_eq!(
        tokio::time::timeout(WAIT, approval::approval_wait(&new, &pending))
            .await
            .unwrap()
            .unwrap()
            .id,
        account
    );
}

#[tokio::test]
async fn declining_an_open_request_reports_declined_not_cancelled() {
    let (full, _events, new, _new_events, pending, _, account) = setup().await;
    let id = approval::approval_start(&new, &pending).await.unwrap();
    tokio::time::timeout(WAIT, async {
        tokio::join!(
            approval::approval_open(&full, account, id),
            approval::approval_digits(&new, &pending)
        )
    })
    .await
    .unwrap()
    .0
    .unwrap();
    approval::approval_decline(&full, account, id)
        .await
        .unwrap();
    let reason = approval::approval_wait(&new, &pending).await.unwrap_err();
    assert_eq!(reason.kind, "ApprovalEnded");
    assert_eq!(reason.message, "Declined");
}

#[tokio::test]
async fn cancel_interrupts_a_wait_for_digits() {
    let (_full, _events, new, _new_events, pending, _, _) = setup().await;
    approval::approval_start(&new, &pending).await.unwrap();
    let (waiting, cancelling) = tokio::join!(
        async { approval::approval_digits(&new, &pending).await },
        async {
            tokio::task::yield_now().await;
            approval::approval_cancel(&new, &pending).await
        },
    );
    assert_eq!(waiting.unwrap_err().kind, "NotFound");
    cancelling.unwrap();
}

#[tokio::test]
async fn kit_interrupts_a_pending_digits_wait_without_a_state_lock() {
    let (_full, _events, new, _new_events, pending, kit, account) = setup().await;
    approval::approval_start(&new, &pending).await.unwrap();
    let (waiting, used) = tokio::time::timeout(WAIT, async {
        tokio::join!(
            async { approval::approval_digits(&new, &pending).await },
            async {
                tokio::task::yield_now().await;
                approval::approval_use_kit(&new, &pending, &kit).await
            },
        )
    })
    .await
    .expect("kit blocked behind digits");
    assert_eq!(waiting.unwrap_err().kind, "NotFound");
    assert_eq!(used.unwrap().id, account);
}

#[tokio::test]
async fn pending_expiry_cancels_an_active_approval() {
    let (full, _events, mut new, _new_events, pending, _, account) = setup().await;
    new.pending_lifetime = Duration::from_millis(100);
    // This test uses the explicit expiration entrypoint rather than restarting the timer.
    let id = approval::approval_start(&new, &pending).await.unwrap();
    new.expire_pending(pending.clone());
    tokio::time::timeout(WAIT, async {
        loop {
            if approval::approval_requests(&full, account)
                .await
                .unwrap()
                .iter()
                .all(|r| r.id != id)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("expiration did not cancel the relay request");
    assert_eq!(
        approval::approval_wait(&new, &pending)
            .await
            .unwrap_err()
            .kind,
        "NotFound"
    );
}
