mod common;

use basehero_app_lib::commands::account::{
    accounts, devices, kit_saved, new_kit, remove_device, set_kit_saved, sign_in_cancel,
    sign_in_start, sign_in_with_kit, sign_out, sign_up,
};
use basehero_app_lib::views::{AppEvent, SignInForm, SignUpForm};
use bh_core::{RecoveryKit, test_support::Fault};
use bh_testkit::{LocalServer, TEST_PASSWORD, invite};
use common::{open_at, state_at};
use std::time::Duration;

fn server() -> &'static LocalServer {
    LocalServer::shared()
}

fn form() -> SignUpForm {
    SignUpForm {
        invite: invite(server()),
        email: format!("{}@example.test", bh_core::AccountId::random()),
        password: TEST_PASSWORD.to_string().into(),
        device_name: "Mac".into(),
    }
}

#[tokio::test]
async fn sign_up_returns_a_kit_and_creates_the_personal_base() {
    let (state, _events) = state_at(server().url());
    let out = sign_up(&state, form()).await.unwrap();
    assert_eq!(out.kit.replace('-', "").len(), 26);
    let names: Vec<_> = state
        .core
        .account(out.account.id)
        .unwrap()
        .bases()
        .into_iter()
        .map(|b| b.name)
        .collect();
    assert_eq!(names, ["Personal"]);
    assert_eq!(accounts(&state).unwrap()[0].id, out.account.id);
}

#[tokio::test]
async fn sign_up_returns_kit_even_when_personal_base_fails_and_next_sign_in_creates_it() {
    let (first, _events) = state_at(server().url());
    first.core.inject_fault(Fault {
        method: "POST",
        path: "v1/bases",
        lost_reply: false,
        times: 2,
    });
    let signed = sign_up(&first, form()).await.unwrap();
    assert_eq!(signed.kit.replace('-', "").len(), 26);
    assert!(
        first
            .core
            .account(signed.account.id)
            .unwrap()
            .bases()
            .is_empty()
    );
    sign_out(&first, signed.account.id).await.unwrap();
    let pending = sign_in_start(
        &first,
        SignInForm {
            email: signed.account.email,
            password: TEST_PASSWORD.into(),
            device_name: "Fold".into(),
        },
    )
    .await
    .unwrap();
    sign_in_with_kit(&first, &pending, &signed.kit)
        .await
        .unwrap();
    assert_eq!(
        first.core.account(signed.account.id).unwrap().bases()[0].name,
        "Personal"
    );
}

#[tokio::test]
async fn pending_sign_in_expires_without_another_command() {
    let (first, _events) = state_at(server().url());
    let signed = sign_up(&first, form()).await.unwrap();
    let (mut second, _events) = state_at(server().url());
    second.pending_lifetime = Duration::from_millis(30);
    let id = sign_in_start(
        &second,
        SignInForm {
            email: signed.account.email,
            password: TEST_PASSWORD.into(),
            device_name: "Fold".into(),
        },
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while second.pending.lock().unwrap().contains_key(&id) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("pending sign-in was not removed by its timer");
}

#[tokio::test]
async fn a_wrong_kit_keeps_the_pending_sign_in_for_another_try() {
    let (first, _first_events) = state_at(server().url());
    let signed = sign_up(&first, form()).await.unwrap();
    let (second, _second_events) = state_at(server().url());
    let pending = sign_in_start(
        &second,
        SignInForm {
            email: signed.account.email.clone(),
            password: TEST_PASSWORD.into(),
            device_name: "Fold".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(pending.len(), 32);
    let wrong = RecoveryKit::generate().display();
    assert_eq!(
        sign_in_with_kit(&second, &pending, &wrong)
            .await
            .unwrap_err()
            .kind,
        "BadKit"
    );
    let account = sign_in_with_kit(&second, &pending, &signed.kit)
        .await
        .unwrap();
    assert_eq!(account.id, signed.account.id);
    assert_eq!(
        sign_in_with_kit(&second, &pending, &signed.kit)
            .await
            .unwrap_err()
            .kind,
        "NotFound"
    );
    let list = devices(&second, account.id).await.unwrap();
    assert_eq!(list.iter().filter(|device| device.this_device).count(), 1);
}

#[tokio::test]
async fn an_unknown_or_cancelled_pending_id_is_not_found() {
    let (state, _events) = state_at(server().url());
    assert_eq!(
        sign_in_with_kit(&state, "unknown", "not a kit")
            .await
            .unwrap_err()
            .kind,
        "NotFound"
    );
    let signed = sign_up(&state, form()).await.unwrap();
    let (other, _other_events) = state_at(server().url());
    let pending = sign_in_start(
        &other,
        SignInForm {
            email: signed.account.email,
            password: TEST_PASSWORD.into(),
            device_name: "Fold".into(),
        },
    )
    .await
    .unwrap();
    sign_in_cancel(&other, &pending).unwrap();
    assert_eq!(
        sign_in_with_kit(&other, &pending, &signed.kit)
            .await
            .unwrap_err()
            .kind,
        "NotFound"
    );
}

#[tokio::test]
async fn a_kit_saved_flag_survives_restart_but_a_new_kit_clears_it() {
    let (state, events) = state_at(server().url());
    let signed = sign_up(&state, form()).await.unwrap();
    assert!(!kit_saved(&state, signed.account.id).unwrap());
    set_kit_saved(&state, signed.account.id).unwrap();
    assert!(kit_saved(&state, signed.account.id).unwrap());
    drop(state);
    let again = open_at(events.data_dir(), server().url(), &events);
    assert!(kit_saved(&again, signed.account.id).unwrap());
    let replacement = new_kit(&again, signed.account.id, TEST_PASSWORD)
        .await
        .unwrap();
    assert_eq!(replacement.replace('-', "").len(), 26);
    assert!(!kit_saved(&again, signed.account.id).unwrap());
}

#[tokio::test]
async fn sign_out_forgets_the_account() {
    let (state, events) = state_at(server().url());
    let signed = sign_up(&state, form()).await.unwrap();
    sign_out(&state, signed.account.id).await.unwrap();
    assert!(accounts(&state).unwrap().is_empty());
    assert_eq!(
        kit_saved(&state, signed.account.id).unwrap_err().kind,
        "NotFound"
    );
    assert!(matches!(
        events.wait_for(|event| matches!(event, AppEvent::Account {
        account, event: bh_core::AccountEvent::Removed
    } if *account == signed.account.id)),
        AppEvent::Account { .. }
    ));
}

#[tokio::test]
async fn events_resume_after_sign_out_and_sign_in_again() {
    let (state, events) = state_at(server().url());
    let signed = sign_up(&state, form()).await.unwrap();
    sign_out(&state, signed.account.id).await.unwrap();
    events.wait_for(|e| {
        matches!(
            e,
            AppEvent::Account {
                event: bh_core::AccountEvent::Removed,
                ..
            }
        )
    });
    let pending = sign_in_start(
        &state,
        SignInForm {
            email: signed.account.email,
            password: TEST_PASSWORD.into(),
            device_name: "Mac".into(),
        },
    )
    .await
    .unwrap();
    sign_in_with_kit(&state, &pending, &signed.kit)
        .await
        .unwrap();
    let is_change = |e: &AppEvent| {
        matches!(e, AppEvent::Account {
        account, event: bh_core::AccountEvent::BasesChanged
    } if *account == signed.account.id)
    };
    let before = events.count(is_change);
    state
        .core
        .account(signed.account.id)
        .unwrap()
        .create_base("After sign-in")
        .await
        .unwrap();
    events.wait_for_count(before + 1, is_change);
}

#[tokio::test]
async fn removing_this_device_signs_out_the_app_shell() {
    let (state, events) = state_at(server().url());
    let signed = sign_up(&state, form()).await.unwrap();
    let own = state.core.account(signed.account.id).unwrap().device_id();
    remove_device(&state, signed.account.id, own).await.unwrap();
    assert!(accounts(&state).unwrap().is_empty());
    assert_eq!(
        kit_saved(&state, signed.account.id).unwrap_err().kind,
        "NotFound"
    );
    assert!(
        !events
            .data_dir()
            .join("accounts")
            .join(signed.account.id.to_string())
            .exists()
    );
}

#[tokio::test]
async fn the_app_opens_offline_with_its_accounts_and_bases() {
    let (state, events) = state_at(server().url());
    let signed = sign_up(&state, form()).await.unwrap();
    drop(state);
    let offline = open_at(
        events.data_dir(),
        "http://127.0.0.1:9".parse().unwrap(),
        &events,
    );
    assert_eq!(accounts(&offline).unwrap()[0].id, signed.account.id);
    let names: Vec<_> = offline
        .core
        .account(signed.account.id)
        .unwrap()
        .bases()
        .into_iter()
        .map(|b| b.name)
        .collect();
    assert_eq!(names, ["Personal"]);
}
