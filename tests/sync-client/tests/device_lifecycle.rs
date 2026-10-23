//! Headless device recovery and control, exercised through the same client,
//! account owner and hosted service used by the app.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_account::{
    DeviceId, REMOVAL_WAIT_MS, personal,
    recovery::{self, Password, RecoveryCode, RecoveryKeys},
};
use bh_authz::proto::{FromService, RecoveryAttachment, ToService, account_log_wrap};
use bh_storage::AlertKind;
use bh_sync::{
    permit::AppendAck,
    wire::{Request, Response},
};
use bh_sync_client::{
    Client, RecoverError, RemovalVerdict, Signer, SyncStatus, data::DataSocket, recover,
};
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use support::{
    device::{Device, ready, until},
    fake::Hosted,
    pair::{Joiner, bootstrapped, paired},
};

const PASSWORD: &str = "correct horse battery staple";

// Send one signed account control through the home, which checks its
// time-bound admission and confirms it when the log orders its append.
async fn submit_control(
    hosted: &Arc<Hosted>,
    client: &Client,
    log: bh_sync::permit::LogId,
    original: Vec<u8>,
) -> u64 {
    let answer = client
        .authz()
        .await
        .unwrap()
        .ask(ToService::SubmitControl {
            log,
            event: original.clone(),
            delivery: None,
            attachment: None,
        })
        .await
        .unwrap();
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    let [append] = <[_; 1]>::try_from(items).unwrap();
    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    let event = account_log_wrap(&original, None).unwrap().encode();
    match data
        .ask(|id| Request::Append {
            id,
            permit: append.unwrap(),
            event,
        })
        .await
        .unwrap()
    {
        Response::Acked { ack, .. } => AppendAck::decode(&ack).unwrap().head.position,
        other => panic!("{other:?}"),
    }
}

async fn signed_up_with_status(
    hosted: &Arc<Hosted>,
) -> (Device, Client, tokio::sync::watch::Receiver<SyncStatus>) {
    let mac = Device::new();
    let (client, status) = mac.start(hosted);
    until(30, "home and directory ready", || {
        !mac.home_pending() && mac.signer.directory_state().unwrap() == Some((1, true))
    })
    .await;
    (mac, client, status)
}

async fn signed_up(hosted: &Arc<Hosted>) -> (Device, Client) {
    let (mac, client, _) = signed_up_with_status(hosted).await;
    (mac, client)
}

fn kit(mac: &Device) -> RecoveryCode {
    RecoveryCode::from_kit_text(mac.kit.as_deref().unwrap()).unwrap()
}

async fn recover_onto(
    hosted: &Arc<Hosted>,
    mac: &Device,
    joiner: &Joiner,
    password: &str,
    code: &RecoveryCode,
) -> Result<(), RecoverError> {
    let mut account = joiner.account();
    recover(
        &mac.endpoint(hosted),
        hosted.connector(),
        joiner.owner.clone(),
        joiner.id,
        &mut account,
        joiner.prover(),
        &Password::new(password).unwrap(),
        code,
    )
    .await
    .map(drop)
}

fn alerts(device: &Device) -> Vec<AlertKind> {
    device
        .owner
        .shared_database(device.id)
        .unwrap()
        .lock()
        .unwrap()
        .alerts(50)
        .unwrap()
        .into_iter()
        .map(|a| a.kind)
        .collect()
}

async fn joined(hosted: &Arc<Hosted>, mac: &Device) -> Device {
    let fold = Device::join(mac, hosted).await;
    until(20, "addition followed", || {
        mac.signer.current_account().unwrap().head().position >= 4
    })
    .await;
    fold
}

async fn pending(client: &Client, from: DeviceId) -> u64 {
    let verdict = client.removal_verdict();
    until(30, "pending removal verified", || {
        matches!(*verdict.borrow(), RemovalVerdict::Pending { .. })
    })
    .await;
    let RemovalVerdict::Pending { deadline_ms, by } = *verdict.borrow() else {
        unreachable!()
    };
    assert!(by == Some(from));
    deadline_ms
}

#[tokio::test(start_paused = true)]
async fn step1_recover_with_no_other_device_and_edit_notes() {
    // Host screen: devices.rs::a_recovered_device_opens_its_notes_and_names_itself.
    let hosted = Hosted::new();
    let (mac, mac_client) = signed_up(&hosted).await;
    let (writer, update) = mac.new_note("before recovery");
    until(30, "first note accepted", || mac.acked(update).is_some()).await;
    mac_client.shutdown().await;
    let emu = Joiner::new();
    recover_onto(&hosted, &mac, &emu, PASSWORD, &kit(&mac))
        .await
        .unwrap();
    let emu = emu.into_device();
    assert!(emu.usable());
    emu.authorize().unwrap();
    let (emu_client, _) = emu.start(&hosted);
    until(30, "notes received", || {
        emu.paragraphs(writer.note) == ["before recovery"]
    })
    .await;
    assert_eq!(emu.paragraphs(writer.note), ["before recovery"]);
    let mut writer = emu.writer(writer.note);
    let update = emu.append(&mut writer, "after recovery");
    until(30, "recovered edit accepted", || {
        emu.acked(update).is_some()
    })
    .await;
    assert!(emu.acked(update).is_some());
    let (mac_client, _) = mac.start(&hosted);
    until(30, "kit use and added-device notices", || {
        mac_client.wake();
        alerts(&mac).contains(&AlertKind::DeviceAddedByKit)
            && alerts(&mac).contains(&AlertKind::KitUsed)
    })
    .await;
    assert!(alerts(&mac).contains(&AlertKind::DeviceAddedByKit));
    assert!(alerts(&mac).contains(&AlertKind::KitUsed));
    mac_client.shutdown().await;
    emu_client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn step2_change_password_and_kit_refuses_the_old_kit() {
    // Host screens: devices.rs::replace_recovery_rotates_and_retires_the_old_kit.
    // A replaced kit must not spend a password try when presented later.
    let hosted = Hosted::new();
    let (mac, client) = signed_up(&hosted).await;
    let old = kit(&mac);
    let new = replace_kit(&hosted, &mac, &client).await;
    assert!(matches!(
        recover_onto(&hosted, &mac, &Joiner::new(), PASSWORD, &old).await,
        Err(RecoverError::NotRecognised)
    ));
    assert!(
        recover_onto(&hosted, &mac, &Joiner::new(), PASSWORD, &new)
            .await
            .is_ok()
    );
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn step3_cancelled_removal_stays_active_on_live_device() {
    // Host screen: devices.rs::timely_cancel_shows_ready_and_keeps_the_device.
    let hosted = Hosted::new();
    let (mac, mac_client) = signed_up(&hosted).await;
    hosted.edge.clock.advance(REMOVAL_WAIT_MS + 1);
    let fold = joined(&hosted, &mac).await;
    let (fold_client, _) = fold.start(&hosted);
    until(30, "fold registered", || fold.registered()).await;
    let position = submit_control(
        &hosted,
        &mac_client,
        mac.account_log,
        mac.signer.request_removal(fold.signer.device_id()),
    )
    .await;
    fold_client.wake();
    let deadline = pending(&fold_client, mac.signer.device_id()).await;
    let cancel = mac
        .signer
        .cancel_removal(fold.signer.device_id(), position)
        .unwrap();
    assert_eq!(
        submit_control(&hosted, &mac_client, mac.account_log, cancel).await,
        position + 1
    );
    // Advance paused Tokio time while the home can still confirm a timely
    // cancellation. Merely offsetting its TestClock would not fire a timer.
    tokio::time::advance(std::time::Duration::from_secs(301)).await;
    fold_client.check_removal();
    until(30, "live cancellation verified", || {
        fold.signer.current_account().unwrap().head().position > position
            && *fold_client.removal_verdict().borrow() == RemovalVerdict::Active
    })
    .await;
    let until_deadline = deadline - hosted.edge.clock.now() + 1;
    tokio::time::advance(std::time::Duration::from_millis(until_deadline)).await;
    tokio::time::advance(std::time::Duration::from_secs(301)).await;
    assert!(hosted.edge.clock.now() > deadline);
    let mut checked = fold_client.removal_verdict();
    checked.borrow_and_update();
    fold_client.check_removal();
    // The removal lane publishes this watch value only after it has
    // verified the challenged public evidence, even when Active is unchanged.
    tokio::time::timeout(Duration::from_secs(30), checked.changed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(*checked.borrow_and_update(), RemovalVerdict::Active);
    assert!(fold.owner.shared_database(fold.id).is_ok());
    fold_client.shutdown().await;
    mac_client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn step4_removal_through_the_wait() {
    // Host screen: devices.rs::remote_removal_shows_erased_screen_on_target; status: trust.rs::protecting_until_the_base_epoch_reopens.
    let hosted = Hosted::new();
    let (mac, mac_client, mut mac_status) = signed_up_with_status(&hosted).await;
    let fold = joined(&hosted, &mac).await;
    let (fold_client, _) = fold.start(&hosted);
    until(30, "fold registered", || fold.registered()).await;
    // Pair a third device for real so it can receive and use the next key.
    let (third, added) = paired(&hosted, &mac, &mac_client).await;
    bootstrapped(&hosted, &third).await;
    third.authorize().unwrap();
    mac.signer.approve_controls.store(true, Ordering::SeqCst);
    until(30, "third addition followed", || {
        mac.signer.current_account().unwrap().head() == added
    })
    .await;
    let (third_client, _) = third.start(&hosted);
    until(30, "third registered", || third.registered()).await;
    let requested = submit_control(
        &hosted,
        &mac_client,
        mac.account_log,
        mac.signer.request_removal(fold.signer.device_id()),
    )
    .await;
    assert_eq!(requested, added.position + 1);
    fold_client.wake();
    let deadline = pending(&fold_client, mac.signer.device_id()).await;
    assert_eq!(
        *fold_client.removal_verdict().borrow(),
        RemovalVerdict::Pending {
            deadline_ms: deadline,
            by: Some(mac.signer.device_id())
        }
    );
    let (last_note, last) = fold.new_note("last edit during wait");
    fold_client.wake();
    until(30, "last edit accepted", || fold.acked(last).is_some()).await;
    until(
        30,
        "Mac reads the Fold's last edit before the wait ends",
        || {
            mac_client.wake();
            mac.paragraphs(last_note.note) == ["last edit during wait"]
        },
    )
    .await;
    assert_eq!(mac.paragraphs(last_note.note), ["last edit during wait"]);
    let hold = mac.signer.hold_next_sign();
    tokio::time::advance(Duration::from_millis(
        deadline - hosted.edge.clock.now() + 1,
    ))
    .await;
    mac_client.wake();
    fold_client.wake();
    tokio::time::timeout(Duration::from_secs(60), hold.arrived)
        .await
        .unwrap()
        .unwrap();
    // trust.rs::protecting_until_the_base_epoch_reopens asserts the
    // Protecting → Synced watch transition while this signature is held.
    hold.release.send(()).unwrap();
    until(120, "requester synced under the next epoch", || {
        mac_client.wake();
        *mac_status.borrow_and_update() == SyncStatus::Synced
    })
    .await;
    until(30, "removal effective", || {
        matches!(
            *fold_client.removal_verdict().borrow(),
            RemovalVerdict::Removed { .. }
        )
    })
    .await;
    assert_eq!(
        *fold_client.removal_verdict().borrow(),
        RemovalVerdict::Removed { unsent: 0 }
    );
    until(120, "third accepts the next personal key", || {
        third_client.wake();
        third.signer.accepts.load(Ordering::SeqCst) > 0
    })
    .await;
    let (note, update) = third.new_note("after removal");
    third_client.wake();
    until(60, "third edit accepted", || third.acked(update).is_some()).await;
    until(60, "Mac reads the third edit", || {
        mac.paragraphs(note.note) == ["after removal"]
    })
    .await;
    assert_eq!(mac.paragraphs(note.note), ["after removal"]);
    third_client.shutdown().await;
    fold_client.shutdown().await;
    mac_client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn step5_recent_device_is_not_mature_but_mac_is_after_wait() {
    // Host screens: devices.rs::remove_now_with_kit_from_a_mature_device_takes_effect_at_once and remove_now_from_a_recent_device_is_refused_before_signing.
    let hosted = Hosted::new();
    let (mac, client) = signed_up(&hosted).await;
    let fold = joined(&hosted, &mac).await;
    let account = mac.signer.current_account().unwrap();
    let now = hosted.edge.clock.now();
    assert!(!account.is_mature(fold.signer.device_id(), now));
    hosted.edge.clock.advance(REMOVAL_WAIT_MS + 1);
    assert!(account.is_mature(mac.signer.device_id(), hosted.edge.clock.now()));
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn step6_forged_or_unconfirmed_removals_are_refused_with_alert_and_no_erase() {
    // Host refused alert: devices.rs::forged_removal_alert_is_visible_in_host.
    for kind in [
        "bad_signature",
        "wrong_signer",
        "missing_confirmation",
        "foreign_root",
    ] {
        let hosted = Hosted::new();
        let (target, client) = signed_up(&hosted).await;
        client.shutdown().await;
        let position = hosted
            .edge
            .order_account(target.account_log, &target.signer.remove_self());
        match kind {
            "bad_signature" => hosted.corrupt_accepted_account(target.account_log, true),
            "wrong_signer" => {
                hosted.edge.serve_account(
                    target.account_log,
                    position,
                    &[target.signer.remove_self_signed_by_ordinary_key()],
                );
                hosted.confirm_served_account(target.account_log);
            }
            "missing_confirmation" => {
                hosted.omit_account_confirmation(target.account_log, position)
            }
            "foreign_root" => hosted.foreign_root_account_confirmations(target.account_log),
            _ => unreachable!(),
        }
        let (client, _) = target.start(&hosted);
        until(30, "forged removal refused", || {
            *client.removal_verdict().borrow() == RemovalVerdict::Refused
        })
        .await;
        assert_eq!(
            *client.removal_verdict().borrow(),
            RemovalVerdict::Refused,
            "{kind}"
        );
        assert!(
            alerts(&target).contains(&AlertKind::RefusedChange),
            "{kind}"
        );
        assert!(target.owner.shared_database(target.id).is_ok(), "{kind}");
        client.shutdown().await;
    }
}

// A real member signs a rotation tied to a pending request before that
// request's deadline. The fake home certifies those bytes as a hostile home
// might; the target must not accept them as a valid reason to erase.
#[tokio::test(start_paused = true)]
async fn step6_early_rotation_is_refused_without_erasing() {
    let hosted = Hosted::new();
    let (mac, mac_client) = signed_up(&hosted).await;
    hosted.edge.clock.advance(REMOVAL_WAIT_MS + 1);
    let fold = joined(&hosted, &mac).await;
    let requested = submit_control(
        &hosted,
        &mac_client,
        mac.account_log,
        mac.signer.request_removal(fold.signer.device_id()),
    )
    .await;
    until(30, "request followed before signing rotation", || {
        mac.signer.current_account().unwrap().head().position == requested
    })
    .await;
    let deadline = hosted.edge.clock.now() + REMOVAL_WAIT_MS;
    assert!(hosted.edge.clock.now() < deadline);
    let (rotation, _, _) = mac
        .signer
        .rotate_personal(requested, hosted.edge.clock.now());
    let cancel = mac
        .signer
        .cancel_removal(fold.signer.device_id(), requested)
        .unwrap();
    let cancelled = submit_control(&hosted, &mac_client, mac.account_log, cancel).await;
    // Keep the real home serving a valid head so that the hostile fake can
    // substitute a signed early rotation at its exact ordered position.
    hosted
        .edge
        .serve_account(mac.account_log, cancelled, &[rotation]);
    hosted.keep_served_account_head();
    hosted.confirm_served_account(mac.account_log);
    let (fold_client, _) = fold.start(&hosted);
    fold_client.check_removal();
    until(30, "early rotation rejected", || {
        *fold_client.removal_verdict().borrow() == RemovalVerdict::Refused
    })
    .await;
    assert_eq!(
        *fold_client.removal_verdict().borrow(),
        RemovalVerdict::Refused
    );
    assert!(alerts(&fold).contains(&AlertKind::RefusedChange));
    assert!(fold.owner.shared_database(fold.id).is_ok());
    fold_client.shutdown().await;
    mac_client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn step7_flag_inputs_are_available_for_about() {
    // About screen: apps/client/src-tauri/src/about.rs::about_reports_no_test_settings_in_a_default_build.
    let info = bh_flags::build_info();
    assert!(!info.build.is_empty());
    assert!(!info.commit.is_empty());
    assert!(
        bh_flags::off_default().is_empty(),
        "the default build has no test settings"
    );
}

#[tokio::test(start_paused = true)]
async fn try_counters_wrong_code_no_try_then_five_hourly_daily_across_restart() {
    let hosted = Hosted::new();
    let (mac, client) = signed_up(&hosted).await;
    client.shutdown().await;
    let wrong_code = RecoveryCode::generate();
    for _ in 0..3 {
        assert!(matches!(
            recover_onto(&hosted, &mac, &Joiner::new(), PASSWORD, &wrong_code).await,
            Err(RecoverError::NotRecognised)
        ));
    }
    let mut last = None;
    for remaining in (0..5).rev() {
        let error = recover_onto(
            &hosted,
            &mac,
            &Joiner::new(),
            "not the password",
            &kit(&mac),
        )
        .await
        .unwrap_err();
        let RecoverError::PasswordMismatch {
            tries_left,
            next_try_ms,
        } = error
        else {
            panic!("{error:?}")
        };
        assert_eq!(tries_left, remaining);
        last = next_try_ms;
    }
    let next = last.expect("hourly wait");
    assert_eq!(next, hosted.edge.clock.now() + 3_600_000);
    hosted.restart_service().await;
    assert_eq!(
        recover_onto(&hosted, &mac, &Joiner::new(), PASSWORD, &kit(&mac)).await,
        Err(RecoverError::Wait { next_try_ms: next })
    );
    let fifth = next - 3_600_000;
    for hour in 1..=24 {
        let at = fifth + hour * 3_600_000;
        hosted.edge.clock.advance(at - hosted.edge.clock.now());
        let error = recover_onto(
            &hosted,
            &mac,
            &Joiner::new(),
            "not the password",
            &kit(&mac),
        )
        .await
        .unwrap_err();
        let RecoverError::PasswordMismatch {
            tries_left: 0,
            next_try_ms: Some(next_try_ms),
        } = error
        else {
            panic!("{error:?}")
        };
        assert_eq!(
            next_try_ms,
            at + if hour == 24 { 86_400_000 } else { 3_600_000 }
        );
    }
    assert_eq!(
        recover_onto(&hosted, &mac, &Joiner::new(), PASSWORD, &kit(&mac)).await,
        Err(RecoverError::Wait {
            next_try_ms: fifth + 2 * 86_400_000
        })
    );
}

#[tokio::test(start_paused = true)]
async fn mutual_removal_resolves_by_first_deadline() {
    let hosted = Hosted::new();
    let (mac, mac_client) = signed_up(&hosted).await;
    let fold = joined(&hosted, &mac).await;
    let (fold_client, _) = fold.start(&hosted);
    until(30, "fold registered", || fold.registered()).await;
    hosted.edge.order_account(
        mac.account_log,
        &mac.signer.request_removal(fold.signer.device_id()),
    );
    fold_client.wake();
    let first = pending(&fold_client, mac.signer.device_id()).await;
    until(30, "mac follows its request", || {
        mac.signer.current_account().unwrap().head().position >= 5
    })
    .await;
    hosted.edge.clock.advance(1_000);
    hosted.edge.order_account(
        mac.account_log,
        &fold.signer.request_removal(mac.signer.device_id()),
    );
    mac_client.wake();
    let second = pending(&mac_client, fold.signer.device_id()).await;
    assert!(first < second);
    hosted
        .edge
        .clock
        .advance(first - hosted.edge.clock.now() + 1);
    fold_client.wake();
    mac_client.wake();
    until(30, "first removal wins", || {
        matches!(
            *fold_client.removal_verdict().borrow(),
            RemovalVerdict::Removed { .. }
        )
    })
    .await;
    until(30, "later request lapses", || {
        *mac_client.removal_verdict().borrow() == RemovalVerdict::Active
    })
    .await;
    assert_eq!(
        *mac_client.removal_verdict().borrow(),
        RemovalVerdict::Active
    );
    fold_client.shutdown().await;
    mac_client.shutdown().await;
}

/// Still needs the admission snapshot and three scenarios before enabling:
/// rotation during recovery, cancellation of the pending request, and the
/// requester's own removal before its deadline.
#[tokio::test(start_paused = true)]
#[ignore = "needs the admission snapshot"]
async fn recover_while_another_removal_is_pending_keeps_its_deadline() {
    let hosted = Hosted::new();
    let (mac, mac_client) = signed_up(&hosted).await;
    let fold = joined(&hosted, &mac).await;
    let (fold_client, _) = fold.start(&hosted);
    until(30, "fold registered", || fold.registered()).await;
    hosted.edge.order_account(
        mac.account_log,
        &mac.signer.request_removal(fold.signer.device_id()),
    );
    fold_client.wake();
    let deadline = pending(&fold_client, mac.signer.device_id()).await;
    let joiner = Joiner::new();
    recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac))
        .await
        .unwrap();
    let recovered = joiner.into_device();
    assert!(
        recovered
            .signer
            .current_account()
            .unwrap()
            .pending_removals(hosted.edge.clock.now())
            .iter()
            .any(|r| r.deadline_ms == deadline)
    );
    hosted
        .edge
        .clock
        .advance(deadline - hosted.edge.clock.now() + 1);
    fold_client.wake();
    until(30, "original deadline effective", || {
        matches!(
            *fold_client.removal_verdict().borrow(),
            RemovalVerdict::Removed { .. }
        )
    })
    .await;
    fold_client.shutdown().await;
    mac_client.shutdown().await;
}

// Submit a signed replacement to the home, just as the account owner does.
async fn replace_kit(hosted: &Arc<Hosted>, mac: &Device, client: &Client) -> RecoveryCode {
    mac.signer
        .approve_controls
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let (mut account, cap, _) = mac.signer.account_owner();
    let state = account.verified(&cap).unwrap().clone();
    let current = ready(account.open_current_personal(&cap)).unwrap();
    let keys = RecoveryKeys::generate();
    let code = RecoveryCode::generate();
    let record =
        recovery::prepare_replacement(&state, &keys, &Password::new(PASSWORD).unwrap(), &code)
            .unwrap();
    let seal = personal::seal_for_new_recovery(&state, &current, &keys.public()).unwrap();
    let request = state
        .replace_recovery(
            mac.signer.device_id(),
            keys.public(),
            record.digest(),
            personal::seal_digest(&seal),
        )
        .unwrap();
    let event = ready(account.sign_control(&cap, &request)).unwrap();
    let answer = client
        .authz()
        .await
        .unwrap()
        .ask(ToService::SubmitControl {
            log: mac.account_log,
            event: event.as_bytes().to_vec(),
            delivery: None,
            attachment: Some(Box::new(RecoveryAttachment {
                record: Some(record.as_bytes().to_vec()),
                recovery_seal: seal,
                rotation_body: None,
            })),
        })
        .await
        .unwrap();
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    let [append] = <[_; 1]>::try_from(items).unwrap();
    let data = DataSocket::open(hosted.connector().as_ref()).await.unwrap();
    let wrapped = account_log_wrap(event.as_bytes(), None).unwrap().encode();
    assert!(matches!(data.ask(|id| Request::Append {
        id, permit: append.unwrap(), event: wrapped,
    }).await.unwrap(), Response::Acked { ack, .. } if AppendAck::decode(&ack).unwrap().head.position == 4));
    code
}
