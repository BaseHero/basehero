//! Recovering an account with its password and kit when no device of it
//! survives: a fresh container claims the kit from the home, verifies the
//! account's history under the hosting root, adds itself with the recovery
//! key on that one connection, admits its own base from the account
//! directory and copies its addition into the base with the recovery key.
//! Real signed-up devices, the real authorization service behind the
//! attested channel, and the hosted fake's data edge, on a paused runtime.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_account::{
    AccountEvent, DevicePublicKeys, REMOVAL_WAIT_MS,
    directory::DirectoryEntry,
    personal,
    recovery::{self, Password, RecoveryCode, RecoveryKeys},
};
use bh_authz::proto::{
    FromService, RecoveryAnswer, RecoveryAttachment, ToService, account_log_unwrap,
    account_log_wrap,
};
use bh_crypto::{KemKey, SigningKey};
use bh_device::base_keys::SealHeader;
use bh_event::account_run::decode_copies;
use bh_storage::AlertKind;
use bh_sync::{
    Route,
    permit::{AppendAck, LogId},
    wire::{Request, Response},
};
use bh_sync_client::{Client, RecoverError, Signer, SyncStatus, data::DataSocket, recover};
use std::{
    path::Path,
    sync::{Arc, atomic::Ordering},
};
use support::{
    device::{Device, ready, until},
    fake::{ConfirmTamper, Hook, Hosted},
    pair::{Joiner, bootstrapped, paired},
};
use tokio::sync::watch;

const PASSWORD: &str = "correct horse battery staple";

type Started = (Client, watch::Receiver<SyncStatus>);

/// A signed-up device whose home holds its kit and whose own base's
/// directory entry is written, its client running.
async fn signed_up(hosted: &Arc<Hosted>) -> (Device, Started) {
    let mac = Device::new();
    let started = mac.start(hosted);
    until(30, "home stored and entry written", || {
        !mac.home_pending() && mac.signer.directory_state().unwrap() == Some((1, true))
    })
    .await;
    (mac, started)
}

/// As `signed_up`, with a note written and acknowledged, and the device
/// then lost: its client never runs again. The note's id.
async fn lost_with_a_note(hosted: &Arc<Hosted>) -> (Device, [u8; 32]) {
    let (mac, (client, _)) = signed_up(hosted).await;
    let (writer, update) = mac.new_note("Written before the loss");
    until(20, "note acknowledged", || mac.acked(update).is_some()).await;
    client.shutdown().await;
    (mac, writer.note)
}

fn kit(mac: &Device) -> RecoveryCode {
    RecoveryCode::from_kit_text(mac.kit.as_deref().unwrap()).unwrap()
}

/// Recover `mac`'s account onto `joiner` with `password` and `code`, over
/// the endpoint every device of the account uses.
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

/// The account log's originals, in order.
fn originals(hosted: &Hosted, mac: &Device) -> Vec<Vec<u8>> {
    hosted
        .edge
        .entries(mac.account_log)
        .iter()
        .map(|(_, event)| account_log_unwrap(event).unwrap().0.to_vec())
        .collect()
}

/// How many devices the account log ever added.
fn additions(hosted: &Hosted, mac: &Device) -> usize {
    originals(hosted, mac)
        .iter()
        .filter(|original| {
            matches!(
                AccountEvent::decode(original).unwrap().change(),
                bh_account::AccountChange::DeviceAdded { .. }
            )
        })
        .count()
}

/// Each accepted account copy in `device`'s own base, in order: the
/// account originals it copied.
fn runs(hosted: &Hosted, device: &Device) -> Vec<Vec<Vec<u8>>> {
    hosted
        .edge
        .entries(device.log())
        .iter()
        .filter(|(ordered, _)| ordered.route() == Route::Control && ordered.head().position > 1)
        .filter_map(|(ordered, _)| {
            let fact = device
                .owner
                .control_fact(device.id, device.log(), ordered.head().position)
                .unwrap()?;
            let record = fact.account_change.filter(|_| fact.accepted)?;
            Some(
                decode_copies(&record)
                    .unwrap()
                    .into_iter()
                    .map(|copy| copy.original)
                    .collect(),
            )
        })
        .collect()
}

/// The times of the kit-used alerts `device` keeps, oldest first.
fn kit_used(device: &Device) -> Vec<u64> {
    let mut times: Vec<u64> = device
        .owner
        .shared_database(device.id)
        .unwrap()
        .lock()
        .unwrap()
        .alerts(50)
        .unwrap()
        .into_iter()
        .filter(|alert| alert.kind == AlertKind::KitUsed)
        .filter_map(|alert| alert.time_ms)
        .collect();
    times.sort_unstable();
    times
}

fn copied(device: &Device) -> u64 {
    device
        .progress()
        .account
        .map_or(0, |(position, _)| position)
}

/// Every file under `dir`, the databases' WAL and sidecars included.
fn files(dir: &Path) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(files(&path));
        } else {
            out.push(std::fs::read(&path).unwrap());
        }
    }
    out
}

fn holds(dir: &Path, needle: &[u8]) -> bool {
    files(dir)
        .iter()
        .any(|bytes| bytes.windows(needle.len()).any(|w| w == needle))
}

/// The ordinary answer of a recovery claim's tries: the next wrong
/// password's.
async fn tries_left(hosted: &Arc<Hosted>, mac: &Device) -> u8 {
    match recover_onto(hosted, mac, &Joiner::new(), "not the password", &kit(mac)).await {
        Err(RecoverError::PasswordMismatch { tries_left, .. }) => tries_left,
        other => panic!("{other:?}"),
    }
}

/// Replace the account's kit from `mac`, as a password-and-kit change
/// does, ordering its ReplaceRecovery through the account home. The base
/// does not copy it: `mac` holds no approval for a control. The new kit's
/// code.
async fn replace_kit(hosted: &Arc<Hosted>, mac: &Device, client: &Client) -> RecoveryCode {
    mac.signer
        .approve_controls
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let (mut account, cap, _) = mac.signer.account_owner();
    let state = account.verified(&cap).unwrap().clone();
    let current = ready(account.open_current_personal(&cap)).unwrap();
    let keys = RecoveryKeys::generate();
    let code = RecoveryCode::generate();
    let password = Password::new(PASSWORD).unwrap();
    let record = recovery::prepare_replacement(&state, &keys, &password, &code).unwrap();
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
    match data
        .ask(|id| Request::Append {
            id,
            permit: append.unwrap(),
            event: wrapped,
        })
        .await
        .unwrap()
    {
        Response::Acked { ack, .. } => {
            assert_eq!(AppendAck::decode(&ack).unwrap().head.position, 4);
        }
        other => panic!("{other:?}"),
    }
    code
}

#[tokio::test(start_paused = true)]
async fn recover_with_no_surviving_device_opens_and_edits_own_base_notes() {
    let hosted = Hosted::new();
    let (mac, note) = lost_with_a_note(&hosted).await;

    let joiner = Joiner::new();
    recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac))
        .await
        .unwrap();
    let fold = joiner.into_device();
    assert!(fold.usable());
    assert_eq!(fold.base, mac.base);
    fold.authorize().unwrap();
    let (client, _) = fold.start(&hosted);
    until(20, "note received", || {
        fold.paragraphs(note) == vec!["Written before the loss".to_string()]
    })
    .await;
    let mut writer = fold.writer(note);
    let update = fold.append(&mut writer, "Written after recovery");
    until(20, "new edit acknowledged", || fold.acked(update).is_some()).await;
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn recovered_addition_waits_from_its_confirmation() {
    let hosted = Hosted::new();
    let (mac, _) = lost_with_a_note(&hosted).await;
    // The addition is ordered, then the home's clock moves on before it
    // confirms it.
    hosted
        .edge
        .hook(Hook::AdvanceAfterAccountAppend { ms: 5_000 });
    let permitted = hosted.edge.clock.now();
    let joiner = Joiner::new();
    recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac))
        .await
        .unwrap();
    let fold = joiner.into_device();
    let state = fold.signer.current_account().unwrap();
    let added = state.added_at(fold.signer.device_id()).unwrap();
    assert!(added >= permitted + 5_000, "from its confirmation");
    assert!(added <= hosted.edge.clock.now());
    // A recovered device is not old enough to remove another at once
    // until the wait has passed since then.
    let device = fold.signer.device_id();
    assert!(!state.is_mature(device, added + REMOVAL_WAIT_MS - 1));
    assert!(state.is_mature(device, added + REMOVAL_WAIT_MS));
}

#[tokio::test(start_paused = true)]
async fn directory_discovers_the_own_base_and_the_recovery_key_copies_the_addition() {
    let hosted = Hosted::new();
    let (mac, _) = lost_with_a_note(&hosted).await;
    let reads = hosted
        .edge
        .directory_reads
        .load(std::sync::atomic::Ordering::SeqCst);
    let joiner = Joiner::new();
    recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac))
        .await
        .unwrap();
    assert!(
        hosted
            .edge
            .directory_reads
            .load(std::sync::atomic::Ordering::SeqCst)
            > reads,
        "the base was found in the directory"
    );
    let fold = joiner.into_device();
    assert_eq!(fold.base, mac.base);
    // One run copied this device's addition, and the base holds it.
    let addition = originals(&hosted, &mac)[3].clone();
    assert_eq!(runs(&hosted, &fold).last(), Some(&vec![addition]));
    assert_eq!(copied(&fold), 4);
    // The recovered device signed no base control of its own: the copy is
    // the recovery key's, as the base verified it.
    assert_eq!(
        fold.signer
            .control_signatures
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[tokio::test(start_paused = true)]
async fn base_that_missed_a_kit_change_is_unstuck_by_the_next_recovery() {
    let hosted = Hosted::new();
    let (mac, (client, _)) = signed_up(&hosted).await;
    let before = mac.signer.current_account().unwrap();
    let old = kit(&mac);
    let old_keys = recovery::open_current_record(
        &before,
        &mac.retained().recovery_record,
        &Password::new(PASSWORD).unwrap(),
        &old,
    )
    .unwrap();
    let code = replace_kit(&hosted, &mac, &client).await;
    client.shutdown().await;
    assert_eq!(copied(&mac), 3, "the base never copied the kit change");

    // The old kit is no longer recognised.
    assert_eq!(
        recover_onto(&hosted, &mac, &Joiner::new(), PASSWORD, &old).await,
        Err(RecoverError::NotRecognised)
    );
    let joiner = Joiner::new();
    recover_onto(&hosted, &mac, &joiner, PASSWORD, &code)
        .await
        .unwrap();
    let fold = joiner.into_device();
    let log = originals(&hosted, &mac);
    assert_eq!(log.len(), 5);
    assert_eq!(
        runs(&hosted, &fold).last(),
        Some(&vec![log[3].clone(), log[4].clone()]),
        "the kit change and the addition, in one run"
    );
    assert_eq!(copied(&fold), 5);
    // The replaced kit's key signs no run for the account as it is now.
    let after = fold.signer.current_account().unwrap();
    assert!(
        old_keys
            .sign_base_control(&after, after.recovery_keys().unwrap().signing(), &[0; 400])
            .is_err()
    );
    assert!(
        old_keys
            .sign_base_control(&after, old_keys.public().signing(), &[0; 400])
            .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn retry_after_the_addition_resumes_the_same_device() {
    let hosted = Hosted::new();
    let (mac, _) = lost_with_a_note(&hosted).await;
    // The addition is ordered and confirmed; the confirmation's answer is
    // lost with the connection.
    hosted.lose_next_confirm_answer();
    let joiner = Joiner::new();
    recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac))
        .await
        .unwrap();
    assert_eq!(additions(&hosted, &mac), 1, "one addition, no second");
    assert_eq!(originals(&hosted, &mac).len(), 4);
    let device = joiner.keys.id();
    // And asked again from the start, it adds no other device.
    recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac))
        .await
        .unwrap();
    assert_eq!(originals(&hosted, &mac).len(), 4);
    let fold = joiner.into_device();
    assert!(fold.signer.device_id() == device);
    assert_eq!(tries_left(&hosted, &mac).await, 4, "no try was used");
}

#[tokio::test(start_paused = true)]
async fn wrong_code_uses_no_try() {
    let hosted = Hosted::new();
    let (mac, _) = lost_with_a_note(&hosted).await;
    let joiner = Joiner::new();
    for _ in 0..6 {
        assert_eq!(
            recover_onto(&hosted, &mac, &joiner, PASSWORD, &RecoveryCode::generate()).await,
            Err(RecoverError::NotRecognised)
        );
    }
    assert!(!joiner.has_account());
    assert_eq!(tries_left(&hosted, &mac).await, 4);
}

#[tokio::test(start_paused = true)]
async fn wrong_password_uses_a_try_and_reports_remaining() {
    let hosted = Hosted::new();
    let (mac, _) = lost_with_a_note(&hosted).await;
    let joiner = Joiner::new();
    for expected in (0..5).rev() {
        let Err(RecoverError::PasswordMismatch {
            tries_left,
            next_try_ms,
        }) = recover_onto(&hosted, &mac, &joiner, "not the password", &kit(&mac)).await
        else {
            panic!("not a mismatch");
        };
        assert_eq!(tries_left, expected);
        // The free tries used, the next one waits.
        assert_eq!(next_try_ms.is_some(), expected == 0);
    }
    let Err(RecoverError::Wait { next_try_ms }) =
        recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac)).await
    else {
        panic!("not a wait");
    };
    assert!(next_try_ms > hosted.edge.clock.now());
    assert!(!joiner.has_account());
}

#[tokio::test(start_paused = true)]
async fn a_lost_answer_to_a_wrong_password_uses_one_try() {
    let hosted = Hosted::new();
    let (mac, _) = lost_with_a_note(&hosted).await;
    // The home judges the claim and its answer is lost: recovery does not
    // claim again by itself, which could use another try.
    hosted.lose_next_recover_answer();
    assert_eq!(
        recover_onto(
            &hosted,
            &mac,
            &Joiner::new(),
            "not the password",
            &kit(&mac)
        )
        .await,
        Err(RecoverError::Unreachable)
    );
    assert_eq!(tries_left(&hosted, &mac).await, 3, "one try for that call");
}

#[tokio::test(start_paused = true)]
async fn interrupted_before_copies_asks_again_and_costs_no_try() {
    let hosted = Hosted::new();
    let (mac, note) = lost_with_a_note(&hosted).await;
    // The copy's append commits; then the home stops answering before this
    // device learns it was ordered.
    hosted.edge.hook(Hook::DropAfterAppend { then_down: true });
    let joiner = Joiner::new();
    assert_eq!(
        recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac)).await,
        Err(RecoverError::Unreachable)
    );
    assert_eq!(additions(&hosted, &mac), 1);
    hosted.come_up();
    // Asked again, recovery checks the kit again and finishes.
    recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac))
        .await
        .unwrap();
    assert_eq!(additions(&hosted, &mac), 1, "the same device resumed");
    let fold = joiner.into_device();
    assert_eq!(copied(&fold), 4);
    fold.authorize().unwrap();
    let (client, _) = fold.start(&hosted);
    until(20, "note received", || {
        fold.paragraphs(note) == vec!["Written before the loss".to_string()]
    })
    .await;
    client.shutdown().await;
    assert_eq!(tries_left(&hosted, &mac).await, 4, "no try was used");
}

#[tokio::test(start_paused = true)]
async fn recovered_device_keeps_neither_code_nor_recovery_key() {
    let hosted = Hosted::new();
    let (mac, _) = lost_with_a_note(&hosted).await;
    let code = kit(&mac);
    let state = mac.signer.current_account().unwrap();
    let keys = recovery::open_current_record(
        &state,
        &mac.retained().recovery_record,
        &Password::new(PASSWORD).unwrap(),
        &code,
    )
    .unwrap();
    let receiving = keys.receiver().export_seed();
    let joiner = Joiner::new();
    // Interrupted once after its addition, then finished.
    hosted
        .edge
        .hook(Hook::DropAfterAccountAppend { then_down: true });
    assert_eq!(
        recover_onto(&hosted, &mac, &joiner, PASSWORD, &code).await,
        Err(RecoverError::Unreachable)
    );
    hosted.come_up();
    recover_onto(&hosted, &mac, &joiner, PASSWORD, &code)
        .await
        .unwrap();
    let dir = joiner.dir.path().to_path_buf();
    for needle in [
        code.expose().as_slice(),
        mac.kit.as_deref().unwrap().as_bytes(),
        receiving.expose().as_slice(),
    ] {
        assert!(!holds(&dir, needle));
    }
    // The scan finds what is there: the account's genesis.
    assert!(holds(&dir, &mac.originals[0]));
}

#[tokio::test(start_paused = true)]
async fn other_devices_alert_kit_used_and_device_added_by_kit() {
    let hosted = Hosted::new();
    let (mac, (client, _)) = signed_up(&hosted).await;
    let alerts = |kind| {
        mac.owner
            .shared_database(mac.id)
            .unwrap()
            .lock()
            .unwrap()
            .alerts(50)
            .unwrap()
            .into_iter()
            .filter(|alert| alert.kind == kind)
            .count()
    };
    let joiner = Joiner::new();
    recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac))
        .await
        .unwrap();
    until(20, "both alerts", || {
        client.wake();
        alerts(AlertKind::DeviceAddedByKit) == 1 && alerts(AlertKind::KitUsed) == 1
    })
    .await;
    // A new session reads the notices again, from the newest kept: the
    // same notice records no second alert.
    client.shutdown().await;
    let before = hosted.edge.notice_reads.load(Ordering::SeqCst);
    let (client, _) = mac.start(&hosted);
    // Nothing else runs on the paused runtime: a wake after the read is
    // after its answer was kept.
    until(20, "notices read again", || {
        hosted.edge.notice_reads.load(Ordering::SeqCst) > before
    })
    .await;
    assert_eq!(alerts(AlertKind::KitUsed), 1);
    assert_eq!(alerts(AlertKind::DeviceAddedByKit), 1);
    client.shutdown().await;
}

/// A device paired after a recovery alerts only the kit uses after it
/// joined; a device that was there alerts the recovery.
#[tokio::test(start_paused = true)]
async fn a_device_added_after_a_recovery_alerts_only_later_kit_uses() {
    let hosted = Hosted::new();
    let (mac, (client, _)) = signed_up(&hosted).await;
    let joiner = Joiner::new();
    recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac))
        .await
        .unwrap();
    until(20, "the existing device alerts the recovery", || {
        client.wake();
        kit_used(&mac).len() == 1
    })
    .await;
    let recovered = kit_used(&mac)[0];
    let (tab, _) = paired(&hosted, &mac, &client).await;
    bootstrapped(&hosted, &tab).await;
    tab.authorize().unwrap();
    // The kit used again after the tab joined: a running device checks it.
    client
        .recovery_keys(&Password::new(PASSWORD).unwrap(), &kit(&mac))
        .await
        .unwrap();
    let (tab_client, _) = tab.start(&hosted);
    // One read answers both notices at once, kept together.
    until(20, "the tab alerts a kit use", || {
        !kit_used(&tab).is_empty()
    })
    .await;
    let seen = kit_used(&tab);
    assert_eq!(seen.len(), 1, "only the use after it joined");
    assert!(seen[0] > recovered);
    tab_client.shutdown().await;
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn released_objects_that_do_not_match_the_log_are_refused() {
    let hosted = Hosted::new();
    let (mac, _) = lost_with_a_note(&hosted).await;
    let joiner = Joiner::new();
    let other = Device::new();
    let other_genesis = other.originals[0].clone();
    type Tamper = fn(&mut Vec<u8>, &mut Vec<u8>, &mut Vec<u8>, &[u8]);
    let tampers: [Tamper; 3] = [
        |_, record, _, _| *record.last_mut().unwrap() ^= 1,
        |_, _, seal, _| *seal.last_mut().unwrap() ^= 1,
        |genesis, _, _, other| *genesis = other.to_vec(),
    ];
    for tamper in tampers {
        let other_genesis = other_genesis.clone();
        hosted.tamper_recovery(Some(Box::new(move |answer| {
            if let RecoveryAnswer::Released {
                genesis,
                record,
                recovery_seal,
            } = answer
            {
                tamper(genesis, record, recovery_seal, &other_genesis);
            }
        })));
        assert_eq!(
            recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac)).await,
            Err(RecoverError::Invalid)
        );
        assert!(!joiner.has_account(), "nothing kept");
    }
    hosted.tamper_recovery(None);
    assert_eq!(additions(&hosted, &mac), 0, "no device was added");
    recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac))
        .await
        .unwrap();
}

/// The account's history is verified from its genesis under the hosting
/// root, and so is the addition's order: a confirmation another root
/// signed, an accepted head for another challenge or naming other bytes,
/// or an entry whose predecessor is not the one before it, is refused,
/// and the device is not added or kept.
#[tokio::test(start_paused = true)]
async fn account_evidence_that_does_not_verify_is_refused() {
    type Hostile = fn(&Hosted, LogId);
    let hostile: [Hostile; 4] = [
        |hosted, log| hosted.foreign_root_account_confirmations(log),
        |hosted, log| hosted.accepted_account_head_for_other_challenge(log),
        |hosted, log| hosted.corrupt_accepted_account(log, true),
        |hosted, log| hosted.wrong_account_predecessor(log, 2),
    ];
    for (case, hostile) in hostile.into_iter().enumerate() {
        let hosted = Hosted::new();
        let (mac, _) = lost_with_a_note(&hosted).await;
        hostile(&hosted, mac.account_log);
        let joiner = Joiner::new();
        assert_eq!(
            recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac)).await,
            Err(RecoverError::Invalid),
            "case {case}"
        );
        assert_eq!(additions(&hosted, &mac), 0, "case {case}");
        assert!(!joiner.has_account(), "case {case}");
    }
    // The addition's own confirmation, under another root or for another
    // challenge: the device is added, but recovery does not go on from it.
    for (case, tamper) in [ConfirmTamper::Root, ConfirmTamper::Challenge]
        .into_iter()
        .enumerate()
    {
        let hosted = Hosted::new();
        let (mac, _) = lost_with_a_note(&hosted).await;
        hosted.tamper_confirmations(Some(tamper));
        let joiner = Joiner::new();
        assert_eq!(
            recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac)).await,
            Err(RecoverError::Invalid),
            "confirmation case {case}"
        );
        assert!(!joiner.has_account(), "confirmation case {case}");
    }
}

#[tokio::test(start_paused = true)]
async fn recovery_never_receives_an_old_content_epoch_key() {
    let hosted = Hosted::new();
    let (mac, (client, _)) = signed_up(&hosted).await;
    let genesis_epoch = mac.progress().epoch_id.unwrap();
    let genesis_key = mac.content_key();
    // A device joins and leaves: the base rekeys under a new personal key
    // and its directory entry is written again.
    let control = SigningKey::generate();
    let member = DevicePublicKeys::new(
        SigningKey::generate().public(),
        control.public(),
        KemKey::generate().public(),
    )
    .unwrap();
    hosted
        .edge
        .order_account(mac.account_log, &mac.signer.add_device(member.clone()));
    until(20, "member copied", || {
        client.wake();
        copied(&mac) == 4
    })
    .await;
    let request = mac
        .signer
        .current_account()
        .unwrap()
        .remove_self(member.id())
        .unwrap();
    let leave = request
        .finish(control.sign(request.signing_bytes()))
        .unwrap();
    hosted.edge.order_account(mac.account_log, leave.as_bytes());
    until(120, "rekeyed and its entry written", || {
        client.wake();
        mac.progress()
            .epoch_id
            .is_some_and(|epoch| epoch != genesis_epoch)
            && matches!(mac.signer.directory_state().unwrap(), Some((v, true)) if v > 1)
    })
    .await;
    let current_key = {
        let mut key = None;
        mac.signer
            .with_epoch_keys(mac.base, mac.progress().epoch_id, &mut |_, content| {
                key = content.map(|k| k.expose().to_vec());
            })
            .unwrap();
        key.unwrap()
    };
    client.shutdown().await;

    let joiner = Joiner::new();
    assert_eq!(
        recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac)).await,
        Err(RecoverError::AwaitingAdmission)
    );
    // The account's progress is kept; nothing of the base, no blank base,
    // and neither epoch's key.
    assert!(joiner.has_account());
    assert!(!joiner.has_own_base());
    assert!(joiner.authorize(mac.base.0).is_err());
    let dir = joiner.dir.path().to_path_buf();
    assert!(!holds(&dir, genesis_key.expose()));
    assert!(!holds(&dir, &current_key));
    // Asked again, it waits again and adds no second device.
    assert_eq!(
        recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac)).await,
        Err(RecoverError::AwaitingAdmission)
    );
    assert_eq!(additions(&hosted, &mac), 2);
    // An entry under the new personal key that carries the base's original
    // seals, to the replaced key, is refused: no old key admits the base.
    let (id, _, _) = hosted
        .edge
        .directory(mac.account_log)
        .into_iter()
        .max_by_key(|(_, version, _)| *version)
        .unwrap();
    let package =
        bh_device::base_keys::InitialBaseKeyPackage::decode(&mac.own_base_package()).unwrap();
    serve_entry(
        &hosted,
        &mac,
        id,
        &DirectoryEntry::Base {
            base: mac.base.0,
            server: "http://edge.invalid".into(),
            epoch_id: genesis_epoch,
            current_key_seal: package.content_seal().to_vec(),
            metadata_seal: package.metadata_seal().to_vec(),
            own: true,
        },
    );
    let joiner = Joiner::new();
    assert_eq!(
        recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac)).await,
        Err(RecoverError::Invalid)
    );
    assert!(!joiner.has_own_base());
    assert!(!holds(joiner.dir.path(), genesis_key.expose()));
}

/// The own base's entry as `mac` wrote it: base, server, epoch, and its
/// content and metadata seals.
async fn written_entry(hosted: &Hosted, mac: &Device) -> ([u8; 32], DirectoryEntry) {
    let [(id, _, bytes)] = <[_; 1]>::try_from(hosted.edge.directory(mac.account_log)).unwrap();
    let mut opened = mac
        .signer
        .open_directory_entries(vec![bytes])
        .await
        .unwrap();
    (id, opened.remove(0).ok().unwrap().entry)
}

/// Serve, in place of the own base's entry, `entry` as `mac` signs it.
fn serve_entry(hosted: &Hosted, mac: &Device, id: [u8; 32], entry: &DirectoryEntry) {
    let bytes = signed_entry(mac, entry);
    hosted
        .edge
        .put_directory_entry(mac.account_log, id, 2, bytes);
}

/// `entry` as `device` signs it for its own account.
fn signed_entry(device: &Device, entry: &DirectoryEntry) -> Vec<u8> {
    let (mut account, cap, _) = device.signer.account_owner();
    ready(account.prepare_directory_entry(&cap, entry, 2)).unwrap()
}

/// `genuine`, the own base's entry, as an entry for `base` that says
/// whether it is the own base.
fn entry_for(genuine: &DirectoryEntry, base: [u8; 32], own: bool) -> DirectoryEntry {
    let DirectoryEntry::Base {
        server,
        epoch_id,
        current_key_seal,
        metadata_seal,
        ..
    } = genuine
    else {
        panic!("a base entry")
    };
    DirectoryEntry::Base {
        base,
        server: server.clone(),
        epoch_id: *epoch_id,
        current_key_seal: current_key_seal.clone(),
        metadata_seal: metadata_seal.clone(),
        own,
    }
}

/// The directory also lists another base of the account, before or after
/// the own base's entry: recovery admits the own base, as its entry says.
#[tokio::test(start_paused = true)]
async fn the_own_base_is_recovered_beside_another_base() {
    for other_id in [[0; 32], [0xff; 32]] {
        let hosted = Hosted::new();
        let (mac, _) = lost_with_a_note(&hosted).await;
        let (_, genuine) = written_entry(&hosted, &mac).await;
        hosted.edge.put_directory_entry(
            mac.account_log,
            other_id,
            2,
            signed_entry(&mac, &entry_for(&genuine, [5; 32], false)),
        );
        let joiner = Joiner::new();
        recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac))
            .await
            .unwrap();
        let fold = joiner.into_device();
        assert_eq!(fold.base, mac.base);
        fold.authorize().unwrap();
    }
}

/// A claim to be the own base that the account did not make is ignored,
/// and two claims are refused: never another base or a blank one.
#[tokio::test(start_paused = true)]
async fn an_own_base_claim_the_account_did_not_make_admits_nothing() {
    let hosted = Hosted::new();
    let (mac, (client, _)) = signed_up(&hosted).await;
    let (other, (other_client, _)) = signed_up(&hosted).await;
    other_client.shutdown().await;
    client.shutdown().await;
    let (id, genuine) = written_entry(&hosted, &mac).await;
    // Another account's device claims its base is this account's own.
    let wrong_account = signed_entry(&other, &entry_for(&genuine, other.base.0, true));
    // A claim for another base whose signature no device made.
    let mut unsigned = signed_entry(&mac, &entry_for(&genuine, [5; 32], true));
    *unsigned.last_mut().unwrap() ^= 1;
    let put = |id: [u8; 32], bytes: Vec<u8>| {
        hosted
            .edge
            .put_directory_entry(mac.account_log, id, 2, bytes)
    };
    put([0; 32], wrong_account);
    put([1; 32], unsigned.clone());
    let joiner = Joiner::new();
    recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac))
        .await
        .unwrap();
    assert_eq!(joiner.into_device().base, mac.base);

    // With the own base's entry itself unsigned, the only entry left that
    // the account signed does not say it is the own base: nothing is
    // admitted, not even the base it names.
    let mut forged = signed_entry(&mac, &genuine);
    *forged.last_mut().unwrap() ^= 1;
    put(id, forged);
    put(
        [1; 32],
        signed_entry(&mac, &entry_for(&genuine, mac.base.0, false)),
    );
    let joiner = Joiner::new();
    assert_eq!(
        recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac)).await,
        Err(RecoverError::Unreachable)
    );
    assert!(!joiner.has_own_base());
    assert!(!holds(joiner.dir.path(), mac.content_key().expose()));

    // Two bases the account's own device says are its own.
    put(id, signed_entry(&mac, &genuine));
    put(
        [1; 32],
        signed_entry(&mac, &entry_for(&genuine, [5; 32], true)),
    );
    let joiner = Joiner::new();
    assert_eq!(
        recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac)).await,
        Err(RecoverError::Invalid)
    );
    assert!(!joiner.has_own_base());
    assert!(!holds(joiner.dir.path(), mac.content_key().expose()));
}

/// An entry another device of the account signed that does not admit the
/// own base is refused, and nothing of the base is kept: one whose M seal
/// is another base's, one naming another epoch than its content seal's, or
/// one whose M seal names a device the account does not hold.
#[tokio::test(start_paused = true)]
async fn an_entry_that_does_not_admit_the_own_base_is_refused() {
    let hosted = Hosted::new();
    let (mac, (client, _)) = signed_up(&hosted).await;
    let (other, (other_client, _)) = signed_up(&hosted).await;
    other_client.shutdown().await;
    client.shutdown().await;
    let (id, genuine) = written_entry(&hosted, &mac).await;
    let DirectoryEntry::Base {
        base,
        server,
        epoch_id,
        current_key_seal,
        metadata_seal,
        ..
    } = genuine
    else {
        panic!("a base entry")
    };
    // M's seal with its header altered: as another base's, or as a device
    // the account does not hold would have made it.
    let altered = |alter: &dyn Fn(&mut SealHeader)| {
        let mut header = SealHeader::decode(&metadata_seal).unwrap();
        alter(&mut header);
        let mut seal = header.encode();
        seal.extend_from_slice(&metadata_seal[seal.len()..]);
        seal
    };
    let another_base = altered(&|header| header.base = other.base);
    let stranger = altered(&|header| header.device = bh_account::DeviceId([7; 32]));
    let entry = |base, epoch_id, metadata_seal| DirectoryEntry::Base {
        base,
        server: server.clone(),
        epoch_id,
        current_key_seal: current_key_seal.clone(),
        metadata_seal,
        own: true,
    };
    let hostile = [
        entry(base, epoch_id, another_base),
        entry(base, [9; 32], metadata_seal.clone()),
        entry(base, epoch_id, stranger),
    ];
    for (case, entry) in hostile.iter().enumerate() {
        serve_entry(&hosted, &mac, id, entry);
        let joiner = Joiner::new();
        assert_eq!(
            recover_onto(&hosted, &mac, &joiner, PASSWORD, &kit(&mac)).await,
            Err(RecoverError::Invalid),
            "case {case}"
        );
        assert!(!joiner.has_own_base(), "case {case}");
        assert!(joiner.authorize(mac.base.0).is_err(), "case {case}");
    }
    // The entry as it was written admits the base.
    serve_entry(
        &hosted,
        &mac,
        id,
        &entry(base, epoch_id, metadata_seal.clone()),
    );
    recover_onto(&hosted, &mac, &Joiner::new(), PASSWORD, &kit(&mac))
        .await
        .unwrap();
}

#[ignore = "needs the admission snapshot"]
#[tokio::test(start_paused = true)]
async fn recover_after_rotation_opens_every_acknowledged_note_with_only_the_current_key() {
    // After a base-key rotation, recovery opens every acknowledged note,
    // from before and after the rotation, while no epoch key but the
    // current one ever reaches the recovered device.
}

// ---- The recovery keys a running device checks the kit for ----

#[tokio::test(start_paused = true)]
async fn the_right_kit_opens_the_recovery_keys_the_log_names() {
    let hosted = Hosted::new();
    let (mac, (client, _)) = signed_up(&hosted).await;
    let keys = client
        .recovery_keys(&Password::new(PASSWORD).unwrap(), &kit(&mac))
        .await
        .unwrap();
    let state = mac.signer.current_account().unwrap();
    assert!(&keys.public() == state.recovery_keys().unwrap());
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_wrong_code_for_the_recovery_keys_uses_no_try() {
    let hosted = Hosted::new();
    let (mac, (client, _)) = signed_up(&hosted).await;
    for _ in 0..6 {
        assert!(matches!(
            client
                .recovery_keys(&Password::new(PASSWORD).unwrap(), &RecoveryCode::generate())
                .await,
            Err(RecoverError::NotRecognised)
        ));
    }
    client.shutdown().await;
    assert_eq!(tries_left(&hosted, &mac).await, 4);
}

#[tokio::test(start_paused = true)]
async fn a_wrong_password_for_the_recovery_keys_uses_a_try() {
    let hosted = Hosted::new();
    let (mac, (client, _)) = signed_up(&hosted).await;
    assert!(matches!(
        client
            .recovery_keys(&Password::new("not the password").unwrap(), &kit(&mac))
            .await,
        Err(RecoverError::PasswordMismatch { tries_left: 4, .. })
    ));
    client.shutdown().await;
    assert_eq!(tries_left(&hosted, &mac).await, 3);
}
