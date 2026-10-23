//! The home's recovery check: a claim sealed for this connection's nonce,
//! found by its proof alone, and the durable five, hourly, daily schedule.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_account::recovery::{self, Password, RecoveryCode};
use bh_authz::{
    Service,
    proto::{FromService, RecoverPurpose, RecoveryAnswer, Refusal, ToService},
};
use support::{claims::*, *};

#[tokio::test]
async fn recovery_refreshes_and_checks_record_and_seal_before_release() {
    let harness = Harness::new();
    let service = harness.service();
    let home = Home::new(&harness, &service).await;
    let reads = harness.edge.reads.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        try_claim(&harness, &service, &home.right).await,
        FromService::Recovery(home.released())
    );
    assert_eq!(
        harness.edge.reads.load(std::sync::atomic::Ordering::SeqCst),
        reads + 1
    );
    let db = rusqlite::Connection::open(harness.dir.path().join("authz.sqlite")).unwrap();
    db.execute(
        "UPDATE recovery_records SET recovery_seal=?1 WHERE account=?2",
        rusqlite::params![vec![0u8; 1299], home.signup.account.id.0.as_slice()],
    )
    .unwrap();
    assert_eq!(
        try_claim(&harness, &service, &home.right).await,
        FromService::Unavailable
    );
    db.execute(
        "UPDATE recovery_records SET recovery_seal=?1, record=?2 WHERE account=?3",
        rusqlite::params![
            home.signup.recovery_seal,
            vec![0u8; 1300],
            home.signup.account.id.0.as_slice()
        ],
    )
    .unwrap();
    assert_eq!(
        try_claim(&harness, &service, &home.right).await,
        FromService::Unavailable
    );
}

#[tokio::test]
async fn confirmed_replacement_retires_the_old_kit_and_retries_exactly() {
    use bh_account::{personal, recovery::RecoveryKeys};
    use bh_authz::proto::{RecoveryAttachment, account_log_wrap};
    let harness = Harness::new();
    let service = harness.service();
    let home = Home::new(&harness, &service).await;
    let keys = RecoveryKeys::generate();
    let code = RecoveryCode::generate();
    let record = recovery::prepare_replacement(
        &home.signup.account.verified,
        &keys,
        &Password::new(PASSWORD).unwrap(),
        &code,
    )
    .unwrap();
    let seal = personal::seal_for_new_recovery(
        &home.signup.account.verified,
        home.signup.account.personal.as_ref().unwrap(),
        &keys.public(),
    )
    .unwrap();
    let draft = home
        .signup
        .account
        .verified
        .replace_recovery(
            home.device.id(),
            keys.public(),
            record.digest(),
            personal::seal_digest(&seal),
        )
        .unwrap();
    let event = draft
        .finish(home.device.control.sign(draft.signing_bytes()))
        .unwrap();
    let mut session = session(&service, &home.signup.account, &home.device).await;
    let attachment = RecoveryAttachment {
        record: Some(record.as_bytes().to_vec()),
        recovery_seal: seal.clone(),
        rotation_body: None,
    };
    for wrong in [
        RecoveryAttachment {
            record: None,
            ..attachment.clone()
        },
        RecoveryAttachment {
            rotation_body: Some(bh_sync::Digest([1; 32])),
            ..attachment.clone()
        },
        RecoveryAttachment {
            recovery_seal: vec![0; seal.len()],
            ..attachment.clone()
        },
    ] {
        assert!(matches!(
            session
                .handle(ToService::SubmitControl {
                    log: home.signup.account.log,
                    event: event.as_bytes().to_vec(),
                    delivery: None,
                    attachment: Some(Box::new(wrong)),
                })
                .await,
            FromService::Refused {
                reason: Refusal::Invalid
            }
        ));
    }
    let submitted = session
        .handle(ToService::SubmitControl {
            log: home.signup.account.log,
            event: event.as_bytes().to_vec(),
            delivery: None,
            attachment: Some(Box::new(attachment)),
        })
        .await;
    let FromService::Permits { items } = submitted else {
        panic!("{submitted:?}")
    };
    let wrapped = account_log_wrap(event.as_bytes(), None).unwrap();
    harness
        .edge
        .append(items.last().unwrap().as_ref().unwrap(), &wrapped)
        .unwrap();
    let request = ToService::ConfirmControl {
        log: home.signup.account.log,
        event: wrapped.digest(),
        challenge: [17; 32],
    };
    harness
        .edge
        .fail_retire_once
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let first = session.handle(request.clone()).await;
    assert!(matches!(first, FromService::Confirmed { .. }), "{first:?}");
    assert!(
        harness
            .edge
            .home_objects
            .lock()
            .unwrap()
            .contains_key(&home.signup.account.log.id),
        "a failed retirement does not roll back accepted replacement"
    );
    assert_eq!(session.handle(request).await, first);
    assert!(
        !harness
            .edge
            .home_objects
            .lock()
            .unwrap()
            .contains_key(&home.signup.account.log.id),
        "initial home bundle must be retired after durable replacement"
    );
    assert_eq!(
        try_claim(&harness, &service, &home.right).await,
        NOT_RECOGNISED
    );
    let new_claim = recovery::claim(&Password::new(PASSWORD).unwrap(), &code).unwrap();
    assert_eq!(
        try_claim(&harness, &service, &new_claim).await,
        FromService::Recovery(RecoveryAnswer::Released {
            genesis: home.signup.account.genesis.clone(),
            record: record.as_bytes().to_vec(),
            recovery_seal: seal,
        })
    );
}

#[tokio::test]
async fn replacement_confirmed_before_initial_upload_can_progress_and_release_new_kit() {
    use bh_account::{personal, recovery::RecoveryKeys};
    use bh_authz::proto::{RecoveryAttachment, account_log_wrap};
    let h = Harness::new();
    let service = h.service();
    let first = Device::new();
    let signup = Signup::new(&first, PASSWORD);
    h.publish(&signup.account);
    let mut c = session(&service, &signup.account, &first).await;
    let keys = RecoveryKeys::generate();
    let code = RecoveryCode::generate();
    let record = recovery::prepare_replacement(
        &signup.account.verified,
        &keys,
        &Password::new(PASSWORD).unwrap(),
        &code,
    )
    .unwrap();
    let seal = personal::seal_for_new_recovery(
        &signup.account.verified,
        signup.account.personal.as_ref().unwrap(),
        &keys.public(),
    )
    .unwrap();
    let draft = signup
        .account
        .verified
        .replace_recovery(
            first.id(),
            keys.public(),
            record.digest(),
            personal::seal_digest(&seal),
        )
        .unwrap();
    let event = draft
        .finish(first.control.sign(draft.signing_bytes()))
        .unwrap();
    let answer = c
        .handle(ToService::SubmitControl {
            log: signup.account.log,
            event: event.as_bytes().to_vec(),
            delivery: None,
            attachment: Some(Box::new(RecoveryAttachment {
                record: Some(record.as_bytes().to_vec()),
                recovery_seal: seal.clone(),
                rotation_body: None,
            })),
        })
        .await;
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    let wrapped = account_log_wrap(event.as_bytes(), None).unwrap();
    h.edge
        .append(items.last().unwrap().as_ref().unwrap(), &wrapped)
        .unwrap();
    let confirm = ToService::ConfirmControl {
        log: signup.account.log,
        event: wrapped.digest(),
        challenge: [19; 32],
    };
    let first_answer = c.handle(confirm.clone()).await;
    assert!(
        matches!(first_answer, FromService::Confirmed { .. }),
        "{first_answer:?}"
    );
    assert_eq!(c.handle(confirm).await, first_answer);
    assert!(
        matches!(
            c.handle(ToService::Permits {
                items: vec![read_events(signup.account.log)],
            })
            .await,
            FromService::Permits { .. }
        ),
        "successor refresh must not be poisoned"
    );
    assert!(
        matches!(
            c.handle(signup.store.clone()).await,
            FromService::HomeObjectsStored { .. }
        ),
        "late initial upload must not block refresh"
    );
    let old = recovery::claim(&Password::new(PASSWORD).unwrap(), &signup.code).unwrap();
    let new = recovery::claim(&Password::new(PASSWORD).unwrap(), &code).unwrap();
    assert_eq!(try_claim(&h, &service, &old).await, NOT_RECOGNISED);
    assert_eq!(
        try_claim(&h, &service, &new).await,
        FromService::Recovery(RecoveryAnswer::Released {
            genesis: signup.account.genesis,
            record: record.as_bytes().to_vec(),
            recovery_seal: seal,
        })
    );
}

#[tokio::test]
async fn lapsed_replacement_attachment_is_consumed_without_retiring_the_kit() {
    lapsed_attachment(false).await;
}

#[tokio::test]
async fn lapsed_rotation_attachment_is_consumed_without_changing_the_seal() {
    lapsed_attachment(true).await;
}

async fn lapsed_attachment(rotation: bool) {
    use bh_account::{
        ConfirmedTime, ControlOutcome, REMOVAL_WAIT_MS,
        personal::{self, PersonalKey},
        recovery::RecoveryKeys,
    };
    use bh_authz::proto::{RecoveryAttachment, account_log_wrap, rotation_body};
    use support::native::session_as;
    let h = Harness::new();
    let service = h.service();
    let home = Home::new(&h, &service).await;
    let a = &home.device;
    let b = Device::new();
    let c = Device::new();
    let mut owner = session(&service, &home.signup.account, a).await;
    let mut view = home.signup.account.verified.clone();
    let at = h.clock.now();
    let time = |ms| {
        Some(ConfirmedTime {
            earliest_ms: ms,
            latest_ms: ms,
        })
    };
    for target in [&b, &c] {
        let draft = view.add_device(a.id(), target.keys.clone()).unwrap();
        let event = draft.finish(a.control.sign(draft.signing_bytes())).unwrap();
        submit(&h, &mut owner, &home.signup.account, event.as_bytes()).await;
        confirmation_original(&mut owner, home.signup.account.log, event.as_bytes()).await;
        view.apply_timed(event.as_bytes(), time(at)).unwrap();
    }
    let removed = if rotation {
        let draft = view.remove_self(c.id()).unwrap();
        let event = draft.finish(c.control.sign(draft.signing_bytes())).unwrap();
        let mut by_c = session_as(
            &service,
            &view,
            &home.signup.account.genesis,
            c.id(),
            |message| c.ordinary.sign(message),
        )
        .await;
        submit(&h, &mut by_c, &home.signup.account, event.as_bytes()).await;
        confirmation_original(&mut owner, home.signup.account.log, event.as_bytes()).await;
        view.apply_timed(event.as_bytes(), time(at)).unwrap();
        Some(event)
    } else {
        None
    };
    let requested_at = at + 10_000;
    h.clock.set(requested_at);
    let draft = view.request_removal(a.id(), b.id()).unwrap();
    let request = draft.finish(a.control.sign(draft.signing_bytes())).unwrap();
    submit(&h, &mut owner, &home.signup.account, request.as_bytes()).await;
    confirmation_original(&mut owner, home.signup.account.log, request.as_bytes()).await;
    view.apply_timed(request.as_bytes(), time(requested_at))
        .unwrap();
    let deadline = requested_at + REMOVAL_WAIT_MS;
    h.clock.set(deadline - 100);
    let mut by_b = session_as(
        &service,
        &view,
        &home.signup.account.genesis,
        b.id(),
        |message| b.ordinary.sign(message),
    )
    .await;
    let (event, attachment, body, new_kit) = if rotation {
        let prepared =
            personal::prepare_rotation(&view.advanced(deadline - 100), &PersonalKey::generate())
                .unwrap();
        let draft = view
            .rotate_personal(
                b.id(),
                removed.as_ref().unwrap().head().position,
                prepared.public,
                prepared.device_seals_digest,
                prepared.recovery_seal_digest,
            )
            .unwrap();
        let event = draft
            .finish(b.ordinary.sign(draft.signing_bytes()))
            .unwrap();
        let body = rotation_body(&prepared.body).unwrap();
        let commitment =
            stage_rotation(&h, &mut by_b, home.signup.account.log, &prepared.body).await;
        (
            event,
            RecoveryAttachment {
                record: None,
                recovery_seal: prepared.recovery_seal,
                rotation_body: Some(commitment),
            },
            Some(body),
            None,
        )
    } else {
        let keys = RecoveryKeys::generate();
        let code = RecoveryCode::generate();
        let record =
            recovery::prepare_replacement(&view, &keys, &Password::new(PASSWORD).unwrap(), &code)
                .unwrap();
        let seal = personal::seal_for_new_recovery(
            &view,
            home.signup.account.personal.as_ref().unwrap(),
            &keys.public(),
        )
        .unwrap();
        let draft = view
            .replace_recovery(
                b.id(),
                keys.public(),
                record.digest(),
                personal::seal_digest(&seal),
            )
            .unwrap();
        let event = draft.finish(b.control.sign(draft.signing_bytes())).unwrap();
        (
            event,
            RecoveryAttachment {
                record: Some(record.as_bytes().to_vec()),
                recovery_seal: seal,
                rotation_body: None,
            },
            None,
            Some(code),
        )
    };
    let answer = by_b
        .handle(ToService::SubmitControl {
            log: home.signup.account.log,
            event: event.as_bytes().to_vec(),
            delivery: None,
            attachment: Some(Box::new(attachment)),
        })
        .await;
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    let wrapped =
        account_log_wrap(event.as_bytes(), body.as_ref().map(|b| b.commitment())).unwrap();
    h.clock.set(deadline - 2);
    let [append] = <[_; 1]>::try_from(items).unwrap();
    h.edge.append(append.as_ref().unwrap(), &wrapped).unwrap();
    drop(by_b);
    drop(owner);
    drop(service);
    h.clock.set(deadline + 1);
    let restarted = h.service();
    let mut owner = session_as(
        &restarted,
        &home.signup.account.verified,
        &home.signup.account.genesis,
        a.id(),
        |message| a.ordinary.sign(message),
    )
    .await;
    let confirm = ToService::ConfirmControl {
        log: home.signup.account.log,
        event: wrapped.digest(),
        challenge: [87; 32],
    };
    let first = owner.handle(confirm.clone()).await;
    assert!(matches!(first, FromService::Confirmed { .. }), "{first:?}");
    assert_eq!(owner.handle(confirm).await, first);
    drop(owner);
    drop(restarted);
    let restarted = h.service();
    let mut owner = session_as(
        &restarted,
        &home.signup.account.verified,
        &home.signup.account.genesis,
        a.id(),
        |message| a.ordinary.sign(message),
    )
    .await;
    let retry = owner
        .handle(ToService::ConfirmControl {
            log: home.signup.account.log,
            event: wrapped.digest(),
            challenge: [87; 32],
        })
        .await;
    assert_eq!(
        retry, first,
        "confirmation survives another restart byte-for-byte"
    );
    let db = rusqlite::Connection::open(h.dir.path().join("authz.sqlite")).unwrap();
    let pending: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM pending_attachments WHERE account=?1",
            [home.signup.account.id.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending, 0, "lapsed attachment is consumed atomically");
    assert!(
        h.edge
            .home_objects
            .lock()
            .unwrap()
            .contains_key(&home.signup.account.log.id),
        "lapsed replacement cannot retire the original bundle"
    );
    assert_eq!(
        try_claim(&h, &restarted, &home.right).await,
        FromService::Recovery(home.released())
    );
    if let Some(code) = new_kit {
        let claim = recovery::claim(&Password::new(PASSWORD).unwrap(), &code).unwrap();
        assert_eq!(try_claim(&h, &restarted, &claim).await, NOT_RECOGNISED);
    }
    assert_eq!(
        view.apply_timed_with_outcome(event.as_bytes(), time(deadline + 1))
            .unwrap(),
        ControlOutcome::Lapsed
    );
    let next_device = Device::new();
    let draft = view.add_device(a.id(), next_device.keys).unwrap();
    let next = draft.finish(a.control.sign(draft.signing_bytes())).unwrap();
    submit(&h, &mut owner, &home.signup.account, next.as_bytes()).await;
    confirmation_original(&mut owner, home.signup.account.log, next.as_bytes()).await;
}

#[tokio::test]
async fn rotation_attachment_is_staged_and_only_activates_after_verified_readback() {
    use bh_account::{
        ConfirmedTime,
        personal::{self, PersonalKey},
        recovery::RecoveryKeys,
    };
    use bh_authz::proto::{RecoveryAttachment, account_log_wrap, rotation_body};
    let harness = Harness::new();
    let service = harness.service();
    let home = Home::new(&harness, &service).await;
    let keys = RecoveryKeys::generate();
    let code = RecoveryCode::generate();
    let record = recovery::prepare_replacement(
        &home.signup.account.verified,
        &keys,
        &Password::new(PASSWORD).unwrap(),
        &code,
    )
    .unwrap();
    let seal = personal::seal_for_new_recovery(
        &home.signup.account.verified,
        home.signup.account.personal.as_ref().unwrap(),
        &keys.public(),
    )
    .unwrap();
    let draft = home
        .signup
        .account
        .verified
        .replace_recovery(
            home.device.id(),
            keys.public(),
            record.digest(),
            personal::seal_digest(&seal),
        )
        .unwrap();
    let replaced = draft
        .finish(home.device.control.sign(draft.signing_bytes()))
        .unwrap();
    let mut session = session(&service, &home.signup.account, &home.device).await;
    let answer = session
        .handle(ToService::SubmitControl {
            log: home.signup.account.log,
            event: replaced.as_bytes().to_vec(),
            delivery: None,
            attachment: Some(Box::new(RecoveryAttachment {
                record: Some(record.as_bytes().to_vec()),
                recovery_seal: seal,
                rotation_body: None,
            })),
        })
        .await;
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    let wrapped = account_log_wrap(replaced.as_bytes(), None).unwrap();
    harness
        .edge
        .append(items.last().unwrap().as_ref().unwrap(), &wrapped)
        .unwrap();
    assert!(matches!(
        session
            .handle(ToService::ConfirmControl {
                log: home.signup.account.log,
                event: wrapped.digest(),
                challenge: [1; 32]
            })
            .await,
        FromService::Confirmed { .. }
    ));
    let mut predecessor = home.signup.account.verified.clone();
    predecessor
        .apply_timed(
            replaced.as_bytes(),
            Some(ConfirmedTime {
                earliest_ms: harness.clock.now(),
                latest_ms: harness.clock.now(),
            }),
        )
        .unwrap();
    let rotated_key = PersonalKey::generate();
    let prepared = personal::prepare_rotation(&predecessor, &rotated_key).unwrap();
    let draft = predecessor
        .rotate_personal(
            home.device.id(),
            replaced.head().position,
            prepared.public,
            prepared.device_seals_digest,
            prepared.recovery_seal_digest,
        )
        .unwrap();
    let rotated = draft
        .finish(home.device.ordinary.sign(draft.signing_bytes()))
        .unwrap();
    // ConfirmControl never accepts a raw frame as a BodyObject: stage the
    // canonical purpose-two padded body under its independent commitment.
    let object = rotation_body(&prepared.body).unwrap();
    let commitment = stage_rotation(
        &harness,
        &mut session,
        home.signup.account.log,
        &prepared.body,
    )
    .await;
    assert_eq!(commitment, object.commitment());
    let answer = session
        .handle(ToService::SubmitControl {
            log: home.signup.account.log,
            event: rotated.as_bytes().to_vec(),
            delivery: None,
            attachment: Some(Box::new(RecoveryAttachment {
                record: None,
                recovery_seal: prepared.recovery_seal.clone(),
                rotation_body: Some(commitment),
            })),
        })
        .await;
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    // The body is staged already: only its append is permitted.
    assert_eq!(items.len(), 1);
    let wrapped = account_log_wrap(rotated.as_bytes(), Some(object.commitment())).unwrap();
    harness
        .edge
        .append(items[0].as_ref().unwrap(), &wrapped)
        .unwrap();
    harness
        .edge
        .corrupt_body
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        session
            .handle(ToService::ConfirmControl {
                log: home.signup.account.log,
                event: wrapped.digest(),
                challenge: [2; 32]
            })
            .await,
        FromService::Unavailable
    );
    harness
        .edge
        .corrupt_body
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let confirmation = session
        .handle(ToService::ConfirmControl {
            log: home.signup.account.log,
            event: wrapped.digest(),
            challenge: [2; 32],
        })
        .await;
    assert!(
        matches!(confirmation, FromService::Confirmed { .. }),
        "{confirmation:?}"
    );
    let claim = recovery::claim(&Password::new(PASSWORD).unwrap(), &code).unwrap();
    // A delayed/repeated initial-home acknowledgement must not restore the
    // initial seal after rotation while keeping the same recovery record.
    assert!(matches!(
        session.handle(home.signup.store.clone()).await,
        FromService::HomeObjectsStored { .. }
    ));
    assert_eq!(
        try_claim(&harness, &service, &claim).await,
        FromService::Recovery(RecoveryAnswer::Released {
            genesis: home.signup.account.genesis,
            record: record.as_bytes().to_vec(),
            recovery_seal: prepared.recovery_seal
        })
    );
}

#[tokio::test]
async fn late_initial_bundle_ack_cannot_overwrite_rotated_seal_for_same_record() {
    rotate_after_self_removal(true).await;
}

#[tokio::test]
async fn rotation_without_initial_index_is_refused_until_upload_then_confirms() {
    rotate_after_self_removal(false).await;
}

async fn rotate_after_self_removal(initial_uploaded: bool) {
    use bh_account::{
        ConfirmedTime,
        personal::{self, PersonalKey},
    };
    use bh_authz::proto::{RecoveryAttachment, account_log_wrap, rotation_body};
    use support::native::session_as;
    let h = Harness::new();
    let service = h.service();
    let home = if initial_uploaded {
        Home::new(&h, &service).await
    } else {
        let device = Device::new();
        let signup = Signup::new(&device, PASSWORD);
        h.publish(&signup.account);
        Home {
            right: recovery::claim(&Password::new(PASSWORD).unwrap(), &signup.code).unwrap(),
            wrong_password: recovery::claim(&Password::new("wrong horse").unwrap(), &signup.code)
                .unwrap(),
            signup,
            device,
        }
    };
    let mut owner = session(&service, &home.signup.account, &home.device).await;
    let other = Device::new();
    let draft = home
        .signup
        .account
        .verified
        .add_device(home.device.id(), other.keys.clone())
        .unwrap();
    let add = draft
        .finish(home.device.control.sign(draft.signing_bytes()))
        .unwrap();
    submit(&h, &mut owner, &home.signup.account, add.as_bytes()).await;
    confirmation_original(&mut owner, home.signup.account.log, add.as_bytes()).await;
    let now = h.clock.now();
    let time = Some(ConfirmedTime {
        earliest_ms: now,
        latest_ms: now,
    });
    let mut view = home.signup.account.verified.clone();
    view.apply_timed(add.as_bytes(), time).unwrap();
    let mut joining = session_as(
        &service,
        &view,
        &home.signup.account.genesis,
        other.id(),
        |m| other.ordinary.sign(m),
    )
    .await;
    let draft = view.remove_self(other.id()).unwrap();
    let remove = draft
        .finish(other.control.sign(draft.signing_bytes()))
        .unwrap();
    submit(&h, &mut joining, &home.signup.account, remove.as_bytes()).await;
    confirmation_original(&mut owner, home.signup.account.log, remove.as_bytes()).await;
    view.apply_timed(remove.as_bytes(), time).unwrap();
    let prepared = personal::prepare_rotation(&view, &PersonalKey::generate()).unwrap();
    let draft = view
        .rotate_personal(
            home.device.id(),
            remove.head().position,
            prepared.public,
            prepared.device_seals_digest,
            prepared.recovery_seal_digest,
        )
        .unwrap();
    let rotate = draft
        .finish(home.device.ordinary.sign(draft.signing_bytes()))
        .unwrap();
    let commitment = stage_rotation(&h, &mut owner, home.signup.account.log, &prepared.body).await;
    let request = ToService::SubmitControl {
        log: home.signup.account.log,
        event: rotate.as_bytes().to_vec(),
        delivery: None,
        attachment: Some(Box::new(RecoveryAttachment {
            record: None,
            recovery_seal: prepared.recovery_seal.clone(),
            rotation_body: Some(commitment),
        })),
    };
    let mut answer = owner.handle(request.clone()).await;
    if !initial_uploaded {
        assert!(
            matches!(
                answer,
                FromService::Refused {
                    reason: Refusal::Invalid
                }
            ),
            "no rotation append permit before current record exists: {answer:?}"
        );
        assert!(
            h.edge
                .after(home.signup.account.log, view.head().position)
                .is_empty()
        );
        assert!(matches!(
            owner.handle(home.signup.store.clone()).await,
            FromService::HomeObjectsStored { .. }
        ));
        answer = owner.handle(request).await;
    }
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    let body = rotation_body(&prepared.body).unwrap();
    let wrapped = account_log_wrap(rotate.as_bytes(), Some(body.commitment())).unwrap();
    let [append] = <[_; 1]>::try_from(items).unwrap();
    h.edge.append(append.as_ref().unwrap(), &wrapped).unwrap();
    assert!(matches!(
        owner
            .handle(ToService::ConfirmControl {
                log: home.signup.account.log,
                event: wrapped.digest(),
                challenge: [1; 32]
            })
            .await,
        FromService::Confirmed { .. }
    ));
    let answer = owner.handle(home.signup.store.clone()).await;
    assert!(
        matches!(answer, FromService::HomeObjectsStored { .. }),
        "{answer:?}"
    );
    assert_eq!(
        try_claim(&h, &service, &home.right).await,
        FromService::Recovery(RecoveryAnswer::Released {
            genesis: home.signup.account.genesis,
            record: home.signup.record,
            recovery_seal: prepared.recovery_seal,
        })
    );
}

async fn confirmation_original(
    c: &mut bh_authz::Connection,
    log: bh_authz::proto::LogId,
    original: &[u8],
) {
    let event = bh_authz::proto::account_log_wrap(original, None)
        .unwrap()
        .digest();
    let answer = c
        .handle(ToService::ConfirmControl {
            log,
            event,
            challenge: [7; 32],
        })
        .await;
    assert!(
        matches!(answer, FromService::Confirmed { .. }),
        "{answer:?}"
    );
}

#[tokio::test]
async fn wrong_code_is_not_recognised_and_uses_no_try() {
    let harness = Harness::new();
    let service = harness.service();
    let home = Home::new(&harness, &service).await;
    let password = Password::new(PASSWORD).unwrap();
    for _ in 0..10 {
        let other = recovery::claim(&password, &RecoveryCode::generate()).unwrap();
        assert_eq!(try_claim(&harness, &service, &other).await, NOT_RECOGNISED);
    }
    assert_eq!(
        try_claim(&harness, &service, &home.right).await,
        FromService::Recovery(home.released())
    );
    // Nothing was counted against the record.
    assert_eq!(
        try_claim(&harness, &service, &home.wrong_password).await,
        mismatch(4, None)
    );
}

#[tokio::test]
async fn wrong_password_reports_tries_left_then_the_next_time() {
    let harness = Harness::new();
    let service = harness.service();
    let home = Home::new(&harness, &service).await;
    for tries_left in [4, 3, 2, 1] {
        harness.clock.advance(1_000);
        assert_eq!(
            try_claim(&harness, &service, &home.wrong_password).await,
            mismatch(tries_left, None)
        );
    }
    harness.clock.advance(1_000);
    let fifth = harness.clock.now();
    assert_eq!(
        try_claim(&harness, &service, &home.wrong_password).await,
        mismatch(0, Some(fifth + HOUR))
    );
}

#[tokio::test]
async fn lockout_is_five_free_then_hourly_for_a_day_then_daily() {
    let harness = Harness::new();
    let service = harness.service();
    let home = Home::new(&harness, &service).await;
    for _ in 0..4 {
        try_claim(&harness, &service, &home.wrong_password).await;
    }
    let f = harness.clock.now();
    assert_eq!(
        try_claim(&harness, &service, &home.wrong_password).await,
        mismatch(0, Some(f + HOUR))
    );
    let mut next = f + HOUR;
    // One an hour until a day after the fifth failure.
    while next < f + DAY {
        harness.clock.set(next - 1);
        // An early try waits, whatever its password, and is not counted.
        assert_eq!(
            try_claim(&harness, &service, &home.wrong_password).await,
            wait(next)
        );
        assert_eq!(try_claim(&harness, &service, &home.right).await, wait(next));
        harness.clock.set(next);
        assert_eq!(
            try_claim(&harness, &service, &home.wrong_password).await,
            mismatch(0, Some(next + HOUR))
        );
        next += HOUR;
    }
    assert_eq!(next, f + DAY);
    harness.clock.set(f + DAY);
    assert_eq!(
        try_claim(&harness, &service, &home.wrong_password).await,
        mismatch(0, Some(f + 2 * DAY))
    );
    // Then one a day.
    harness.clock.set(f + 2 * DAY - 1);
    assert_eq!(
        try_claim(&harness, &service, &home.wrong_password).await,
        wait(f + 2 * DAY)
    );
    harness.clock.set(f + 2 * DAY);
    assert_eq!(
        try_claim(&harness, &service, &home.wrong_password).await,
        mismatch(0, Some(f + 3 * DAY))
    );
}

#[tokio::test]
async fn a_try_waits_for_its_earliest_bound_and_counts_from_its_latest() {
    let harness = Harness::new();
    let service = harness.service();
    let home = Home::new(&harness, &service).await;
    for _ in 0..4 {
        try_claim(&harness, &service, &home.wrong_password).await;
    }
    harness.clock.set_uncertainty(500);
    let fifth = harness.clock.now();
    assert_eq!(
        try_claim(&harness, &service, &home.wrong_password).await,
        mismatch(0, Some(fifth + 500 + HOUR))
    );
    // The latest bound has reached the next try, the earliest has not.
    harness.clock.set(fifth + HOUR + 1);
    assert_eq!(
        try_claim(&harness, &service, &home.right).await,
        wait(fifth + 500 + HOUR)
    );
    harness.clock.set(fifth + 500 + HOUR);
    assert_eq!(
        try_claim(&harness, &service, &home.right).await,
        FromService::Recovery(home.released())
    );
}

#[tokio::test]
async fn release_and_kit_replacement_reset_the_counter() {
    let harness = Harness::new();
    let service = harness.service();
    let home = Home::new(&harness, &service).await;
    for tries_left in [4, 3, 2, 1] {
        assert_eq!(
            try_claim(&harness, &service, &home.wrong_password).await,
            mismatch(tries_left, None)
        );
    }
    assert_eq!(
        try_claim(&harness, &service, &home.right).await,
        FromService::Recovery(home.released())
    );
    for tries_left in [4, 3, 2, 1, 0] {
        assert!(matches!(
            try_claim(&harness, &service, &home.wrong_password).await,
            FromService::Recovery(RecoveryAnswer::PasswordMismatch { tries_left: left, .. })
                if left == tries_left
        ));
    }
    // Locked out, then released at the next try: five free again.
    harness.clock.advance(HOUR);
    assert_eq!(
        try_claim(&harness, &service, &home.right).await,
        FromService::Recovery(home.released())
    );
    assert_eq!(
        try_claim(&harness, &service, &home.wrong_password).await,
        mismatch(4, None)
    );
    // A kit replacement retires the record with its tries: the store's
    // `kit_replacement_retires_the_old_record_with_its_tries` checks it, as
    // the replacement arrives only through a confirmed account change.
}

#[tokio::test]
async fn right_code_and_password_release_record_and_seal_and_queue_a_notice() {
    let harness = Harness::new();
    let service = harness.service();
    let home = Home::new(&harness, &service).await;
    let other = Home::new(&harness, &service).await;
    let mut connection = session(&service, &home.signup.account, &home.device).await;
    let notices = |after_ms| ToService::ReadNotices { after_ms };
    assert_eq!(
        connection.handle(notices(0)).await,
        FromService::Notices {
            kit_used_ms: vec![]
        }
    );
    harness.clock.advance(1_000);
    let used = harness.clock.now();
    let answer = try_claim(&harness, &service, &home.right).await;
    let FromService::Recovery(RecoveryAnswer::Released {
        genesis,
        record,
        recovery_seal,
    }) = &answer
    else {
        panic!("{answer:?}")
    };
    // The record opens under the password and code for this account, and
    // the seal is the one the account's history names.
    assert_eq!(genesis, &home.signup.account.genesis);
    assert_eq!(
        recovery::account_of_record(record, &Password::new(PASSWORD).unwrap(), &home.signup.code)
            .map(|account| account.0),
        Ok(home.signup.account.id.0)
    );
    assert_eq!(recovery_seal, &home.signup.recovery_seal);
    assert_eq!(
        connection.handle(notices(0)).await,
        FromService::Notices {
            kit_used_ms: vec![used]
        }
    );
    assert_eq!(
        connection.handle(notices(used)).await,
        FromService::Notices {
            kit_used_ms: vec![]
        }
    );
    // A second release at the same moment is a later notice, not a lost one.
    try_claim(&harness, &service, &home.right).await;
    assert_eq!(
        connection.handle(notices(used)).await,
        FromService::Notices {
            kit_used_ms: vec![used + 1]
        }
    );
    // Another account is told nothing; reading needs an authenticated device.
    let mut theirs = session(&service, &other.signup.account, &other.device).await;
    assert_eq!(
        theirs.handle(notices(0)).await,
        FromService::Notices {
            kit_used_ms: vec![]
        }
    );
    let (mut anonymous, _, _) = connect(&service);
    assert_eq!(
        anonymous.handle(notices(0)).await,
        FromService::Refused {
            reason: Refusal::Unauthenticated
        }
    );
}

#[tokio::test]
async fn a_correct_recheck_costs_no_try() {
    let harness = Harness::new();
    let service = harness.service();
    let home = Home::new(&harness, &service).await;
    for _ in 0..3 {
        assert_eq!(
            try_claim(&harness, &service, &home.right).await,
            FromService::Recovery(home.released())
        );
    }
    assert_eq!(
        try_claim(&harness, &service, &home.wrong_password).await,
        mismatch(4, None)
    );
}

#[tokio::test]
async fn sign_purpose_releases_only_the_sessions_own_account() {
    let harness = Harness::new();
    let service = harness.service();
    let home = Home::new(&harness, &service).await;
    let other = Home::new(&harness, &service).await;
    // Unauthenticated, Sign is refused before anything is judged.
    let (mut anonymous, _, challenge) = connect(&service);
    assert_eq!(
        try_on(
            &harness,
            &mut anonymous,
            challenge,
            &home.right,
            RecoverPurpose::Sign
        )
        .await,
        FromService::Refused {
            reason: Refusal::Unauthenticated
        }
    );
    // On a session, another account's kit is not recognised and costs it
    // nothing; the session's own is released, with no recovery session.
    let signed_in = || async {
        let (mut connection, binding, challenge) = connect(&service);
        let answer = connection
            .handle(authenticate_message(
                &home.signup.account,
                &home.device,
                binding,
                challenge,
            ))
            .await;
        assert!(matches!(answer, FromService::Authenticated { .. }));
        (connection, challenge)
    };
    for claim in [&other.right, &other.wrong_password] {
        let (mut connection, challenge) = signed_in().await;
        assert_eq!(
            try_on(
                &harness,
                &mut connection,
                challenge,
                claim,
                RecoverPurpose::Sign
            )
            .await,
            NOT_RECOGNISED
        );
    }
    assert_eq!(
        try_claim(&harness, &service, &other.wrong_password).await,
        mismatch(4, None)
    );
    let (mut connection, challenge) = signed_in().await;
    assert_eq!(
        try_on(
            &harness,
            &mut connection,
            challenge,
            &home.right,
            RecoverPurpose::Sign
        )
        .await,
        FromService::Recovery(home.released())
    );
    assert!(connection.recovering().is_none());
    // A claim sealed for one purpose is not taken for the other.
    let (mut connection, _, challenge) = connect(&service);
    let ToService::Recover { sealed, .. } =
        sealed(&harness, &home.right, challenge, RecoverPurpose::Sign)
    else {
        unreachable!()
    };
    assert_eq!(
        connection
            .handle(ToService::Recover {
                sealed,
                purpose: RecoverPurpose::AddDevice,
            })
            .await,
        NOT_RECOGNISED
    );
    assert!(connection.recovering().is_none());
    // AddDevice on an unauthenticated connection opens a recovery session
    // for the released account.
    let (mut connection, _, challenge) = connect(&service);
    assert_eq!(
        try_on(
            &harness,
            &mut connection,
            challenge,
            &home.right,
            RecoverPurpose::AddDevice
        )
        .await,
        FromService::Recovery(home.released())
    );
    assert_eq!(
        connection.recovering().map(|account| account.0),
        Some(home.signup.account.id.0)
    );
}

#[tokio::test]
async fn recovery_session_submits_and_confirms_only_its_one_recovery_addition() {
    use bh_account::personal;
    use bh_authz::proto::{Delivery, account_log_wrap, delivery_body};
    let h = Harness::new();
    let service = h.service();
    let home = Home::new(&h, &service).await;
    let account = &home.signup.account;
    let keys = recovery::open_current_record(
        &account.verified,
        &home.signup.record,
        &Password::new(PASSWORD).unwrap(),
        &home.signup.code,
    )
    .unwrap();
    let personal = personal::open_for_recovery(
        &account.verified,
        &home.signup.recovery_seal,
        keys.receiver(),
    )
    .unwrap();
    let joined = Device::new();
    let draft = account
        .verified
        .add_device_by_recovery(joined.keys.clone())
        .unwrap();
    let add = draft.finish_with_recovery(&keys).unwrap();
    let frame = personal::seal_for_device_by_recovery(
        &account.verified,
        &personal,
        &keys,
        &joined.keys,
        &add,
    )
    .unwrap();
    let body = delivery_body(&frame).unwrap();
    let wrapped = account_log_wrap(add.as_bytes(), Some(body.commitment())).unwrap();
    let (mut c, _, nonce) = connect(&service);
    assert!(matches!(
        try_on(&h, &mut c, nonce, &home.right, RecoverPurpose::AddDevice).await,
        FromService::Recovery(RecoveryAnswer::Released { .. })
    ));
    let denied = FromService::Refused {
        reason: Refusal::Unauthenticated,
    };
    assert_eq!(
        c.handle(ToService::ReadAccountEvidence {
            genesis: account.genesis.clone(),
            first: 1,
            last: 3,
            challenge: [1; 32]
        })
        .await,
        denied
    );
    let submit = ToService::SubmitControl {
        log: account.log,
        event: add.as_bytes().to_vec(),
        delivery: Some(Box::new(Delivery {
            recipient: joined.keys.clone(),
            frame,
        })),
        attachment: None,
    };
    let answer = c.handle(submit.clone()).await;
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    assert_eq!(c.handle(submit).await, denied);
    let ask = || ToService::ConfirmControl {
        log: account.log,
        event: wrapped.digest(),
        challenge: [2; 32],
    };
    assert_eq!(
        c.handle(ask()).await,
        FromService::Refused {
            reason: Refusal::NotOrdered
        }
    );
    h.edge
        .stage(items[0].as_ref().unwrap(), body.bytes())
        .unwrap();
    h.edge.append(items[1].as_ref().unwrap(), &wrapped).unwrap();
    let answer = c.handle(ask()).await;
    let FromService::Confirmed { confirmation, .. } = answer else {
        panic!("{answer:?}")
    };
    let FromService::Confirmed {
        confirmation: retry,
        ..
    } = c.handle(ask()).await
    else {
        panic!("retry")
    };
    assert_eq!(confirmation, retry);
    assert_eq!(
        c.handle(ToService::ConfirmControl {
            log: account.log,
            event: bh_sync::Digest([0; 32]),
            challenge: [2; 32]
        })
        .await,
        denied
    );
}

#[tokio::test]
async fn the_claim_is_bound_to_this_connections_challenge() {
    let harness = Harness::new();
    let service = harness.service();
    let home = Home::new(&harness, &service).await;
    let (mut first, _, challenge) = connect(&service);
    let (mut second, _, _) = connect(&service);
    let claim = sealed(&harness, &home.right, challenge, RecoverPurpose::AddDevice);
    assert_eq!(second.handle(claim.clone()).await, NOT_RECOGNISED);
    assert!(second.recovering().is_none());
    assert_eq!(
        first.handle(claim.clone()).await,
        FromService::Recovery(home.released())
    );
    // The nonce is spent by the first claim on a connection.
    assert_eq!(
        first.handle(claim).await,
        FromService::Refused {
            reason: Refusal::Unauthenticated
        }
    );
    // A claim that is not a sealed claim at all is malformed.
    let (mut third, _, _) = connect(&service);
    assert_eq!(
        third
            .handle(ToService::Recover {
                sealed: vec![1; 40],
                purpose: RecoverPurpose::AddDevice,
            })
            .await,
        FromService::Refused {
            reason: Refusal::Malformed
        }
    );
}

#[tokio::test]
async fn a_service_without_a_recovery_key_refuses_claims() {
    let harness = Harness::new();
    let home = Home::new(&harness, &harness.service()).await;
    let service = Service::open(
        &harness.dir.path().join("authz.sqlite"),
        harness.keys(),
        harness.clock.clone(),
        harness.edge.clone(),
    )
    .unwrap();
    assert_eq!(
        try_claim(&harness, &service, &home.right).await,
        FromService::Refused {
            reason: Refusal::Unsupported
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_tries_count_one_at_a_time() {
    let harness = std::sync::Arc::new(Harness::new());
    let service = harness.service();
    let home = std::sync::Arc::new(Home::new(&harness, &service).await);
    // Twenty wrong tries at once: five are counted, the rest wait.
    let tries: Vec<_> = (0..20)
        .map(|_| {
            let (mut connection, _, challenge) = connect(&service);
            let claim = sealed(
                &harness,
                &home.wrong_password,
                challenge,
                RecoverPurpose::AddDevice,
            );
            tokio::spawn(async move { connection.handle(claim).await })
        })
        .collect();
    let mut left = vec![];
    let now = harness.clock.now();
    for answer in tries {
        match answer.await.unwrap() {
            FromService::Recovery(RecoveryAnswer::PasswordMismatch { tries_left, .. }) => {
                left.push(tries_left)
            }
            answer => assert_eq!(answer, wait(now + HOUR)),
        }
    }
    left.sort();
    assert_eq!(left, vec![0, 1, 2, 3, 4]);
}
