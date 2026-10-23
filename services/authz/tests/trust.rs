//! Timed account authority and its content-permission boundary.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_account::{ConfirmedTime, REMOVAL_WAIT_MS};
use bh_authz::proto::{FromService, Refusal, ToService, Want};
use bh_sync::{
    Digest,
    evidence::{AcceptedHead, OrderingConfirmation},
};
use std::sync::atomic::Ordering;
use support::*;

fn request(account: &Account, author: &Device, target: &Device) -> Vec<u8> {
    let draft = account
        .verified
        .request_removal(author.id(), target.id())
        .unwrap();
    draft
        .finish(author.control.sign(draft.signing_bytes()))
        .unwrap()
        .as_bytes()
        .to_vec()
}

async fn confirmation(
    connection: &mut bh_authz::Connection,
    account: &Account,
    original: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    let event = bh_authz::proto::account_log_wrap(original, None)
        .unwrap()
        .digest();
    match connection
        .handle(ToService::ConfirmControl {
            log: account.log,
            event,
            challenge: [7; 32],
        })
        .await
    {
        FromService::Confirmed { confirmation, head } => (confirmation, head),
        answer => panic!("confirmation: {answer:?}"),
    }
}

#[tokio::test]
async fn retried_confirmation_returns_the_same_evidence_and_deadline() {
    let h = Harness::new();
    h.clock.set(100);
    let a = Device::new();
    let b = Device::new();
    let mut account = Account::create_full(&a);
    account.add_device(&a, &b);
    h.publish(&account);
    let service = h.service();
    let mut c = session(&service, &account, &a).await;
    let original = request(&account, &a, &b);
    let permit = single_permit(
        c.handle(ToService::SubmitControl {
            log: account.log,
            event: original.clone(),
            delivery: None,
            attachment: None,
        })
        .await,
    );
    h.clock.set(105);
    h.edge
        .append(
            &permit,
            &bh_authz::proto::account_log_wrap(&original, None).unwrap(),
        )
        .unwrap();
    h.clock.set(110);
    let (first, head) = confirmation(&mut c, &account, &original).await;
    let claim = *OrderingConfirmation::decode(&first)
        .unwrap()
        .verify_for(&h.root.public(), &original, None)
        .unwrap();
    assert_eq!(
        (claim.bounds.earliest_ms, claim.bounds.latest_ms),
        (110, 110)
    );
    let accepted = AcceptedHead::verify(&head, &h.root.public(), account.log, &[7; 32]).unwrap();
    assert_eq!(accepted.evidence, bh_crypto::hash(&first));
    h.clock.set(170);
    assert_eq!(confirmation(&mut c, &account, &original).await.0, first);
    drop(c);
    drop(service);
    let restarted = h.service();
    let (mut c, binding, challenge) = connect(&restarted);
    assert!(matches!(
        c.handle(authenticate_message(&account, &a, binding, challenge))
            .await,
        FromService::Authenticated { .. }
    ));
    assert_eq!(confirmation(&mut c, &account, &original).await.0, first);
    let mut view = account.verified.clone();
    view.apply_timed(
        &original,
        Some(ConfirmedTime {
            earliest_ms: 110,
            latest_ms: 110,
        }),
    )
    .unwrap();
    assert_eq!(
        view.pending_removals(170)[0].deadline_ms,
        110 + REMOVAL_WAIT_MS
    );
}

#[tokio::test]
async fn late_addition_survives_crash_but_never_activates_its_delivery() {
    use bh_authz::proto::{Delivery, account_log_wrap, delivery_body};
    let h = Harness::new();
    h.clock.set(100);
    let a = Device::new();
    let b = Device::new();
    let joined = Device::new();
    let mut account = Account::create_full(&a);
    account.add_device(&a, &b);
    h.publish(&account);
    let service = h.service();
    let mut owner = session(&service, &account, &a).await;
    let mut target = session(&service, &account, &b).await;
    let removal = request(&account, &a, &b);
    submit(&h, &mut owner, &account, &removal).await;
    confirmation(&mut owner, &account, &removal).await;
    account
        .verified
        .apply_timed(
            &removal,
            Some(ConfirmedTime {
                earliest_ms: 100,
                latest_ms: 100,
            }),
        )
        .unwrap();
    let deadline = 100 + REMOVAL_WAIT_MS;
    h.clock.set(deadline - 10);
    let (add, frame) = account.add_with_delivery(&b, &joined);
    let body = delivery_body(&frame).unwrap();
    let wrapped = account_log_wrap(add.as_bytes(), Some(body.commitment())).unwrap();
    let answer = target
        .handle(ToService::SubmitControl {
            log: account.log,
            event: add.as_bytes().to_vec(),
            delivery: Some(Box::new(Delivery {
                recipient: joined.keys.clone(),
                frame,
            })),
            attachment: None,
        })
        .await;
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    h.clock.set(deadline - 2);
    h.edge
        .stage(items[0].as_ref().unwrap(), body.bytes())
        .unwrap();
    h.edge.append(items[1].as_ref().unwrap(), &wrapped).unwrap();
    drop(target);
    drop(owner);
    drop(service);
    h.clock.set(deadline + 1);
    assert_eq!(
        account
            .verified
            .apply_timed_with_outcome(
                add.as_bytes(),
                Some(ConfirmedTime {
                    earliest_ms: deadline + 1,
                    latest_ms: deadline + 1
                })
            )
            .unwrap(),
        bh_account::ControlOutcome::Lapsed
    );
    assert!(account.verified.active_device(joined.id()).is_err());
    let service = h.service();
    let mut owner = session(&service, &account, &a).await;
    let ask = || ToService::ConfirmControl {
        log: account.log,
        event: wrapped.digest(),
        challenge: [8; 32],
    };
    let first = owner.handle(ask()).await;
    let FromService::Confirmed {
        confirmation: first,
        ..
    } = first
    else {
        panic!("{first:?}")
    };
    let FromService::Confirmed {
        confirmation: retry,
        ..
    } = owner.handle(ask()).await
    else {
        panic!("retry")
    };
    assert_eq!(first, retry);
    let batch = owner
        .handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log: account.log,
                after: bh_sync::Head::EMPTY,
                max_events: 10,
            },
        })
        .await;
    assert!(
        matches!(
            batch,
            FromService::ReadBatch {
                result: bh_authz::proto::ReadBatchResult::Selected {
                    body_permit: None,
                    ..
                },
                ..
            }
        ),
        "lapsed originals remain readable without releasing delivery bodies: {batch:?}"
    );
    let read = || ToService::Permits {
        items: vec![Want::ReadBodies {
            log: account.log,
            bodies: vec![body.commitment()],
        }],
    };
    assert!(
        matches!(owner.handle(read()).await, FromService::Permits { items } if items == vec![Err(Refusal::Unknown)])
    );
    drop(owner);
    drop(service);
    let restarted = h.service();
    let mut owner = session(&restarted, &account, &a).await;
    assert!(
        matches!(owner.handle(read()).await, FromService::Permits { items } if items == vec![Err(Refusal::Unknown)])
    );
    let draft = account
        .verified
        .add_device(a.id(), Device::new().keys)
        .unwrap();
    let next = draft.finish(a.control.sign(draft.signing_bytes())).unwrap();
    single_permit(
        owner
            .handle(ToService::SubmitControl {
                log: account.log,
                event: next.as_bytes().to_vec(),
                delivery: None,
                attachment: None,
            })
            .await,
    );
}

#[tokio::test]
async fn not_yet_ordered_is_refused_not_confirmed() {
    let h = Harness::new();
    let a = Device::new();
    let account = Account::create_full(&a);
    h.publish(&account);
    let service = h.service();
    let mut c = session(&service, &account, &a).await;
    assert!(matches!(
        c.handle(ToService::ConfirmControl {
            log: account.log,
            event: Digest([9; 32]),
            challenge: [7; 32]
        })
        .await,
        FromService::Refused {
            reason: Refusal::NotOrdered
        }
    ));
}

#[tokio::test]
async fn unconfirmed_entry_is_confirmed_at_next_refresh_and_bounds_never_regress() {
    let h = Harness::new();
    h.clock.set(100);
    let a = Device::new();
    let b = Device::new();
    let mut account = Account::create_full(&a);
    h.publish(&account);
    let service = h.service();
    let mut c = session(&service, &account, &a).await;
    let added = account.add_device(&a, &b);
    h.clock.set(105);
    h.order_account_event(&account, &added);
    h.clock.set(200);
    single_permit(
        c.handle(ToService::Permits {
            items: vec![read_events(account.log)],
        })
        .await,
    );
    let (first, _) = confirmation(&mut c, &account, &added).await;
    assert_eq!(
        OrderingConfirmation::decode(&first)
            .unwrap()
            .claim()
            .bounds
            .latest_ms,
        200
    );
    let remove = account.remove_self(&b);
    h.clock.set(150);
    h.order_account_event(&account, &remove);
    let (second, _) = confirmation(&mut c, &account, &remove).await;
    let bounds = OrderingConfirmation::decode(&second)
        .unwrap()
        .claim()
        .bounds;
    assert_eq!((bounds.earliest_ms, bounds.latest_ms), (200, 200));
}

#[tokio::test]
async fn pending_target_permits_are_capped_and_refused_from_deadline_without_rotation() {
    let h = Harness::new();
    h.clock.set(100);
    let a = Device::new();
    let b = Device::new();
    let mut account = Account::create_full(&a);
    account.add_device(&a, &b);
    h.publish(&account);
    let service = h.service();
    let mut owner = session(&service, &account, &a).await;
    let mut target = session(&service, &account, &b).await;
    let original = request(&account, &a, &b);
    submit(&h, &mut owner, &account, &original).await;
    confirmation(&mut owner, &account, &original).await;
    let deadline = 100 + REMOVAL_WAIT_MS;
    h.clock.set(deadline - 10_000);
    for want in [
        read_events(account.log),
        Want::ReadControls {
            log: account.log,
            after: 0,
        },
        Want::ReadDirectory { log: account.log },
    ] {
        let bytes = single_permit(
            target
                .handle(ToService::Permits { items: vec![want] })
                .await,
        );
        assert_eq!(h.permit(&bytes).deadline_ms, deadline);
    }
    h.clock.set(deadline);
    assert!(matches!(
        target
            .handle(ToService::Permits {
                items: vec![read_events(account.log)]
            })
            .await,
        FromService::Refused {
            reason: Refusal::NotActive
        }
    ));
    let (mut c, binding, challenge) = connect(&service);
    assert!(matches!(
        c.handle(authenticate_message(&account, &b, binding, challenge))
            .await,
        FromService::Refused {
            reason: Refusal::NotActive
        }
    ));
}

#[tokio::test]
async fn pending_targets_submit_and_batch_permissions_end_at_the_deadline() {
    let h = Harness::new();
    h.clock.set(100);
    let a = Device::new();
    let b = Device::new();
    let mut account = Account::create_full(&a);
    account.add_device(&a, &b);
    h.publish(&account);
    let service = h.service();
    let mut owner = session(&service, &account, &a).await;
    let mut target = session(&service, &account, &b).await;
    let removal = request(&account, &a, &b);
    submit(&h, &mut owner, &account, &removal).await;
    confirmation(&mut owner, &account, &removal).await;
    account
        .verified
        .apply_timed(
            &removal,
            Some(ConfirmedTime {
                earliest_ms: 100,
                latest_ms: 100,
            }),
        )
        .unwrap();
    let deadline = 100 + REMOVAL_WAIT_MS;
    h.clock.set(deadline - 10_000);
    let draft = account
        .verified
        .add_device(b.id(), Device::new().keys)
        .unwrap();
    let addition = draft.finish(b.control.sign(draft.signing_bytes())).unwrap();
    let permit = single_permit(
        target
            .handle(ToService::SubmitControl {
                log: account.log,
                event: addition.as_bytes().to_vec(),
                delivery: None,
                attachment: None,
            })
            .await,
    );
    assert_eq!(h.permit(&permit).deadline_ms, deadline);
    let answer = target
        .handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log: account.log,
                after: bh_sync::Head::EMPTY,
                max_events: 10,
            },
        })
        .await;
    assert!(
        matches!(answer, FromService::ReadBatch { deadline_ms, .. } if deadline_ms == deadline),
        "{answer:?}"
    );
}

#[tokio::test]
async fn cancel_submitted_when_latest_reaches_deadline_is_refused_lapsed() {
    let h = Harness::new();
    h.clock.set(100);
    let a = Device::new();
    let b = Device::new();
    let mut account = Account::create_full(&a);
    account.add_device(&a, &b);
    h.publish(&account);
    let service = h.service();
    let mut c = session(&service, &account, &a).await;
    let original = request(&account, &a, &b);
    submit(&h, &mut c, &account, &original).await;
    confirmation(&mut c, &account, &original).await;
    account
        .verified
        .apply_timed(
            &original,
            Some(ConfirmedTime {
                earliest_ms: 100,
                latest_ms: 100,
            }),
        )
        .unwrap();
    let draft = account.verified.cancel_removal(a.id(), 5).unwrap();
    let cancel = draft.finish(a.control.sign(draft.signing_bytes())).unwrap();
    h.clock.set(100 + REMOVAL_WAIT_MS - 5);
    h.clock.set_uncertainty(5);
    assert!(matches!(
        c.handle(ToService::SubmitControl {
            log: account.log,
            event: cancel.as_bytes().to_vec(),
            delivery: None,
            attachment: None
        })
        .await,
        FromService::Refused {
            reason: Refusal::Lapsed
        }
    ));
}

#[tokio::test]
async fn immature_remove_now_is_invalid_even_with_both_real_signatures() {
    use bh_account::{AccountEvent, AccountId, VerifiedAccount, recovery::RecoveryKeys};
    use bh_authz::proto::{LogId, LogKind, account_log_id};
    use support::native::session_as;
    let h = Harness::new();
    h.clock.set(100);
    let a = Device::new();
    let b = Device::new();
    let recovery = RecoveryKeys::generate();
    let genesis_draft = AccountEvent::genesis(a.keys.clone(), recovery.public());
    let genesis = genesis_draft
        .finish(a.control.sign(genesis_draft.signing_bytes()))
        .unwrap();
    let id = AccountId::of_genesis(&genesis).unwrap();
    let genesis = genesis.as_bytes().to_vec();
    let account = Account {
        verified: VerifiedAccount::from_genesis(id, &genesis).unwrap(),
        log: LogId {
            kind: LogKind::Account,
            id: account_log_id(&genesis).unwrap(),
        },
        id,
        originals: vec![genesis.clone()],
        genesis,
        personal: None,
    };
    h.publish(&account);
    let service = h.service();
    let mut first = session(&service, &account, &a).await;
    let draft = account.verified.add_device(a.id(), b.keys.clone()).unwrap();
    let add = draft.finish(a.control.sign(draft.signing_bytes())).unwrap();
    submit(&h, &mut first, &account, add.as_bytes()).await;
    confirmation(&mut first, &account, add.as_bytes()).await;
    let mut view = account.verified.clone();
    view.apply_timed(
        add.as_bytes(),
        Some(ConfirmedTime {
            earliest_ms: 100,
            latest_ms: 100,
        }),
    )
    .unwrap();
    let mut second = session_as(&service, &view, &account.genesis, b.id(), |message| {
        b.ordinary.sign(message)
    })
    .await;
    let removal = view.remove_now(b.id(), a.id()).unwrap();
    let event = removal
        .finish(
            b.control.sign(&removal.device_signing_bytes()),
            removal.sign_recovery(&recovery),
        )
        .unwrap();
    h.clock.set(101);
    assert!(matches!(
        second
            .handle(ToService::SubmitControl {
                log: account.log,
                event: event.as_bytes().to_vec(),
                delivery: None,
                attachment: None,
            })
            .await,
        FromService::Refused {
            reason: Refusal::Invalid
        }
    ));
}

#[tokio::test]
async fn cancel_confirmed_at_deadline_is_lapsed_but_ordered() {
    let h = Harness::new();
    h.clock.set(100);
    let a = Device::new();
    let b = Device::new();
    let mut account = Account::create_full(&a);
    account.add_device(&a, &b);
    h.publish(&account);
    let service = h.service();
    let mut c = session(&service, &account, &a).await;
    h.clock.set(10_000);
    let removal = request(&account, &a, &b);
    submit(&h, &mut c, &account, &removal).await;
    confirmation(&mut c, &account, &removal).await;
    account
        .verified
        .apply_timed(
            &removal,
            Some(ConfirmedTime {
                earliest_ms: 10_000,
                latest_ms: 10_000,
            }),
        )
        .unwrap();
    let draft = account.verified.cancel_removal(a.id(), 5).unwrap();
    let cancel = draft.finish(a.control.sign(draft.signing_bytes())).unwrap();
    let deadline = 10_000 + REMOVAL_WAIT_MS;
    h.clock.set(deadline - 100);
    let submitted = submit(&h, &mut c, &account, cancel.as_bytes()).await;
    assert!(
        matches!(submitted, FromService::Permits { .. }),
        "{submitted:?}"
    );
    h.clock.set(deadline);
    let (proof, _) = confirmation(&mut c, &account, cancel.as_bytes()).await;
    assert_eq!(
        OrderingConfirmation::decode(&proof)
            .unwrap()
            .claim()
            .bounds
            .latest_ms,
        deadline
    );
    let outcome = account
        .verified
        .apply_timed_with_outcome(
            cancel.as_bytes(),
            Some(ConfirmedTime {
                earliest_ms: deadline,
                latest_ms: deadline,
            }),
        )
        .unwrap();
    assert_eq!(outcome, bh_account::ControlOutcome::Applied);
    assert!(account.verified.active_device(b.id()).is_err());
    assert!(matches!(
        c.handle(ToService::Permits {
            items: vec![read_events(account.log)],
        })
        .await,
        FromService::Permits { .. }
    ));
}

#[tokio::test]
async fn content_permits_add_no_confirmation_only_read() {
    let harness = Harness::new();
    let device = Device::new();
    let mut account = Account::create_full(&device);
    let leaving = Device::new();
    account.add_device(&device, &leaving);
    harness.publish(&account);
    let service = harness.service();
    let mut connection = session(&service, &account, &device).await;
    let genesis = account.base_genesis(&device);
    let answer = connection.handle(genesis.register()).await;
    order_genesis(&harness, &answer, &genesis);
    let request = || ToService::Permits {
        items: vec![Want::Append {
            log: genesis.log(),
            event: base_event(42).0.encode(),
            epoch: bh_event::key_id(&genesis.content),
        }],
    };
    // Warm the base record first: this assertion is about an ordinary content
    // permit, not loading or rebuilding a base's control state.
    single_permit(connection.handle(request()).await);
    let reads = harness.edge.reads.load(Ordering::SeqCst);
    let control_reads = harness.edge.control_reads.load(Ordering::SeqCst);
    single_permit(connection.handle(request()).await);
    assert_eq!(
        harness.edge.reads.load(Ordering::SeqCst),
        reads + 1,
        "ordinary content permissions need exactly their currentness lookup"
    );
    assert_eq!(
        harness.edge.control_reads.load(Ordering::SeqCst),
        control_reads,
        "a warmed base without pending controls needs no additional read"
    );

    // A new original is discovered by the next ordinary currentness lookup.
    // Its confirmation must be stored during that same lookup, not by a
    // subsequent confirmation-specific round trip.
    let removal = account.remove_self(&leaving);
    harness.order_account_event(&account, &removal);
    let reads = harness.edge.reads.load(Ordering::SeqCst);
    let answer = connection.handle(request()).await;
    assert!(
        matches!(answer, FromService::Permits { ref items }
            if items.len() == 1 && matches!(items[0], Err(Refusal::AccountChangePending))),
        "the base must copy the newly discovered account change: {answer:?}"
    );
    assert_eq!(harness.edge.reads.load(Ordering::SeqCst), reads + 1);
    assert_eq!(
        harness.edge.control_reads.load(Ordering::SeqCst),
        control_reads
    );
    let db = rusqlite::Connection::open(harness.dir.path().join("authz.sqlite")).unwrap();
    let confirmation_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM account_confirmations WHERE account=?1 AND position=5",
            [account.id.0.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(confirmation_count, 1, "confirm in the existing lookup");
}
