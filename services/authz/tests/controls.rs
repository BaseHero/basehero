//! Account controls, own-base registration and base controls.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_authz::{
    Connection, Service,
    proto::{
        ACCOUNT_EPOCH, Delivery, FromService, MetadataKey, Refusal, ToService, Want,
        account_log_unwrap, account_log_wrap, delivery_body,
    },
};
use bh_sync::{
    BodyObject, Digest, Head,
    permit::{LogId, LogKind, Scope},
    referenced_body,
};
use rusqlite::Connection as SqlConnection;
use std::sync::atomic::Ordering;
use support::{
    native::{Fold, Mac, order},
    *,
};

fn refused(answer: FromService, reason: Refusal) {
    assert!(
        matches!(answer, FromService::Refused { reason: r } if r == reason),
        "{answer:?}"
    );
}

#[tokio::test]
async fn a_new_account_orders_its_genesis_and_controls_through_the_service() {
    let harness = Harness::new();
    let first = Device::new();
    let second = Device::new();
    let mut account = Account::create(&first);
    let service = harness.service();
    // Nothing is on the edge: the device authenticates at its genesis.
    let mut connection = session(&service, &account, &first).await;
    let signed = single_permit(
        submit(
            &harness,
            &mut connection,
            &account,
            &account.genesis.clone(),
        )
        .await,
    );
    let Scope::Append {
        log,
        event,
        body,
        epoch,
        after,
        attached: None,
    } = harness.permit(&signed).scope
    else {
        panic!("append")
    };
    assert!(log == account.log);
    assert_eq!(
        event,
        account_log_wrap(&account.genesis, None).unwrap().digest()
    );
    assert_eq!(
        (body, epoch, after),
        (None, ACCOUNT_EPOCH, Some(Head::EMPTY))
    );
    assert_eq!(harness.edge.head(account.log).position, 1);
    // QR device addition is an ordinary control, appended after the head.
    let addition = account.add_device(&first, &second);
    let before = harness.edge.head(account.log);
    let signed = single_permit(submit(&harness, &mut connection, &account, &addition).await);
    let Scope::Append { after, .. } = harness.permit(&signed).scope else {
        panic!("append")
    };
    assert_eq!(after, Some(before));
    assert_eq!(harness.edge.head(account.log).position, 2);
    // The added device can now authenticate and read the account log.
    let mut joined = session(&service, &account, &second).await;
    single_permit(
        joined
            .handle(ToService::Permits {
                items: vec![read_events(account.log)],
            })
            .await,
    );
}

#[tokio::test]
async fn removed_device_refused_after_control() {
    let harness = Harness::new();
    let first = Device::new();
    let second = Device::new();
    let mut account = Account::create(&first);
    account.add_device(&first, &second);
    harness.publish(&account);
    let service = harness.service();
    let mut leaving = session(&service, &account, &second).await;
    let mut staying = session(&service, &account, &first).await;
    let removal = account.remove_self(&second);
    single_permit(submit(&harness, &mut leaving, &account, &removal).await);
    // The next request on the removed device's open session is refused, and
    // other devices of the account are unaffected.
    let request = || ToService::Permits {
        items: vec![read_events(account.log)],
    };
    assert!(matches!(
        leaving.handle(request()).await,
        FromService::Refused {
            reason: Refusal::NotActive
        }
    ));
    single_permit(staying.handle(request()).await);
    // It cannot authenticate again either.
    let (mut connection, binding, challenge) = connect(&service);
    let answer = connection
        .handle(ToService::Authenticate {
            proof: proof_at(&account.at(2), &second, binding, challenge),
            account: account.id,
            device: second.id(),
            genesis: account.genesis.clone(),
        })
        .await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::NotActive
            }
        ),
        "{answer:?}"
    );
}

#[tokio::test]
async fn failed_home_key_lookup_returns_unavailable_without_append_permit() {
    let h = Harness::new();
    let owner = Device::new();
    let mut account = Account::create(&owner);
    h.publish(&account);
    let service = h.service();
    let mut connection = session(&service, &account, &owner).await;
    let original = account.add_device(&owner, &Device::new());
    let before = h.edge.head(account.log);
    SqlConnection::open(h.disk())
        .unwrap()
        .execute_batch("DROP TABLE projection_keys")
        .unwrap();
    let answer = submit(&h, &mut connection, &account, &original).await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    assert_eq!(h.edge.head(account.log), before);
    let db = SqlConnection::open(h.disk()).unwrap();
    let count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM account_events WHERE account=?1",
            [account.id.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn failed_home_membership_lookup_returns_unavailable_without_permit() {
    let h = Harness::new();
    let owner = Device::new();
    let removed = Device::new();
    let mut account = Account::create(&owner);
    account.add_device(&owner, &removed);
    h.publish(&account);
    let service = h.service();
    let mut leaving = session(&service, &account, &removed).await;
    let removal = account.remove_self(&removed);
    single_permit(submit(&h, &mut leaving, &account, &removal).await);
    let before = h.edge.head(account.log);
    SqlConnection::open(h.disk())
        .unwrap()
        .execute_batch("DROP TABLE projection_devices")
        .unwrap();
    let answer = leaving
        .handle(ToService::Permits {
            items: vec![read_events(account.log)],
        })
        .await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    assert_eq!(h.edge.head(account.log), before);
}

#[tokio::test]
async fn failed_base_index_lookup_confirming_a_copy_returns_unavailable() {
    let (harness, mut mac, _service, mut connection) = own_base().await;
    let add = mac.pair(&Fold::new());
    mac.submit_account(&harness, &mut connection, &add).await;
    let copy = mac.copy(add.as_bytes()).unwrap();
    let answer = connection.handle(mac.submit_copy(&copy)).await;
    order(&harness, &answer, &copy).unwrap();
    // Applying the ordered copy reads the BASE copy's index, which fails:
    // a transient fault, not a record the device must register again.
    SqlConnection::open(harness.disk())
        .unwrap()
        .execute(
            "DELETE FROM projection_sources WHERE kind=2 AND source=?1",
            [mac.base.0.as_slice()],
        )
        .unwrap();
    let answer = connection
        .handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log: mac.base_log(),
                after: Head::EMPTY,
                max_events: 48,
            },
        })
        .await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
}

#[tokio::test]
async fn invalid_control_refused_no_permit() {
    let harness = Harness::new();
    let first = Device::new();
    let second = Device::new();
    let mut account = Account::create(&first);
    harness.publish(&account);
    let service = harness.service();
    let mut connection = session(&service, &account, &first).await;
    let head = harness.edge.head(account.log);
    // A control signed by a device the account does not have.
    let mut elsewhere = Account::create(&second);
    let foreign = elsewhere.add_device(&second, &Device::new());
    // A control prepared on a stale view: another control was ordered first.
    let stale = {
        let mut copy = Account::create(&first);
        copy.verified = account.verified.clone();
        copy.originals = account.originals.clone();
        copy.genesis = account.genesis.clone();
        copy.add_device(&first, &Device::new())
    };
    let addition = account.add_device(&first, &second);
    single_permit(submit(&harness, &mut connection, &account, &addition).await);
    let head_after = harness.edge.head(account.log);
    assert_eq!(head_after.position, head.position + 1);
    let mut tampered = account.add_device(&first, &Device::new());
    *tampered.last_mut().unwrap() ^= 1;
    for event in [
        vec![1, 2, 3],
        foreign,
        stale,
        tampered,
        account.genesis.clone(),
    ] {
        let answer = connection
            .handle(ToService::SubmitControl {
                log: account.log,
                event,
                delivery: None,
                attachment: None,
            })
            .await;
        assert!(
            matches!(
                answer,
                FromService::Refused {
                    reason: Refusal::Invalid
                }
            ),
            "{answer:?}"
        );
    }
    // Another account's log, and a base log: base controls are not supported.
    let answer = connection
        .handle(ToService::SubmitControl {
            log: elsewhere.log,
            event: elsewhere.genesis.clone(),
            delivery: None,
            attachment: None,
        })
        .await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Unknown
            }
        ),
        "{answer:?}"
    );
    let answer = connection
        .handle(ToService::SubmitControl {
            log: LogId {
                kind: LogKind::Base,
                id: [4; 32],
            },
            event: vec![1; 1024],
            delivery: None,
            attachment: None,
        })
        .await;
    refused(answer, Refusal::Unsupported);
    assert_eq!(harness.edge.head(account.log), head_after);
}

#[tokio::test]
async fn register_base_verifies_its_genesis_and_takes_the_content_epoch() {
    let harness = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    harness.publish(&account);
    let service = harness.service();
    let mut connection = session(&service, &account, &device).await;
    let genesis = account.base_genesis(&device);
    let base = genesis.log();
    let answer = connection.handle(genesis.register()).await;
    let FromService::Permits { items } = &answer else {
        panic!("{answer:?}")
    };
    let [stage, append] = [&items[0], &items[1]].map(|i| harness.permit(i.as_ref().unwrap()));
    let commitment = BodyObject::new(genesis.body.clone()).unwrap().commitment();
    assert_eq!(commitment, referenced_body(&genesis.descriptor).unwrap());
    assert!(
        stage.scope
            == Scope::Stage {
                log: base,
                body: commitment,
                len: genesis.body.len() as u32,
            }
    );
    // The content epoch is the content key's id, never the metadata key's,
    // and the two keys are independent.
    let epoch = bh_event::key_id(&genesis.content);
    assert_ne!(epoch, bh_event::key_id(&genesis.metadata));
    assert!(
        append.scope
            == Scope::Append {
                log: base,
                event: genesis.descriptor.digest(),
                body: Some(commitment),
                epoch,
                after: Some(Head::EMPTY),
                attached: None,
            }
    );
    order_genesis(&harness, &answer, &genesis);
    // An exact retry is answered the same way.
    let FromService::Permits { items } = connection.handle(genesis.register()).await else {
        panic!("retry")
    };
    assert!(harness.permit(items[0].as_ref().unwrap()).scope == stage.scope);
    assert!(harness.permit(items[1].as_ref().unwrap()).scope == append.scope);
    // Content appends carry that epoch; the metadata key's id is refused.
    let (content, _) = base_event(2);
    let FromService::Permits { items } = connection
        .handle(ToService::Permits {
            items: vec![
                Want::Append {
                    log: base,
                    event: content.encode(),
                    epoch,
                },
                Want::Append {
                    log: base,
                    event: content.encode(),
                    epoch: bh_event::key_id(&genesis.metadata),
                },
            ],
        })
        .await
    else {
        panic!("permits")
    };
    assert!(items[0].is_ok());
    assert_eq!(items[1].as_ref().err(), Some(&Refusal::Epoch));
}

#[tokio::test]
async fn another_account_cannot_register_a_base_first() {
    let harness = Harness::new();
    let mine = Device::new();
    let theirs = Device::new();
    let account = Account::create_full(&mine);
    let other = Account::create_full(&theirs);
    harness.publish(&account);
    harness.publish(&other);
    let service = harness.service();
    let genesis = account.base_genesis(&mine);
    // Copied descriptor, body and M, at either account's head: refused, and
    // nothing is recorded.
    let mut stranger = session(&service, &other, &theirs).await;
    refused(stranger.handle(genesis.register()).await, Refusal::Invalid);
    let ToService::RegisterBase {
        descriptor,
        body,
        metadata,
        ..
    } = genesis.register()
    else {
        unreachable!()
    };
    let at_their_head = ToService::RegisterBase {
        descriptor,
        body,
        creator_head: other.verified.head(),
        metadata,
    };
    refused(stranger.handle(at_their_head).await, Refusal::Invalid);
    let FromService::Permits { items } = stranger
        .handle(ToService::Permits {
            items: vec![read_events(genesis.log())],
        })
        .await
    else {
        panic!("permits")
    };
    assert_eq!(items[0], Err(Refusal::Unknown));
    // The creator still registers it, and the stranger still has no access.
    let mut connection = session(&service, &account, &mine).await;
    let answer = connection.handle(genesis.register()).await;
    order_genesis(&harness, &answer, &genesis);
    refused(stranger.handle(genesis.register()).await, Refusal::Invalid);
    let FromService::Permits { items } = stranger
        .handle(ToService::Permits {
            items: vec![read_events(genesis.log())],
        })
        .await
    else {
        panic!("permits")
    };
    assert_eq!(items[0], Err(Refusal::Unknown));
}

#[tokio::test]
async fn a_tampered_genesis_or_wrong_key_registers_nothing() {
    let harness = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    harness.publish(&account);
    let service = harness.service();
    let mut connection = session(&service, &account, &device).await;
    let genesis = account.base_genesis(&device);
    type Change<'a> = &'a dyn Fn(&mut Vec<u8>, &mut Vec<u8>, &mut bh_account::Head);
    let with = |change: Change| {
        let mut descriptor = genesis.descriptor.encode();
        let mut body = genesis.body.clone();
        let mut head = genesis.creator_head;
        change(&mut descriptor, &mut body, &mut head);
        let ToService::RegisterBase { metadata, .. } = genesis.register() else {
            unreachable!()
        };
        ToService::RegisterBase {
            descriptor,
            body,
            creator_head: head,
            metadata,
        }
    };
    let invalid = [
        with(&|d, _, _| *d.last_mut().unwrap() ^= 1),
        with(&|d, _, _| d[3] ^= 1),
        with(&|d, _, _| d[40] ^= 1),
        with(&|_, b, _| b[100] ^= 1),
        with(&|_, _, h| h.hash[0] ^= 1),
        with(&|_, _, h| h.position -= 1),
        with(&|_, _, h| h.position += 1),
        with(&|_, _, h| h.position = 0),
        genesis.register_with(&bh_crypto::Secret::random()),
        // K is not M.
        genesis.register_with(&genesis.content),
    ];
    for message in invalid {
        refused(connection.handle(message).await, Refusal::Invalid);
    }
    // Bytes that are no event, or a body of no body size, are malformed.
    refused(
        connection.handle(with(&|d, _, _| d.truncate(40))).await,
        Refusal::Malformed,
    );
    refused(
        connection.handle(with(&|_, b, _| b.push(0))).await,
        Refusal::Malformed,
    );
    // Nothing was recorded: the base serves no one, and the genuine
    // registration still succeeds.
    let FromService::Permits { items } = connection
        .handle(ToService::Permits {
            items: vec![read_events(genesis.log())],
        })
        .await
    else {
        panic!("permits")
    };
    assert_eq!(items[0], Err(Refusal::Unknown));
    let answer = connection.handle(genesis.register()).await;
    order_genesis(&harness, &answer, &genesis);
}

#[tokio::test]
async fn a_genesis_verifies_at_its_historical_head_with_an_active_device_now() {
    let harness = Harness::new();
    let first = Device::new();
    let second = Device::new();
    let mut account = Account::create_full(&first);
    // The first device makes the base, then the account moves on: a second
    // device joins and the first leaves.
    let genesis = account.base_genesis(&first);
    account.add_device(&first, &second);
    harness.publish(&account);
    let service = harness.service();
    let mut leaving = session(&service, &account, &first).await;
    account.remove_self(&first);
    harness.publish(&account);
    // The removed device's open session is refused now ...
    refused(leaving.handle(genesis.register()).await, Refusal::NotActive);
    // ... and the account's active device registers the historical genesis.
    let mut staying = session(&service, &account, &second).await;
    let answer = staying.handle(genesis.register()).await;
    order_genesis(&harness, &answer, &genesis);
}

#[tokio::test]
async fn the_metadata_key_is_never_stored() {
    let harness = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    harness.publish(&account);
    let genesis = account.base_genesis(&device);
    {
        let service = harness.service();
        let mut connection = session(&service, &account, &device).await;
        let answer = connection.handle(genesis.register()).await;
        order_genesis(&harness, &answer, &genesis);
    }
    // Base controls carry M too: an addition and a removal copied.
    let mut mac = Mac::new(&harness);
    {
        let service = harness.service();
        let mut connection = mac.session(&service).await;
        mac.register_and_order(&harness, &mut connection).await;
        let fold = Fold::new();
        let add = mac.pair(&fold);
        mac.submit_account(&harness, &mut connection, &add).await;
        mac.copy_ordered(&harness, &mut connection, add.as_bytes())
            .await;
        let removal = mac.remove(&fold);
        harness.order_original(mac.log, removal.as_bytes());
        let copy = mac.copy(removal.as_bytes()).unwrap();
        // Submitted, and left pending.
        let answer = connection.handle(mac.submit_copy(&copy)).await;
        assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    }
    let keys = [
        genesis.metadata.expose(),
        genesis.content.expose(),
        mac.metadata.expose(),
        mac.content.expose(),
    ];
    for entry in std::fs::read_dir(harness.dir.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !bytes
                .windows(32)
                .any(|w| keys.iter().any(|k| k.as_slice() == w))
        );
    }
}

/// An account with a published personal key, its first device, a session for
/// it, and the harness, ready to add a device with its delivery.
async fn pairing() -> (Harness, Account, Device, Service, Connection) {
    let harness = Harness::new();
    let first = Device::new();
    let account = Account::create_full(&first);
    harness.publish(&account);
    let service = harness.service();
    let connection = session(&service, &account, &first).await;
    (harness, account, first, service, connection)
}
fn submit_with(account: &Account, event: &[u8], recipient: &Device, frame: &[u8]) -> ToService {
    ToService::SubmitControl {
        log: account.log,
        event: event.to_vec(),
        delivery: Some(Box::new(Delivery {
            recipient: recipient.keys.clone(),
            frame: frame.to_vec(),
        })),
        attachment: None,
    }
}

#[tokio::test]
async fn an_addition_and_its_delivery_are_staged_and_ordered_together() {
    let (harness, mut account, first, service, mut connection) = pairing().await;
    let new = Device::new();
    let (added, frame) = account.add_with_delivery(&first, &new);
    let head = harness.edge.head(account.log);
    let message = submit_with(&account, added.as_bytes(), &new, &frame);
    let answer = connection.handle(message.clone()).await;
    let FromService::Permits { items } = &answer else {
        panic!("{answer:?}")
    };
    let body = delivery_body(&frame).unwrap();
    let commitment = body.commitment();
    let wrapped = account_log_wrap(added.as_bytes(), Some(commitment)).unwrap();
    let [stage, append] = [&items[0], &items[1]].map(|i| harness.permit(i.as_ref().unwrap()));
    assert!(
        stage.scope
            == Scope::Stage {
                log: account.log,
                body: commitment,
                len: body.bytes().len() as u32,
            }
    );
    assert!(
        append.scope
            == Scope::Append {
                log: account.log,
                event: wrapped.digest(),
                body: Some(commitment),
                epoch: ACCOUNT_EPOCH,
                after: Some(head),
                attached: None,
            }
    );
    // The original signed bytes travel unchanged inside the wrapper.
    assert!(account_log_unwrap(&wrapped).unwrap() == (added.as_bytes(), Some(commitment)));
    // A retry before ordering names the same wrapper and body.
    let FromService::Permits { items: again } = connection.handle(message).await else {
        panic!("retry")
    };
    assert!(harness.permit(again[0].as_ref().unwrap()).scope == stage.scope);
    assert!(harness.permit(again[1].as_ref().unwrap()).scope == append.scope);
    // The body cannot be skipped: the log object requires it staged.
    assert_eq!(
        harness
            .edge
            .append(items[1].as_ref().unwrap(), &wrapped)
            .err()
            .as_deref(),
        Some("NotStaged")
    );
    harness
        .edge
        .stage(items[0].as_ref().unwrap(), body.bytes())
        .unwrap();
    harness
        .edge
        .append(items[1].as_ref().unwrap(), &wrapped)
        .unwrap();
    account.apply(&added);
    // The added device authenticates and may read the delivery; an unrelated
    // digest is not readable, whoever asks.
    let mut joined = session(&service, &account, &new).await;
    let reads = ToService::Permits {
        items: vec![
            Want::ReadBodies {
                log: account.log,
                bodies: vec![commitment],
            },
            Want::ReadBodies {
                log: account.log,
                bodies: vec![Digest([9; 32])],
            },
            Want::ReadBodies {
                log: account.log,
                bodies: vec![commitment, Digest([9; 32])],
            },
        ],
    };
    for connection in [&mut joined, &mut connection] {
        let FromService::Permits { items } = connection.handle(reads.clone()).await else {
            panic!("permits")
        };
        assert!(
            harness.permit(items[0].as_ref().unwrap()).scope
                == Scope::ReadBodies {
                    log: account.log,
                    bodies: vec![commitment]
                }
        );
        assert_eq!(items[1], Err(Refusal::Unknown));
        assert_eq!(items[2], Err(Refusal::Unknown));
    }
    // Once the added device leaves, it can read nothing; nor can a
    // connection that never authenticated.
    let removal = account.remove_self(&new);
    single_permit(submit(&harness, &mut joined, &account, &removal).await);
    refused(joined.handle(reads.clone()).await, Refusal::NotActive);
    let (mut anonymous, _, _) = connect(&service);
    refused(anonymous.handle(reads).await, Refusal::Unauthenticated);
}

#[tokio::test]
async fn a_delivery_not_bound_to_its_addition_gets_no_permit() {
    let (harness, account, first, _service, mut connection) = pairing().await;
    let new = Device::new();
    let (added, frame) = account.add_with_delivery(&first, &new);
    let (other_added, other_frame) = account.add_with_delivery(&first, &Device::new());
    let head = harness.edge.head(account.log);
    let mut bad_signature = frame.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    let mut bad_envelope = frame.clone();
    bad_envelope[8 + 75] ^= 1;
    // The recipient signing its own delivery: valid after the add, but not
    // by a device the account had.
    let self_signed = {
        let mut copy = frame.clone();
        let n = copy.len();
        copy[n - 96..n - 64].copy_from_slice(&new.id().0);
        let signature = new.ordinary.sign(&copy[..n - 64]);
        copy[n - 64..].copy_from_slice(&signature);
        copy
    };
    // Another account's genuine delivery.
    let (foreign_frame, foreign_new) = {
        let device = Device::new();
        let elsewhere = Account::create_full(&device);
        let new = Device::new();
        (elsewhere.add_with_delivery(&device, &new).1, new)
    };
    let personal = account.personal.as_ref().unwrap().public();
    // A forged frame to the right device is accepted here, so the forgeries
    // below differ from a genuine delivery only in what each names.
    let forged = account.forge_delivery(&first, &new.keys, &personal);
    let to_active = account.forge_delivery(&first, &first.keys, &personal);
    let stale_publication = account.forge_delivery(&first, &new.keys, &[5; 1216]);
    let removal = {
        let draft = account.verified.remove_self(first.id()).unwrap();
        draft
            .finish(first.control.sign(draft.signing_bytes()))
            .unwrap()
    };
    let cases = [
        submit_with(&account, added.as_bytes(), &new, &bad_signature),
        submit_with(&account, added.as_bytes(), &new, &bad_envelope),
        submit_with(&account, added.as_bytes(), &new, &self_signed),
        submit_with(&account, added.as_bytes(), &new, &frame[..frame.len() - 1]),
        // The delivery to another device than the one added, either way named.
        submit_with(&account, added.as_bytes(), &new, &other_frame),
        submit_with(&account, other_added.as_bytes(), &new, &frame),
        // An already-active device is not the one this addition introduces.
        submit_with(&account, added.as_bytes(), &first, &frame),
        submit_with(&account, added.as_bytes(), &first, &to_active),
        submit_with(&account, added.as_bytes(), &new, &stale_publication),
        submit_with(&account, added.as_bytes(), &foreign_new, &foreign_frame),
        submit_with(&account, added.as_bytes(), &new, &foreign_frame),
        // A delivery on a control that adds no device.
        submit_with(&account, removal.as_bytes(), &new, &frame),
    ];
    for message in cases {
        refused(connection.handle(message).await, Refusal::Invalid);
    }
    assert_eq!(harness.edge.head(account.log), head);
    // The forged frame to the added device passes the public checks: only
    // the recipient can tell its seed is not the personal key.
    let FromService::Permits { items } = connection
        .handle(submit_with(&account, added.as_bytes(), &new, &forged))
        .await
    else {
        panic!("forged frame shape")
    };
    assert_eq!(items.len(), 2);
    // The genuine pair still gets its permits.
    let FromService::Permits { items } = connection
        .handle(submit_with(&account, added.as_bytes(), &new, &frame))
        .await
    else {
        panic!("permits")
    };
    assert_eq!(items.len(), 2);
}

/// A Mac whose own base is registered and its genesis ordered, with the
/// service and the Mac's session.
async fn own_base() -> (Harness, Mac, Service, Connection) {
    let harness = Harness::new();
    let mut mac = Mac::new(&harness);
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    mac.register_and_order(&harness, &mut connection).await;
    (harness, mac, service, connection)
}

/// One content append on the Mac's base under `epoch`, answered alone.
async fn write(
    connection: &mut Connection,
    mac: &Mac,
    epoch: [u8; 32],
) -> Result<Vec<u8>, Refusal> {
    let answer = connection
        .handle(ToService::Permits {
            items: vec![Want::Append {
                log: mac.base_log(),
                event: base_event(3).0.encode(),
                epoch,
            }],
        })
        .await;
    match answer {
        FromService::Permits { mut items } => items.remove(0),
        FromService::Refused { reason } => Err(reason),
        other => panic!("{other:?}"),
    }
}

fn scopes(harness: &Harness, answer: &FromService) -> Vec<Scope> {
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    items
        .iter()
        .map(|i| harness.permit(i.as_ref().unwrap()).scope)
        .collect()
}

#[tokio::test]
async fn base_copy_of_ordered_add_permitted() {
    let (harness, mut mac, service, mut connection) = own_base().await;
    let epoch = bh_event::key_id(&mac.content);
    // The Mac has written before it pairs: content follows the genesis.
    let note = mac.note("before pairing");
    let FromService::Permits { items } = connection
        .handle(ToService::Permits {
            items: vec![
                Want::Stage {
                    log: mac.base_log(),
                    body: BodyObject::new(note.body.clone()).unwrap().commitment(),
                    len: note.body.len() as u32,
                },
                Want::Append {
                    log: mac.base_log(),
                    event: note.descriptor.encode(),
                    epoch,
                },
            ],
        })
        .await
    else {
        panic!("permits")
    };
    let note_answer = FromService::Permits { items };
    order(&harness, &note_answer, &note).unwrap();
    assert_eq!(mac.pull(&harness), vec![bh_event::Outcome::Accepted]);
    let genesis_head = harness.edge.after(mac.base_log(), 0)[0].0.head();
    let fold = Fold::new();
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    let copy = mac.copy(add.as_bytes()).unwrap();
    let answer = connection.handle(mac.submit_copy(&copy)).await;
    let body = BodyObject::new(copy.body.clone()).unwrap().commitment();
    // A stage permit for its body and an append permit after the control
    // head, the genesis, not the log head; an addition keeps the epoch.
    assert!(
        scopes(&harness, &answer)
            == vec![
                Scope::Stage {
                    log: mac.base_log(),
                    body,
                    len: copy.body.len() as u32,
                },
                Scope::Append {
                    log: mac.base_log(),
                    event: copy.descriptor.digest(),
                    body: Some(body),
                    epoch,
                    after: Some(genesis_head),
                    attached: None,
                },
            ]
    );
    order(&harness, &answer, &copy).unwrap();
    assert_eq!(mac.pull(&harness), vec![bh_event::Outcome::Accepted]);
    // Once copied the Fold writes. Confirming the copy reads the base's
    // controls once; later permits read none.
    let mut folded = mac.fold_session(&service, &fold).await;
    let reads = harness.edge.control_reads.load(Ordering::SeqCst);
    write(&mut folded, &mac, epoch).await.unwrap();
    write(&mut connection, &mac, epoch).await.unwrap();
    write(&mut folded, &mac, epoch).await.unwrap();
    assert_eq!(harness.edge.control_reads.load(Ordering::SeqCst), reads + 1);
}

#[tokio::test]
async fn base_copy_must_equal_ordered_account_event() {
    let (harness, mut mac, _service, mut connection) = own_base().await;
    let base_position = mac.originals.len();
    let at_base = mac.ordered.clone();
    let (first, second, third) = (Fold::new(), Fold::new(), Fold::new());
    let add = mac.pair(&first);
    mac.submit_account(&harness, &mut connection, &add).await;
    let next = mac.pair(&second);
    mac.submit_account(&harness, &mut connection, &next).await;
    // Valid next events for the base's copy of the account, which the
    // device producer copies, but not the ordered one: an addition never
    // ordered, and the second addition signed first.
    let forged = mac.sign_add(&at_base, &third);
    let reordered = mac.sign_add(&at_base, &second);
    // A copy skipping the ordered next event, which only a device lying
    // about the base's copy of the account makes.
    let claimed = mac.at(base_position + 1);
    let skipped = mac.copy_claiming(&claimed, next.as_bytes());
    let control_head = harness.edge.head(mac.base_log());
    for copy in [
        mac.copy(forged.as_bytes()).unwrap(),
        mac.copy(reordered.as_bytes()).unwrap(),
        skipped,
    ] {
        refused(
            connection.handle(mac.submit_copy(&copy)).await,
            Refusal::Invalid,
        );
    }
    assert_eq!(harness.edge.head(mac.base_log()), control_head);
    // Nothing is pending: the ordered next event copies, then the one after.
    mac.copy_ordered(&harness, &mut connection, add.as_bytes())
        .await;
    // Copying it again is a replay.
    let again = mac.copy_claiming(&at_base, add.as_bytes());
    refused(
        connection.handle(mac.submit_copy(&again)).await,
        Refusal::Invalid,
    );
    mac.copy_ordered(&harness, &mut connection, next.as_bytes())
        .await;
    assert_eq!(mac.history.account_head(), next.head());
}

#[tokio::test]
async fn base_control_wrong_m_or_tampered_refused() {
    let (harness, mut mac, _service, mut connection) = own_base().await;
    let fold = Fold::new();
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    let copy = mac.copy(add.as_bytes()).unwrap();
    let submit = |descriptor: Vec<u8>, body: Vec<u8>, metadata: &bh_crypto::Secret<32>| {
        ToService::SubmitBaseControl {
            log: mac.base_log(),
            descriptor,
            body,
            metadata: MetadataKey::new(metadata),
        }
    };
    let descriptor = copy.descriptor.encode();
    let flip = |bytes: &[u8], at: usize| {
        let mut bytes = bytes.to_vec();
        bytes[at] ^= 1;
        bytes
    };
    for message in [
        submit(
            descriptor.clone(),
            copy.body.clone(),
            &bh_crypto::Secret::random(),
        ),
        // K is not M.
        submit(descriptor.clone(), copy.body.clone(), &mac.content),
        submit(
            flip(&descriptor, descriptor.len() - 1),
            copy.body.clone(),
            &mac.metadata,
        ),
        submit(flip(&descriptor, 100), copy.body.clone(), &mac.metadata),
        submit(descriptor.clone(), flip(&copy.body, 10), &mac.metadata),
    ] {
        refused(connection.handle(message).await, Refusal::Invalid);
    }
    refused(
        connection
            .handle(submit(
                descriptor[..40].to_vec(),
                copy.body.clone(),
                &mac.metadata,
            ))
            .await,
        Refusal::Malformed,
    );
    // Nothing is pending: the genuine copy is permitted.
    let answer = connection.handle(mac.submit_copy(&copy)).await;
    order(&harness, &answer, &copy).unwrap();
}

#[tokio::test]
async fn base_control_from_inactive_device_refused() {
    let (harness, mut mac, service, mut connection) = own_base().await;
    let fold = Fold::new();
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    mac.copy_ordered(&harness, &mut connection, add.as_bytes())
        .await;
    let mut folded = mac.fold_session(&service, &fold).await;
    let removal = mac.remove(&fold);
    harness.order_original(mac.log, removal.as_bytes());
    let copy = mac.copy(removal.as_bytes()).unwrap();
    refused(
        folded.handle(mac.submit_copy(&copy)).await,
        Refusal::NotActive,
    );
    let answer = connection.handle(mac.submit_copy(&copy)).await;
    order(&harness, &answer, &copy).unwrap();
}

#[tokio::test]
async fn base_control_on_account_log_refused() {
    let (harness, mut mac, service, mut connection) = own_base().await;
    let fold = Fold::new();
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    let copy = mac.copy(add.as_bytes()).unwrap();
    let ToService::SubmitBaseControl {
        descriptor,
        body,
        metadata,
        ..
    } = mac.submit_copy(&copy)
    else {
        unreachable!()
    };
    let on = |log| ToService::SubmitBaseControl {
        log,
        descriptor: descriptor.clone(),
        body: body.clone(),
        metadata: metadata.clone(),
    };
    // The account's own log, and a base nobody registered.
    refused(connection.handle(on(mac.log)).await, Refusal::Unknown);
    let unknown = LogId {
        kind: LogKind::Base,
        id: [4; 32],
    };
    refused(connection.handle(on(unknown)).await, Refusal::Unknown);
    // Another account's session, on this account's base.
    let other = Mac::new(&harness);
    let mut theirs = other.session(&service).await;
    refused(theirs.handle(on(mac.base_log())).await, Refusal::Unknown);
    assert_eq!(harness.edge.after(mac.base_log(), 1).len(), 0);
}

#[tokio::test]
async fn removal_copy_permit_closes_epoch() {
    let (harness, mut mac, _service, mut connection) = own_base().await;
    let fold = Fold::new();
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    mac.copy_ordered(&harness, &mut connection, add.as_bytes())
        .await;
    let control_head = harness.edge.head(mac.base_log());
    let removal = mac.remove(&fold);
    harness.order_original(mac.log, removal.as_bytes());
    let copy = mac.copy(removal.as_bytes()).unwrap();
    let answer = connection.handle(mac.submit_copy(&copy)).await;
    let Scope::Append { epoch, after, .. } = scopes(&harness, &answer)[1].clone() else {
        panic!("append")
    };
    assert_eq!((epoch, after), ([0; 32], Some(control_head)));
    order(&harness, &answer, &copy).unwrap();
    assert_eq!(mac.pull(&harness), vec![bh_event::Outcome::Accepted]);
    assert_eq!(mac.history.epoch_id(), None);
    assert_eq!(harness.edge.epoch(mac.base_log()), [0; 32]);
}

#[tokio::test]
async fn service_rekey_orders_attached_seal_set_and_refuses_old_epoch() {
    use bh_account::personal::{self, PersonalKey};
    use bh_authz::proto::{RecoveryAttachment, account_log_wrap, rotation_body};
    let (h, mut mac, _service, mut connection) = own_base().await;
    assert!(matches!(
        connection.handle(mac.home_objects.clone()).await,
        FromService::HomeObjectsStored { .. }
    ));
    let fold = Fold::new();
    let add = mac.pair(&fold);
    mac.submit_account(&h, &mut connection, &add).await;
    mac.copy_ordered(&h, &mut connection, add.as_bytes()).await;
    let removed = mac.remove(&fold);
    h.order_original(mac.log, removed.as_bytes());
    mac.copy_ordered(&h, &mut connection, removed.as_bytes())
        .await;
    // This fixture's local owner still has legacy (untimed) originals;
    // rekey preparation must use the same confirmed projection the home and
    // base copied, not its untimed compatibility view.
    let time = bh_account::ConfirmedTime {
        earliest_ms: h.clock.now(),
        latest_ms: h.clock.now(),
    };
    let mut timed = mac.anchor.clone();
    timed.apply_timed(add.as_bytes(), Some(time)).unwrap();
    timed.apply_timed(removed.as_bytes(), Some(time)).unwrap();
    mac.ordered = timed;
    let old_epoch = bh_event::key_id(&mac.content);
    assert_eq!(h.edge.epoch(mac.base_log()), [0; 32]);
    let next_personal = PersonalKey::generate();
    let prepared = personal::prepare_rotation(&mac.ordered, &next_personal).unwrap();
    let rotation = mac.sign_rotation(removed.head().position, &prepared);
    let commitment = stage_rotation(&h, &mut connection, mac.log, &prepared.body).await;
    let answer = connection
        .handle(ToService::SubmitControl {
            log: mac.log,
            event: rotation.as_bytes().to_vec(),
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
    let body = rotation_body(&prepared.body).unwrap();
    let wrapped = account_log_wrap(rotation.as_bytes(), Some(body.commitment())).unwrap();
    let [append] = <[_; 1]>::try_from(items).unwrap();
    h.edge.append(append.as_ref().unwrap(), &wrapped).unwrap();
    let answer = connection
        .handle(ToService::ConfirmControl {
            log: mac.log,
            event: wrapped.digest(),
            challenge: [19; 32],
        })
        .await;
    let FromService::Confirmed { confirmation, .. } = answer else {
        panic!("{answer:?}")
    };
    let next_epoch = bh_crypto::Secret::<32>::random();
    let (rekey, seal_set) = mac.signed_rekey(&rotation, &confirmation, &next_epoch);
    let answer = connection.handle(mac.submit_copy(&rekey)).await;
    let FromService::Permits { items } = &answer else {
        panic!("{answer:?}")
    };
    assert_eq!(items.len(), 2, "base body and append");
    let scopes = scopes(&h, &answer);
    assert!(
        matches!(scopes[1], Scope::Append { attached: Some(digest), .. }
        if digest == seal_set.commitment())
    );
    let seal_stage = single_permit(
        connection
            .handle(ToService::Permits {
                items: vec![Want::Stage {
                    log: mac.base_log(),
                    body: seal_set.commitment(),
                    len: seal_set.bytes().len() as u32,
                }],
            })
            .await,
    );
    h.edge.stage(&seal_stage, seal_set.bytes()).unwrap();
    h.edge
        .stage(items[0].as_ref().unwrap(), &rekey.body)
        .unwrap();
    h.edge
        .append(items[1].as_ref().unwrap(), &rekey.descriptor)
        .unwrap();
    assert_eq!(
        write(&mut connection, &mac, old_epoch).await,
        Err(Refusal::Epoch)
    );
    let new_id = bh_event::key_id(&next_epoch);
    assert!(write(&mut connection, &mac, new_id).await.is_ok());
}

#[tokio::test]
async fn content_refused_while_removal_uncopied() {
    let (harness, mut mac, _service, mut connection) = own_base().await;
    let epoch = bh_event::key_id(&mac.content);
    let fold = Fold::new();
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    mac.copy_ordered(&harness, &mut connection, add.as_bytes())
        .await;
    write(&mut connection, &mac, epoch).await.unwrap();
    // The Fold leaves the account; until its removal is copied into the
    // base, the base takes no content from anyone.
    let removal = mac.remove(&fold);
    harness.order_original(mac.log, removal.as_bytes());
    assert_eq!(
        write(&mut connection, &mac, epoch).await,
        Err(Refusal::AccountChangePending)
    );
    // Reading goes on.
    single_permit(
        connection
            .handle(ToService::Permits {
                items: vec![read_events(mac.base_log())],
            })
            .await,
    );
    mac.copy_ordered(&harness, &mut connection, removal.as_bytes())
        .await;
    assert_eq!(
        write(&mut connection, &mac, epoch).await,
        Err(Refusal::Epoch)
    );
}

#[tokio::test]
async fn content_requires_author_in_base_projection() {
    let (harness, mut mac, service, mut connection) = own_base().await;
    let epoch = bh_event::key_id(&mac.content);
    let fold = Fold::new();
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    // The Fold is in the account, not yet in the base's copy of it: it
    // reads the base but cannot write to it.
    let mut folded = mac.fold_session(&service, &fold).await;
    assert_eq!(
        write(&mut folded, &mac, epoch).await,
        Err(Refusal::NotActive)
    );
    single_permit(
        folded
            .handle(ToService::Permits {
                items: vec![read_events(mac.base_log())],
            })
            .await,
    );
    assert_eq!(
        write(&mut connection, &mac, epoch).await,
        Err(Refusal::AccountChangePending)
    );
    mac.copy_ordered(&harness, &mut connection, add.as_bytes())
        .await;
    write(&mut folded, &mac, epoch).await.unwrap();
    write(&mut connection, &mac, epoch).await.unwrap();
}

#[tokio::test]
async fn content_refused_when_epoch_closed() {
    let (harness, mut mac, _service, mut connection) = own_base().await;
    let epoch = bh_event::key_id(&mac.content);
    let fold = Fold::new();
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    mac.copy_ordered(&harness, &mut connection, add.as_bytes())
        .await;
    let removal = mac.remove(&fold);
    harness.order_original(mac.log, removal.as_bytes());
    mac.copy_ordered(&harness, &mut connection, removal.as_bytes())
        .await;
    for epoch in [epoch, [0; 32], bh_event::key_id(&mac.metadata)] {
        assert_eq!(
            write(&mut connection, &mac, epoch).await,
            Err(Refusal::Epoch)
        );
    }
}

#[tokio::test]
async fn pending_confirmed_without_m() {
    let (harness, mut mac, service, mut connection) = own_base().await;
    let epoch = bh_event::key_id(&mac.content);
    let fold = Fold::new();
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    let copy = mac.copy(add.as_bytes()).unwrap();
    let answer = connection.handle(mac.submit_copy(&copy)).await;
    order(&harness, &answer, &copy).unwrap();
    mac.pull(&harness);
    // A plain permit request, carrying no key, confirms the ordered copy.
    let mut folded = mac.fold_session(&service, &fold).await;
    write(&mut folded, &mac, epoch).await.unwrap();
    // The next control follows the confirmed one.
    let control_head = harness.edge.head(mac.base_log());
    let removal = mac.remove(&fold);
    harness.order_original(mac.log, removal.as_bytes());
    let copy = mac.copy(removal.as_bytes()).unwrap();
    let answer = connection.handle(mac.submit_copy(&copy)).await;
    let Scope::Append { after, .. } = scopes(&harness, &answer)[1].clone() else {
        panic!("append")
    };
    assert_eq!(after, Some(control_head));
}

#[tokio::test]
async fn one_pending_control_per_base() {
    let (harness, mut mac, _service, mut connection) = own_base().await;
    let fold = Fold::new();
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    let first = mac.copy(add.as_bytes()).unwrap();
    let answer = connection.handle(mac.submit_copy(&first)).await;
    // While it is pending, a request's appends read the base's controls once.
    let reads = harness.edge.control_reads.load(Ordering::SeqCst);
    let append = Want::Append {
        log: mac.base_log(),
        event: base_event(3).0.encode(),
        epoch: bh_event::key_id(&mac.content),
    };
    let FromService::Permits { items } = connection
        .handle(ToService::Permits {
            items: vec![append.clone(), append.clone(), append],
        })
        .await
    else {
        panic!("permits")
    };
    assert_eq!(items, vec![Err(Refusal::AccountChangePending); 3]);
    assert_eq!(harness.edge.control_reads.load(Ordering::SeqCst), reads + 1);
    // The same bytes again get fresh permits for the same predecessor.
    harness.clock.advance(1_000);
    let again = connection.handle(mac.submit_copy(&first)).await;
    assert!(scopes(&harness, &again) == scopes(&harness, &answer));
    let FromService::Permits { items } = &again else {
        unreachable!()
    };
    assert!(
        harness.permit(items[1].as_ref().unwrap()).issued_ms > {
            let FromService::Permits { items } = &answer else {
                unreachable!()
            };
            harness.permit(items[1].as_ref().unwrap()).issued_ms
        }
    );
    // A different copy of the same event waits for the first.
    let second = mac.copy(add.as_bytes()).unwrap();
    assert_ne!(second.descriptor.digest(), first.descriptor.digest());
    refused(
        connection.handle(mac.submit_copy(&second)).await,
        Refusal::Conflict,
    );
    // Its permits lapse unused; a minute after their deadline the other
    // copy may go.
    harness.clock.advance(30_000 + 59_000);
    refused(
        connection.handle(mac.submit_copy(&second)).await,
        Refusal::Conflict,
    );
    harness.clock.advance(2_000);
    let answer = connection.handle(mac.submit_copy(&second)).await;
    assert!(order(&harness, &again, &first).is_err());
    order(&harness, &answer, &second).unwrap();
    assert_eq!(mac.pull(&harness), vec![bh_event::Outcome::Accepted]);
}

#[tokio::test]
async fn registering_again_keeps_a_pending_control() {
    let (harness, mut mac, service, mut connection) = own_base().await;
    let fold = Fold::new();
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    let copy = mac.copy(add.as_bytes()).unwrap();
    let answer = connection.handle(mac.submit_copy(&copy)).await;
    let again = connection.handle(mac.register()).await;
    assert!(matches!(again, FromService::Permits { .. }), "{again:?}");
    // Ordered after the record was rebuilt, it is still confirmed.
    order(&harness, &answer, &copy).unwrap();
    let mut folded = mac.fold_session(&service, &fold).await;
    write(&mut folded, &mac, bh_event::key_id(&mac.content))
        .await
        .unwrap();
}

#[tokio::test]
async fn base_run_of_ordered_add_permitted_and_confirmed() {
    let (harness, mut mac, service, mut connection) = own_base().await;
    let epoch = bh_event::key_id(&mac.content);
    let fold = Fold::new();
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    let confirmation = mac.confirm(&add);
    let copy = mac.copy_run(&[(add.as_bytes().to_vec(), confirmation)]);
    let answer = connection.handle(mac.submit_copy(&copy)).await;
    // An addition keeps the epoch, and a run attaches no other body.
    let Scope::Append {
        epoch: permitted,
        attached,
        ..
    } = scopes(&harness, &answer)[1].clone()
    else {
        panic!("append")
    };
    assert_eq!((permitted, attached), (epoch, None));
    order(&harness, &answer, &copy).unwrap();
    assert_eq!(mac.pull(&harness), vec![bh_event::Outcome::Accepted]);
    // Confirming the run by its readback applies it, with its confirmed
    // time, to the base's copy of the account: the Fold writes.
    let mut folded = mac.fold_session(&service, &fold).await;
    write(&mut folded, &mac, epoch).await.unwrap();
    write(&mut connection, &mac, epoch).await.unwrap();
}

#[tokio::test]
async fn base_run_must_equal_ordered_account_events() {
    let (harness, mut mac, _service, mut connection) = own_base().await;
    let at_base = mac.ordered.clone();
    let (first, second) = (Fold::new(), Fold::new());
    let add = mac.pair(&first);
    mac.submit_account(&harness, &mut connection, &add).await;
    // A valid next event for the base's copy, never ordered in the account.
    let forged = mac.sign_add(&at_base, &second);
    let confirmation = mac.confirm(&forged);
    let copy = mac.copy_run(&[(forged.as_bytes().to_vec(), confirmation)]);
    refused(
        connection.handle(mac.submit_copy(&copy)).await,
        Refusal::Invalid,
    );
    let confirmation = mac.confirm(&add);
    let copy = mac.copy_run(&[(add.as_bytes().to_vec(), confirmation)]);
    let answer = connection.handle(mac.submit_copy(&copy)).await;
    order(&harness, &answer, &copy).unwrap();
    assert_eq!(mac.pull(&harness), vec![bh_event::Outcome::Accepted]);
    assert_eq!(mac.history.account_head(), add.head());
}
