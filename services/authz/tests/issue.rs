//! Authentication and permit issuance.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_authz::proto::{FromService, Refusal, ToService, Want};
use bh_sync::{Digest, permit::Scope, referenced_body};
use std::sync::atomic::Ordering;
use support::*;

#[tokio::test]
async fn unknown_device_refused() {
    let harness = Harness::new();
    let first = Device::new();
    let account = Account::create(&first);
    harness.publish(&account);
    let service = harness.service();
    // A device that was never added signs a well-formed proof at the head.
    let stranger = Device::new();
    let (mut connection, binding, challenge) = connect(&service);
    let answer = connection
        .handle(ToService::Authenticate {
            proof: raw_proof(&account, &stranger, binding, challenge),
            account: account.id,
            device: stranger.id(),
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
    // Nothing is issued on that connection, and its challenge is spent.
    let answer = connection
        .handle(ToService::Permits {
            items: vec![read_events(account.log)],
        })
        .await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Unauthenticated
            }
        ),
        "{answer:?}"
    );
    // A genesis that is not the named account's is refused too.
    let (mut connection, binding, challenge) = connect(&service);
    let answer = connection
        .handle(ToService::Authenticate {
            proof: proof_at(&account.verified, &first, binding, challenge),
            account: account.id,
            device: first.id(),
            genesis: Account::create(&stranger).genesis,
        })
        .await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Unauthenticated
            }
        ),
        "{answer:?}"
    );
}

#[tokio::test]
async fn challenge_single_use() {
    let harness = Harness::new();
    let device = Device::new();
    let account = Account::create(&device);
    harness.publish(&account);
    let service = harness.service();
    let (mut connection, binding, challenge) = connect(&service);
    let message = authenticate_message(&account, &device, binding, challenge);
    assert!(matches!(
        connection.handle(message.clone()).await,
        FromService::Authenticated { .. }
    ));
    // The same proof again on the same connection: the challenge is spent.
    assert!(matches!(
        connection.handle(message.clone()).await,
        FromService::Refused {
            reason: Refusal::Unauthenticated
        }
    ));
    // On another connection the binding and challenge differ.
    let (mut other, _, _) = connect(&service);
    assert!(matches!(
        other.handle(message).await,
        FromService::Refused {
            reason: Refusal::Unauthenticated
        }
    ));
    // Each connection's challenge is fresh.
    let (_, _, again) = connect(&service);
    assert_ne!(again, challenge);
}

#[tokio::test]
async fn permit_deadline_bound() {
    let harness = Harness::new();
    let device = Device::new();
    let account = Account::create(&device);
    harness.publish(&account);
    let service = harness.service();
    let mut connection = session(&service, &account, &device).await;
    // Each head lookup takes 5 s of the clock: a permit's life starts when the
    // lookup that supports it starts, never later.
    harness.edge.read_takes.store(5_000, Ordering::SeqCst);
    let before = harness.clock.now();
    let answer = connection
        .handle(ToService::Permits {
            items: vec![
                read_events(account.log),
                Want::Subscribe { log: account.log },
            ],
        })
        .await;
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    assert_eq!(items.len(), 2);
    for item in items {
        let signed = item.unwrap();
        let permit = bh_sync::permit::verify(harness.root.public(), &signed, before).unwrap();
        assert_eq!(permit.issued_ms, before);
        assert!(permit.deadline_ms - permit.issued_ms <= 30_000);
        assert_eq!(permit.deadline_ms, before + 30_000);
    }
    assert!(harness.clock.now() >= before + 5_000);
    // A later request is supported by its own, later lookup.
    let later = harness.clock.now();
    let signed = single_permit(
        connection
            .handle(ToService::Permits {
                items: vec![read_events(account.log)],
            })
            .await,
    );
    assert_eq!(harness.permit(&signed).issued_ms, later);
}

#[tokio::test]
async fn edge_unreachable_means_unavailable() {
    let harness = Harness::new();
    let device = Device::new();
    let account = Account::create(&device);
    harness.publish(&account);
    let service = harness.service();
    let mut connection = session(&service, &account, &device).await;
    harness.edge.down.store(true, Ordering::SeqCst);
    let reads = harness.edge.reads.load(Ordering::SeqCst);
    for message in [
        ToService::Permits {
            items: vec![read_events(account.log)],
        },
        ToService::SubmitControl {
            log: account.log,
            event: account.genesis.clone(),
            delivery: None,
        },
    ] {
        assert!(matches!(
            connection.handle(message).await,
            FromService::Unavailable
        ));
    }
    assert!(
        harness.edge.reads.load(Ordering::SeqCst) > reads,
        "it tried"
    );
    let (mut fresh, binding, challenge) = connect(&service);
    assert!(matches!(
        fresh
            .handle(authenticate_message(&account, &device, binding, challenge))
            .await,
        FromService::Unavailable
    ));
    // Once the edge answers again, the same session is served.
    harness.edge.down.store(false, Ordering::SeqCst);
    single_permit(
        connection
            .handle(ToService::Permits {
                items: vec![read_events(account.log)],
            })
            .await,
    );
}

#[tokio::test]
async fn append_permit_binds_the_body_its_event_references() {
    let harness = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    harness.publish(&account);
    let service = harness.service();
    let mut connection = session(&service, &account, &device).await;
    let genesis = account.base_genesis(&device);
    let base = genesis.log();
    let epoch = bh_event::key_id(&genesis.content);
    let answer = connection.handle(genesis.register()).await;
    order_genesis(&harness, &answer, &genesis);
    // A content append: the permit names exactly the event and the body its
    // first 32 envelope bytes commit to, with no predecessor.
    let (content, content_body) = base_event(2);
    let signed = single_permit(
        connection
            .handle(ToService::Permits {
                items: vec![Want::Append {
                    log: base,
                    event: content.encode(),
                    epoch,
                }],
            })
            .await,
    );
    let Scope::Append {
        log,
        event,
        body,
        epoch: permitted,
        after,
    } = harness.permit(&signed).scope
    else {
        panic!("append scope")
    };
    assert!(log == base);
    assert_eq!(event, content.digest());
    assert_eq!(body, Some(referenced_body(&content).unwrap()));
    assert_ne!(body, None);
    assert_eq!((permitted, after), (epoch, None));
    // The edge then refuses it until that body is staged.
    assert_eq!(
        harness.edge.append(&signed, &content).err().as_deref(),
        Some("NotStaged")
    );
    let stage = single_permit(
        connection
            .handle(ToService::Permits {
                items: vec![Want::Stage {
                    log: base,
                    body: referenced_body(&content).unwrap(),
                    len: 1024,
                }],
            })
            .await,
    );
    harness.edge.stage(&stage, &content_body).unwrap();
    assert_eq!(harness.edge.append(&signed, &content).unwrap().position, 2);
    // Bytes that are not an event, and the wrong epoch, are refused per item.
    let answer = connection
        .handle(ToService::Permits {
            items: vec![
                Want::Append {
                    log: base,
                    event: vec![0; 40],
                    epoch,
                },
                Want::Append {
                    log: base,
                    event: content.encode(),
                    epoch: [8; 32],
                },
                Want::ReadBodies {
                    log: base,
                    bodies: vec![Digest([1; 32])],
                },
            ],
        })
        .await;
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    assert_eq!(items[0].as_ref().err(), Some(&Refusal::Malformed));
    assert_eq!(items[1].as_ref().err(), Some(&Refusal::Epoch));
    assert!(items[2].is_ok());
}

#[tokio::test]
async fn a_proof_at_an_older_verified_head_authenticates_at_the_current_one() {
    let harness = Harness::new();
    let first = Device::new();
    let second = Device::new();
    let mut account = Account::create(&first);
    account.add_device(&first, &second);
    harness.publish(&account);
    let service = harness.service();
    // The first device has not seen the addition yet: it signs at position 1.
    let (mut connection, binding, challenge) = connect(&service);
    let answer = connection
        .handle(ToService::Authenticate {
            proof: proof_at(&account.at(1), &first, binding, challenge),
            account: account.id,
            device: first.id(),
            genesis: account.genesis.clone(),
        })
        .await;
    let FromService::Authenticated { account_head } = answer else {
        panic!("{answer:?}")
    };
    assert_eq!(account_head, account.verified.head());
    // A proof at a head the account never had is refused.
    let (mut connection, binding, challenge) = connect(&service);
    let mut proof = proof_at(&account.at(1), &first, binding, challenge);
    proof[74] ^= 1;
    assert!(matches!(
        connection
            .handle(ToService::Authenticate {
                proof,
                account: account.id,
                device: first.id(),
                genesis: account.genesis.clone(),
            })
            .await,
        FromService::Refused {
            reason: Refusal::Unauthenticated
        }
    ));
}

#[tokio::test]
async fn permits_only_for_the_sessions_account_and_its_bases() {
    let harness = Harness::new();
    let mine = Device::new();
    let theirs = Device::new();
    let account = Account::create(&mine);
    let other = Account::create(&theirs);
    harness.publish(&account);
    harness.publish(&other);
    let service = harness.service();
    let mut connection = session(&service, &account, &mine).await;
    let unknown_base = bh_sync::permit::LogId {
        kind: bh_sync::permit::LogKind::Base,
        id: [9; 32],
    };
    let answer = connection
        .handle(ToService::Permits {
            items: vec![
                read_events(other.log),
                read_events(unknown_base),
                Want::Append {
                    log: account.log,
                    event: base_event(3).0.encode(),
                    epoch: [0; 32],
                },
                Want::Subscribe { log: account.log },
            ],
        })
        .await;
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    assert_eq!(items[0].as_ref().err(), Some(&Refusal::Unknown));
    assert_eq!(items[1].as_ref().err(), Some(&Refusal::Unknown));
    // Account logs take appends only as verified controls.
    assert_eq!(items[2].as_ref().err(), Some(&Refusal::Unsupported));
    assert!(items[3].is_ok());
}
