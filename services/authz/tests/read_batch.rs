#![cfg(feature = "synthetic-attestation")]
mod support;
use bh_authz::proto::{FromService, ReadBatchResult, Refusal, ToService, Want};
use bh_sync::{BodyObject, Head, permit::Scope, receipt};
use std::sync::atomic::Ordering;
use support::*;

#[tokio::test]
async fn owned_base_returns_exact_descriptor_receipt_and_existing_body_scope() {
    let h = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    h.publish(&account);
    let service = h.service();
    let mut connection = session(&service, &account, &device).await;
    let genesis = account.base_genesis(&device);
    let log = genesis.log();
    let registered = connection.handle(genesis.register()).await;
    order_genesis(&h, &registered, &genesis);
    let before = h.edge.reads.load(std::sync::atomic::Ordering::SeqCst);
    let reply = connection
        .handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log,
                after: Head::EMPTY,
                max_events: 48,
            },
        })
        .await;
    let FromService::ReadBatch {
        result:
            ReadBatchResult::Selected {
                items,
                receipt: Some(signed),
                body_permit: Some(permit),
                possibly_more,
            },
        issued_ms,
        deadline_ms,
        ..
    } = reply
    else {
        panic!("read batch: {reply:?}");
    };
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].1, genesis.descriptor.encode());
    let tail = h.edge.head(log);
    assert_eq!(
        receipt::verify(&h.root.public(), bh_sync::BaseId(log.id), &signed)
            .unwrap()
            .head(),
        tail
    );
    assert!(!possibly_more);
    let checked = h.permit(&permit);
    assert_eq!(checked.issued_ms, issued_ms);
    assert_eq!(checked.deadline_ms, deadline_ms);
    assert_eq!(
        checked.scope,
        Scope::ReadBodies {
            log,
            bodies: vec![bh_sync::BodyObject::new(genesis.body).unwrap().commitment()]
        }
    );
    assert_eq!(
        h.edge.reads.load(std::sync::atomic::Ordering::SeqCst) - before,
        3
    ); // one account refresh, one control check, one selection
    let before = h.edge.reads.load(Ordering::SeqCst);
    assert!(matches!(
        connection
            .handle(ToService::ReadBatch {
                want: Want::ReadBatch {
                    log,
                    after: Head::EMPTY,
                    max_events: 48
                },
            })
            .await,
        FromService::ReadBatch { .. }
    ));
    assert_eq!(h.edge.reads.load(Ordering::SeqCst) - before, 3);
}

#[tokio::test]
async fn read_batch_distinguishes_uncopied_account_change_and_inactive_base_member() {
    let h = Harness::new();
    let creator = Device::new();
    let mut account = Account::create_full(&creator);
    h.publish(&account);
    let service = h.service();
    let mut owner = session(&service, &account, &creator).await;
    let genesis = account.base_genesis(&creator);
    let log = genesis.log();
    order_genesis(&h, &owner.handle(genesis.register()).await, &genesis);
    let newcomer = Device::new();
    account.add_device(&creator, &newcomer);
    h.publish(&account);
    let mut newcomer_session = session(&service, &account, &newcomer).await;
    let request = || ToService::ReadBatch {
        want: Want::ReadBatch {
            log,
            after: Head::EMPTY,
            max_events: 48,
        },
    };
    assert!(matches!(
        owner.handle(request()).await,
        FromService::Refused {
            reason: Refusal::AccountChangePending
        }
    ));
    assert!(matches!(
        newcomer_session.handle(request()).await,
        FromService::Refused {
            reason: Refusal::NotActive
        }
    ));
}

#[tokio::test]
async fn own_account_cursor_is_outer_head_not_original_head() {
    let h = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    h.publish(&account);
    let service = h.service();
    let mut connection = session(&service, &account, &device).await;
    let answer = connection
        .handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log: account.log,
                after: Head::EMPTY,
                max_events: 48,
            },
        })
        .await;
    let FromService::ReadBatch {
        result:
            ReadBatchResult::Selected {
                items,
                receipt: None,
                body_permit: None,
                possibly_more: false,
            },
        ..
    } = answer
    else {
        panic!("account: {answer:?}");
    };
    assert_eq!(items.len(), 3);
    assert_ne!(
        h.edge.head(account.log).hash.0,
        account.verified.head().hash
    );
    let after = h.edge.head(account.log);
    let before = h.edge.reads.load(Ordering::SeqCst);
    let empty = connection
        .handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log: account.log,
                after,
                max_events: 48,
            },
        })
        .await;
    assert!(
        matches!(&empty, FromService::ReadBatch { result: ReadBatchResult::Selected { items, receipt: None, body_permit: None, possibly_more: false }, .. } if items.is_empty()),
        "{empty:?}"
    );
    assert_eq!(h.edge.reads.load(Ordering::SeqCst) - before, 2);
    let before = h.edge.reads.load(Ordering::SeqCst);
    assert!(matches!(
        connection
            .handle(ToService::ReadBatch {
                want: Want::ReadBatch {
                    log: account.log,
                    after,
                    max_events: 48
                },
            })
            .await,
        FromService::ReadBatch { .. }
    ));
    assert_eq!(h.edge.reads.load(Ordering::SeqCst) - before, 2);
    eprintln!(
        "account-empty: authz-plaintext={} encrypted-record={} request-plaintext=79",
        empty.encode().unwrap().len(),
        empty.encode().unwrap().len() + 60
    );
    let wrong = connection
        .handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log: account.log,
                after: Head {
                    position: after.position,
                    hash: bh_sync::Digest(account.verified.head().hash),
                },
                max_events: 48,
            },
        })
        .await;
    assert!(matches!(wrong, FromService::Unavailable), "{wrong:?}");
}

#[tokio::test]
async fn account_delivery_uses_canonical_wrapper_and_verified_digest() {
    let h = Harness::new();
    let device = Device::new();
    let mut account = Account::create_full(&device);
    h.publish(&account);
    let service = h.service();
    let mut connection = session(&service, &account, &device).await;
    let after = h.edge.head(account.log);
    let newcomer = Device::new();
    let (event, frame) = account.add_with_delivery(&device, &newcomer);
    account.apply(&event);
    let body = bh_authz::proto::delivery_body(&frame).unwrap();
    let digest = body.commitment();
    let wrapped = bh_authz::proto::account_log_wrap(event.as_bytes(), Some(digest)).unwrap();
    h.edge
        .stage(
            &h.sign(Scope::Stage {
                log: account.log,
                body: digest,
                len: body.bytes().len() as u32,
            }),
            body.bytes(),
        )
        .unwrap();
    h.edge
        .append(
            &h.sign(Scope::Append {
                log: account.log,
                event: wrapped.digest(),
                body: Some(digest),
                epoch: bh_authz::proto::ACCOUNT_EPOCH,
                after: Some(after),
            }),
            &wrapped,
        )
        .unwrap();
    let reply = connection
        .handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log: account.log,
                after,
                max_events: 48,
            },
        })
        .await;
    let FromService::ReadBatch {
        result:
            ReadBatchResult::Selected {
                items,
                receipt: None,
                body_permit: Some(permit),
                ..
            },
        ..
    } = reply
    else {
        panic!("delivery: {reply:?}");
    };
    assert_eq!(items.len(), 1);
    assert_eq!(
        h.permit(&permit).scope,
        Scope::ReadBodies {
            log: account.log,
            bodies: vec![digest]
        }
    );
}

#[tokio::test]
async fn oversized_complete_page_returns_exact_legacy_repair_scope_once() {
    let h = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    h.publish(&account);
    let service = h.service();
    let mut connection = session(&service, &account, &device).await;
    let genesis = account.base_genesis(&device);
    let log = genesis.log();
    order_genesis(&h, &connection.handle(genesis.register()).await, &genesis);
    for n in 0..63u8 {
        let (event, body) = base_event(n);
        let digest = BodyObject::new(body.clone()).unwrap().commitment();
        h.edge
            .stage(
                &h.sign(Scope::Stage {
                    log,
                    body: digest,
                    len: 1024,
                }),
                &body,
            )
            .unwrap();
        h.edge
            .append(
                &h.sign(Scope::Append {
                    log,
                    event: event.digest(),
                    body: Some(digest),
                    epoch: h.edge.epoch(log),
                    after: None,
                }),
                &event,
            )
            .unwrap();
    }
    let before = h.edge.reads.load(Ordering::SeqCst);
    let request = |max_events| ToService::ReadBatch {
        want: Want::ReadBatch {
            log,
            after: Head::EMPTY,
            max_events,
        },
    };
    let fits = connection.handle(request(48)).await;
    let FromService::ReadBatch {
        result:
            ReadBatchResult::Selected {
                items,
                receipt: Some(receipt),
                body_permit: Some(_),
                possibly_more: true,
            },
        ..
    } = &fits
    else {
        panic!("48: {fits:?}");
    };
    assert_eq!(items.len(), 48);
    let bytes = fits.encode().unwrap();
    assert!(bytes.len() <= 65_536, "48 reply {} bytes", bytes.len());
    let repair = connection.handle(request(64)).await;
    let FromService::ReadBatch {
        result: ReadBatchResult::Repair { events_permit },
        ..
    } = &repair
    else {
        panic!("64: {repair:?}");
    };
    assert_eq!(
        h.permit(events_permit).scope,
        Scope::ReadEvents {
            log,
            first: 1,
            last: 64
        }
    );
    assert_eq!(h.edge.reads.load(Ordering::SeqCst) - before, 6); // no reread to shrink a selected page
    let edge_response = bh_sync::wire::Response::Events {
        id: 1,
        items: items.clone(),
        receipt: Some(*receipt),
    }
    .encode()
    .unwrap();
    let edge_request = bh_sync::wire::Request::Read {
        id: 1,
        permit: h.sign(Scope::ReadEvents {
            log,
            first: 1,
            last: 48,
        }),
    }
    .encode()
    .unwrap();
    eprintln!(
        "base-48: authz-plaintext={} encrypted-record={} internal-reads=3 edge-request={} edge-events={}; base-64-repair: authz-plaintext={} encrypted-record={} internal-reads=3; request-plaintext=79",
        bytes.len(),
        bytes.len() + 60,
        edge_request.len(),
        edge_response.len(),
        repair.encode().unwrap().len(),
        repair.encode().unwrap().len() + 60
    );
}

#[tokio::test]
async fn invalid_account_ordering_repairs_instead_of_hiding_a_fork() {
    let h = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    h.publish(&account);
    let service = h.service();
    let mut connection = session(&service, &account, &device).await;
    h.edge.corrupt_ordering.store(true, Ordering::SeqCst);
    let reply = connection
        .handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log: account.log,
                after: Head::EMPTY,
                max_events: 48,
            },
        })
        .await;
    assert!(
        matches!(
            reply,
            FromService::ReadBatch {
                result: ReadBatchResult::Repair { .. },
                ..
            }
        ),
        "{reply:?}"
    );
}

#[tokio::test]
async fn empty_page_cannot_erase_a_known_committed_control() {
    let h = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    h.publish(&account);
    let service = h.service();
    let mut connection = session(&service, &account, &device).await;
    let genesis = account.base_genesis(&device);
    let log = genesis.log();
    order_genesis(&h, &connection.handle(genesis.register()).await, &genesis);
    h.edge.hide_batch.store(true, Ordering::SeqCst);
    let answer = connection
        .handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log,
                after: Head::EMPTY,
                max_events: 48,
            },
        })
        .await;
    assert!(
        matches!(answer, FromService::Unavailable),
        "cannot report caught up below verified control: {answer:?}"
    );
}

#[tokio::test]
async fn invalid_or_missing_tail_never_gets_body_grant() {
    let h = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    h.publish(&account);
    let service = h.service();
    let mut connection = session(&service, &account, &device).await;
    let genesis = account.base_genesis(&device);
    let log = genesis.log();
    order_genesis(&h, &connection.handle(genesis.register()).await, &genesis);
    let request = || ToService::ReadBatch {
        want: Want::ReadBatch {
            log,
            after: Head::EMPTY,
            max_events: 48,
        },
    };
    h.edge.corrupt_receipt.store(true, Ordering::SeqCst);
    let bad = connection.handle(request()).await;
    assert!(
        matches!(
            bad,
            FromService::ReadBatch {
                result: ReadBatchResult::Repair { .. },
                ..
            }
        ),
        "{bad:?}"
    );
    h.edge.corrupt_receipt.store(false, Ordering::SeqCst);
    h.edge.corrupt_ordering.store(true, Ordering::SeqCst);
    let fork = connection.handle(request()).await;
    assert!(
        matches!(
            fork,
            FromService::ReadBatch {
                result: ReadBatchResult::Repair { .. },
                ..
            }
        ),
        "{fork:?}"
    );
    h.edge.corrupt_ordering.store(false, Ordering::SeqCst);
    h.edge.omit_receipt.store(true, Ordering::SeqCst);
    let missing = connection.handle(request()).await;
    assert!(matches!(missing, FromService::Unavailable), "{missing:?}");
}

#[tokio::test]
async fn expired_during_immutable_selection_never_issues_fresh_grant() {
    let h = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    h.publish(&account);
    let service = h.service();
    let mut connection = session(&service, &account, &device).await;
    let genesis = account.base_genesis(&device);
    let log = genesis.log();
    order_genesis(&h, &connection.handle(genesis.register()).await, &genesis);
    h.edge.read_takes.store(12_000, Ordering::SeqCst);
    let reply = connection
        .handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log,
                after: Head::EMPTY,
                max_events: 48,
            },
        })
        .await;
    assert!(matches!(reply, FromService::Unavailable), "{reply:?}");
}

#[tokio::test]
async fn unauthorized_read_is_refused_not_empty_or_repair() {
    let h = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    h.publish(&account);
    let service = h.service();
    let mut connection = session(&service, &account, &device).await;
    let reply = connection
        .handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log: bh_authz::proto::LogId {
                    kind: bh_authz::proto::LogKind::Base,
                    id: [7; 32],
                },
                after: Head::EMPTY,
                max_events: 48,
            },
        })
        .await;
    assert!(
        matches!(
            reply,
            FromService::Refused {
                reason: Refusal::Unknown
            }
        ),
        "{reply:?}"
    );
}
