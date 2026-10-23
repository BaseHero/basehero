//! Presence authorization follows the content-append membership decision.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_authz::{
    Connection, EdgeReader,
    proto::{FromService, LogId, LogKind, Refusal, ToService, Want},
};
use bh_sync::{BodyObject, permit::Scope};
use support::{
    native::{Fold, Mac},
    *,
};

async fn ask(connection: &mut Connection, log: LogId, epoch: [u8; 32]) -> Result<Vec<u8>, Refusal> {
    let answer = connection
        .handle(ToService::Permits {
            items: vec![Want::Presence { log, epoch }],
        })
        .await;
    let FromService::Permits { mut items } = answer else {
        panic!("{answer:?}")
    };
    items.remove(0)
}

#[tokio::test]
async fn active_device_gets_short_presence_permit_without_an_event() {
    let harness = Harness::new();
    let mut mac = Mac::new(&harness);
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    mac.register_and_order(&harness, &mut connection).await;
    let epoch = bh_event::key_id(&mac.content);
    let before = harness.clock.now();
    let signed = ask(&mut connection, mac.base_log(), epoch).await.unwrap();
    assert_eq!(signed.len(), 294);
    let permit = harness.permit(&signed);
    assert!(
        permit.scope
            == Scope::Presence {
                log: mac.base_log(),
                epoch
            }
    );
    assert_eq!(permit.issued_ms, before);
    assert_eq!(permit.deadline_ms, before + 30_000);
    // A presence permission is not a content append or read permission.
    assert_eq!(
        harness.edge.append(&signed, &base_event(3).0).unwrap_err(),
        "scope"
    );
    assert!(harness.edge.read_bodies(signed).await.is_err());
    assert_eq!(harness.edge.head(mac.base_log()).position, 1);
    assert_eq!(
        ask(&mut connection, mac.base_log(), [4; 32]).await,
        Err(Refusal::Epoch)
    );
}

#[tokio::test]
async fn presence_refuses_inactive_projection_and_pending_account_change() {
    let harness = Harness::new();
    let mut mac = Mac::new(&harness);
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    mac.register_and_order(&harness, &mut connection).await;
    let epoch = bh_event::key_id(&mac.content);
    let fold = Fold::new();
    let addition = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &addition)
        .await;
    let mut folded = mac.fold_session(&service, &fold).await;
    assert_eq!(
        ask(&mut folded, mac.base_log(), epoch).await,
        Err(Refusal::NotActive)
    );
    assert_eq!(
        ask(&mut connection, mac.base_log(), epoch).await,
        Err(Refusal::AccountChangePending)
    );
    mac.copy_ordered(&harness, &mut connection, addition.as_bytes())
        .await;
    assert!(ask(&mut folded, mac.base_log(), epoch).await.is_ok());
    let removal = mac.remove(&fold);
    harness.order_original(mac.log, removal.as_bytes());
    assert_eq!(
        ask(&mut connection, mac.base_log(), epoch).await,
        Err(Refusal::AccountChangePending)
    );
    mac.copy_ordered(&harness, &mut connection, removal.as_bytes())
        .await;
    assert_eq!(
        ask(&mut connection, mac.base_log(), epoch).await,
        Err(Refusal::Epoch)
    );
    assert_eq!(
        ask(&mut connection, mac.base_log(), [0; 32]).await,
        Err(Refusal::Epoch)
    );
}

#[tokio::test]
async fn presence_refuses_account_log_foreign_and_unknown_bases() {
    let harness = Harness::new();
    let mut mac = Mac::new(&harness);
    let mut other = Mac::new(&harness);
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    mac.register_and_order(&harness, &mut connection).await;
    let mut foreign = other.session(&service).await;
    other.register_and_order(&harness, &mut foreign).await;
    let epoch = bh_event::key_id(&mac.content);
    assert_eq!(
        ask(&mut connection, mac.log, epoch).await,
        Err(Refusal::Unsupported)
    );
    assert_eq!(
        ask(&mut connection, other.base_log(), epoch).await,
        Err(Refusal::Unknown)
    );
    assert_eq!(
        ask(
            &mut connection,
            LogId {
                kind: LogKind::Base,
                id: [9; 32]
            },
            epoch
        )
        .await,
        Err(Refusal::Unknown)
    );
}

#[tokio::test]
async fn unaccounted_base_control_refuses_presence_until_resync() {
    let harness = Harness::new();
    let mut mac = Mac::new(&harness);
    let fold = Fold::new();
    let epoch = bh_event::key_id(&mac.content);
    {
        let service = harness.service();
        let mut connection = mac.session(&service).await;
        mac.register_and_order(&harness, &mut connection).await;
        let add = mac.pair(&fold);
        mac.submit_account(&harness, &mut connection, &add).await;
    }
    let add = mac.originals.last().unwrap().clone();
    let copy = mac.copy(&add).unwrap();
    let body = BodyObject::new(copy.body.clone()).unwrap().commitment();
    harness
        .edge
        .stage(
            &harness.sign(Scope::Stage {
                log: mac.base_log(),
                body,
                len: copy.body.len() as u32,
            }),
            &copy.body,
        )
        .unwrap();
    harness
        .edge
        .append(
            &harness.sign(Scope::Append {
                log: mac.base_log(),
                event: copy.descriptor.digest(),
                body: Some(body),
                epoch,
                after: Some(harness.edge.head(mac.base_log())),
                attached: None,
            }),
            &copy.descriptor,
        )
        .unwrap();
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    assert_eq!(
        ask(&mut connection, mac.base_log(), epoch).await,
        Err(Refusal::Resync)
    );
    assert!(matches!(
        connection.handle(mac.register()).await,
        FromService::Permits { .. }
    ));
    assert!(ask(&mut connection, mac.base_log(), epoch).await.is_ok());
}

#[tokio::test]
async fn refused_presence_item_does_not_affect_other_permits() {
    let harness = Harness::new();
    let mut mac = Mac::new(&harness);
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    mac.register_and_order(&harness, &mut connection).await;
    let epoch = bh_event::key_id(&mac.content);
    let answer = connection
        .handle(ToService::Permits {
            items: vec![
                Want::Presence {
                    log: mac.base_log(),
                    epoch: [8; 32],
                },
                Want::Subscribe {
                    log: mac.base_log(),
                },
                Want::Presence {
                    log: mac.base_log(),
                    epoch,
                },
            ],
        })
        .await;
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    assert_eq!(items.len(), 3);
    assert_eq!(items[0], Err(Refusal::Epoch));
    assert!(
        harness.permit(items[1].as_ref().unwrap()).scope
            == Scope::Subscribe {
                log: mac.base_log()
            }
    );
    assert!(
        harness.permit(items[2].as_ref().unwrap()).scope
            == Scope::Presence {
                log: mac.base_log(),
                epoch
            }
    );
}
