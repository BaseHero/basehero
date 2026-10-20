//! Restart from the protected disk: nothing is issued from stored state alone.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_authz::{
    Connection,
    proto::{FromService, Refusal, ToService, Want},
};
use bh_sync::{BodyObject, permit::Scope};
use std::sync::atomic::Ordering;
use support::{
    native::{Fold, Mac, order},
    *,
};

#[tokio::test]
async fn restart_refreshes_before_issuing() {
    let harness = Harness::new();
    let first = Device::new();
    let second = Device::new();
    let mut account = Account::create(&first);
    account.add_device(&first, &second);
    harness.publish(&account);
    let service = harness.service();
    let mut connection = session(&service, &account, &second).await;
    single_permit(
        connection
            .handle(ToService::Permits {
                items: vec![read_events(account.log)],
            })
            .await,
    );
    drop(connection);
    drop(service);
    // While the service is down the second device's removal is ordered
    // elsewhere. The disk still says the device is active.
    let removal = account.remove_self(&second);
    harness.order_account_event(&account, &removal);
    let service = harness.service();
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
    // The remaining device authenticates at the refreshed head.
    let connection = session(&service, &account, &first).await;
    drop(connection);
}

#[tokio::test]
async fn after_restart_an_unreachable_edge_means_unavailable() {
    let harness = Harness::new();
    let device = Device::new();
    let account = Account::create(&device);
    harness.publish(&account);
    drop(session(&harness.service(), &account, &device).await);
    harness.edge.down.store(true, Ordering::SeqCst);
    let service = harness.service();
    let (mut connection, binding, challenge) = connect(&service);
    assert!(matches!(
        connection
            .handle(authenticate_message(&account, &device, binding, challenge))
            .await,
        FromService::Unavailable
    ));
}

#[tokio::test]
async fn registered_bases_survive_restart() {
    let harness = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    harness.publish(&account);
    let genesis = account.base_genesis(&device);
    let epoch = bh_event::key_id(&genesis.content);
    let first_answer = {
        let service = harness.service();
        let mut connection = session(&service, &account, &device).await;
        let answer = connection.handle(genesis.register()).await;
        assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
        answer
    };
    let service = harness.service();
    let mut connection = session(&service, &account, &device).await;
    single_permit(
        connection
            .handle(ToService::Permits {
                items: vec![Want::Append {
                    log: genesis.log(),
                    event: base_event(2).0.encode(),
                    epoch,
                }],
            })
            .await,
    );
    // After the restart, the exact registration is retried and answered the
    // same way, and its permits order the genesis.
    let answer = connection.handle(genesis.register()).await;
    let scopes = |answer: &FromService| {
        let FromService::Permits { items } = answer else {
            panic!("{answer:?}")
        };
        items
            .iter()
            .map(|i| harness.permit(i.as_ref().unwrap()).scope)
            .collect::<Vec<_>>()
    };
    assert!(scopes(&answer) == scopes(&first_answer));
    order_genesis(&harness, &answer, &genesis);
}

/// One content append on the Mac's base under its content epoch.
async fn write(connection: &mut Connection, mac: &Mac) -> Result<Vec<u8>, Refusal> {
    let answer = connection
        .handle(ToService::Permits {
            items: vec![Want::Append {
                log: mac.base_log(),
                event: base_event(3).0.encode(),
                epoch: bh_event::key_id(&mac.content),
            }],
        })
        .await;
    match answer {
        FromService::Permits { mut items } => items.remove(0),
        FromService::Refused { reason } => Err(reason),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn restart_confirms_pending_from_disk() {
    let harness = Harness::new();
    let mut mac = Mac::new(&harness);
    let fold = Fold::new();
    let copy;
    let answer = {
        let service = harness.service();
        let mut connection = mac.session(&service).await;
        mac.register_and_order(&harness, &mut connection).await;
        let add = mac.pair(&fold);
        mac.submit_account(&harness, &mut connection, &add).await;
        copy = mac.copy(add.as_bytes()).unwrap();
        connection.handle(mac.submit_copy(&copy)).await
    };
    // The service restarts; the copy is ordered meanwhile, under the
    // permits it issued before.
    order(&harness, &answer, &copy).unwrap();
    mac.pull(&harness);
    let service = harness.service();
    let mut folded = mac.fold_session(&service, &fold).await;
    write(&mut folded, &mac).await.unwrap();
    // The next control follows it.
    let control_head = harness.edge.head(mac.base_log());
    let removal = mac.remove(&fold);
    harness.order_original(mac.log, removal.as_bytes());
    let mut connection = mac.session(&service).await;
    let copy = mac.copy(removal.as_bytes()).unwrap();
    let FromService::Permits { items } = connection.handle(mac.submit_copy(&copy)).await else {
        panic!("permits")
    };
    let Scope::Append { after, .. } = harness.permit(items[1].as_ref().unwrap()).scope else {
        panic!("append")
    };
    assert_eq!(after, Some(control_head));
}

#[tokio::test]
async fn unknown_control_requires_resync_then_register_rebuilds() {
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
    // While the service is down, the copy is ordered under permits it did
    // not issue: the state it lost, or another instance's.
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
            }),
            &copy.descriptor,
        )
        .unwrap();
    assert_eq!(mac.pull(&harness), vec![bh_event::Outcome::Accepted]);
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    let mut folded = mac.fold_session(&service, &fold).await;
    // The service cannot account for the base's controls without M.
    assert_eq!(write(&mut folded, &mac).await, Err(Refusal::Resync));
    assert_eq!(write(&mut connection, &mac).await, Err(Refusal::Resync));
    let second = Fold::new();
    let next = mac.pair(&second);
    mac.submit_account(&harness, &mut connection, &next).await;
    let next_copy = mac.copy(next.as_bytes()).unwrap();
    let answer = connection.handle(mac.submit_copy(&next_copy)).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Resync
            }
        ),
        "{answer:?}"
    );
    // Registering again with M replays the base's controls: the Fold's
    // copied addition counts (its write waits only for the next copy), and
    // the next copy follows it.
    let answer = connection.handle(mac.register()).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    assert_eq!(
        write(&mut folded, &mac).await,
        Err(Refusal::AccountChangePending)
    );
    let control_head = harness.edge.head(mac.base_log());
    let answer = connection.handle(mac.submit_copy(&next_copy)).await;
    let FromService::Permits { items } = &answer else {
        panic!("{answer:?}")
    };
    let Scope::Append { after, .. } = harness.permit(items[1].as_ref().unwrap()).scope else {
        panic!("append")
    };
    assert_eq!(after, Some(control_head));
    order(&harness, &answer, &next_copy).unwrap();
    assert_eq!(mac.pull(&harness), vec![bh_event::Outcome::Accepted]);
    write(&mut folded, &mac).await.unwrap();
}
