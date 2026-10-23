//! A base's first registration is provisional until its exact genesis is
//! read back ordered; an accepted record is never demoted, and one recorded
//! before canonical order pauses only that base.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_authz::{
    Connection, Service,
    proto::{FromService, Refusal, ToService, Want},
};
use bh_event::Outcome;
use bh_sync::{BodyObject, permit::Scope};
use std::sync::Arc;
use support::{
    native::{Fold, Mac},
    *,
};
use tokio::sync::Semaphore;

fn append(log: bh_authz::proto::LogId, epoch: [u8; 32]) -> ToService {
    ToService::Permits {
        items: vec![Want::Append {
            log,
            event: base_event(3).0.encode(),
            epoch,
        }],
    }
}

#[tokio::test]
async fn a_lost_genesis_ack_is_retried_and_the_record_accepted() {
    let harness = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    harness.publish(&account);
    let genesis = account.base_genesis(&device);
    let log = genesis.log();
    let service = harness.service();
    let mut connection = session(&service, &account, &device).await;
    let first = connection.handle(genesis.register()).await;
    // Ordered, but its acknowledgement never reached the device.
    order_genesis(&harness, &first, &genesis);
    assert_eq!(base_status(&harness.disk(), log.id), Some(1));
    // The retried registration reads the genesis back: accepted, and the
    // same permits, under which the log returns the original order.
    let again = connection.handle(genesis.register()).await;
    assert_eq!(base_status(&harness.disk(), log.id), Some(2));
    let FromService::Permits { items } = &again else {
        panic!("{again:?}")
    };
    let head = harness.edge.head(log);
    assert_eq!(
        harness
            .edge
            .append(items[1].as_ref().unwrap(), &genesis.descriptor),
        Ok(head)
    );
    single_permit(
        connection
            .handle(append(log, bh_event::key_id(&genesis.content)))
            .await,
    );
}

#[tokio::test]
async fn a_genesis_endpoint_without_an_observed_genesis_cannot_promote() {
    for restart in [false, true] {
        let harness = Harness::new();
        let device = Device::new();
        let account = Account::create_full(&device);
        harness.publish(&account);
        let genesis = account.base_genesis(&device);
        let log = genesis.log();
        let service = harness.service();
        let mut connection = session(&service, &account, &device).await;
        order_genesis(
            &harness,
            &connection.handle(genesis.register()).await,
            &genesis,
        );
        assert_eq!(base_status(&harness.disk(), log.id), Some(1));
        // Keep the genuine signed endpoint but omit every item on the page.
        *harness.edge.rewrite_controls.lock().unwrap() = Some(Box::new(|items| items.clear()));
        if restart {
            drop(connection);
            drop(service);
            let reopened = harness.service();
            connection = session(&reopened, &account, &device).await;
        }
        let answer = connection
            .handle(append(log, bh_event::key_id(&genesis.content)))
            .await;
        assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
        assert_eq!(base_status(&harness.disk(), log.id), Some(1));
        *harness.edge.rewrite_controls.lock().unwrap() = None;
        single_permit(
            connection
                .handle(append(log, bh_event::key_id(&genesis.content)))
                .await,
        );
        assert_eq!(base_status(&harness.disk(), log.id), Some(2));
    }
}

#[tokio::test]
async fn an_accepted_record_is_never_demoted() {
    let harness = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    harness.publish(&account);
    let genesis = account.base_genesis(&device);
    let log = genesis.log();
    let service = harness.service();
    let mut connection = session(&service, &account, &device).await;
    order_genesis(
        &harness,
        &connection.handle(genesis.register()).await,
        &genesis,
    );
    single_permit(
        connection
            .handle(append(log, bh_event::key_id(&genesis.content)))
            .await,
    );
    assert_eq!(base_status(&harness.disk(), log.id), Some(2));
    let before = projection_rows(&harness.disk(), log.id);
    // A server that serves the base empty cannot make a retried
    // registration provisional again.
    harness.edge.truncate(log, 0);
    let answer = connection.handle(genesis.register()).await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    assert_eq!(projection_rows(&harness.disk(), log.id), before);
}

/// A provisional base whose genesis and one copy another instance ordered,
/// so this one never judged it: registering again replays both.
struct Copied {
    harness: Harness,
    mac: Mac,
    fold: Fold,
    epoch: [u8; 32],
    service: Service,
    connection: Connection,
}
async fn copied() -> Copied {
    let harness = Harness::new();
    let mut mac = Mac::new(&harness);
    let fold = Fold::new();
    let epoch = bh_event::key_id(&mac.content);
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    let registered = connection.handle(mac.register()).await;
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    support::native::order(&harness, &registered, &mac.genesis).unwrap();
    assert_eq!(mac.pull(&harness), vec![Outcome::Accepted]);
    let copy = mac.copy(add.as_bytes()).unwrap();
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
    assert_eq!(mac.pull(&harness), vec![Outcome::Accepted]);
    Copied {
        harness,
        mac,
        fold,
        epoch,
        service,
        connection,
    }
}

#[tokio::test]
async fn a_provisional_base_with_unknown_later_controls_needs_registration() {
    let Copied {
        harness,
        mac,
        fold,
        epoch,
        service,
        mut connection,
    } = copied().await;
    let answer = connection.handle(append(mac.base_log(), epoch)).await;
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    assert_eq!(items[0].clone().err(), Some(Refusal::Resync));
    assert_eq!(base_status(&harness.disk(), mac.base.0), Some(1));
    // Registering again with M judges it: accepted, the Fold's addition
    // counts.
    let answer = connection.handle(mac.register()).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    assert_eq!(base_status(&harness.disk(), mac.base.0), Some(2));
    let mut folded = mac.fold_session(&service, &fold).await;
    single_permit(folded.handle(append(mac.base_log(), epoch)).await);
}

#[tokio::test]
async fn a_legacy_base_record_pauses_only_that_base() {
    let harness = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    harness.publish(&account);
    let (legacy, healthy) = (account.base_genesis(&device), account.base_genesis(&device));
    {
        let service = harness.service();
        let mut connection = session(&service, &account, &device).await;
        for genesis in [&legacy, &healthy] {
            order_genesis(
                &harness,
                &connection.handle(genesis.register()).await,
                genesis,
            );
        }
    }
    // One base's record is as an older service left it.
    rusqlite::Connection::open(harness.disk())
        .unwrap()
        .execute(
            "UPDATE base_controls SET format=NULL, status=NULL, raw_order=NULL WHERE base=?1",
            [legacy.log().id.as_slice()],
        )
        .unwrap();
    let before = projection_rows(&harness.disk(), legacy.log().id);
    let service = harness.service();
    let mut connection = session(&service, &account, &device).await;
    for request in [
        append(legacy.log(), bh_event::key_id(&legacy.content)),
        ToService::Permits {
            items: vec![read_events(legacy.log())],
        },
    ] {
        let answer = connection.handle(request).await;
        let FromService::Permits { items } = answer else {
            panic!("{answer:?}")
        };
        assert_eq!(items[0].clone().err(), Some(Refusal::Unsupported));
    }
    let answer = connection.handle(legacy.register()).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Unsupported
            }
        ),
        "{answer:?}"
    );
    assert_eq!(projection_rows(&harness.disk(), legacy.log().id), before);
    single_permit(
        connection
            .handle(append(healthy.log(), bh_event::key_id(&healthy.content)))
            .await,
    );
}

#[tokio::test]
async fn a_republished_base_keeps_only_its_selected_generation() {
    let Copied {
        harness,
        mac,
        mut connection,
        ..
    } = copied().await;
    let disk = harness.disk();
    let base = mac.base.0;
    // Each registration replays the copy into a new generation and replaces
    // the one before it, which is cleaned before it answers.
    for _ in 0..2 {
        let answer = connection.handle(mac.register()).await;
        assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    }
    let generations = base_generations(&disk, base);
    assert_eq!(generations.len(), 3, "{generations:?}");
    assert!(
        generations[..2].iter().all(|g| g.1 == 2 && g.2 == 0),
        "{generations:?}"
    );
    let (generation, phase, rows) = generations[2];
    assert!(phase == 1 && rows > 0, "{generations:?}");
    let selected: i64 = rusqlite::Connection::open(&disk)
        .unwrap()
        .query_row(
            "SELECT generation FROM projection_selected WHERE kind=2 AND source=?1",
            [base.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(selected, generation);
    // The record still reads and grants from the remaining generation.
    single_permit(
        connection
            .handle(append(mac.base_log(), bh_event::key_id(&mac.content)))
            .await,
    );
}

#[tokio::test]
async fn a_cancelled_registration_leaves_no_staged_generation() {
    let Copied {
        harness,
        mac,
        service,
        mut connection,
        ..
    } = copied().await;
    let disk = harness.disk();
    let base = mac.base.0;
    let answer = connection.handle(mac.register()).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    let selected = *base_generations(&disk, base).last().unwrap();
    let before = projection_rows(&disk, base);
    // The next registration stages the whole replay, then waits before its
    // publication; its connection then closes, dropping the request.
    let entered = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    service.hold_base_publication(Arc::new({
        let (entered, release) = (entered.clone(), release.clone());
        move |_| {
            let (entered, release) = (entered.clone(), release.clone());
            Box::pin(async move {
                entered.add_permits(1);
                release.acquire().await.unwrap().forget();
            })
        }
    }));
    let mut cancelled = mac.session(&service).await;
    let request = mac.register();
    let pending = tokio::spawn(async move { cancelled.handle(request).await });
    entered.acquire().await.unwrap().forget();
    let staged = *base_generations(&disk, base).last().unwrap();
    assert!(
        staged.0 > selected.0 && staged.1 == 0 && staged.2 > selected.2 / 2,
        "{staged:?} {selected:?}"
    );
    pending.abort();
    assert!(pending.await.unwrap_err().is_cancelled());
    service.staging_cleaned().await;
    let after = base_generations(&disk, base);
    assert!(after.contains(&(staged.0, 2, 0)), "{after:?}");
    assert!(after.contains(&selected), "{after:?}");
    assert_eq!(projection_rows(&disk, base), before);
}
