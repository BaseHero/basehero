//! Restart from the protected disk: nothing is issued from stored state alone.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_authz::{
    Connection,
    proto::{FromService, RecoveryAnswer, Refusal, ToService, Want},
};
use bh_sync::{BodyObject, permit::Scope};
use std::sync::atomic::Ordering;
use support::{
    claims::*,
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
async fn a_provisional_genesis_survives_restart_and_grants_only_its_retry() {
    let harness = Harness::new();
    let device = Device::new();
    let account = Account::create_full(&device);
    harness.publish(&account);
    let genesis = account.base_genesis(&device);
    let epoch = bh_event::key_id(&genesis.content);
    let log = genesis.log();
    let first_answer = {
        let service = harness.service();
        let mut connection = session(&service, &account, &device).await;
        let answer = connection.handle(genesis.register()).await;
        assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
        answer
    };
    assert_eq!(base_status(&harness.disk(), log.id), Some(1));
    let service = harness.service();
    let mut connection = session(&service, &account, &device).await;
    // Until its genesis is read back ordered, the base grants nothing but
    // that genesis's own retry.
    let (event, body) = base_event(2);
    for item in [
        Want::Append {
            log,
            event: event.encode(),
            epoch,
        },
        Want::Presence { log, epoch },
        Want::ReadEvents {
            log,
            first: 1,
            last: 64,
        },
        Want::Stage {
            log,
            body: BodyObject::new(body.clone()).unwrap().commitment(),
            len: body.len() as u32,
        },
        Want::Subscribe { log },
        Want::ReadControls { log, after: 0 },
    ] {
        let answer = connection
            .handle(ToService::Permits { items: vec![item] })
            .await;
        assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    }
    let answer = connection
        .handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log,
                after: bh_sync::Head::EMPTY,
                max_events: 8,
            },
        })
        .await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    assert_eq!(base_status(&harness.disk(), log.id), Some(1));
    // The exact registration is retried and answered the same way, and its
    // permits order the genesis.
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
    drop(connection);
    drop(service);
    assert_eq!(base_status(&harness.disk(), log.id), Some(1));
    // After another restart, the first content request reads the genesis
    // back, promotes the base and is granted.
    let service = harness.service();
    let mut connection = session(&service, &account, &device).await;
    single_permit(
        connection
            .handle(ToService::Permits {
                items: vec![Want::Append {
                    log,
                    event: base_event(3).0.encode(),
                    epoch,
                }],
            })
            .await,
    );
    assert_eq!(base_status(&harness.disk(), log.id), Some(2));
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
                attached: None,
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

#[tokio::test]
async fn tries_survive_restart() {
    let harness = Harness::new();
    let home = {
        let service = harness.service();
        let home = Home::new(&harness, &service).await;
        for _ in 0..5 {
            try_claim(&harness, &service, &home.wrong_password).await;
        }
        home
    };
    let fifth = harness.clock.now();
    let service = harness.service();
    assert_eq!(
        try_claim(&harness, &service, &home.right).await,
        wait(fifth + HOUR)
    );
    harness.clock.set(fifth + HOUR);
    assert_eq!(
        try_claim(&harness, &service, &home.wrong_password).await,
        mismatch(0, Some(fifth + 2 * HOUR))
    );
    // A release survives too: after it, five are free again.
    harness.clock.set(fifth + 2 * HOUR);
    assert_eq!(
        try_claim(&harness, &service, &home.right).await,
        FromService::Recovery(home.released())
    );
    drop(service);
    assert_eq!(
        try_claim(&harness, &harness.service(), &home.wrong_password).await,
        mismatch(4, None)
    );
}

#[tokio::test]
async fn clock_step_back_does_not_reopen_tries() {
    let harness = Harness::new();
    let service = harness.service();
    let home = Home::new(&harness, &service).await;
    for _ in 0..5 {
        harness.clock.advance(1_000);
        try_claim(&harness, &service, &home.wrong_password).await;
    }
    let fifth = harness.clock.now();
    harness.clock.set(fifth + HOUR);
    assert_eq!(
        try_claim(&harness, &service, &home.wrong_password).await,
        mismatch(0, Some(fifth + 2 * HOUR))
    );
    // The clock steps back before the first failure: still the same wait,
    // for either password, and nothing counted.
    for back in [fifth + HOUR - 1, fifth - 10 * HOUR, 0] {
        harness.clock.set(back);
        for claim in [&home.wrong_password, &home.right] {
            assert_eq!(
                try_claim(&harness, &service, claim).await,
                wait(fifth + 2 * HOUR)
            );
        }
    }
    harness.clock.set(fifth + 2 * HOUR);
    assert_eq!(
        try_claim(&harness, &service, &home.wrong_password).await,
        mismatch(0, Some(fifth + 3 * HOUR))
    );
}

/// Return the service's disk to the schema-3 shape the deployed service
/// left, keeping its rows: the tables and columns schema 4 added go.
fn back_to_schema_three(path: &std::path::Path) {
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute_batch(
        "DROP TABLE base_generations;
         DROP TABLE base_raw;
         DROP TABLE base_ids;
         DROP TABLE projection_copies;
         ALTER TABLE base_stops DROP COLUMN path_generation;
         DROP TABLE projection_sources;
         DROP TABLE projection_selected;
         DROP TABLE projection_current;
         DROP TABLE projection_active;
         DROP TABLE projection_snapshots;
         DROP TABLE projection_snapshot_devices;
         DROP TABLE projection_devices;
         DROP TABLE projection_keys;
         DROP TABLE projection_times;
         DROP TABLE account_applied_bodies;
         DROP TABLE account_confirmations;
         DROP TABLE recovery_index;
         DROP TABLE recovery_records;
         DROP TABLE recovery_tries;
         DROP TABLE recovery_notices;
         DROP TABLE pending_attachments;
         ALTER TABLE base_account_changes DROP COLUMN confirmation;
         ALTER TABLE base_pending DROP COLUMN seal_set;
         ALTER TABLE accounts DROP COLUMN format;
         ALTER TABLE accounts DROP COLUMN opening;
         ALTER TABLE base_controls DROP COLUMN format;
         ALTER TABLE base_controls DROP COLUMN status;
         ALTER TABLE base_controls DROP COLUMN raw_order;
         DROP TABLE base_control_ids;
         UPDATE meta SET value=3 WHERE key='schema';",
    )
    .unwrap();
}

#[tokio::test]
async fn schema_three_disk_upgrades_to_four_keeping_bases_and_marking_events_legacy() {
    let harness = Harness::new();
    let device = Device::new();
    let mut account = Account::create_full(&device);
    harness.publish(&account);
    let genesis = account.base_genesis(&device);
    {
        let service = harness.service();
        let mut connection = session(&service, &account, &device).await;
        let answer = connection.handle(genesis.register()).await;
        order_genesis(&harness, &answer, &genesis);
    }
    // Obtain a real service-signed confirmation for an account change after
    // the original prefix, then migrate the projection as an old disk would.
    account.add_device(&device, &Device::new());
    harness.publish(&account);
    let migrated = account.originals.len() as i64;
    {
        let service = harness.service();
        let _connection = session(&service, &account, &device).await;
    }
    let path = harness.disk();
    let valid_confirmation: Vec<u8> = rusqlite::Connection::open(&path)
        .unwrap()
        .query_row(
            "SELECT confirmation FROM account_confirmations WHERE account=?1 AND position=?2",
            rusqlite::params![account.id.0.as_slice(), migrated],
            |r| r.get(0),
        )
        .unwrap();
    back_to_schema_three(&path);
    let service = harness.service();
    // Installing that valid, later confirmation cannot turn an untimed
    // migrated prefix into a verified canonical account projection.
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "INSERT INTO account_confirmations(account, position, confirmation) VALUES(?1, ?2, ?3)",
            rusqlite::params![account.id.0.as_slice(), migrated, valid_confirmation],
        )
        .unwrap();
    // The migrated account's projection predates canonical order: that
    // account alone pauses, with its untimed prefix never relabelled, even
    // once a later event its checker could confirm is ordered.
    let refused = |answer: FromService| {
        assert!(
            matches!(
                answer,
                FromService::Refused {
                    reason: Refusal::Unsupported
                }
            ),
            "{answer:?}"
        )
    };
    let (mut connection, binding, challenge) = connect(&service);
    refused(
        connection
            .handle(authenticate_message(&account, &device, binding, challenge))
            .await,
    );
    account.add_device(&device, &Device::new());
    harness.publish(&account);
    let (mut connection, binding, challenge) = connect(&service);
    refused(
        connection
            .handle(authenticate_message(&account, &device, binding, challenge))
            .await,
    );
    // An unrelated account on the same service is served in full.
    let other = Device::new();
    let healthy = Account::create_full(&other);
    harness.publish(&healthy);
    let mut connection = session(&service, &healthy, &other).await;
    let base = healthy.base_genesis(&other);
    let answer = connection.handle(base.register()).await;
    order_genesis(&harness, &answer, &base);
    single_permit(
        connection
            .handle(ToService::Permits {
                items: vec![Want::Append {
                    log: base.log(),
                    event: base_event(4).0.encode(),
                    epoch: bh_event::key_id(&base.content),
                }],
            })
            .await,
    );
    drop(connection);
    drop(service);
    let db = rusqlite::Connection::open(&path).unwrap();
    let count = |sql: &str| db.query_row(sql, [], |r| r.get::<_, i64>(0)).unwrap();
    let of_migrated = |sql: &str| {
        db.query_row(sql, [account.id.0.as_slice()], |r| r.get::<_, i64>(0))
            .unwrap()
    };
    assert_eq!(count("SELECT value FROM meta WHERE key='schema'"), 7);
    // The migrated events stay as they were: legacy, with no confirmation,
    // and nothing appended or relabelled.
    assert_eq!(
        of_migrated("SELECT COUNT(*) FROM account_events WHERE account=?1"),
        migrated
    );
    assert_eq!(
        of_migrated("SELECT COUNT(*) FROM account_confirmations WHERE account=?1"),
        1
    );
    assert_eq!(
        of_migrated(
            "SELECT COUNT(*) FROM accounts WHERE account=?1 AND format IS NULL AND opening IS NULL"
        ),
        1
    );
    assert_eq!(
        of_migrated("SELECT COUNT(*) FROM bases WHERE account=?1"),
        1
    );
    let legacy_bases: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM base_controls WHERE base=?1 AND format IS NULL",
            [genesis.log().id.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(legacy_bases, 1);
    for table in [
        "recovery_index",
        "recovery_records",
        "recovery_tries",
        "recovery_notices",
        "pending_attachments",
    ] {
        assert_eq!(count(&format!("SELECT COUNT(*) FROM {table}")), 0);
    }
}

#[tokio::test]
async fn an_upgraded_disk_releases_a_record_indexed_after_it() {
    let harness = Harness::new();
    {
        // A service that ran schema 3 and served this account before.
        let device = Device::new();
        let account = Account::create(&device);
        harness.publish(&account);
        drop(session(&harness.service(), &account, &device).await);
    }
    back_to_schema_three(&harness.dir.path().join("authz.sqlite"));
    let service = harness.service();
    let home = Home::new(&harness, &service).await;
    assert!(matches!(
        try_claim(&harness, &service, &home.right).await,
        FromService::Recovery(RecoveryAnswer::Released { .. })
    ));
}
