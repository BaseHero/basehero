//! Real HOME originals/commitments, short network pages and indexed historical cuts.
#![cfg(feature = "synthetic-attestation")]
#[path = "../../tests/support/mod.rs"]
mod support;
use super::projection;
use bh_account::{ConfirmedTime, REMOVAL_WAIT_MS, projection as account_projection};
use bh_authz::proto::{FromService, ToService, account_log_wrap};
use bh_authz_test_alloc::{BYTES, Counting};
use bh_sync::{Route, evidence::OrderingConfirmation};
use rusqlite::{Connection, params};
#[global_allocator]
static ALLOC: Counting = Counting;
use support::*;

fn older(account: &Account, position: usize) -> Account {
    Account {
        genesis: account.genesis.clone(),
        id: account.id,
        log: account.log,
        verified: account.at(position),
        originals: account.originals[..position].to_vec(),
        personal: None,
    }
}

fn older_cancels(account: &Account, position: usize) -> Account {
    let timed: Vec<_> = account.originals[..position]
        .iter()
        .enumerate()
        .map(|(i, bytes)| {
            let pos = i as u64 + 1;
            let time = if pos == 1 {
                None
            } else if pos == 2 {
                Some(ConfirmedTime {
                    earliest_ms: TIME_START,
                    latest_ms: TIME_START,
                })
            } else {
                let at = TIME_START + REMOVAL_WAIT_MS + 100 + pos;
                Some(ConfirmedTime {
                    earliest_ms: at,
                    latest_ms: at,
                })
            };
            (bytes.as_slice(), time)
        })
        .collect();
    let verified = bh_account::VerifiedAccount::replay_timed(
        account.id,
        &timed,
        bh_account::Head {
            position: position as u64,
            hash: bh_crypto::hash(&account.originals[position - 1]),
        },
    )
    .unwrap();
    Account {
        genesis: account.genesis.clone(),
        id: account.id,
        log: account.log,
        verified,
        originals: account.originals[..position].to_vec(),
        personal: None,
    }
}

fn populate(cycles: usize) -> (Harness, Device, Account) {
    let h = Harness::new();
    let owner = Device::new();
    let mut account = Account::create(&owner);
    for _ in 0..cycles {
        let extra = Device::new();
        account.add_device(&owner, &extra);
        account.remove_self(&extra);
    }
    // Directly order the prebuilt, signed originals in the synthetic edge.
    // Its ordinary append deduplication linearly searches prior IDs on every
    // insertion, obscuring the authority cost with quadratic fixture setup.
    for original in &account.originals {
        h.edge.force_append(
            account.log,
            &account_log_wrap(original, None).unwrap(),
            Route::Control,
        );
    }
    (h, owner, account)
}

async fn populate_cancels(cycles: usize) -> (Harness, Device, Account) {
    let h = Harness::new();
    let owner = Device::new();
    let target = Device::new();
    let mut account = Account::create(&owner);
    let draft = account
        .verified
        .add_device(owner.id(), target.keys.clone())
        .unwrap();
    let added = draft
        .finish(owner.control.sign(draft.signing_bytes()))
        .unwrap();
    let first = ConfirmedTime {
        earliest_ms: TIME_START,
        latest_ms: TIME_START,
    };
    account
        .verified
        .apply_timed(added.as_bytes(), Some(first))
        .unwrap();
    account.originals.push(added.as_bytes().to_vec()); // Two active devices stay fixed.
    for _ in 0..cycles {
        let request_position = account.verified.head().position + 1;
        let draft = account
            .verified
            .request_removal(owner.id(), target.id())
            .unwrap();
        let request = draft
            .finish(owner.control.sign(draft.signing_bytes()))
            .unwrap();
        let at = TIME_START + REMOVAL_WAIT_MS + 100 + request_position;
        let time = ConfirmedTime {
            earliest_ms: at,
            latest_ms: at,
        };
        account
            .verified
            .apply_timed(request.as_bytes(), Some(time))
            .unwrap();
        account.originals.push(request.as_bytes().to_vec());
        let draft = account
            .verified
            .cancel_removal(owner.id(), request_position)
            .unwrap();
        let cancel = draft
            .finish(owner.control.sign(draft.signing_bytes()))
            .unwrap();
        let at = TIME_START + REMOVAL_WAIT_MS + 100 + account.verified.head().position + 1;
        let time = ConfirmedTime {
            earliest_ms: at,
            latest_ms: at,
        };
        account
            .verified
            .apply_timed(cancel.as_bytes(), Some(time))
            .unwrap();
        account.originals.push(cancel.as_bytes().to_vec());
    }
    // The initial addition receives its own real hosted confirmation before
    // the owner matures; the later bounded request/cancel pages are current.
    for original in &account.originals[..2] {
        h.edge.force_append(
            account.log,
            &account_log_wrap(original, None).unwrap(),
            Route::Control,
        );
    }
    let first_two: Vec<_> = account.originals[..2]
        .iter()
        .enumerate()
        .map(|(i, bytes)| (bytes.as_slice(), (i == 1).then_some(first)))
        .collect();
    let initial = bh_account::VerifiedAccount::replay_timed(
        account.id,
        &first_two,
        bh_account::Head {
            position: 2,
            hash: bh_crypto::hash(&account.originals[1]),
        },
    )
    .unwrap();
    let early = Account {
        genesis: account.genesis.clone(),
        id: account.id,
        log: account.log,
        verified: initial,
        originals: account.originals[..2].to_vec(),
        personal: None,
    };
    let service = h.service();
    let _ = session(&service, &early, &owner).await;
    drop(service);
    h.clock
        .set(TIME_START + REMOVAL_WAIT_MS + 100 + (cycles * 2 + 2) as u64);
    for original in &account.originals[2..] {
        h.edge.force_append(
            account.log,
            &account_log_wrap(original, None).unwrap(),
            Route::Control,
        );
    }
    (h, owner, account)
}

#[tokio::test]
async fn timed_full_replay_oracle_agrees_with_hosted_snapshots_and_kept_proofs() {
    let (h, owner, account) = populate_cancels(65).await;
    let service = h.service();
    let _ = session(&service, &account, &owner).await;
    let db = Connection::open(h.disk()).unwrap();
    let mut originals = Vec::new();
    let mut timed = Vec::new();
    let mut proofs = Vec::new();
    for (i, source) in account.originals.iter().enumerate() {
        let position = (i + 1) as i64;
        let original: Vec<u8> = db
            .query_row(
                "SELECT bytes FROM account_events WHERE account=?1 AND position=?2",
                params![account.id.0.as_slice(), position],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(&original, source);
        let time = if position == 1 {
            None
        } else {
            let proof: Vec<u8> = db.query_row(
                "SELECT confirmation FROM account_confirmations WHERE account=?1 AND position=?2",
                params![account.id.0.as_slice(), position], |r| r.get(0)).unwrap();
            let evidence = OrderingConfirmation::decode(&proof).unwrap();
            let claim = evidence
                .verify_for(&h.root.public(), &original, None)
                .unwrap();
            assert_eq!(claim.original_head.position, position as u64);
            let bounds = claim.bounds;
            proofs.push(proof);
            Some(ConfirmedTime {
                earliest_ms: bounds.earliest_ms,
                latest_ms: bounds.latest_ms,
            })
        };
        originals.push(original);
        timed.push(time);
    }
    let (mut reader, _, _) = connect(&service);
    for (first, last) in [(1, 64), (65, 128), (129, 132)] {
        let result = reader
            .handle(ToService::ReadAccountEvidence {
                genesis: account.genesis.clone(),
                first,
                last,
                challenge: [8; 32],
            })
            .await;
        let FromService::AccountEvidence { confirmations, .. } = result else {
            panic!("evidence: {result:?}")
        };
        assert_eq!(
            confirmations,
            proofs[(first.max(2) - 2) as usize..(last - 1) as usize]
        );
    }
    for position in [1usize, 2, 3, 63, 64, 65, 127, 128, 131, 132] {
        let entries: Vec<_> = originals[..position]
            .iter()
            .zip(&timed[..position])
            .map(|(bytes, at)| (bytes.as_slice(), *at))
            .collect();
        let full = bh_account::VerifiedAccount::replay_timed(
            account.id,
            &entries,
            bh_account::Head {
                position: position as u64,
                hash: bh_crypto::hash(&originals[position - 1]),
            },
        )
        .unwrap();
        let current = position == originals.len();
        if current || position == 1 || position % 64 == 0 {
            let table = if current {
                "projection_current"
            } else {
                "projection_snapshots"
            };
            let summary: Vec<u8> = db.query_row(&format!(
                "SELECT summary FROM {table} WHERE account=?1 AND kind=1 AND source=?2 AND generation=1 AND position=?3"),
                params![account.id.0.as_slice(),account.log.id.as_slice(),position as i64], |r|r.get(0)).unwrap();
            assert_eq!(
                summary,
                account_projection::capture(&full).summary,
                "cut {position}"
            );
            let table = if current {
                "projection_active"
            } else {
                "projection_snapshot_devices"
            };
            let query = if current {
                format!(
                    "SELECT device FROM {table} WHERE account=?1 AND kind=1 AND source=?2 AND generation=1 ORDER BY device"
                )
            } else {
                format!(
                    "SELECT device FROM {table} WHERE account=?1 AND kind=1 AND source=?2 AND generation=1 AND position={} ORDER BY device",
                    position
                )
            };
            let actual: Vec<Vec<u8>> = db
                .prepare(&query)
                .unwrap()
                .query_map(
                    params![account.id.0.as_slice(), account.log.id.as_slice()],
                    |r| r.get(0),
                )
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            let expected: Vec<Vec<u8>> = account_projection::capture(&full)
                .active
                .iter()
                .map(|d| d.device.to_vec())
                .collect();
            assert_eq!(actual, expected, "membership cut {position}");
        }
        let older = Account {
            genesis: account.genesis.clone(),
            id: account.id,
            log: account.log,
            verified: full,
            originals: originals[..position].to_vec(),
            personal: None,
        };
        let (mut connection, binding, challenge) = connect(&service);
        assert!(
            matches!(connection.handle(authenticate_message(&older, &owner, binding, challenge)).await,
            FromService::Authenticated { account_head } if account_head == account.verified.head()),
            "authentication at historical cut {position}"
        );
    }
}

#[tokio::test]
async fn cancelled_removal_cycles_keep_obligations_bounded() {
    let (_, _, account) = populate_cancels(65).await;
    assert_eq!(account.originals.len(), 132);
    assert!(account_projection::capture(&account.verified).summary.len() < 4096);
}

fn grid(db: &Connection, account: &Account, positions: &[u64]) -> Vec<u64> {
    let mut seeks = Vec::new();
    for &position in positions {
        let cut:i64=db.query_row("SELECT position FROM projection_snapshots WHERE account=?1 AND kind=1 AND source=?2 AND generation=1 AND position<=?3 ORDER BY position DESC LIMIT 1",
            params![account.id.0.as_slice(),account.log.id.as_slice(),position as i64],|r|r.get(0)).unwrap();
        let suffix:i64=db.query_row("SELECT COUNT(*) FROM account_events WHERE account=?1 AND position>?2 AND position<=?3",
            params![account.id.0.as_slice(),cut,position as i64],|r|r.get(0)).unwrap();
        assert_eq!(suffix as u64, position - cut as u64);
        assert!(
            suffix <= 63,
            "position {position} sought {suffix} original rows after grid {cut}"
        );
        seeks.push(suffix as u64);
    }
    seeks
}

async fn cold_auth_bytes(h: &Harness, account: &Account, owner: &Device) -> (usize, usize, usize) {
    BYTES.with(|n| n.set(Some(0)));
    let service = h.service();
    let open = BYTES.with(|n| n.replace(None).unwrap());
    BYTES.with(|n| n.set(Some(0)));
    let (mut connection, binding, challenge) = connect(&service);
    let message = authenticate_message(account, owner, binding, challenge);
    let prepared = BYTES.with(|n| n.replace(None).unwrap());
    BYTES.with(|n| n.set(Some(0)));
    let answer = connection.handle(message).await;
    let handled = BYTES.with(|n| n.replace(None).unwrap());
    assert!(
        matches!(answer,FromService::Authenticated {account_head} if account_head==account.verified.head())
    );
    (open, prepared, handled)
}

#[tokio::test]
async fn historical_membership_uses_snapshot_not_current_rows() {
    let h = Harness::new();
    let owner = Device::new();
    let removed = Device::new();
    let mut account = Account::create(&owner);
    account.add_device(&owner, &removed); // position 2
    for _ in 0..31 {
        let extra = Device::new();
        account.add_device(&owner, &extra);
        account.remove_self(&extra);
    }
    assert_eq!(account.verified.head().position, 64);
    account.remove_self(&removed); // position 65
    for original in &account.originals {
        h.edge.force_append(
            account.log,
            &account_log_wrap(original, None).unwrap(),
            Route::Control,
        );
    }
    let service = h.service();
    let _ = session(&service, &account, &owner).await;
    let db = Connection::open(h.disk()).unwrap();
    let historical:i64=db.query_row("SELECT COUNT(*) FROM projection_snapshot_devices WHERE account=?1 AND kind=1 AND source=?2 AND generation=1 AND position=64 AND device=?3",
        params![account.id.0.as_slice(),account.log.id.as_slice(),removed.id().0.as_slice()],|r|r.get(0)).unwrap();
    let current:i64=db.query_row("SELECT COUNT(*) FROM projection_active WHERE account=?1 AND kind=1 AND source=?2 AND generation=1 AND device=?3",
        params![account.id.0.as_slice(),account.log.id.as_slice(),removed.id().0.as_slice()],|r|r.get(0)).unwrap();
    assert_eq!((historical, current), (1, 0));
    drop(db);
    let prior = older(&account, 64);
    let (mut connection, binding, challenge) = connect(&service);
    assert!(
        matches!(connection.handle(authenticate_message(&prior,&owner,binding,challenge)).await,
        FromService::Authenticated {account_head} if account_head==account.verified.head())
    );
    let (mut removed_connection, binding, challenge) = connect(&service);
    assert!(matches!(
        removed_connection
            .handle(authenticate_message(&prior, &removed, binding, challenge))
            .await,
        FromService::Refused {
            reason: bh_authz::proto::Refusal::NotActive
        }
    ));
}

#[tokio::test]
async fn historical_view_replays_at_most_63_and_misaligned_pages() {
    let (h, owner, account) = populate(65); // 131 originals; final network page is short.
    let service = h.service();
    let _ = session(&service, &account, &owner).await;
    drop(service);
    let db = Connection::open(h.disk()).unwrap();
    assert_eq!(
        grid(&db, &account, &[1, 3, 63, 64, 65, 127, 128, 129, 131]),
        [0, 2, 62, 0, 1, 63, 0, 1, 3]
    );
    let snapshots: Vec<i64> = db
        .prepare("SELECT position FROM projection_snapshots WHERE account=?1 ORDER BY position")
        .unwrap()
        .query_map([account.id.0.as_slice()], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(snapshots, [1, 64, 128]);
    drop(db);
    let service = h.service();
    for position in [3, 63, 64, 65, 127, 128, 129] {
        let prior = older(&account, position);
        let (mut connection, binding, challenge) = connect(&service);
        assert!(
            matches!(connection.handle(authenticate_message(&prior,&owner,binding,challenge)).await,
            FromService::Authenticated {account_head} if account_head==account.verified.head())
        );
    }
}

#[tokio::test]
async fn cold_home_restores_from_current_checkpoint_at_20k() {
    let (small, small_owner, small_account) = populate_cancels(65).await;
    let warm = small.service();
    let _ = session(&warm, &small_account, &small_owner).await;
    drop(warm);
    let small_bytes = cold_auth_bytes(&small, &small_account, &small_owner).await;
    let (h, owner, account) = populate_cancels(10_000).await; // 20,002 real signed originals, built once.
    assert!(account_projection::capture(&account.verified).summary.len() < 4096);
    let service = h.service();
    let _ = session(&service, &account, &owner).await;
    drop(service);
    let db = Connection::open(h.disk()).unwrap();
    let positions = [1, 3, 63, 64, 65, 127, 128, 19_999, 20_002];
    let suffix = grid(&db, &account, &positions);
    assert_eq!(suffix[7], 31);
    assert_eq!(suffix[8], 34); // Grid lookup; current restores its separate latest checkpoint.
    let latest: i64 = db
        .query_row(
            "SELECT position FROM projection_current WHERE account=?1 AND kind=1 AND source=?2",
            params![account.id.0.as_slice(), account.log.id.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(latest, 20_002);
    let snapshots:i64=db.query_row("SELECT COUNT(*) FROM projection_snapshots WHERE account=?1 AND kind=1 AND source=?2 AND generation=1",
        params![account.id.0.as_slice(),account.log.id.as_slice()],|r|r.get(0)).unwrap();
    assert_eq!(snapshots, 313);
    let legacy_rows: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM account_events WHERE account=?1",
            [account.id.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(legacy_rows, 20_002); // Old Store::account decoded every such row.
    let plans:Vec<String>=db.prepare("EXPLAIN QUERY PLAN SELECT position FROM projection_snapshots
        WHERE account=?1 AND kind=1 AND source=?2 AND generation=1 AND position<=?3 ORDER BY position DESC LIMIT 1").unwrap()
        .query_map(params![account.id.0.as_slice(),account.log.id.as_slice(),19_999i64],|r|r.get(3)).unwrap()
        .collect::<Result<_,_>>().unwrap();
    assert!(
        plans
            .iter()
            .any(|p| p.contains("SEARCH projection_snapshots")),
        "{plans:?}"
    );
    assert!(
        !plans
            .iter()
            .any(|p| p.contains("SCAN ") || p.contains("TEMP B-TREE")),
        "{plans:?}"
    );
    drop(db);
    projection::begin_work();
    let large_bytes = cold_auth_bytes(&h, &account, &owner).await;
    let current_work = projection::end_work();
    assert_eq!(current_work.transitions, 0);
    assert_eq!(current_work.decoded_rows, 0);
    assert_eq!(current_work.decoded_bytes, 0);
    assert_eq!((current_work.fullscan_steps, current_work.sorts), (0, 0));
    assert!(current_work.measured_statements >= 2);
    assert!(!current_work.sources.is_empty());
    assert!(
        current_work
            .sources
            .iter()
            .all(|key| key.account == account.id)
    );
    eprintln!(
        "cold HOME auth Rust bytes (open,proof,handle): 132 originals={small_bytes:?}, 20,002 originals={large_bytes:?}; snapshots={snapshots}, suffix@19999={}",
        suffix[7]
    );
    assert!(
        large_bytes.2 <= small_bytes.2 + 524_288,
        "cold authority allocation grew with history: {small_bytes:?} -> {large_bytes:?}"
    );
    let restarted = h.service();
    let c = session(&restarted, &account, &owner).await;
    assert!(c.authenticated());
    let prior = older_cancels(&account, 19_999);
    let (mut connection, binding, challenge) = connect(&restarted);
    projection::begin_work();
    assert!(matches!(
        connection
            .handle(authenticate_message(&prior, &owner, binding, challenge))
            .await,
        FromService::Authenticated { .. }
    ));
    let history_work = projection::end_work();
    assert_eq!(
        history_work.transitions, 31,
        "actual verified transitions at 19,999"
    );
    assert_eq!(
        history_work.decoded_rows, 31,
        "actual fetched proof/original pairs"
    );
    assert!(history_work.decoded_bytes > 31 * 64 && history_work.decoded_bytes < 31 * 4096);
    assert_eq!((history_work.fullscan_steps, history_work.sorts), (0, 0));
    assert!(history_work.measured_statements >= 2);
    eprintln!(
        "measured HOME work: current transitions={} decoded_rows={} decoded_bytes={} SQL status={}/{} over {} statements, earlier@19999 transitions={} decoded_rows={} decoded_bytes={} SQL status={}/{} over {} statements",
        current_work.transitions,
        current_work.decoded_rows,
        current_work.decoded_bytes,
        current_work.fullscan_steps,
        current_work.sorts,
        current_work.measured_statements,
        history_work.transitions,
        history_work.decoded_rows,
        history_work.decoded_bytes,
        history_work.fullscan_steps,
        history_work.sorts,
        history_work.measured_statements
    );
    assert!(!history_work.sources.is_empty());
    assert!(
        history_work
            .sources
            .iter()
            .all(|key| key.account == account.id)
    );
}

// BASE copies: one Mac's own base, its copy of the account beyond the HOME
// anchor its genesis names, carried in real native account-run controls.
use bh_authz::proto::Want;
use bh_authz_test_alloc::PEAK;
use support::native::{Fold, Mac, order};

/// One request by the Fold to remove the Mac, or its cancellation, signed
/// by the Fold, applied timed to the Mac's account, ordered on its HOME log;
/// with the confirmation the native copier carries.
fn trust_change(
    h: &Harness,
    mac: &mut Mac,
    fold: &Fold,
    cancel: Option<u64>,
) -> (Vec<u8>, Vec<u8>) {
    let at = bh_authz::Clock::now_ms(&*h.clock).unwrap();
    let draft = match cancel {
        None => mac.ordered.request_removal(fold.id(), mac.device()),
        Some(request) => mac.ordered.cancel_removal(fold.id(), request),
    }
    .unwrap();
    let event = draft
        .finish(fold.control.sign(draft.signing_bytes()))
        .unwrap();
    mac.ordered
        .apply_timed(
            event.as_bytes(),
            Some(ConfirmedTime {
                earliest_ms: at,
                latest_ms: at,
            }),
        )
        .unwrap();
    mac.originals.push(event.as_bytes().to_vec());
    h.order_original(mac.log, event.as_bytes());
    (event.as_bytes().to_vec(), mac.confirm(&event))
}

/// `pairs` request/cancel cycles: two devices, nothing left outstanding.
fn cancel_run(h: &Harness, mac: &mut Mac, fold: &Fold, pairs: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut run = Vec::with_capacity(pairs * 2);
    for _ in 0..pairs {
        let request = mac.ordered.head().position + 1;
        run.push(trust_change(h, mac, fold, None));
        run.push(trust_change(h, mac, fold, Some(request)));
    }
    run
}

/// Copy `run` into the base as one native account-run control, through the
/// service, order it and pull it.
async fn copy_run(
    h: &Harness,
    mac: &mut Mac,
    connection: &mut bh_authz::Connection,
    run: &[(Vec<u8>, Vec<u8>)],
) {
    let copy = mac.copy_run(run);
    let answer = connection.handle(mac.submit_copy(&copy)).await;
    order(h, &answer, &copy).unwrap();
    assert_eq!(mac.pull(h), vec![bh_event::Outcome::Accepted]);
}

fn content_append(mac: &Mac) -> ToService {
    ToService::Permits {
        items: vec![Want::Append {
            log: mac.base_log(),
            event: base_event(3).0.encode(),
            epoch: bh_event::key_id(&mac.content),
        }],
    }
}

/// The Mac's registered base with its Fold's copied addition and `runs`
/// runs of 64 copied originals; with `repeats`, each run's page also holds
/// that many rejected duplicate genesis controls, so every page is full and
/// alike whatever the history length.
async fn base_fixture(runs: usize, repeats: usize) -> (Harness, Mac, Fold) {
    let h = Harness::new();
    let mut mac = Mac::new(&h);
    let fold = Fold::new();
    let service = h.service();
    let mut connection = mac.session(&service).await;
    mac.register_and_order(&h, &mut connection).await;
    // The Fold's addition is the account's first timed event; its later
    // cancellations need it mature, its requests' deadlines still ahead.
    let at = bh_authz::Clock::now_ms(&*h.clock).unwrap();
    let add = mac.sign_add(&mac.ordered.clone(), &fold);
    mac.ordered
        .apply_timed(
            add.as_bytes(),
            Some(ConfirmedTime {
                earliest_ms: at,
                latest_ms: at,
            }),
        )
        .unwrap();
    mac.originals.push(add.as_bytes().to_vec());
    mac.submit_account(&h, &mut connection, &add).await;
    let first = [(add.as_bytes().to_vec(), mac.confirm(&add))];
    copy_run(&h, &mut mac, &mut connection, &first).await;
    h.clock.set(at + REMOVAL_WAIT_MS + 100);
    for _ in 0..runs {
        let run = cancel_run(&h, &mut mac, &fold, 32);
        let mut connection = mac.session(&service).await;
        copy_run(&h, &mut mac, &mut connection, &run).await;
        if repeats > 0 {
            for _ in 0..repeats {
                h.edge
                    .force_append(mac.base_log(), &mac.genesis.descriptor, Route::Control);
            }
            assert!(
                mac.pull(&h)
                    .iter()
                    .all(|o| *o == bh_event::Outcome::Rejected)
            );
            let answer = connection.handle(mac.register()).await;
            assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
        }
    }
    let mut connection = mac.session(&service).await;
    single_permit(connection.handle(content_append(&mac)).await);
    (h, mac, fold)
}

fn copied_rows(h: &Harness, mac: &Mac) -> i64 {
    let db = Connection::open(h.disk()).unwrap();
    let old: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM base_account_changes WHERE base=?1",
            [mac.base.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let new: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM projection_copies WHERE kind=2 AND source=?1",
            [mac.base.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap_or(0);
    old + new
}

#[tokio::test]
async fn cold_base_restores_without_copies_or_anchor_replay() {
    let mut measured = Vec::new();
    for runs in [1, 16] {
        let (h, mac, _) = base_fixture(runs, 0).await;
        assert_eq!(copied_rows(&h, &mac), 1 + 64 * runs as i64);
        let service = h.service();
        let mut connection = mac.session(&service).await;
        projection::begin_work();
        let answer = connection.handle(content_append(&mac)).await;
        let work = projection::end_work();
        single_permit(answer);
        eprintln!(
            "cold BASE load, {} copies: transitions={} decoded_rows={} decoded_bytes={} SQL status={}/{} over {} statements",
            1 + 64 * runs,
            work.transitions,
            work.decoded_rows,
            work.decoded_bytes,
            work.fullscan_steps,
            work.sorts,
            work.measured_statements
        );
        // Only this base's own copy, which restores over its pinned prefix.
        let base = projection::SourceKey {
            account: mac.ordered.id(),
            source: projection::Source::Base(mac.base),
        };
        assert!(!work.sources.is_empty() && work.sources.iter().all(|key| *key == base));
        measured.push((
            work.transitions,
            work.decoded_rows,
            work.decoded_bytes,
            work.fullscan_steps,
            work.sorts,
        ));
    }
    for (transitions, rows, bytes, scans, sorts) in &measured {
        assert_eq!(
            *transitions, 0,
            "cold BASE load replayed copies or its anchor: {measured:?}"
        );
        assert!(
            *rows <= 2 && *bytes <= 2 * 4096,
            "cold BASE load decoded copies: {measured:?}"
        );
        assert_eq!((*scans, *sorts), (0, 0), "{measured:?}");
    }
    assert_eq!(
        measured[0], measured[1],
        "cold BASE load work grew with history"
    );
}

/// Rust bytes the service allocates to permit, then confirm, one copy
/// control carrying `run`.
async fn mutation_bytes(
    h: &Harness,
    mac: &mut Mac,
    connection: &mut bh_authz::Connection,
    run: &[(Vec<u8>, Vec<u8>)],
) -> usize {
    let copy = mac.copy_run(run);
    let request = mac.submit_copy(&copy);
    BYTES.with(|n| n.set(Some(0)));
    let answer = connection.handle(request).await;
    let permit = BYTES.with(|n| n.replace(None).unwrap());
    order(h, &answer, &copy).unwrap();
    assert_eq!(mac.pull(h), vec![bh_event::Outcome::Accepted]);
    let request = content_append(mac);
    BYTES.with(|n| n.set(Some(0)));
    let answer = connection.handle(request).await;
    let confirm = BYTES.with(|n| n.replace(None).unwrap());
    single_permit(answer);
    permit + confirm
}

#[tokio::test]
async fn base_mutation_writes_only_new_copies() {
    let mut measured = Vec::new();
    for runs in [1, 16] {
        let (h, mut mac, fold) = base_fixture(runs, 0).await;
        let service = h.service();
        let mut connection = mac.session(&service).await;
        single_permit(connection.handle(content_append(&mac)).await);
        let before = copied_rows(&h, &mac);
        // One copied original, then a 64-original run.
        let request = mac.ordered.head().position + 1;
        let one = vec![trust_change(&h, &mut mac, &fold, None)];
        let mut connection = mac.session(&service).await;
        let single = mutation_bytes(&h, &mut mac, &mut connection, &one).await;
        assert_eq!(copied_rows(&h, &mac), before + 1);
        let mut run = vec![trust_change(&h, &mut mac, &fold, Some(request))];
        run.extend(cancel_run(&h, &mut mac, &fold, 31));
        run.push(trust_change(&h, &mut mac, &fold, None));
        assert_eq!(run.len(), 64);
        let mut connection = mac.session(&service).await;
        let full = mutation_bytes(&h, &mut mac, &mut connection, &run).await;
        assert_eq!(copied_rows(&h, &mac), before + 65);
        eprintln!(
            "BASE mutation Rust bytes with {} prior copies: one copy={single}, 64 copies={full}",
            1 + 64 * runs
        );
        measured.push((single, full));
    }
    let (small, large) = (measured[0], measured[1]);
    assert!(
        large.0 <= small.0 + 65_536,
        "one-copy mutation grew with history: {small:?} -> {large:?}"
    );
    assert!(
        large.1 <= small.1 + 65_536,
        "64-copy mutation grew with history: {small:?} -> {large:?}"
    );
}

#[tokio::test]
async fn registration_keeps_bounded_candidate_memory() {
    let mut measured = Vec::new();
    for runs in [1, 16] {
        let (h, mac, _) = base_fixture(runs, 63).await;
        let service = h.service();
        let mut connection = mac.session(&service).await;
        let request = mac.register();
        PEAK.with(|n| n.set(Some((0, 0))));
        let answer = connection.handle(request).await;
        let (_, peak) = PEAK.with(|n| n.replace(None).unwrap());
        assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
        let controls = h.edge.head(mac.base_log());
        eprintln!(
            "registration peak live Rust bytes over {} copies, base head {}: {peak}",
            1 + 64 * runs,
            controls.position
        );
        measured.push(peak);
    }
    // Staged rows replace the copies, IDs and raw path the replay used to
    // hold. What remains is one page and one effect, plus the account
    // library's in-memory record of requests resolved while a view stays
    // loaded (about 48 bytes per resolved request per live view copy here).
    assert!(
        measured[1] <= measured[0] + 131_072,
        "registration memory grew with history: {measured:?}"
    );
}

#[tokio::test]
async fn one_member_partition_does_not_read_other_sources() {
    use projection::{Source, SourceKey};
    let h = Harness::new();
    let service = h.service();
    let mut macs = Vec::new();
    for _ in 0..16 {
        let mut mac = Mac::new(&h);
        let mut connection = mac.session(&service).await;
        mac.register_and_order(&h, &mut connection).await;
        single_permit(connection.handle(content_append(&mac)).await);
        macs.push(mac);
    }
    drop(service);
    let service = h.service();
    for (i, mac) in macs.iter_mut().enumerate().step_by(5) {
        let home = SourceKey {
            account: mac.ordered.id(),
            source: Source::Home(mac.log),
        };
        let base = SourceKey {
            account: mac.ordered.id(),
            source: Source::Base(mac.base),
        };
        let mut connection = mac.session(&service).await;
        // A cold base load, then a copied addition through its index.
        projection::begin_work();
        single_permit(connection.handle(content_append(mac)).await);
        let fold = Fold::new();
        let add = mac.pair(&fold);
        mac.submit_account(&h, &mut connection, &add).await;
        let copy = mac.copy(add.as_bytes()).unwrap();
        let answer = connection.handle(mac.submit_copy(&copy)).await;
        order(&h, &answer, &copy).unwrap();
        assert_eq!(mac.pull(&h), vec![bh_event::Outcome::Accepted]);
        let mut connection = mac.session(&service).await;
        single_permit(connection.handle(content_append(mac)).await);
        let work = projection::end_work();
        assert!(
            work.sources.iter().all(|k| *k == home || *k == base),
            "partition {i} read another member's source"
        );
        assert!(work.sources.contains(&home) && work.sources.contains(&base));
        assert_eq!(work.transitions, 0, "partition {i}");
        assert_eq!((work.fullscan_steps, work.sorts), (0, 0), "partition {i}");
        eprintln!(
            "partition {i} of 16: {} source lookups (HOME {} / BASE {}), {} decoded rows, {} statements",
            work.sources.len(),
            work.sources.iter().filter(|k| **k == home).count(),
            work.sources.iter().filter(|k| **k == base).count(),
            work.decoded_rows,
            work.measured_statements
        );
    }
}
