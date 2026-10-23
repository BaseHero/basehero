//! A base's controls count only when every raw control links to an
//! endpoint the hosting root signed: an omitted, substituted or withheld
//! control changes neither what the service grants nor its durable record.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_authz::{
    Connection,
    proto::{FromService, Refusal, ToService, Want},
};
use bh_event::{Encoded, Outcome};
use bh_sync::{Commitment, Digest, Route};
use std::sync::atomic::Ordering;
use support::{
    native::{Fold, Mac, order},
    *,
};

/// Copy an account event into the Mac's base through the service, order the
/// copy and pull it; returns the copy.
async fn copied(
    harness: &Harness,
    mac: &mut Mac,
    connection: &mut Connection,
    account_event: &[u8],
) -> Encoded {
    let copy = mac.copy(account_event).unwrap();
    let answer = connection.handle(mac.submit_copy(&copy)).await;
    order(harness, &answer, &copy).unwrap();
    assert_eq!(mac.pull(harness), vec![Outcome::Accepted]);
    copy
}

/// The complete raw-control path a stop pins: the replay candidate's staged
/// commitments it references, in order.
fn stop_path(harness: &Harness, base: [u8; 32]) -> Vec<u8> {
    let db = rusqlite::Connection::open(harness.disk()).unwrap();
    let generation: i64 = db
        .query_row(
            "SELECT path_generation FROM base_stops WHERE base=?1 AND scan_controls IS NULL",
            [base.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let mut statement = db
        .prepare(
            "SELECT commitment FROM base_raw WHERE base=?1 AND generation=?2 ORDER BY position",
        )
        .unwrap();
    statement
        .query_map(rusqlite::params![base.as_slice(), generation], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .unwrap()
        .flat_map(Result::unwrap)
        .collect()
}

/// One permit for the base's controls: a forced confirmation.
async fn read_controls(connection: &mut Connection, mac: &Mac) -> FromService {
    connection
        .handle(ToService::Permits {
            items: vec![Want::ReadControls {
                log: mac.base_log(),
                after: 0,
            }],
        })
        .await
}

/// The Mac's base: its genesis G, the copied addition P of a Fold, the
/// Fold's copied removal R, closing the epoch, and the copied addition Q of
/// another Fold, all confirmed by a service that has since stopped.
async fn removed() -> (Harness, Mac, [Encoded; 3]) {
    let harness = Harness::new();
    let mut mac = Mac::new(&harness);
    let (fold, other) = (Fold::new(), Fold::new());
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    mac.register_and_order(&harness, &mut connection).await;
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    let p = copied(&harness, &mut mac, &mut connection, add.as_bytes()).await;
    let removal = mac.remove(&fold);
    harness.order_original(mac.log, removal.as_bytes());
    let mut connection = mac.session(&service).await;
    let r = copied(&harness, &mut mac, &mut connection, removal.as_bytes()).await;
    let add = mac.pair(&other);
    mac.submit_account(&harness, &mut connection, &add).await;
    let q = copied(&harness, &mut mac, &mut connection, add.as_bytes()).await;
    let answer = read_controls(&mut connection, &mac).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    (harness, mac, [p, r, q])
}

async fn seen_fixture(
    candidate_known_only: bool,
    accept: bool,
) -> (Harness, Mac, Encoded, [u8; 300]) {
    let harness = Harness::new();
    let mut mac = Mac::new(&harness);
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    mac.register_and_order(&harness, &mut connection).await;
    if accept {
        let answer = read_controls(&mut connection, &mac).await;
        assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    }
    let added = mac.pair(&Fold::new());
    mac.submit_account(&harness, &mut connection, &added).await;
    // A rejected duplicate is a raw position that replay's candidate knows,
    // but the previously accepted durable projection does not.
    if candidate_known_only {
        harness
            .edge
            .force_append(mac.base_log(), &mac.genesis.descriptor, Route::Control);
    }
    let known = if candidate_known_only {
        harness.edge.head(mac.base_log())
    } else {
        mac.history.head()
    };
    let false_head = bh_sync::Head {
        position: known.position,
        hash: Digest([91; 32]),
    };
    assert_ne!(false_head, known);
    let receipt = mac.receipt(false_head);
    let copy = mac.copy_with_seen_receipt(added.as_bytes(), false_head, receipt);
    (harness, mac, copy, receipt)
}

#[tokio::test]
async fn a_rooted_seen_receipt_in_submission_stops_and_retains_its_witness() {
    let (harness, mac, copy, receipt) = seen_fixture(false, true).await;
    let before = projection_rows(&harness.disk(), mac.base.0);
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    let answer = connection.handle(mac.submit_copy(&copy)).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Conflict
            }
        ),
        "{answer:?}"
    );
    assert_eq!(projection_rows(&harness.disk(), mac.base.0), before);
    let db = rusqlite::Connection::open(harness.disk()).unwrap();
    let (stored, known_position, known_hash, pinned_root): (Vec<u8>, i64, Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT seen_receipt, known_position, known_hash, hosting_root FROM base_stops WHERE base=?1",
            [mac.base.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(stored, receipt);
    assert_eq!(pinned_root, harness.root.public());
    assert_eq!(
        (known_position as u64, known_hash),
        (
            mac.history.head().position,
            mac.history.head().hash.0.to_vec()
        )
    );
    drop(db);
    for answer in [
        connection.handle(mac.submit_copy(&copy)).await,
        connection.handle(mac.register()).await,
    ] {
        assert!(
            matches!(
                answer,
                FromService::Refused {
                    reason: Refusal::Conflict
                }
            ),
            "{answer:?}"
        );
    }
    let reopened = harness.service();
    let mut retry = mac.session(&reopened).await;
    let answer = retry.handle(mac.register()).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Conflict
            }
        ),
        "{answer:?}"
    );
    let mut healthy = Mac::new(&harness);
    let mut session = healthy.session(&reopened).await;
    healthy.register_and_order(&harness, &mut session).await;
    assert!(matches!(
        read_controls(&mut session, &healthy).await,
        FromService::Permits { .. }
    ));
}

#[tokio::test]
async fn replay_seen_receipt_stops_only_after_complete_rooted_raw_coverage() {
    for missing_suffix in [true, false] {
        let (harness, mac, copy, receipt) = seen_fixture(true, true).await;
        let before = projection_rows(&harness.disk(), mac.base.0);
        let body = bh_sync::BodyObject::new(copy.body.clone())
            .unwrap()
            .commitment();
        harness
            .edge
            .stage(
                &harness.sign(bh_sync::permit::Scope::Stage {
                    log: mac.base_log(),
                    body,
                    len: copy.body.len() as u32,
                }),
                &copy.body,
            )
            .unwrap();
        for _ in 0..65 {
            harness
                .edge
                .force_append(mac.base_log(), &copy.descriptor, Route::Control);
        }
        if missing_suffix {
            *harness.edge.rewrite_controls.lock().unwrap() = Some(Box::new(|controls| {
                controls.pop();
            }));
        }
        let service = harness.service();
        let mut connection = mac.session(&service).await;
        let answer = connection.handle(mac.register()).await;
        if missing_suffix {
            assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
            let stopped: i64 = rusqlite::Connection::open(harness.disk())
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM base_stops WHERE base=?1",
                    [mac.base.0.as_slice()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(stopped, 0);
            *harness.edge.rewrite_controls.lock().unwrap() = None;
            let answer = connection.handle(mac.register()).await;
            assert!(
                matches!(
                    answer,
                    FromService::Refused {
                        reason: Refusal::Conflict
                    }
                ),
                "{answer:?}"
            );
        } else {
            assert!(
                matches!(
                    answer,
                    FromService::Refused {
                        reason: Refusal::Conflict
                    }
                ),
                "{answer:?}"
            );
        }
        type SeenRows = (Vec<u8>, i64, Vec<u8>, Vec<u8>, Vec<u8>);
        let (stored, position, hash, endpoint, endpoint_receipt): SeenRows =
            rusqlite::Connection::open(harness.disk()).unwrap().query_row(
                "SELECT seen_receipt, known_position, known_hash, observed, receipt FROM base_stops WHERE base=?1",
                [mac.base.0.as_slice()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            ).unwrap();
        let controls = stop_path(&harness, mac.base.0);
        assert_eq!(stored, receipt);
        assert_eq!(position, 2); // candidate-only rejected duplicate, not durable genesis
        assert_ne!(hash, mac.history.head().hash.0);
        let seen = bh_sync::receipt::verify(&harness.root.public(), mac.base, &stored)
            .unwrap()
            .head();
        assert_eq!(seen.position, position as u64);
        assert_ne!(seen.hash.0.to_vec(), hash);
        let end = bh_sync::OrderState::decode(&endpoint).unwrap();
        assert_eq!(
            bh_sync::receipt::verify(&harness.root.public(), mac.base, &endpoint_receipt)
                .unwrap()
                .head(),
            end.head(mac.base)
        );
        assert_eq!(controls.len(), 67 * Commitment::LEN);
        assert_eq!(projection_rows(&harness.disk(), mac.base.0), before);
    }
}

#[tokio::test]
async fn unverified_replay_body_cannot_poison_a_base() {
    let (harness, mac, copy, _) = seen_fixture(false, true).await;
    let before = projection_rows(&harness.disk(), mac.base.0);
    let body = bh_sync::BodyObject::new(copy.body.clone())
        .unwrap()
        .commitment();
    harness
        .edge
        .stage(
            &harness.sign(bh_sync::permit::Scope::Stage {
                log: mac.base_log(),
                body,
                len: copy.body.len() as u32,
            }),
            &copy.body,
        )
        .unwrap();
    harness
        .edge
        .force_append(mac.base_log(), &copy.descriptor, Route::Control);
    harness.edge.corrupt_body.store(true, Ordering::SeqCst);
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    let answer = connection.handle(mac.register()).await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    assert_eq!(projection_rows(&harness.disk(), mac.base.0), before);
    let count: i64 = rusqlite::Connection::open(harness.disk())
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM base_stops WHERE base=?1",
            [mac.base.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 0);
    harness.edge.corrupt_body.store(false, Ordering::SeqCst);
    let answer = connection.handle(mac.register()).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Conflict
            }
        ),
        "{answer:?}"
    );
}

#[tokio::test]
async fn provisional_replay_stops_on_covered_seen_conflict_without_promotion() {
    let (harness, mac, copy, receipt) = seen_fixture(false, false).await;
    let before = projection_rows(&harness.disk(), mac.base.0);
    assert_eq!(base_status(&harness.disk(), mac.base.0), Some(1));
    let body = bh_sync::BodyObject::new(copy.body.clone())
        .unwrap()
        .commitment();
    harness
        .edge
        .stage(
            &harness.sign(bh_sync::permit::Scope::Stage {
                log: mac.base_log(),
                body,
                len: copy.body.len() as u32,
            }),
            &copy.body,
        )
        .unwrap();
    harness
        .edge
        .force_append(mac.base_log(), &copy.descriptor, Route::Control);
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    let answer = connection.handle(mac.register()).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Conflict
            }
        ),
        "{answer:?}"
    );
    assert_eq!(base_status(&harness.disk(), mac.base.0), Some(1));
    assert_eq!(projection_rows(&harness.disk(), mac.base.0), before);
    let stored: Vec<u8> = rusqlite::Connection::open(harness.disk())
        .unwrap()
        .query_row(
            "SELECT seen_receipt FROM base_stops WHERE base=?1",
            [mac.base.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, receipt);
}

#[tokio::test]
async fn seen_witness_needs_no_later_control_body_once_raw_path_is_complete() {
    let (harness, mac, copy, _) = seen_fixture(true, true).await;
    let body = bh_sync::BodyObject::new(copy.body.clone())
        .unwrap()
        .commitment();
    harness
        .edge
        .stage(
            &harness.sign(bh_sync::permit::Scope::Stage {
                log: mac.base_log(),
                body,
                len: copy.body.len() as u32,
            }),
            &copy.body,
        )
        .unwrap();
    harness
        .edge
        .force_append(mac.base_log(), &copy.descriptor, Route::Control);
    // This later descriptor has no staged body. Its raw commitment still
    // links and must not make the earlier rooted witness disappear.
    harness
        .edge
        .force_append(mac.base_log(), &base_event(4).0, Route::Control);
    for _ in 0..64 {
        harness
            .edge
            .force_append(mac.base_log(), &copy.descriptor, Route::Control);
    }
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    let answer = connection.handle(mac.register()).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Conflict
            }
        ),
        "{answer:?}"
    );
}

#[tokio::test]
async fn wrong_root_seen_receipt_and_wrong_body_do_not_stop() {
    let (harness, mac, copy, _) = seen_fixture(false, true).await;
    let false_head = bh_sync::Head {
        position: mac.history.head().position,
        hash: Digest([91; 32]),
    };
    let wrong = bh_crypto::SigningKey::generate();
    let certificate = bh_sync::receipt::verify_certificate(
        &wrong.public(),
        &bh_sync::receipt::certify(&wrong, wrong.public()),
    )
    .unwrap();
    let false_receipt = bh_sync::receipt::sign(&certificate, &wrong, mac.base, false_head).unwrap();
    // A signed member assertion with a receipt under another root is not evidence.
    let added = mac.originals.last().unwrap().clone();
    let mut mac = mac;
    let invalid = mac.copy_with_seen_receipt(&added, false_head, false_receipt);
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    let answer = connection.handle(mac.submit_copy(&invalid)).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Invalid
            }
        ),
        "{answer:?}"
    );
    let genuine_receipt = mac.receipt(mac.history.head());
    let false_claim = mac.copy_with_seen_receipt(&added, false_head, genuine_receipt);
    let answer = connection.handle(mac.submit_copy(&false_claim)).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Invalid
            }
        ),
        "{answer:?}"
    );
    let mut broken_proof = mac.receipt(false_head);
    broken_proof[299] ^= 1;
    let broken = mac.copy_with_seen_receipt(&added, false_head, broken_proof);
    let answer = connection.handle(mac.submit_copy(&broken)).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Invalid
            }
        ),
        "{answer:?}"
    );
    let mut bad_body = Encoded {
        descriptor: copy.descriptor.clone(),
        body: copy.body.clone(),
    };
    bad_body.body[0] ^= 1;
    let answer = connection.handle(mac.submit_copy(&bad_body)).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Invalid
            }
        ),
        "{answer:?}"
    );
    let mut broken_binding = copy.descriptor.encode();
    broken_binding[80] ^= 1;
    let answer = connection
        .handle(ToService::SubmitBaseControl {
            log: mac.base_log(),
            descriptor: broken_binding,
            body: copy.body.clone(),
            metadata: bh_authz::proto::MetadataKey::new(&mac.metadata),
        })
        .await;
    assert!(
        !matches!(
            answer,
            FromService::Permits { .. }
                | FromService::Refused {
                    reason: Refusal::Conflict
                }
        ),
        "{answer:?}"
    );
    let stopped: i64 = rusqlite::Connection::open(harness.disk())
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM base_stops WHERE base=?1",
            [mac.base.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stopped, 0);
    let answer = connection.handle(mac.register()).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
}

fn omit(harness: &Harness, omitted: Vec<Digest>) {
    *harness.edge.rewrite_controls.lock().unwrap() = Some(Box::new(move |controls| {
        controls.retain(|(c, _)| !omitted.contains(&c.event_digest()))
    }));
}

#[tokio::test]
async fn an_omitted_removal_or_segment_cannot_replace_the_durable_projection() {
    for omitted in [&[1][..], &[0, 1]] {
        let (harness, mac, controls) = removed().await;
        let before = projection_rows(&harness.disk(), mac.base.0);
        // Restarted on the same disk, the service is handed the base's
        // controls with the removal (and the addition before it) left out:
        // the later genuine control no longer links.
        let service = harness.service();
        omit(
            &harness,
            omitted
                .iter()
                .map(|&i| controls[i].descriptor.digest())
                .collect(),
        );
        let mut connection = mac.session(&service).await;
        let answer = connection.handle(mac.register()).await;
        assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
        assert_eq!(projection_rows(&harness.disk(), mac.base.0), before);
        // From the honest log the same projection is rebuilt, byte for byte.
        *harness.edge.rewrite_controls.lock().unwrap() = None;
        let answer = connection.handle(mac.register()).await;
        assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
        assert_eq!(projection_rows(&harness.disk(), mac.base.0), before);
    }
}

#[tokio::test]
async fn a_false_pointer_at_the_same_endpoint_grants_nothing() {
    let (harness, mac, [p, r, q]) = removed().await;
    // The service lost its disk; the device registers the base again.
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", harness.disk().display()));
    }
    let service = harness.service();
    // The server drops the removal and re-points the later control at the
    // addition before it. Its endpoint is the genuine, signed one.
    let (p, r, q) = (
        p.descriptor.digest(),
        r.descriptor.digest(),
        q.descriptor.digest(),
    );
    let base = mac.base;
    *harness.edge.rewrite_controls.lock().unwrap() = Some(Box::new(move |controls| {
        let after_p = controls
            .iter()
            .find(|(c, _)| c.event_digest() == p)
            .unwrap()
            .0
            .after();
        controls.retain(|(c, _)| c.event_digest() != r);
        for (c, e) in controls.iter_mut() {
            if c.event_digest() == q {
                *c = Commitment::order(base, after_p, e, Route::Control).unwrap();
            }
        }
    }));
    let mut connection = mac.session(&service).await;
    let answer = connection.handle(mac.register()).await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    assert!(projection_rows(&harness.disk(), mac.base.0).is_empty());
    // The honest log rebuilds the record with the removal: its epoch is
    // closed, so the old content key writes nothing.
    *harness.edge.rewrite_controls.lock().unwrap() = None;
    let answer = connection.handle(mac.register()).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    let answer = connection
        .handle(ToService::Permits {
            items: vec![Want::Append {
                log: mac.base_log(),
                event: base_event(3).0.encode(),
                epoch: bh_event::key_id(&mac.content),
            }],
        })
        .await;
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    assert_eq!(items[0].clone().err(), Some(Refusal::Epoch));
}

#[tokio::test]
async fn sparse_restart_authenticates_new_tail_without_a_content_prefix_lookup() {
    let harness = Harness::new();
    let mut mac = Mac::new(&harness);
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    mac.register_and_order(&harness, &mut connection).await;
    let log = mac.base_log();
    let content = base_event(3).0;
    harness.edge.force_append(log, &content, Route::Content);
    assert!(matches!(
        connection.handle(mac.register()).await,
        FromService::Permits { .. }
    ));
    let before = projection_rows(&harness.disk(), mac.base.0);
    // A forced control read at this point receives zero NEW controls and
    // still covers the trailing content endpoint, not just raw genesis.
    let answer = read_controls(&mut connection, &mac).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    let db = rusqlite::Connection::open(harness.disk()).unwrap();
    let raw: Vec<u8> = db
        .query_row(
            "SELECT raw_order FROM base_controls WHERE base=?1",
            [mac.base.0.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(bh_sync::OrderState::decode(&raw).unwrap().position(), 1);
    drop(db);
    drop(connection);
    drop(service);
    // Sparse authority keeps the last raw checkpoint, not an unproved
    // cross-content-prefix link. A different signed content-only endpoint
    // still requires an operation-local signed endpoint and full raw coverage.
    harness.edge.truncate(log, 1);
    harness
        .edge
        .force_append(log, &base_event(4).0, Route::Content);
    harness
        .edge
        .force_append(log, &base_event(5).0, Route::Content);
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    let reads = harness.edge.control_reads.load(Ordering::SeqCst);
    let answer = connection.handle(mac.register()).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    assert_eq!(harness.edge.control_reads.load(Ordering::SeqCst), reads + 1);
    assert_eq!(projection_rows(&harness.disk(), mac.base.0), before);
    harness.edge.withhold_endpoint.store(true, Ordering::SeqCst);
    let answer = read_controls(&mut connection, &mac).await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    harness
        .edge
        .withhold_endpoint
        .store(false, Ordering::SeqCst);
    let answer = read_controls(&mut connection, &mac).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
}

#[tokio::test]
async fn a_withheld_endpoint_changes_nothing() {
    let (harness, mac, _) = removed().await;
    let before = projection_rows(&harness.disk(), mac.base.0);
    let service = harness.service();
    harness.edge.withhold_endpoint.store(true, Ordering::SeqCst);
    let mut connection = mac.session(&service).await;
    let answer = read_controls(&mut connection, &mac).await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    let answer = connection.handle(mac.register()).await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    assert_eq!(projection_rows(&harness.disk(), mac.base.0), before);
    harness
        .edge
        .withhold_endpoint
        .store(false, Ordering::SeqCst);
    let answer = read_controls(&mut connection, &mac).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
}

#[tokio::test]
async fn an_invalid_receipt_cannot_cover_a_base() {
    let (harness, mac, _) = removed().await;
    let before = projection_rows(&harness.disk(), mac.base.0);
    let service = harness.service();
    harness
        .edge
        .corrupt_coverage_receipt
        .store(true, Ordering::SeqCst);
    let mut connection = mac.session(&service).await;
    let answer = read_controls(&mut connection, &mac).await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    assert_eq!(projection_rows(&harness.disk(), mac.base.0), before);
    harness
        .edge
        .corrupt_coverage_receipt
        .store(false, Ordering::SeqCst);
    let answer = read_controls(&mut connection, &mac).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
}

#[tokio::test]
async fn a_valid_receipt_under_another_root_or_mismatched_endpoint_covers_nothing() {
    let (harness, mac, _) = removed().await;
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    let before = projection_rows(&harness.disk(), mac.base.0);
    harness
        .edge
        .wrong_coverage_root
        .store(true, Ordering::SeqCst);
    let answer = read_controls(&mut connection, &mac).await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    assert_eq!(projection_rows(&harness.disk(), mac.base.0), before);
    harness
        .edge
        .wrong_coverage_root
        .store(false, Ordering::SeqCst);
    harness
        .edge
        .malformed_endpoint
        .store(true, Ordering::SeqCst);
    let answer = read_controls(&mut connection, &mac).await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    assert_eq!(projection_rows(&harness.disk(), mac.base.0), before);
}

#[tokio::test]
async fn a_signed_content_endpoint_at_the_durable_control_global_position_stops() {
    for register in [false, true] {
        for accepted_before_raw in [false, true] {
            let (harness, mac, [p, ..]) = removed().await;
            let log = mac.base_log();
            if accepted_before_raw {
                harness
                    .edge
                    .force_append(log, &p.descriptor, Route::Control);
                let service = harness.service();
                let mut connection = mac.session(&service).await;
                let answer = connection.handle(mac.register()).await;
                assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
            }
            let before = projection_rows(&harness.disk(), log.id);
            let honest = harness.edge.after(log, 0);
            harness.edge.truncate(log, 2);
            harness
                .edge
                .force_append(log, &base_event(3).0, Route::Content);
            harness
                .edge
                .force_append(log, &base_event(4).0, Route::Content);
            let service = harness.service();
            let mut connection = mac.session(&service).await;
            let answer = if register {
                connection.handle(mac.register()).await
            } else {
                read_controls(&mut connection, &mac).await
            };
            assert!(
                matches!(
                    answer,
                    FromService::Refused {
                        reason: Refusal::Conflict
                    }
                ),
                "{answer:?}"
            );
            let db = rusqlite::Connection::open(harness.disk()).unwrap();
            let (known_pos, known_hash, observed_hash): (i64, Vec<u8>, Vec<u8>) = db.query_row(
                "SELECT known_position, known_hash, observed_hash FROM base_stops WHERE base=?1",
                [log.id.as_slice()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            ).unwrap();
            assert_eq!(known_pos, 4);
            assert_ne!(known_hash, observed_hash);
            drop(db);
            assert_eq!(projection_rows(&harness.disk(), log.id), before);
            harness.edge.truncate(log, 0);
            for (ordered, event, _) in honest {
                harness.edge.force_append(log, &event, ordered.route());
            }
            let answer = connection.handle(mac.register()).await;
            assert!(
                matches!(
                    answer,
                    FromService::Refused {
                        reason: Refusal::Conflict
                    }
                ),
                "{answer:?}"
            );
            let reopened = harness.service();
            let mut connection = mac.session(&reopened).await;
            let answer = connection.handle(mac.register()).await;
            assert!(
                matches!(
                    answer,
                    FromService::Refused {
                        reason: Refusal::Conflict
                    }
                ),
                "{answer:?}"
            );
        }
    }
}

#[tokio::test]
async fn signed_global_conflict_is_not_hidden_by_an_unverified_raw_page_item() {
    let (harness, mac, _) = removed().await;
    let log = mac.base_log();
    let before = projection_rows(&harness.disk(), log.id);
    harness.edge.truncate(log, 2);
    harness
        .edge
        .force_append(log, &base_event(3).0, Route::Content);
    harness
        .edge
        .force_append(log, &base_event(4).0, Route::Content);
    *harness.edge.rewrite_controls.lock().unwrap() = Some(Box::new(move |items| {
        let event = items[1].1.clone();
        // Valid commitment and descriptor, but for a different log. The
        // genuine signed endpoint still independently contradicts Q.
        let other_base = bh_sync::BaseId::from_genesis(&event);
        items[1].0 = Commitment::order(
            other_base,
            bh_sync::OrderState::EMPTY,
            &event,
            Route::Control,
        )
        .unwrap();
    }));
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    let answer = connection.handle(mac.register()).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Conflict
            }
        ),
        "{answer:?}"
    );
    assert_eq!(projection_rows(&harness.disk(), log.id), before);
}

#[tokio::test]
async fn a_wrong_root_or_different_global_position_is_not_a_control_conflict() {
    let (harness, mac, _) = removed().await;
    let log = mac.base_log();
    let before = projection_rows(&harness.disk(), log.id);
    let honest = harness.edge.after(log, 0);
    harness.edge.truncate(log, 2);
    for n in 3..=4 {
        harness
            .edge
            .force_append(log, &base_event(n).0, Route::Content);
    }
    harness
        .edge
        .wrong_coverage_root
        .store(true, Ordering::SeqCst);
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    let answer = read_controls(&mut connection, &mac).await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    harness
        .edge
        .wrong_coverage_root
        .store(false, Ordering::SeqCst);
    harness
        .edge
        .force_append(log, &base_event(5).0, Route::Content);
    let answer = connection.handle(mac.register()).await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    let stopped: i64 = rusqlite::Connection::open(harness.disk())
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM base_stops WHERE base=?1",
            [log.id.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stopped, 0);
    assert_eq!(projection_rows(&harness.disk(), log.id), before);
    harness.edge.truncate(log, 0);
    for (ordered, event, _) in honest {
        harness.edge.force_append(log, &event, ordered.route());
    }
    let answer = connection.handle(mac.register()).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    assert_eq!(projection_rows(&harness.disk(), log.id), before);
}

#[tokio::test]
async fn replay_retains_the_earlier_conflicting_control_and_its_rooted_path() {
    for missing_suffix in [true, false] {
        let (harness, mac, [p, _, q]) = removed().await;
        let log = mac.base_log();
        let before = projection_rows(&harness.disk(), log.id);
        harness.edge.truncate(log, 2);
        for _ in 0..3 {
            harness
                .edge
                .force_append(log, &p.descriptor, Route::Control);
        }
        if missing_suffix {
            *harness.edge.rewrite_controls.lock().unwrap() = Some(Box::new(|controls| {
                controls.pop();
            }));
        }
        let service = harness.service();
        let mut connection = mac.session(&service).await;
        let answer = connection.handle(mac.register()).await;
        if missing_suffix {
            assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
            let count: i64 = rusqlite::Connection::open(harness.disk())
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM base_stops WHERE base=?1",
                    [log.id.as_slice()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 0);
            *harness.edge.rewrite_controls.lock().unwrap() = None;
            let answer = connection.handle(mac.register()).await;
            assert!(
                matches!(
                    answer,
                    FromService::Refused {
                        reason: Refusal::Conflict
                    }
                ),
                "{answer:?}"
            );
        } else {
            assert!(
                matches!(
                    answer,
                    FromService::Refused {
                        reason: Refusal::Conflict
                    }
                ),
                "{answer:?}"
            );
        }
        assert_eq!(projection_rows(&harness.disk(), log.id), before);
        let db = rusqlite::Connection::open(harness.disk()).unwrap();
        let (known_pos, known_hash, endpoint, endpoint_receipt): (i64, Vec<u8>, Vec<u8>, Vec<u8>) =
            db.query_row(
                "SELECT known_position, known_hash, observed, receipt
                 FROM base_stops WHERE base=?1",
                [log.id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        let raw = stop_path(&harness, log.id);
        let (observed_hash, known_digest, observed_digest): (Vec<u8>, Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT observed_hash, known_digest, observed_digest FROM base_stops WHERE base=?1",
                [log.id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(known_pos, 4);
        assert_eq!(known_hash, mac.history.head().hash.0);
        assert_ne!(known_hash, observed_hash);
        assert_eq!(known_digest, q.descriptor.digest().0);
        assert_eq!(observed_digest, p.descriptor.digest().0);
        assert_eq!(raw.len(), 5 * Commitment::LEN);
        let mut last = bh_sync::RawControlHead::EMPTY;
        let mut matched = false;
        let (chunks, remainder) = raw.as_chunks::<{ Commitment::LEN }>();
        assert!(remainder.is_empty());
        for bytes in chunks {
            let control = Commitment::decode(bytes).unwrap();
            assert_eq!(control.before().raw_control(), last);
            last = control.after().raw_control();
            if control.head().position == known_pos as u64 {
                assert_eq!(control.head().hash.0.to_vec(), observed_hash);
                matched = true;
            }
        }
        assert!(matched);
        let endpoint = bh_sync::OrderState::decode(&endpoint).unwrap();
        assert_eq!(last, endpoint.raw_control());
        assert_eq!(
            bh_sync::receipt::verify(&harness.root.public(), mac.base, &endpoint_receipt)
                .unwrap()
                .head(),
            endpoint.head(mac.base)
        );
        drop(db);
        let reopened = harness.service();
        let mut retry = mac.session(&reopened).await;
        let answer = retry.handle(mac.register()).await;
        assert!(
            matches!(
                answer,
                FromService::Refused {
                    reason: Refusal::Conflict
                }
            ),
            "{answer:?}"
        );
    }
}

#[tokio::test]
async fn a_history_contradicting_the_durable_checkpoint_changes_nothing() {
    let (harness, mac, [p, ..]) = removed().await;
    let before = projection_rows(&harness.disk(), mac.base.0);
    let service = harness.service();
    let honest = harness.edge.after(mac.base_log(), 0);
    // The server serves another history after the addition: repeats of it
    // where the removal and the later addition were, each signed for.
    harness.edge.truncate(mac.base_log(), 2);
    for _ in 0..2 {
        harness
            .edge
            .force_append(mac.base_log(), &p.descriptor, Route::Control);
    }
    let mut connection = mac.session(&service).await;
    let answer = read_controls(&mut connection, &mac).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Conflict
            }
        ),
        "{answer:?}"
    );
    assert_eq!(projection_rows(&harness.disk(), mac.base.0), before);
    let db = rusqlite::Connection::open(harness.disk()).unwrap();
    let evidence: (Vec<u8>, Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT remembered, observed, receipt FROM base_stops WHERE base=?1",
            [mac.base.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let remembered = bh_sync::OrderState::decode(&evidence.0).unwrap();
    let observed = bh_sync::OrderState::decode(&evidence.1).unwrap();
    assert_eq!(
        remembered.raw_control().position,
        observed.raw_control().position
    );
    assert_ne!(remembered.raw_control(), observed.raw_control());
    assert_eq!(
        bh_sync::receipt::verify(&harness.root.public(), mac.base, &evidence.2)
            .unwrap()
            .head(),
        observed.head(mac.base)
    );
    drop(db);
    harness.edge.truncate(mac.base_log(), 0);
    for (ordered, event, _) in honest {
        harness
            .edge
            .force_append(mac.base_log(), &event, ordered.route());
    }
    let answer = read_controls(&mut connection, &mac).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Conflict
            }
        ),
        "{answer:?}"
    );
    let answer = connection.handle(mac.register()).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Conflict
            }
        ),
        "{answer:?}"
    );
    for item in [
        read_events(mac.base_log()),
        Want::ReadBodies {
            log: mac.base_log(),
            bodies: vec![],
        },
        Want::Stage {
            log: mac.base_log(),
            body: Digest([3; 32]),
            len: 1024,
        },
        Want::Subscribe {
            log: mac.base_log(),
        },
        Want::Append {
            log: mac.base_log(),
            event: base_event(3).0.encode(),
            epoch: bh_event::key_id(&mac.content),
        },
        Want::Presence {
            log: mac.base_log(),
            epoch: bh_event::key_id(&mac.content),
        },
        Want::ReadControls {
            log: mac.base_log(),
            after: 0,
        },
    ] {
        let answer = connection
            .handle(ToService::Permits { items: vec![item] })
            .await;
        assert!(
            matches!(
                answer,
                FromService::Refused {
                    reason: Refusal::Conflict
                }
            ),
            "{answer:?}"
        );
    }
    let answer = connection
        .handle(ToService::ReadBatch {
            want: Want::ReadBatch {
                log: mac.base_log(),
                after: bh_sync::Head::EMPTY,
                max_events: 8,
            },
        })
        .await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Conflict
            }
        ),
        "{answer:?}"
    );
    let service = harness.service();
    let mut restarted = mac.session(&service).await;
    let answer = restarted.handle(mac.register()).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Conflict
            }
        ),
        "{answer:?}"
    );
    assert_eq!(projection_rows(&harness.disk(), mac.base.0), before);
    let mut other = Mac::new(&harness);
    let mut healthy = other.session(&service).await;
    other.register_and_order(&harness, &mut healthy).await;
    let answer = read_controls(&mut healthy, &other).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
}

#[tokio::test]
async fn a_verified_registration_candidate_cannot_publish_after_another_instance_stops() {
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    let (harness, mac, [p, ..]) = removed().await;
    harness
        .edge
        .force_append(mac.base_log(), &p.descriptor, Route::Control);
    let before = projection_rows(&harness.disk(), mac.base.0);
    let first = harness.service();
    let mut warm = mac.session(&first).await;
    let answer = warm
        .handle(ToService::Permits {
            items: vec![read_events(mac.base_log())],
        })
        .await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    let entered = Arc::new(Semaphore::new(0));
    let release = Arc::new(Semaphore::new(0));
    first.hold_base_publication(Arc::new({
        let (entered, release) = (entered.clone(), release.clone());
        move |_| {
            let (entered, release) = (entered.clone(), release.clone());
            Box::pin(async move {
                entered.add_permits(1);
                release.acquire().await.unwrap().forget();
            })
        }
    }));
    let mut candidate = mac.session(&first).await;
    let request = mac.register();
    let pending = tokio::spawn(async move { candidate.handle(request).await });
    entered.acquire().await.unwrap().forget();
    // The first registration has verified its genuine endpoint and raw chain.
    // Another service authenticates a contradictory raw head at the same
    // position, while the first still holds its unsaved candidate.
    harness.edge.truncate(mac.base_log(), 2);
    for _ in 0..2 {
        harness
            .edge
            .force_append(mac.base_log(), &p.descriptor, Route::Control);
    }
    let second = harness.service();
    let mut other = mac.session(&second).await;
    let stop = read_controls(&mut other, &mac).await;
    assert!(
        matches!(
            stop,
            FromService::Refused {
                reason: Refusal::Conflict
            }
        ),
        "{stop:?}"
    );
    release.add_permits(1);
    let answer = pending.await.unwrap();
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Conflict
            }
        ),
        "{answer:?}"
    );
    let answer = warm
        .handle(ToService::Permits {
            items: vec![read_events(mac.base_log())],
        })
        .await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Conflict
            }
        ),
        "{answer:?}"
    );
    assert_eq!(projection_rows(&harness.disk(), mac.base.0), before);
}

#[tokio::test]
async fn two_signed_same_position_page_endpoints_stop_only_this_base() {
    let (harness, mac, [p, ..]) = removed().await;
    let log = mac.base_log();
    for _ in 0..65 {
        harness
            .edge
            .force_append(log, &p.descriptor, Route::Control);
    }
    let before = projection_rows(&harness.disk(), log.id);
    *harness.edge.fork_after_control_read.lock().unwrap() =
        Some((log, 68, base_event(4).0, Route::Content));
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    let answer = connection.handle(mac.register()).await;
    assert!(
        matches!(
            answer,
            FromService::Refused {
                reason: Refusal::Conflict
            }
        ),
        "{answer:?}"
    );
    assert_eq!(projection_rows(&harness.disk(), log.id), before);
    assert!(harness.edge.control_reads.load(Ordering::SeqCst) >= 2);
    let db = rusqlite::Connection::open(harness.disk()).unwrap();
    let (old, new, old_receipt, new_receipt): (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT remembered, observed, remembered_receipt, receipt FROM base_stops WHERE base=?1",
            [log.id.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    let old = bh_sync::OrderState::decode(&old).unwrap();
    let new = bh_sync::OrderState::decode(&new).unwrap();
    assert_eq!(old.position(), new.position());
    assert_ne!(old, new);
    for (opening, receipt) in [(old, old_receipt), (new, new_receipt)] {
        assert_eq!(
            bh_sync::receipt::verify(&harness.root.public(), mac.base, &receipt)
                .unwrap()
                .head(),
            opening.head(mac.base)
        );
    }
}

#[tokio::test]
async fn repeated_and_wrong_route_controls_hold_their_place_without_effect() {
    let harness = Harness::new();
    let mut mac = Mac::new(&harness);
    let fold = Fold::new();
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    mac.register_and_order(&harness, &mut connection).await;
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    let copy = mac.copy(add.as_bytes()).unwrap();
    // A server orders the copy on the content route first: that reserves
    // only its content-route ID.
    harness
        .edge
        .force_append(mac.base_log(), &copy.descriptor, Route::Content);
    assert_eq!(mac.pull(&harness), vec![Outcome::Rejected]);
    let answer = connection.handle(mac.submit_copy(&copy)).await;
    let ordered = order(&harness, &answer, &copy).unwrap();
    assert_eq!(mac.pull(&harness), vec![Outcome::Accepted]);
    // Then it orders the exact copy again on the control route.
    let repeat = harness
        .edge
        .force_append(mac.base_log(), &copy.descriptor, Route::Control);
    assert_eq!(
        repeat.event_id(),
        copy.descriptor.publication_id(Route::Control)
    );
    assert_eq!(mac.pull(&harness), vec![Outcome::Rejected]);
    // Replayed from genesis, the repeat is rejected by its first-used ID: it
    // holds its position and nothing else.
    let answer = connection.handle(mac.register()).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    let mut folded = mac.fold_session(&service, &fold).await;
    let answer = folded
        .handle(ToService::Permits {
            items: vec![Want::Append {
                log: mac.base_log(),
                event: base_event(3).0.encode(),
                epoch: bh_event::key_id(&mac.content),
            }],
        })
        .await;
    let FromService::Permits { items } = answer else {
        panic!("{answer:?}")
    };
    assert!(items[0].is_ok(), "{items:?}");
    let db = rusqlite::Connection::open(harness.disk()).unwrap();
    let (control, head): (i64, i64) = db
        .query_row(
            "SELECT control_position, head_position FROM base_controls WHERE base=?1",
            [mac.base.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(
        (control as u64, head as u64),
        (ordered.position, repeat.head().position)
    );
    // The next control follows the repeat.
    let removal = mac.remove(&fold);
    harness.order_original(mac.log, removal.as_bytes());
    let mut connection = mac.session(&service).await;
    let next = mac.copy(removal.as_bytes()).unwrap();
    let FromService::Permits { items } = connection.handle(mac.submit_copy(&next)).await else {
        panic!("permits")
    };
    let bh_sync::permit::Scope::Append { after, .. } =
        harness.permit(items[1].as_ref().unwrap()).scope
    else {
        panic!("append")
    };
    assert_eq!(after, Some(repeat.head()));
}

#[tokio::test]
async fn a_scan_covers_exactly_its_first_endpoint_across_pages() {
    let harness = Harness::new();
    let mut mac = Mac::new(&harness);
    let fold = Fold::new();
    let service = harness.service();
    let mut connection = mac.session(&service).await;
    mac.register_and_order(&harness, &mut connection).await;
    let add = mac.pair(&fold);
    mac.submit_account(&harness, &mut connection, &add).await;
    let p = copied(&harness, &mut mac, &mut connection, add.as_bytes()).await;
    let base = mac.base_log();
    let repeat = |n: usize| {
        for _ in 0..n {
            harness
                .edge
                .force_append(base, &p.descriptor, Route::Control);
        }
    };
    let raw_head = || {
        rusqlite::Connection::open(harness.disk())
            .unwrap()
            .query_row(
                "SELECT head_position FROM base_controls WHERE base=?1",
                [mac.base.0.as_slice()],
                |r| r.get::<_, i64>(0),
            )
            .unwrap() as u64
    };
    // Exactly one full page of controls, ending at the endpoint: one read.
    repeat(62);
    let reads = harness.edge.control_reads.load(Ordering::SeqCst);
    let answer = connection.handle(mac.register()).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    assert_eq!(harness.edge.control_reads.load(Ordering::SeqCst), reads + 1);
    assert_eq!(raw_head(), 64);
    // Two pages: a control ordered once the first is read is past the
    // endpoint the scan covers.
    repeat(8);
    *harness.edge.append_after_control_read.lock().unwrap() = Some((base, p.descriptor.clone()));
    let reads = harness.edge.control_reads.load(Ordering::SeqCst);
    let answer = connection.handle(mac.register()).await;
    assert!(matches!(answer, FromService::Permits { .. }), "{answer:?}");
    assert_eq!(harness.edge.control_reads.load(Ordering::SeqCst), reads + 2);
    assert_eq!(raw_head(), 72);
    // A later page naming another endpoint covers nothing.
    let before = projection_rows(&harness.disk(), mac.base.0);
    harness.edge.ignore_through.store(true, Ordering::SeqCst);
    repeat(60);
    *harness.edge.append_after_control_read.lock().unwrap() = Some((base, p.descriptor.clone()));
    let answer = connection.handle(mac.register()).await;
    assert!(matches!(answer, FromService::Unavailable), "{answer:?}");
    assert_eq!(projection_rows(&harness.disk(), mac.base.0), before);
}
