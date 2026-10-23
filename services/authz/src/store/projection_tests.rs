use super::projection::{Pin, ProjectionHeader, ProjectionWrite, Source, SourceKey};
use super::*;
use bh_account::{
    AccountEvent, DeviceId, DevicePublicKeys, VerifiedAccount, projection as account_projection,
};
use bh_sync::canonical::CanonicalCommitment;
use std::sync::Arc;

fn seed_unwritten() -> (
    tempfile::TempDir,
    Arc<Store>,
    SourceKey,
    Vec<u8>,
    OrderState,
    ProjectionWrite,
) {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("authz.sqlite")).unwrap());
    let (key, genesis, opening, write) = seed_on();
    (dir, store, key, genesis, opening, write)
}

pub(super) fn seed_on() -> (SourceKey, Vec<u8>, OrderState, ProjectionWrite) {
    let (key, genesis, opening, write, _, _) = seed_on_with_signer();
    (key, genesis, opening, write)
}
pub(super) fn seed_on_with_signer() -> (
    SourceKey,
    Vec<u8>,
    OrderState,
    ProjectionWrite,
    bh_crypto::SigningKey,
    bh_crypto::SigningKey,
) {
    let signer = bh_crypto::SigningKey::generate();
    let ordinary = bh_crypto::SigningKey::generate();
    let keys = DevicePublicKeys::new(
        ordinary.public(),
        signer.public(),
        bh_crypto::KemKey::generate().public(),
    )
    .unwrap();
    let recovery = bh_account::recovery::RecoveryKeys::generate();
    let draft = AccountEvent::genesis(keys, recovery.public());
    let genesis = draft
        .finish(signer.sign(draft.signing_bytes()))
        .unwrap()
        .as_bytes()
        .to_vec();
    let id = AccountId::of_genesis(&AccountEvent::decode(&genesis).unwrap()).unwrap();
    let log = bh_authz_proto::account_log_id(&genesis).unwrap();
    let wrapped = bh_authz_proto::account_log_wrap(&genesis, None).unwrap();
    let opening = CanonicalCommitment::order(
        BaseId(log),
        OrderState::EMPTY,
        wrapped.digest(),
        Route::Control,
    )
    .unwrap()
    .after();
    let key = SourceKey {
        account: id,
        source: Source::Home(bh_authz_proto::LogId {
            kind: bh_authz_proto::LogKind::Account,
            id: log,
        }),
    };
    let view = VerifiedAccount::from_genesis(id, &genesis).unwrap();
    let checkpoint = account_projection::capture(&view);
    let write = ProjectionWrite {
        header: ProjectionHeader {
            pin: Pin {
                key,
                generation: 1,
                cut: view.head(),
            },
            root: [7; 32],
            opening,
            prefix: None,
        },
        checkpoint,
        delta: account_projection::delta(&view),
        snapshots: vec![projection::HistoricalSnapshot {
            checkpoint: account_projection::capture(&view),
            opening,
        }],
    };
    (key, genesis, opening, write, signer, ordinary)
}

fn seed() -> (
    tempfile::TempDir,
    Arc<Store>,
    SourceKey,
    Vec<u8>,
    OrderState,
) {
    let (dir, store, key, genesis, opening, write) = seed_unwritten();
    store
        .extend_projected(
            &key.account.0,
            &match key.source {
                Source::Home(log) => log.id,
                Source::Base(_) => unreachable!(),
            },
            OrderState::EMPTY,
            opening,
            &[StoredEvent {
                original: genesis.clone(),
                body: None,
            }],
            ConfirmedPage {
                confirmations: &[],
                activations: &[],
            },
            &write,
            &[],
        )
        .unwrap();
    (dir, store, key, genesis, opening)
}

#[test]
fn home_projection_rolls_back_original_and_index_on_each_writer_failure() {
    for table in [
        "account_events",
        "accounts",
        "projection_sources",
        "projection_selected",
        "projection_times",
        "projection_active",
        "projection_devices",
        "projection_keys",
        "projection_current",
        "projection_snapshots",
        "projection_snapshot_devices",
    ] {
        let (_dir, store, key, genesis, opening, write) = seed_unwritten();
        store.with(|db| db.execute_batch(&format!(
            "CREATE TRIGGER fail_write BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'injected'); END;"
        ))).unwrap();
        let Source::Home(log) = key.source else {
            unreachable!()
        };
        assert!(
            store
                .extend_projected(
                    &key.account.0,
                    &log.id,
                    OrderState::EMPTY,
                    opening,
                    &[StoredEvent {
                        original: genesis.clone(),
                        body: None
                    }],
                    ConfirmedPage {
                        confirmations: &[],
                        activations: &[]
                    },
                    &write,
                    &[]
                )
                .is_err(),
            "{table}"
        );
        assert!(
            store.account(&key.account.0).unwrap().is_none(),
            "{table} wrote the original"
        );
        assert!(
            store.current_projection(key).unwrap().is_none(),
            "{table} selected partial authority"
        );
        store
            .with(|db| db.execute_batch("DROP TRIGGER fail_write;"))
            .unwrap();
        assert!(
            store
                .extend_projected(
                    &key.account.0,
                    &log.id,
                    OrderState::EMPTY,
                    opening,
                    &[StoredEvent {
                        original: genesis,
                        body: None
                    }],
                    ConfirmedPage {
                        confirmations: &[],
                        activations: &[]
                    },
                    &write,
                    &[]
                )
                .is_ok(),
            "{table} blocked retry"
        );
    }
}

fn signed_next() -> (
    tempfile::TempDir,
    Arc<Store>,
    SourceKey,
    OrderState,
    OrderState,
    ProjectionWrite,
    StoredEvent,
    Vec<u8>,
) {
    use bh_sync::{
        evidence::{ConfirmationClaim, OrderingConfirmation, TimeBounds, original_digest},
        permit,
    };
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("authz.sqlite")).unwrap());
    let (key, genesis, previous, mut first, signer, _) = seed_on_with_signer();
    let root = bh_crypto::SigningKey::generate();
    let service = bh_crypto::SigningKey::generate();
    let certificate = permit::certify(&root, service.public());
    first.header.root = root.public();
    let Source::Home(log) = key.source else {
        unreachable!()
    };
    store
        .extend_projected(
            &key.account.0,
            &log.id,
            OrderState::EMPTY,
            previous,
            &[StoredEvent {
                original: genesis.clone(),
                body: None,
            }],
            ConfirmedPage {
                confirmations: &[],
                activations: &[],
            },
            &first,
            &[],
        )
        .unwrap();
    let Record::Canonical(current) = store.current_projection(key).unwrap().unwrap() else {
        panic!()
    };
    let view = store
        .restore_projection(current, key, root.public(), &genesis)
        .unwrap();
    let new_keys = DevicePublicKeys::new(
        bh_crypto::SigningKey::generate().public(),
        bh_crypto::SigningKey::generate().public(),
        bh_crypto::KemKey::generate().public(),
    )
    .unwrap();
    let owner_id = view.active_devices().unwrap().next().unwrap().id();
    let draft = view.add_device(owner_id, new_keys).unwrap();
    let event = StoredEvent {
        original: draft
            .finish(signer.sign(draft.signing_bytes()))
            .unwrap()
            .as_bytes()
            .to_vec(),
        body: Some(Digest([5; 32])),
    };
    let bounds = TimeBounds {
        earliest_ms: 100,
        latest_ms: 100,
    };
    let next = view
        .applied_batch_timed(&[(&event.original, Some(crate::confirm::time(bounds)))])
        .unwrap();
    let wrapper = bh_authz_proto::account_log_wrap(&event.original, event.body).unwrap();
    let after =
        CanonicalCommitment::order(BaseId(log.id), previous, wrapper.digest(), Route::Control)
            .unwrap()
            .after();
    let proof = OrderingConfirmation::sign(
        &service,
        &certificate,
        ConfirmationClaim {
            log,
            original: original_digest(&event.original),
            original_previous: crate::confirm::head(first.checkpoint.head),
            original_head: crate::confirm::head(next.head()),
            body: event.body,
            ordered: after.head(BaseId(log.id)),
            bounds,
        },
    )
    .encode()
    .to_vec();
    let write = ProjectionWrite {
        header: ProjectionHeader {
            pin: Pin {
                key,
                generation: 1,
                cut: next.head(),
            },
            root: root.public(),
            opening: after,
            prefix: None,
        },
        checkpoint: account_projection::capture(&next),
        delta: account_projection::delta(&next),
        snapshots: vec![],
    };
    (dir, store, key, previous, after, write, event, proof)
}

#[test]
fn signed_page_faults_after_proof_body_and_attachment_roll_back_whole_state() {
    for table in [
        "account_confirmations",
        "confirmed_events",
        "account_applied_bodies",
        "pending_attachments",
    ] {
        let (dir, store, key, previous, after, write, event, proof) = signed_next();
        let Source::Home(log) = key.source else {
            unreachable!()
        };
        let wrapper = bh_authz_proto::account_log_wrap(&event.original, event.body).unwrap();
        store
            .stage_attachment(
                &key.account.0,
                wrapper.digest(),
                &Attachment {
                    record: None,
                    recovery_seal: vec![],
                    rotation_body: None,
                },
            )
            .unwrap();
        let trigger = if table == "pending_attachments" {
            "DELETE"
        } else {
            "INSERT"
        };
        store.with(|db| db.execute_batch(&format!(
            "CREATE TRIGGER fail_write BEFORE {trigger} ON {table} BEGIN SELECT RAISE(ABORT,'injected'); END;"))).unwrap();
        let page = |proof: &Vec<u8>| vec![(2, proof.clone())];
        let confirmations = page(&proof);
        let activations = [(2, None)];
        let applied = [projection::AppliedBody {
            position: 2,
            digest: event.body.unwrap(),
        }];
        assert!(
            store
                .extend_projected(
                    &key.account.0,
                    &log.id,
                    previous,
                    after,
                    &[StoredEvent {
                        original: event.original.clone(),
                        body: event.body
                    }],
                    ConfirmedPage {
                        confirmations: &confirmations,
                        activations: &activations
                    },
                    &write,
                    &applied
                )
                .is_err(),
            "{table}"
        );
        drop(store);
        let reopened = Store::open(&dir.path().join("authz.sqlite")).unwrap();
        let Record::Canonical(old) = reopened.current_projection(key).unwrap().unwrap() else {
            panic!()
        };
        assert_eq!(old.checkpoint.head.position, 1, "{table}");
        let stored = reopened.account(&key.account.0).unwrap().unwrap();
        assert_eq!(stored.events.len(), 1, "{table}");
        assert!(stored.confirmations.is_empty(), "{table}");
        assert!(
            !reopened
                .body_applied(old.header.pin, event.body.unwrap())
                .unwrap(),
            "{table}"
        );
        assert!(
            reopened
                .with(|db| db.query_row(
                    "SELECT COUNT(*) FROM pending_attachments WHERE account=?1",
                    [key.account.0.as_slice()],
                    |r| r.get::<_, i64>(0)
                ))
                .unwrap()
                == 1,
            "{table}"
        );
    }
}

#[test]
fn deferred_commit_failure_rolls_back_original_proof_body_and_attachment() {
    let (dir, store, key, previous, after, write, event, proof) = signed_next();
    let Source::Home(log) = key.source else {
        unreachable!()
    };
    let wrapped = bh_authz_proto::account_log_wrap(&event.original, event.body).unwrap();
    store
        .stage_attachment(
            &key.account.0,
            wrapped.digest(),
            &Attachment {
                record: None,
                recovery_seal: vec![],
                rotation_body: None,
            },
        )
        .unwrap();
    store.with(|db| db.execute_batch("PRAGMA foreign_keys=ON;
        CREATE TABLE commit_parent(id INTEGER PRIMARY KEY);
        CREATE TABLE commit_guard(id INTEGER, parent INTEGER REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
        CREATE TRIGGER fail_commit AFTER INSERT ON account_applied_bodies BEGIN
          INSERT INTO commit_guard(id,parent) VALUES(1,99);
        END;" )).unwrap();
    let confirmations = [(2, proof)];
    let activations = [(2, None)];
    let applied = [projection::AppliedBody {
        position: 2,
        digest: event.body.unwrap(),
    }];
    assert!(
        store
            .extend_projected(
                &key.account.0,
                &log.id,
                previous,
                after,
                &[event],
                ConfirmedPage {
                    confirmations: &confirmations,
                    activations: &activations
                },
                &write,
                &applied
            )
            .is_err()
    );
    drop(store);
    let reopened = Store::open(&dir.path().join("authz.sqlite")).unwrap();
    assert_eq!(
        reopened
            .account(&key.account.0)
            .unwrap()
            .unwrap()
            .events
            .len(),
        1
    );
    let Record::Canonical(current) = reopened.current_projection(key).unwrap().unwrap() else {
        panic!()
    };
    assert_eq!(current.checkpoint.head.position, 1);
    assert_eq!(
        reopened
            .with(
                |db| db.query_row("SELECT COUNT(*) FROM commit_guard", [], |r| r
                    .get::<_, i64>(0))
            )
            .unwrap(),
        0
    );
    assert_eq!(
        reopened
            .with(|db| db.query_row(
                "SELECT COUNT(*) FROM pending_attachments WHERE account=?1",
                [key.account.0.as_slice()],
                |r| r.get::<_, i64>(0)
            ))
            .unwrap(),
        1
    );
}

// The signed page remains small; activation objects use valid recovery records
// addressed to this account, including an existing indexed record with tries.
fn recovery_record_for(account: AccountId) -> Vec<u8> {
    use bh_account::recovery::{Password, RecoveryCode, RecoveryKeys, prepare_record};
    let control = bh_crypto::SigningKey::generate();
    let keys = DevicePublicKeys::new(
        bh_crypto::SigningKey::generate().public(),
        control.public(),
        bh_crypto::KemKey::generate().public(),
    )
    .unwrap();
    let recovery = RecoveryKeys::generate();
    let draft = AccountEvent::genesis(keys, recovery.public());
    let genesis = draft.finish(control.sign(draft.signing_bytes())).unwrap();
    let id = AccountId::of_genesis(&genesis).unwrap();
    let view = VerifiedAccount::from_genesis(id, genesis.as_bytes()).unwrap();
    let mut record = prepare_record(
        &view,
        &recovery,
        &Password::new("fixture password").unwrap(),
        &RecoveryCode::generate(),
    )
    .unwrap()
    .as_bytes()
    .to_vec();
    record[10..42].copy_from_slice(&account.0);
    assert!(
        bh_account::recovery::record_checks(&record)
            .unwrap()
            .account
            == account
    );
    record
}

fn object_rows(store: &Store, account: AccountId) -> Vec<Vec<String>> {
    store.with(|db| {
        let mut result = Vec::new();
        for sql in [
            "SELECT hex(record)||':'||hex(recovery_seal)||':'||hex(record_digest)||':'||hex(seal_digest) FROM recovery_records WHERE account=?1",
            "SELECT hex(proof_check)||':'||hex(record_digest) FROM recovery_index WHERE account=?1 ORDER BY proof_check",
            "SELECT hex(t.record_digest)||':'||t.failures||':'||coalesce(t.next_ms,-1) FROM recovery_tries t JOIN recovery_records r ON r.record_digest=t.record_digest WHERE r.account=?1",
            "SELECT hex(prefix_digest) FROM retire_home WHERE account=?1",
        ] {
            result.push(db.prepare(sql)?.query_map([account.0.as_slice()], |r| r.get(0))?.collect::<Result<Vec<String>,_>>()?);
        }
        Ok(result)
    }).unwrap()
}

#[test]
fn activation_object_faults_roll_back_replacement_rotation_and_whole_signed_page() {
    for mode in ["replace", "rotate"] {
        for (table, operation) in [
            ("recovery_records", "UPDATE"),
            ("recovery_index", "INSERT"),
            ("retire_home", "INSERT"),
            ("accounts", "UPDATE"),
            ("account_applied_bodies", "INSERT"),
            ("commit", "DEFERRED"),
        ] {
            // Only the writes each activation actually makes: replacement deletes
            // and inserts records (plus index/retirement), rotation updates the record.
            if mode == "rotate" && (table == "recovery_index" || table == "retire_home") {
                continue;
            }
            if mode == "replace" && operation == "UPDATE" && table == "recovery_records" {
                continue;
            }
            let (dir, store, key, previous, after, write, event, proof) = signed_next();
            let Source::Home(log) = key.source else {
                unreachable!()
            };
            let old = recovery_record_for(key.account);
            let old_checks = bh_account::recovery::record_checks(&old).unwrap();
            let old_seal = vec![7; 1300];
            store
                .put_recovery(&key.account.0, &old, &old_seal, None)
                .unwrap();
            store.record_failure(&old_checks.digest, 10).unwrap();
            let before = object_rows(&store, key.account);
            let replacement = recovery_record_for(key.account);
            let new_checks = bh_account::recovery::record_checks(&replacement).unwrap();
            assert_ne!(new_checks.digest, old_checks.digest);
            let new_seal = vec![8; 1300];
            let effect = if mode == "replace" {
                Activation::Replace {
                    old: old_checks.digest,
                    record: replacement.clone(),
                    seal: new_seal.clone(),
                    prefix: Digest([4; 32]),
                }
            } else {
                Activation::Rotate {
                    seal: new_seal.clone(),
                }
            };
            let wrapped = bh_authz_proto::account_log_wrap(&event.original, event.body).unwrap();
            store
                .stage_attachment(
                    &key.account.0,
                    wrapped.digest(),
                    &Attachment {
                        record: (mode == "replace").then_some(replacement),
                        recovery_seal: new_seal,
                        rotation_body: None,
                    },
                )
                .unwrap();
            if table == "commit" {
                store.with(|db| db.execute_batch("PRAGMA foreign_keys=ON;
                    CREATE TABLE commit_parent(id INTEGER PRIMARY KEY);
                    CREATE TABLE commit_guard(parent INTEGER REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
                    CREATE TRIGGER fail_write AFTER INSERT ON account_applied_bodies BEGIN
                      INSERT INTO commit_guard(parent) VALUES(99);
                    END;" )).unwrap();
            } else {
                store.with(|db| db.execute_batch(&format!(
                    "CREATE TRIGGER fail_write AFTER {operation} ON {table} BEGIN SELECT RAISE(ABORT,'injected'); END;"
                ))).unwrap();
            }
            let confirmations = [(2, proof)];
            let activations = [(2, Some(effect))];
            let applied = [projection::AppliedBody {
                position: 2,
                digest: event.body.unwrap(),
            }];
            assert!(
                store
                    .extend_projected(
                        &key.account.0,
                        &log.id,
                        previous,
                        after,
                        &[StoredEvent {
                            original: event.original.clone(),
                            body: event.body
                        }],
                        ConfirmedPage {
                            confirmations: &confirmations,
                            activations: &activations
                        },
                        &write,
                        &applied
                    )
                    .is_err(),
                "{mode}/{table}"
            );
            drop(store);
            let reopened = Store::open(&dir.path().join("authz.sqlite")).unwrap();
            assert_eq!(
                object_rows(&reopened, key.account),
                before,
                "{mode}/{table}"
            );
            assert!(
                reopened
                    .recovery_by_proof(&old_checks.proof_check)
                    .unwrap()
                    .is_some(),
                "{mode}/{table}"
            );
            assert!(
                reopened
                    .recovery_by_proof(&new_checks.proof_check)
                    .unwrap()
                    .is_none(),
                "{mode}/{table}"
            );
            assert!(
                reopened.tries(&old_checks.digest).unwrap().is_some(),
                "{mode}/{table}"
            );
            let Record::Canonical(current) = reopened.current_projection(key).unwrap().unwrap()
            else {
                panic!()
            };
            assert_eq!(current.checkpoint.head.position, 1, "{mode}/{table}");
            assert_eq!(current.checkpoint.active.len(), 1, "{mode}/{table}");
            let old_page = reopened.account(&key.account.0).unwrap().unwrap();
            assert_eq!(old_page.events.len(), 1, "{mode}/{table}");
            assert!(old_page.confirmations.is_empty(), "{mode}/{table}");
            assert!(
                !reopened
                    .body_applied(current.header.pin, event.body.unwrap())
                    .unwrap(),
                "{mode}/{table}"
            );
            assert!(
                reopened
                    .attachment(&key.account.0, wrapped.digest())
                    .unwrap()
                    .is_some(),
                "{mode}/{table}"
            );
            reopened
                .with(|db| db.execute_batch("DROP TRIGGER fail_write;"))
                .unwrap();
            let committed = reopened
                .extend_projected(
                    &key.account.0,
                    &log.id,
                    previous,
                    after,
                    &[StoredEvent {
                        original: event.original.clone(),
                        body: event.body,
                    }],
                    ConfirmedPage {
                        confirmations: &confirmations,
                        activations: &activations,
                    },
                    &write,
                    &applied,
                )
                .unwrap();
            let Record::Canonical(now) = reopened.current_projection(key).unwrap().unwrap() else {
                panic!()
            };
            assert!(now.header.pin == committed, "{mode}/{table}");
            assert_eq!(now.checkpoint.head.position, 2, "{mode}/{table}");
            assert_eq!(now.checkpoint.active.len(), 2, "{mode}/{table}");
            assert!(
                reopened
                    .body_applied(committed, event.body.unwrap())
                    .unwrap(),
                "{mode}/{table}"
            );
            assert_eq!(
                reopened
                    .account(&key.account.0)
                    .unwrap()
                    .unwrap()
                    .confirmations
                    .len(),
                1,
                "{mode}/{table}"
            );
            assert!(
                reopened
                    .attachment(&key.account.0, wrapped.digest())
                    .unwrap()
                    .is_none(),
                "{mode}/{table}"
            );
            let digests = reopened.recovery_digests(&key.account.0).unwrap().unwrap();
            assert_eq!(
                digests.record,
                if mode == "replace" {
                    new_checks.digest
                } else {
                    old_checks.digest
                },
                "{mode}/{table}"
            );
            assert_eq!(
                digests.seal,
                bh_account::personal::seal_digest(&vec![8; 1300]),
                "{mode}/{table}"
            );
            if mode == "replace" {
                assert!(
                    reopened
                        .recovery_by_proof(&old_checks.proof_check)
                        .unwrap()
                        .is_none(),
                    "{mode}/{table}"
                );
                assert!(
                    reopened
                        .recovery_by_proof(&new_checks.proof_check)
                        .unwrap()
                        .is_some(),
                    "{mode}/{table}"
                );
                assert!(
                    reopened.tries(&old_checks.digest).unwrap().is_none(),
                    "{mode}/{table}"
                );
                assert_ne!(object_rows(&reopened, key.account), before);
            } else {
                assert!(
                    reopened.tries(&old_checks.digest).unwrap().is_some(),
                    "{mode}/{table}"
                );
            }
        }
    }
}

#[test]
fn signed_proof_callback_runs_before_writer_and_opening_cut_cas_refuses() {
    for column in ["opening", "log_hash", "position"] {
        let (dir, store, key, previous, after, write, event, proof) = signed_next();
        let Source::Home(log) = key.source else {
            unreachable!()
        };
        let (other_key, other_genesis, other_opening, other_write) = seed_on();
        let Source::Home(other_log) = other_key.source else {
            unreachable!()
        };
        store
            .extend_projected(
                &other_key.account.0,
                &other_log.id,
                OrderState::EMPTY,
                other_opening,
                &[StoredEvent {
                    original: other_genesis,
                    body: None,
                }],
                ConfirmedPage {
                    confirmations: &[],
                    activations: &[],
                },
                &other_write,
                &[],
            )
            .unwrap();
        let probe = Arc::clone(&store);
        projection::validation_hook(move || {
            assert!(
                probe.db.try_lock().is_ok(),
                "signed proof validation held writer"
            );
            assert!(matches!(
                probe.current_projection(key).unwrap(),
                Some(Record::Canonical(_))
            ));
            probe
                .with(|db| {
                    db.execute(
                        &format!("UPDATE accounts SET {column}=?1 WHERE account=?2"),
                        params![
                            if column == "position" {
                                rusqlite::types::Value::Integer(9)
                            } else if column == "opening" {
                                rusqlite::types::Value::Blob(OrderState::EMPTY.encode().to_vec())
                            } else {
                                rusqlite::types::Value::Blob(vec![9u8; 32])
                            },
                            key.account.0.as_slice()
                        ],
                    )
                })
                .unwrap();
            Ok(())
        });
        let confirmations = [(2, proof)];
        assert!(
            store
                .extend_projected(
                    &key.account.0,
                    &log.id,
                    previous,
                    after,
                    &[event],
                    ConfirmedPage {
                        confirmations: &confirmations,
                        activations: &[]
                    },
                    &write,
                    &[]
                )
                .is_err()
        );
        drop(store);
        let reopened = Store::open(&dir.path().join("authz.sqlite")).unwrap();
        assert_eq!(
            reopened
                .with(|db| db.query_row(
                    "SELECT COUNT(*) FROM account_events WHERE account=?1",
                    [key.account.0.as_slice()],
                    |r| r.get::<_, i64>(0)
                ))
                .unwrap(),
            1
        );
        let Record::Canonical(current) = reopened.current_projection(key).unwrap().unwrap() else {
            panic!()
        };
        assert_eq!(current.checkpoint.head.position, 1);
        let Record::Canonical(other) = reopened.current_projection(other_key).unwrap().unwrap()
        else {
            panic!()
        };
        assert_eq!(other.checkpoint.head, other_write.header.pin.cut);
    }
}

#[test]
fn invalid_signed_proof_is_refused_before_writer_and_without_partial_write() {
    let (dir, store, key, previous, after, write, event, mut proof) = signed_next();
    let Source::Home(log) = key.source else {
        unreachable!()
    };
    proof[0] ^= 0xff;
    let confirmations = [(2, proof)];
    assert!(
        store
            .extend_projected(
                &key.account.0,
                &log.id,
                previous,
                after,
                &[event],
                ConfirmedPage {
                    confirmations: &confirmations,
                    activations: &[]
                },
                &write,
                &[]
            )
            .is_err()
    );
    drop(store);
    let reopened = Store::open(&dir.path().join("authz.sqlite")).unwrap();
    assert_eq!(
        reopened
            .account(&key.account.0)
            .unwrap()
            .unwrap()
            .events
            .len(),
        1
    );
}

#[test]
fn failing_signed_proof_callback_refuses_without_partial_write() {
    let (dir, store, key, previous, after, write, event, proof) = signed_next();
    let Source::Home(log) = key.source else {
        unreachable!()
    };
    let probe = Arc::clone(&store);
    projection::validation_hook(move || {
        assert!(probe.db.try_lock().is_ok());
        Err(rusqlite::Error::InvalidQuery)
    });
    let confirmations = [(2, proof)];
    assert!(matches!(
        store.extend_projected(
            &key.account.0,
            &log.id,
            previous,
            after,
            &[event],
            ConfirmedPage {
                confirmations: &confirmations,
                activations: &[]
            },
            &write,
            &[]
        ),
        Err(ServiceError::Storage)
    ));
    drop(store);
    let reopened = Store::open(&dir.path().join("authz.sqlite")).unwrap();
    assert_eq!(
        reopened
            .account(&key.account.0)
            .unwrap()
            .unwrap()
            .events
            .len(),
        1
    );
    assert_eq!(
        reopened
            .with(
                |db| db.query_row("SELECT COUNT(*) FROM projection_times", [], |r| r
                    .get::<_, i64>(0))
            )
            .unwrap(),
        1
    );
}

#[test]
fn timed_request_cancel_history_uses_real_bounded_suffix_transitions() {
    use bh_account::{ConfirmedTime, REMOVAL_WAIT_MS};
    use bh_sync::{
        evidence::{ConfirmationClaim, OrderingConfirmation, TimeBounds, original_digest},
        permit,
    };
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("authz.sqlite")).unwrap());
    let (key, genesis, mut outer, mut first, owner, _) = seed_on_with_signer();
    let Source::Home(log) = key.source else {
        unreachable!()
    };
    let root = bh_crypto::SigningKey::generate();
    let service = bh_crypto::SigningKey::generate();
    let certificate = permit::certify(&root, service.public());
    first.header.root = root.public();
    store
        .extend_projected(
            &key.account.0,
            &log.id,
            OrderState::EMPTY,
            outer,
            &[StoredEvent {
                original: genesis.clone(),
                body: None,
            }],
            ConfirmedPage {
                confirmations: &[],
                activations: &[],
            },
            &first,
            &[],
        )
        .unwrap();
    let target_control = bh_crypto::SigningKey::generate();
    let target = DevicePublicKeys::new(
        bh_crypto::SigningKey::generate().public(),
        target_control.public(),
        bh_crypto::KemKey::generate().public(),
    )
    .unwrap();
    let target_id = target.id();
    let reused_after_lapse = DevicePublicKeys::new(
        bh_crypto::SigningKey::generate().public(),
        bh_crypto::SigningKey::generate().public(),
        bh_crypto::KemKey::generate().public(),
    )
    .unwrap();
    let owner_id =
        account_projection::restore(first.checkpoint, 1, store.history_index(first.header.pin))
            .unwrap()
            .active_devices()
            .unwrap()
            .next()
            .unwrap()
            .id();
    let mut originals = vec![genesis];
    let mut times = vec![None];
    let mut proofs = vec![None];
    let mut view = {
        let Record::Canonical(stored) = store.current_projection(key).unwrap().unwrap() else {
            panic!()
        };
        store
            .restore_projection(stored, key, root.public(), &originals[0])
            .unwrap()
    };
    let mut previous = outer;
    // Each call is at most one fixed-grid page; the initial add is confirmed
    // before its deadline and every request/cancel pair resolves its obligation.
    for page_number in 0..3 {
        let mut events = Vec::new();
        let mut confirmations = Vec::new();
        let mut snapshots = Vec::new();
        let page_start = previous;
        let count = if page_number < 2 {
            64 - view.head().position % 64
        } else {
            135 - view.head().position
        };
        for _ in 0..count {
            let position = view.head().position + 1;
            let draft = if position == 2 {
                view.add_device(owner_id, target.clone()).unwrap()
            } else if position == 134 {
                view.add_device(target_id, reused_after_lapse.clone())
                    .unwrap()
            } else if position == 135 {
                view.add_device(owner_id, reused_after_lapse.clone())
                    .unwrap()
            } else if position % 2 == 1 {
                view.request_removal(owner_id, target_id).unwrap()
            } else {
                view.cancel_removal(owner_id, position - 1).unwrap()
            };
            let signature = if position == 134 {
                target_control.sign(draft.signing_bytes())
            } else {
                owner.sign(draft.signing_bytes())
            };
            let original = draft.finish(signature).unwrap().as_bytes().to_vec();
            let at = if position == 2 {
                100
            } else if position >= 134 {
                100 + 2 * REMOVAL_WAIT_MS + position
            } else {
                100 + REMOVAL_WAIT_MS + position
            };
            let bounds = TimeBounds {
                earliest_ms: at,
                latest_ms: at,
            };
            let old_head = view.head();
            let (next, outcome) = view
                .applied_batch_timed_with_outcomes(&[(
                    &original,
                    Some(crate::confirm::time(bounds)),
                )])
                .unwrap();
            if position == 134 {
                assert_eq!(outcome, vec![bh_account::ControlOutcome::Lapsed]);
            }
            view = next;
            let wrapper = bh_authz_proto::account_log_wrap(&original, None).unwrap();
            outer =
                CanonicalCommitment::order(BaseId(log.id), outer, wrapper.digest(), Route::Control)
                    .unwrap()
                    .after();
            let proof = OrderingConfirmation::sign(
                &service,
                &certificate,
                ConfirmationClaim {
                    log,
                    original: original_digest(&original),
                    original_previous: crate::confirm::head(old_head),
                    original_head: crate::confirm::head(view.head()),
                    body: None,
                    ordered: outer.head(BaseId(log.id)),
                    bounds,
                },
            )
            .encode()
            .to_vec();
            if position.is_multiple_of(64) {
                snapshots.push(projection::HistoricalSnapshot {
                    checkpoint: account_projection::capture(&view),
                    opening: outer,
                });
            }
            events.push(StoredEvent {
                original: original.clone(),
                body: None,
            });
            confirmations.push((position, proof.clone()));
            originals.push(original);
            proofs.push(Some(proof));
            times.push(Some(ConfirmedTime {
                earliest_ms: at,
                latest_ms: at,
            }));
        }
        let write = ProjectionWrite {
            header: ProjectionHeader {
                pin: Pin {
                    key,
                    generation: 1,
                    cut: view.head(),
                },
                root: root.public(),
                opening: outer,
                prefix: None,
            },
            checkpoint: account_projection::capture(&view),
            delta: account_projection::delta(&view),
            snapshots,
        };
        let pin = store
            .extend_projected(
                &key.account.0,
                &log.id,
                page_start,
                outer,
                &events,
                ConfirmedPage {
                    confirmations: &confirmations,
                    activations: &[],
                },
                &write,
                &[],
            )
            .unwrap();
        view = account_projection::rebase(view, pin.cut, pin.generation, store.history_index(pin))
            .unwrap();
        previous = outer;
    }
    assert_eq!(originals.len(), 135);
    assert_eq!(view.seen_device(reused_after_lapse.id()), Ok(true));
    let pin = Pin {
        key,
        generation: 1,
        cut: view.head(),
    };
    let _ = crate::confirm::take_replay_transitions();
    let _ = take_full_account_read();
    let Record::Canonical(current) = store.current_projection(key).unwrap().unwrap() else {
        panic!()
    };
    let cold = store
        .restore_projection(current, key, root.public(), &originals[0])
        .unwrap();
    assert_eq!(crate::confirm::take_replay_transitions(), 0);
    assert_eq!(
        take_full_account_read(),
        (0, 0),
        "cold restore must not reach full account reads"
    );
    assert_eq!(
        account_projection::capture(&cold).summary,
        account_projection::capture(&view).summary
    );
    for position in [1u64, 3, 63, 64, 65, 127, 128, 131, 132, 133, 134, 135] {
        let snapshot = store.projection_at(pin, position).unwrap();
        let cut = snapshot.header.pin.cut.position;
        let saved_opening = snapshot.header.opening;
        let prior = store
            .restore_projection(snapshot, key, root.public(), &originals[0])
            .unwrap();
        let entries = if cut == position {
            Vec::new()
        } else {
            store.history_range(pin, cut + 1, position).unwrap()
        };
        for entry in &entries {
            assert_eq!(
                entry.confirmation.as_deref(),
                proofs[(entry.position - 1) as usize].as_deref()
            );
        }
        let decoded_bytes: usize = entries
            .iter()
            .map(|entry| {
                entry.event.original.len() + entry.confirmation.as_ref().map_or(0, Vec::len)
            })
            .sum();
        assert!(
            decoded_bytes <= 63 * 8192,
            "only the bounded decoded suffix is staged"
        );
        let (actual, _) =
            crate::confirm::replay_suffix(prior, log, saved_opening, &entries, &root.public())
                .unwrap();
        assert_eq!(
            crate::confirm::take_replay_transitions(),
            (position - cut) as usize
        );
        assert_eq!(
            take_full_account_read(),
            (0, 0),
            "historical restore must not read full account"
        );
        assert!(position - cut <= 63);
        let history: Vec<_> = originals[..position as usize]
            .iter()
            .zip(&times[..position as usize])
            .map(|(o, t)| (o.as_slice(), *t))
            .collect();
        let full = VerifiedAccount::replay_timed(
            key.account,
            &history,
            bh_account::Head {
                position,
                hash: bh_crypto::hash(&originals[position as usize - 1]),
            },
        )
        .unwrap();
        assert_eq!(actual.head(), full.head());
        assert_eq!(
            account_projection::capture(&actual).summary,
            account_projection::capture(&full).summary
        );
        let member = |v: &VerifiedAccount| {
            account_projection::capture(v)
                .active
                .into_iter()
                .map(|r| (r.device, r.keys, r.added))
                .collect::<Vec<_>>()
        };
        assert_eq!(member(&actual), member(&full));
        for at in [
            100,
            100 + REMOVAL_WAIT_MS,
            100 + REMOVAL_WAIT_MS + 200,
            100 + 2 * REMOVAL_WAIT_MS + 133,
        ] {
            assert_eq!(
                actual.device_state(target_id, at),
                full.device_state(target_id, at)
            );
        }
    }
    assert_eq!(
        store.account(&key.account.0).unwrap().unwrap().events.len(),
        135,
        "the retired full read demonstrably loads all rows, unlike a cold checkpoint"
    );
    let (rows, bytes) = take_full_account_read();
    assert_eq!(rows, 135);
    assert!(
        bytes > 135 * 64,
        "actual old full-read bytes, not a synthetic counter"
    );
}

#[test]
fn hosted_recovery_replacement_and_rotation_match_timed_full_replay() {
    use bh_account::recovery::RecoveryKeys;
    use bh_sync::{
        evidence::{ConfirmationClaim, OrderingConfirmation, TimeBounds, original_digest},
        permit,
    };
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("authz.sqlite")).unwrap());
    let (key, genesis, mut outer, mut first, control, ordinary) = seed_on_with_signer();
    let Source::Home(log) = key.source else {
        unreachable!()
    };
    let root = bh_crypto::SigningKey::generate();
    let service = bh_crypto::SigningKey::generate();
    let certificate = permit::certify(&root, service.public());
    first.header.root = root.public();
    store
        .extend_projected(
            &key.account.0,
            &log.id,
            OrderState::EMPTY,
            outer,
            &[StoredEvent {
                original: genesis.clone(),
                body: None,
            }],
            ConfirmedPage {
                confirmations: &[],
                activations: &[],
            },
            &first,
            &[],
        )
        .unwrap();
    let Record::Canonical(current) = store.current_projection(key).unwrap().unwrap() else {
        panic!()
    };
    let mut view = store
        .restore_projection(current, key, root.public(), &genesis)
        .unwrap();
    let author = view.active_devices().unwrap().next().unwrap().id();
    let mut events = Vec::new();
    let mut proofs = Vec::new();
    let mut originals = vec![genesis.clone()];
    let mut times = vec![None];
    let previous = outer;
    let published = bh_crypto::KemKey::generate().public();
    let rotated = bh_crypto::KemKey::generate().public();
    let replacement = RecoveryKeys::generate().public();
    for position in 2..=5 {
        let draft = match position {
            2 => view.prepare_recovery_record(author, [3; 32]).unwrap(),
            3 => view
                .publish_personal_key(author, published, [4; 32], [5; 32])
                .unwrap(),
            4 => view
                .replace_recovery(author, replacement.clone(), [6; 32], [7; 32])
                .unwrap(),
            5 => view
                .rotate_personal(author, 4, rotated, [8; 32], [9; 32])
                .unwrap(),
            _ => unreachable!(),
        };
        let signature = if position == 5 {
            ordinary.sign(draft.signing_bytes())
        } else {
            control.sign(draft.signing_bytes())
        };
        let original = draft.finish(signature).unwrap().as_bytes().to_vec();
        let bounds = TimeBounds {
            earliest_ms: 100 + position,
            latest_ms: 100 + position,
        };
        let old_head = view.head();
        view = view
            .applied_batch_timed(&[(&original, Some(crate::confirm::time(bounds)))])
            .unwrap();
        let wrapped = bh_authz_proto::account_log_wrap(&original, None).unwrap();
        outer = CanonicalCommitment::order(BaseId(log.id), outer, wrapped.digest(), Route::Control)
            .unwrap()
            .after();
        let proof = OrderingConfirmation::sign(
            &service,
            &certificate,
            ConfirmationClaim {
                log,
                original: original_digest(&original),
                original_previous: crate::confirm::head(old_head),
                original_head: crate::confirm::head(view.head()),
                body: None,
                ordered: outer.head(BaseId(log.id)),
                bounds,
            },
        )
        .encode()
        .to_vec();
        originals.push(original.clone());
        times.push(Some(crate::confirm::time(bounds)));
        events.push(StoredEvent {
            original,
            body: None,
        });
        proofs.push((position, proof));
    }
    let write = ProjectionWrite {
        header: ProjectionHeader {
            pin: Pin {
                key,
                generation: 1,
                cut: view.head(),
            },
            root: root.public(),
            opening: outer,
            prefix: None,
        },
        checkpoint: account_projection::capture(&view),
        delta: account_projection::delta(&view),
        snapshots: vec![],
    };
    let pin = store
        .extend_projected(
            &key.account.0,
            &log.id,
            previous,
            outer,
            &events,
            ConfirmedPage {
                confirmations: &proofs,
                activations: &[],
            },
            &write,
            &[],
        )
        .unwrap();
    for position in [3u64, 4, 5] {
        let snapshot = store.projection_at(pin, position).unwrap();
        let cut = snapshot.header.pin.cut.position;
        let opening = snapshot.header.opening;
        let prior = store
            .restore_projection(snapshot, key, root.public(), &genesis)
            .unwrap();
        let entries = store.history_range(pin, cut + 1, position).unwrap();
        for entry in &entries {
            assert_eq!(
                entry.confirmation.as_deref(),
                Some(proofs[(entry.position - 2) as usize].1.as_slice())
            );
        }
        let (actual, _) =
            crate::confirm::replay_suffix(prior, log, opening, &entries, &root.public()).unwrap();
        let history: Vec<_> = originals[..position as usize]
            .iter()
            .zip(&times[..position as usize])
            .map(|(event, time)| (event.as_slice(), *time))
            .collect();
        let full = VerifiedAccount::replay_timed(
            key.account,
            &history,
            bh_account::Head {
                position,
                hash: bh_crypto::hash(&originals[position as usize - 1]),
            },
        )
        .unwrap();
        assert_eq!(actual.head(), full.head());
        assert_eq!(
            account_projection::capture(&actual).summary,
            account_projection::capture(&full).summary
        );
        assert_eq!(actual.record_digest(), full.record_digest());
        assert_eq!(actual.personal_public(), full.personal_public());
        assert_eq!(actual.rotation_due(110), full.rotation_due(110));
    }
}

#[test]
fn local_untimed_prefix_then_timed_replay_matches_incremental_view() {
    let (key, genesis, _, _, signer, _) = seed_on_with_signer();
    let first = VerifiedAccount::from_genesis(key.account, &genesis).unwrap();
    let owner = first.active_devices().unwrap().next().unwrap().id();
    let keys = || {
        DevicePublicKeys::new(
            bh_crypto::SigningKey::generate().public(),
            bh_crypto::SigningKey::generate().public(),
            bh_crypto::KemKey::generate().public(),
        )
        .unwrap()
    };
    let draft = first.add_device(owner, keys()).unwrap();
    let untimed = draft
        .finish(signer.sign(draft.signing_bytes()))
        .unwrap()
        .as_bytes()
        .to_vec();
    let middle = first.applied(&untimed).unwrap();
    let draft = middle.add_device(owner, keys()).unwrap();
    let timed = draft
        .finish(signer.sign(draft.signing_bytes()))
        .unwrap()
        .as_bytes()
        .to_vec();
    let at = bh_account::ConfirmedTime {
        earliest_ms: 101,
        latest_ms: 101,
    };
    let incremental = middle.applied_batch_timed(&[(&timed, Some(at))]).unwrap();
    let full = VerifiedAccount::replay_timed(
        key.account,
        &[
            (genesis.as_slice(), None),
            (untimed.as_slice(), None),
            (timed.as_slice(), Some(at)),
        ],
        incremental.head(),
    )
    .unwrap();
    assert_eq!(
        account_projection::capture(&incremental).summary,
        account_projection::capture(&full).summary
    );
    let members = |view: &VerifiedAccount| {
        account_projection::capture(view)
            .active
            .into_iter()
            .map(|row| (row.device, row.keys, row.added))
            .collect::<Vec<_>>()
    };
    assert_eq!(members(&incremental), members(&full));
    // This is a local library comparison, not permission for canonical HOME
    // to accept an original at position two without its signed confirmation.
}

#[test]
fn timed_full_replay_matches_indexed_snapshot_suffix_and_original_proof_bytes() {
    let (_dir, store, key, previous, after, write, event, proof) = signed_next();
    let Source::Home(log) = key.source else {
        unreachable!()
    };
    let genesis = store.account_event(&key.account.0, 1).unwrap().unwrap();
    let original = event.original.clone();
    let confirmations = [(2, proof.clone())];
    store
        .extend_projected(
            &key.account.0,
            &log.id,
            previous,
            after,
            &[event],
            ConfirmedPage {
                confirmations: &confirmations,
                activations: &[],
            },
            &write,
            &[],
        )
        .unwrap();
    let full = VerifiedAccount::replay_timed(
        key.account,
        &[
            (genesis.as_slice(), None),
            (
                original.as_slice(),
                Some(crate::confirm::time(bh_sync::evidence::TimeBounds {
                    earliest_ms: 100,
                    latest_ms: 100,
                })),
            ),
        ],
        write.header.pin.cut,
    )
    .unwrap();
    let _ = crate::confirm::take_replay_transitions();
    let Record::Canonical(latest) = store.current_projection(key).unwrap().unwrap() else {
        panic!()
    };
    let restored = store
        .restore_projection(latest, key, write.header.root, &genesis)
        .unwrap();
    let snapshot = store.projection_at(write.header.pin, 1).unwrap();
    let old = store
        .restore_projection(snapshot, key, write.header.root, &genesis)
        .unwrap();
    assert_eq!(
        crate::confirm::take_replay_transitions(),
        0,
        "current checkpoint must not replay originals"
    );
    let entries = store.history_range(write.header.pin, 2, 2).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].confirmation.as_deref(), Some(proof.as_slice()));
    let (suffix, outer) =
        crate::confirm::replay_suffix(old, log, previous, &entries, &write.header.root).unwrap();
    assert_eq!(crate::confirm::take_replay_transitions(), 1);
    assert_eq!(outer, after);
    for actual in [&restored, &suffix] {
        assert_eq!(actual.head(), full.head());
        assert_eq!(
            account_projection::capture(actual).summary,
            account_projection::capture(&full).summary
        );
        let rows = |view: &VerifiedAccount| {
            account_projection::capture(view)
                .active
                .into_iter()
                .map(|row| (row.device, row.keys, row.added))
                .collect::<Vec<_>>()
        };
        assert_eq!(rows(actual), rows(&full));
        assert_eq!(actual.record_digest(), full.record_digest());
        assert_eq!(actual.personal_public().err(), full.personal_public().err());
    }
    assert_eq!(
        store.confirmation(&key.account.0, 2).unwrap().as_deref(),
        Some(proof.as_slice())
    );
}

#[test]
fn suffix_replay_requires_full_canonical_order_not_just_a_position() {
    let (_dir, store, key, genesis, outer) = seed();
    let Record::Canonical(stored) = store.current_projection(key).unwrap().unwrap() else {
        panic!()
    };
    let view = store
        .restore_projection(stored, key, [7; 32], &genesis)
        .unwrap();
    let Source::Home(log) = key.source else {
        unreachable!()
    };
    let (view, after) = crate::confirm::replay_suffix(view, log, outer, &[], &[7; 32]).unwrap();
    assert_eq!(view.head().position, 1);
    assert_eq!(after, outer);
    let entry = projection::HistoricalEntry {
        position: 2,
        event: StoredEvent {
            original: genesis,
            body: None,
        },
        confirmation: None,
    };
    assert!(crate::confirm::replay_suffix(view, log, after, &[entry], &[7; 32]).is_err());
}

#[test]
fn projection_validation_finishes_before_writer_and_stale_selection_cannot_commit() {
    let (_dir, store, key, genesis, opening, write) = seed_unwritten();
    let Source::Home(log) = key.source else {
        unreachable!()
    };
    let probe = Arc::clone(&store);
    projection::validation_hook(move || {
        // A validation callback may reenter the Store for a short read. It
        // cannot do so while the SQLite connection's writer mutex is held.
        assert!(
            probe.db.try_lock().is_ok(),
            "validation ran under writer lock"
        );
        assert!(probe.current_projection(key).unwrap().is_none());
        probe
            .with(|db| {
                db.execute(
            "INSERT INTO projection_selected(account,kind,source,generation) VALUES(?1,1,?2,2)",
            params![key.account.0.as_slice(), log.id.as_slice()],
        )
            })
            .unwrap();
        Ok(())
    });
    assert!(
        store
            .extend_projected(
                &key.account.0,
                &log.id,
                OrderState::EMPTY,
                opening,
                &[StoredEvent {
                    original: genesis,
                    body: None
                }],
                ConfirmedPage {
                    confirmations: &[],
                    activations: &[]
                },
                &write,
                &[]
            )
            .is_err()
    );
    assert!(store.account(&key.account.0).unwrap().is_none());
    assert!(
        store
            .with(
                |db| db.query_row("SELECT COUNT(*) FROM projection_times", [], |r| r
                    .get::<_, i64>(0))
            )
            .unwrap()
            == 0
    );
}

#[test]
fn home_projection_transaction_is_atomic() {
    let (_dir, store, key, genesis, opening, mut write) = seed_unwritten();
    let Source::Home(log) = key.source else {
        unreachable!()
    };
    write.delta.expected.0 = 1;
    assert!(
        store
            .extend_projected(
                &key.account.0,
                &log.id,
                OrderState::EMPTY,
                opening,
                &[StoredEvent {
                    original: genesis.clone(),
                    body: None
                }],
                ConfirmedPage {
                    confirmations: &[],
                    activations: &[]
                },
                &write,
                &[]
            )
            .is_err()
    );
    assert!(store.account(&key.account.0).unwrap().is_none());
    assert!(store.current_projection(key).unwrap().is_none());
    write.delta.expected.0 = 0;
    let pin = store
        .extend_projected(
            &key.account.0,
            &log.id,
            OrderState::EMPTY,
            opening,
            &[StoredEvent {
                original: genesis,
                body: None,
            }],
            ConfirmedPage {
                confirmations: &[],
                activations: &[],
            },
            &write,
            &[],
        )
        .unwrap();
    assert_eq!(pin.cut.position, 1);
    assert!(matches!(
        store.current_projection(key).unwrap(),
        Some(Record::Canonical(_))
    ));
}

#[test]
fn projection_restore_checks_source_root_cut_and_opening() {
    let (_dir, store, key, genesis, opening) = seed();
    let Record::Canonical(stored) = store.current_projection(key).unwrap().unwrap() else {
        panic!("new canonical source must be selected")
    };
    assert_eq!(
        store
            .restore_projection(stored, key, [7; 32], &genesis)
            .unwrap()
            .head()
            .position,
        1
    );
    let Record::Canonical(stored) = store.current_projection(key).unwrap().unwrap() else {
        panic!()
    };
    assert!(
        store
            .restore_projection(stored, key, [8; 32], &genesis)
            .is_err()
    );
    let Record::Canonical(mut stored) = store.current_projection(key).unwrap().unwrap() else {
        panic!()
    };
    stored.header.opening = OrderState::EMPTY;
    assert!(
        store
            .restore_projection(stored, key, [7; 32], &genesis)
            .is_err()
    );
    let Record::Canonical(mut stored) = store.current_projection(key).unwrap().unwrap() else {
        panic!()
    };
    stored.header.pin.cut.hash = [9; 32];
    assert!(
        store
            .restore_projection(stored, key, [7; 32], &genesis)
            .is_err()
    );
    let Record::Canonical(mut stored) = store.current_projection(key).unwrap().unwrap() else {
        panic!()
    };
    stored.header.pin.generation = 2;
    assert!(
        store
            .restore_projection(stored, key, [7; 32], &genesis)
            .is_err()
    );
    assert_ne!(opening, OrderState::EMPTY);
}

#[test]
fn projection_restore_rejects_forged_outer_opening_even_if_metadata_agrees() {
    let (_dir, store, key, genesis, _) = seed();
    let Source::Home(log) = key.source else {
        unreachable!()
    };
    let fake = OrderState::new(
        bh_sync::RawControlHead {
            position: 1,
            node_hash: Digest([3; 32]),
        },
        0,
        Digest([0; 32]),
    )
    .unwrap();
    store
        .with(|db| {
            db.execute(
                "UPDATE projection_current SET opening=?1 WHERE account=?2",
                params![fake.encode().as_slice(), key.account.0.as_slice()],
            )?;
            db.execute(
                "UPDATE accounts SET opening=?1,log_hash=?2 WHERE account=?3",
                params![
                    fake.encode().as_slice(),
                    fake.head(BaseId(log.id)).hash.0.as_slice(),
                    key.account.0.as_slice()
                ],
            )?;
            Ok(())
        })
        .unwrap();
    let Record::Canonical(stored) = store.current_projection(key).unwrap().unwrap() else {
        panic!()
    };
    assert!(
        store
            .restore_projection(stored, key, [7; 32], &genesis)
            .is_err()
    );
}

#[test]
fn known_untimed_genesis_is_none_but_missing_time_is_unavailable() {
    let (_dir, store, key, _, _) = seed();
    let Record::Canonical(stored) = store.current_projection(key).unwrap().unwrap() else {
        panic!()
    };
    let pin = stored.header.pin;
    let index = store.history_index(pin);
    assert_eq!(index.confirmed_time(pin.cut, 1).unwrap(), None);
    store
        .with(|db| {
            db.execute(
                "DELETE FROM projection_times WHERE account=?1 AND position=1",
                [key.account.0.as_slice()],
            )
        })
        .unwrap();
    assert!(matches!(
        index.confirmed_time(pin.cut, 1),
        Err(bh_account::Error::Unavailable)
    ));
}

#[test]
fn home_source_isolation_across_sixteen_partitions() {
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("authz.sqlite")).unwrap());
    let mut sources = Vec::new();
    for _ in 0..16 {
        let (key, genesis, opening, write) = seed_on();
        let Source::Home(log) = key.source else {
            unreachable!()
        };
        store
            .extend_projected(
                &key.account.0,
                &log.id,
                OrderState::EMPTY,
                opening,
                &[StoredEvent {
                    original: genesis.clone(),
                    body: None,
                }],
                ConfirmedPage {
                    confirmations: &[],
                    activations: &[],
                },
                &write,
                &[],
            )
            .unwrap();
        sources.push((key, genesis));
    }
    for (key, genesis) in &sources {
        projection::begin_work();
        let Record::Canonical(stored) = store.current_projection(*key).unwrap().unwrap() else {
            panic!()
        };
        let view = store
            .restore_projection(stored, *key, [7; 32], genesis)
            .unwrap();
        assert_eq!(view.head().position, 1);
        let work = projection::end_work();
        assert!(!work.sources.is_empty());
        assert!(work.sources.iter().all(|observed| observed == key));
        assert_eq!((work.transitions, work.decoded_rows), (0, 0));
        let Source::Home(log) = key.source else {
            unreachable!()
        };
        assert_eq!(store.with(|db| db.query_row("SELECT COUNT(*) FROM projection_sources WHERE account=?1 AND kind=1 AND source=?2",
            params![key.account.0.as_slice(),log.id.as_slice()],|r|r.get::<_,i64>(0))).unwrap(),1);
    }
    // 1 exact source and 1 selected generation per operation, independent
    // of the other 15; 1000 members need the same indexed seeks, not 1000 scans.
}

#[test]
fn projection_queries_seek_without_full_scans() {
    use rusqlite::{params_from_iter, types::Value};
    let (_dir, store, key, _, _) = seed();
    let Source::Home(log) = key.source else {
        unreachable!()
    };
    let prefix = vec![
        Value::Blob(key.account.0.to_vec()),
        Value::Integer(1),
        Value::Blob(log.id.to_vec()),
        Value::Integer(1),
    ];
    let plans = [
        (
            "SELECT bytes FROM account_events WHERE account=?1 AND position=?2",
            vec![prefix[0].clone(), Value::Integer(1)],
        ),
        (
            "SELECT position FROM projection_snapshots WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4 AND position<=?5 ORDER BY position DESC LIMIT 1",
            {
                let mut p = prefix.clone();
                p.push(Value::Integer(1));
                p
            },
        ),
        (
            "SELECT device,keys,added FROM projection_snapshot_devices WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4 AND position=?5 ORDER BY device",
            {
                let mut p = prefix.clone();
                p.push(Value::Integer(1));
                p
            },
        ),
        (
            "SELECT device,keys,added FROM projection_active WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4 ORDER BY device",
            prefix.clone(),
        ),
        (
            "SELECT first_position FROM projection_devices WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4 AND device=?5 AND first_position<=?6",
            {
                let mut p = prefix.clone();
                p.extend([Value::Blob([8; 32].to_vec()), Value::Integer(1)]);
                p
            },
        ),
        (
            "SELECT first_position FROM projection_keys WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4 AND key_kind=?5 AND key_hash=?6 AND first_position<=?7",
            {
                let mut p = prefix.clone();
                p.extend([
                    Value::Integer(0),
                    Value::Blob([8; 32].to_vec()),
                    Value::Integer(1),
                ]);
                p
            },
        ),
        (
            "SELECT earliest,latest FROM projection_times WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4 AND position=?5",
            {
                let mut p = prefix.clone();
                p.push(Value::Integer(1));
                p
            },
        ),
        (
            "SELECT position FROM account_applied_bodies WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4 AND digest=?5 AND position<=?6",
            {
                let mut p = prefix.clone();
                p.extend([Value::Blob([8; 32].to_vec()), Value::Integer(1)]);
                p
            },
        ),
    ];
    store
        .with(|db| {
            for (sql, values) in &plans {
                let mut statement = db.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))?;
                let details: Vec<String> = statement
                    .query_map(params_from_iter(values.iter()), |r| r.get(3))?
                    .collect::<Result<_, _>>()?;
                assert!(
                    details.iter().any(|detail| detail.contains("SEARCH ")),
                    "{sql}: {details:?}"
                );
                assert!(
                    !details
                        .iter()
                        .any(|detail| detail.contains("SCAN ") || detail.contains("TEMP B-TREE")),
                    "{sql}: {details:?}"
                );
            }
            Ok(())
        })
        .unwrap();
}

#[test]
fn equal_heads_do_not_alias_sources() {
    let (_dir, store, key, genesis, _) = seed();
    let other = SourceKey {
        source: Source::Base(BaseId(key.account.0)),
        ..key
    };
    assert!(store.current_projection(other).unwrap().is_none());
    let wrong_log_kind = SourceKey {
        source: Source::Home(bh_authz_proto::LogId {
            kind: bh_authz_proto::LogKind::Base,
            id: match key.source {
                Source::Home(log) => log.id,
                _ => unreachable!(),
            },
        }),
        ..key
    };
    assert!(store.current_projection(wrong_log_kind).unwrap().is_none());
    let Record::Canonical(stored) = store.current_projection(key).unwrap().unwrap() else {
        panic!()
    };
    assert!(
        store
            .restore_projection(stored, other, [7; 32], &genesis)
            .is_err()
    );
}

#[test]
fn index_failure_is_unavailable_not_absent() {
    let (_dir, store, key, _, _) = seed();
    let Record::Canonical(stored) = store.current_projection(key).unwrap().unwrap() else {
        panic!()
    };
    let index = store.history_index(stored.header.pin);
    let cut = stored.header.pin.cut;
    assert!(!index.device_seen(cut, &DeviceId([8; 32])).unwrap());
    // A superseded selection must remain queryable. Removing the actual
    // source generation, unlike changing selection, destroys index evidence.
    store
        .with(|db| {
            db.execute(
                "DELETE FROM projection_sources WHERE account=?1",
                [key.account.0.as_slice()],
            )
        })
        .unwrap();
    assert!(matches!(
        index.device_seen(cut, &DeviceId([8; 32])),
        Err(bh_account::Error::Unavailable)
    ));
}
