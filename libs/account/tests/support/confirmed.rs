use super::*;
use bh_account::{ConfirmedTime, DeviceId, RequestState, VerifiedAccount};

const WAIT: u64 = 259_200_000;
fn evidence(at: u64, proof: &[u8]) -> Option<(ConfirmedTime, Vec<u8>)> {
    Some((
        ConfirmedTime {
            earliest_ms: at,
            latest_ms: at + 2,
        },
        proof.to_vec(),
    ))
}

// Two confirmed additions ensure the second needs indexed time evidence rather
// than the timeline's legacy/first-confirmation fallback.
fn confirmed_changes(owner: &mut Owner, cap: &AccountCapability) -> (DeviceId, Head) {
    for (seed, at, proof) in [
        (70, 10, b"first proof".as_slice()),
        (80, 20, b"second proof".as_slice()),
    ] {
        let request = owner.prepare_add_device(cap, test_keys(seed)).unwrap();
        let event = ready(owner.sign_control(cap, &request)).unwrap();
        owner
            .apply_incoming_timed(&[(event.as_bytes(), evidence(at, proof))])
            .unwrap();
    }
    let target = test_keys(80).id();
    let author = cap.device_id();
    let request = owner
        .verified(cap)
        .unwrap()
        .request_removal(author, target)
        .unwrap();
    let event = ready(owner.sign_control(cap, &request)).unwrap();
    let head = owner
        .apply_incoming_timed(&[(event.as_bytes(), evidence(30, b"removal proof"))])
        .unwrap();
    (target, head)
}
fn check_deadline(view: &VerifiedAccount, target: DeviceId) {
    assert_eq!(view.added_at(target), Some(22));
    assert!(!view.is_mature(target, WAIT + 21));
    // Maturity at the addition boundary precedes the removal deadline.
    assert!(view.is_mature(target, WAIT + 22));
    assert_eq!(
        view.request_state(6, WAIT + 31),
        Ok(RequestState::Pending {
            deadline_ms: WAIT + 32
        })
    );
    assert_eq!(
        view.request_state(6, WAIT + 32),
        Ok(RequestState::Effective)
    );
}

#[test]
fn verified_alerts_survive_reopen_and_deadline_without_a_successor() {
    use bh_storage::AlertKind;
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let (target, _) = confirmed_changes(&mut owner, &cap);
    let db = bh_storage::DeviceDatabase::open(&h.path).unwrap();
    let alerts = db.alerts(10).unwrap();
    assert_eq!(alerts.len(), 3);
    assert_eq!(alerts[0].kind, AlertKind::RemovalRequested);
    assert_eq!(alerts[0].position, Some(6));
    assert_eq!(alerts[0].subject, Some(target.0));
    assert_eq!(alerts[0].deadline_ms, Some(WAIT + 32));
    assert_eq!(alerts[1].kind, AlertKind::DeviceAddedByQr);
    assert_eq!(alerts[2].kind, AlertKind::DeviceAddedByQr);
    assert_eq!(db.alert_cursor().unwrap(), 6);
    drop(db);
    drop(owner);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    owner
        .observe_accepted_alerts(
            &cap,
            owner.verified(&cap).unwrap().head(),
            ConfirmedTime {
                earliest_ms: WAIT + 31,
                latest_ms: WAIT + 31,
            },
        )
        .unwrap();
    assert_eq!(
        bh_storage::DeviceDatabase::open(&h.path)
            .unwrap()
            .alerts(10)
            .unwrap()
            .len(),
        3
    );
    owner
        .observe_accepted_alerts(
            &cap,
            owner.verified(&cap).unwrap().head(),
            ConfirmedTime {
                earliest_ms: WAIT + 32,
                latest_ms: WAIT + 32,
            },
        )
        .unwrap();
    let db = bh_storage::DeviceDatabase::open(&h.path).unwrap();
    assert_eq!(db.alerts(10).unwrap().len(), 4);
    assert_eq!(db.alerts(1).unwrap()[0].kind, AlertKind::RemovalEffective);
    assert_eq!(db.alerts(1).unwrap()[0].position, Some(6));
    drop(db);
    drop(owner);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    owner
        .observe_accepted_alerts(
            &cap,
            owner.verified(&cap).unwrap().head(),
            ConfirmedTime {
                earliest_ms: WAIT + 33,
                latest_ms: WAIT + 33,
            },
        )
        .unwrap();
    assert_eq!(
        bh_storage::DeviceDatabase::open(&h.path)
            .unwrap()
            .alerts(10)
            .unwrap()
            .len(),
        4
    );
}

#[test]
fn target_persists_requested_and_cancelled_alerts_with_confirmed_deadline() {
    use bh_account::{
        DevicePublicKeys,
        crypto::{KemKey, SigningKey},
    };
    use bh_storage::AlertKind;
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let control = SigningKey::generate();
    let fold = DevicePublicKeys::new(
        SigningKey::generate().public(),
        control.public(),
        KemKey::generate().public(),
    )
    .unwrap();
    let add = owner.prepare_add_device(&cap, fold.clone()).unwrap();
    let add = ready(owner.sign_control(&cap, &add)).unwrap();
    owner
        .apply_incoming_timed(&[(add.as_bytes(), evidence(10, b"added"))])
        .unwrap();
    let request = owner
        .verified(&cap)
        .unwrap()
        .request_removal(fold.id(), cap.device_id())
        .unwrap();
    let request = request
        .finish(control.sign(request.signing_bytes()))
        .unwrap();
    owner
        .apply_incoming_timed(&[(request.as_bytes(), evidence(20, b"request"))])
        .unwrap();
    let alerts = bh_storage::DeviceDatabase::open(&h.path)
        .unwrap()
        .alerts(1)
        .unwrap();
    assert_eq!(alerts[0].kind, AlertKind::RemovalRequested);
    assert_eq!(alerts[0].subject, Some(cap.device_id().0));
    assert_eq!(alerts[0].actor, Some(fold.id().0));
    assert_eq!(alerts[0].deadline_ms, Some(WAIT + 22));
    let cancel = owner
        .verified(&cap)
        .unwrap()
        .cancel_removal(fold.id(), request.head().position)
        .unwrap();
    let cancel = cancel.finish(control.sign(cancel.signing_bytes())).unwrap();
    owner
        .apply_incoming_timed(&[(cancel.as_bytes(), evidence(WAIT + 13, b"cancel"))])
        .unwrap();
    let alerts = bh_storage::DeviceDatabase::open(&h.path)
        .unwrap()
        .alerts(1)
        .unwrap();
    assert_eq!(alerts[0].kind, AlertKind::RemovalCancelled);
    assert_eq!(alerts[0].subject, Some(cap.device_id().0));
    assert_eq!(alerts[0].actor, Some(fold.id().0));
    drop(owner);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    assert_eq!(
        owner
            .verified(&cap)
            .unwrap()
            .request_state(request.head().position, WAIT + 30),
        Ok(RequestState::Resolved)
    );
    assert_eq!(
        bh_storage::DeviceDatabase::open(&h.path)
            .unwrap()
            .alerts(10)
            .unwrap()
            .iter()
            .filter(|a| matches!(
                a.kind,
                AlertKind::RemovalRequested | AlertKind::RemovalCancelled
            ))
            .count(),
        2
    );
}

#[test]
fn deadline_observation_binds_later_history_and_survives_restart() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    confirmed_changes(&mut owner, &cap);
    let head = owner.verified(&cap).unwrap().head();
    let floor = WAIT + 32;
    owner
        .observe_accepted_alerts(
            &cap,
            head,
            ConfirmedTime {
                earliest_ms: floor,
                latest_ms: floor + 4,
            },
        )
        .unwrap();
    owner
        .observe_accepted_alerts(
            &cap,
            head,
            ConfirmedTime {
                earliest_ms: floor - 1,
                latest_ms: floor + 4,
            },
        )
        .unwrap();
    assert_eq!(
        bh_storage::DeviceDatabase::open(&h.path)
            .unwrap()
            .observed_account_floor()
            .unwrap(),
        Some(floor)
    );
    drop(owner);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let late = owner
        .verified(&cap)
        .unwrap()
        .cancel_removal(cap.device_id(), 6)
        .unwrap();
    let late = ready(owner.sign_control(&cap, &late)).unwrap();
    assert!(matches!(
        owner.apply_incoming_timed(&[(
            late.as_bytes(),
            evidence(floor - 1, b"contradictory confirmation")
        )]),
        Err(OwnerError::Invalid(bh_account::Error::TimeRegressed))
    ));
    assert_eq!(h.stored().head, head);
    assert!(h.stored().stopped);
    assert_eq!(
        bh_storage::DeviceDatabase::open(&h.path)
            .unwrap()
            .alerts(1)
            .unwrap()[0]
            .kind,
        bh_storage::AlertKind::RemovalEffective
    );
    assert_eq!(
        bh_storage::DeviceDatabase::open(&h.path)
            .unwrap()
            .observed_account_floor()
            .unwrap(),
        Some(floor)
    );
}

#[test]
fn deleted_projection_repair_cannot_forget_observed_deadline() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    confirmed_changes(&mut owner, &cap);
    let head = owner.verified(&cap).unwrap().head();
    owner
        .observe_accepted_alerts(
            &cap,
            head,
            ConfirmedTime {
                earliest_ms: WAIT + 32,
                latest_ms: WAIT + 32,
            },
        )
        .unwrap();
    drop(owner);
    h.raw()
        .execute("DELETE FROM account_projection", [])
        .unwrap();
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let cancel = owner
        .verified(&cap)
        .unwrap()
        .cancel_removal(cap.device_id(), 6)
        .unwrap();
    let cancel = ready(owner.sign_control(&cap, &cancel)).unwrap();
    assert!(matches!(
        owner.apply_incoming_timed(&[(
            cancel.as_bytes(),
            evidence(WAIT + 31, b"backdated after repair")
        )]),
        Err(OwnerError::Invalid(bh_account::Error::TimeRegressed))
    ));
    assert_eq!(h.stored().head, head);
    let db = bh_storage::DeviceDatabase::open(&h.path).unwrap();
    assert_eq!(
        db.alerts(1).unwrap()[0].kind,
        bh_storage::AlertKind::RemovalEffective
    );
    assert_eq!(db.observed_account_floor().unwrap(), Some(WAIT + 32));
}

#[test]
fn stale_owner_cannot_append_below_another_owners_observed_floor() {
    let h = Harness::new();
    complete(&h);
    let mut stale = h.owner();
    let cap = activate(&mut stale);
    confirmed_changes(&mut stale, &cap);
    let head = stale.verified(&cap).unwrap().head();
    let cancel = stale
        .verified(&cap)
        .unwrap()
        .cancel_removal(cap.device_id(), 6)
        .unwrap();
    let cancel = ready(stale.sign_control(&cap, &cancel)).unwrap();
    let mut observer = h.owner();
    let other_cap = activate(&mut observer);
    observer
        .observe_accepted_alerts(
            &other_cap,
            head,
            ConfirmedTime {
                earliest_ms: WAIT + 32,
                latest_ms: WAIT + 32,
            },
        )
        .unwrap();
    assert!(matches!(
        stale.apply_incoming_timed(&[(cancel.as_bytes(), evidence(WAIT + 31, b"stale owner"))]),
        Err(OwnerError::Invalid(bh_account::Error::TimeRegressed))
    ));
    assert_eq!(h.stored().head, head);
    assert!(h.stored().stopped);
    let db = bh_storage::DeviceDatabase::open(&h.path).unwrap();
    assert_eq!(
        db.alerts(1).unwrap()[0].kind,
        bh_storage::AlertKind::RemovalEffective
    );
    assert_eq!(db.observed_account_floor().unwrap(), Some(WAIT + 32));
}

#[test]
fn observed_legacy_missing_proof_is_retryable_on_same_owner() {
    legacy_missing_proof_is_retryable(false);
}

#[test]
fn stale_legacy_missing_proof_is_retryable_at_transaction_guard() {
    legacy_missing_proof_is_retryable(true);
}

fn legacy_missing_proof_is_retryable(stale: bool) {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let head = owner.verified(&cap).unwrap().head();
    assert_eq!(head.position, 3);
    let request = owner.prepare_add_device(&cap, test_keys(92)).unwrap();
    let event = ready(owner.sign_control(&cap, &request)).unwrap();
    let time = ConfirmedTime {
        earliest_ms: 100,
        latest_ms: 102,
    };
    if stale {
        let mut observer = h.owner();
        let other_cap = activate(&mut observer);
        observer
            .observe_accepted_alerts(&other_cap, head, time)
            .unwrap();
        // This owner's shared verifier has not learned the observation: only
        // the canonical SQLite append guard can refuse the missing evidence.
        owner
            .verified(&cap)
            .unwrap()
            .clone()
            .apply_timed(event.as_bytes(), None)
            .unwrap();
    } else {
        owner.observe_accepted_alerts(&cap, head, time).unwrap();
    }
    let db = bh_storage::DeviceDatabase::open(&h.path).unwrap();
    let cursor = db.alert_cursor().unwrap();
    assert!(db.alerts(10).unwrap().is_empty());
    let generation = h.generation.current();
    assert!(matches!(
        owner.apply_incoming(&[event.as_bytes()]),
        Err(OwnerError::Refused(bh_account::Error::MissingTime))
    ));
    assert!(!h.stored().stopped);
    assert_eq!(h.stored().head, head);
    assert_eq!(owner.verified(&cap).unwrap().head(), head);
    assert_eq!(h.generation.current(), generation);
    assert!(db.alerts(10).unwrap().is_empty());
    assert_eq!(db.alert_cursor().unwrap(), cursor);
    assert_eq!(db.observed_account_floor().unwrap(), Some(100));
    assert!(db.confirmation(4).unwrap().is_none());
    if !stale {
        // Storage's guard is not a substitute for shared timeline validation.
        assert_eq!(
            owner
                .verified(&cap)
                .unwrap()
                .clone()
                .apply_timed(event.as_bytes(), None),
            Err(bh_account::Error::MissingTime)
        );
    }
    assert_eq!(
        owner
            .apply_incoming_timed(&[(event.as_bytes(), evidence(100, b"verified add"))])
            .unwrap(),
        event.head()
    );
    assert_eq!(owner.verified(&cap).unwrap().head(), event.head());
    assert_eq!(h.generation.current(), generation);
    assert!(!h.stored().stopped);
    assert_eq!(h.stored().head, event.head());
    assert_eq!(db.alert_cursor().unwrap(), 4);
    assert_eq!(db.alerts(10).unwrap().len(), 1);
    assert_eq!(
        db.alerts(1).unwrap()[0].kind,
        bh_storage::AlertKind::DeviceAddedByQr
    );
    assert_eq!(db.confirmation(4).unwrap().unwrap().bytes, b"verified add");
    drop(owner);
    // Rebuilding the untimed accepted prefix still precedes floor installation.
    h.raw()
        .execute("DELETE FROM account_projection", [])
        .unwrap();
    let mut reopened = h.owner();
    let cap = activate(&mut reopened);
    assert_eq!(reopened.verified(&cap).unwrap().head(), event.head());
    assert_eq!(db.observed_account_floor().unwrap(), Some(100));
}

#[test]
fn failed_deadline_alert_does_not_advance_the_observation_floor() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    confirmed_changes(&mut owner, &cap);
    h.raw().execute_batch("CREATE TRIGGER fail_observed_alert BEFORE INSERT ON security_alerts WHEN NEW.kind=6 BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    let head = owner.verified(&cap).unwrap().head();
    assert!(matches!(
        owner.observe_accepted_alerts(
            &cap,
            head,
            ConfirmedTime {
                earliest_ms: WAIT + 32,
                latest_ms: WAIT + 32
            }
        ),
        Err(OwnerError::Journal(_))
    ));
    let db = bh_storage::DeviceDatabase::open(&h.path).unwrap();
    assert_eq!(db.observed_account_floor().unwrap(), None);
    assert_eq!(db.alert_cursor().unwrap(), 6);
    assert_eq!(db.alerts(10).unwrap().len(), 3);
}

#[test]
fn unauthenticated_regressing_entry_does_not_stop_account() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    confirmed_changes(&mut owner, &cap);
    let head = owner.verified(&cap).unwrap().head();
    owner
        .observe_accepted_alerts(
            &cap,
            head,
            ConfirmedTime {
                earliest_ms: WAIT + 32,
                latest_ms: WAIT + 32,
            },
        )
        .unwrap();
    let request = owner.prepare_add_device(&cap, test_keys(92)).unwrap();
    let event = ready(owner.sign_control(&cap, &request)).unwrap();
    let mut forged = event.as_bytes().to_vec();
    *forged.last_mut().unwrap() ^= 1;
    assert!(matches!(
        owner.apply_incoming_timed(&[(&forged, evidence(WAIT + 31, b"invalid entry"))]),
        Err(OwnerError::Refused(bh_account::Error::BadSignature))
    ));
    assert!(matches!(
        owner.apply_incoming_timed(&[(
            event.as_bytes(),
            Some((
                ConfirmedTime {
                    earliest_ms: WAIT + 31,
                    latest_ms: WAIT + 30,
                },
                b"malformed bounds".to_vec(),
            ))
        )]),
        Err(OwnerError::Refused(bh_account::Error::Malformed))
    ));
    assert!(matches!(
        owner.apply_incoming_timed(&[(
            b"malformed original",
            evidence(WAIT + 31, b"invalid entry")
        )]),
        Err(OwnerError::Refused(bh_account::Error::Malformed))
    ));
    assert!(!h.stored().stopped);
    assert_eq!(h.stored().head, head);
    assert_eq!(owner.verified(&cap).unwrap().head(), head);
}

#[test]
fn non_regressing_event_after_observation_applies_and_floor_never_lowers() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    confirmed_changes(&mut owner, &cap);
    let head = owner.verified(&cap).unwrap().head();
    owner
        .observe_accepted_alerts(
            &cap,
            head,
            ConfirmedTime {
                earliest_ms: WAIT + 40,
                latest_ms: WAIT + 43,
            },
        )
        .unwrap();
    owner
        .observe_accepted_alerts(
            &cap,
            head,
            ConfirmedTime {
                earliest_ms: WAIT + 32,
                latest_ms: WAIT + 32,
            },
        )
        .unwrap();
    assert_eq!(
        bh_storage::DeviceDatabase::open(&h.path)
            .unwrap()
            .observed_account_floor()
            .unwrap(),
        Some(WAIT + 40)
    );
    drop(owner);
    bh_storage::DeviceDatabase::open(&h.path)
        .unwrap()
        .reset_account_projection(h.stored().anchor.0)
        .unwrap();
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let request = owner.prepare_add_device(&cap, test_keys(91)).unwrap();
    let added = ready(owner.sign_control(&cap, &request)).unwrap();
    owner
        .apply_incoming_timed(&[(added.as_bytes(), evidence(WAIT + 43, b"later"))])
        .unwrap();
    assert_eq!(h.stored().head.position, 7);
    assert_eq!(
        bh_storage::DeviceDatabase::open(&h.path)
            .unwrap()
            .observed_account_floor()
            .unwrap(),
        Some(WAIT + 40)
    );
}

#[test]
fn cancel_only_alerts_when_pending_became_cancelled_and_immediate_removal_is_effective() {
    use bh_account::{REMOVAL_WAIT_MS as W, RequestState, recovery::RecoveryKeys};
    use bh_storage::AlertKind;
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let (target, _) = confirmed_changes(&mut owner, &cap);
    // Untimed signup matures at the first confirmation's upper bound (12).
    let cancel = owner
        .verified(&cap)
        .unwrap()
        .cancel_removal(cap.device_id(), 6)
        .unwrap();
    let cancel = ready(owner.sign_control(&cap, &cancel)).unwrap();
    owner
        .apply_incoming_timed(&[(cancel.as_bytes(), evidence(W + 13, b"cancel"))])
        .unwrap();
    let db = bh_storage::DeviceDatabase::open(&h.path).unwrap();
    assert_eq!(db.alerts(1).unwrap()[0].kind, AlertKind::RemovalCancelled);
    assert_eq!(db.alerts(1).unwrap()[0].subject, Some(target.0));
    drop(db);
    assert_eq!(
        owner.verified(&cap).unwrap().request_state(6, W + 50),
        Ok(RequestState::Cancelled)
    );
    // A valid cancel of a resolved request is a no-op and not a success alert.
    let no_op = owner
        .verified(&cap)
        .unwrap()
        .cancel_removal(cap.device_id(), 6)
        .unwrap();
    let no_op = ready(owner.sign_control(&cap, &no_op)).unwrap();
    owner
        .apply_incoming_timed(&[(no_op.as_bytes(), evidence(W + 14, b"no-op"))])
        .unwrap();
    assert_eq!(
        bh_storage::DeviceDatabase::open(&h.path)
            .unwrap()
            .alerts(10)
            .unwrap()
            .len(),
        4
    );
    let next = RecoveryKeys::generate();
    let kit = owner
        .verified(&cap)
        .unwrap()
        .replace_recovery(cap.device_id(), next.public(), [101; 32], [102; 32])
        .unwrap();
    let kit = ready(owner.sign_control(&cap, &kit)).unwrap();
    owner
        .apply_incoming_timed(&[(kit.as_bytes(), evidence(W + 15, b"kit"))])
        .unwrap();
    let alerts = bh_storage::DeviceDatabase::open(&h.path)
        .unwrap()
        .alerts(1)
        .unwrap();
    assert_eq!(alerts[0].kind, AlertKind::KitChanged);
    drop(owner);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    assert_eq!(
        bh_storage::DeviceDatabase::open(&h.path)
            .unwrap()
            .alerts(10)
            .unwrap()
            .len(),
        5
    );
    // The original request was cancelled: no deadline alert on observation.
    let head = owner.verified(&cap).unwrap().head();
    owner
        .observe_accepted_alerts(
            &cap,
            head,
            ConfirmedTime {
                earliest_ms: W + 33,
                latest_ms: W + 33,
            },
        )
        .unwrap();
    assert_eq!(
        bh_storage::DeviceDatabase::open(&h.path)
            .unwrap()
            .alerts(10)
            .unwrap()
            .len(),
        5
    );
}

#[test]
fn late_cancel_is_no_effect_and_deadline_alert_is_not_repeated() {
    use bh_storage::AlertKind;
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    confirmed_changes(&mut owner, &cap);
    let cancel = owner
        .verified(&cap)
        .unwrap()
        .cancel_removal(cap.device_id(), 6)
        .unwrap();
    let cancel = ready(owner.sign_control(&cap, &cancel)).unwrap();
    owner
        .apply_incoming_timed(&[(cancel.as_bytes(), evidence(WAIT + 32, b"late"))])
        .unwrap();
    let alerts = bh_storage::DeviceDatabase::open(&h.path)
        .unwrap()
        .alerts(10)
        .unwrap();
    assert_eq!(alerts.len(), 4);
    assert_eq!(alerts[0].kind, AlertKind::RemovalEffective);
    assert!(!alerts.iter().any(|a| a.kind == AlertKind::RemovalCancelled));
}

#[test]
fn failed_account_commit_has_no_alert_or_cursor() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let before_cursor = bh_storage::DeviceDatabase::open(&h.path)
        .unwrap()
        .alert_cursor()
        .unwrap();
    let request = owner.prepare_add_device(&cap, test_keys(90)).unwrap();
    let event = ready(owner.sign_control(&cap, &request)).unwrap();
    h.raw().execute_batch("CREATE TRIGGER fail_alert_commit BEFORE INSERT ON security_alerts BEGIN SELECT RAISE(ABORT,'injected'); END;").unwrap();
    assert!(
        owner
            .apply_incoming_timed(&[(event.as_bytes(), evidence(10, b"proof"))])
            .is_err()
    );
    assert_eq!(h.stored().head.position, 3);
    let db = bh_storage::DeviceDatabase::open(&h.path).unwrap();
    assert_eq!(db.alert_cursor().unwrap(), before_cursor);
    assert!(db.alerts(10).unwrap().is_empty());
}

#[test]
fn confirmed_history_survives_reopen_with_its_confirmations() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let (target, head) = confirmed_changes(&mut owner, &cap);
    check_deadline(owner.verified(&cap).unwrap(), target);
    drop(owner);
    let db = bh_storage::DeviceDatabase::open(&h.path).unwrap();
    for (position, at, proof) in [
        (4, 10, b"first proof".as_slice()),
        (5, 20, b"second proof".as_slice()),
        (6, 30, b"removal proof".as_slice()),
    ] {
        let row = db.confirmation(position).unwrap().unwrap();
        assert_eq!(
            (row.earliest_ms, row.latest_ms, row.bytes),
            (at, at + 2, proof.to_vec())
        );
    }
    drop(db);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    assert_eq!(owner.verified(&cap).unwrap().head(), head);
    check_deadline(owner.verified(&cap).unwrap(), target);
    let past = owner.verified_at(&cap, 5).unwrap();
    assert_eq!(past.added_at(target), Some(22));
    assert!(past.is_mature(target, WAIT + 22));
    assert_eq!(
        h.journal()
            .history_prefix(None, 256)
            .unwrap()
            .unwrap()
            .times[4],
        evidence(20, b"unused").map(|e| e.0)
    );
}

#[test]
fn confirmed_history_rebuild_preserves_deadline_and_maturity() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let (target, head) = confirmed_changes(&mut owner, &cap);
    drop(owner);
    h.raw()
        .execute("DELETE FROM account_projection", [])
        .unwrap();
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    assert_eq!(owner.verified(&cap).unwrap().head(), head);
    check_deadline(owner.verified(&cap).unwrap(), target);
}

#[test]
fn timed_commit_failure_rolls_back_events_confirmations_and_head() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let before = h.stored().head;
    let request = owner.prepare_add_device(&cap, test_keys(90)).unwrap();
    let event = ready(owner.sign_control(&cap, &request)).unwrap();
    // The head write follows original and confirmation insertions. Abort there.
    h.raw().execute_batch("CREATE TRIGGER fail_head BEFORE UPDATE ON account_state WHEN EXISTS(SELECT 1 FROM account_confirmations WHERE position=4) BEGIN SELECT RAISE(ABORT,'injected head failure'); END;").unwrap();
    assert!(matches!(
        owner.apply_incoming_timed(&[(event.as_bytes(), evidence(10, b"rollback proof"))]),
        Err(OwnerError::Journal(_))
    ));
    assert_eq!(h.stored().head, before);
    assert_eq!(h.stored().history.len(), 3);
    assert_eq!(
        h.raw()
            .query_row("SELECT count(*) FROM account_confirmations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        h.raw()
            .query_row("SELECT through_position FROM account_projection", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        3
    );
    assert!(
        !cap.is_current(),
        "failed durable writes must retain the existing fail-closed fence"
    );
    assert!(owner.verified(&cap).is_err());
    h.raw().execute_batch("DROP TRIGGER fail_head").unwrap();
    drop(owner);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    assert_eq!(owner.verified(&cap).unwrap().head(), before);
    owner
        .apply_incoming_timed(&[(event.as_bytes(), evidence(10, b"rollback proof"))])
        .unwrap();
    assert_eq!(owner.verified(&cap).unwrap().head().position, 4);
}

#[test]
fn untimed_commit_refuses_a_timed_projection() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let request = owner.prepare_add_device(&cap, test_keys(90)).unwrap();
    let event = ready(owner.sign_control(&cap, &request)).unwrap();
    let candidate = owner
        .verified(&cap)
        .unwrap()
        .clone()
        .applied_batch_timed(&[(event.as_bytes(), evidence(10, b"proof").map(|e| e.0))])
        .unwrap();
    let mut fence = None;
    let result = h.journal().commit_projected_fenced(
        candidate.id(),
        &[event.as_bytes()],
        candidate.head(),
        false,
        Some(&candidate),
        |success| fence = Some(success),
    );
    assert!(
        result.is_err(),
        "a projection cannot commit while discarding its confirmed time"
    );
    assert_eq!(fence, Some(false));
    assert_eq!(h.stored().head.position, 3);
}

#[test]
fn rebuild_cannot_checkpoint_unstored_confirmation_bounds() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let request = owner.prepare_add_device(&cap, test_keys(90)).unwrap();
    let event = ready(owner.sign_control(&cap, &request)).unwrap();
    let candidate = owner
        .verified(&cap)
        .unwrap()
        .clone()
        .applied_batch_timed(&[(event.as_bytes(), evidence(10, b"proof").map(|e| e.0))])
        .unwrap();
    let mut journal = h.journal();
    // Original-only history may be staged for replay, but a timed checkpoint
    // must never publish authority whose evidence was not stored with it.
    journal
        .commit_verified(candidate.id(), &[event.as_bytes()], candidate.head(), false)
        .unwrap();
    assert!(journal.advance_projection(&candidate).is_err());
    assert_eq!(
        h.raw()
            .query_row("SELECT through_position FROM account_projection", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        3
    );
}

#[test]
fn confirmation_index_checks_anchor_epoch_and_cut() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    confirmed_changes(&mut owner, &cap);
    let db = bh_storage::DeviceDatabase::open(&h.path).unwrap();
    let projection = db.account_projection().unwrap().unwrap();
    let pool = db.read_pool().unwrap();
    let anchor = projection.anchor;
    let epoch = projection.epoch;
    assert_eq!(
        pool.account_confirmed_time(anchor, epoch, 6, 5).unwrap(),
        Some((20, 22))
    );
    assert_eq!(
        pool.account_confirmed_time(anchor, epoch, 4, 5).unwrap(),
        None
    );
    assert_eq!(
        pool.account_confirmed_time(anchor, epoch, 6, 2).unwrap(),
        None
    );
    assert!(matches!(
        pool.account_confirmed_time([0; 32], epoch, 6, 5),
        Err(bh_storage::StoreError::AuthorityChanged)
    ));
    assert!(matches!(
        pool.account_confirmed_time(anchor, epoch + 1, 6, 5),
        Err(bh_storage::StoreError::AuthorityChanged)
    ));
    assert!(matches!(
        pool.account_confirmed_time(anchor, epoch, 7, 5),
        Err(bh_storage::StoreError::AuthorityChanged)
    ));
    h.raw()
        .execute("DELETE FROM account_projection", [])
        .unwrap();
    assert!(matches!(
        pool.account_confirmed_time(anchor, epoch, 6, 5),
        Err(bh_storage::StoreError::AuthorityChanged)
    ));
}

#[test]
fn confirmed_history_nonindexed_activation_replays_times() {
    let generation = AccountGeneration::new();
    let store = FakeStore::new(generation.clone());
    let database = std::sync::Arc::new(std::sync::Mutex::new(
        bh_storage::DeviceDatabase::open(":memory:").unwrap(),
    ));
    let make_owner = || {
        bh_account::owner::AccountOwner::new(
            DeviceJournal::from_shared(database.clone()),
            store.clone(),
            PlainProtector,
            generation.clone(),
        )
    };
    let mut owner = make_owner();
    let setup = begin(&mut owner);
    owner.confirm_kit_saved().unwrap();
    owner.confirm_home_ordered(setup.head, None).unwrap();
    let cap = activate(&mut owner);
    let (target, head) = confirmed_changes(&mut owner, &cap);
    drop(owner);
    assert!(
        database
            .lock()
            .unwrap()
            .account_projection()
            .unwrap()
            .is_none()
    );
    let mut owner = make_owner();
    let cap = activate(&mut owner);
    assert_eq!(owner.verified(&cap).unwrap().head(), head);
    check_deadline(owner.verified(&cap).unwrap(), target);
}

#[test]
fn missing_confirmation_refuses_new_control_without_erasing_authority() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let add = owner.prepare_add_device(&cap, test_keys(90)).unwrap();
    let add = ready(owner.sign_control(&cap, &add)).unwrap();
    owner.apply_incoming(&[add.as_bytes()]).unwrap();
    let before = owner.verified(&cap).unwrap().head();
    let request = owner
        .verified(&cap)
        .unwrap()
        .request_removal(cap.device_id(), test_keys(90).id())
        .unwrap();
    let event = ready(owner.sign_control(&cap, &request)).unwrap();
    assert!(
        owner
            .apply_incoming_timed(&[(event.as_bytes(), None)])
            .is_err()
    );
    assert_eq!(owner.verified(&cap).unwrap().head(), before);
    assert!(cap.is_current());
    assert!(
        owner
            .apply_incoming_timed(&[(event.as_bytes(), evidence(10, b""))])
            .is_err()
    );
    assert_eq!(owner.verified(&cap).unwrap().head(), before);
    assert!(cap.is_current());
    owner
        .apply_incoming_timed(&[(event.as_bytes(), evidence(10, b"retry proof"))])
        .unwrap();
}

/// A joining device adopts the history it verified with every
/// confirmation from its first commit, never untimed, and an interrupted
/// admission's retry keeps exactly what it committed.
#[test]
fn joining_device_adopts_timed_history_from_its_first_commit() {
    use bh_account::pairing::{Reply, ShowingSession, scanner_identity};
    let showing = Harness::new();
    let setup = complete(&showing);
    let joiner = Harness::new();
    let identity = ready(scanner_identity(
        &mut joiner.journal(),
        &mut joiner.store.clone(),
        ControlKeyPolicy::AppEnforcedOwnerConfirmation,
    ))
    .unwrap();
    // The same joining identity, as an older build would have admitted it.
    let legacy = Harness::new();
    std::fs::copy(&joiner.path, &legacy.path).unwrap();
    let mut first = showing.owner();
    let cap = activate(&mut first);
    let session = ShowingSession::new(setup.anchor, cap.device_id());
    session
        .receive(&Reply::make(&session.qr().unwrap(), identity.keys.clone(), b"Fold").unwrap())
        .unwrap();
    let request = session.prepare(&first, &cap).unwrap();
    let added = ready(first.sign_control(&cap, &request)).unwrap();
    let head = first
        .apply_incoming_timed(&[(added.as_bytes(), evidence(30, b"added"))])
        .unwrap();
    let history = showing.stored().history;
    let proofs = [
        None,
        evidence(10, b"record"),
        evidence(20, b"key"),
        evidence(30, b"added"),
    ];
    let timed: Vec<_> = history
        .iter()
        .map(Vec::as_slice)
        .zip(proofs.clone())
        .collect();
    let mut owner = joiner.owner();

    // A network admission never commits a proofless entry after genesis.
    let mut untimed = timed.clone();
    untimed[2].1 = None;
    assert!(matches!(
        owner.adopt_joined_timed(setup.anchor, &untimed),
        Err(OwnerError::Refused(bh_account::Error::MissingTime))
    ));
    let mut empty = timed.clone();
    empty[3].1 = evidence(30, b"");
    assert!(owner.adopt_joined_timed(setup.anchor, &empty).is_err());
    assert!(joiner.journal().load().unwrap().is_none());

    assert_eq!(
        owner.adopt_joined_timed(setup.anchor, &timed).unwrap(),
        head
    );
    let db = bh_storage::DeviceDatabase::open(&joiner.path).unwrap();
    assert!(db.confirmation(1).unwrap().is_none());
    for (position, proof) in proofs.iter().enumerate().skip(1) {
        let (time, bytes) = proof.clone().unwrap();
        let row = db.confirmation(position as u64 + 1).unwrap().unwrap();
        assert_eq!(
            (row.earliest_ms, row.latest_ms, row.bytes),
            (time.earliest_ms, time.latest_ms, bytes)
        );
    }
    // A retry keeps what was committed; other evidence is never written.
    assert_eq!(
        owner.adopt_joined_timed(setup.anchor, &timed).unwrap(),
        head
    );
    let mut other = timed.clone();
    other[3].1 = evidence(31, b"other");
    assert!(matches!(
        owner.adopt_joined_timed(setup.anchor, &other),
        Err(OwnerError::Stale)
    ));
    assert_eq!(db.confirmation(4).unwrap().unwrap().bytes, b"added");
    let joined = activate(&mut owner);
    assert_eq!(owner.verified(&joined).unwrap().head(), head);
    assert_eq!(
        joiner
            .journal()
            .history_prefix(None, 256)
            .unwrap()
            .unwrap()
            .times,
        proofs.map(|p| p.map(|e| e.0))
    );

    // An admission an older build committed untimed is not silently kept.
    let mut owner = legacy.owner();
    let refs: Vec<&[u8]> = history.iter().map(Vec::as_slice).collect();
    assert_eq!(owner.adopt_joined(setup.anchor, &refs).unwrap(), head);
    assert!(matches!(
        owner.adopt_joined_timed(setup.anchor, &timed),
        Err(OwnerError::Stale)
    ));
    assert!(
        bh_storage::DeviceDatabase::open(&legacy.path)
            .unwrap()
            .confirmation(4)
            .unwrap()
            .is_none()
    );
}
