//! Ordering evidence and timed replay share the account's one transition rule.
use crate::{
    Bounds, PermitKeys,
    store::{StoredEvent, projection::HistoricalEntry},
};
use bh_account::{ConfirmedTime, ControlOutcome, VerifiedAccount};
use bh_authz_proto::LogId;
use bh_sync::{
    BaseId, Digest, Head, OrderState, Route,
    canonical::CanonicalCommitment,
    evidence::{
        AcceptedHead, ConfirmationClaim, OrderingConfirmation, TimeBounds, original_digest,
    },
};

pub(crate) fn clamp(now: Bounds, floor: Option<TimeBounds>) -> TimeBounds {
    let floor = floor.unwrap_or(TimeBounds {
        earliest_ms: 0,
        latest_ms: 0,
    });
    TimeBounds {
        earliest_ms: now.earliest_ms.max(floor.earliest_ms),
        latest_ms: now.latest_ms.max(floor.latest_ms),
    }
}

pub(crate) fn time(bounds: TimeBounds) -> ConfirmedTime {
    ConfirmedTime {
        earliest_ms: bounds.earliest_ms,
        latest_ms: bounds.latest_ms,
    }
}

pub(crate) fn head(head: bh_account::Head) -> Head {
    Head {
        position: head.position,
        hash: Digest(head.hash),
    }
}

pub(crate) fn apply(
    keys: &PermitKeys,
    account: VerifiedAccount,
    log: LogId,
    event: &StoredEvent,
    ordered: Head,
    bounds: TimeBounds,
) -> Result<(VerifiedAccount, Vec<u8>, ControlOutcome), ()> {
    let previous = head(account.head());
    let (account, outcomes) = account
        .applied_batch_timed_with_outcomes(&[(&event.original, Some(time(bounds)))])
        .map_err(|_| ())?;
    let outcome = outcomes[0];
    let confirmation = OrderingConfirmation::sign(
        &keys.key,
        &keys.certificate,
        ConfirmationClaim {
            log,
            original: original_digest(&event.original),
            original_previous: previous,
            original_head: head(account.head()),
            body: event.body,
            ordered,
            bounds,
        },
    );
    Ok((account, confirmation.encode().to_vec(), outcome))
}

pub(crate) fn accepted(
    keys: &PermitKeys,
    log: LogId,
    challenge: [u8; 32],
    account: &VerifiedAccount,
    confirmation: Option<&[u8]>,
    bounds: TimeBounds,
) -> Vec<u8> {
    AcceptedHead::sign(
        &keys.key,
        &keys.certificate,
        log,
        challenge,
        head(account.head()),
        confirmation.map_or([0; 32], bh_crypto::hash),
        bounds,
    )
}

#[cfg(test)]
thread_local! {
    static REPLAY_TRANSITIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
#[cfg(test)]
pub(crate) fn take_replay_transitions() -> usize {
    REPLAY_TRANSITIONS.with(|counter| counter.replace(0))
}

/// Verify a bounded stored HOME suffix against the checkpoint's exact outer
/// opening. Every non-genesis canonical original has its original signed
/// confirmation, whose FULL ordered head must match the reconstructed wrapper.
pub(crate) fn replay_suffix(
    mut view: VerifiedAccount,
    log: LogId,
    mut before: OrderState,
    entries: &[HistoricalEntry],
    root: &[u8; 32],
) -> Result<(VerifiedAccount, OrderState), ()> {
    for entry in entries {
        if entry.position != view.head().position.checked_add(1).ok_or(())? || entry.position < 2 {
            return Err(());
        }
        let bytes = entry.confirmation.as_ref().ok_or(())?;
        let proof = OrderingConfirmation::decode(bytes).map_err(|_| ())?;
        let claim = proof
            .verify_for(root, &entry.event.original, entry.event.body)
            .map_err(|_| ())?;
        let wrapped = bh_authz_proto::account_log_wrap(&entry.event.original, entry.event.body)
            .map_err(|_| ())?;
        let after =
            CanonicalCommitment::order(BaseId(log.id), before, wrapped.digest(), Route::Control)
                .map_err(|_| ())?
                .after();
        if claim.log != log
            || claim.original_previous != head(view.head())
            || claim.ordered != after.head(BaseId(log.id))
            || claim.bounds.earliest_ms > claim.bounds.latest_ms
        {
            return Err(());
        }
        view = view
            .applied_batch_timed(&[(&entry.event.original, Some(time(claim.bounds)))])
            .map_err(|_| ())?;
        #[cfg(test)]
        {
            REPLAY_TRANSITIONS.with(|counter| counter.set(counter.get() + 1));
            crate::store::projection::transition_work();
        }
        if claim.original_head != head(view.head()) {
            return Err(());
        }
        before = after;
    }
    Ok((view, before))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_account::{AccountEvent, AccountId, DevicePublicKeys, recovery::RecoveryKeys};
    use bh_authz_proto::{LogKind, account_log_id};
    use bh_sync::{BaseId, Route, canonical::CanonicalCommitment, permit};

    #[test]
    fn suffix_rejects_valid_signed_proof_with_wrong_full_ordered_hash() {
        let root = bh_crypto::SigningKey::generate();
        let service_key = bh_crypto::SigningKey::generate();
        let certificate = permit::certify(&root, service_key.public());
        let owner = bh_crypto::SigningKey::generate();
        let recovery = RecoveryKeys::generate();
        let draft = AccountEvent::genesis(
            DevicePublicKeys::new(
                bh_crypto::SigningKey::generate().public(),
                owner.public(),
                bh_crypto::KemKey::generate().public(),
            )
            .unwrap(),
            recovery.public(),
        );
        let genesis = draft.finish(owner.sign(draft.signing_bytes())).unwrap();
        let id = AccountId::of_genesis(&genesis).unwrap();
        let log = LogId {
            kind: LogKind::Account,
            id: account_log_id(genesis.as_bytes()).unwrap(),
        };
        let view = VerifiedAccount::from_genesis(id, genesis.as_bytes()).unwrap();
        let genesis_wrapper = bh_authz_proto::account_log_wrap(genesis.as_bytes(), None).unwrap();
        let opening = CanonicalCommitment::order(
            BaseId(log.id),
            OrderState::EMPTY,
            genesis_wrapper.digest(),
            Route::Control,
        )
        .unwrap()
        .after();
        let extra = DevicePublicKeys::new(
            bh_crypto::SigningKey::generate().public(),
            bh_crypto::SigningKey::generate().public(),
            bh_crypto::KemKey::generate().public(),
        )
        .unwrap();
        let owner_id = view.active_devices().unwrap().next().unwrap().id();
        let draft = view.add_device(owner_id, extra).unwrap();
        let added = draft.finish(owner.sign(draft.signing_bytes())).unwrap();
        let original = added.as_bytes().to_vec();
        let next = view
            .clone()
            .applied_batch_timed(&[(
                &original,
                Some(time(TimeBounds {
                    earliest_ms: 100,
                    latest_ms: 100,
                })),
            )])
            .unwrap();
        let wrapper = bh_authz_proto::account_log_wrap(&original, None).unwrap();
        let actual =
            CanonicalCommitment::order(BaseId(log.id), opening, wrapper.digest(), Route::Control)
                .unwrap()
                .after()
                .head(BaseId(log.id));
        let false_head = Head {
            position: actual.position,
            hash: Digest([19; 32]),
        };
        assert_ne!(actual, false_head);
        let proof = OrderingConfirmation::sign(
            &service_key,
            &certificate,
            ConfirmationClaim {
                log,
                original: original_digest(&original),
                original_previous: head(view.head()),
                original_head: head(next.head()),
                body: None,
                ordered: false_head,
                bounds: TimeBounds {
                    earliest_ms: 100,
                    latest_ms: 100,
                },
            },
        );
        let entries = [HistoricalEntry {
            position: 2,
            event: StoredEvent {
                original,
                body: None,
            },
            confirmation: Some(proof.encode().to_vec()),
        }];
        assert!(replay_suffix(view, log, opening, &entries, &root.public()).is_err());
    }
}
