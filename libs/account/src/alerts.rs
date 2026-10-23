//! Security-alert facts from accepted account authority, never untrusted service text.
//! This lives in bh-account because the account journal commits the facts in the
//! same SQLite transaction as the verified originals and projection.

use bh_storage::{AlertKind, NewAlert};

use crate::trust::ConfirmedTime;
use crate::{
    AccountChange, AccountEvent, ControlOutcome, DeviceId, Error, PendingRemoval, RequestState,
    VerifiedAccount,
};

fn device(id: DeviceId) -> Option<[u8; 32]> {
    Some(id.0)
}

fn alert(
    kind: AlertKind,
    position: u64,
    subject: Option<[u8; 32]>,
    actor: Option<[u8; 32]>,
    time_ms: Option<u64>,
    deadline_ms: Option<u64>,
) -> NewAlert {
    NewAlert {
        kind,
        position: Some(position),
        subject,
        actor,
        time_ms,
        deadline_ms,
    }
}

/// Compare the pending set before the observation with the verified state at
/// its confirmed lower bound. Request positions are stable deduplication keys,
/// even if no new event was ordered at this observation.
pub(crate) fn deadlines(
    pending: &[PendingRemoval],
    after: &VerifiedAccount,
    own: DeviceId,
    at_ms: u64,
) -> Result<Vec<NewAlert>, Error> {
    pending
        .iter()
        .filter(|p| p.target != own)
        .filter_map(|p| match after.request_state(p.request, at_ms) {
            Ok(RequestState::Effective) => Some(Ok(alert(
                AlertKind::RemovalEffective,
                p.request,
                device(p.target),
                p.by.map(|id| id.0),
                Some(p.deadline_ms),
                None,
            ))),
            Ok(_) => None,
            Err(e) => Some(Err(e)),
        })
        .collect()
}

/// Apply one original with the shared outcome and inspect the *result*, not
/// just the requested tag. The caller commits all returned facts atomically.
pub(crate) fn apply(
    view: &mut VerifiedAccount,
    original: &[u8],
    time: Option<ConfirmedTime>,
    own: DeviceId,
) -> Result<Vec<NewAlert>, Error> {
    let pending = view.pending_removals(0);
    let event = AccountEvent::decode(original)?;
    let outcome = view.apply_timed_with_outcome(original, time)?;
    let mut alerts = Vec::new();
    if let Some(c) = time {
        alerts.extend(deadlines(&pending, view, own, c.earliest_ms)?);
    }
    if outcome == ControlOutcome::Lapsed {
        return Ok(alerts);
    }
    let position = event.position;
    let at = time.map(|c| c.earliest_ms).unwrap_or(0);
    let when = time.map(|c| c.earliest_ms);
    match event.change() {
        AccountChange::DeviceAdded {
            device: added,
            by_recovery,
            by,
        } if added != own => {
            alerts.push(alert(
                if by_recovery {
                    AlertKind::DeviceAddedByKit
                } else {
                    AlertKind::DeviceAddedByQr
                },
                position,
                device(added),
                by.map(|id| id.0),
                when,
                None,
            ));
        }
        AccountChange::RemovalRequested {
            request,
            target,
            by,
        } => {
            if let RequestState::Pending { deadline_ms } = view.request_state(request, at)? {
                alerts.push(alert(
                    AlertKind::RemovalRequested,
                    position,
                    device(target),
                    by.map(|id| id.0),
                    when,
                    Some(deadline_ms),
                ));
            }
        }
        AccountChange::RemovalCancelled { request, by } => {
            if let Some(pending) = pending.iter().find(|p| p.request == request)
                && matches!(view.request_state(request, at), Ok(RequestState::Cancelled))
            {
                alerts.push(alert(
                    AlertKind::RemovalCancelled,
                    position,
                    device(pending.target),
                    by.map(|id| id.0),
                    when,
                    None,
                ));
            }
        }
        AccountChange::DeviceRemovedSelf { device: removed } if removed != own => {
            alerts.push(alert(
                AlertKind::RemovalEffective,
                position,
                device(removed),
                device(removed),
                when,
                None,
            ));
        }
        AccountChange::RemovedNow { target, by } if target != own => {
            alerts.push(alert(
                AlertKind::RemovalEffective,
                position,
                device(target),
                device(by),
                when,
                None,
            ));
        }
        AccountChange::RecoveryReplaced { by } => {
            alerts.push(alert(
                AlertKind::KitChanged,
                position,
                None,
                device(by),
                when,
                None,
            ));
        }
        _ => {}
    }
    Ok(alerts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountId, DevicePublicKeys, REMOVAL_WAIT_MS as WAIT, SigningRequest,
        crypto::{KemKey, SigningKey},
        recovery::RecoveryKeys,
    };

    struct Device {
        key: SigningKey,
        public: DevicePublicKeys,
    }
    impl Device {
        fn new() -> Self {
            let key = SigningKey::generate();
            Self {
                public: DevicePublicKeys::new(
                    SigningKey::generate().public(),
                    key.public(),
                    KemKey::generate().public(),
                )
                .unwrap(),
                key,
            }
        }
        fn id(&self) -> DeviceId {
            self.public.id()
        }
        fn sign(&self, request: SigningRequest) -> Vec<u8> {
            request
                .finish(self.key.sign(request.signing_bytes()))
                .unwrap()
                .as_bytes()
                .to_vec()
        }
    }
    fn timed(ms: u64) -> Option<ConfirmedTime> {
        Some(ConfirmedTime {
            earliest_ms: ms,
            latest_ms: ms,
        })
    }
    fn setup() -> (VerifiedAccount, Device, RecoveryKeys) {
        let mac = Device::new();
        let kit = RecoveryKeys::generate();
        let genesis = AccountEvent::genesis(mac.public.clone(), kit.public());
        let genesis = mac.sign(genesis);
        let mut account =
            VerifiedAccount::from_genesis(AccountId(crate::crypto::hash(&genesis)), &genesis)
                .unwrap();
        let record = account.prepare_recovery_record(mac.id(), [3; 32]).unwrap();
        account.apply(&mac.sign(record)).unwrap();
        let personal = account
            .publish_personal_key(mac.id(), KemKey::generate().public(), [4; 32], [5; 32])
            .unwrap();
        account.apply(&mac.sign(personal)).unwrap();
        (account, mac, kit)
    }
    #[test]
    fn qr_and_kit_additions_and_both_immediate_removals_are_accepted_facts() {
        let (mut account, mac, kit) = setup();
        let qr = Device::new();
        let by_qr = mac.sign(account.add_device(mac.id(), qr.public.clone()).unwrap());
        assert_eq!(
            apply(&mut account, &by_qr, timed(10), mac.id()).unwrap()[0].kind,
            AlertKind::DeviceAddedByQr
        );
        let recovered = Device::new();
        let by_kit = account
            .add_device_by_recovery(recovered.public.clone())
            .unwrap()
            .finish_with_recovery(&kit)
            .unwrap();
        assert_eq!(
            apply(&mut account, by_kit.as_bytes(), timed(20), mac.id()).unwrap()[0].kind,
            AlertKind::DeviceAddedByKit
        );
        let own = mac.sign(account.remove_self(mac.id()).unwrap());
        let mut copy = account.clone();
        assert!(
            apply(&mut copy, &own, timed(30), mac.id())
                .unwrap()
                .is_empty()
        );
        let leave = qr.sign(account.remove_self(qr.id()).unwrap());
        assert_eq!(
            apply(&mut account, &leave, timed(30), mac.id()).unwrap()[0].kind,
            AlertKind::RemovalEffective
        );
        let now = account.remove_now(mac.id(), recovered.id()).unwrap();
        let now = now
            .finish(
                mac.key.sign(&now.device_signing_bytes()),
                now.sign_recovery(&kit),
            )
            .unwrap();
        assert_eq!(
            apply(&mut account, now.as_bytes(), timed(WAIT + 21), mac.id()).unwrap()[0].kind,
            AlertKind::RemovalEffective
        );
    }

    #[test]
    fn target_is_alerted_when_removal_is_requested_and_cancelled() {
        let (mut account, mac, _) = setup();
        let fold = Device::new();
        let added = mac.sign(account.add_device(mac.id(), fold.public.clone()).unwrap());
        apply(&mut account, &added, timed(10), mac.id()).unwrap();
        let request = fold.sign(account.request_removal(fold.id(), mac.id()).unwrap());
        let requested = apply(&mut account, &request, timed(20), mac.id()).unwrap();
        assert_eq!(requested.len(), 1);
        assert_eq!(requested[0].kind, AlertKind::RemovalRequested);
        assert_eq!(requested[0].subject, Some(mac.id().0));
        assert_eq!(requested[0].actor, Some(fold.id().0));
        assert_eq!(requested[0].deadline_ms, Some(WAIT + 20));
        let cancel = fold.sign(account.cancel_removal(fold.id(), 5).unwrap());
        let cancelled = apply(&mut account, &cancel, timed(WAIT + 11), mac.id()).unwrap();
        assert_eq!(cancelled.len(), 1);
        assert_eq!(cancelled[0].kind, AlertKind::RemovalCancelled);
        assert_eq!(cancelled[0].subject, Some(mac.id().0));
        assert_eq!(cancelled[0].actor, Some(fold.id().0));
    }

    #[test]
    fn already_removed_request_lapses_without_another_requested_alert() {
        let (mut account, mac, kit) = setup();
        let fold = Device::new();
        let add = mac.sign(account.add_device(mac.id(), fold.public.clone()).unwrap());
        apply(&mut account, &add, timed(10), mac.id()).unwrap();
        let first = mac.sign(account.request_removal(mac.id(), fold.id()).unwrap());
        apply(&mut account, &first, timed(20), mac.id()).unwrap();
        let second = account
            .request_removal_by_recovery(fold.id())
            .unwrap()
            .finish_with_recovery(&kit)
            .unwrap();
        let alerted = apply(&mut account, second.as_bytes(), timed(WAIT + 20), mac.id()).unwrap();
        assert_eq!(alerted.len(), 1);
        assert_eq!(alerted[0].kind, AlertKind::RemovalEffective);
        assert_eq!(alerted[0].position, Some(5));
    }

    #[test]
    fn lapsed_addition_never_reports_an_admission() {
        let (mut account, mac, _) = setup();
        let fold = Device::new();
        let add = mac.sign(account.add_device(mac.id(), fold.public.clone()).unwrap());
        apply(&mut account, &add, timed(10), mac.id()).unwrap();
        let request = mac.sign(account.request_removal(mac.id(), fold.id()).unwrap());
        let alerted = apply(&mut account, &request, timed(20), mac.id()).unwrap();
        assert_eq!(alerted[0].kind, AlertKind::RemovalRequested);
        assert_eq!(alerted[0].deadline_ms, Some(WAIT + 20));
        let phone = Device::new();
        let stale = fold.sign(account.add_device(fold.id(), phone.public).unwrap());
        let alerts = apply(&mut account, &stale, timed(WAIT + 20), mac.id()).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].kind, AlertKind::RemovalEffective);
        assert_eq!(alerts[0].position, Some(5)); // request, not the lapsed add
    }
}
