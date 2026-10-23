//! Changes to who is trusted: removals, cancellations, recovery-key
//! replacement and personal-key rotation, and the requests that sign them.
use crate::history::{Control, ROLE_DEVICE, ROLE_RECOVERY, Signer, cosign_bytes};
use crate::recovery::RecoveryKeys;
use crate::{
    AccountEvent, DeviceId, DevicePublicKeys, Error, PersonalPublication, RecoveryPublicKeys,
    SigningRequest, VerifiedAccount, crypto::verify,
};
use std::collections::BTreeMap;

/// How long a removal request waits before it takes effect.
pub const REMOVAL_WAIT_MS: u64 = bh_flags::REMOVAL_WAIT_MS;

/// Time bounds from an ordering confirmation the caller has already verified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmedTime {
    pub earliest_ms: u64,
    pub latest_ms: u64,
}

/// A removal request still waiting for its deadline. `by: None` is the
/// recovery key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PendingRemoval {
    pub request: u64,
    pub target: DeviceId,
    pub by: Option<DeviceId>,
    pub deadline_ms: u64,
}
// Avoid putting device identifiers in automatic diagnostics.
impl std::fmt::Debug for PendingRemoval {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingRemoval")
            .field("request", &self.request)
            .field("deadline_ms", &self.deadline_ms)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestState {
    Pending {
        deadline_ms: u64,
    },
    Cancelled,
    Effective,
    /// Its requester or its target was removed first. Unlike
    /// `ControlOutcome::Lapsed`, an entry whose own signer was removed first.
    Lapsed,
    /// No longer pending, resolved before this projection was loaded: how
    /// is not kept. Its target's `device_state` says whether it was removed.
    Resolved,
}

/// A device whose removal is pending stays active, and may sign, until the
/// deadline is established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceState {
    Active,
    RemovalPending { request: u64, deadline_ms: u64 },
    Removed,
}

/// A change after which the personal key must rotate, named by the position
/// a rotation gives as its reason.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RotationReason {
    Removal { request: u64, target: DeviceId },
    RemovedNow { position: u64, target: DeviceId },
    RemovedSelf { position: u64, device: DeviceId },
    RecoveryReplaced { position: u64 },
}
impl RotationReason {
    pub fn position(&self) -> u64 {
        match *self {
            Self::Removal { request, .. } => request,
            Self::RemovedNow { position, .. }
            | Self::RemovedSelf { position, .. }
            | Self::RecoveryReplaced { position } => position,
        }
    }
}
impl std::fmt::Debug for RotationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match self {
            Self::Removal { .. } => "Removal",
            Self::RemovedNow { .. } => "RemovedNow",
            Self::RemovedSelf { .. } => "RemovedSelf",
            Self::RecoveryReplaced { .. } => "RecoveryReplaced",
        };
        write!(f, "{kind}({})", self.position())
    }
}

/// An established change awaiting rotation, and when it was established:
/// a request's deadline, or the confirmed `latest_ms` of an immediate change.
#[derive(Clone, Copy)]
pub(crate) struct Effect {
    pub reason: RotationReason,
    pub established_ms: u64,
}

/// The account's confirmed time and the membership changes that wait on it.
/// Pending requests are bounded by membership (one per requester and
/// target), and effects by the removals since the last rotation plus at most
/// one kit change; advancing
/// costs O(pending requests), never a history scan.
#[derive(Clone, Default)]
pub(crate) struct Timeline {
    /// Position and `latest_ms` of the first confirmed entry.
    pub first: Option<(u64, u64)>,
    pub last: Option<ConfirmedTime>,
    /// Locally remembered accepted-head lower bound. It is loaded from the
    /// canonical account state's observation column only after replay reaches
    /// the remembered head; it is not a signed event or a history replay input.
    pub observed_earliest_ms: Option<u64>,
    pub pending: BTreeMap<u64, PendingRemoval>,
    /// How requests resolved while this projection was loaded ended. Kept
    /// only in memory, never in the summary.
    pub resolved: BTreeMap<u64, RequestState>,
    /// Established effects no rotation has fulfilled yet.
    pub effects: BTreeMap<u64, Effect>,
}
impl Timeline {
    /// Untimed entries are legacy history: allowed only before the first
    /// confirmed entry or accepted-head observation, and only where `untimed` permits.
    pub fn confirm(
        &mut self,
        position: u64,
        time: Option<ConfirmedTime>,
        untimed: bool,
    ) -> Result<(), Error> {
        let Some(c) = time else {
            return if untimed && self.first.is_none() && self.observed_earliest_ms.is_none() {
                Ok(())
            } else {
                Err(Error::MissingTime)
            };
        };
        if c.earliest_ms > c.latest_ms {
            return Err(Error::Malformed);
        }
        if self
            .last
            .is_some_and(|l| c.earliest_ms < l.earliest_ms || c.latest_ms < l.latest_ms)
            || self
                .observed_earliest_ms
                .is_some_and(|floor| c.earliest_ms < floor)
        {
            return Err(Error::TimeRegressed);
        }
        self.first.get_or_insert((position, c.latest_ms));
        self.last = Some(c);
        Ok(())
    }
    /// Requests resolved by `at_ms`: due requests in `(deadline, position)`
    /// order; each still pending removes its target, and lapses every pending
    /// request by or against that target.
    fn resolving(&self, at_ms: u64) -> BTreeMap<u64, RequestState> {
        let mut due: Vec<_> = self
            .pending
            .values()
            .filter(|p| p.deadline_ms <= at_ms)
            .map(|p| (p.deadline_ms, p.request))
            .collect();
        let mut out = BTreeMap::new();
        if due.is_empty() {
            return out;
        }
        due.sort_unstable();
        // Each device's requests, by it or against it, are visited once.
        let mut involving: BTreeMap<DeviceId, Vec<u64>> = BTreeMap::new();
        for p in self.pending.values() {
            involving.entry(p.target).or_default().push(p.request);
            if let Some(by) = p.by {
                involving.entry(by).or_default().push(p.request);
            }
        }
        for (_, request) in due {
            if out.contains_key(&request) {
                continue;
            }
            out.insert(request, RequestState::Effective);
            let target = self.pending[&request].target;
            for lapsed in involving.remove(&target).unwrap_or_default() {
                out.entry(lapsed).or_insert(RequestState::Lapsed);
            }
        }
        out
    }
    /// Resolve every request due by `at_ms`; returns the removed targets
    /// with the requests that removed them.
    pub fn advance(&mut self, at_ms: u64) -> Vec<(DeviceId, u64)> {
        let mut removed = Vec::new();
        for (request, state) in self.resolving(at_ms) {
            let Some(p) = self.pending.remove(&request) else {
                continue;
            };
            self.resolved.insert(request, state);
            if state == RequestState::Effective {
                let target = p.target;
                self.effects.insert(
                    request,
                    Effect {
                        reason: RotationReason::Removal { request, target },
                        established_ms: p.deadline_ms,
                    },
                );
                removed.push((target, request));
            }
        }
        removed
    }
    pub fn lapse(&mut self, lapses: impl Fn(&PendingRemoval) -> bool) {
        let lapsed: Vec<u64> = self
            .pending
            .values()
            .filter(|p| lapses(p))
            .map(|p| p.request)
            .collect();
        for request in lapsed {
            self.pending.remove(&request);
            self.resolved.insert(request, RequestState::Lapsed);
        }
    }
    /// A rotation for `reason` fulfils every effect established at or
    /// before it, ties by position; later effects stay due.
    pub fn fulfil(&mut self, reason: u64) -> Result<(), Error> {
        let Some(effect) = self.effects.get(&reason) else {
            return Err(if self.pending.contains_key(&reason) {
                Error::TooEarly
            } else {
                Error::NotPermitted
            });
        };
        let bound = (effect.established_ms, reason);
        self.effects
            .retain(|position, e| (e.established_ms, *position) > bound);
        Ok(())
    }
}

/// What one event asks to change, for showing account history. `by: None` is
/// the recovery key. Whether a cancellation took effect is account state
/// (`request_state`), not part of its event, and a lapsed event changed
/// nothing (`ControlOutcome`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AccountChange {
    DeviceAdded {
        device: DeviceId,
        by_recovery: bool,
        by: Option<DeviceId>,
    },
    DeviceRemovedSelf {
        device: DeviceId,
    },
    RemovalRequested {
        request: u64,
        target: DeviceId,
        by: Option<DeviceId>,
    },
    RemovedNow {
        target: DeviceId,
        by: DeviceId,
    },
    RemovalCancelled {
        request: u64,
        by: Option<DeviceId>,
    },
    RecoveryReplaced {
        by: DeviceId,
    },
    PersonalRotated {
        reason: u64,
        by: DeviceId,
    },
    Setup,
}

impl AccountEvent {
    pub fn change(&self) -> AccountChange {
        let by = match self.signer {
            Signer::Device => Some(self.author),
            Signer::Recovery => None,
        };
        match &self.control {
            Control::Genesis { .. } | Control::RecoveryRecord(_) | Control::PersonalKey(_) => {
                AccountChange::Setup
            }
            Control::AddDevice(keys) => AccountChange::DeviceAdded {
                device: keys.id(),
                by_recovery: by.is_none(),
                by,
            },
            Control::RemoveSelf => AccountChange::DeviceRemovedSelf {
                device: self.author,
            },
            Control::RemoveRequest(target) => AccountChange::RemovalRequested {
                request: self.position,
                target: *target,
                by,
            },
            Control::RemoveNow(target) => AccountChange::RemovedNow {
                target: *target,
                by: self.author,
            },
            Control::Cancel(request) => AccountChange::RemovalCancelled {
                request: *request,
                by,
            },
            Control::ReplaceRecovery { .. } => AccountChange::RecoveryReplaced { by: self.author },
            Control::RotatePersonal { reason, .. } => AccountChange::PersonalRotated {
                reason: *reason,
                by: self.author,
            },
        }
    }
}

impl SigningRequest {
    pub fn finish_with_recovery(&self, keys: &RecoveryKeys) -> Result<AccountEvent, Error> {
        self.finish(keys.sign(self.signing_bytes()))
    }
}

/// An immediate removal: the author's second key and the recovery key each
/// sign the same unsigned event under their own role; neither signs the other.
pub struct CosigningRequest {
    unsigned: Vec<u8>,
    device_key: [u8; 32],
    recovery_key: [u8; 32],
}
impl CosigningRequest {
    pub fn device_signing_bytes(&self) -> Vec<u8> {
        cosign_bytes(ROLE_DEVICE, &self.unsigned)
    }
    pub fn recovery_signing_bytes(&self) -> Vec<u8> {
        cosign_bytes(ROLE_RECOVERY, &self.unsigned)
    }
    pub fn sign_recovery(&self, keys: &RecoveryKeys) -> [u8; 64] {
        keys.sign(&self.recovery_signing_bytes())
    }
    pub fn device_key(&self) -> &[u8; 32] {
        &self.device_key
    }
    pub fn recovery_key(&self) -> &[u8; 32] {
        &self.recovery_key
    }
    pub fn finish(&self, device: [u8; 64], recovery: [u8; 64]) -> Result<AccountEvent, Error> {
        verify(&self.device_key, &self.device_signing_bytes(), &device)
            .map_err(|_| Error::BadSignature)?;
        verify(
            &self.recovery_key,
            &self.recovery_signing_bytes(),
            &recovery,
        )
        .map_err(|_| Error::BadSignature)?;
        let mut bytes = self.unsigned.clone();
        bytes.extend(device);
        bytes.extend(recovery);
        AccountEvent::decode(&bytes)
    }
}

/// Queries at a time: each sees the account advanced to `at_ms` without
/// changing it. Pass established time (a confirmation's `earliest_ms`), never
/// a guess that could make a removal look effective early.
impl VerifiedAccount {
    /// Bind future confirmations to an accepted-head observation without
    /// changing this history's head or its signed event identities.
    pub(crate) fn remember_observation_floor(&mut self, earliest_ms: u64) {
        self.timeline.observed_earliest_ms = Some(
            self.timeline
                .observed_earliest_ms
                .unwrap_or(0)
                .max(earliest_ms),
        );
    }

    /// A copy advanced to `at_ms`; its head is unchanged.
    pub fn advanced(&self, at_ms: u64) -> VerifiedAccount {
        let mut copy = self.clone();
        copy.advance_to(at_ms);
        copy
    }
    pub fn pending_removals(&self, at_ms: u64) -> Vec<PendingRemoval> {
        if self.running().is_err() {
            return Vec::new();
        }
        let resolving = self.timeline.resolving(at_ms);
        self.timeline
            .pending
            .values()
            .filter(|p| !resolving.contains_key(&p.request))
            .copied()
            .collect()
    }
    pub fn request_state(&self, request: u64, at_ms: u64) -> Result<RequestState, Error> {
        self.running()?;
        if let Some(p) = self.timeline.pending.get(&request) {
            let pending = RequestState::Pending {
                deadline_ms: p.deadline_ms,
            };
            return Ok(self
                .timeline
                .resolving(at_ms)
                .get(&request)
                .copied()
                .unwrap_or(pending));
        }
        if let Some(state) = self.timeline.resolved.get(&request) {
            return Ok(*state);
        }
        if request == 0 || request > self.head().position {
            return Err(Error::NotPermitted);
        }
        Ok(RequestState::Resolved)
    }
    pub fn device_state(&self, device: DeviceId, at_ms: u64) -> Result<DeviceState, Error> {
        self.running()?;
        if self.active_device(device).is_err() {
            return if self.seen_device(device)? {
                Ok(DeviceState::Removed)
            } else {
                Err(Error::NotActive)
            };
        }
        let resolving = self.timeline.resolving(at_ms);
        let mut first: Option<&PendingRemoval> = None;
        for p in self
            .timeline
            .pending
            .values()
            .filter(|p| p.target == device)
        {
            match resolving.get(&p.request) {
                Some(RequestState::Effective) => return Ok(DeviceState::Removed),
                Some(_) => {}
                None => {
                    if first.is_none_or(|f| (p.deadline_ms, p.request) < (f.deadline_ms, f.request))
                    {
                        first = Some(p);
                    }
                }
            }
        }
        Ok(
            first.map_or(DeviceState::Active, |p| DeviceState::RemovalPending {
                request: p.request,
                deadline_ms: p.deadline_ms,
            }),
        )
    }
    /// The earliest established effect no rotation has fulfilled, by
    /// establishing time, then position. A rotation for the latest due
    /// effect fulfils them all.
    pub fn rotation_due(&self, at_ms: u64) -> Option<RotationReason> {
        self.due_effects(at_ms)
            .into_iter()
            .min_by_key(|e| (e.established_ms, e.reason.position()))
            .map(|e| e.reason)
    }
    /// The reason for a rotation made at `at_ms`: the latest effect
    /// established by then that no rotation has fulfilled, by establishing
    /// time, then position, so that one rotation fulfils every one due. An
    /// immediate change confirmed with `latest_ms` after `at_ms` waits.
    pub fn rotation_reason(&self, at_ms: u64) -> Option<RotationReason> {
        self.due_effects(at_ms)
            .into_iter()
            .filter(|e| e.established_ms <= at_ms)
            .max_by_key(|e| (e.established_ms, e.reason.position()))
            .map(|e| e.reason)
    }
    /// Unfulfilled effects, with requests whose deadline `at_ms` reaches.
    fn due_effects(&self, at_ms: u64) -> Vec<Effect> {
        if self.running().is_err() {
            return Vec::new();
        }
        let established = self
            .timeline
            .resolving(at_ms)
            .into_iter()
            .filter(|(_, state)| *state == RequestState::Effective)
            .map(|(request, _)| {
                let p = &self.timeline.pending[&request];
                Effect {
                    reason: RotationReason::Removal {
                        request,
                        target: p.target,
                    },
                    established_ms: p.deadline_ms,
                }
            });
        self.timeline
            .effects
            .values()
            .copied()
            .chain(established)
            .collect()
    }
    /// When an active device was added: its addition's `latest_ms`; for one
    /// added before the first confirmed entry, that entry's `latest_ms`.
    pub fn added_at(&self, device: DeviceId) -> Option<u64> {
        self.added_ms(device).ok().flatten()
    }
    pub fn is_mature(&self, device: DeviceId, at_ms: u64) -> bool {
        self.mature(device, at_ms).unwrap_or(false)
    }
    /// Unknown local evidence is `Unavailable`, never a guessed time.
    pub(crate) fn mature(&self, device: DeviceId, at_ms: u64) -> Result<bool, Error> {
        Ok(self
            .added_ms(device)?
            .and_then(|added| added.checked_add(REMOVAL_WAIT_MS))
            .is_some_and(|mature| mature <= at_ms))
    }
    fn added_ms(&self, device: DeviceId) -> Result<Option<u64>, Error> {
        self.running()?;
        let (Some(position), Some((first, first_latest))) =
            (self.added_position(device), self.timeline.first)
        else {
            return Ok(None);
        };
        if position <= first {
            return Ok(Some(first_latest));
        }
        match self.confirmed_time(position)? {
            Some(time) => Ok(Some(time.latest_ms)),
            None => Err(Error::Unavailable),
        }
    }
}

impl VerifiedAccount {
    pub fn add_device_by_recovery(&self, keys: DevicePublicKeys) -> Result<SigningRequest, Error> {
        self.check_new_device(&keys)?;
        self.by_recovery(Control::AddDevice(Box::new(keys)))
    }
    pub fn request_removal(
        &self,
        author: DeviceId,
        target: DeviceId,
    ) -> Result<SigningRequest, Error> {
        let signer = self.removing(author, target)?;
        self.prepare(author, Control::RemoveRequest(target), signer)
    }
    pub fn request_removal_by_recovery(&self, target: DeviceId) -> Result<SigningRequest, Error> {
        self.active_device(target)?;
        self.by_recovery(Control::RemoveRequest(target))
    }
    pub fn remove_now(
        &self,
        author: DeviceId,
        target: DeviceId,
    ) -> Result<CosigningRequest, Error> {
        let device_key = self.removing(author, target)?;
        let recovery_key = *self.recovery_keys()?.signing();
        let unsigned = self
            .prepare(author, Control::RemoveNow(target), device_key)?
            .into_unsigned();
        Ok(CosigningRequest {
            unsigned,
            device_key,
            recovery_key,
        })
    }
    pub fn cancel_removal(&self, author: DeviceId, request: u64) -> Result<SigningRequest, Error> {
        let signer = *self.active_device(author)?.control();
        self.prepare(author, Control::Cancel(request), signer)
    }
    pub fn cancel_removal_by_recovery(&self, request: u64) -> Result<SigningRequest, Error> {
        self.by_recovery(Control::Cancel(request))
    }
    pub fn replace_recovery(
        &self,
        author: DeviceId,
        recovery: RecoveryPublicKeys,
        record_digest: [u8; 32],
        recovery_seal_digest: [u8; 32],
    ) -> Result<SigningRequest, Error> {
        let signer = *self.active_device(author)?.control();
        self.initial_materials()?;
        self.check_new_recovery(&recovery)?;
        self.prepare(
            author,
            Control::ReplaceRecovery {
                recovery: Box::new(recovery),
                record_digest,
                recovery_seal_digest,
            },
            signer,
        )
    }
    /// Signed with the author's ordinary key: the signed log already fixes who
    /// receives the new key, so a rotation needs no second-key prompt.
    pub fn rotate_personal(
        &self,
        author: DeviceId,
        reason: u64,
        public: [u8; 1216],
        device_seals_digest: [u8; 32],
        recovery_seal_digest: [u8; 32],
    ) -> Result<SigningRequest, Error> {
        let signer = *self.active_device(author)?.signing();
        self.prepare(
            author,
            Control::RotatePersonal {
                reason,
                publication: Box::new(PersonalPublication::new(
                    public,
                    device_seals_digest,
                    recovery_seal_digest,
                )),
            },
            signer,
        )
    }
    /// The author's second key, for removing another active device.
    fn removing(&self, author: DeviceId, target: DeviceId) -> Result<[u8; 32], Error> {
        let signer = *self.active_device(author)?.control();
        if author == target {
            return Err(Error::NotPermitted);
        }
        self.active_device(target)?;
        Ok(signer)
    }
    fn by_recovery(&self, control: Control) -> Result<SigningRequest, Error> {
        let keys = self.recovery_keys()?;
        self.prepare_as(keys.author(), Signer::Recovery, control, *keys.signing())
    }
}

#[cfg(test)]
mod cosign_tests {
    use super::*;
    use crate::AccountId;
    use crate::crypto::{KemKey, SigningKey};

    #[test]
    fn a_recovery_signature_over_other_bytes_is_not_a_cosignature() {
        let first = SigningKey::generate();
        let second = SigningKey::generate();
        let public = |control: &SigningKey| {
            DevicePublicKeys::new(
                SigningKey::generate().public(),
                control.public(),
                KemKey::generate().public(),
            )
            .unwrap()
        };
        let (mac, fold) = (public(&first), public(&second));
        let recovery = RecoveryKeys::generate();
        let draft = AccountEvent::genesis(mac.clone(), recovery.public());
        let genesis = draft.finish(first.sign(draft.signing_bytes())).unwrap();
        let mut acct = VerifiedAccount::from_genesis(
            AccountId::of_genesis(&genesis).unwrap(),
            genesis.as_bytes(),
        )
        .unwrap();
        let add = acct.add_device(mac.id(), fold.clone()).unwrap();
        let add = add.finish(first.sign(add.signing_bytes())).unwrap();
        acct.apply(add.as_bytes()).unwrap();
        let r = acct.remove_now(mac.id(), fold.id()).unwrap();
        let device = first.sign(&r.device_signing_bytes());
        let valid = r.finish(device, r.sign_recovery(&recovery)).unwrap();
        let unsigned = &valid.as_bytes()[..valid.as_bytes().len() - 128];
        let time = Some(ConfirmedTime {
            earliest_ms: 10,
            latest_ms: 10,
        });
        let mut candidate = acct.clone();
        let matured = candidate.apply_timed(valid.as_bytes(), time);
        assert_eq!(matured, Err(Error::NotMature));
        for message in [r.device_signing_bytes(), unsigned.to_vec()] {
            let bytes = [unsigned, &device, &recovery.sign(&message)].concat();
            let mut candidate = acct.clone();
            assert_eq!(
                candidate.apply_timed(&bytes, time),
                Err(Error::BadSignature)
            );
        }
    }
}
