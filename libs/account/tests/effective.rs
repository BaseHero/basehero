use bh_account::{
    AccountEvent, AccountId, ConfirmedTime, ControlOutcome, DeviceId, DevicePublicKeys,
    DeviceState, Error, PendingRemoval, REMOVAL_WAIT_MS as W, RequestState, RotationReason,
    SigningRequest, VerifiedAccount,
    crypto::{KemKey, SigningKey},
    recovery::RecoveryKeys,
};

struct Device {
    ordinary: SigningKey,
    control: SigningKey,
    public: DevicePublicKeys,
}
impl Device {
    fn new() -> Self {
        let ordinary = SigningKey::generate();
        let control = SigningKey::generate();
        let public = DevicePublicKeys::new(
            ordinary.public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        Self {
            ordinary,
            control,
            public,
        }
    }
    fn id(&self) -> DeviceId {
        self.public.id()
    }
}

struct Fixture {
    mac: Device,
    fold: Device,
    phone: Device,
    recovery: RecoveryKeys,
    acct: VerifiedAccount,
}

fn t(earliest_ms: u64, latest_ms: u64) -> Option<ConfirmedTime> {
    Some(ConfirmedTime {
        earliest_ms,
        latest_ms,
    })
}

fn signed(request: SigningRequest, key: &SigningKey) -> Vec<u8> {
    request
        .finish(key.sign(request.signing_bytes()))
        .unwrap()
        .as_bytes()
        .to_vec()
}

impl Fixture {
    /// The Mac signs up with complete materials and adds the Fold, all before
    /// the account's first confirmed entry.
    fn untimed() -> Self {
        let mac = Device::new();
        let recovery = RecoveryKeys::generate();
        let draft = AccountEvent::genesis(mac.public.clone(), recovery.public());
        let genesis = draft
            .finish(mac.control.sign(draft.signing_bytes()))
            .unwrap();
        let mut acct = VerifiedAccount::from_genesis(
            AccountId::of_genesis(&genesis).unwrap(),
            genesis.as_bytes(),
        )
        .unwrap();
        let record = acct.prepare_recovery_record(mac.id(), [3; 32]).unwrap();
        acct.apply(&signed(record, &mac.control)).unwrap();
        let personal = acct
            .publish_personal_key(mac.id(), KemKey::generate().public(), [4; 32], [5; 32])
            .unwrap();
        acct.apply(&signed(personal, &mac.control)).unwrap();
        let fold = Device::new();
        acct.apply(&add(&acct, &mac, &fold)).unwrap();
        Self {
            mac,
            fold,
            phone: Device::new(),
            recovery,
            acct,
        }
    }
    /// Then the Mac adds the Phone in the first confirmed entry, at 0, so every
    /// device matures at `W`.
    fn new() -> Self {
        let mut f = Self::untimed();
        let bytes = add(&f.acct, &f.mac, &f.phone);
        apply(&mut f.acct, &bytes, t(0, 0));
        f
    }
}

fn apply(acct: &mut VerifiedAccount, bytes: &[u8], time: Option<ConfirmedTime>) -> u64 {
    acct.apply_timed(bytes, time).unwrap();
    acct.head().position
}

fn refused(acct: &VerifiedAccount, bytes: &[u8], time: Option<ConfirmedTime>) -> Error {
    let mut candidate = acct.clone();
    let before = candidate.head();
    let error = candidate.apply_timed(bytes, time).unwrap_err();
    assert_eq!(candidate.head(), before);
    error
}

fn add(acct: &VerifiedAccount, by: &Device, new: &Device) -> Vec<u8> {
    signed(
        acct.add_device(by.id(), new.public.clone()).unwrap(),
        &by.control,
    )
}

fn request(acct: &VerifiedAccount, by: &Device, target: DeviceId) -> Vec<u8> {
    signed(acct.request_removal(by.id(), target).unwrap(), &by.control)
}

fn cancel(acct: &VerifiedAccount, by: &Device, request: u64) -> Vec<u8> {
    signed(acct.cancel_removal(by.id(), request).unwrap(), &by.control)
}

fn rotation(acct: &VerifiedAccount, by: &Device, reason: u64) -> Vec<u8> {
    signed(
        acct.rotate_personal(
            by.id(),
            reason,
            KemKey::generate().public(),
            [8; 32],
            [9; 32],
        )
        .unwrap(),
        &by.ordinary,
    )
}

fn remove_now(
    acct: &VerifiedAccount,
    by: &Device,
    target: DeviceId,
    recovery: &RecoveryKeys,
) -> Vec<u8> {
    let r = acct.remove_now(by.id(), target).unwrap();
    r.finish(
        by.control.sign(&r.device_signing_bytes()),
        r.sign_recovery(recovery),
    )
    .unwrap()
    .as_bytes()
    .to_vec()
}

#[test]
fn wait_starts_at_latest_and_ends_by_earliest() -> Result<(), Error> {
    let mut f = Fixture::untimed();
    let (b, acct) = (f.fold.id(), &mut f.acct);
    let bytes = request(acct, &f.mac, b);
    let r = apply(acct, &bytes, t(100, 104));
    let pending = DeviceState::RemovalPending {
        request: r,
        deadline_ms: 104 + W,
    };
    assert_eq!(acct.device_state(b, 100 + W)?, pending);
    assert_eq!(acct.device_state(b, 104 + W - 1)?, pending);
    assert_eq!(acct.device_state(b, 104 + W)?, DeviceState::Removed);
    assert_eq!(
        acct.pending_removals(104 + W - 1),
        vec![PendingRemoval {
            request: r,
            target: b,
            by: Some(f.mac.id()),
            deadline_ms: 104 + W,
        }]
    );
    assert!(acct.pending_removals(104 + W).is_empty());
    // A query advances a copy; the account itself is unchanged.
    assert!(acct.active_device(b).is_ok());
    assert_eq!(acct.head().position, r);
    Ok(())
}

#[test]
fn mutual_removal_first_deadline_wins_without_rotation() -> Result<(), Error> {
    let mut f = Fixture::new();
    let (a, b, acct) = (f.mac.id(), f.fold.id(), &mut f.acct);
    let bytes = request(acct, &f.mac, b);
    let r_a = apply(acct, &bytes, t(100, 100));
    let bytes = request(acct, &f.fold, a);
    let r_b = apply(acct, &bytes, t(101, 101));
    let at = acct.advanced(100 + W);
    assert_eq!(at.head(), acct.head());
    assert_eq!(at.device_state(b, 100 + W)?, DeviceState::Removed);
    assert_eq!(at.active_device(b).err(), Some(Error::NotActive));
    assert_eq!(at.request_state(r_a, 100 + W)?, RequestState::Effective);
    assert_eq!(at.request_state(r_b, 100 + W)?, RequestState::Lapsed);
    assert_eq!(acct.device_state(a, 101 + W)?, DeviceState::Active);
    assert_eq!(acct.request_state(r_b, 101 + W)?, RequestState::Lapsed);
    assert_eq!(
        acct.rotation_due(101 + W),
        Some(RotationReason::Removal {
            request: r_a,
            target: b
        })
    );
    assert_eq!(acct.rotation_due(100 + W - 1), None);
    Ok(())
}

#[test]
fn equal_deadlines_resolve_by_request_position() -> Result<(), Error> {
    let mut f = Fixture::new();
    let (a, b, acct) = (f.mac.id(), f.fold.id(), &mut f.acct);
    let bytes = request(acct, &f.fold, a);
    let r_b = apply(acct, &bytes, t(100, 100));
    let bytes = request(acct, &f.mac, b);
    let r_a = apply(acct, &bytes, t(100, 100));
    assert_eq!(acct.device_state(a, 100 + W)?, DeviceState::Removed);
    assert_eq!(acct.device_state(b, 100 + W)?, DeviceState::Active);
    assert_eq!(acct.request_state(r_b, 100 + W)?, RequestState::Effective);
    assert_eq!(acct.request_state(r_a, 100 + W)?, RequestState::Lapsed);
    // Applying a later entry establishes the same outcome.
    let bytes = add(acct, &f.fold, &Device::new());
    apply(acct, &bytes, t(100 + W, 100 + W));
    assert_eq!(acct.active_device(a).err(), Some(Error::NotActive));
    assert!(acct.active_device(b).is_ok());
    Ok(())
}

#[test]
fn cancel_strictly_before_the_deadline_keeps_the_device() -> Result<(), Error> {
    let mut f = Fixture::new();
    let (b, acct) = (f.fold.id(), &mut f.acct);
    let bytes = request(acct, &f.mac, b);
    let r = apply(acct, &bytes, t(100, 100));
    let d = 100 + W;
    let bytes = cancel(acct, &f.phone, r);
    apply(acct, &bytes, t(d - 2, d - 1));
    assert_eq!(acct.request_state(r, d + 1)?, RequestState::Cancelled);
    assert_eq!(acct.device_state(b, d + 1)?, DeviceState::Active);
    assert_eq!(acct.rotation_due(d + 1), None);
    assert!(acct.pending_removals(d - 1).is_empty());
    Ok(())
}

#[test]
fn cancel_confirmed_at_or_after_the_deadline_cancels_nothing() -> Result<(), Error> {
    let mut f = Fixture::new();
    let (b, acct) = (f.fold.id(), &mut f.acct);
    let bytes = request(acct, &f.mac, b);
    let r = apply(acct, &bytes, t(100, 100));
    let d = 100 + W;
    let bytes = cancel(acct, &f.phone, r);
    // Applied under the cancel's own rule, which makes it a no-op: the
    // request's state, not the outcome, says whether anything was cancelled.
    assert_eq!(
        acct.apply_timed_with_outcome(&bytes, t(d - 5, d))?,
        ControlOutcome::Applied
    );
    assert!(!acct.is_stopped());
    // The request stays on course: still pending until the deadline is
    // established, then effective.
    assert_eq!(
        acct.request_state(r, d - 1)?,
        RequestState::Pending { deadline_ms: d }
    );
    assert_eq!(acct.request_state(r, d)?, RequestState::Effective);
    assert_eq!(acct.device_state(b, d)?, DeviceState::Removed);
    // A cancel after the request took effect is also a no-op.
    let bytes = cancel(acct, &f.mac, r);
    acct.apply_timed(&bytes, t(d + 1, d + 1))?;
    assert_eq!(acct.request_state(r, d + 1)?, RequestState::Effective);
    assert!(!acct.is_stopped());
    Ok(())
}

#[test]
fn pending_target_stays_active_and_may_sign_until_established() -> Result<(), Error> {
    let mut f = Fixture::new();
    let (b, acct) = (f.fold.id(), &mut f.acct);
    let bytes = request(acct, &f.mac, b);
    apply(acct, &bytes, t(100, 100));
    let d = 100 + W;
    assert!(acct.active_device(b).is_ok());
    let bytes = add(acct, &f.fold, &Device::new());
    acct.clone().apply_timed(&bytes, t(d - 1, d + 3))?;
    // Confirmed once established, it lapses.
    assert_eq!(
        acct.clone().apply_timed_with_outcome(&bytes, t(d, d)),
        Ok(ControlOutcome::Lapsed)
    );
    Ok(())
}

#[test]
fn rotation_fulfils_but_never_activates_a_removal() -> Result<(), Error> {
    let mut f = Fixture::new();
    let (b, acct) = (f.fold.id(), &mut f.acct);
    let bytes = request(acct, &f.mac, b);
    let r = apply(acct, &bytes, t(100, 100));
    let d = 100 + W;
    let early = rotation(acct, &f.mac, r);
    assert_eq!(refused(acct, &early, t(d - 1, d - 1)), Error::TooEarly);
    assert_eq!(acct.device_state(b, d)?, DeviceState::Removed);
    let bytes = rotation(acct, &f.mac, r);
    apply(acct, &bytes, t(d, d));
    assert_eq!(acct.rotation_due(d), None);
    assert_eq!(acct.device_state(b, d)?, DeviceState::Removed);
    assert_eq!(acct.request_state(r, d)?, RequestState::Effective);
    assert_eq!(
        &acct.personal_public()?[..],
        &bytes[bytes.len() - 64 - 64 - 1216..][..1216]
    );
    let again = rotation(acct, &f.mac, r);
    assert_eq!(refused(acct, &again, t(d, d)), Error::NotPermitted);
    Ok(())
}

#[test]
fn one_rotation_fulfils_every_effect_established_by_its_reason() -> Result<(), Error> {
    let mut f = Fixture::new();
    let (b, c, acct) = (f.fold.id(), f.phone.id(), &mut f.acct);
    let bytes = request(acct, &f.mac, b);
    let r1 = apply(acct, &bytes, t(100, 100));
    let bytes = request(acct, &f.mac, c);
    let r2 = apply(acct, &bytes, t(200, 200));
    let (d1, d2) = (100 + W, 200 + W);
    let first = RotationReason::Removal {
        request: r1,
        target: b,
    };
    let second = RotationReason::Removal {
        request: r2,
        target: c,
    };
    assert_eq!(acct.rotation_due(d1 - 1), None);
    assert_eq!(acct.rotation_due(d1), Some(first));
    assert_eq!(acct.rotation_due(d2), Some(first));
    // A rotation for a reason that is not an effect fulfils nothing.
    let unrelated = rotation(acct, &f.mac, 2);
    assert_eq!(refused(acct, &unrelated, t(d2, d2)), Error::NotPermitted);

    // The reason established at D2 fulfils both.
    let mut both = acct.clone();
    let bytes = rotation(&both, &f.mac, r2);
    apply(&mut both, &bytes, t(d2, d2));
    assert_eq!(both.rotation_due(d2), None);
    let again = rotation(&both, &f.mac, r1);
    assert_eq!(refused(&both, &again, t(d2, d2)), Error::NotPermitted);

    // The reason established at D1 leaves D2's due.
    let mut one = acct.clone();
    let bytes = rotation(&one, &f.mac, r1);
    apply(&mut one, &bytes, t(d2, d2));
    assert_eq!(one.rotation_due(d2), Some(second));

    // An effect established at the same time but later in the log stays due.
    let bytes = signed(
        acct.replace_recovery(
            f.mac.id(),
            RecoveryKeys::generate().public(),
            [6; 32],
            [7; 32],
        )?,
        &f.mac.control,
    );
    let replaced = apply(acct, &bytes, t(d2, d2));
    let bytes = rotation(acct, &f.mac, r2);
    apply(acct, &bytes, t(d2, d2));
    assert_eq!(
        acct.rotation_due(d2),
        Some(RotationReason::RecoveryReplaced { position: replaced })
    );
    let bytes = rotation(acct, &f.mac, replaced);
    apply(acct, &bytes, t(d2, d2));
    assert_eq!(acct.rotation_due(d2), None);

    // Order is by establishing time, not log position: an earlier request
    // established after an immediate removal stays due.
    let mut f = Fixture::new();
    let (b, c, acct) = (f.fold.id(), f.phone.id(), &mut f.acct);
    let bytes = request(acct, &f.mac, b);
    let r = apply(acct, &bytes, t(100, 100));
    let bytes = remove_now(acct, &f.mac, c, &f.recovery);
    let now = apply(acct, &bytes, t(W, W));
    let bytes = rotation(acct, &f.mac, now);
    apply(acct, &bytes, t(100 + W, 100 + W));
    assert_eq!(
        acct.rotation_due(100 + W),
        Some(RotationReason::Removal {
            request: r,
            target: b
        })
    );
    Ok(())
}

#[test]
fn a_second_pending_request_for_the_same_pair_is_refused() -> Result<(), Error> {
    let mut f = Fixture::new();
    let (b, acct) = (f.fold.id(), &mut f.acct);
    let bytes = request(acct, &f.mac, b);
    let r = apply(acct, &bytes, t(100, 100));
    let again = request(acct, &f.mac, b);
    assert_eq!(refused(acct, &again, t(101, 101)), Error::NotPermitted);
    // Other requesters, the recovery key among them, may still ask.
    let bytes = request(acct, &f.phone, b);
    apply(acct, &bytes, t(101, 101));
    let by_recovery = |acct: &VerifiedAccount| {
        acct.request_removal_by_recovery(b)
            .unwrap()
            .finish_with_recovery(&f.recovery)
            .unwrap()
            .as_bytes()
            .to_vec()
    };
    let bytes = by_recovery(acct);
    apply(acct, &bytes, t(102, 102));
    let bytes = by_recovery(acct);
    assert_eq!(refused(acct, &bytes, t(103, 103)), Error::NotPermitted);
    // Once the first is no longer pending, the pair may ask again.
    let bytes = cancel(acct, &f.phone, r);
    apply(acct, &bytes, t(W, W));
    assert_eq!(acct.request_state(r, W)?, RequestState::Cancelled);
    let bytes = request(acct, &f.mac, b);
    apply(acct, &bytes, t(W, W));
    assert_eq!(acct.pending_removals(W).len(), 3);
    Ok(())
}

#[test]
fn canceller_must_be_mature_and_not_the_target() -> Result<(), Error> {
    let mut f = Fixture::untimed();
    let tablet = Device::new();
    let (b, acct) = (f.fold.id(), &mut f.acct);
    let bytes = add(acct, &f.mac, &tablet);
    let added = apply(acct, &bytes, t(0, 0));
    let bytes = request(acct, &f.mac, b);
    let r = apply(acct, &bytes, t(1, 1));
    let by_tablet = cancel(acct, &tablet, r);
    // Every device here matures at W, from the first confirmed entry.
    assert_eq!(refused(acct, &by_tablet, t(W - 1, W - 1)), Error::NotMature);
    assert_eq!(
        refused(acct, &cancel(acct, &f.fold, r), t(W, W)),
        Error::NotPermitted
    );
    // Naming a position after the head is refused; naming anything else
    // that is not a pending request is a valid no-op.
    for beyond in [0, acct.head().position + 1] {
        assert_eq!(
            refused(acct, &cancel(acct, &f.mac, beyond), t(W, W)),
            Error::NotPermitted
        );
    }
    let mut no_op = acct.clone();
    no_op.apply_timed(&cancel(acct, &f.mac, added), t(W, W))?;
    assert!(!no_op.is_stopped());
    assert_eq!(no_op.request_state(r, W)?, acct.request_state(r, W)?);
    let mut matured = acct.clone();
    matured.apply_timed(&by_tablet, t(W, W))?;
    assert_eq!(matured.request_state(r, W)?, RequestState::Cancelled);
    let by_recovery = acct
        .cancel_removal_by_recovery(r)?
        .finish_with_recovery(&f.recovery)?;
    acct.apply_timed(by_recovery.as_bytes(), t(W - 1, W - 1))?;
    assert_eq!(acct.request_state(r, W)?, RequestState::Cancelled);
    assert_eq!(acct.device_state(b, 1 + W)?, DeviceState::Active);
    Ok(())
}

#[test]
fn remove_now_requires_a_mature_author_and_takes_effect_at_once() -> Result<(), Error> {
    let mut f = Fixture::untimed();
    let (b, acct) = (f.fold.id(), &mut f.acct);
    let added = acct
        .add_device_by_recovery(f.phone.public.clone())?
        .finish_with_recovery(&f.recovery)?;
    apply(acct, added.as_bytes(), t(5, 9));
    assert_eq!(acct.added_at(f.phone.id()), Some(9));
    let bytes = remove_now(acct, &f.phone, b, &f.recovery);
    assert_eq!(refused(acct, &bytes, t(9 + W - 1, 9 + W)), Error::NotMature);
    let position = apply(acct, &bytes, t(9 + W, 9 + W));
    assert_eq!(acct.device_state(b, 9 + W)?, DeviceState::Removed);
    assert_eq!(acct.active_device(b).err(), Some(Error::NotActive));
    assert_eq!(
        acct.rotation_due(9 + W),
        Some(RotationReason::RemovedNow {
            position,
            target: b
        })
    );
    Ok(())
}

#[test]
fn legacy_devices_mature_from_the_first_confirmed_entry() -> Result<(), Error> {
    let mut f = Fixture::untimed();
    let (a, acct) = (f.mac.id(), &mut f.acct);
    assert_eq!(acct.added_at(a), None);
    assert!(!acct.is_mature(a, u64::MAX));
    let bytes = add(acct, &f.mac, &f.phone);
    apply(acct, &bytes, t(5, 9));
    for device in [a, f.fold.id(), f.phone.id()] {
        assert_eq!(acct.added_at(device), Some(9));
        assert!(!acct.is_mature(device, 9 + W - 1));
        assert!(acct.is_mature(device, 9 + W));
    }
    let tablet = Device::new();
    let bytes = add(acct, &f.mac, &tablet);
    apply(acct, &bytes, t(20, 30));
    assert_eq!(acct.added_at(tablet.id()), Some(30));
    assert_eq!(acct.added_at(DeviceId([1; 32])), None);
    Ok(())
}

#[test]
fn after_the_first_confirmed_entry_every_entry_needs_a_confirmation() -> Result<(), Error> {
    let mut f = Fixture::untimed();
    let acct = &mut f.acct;
    // Before it, only device-signed setup, additions and self-removal may be untimed.
    let by_recovery = acct
        .add_device_by_recovery(Device::new().public)?
        .finish_with_recovery(&f.recovery)?;
    assert_eq!(
        refused(acct, by_recovery.as_bytes(), None),
        Error::MissingTime
    );
    let bytes = request(acct, &f.mac, f.fold.id());
    assert_eq!(refused(acct, &bytes, None), Error::MissingTime);
    acct.clone()
        .apply_timed(&add(acct, &f.mac, &Device::new()), None)?;
    let bytes = add(acct, &f.mac, &f.phone);
    apply(acct, &bytes, t(5, 9));
    let late = add(acct, &f.mac, &Device::new());
    let mut candidate = acct.clone();
    assert_eq!(candidate.apply_timed(&late, None), Err(Error::MissingTime));
    // A missing confirmation is not invalid history: retry once it arrives.
    assert!(!candidate.is_stopped());
    candidate.apply_timed(&late, t(10, 10))?;
    Ok(())
}

#[test]
fn request_lapses_when_its_requester_is_removed_first() -> Result<(), Error> {
    let mut f = Fixture::new();
    let (b, c, acct) = (f.fold.id(), f.phone.id(), &mut f.acct);
    let bytes = request(acct, &f.fold, c);
    let r = apply(acct, &bytes, t(100, 100));
    let bytes = signed(acct.remove_self(b)?, &f.fold.control);
    apply(acct, &bytes, t(200, 200));
    assert_eq!(acct.request_state(r, 200)?, RequestState::Lapsed);
    assert_eq!(acct.device_state(c, 100 + W)?, DeviceState::Active);
    assert_eq!(acct.device_state(b, 200)?, DeviceState::Removed);
    assert!(acct.pending_removals(200).is_empty());
    Ok(())
}

#[test]
fn replace_recovery_and_remove_self_are_due_for_rotation_at_once() -> Result<(), Error> {
    let mut f = Fixture::new();
    let (b, acct) = (f.fold.id(), &mut f.acct);
    let bytes = signed(
        acct.replace_recovery(
            f.mac.id(),
            RecoveryKeys::generate().public(),
            [6; 32],
            [7; 32],
        )?,
        &f.mac.control,
    );
    let replaced = apply(acct, &bytes, t(10, 10));
    assert_eq!(
        acct.rotation_due(10),
        Some(RotationReason::RecoveryReplaced { position: replaced })
    );
    let bytes = rotation(acct, &f.mac, replaced);
    apply(acct, &bytes, t(10, 10));
    assert_eq!(acct.rotation_due(10), None);
    let bytes = signed(acct.remove_self(b)?, &f.fold.control);
    let left = apply(acct, &bytes, t(20, 20));
    assert_eq!(
        acct.rotation_due(20),
        Some(RotationReason::RemovedSelf {
            position: left,
            device: b
        })
    );
    Ok(())
}

#[test]
fn times_never_go_backwards() {
    let mut f = Fixture::new();
    let acct = &mut f.acct;
    let bytes = add(acct, &f.mac, &Device::new());
    apply(acct, &bytes, t(100, 200));
    let ev = add(acct, &f.mac, &Device::new());
    assert_eq!(
        acct.clone().apply_timed(&ev, t(99, 200)).err(),
        Some(Error::TimeRegressed)
    );
    assert_eq!(
        acct.clone().apply_timed(&ev, t(100, 199)).err(),
        Some(Error::TimeRegressed)
    );
    // Bounds whose earliest follows their latest are not a confirmation.
    assert_eq!(
        acct.clone().apply_timed(&ev, t(301, 300)).err(),
        Some(Error::Malformed)
    );
    acct.apply_timed(&ev, t(100, 200)).unwrap();
}

#[test]
fn queries_beyond_the_head_or_on_unknown_devices_are_refused() {
    let f = Fixture::new();
    let head = f.acct.head().position;
    for beyond in [0, head + 1] {
        assert_eq!(
            f.acct.request_state(beyond, 0).err(),
            Some(Error::NotPermitted)
        );
    }
    // A position that is not a pending request is indistinguishable from a
    // request resolved before this projection was loaded.
    assert_eq!(f.acct.request_state(2, 0), Ok(RequestState::Resolved));
    assert_eq!(
        f.acct.device_state(DeviceId([1; 32]), 0).err(),
        Some(Error::NotActive)
    );
}
