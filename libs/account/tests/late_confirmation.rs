//! Entries confirmed only after their author lost authority to a removal's
//! deadline: authentic, well-formed ones lapse with no effect and the account
//! keeps working; anything else is still refused.
use bh_account::{
    AccountEvent, AccountId, ConfirmedTime, ControlOutcome, DeviceId, DevicePublicKeys,
    DeviceState, Error, Head, REMOVAL_WAIT_MS as W, RecoveryPublicKeys, RequestState,
    RotationReason, SigningRequest, VerifiedAccount,
    crypto::{KemKey, SigningKey},
    journal::AccountJournal,
    storage::DeviceJournal,
};

const DOMAIN: &[u8] = b"BaseHero account event\0";
const POSITION_AT: usize = DOMAIN.len() + 2 + 2;
const PREVIOUS_AT: usize = POSITION_AT + 8;
const COSIGN_DOMAIN: &[u8] = b"BaseHero account cosign\0";

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

fn add(acct: &VerifiedAccount, by: &Device, new: &Device) -> Vec<u8> {
    signed(
        acct.add_device(by.id(), new.public.clone()).unwrap(),
        &by.control,
    )
}

fn head_of(bytes: &[u8]) -> Head {
    AccountEvent::decode(bytes).unwrap().head()
}

/// Replace the only occurrence of `from` in the signed part, then sign the
/// result with `key`: a real signature over altered bytes.
fn altered(bytes: &[u8], from: &[u8], to: &[u8], key: &SigningKey) -> Vec<u8> {
    let mut unsigned = bytes[..bytes.len() - 64].to_vec();
    let at: Vec<_> = (0..=unsigned.len() - from.len())
        .filter(|&i| unsigned[i..i + from.len()] == *from)
        .collect();
    assert_eq!(at.len(), 1, "one occurrence to replace");
    unsigned.splice(at[0]..at[0] + from.len(), to.iter().copied());
    let signature = key.sign(&unsigned);
    [unsigned, signature.to_vec()].concat()
}

fn resigned(mut bytes: Vec<u8>, key: &SigningKey) -> Vec<u8> {
    let split = bytes.len() - 64;
    let signature = key.sign(&bytes[..split]);
    bytes[split..].copy_from_slice(&signature);
    bytes
}

/// Refused on a candidate: no outcome, the head unchanged, and the account
/// stopped as for any other invalid history.
fn refused(acct: &VerifiedAccount, bytes: &[u8], time: Option<ConfirmedTime>) -> Error {
    let mut candidate = acct.clone();
    let error = candidate.apply_timed_with_outcome(bytes, time).unwrap_err();
    assert_eq!(candidate.head(), acct.head());
    assert!(candidate.is_stopped(), "{error:?} stops the account");
    error
}

/// The Mac signs up and adds the Fold, then the Phone in the first confirmed
/// entry, at 0. At 100 the Mac's request to remove the Fold is confirmed, so
/// the Fold loses its authority at `D`.
struct Late {
    mac: Device,
    fold: Device,
    phone: Device,
    tablet: Device,
    anchor: AccountId,
    /// Original signed entries with their confirmed times, as a store keeps them.
    entries: Vec<(Vec<u8>, Option<ConfirmedTime>)>,
    acct: VerifiedAccount,
    request: u64,
    /// The recovery key's signing half, so tests can cosign any bytes.
    recovery: SigningKey,
}
const D: u64 = 100 + W;

impl Late {
    fn new() -> Self {
        Self::with(|_| {})
    }
    /// `new`, with `prelude` run just before the Fold's removal is requested.
    fn with(prelude: impl FnOnce(&mut Self)) -> Self {
        let (mac, fold, phone) = (Device::new(), Device::new(), Device::new());
        let recovery = SigningKey::generate();
        let recovery_public =
            RecoveryPublicKeys::new(recovery.public(), KemKey::generate().public());
        let genesis = signed(
            AccountEvent::genesis(mac.public.clone(), recovery_public),
            &mac.control,
        );
        let anchor = AccountId::of_genesis(&AccountEvent::decode(&genesis).unwrap()).unwrap();
        let acct = VerifiedAccount::from_genesis(anchor, &genesis).unwrap();
        let mut late = Self {
            mac,
            fold,
            phone,
            tablet: Device::new(),
            anchor,
            entries: vec![(genesis, None)],
            acct,
            request: 0,
            recovery,
        };
        let record = late
            .acct
            .prepare_recovery_record(late.mac.id(), [3; 32])
            .unwrap();
        late.push(signed(record, &late.mac.control), None);
        let personal = late
            .acct
            .publish_personal_key(late.mac.id(), KemKey::generate().public(), [4; 32], [5; 32])
            .unwrap();
        late.push(signed(personal, &late.mac.control), None);
        late.push(add(&late.acct, &late.mac, &late.fold), None);
        late.push(add(&late.acct, &late.mac, &late.phone), t(0, 0));
        prelude(&mut late);
        let request = late
            .acct
            .request_removal(late.mac.id(), late.fold.id())
            .unwrap();
        late.push(signed(request, &late.mac.control), t(100, 100));
        late.request = late.acct.head().position;
        late
    }
    /// Apply and record an entry, returning its outcome.
    fn push(&mut self, bytes: Vec<u8>, time: Option<ConfirmedTime>) -> ControlOutcome {
        let outcome = self.acct.apply_timed_with_outcome(&bytes, time).unwrap();
        self.entries.push((bytes, time));
        outcome
    }
    /// The Fold's addition of the Tablet, signed while it still had authority.
    fn fold_adds_tablet(&self) -> Vec<u8> {
        add(&self.acct, &self.fold, &self.tablet)
    }
    /// A replay of the first `len` recorded entries.
    fn replayed(&self, len: usize) -> VerifiedAccount {
        let history: Vec<_> = self.entries[..len]
            .iter()
            .map(|(bytes, time)| (bytes.as_slice(), *time))
            .collect();
        let head = head_of(&self.entries[len - 1].0);
        VerifiedAccount::replay_timed(self.anchor, &history, head).unwrap()
    }
    fn active(view: &VerifiedAccount) -> Vec<[u8; 32]> {
        view.active_devices().unwrap().map(|k| k.id().0).collect()
    }
}

#[test]
fn an_addition_confirmed_after_its_author_lost_authority_lapses() {
    let mut late = Late::new();
    let (fold, tablet) = (late.fold.id(), late.tablet.id());
    let bytes = late.fold_adds_tablet();
    let lapsed_at = late.entries.len();
    let position = late.acct.head().position + 1;
    assert_eq!(
        late.push(bytes.clone(), t(D + 1, D + 1)),
        ControlOutcome::Lapsed
    );

    // The original is history at its position; the account keeps running.
    let acct = &late.acct;
    assert!(!acct.is_stopped());
    assert_eq!(acct.head(), head_of(&bytes));
    assert_eq!(acct.head().position, position);
    // No Tablet: not active, never seen, not a member at its entry.
    assert_eq!(acct.active_device(tablet).err(), Some(Error::NotActive));
    assert_eq!(acct.seen_device(tablet), Ok(false));
    assert_eq!(acct.active_at(tablet, position), Ok(false));
    assert_eq!(acct.added_at(tablet), None);
    // The deadline's removal stands, and its rotation is due.
    assert_eq!(acct.active_device(fold).err(), Some(Error::NotActive));
    assert_eq!(acct.device_state(fold, D + 1), Ok(DeviceState::Removed));
    assert_eq!(
        acct.request_state(late.request, D + 1),
        Ok(RequestState::Effective)
    );
    let due = Some(RotationReason::Removal {
        request: late.request,
        target: fold,
    });
    assert_eq!(acct.rotation_due(D + 1), due);
    assert_eq!(
        Late::active(acct),
        Late::active(&late.replayed(lapsed_at + 1))
    );

    // A replay of the same prefix reaches the same outcome.
    let mut prefix = late.replayed(lapsed_at);
    assert_eq!(
        prefix.apply_timed_with_outcome(&bytes, t(D + 1, D + 1)),
        Ok(ControlOutcome::Lapsed)
    );
    assert_eq!(prefix.head(), late.acct.head());

    // The Mac, still in the account, appends the next entry: the Tablet again,
    // with the same keys.
    let retry = add(&late.acct, &late.mac, &late.tablet);
    assert_eq!(late.push(retry, t(D + 2, D + 2)), ControlOutcome::Applied);
    assert_eq!(
        late.acct.active_at(tablet, late.acct.head().position),
        Ok(true)
    );
    let replayed = late.replayed(late.entries.len());
    assert_eq!(replayed.head(), late.acct.head());
    assert_eq!(Late::active(&replayed), Late::active(&late.acct));
    assert_eq!(replayed.active_at(tablet, position), Ok(false));
    assert_eq!(replayed.rotation_due(D + 2), due);
}

#[test]
fn an_addition_confirmed_before_the_deadline_still_applies() {
    let mut late = Late::new();
    let bytes = late.fold_adds_tablet();
    // Judged at its earliest time, even if its latest is past the deadline.
    let mut spanning = late.acct.clone();
    assert_eq!(
        spanning.apply_timed_with_outcome(&bytes, t(D - 1, D + 3)),
        Ok(ControlOutcome::Applied)
    );
    assert_eq!(late.push(bytes, t(D - 1, D - 1)), ControlOutcome::Applied);
    assert!(late.acct.active_device(late.tablet.id()).is_ok());
    // The Fold's removal still follows; the Tablet it added stays.
    let next = add(&late.acct, &late.mac, &Device::new());
    assert_eq!(late.push(next, t(D, D)), ControlOutcome::Applied);
    assert_eq!(
        late.acct.active_device(late.fold.id()).err(),
        Some(Error::NotActive)
    );
    assert!(late.acct.active_device(late.tablet.id()).is_ok());
}

#[test]
fn only_authentic_well_formed_history_lapses() {
    let late = Late::new();
    let (acct, fold) = (&late.acct, &late.fold.control);
    let late_time = t(D + 1, D + 1);
    let bytes = late.fold_adds_tablet();
    let tablet = &late.tablet.public;
    let phone = &late.phone.public;

    let mut corrupted = bytes.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    assert_eq!(refused(acct, &corrupted, late_time), Error::BadSignature);
    let ordinary = resigned(bytes.clone(), &late.fold.ordinary);
    assert_eq!(refused(acct, &ordinary, late_time), Error::BadSignature);

    let mut skipped = bytes.clone();
    skipped[POSITION_AT..PREVIOUS_AT].copy_from_slice(&(acct.head().position + 2).to_be_bytes());
    let skipped = resigned(skipped, fold);
    assert_eq!(refused(acct, &skipped, late_time), Error::WrongPredecessor);
    let forked = altered(&bytes, &acct.head().hash, &[7; 32], fold);
    assert_eq!(refused(acct, &forked, late_time), Error::Fork);

    let trailing = [bytes.as_slice(), &[0]].concat();
    assert_eq!(refused(acct, &trailing, late_time), Error::Malformed);
    assert_eq!(
        refused(acct, &bytes[..bytes.len() - 1], late_time),
        Error::Malformed
    );

    // Admissions reusing a key or a device, each really signed by the Fold.
    let reused = altered(&bytes, tablet.receiving(), phone.receiving(), fold);
    assert_eq!(refused(acct, &reused, late_time), Error::KeyReuse);
    let same_keys = altered(&bytes, tablet.control(), tablet.signing(), fold);
    assert_eq!(refused(acct, &same_keys, late_time), Error::KeyReuse);
    let phone_keys = [
        phone.signing().as_slice(),
        phone.control(),
        phone.receiving(),
    ]
    .concat();
    let tablet_keys = [
        tablet.signing().as_slice(),
        tablet.control(),
        tablet.receiving(),
    ]
    .concat();
    let duplicate = altered(&bytes, &tablet_keys, &phone_keys, fold);
    assert_eq!(refused(acct, &duplicate, late_time), Error::DuplicateDevice);

    // A device that never joined.
    let stranger = altered(
        &bytes,
        &late.fold.id().0,
        &late.tablet.id().0,
        &late.tablet.control,
    );
    assert_eq!(refused(acct, &stranger, late_time), Error::NotActive);

    // An author whose removal an earlier entry already established. The same
    // entry confirmed before the deadline has the same head, so the Fold can
    // sign its successor.
    let next = add(acct, &late.mac, &Device::new());
    let mut removed = acct.clone();
    removed.apply_timed(&next, t(D, D)).unwrap();
    let mut before = acct.clone();
    before.apply_timed(&next, t(D - 1, D - 1)).unwrap();
    assert_eq!(before.head(), removed.head());
    let after_removal = add(&before, &late.fold, &late.tablet);
    assert_eq!(
        refused(&removed, &after_removal, t(D + 1, D + 1)),
        Error::NotActive
    );
}

#[test]
fn a_lapsed_authors_other_controls_have_no_effect() {
    let late = Late::new();
    let (acct, fold) = (&late.acct, &late.fold);
    let late_time = t(D + 1, D + 1);
    let personal = *acct.personal_public().unwrap();
    let due = Some(RotationReason::Removal {
        request: late.request,
        target: fold.id(),
    });
    let rotation = |public: [u8; 1216]| {
        signed(
            acct.rotate_personal(fold.id(), late.request, public, [8; 32], [9; 32])
                .unwrap(),
            &fold.ordinary,
        )
    };
    let controls = [
        signed(
            acct.request_removal(fold.id(), late.phone.id()).unwrap(),
            &fold.control,
        ),
        // Naming a position that is not a pending request: a valid no-op.
        signed(acct.cancel_removal(fold.id(), 2).unwrap(), &fold.control),
        signed(acct.remove_self(fold.id()).unwrap(), &fold.control),
        rotation(KemKey::generate().public()),
    ];
    for bytes in controls {
        let mut view = acct.clone();
        assert_eq!(
            view.apply_timed_with_outcome(&bytes, late_time),
            Ok(ControlOutcome::Lapsed)
        );
        assert_eq!(view.head(), head_of(&bytes));
        assert!(view.pending_removals(D + 1).is_empty());
        assert_eq!(
            view.request_state(late.request, D + 1),
            Ok(RequestState::Effective)
        );
        assert_eq!(view.rotation_due(D + 1), due, "nothing fulfilled or added");
        assert_eq!(view.personal_public(), Ok(&personal));
        assert_eq!(Late::active(&view).len(), 2);
    }
    // Requirements that do not depend on time are still checked.
    assert_eq!(
        refused(acct, &rotation(personal), late_time),
        Error::KeyReuse
    );
}

#[test]
fn a_late_cancel_of_its_authors_own_pending_removal_is_refused() {
    let late = Late::new();
    let (acct, fold) = (&late.acct, &late.fold);
    let own = signed(
        acct.cancel_removal(fold.id(), late.request).unwrap(),
        &fold.control,
    );
    // Invalid when signed, so a later deadline never makes it a lapse.
    for time in [t(D - 1, D - 1), t(D + 1, D + 1)] {
        assert_eq!(refused(acct, &own, time), Error::NotPermitted);
    }
    // The Phone and the recovery key may still cancel it.
    let phone = signed(
        acct.cancel_removal(late.phone.id(), late.request).unwrap(),
        &late.phone.control,
    );
    let recovery = signed(
        acct.cancel_removal_by_recovery(late.request).unwrap(),
        &late.recovery,
    );
    for bytes in [phone, recovery] {
        let mut view = acct.clone();
        assert_eq!(
            view.apply_timed_with_outcome(&bytes, t(D - 1, D - 1)),
            Ok(ControlOutcome::Applied)
        );
        assert_eq!(
            view.request_state(late.request, D + 1),
            Ok(RequestState::Cancelled)
        );
    }
}

/// `author`'s immediate removal of `target`, cosigned by its second key and
/// the recovery key over exactly these bytes.
fn removes_now(late: &Late, author: &Device, target: DeviceId) -> Vec<u8> {
    let r = late.acct.remove_now(author.id(), late.phone.id()).unwrap();
    let unsigned = &r.device_signing_bytes()[COSIGN_DOMAIN.len() + 1..];
    let at = unsigned.len() - 32;
    assert_eq!(
        unsigned[at..],
        late.phone.id().0,
        "the target ends the body"
    );
    let unsigned = [&unsigned[..at], &target.0].concat();
    let cosign =
        |role: u8, key: &SigningKey| key.sign(&[COSIGN_DOMAIN, &[role], &unsigned].concat());
    [
        unsigned.clone(),
        cosign(1, &author.control).to_vec(),
        cosign(2, &late.recovery).to_vec(),
    ]
    .concat()
}

#[test]
fn late_controls_naming_a_target_absent_before_them_are_refused() {
    // The Gone joins at 10 and leaves at 20, before the Fold's removal request.
    let gone = Device::new();
    let late = Late::with(|late| {
        let bytes = add(&late.acct, &late.mac, &gone);
        late.push(bytes, t(10, 10));
        let bytes = signed(late.acct.remove_self(gone.id()).unwrap(), &gone.control);
        late.push(bytes, t(20, 20));
    });
    let (acct, fold, phone) = (&late.acct, &late.fold, late.phone.id());
    let late_time = t(D + 1, D + 1);
    // The same controls naming the Phone, still a member, lapse.
    let request = signed(
        acct.request_removal(fold.id(), phone).unwrap(),
        &fold.control,
    );
    let mut view = acct.clone();
    assert_eq!(
        view.apply_timed_with_outcome(&request, late_time),
        Ok(ControlOutcome::Lapsed)
    );
    let mut view = acct.clone();
    assert_eq!(
        view.apply_timed_with_outcome(&removes_now(&late, fold, phone), late_time),
        Ok(ControlOutcome::Lapsed)
    );
    // Naming a device that was never a member, or had already left, each
    // really signed, is refused rather than lapsed.
    for target in [late.tablet.id(), gone.id()] {
        let named = altered(&request, &phone.0, &target.0, &fold.control);
        assert_eq!(refused(acct, &named, late_time), Error::NotActive);
        let now = removes_now(&late, fold, target);
        assert_eq!(refused(acct, &now, late_time), Error::NotActive);
    }
}

#[test]
fn a_late_rotation_must_name_an_outstanding_reason() {
    // At 10 the Mac replaces the recovery key and at 20 rotates for it; at
    // 30 it asks to remove the Phone, which the new recovery key cancels at 40.
    let (mut fulfilled, mut cancelled) = (0, 0);
    let late = Late::with(|late| {
        let next = SigningKey::generate();
        let public = RecoveryPublicKeys::new(next.public(), KemKey::generate().public());
        let request = late
            .acct
            .replace_recovery(late.mac.id(), public, [6; 32], [7; 32])
            .unwrap();
        late.push(signed(request, &late.mac.control), t(10, 10));
        fulfilled = late.acct.head().position;
        let request = late
            .acct
            .rotate_personal(
                late.mac.id(),
                fulfilled,
                KemKey::generate().public(),
                [8; 32],
                [9; 32],
            )
            .unwrap();
        late.push(signed(request, &late.mac.ordinary), t(20, 20));
        let request = late
            .acct
            .request_removal(late.mac.id(), late.phone.id())
            .unwrap();
        late.push(signed(request, &late.mac.control), t(30, 30));
        cancelled = late.acct.head().position;
        let request = late.acct.cancel_removal_by_recovery(cancelled).unwrap();
        late.push(signed(request, &next), t(40, 40));
        late.recovery = next;
    });
    let (acct, fold) = (&late.acct, &late.fold);
    assert_eq!(
        acct.request_state(cancelled, 40),
        Ok(RequestState::Cancelled)
    );
    let rotation = |reason: u64| {
        signed(
            acct.rotate_personal(
                fold.id(),
                reason,
                KemKey::generate().public(),
                [8; 32],
                [9; 32],
            )
            .unwrap(),
            &fold.ordinary,
        )
    };
    let late_time = t(D + 1, D + 1);
    // For the request still pending before it, it lapses.
    let mut view = acct.clone();
    assert_eq!(
        view.apply_timed_with_outcome(&rotation(late.request), late_time),
        Ok(ControlOutcome::Lapsed)
    );
    // An unknown, fulfilled or cancelled reason is refused rather than lapsed.
    for reason in [2, acct.head().position + 1, fulfilled, cancelled] {
        assert_eq!(
            refused(acct, &rotation(reason), late_time),
            Error::NotPermitted,
            "reason {reason}"
        );
    }
}

#[test]
fn a_late_removal_whose_target_its_deadline_removed_lapses() {
    let late_time = t(D + 1, D + 1);
    // The Phone's request, the recovery key's request and the Mac's cosigned
    // immediate removal, each naming the Fold while it was still a member.
    for kind in 0..3 {
        let mut late = Late::new();
        let fold = late.fold.id();
        let bytes = match kind {
            0 => signed(
                late.acct.request_removal(late.phone.id(), fold).unwrap(),
                &late.phone.control,
            ),
            1 => signed(
                late.acct.request_removal_by_recovery(fold).unwrap(),
                &late.recovery,
            ),
            _ => removes_now(&late, &late.mac, fold),
        };
        // Before the deadline it applies as usual.
        let mut view = late.acct.clone();
        assert_eq!(
            view.apply_timed_with_outcome(&bytes, t(D - 1, D - 1)),
            Ok(ControlOutcome::Applied),
            "kind {kind}"
        );

        let lapsed_at = late.entries.len();
        assert_eq!(
            late.push(bytes.clone(), late_time),
            ControlOutcome::Lapsed,
            "kind {kind}"
        );
        // The original is history at its position; the deadline's removal
        // stands and nothing else was removed, requested or made due.
        let acct = &late.acct;
        assert!(!acct.is_stopped());
        assert_eq!(acct.head(), head_of(&bytes));
        assert_eq!(acct.device_state(fold, D + 1), Ok(DeviceState::Removed));
        assert_eq!(
            acct.request_state(late.request, D + 1),
            Ok(RequestState::Effective)
        );
        assert!(acct.pending_removals(D + 1).is_empty());
        let due = Some(RotationReason::Removal {
            request: late.request,
            target: fold,
        });
        assert_eq!(acct.rotation_due(D + 1), due);
        let mut survivors = vec![late.mac.id().0, late.phone.id().0];
        survivors.sort();
        assert_eq!(Late::active(acct), survivors);
        // A replay of the same prefix reaches the same outcome.
        let mut prefix = late.replayed(lapsed_at);
        assert_eq!(
            prefix.apply_timed_with_outcome(&bytes, late_time),
            Ok(ControlOutcome::Lapsed)
        );
        assert_eq!(prefix.head(), late.acct.head());

        // The Mac appends the next entry, and the whole history replays.
        let next = add(&late.acct, &late.mac, &late.tablet);
        assert_eq!(late.push(next, t(D + 2, D + 2)), ControlOutcome::Applied);
        let replayed = late.replayed(late.entries.len());
        assert_eq!(replayed.head(), late.acct.head());
        assert_eq!(Late::active(&replayed), Late::active(&late.acct));
        assert_eq!(replayed.rotation_due(D + 2), due);
    }
}

#[test]
fn late_controls_against_a_removed_target_keep_their_existing_outcomes() {
    let late = Late::new();
    let acct = &late.acct;
    // A request against the Fold after an earlier entry's deadline removed it
    // is refused. Confirmed before the deadline, that entry has the same head,
    // so the Phone can sign the request as its successor.
    let next = add(acct, &late.mac, &Device::new());
    let mut removed = acct.clone();
    removed.apply_timed(&next, t(D, D)).unwrap();
    let mut before = acct.clone();
    before.apply_timed(&next, t(D - 1, D - 1)).unwrap();
    let request = signed(
        before
            .request_removal(late.phone.id(), late.fold.id())
            .unwrap(),
        &late.phone.control,
    );
    assert_eq!(
        refused(&removed, &request, t(D + 1, D + 1)),
        Error::NotActive
    );
    // A cancel confirmed after the deadline is applied, as the no-op its own
    // rule makes it: `Applied` is not a cancellation. The request was pending
    // before it and is effective, not cancelled, after it.
    let cancel = signed(
        acct.cancel_removal(late.mac.id(), late.request).unwrap(),
        &late.mac.control,
    );
    let pending = RequestState::Pending { deadline_ms: D };
    assert_eq!(acct.request_state(late.request, D - 1), Ok(pending));
    let mut view = acct.clone();
    assert_eq!(
        view.apply_timed_with_outcome(&cancel, t(D + 1, D + 1)),
        Ok(ControlOutcome::Applied)
    );
    assert_eq!(
        view.request_state(late.request, D + 1),
        Ok(RequestState::Effective)
    );
    // Only pending before and cancelled after is a cancellation.
    let mut view = acct.clone();
    assert_eq!(
        view.apply_timed_with_outcome(&cancel, t(D - 1, D - 1)),
        Ok(ControlOutcome::Applied)
    );
    assert_eq!(
        view.request_state(late.request, D + 1),
        Ok(RequestState::Cancelled)
    );
}

#[test]
fn a_batch_reports_each_outcome_and_rolls_back_on_an_invalid_tail() {
    let late = Late::new();
    let lapsed = late.fold_adds_tablet();
    let mut after = late.acct.clone();
    after.apply_timed(&lapsed, t(D + 1, D + 1)).expect("lapses");
    let retry = add(&after, &late.mac, &late.tablet);
    let (view, outcomes) = late
        .acct
        .clone()
        .applied_batch_timed_with_outcomes(&[(&lapsed, t(D + 1, D + 1)), (&retry, t(D + 2, D + 2))])
        .unwrap();
    assert_eq!(outcomes, [ControlOutcome::Lapsed, ControlOutcome::Applied]);
    assert_eq!(view.head(), head_of(&retry));
    assert!(view.active_device(late.tablet.id()).is_ok());

    let mut invalid = retry.clone();
    *invalid.last_mut().unwrap() ^= 1;
    let result = late.acct.clone().applied_batch_timed_with_outcomes(&[
        (&lapsed, t(D + 1, D + 1)),
        (&invalid, t(D + 2, D + 2)),
    ]);
    assert_eq!(result.err(), Some(Error::BadSignature));
    // Applied one by one, the lapse is kept and the invalid entry stops the
    // account at it.
    let mut mutable = late.acct.clone();
    assert_eq!(
        mutable.apply_timed_with_outcome(&lapsed, t(D + 1, D + 1)),
        Ok(ControlOutcome::Lapsed)
    );
    assert_eq!(
        refused(&mutable, &invalid, t(D + 2, D + 2)),
        Error::BadSignature
    );
}

#[test]
fn a_reloaded_projection_keeps_the_lapse() {
    let mut late = Late::new();
    let lapsed = late.fold_adds_tablet();
    late.push(lapsed, t(D + 1, D + 1));

    let dir = tempfile::tempdir().unwrap();
    let mut journal = DeviceJournal::open(dir.path().join("account.sqlite")).unwrap();
    let genesis = &late.entries[0].0;
    journal
        .commit_verified(late.anchor, &[genesis], head_of(genesis), false)
        .unwrap();
    let mut view = journal.load_projection().unwrap().unwrap().account;
    let rest = &late.entries[1..];
    for (bytes, time) in rest {
        view.apply_timed(bytes, *time).unwrap();
    }
    let events: Vec<_> = rest.iter().map(|(bytes, _)| bytes.as_slice()).collect();
    let evidence: Vec<_> = rest
        .iter()
        .map(|(_, time)| time.map(|time| (time, b"verified confirmation fixture".to_vec())))
        .collect();
    journal
        .commit_timed_fenced(
            late.anchor,
            &events,
            &evidence,
            view.head(),
            false,
            Some(&view),
            |ok| assert!(ok),
        )
        .unwrap();

    let mut loaded = journal.load_projection().unwrap().unwrap().account;
    assert_eq!(loaded.head(), late.acct.head());
    assert_eq!(Late::active(&loaded), Late::active(&late.acct));
    assert_eq!(loaded.seen_device(late.tablet.id()), Ok(false));
    // The stored index never recorded the lapsed addition's keys.
    let retry = add(&loaded, &late.mac, &late.tablet);
    assert_eq!(
        loaded.apply_timed_with_outcome(&retry, t(D + 2, D + 2)),
        Ok(ControlOutcome::Applied)
    );
}
