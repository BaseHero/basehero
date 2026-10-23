//! Choosing a rotation's reason, and staging signed trust controls before
//! their order: what is staged survives restart, is never accepted early,
//! and settles once verified history holds its position.
#[path = "support/account.rs"]
mod account;
#[path = "support/owner_db.rs"]
mod owner_db;
#[allow(dead_code)]
#[path = "support/protector.rs"]
mod protector;
#[path = "support/store.rs"]
mod store;

use account::{Device, account, add as add_device, signed, t};
use bh_account::journal::{AccountJournal, JournalError, StagedControl};
use bh_account::owner::OwnerError;
use bh_account::owner::staging::Settled;
use bh_account::personal::{PersonalKey, prepare_rotation, verify_rotation_body};
use bh_account::{
    AccountChange, AccountEvent, ConfirmedTime, DeviceState, Error, REMOVAL_WAIT_MS as W,
    RotationReason,
};
use owner_db::{Harness, Other, Owner, add, apply, apply_at, ready};

// ---- The reason a rotation gives ----

#[test]
fn rotation_reason_is_the_latest_due_effect_and_one_rotation_fulfils_all() {
    let mut a = account("correct horse");
    let (b, c, e) = (Device::new(), Device::new(), Device::new());
    for (device, ms) in [(&b, 10), (&c, 11), (&e, 12)] {
        let added = add_device(&a.acct, &a.mac, device);
        a.acct.apply_timed(added.as_bytes(), t(ms, ms)).unwrap();
    }
    // A removal request established at its deadline, after two immediate
    // removals with later positions.
    let request = signed(
        a.acct.request_removal(a.mac.id(), e.id()).unwrap(),
        &a.mac.control,
    );
    a.acct.apply_timed(request.as_bytes(), t(20, 20)).unwrap();
    let r = a.acct.head().position;
    let mut left = Vec::new();
    for (device, ms) in [(&b, 100), (&c, 200)] {
        let leave = signed(a.acct.remove_self(device.id()).unwrap(), &device.control);
        a.acct.apply_timed(leave.as_bytes(), t(ms, ms)).unwrap();
        left.push(RotationReason::RemovedSelf {
            position: a.acct.head().position,
            device: device.id(),
        });
    }
    let deadline = 20 + W;
    let removal = RotationReason::Removal {
        request: r,
        target: e.id(),
    };
    assert_eq!(a.acct.rotation_reason(deadline), Some(removal));
    assert_eq!(a.acct.rotation_reason(deadline - 1), Some(left[1]));
    assert_eq!(a.acct.rotation_reason(150), Some(left[0]));
    // Unchanged: `rotation_due` names the earliest.
    assert_eq!(a.acct.rotation_due(deadline), Some(left[0]));

    let after = a.acct.advanced(deadline);
    let next = PersonalKey::generate();
    let prepared = prepare_rotation(&after, &next).unwrap();
    let rotation = signed(
        a.acct
            .rotate_personal(
                a.mac.id(),
                removal.position(),
                prepared.public,
                prepared.device_seals_digest,
                prepared.recovery_seal_digest,
            )
            .unwrap(),
        &a.mac.ordinary,
    );
    verify_rotation_body(&after, &rotation, &prepared.body).unwrap();
    a.acct
        .apply_timed(rotation.as_bytes(), t(deadline, deadline))
        .unwrap();
    assert_eq!(a.acct.rotation_due(deadline), None);
    assert_eq!(a.acct.rotation_reason(deadline), None);
}

#[test]
fn an_effect_established_after_the_time_is_not_a_reason() {
    let mut a = account("correct horse");
    let b = Device::new();
    let added = add_device(&a.acct, &a.mac, &b);
    a.acct.apply_timed(added.as_bytes(), t(10, 10)).unwrap();
    let leave = signed(a.acct.remove_self(b.id()).unwrap(), &b.control);
    a.acct.apply_timed(leave.as_bytes(), t(100, 400)).unwrap();
    let left = RotationReason::RemovedSelf {
        position: a.acct.head().position,
        device: b.id(),
    };
    assert_eq!(a.acct.rotation_reason(399), None);
    assert_eq!(a.acct.rotation_reason(400), Some(left));
    // `rotation_due(0)` still names any established, unfulfilled effect;
    // base rekeying keeps an epoch closed on it.
    assert_eq!(a.acct.rotation_due(0), Some(left));
}

#[test]
fn rotation_due_at_zero_still_ignores_a_pending_deadline() {
    let mut a = account("correct horse");
    let b = Device::new();
    let added = add_device(&a.acct, &a.mac, &b);
    a.acct.apply_timed(added.as_bytes(), t(10, 10)).unwrap();
    let request = signed(
        a.acct.request_removal(a.mac.id(), b.id()).unwrap(),
        &a.mac.control,
    );
    a.acct.apply_timed(request.as_bytes(), t(20, 20)).unwrap();
    assert_eq!(a.acct.rotation_due(0), None);
    assert_eq!(a.acct.rotation_reason(20 + W - 1), None);
    assert!(a.acct.rotation_due(20 + W).is_some());
}

// ---- Staging over the device database ----

/// This device signed up; B and C were added; C then removed itself at
/// 2_000, so a rotation is due for it.
struct Staging {
    h: Harness,
    owner: Owner,
    cap: bh_account::owner::AccountCapability,
    b: Other,
    left: u64,
}
fn staging() -> Staging {
    let h = Harness::new();
    let (mut owner, cap) = h.signup();
    let (b, c) = (Other::new(), Other::new());
    add(&mut owner, &cap, &b, 1_000);
    add(&mut owner, &cap, &c, 1_100);
    let leave = c.sign_control(owner.verified(&cap).unwrap().remove_self(c.id()).unwrap());
    let left = apply(&mut owner, &leave, 2_000);
    Staging {
        h,
        owner,
        cap,
        b,
        left,
    }
}

fn current(owner: &mut Owner, cap: &bh_account::owner::AccountCapability) -> [u8; 1216] {
    ready(owner.open_current_personal(cap)).unwrap().public()
}

#[test]
fn a_staged_rotation_survives_reopen_with_its_exact_bytes() {
    let mut s = staging();
    let staged = ready(s.owner.stage_rotation(&s.cap, 2_000)).unwrap();
    assert_eq!(staged.kind, 9);
    let event = AccountEvent::decode(&staged.event).unwrap();
    assert_eq!(
        event.previous_head(),
        s.owner.verified(&s.cap).unwrap().head()
    );
    assert!(matches!(
        event.change(),
        AccountChange::PersonalRotated { reason, by } if reason == s.left && by == s.cap.device_id()
    ));
    assert!(staged.body.is_some() && staged.attachment.is_some());
    assert_eq!(staged.sealed_kit, None);

    let (mut owner, cap) = s.h.restart();
    assert_eq!(owner.staged_control().unwrap(), Some(staged.clone()));
    // Staging again keeps the proposal already made: no second key.
    assert_eq!(ready(owner.stage_rotation(&cap, 2_000)).unwrap(), staged);
    assert_eq!(owner.staged_control().unwrap(), Some(staged));
}

#[test]
fn staging_refuses_a_stale_or_non_next_event() {
    let mut s = staging();
    let view = s.owner.verified(&s.cap).unwrap().clone();
    let request = view.request_removal(s.cap.device_id(), s.b.id()).unwrap();
    let stale = ready(s.owner.sign_control(&s.cap, &request)).unwrap();
    // An addition is staged as an admission, not as a trust control.
    let d = Other::new();
    let request = s
        .owner
        .prepare_add_device(&s.cap, d.public.clone())
        .unwrap();
    let addition = ready(s.owner.sign_control(&s.cap, &request)).unwrap();
    assert_eq!(
        s.owner
            .stage_control(&s.cap, addition.as_bytes(), None, None, None)
            .err(),
        Some(OwnerError::Invalid(Error::NotPermitted))
    );
    assert_eq!(
        s.owner
            .stage_control(&s.cap, b"not an event", None, None, None)
            .err(),
        Some(OwnerError::Invalid(Error::Malformed))
    );
    // The head moves on; what was signed at the old head is not next.
    apply(&mut s.owner, &addition, 2_100);
    assert_eq!(
        s.owner
            .stage_control(&s.cap, stale.as_bytes(), None, None, None)
            .err(),
        Some(OwnerError::Invalid(Error::WrongPredecessor))
    );
    assert_eq!(s.owner.staged_control().unwrap(), None);
}

#[test]
fn a_second_different_stage_is_refused() {
    let mut s = staging();
    let d = Other::new();
    add(&mut s.owner, &s.cap, &d, 2_100);
    let view = s.owner.verified(&s.cap).unwrap().clone();
    let first = ready(s.owner.sign_control(
        &s.cap,
        &view.request_removal(s.cap.device_id(), s.b.id()).unwrap(),
    ))
    .unwrap();
    let second = ready(s.owner.sign_control(
        &s.cap,
        &view.request_removal(s.cap.device_id(), d.id()).unwrap(),
    ))
    .unwrap();
    let staged = s
        .owner
        .stage_control(&s.cap, first.as_bytes(), None, None, None)
        .unwrap();
    assert_eq!(staged.kind, 5);
    assert_eq!(staged.event, first.as_bytes());
    // The same bytes again are the same stage.
    assert_eq!(
        s.owner
            .stage_control(&s.cap, first.as_bytes(), None, None, None)
            .unwrap(),
        staged
    );
    assert_eq!(
        s.owner
            .stage_control(&s.cap, second.as_bytes(), None, None, None)
            .err(),
        Some(OwnerError::Journal(JournalError::StagedControlExists))
    );
    assert_eq!(
        ready(s.owner.stage_rotation(&s.cap, 2_100)).err(),
        Some(OwnerError::Journal(JournalError::StagedControlExists))
    );
    assert_eq!(s.owner.staged_control().unwrap(), Some(staged));
}

#[test]
fn a_staged_rotation_is_accepted_only_after_its_order_and_acceptance() {
    let mut s = staging();
    let before = current(&mut s.owner, &s.cap);
    let staged = ready(s.owner.stage_rotation(&s.cap, 2_000)).unwrap();
    assert_eq!(current(&mut s.owner, &s.cap), before);
    // Not ordered yet: nothing settles and the stage stays.
    assert!(s.owner.settle_staged().unwrap().is_none());
    assert_eq!(s.owner.staged_control().unwrap(), Some(staged.clone()));

    let position = apply_at(&mut s.owner, &staged.event, 2_100, 2_105);
    assert_eq!(current(&mut s.owner, &s.cap), before);
    // A restart before settling settles the same way.
    let (mut owner, cap) = s.h.restart();
    let settled = owner.settle_staged().unwrap().unwrap();
    assert_eq!(
        settled.outcome,
        Settled::Accepted {
            position,
            bounds: ConfirmedTime {
                earliest_ms: 2_100,
                latest_ms: 2_105,
            },
        }
    );
    assert_eq!(settled.staged, staged);
    assert_eq!(owner.staged_control().unwrap(), None);
    assert!(owner.settle_staged().unwrap().is_none());
    assert_eq!(current(&mut owner, &cap), before);

    let accepted =
        ready(owner.accept_rotation(&cap, position, staged.body.as_ref().unwrap())).unwrap();
    assert_ne!(accepted.public(), before);
    assert_eq!(
        &accepted.public(),
        owner.verified(&cap).unwrap().personal_public().unwrap()
    );
    assert_eq!(current(&mut owner, &cap), accepted.public());
}

#[test]
fn losing_rotation_never_overwrites_the_accepted_personal_key() {
    let mut s = staging();
    let before = current(&mut s.owner, &s.cap);
    let staged = ready(s.owner.stage_rotation(&s.cap, 2_000)).unwrap();
    // B rotates for the same removal and is ordered first.
    let view = s.owner.verified(&s.cap).unwrap().clone();
    let winner_key = PersonalKey::generate();
    let prepared = prepare_rotation(&view.advanced(2_000), &winner_key).unwrap();
    let winner = s.b.sign_ordinary(
        view.rotate_personal(
            s.b.id(),
            s.left,
            prepared.public,
            prepared.device_seals_digest,
            prepared.recovery_seal_digest,
        )
        .unwrap(),
    );
    let position = apply(&mut s.owner, &winner, 2_100);
    let settled = s.owner.settle_staged().unwrap().unwrap();
    assert_eq!(settled.outcome, Settled::Lost);
    assert_eq!(settled.staged, staged);
    assert_eq!(s.owner.staged_control().unwrap(), None);
    assert_eq!(current(&mut s.owner, &s.cap), before);
    // The losing proposal can never become this device's key.
    assert!(
        ready(
            s.owner
                .accept_rotation(&s.cap, position, staged.body.as_ref().unwrap())
        )
        .is_err()
    );
    assert_eq!(current(&mut s.owner, &s.cap), before);
    let accepted = ready(s.owner.accept_rotation(&s.cap, position, &prepared.body)).unwrap();
    assert_eq!(accepted.public(), winner_key.public());
    assert_eq!(current(&mut s.owner, &s.cap), winner_key.public());
}

#[test]
fn a_cancel_settles_by_whether_it_was_confirmed_before_the_deadline() {
    let mut s = staging();
    let d = Other::new();
    add(&mut s.owner, &s.cap, &d, 2_010);
    let me = s.cap.device_id();
    // B asks to remove D; this device, mature since 1_000 + W, cancels in time.
    let view = s.owner.verified(&s.cap).unwrap().clone();
    let request =
        s.b.sign_control(view.request_removal(s.b.id(), d.id()).unwrap());
    let r1 = apply(&mut s.owner, &request, 3_000);
    let d1 = 3_000 + W;
    let view = s.owner.verified(&s.cap).unwrap().clone();
    let cancel = ready(
        s.owner
            .sign_control(&s.cap, &view.cancel_removal(me, r1).unwrap()),
    )
    .unwrap();
    s.owner
        .stage_control(&s.cap, cancel.as_bytes(), None, None, None)
        .unwrap();
    let position = apply_at(&mut s.owner, cancel.as_bytes(), d1 - 2, d1 - 1);
    assert_eq!(
        s.owner.settle_staged().unwrap().unwrap().outcome,
        Settled::Accepted {
            position,
            bounds: ConfirmedTime {
                earliest_ms: d1 - 2,
                latest_ms: d1 - 1,
            },
        }
    );

    // B asks again; this cancel is confirmed only at the deadline.
    let view = s.owner.verified(&s.cap).unwrap().clone();
    let request =
        s.b.sign_control(view.request_removal(s.b.id(), d.id()).unwrap());
    let r2 = apply(&mut s.owner, &request, d1);
    let d2 = d1 + W;
    let view = s.owner.verified(&s.cap).unwrap().clone();
    let cancel = ready(
        s.owner
            .sign_control(&s.cap, &view.cancel_removal(me, r2).unwrap()),
    )
    .unwrap();
    s.owner
        .stage_control(&s.cap, cancel.as_bytes(), None, None, None)
        .unwrap();
    apply_at(&mut s.owner, cancel.as_bytes(), d2 - 5, d2);
    // Settling is the same after a restart.
    let (mut owner, cap) = s.h.restart();
    assert_eq!(
        owner.settle_staged().unwrap().unwrap().outcome,
        Settled::CancelTookEffect
    );
    assert!(owner.settle_staged().unwrap().is_none());
    assert_eq!(
        owner.verified(&cap).unwrap().device_state(d.id(), d2),
        Ok(DeviceState::Removed)
    );
}

#[test]
fn a_concurrently_changed_stage_is_not_cleared_and_settling_retries() {
    let mut s = staging();
    let mine = ready(s.owner.stage_rotation(&s.cap, 2_000)).unwrap();
    // Another writer settles this stage and stages B's rotation instead.
    let view = s.owner.verified(&s.cap).unwrap().clone();
    let prepared = prepare_rotation(&view.advanced(2_000), &PersonalKey::generate()).unwrap();
    let theirs = StagedControl {
        kind: 9,
        event: s
            .b
            .sign_ordinary(
                view.rotate_personal(
                    s.b.id(),
                    s.left,
                    prepared.public,
                    prepared.device_seals_digest,
                    prepared.recovery_seal_digest,
                )
                .unwrap(),
            )
            .as_bytes()
            .to_vec(),
        body: Some(prepared.body.clone()),
        attachment: Some(prepared.recovery_seal.clone()),
        sealed_kit: None,
    };
    let mut journal = s.h.journal();
    journal.clear_staged_control(&mine).unwrap();
    journal.stage_control(&theirs).unwrap();
    // A clear of what was read before is refused, and nothing is lost.
    assert_eq!(
        journal.clear_staged_control(&mine),
        Err(JournalError::StagedControlChanged)
    );
    assert_eq!(s.owner.staged_control().unwrap(), Some(theirs.clone()));
    // Retrying settles what is staged now: this device's rotation won.
    apply_at(&mut s.owner, &mine.event, 2_100, 2_100);
    let settled = s.owner.settle_staged().unwrap().unwrap();
    assert_eq!(settled.outcome, Settled::Lost);
    assert_eq!(settled.staged, theirs);
    assert_eq!(s.owner.staged_control().unwrap(), None);
}

#[test]
fn a_refused_control_is_discarded_only_as_staged_and_a_rotation_can_stage() {
    let mut s = staging();
    let view = s.owner.verified(&s.cap).unwrap().clone();
    let request = ready(s.owner.sign_control(
        &s.cap,
        &view.request_removal(s.cap.device_id(), s.b.id()).unwrap(),
    ))
    .unwrap();
    let staged = s
        .owner
        .stage_control(&s.cap, request.as_bytes(), None, None, None)
        .unwrap();
    // A stuck stage blocks the rotation the removal is due.
    assert_eq!(
        ready(s.owner.stage_rotation(&s.cap, 2_000)).err(),
        Some(OwnerError::Journal(JournalError::StagedControlExists))
    );
    // Only the exact row read is discarded.
    let other = StagedControl {
        event: b"other bytes".to_vec(),
        ..staged.clone()
    };
    assert_eq!(
        s.owner.discard_staged(&other).err(),
        Some(OwnerError::Journal(JournalError::StagedControlChanged))
    );
    assert_eq!(s.owner.staged_control().unwrap(), Some(staged.clone()));
    s.owner.discard_staged(&staged).unwrap();
    assert_eq!(s.owner.staged_control().unwrap(), None);
    let rotation = ready(s.owner.stage_rotation(&s.cap, 2_000)).unwrap();
    assert_eq!(rotation.kind, 9);
    // A late discard of the refused row never clears what is staged now.
    assert_eq!(
        s.owner.discard_staged(&staged).err(),
        Some(OwnerError::Journal(JournalError::StagedControlChanged))
    );
    assert_eq!(s.owner.staged_control().unwrap(), Some(rotation.clone()));
    // With nothing staged, it changes nothing.
    s.owner.discard_staged(&rotation).unwrap();
    s.owner.discard_staged(&rotation).unwrap();
    assert_eq!(s.owner.staged_control().unwrap(), None);
}

#[test]
fn a_rotation_names_its_exact_signed_body() {
    let mut s = staging();
    let staged = ready(s.owner.stage_rotation(&s.cap, 2_000)).unwrap();
    let body = staged.body.as_ref().unwrap();
    use bh_account::owner::staging::{
        device_seals_digest, published_device_digest, rotation_body_digest, signs_rotation_body,
    };
    assert_eq!(
        rotation_body_digest(&staged.event),
        Some(device_seals_digest(body))
    );
    assert_eq!(
        published_device_digest(&staged.event),
        Some(device_seals_digest(body))
    );
    // The signup's publication is the key the account started with.
    let signup =
        s.h.journal()
            .history_prefix(
                Some(bh_account::journal::HistoryCursor {
                    anchor: s.cap.account_id(),
                    cut: s.owner.verified(&s.cap).unwrap().head(),
                    next_position: 3,
                }),
                1,
            )
            .unwrap()
            .unwrap()
            .events
            .remove(0);
    assert_eq!(
        published_device_digest(&signup).as_ref(),
        Some(
            s.owner
                .verified_at(&s.cap, 3)
                .unwrap()
                .personal_publication()
                .unwrap()
                .device_digest()
        )
    );
    assert_eq!(rotation_body_digest(&signup), None);
    assert!(signs_rotation_body(&staged.event, body));
    let mut other = body.clone();
    other[0] ^= 1;
    assert!(!signs_rotation_body(&staged.event, &other));
    // Not a rotation: nothing is named.
    let view = s.owner.verified(&s.cap).unwrap().clone();
    let request = ready(s.owner.sign_control(
        &s.cap,
        &view.request_removal(s.cap.device_id(), s.b.id()).unwrap(),
    ))
    .unwrap();
    assert_eq!(rotation_body_digest(request.as_bytes()), None);
    assert_eq!(published_device_digest(request.as_bytes()), None);
    assert!(!signs_rotation_body(request.as_bytes(), body));
    assert_eq!(rotation_body_digest(b"not an event"), None);
}

// ---- A changed kit's protector key ----

type Rotating = bh_account::owner::AccountOwner<
    bh_account::storage::DeviceJournal,
    store::FakeStore,
    protector::RotatingProtector,
>;

/// Saving a changed kit, or losing its replacement, leaves no protector key
/// behind for it: the kit's own key is retired and none is made in its
/// place.
#[test]
fn a_changed_kit_leaves_no_protector_key() {
    let h = Harness::new();
    let protector = protector::RotatingProtector::default();
    let mut owner: Rotating = bh_account::owner::AccountOwner::new(
        h.journal(),
        h.store.clone(),
        protector.clone(),
        h.generation.clone(),
    );
    let setup = ready(owner.begin_first_device(
        bh_account::platform::ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        &bh_account::recovery::Password::new("synthetic staging test").unwrap(),
    ))
    .unwrap();
    owner.confirm_kit_saved().unwrap();
    owner.confirm_home_ordered(setup.head, None).unwrap();
    let cap = match ready(owner.activate()).unwrap() {
        bh_account::owner::AccountLoad::Active(cap) => cap,
        other => panic!("not active: {other:?}"),
    };
    let b = Other::new();
    let added = ready(owner.sign_control(
        &cap,
        &owner.prepare_add_device(&cap, b.public.clone()).unwrap(),
    ))
    .unwrap();
    owner
        .apply_incoming_timed(&[(added.as_bytes(), owner_db::at(1_000, 1_000))])
        .unwrap();
    let live = protector.live();
    let password = bh_account::recovery::Password::new("a new password").unwrap();

    // Saved.
    ready(owner.stage_recovery_replacement(&cap, &password)).unwrap();
    assert_eq!(protector.live(), live + 1, "the new kit's key");
    owner.confirm_staged_kit().unwrap();
    assert_eq!(protector.live(), live, "no key left for the saved kit");
    let kept = owner.staged_control().unwrap().unwrap();
    assert_eq!((kept.kind, kept.sealed_kit.is_none()), (8, true));
    owner.discard_staged(&kept).unwrap();

    // Lost while its kit shows.
    ready(owner.stage_recovery_replacement(&cap, &password)).unwrap();
    assert_eq!(protector.live(), live + 1);
    let leave = b.sign_control(owner.verified(&cap).unwrap().remove_self(b.id()).unwrap());
    owner
        .apply_incoming_timed(&[(leave.as_bytes(), owner_db::at(2_000, 2_000))])
        .unwrap();
    let settled = owner.settle_staged().unwrap().unwrap();
    assert_eq!(settled.outcome, Settled::Lost);
    assert_eq!(protector.live(), live, "no key left for the lost kit");
}
