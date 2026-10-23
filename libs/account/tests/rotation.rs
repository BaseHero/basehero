#[path = "support/account.rs"]
mod account;
#[path = "support/native.rs"]
mod native;
use account::{Account, Device, account, add, signed, t};

use bh_account::{
    AccountEvent, Error, REMOVAL_WAIT_MS as W, RotationReason, VerifiedAccount,
    personal::{
        PersonalKey, PreparedRotation, open_for_recovery, open_rotation_for_recovery,
        prepare_rotation, seal_for_device_by_recovery, verify_device_delivery,
        verify_rotation_body,
    },
    recovery::RecoveryKeys,
};

struct Fixture {
    a: Account,
    fold: Device,
    phone: Device,
}

/// The Mac adds the Fold untimed, then the Phone in the first confirmed entry.
fn setup() -> Fixture {
    let mut a = account("correct horse");
    let fold = Device::new();
    let phone = Device::new();
    let event = add(&a.acct, &a.mac, &fold);
    a.acct.apply(event.as_bytes()).unwrap();
    let event = add(&a.acct, &a.mac, &phone);
    a.acct.apply_timed(event.as_bytes(), t(0, 0)).unwrap();
    Fixture { a, fold, phone }
}

/// The Mac asks to remove `target`, confirmed at `at`; returns the request.
fn request(acct: &mut VerifiedAccount, by: &Device, target: &Device, at: u64) -> u64 {
    let event = signed(
        acct.request_removal(by.id(), target.id()).unwrap(),
        &by.control,
    );
    acct.apply_timed(event.as_bytes(), t(at, at)).unwrap();
    acct.head().position
}

fn rotation(
    acct: &VerifiedAccount,
    by: &Device,
    reason: u64,
    p: &PreparedRotation,
) -> AccountEvent {
    signed(
        acct.rotate_personal(
            by.id(),
            reason,
            p.public,
            p.device_seals_digest,
            p.recovery_seal_digest,
        )
        .unwrap(),
        &by.ordinary,
    )
}

#[test]
fn rotation_seals_exactly_the_remaining_devices_and_recovery() {
    let mut f = setup();
    let reason = request(&mut f.a.acct, &f.a.mac, &f.fold, 100);
    let deadline = 100 + W;
    let after = f.a.acct.advanced(deadline);
    let next = PersonalKey::generate();
    let prepared = prepare_rotation(&after, &next).unwrap();
    assert_eq!(prepared.public, next.public());
    let event = rotation(&f.a.acct, &f.a.mac, reason, &prepared);
    assert_eq!(verify_rotation_body(&after, &event, &prepared.body), Ok(()));

    // Sealed to the reason's target: prepared before its deadline.
    let before = f.a.acct.advanced(deadline - 1);
    let stale = prepare_rotation(&before, &PersonalKey::generate()).unwrap();
    let stale_event = rotation(&f.a.acct, &f.a.mac, reason, &stale);
    assert_eq!(
        verify_rotation_body(&after, &stale_event, &stale.body),
        Err(Error::InvalidCredentials)
    );
    // A body the event does not commit to.
    assert_eq!(
        verify_rotation_body(&after, &event, &stale.body),
        Err(Error::InvalidCredentials)
    );
    // An active device missing: the Tablet joined after the body was made.
    let mut grown = f.a.acct.clone();
    let tablet = Device::new();
    let added = add(&grown, &f.a.mac, &tablet);
    grown.apply_timed(added.as_bytes(), t(200, 200)).unwrap();
    let grown_event = rotation(&grown, &f.a.mac, reason, &prepared);
    assert_eq!(
        verify_rotation_body(&grown.advanced(deadline), &grown_event, &prepared.body),
        Err(Error::InvalidCredentials)
    );
    // Not yet due when the view is before the deadline.
    assert_eq!(
        verify_rotation_body(&before, &event, &prepared.body),
        Err(Error::TooEarly)
    );

    f.a.acct
        .apply_timed(event.as_bytes(), t(deadline, deadline))
        .unwrap();
    assert_eq!(f.a.acct.personal_public().unwrap(), &next.public());
    for device in [&f.a.mac, &f.phone] {
        let opened =
            native::open_rotation(&f.a.acct, &prepared.body, &device.public, &device.receiver)
                .unwrap();
        assert_eq!(opened.public(), next.public());
    }
    let receiver = f.a.recovery.receiver();
    assert_eq!(
        open_rotation_for_recovery(&f.a.acct, &prepared.recovery_seal, receiver)
            .unwrap()
            .public(),
        next.public()
    );
    assert_eq!(
        open_for_recovery(&f.a.acct, &prepared.recovery_seal, receiver)
            .unwrap()
            .public(),
        next.public()
    );
    // The initial recovery seal named the old key.
    assert!(open_for_recovery(&f.a.acct, f.a.publication.recovery_seal(), receiver).is_err());
}

#[test]
fn a_seal_to_a_target_whose_removal_is_still_due_is_tolerated() {
    let mut f = setup();
    let fold_request = request(&mut f.a.acct, &f.a.mac, &f.fold, 100);
    let phone_request = request(&mut f.a.acct, &f.a.mac, &f.phone, 200);
    let (fold_deadline, phone_deadline) = (100 + W, 200 + W);
    // Prepared once the Fold's removal took effect, while the Phone's waited.
    let prepared =
        prepare_rotation(&f.a.acct.advanced(fold_deadline), &PersonalKey::generate()).unwrap();
    let event = rotation(&f.a.acct, &f.a.mac, fold_request, &prepared);
    // Confirmed only after the Phone's deadline too.
    let confirmed = f.a.acct.advanced(phone_deadline);
    assert_eq!(
        verify_rotation_body(&confirmed, &event, &prepared.body),
        Ok(())
    );
    // A rotation for the Phone's removal fulfils both, so its seal is refused.
    let both = rotation(&f.a.acct, &f.a.mac, phone_request, &prepared);
    assert_eq!(
        verify_rotation_body(&confirmed, &both, &prepared.body),
        Err(Error::InvalidCredentials)
    );
    // The Phone's effect stays due for the next rotation.
    f.a.acct
        .apply_timed(event.as_bytes(), t(phone_deadline, phone_deadline))
        .unwrap();
    assert_eq!(
        f.a.acct.rotation_due(phone_deadline),
        Some(RotationReason::Removal {
            request: phone_request,
            target: f.phone.id(),
        })
    );
}

#[test]
fn removed_device_cannot_open_the_rotation() {
    let mut f = setup();
    let reason = request(&mut f.a.acct, &f.a.mac, &f.fold, 100);
    let deadline = 100 + W;
    let prepared =
        prepare_rotation(&f.a.acct.advanced(deadline), &PersonalKey::generate()).unwrap();
    let event = rotation(&f.a.acct, &f.a.mac, reason, &prepared);
    f.a.acct
        .apply_timed(event.as_bytes(), t(deadline, deadline))
        .unwrap();
    assert!(
        native::open_rotation(&f.a.acct, &prepared.body, &f.fold.public, &f.fold.receiver).is_err()
    );
    // Nothing in the body names the Fold.
    assert!(!prepared.body.windows(32).any(|w| w == f.fold.id().0));
    // A changed body is not the committed one.
    let mut tampered = prepared.body.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        native::open_rotation(&f.a.acct, &tampered, &f.a.mac.public, &f.a.mac.receiver).err(),
        Some(Error::InvalidCredentials)
    );
}

#[test]
fn recovery_delivery_opens_on_the_added_device() {
    let mut a = account("correct horse");
    let phone = Device::new();
    let admission = a
        .acct
        .add_device_by_recovery(phone.public.clone())
        .unwrap()
        .finish_with_recovery(&a.recovery)
        .unwrap();
    assert_eq!(
        seal_for_device_by_recovery(
            &a.acct,
            &a.personal,
            &RecoveryKeys::generate(),
            &phone.public,
            &admission
        )
        .err(),
        Some(Error::InvalidCredentials)
    );
    // Only the exact signed addition of this recipient.
    let other = Device::new();
    assert_eq!(
        seal_for_device_by_recovery(&a.acct, &a.personal, &a.recovery, &other.public, &admission)
            .err(),
        Some(Error::InvalidCredentials)
    );
    let frame =
        seal_for_device_by_recovery(&a.acct, &a.personal, &a.recovery, &phone.public, &admission)
            .unwrap();
    a.acct.apply_timed(admission.as_bytes(), t(10, 10)).unwrap();
    assert!(
        verify_device_delivery(&a.acct, &frame, &phone.public).unwrap()
            == a.acct.recovery_author().unwrap()
    );
    let opened = native::open_device(&a.acct, &frame, &phone.public, &phone.receiver).unwrap();
    assert_eq!(opened.public(), a.personal.public());

    // Once the recovery key is replaced, its deliveries no longer verify.
    let replace = signed(
        a.acct
            .replace_recovery(
                a.mac.id(),
                RecoveryKeys::generate().public(),
                [6; 32],
                [7; 32],
            )
            .unwrap(),
        &a.mac.control,
    );
    a.acct.apply_timed(replace.as_bytes(), t(20, 20)).unwrap();
    assert!(verify_device_delivery(&a.acct, &frame, &phone.public).is_err());
}
