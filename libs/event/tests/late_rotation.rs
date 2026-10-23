//! A personal-key rotation signed before its author's removal deadline but
//! confirmed after it lapses in the account. A base never rekeys for it; it
//! may copy it in a run, which then carries only the deadline's removal.
#[path = "support/runs.rs"]
mod runs;

use bh_account::{AccountEvent, DeviceState, REMOVAL_WAIT_MS as W, RotationReason};
use bh_crypto::Secret;
use bh_event::{
    ACCOUNT_REKEY, Binding, CLASS_CONTROL, Copier, Outcome,
    account_run::{base_account, prepare_account_run},
    key_id,
    rekey::prepare_rekey,
};
use bh_sync::Route;
use runs::{Base, Confirmed, Recovery, hosting_root, receipt_for, root};

const START: u64 = 1_000_000;
/// When the first device loses its authority.
const D: u64 = START + 2 + W;
const PREVIOUS_AT: usize = b"BaseHero account event\0".len() + 2 + 2 + 8;

/// The first device adds the second and third at `START` and replaces the
/// recovery key at `START + 1`, so a rotation is due; at `START + 2` the third
/// asks to remove the first. The base copies all of it. The first then signs
/// the rotation, but its home confirms it only at `D + 1`.
struct Late {
    f: Base,
    rotation: Confirmed,
    replaced: u64,
    request: u64,
}
fn late() -> Late {
    let mut f = Base::new();
    let add = f.add(&f.first, &f.second);
    let second = f.order_at(&add, START);
    let add = f.add(&f.first, &f.third);
    let third = f.order_at(&add, START);
    let replace = f.replace_recovery(&f.first, &Recovery::new());
    let replaced = replace.head().position;
    let replacement = f.order_at(&replace, START + 1);
    let request = f.request_removal(&f.third, &f.first);
    let position = request.head().position;
    let requested = f.order_at(&request, START + 2);
    let run = f.run(&f.first, &[second, third, replacement, requested]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    assert_eq!(f.history.epoch_id(), Some(key_id(&f.epoch)));
    let rotate = f.rotate(&f.first, replaced);
    let rotation = f.order_at(&rotate, D + 1);
    Late {
        f,
        rotation,
        replaced,
        request: position,
    }
}

#[test]
fn a_later_deadline_keeps_the_epoch_closed_until_the_coalesced_rotation() {
    use bh_account::personal::{PersonalKey, prepare_rotation, verify_rotation_body};
    let mut f = Base::new();
    let second = f.order_at(&f.add(&f.first, &f.second), START);
    let third = f.order_at(&f.add(&f.first, &f.third), START);
    let removal1 = f.request_removal(&f.first, &f.second);
    let first_reason = removal1.head().position;
    let requested1 = f.order_at(&removal1, START + 1);
    let removal2 = f.request_removal(&f.first, &f.third);
    let last_reason = removal2.head().position;
    let requested2 = f.order_at(&removal2, START + 2);
    let run = f.run(&f.first, &[second, third, requested1, requested2]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    // The body is prepared after the first deadline but before the second.
    let at_first = f.ordered.advanced(START + 1 + W);
    let prepared = prepare_rotation(&at_first, &PersonalKey::generate()).unwrap();
    let draft = at_first
        .rotate_personal(
            f.first.id(),
            first_reason,
            prepared.public,
            prepared.device_seals_digest,
            prepared.recovery_seal_digest,
        )
        .unwrap();
    let rotation = draft
        .finish(f.first.signing.sign(draft.signing_bytes()))
        .unwrap();
    let at_second = f.ordered.advanced(START + 2 + W);
    // Authentic, but includes the third device whose removal is still due.
    verify_rotation_body(&at_second, &rotation, &prepared.body).unwrap();
    let confirmed = f.order_at(&rotation, START + 2 + W);
    let next = Secret::<32>::random();
    let rekey = Base::sign_rekey(f.rekey(&f.first, &confirmed, &next, &seals()), &f.first);
    assert_eq!(f.step(&rekey, Route::Control), Outcome::Accepted);
    assert_eq!(
        f.history.epoch_id(),
        None,
        "a removed recipient still has this personal key"
    );
    assert_eq!(f.spine.state().epoch, None);
    assert!(f.account.rotation_due(START + 2 + W).is_some());
    // Copying the first rotation advances history so the coalesced one can follow.
    let rotation = f.rotate(&f.first, last_reason);
    let confirmed = f.order_at(&rotation, START + 3 + W);
    let safe = Secret::<32>::random();
    let rekey = Base::sign_rekey(f.rekey(&f.first, &confirmed, &safe, &seals()), &f.first);
    assert_eq!(f.step(&rekey, Route::Control), Outcome::Accepted);
    assert_eq!(f.history.epoch_id(), Some(key_id(&safe)));
    assert_eq!(f.spine.state().epoch, Some(key_id(&safe)));
}

fn seals() -> Vec<Vec<u8>> {
    vec![vec![7; 1499], vec![8; 1499]]
}

/// A rekey body exactly as given.
fn rekey_payload(rotation: &Confirmed, key: [u8; 32], count: u16, set: [u8; 32]) -> Vec<u8> {
    let mut data = (rotation.0.len() as u32).to_be_bytes().to_vec();
    data.extend(&rotation.0);
    data.extend(&rotation.1);
    data.extend(key);
    data.extend(count.to_be_bytes());
    data.extend(set);
    data
}

fn prepared_run(f: &Base, copier: &runs::Device, run: &[Confirmed]) -> bool {
    prepare_account_run(
        f.base,
        &f.account,
        Copier::Device(copier.id()),
        &f.metadata,
        f.seen(),
        receipt_for(f.base, f.history.head()),
        run,
    )
    .is_ok()
}

#[test]
fn a_lapsed_rotation_cannot_rekey_even_by_a_current_device() {
    let Late {
        mut f, rotation, ..
    } = late();
    let next = Secret::<32>::random();
    // The third device, still a member, signs the rekey anyway.
    let rekey = f.control(
        Binding {
            mode: 2,
            ..f.binding(f.third.id(), CLASS_CONTROL)
        },
        ACCOUNT_REKEY,
        &rekey_payload(&rotation, key_id(&next), 2, [9; 32]),
        &f.third.signing,
    );
    assert_eq!(f.history_verdict(&rekey, Route::Control), Outcome::Rejected);
    assert_eq!(f.spine_verdict(&rekey).err(), Some(Outcome::Rejected));
    // Nor does the library prepare one.
    let prepared = prepare_rekey(
        f.base,
        &f.account,
        f.third.id(),
        &f.metadata,
        f.seen(),
        receipt_for(f.base, f.history.head()),
        &rotation.0,
        &rotation.1,
        &next,
        &seals(),
    );
    assert!(
        prepared.is_err(),
        "no rekey is prepared for a lapsed rotation"
    );
    assert_eq!(f.step(&rekey, Route::Control), Outcome::Rejected);
    // No epoch installed: the old key stays, and the account copy is unchanged.
    assert_eq!(f.history.epoch_id(), Some(key_id(&f.epoch)));
    assert_eq!(f.spine.state().epoch, Some(key_id(&f.epoch)));
    assert!(f.account.active_device(f.first.id()).is_ok());
}

#[test]
fn a_lapsed_rotation_copies_in_a_run_that_only_removes_its_author() {
    let Late {
        mut f,
        rotation,
        replaced,
        request,
    } = late();
    let personal = *f.account.personal_public().unwrap();
    let run = f.run(&f.third, std::slice::from_ref(&rotation));
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);

    // The original is the base copy's next event; it rotated nothing.
    assert_eq!(f.account.head(), f.ordered.head());
    assert_eq!(f.account.personal_public(), Ok(&personal));
    assert_eq!(
        f.account.rotation_due(D + 1),
        Some(RotationReason::RecoveryReplaced { position: replaced })
    );
    // The deadline it reached removed the first device and closed the epoch.
    assert_eq!(
        f.account.active_device(f.first.id()).err(),
        Some(bh_account::Error::NotActive)
    );
    assert_eq!(
        f.account.device_state(f.first.id(), D + 1),
        Ok(DeviceState::Removed)
    );
    assert_eq!(f.history.epoch_id(), None);
    assert_eq!(f.spine.state().epoch, None);
    // The stored copies replay to the same account.
    let rebuilt = base_account(&f.anchor, &f.changes, &root()).unwrap();
    assert_eq!(rebuilt.head(), f.account.head());
    assert_eq!(rebuilt.personal_public(), Ok(&personal));
    assert!(rebuilt.active_device(f.first.id()).is_err());

    // The third device's own rotation fulfils both effects and rekeys.
    let rotate = f.rotate(&f.third, request);
    let rotated = f.order_at(&rotate, D + 2);
    assert!(
        !prepared_run(&f, &f.third, std::slice::from_ref(&rotated)),
        "a rotation that takes effect reaches the base only in its rekey"
    );
    let next = Secret::<32>::random();
    let rekey = Base::sign_rekey(f.rekey(&f.third, &rotated, &next, &seals()), &f.third);
    assert_eq!(f.step(&rekey, Route::Control), Outcome::Accepted);
    assert_eq!(f.history.epoch_id(), Some(key_id(&next)));
    assert_eq!(f.spine.state().epoch, Some(key_id(&next)));
    assert_eq!(f.account.rotation_due(D + 2), None);
    assert_ne!(f.account.personal_public(), Ok(&personal));
}

#[test]
fn a_late_rotation_with_a_bad_signature_or_fork_is_refused() {
    let Late { f, rotation, .. } = late();
    let confirmed = |bytes: Vec<u8>| -> Confirmed {
        let event = AccountEvent::decode(&bytes).unwrap();
        let confirmation =
            Base::confirmation_by(&hosting_root(), &f.account, &event, D + 1, D + 1, 99);
        (bytes, confirmation)
    };
    let mut corrupted = rotation.0.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    let mut forked = rotation.0.clone();
    forked[PREVIOUS_AT..PREVIOUS_AT + 32].copy_from_slice(&[7; 32]);
    let split = forked.len() - 64;
    let signature = f.first.signing.sign(&forked[..split]);
    forked[split..].copy_from_slice(&signature);
    for (name, bytes) in [("bad signature", corrupted), ("fork", forked)] {
        let entry = confirmed(bytes);
        assert!(!prepared_run(&f, &f.third, std::slice::from_ref(&entry)));
        let run = f.run_signed(f.third.id(), &f.third.control, std::slice::from_ref(&entry));
        assert_eq!(
            f.history_verdict(&run, Route::Control),
            Outcome::Rejected,
            "{name}: History"
        );
        assert_eq!(
            f.spine_verdict(&run).err(),
            Some(Outcome::Rejected),
            "{name}: ControlSpine"
        );
        let rekey = f.control(
            Binding {
                mode: 2,
                ..f.binding(f.third.id(), CLASS_CONTROL)
            },
            ACCOUNT_REKEY,
            &rekey_payload(&entry, [5; 32], 2, [9; 32]),
            &f.third.signing,
        );
        assert_eq!(f.history_verdict(&rekey, Route::Control), Outcome::Rejected);
    }
}
