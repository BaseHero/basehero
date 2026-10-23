//! Account runs copied into a base reach the account's own verdict: each
//! event applies with the time its confirmation proves, under the base's
//! pinned hosting root, and only a key active once the run applies copies.
#[path = "support/runs.rs"]
mod runs;

use bh_account::{DeviceState, REMOVAL_WAIT_MS, RequestState};
use bh_crypto::SigningKey;
use bh_event::{
    ACCOUNT_CHANGE_V2, CLASS_CONTROL, Copier, MAX_RUN, Outcome,
    account_run::{base_account, prepare_account_run},
    key_id,
};
use bh_sync::{Route, evidence::OrderingConfirmation};
use runs::{Base, Device, Recovery, hosting_root, receipt_for, root};

const START: u64 = 1_000_000;
const W: u64 = REMOVAL_WAIT_MS;

/// A base whose copy of the account has the second device, added at `START`:
/// the account's first confirmed entry.
fn with_second() -> Base {
    let mut f = Base::new();
    let add = f.add(&f.first, &f.second);
    let added = f.order_at(&add, START);
    let run = f.run(&f.first, &[added]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    f
}

fn open(f: &Base) -> Option<[u8; 32]> {
    Some(key_id(&f.epoch))
}

#[test]
fn run_applies_the_homes_rules_with_its_confirmations() {
    let mut f = Base::new();
    let add = f.add(&f.first, &f.second);
    let added = f.order_at(&add, START);
    let request = f.request_removal(&f.first, &f.second);
    let requested = f.order_at(&request, START + 10);
    let position = request.head().position;
    let run = f.run(&f.first, &[added, requested]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    assert_eq!(f.account.head(), f.ordered.head());
    let second = f.second.id();
    let deadline = START + 10 + W;
    for at in [START + 10, deadline - 1, deadline] {
        assert_eq!(
            f.account.device_state(second, at),
            f.ordered.device_state(second, at)
        );
        assert_eq!(
            f.account.request_state(position, at),
            f.ordered.request_state(position, at)
        );
    }
    assert_eq!(
        f.account.device_state(second, deadline - 1),
        Ok(DeviceState::RemovalPending {
            request: position,
            deadline_ms: deadline,
        })
    );
    // A pending removal removes nobody yet: the epoch stays open.
    assert_eq!(f.history.epoch_id(), open(&f));

    let cancel = f.cancel_by_recovery(position);
    let cancelled = f.order_at(&cancel, START + 20);
    let run = f.run(&f.first, &[cancelled]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    for state in [&f.account, &f.ordered] {
        assert_eq!(
            state.request_state(position, deadline + 1),
            Ok(RequestState::Cancelled)
        );
        assert_eq!(
            state.device_state(second, deadline + 1),
            Ok(DeviceState::Active)
        );
    }

    let next = Recovery::new();
    let replace = f.replace_recovery(&f.first, &next);
    let replaced = f.order_at(&replace, START + 30);
    let run = f.run(&f.first, &[replaced]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    assert!(f.account.recovery_author() == f.ordered.recovery_author());
    assert_eq!(f.account.head(), f.ordered.head());
    assert_eq!(f.spine.state().account, f.ordered.head());
    assert_eq!(f.history.epoch_id(), open(&f));
}

#[test]
fn missing_or_foreign_root_confirmation_cannot_authorize_early_removal() {
    let mut f = with_second();
    let now = f.remove_now(&f.first, &f.second);
    let mature = START + W;
    let confirm = |authority: &SigningKey, at: u64| {
        Base::confirmation_by(authority, &f.ordered, &now, at, at, 99)
    };
    let genuine = confirm(&hosting_root(), mature);
    // The latest bound's low byte, after the signature covered it.
    let mut altered = genuine.clone();
    altered[2 + 33 + 32 + 40 + 40 + 33 + 40 + 15] ^= 1;
    assert!(OrderingConfirmation::decode(&altered).is_ok());
    let epoch = f.history.epoch_id();
    let head = f.account.head();
    for (name, confirmation) in [
        ("missing", vec![0; OrderingConfirmation::LEN]),
        ("foreign root", confirm(&SigningKey::generate(), mature)),
        ("altered bounds", altered),
        (
            "before the author matured",
            confirm(&hosting_root(), mature - 1),
        ),
    ] {
        let run = f.run_signed(
            f.first.id(),
            &f.first.control,
            &[(now.as_bytes().to_vec(), confirmation)],
        );
        assert_eq!(f.step(&run, Route::Control), Outcome::Rejected, "{name}");
        assert_eq!(f.history.epoch_id(), epoch, "{name}");
        assert_eq!(f.account.head(), head, "{name}");
    }
    // A legacy copy carries no confirmation at all.
    let legacy = f.legacy(&f.first, now.as_bytes());
    assert_eq!(f.step(&legacy, Route::Control), Outcome::Rejected);
    assert_eq!(f.history.epoch_id(), epoch);
    // Confirmed once the author is mature, it removes the device and closes
    // the epoch.
    let removed = f.order_at(&now, mature);
    let run = f.run(&f.first, &[removed]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    assert_eq!(f.history.epoch_id(), None);
    assert_eq!(f.spine.state().epoch, None);
}

#[test]
fn base_and_account_replay_agree_at_the_deadline() {
    let mut f = with_second();
    let request = f.request_removal(&f.first, &f.second);
    let requested = f.order_at(&request, START + 10);
    let run = f.run(&f.first, &[requested]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    let deadline = START + 10 + W;
    let second = f.second.id();
    // A run whose last confirmation is earlier than the deadline keeps the
    // second device and the epoch.
    let add = f.add(&f.first, &f.third);
    let before = f.order_at(&add, deadline - 1);
    let run = f.run(&f.first, &[before]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    assert_eq!(f.history.epoch_id(), open(&f));
    assert!(f.account.active_device(second).is_ok());
    assert!(
        f.ordered
            .advanced(deadline - 1)
            .active_device(second)
            .is_ok()
    );
    // One whose confirmation reaches it removes the device, as the account
    // replay does, and closes the epoch.
    let fourth = Device::new();
    let add = f.add(&f.first, &fourth);
    let at = f.order_at(&add, deadline);
    let run = f.run(&f.first, &[at]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    assert_eq!(f.history.epoch_id(), None);
    assert!(f.account.active_device(second).is_err());
    assert!(f.ordered.active_device(second).is_err());
    assert_eq!(
        f.account.device_state(second, deadline),
        f.ordered.device_state(second, deadline)
    );
}

#[test]
fn a_removal_whose_target_its_deadline_removed_copies_as_a_no_op() {
    let mut f = with_second();
    let add = f.add(&f.first, &f.third);
    let added = f.order_at(&add, START + 1);
    let request = f.request_removal(&f.first, &f.second);
    let position = request.head().position;
    let requested = f.order_at(&request, START + 10);
    let run = f.run(&f.first, &[added, requested]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    let deadline = START + 10 + W;
    let second = f.second.id();
    // The third device asks to remove the second too, signed while it was a
    // member, but confirmed only after the deadline: it lapses.
    let again = f.request_removal(&f.third, &f.second);
    let lapsed = f.order_at(&again, deadline + 1);
    let run = f.run(&f.first, &[lapsed]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    assert_eq!(f.account.head(), f.ordered.head());
    // Only the deadline's removal happened, and it closed the epoch.
    for state in [&f.account, &f.ordered] {
        assert_eq!(
            state.device_state(second, deadline + 1),
            Ok(DeviceState::Removed)
        );
        assert_eq!(
            state.request_state(position, deadline + 1),
            Ok(RequestState::Effective)
        );
        assert!(state.pending_removals(deadline + 1).is_empty());
    }
    assert_eq!(f.history.epoch_id(), None);
    assert_eq!(f.spine.state().epoch, None);
    // The stored copies replay to the same account.
    let rebuilt = base_account(&f.anchor, &f.changes, &root()).unwrap();
    assert_eq!(rebuilt.head(), f.account.head());
    assert!(rebuilt.active_device(second).is_err());
    assert!(rebuilt.pending_removals(deadline + 1).is_empty());
}

#[test]
fn current_recovery_key_unsticks_a_base_that_missed_a_replace_recovery() {
    let mut f = Base::new();
    let old = f.account.recovery_author().unwrap();
    let next = Recovery::new();
    let replace = f.replace_recovery(&f.first, &next);
    let replaced = f.order_at(&replace, START);
    // A device the new recovery key adds, say on a recovered device that has
    // no surviving peer.
    let fourth = Device::new();
    let add = f.add_by_recovery(&next, &fourth);
    let added = f.order_at(&add, START + 1);
    let run = [replaced, added];
    // The replaced recovery key is not active once the run applies.
    let stale = f.run_signed(old, &f.recovery.signing, &run);
    assert_eq!(f.step(&stale, Route::Control), Outcome::Rejected);
    let copied = f.run_by_recovery(&next, &run);
    assert_eq!(f.step(&copied, Route::Control), Outcome::Accepted);
    assert_eq!(f.account.head(), f.ordered.head());
    assert_eq!(f.history.account_head(), f.ordered.head());
    // The added device writes.
    let note = f.note(&fourth, "recovered");
    assert_eq!(f.step(&note, Route::Content), Outcome::Accepted);
}

#[test]
fn removed_device_cannot_copy() {
    let mut f = with_second();
    let leave = f.remove_self(&f.second);
    let left = f.order_at(&leave, START + 1);
    assert!(
        prepare_account_run(
            f.base,
            &f.account,
            Copier::Device(f.second.id()),
            &f.metadata,
            f.seen(),
            receipt_for(f.base, f.history.head()),
            std::slice::from_ref(&left),
        )
        .is_err()
    );
    let by_leaver = f.run_signed(
        f.second.id(),
        &f.second.control,
        std::slice::from_ref(&left),
    );
    assert_eq!(f.step(&by_leaver, Route::Control), Outcome::Rejected);
    let run = f.run(&f.first, &[left]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    assert_eq!(f.history.epoch_id(), None);
    // Once removed it copies nothing later either.
    let add = f.add(&f.first, &f.third);
    let added = f.order_at(&add, START + 2);
    let late = f.run_signed(
        f.second.id(),
        &f.second.control,
        std::slice::from_ref(&added),
    );
    assert_eq!(f.step(&late, Route::Control), Outcome::Rejected);
    let run = f.run(&f.first, &[added]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
}

#[test]
fn run_length_is_one_to_sixty_four() {
    let mut f = Base::new();
    let devices: Vec<Device> = (0..=MAX_RUN).map(|_| Device::new()).collect();
    let mut run = Vec::new();
    for (i, device) in devices.iter().enumerate() {
        let add = f.add(&f.first, device);
        run.push(f.order_at(&add, START + i as u64));
    }
    assert_eq!(run.len(), 65);
    let producer = |run: &[runs::Confirmed]| {
        prepare_account_run(
            f.base,
            &f.account,
            Copier::Device(f.first.id()),
            &f.metadata,
            f.seen(),
            receipt_for(f.base, f.history.head()),
            run,
        )
    };
    assert!(producer(&[]).is_err());
    assert!(producer(&run).is_err());
    for (name, data) in [
        ("empty", Base::run_payload(0, &[])),
        ("sixty-five", Base::run_payload(65, &run)),
        // A count that disagrees with the entries.
        ("short", Base::run_payload(2, &run[..1])),
    ] {
        let control = f.control(
            f.binding(f.first.id(), CLASS_CONTROL),
            ACCOUNT_CHANGE_V2,
            &data,
            &f.first.control,
        );
        assert_eq!(
            f.step(&control, Route::Control),
            Outcome::Rejected,
            "{name}"
        );
    }
    let full = f.run(&f.first, &run[..MAX_RUN]);
    assert_eq!(f.step(&full, Route::Control), Outcome::Accepted);
    let last = bh_account::AccountEvent::decode(&run[MAX_RUN - 1].0).unwrap();
    assert_eq!(f.history.account_head(), last.head());
    let one = f.run(&f.first, &run[MAX_RUN..]);
    assert_eq!(f.step(&one, Route::Control), Outcome::Accepted);
    assert_eq!(f.history.account_head(), f.ordered.head());
}

#[test]
fn rotation_in_a_run_is_rejected() {
    let mut f = with_second();
    let leave = f.remove_self(&f.second);
    let left = f.order_at(&leave, START + 1);
    let rotate = f.rotate(&f.first, leave.head().position);
    let rotated = f.order_at(&rotate, START + 2);
    let both = [left.clone(), rotated];
    assert!(
        prepare_account_run(
            f.base,
            &f.account,
            Copier::Device(f.first.id()),
            &f.metadata,
            f.seen(),
            receipt_for(f.base, f.history.head()),
            &both,
        )
        .is_err()
    );
    let run = f.run_signed(f.first.id(), &f.first.control, &both);
    assert_eq!(f.step(&run, Route::Control), Outcome::Rejected);
    // Without it the run applies; the rotation reaches the base in its rekey.
    let run = f.run(&f.first, &[left]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
}
