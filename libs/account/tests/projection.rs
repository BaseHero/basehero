use std::sync::Arc;

use bh_account::{
    AccountEvent, AccountId, ConfirmedTime, DeviceId, DevicePublicKeys, Error, Head,
    RecoveryPublicKeys, RequestState, VerifiedAccount,
    crypto::{KemKey, SigningKey, hash},
    projection::{self, Checkpoint, HistoryIndex, KeyUse},
};

struct Device {
    signing: SigningKey,
    control: SigningKey,
    keys: DevicePublicKeys,
}
impl Device {
    fn new() -> Self {
        let signing = SigningKey::generate();
        let control = SigningKey::generate();
        let keys = DevicePublicKeys::new(
            signing.public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        Self {
            signing,
            control,
            keys,
        }
    }
    fn id(&self) -> DeviceId {
        self.keys.id()
    }
}
const START: u64 = bh_account::REMOVAL_WAIT_MS + 20;
fn time(n: u64) -> Option<ConfirmedTime> {
    Some(ConfirmedTime {
        earliest_ms: n,
        latest_ms: n,
    })
}
fn signed(request: bh_account::SigningRequest, key: &SigningKey) -> AccountEvent {
    request.finish(key.sign(request.signing_bytes())).unwrap()
}
struct Fixture {
    first: Device,
    second: Device,
    account: VerifiedAccount,
    events: Vec<(Vec<u8>, Option<ConfirmedTime>)>,
}
impl Fixture {
    fn new() -> Self {
        let first = Device::new();
        let second = Device::new();
        let recovery =
            RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public());
        let genesis = signed(
            AccountEvent::genesis(first.keys.clone(), recovery),
            &first.control,
        );
        let account = VerifiedAccount::from_genesis(
            AccountId::of_genesis(&genesis).unwrap(),
            genesis.as_bytes(),
        )
        .unwrap();
        let mut f = Self {
            first,
            second,
            account,
            events: vec![(genesis.as_bytes().to_vec(), time(10))],
        };
        // The initial verifier is untimed, so replay the first confirmed entry.
        f.replay();
        let record = signed(
            f.account
                .prepare_recovery_record(f.first.id(), [3; 32])
                .unwrap(),
            &f.first.control,
        );
        f.push(record, 11);
        let personal = signed(
            f.account
                .publish_personal_key(f.first.id(), KemKey::generate().public(), [4; 32], [5; 32])
                .unwrap(),
            &f.first.control,
        );
        f.push(personal, 12);
        let add = signed(
            f.account
                .add_device(f.first.id(), f.second.keys.clone())
                .unwrap(),
            &f.first.control,
        );
        f.push(add, 13);
        f
    }
    fn push(&mut self, event: AccountEvent, at: u64) {
        self.account
            .apply_timed(event.as_bytes(), time(at))
            .unwrap();
        self.events.push((event.as_bytes().to_vec(), time(at)));
    }
    fn replay(&mut self) {
        let events: Vec<_> = self
            .events
            .iter()
            .map(|(e, t)| (e.as_slice(), *t))
            .collect();
        self.account =
            VerifiedAccount::replay_timed(self.account.id(), &events, self.account.head()).unwrap();
    }
    fn request(&mut self, at: u64) -> u64 {
        let e = signed(
            self.account
                .request_removal(self.first.id(), self.second.id())
                .unwrap(),
            &self.first.control,
        );
        let position = e.head().position;
        self.push(e, at);
        position
    }
    fn cancel(&mut self, request: u64, at: u64) {
        let e = signed(
            self.account
                .cancel_removal(self.first.id(), request)
                .unwrap(),
            &self.first.control,
        );
        self.push(e, at);
    }
    fn index(&self, cut: Head) -> Arc<dyn HistoryIndex> {
        Arc::new(FixtureIndex::new(
            cut,
            self.events.clone(),
            self.first.id(),
            7,
        ))
    }
    fn index_epoch(&self, cut: Head, epoch: u64) -> Arc<dyn HistoryIndex> {
        Arc::new(FixtureIndex::new(
            cut,
            self.events.clone(),
            self.first.id(),
            epoch,
        ))
    }
    fn restored(&self) -> VerifiedAccount {
        projection::restore(
            projection::capture(&self.account),
            7,
            self.index(self.account.head()),
        )
        .unwrap()
    }
}
struct FixtureIndex {
    cut: Head,
    events: Vec<(Vec<u8>, Option<ConfirmedTime>)>,
    source: AccountId,
    genesis_device: DeviceId,
    generation: u64,
    expected_generation: u64,
    fault: bool,
}
impl FixtureIndex {
    fn new(
        cut: Head,
        events: Vec<(Vec<u8>, Option<ConfirmedTime>)>,
        genesis_device: DeviceId,
        generation: u64,
    ) -> Self {
        let source = AccountId(hash(&events[0].0));
        Self {
            cut,
            events,
            source,
            genesis_device,
            generation,
            expected_generation: generation,
            fault: false,
        }
    }
    fn allowed(&self, cut: Head) -> Result<(), Error> {
        if self.fault
            || self.source != AccountId(hash(&self.events[0].0))
            || self.generation != self.expected_generation
            || cut != self.cut
            || self
                .events
                .get(cut.position as usize - 1)
                .is_none_or(|(bytes, _)| hash(bytes) != cut.hash)
        {
            Err(Error::Unavailable)
        } else {
            Ok(())
        }
    }
    fn seen(&self, cut: Head, id: DeviceId) -> Result<bool, Error> {
        self.allowed(cut)?;
        Ok(id == self.genesis_device || self.events[..cut.position as usize].iter().any(|(b,_)| {
            let e = AccountEvent::decode(b).unwrap();
            matches!(e.change(), bh_account::AccountChange::DeviceAdded { device, .. } if device == id)
        }))
    }
}
impl HistoryIndex for FixtureIndex {
    fn event_matches(&self, cut: Head, position: u64, bytes: &[u8]) -> Result<bool, Error> {
        self.allowed(cut)?;
        Ok(position > 0
            && position <= cut.position
            && self.events[(position - 1) as usize].0 == bytes)
    }
    fn device_seen(&self, cut: Head, id: &DeviceId) -> Result<bool, Error> {
        self.seen(cut, *id)
    }
    fn key_used(&self, cut: Head, key: KeyUse<'_>) -> Result<bool, Error> {
        self.allowed(cut)?;
        // A real historical key is matched against retained original signed bytes,
        // not a fabricated boolean for the particular test case.
        Ok(self.events[..cut.position as usize]
            .iter()
            .any(|(bytes, _)| match key {
                KeyUse::Signing(k) => bytes.windows(k.len()).any(|w| w == k),
                KeyUse::Receiving(k) => bytes.windows(k.len()).any(|w| w == k),
            }))
    }
    fn confirmed_time(&self, cut: Head, position: u64) -> Result<Option<ConfirmedTime>, Error> {
        self.allowed(cut)?;
        if position == 0 || position > cut.position {
            return Err(Error::Unavailable);
        }
        Ok(self.events[(position - 1) as usize].1)
    }
}

#[test]
fn projection_roundtrip_matches_verified_history() {
    let mut f = Fixture::new();
    let cancelled = f.request(START);
    let cuts = [f.account.head()];
    f.cancel(cancelled, START + 1);
    let request = f.request(START + 2);
    for head in cuts.into_iter().chain([f.account.head()]) {
        let slice = &f.events[..head.position as usize];
        let replay = VerifiedAccount::replay_timed(
            f.account.id(),
            &slice
                .iter()
                .map(|(b, t)| (b.as_slice(), *t))
                .collect::<Vec<_>>(),
            head,
        )
        .unwrap();
        let restored = projection::restore(
            projection::capture(&replay),
            7,
            Arc::new(FixtureIndex::new(head, slice.to_vec(), f.first.id(), 7)),
        )
        .unwrap();
        assert_eq!(restored.head(), head);
        assert_eq!(
            restored.active_device(f.second.id()).is_ok(),
            replay.active_device(f.second.id()).is_ok()
        );
        assert_eq!(
            restored.recovery_keys().unwrap().signing(),
            replay.recovery_keys().unwrap().signing()
        );
        assert_eq!(
            restored.personal_public().unwrap(),
            replay.personal_public().unwrap()
        );
        assert_eq!(
            restored.pending_removals(START + 3),
            replay.pending_removals(START + 3)
        );
        assert_eq!(
            restored.rotation_due(START + 3 + bh_account::REMOVAL_WAIT_MS),
            replay.rotation_due(START + 3 + bh_account::REMOVAL_WAIT_MS)
        );
        assert_eq!(
            restored.request_state(request, START + 3).ok(),
            replay.request_state(request, START + 3).ok()
        );
        assert_eq!(
            restored.added_at(f.second.id()),
            replay.added_at(f.second.id())
        );
        let a = signed(
            replay
                .cancel_removal(f.first.id(), request.min(head.position))
                .unwrap(),
            &f.first.control,
        );
        let next_time = time(START + 4);
        let (after_restore, restore_outcome) = restored
            .clone()
            .applied_batch_timed_with_outcomes(&[(a.as_bytes(), next_time)])
            .unwrap();
        let (after_replay, replay_outcome) = replay
            .clone()
            .applied_batch_timed_with_outcomes(&[(a.as_bytes(), next_time)])
            .unwrap();
        assert_eq!(restore_outcome, replay_outcome);
        assert_eq!(
            after_restore.pending_removals(START + 4),
            after_replay.pending_removals(START + 4)
        );
        assert_eq!(
            restored_at_regressed_time(&replay, &f.first),
            Err(Error::TimeRegressed)
        );
        assert_eq!(
            restored_at_regressed_time(&restored, &f.first),
            Err(Error::TimeRegressed)
        );
    }
}

// The preceding loop checks the current last bound by trying a signed successor
// earlier than that bound; the first bound is exercised by `added_at` below.
fn restored_at_regressed_time(view: &VerifiedAccount, first: &Device) -> Result<(), Error> {
    let next = signed(
        view.cancel_removal(first.id(), view.head().position)
            .unwrap(),
        &first.control,
    );
    view.clone()
        .applied_batch_timed(&[(next.as_bytes(), time(10))])
        .map(|_| ())
}

#[test]
fn stopped_checkpoint_stays_stopped() {
    let mut f = Fixture::new();
    let mut broken = signed(
        f.account
            .request_removal(f.first.id(), f.second.id())
            .unwrap(),
        &f.first.control,
    )
    .as_bytes()
    .to_vec();
    *broken.last_mut().unwrap() ^= 1;
    assert_eq!(
        f.account.apply_timed(&broken, time(20)),
        Err(Error::BadSignature)
    );
    assert!(f.account.is_stopped());
    let restored = f.restored();
    assert!(restored.is_stopped());
    assert_eq!(
        restored.active_device(f.first.id()).err(),
        Some(Error::Stopped)
    );
    assert_eq!(restored.recovery_keys().err(), Some(Error::Stopped));
    assert_eq!(
        restored.clone().applied(&broken).err(),
        Some(Error::Stopped)
    );
    let rebased = projection::rebase(
        restored,
        f.account.head(),
        8,
        f.index_epoch(f.account.head(), 8),
    )
    .unwrap();
    assert!(rebased.is_stopped());
    assert_eq!(
        rebased.active_device(f.first.id()).err(),
        Some(Error::Stopped)
    );
}

#[test]
fn malformed_checkpoint_refuses_summary_and_active_keys() {
    let f = Fixture::new();
    let good = projection::capture(&f.account);
    let restore = |c: Checkpoint| projection::restore(c, 7, f.index(f.account.head())).err();
    let mut c = projection::capture(&f.account);
    c.summary[7] = b'9';
    assert_eq!(restore(c), Some(Error::Malformed));
    let mut c = projection::capture(&f.account);
    c.summary.pop();
    assert_eq!(restore(c), Some(Error::Malformed));
    let mut c = projection::capture(&f.account);
    c.summary.push(0);
    assert_eq!(restore(c), Some(Error::Malformed));
    let mut c = projection::capture(&f.account);
    c.active.push(projection::AccountDeviceRow {
        device: good.active[0].device,
        keys: good.active[0].keys.clone(),
        added: good.active[0].added,
    });
    assert_eq!(restore(c), Some(Error::Malformed));
    let mut c = projection::capture(&f.account);
    c.active[0].keys[0] ^= 1;
    assert_eq!(restore(c), Some(Error::Malformed));
}

#[test]
fn unavailable_index_never_becomes_unused_key() {
    let f = Fixture::new();
    let cut = f.account.head();
    let mut fault = FixtureIndex::new(cut, f.events.clone(), f.first.id(), 7);
    fault.fault = true;
    let candidate = DevicePublicKeys::new(
        *f.second.keys.signing(),
        SigningKey::generate().public(),
        KemKey::generate().public(),
    )
    .unwrap();
    let view = projection::restore(projection::capture(&f.account), 7, Arc::new(fault)).unwrap();
    assert_eq!(
        view.add_device(f.first.id(), candidate.clone()).err(),
        Some(Error::Unavailable)
    );
    assert_eq!(
        view.clone()
            .applied_batch(&[signed(
                f.account
                    .add_device(f.first.id(), Device::new().keys)
                    .unwrap(),
                &f.first.control
            )
            .as_bytes()])
            .err(),
        Some(Error::Unavailable)
    );
    fault = FixtureIndex::new(
        Head {
            hash: [9; 32],
            ..cut
        },
        f.events.clone(),
        f.first.id(),
        7,
    );
    let wrong_cut =
        projection::restore(projection::capture(&f.account), 8, Arc::new(fault)).unwrap();
    assert_eq!(
        wrong_cut.add_device(f.first.id(), candidate.clone()).err(),
        Some(Error::Unavailable)
    );
    for bad in [0, 1] {
        let mut index = FixtureIndex::new(cut, f.events.clone(), f.first.id(), 7);
        if bad == 0 {
            index.source = AccountId([9; 32]);
        } else {
            index.generation = 8;
        }
        let wrong =
            projection::restore(projection::capture(&f.account), 7, Arc::new(index)).unwrap();
        assert_eq!(
            wrong.add_device(f.first.id(), candidate.clone()).err(),
            Some(Error::Unavailable)
        );
    }
    let correct = f.restored();
    assert_eq!(
        correct.add_device(f.first.id(), candidate).err(),
        Some(Error::KeyReuse)
    );
    assert_eq!(
        correct
            .add_device(f.first.id(), f.second.keys.clone())
            .err(),
        Some(Error::DuplicateDevice)
    );
}

fn assert_same_delta(
    a: &projection::AccountProjectionDelta,
    b: &projection::AccountProjectionDelta,
) {
    assert_eq!(a.epoch, b.epoch);
    assert_eq!(a.expected, b.expected);
    assert_eq!(a.through, b.through);
    assert_eq!(a.summary, b.summary);
    assert_eq!(a.added.len(), b.added.len());
    for (a, b) in a.added.iter().zip(&b.added) {
        assert_eq!((a.device, &a.keys, a.added), (b.device, &b.keys, b.added));
    }
    assert_eq!(a.removed, b.removed);
    assert_eq!(a.keys, b.keys);
}

#[test]
fn wrong_committed_head_cannot_rebase() {
    let mut f = Fixture::new();
    let mut view = f.restored();
    let previous = view.head();
    let new = Device::new();
    let event = signed(
        view.add_device(f.first.id(), new.keys.clone()).unwrap(),
        &f.first.control,
    );
    f.push(event.clone(), START);
    view.apply_timed(event.as_bytes(), time(START)).unwrap();
    let original = projection::delta(&view);
    assert_eq!(original.expected, (previous.position, previous.hash));
    assert_eq!(original.through, (event.head().position, event.head().hash));
    assert_eq!((original.added.len(), original.keys.len()), (1, 3));
    assert_eq!(
        (original.added[0].device, original.added[0].added),
        (new.id().0, event.head().position)
    );
    for wrong in [
        Head {
            position: view.head().position - 1,
            ..view.head()
        },
        Head {
            hash: [42; 32],
            ..view.head()
        },
    ] {
        assert_eq!(
            projection::rebase(view.clone(), wrong, 8, f.index_epoch(view.head(), 8)).err(),
            Some(Error::WrongPredecessor)
        );
        assert_same_delta(&projection::delta(&view), &original);
    }
    // The accepted view is still usable. The fixture includes the *new* exact
    // original and time before supplying a new committed index to rebase.
    let committed = view.head();
    let index = f.index_epoch(committed, 8);
    assert_eq!(
        index.event_matches(committed, committed.position, event.as_bytes()),
        Ok(true)
    );
    assert_eq!(
        index.confirmed_time(committed, committed.position),
        Ok(time(START))
    );
    let mut rebased = projection::rebase(view, committed, 8, index).unwrap();
    let empty = projection::delta(&rebased);
    assert_eq!(empty.epoch, Some(8));
    assert_eq!(empty.expected, (committed.position, committed.hash));
    assert_eq!(empty.expected, empty.through);
    assert!(empty.added.is_empty() && empty.removed.is_empty() && empty.keys.is_empty());
    assert!(rebased.active_device(new.id()).is_ok());
    let next = Device::new();
    let successor = signed(
        rebased.add_device(f.first.id(), next.keys.clone()).unwrap(),
        &f.first.control,
    );
    f.push(successor.clone(), START + 1);
    rebased
        .apply_timed(successor.as_bytes(), time(START + 1))
        .unwrap();
    let suffix = projection::delta(&rebased);
    assert_eq!(suffix.expected, empty.through);
    assert_eq!(suffix.through.0, suffix.expected.0 + 1);
    assert_eq!((suffix.added.len(), suffix.keys.len()), (1, 3));
    assert_eq!(suffix.added[0].device, next.id().0);
}

#[test]
fn checkpoint_size_depends_on_live_state_not_history() {
    let mut f = Fixture::new();
    let initial = projection::capture(&f.account);
    let mut view = f.restored();
    let mut at = START;
    for generation in 8..20 {
        let previous = view.head();
        let prior_summary = projection::capture(&view).summary;
        let request = f.request(at);
        f.cancel(request, at + 1);
        let batch = &f.events[previous.position as usize..];
        assert_eq!(batch.len(), 2);
        view = view
            .applied_batch_timed(
                &batch
                    .iter()
                    .map(|(bytes, time)| (bytes.as_slice(), *time))
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        let delta = projection::delta(&view);
        assert_eq!(delta.epoch, Some(generation - 1));
        assert_eq!(delta.expected, (previous.position, previous.hash));
        assert_eq!(
            delta.through,
            (f.account.head().position, f.account.head().hash)
        );
        assert_eq!(delta.through.0, delta.expected.0 + 2);
        assert_eq!(
            view.request_state(request, at + 1),
            Ok(RequestState::Cancelled)
        );
        assert_eq!(delta.summary, projection::capture(&view).summary);
        assert_ne!(delta.summary, prior_summary);
        assert!(delta.added.is_empty() && delta.removed.is_empty() && delta.keys.is_empty());
        let captured = projection::capture(&view);
        assert_eq!(captured.summary.len(), initial.summary.len());
        assert_eq!(captured.active.len(), initial.active.len());
        assert_eq!(
            captured.active.iter().map(|r| r.keys.len()).sum::<usize>(),
            initial.active.iter().map(|r| r.keys.len()).sum::<usize>()
        );
        // Simulate committing this exact two-original/two-confirmation batch.
        let committed = view.head();
        let index = f.index_epoch(committed, generation);
        for (offset, (bytes, confirmed)) in batch.iter().enumerate() {
            let position = previous.position + offset as u64 + 1;
            assert_eq!(index.event_matches(committed, position, bytes), Ok(true));
            assert_eq!(index.confirmed_time(committed, position), Ok(*confirmed));
        }
        view = projection::rebase(view, committed, generation, index).unwrap();
        let empty = projection::delta(&view);
        assert_eq!(empty.epoch, Some(generation));
        assert_eq!(empty.expected, (committed.position, committed.hash));
        assert_eq!(empty.expected, empty.through);
        assert!(empty.added.is_empty() && empty.removed.is_empty() && empty.keys.is_empty());
        at += 2;
    }
    assert_eq!(f.events.len(), 28);
    let final_state = projection::capture(&view);
    assert_eq!(final_state.active.len(), 2);
    println!(
        "bounded projection: originals={}, initial_summary_bytes={}, final_summary_bytes={}, active_entries={}, active_key_bytes={}",
        f.events.len(),
        initial.summary.len(),
        final_state.summary.len(),
        final_state.active.len(),
        final_state
            .active
            .iter()
            .map(|r| r.keys.len())
            .sum::<usize>()
    );
}

#[test]
fn expired_request_and_unfulfilled_rotation_survive_reopen() {
    let mut f = Fixture::new();
    let request = f.request(START);
    let deadline = START + bh_account::REMOVAL_WAIT_MS;
    let before = f.restored();
    assert_eq!(
        before.request_state(request, deadline - 1),
        Ok(RequestState::Pending {
            deadline_ms: deadline
        })
    );
    assert_eq!(
        before.request_state(request, deadline),
        Ok(RequestState::Effective)
    );
    // Confirm a no-op cancellation at the deadline to materialize removal.
    let late = signed(
        f.account.cancel_removal(f.first.id(), request).unwrap(),
        &f.first.control,
    );
    f.push(late, deadline);
    let after = f.restored();
    assert_eq!(
        after.active_device(f.second.id()).err(),
        Some(Error::NotActive)
    );
    assert_eq!(
        after.rotation_due(deadline),
        f.account.rotation_due(deadline)
    );
    assert!(after.rotation_due(deadline).is_some());
    let rebased = projection::rebase(
        after.clone(),
        after.head(),
        8,
        f.index_epoch(after.head(), 8),
    )
    .unwrap();
    assert_eq!(rebased.rotation_due(deadline), after.rotation_due(deadline));
    assert_eq!(
        after.added_at(f.first.id()),
        f.account.added_at(f.first.id())
    );
    let rotation = signed(
        f.account
            .rotate_personal(
                f.first.id(),
                request,
                KemKey::generate().public(),
                [8; 32],
                [9; 32],
            )
            .unwrap(),
        &f.first.signing,
    );
    let (restored, result) = after
        .applied_batch_timed_with_outcomes(&[(rotation.as_bytes(), time(deadline + 1))])
        .unwrap();
    assert_eq!(result, vec![bh_account::ControlOutcome::Applied]);
    f.push(rotation, deadline + 1);
    assert_eq!(restored.rotation_due(deadline + 1), None);
    assert_eq!(
        restored.personal_public().unwrap(),
        f.account.personal_public().unwrap()
    );
}

#[test]
fn pending_lapse_has_same_next_event_outcome_after_reopen() {
    let mut f = Fixture::new();
    let first_request = f.request(START);
    let second_request = signed(
        f.account
            .request_removal(f.second.id(), f.first.id())
            .unwrap(),
        &f.second.control,
    );
    f.push(second_request, START + 1);
    let cut = f.account.head();
    let restored = f.restored();
    assert_eq!(restored.pending_removals(START + 2).len(), 2);
    let deadline = START + bh_account::REMOVAL_WAIT_MS;
    let late = signed(
        f.account
            .cancel_removal(f.first.id(), first_request)
            .unwrap(),
        &f.first.control,
    );
    let (next, outcome) = restored
        .applied_batch_timed_with_outcomes(&[(late.as_bytes(), time(deadline))])
        .unwrap();
    let (full, full_outcome) = f
        .account
        .applied_batch_timed_with_outcomes(&[(late.as_bytes(), time(deadline))])
        .unwrap();
    assert_eq!(outcome, full_outcome);
    assert_eq!(next.head(), full.head());
    assert_eq!(
        next.active_device(f.second.id()).err(),
        Some(Error::NotActive)
    );
    assert_eq!(
        next.active_device(f.first.id()).is_ok(),
        full.active_device(f.first.id()).is_ok()
    );
    assert_eq!(next.rotation_due(deadline), full.rotation_due(deadline));
    assert_eq!(projection::delta(&next).expected, (cut.position, cut.hash));
}

#[test]
fn index_remembers_genesis_device_after_removal() {
    let mut f = Fixture::new();
    let self_removal = signed(
        f.account.remove_self(f.first.id()).unwrap(),
        &f.first.control,
    );
    f.push(self_removal, START);
    let restored = f.restored();
    assert_eq!(restored.seen_device(f.first.id()), Ok(true));
    assert_eq!(
        restored.active_device(f.first.id()).err(),
        Some(Error::NotActive)
    );
}

#[test]
fn replacement_effect_survives_reopen() {
    let mut f = Fixture::new();
    let request = f.request(START);
    let replacement = signed(
        f.account
            .replace_recovery(
                f.first.id(),
                RecoveryPublicKeys::new(
                    SigningKey::generate().public(),
                    KemKey::generate().public(),
                ),
                [6; 32],
                [7; 32],
            )
            .unwrap(),
        &f.first.control,
    );
    f.push(replacement, START + 1);
    let restored = f.restored();
    assert_eq!(
        restored.request_state(request, START + 2),
        f.account.request_state(request, START + 2)
    );
    assert_eq!(
        restored.recovery_keys().unwrap().signing(),
        f.account.recovery_keys().unwrap().signing()
    );
    assert_eq!(
        restored.rotation_due(START + 2),
        f.account.rotation_due(START + 2)
    );
    assert!(restored.rotation_due(START + 2).is_some());
}

#[test]
fn incoming_signed_key_reuse_fails_closed_on_missing_index() {
    let f = Fixture::new();
    let cut = f.account.head();
    let fresh = Device::new();
    let reused = DevicePublicKeys::new(
        *f.second.keys.control(),
        *fresh.keys.control(),
        *fresh.keys.receiving(),
    )
    .unwrap();
    let mut bytes = b"BaseHero account event\0".to_vec();
    bytes.extend(1u16.to_be_bytes());
    bytes.extend(1u16.to_be_bytes());
    bytes.extend((cut.position + 1).to_be_bytes());
    bytes.extend(cut.hash);
    bytes.extend(f.account.id().0);
    bytes.extend(f.first.id().0);
    bytes.push(1);
    bytes.extend(reused.signing());
    bytes.extend(reused.control());
    bytes.extend(reused.receiving());
    bytes.extend(f.first.control.sign(&bytes));
    assert_eq!(f.restored().applied(&bytes).err(), Some(Error::KeyReuse));
    let unavailable = projection::restore(
        projection::capture(&f.account),
        7,
        Arc::new(FixtureIndex {
            fault: true,
            ..FixtureIndex::new(cut, f.events.clone(), f.first.id(), 7)
        }),
    )
    .unwrap();
    assert_eq!(unavailable.applied(&bytes).err(), Some(Error::Unavailable));
}
