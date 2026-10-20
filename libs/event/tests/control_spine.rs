//! The service-side control follower gives exactly `History`'s verdict and
//! effect for a base's controls, without seeing its content; and `History`
//! refuses a sealed class the ordered route disagrees with.
use bh_account::{AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount};
use bh_crypto::{KemKey, Secret, SigningKey};
use bh_event::{
    ACCOUNT_CHANGE, Binding, CLASS_CONTENT, CLASS_CONTROL, ControlChange, ControlSpine, Encoded,
    GENESIS, History, NOTE, Outcome, Payload, key_id, note_payload, seal,
    writer::DeviceWriterDeclaration,
};
use bh_sync::receipt::{self, RECEIPT_LEN};
use bh_sync::{BaseId, Commitment, EventId, Head, Route};

fn hosting_root() -> SigningKey {
    SigningKey::from_seed(&Secret::from_slice(&[0x61; 32]).unwrap())
}
fn root() -> [u8; 32] {
    hosting_root().public()
}
fn receipt_for(base: BaseId, head: Head) -> [u8; RECEIPT_LEN] {
    let key = SigningKey::from_seed(&Secret::from_slice(&[0x62; 32]).unwrap());
    let certificate =
        receipt::verify_certificate(&root(), &receipt::certify(&hosting_root(), key.public()))
            .unwrap();
    receipt::sign(&certificate, &key, base, head).unwrap()
}

struct Device {
    signing: SigningKey,
    control: SigningKey,
    receive: KemKey,
}
impl Device {
    fn new() -> Self {
        Self {
            signing: SigningKey::generate(),
            control: SigningKey::generate(),
            receive: KemKey::generate(),
        }
    }
    fn keys(&self) -> DevicePublicKeys {
        DevicePublicKeys::new(
            self.signing.public(),
            self.control.public(),
            self.receive.public(),
        )
        .unwrap()
    }
}

/// A base whose devices verify everything and whose service follows only
/// its controls.
struct Fixture {
    first: Device,
    second: Device,
    third: Device,
    /// The base's copy of the account, as both followers apply it.
    account: VerifiedAccount,
    metadata: Secret<32>,
    epoch: Secret<32>,
    base: BaseId,
    history: History,
    spine: ControlSpine,
    control: [u8; 32],
    genesis_control: [u8; 32],
    genesis_account: bh_account::Head,
    genesis: Encoded,
    genesis_order: Commitment,
}
impl Fixture {
    fn new() -> Self {
        let first = Device::new();
        let req = AccountEvent::genesis(
            first.keys(),
            RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public()),
        );
        let account_genesis = req.finish(first.control.sign(req.signing_bytes())).unwrap();
        let id = AccountId::of_genesis(&account_genesis).unwrap();
        let account = VerifiedAccount::from_genesis(id, account_genesis.as_bytes()).unwrap();
        let metadata = Secret::<32>::random();
        let epoch = Secret::<32>::random();
        let mut data = Vec::new();
        data.extend(id.0);
        data.extend(account.head().position.to_be_bytes());
        data.extend(account.head().hash);
        data.extend([0; 32]);
        data.extend(key_id(&epoch));
        data.extend(key_id(&metadata));
        let genesis = seal(
            Binding {
                version: 1,
                highest: 1,
                mode: 1,
                base: [0; 32],
                audience: [0; 32],
                epoch: key_id(&metadata),
                event_id: EventId(bh_crypto::random()),
                account: id,
                device: first.keys().id(),
                account_head: account.head(),
                seen: Head::EMPTY,
                seen_control: [0; 32],
                class: CLASS_CONTROL,
                padded: 0,
                commitment: [0; 32],
                seen_receipt: [0; RECEIPT_LEN],
            },
            Payload {
                kind: GENESIS,
                data: &data,
            },
            &first.signing,
            &metadata,
            None,
        )
        .unwrap();
        let base = BaseId::from_genesis(&genesis.descriptor);
        let genesis_order =
            Commitment::order(base, Head::EMPTY, &genesis.descriptor, Route::Control).unwrap();
        let mut history = History::with_account(&account, base, root(), 1).unwrap();
        let prepared = history
            .prepare(
                &genesis_order,
                &genesis.descriptor,
                Some(&genesis.body),
                &metadata,
                None,
            )
            .unwrap();
        history.consume_unapplied(prepared).unwrap();
        let (spine, verified) = ControlSpine::from_genesis(
            &account,
            &genesis.descriptor,
            &genesis.body,
            &metadata,
            root(),
            &genesis_order,
        )
        .unwrap();
        assert_eq!(verified.base, base);
        assert_eq!(verified.content_key_id, key_id(&epoch));
        let control = genesis_order.event_digest().0;
        Self {
            first,
            second: Device::new(),
            third: Device::new(),
            genesis_account: account.head(),
            account,
            metadata,
            epoch,
            base,
            history,
            spine,
            control,
            genesis_control: control,
            genesis,
            genesis_order,
        }
    }
    fn binding(&self, device: &Device, class: u8) -> Binding {
        Binding {
            version: 2,
            highest: 2,
            mode: 0,
            base: self.base.0,
            audience: [0; 32],
            epoch: if class == CLASS_CONTROL {
                key_id(&self.metadata)
            } else {
                key_id(&self.epoch)
            },
            event_id: EventId(bh_crypto::random()),
            account: self.account.id(),
            device: device.keys().id(),
            account_head: self.account.head(),
            seen: self.history.head(),
            seen_control: self.control,
            class,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: receipt_for(self.base, self.history.head()),
        }
    }
    fn order(&self, event: &Encoded, route: Route) -> Commitment {
        Commitment::order(self.base, self.history.head(), &event.descriptor, route).unwrap()
    }
    fn note(&self, device: &Device, text: &str) -> Encoded {
        let data = note_payload(
            [7; 32],
            DeviceWriterDeclaration {
                account: [4; 32],
                device: [5; 32],
                nonce: [6; 32],
            },
            &bh_core::note::Note::new()
                .unwrap()
                .append_paragraph(text)
                .unwrap(),
        );
        seal(
            self.binding(device, CLASS_CONTENT),
            Payload {
                kind: NOTE,
                data: &data,
            },
            &device.signing,
            &self.metadata,
            Some(&self.epoch),
        )
        .unwrap()
    }
    /// A base copy of one account event, authored and signed as given.
    fn copy(&self, binding: Binding, account_event: &[u8], signer: &SigningKey) -> Encoded {
        seal(
            binding,
            Payload {
                kind: ACCOUNT_CHANGE,
                data: account_event,
            },
            signer,
            &self.metadata,
            None,
        )
        .unwrap()
    }
    fn add(&self, author: &Device, added: &Device) -> AccountEvent {
        let request = self
            .account
            .add_device(author.keys().id(), added.keys())
            .unwrap();
        request
            .finish(author.control.sign(request.signing_bytes()))
            .unwrap()
    }
    fn remove(&self, device: &Device) -> AccountEvent {
        let request = self.account.remove_self(device.keys().id()).unwrap();
        request
            .finish(device.control.sign(request.signing_bytes()))
            .unwrap()
    }
    /// Order and verify one event on every device; the service follows it
    /// only when it is a control-route event.
    fn step(&mut self, event: &Encoded, route: Route) -> Outcome {
        let ordered = self.order(event, route);
        let mut history = self.history.clone();
        let outcome = history_verdict(&mut history, &ordered, event, self);
        self.history = history;
        if outcome == Outcome::Accepted && route == Route::Control {
            let effect = self
                .spine
                .check(
                    &self.account,
                    &event.descriptor,
                    &event.body,
                    &self.metadata,
                    &ordered,
                )
                .unwrap();
            self.account.apply(&effect.account_event).unwrap();
            self.spine.apply(effect, &ordered).unwrap();
            self.control = ordered.event_digest().0;
        }
        outcome
    }
    fn content(&mut self, notes: usize) {
        for n in 0..notes {
            let note = self.note(&self.first, &format!("arbitrary {n}"));
            assert_eq!(self.step(&note, Route::Content), Outcome::Accepted);
        }
    }
}

/// History's verdict on one ordered event, advancing it.
fn history_verdict(
    history: &mut History,
    ordered: &Commitment,
    event: &Encoded,
    f: &Fixture,
) -> Outcome {
    match history.prepare(
        ordered,
        &event.descriptor,
        Some(&event.body),
        &f.metadata,
        Some(&f.epoch),
    ) {
        Ok(prepared) => history.consume_unapplied(prepared).unwrap().outcome(),
        Err(outcome) => outcome,
    }
}

fn spine_verdict(f: &Fixture, event: &Encoded, ordered: &Commitment) -> Outcome {
    match f.spine.check(
        &f.account,
        &event.descriptor,
        &event.body,
        &f.metadata,
        ordered,
    ) {
        Ok(_) => Outcome::Accepted,
        Err(outcome) => outcome,
    }
}

/// Genesis, content, an add copy for the second device, then more content:
/// every corpus case is ordered after content the service never saw.
fn busy() -> Fixture {
    let mut f = Fixture::new();
    f.content(2);
    let add = f.add(&f.first, &f.second);
    let copy = f.copy(
        f.binding(&f.first, CLASS_CONTROL),
        add.as_bytes(),
        &f.first.control,
    );
    assert_eq!(f.step(&copy, Route::Control), Outcome::Accepted);
    f.content(3);
    f
}

#[test]
fn control_on_content_route_rejected() {
    let mut f = Fixture::new();
    f.content(1);
    let add = f.add(&f.first, &f.second);
    let copy = f.copy(
        f.binding(&f.first, CLASS_CONTROL),
        add.as_bytes(),
        &f.first.control,
    );
    let ordered = f.order(&copy, Route::Content);
    assert_eq!(spine_verdict(&f, &copy, &ordered), Outcome::Rejected);
    let account_head = f.history.account_head();
    assert_eq!(f.step(&copy, Route::Content), Outcome::Rejected);
    // It holds its position and nothing else.
    assert_eq!(f.history.head(), ordered.head());
    assert_eq!(f.history.account_head(), account_head);
    assert!(!f.history.is_stopped());
    // The same copy, sealed again on the control route, applies.
    let copy = f.copy(
        f.binding(&f.first, CLASS_CONTROL),
        add.as_bytes(),
        &f.first.control,
    );
    assert_eq!(f.step(&copy, Route::Control), Outcome::Accepted);
    assert_eq!(f.history.account_head(), add.head());
    let note = f.note(&f.second, "now a member");
    assert_eq!(f.step(&note, Route::Content), Outcome::Accepted);
}

#[test]
fn content_on_control_route_rejected() {
    let mut f = Fixture::new();
    f.content(1);
    let note = f.note(&f.first, "on the wrong route");
    let ordered = f.order(&note, Route::Control);
    assert_eq!(spine_verdict(&f, &note, &ordered), Outcome::Rejected);
    assert_eq!(f.step(&note, Route::Control), Outcome::Rejected);
    assert_eq!(f.history.head(), ordered.head());
    assert!(!f.history.is_stopped());
    let next = f.note(&f.first, "next");
    assert_eq!(f.step(&next, Route::Content), Outcome::Accepted);
}

#[test]
fn genesis_on_content_route_stops() {
    let f = Fixture::new();
    // A sequencer can only label a genesis as content by committing a chain
    // `Commitment::order` refuses to build.
    let mut bytes = f.genesis_order.encode();
    let route = 2 + 32 + 8 + 32 + 32 + 32;
    assert_eq!(bytes[route], Route::Control as u8);
    bytes[route] = Route::Content as u8;
    let prefix = bytes.len() - 32;
    let mut chained = b"bh/chain/v1\0".to_vec();
    chained.extend(&bytes[..prefix]);
    let hash = bh_crypto::hash(&chained);
    bytes[prefix..].copy_from_slice(&hash);
    let content = Commitment::decode(&bytes).unwrap();
    assert_eq!(content.route(), Route::Content);
    let mut history = History::with_account(&f.account, f.base, root(), 1).unwrap();
    assert_eq!(
        history
            .prepare(
                &content,
                &f.genesis.descriptor,
                Some(&f.genesis.body),
                &f.metadata,
                None,
            )
            .err(),
        Some(Outcome::IntegrityStop)
    );
    assert!(history.is_stopped());
    assert_eq!(
        ControlSpine::from_genesis(
            &f.account,
            &f.genesis.descriptor,
            &f.genesis.body,
            &f.metadata,
            root(),
            &content,
        )
        .err(),
        Some(Outcome::IntegrityStop)
    );
}

#[test]
fn spine_verdict_equals_history_verdict() {
    let f = busy();
    let add_third = f.add(&f.first, &f.third);
    let remove_second = f.remove(&f.second);
    let fourth = Device::new();
    let skipped = {
        let mut ahead = f.account.clone();
        ahead.apply(add_third.as_bytes()).unwrap();
        let request = ahead
            .add_device(f.first.keys().id(), fourth.keys())
            .unwrap();
        request
            .finish(f.first.control.sign(request.signing_bytes()))
            .unwrap()
    };
    let cases: Vec<(&str, Encoded, Route, Outcome)> = vec![
        (
            "valid add copy",
            f.copy(
                f.binding(&f.first, CLASS_CONTROL),
                add_third.as_bytes(),
                &f.first.control,
            ),
            Route::Control,
            Outcome::Accepted,
        ),
        (
            "valid remove copy",
            f.copy(
                f.binding(&f.first, CLASS_CONTROL),
                remove_second.as_bytes(),
                &f.first.control,
            ),
            Route::Control,
            Outcome::Accepted,
        ),
        (
            "stale seen_control",
            f.copy(
                Binding {
                    seen_control: f.genesis_control,
                    ..f.binding(&f.first, CLASS_CONTROL)
                },
                add_third.as_bytes(),
                &f.first.control,
            ),
            Route::Control,
            Outcome::Rejected,
        ),
        (
            "wrong account head",
            f.copy(
                Binding {
                    account_head: f.genesis_account,
                    ..f.binding(&f.first, CLASS_CONTROL)
                },
                add_third.as_bytes(),
                &f.first.control,
            ),
            Route::Control,
            Outcome::Rejected,
        ),
        (
            "ordinary-key signature on a control",
            f.copy(
                f.binding(&f.first, CLASS_CONTROL),
                add_third.as_bytes(),
                &f.first.signing,
            ),
            Route::Control,
            Outcome::Rejected,
        ),
        (
            "content class",
            f.note(&f.first, "content on the control route"),
            Route::Control,
            Outcome::Rejected,
        ),
        (
            "wrong epoch field",
            f.copy(
                Binding {
                    epoch: key_id(&f.epoch),
                    ..f.binding(&f.first, CLASS_CONTROL)
                },
                add_third.as_bytes(),
                &f.first.control,
            ),
            Route::Control,
            Outcome::Rejected,
        ),
        (
            "bad receipt",
            f.copy(
                Binding {
                    seen_receipt: receipt_for(f.base, f.genesis_order.head()),
                    ..f.binding(&f.first, CLASS_CONTROL)
                },
                add_third.as_bytes(),
                &f.first.control,
            ),
            Route::Control,
            Outcome::Rejected,
        ),
        (
            "inactive device",
            f.copy(
                f.binding(&f.third, CLASS_CONTROL),
                add_third.as_bytes(),
                &f.third.control,
            ),
            Route::Control,
            Outcome::Rejected,
        ),
        (
            "skipped account event",
            f.copy(
                f.binding(&f.first, CLASS_CONTROL),
                skipped.as_bytes(),
                &f.first.control,
            ),
            Route::Control,
            Outcome::Rejected,
        ),
    ];
    for (name, event, route, expected) in &cases {
        let ordered = f.order(event, *route);
        let mut history = f.history.clone();
        let devices = history_verdict(&mut history, &ordered, event, &f);
        let service = spine_verdict(&f, event, &ordered);
        assert_eq!(devices, *expected, "{name}: History");
        assert_eq!(service, devices, "{name}: ControlSpine against History");
        assert!(!history.is_stopped(), "{name}");
    }
}

#[test]
fn spine_seen_rule_matches_history_for_observations_before_the_last_control() {
    let mut f = Fixture::new();
    f.content(2);
    // What the first device had seen before the add copy was ordered.
    let earlier = (f.history.head(), f.control, f.account.head());
    let add = f.add(&f.first, &f.second);
    let copy = f.copy(
        f.binding(&f.first, CLASS_CONTROL),
        add.as_bytes(),
        &f.first.control,
    );
    assert_eq!(f.step(&copy, Route::Control), Outcome::Accepted);
    f.content(2);
    let add_third = f.add(&f.first, &f.third);
    for (name, binding) in [
        (
            "truthful observation from before the last control",
            Binding {
                seen: earlier.0,
                seen_control: earlier.1,
                account_head: earlier.2,
                seen_receipt: receipt_for(f.base, earlier.0),
                ..f.binding(&f.first, CLASS_CONTROL)
            },
        ),
        (
            "an earlier position claiming the last control",
            Binding {
                seen: earlier.0,
                seen_receipt: receipt_for(f.base, earlier.0),
                ..f.binding(&f.first, CLASS_CONTROL)
            },
        ),
    ] {
        let event = f.copy(binding, add_third.as_bytes(), &f.first.control);
        let ordered = f.order(&event, Route::Control);
        let mut history = f.history.clone();
        let devices = history_verdict(&mut history, &ordered, &event, &f);
        assert_eq!(devices, Outcome::Rejected, "{name}");
        assert_eq!(spine_verdict(&f, &event, &ordered), devices, "{name}");
    }
    // A truthful observation at any position since the last control is
    // valid without the service having seen that content.
    let since = f.history.head();
    f.content(2);
    let event = f.copy(
        Binding {
            seen: since,
            seen_receipt: receipt_for(f.base, since),
            ..f.binding(&f.first, CLASS_CONTROL)
        },
        add_third.as_bytes(),
        &f.first.control,
    );
    let ordered = f.order(&event, Route::Control);
    let mut history = f.history.clone();
    assert_eq!(
        history_verdict(&mut history, &ordered, &event, &f),
        Outcome::Accepted
    );
    assert_eq!(spine_verdict(&f, &event, &ordered), Outcome::Accepted);
}

#[test]
fn spine_effect_matches_history_transition() {
    let f = busy();
    let add_third = f.add(&f.first, &f.third);
    let remove_second = f.remove(&f.second);
    for (event, change) in [
        (
            f.copy(
                f.binding(&f.first, CLASS_CONTROL),
                add_third.as_bytes(),
                &f.first.control,
            ),
            ControlChange::AddDevice,
        ),
        (
            f.copy(
                f.binding(&f.first, CLASS_CONTROL),
                remove_second.as_bytes(),
                &f.first.control,
            ),
            ControlChange::RemoveSelf,
        ),
    ] {
        let ordered = f.order(&event, Route::Control);
        let mut history = f.history.clone();
        assert_eq!(
            history_verdict(&mut history, &ordered, &event, &f),
            Outcome::Accepted
        );
        let effect = f
            .spine
            .check(
                &f.account,
                &event.descriptor,
                &event.body,
                &f.metadata,
                &ordered,
            )
            .unwrap();
        assert_eq!(effect.change, change);
        assert_eq!(effect.digest, ordered.event_digest());
        assert_eq!(effect.epoch_after, history.epoch_id());
        assert_eq!(effect.account_head_after, history.account_head());
        assert_eq!(
            effect.epoch_after,
            match change {
                ControlChange::AddDevice => Some(key_id(&f.epoch)),
                ControlChange::RemoveSelf => None,
            }
        );
        // Checked before ordering, the same submission has the same effect.
        let submitted = f
            .spine
            .check_submission(&f.account, &event.descriptor, &event.body, &f.metadata)
            .unwrap();
        assert_eq!(submitted, effect);
        let mut spine = f.spine.clone();
        spine.apply(effect, &ordered).unwrap();
        let state = spine.state();
        assert_eq!(state.epoch, history.epoch_id());
        assert_eq!(state.account, history.account_head());
        assert_eq!(state.control_digest, ordered.event_digest().0);
        assert_eq!(state.control_head, ordered.head());
        assert_eq!(state.floor, history.floor());
        assert_eq!(
            state.account_changes.last().map(Vec::as_slice),
            Some(match change {
                ControlChange::AddDevice => add_third.as_bytes(),
                ControlChange::RemoveSelf => remove_second.as_bytes(),
            })
        );
    }
}

#[test]
fn submission_effect_cannot_apply_at_its_seen_position() {
    let mut f = Fixture::new();
    f.content(1);
    let add = f.add(&f.first, &f.second);
    let copy = f.copy(
        f.binding(&f.first, CLASS_CONTROL),
        add.as_bytes(),
        &f.first.control,
    );
    let effect = f
        .spine
        .check_submission(&f.account, &copy.descriptor, &copy.body, &f.metadata)
        .unwrap();
    // The untrusted sequencer places it at the already attested content
    // position, while its previous head still follows this spine's control.
    let ordered = Commitment::order(
        f.base,
        f.genesis_order.head(),
        &copy.descriptor,
        Route::Control,
    )
    .unwrap();
    assert_eq!(ordered.head().position, f.history.head().position);
    let before = f.spine.state().clone();
    assert_eq!(f.spine.apply(effect, &ordered), Err(Outcome::IntegrityStop));
    assert!(f.spine.state() == &before);
}

#[test]
fn effects_judged_against_the_same_predecessor_cannot_both_apply() {
    let mut f = Fixture::new();
    let second = f.add(&f.first, &f.second);
    let third = f.add(&f.first, &f.third);
    let copy_second = f.copy(
        f.binding(&f.first, CLASS_CONTROL),
        second.as_bytes(),
        &f.first.control,
    );
    let copy_third = f.copy(
        f.binding(&f.first, CLASS_CONTROL),
        third.as_bytes(),
        &f.first.control,
    );
    let first = f
        .spine
        .check_submission(
            &f.account,
            &copy_second.descriptor,
            &copy_second.body,
            &f.metadata,
        )
        .unwrap();
    let stale = f
        .spine
        .check_submission(
            &f.account,
            &copy_third.descriptor,
            &copy_third.body,
            &f.metadata,
        )
        .unwrap();
    let first_order = f.order(&copy_second, Route::Control);
    let second_order = Commitment::order(
        f.base,
        first_order.head(),
        &copy_third.descriptor,
        Route::Control,
    )
    .unwrap();
    f.spine.apply(first, &first_order).unwrap();
    let after_first = f.spine.state().clone();
    assert_eq!(
        f.spine.apply(stale, &second_order),
        Err(Outcome::IntegrityStop)
    );
    assert!(f.spine.state() == &after_first);
}

#[test]
fn control_at_the_control_head_must_extend_its_exact_hash() {
    let mut f = Fixture::new();
    let add = f.add(&f.first, &f.second);
    let copy = f.copy(
        f.binding(&f.first, CLASS_CONTROL),
        add.as_bytes(),
        &f.first.control,
    );
    let forked = Commitment::order(
        f.base,
        Head {
            position: f.spine.state().control_head.position,
            hash: bh_sync::Digest([0x83; 32]),
        },
        &copy.descriptor,
        Route::Control,
    )
    .unwrap();
    assert_eq!(
        f.spine.check(
            &f.account,
            &copy.descriptor,
            &copy.body,
            &f.metadata,
            &forked
        ),
        Err(Outcome::IntegrityStop)
    );
    assert_eq!(f.spine.apply_rejected(&forked), Err(Outcome::IntegrityStop));
}

#[test]
fn rejected_control_holds_its_position_in_the_spine() {
    let mut f = busy();
    let add_third = f.add(&f.first, &f.third);
    let forged = f.copy(
        f.binding(&f.first, CLASS_CONTROL),
        add_third.as_bytes(),
        &f.first.signing,
    );
    let ordered = f.order(&forged, Route::Control);
    assert_eq!(spine_verdict(&f, &forged, &ordered), Outcome::Rejected);
    assert_eq!(f.step(&forged, Route::Control), Outcome::Rejected);
    let before = f.spine.state().clone();
    f.spine.apply_rejected(&ordered).unwrap();
    let state = f.spine.state();
    assert_eq!(state.control_head, ordered.head());
    assert_eq!(state.control, before.control);
    assert_eq!(state.control_digest, before.control_digest);
    assert_eq!(state.account, before.account);
    // An ordered control at or before the control head is the sequencer
    // contradicting itself.
    assert_eq!(
        f.spine
            .check(
                &f.account,
                &forged.descriptor,
                &forged.body,
                &f.metadata,
                &ordered
            )
            .err(),
        Some(Outcome::IntegrityStop)
    );
    f.content(1);
    // An author who saw the rejected control's position saw the last valid
    // control there.
    let at_rejected = ordered.head();
    let copy = f.copy(
        Binding {
            seen: at_rejected,
            seen_receipt: receipt_for(f.base, at_rejected),
            ..f.binding(&f.first, CLASS_CONTROL)
        },
        add_third.as_bytes(),
        &f.first.control,
    );
    let next = f.order(&copy, Route::Control);
    let effect = f
        .spine
        .check(&f.account, &copy.descriptor, &copy.body, &f.metadata, &next)
        .unwrap();
    // An effect applies only at the position its control was ordered.
    let mut spine = f.spine.clone();
    assert_eq!(
        spine.apply(effect.clone(), &ordered).err(),
        Some(Outcome::IntegrityStop)
    );
    assert_eq!(f.step(&copy, Route::Control), Outcome::Accepted);
    assert_eq!(f.spine.state().control_digest, effect.digest.0);
    assert_eq!(f.spine.state().account, add_third.head());
}
