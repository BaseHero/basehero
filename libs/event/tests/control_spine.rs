//! The service-side control follower gives exactly `History`'s verdict and
//! effect for a base's controls, without seeing its content; and `History`
//! refuses a sealed class the ordered route disagrees with.
use bh_account::{AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount};
use bh_crypto::{KemKey, Secret, SigningKey};
use bh_event::{
    ACCOUNT_CHANGE, ACCOUNT_CHANGE_V2, ACCOUNT_REKEY, Binding, CLASS_CONTENT, CLASS_CONTROL,
    ControlChange, ControlSpine, Encoded, GENESIS, History, NOTE, Outcome, Payload, key_id,
    note_payload, rekey::rekey_seals, seal, writer::DeviceWriterDeclaration,
};
use bh_sync::receipt::{self, RECEIPT_LEN};
use bh_sync::{BaseId, Commitment, EventId, Head, OpaqueEvent, Route};

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
    /// First uses of control-route IDs, as a follower's durable record.
    ids: std::collections::HashSet<EventId>,
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
                version: 3,
                highest: 3,
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
        let genesis_order = Commitment::order(
            base,
            bh_sync::OrderState::EMPTY,
            &genesis.descriptor,
            Route::Control,
        )
        .unwrap();
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
            ids: [genesis_order.event_id()].into(),
            genesis_order,
        }
    }
    /// Whether a control-route ID was used before, by this base's record.
    fn used(&self) -> impl Fn(EventId) -> Result<bool, Outcome> + '_ {
        |id| Ok(self.ids.contains(&id))
    }
    fn binding(&self, device: &Device, class: u8) -> Binding {
        Binding {
            version: 3,
            highest: 3,
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
        Commitment::order(
            self.base,
            self.history.order_state(),
            &event.descriptor,
            route,
        )
        .unwrap()
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
        if route == Route::Control {
            let checked = self.spine.check(
                &self.account,
                &event.descriptor,
                &event.body,
                &self.metadata,
                &ordered,
                &self.used(),
            );
            match outcome {
                Outcome::Accepted => {
                    let effect = checked.unwrap();
                    bh_event::account_run::apply_copies(
                        &mut self.account,
                        &effect.account_copies,
                        &root(),
                    )
                    .unwrap();
                    self.spine.apply(effect, &ordered).unwrap();
                    self.control = ordered.event_digest().0;
                }
                // Every raw control holds its place in the spine's order.
                Outcome::Rejected => {
                    assert_eq!(checked.err(), Some(Outcome::Rejected));
                    self.spine.apply_rejected(&ordered).unwrap();
                }
                _ => return outcome,
            }
            self.ids.insert(ordered.event_id());
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
        &f.used(),
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
fn genesis_on_content_route_cannot_decode() {
    let f = Fixture::new();
    // Canonical framing rejects a content genesis before either verifier
    // can be handed a forged commitment.
    let mut bytes = f.genesis_order.encode();
    assert_eq!(bytes[34], Route::Control as u8);
    bytes[34] = Route::Content as u8;
    assert!(Commitment::decode(&bytes).is_err());
    assert!(
        Commitment::order(
            f.base,
            bh_sync::OrderState::EMPTY,
            &f.genesis.descriptor,
            Route::Content,
        )
        .is_err()
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
                &f.used(),
            )
            .unwrap();
        assert_eq!(effect.change, change);
        assert_eq!(effect.digest, ordered.event_digest());
        assert_eq!(effect.epoch_after, history.epoch_id());
        assert_eq!(effect.account_head_after, history.account_head());
        assert_eq!(
            effect.epoch_after,
            match change {
                ControlChange::RemoveSelf => None,
                _ => Some(key_id(&f.epoch)),
            }
        );
        // Checked before ordering, the same submission has the same effect.
        let submitted = f
            .spine
            .check_submission(
                &f.account,
                &event.descriptor,
                &event.body,
                &f.metadata,
                &f.used(),
            )
            .unwrap();
        assert_eq!(submitted, effect);
        // The effect carries its exact copies; the spine keeps only heads.
        let copies = effect.account_copies.clone();
        let mut spine = f.spine.clone();
        spine.apply(effect, &ordered).unwrap();
        let state = spine.state();
        assert_eq!(state.epoch, history.epoch_id());
        assert_eq!(state.account, history.account_head());
        assert_eq!(state.control_digest, ordered.event_digest().0);
        assert_eq!(state.control_head, ordered.head());
        assert_eq!(state.floor, history.floor());
        assert_eq!(copies.len(), 1);
        let copied = copies.last().unwrap();
        assert_eq!(copied.confirmation, None);
        assert_eq!(
            copied.original,
            match change {
                ControlChange::RemoveSelf => remove_second.as_bytes(),
                _ => add_third.as_bytes(),
            }
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
        .check_submission(
            &f.account,
            &copy.descriptor,
            &copy.body,
            &f.metadata,
            &f.used(),
        )
        .unwrap();
    // The untrusted sequencer places it at the already attested content
    // position, while its previous head still follows this spine's control.
    let ordered = Commitment::order(
        f.base,
        f.genesis_order.after(),
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
            &f.used(),
        )
        .unwrap();
    let stale = f
        .spine
        .check_submission(
            &f.account,
            &copy_third.descriptor,
            &copy_third.body,
            &f.metadata,
            &f.used(),
        )
        .unwrap();
    let first_order = f.order(&copy_second, Route::Control);
    let second_order = Commitment::order(
        f.base,
        first_order.after(),
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
    // A structurally valid but untrusted canonical opening for a forked raw
    // control. Never synthesize an opening from the visible control Head.
    let before = f.genesis_order.after();
    let forked_before = bh_sync::OrderState::new(
        bh_sync::RawControlHead {
            position: before.raw_control().position,
            node_hash: bh_sync::Digest([0x83; 32]),
        },
        before.suffix_count(),
        before.suffix_hash(),
    )
    .unwrap();
    let forked =
        Commitment::order(f.base, forked_before, &copy.descriptor, Route::Control).unwrap();
    assert_eq!(
        f.spine.check(
            &f.account,
            &copy.descriptor,
            &copy.body,
            &f.metadata,
            &forked,
            &f.used(),
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
    let before = f.spine.state().clone();
    assert_eq!(f.step(&forged, Route::Control), Outcome::Rejected);
    let state = f.spine.state();
    assert_eq!(state.order, ordered.after());
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
                &ordered,
                &f.used(),
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
        .check(
            &f.account,
            &copy.descriptor,
            &copy.body,
            &f.metadata,
            &next,
            &f.used(),
        )
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

#[path = "support/runs.rs"]
mod runs;

const START: u64 = 1_000_000;

/// A base whose copy of the account has the second device, then the
/// second device's self-removal ordered in the account but not copied.
fn leaving() -> (runs::Base, runs::Confirmed, u64) {
    let mut f = runs::Base::new();
    let add = f.add(&f.first, &f.second);
    let added = f.order_at(&add, START);
    let run = f.run(&f.first, &[added]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    let leave = f.remove_self(&f.second);
    let left = f.order_at(&leave, START + 1);
    (f, left, leave.head().position)
}

/// `leaving`, with the removal copied and the rotation it requires ordered.
fn rotated() -> (runs::Base, runs::Confirmed) {
    let (mut f, left, reason) = leaving();
    let run = f.run(&f.first, &[left]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    let rotate = f.rotate(&f.first, reason);
    let rotation = f.order_at(&rotate, START + 2);
    (f, rotation)
}

/// A rekey body exactly as given.
fn rekey_payload(rotation: &runs::Confirmed, key: [u8; 32], count: u16, set: [u8; 32]) -> Vec<u8> {
    let mut data = (rotation.0.len() as u32).to_be_bytes().to_vec();
    data.extend(&rotation.0);
    data.extend(&rotation.1);
    data.extend(key);
    data.extend(count.to_be_bytes());
    data.extend(set);
    data
}

fn seals() -> Vec<Vec<u8>> {
    vec![vec![7; 1499], vec![8; 1499]]
}

#[test]
fn removal_closes_the_epoch_and_rekey_reopens_it_with_the_new_id() {
    let (mut f, left, reason) = leaving();
    let old = Secret::from_slice(f.epoch.expose()).unwrap();
    // Sealed before the removal is copied, ordered after it.
    let late = f.note(&f.first, "under the old key");
    let run = f.run(&f.first, &[left]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    assert_eq!(f.history.epoch_id(), None);
    assert_eq!(f.spine.state().epoch, None);
    assert_eq!(f.step(&late, Route::Content), Outcome::Rejected);

    let rotate = f.rotate(&f.first, reason);
    let rotation = f.order_at(&rotate, START + 2);
    let next = Secret::<32>::random();
    let rekey = runs::Base::sign_rekey(f.rekey(&f.first, &rotation, &next, &seals()), &f.first);
    assert_eq!(f.step(&rekey, Route::Control), Outcome::Accepted);
    assert_eq!(f.history.epoch_id(), Some(key_id(&next)));
    assert_eq!(f.spine.state().epoch, Some(key_id(&next)));
    assert_eq!(f.history.account_head(), f.ordered.head());
    f.epoch = next;
    let fresh = f.note(&f.first, "under the new key");
    assert_eq!(f.step(&fresh, Route::Content), Outcome::Accepted);
    let stale = f.note_under(&f.first, "under the old key again", &old);
    assert_eq!(f.step(&stale, Route::Content), Outcome::Rejected);
}

#[test]
fn removal_closes_the_epoch_even_when_no_seal_opens() {
    let (mut f, left, reason) = leaving();
    // The removal carries no seal: the epoch closes before anyone holds the
    // replacement key.
    let run = f.run(&f.first, &[left]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    assert_eq!(f.history.epoch_id(), None);
    // A rekey whose seals open for nobody still names the epoch: judging it
    // never opens a seal.
    let rotate = f.rotate(&f.first, reason);
    let rotation = f.order_at(&rotate, START + 2);
    let next = Secret::<32>::random();
    let rekey = runs::Base::sign_rekey(
        f.rekey(&f.first, &rotation, &next, &[vec![0; 1499]]),
        &f.first,
    );
    assert_eq!(f.step(&rekey, Route::Control), Outcome::Accepted);
    assert_eq!(f.history.epoch_id(), Some(key_id(&next)));
}

#[test]
fn rekey_must_use_the_ordinary_key_mode_and_others_must_not() {
    let (mut f, rotation) = rotated();
    let next = key_id(&Secret::random());
    let body = rekey_payload(&rotation, next, 1, [9; 32]);
    let ordinary = |mode| Binding {
        mode,
        ..f.binding(f.first.keys().id(), CLASS_CONTROL)
    };
    let fourth = runs::Device::new();
    let add = f.add(&f.first, &fourth);
    let confirmation = runs::Base::confirmation_by(
        &runs::hosting_root(),
        &f.ordered,
        &add,
        START + 3,
        START + 3,
        50,
    );
    let run = runs::Base::run_payload(1, &[(add.as_bytes().to_vec(), confirmation)]);
    for (name, binding, kind, data, signer) in [
        (
            "rekey in mode 0, control key",
            ordinary(0),
            ACCOUNT_REKEY,
            &body,
            &f.first.control,
        ),
        (
            "rekey in mode 0, ordinary key",
            ordinary(0),
            ACCOUNT_REKEY,
            &body,
            &f.first.signing,
        ),
        (
            "rekey in mode 2, control key",
            ordinary(2),
            ACCOUNT_REKEY,
            &body,
            &f.first.control,
        ),
        (
            "run in mode 2, ordinary key",
            ordinary(2),
            ACCOUNT_CHANGE_V2,
            &run,
            &f.first.signing,
        ),
        (
            "run in mode 2, control key",
            ordinary(2),
            ACCOUNT_CHANGE_V2,
            &run,
            &f.first.control,
        ),
        (
            "legacy copy in mode 2",
            ordinary(2),
            ACCOUNT_CHANGE,
            &add.as_bytes().to_vec(),
            &f.first.signing,
        ),
    ] {
        let event = f.control(binding, kind, data, signer);
        assert_eq!(
            f.history_verdict(&event, Route::Control),
            Outcome::Rejected,
            "{name}"
        );
        assert_eq!(
            f.spine_verdict(&event).err(),
            Some(Outcome::Rejected),
            "{name}"
        );
    }
    let valid = f.control(ordinary(2), ACCOUNT_REKEY, &body, &f.first.signing);
    assert_eq!(f.step(&valid, Route::Control), Outcome::Accepted);
    assert_eq!(f.history.epoch_id(), Some(next));

    // A legacy copy that is otherwise valid, in the ordinary-key mode.
    let mut f = runs::Base::new();
    let add = f.add(&f.first, &f.second);
    f.ordered.apply(add.as_bytes()).unwrap();
    let event = f.control(
        Binding {
            mode: 2,
            ..f.binding(f.first.keys().id(), CLASS_CONTROL)
        },
        ACCOUNT_CHANGE,
        add.as_bytes(),
        &f.first.signing,
    );
    assert_eq!(f.history_verdict(&event, Route::Control), Outcome::Rejected);
    assert_eq!(f.spine_verdict(&event).err(), Some(Outcome::Rejected));
    let legacy = f.legacy(&f.first, add.as_bytes());
    assert_eq!(f.step(&legacy, Route::Control), Outcome::Accepted);
}

#[test]
fn legacy_account_change_copies_stay_readable() {
    let mut f = runs::Base::new();
    // Untimed legacy history: an addition the base copies as before.
    let add = f.add(&f.first, &f.second);
    f.ordered.apply(add.as_bytes()).unwrap();
    let legacy = f.legacy(&f.first, add.as_bytes());
    let copied = f.spine_verdict(&legacy).unwrap().account_copies;
    assert_eq!(f.step(&legacy, Route::Control), Outcome::Accepted);
    assert_eq!(f.spine.state().account, f.ordered.head());
    assert_eq!(copied.len(), 1);
    assert_eq!(copied[0].original, add.as_bytes());
    assert_eq!(copied[0].confirmation, None);
    // A device stores the exact account event, as before.
    assert_eq!(f.changes, vec![add.as_bytes().to_vec()]);
    // Confirmed runs follow it.
    let third = f.add(&f.first, &f.third);
    let added = f.order_at(&third, START);
    let run = f.run(&f.first, &[added]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    // A trust change has no untimed legacy copy.
    let request = f.request_removal(&f.first, &f.second);
    let requested = f.order_at(&request, START + 1);
    let untimed = f.legacy(&f.first, request.as_bytes());
    assert_eq!(f.step(&untimed, Route::Control), Outcome::Rejected);
    let run = f.run(&f.first, &[requested]);
    assert_eq!(f.step(&run, Route::Control), Outcome::Accepted);
    // Stored records rebuild the base's copy, legacy and confirmed alike.
    let rebuilt = bh_event::account_run::base_account(&f.anchor, &f.changes, &root()).unwrap();
    assert_eq!(rebuilt.head(), f.history.account_head());
    let replayed = History::replay_with_account(
        &f.anchor,
        f.base,
        root(),
        &[],
        &f.metadata,
        Some(&f.epoch),
        f.records.clone(),
    )
    .unwrap();
    assert_eq!(replayed.account_head(), f.history.account_head());
    assert_eq!(replayed.head(), f.history.head());
}

#[test]
fn older_readers_pause_on_the_new_kinds() {
    let (f, left, _) = leaving();
    // What this build reads is the pattern a newer build's kinds meet here:
    // a control kind it does not know pauses, by an author it knows.
    let unknown = 0x0104;
    let known = f.control(
        f.binding(f.first.keys().id(), CLASS_CONTROL),
        unknown,
        b"newer",
        &f.first.control,
    );
    assert_eq!(
        f.history_verdict(&known, Route::Control),
        Outcome::UnsupportedPause
    );
    assert_eq!(
        f.spine_verdict(&known).err(),
        Some(Outcome::UnsupportedPause)
    );
    // An account event a run carries with a tag this build does not know.
    let tag = b"BaseHero account event\0".len() + 2 + 2 + 8 + 32 + 32 + 32;
    let mut newer = left.0.clone();
    newer[tag] = 0x40;
    let run = f.run_signed(
        f.first.keys().id(),
        &f.first.control,
        &[(newer.clone(), left.1.clone())],
    );
    assert_eq!(
        f.history_verdict(&run, Route::Control),
        Outcome::UnsupportedPause
    );
    assert_eq!(f.spine_verdict(&run).err(), Some(Outcome::UnsupportedPause));
    // Neither establishes an author not yet active: refused, never a pause
    // anyone holding M could cause.
    let stranger = f.control(
        f.binding(f.third.keys().id(), CLASS_CONTROL),
        unknown,
        b"newer",
        &f.third.control,
    );
    assert_eq!(
        f.history_verdict(&stranger, Route::Control),
        Outcome::Rejected
    );
    assert_eq!(f.spine_verdict(&stranger).err(), Some(Outcome::Rejected));
    let run = f.run_signed(f.third.keys().id(), &f.third.control, &[(newer, left.1)]);
    assert_eq!(f.history_verdict(&run, Route::Control), Outcome::Rejected);
    assert_eq!(f.spine_verdict(&run).err(), Some(Outcome::Rejected));
}

#[test]
fn spine_verdict_equals_history_verdict_for_runs_and_rekeys() {
    let (mut f, left, reason) = leaving();
    let leave = bh_account::AccountEvent::decode(&left.0).unwrap();
    let foreign = runs::Base::confirmation_by(
        &SigningKey::generate(),
        &f.account,
        &leave,
        START + 1,
        START + 1,
        9,
    );
    let one = |pair: &runs::Confirmed| std::slice::from_ref(pair).to_vec();
    let runs_cases: Vec<(&str, Encoded, Outcome)> = vec![
        ("valid run", f.run(&f.first, &one(&left)), Outcome::Accepted),
        (
            "run by the device it removes",
            f.run_signed(f.second.keys().id(), &f.second.control, &one(&left)),
            Outcome::Rejected,
        ),
        (
            "foreign-root confirmation",
            f.run_signed(
                f.first.keys().id(),
                &f.first.control,
                &[(left.0.clone(), foreign)],
            ),
            Outcome::Rejected,
        ),
        (
            "stale account head",
            f.control(
                Binding {
                    account_head: f.anchor.head(),
                    ..f.binding(f.first.keys().id(), CLASS_CONTROL)
                },
                ACCOUNT_CHANGE_V2,
                &runs::Base::run_payload(1, &one(&left)),
                &f.first.control,
            ),
            Outcome::Rejected,
        ),
        (
            "stale seen control",
            f.control(
                Binding {
                    seen_control: f.genesis_order.event_digest().0,
                    ..f.binding(f.first.keys().id(), CLASS_CONTROL)
                },
                ACCOUNT_CHANGE_V2,
                &runs::Base::run_payload(1, &one(&left)),
                &f.first.control,
            ),
            Outcome::Rejected,
        ),
    ];
    for (name, event, expected) in &runs_cases {
        let devices = f.history_verdict(event, Route::Control);
        let service = f.spine_verdict(event).err().unwrap_or(Outcome::Accepted);
        assert_eq!(devices, *expected, "{name}: History");
        assert_eq!(service, devices, "{name}: ControlSpine against History");
    }
    assert_eq!(f.step(&runs_cases[0].1, Route::Control), Outcome::Accepted);
    let rotate = f.rotate(&f.first, reason);
    let rotation = f.order_at(&rotate, START + 2);
    let next = Secret::<32>::random();
    let ordinary = |device: &runs::Device| Binding {
        mode: 2,
        ..f.binding(device.keys().id(), CLASS_CONTROL)
    };
    let body = |count| rekey_payload(&rotation, key_id(&next), count, [9; 32]);
    let prepared = f.rekey(&f.first, &rotation, &next, &seals());
    let set = prepared.seal_set.commitment();
    let rekeys: Vec<(&str, Encoded, Outcome)> = vec![
        (
            "valid rekey",
            runs::Base::sign_rekey(prepared, &f.first),
            Outcome::Accepted,
        ),
        (
            "rekey by the removed device",
            f.control(
                ordinary(&f.second),
                ACCOUNT_REKEY,
                &body(1),
                &f.second.signing,
            ),
            Outcome::Rejected,
        ),
        (
            "rekey with no seal",
            f.control(
                ordinary(&f.first),
                ACCOUNT_REKEY,
                &body(0),
                &f.first.signing,
            ),
            Outcome::Rejected,
        ),
        (
            "rekey of a confirmation from another root",
            f.control(
                ordinary(&f.first),
                ACCOUNT_REKEY,
                &rekey_payload(
                    &(
                        rotation.0.clone(),
                        runs::Base::confirmation_by(
                            &SigningKey::generate(),
                            &f.account,
                            &rotate,
                            START + 2,
                            START + 2,
                            9,
                        ),
                    ),
                    key_id(&next),
                    1,
                    [9; 32],
                ),
                &f.first.signing,
            ),
            Outcome::Rejected,
        ),
    ];
    for (name, event, expected) in &rekeys {
        let devices = f.history_verdict(event, Route::Control);
        let service = f.spine_verdict(event).err().unwrap_or(Outcome::Accepted);
        assert_eq!(devices, *expected, "{name}: History");
        assert_eq!(service, devices, "{name}: ControlSpine against History");
    }
    let effect = f.spine_verdict(&rekeys[0].1).unwrap();
    assert_eq!(effect.change, ControlChange::Rekey);
    assert_eq!(effect.epoch_after, Some(key_id(&next)));
    // The append the service permits must also order exactly this set.
    assert_eq!(effect.seal_set, Some(set));
    assert_eq!(f.step(&rekeys[0].1, Route::Control), Outcome::Accepted);
}

#[test]
fn rekey_commits_to_the_seal_set_not_its_bytes() {
    let (f, rotation) = rotated();
    let next = Secret::<32>::random();
    let prepared = f.rekey(&f.first, &rotation, &next, &seals());
    let set = prepared.seal_set.bytes().to_vec();
    let commitment = prepared.seal_set.commitment();
    let rekey = runs::Base::sign_rekey(prepared, &f.first);
    // The event names its own body; the set is a separate object.
    assert_ne!(
        bh_sync::referenced_body(&rekey.descriptor).unwrap(),
        commitment
    );
    let ordered = f.order_event(&rekey, Route::Control);
    let mut history = f.history.clone();
    let prepared = history
        .prepare(
            &ordered,
            &rekey.descriptor,
            Some(&rekey.body),
            &f.metadata,
            None,
        )
        .unwrap();
    let applied = history.consume_unapplied(prepared).unwrap();
    assert_eq!(applied.outcome(), Outcome::Accepted);
    assert_eq!(
        rekey_seals(&applied, &f.metadata, Some(&set)),
        Ok(Some((key_id(&next), seals())))
    );
    // Not yet fetched: retry later, nothing accepted.
    assert_eq!(
        rekey_seals(&applied, &f.metadata, None),
        Err(bh_event::Error::Unavailable)
    );
    let mut altered = set.clone();
    altered[100] ^= 1;
    assert_eq!(
        rekey_seals(&applied, &f.metadata, Some(&altered)),
        Err(bh_event::Error::Invalid)
    );
    // Another well-formed set for the same key is not the committed one.
    let other = f.rekey(&f.first, &rotation, &next, &seals());
    assert_eq!(
        rekey_seals(&applied, &f.metadata, Some(other.seal_set.bytes())),
        Err(bh_event::Error::Invalid)
    );
    // Any other event has no seals.
    let note = f.note(&f.first, "under the replaced key");
    let ordered = Commitment::order(
        f.base,
        history.order_state(),
        &note.descriptor,
        Route::Content,
    )
    .unwrap();
    let prepared = history
        .prepare(
            &ordered,
            &note.descriptor,
            Some(&note.body),
            &f.metadata,
            None,
        )
        .unwrap();
    let other = history.consume_unapplied(prepared).unwrap();
    assert_eq!(rekey_seals(&other, &f.metadata, Some(&set)), Ok(None));
}

#[test]
fn history_replays_without_the_seal_set() {
    let (mut f, rotation) = rotated();
    let next = Secret::<32>::random();
    let rekey = runs::Base::sign_rekey(f.rekey(&f.first, &rotation, &next, &seals()), &f.first);
    assert_eq!(f.step(&rekey, Route::Control), Outcome::Accepted);
    f.epoch = Secret::from_slice(next.expose()).unwrap();
    let note = f.note(&f.first, "after the rekey");
    assert_eq!(f.step(&note, Route::Content), Outcome::Accepted);
    // Every seal set may since have been deleted: replay needs only the
    // ordered events and their own bodies.
    let replayed = History::replay_with_account(
        &f.anchor,
        f.base,
        root(),
        &[],
        &f.metadata,
        Some(&next),
        f.records.clone(),
    )
    .unwrap();
    assert_eq!(replayed.epoch_id(), Some(key_id(&next)));
    assert_eq!(replayed.account_head(), f.ordered.head());
    assert_eq!(replayed.head(), f.history.head());
    let rebuilt = bh_event::account_run::base_account(&f.anchor, &f.changes, &root()).unwrap();
    assert_eq!(rebuilt.head(), f.ordered.head());
}

#[test]
fn spine_waits_for_an_omitted_control_instead_of_judging_past_it() {
    let mut f = Fixture::new();
    f.content(1);
    let (missed, view) = (f.spine.clone(), f.account.clone());
    let add = f.add(&f.first, &f.second);
    let copy = f.copy(
        f.binding(&f.first, CLASS_CONTROL),
        add.as_bytes(),
        &f.first.control,
    );
    assert_eq!(f.step(&copy, Route::Control), Outcome::Accepted);
    f.content(1);
    let remove = f.remove(&f.second);
    let removal = f.copy(
        f.binding(&f.first, CLASS_CONTROL),
        remove.as_bytes(),
        &f.first.control,
    );
    let ordered = f.order(&removal, Route::Control);
    // A follower handed the removal without the addition before it cannot
    // judge it, nor hold its place: it waits, and nothing it holds moves.
    assert_eq!(
        missed
            .check(
                &view,
                &removal.descriptor,
                &removal.body,
                &f.metadata,
                &ordered,
                &f.used(),
            )
            .err(),
        Some(Outcome::UnavailablePause)
    );
    let mut held = missed.clone();
    assert_eq!(
        held.apply_rejected(&ordered),
        Err(Outcome::UnavailablePause)
    );
    assert!(held.state() == missed.state());
    // Nor does it cover the endpoint the addition leads to.
    assert_eq!(
        missed
            .finish_coverage(ordered.before(), ordered.previous())
            .err(),
        Some(Outcome::UnavailablePause)
    );
    assert_eq!(f.step(&removal, Route::Control), Outcome::Accepted);
    assert_eq!(f.spine.state().epoch, None);
}

#[test]
fn every_raw_control_advances_the_spine_order_and_its_coverage() {
    let mut f = Fixture::new();
    f.content(1);
    let note = f.note(&f.first, "on the control route");
    assert_eq!(f.step(&note, Route::Control), Outcome::Rejected);
    assert_eq!(f.spine.state().order, f.history.order_state());
    f.content(2);
    let add = f.add(&f.first, &f.second);
    let copy = f.copy(
        f.binding(&f.first, CLASS_CONTROL),
        add.as_bytes(),
        &f.first.control,
    );
    assert_eq!(f.step(&copy, Route::Control), Outcome::Accepted);
    let state = f.spine.state().clone();
    assert_eq!(state.order, f.history.order_state());
    assert_eq!(state.order.head(f.base), state.control_head);
    // Trailing content after the last control: the endpoint it reaches is
    // covered, through the head a receipt names.
    f.content(2);
    let coverage = f
        .spine
        .finish_coverage(f.history.order_state(), f.history.head())
        .unwrap();
    assert_eq!(coverage.through(), f.history.head());
    assert_eq!(coverage.raw_control(), state.order.raw_control());
    // An opening the authenticated head does not name proves nothing.
    assert_eq!(
        f.spine
            .finish_coverage(f.history.order_state(), state.control_head)
            .err(),
        Some(Outcome::UnavailablePause)
    );
}

#[test]
fn a_used_control_id_is_rejected_only_on_its_route() {
    let mut f = Fixture::new();
    f.content(1);
    let add = f.add(&f.first, &f.second);
    let copy = f.copy(
        f.binding(&f.first, CLASS_CONTROL),
        add.as_bytes(),
        &f.first.control,
    );
    let ordered = f.order(&copy, Route::Control);
    let control_id = ordered.event_id();
    let check = |used: &dyn Fn(EventId) -> Result<bool, Outcome>| {
        f.spine.check(
            &f.account,
            &copy.descriptor,
            &copy.body,
            &f.metadata,
            &ordered,
            used,
        )
    };
    // The record's first use of this exact routed ID rejects it unjudged;
    // the same bytes' content-route ID reserves nothing here.
    assert_eq!(
        check(&|id| Ok(id == control_id)).err(),
        Some(Outcome::Rejected)
    );
    let content_id = copy.descriptor.publication_id(Route::Content);
    assert_ne!(content_id, control_id);
    assert!(check(&|id| Ok(id == content_id)).is_ok());
    // A record it cannot read is missing evidence.
    assert_eq!(
        check(&|_| Err(Outcome::UnavailablePause)).err(),
        Some(Outcome::UnavailablePause)
    );
    assert_eq!(
        f.spine
            .check_submission(
                &f.account,
                &copy.descriptor,
                &copy.body,
                &f.metadata,
                &|id| Ok(id == control_id),
            )
            .err(),
        Some(Outcome::Rejected)
    );
    // Ordered again after its first use, both followers reject it.
    assert_eq!(f.step(&copy, Route::Control), Outcome::Accepted);
    let again = f.order(&copy, Route::Control);
    assert_eq!(again.event_id(), control_id);
    assert_eq!(f.step(&copy, Route::Control), Outcome::Rejected);
    assert_eq!(f.spine.state().order, again.after());
}

#[test]
fn spine_inspection_without_a_body_matches_history() {
    let mut f = Fixture::new();
    f.content(1);
    let add = f.add(&f.first, &f.second);
    let copy = f.copy(
        f.binding(&f.first, CLASS_CONTROL),
        add.as_bytes(),
        &f.first.control,
    );
    let ordered = f.order(&copy, Route::Control);
    let control_id = ordered.event_id();
    // A valid control's verdict needs its body.
    assert_eq!(
        f.spine.inspect(
            &f.account,
            &copy.descriptor,
            &f.metadata,
            &ordered,
            &f.used()
        ),
        Ok(())
    );
    assert!(
        f.history
            .inspect(&ordered, &copy.descriptor, &f.metadata)
            .is_ok()
    );
    // A used ID, or bytes that are no signed original, are rejected
    // without one, by both followers.
    assert_eq!(
        f.spine
            .inspect(&f.account, &copy.descriptor, &f.metadata, &ordered, &|id| {
                Ok(id == control_id)
            }),
        Err(Outcome::Rejected)
    );
    let garbage = OpaqueEvent::new(EventId([42; 32]), vec![42; 1024]).unwrap();
    let ordered = f.order(
        &Encoded {
            descriptor: garbage.clone(),
            body: Vec::new(),
        },
        Route::Control,
    );
    assert_eq!(
        f.spine
            .inspect(&f.account, &garbage, &f.metadata, &ordered, &f.used()),
        Err(Outcome::Rejected)
    );
    assert_eq!(
        f.history.inspect(&ordered, &garbage, &f.metadata).err(),
        Some(Outcome::Rejected)
    );
}
