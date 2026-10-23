//! A base whose copy of the account follows confirmed account events: the
//! account log as its home orders and times it, the base's devices verifying
//! every event and the service following only its controls.
#![allow(dead_code)] // Each test file uses part of this fixture.

use bh_account::{
    AccountEvent, AccountId, DeviceId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount,
};
use bh_crypto::{KemKey, Secret, SigningKey};
use bh_event::{
    ACCOUNT_CHANGE, ACCOUNT_CHANGE_V2, Binding, CLASS_CONTENT, CLASS_CONTROL, ControlEffect,
    ControlSpine, Copier, Encoded, GENESIS, History, NOTE, Outcome, Payload, Seen,
    account_run::{apply_copies, prepare_account_run},
    key_id, note_payload,
    rekey::{PreparedRekey, prepare_rekey},
    seal,
    writer::DeviceWriterDeclaration,
};
use bh_sync::{
    BaseId, Commitment, Digest, EventId, Head, Route,
    evidence::{ConfirmationClaim, OrderingConfirmation, TimeBounds, original_digest},
    permit::{self, LogId, LogKind},
    receipt::{self, RECEIPT_LEN},
};

pub fn hosting_root() -> SigningKey {
    SigningKey::from_seed(&Secret::from_slice(&[0x61; 32]).unwrap())
}
pub fn root() -> [u8; 32] {
    hosting_root().public()
}
pub fn receipt_for(base: BaseId, head: Head) -> [u8; RECEIPT_LEN] {
    let key = SigningKey::from_seed(&Secret::from_slice(&[0x62; 32]).unwrap());
    let certificate =
        receipt::verify_certificate(&root(), &receipt::certify(&hosting_root(), key.public()))
            .unwrap();
    receipt::sign(&certificate, &key, base, head).unwrap()
}

pub struct Device {
    pub signing: SigningKey,
    pub control: SigningKey,
    pub receive: KemKey,
}
impl Device {
    pub fn new() -> Self {
        Self {
            signing: SigningKey::generate(),
            control: SigningKey::generate(),
            receive: KemKey::generate(),
        }
    }
    pub fn keys(&self) -> DevicePublicKeys {
        DevicePublicKeys::new(
            self.signing.public(),
            self.control.public(),
            self.receive.public(),
        )
        .unwrap()
    }
    pub fn id(&self) -> DeviceId {
        self.keys().id()
    }
}

pub struct Recovery {
    pub signing: SigningKey,
    pub receive: KemKey,
}
impl Recovery {
    pub fn new() -> Self {
        Self {
            signing: SigningKey::generate(),
            receive: KemKey::generate(),
        }
    }
    pub fn public(&self) -> RecoveryPublicKeys {
        RecoveryPublicKeys::new(self.signing.public(), self.receive.public())
    }
}

/// One account event as its home ordered it: the original and its ordering
/// confirmation.
pub type Confirmed = (Vec<u8>, Vec<u8>);

pub struct Base {
    pub first: Device,
    pub second: Device,
    pub third: Device,
    pub recovery: Recovery,
    /// The account as its home has it, with every confirmed time.
    pub ordered: VerifiedAccount,
    /// The account's confirmed events after the base genesis's head.
    pub log: Vec<Confirmed>,
    /// The base's copy of the account, as both followers apply it.
    pub account: VerifiedAccount,
    /// The account at the head the base genesis names.
    pub anchor: VerifiedAccount,
    pub metadata: Secret<32>,
    pub epoch: Secret<32>,
    pub base: BaseId,
    pub history: History,
    pub spine: ControlSpine,
    pub control: [u8; 32],
    pub genesis: Encoded,
    pub genesis_order: Commitment,
    /// Every ordered event of the base and its body, for replay.
    pub records: Vec<(Commitment, Vec<u8>, Vec<u8>)>,
    /// What each accepted account control left for a device to store.
    pub changes: Vec<Vec<u8>>,
    outer: u64,
}

impl Base {
    /// An account with its recovery record and personal key, and a base
    /// whose genesis names that head.
    pub fn new() -> Self {
        let first = Device::new();
        let recovery = Recovery::new();
        let request = AccountEvent::genesis(first.keys(), recovery.public());
        let genesis = request
            .finish(first.control.sign(request.signing_bytes()))
            .unwrap();
        let id = AccountId::of_genesis(&genesis).unwrap();
        let mut account = VerifiedAccount::from_genesis(id, genesis.as_bytes()).unwrap();
        let request = account
            .prepare_recovery_record(first.id(), [0x31; 32])
            .unwrap();
        let record = request
            .finish(first.control.sign(request.signing_bytes()))
            .unwrap();
        account.apply(record.as_bytes()).unwrap();
        let request = account
            .publish_personal_key(
                first.id(),
                KemKey::generate().public(),
                [0x32; 32],
                [0x33; 32],
            )
            .unwrap();
        let personal = request
            .finish(first.control.sign(request.signing_bytes()))
            .unwrap();
        account.apply(personal.as_bytes()).unwrap();
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
                device: first.id(),
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
        let (spine, _) = ControlSpine::from_genesis(
            &account,
            &genesis.descriptor,
            &genesis.body,
            &metadata,
            root(),
            &genesis_order,
        )
        .unwrap();
        let control = genesis_order.event_digest().0;
        let records = vec![(
            genesis_order,
            genesis.descriptor.encode(),
            genesis.body.clone(),
        )];
        Self {
            first,
            second: Device::new(),
            third: Device::new(),
            recovery,
            ordered: account.clone(),
            log: vec![],
            anchor: account.clone(),
            account,
            metadata,
            epoch,
            base,
            history,
            spine,
            control,
            genesis,
            genesis_order,
            records,
            changes: vec![],
            outer: 3,
        }
    }

    /// The confirmation `signer` (certified under `authority`) signs for
    /// `event` as the next event after `before`, at the given bounds.
    pub fn confirmation_by(
        authority: &SigningKey,
        before: &VerifiedAccount,
        event: &AccountEvent,
        earliest_ms: u64,
        latest_ms: u64,
        ordered: u64,
    ) -> Vec<u8> {
        let key = SigningKey::from_seed(&Secret::from_slice(&[0x63; 32]).unwrap());
        let head = |h: bh_account::Head| Head {
            position: h.position,
            hash: Digest(h.hash),
        };
        let claim = ConfirmationClaim {
            log: LogId {
                kind: LogKind::Account,
                id: [0x64; 32],
            },
            original: original_digest(event.as_bytes()),
            original_previous: head(before.head()),
            original_head: head(event.head()),
            body: None,
            ordered: Head {
                position: ordered,
                hash: Digest([0x65; 32]),
            },
            bounds: TimeBounds {
                earliest_ms,
                latest_ms,
            },
        };
        OrderingConfirmation::sign(&key, &permit::certify(authority, key.public()), claim)
            .encode()
            .to_vec()
    }

    /// Order `event` in the account log, confirmed at `[earliest, latest]`.
    pub fn order(&mut self, event: &AccountEvent, earliest_ms: u64, latest_ms: u64) -> Confirmed {
        self.outer += 1;
        let confirmation = Self::confirmation_by(
            &hosting_root(),
            &self.ordered,
            event,
            earliest_ms,
            latest_ms,
            self.outer,
        );
        self.ordered
            .apply_timed(
                event.as_bytes(),
                Some(bh_account::ConfirmedTime {
                    earliest_ms,
                    latest_ms,
                }),
            )
            .unwrap();
        let confirmed = (event.as_bytes().to_vec(), confirmation);
        self.log.push(confirmed.clone());
        confirmed
    }
    /// Order `event` confirmed at exactly `at`.
    pub fn order_at(&mut self, event: &AccountEvent, at: u64) -> Confirmed {
        self.order(event, at, at)
    }

    pub fn add(&self, author: &Device, added: &Device) -> AccountEvent {
        let request = self.ordered.add_device(author.id(), added.keys()).unwrap();
        request
            .finish(author.control.sign(request.signing_bytes()))
            .unwrap()
    }
    pub fn add_by_recovery(&self, recovery: &Recovery, added: &Device) -> AccountEvent {
        let request = self.ordered.add_device_by_recovery(added.keys()).unwrap();
        request
            .finish(recovery.signing.sign(request.signing_bytes()))
            .unwrap()
    }
    pub fn remove_self(&self, device: &Device) -> AccountEvent {
        let request = self.ordered.remove_self(device.id()).unwrap();
        request
            .finish(device.control.sign(request.signing_bytes()))
            .unwrap()
    }
    pub fn request_removal(&self, author: &Device, target: &Device) -> AccountEvent {
        let request = self
            .ordered
            .request_removal(author.id(), target.id())
            .unwrap();
        request
            .finish(author.control.sign(request.signing_bytes()))
            .unwrap()
    }
    pub fn cancel_by_recovery(&self, request: u64) -> AccountEvent {
        let draft = self.ordered.cancel_removal_by_recovery(request).unwrap();
        draft
            .finish(self.recovery.signing.sign(draft.signing_bytes()))
            .unwrap()
    }
    pub fn remove_now(&self, author: &Device, target: &Device) -> AccountEvent {
        let request = self.ordered.remove_now(author.id(), target.id()).unwrap();
        request
            .finish(
                author.control.sign(&request.device_signing_bytes()),
                self.recovery
                    .signing
                    .sign(&request.recovery_signing_bytes()),
            )
            .unwrap()
    }
    pub fn replace_recovery(&self, author: &Device, next: &Recovery) -> AccountEvent {
        let request = self
            .ordered
            .replace_recovery(author.id(), next.public(), [0x41; 32], [0x42; 32])
            .unwrap();
        request
            .finish(author.control.sign(request.signing_bytes()))
            .unwrap()
    }
    pub fn rotate(&self, author: &Device, reason: u64) -> AccountEvent {
        let request = self
            .ordered
            .rotate_personal(
                author.id(),
                reason,
                KemKey::generate().public(),
                [0x51; 32],
                [0x52; 32],
            )
            .unwrap();
        request
            .finish(author.signing.sign(request.signing_bytes()))
            .unwrap()
    }

    /// A binding for the next event by `device`, claiming what the base's
    /// devices have seen.
    pub fn binding(&self, device: DeviceId, class: u8) -> Binding {
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
            device,
            account_head: self.account.head(),
            seen: self.history.head(),
            seen_control: self.control,
            class,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: receipt_for(self.base, self.history.head()),
        }
    }
    pub fn seen(&self) -> Seen {
        Seen {
            head: self.history.head(),
            control: self.control,
            account: self.account.head(),
        }
    }
    /// A run payload exactly as given: `count || count × (len || original ||
    /// confirmation)`.
    pub fn run_payload(count: u8, run: &[Confirmed]) -> Vec<u8> {
        let mut data = vec![count];
        for (original, confirmation) in run {
            data.extend((original.len() as u32).to_be_bytes());
            data.extend(original);
            data.extend(confirmation);
        }
        data
    }
    /// A control of `kind` and `data`, sealed under `binding` and signed by
    /// `signer`.
    pub fn control(
        &self,
        binding: Binding,
        kind: u16,
        data: &[u8],
        signer: &SigningKey,
    ) -> Encoded {
        seal(
            binding,
            Payload { kind, data },
            signer,
            &self.metadata,
            None,
        )
        .unwrap()
    }
    /// A run copied by a device's control key, through the library producer.
    pub fn run(&self, copier: &Device, run: &[Confirmed]) -> Encoded {
        let request = prepare_account_run(
            self.base,
            &self.account,
            Copier::Device(copier.id()),
            &self.metadata,
            self.seen(),
            receipt_for(self.base, self.history.head()),
            run,
        )
        .unwrap();
        assert_eq!(request.expected_key(), &copier.control.public());
        let signature = copier.control.sign(request.signing_bytes());
        request.finish(signature).unwrap()
    }
    /// A run copied by `recovery`, signed under its recovery author.
    pub fn run_by_recovery(&self, recovery: &Recovery, run: &[Confirmed]) -> Encoded {
        let request = prepare_account_run(
            self.base,
            &self.account,
            Copier::Recovery,
            &self.metadata,
            self.seen(),
            receipt_for(self.base, self.history.head()),
            run,
        )
        .unwrap();
        assert_eq!(request.expected_key(), &recovery.signing.public());
        let signature = recovery.signing.sign(request.signing_bytes());
        request.finish(signature).unwrap()
    }
    /// A run by `author`'s id signed with `signer`, bypassing the producer's
    /// checks.
    pub fn run_signed(&self, author: DeviceId, signer: &SigningKey, run: &[Confirmed]) -> Encoded {
        self.control(
            self.binding(author, CLASS_CONTROL),
            ACCOUNT_CHANGE_V2,
            &Self::run_payload(run.len() as u8, run),
            signer,
        )
    }
    /// A legacy single-event copy by `author`.
    pub fn legacy(&self, author: &Device, event: &[u8]) -> Encoded {
        self.control(
            self.binding(author.id(), CLASS_CONTROL),
            ACCOUNT_CHANGE,
            event,
            &author.control,
        )
    }
    /// The rekey installing `next`, signed with `device`'s ordinary key.
    pub fn rekey(
        &self,
        device: &Device,
        rotation: &Confirmed,
        next: &Secret<32>,
        seals: &[Vec<u8>],
    ) -> PreparedRekey {
        let prepared = prepare_rekey(
            self.base,
            &self.account,
            device.id(),
            &self.metadata,
            self.seen(),
            receipt_for(self.base, self.history.head()),
            &rotation.0,
            &rotation.1,
            next,
            seals,
        )
        .unwrap();
        assert_eq!(prepared.control.expected_key(), &device.signing.public());
        prepared
    }
    pub fn sign_rekey(prepared: PreparedRekey, device: &Device) -> Encoded {
        let signature = device.signing.sign(prepared.control.signing_bytes());
        prepared.control.finish(signature).unwrap()
    }
    pub fn note(&self, device: &Device, text: &str) -> Encoded {
        self.note_under(device, text, &self.epoch)
    }
    pub fn note_under(&self, device: &Device, text: &str, epoch: &Secret<32>) -> Encoded {
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
            Binding {
                epoch: key_id(epoch),
                ..self.binding(device.id(), CLASS_CONTENT)
            },
            Payload {
                kind: NOTE,
                data: &data,
            },
            &device.signing,
            &self.metadata,
            Some(epoch),
        )
        .unwrap()
    }
    pub fn order_event(&self, event: &Encoded, route: Route) -> Commitment {
        Commitment::order(
            self.base,
            self.history.order_state(),
            &event.descriptor,
            route,
        )
        .unwrap()
    }

    /// History's verdict on `event` ordered next, without advancing.
    pub fn history_verdict(&self, event: &Encoded, route: Route) -> Outcome {
        let ordered = self.order_event(event, route);
        let mut history = self.history.clone();
        let outcome = match history.prepare(
            &ordered,
            &event.descriptor,
            Some(&event.body),
            &self.metadata,
            Some(&self.epoch),
        ) {
            Ok(prepared) => history.consume_unapplied(prepared).unwrap().outcome(),
            Err(outcome) => outcome,
        };
        assert!(!history.is_stopped());
        outcome
    }
    /// The service's verdict on a control ordered next.
    pub fn spine_verdict(&self, event: &Encoded) -> Result<ControlEffect, Outcome> {
        let ordered = self.order_event(event, Route::Control);
        // Every raw control this base ordered used its routed ID first.
        self.spine.check(
            &self.account,
            &event.descriptor,
            &event.body,
            &self.metadata,
            &ordered,
            &|id| {
                Ok(self
                    .records
                    .iter()
                    .any(|(o, _, _)| o.route() == Route::Control && o.event_id() == id))
            },
        )
    }

    /// Order and verify one event on every device; the service follows it
    /// when it is a control, and must reach the same verdict and effect.
    pub fn step(&mut self, event: &Encoded, route: Route) -> Outcome {
        let ordered = self.order_event(event, route);
        let service = (route == Route::Control).then(|| self.spine_verdict(event));
        let outcome = match self.history.prepare(
            &ordered,
            &event.descriptor,
            Some(&event.body),
            &self.metadata,
            Some(&self.epoch),
        ) {
            Ok(prepared) => {
                let applied = self.history.consume_unapplied(prepared).unwrap();
                if let Some(change) = applied.account_change() {
                    self.changes.push(change.to_vec());
                }
                applied.outcome()
            }
            Err(outcome) => {
                if let Some(service) = service {
                    assert_eq!(service.err(), Some(outcome), "ControlSpine against History");
                }
                return outcome;
            }
        };
        self.records
            .push((ordered, event.descriptor.encode(), event.body.clone()));
        match service {
            Some(Ok(effect)) => {
                assert_eq!(outcome, Outcome::Accepted, "History against ControlSpine");
                assert_eq!(effect.epoch_after, self.history.epoch_id());
                apply_copies(&mut self.account, &effect.account_copies, &root()).unwrap();
                assert_eq!(effect.account_head_after, self.history.account_head());
                self.spine.apply(effect, &ordered).unwrap();
                self.control = ordered.event_digest().0;
            }
            Some(Err(verdict)) => {
                assert_eq!(outcome, verdict, "History against ControlSpine");
                self.spine.apply_rejected(&ordered).unwrap();
            }
            None => {}
        }
        outcome
    }
}
