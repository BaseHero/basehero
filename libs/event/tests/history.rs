use bh_account::{AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount};
use bh_core::note::Note;
use bh_crypto::{KemKey, Secret, SigningKey, aead_open, aead_seal, derive_key};
use bh_event::{
    ACCOUNT_CHANGE, Binding, CLASS_CONTENT, CLASS_CONTROL, Encoded, GENESIS, History, NOTE,
    NoteTarget, Outcome, Payload, key_id, seal,
};
use bh_sync::{BaseId, Commitment, EventId, Head, OpaqueEvent};

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
struct Fixture {
    first: Device,
    second: Device,
    account: VerifiedAccount,
    metadata: Secret<32>,
    epoch: Secret<32>,
    base: BaseId,
    history: History,
    note: Note,
    control: [u8; 32],
    account_genesis: Vec<u8>,
    genesis: Encoded,
}
impl Fixture {
    fn new() -> Self {
        let first = Device::new();
        let second = Device::new();
        let req = AccountEvent::genesis(
            first.keys(),
            RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public()),
        );
        let account_genesis = req.finish(first.control.sign(req.signing_bytes())).unwrap();
        let id = AccountId::of_genesis(&account_genesis).unwrap();
        let account = VerifiedAccount::from_genesis(id, account_genesis.as_bytes()).unwrap();
        let metadata = Secret::<32>::random();
        let epoch = Secret::<32>::random();
        assert_ne!(key_id(&metadata), key_id(&epoch));
        let binding = Binding {
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
        };
        let mut data = Vec::new();
        data.extend(id.0);
        data.extend(account.head().position.to_be_bytes());
        data.extend(account.head().hash);
        data.extend([0; 32]);
        data.extend(key_id(&epoch));
        data.extend(key_id(&metadata));
        let genesis = seal(
            binding,
            Payload {
                kind: GENESIS,
                data: &data,
            },
            &first.control,
            &metadata,
            None,
        )
        .unwrap();
        assert_eq!(genesis.descriptor.encode().len(), 1062);
        assert_eq!(genesis.body.len(), 1024);
        let base = BaseId::from_genesis(&genesis.descriptor);
        let ordered = Commitment::order(base, Head::EMPTY, &genesis.descriptor).unwrap();
        let mut history = History::new(id, account_genesis.as_bytes(), base, 1).unwrap();
        let mut note = Note::new();
        assert_eq!(
            history
                .inspect(&ordered, &genesis.descriptor, &metadata)
                .unwrap()
                .epoch,
            key_id(&metadata)
        );
        assert_eq!(
            history.apply(
                &ordered,
                &genesis.descriptor,
                Some(&genesis.body),
                &metadata,
                None,
                NoteTarget {
                    id: [7; 32],
                    note: &mut note
                }
            ),
            Outcome::Accepted
        );
        Self {
            first,
            second,
            account,
            metadata,
            epoch,
            base,
            history,
            note,
            control: ordered.event_digest().0,
            account_genesis: account_genesis.as_bytes().to_vec(),
            genesis,
        }
    }
    fn binding(&self, device: &Device, class: u8) -> Binding {
        Binding {
            version: 1,
            highest: 1,
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
        }
    }
    fn create(
        &self,
        binding: Binding,
        kind: u16,
        data: &[u8],
        signer: &SigningKey,
        content: Option<&Secret<32>>,
    ) -> (Encoded, Commitment) {
        let event = seal(
            binding,
            Payload { kind, data },
            signer,
            &self.metadata,
            content,
        )
        .unwrap();
        let ordered = Commitment::order(self.base, self.history.head(), &event.descriptor).unwrap();
        (event, ordered)
    }
    fn content(&self, device: &Device, kind: u16, data: &[u8]) -> (Encoded, Commitment) {
        self.create(
            self.binding(device, CLASS_CONTENT),
            kind,
            data,
            &device.signing,
            Some(&self.epoch),
        )
    }
    fn apply(&mut self, event: &Encoded, ordered: &Commitment, content: bool) -> Outcome {
        let outcome = self.history.apply(
            ordered,
            &event.descriptor,
            Some(&event.body),
            &self.metadata,
            if content { Some(&self.epoch) } else { None },
            NoteTarget {
                id: [7; 32],
                note: &mut self.note,
            },
        );
        if !content && (outcome == Outcome::Accepted || outcome == Outcome::ContentRejected) {
            self.control = ordered.event_digest().0;
        }
        outcome
    }
}
// Re-encrypt the SAME original S/signature under another locally supplied M.
// No new original is signed; the untrusted O/ordering commitment changes.
fn rewrap_metadata(
    event: &OpaqueEvent,
    base: BaseId,
    from: &Secret<32>,
    to: &Secret<32>,
) -> OpaqueEvent {
    let env = event.envelope();
    let mut aad = b"bh/author-binding-aad/v1\0".to_vec();
    aad.extend(1u16.to_be_bytes());
    aad.push(0);
    aad.extend(base.0);
    aad.extend(event.id().0);
    aad.extend(&env[..32]);
    let from_key = derive_key(from, b"bhBind01", 0);
    let plaintext =
        aead_open(&from_key, env[32..56].try_into().unwrap(), &aad, &env[56..]).unwrap();
    let to_key = derive_key(to, b"bhBind01", 0);
    let (nonce, cipher) = aead_seal(&to_key, &aad, plaintext.expose()).unwrap();
    let mut envelope = env[..32].to_vec();
    envelope.extend(nonce);
    envelope.extend(cipher);
    OpaqueEvent::new(event.id(), envelope).unwrap()
}

fn note_delta(text: &str) -> (Vec<u8>, Note) {
    let mut note = Note::new();
    let mut data = vec![7; 32];
    data.extend(note.append_paragraph(text));
    (data, note)
}
// Real re-signing/re-encryption reaches history validation, not just O's hash.
fn rebind(
    event: &OpaqueEvent,
    base: BaseId,
    metadata: &Secret<32>,
    signer: &SigningKey,
    change: impl FnOnce(&mut [u8]),
) -> OpaqueEvent {
    let env = event.envelope();
    let digest = &env[..32];
    let aad = |version: u16| {
        let mut ad = b"bh/author-binding-aad/v1\0".to_vec();
        ad.extend(version.to_be_bytes());
        ad.push(0);
        ad.extend(base.0);
        ad.extend(event.id().0);
        ad.extend(digest);
        ad
    };
    let key = derive_key(metadata, b"bhBind01", 0);
    let nonce: &[u8; 24] = env[32..56].try_into().unwrap();
    let mut plain = aead_open(&key, nonce, &aad(1), &env[56..])
        .unwrap()
        .expose()
        .to_vec();
    change(&mut plain[..346]);
    let mut signed = b"bh/original-envelope/v1\0".to_vec();
    signed.extend(&plain[..346]);
    plain[346..410].copy_from_slice(&signer.sign(&signed));
    let version = u16::from_be_bytes(plain[..2].try_into().unwrap());
    let (nonce, body) = aead_seal(&key, &aad(version), &plain).unwrap();
    plain.fill(0);
    let mut envelope = digest.to_vec();
    envelope.extend(nonce);
    envelope.extend(body);
    OpaqueEvent::new(event.id(), envelope).unwrap()
}

#[test]
fn unrelated_metadata_root_cannot_rewrap_a_valid_content_original() {
    let mut f = Fixture::new();
    let (prior, _) = note_delta("prior");
    let (first, order) = f.content(&f.first, NOTE, &prior);
    assert_eq!(f.apply(&first, &order, true), Outcome::Accepted);
    let note_before = f.note.state();
    let head_before = f.history.head();
    let floor_before = f.history.floor();
    let (data, _) = note_delta("next");
    let (event, original_order) = f.content(&f.first, NOTE, &data);
    assert!(
        f.history
            .inspect(&original_order, &event.descriptor, &f.metadata)
            .is_ok()
    );
    let unrelated_m = Secret::<32>::random();
    assert_ne!(key_id(&unrelated_m), key_id(&f.metadata));
    let rewrapped = rewrap_metadata(&event.descriptor, f.base, &f.metadata, &unrelated_m);
    assert_ne!(rewrapped.digest(), event.descriptor.digest());
    let rewrapped_order = Commitment::order(f.base, head_before, &rewrapped).unwrap();
    assert_eq!(
        f.history
            .inspect(&rewrapped_order, &rewrapped, &unrelated_m)
            .err(),
        Some(Outcome::IntegrityStop)
    );
    assert_eq!(
        f.history.apply(
            &rewrapped_order,
            &rewrapped,
            Some(&event.body),
            &unrelated_m,
            Some(&f.epoch),
            NoteTarget {
                id: [7; 32],
                note: &mut f.note
            }
        ),
        Outcome::IntegrityStop
    );
    assert_eq!(f.note.state(), note_before);
    assert_eq!(f.history.head(), head_before);
    assert_eq!(f.history.floor(), floor_before);
    assert!(f.history.is_stopped());
}

#[test]
fn signed_inner_unknown_account_version_pauses_but_bad_original_stops() {
    let mut f = Fixture::new();
    let (prior, _) = note_delta("prior");
    let (first, order) = f.content(&f.first, NOTE, &prior);
    assert_eq!(f.apply(&first, &order, true), Outcome::Accepted);
    let note_before = f.note.state();
    let head_before = f.history.head();
    let account_before = f.history.account_head();
    let floor_before = f.history.floor();
    let req = f
        .account
        .add_device(f.first.keys().id(), f.second.keys())
        .unwrap();
    let original = req
        .finish(f.first.control.sign(req.signing_bytes()))
        .unwrap();
    let mut future = original.as_bytes().to_vec();
    let version_offset = b"BaseHero account event\0".len();
    future[version_offset..version_offset + 4].copy_from_slice(&[0, 2, 0, 2]);
    let signature = f.first.control.sign(&future[..future.len() - 64]);
    let signature_offset = future.len() - 64;
    future[signature_offset..].copy_from_slice(&signature);
    assert!(matches!(
        AccountEvent::decode(&future),
        Err(bh_account::Error::UnsupportedVersion)
    ));
    let (event, order) = f.create(
        f.binding(&f.first, CLASS_CONTROL),
        ACCOUNT_CHANGE,
        &future,
        &f.first.control,
        None,
    );
    assert!(
        f.history
            .inspect(&order, &event.descriptor, &f.metadata)
            .is_ok()
    );
    assert_eq!(f.apply(&event, &order, false), Outcome::UnsupportedPause);
    assert_eq!(f.history.head(), head_before);
    assert_eq!(f.history.account_head(), account_before);
    assert_eq!(f.history.floor(), floor_before);
    assert_eq!(f.note.state(), note_before);
    assert!(!f.history.is_stopped());
    let mut corrupt = original.as_bytes().to_vec();
    *corrupt.last_mut().unwrap() ^= 1;
    let (event, order) = f.create(
        f.binding(&f.first, CLASS_CONTROL),
        ACCOUNT_CHANGE,
        &corrupt,
        &f.first.control,
        None,
    );
    assert!(
        f.history
            .inspect(&order, &event.descriptor, &f.metadata)
            .is_ok()
    );
    assert_eq!(f.apply(&event, &order, false), Outcome::IntegrityStop);
    assert_eq!(f.history.head(), head_before);
    assert_eq!(f.history.account_head(), account_before);
    assert_eq!(f.note.state(), note_before);
    assert!(f.history.is_stopped());
}

#[test]
fn real_genesis_note_and_selective_descriptor() {
    let mut f = Fixture::new();
    let (data, edited) = note_delta("hello");
    let (event, order) = f.content(&f.first, NOTE, &data);
    assert!(
        f.history
            .inspect(&order, &event.descriptor, &f.metadata)
            .unwrap()
            .device
            == f.first.keys().id()
    );
    assert_eq!(f.history.head().position, 1); // no B needed to verify descriptor/original
    assert_eq!(
        f.history.apply(
            &order,
            &event.descriptor,
            None,
            &f.metadata,
            Some(&f.epoch),
            NoteTarget {
                id: [7; 32],
                note: &mut f.note
            }
        ),
        Outcome::UnavailablePause
    );
    assert_eq!(f.apply(&event, &order, true), Outcome::Accepted);
    assert_eq!(f.note.state(), edited.state());
    assert_eq!(f.history.head().position, 2);
}

#[test]
fn malformed_authentic_note_rejects_content_then_accepts_next() {
    let mut f = Fixture::new();
    let (data, mut edited) = note_delta("prior");
    let (event, order) = f.content(&f.first, NOTE, &data);
    assert_eq!(f.apply(&event, &order, true), Outcome::Accepted);
    let before = f.note.state();
    let mut bad = vec![7; 32];
    bad.extend([0xff, 0xff, 0xff]);
    let (event, order) = f.content(&f.first, NOTE, &bad);
    assert_eq!(f.apply(&event, &order, true), Outcome::ContentRejected);
    assert_eq!(f.note.state(), before);
    assert_eq!(f.history.head(), order.head());
    assert_eq!(f.history.floor(), 1);
    let mut next = vec![7; 32];
    next.extend(edited.append_paragraph("later"));
    let (event, order) = f.content(&f.first, NOTE, &next);
    assert_eq!(f.apply(&event, &order, true), Outcome::Accepted);
    assert_eq!(f.note.state(), edited.state());
}

#[test]
fn unsupported_semantics_pause_and_ciphertext_tamper_stops_without_losing_note() {
    let mut f = Fixture::new();
    let (data, _) = note_delta("prior");
    let (event, order) = f.content(&f.first, NOTE, &data);
    assert_eq!(f.apply(&event, &order, true), Outcome::Accepted);
    let before = f.note.state();
    let head = f.history.head();
    let (unknown, order) = f.content(&f.first, 0xf123, &data);
    assert_eq!(f.apply(&unknown, &order, true), Outcome::UnsupportedPause);
    assert_eq!(f.history.head(), head);
    assert_eq!(f.note.state(), before);
    let (unknown, order) = f.create(
        f.binding(&f.first, CLASS_CONTROL),
        0xf124,
        &[],
        &f.first.control,
        None,
    );
    assert_eq!(f.apply(&unknown, &order, false), Outcome::UnsupportedPause);
    assert_eq!(f.history.head(), head);
    let (mut bad, _) = f.content(&f.first, NOTE, &data);
    bad.body[31] ^= 1; // recompute untrusted outer order: body commitment remains signed and rejects
    let order = Commitment::order(f.base, head, &bad.descriptor).unwrap();
    assert_eq!(f.apply(&bad, &order, true), Outcome::IntegrityStop);
    assert_eq!(f.note.state(), before);
    assert_eq!(f.history.head(), head);
    assert!(f.history.is_stopped());
}

#[test]
fn signed_seen_forks_and_original_signature_are_checked_inside_outer_commitment() {
    let f = Fixture::new();
    let (data, _) = note_delta("one");
    let (event, _) = f.content(&f.first, NOTE, &data);
    for mutate in [
        245usize, 277, 197, 205, 133, 165, 37, 69, 101, 309, 310, 314,
    ] {
        let altered = rebind(
            &event.descriptor,
            f.base,
            &f.metadata,
            &f.first.signing,
            |s| s[mutate] ^= 1,
        );
        let order = Commitment::order(f.base, f.history.head(), &altered).unwrap();
        let mut history = f.history.clone();
        let mut note = Note::new();
        assert_eq!(
            history.apply(
                &order,
                &altered,
                Some(&event.body),
                &f.metadata,
                Some(&f.epoch),
                NoteTarget {
                    id: [7; 32],
                    note: &mut note
                }
            ),
            Outcome::IntegrityStop,
            "S offset {mutate}"
        );
        assert_eq!(note.state(), Note::new().state());
    }
    let altered = rebind(
        &event.descriptor,
        f.base,
        &f.metadata,
        &SigningKey::generate(),
        |_| {},
    );
    let order = Commitment::order(f.base, f.history.head(), &altered).unwrap();
    assert_eq!(
        f.history.inspect(&order, &altered, &f.metadata).err(),
        Some(Outcome::IntegrityStop)
    );
    let wrong = Secret::<32>::random();
    assert_eq!(
        f.history
            .inspect(
                &Commitment::order(f.base, f.history.head(), &event.descriptor).unwrap(),
                &event.descriptor,
                &wrong
            )
            .err(),
        Some(Outcome::IntegrityStop)
    );
}

#[test]
fn account_controls_require_original_account_history_and_close_old_epoch() {
    let mut f = Fixture::new();
    let add = f
        .account
        .add_device(f.first.keys().id(), f.second.keys())
        .unwrap();
    let add = add
        .finish(f.first.control.sign(add.signing_bytes()))
        .unwrap();
    let binding = f.binding(&f.first, CLASS_CONTROL);
    let (event, order) = f.create(
        binding,
        ACCOUNT_CHANGE,
        add.as_bytes(),
        &f.first.control,
        None,
    );
    // Correct current predecessor but fabricated seen chain: genuinely re-signed.
    let fork = rebind(
        &event.descriptor,
        f.base,
        &f.metadata,
        &f.first.control,
        |s| s[245] ^= 1,
    );
    let reordered = Commitment::order(f.base, f.history.head(), &fork).unwrap();
    assert_eq!(
        f.history.inspect(&reordered, &fork, &f.metadata).err(),
        Some(Outcome::IntegrityStop)
    );
    // Latest predecessor at ordering but not at author's claimed seen position.
    let fork = rebind(
        &event.descriptor,
        f.base,
        &f.metadata,
        &f.first.control,
        |s| {
            s[237..245].copy_from_slice(&0u64.to_be_bytes());
            s[245..277].fill(0);
        },
    );
    let reordered = Commitment::order(f.base, f.history.head(), &fork).unwrap();
    assert_eq!(
        f.history.inspect(&reordered, &fork, &f.metadata).err(),
        Some(Outcome::IntegrityStop)
    );
    assert_eq!(f.apply(&event, &order, false), Outcome::Accepted);
    f.account.apply(add.as_bytes()).unwrap();
    // The latest ordering predecessor (the add) was not yet present at the
    // signed seen head (genesis). Keep account prefix valid at that old head.
    let second_remove = f.account.remove_self(f.second.keys().id()).unwrap();
    let second_remove = second_remove
        .finish(f.second.control.sign(second_remove.signing_bytes()))
        .unwrap();
    let (candidate, _) = f.create(
        f.binding(&f.second, CLASS_CONTROL),
        ACCOUNT_CHANGE,
        second_remove.as_bytes(),
        &f.second.control,
        None,
    );
    let genesis_head = Commitment::order(f.base, Head::EMPTY, &f.genesis.descriptor)
        .unwrap()
        .head();
    let original_account_head = AccountEvent::decode(&f.account_genesis).unwrap().head();
    let fork = rebind(
        &candidate.descriptor,
        f.base,
        &f.metadata,
        &f.second.control,
        |s| {
            s[197..205].copy_from_slice(&original_account_head.position.to_be_bytes());
            s[205..237].copy_from_slice(&original_account_head.hash);
            s[237..245].copy_from_slice(&genesis_head.position.to_be_bytes());
            s[245..277].copy_from_slice(&genesis_head.hash.0);
            // signed predecessor remains add's digest, correct at ordering but wrong at seen.
        },
    );
    let reordered = Commitment::order(f.base, f.history.head(), &fork).unwrap();
    assert_eq!(
        f.history.inspect(&reordered, &fork, &f.metadata).err(),
        Some(Outcome::IntegrityStop)
    );
    let (data, _) = note_delta("second device");
    let (note_event, note_order) = f.content(&f.second, NOTE, &data);
    assert_eq!(f.apply(&note_event, &note_order, true), Outcome::Accepted);
    let remove = f.account.remove_self(f.first.keys().id()).unwrap();
    let remove = remove
        .finish(f.first.control.sign(remove.signing_bytes()))
        .unwrap();
    let (event, order) = f.create(
        f.binding(&f.first, CLASS_CONTROL),
        ACCOUNT_CHANGE,
        remove.as_bytes(),
        &f.first.control,
        None,
    );
    assert_eq!(f.apply(&event, &order, false), Outcome::Accepted);
    f.account.apply(remove.as_bytes()).unwrap();
    let checkpoint = f.history.head();
    let (old, ordered) = f.content(&f.second, NOTE, &data);
    assert_eq!(
        f.history
            .inspect(&ordered, &old.descriptor, &f.metadata)
            .err(),
        Some(Outcome::IntegrityStop)
    );
    assert_eq!(f.history.head(), checkpoint);
    // M-only control by remaining device progresses without K_e.
    let second_remove = f.account.remove_self(f.second.keys().id()).unwrap();
    let second_remove = second_remove
        .finish(f.second.control.sign(second_remove.signing_bytes()))
        .unwrap();
    let (event, order) = f.create(
        f.binding(&f.second, CLASS_CONTROL),
        ACCOUNT_CHANGE,
        second_remove.as_bytes(),
        &f.second.control,
        None,
    );
    assert_eq!(f.apply(&event, &order, false), Outcome::Accepted);
    assert_eq!(f.history.account_head(), second_remove.head());
}

#[test]
fn event_version_floor_capability_and_duplicate_identity() {
    let f = Fixture::new();
    let (data, _) = note_delta("version");
    let (event, _) = f.content(&f.first, NOTE, &data);
    for (offset, bytes, expected) in [
        (2usize, [0, 0], Outcome::IntegrityStop),
        (2, [0, 2], Outcome::Accepted),
    ] {
        let changed = rebind(
            &event.descriptor,
            f.base,
            &f.metadata,
            &f.first.signing,
            |s| s[offset..offset + 2].copy_from_slice(&bytes),
        );
        let order = Commitment::order(f.base, f.history.head(), &changed).unwrap();
        let mut state = f.history.clone();
        let mut note = Note::new();
        assert_eq!(
            state.apply(
                &order,
                &changed,
                Some(&event.body),
                &f.metadata,
                Some(&f.epoch),
                NoteTarget {
                    id: [7; 32],
                    note: &mut note
                }
            ),
            expected
        );
        assert_eq!(state.floor(), 1);
    }
    let mut high = History::new(f.account.id(), &f.account_genesis, f.base, 2).unwrap();
    // A remembered v2 floor rejects even a correctly signed v1 genesis.
    let first = Commitment::order(f.base, Head::EMPTY, &f.genesis.descriptor).unwrap();
    let mut note = Note::new();
    assert_eq!(
        high.apply(
            &first,
            &f.genesis.descriptor,
            Some(&f.genesis.body),
            &f.metadata,
            None,
            NoteTarget {
                id: [7; 32],
                note: &mut note
            }
        ),
        Outcome::IntegrityStop
    );
    assert_eq!(high.floor(), 2);
    assert_eq!(high.head(), Head::EMPTY);
    let upgraded = rebind(
        &event.descriptor,
        f.base,
        &f.metadata,
        &f.first.signing,
        |s| {
            s[..2].copy_from_slice(&2u16.to_be_bytes());
            s[2..4].copy_from_slice(&2u16.to_be_bytes());
        },
    );
    let upgrade_order = Commitment::order(f.base, f.history.head(), &upgraded).unwrap();
    assert_eq!(
        f.history
            .inspect(&upgrade_order, &upgraded, &f.metadata)
            .err(),
        Some(Outcome::UnsupportedPause)
    );
    let mut accepted = f.history.clone();
    let mut note = Note::new();
    let order = Commitment::order(f.base, accepted.head(), &event.descriptor).unwrap();
    assert_eq!(
        accepted.apply(
            &order,
            &event.descriptor,
            Some(&event.body),
            &f.metadata,
            Some(&f.epoch),
            NoteTarget {
                id: [7; 32],
                note: &mut note
            }
        ),
        Outcome::Accepted
    );
    let repeat = Commitment::order(f.base, accepted.head(), &event.descriptor).unwrap();
    assert_eq!(
        accepted
            .inspect(&repeat, &event.descriptor, &f.metadata)
            .err(),
        Some(Outcome::IntegrityStop)
    );
    let mut next = f.binding(&f.first, CLASS_CONTENT);
    next.event_id = event.descriptor.id();
    next.seen = accepted.head();
    let different = seal(
        next,
        Payload {
            kind: NOTE,
            data: &data,
        },
        &f.first.signing,
        &f.metadata,
        Some(&f.epoch),
    )
    .unwrap();
    let repeat = Commitment::order(f.base, accepted.head(), &different.descriptor).unwrap();
    assert_eq!(
        accepted
            .inspect(&repeat, &different.descriptor, &f.metadata)
            .err(),
        Some(Outcome::IntegrityStop)
    );
}

#[test]
fn body_padding_authenticated_but_noncanonical_stops_at_plaintext_validation() {
    let mut f = Fixture::new();
    let (data, _) = note_delta("padding");
    let (event, _) = f.content(&f.first, NOTE, &data);
    let signed = f
        .history
        .inspect(
            &Commitment::order(f.base, f.history.head(), &event.descriptor).unwrap(),
            &event.descriptor,
            &f.metadata,
        )
        .unwrap();
    let mut aad = b"bh/payload-aad/v1\0".to_vec();
    aad.extend(signed.version.to_be_bytes());
    aad.push(signed.mode);
    aad.extend(signed.base);
    aad.extend(signed.audience);
    aad.extend(signed.epoch);
    aad.extend(signed.event_id.0);
    aad.extend(signed.padded.to_be_bytes());
    let key = derive_key(&f.epoch, b"bhNote01", 0);
    let mut plain = aead_open(
        &key,
        event.body[..24].try_into().unwrap(),
        &aad,
        &event.body[24..],
    )
    .unwrap()
    .expose()
    .to_vec();
    *plain.last_mut().unwrap() = 1;
    let (nonce, cipher) = aead_seal(&key, &aad, &plain).unwrap();
    plain.fill(0);
    let mut body = nonce.to_vec();
    body.extend(cipher);
    let mut commitment = b"bh/payload-object/v1\0".to_vec();
    commitment.extend(signed.padded.to_be_bytes());
    commitment.extend(&body);
    let digest = bh_crypto::hash(&commitment);
    let old = event.descriptor.envelope();
    let bind_key = derive_key(&f.metadata, b"bhBind01", 0);
    let mut bind_ad = b"bh/author-binding-aad/v1\0".to_vec();
    bind_ad.extend(1u16.to_be_bytes());
    bind_ad.push(0);
    bind_ad.extend(f.base.0);
    bind_ad.extend(event.descriptor.id().0);
    bind_ad.extend(&old[..32]);
    let mut bind_plain = aead_open(
        &bind_key,
        old[32..56].try_into().unwrap(),
        &bind_ad,
        &old[56..],
    )
    .unwrap()
    .expose()
    .to_vec();
    bind_plain[314..346].copy_from_slice(&digest);
    let mut to_sign = b"bh/original-envelope/v1\0".to_vec();
    to_sign.extend(&bind_plain[..346]);
    bind_plain[346..410].copy_from_slice(&f.first.signing.sign(&to_sign));
    let end = bind_ad.len();
    bind_ad[end - 32..].copy_from_slice(&digest);
    let (nonce, cipher) = aead_seal(&bind_key, &bind_ad, &bind_plain).unwrap();
    bind_plain.fill(0);
    let mut envelope = digest.to_vec();
    envelope.extend(nonce);
    envelope.extend(cipher);
    let descriptor = OpaqueEvent::new(event.descriptor.id(), envelope).unwrap();
    let order = Commitment::order(f.base, f.history.head(), &descriptor).unwrap();
    assert!(f.history.inspect(&order, &descriptor, &f.metadata).is_ok());
    assert_eq!(
        f.history.apply(
            &order,
            &descriptor,
            Some(&body),
            &f.metadata,
            Some(&f.epoch),
            NoteTarget {
                id: [7; 32],
                note: &mut f.note
            }
        ),
        Outcome::IntegrityStop
    );
    body.fill(0);
}

#[test]
fn old_truthful_content_seen_head_remains_valid_after_intervening_content() {
    let mut f = Fixture::new();
    let (data, _) = note_delta("a");
    let first = f.binding(&f.first, CLASS_CONTENT);
    let (one, one_order) = f.create(first, NOTE, &data, &f.first.signing, Some(&f.epoch));
    let mut second = first;
    second.event_id = EventId(bh_crypto::random());
    let two = seal(
        second,
        Payload {
            kind: NOTE,
            data: &data,
        },
        &f.first.signing,
        &f.metadata,
        Some(&f.epoch),
    )
    .unwrap();
    assert_eq!(f.apply(&one, &one_order, true), Outcome::Accepted);
    let two_order = Commitment::order(f.base, f.history.head(), &two.descriptor).unwrap();
    assert_eq!(f.apply(&two, &two_order, true), Outcome::Accepted);
}

#[test]
fn wrong_roots_body_substitution_and_unknown_inner_control_are_distinct() {
    let mut f = Fixture::new();
    let (data, _) = note_delta("first");
    let (event, order) = f.content(&f.first, NOTE, &data);
    // An audience key alone cannot open the independent metadata binding.
    assert_eq!(
        f.history.inspect(&order, &event.descriptor, &f.epoch).err(),
        Some(Outcome::IntegrityStop)
    );
    assert_eq!(
        f.history.apply(
            &order,
            &event.descriptor,
            Some(&event.body),
            &f.metadata,
            None,
            NoteTarget {
                id: [7; 32],
                note: &mut f.note
            }
        ),
        Outcome::UnavailablePause
    );
    assert_eq!(f.history.head().position, 1);
    let wrong = Secret::<32>::random();
    assert_eq!(
        f.history.apply(
            &order,
            &event.descriptor,
            Some(&event.body),
            &f.metadata,
            Some(&wrong),
            NoteTarget {
                id: [7; 32],
                note: &mut f.note
            }
        ),
        Outcome::IntegrityStop
    );
    let mut f = Fixture::new();
    let (first, order) = f.content(&f.first, NOTE, &data);
    let (other, _) = f.content(&f.first, NOTE, &data);
    assert_eq!(
        f.history.apply(
            &order,
            &first.descriptor,
            Some(&other.body),
            &f.metadata,
            Some(&f.epoch),
            NoteTarget {
                id: [7; 32],
                note: &mut f.note
            }
        ),
        Outcome::IntegrityStop
    );
    let mut f = Fixture::new();
    let add = f
        .account
        .add_device(f.first.keys().id(), f.second.keys())
        .unwrap();
    let add = add
        .finish(f.first.control.sign(add.signing_bytes()))
        .unwrap();
    let mut unknown = add.as_bytes().to_vec();
    let tag = b"BaseHero account event\0".len() + 2 + 2 + 8 + 32 + 32 + 32;
    unknown[tag] = 99;
    let (event, order) = f.create(
        f.binding(&f.first, CLASS_CONTROL),
        ACCOUNT_CHANGE,
        &unknown,
        &f.first.control,
        None,
    );
    assert_eq!(f.apply(&event, &order, false), Outcome::UnsupportedPause);
    assert_eq!(f.history.head().position, 1);
}

#[test]
fn missing_content_key_refuses_before_packaging_and_wrong_note_target_stops_safely() {
    let mut f = Fixture::new();
    let (data, _) = note_delta("prior");
    let (event, order) = f.content(&f.first, NOTE, &data);
    assert_eq!(f.apply(&event, &order, true), Outcome::Accepted);
    let note_before = f.note.state();
    let head_before = f.history.head();
    let binding = f.binding(&f.first, CLASS_CONTENT);
    assert!(matches!(
        seal(
            binding,
            Payload {
                kind: NOTE,
                data: &data
            },
            &f.first.signing,
            &f.metadata,
            None
        ),
        Err(bh_event::Error::Unavailable)
    ));
    assert_eq!(f.history.head(), head_before);
    assert_eq!(f.note.state(), note_before);
    let mut wrong_note = vec![8; 32];
    wrong_note.extend(&data[32..]);
    let (event, order) = f.content(&f.first, NOTE, &wrong_note);
    assert!(
        f.history
            .inspect(&order, &event.descriptor, &f.metadata)
            .is_ok()
    );
    assert_eq!(f.apply(&event, &order, true), Outcome::IntegrityStop);
    assert_eq!(f.history.head(), head_before);
    assert_eq!(f.note.state(), note_before);
    assert!(f.history.is_stopped());
}

#[test]
fn prepared_routing_is_authenticated_and_local_target_errors_are_recoverable() {
    let mut f = Fixture::new();
    let mut first = Note::new();
    let mut second = Note::new();
    for (id, text) in [([7; 32], "first"), ([8; 32], "second")] {
        let mut authored = Note::new();
        let mut data = id.to_vec();
        data.extend(authored.append_paragraph(text));
        let (event, order) = f.content(&f.first, NOTE, &data);
        let before = f.history.head();
        let prepared = f
            .history
            .prepare(
                &order,
                &event.descriptor,
                Some(&event.body),
                &f.metadata,
                Some(&f.epoch),
            )
            .unwrap();
        assert_eq!(prepared.note_id(), Some(id));
        assert!(
            !event
                .descriptor
                .encode()
                .windows(32)
                .any(|bytes| bytes == id)
        );
        assert_eq!(f.history.head(), before);
        let wrong = if id == [7; 32] {
            &mut second
        } else {
            &mut first
        };
        let wrong_before = wrong.state();
        assert_eq!(
            f.history
                .consume(
                    prepared,
                    Some(NoteTarget {
                        id: [9; 32],
                        note: wrong
                    })
                )
                .err(),
            Some(bh_event::ConsumeError::WrongTarget)
        );
        assert_eq!(wrong.state(), wrong_before);
        assert!(!f.history.is_stopped());
        assert_eq!(f.history.head(), before);
        let prepared = f
            .history
            .prepare(
                &order,
                &event.descriptor,
                Some(&event.body),
                &f.metadata,
                Some(&f.epoch),
            )
            .unwrap();
        let note = if id == [7; 32] {
            &mut first
        } else {
            &mut second
        };
        assert_eq!(
            f.history
                .consume(prepared, Some(NoteTarget { id, note }))
                .map(|v| v.outcome()),
            Ok(Outcome::Accepted)
        );
        assert_eq!(note.state(), authored.state());
    }
    assert_ne!(first.state(), Note::new().state());
    assert_ne!(second.state(), Note::new().state());
    let before = f.history.head();
    let (mut corrupt, order) = f.content(&f.first, NOTE, &[8; 32]);
    assert!(matches!(
        f.history.prepare(
            &order,
            &corrupt.descriptor,
            None,
            &f.metadata,
            Some(&f.epoch)
        ),
        Err(Outcome::UnavailablePause)
    ));
    assert!(matches!(
        f.history.prepare(
            &order,
            &corrupt.descriptor,
            Some(&corrupt.body),
            &f.metadata,
            None
        ),
        Err(Outcome::UnavailablePause)
    ));
    let (unknown, unknown_order) = f.content(&f.first, 0xf123, &[8; 32]);
    assert!(matches!(
        f.history.prepare(
            &unknown_order,
            &unknown.descriptor,
            Some(&unknown.body),
            &f.metadata,
            Some(&f.epoch)
        ),
        Err(Outcome::UnsupportedPause)
    ));
    assert_eq!(f.history.head(), before);
    corrupt.body[30] ^= 1;
    assert!(matches!(
        f.history.prepare(
            &order,
            &corrupt.descriptor,
            Some(&corrupt.body),
            &f.metadata,
            Some(&f.epoch)
        ),
        Err(Outcome::IntegrityStop)
    ));
    assert!(f.history.is_stopped());
    assert_eq!(f.history.head(), before);
    assert_ne!(first.state(), Note::new().state());
    assert_ne!(second.state(), Note::new().state());
}

#[test]
fn prepared_events_require_exact_history_and_controls_need_no_note() {
    let mut f = Fixture::new();
    let (data, _) = note_delta("one");
    let (event, order) = f.content(&f.first, NOTE, &data);
    let stale = f
        .history
        .prepare(
            &order,
            &event.descriptor,
            Some(&event.body),
            &f.metadata,
            Some(&f.epoch),
        )
        .unwrap();
    let fresh = f
        .history
        .prepare(
            &order,
            &event.descriptor,
            Some(&event.body),
            &f.metadata,
            Some(&f.epoch),
        )
        .unwrap();
    let head = f.history.head();
    // Preparation on the original can be consumed by an unchanged trusted
    // transactional clone; no instance-identity requirement is introduced.
    let clone_prepared = f
        .history
        .prepare(
            &order,
            &event.descriptor,
            Some(&event.body),
            &f.metadata,
            Some(&f.epoch),
        )
        .unwrap();
    let mut candidate = f.history.clone();
    let mut clone_note = Note::new();
    assert_eq!(
        candidate
            .consume(
                clone_prepared,
                Some(NoteTarget {
                    id: [7; 32],
                    note: &mut clone_note
                })
            )
            .map(|v| v.outcome()),
        Ok(Outcome::Accepted)
    );
    assert_eq!(f.history.head(), head);
    assert_eq!(
        f.history
            .consume(
                fresh,
                Some(NoteTarget {
                    id: [7; 32],
                    note: &mut f.note
                })
            )
            .map(|v| v.outcome()),
        Ok(Outcome::Accepted)
    );
    let content = f.note.state();
    assert_eq!(
        f.history
            .consume(
                stale,
                Some(NoteTarget {
                    id: [7; 32],
                    note: &mut f.note
                })
            )
            .err(),
        Some(bh_event::ConsumeError::StaleState)
    );
    assert_eq!(f.note.state(), content);
    assert_ne!(f.history.head(), head);
    // An independently prepared event for the same predecessor is stale too,
    // even though its event ID and encrypted note target differ.
    let mut alternate = data.clone();
    alternate[..32].fill(8);
    let (other, other_order) = f.content(&f.first, NOTE, &alternate);
    let pending = f
        .history
        .prepare(
            &other_order,
            &other.descriptor,
            Some(&other.body),
            &f.metadata,
            Some(&f.epoch),
        )
        .unwrap();
    let (winner, winner_order) = f.content(&f.first, NOTE, &data);
    let accepted = f
        .history
        .prepare(
            &winner_order,
            &winner.descriptor,
            Some(&winner.body),
            &f.metadata,
            Some(&f.epoch),
        )
        .unwrap();
    assert_eq!(
        f.history
            .consume(
                accepted,
                Some(NoteTarget {
                    id: [7; 32],
                    note: &mut f.note
                })
            )
            .map(|v| v.outcome()),
        Ok(Outcome::Accepted)
    );
    let head_after = f.history.head();
    assert_eq!(
        f.history
            .consume(
                pending,
                Some(NoteTarget {
                    id: [8; 32],
                    note: &mut Note::new()
                })
            )
            .err(),
        Some(bh_event::ConsumeError::StaleState)
    );
    assert_eq!(f.history.head(), head_after);
    let add = f
        .account
        .add_device(f.first.keys().id(), f.second.keys())
        .unwrap();
    let add = add
        .finish(f.first.control.sign(add.signing_bytes()))
        .unwrap();
    let (event, order) = f.create(
        f.binding(&f.first, CLASS_CONTROL),
        ACCOUNT_CHANGE,
        add.as_bytes(),
        &f.first.control,
        None,
    );
    let stale = f
        .history
        .prepare(
            &order,
            &event.descriptor,
            Some(&event.body),
            &f.metadata,
            None,
        )
        .unwrap();
    let fresh = f
        .history
        .prepare(
            &order,
            &event.descriptor,
            Some(&event.body),
            &f.metadata,
            None,
        )
        .unwrap();
    assert_eq!(fresh.note_id(), None);
    assert_eq!(
        f.history
            .consume(
                fresh,
                Some(NoteTarget {
                    id: [7; 32],
                    note: &mut f.note
                })
            )
            .err(),
        Some(bh_event::ConsumeError::WrongTarget)
    );
    let fresh = f
        .history
        .prepare(
            &order,
            &event.descriptor,
            Some(&event.body),
            &f.metadata,
            None,
        )
        .unwrap();
    assert_eq!(
        f.history.consume(fresh, None).map(|v| v.outcome()),
        Ok(Outcome::Accepted)
    );
    assert_eq!(f.history.account_head(), add.head());
    assert_eq!(
        f.history.consume(stale, None).err(),
        Some(bh_event::ConsumeError::StaleState)
    );
    assert_eq!(f.note.state(), content);
}

#[test]
fn same_head_trust_context_refuses_prepared_genesis() {
    let f = Fixture::new();
    let other = Fixture::new();
    let mut source = History::new(f.account.id(), &f.account_genesis, f.base, 1).unwrap();
    let order = Commitment::order(f.base, Head::EMPTY, &f.genesis.descriptor).unwrap();
    let floor_two = History::new(f.account.id(), &f.account_genesis, f.base, 2).unwrap();
    let other_account =
        History::new(other.account.id(), &other.account_genesis, f.base, 1).unwrap();
    let other_base = History::new(f.account.id(), &f.account_genesis, other.base, 1).unwrap();
    assert_ne!(f.account.head(), other.account.head());
    assert_ne!(f.base, other.base);
    for mut destination in [floor_two, other_account, other_base] {
        assert_eq!(source.head(), Head::EMPTY);
        assert_eq!(destination.head(), Head::EMPTY);
        let before = (
            destination.head(),
            destination.account_head(),
            destination.floor(),
            destination.is_stopped(),
        );
        let prepared = source
            .prepare(
                &order,
                &f.genesis.descriptor,
                Some(&f.genesis.body),
                &f.metadata,
                None,
            )
            .unwrap();
        assert_eq!(prepared.note_id(), None);
        assert_eq!(source.head(), Head::EMPTY);
        assert_eq!(
            destination.consume(prepared, None).err(),
            Some(bh_event::ConsumeError::StaleState)
        );
        assert_eq!(
            (
                destination.head(),
                destination.account_head(),
                destination.floor(),
                destination.is_stopped()
            ),
            before
        );
    }
}

#[test]
fn same_head_integrity_stop_refuses_prepared_note_without_losing_content() {
    let mut f = Fixture::new();
    let (prior, edited) = note_delta("retained");
    let (event, order) = f.content(&f.first, NOTE, &prior);
    assert_eq!(f.apply(&event, &order, true), Outcome::Accepted);
    assert_eq!(f.note.state(), edited.state());
    let before = (
        f.history.head(),
        f.history.account_head(),
        f.history.floor(),
        f.note.state(),
    );
    let (data, _) = note_delta("future");
    let (valid, valid_order) = f.content(&f.first, NOTE, &data);
    let prepared = f
        .history
        .prepare(
            &valid_order,
            &valid.descriptor,
            Some(&valid.body),
            &f.metadata,
            Some(&f.epoch),
        )
        .unwrap();
    assert_eq!(prepared.note_id(), Some([7; 32]));
    let (mut corrupt, corrupt_order) = f.content(&f.first, NOTE, &data);
    corrupt.body[30] ^= 1;
    assert!(matches!(
        f.history.prepare(
            &corrupt_order,
            &corrupt.descriptor,
            Some(&corrupt.body),
            &f.metadata,
            Some(&f.epoch)
        ),
        Err(Outcome::IntegrityStop)
    ));
    assert!(f.history.is_stopped());
    assert_eq!(
        (
            f.history.head(),
            f.history.account_head(),
            f.history.floor(),
            f.note.state()
        ),
        before
    );
    assert_eq!(
        f.history
            .consume(
                prepared,
                Some(NoteTarget {
                    id: [7; 32],
                    note: &mut f.note
                })
            )
            .err(),
        Some(bh_event::ConsumeError::StaleState)
    );
    assert_eq!(
        (
            f.history.head(),
            f.history.account_head(),
            f.history.floor(),
            f.note.state()
        ),
        before
    );
    assert!(f.history.is_stopped());
}

#[test]
fn fresh_seals_are_random_and_descriptor_encoding_is_canonical() {
    let f = Fixture::new();
    let (data, _) = note_delta("same");
    let binding = f.binding(&f.first, CLASS_CONTENT);
    let (one, _) = f.create(binding, NOTE, &data, &f.first.signing, Some(&f.epoch));
    let (two, _) = f.create(binding, NOTE, &data, &f.first.signing, Some(&f.epoch));
    assert_ne!(one.body, two.body);
    assert_ne!(one.descriptor.encode(), two.descriptor.encode());
    let bytes = one.descriptor.encode();
    assert_eq!(OpaqueEvent::decode(&bytes).unwrap().encode(), bytes);
}

#[test]
fn applied_result_binds_ordered_original_body_and_typed_content() {
    use bh_event::AppliedKind;
    use bh_sync::referenced_body;
    let mut f = Fixture::new();
    let (data, edited) = note_delta("bound note");
    let (event, order) = f.content(&f.first, NOTE, &data);
    let prepared = f
        .history
        .prepare(
            &order,
            &event.descriptor,
            Some(&event.body),
            &f.metadata,
            Some(&f.epoch),
        )
        .unwrap();
    let applied = f
        .history
        .consume(
            prepared,
            Some(NoteTarget {
                id: [7; 32],
                note: &mut f.note,
            }),
        )
        .unwrap();
    assert_eq!(applied.commitment(), order);
    assert_eq!(applied.commitment_bytes(), order.encode());
    assert_eq!(applied.descriptor_bytes(), event.descriptor.encode());
    assert_eq!(applied.body_bytes(), event.body);
    assert_eq!(
        applied.body_commitment(),
        referenced_body(&event.descriptor).unwrap()
    );
    assert_eq!(
        applied.body_commitment(),
        bh_sync::BodyObject::new(event.body.clone())
            .unwrap()
            .commitment()
    );
    assert_eq!(applied.head(), f.history.head());
    assert_eq!(applied.floor(), f.history.floor());
    match applied.kind() {
        AppliedKind::NoteAccepted { note_id, delta } => {
            assert_eq!(*note_id, [7; 32]);
            assert_eq!(delta.expose(), &data[32..]);
        }
        _ => panic!("expected accepted note"),
    }
    assert_eq!(f.note.state(), edited.state());
    assert!(!format!("{applied:?}").contains("bound note"));

    let mut bad = vec![7; 32];
    bad.extend([0xff, 0xff, 0xff]);
    let (event, order) = f.content(&f.first, NOTE, &bad);
    let prepared = f
        .history
        .prepare(
            &order,
            &event.descriptor,
            Some(&event.body),
            &f.metadata,
            Some(&f.epoch),
        )
        .unwrap();
    let rejected = f
        .history
        .consume(
            prepared,
            Some(NoteTarget {
                id: [7; 32],
                note: &mut f.note,
            }),
        )
        .unwrap();
    assert!(
        matches!(rejected.kind(), AppliedKind::NoteRejected { note_id } if *note_id == [7; 32])
    );
    assert_eq!(rejected.outcome(), Outcome::ContentRejected);
    assert_eq!(rejected.head(), order.head());
    assert_eq!(f.note.state(), edited.state());

    let add = f
        .account
        .add_device(f.first.keys().id(), f.second.keys())
        .unwrap();
    let add = add
        .finish(f.first.control.sign(add.signing_bytes()))
        .unwrap();
    let (event, order) = f.create(
        f.binding(&f.first, CLASS_CONTROL),
        ACCOUNT_CHANGE,
        add.as_bytes(),
        &f.first.control,
        None,
    );
    let prepared = f
        .history
        .prepare(
            &order,
            &event.descriptor,
            Some(&event.body),
            &f.metadata,
            None,
        )
        .unwrap();
    let control = f.history.consume(prepared, None).unwrap();
    assert!(matches!(control.kind(), AppliedKind::Control));
    assert_eq!(control.outcome(), Outcome::Accepted);
    assert_eq!(control.head(), order.head());
    assert_eq!(control.descriptor_bytes(), event.descriptor.encode());
}

#[test]
fn replay_verifies_records_from_anchors_without_applying_notes() {
    let mut f = Fixture::new();
    let first_order = Commitment::order(f.base, Head::EMPTY, &f.genesis.descriptor).unwrap();
    let mut records = vec![(
        first_order,
        f.genesis.descriptor.encode(),
        f.genesis.body.clone(),
    )];
    let (data, _) = note_delta("first");
    let (event, order) = f.content(&f.first, NOTE, &data);
    assert_eq!(f.apply(&event, &order, true), Outcome::Accepted);
    records.push((order, event.descriptor.encode(), event.body));
    let add = f
        .account
        .add_device(f.first.keys().id(), f.second.keys())
        .unwrap();
    let add = add
        .finish(f.first.control.sign(add.signing_bytes()))
        .unwrap();
    let (event, order) = f.create(
        f.binding(&f.first, CLASS_CONTROL),
        ACCOUNT_CHANGE,
        add.as_bytes(),
        &f.first.control,
        None,
    );
    assert_eq!(f.apply(&event, &order, false), Outcome::Accepted);
    records.push((order, event.descriptor.encode(), event.body));
    f.account.apply(add.as_bytes()).unwrap();
    let live = &f.history;
    let mut replay = History::replay(
        f.account.id(),
        &f.account_genesis,
        f.base,
        1,
        &f.metadata,
        Some(&f.epoch),
        records.clone(),
    )
    .unwrap();
    assert_eq!(replay.head(), live.head());
    assert_eq!(replay.floor(), live.floor());
    assert_eq!(replay.account_head(), live.account_head());
    assert_eq!(replay.metadata_id(), live.metadata_id());
    assert_eq!(replay.epoch_id(), live.epoch_id());
    let (data, _) = note_delta("next");
    let (event, order) = f.content(&f.first, NOTE, &data);
    let mut note = Note::new();
    // A preparation from the live history must consume on the replayed one:
    // this compares the full private predecessor, not just public accessors.
    let prepared = f
        .history
        .prepare(
            &order,
            &event.descriptor,
            Some(&event.body),
            &f.metadata,
            Some(&f.epoch),
        )
        .unwrap();
    assert_eq!(
        replay
            .consume(
                prepared,
                Some(NoteTarget {
                    id: [7; 32],
                    note: &mut note
                })
            )
            .unwrap()
            .outcome(),
        Outcome::Accepted
    );
    assert_eq!(f.apply(&event, &order, true), Outcome::Accepted);
    assert_eq!(replay.head(), f.history.head());

    let check = |records: Vec<(Commitment, Vec<u8>, Vec<u8>)>, base| {
        History::replay(
            f.account.id(),
            &f.account_genesis,
            base,
            1,
            &f.metadata,
            Some(&f.epoch),
            records,
        )
        .err()
    };
    let mut changed = records.clone();
    changed[1].1[40] ^= 1;
    assert_eq!(check(changed, f.base), Some(Outcome::IntegrityStop));
    let mut changed = records.clone();
    changed[1].2[40] ^= 1;
    assert_eq!(check(changed, f.base), Some(Outcome::IntegrityStop));
    let mut changed = records.clone();
    changed[1].0 = records[2].0;
    assert_eq!(check(changed, f.base), Some(Outcome::IntegrityStop));
    // This alternate order has a valid chain from the same predecessor but
    // commits to another descriptor. Only the exact descriptor binding catches it.
    let (alternate, _) = note_delta("another ciphertext");
    let (other, _) = f.content(&f.first, NOTE, &alternate);
    let mut changed = records.clone();
    changed[1].0 = Commitment::order(f.base, records[0].0.head(), &other.descriptor).unwrap();
    assert_eq!(
        check(changed[..2].to_vec(), f.base),
        Some(Outcome::IntegrityStop)
    );
    // A fresh, correctly signed next record with an already-used EventId is
    // refused even though its outer commitment and predecessor are valid.
    let mut repeated = f.binding(&f.first, CLASS_CONTENT);
    repeated.seen = records[2].0.head();
    repeated.event_id = OpaqueEvent::decode(&records[1].1).unwrap().id();
    let (duplicate, _) = f.create(repeated, NOTE, &data, &f.first.signing, Some(&f.epoch));
    let duplicate_order =
        Commitment::order(f.base, records[2].0.head(), &duplicate.descriptor).unwrap();
    let mut changed = records.clone();
    changed.push((
        duplicate_order,
        duplicate.descriptor.encode(),
        duplicate.body,
    ));
    assert_eq!(check(changed, f.base), Some(Outcome::IntegrityStop));
    assert_eq!(
        check(records[1..].to_vec(), f.base),
        Some(Outcome::IntegrityStop)
    );
    let mut changed = records.clone();
    changed.swap(1, 2);
    assert_eq!(check(changed, f.base), Some(Outcome::IntegrityStop));
    let mut changed = records.clone();
    changed.push(records[2].clone());
    assert_eq!(check(changed, f.base), Some(Outcome::IntegrityStop));
    assert_eq!(
        check(records.clone(), BaseId([99; 32])),
        Some(Outcome::IntegrityStop)
    );
    assert_eq!(
        History::replay(
            f.account.id(),
            &f.account_genesis,
            f.base,
            2,
            &f.metadata,
            Some(&f.epoch),
            records.clone()
        )
        .err(),
        Some(Outcome::IntegrityStop)
    );
    let higher = History::replay(
        f.account.id(),
        &f.account_genesis,
        f.base,
        2,
        &f.metadata,
        Some(&f.epoch),
        Vec::<(Commitment, Vec<u8>, Vec<u8>)>::new(),
    )
    .unwrap();
    assert_eq!(higher.floor(), 2);

    let mut stopped = History::replay(
        f.account.id(),
        &f.account_genesis,
        f.base,
        1,
        &f.metadata,
        Some(&f.epoch),
        records,
    )
    .unwrap();
    let before = stopped.head();
    stopped.mark_stopped();
    assert_eq!(stopped.head(), before);
    assert!(stopped.is_stopped());
    assert_eq!(
        stopped
            .prepare(
                &order,
                &event.descriptor,
                Some(&event.body),
                &f.metadata,
                Some(&f.epoch)
            )
            .err(),
        Some(Outcome::IntegrityStop)
    );
}
