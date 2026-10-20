use bh_account::{
    AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount,
    journal::AccountJournal, storage::DeviceJournal,
};
use bh_core::note::Note;
use bh_crypto::{KemKey, Secret, SigningKey, aead_open, aead_seal, derive_key};
use bh_event::{
    ACCOUNT_CHANGE, Binding, CLASS_CONTENT, CLASS_CONTROL, Encoded, GENESIS, History, NOTE,
    NoteTarget, Outcome, Payload, key_id, seal,
};
use bh_sync::receipt::{self, RECEIPT_LEN};
use bh_sync::{BaseId, Commitment, Digest, EventId, Head, OpaqueEvent, Route};

/// The fixtures' pinned hosting root, fixed so re-signed bindings can carry a
/// fresh receipt for whatever head they claim to have seen.
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
            seen_receipt: [0; RECEIPT_LEN],
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
            &first.signing,
            &metadata,
            None,
        )
        .unwrap();
        assert_eq!(genesis.descriptor.encode().len(), 1062);
        assert_eq!(genesis.body.len(), 1024);
        let base = BaseId::from_genesis(&genesis.descriptor);
        let ordered =
            Commitment::order(base, Head::EMPTY, &genesis.descriptor, Route::Control).unwrap();
        let mut history = History::new(id, account_genesis.as_bytes(), base, root(), 1).unwrap();
        let mut note = Note::new().unwrap();
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
    fn create(
        &self,
        binding: Binding,
        kind: u16,
        data: &[u8],
        signer: &SigningKey,
        content: Option<&Secret<32>>,
    ) -> (Encoded, Commitment) {
        let route = if binding.class == CLASS_CONTROL {
            Route::Control
        } else {
            Route::Content
        };
        let event = seal(
            binding,
            Payload { kind, data },
            signer,
            &self.metadata,
            content,
        )
        .unwrap();
        let ordered =
            Commitment::order(self.base, self.history.head(), &event.descriptor, route).unwrap();
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
    aad.extend(2u16.to_be_bytes());
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
    let mut note = Note::new().unwrap();
    let data = with_writer(&note.append_paragraph(text).unwrap());
    (data, note)
}
/// Note 7's payload from an arbitrary declared writer; history checks only
/// that the declaration decodes.
fn with_writer(update: &[u8]) -> Vec<u8> {
    bh_event::note_payload(
        [7; 32],
        bh_event::writer::DeviceWriterDeclaration {
            account: [4; 32],
            device: [5; 32],
            nonce: [6; 32],
        },
        update,
    )
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
    let mut plain = [1u16, 2, 3]
        .into_iter()
        .find_map(|v| aead_open(&key, nonce, &aad(v), &env[56..]).ok())
        .unwrap()
        .expose()
        .to_vec();
    change(&mut plain[..346]);
    // Later versions sign a receipt for the (possibly changed) seen head.
    let version = u16::from_be_bytes(plain[..2].try_into().unwrap());
    let len = if version == 1 { 346 } else { 346 + RECEIPT_LEN };
    if version != 1 {
        let seen = Head {
            position: u64::from_be_bytes(plain[237..245].try_into().unwrap()),
            hash: Digest(plain[245..277].try_into().unwrap()),
        };
        plain[346..len].copy_from_slice(&receipt_for(base, seen));
    }
    plain[len..].fill(0);
    let mut signed = b"bh/original-envelope/v1\0".to_vec();
    signed.extend(&plain[..len]);
    plain[len..len + 64].copy_from_slice(&signer.sign(&signed));
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
    let note_before = f.note.state().unwrap();
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
    let rewrapped_order =
        Commitment::order(f.base, head_before, &rewrapped, Route::Content).unwrap();
    // A root other than the base's is a key this device lacks, not proof.
    assert_eq!(
        f.history
            .inspect(&rewrapped_order, &rewrapped, &unrelated_m)
            .err(),
        Some(Outcome::UnavailablePause)
    );
    // Under the base's own root the rewrapped original does not open.
    assert_eq!(
        f.history.apply(
            &rewrapped_order,
            &rewrapped,
            Some(&event.body),
            &f.metadata,
            Some(&f.epoch),
            NoteTarget {
                id: [7; 32],
                note: &mut f.note
            }
        ),
        Outcome::Rejected
    );
    // Ordered with no effect: the note and floor stay, verification goes on.
    assert_eq!(f.note.state().unwrap(), note_before);
    assert_eq!(f.history.head(), rewrapped_order.head());
    assert_eq!(f.history.floor(), floor_before);
    assert!(!f.history.is_stopped());
}

#[test]
fn indexed_account_evidence_loss_pauses_without_advancing_then_retries_same_view() {
    let mut f = Fixture::new();
    let unique = u128::from_be_bytes(bh_crypto::random::<16>());
    let folder = format!("bh-event-index-{}-{unique:032x}", std::process::id());
    let dir = std::env::temp_dir().join(folder);
    let hidden = dir.with_extension("hidden");
    std::fs::create_dir(&dir).unwrap();
    let mut journal = DeviceJournal::open(dir.join("account.sqlite")).unwrap();
    let id = f.account.id();
    journal
        .commit_verified(id, &[&f.account_genesis], f.account.head(), false)
        .unwrap();
    let indexed = journal.load_projection().unwrap().unwrap();
    assert_eq!(indexed.account.head(), f.account.head());
    f.history = History::with_account(&indexed.account, f.base, root(), 1).unwrap();
    let genesis_order =
        Commitment::order(f.base, Head::EMPTY, &f.genesis.descriptor, Route::Control).unwrap();
    assert_eq!(
        f.history.apply(
            &genesis_order,
            &f.genesis.descriptor,
            Some(&f.genesis.body),
            &f.metadata,
            None,
            NoteTarget {
                id: [7; 32],
                note: &mut f.note
            },
        ),
        Outcome::Accepted
    );
    let req = f
        .account
        .add_device(f.first.keys().id(), f.second.keys())
        .unwrap();
    let original = req
        .finish(f.first.control.sign(req.signing_bytes()))
        .unwrap();
    let (event, order) = f.create(
        f.binding(&f.first, CLASS_CONTROL),
        ACCOUNT_CHANGE,
        original.as_bytes(),
        &f.first.control,
        None,
    );
    let before_head = f.history.head();
    let before_account = f.history.account_head();
    let before_note = f.note.state().unwrap();
    std::fs::rename(&dir, &hidden).unwrap();
    assert_eq!(
        indexed
            .account
            .clone()
            .applied_batch(&[original.as_bytes()])
            .err(),
        Some(bh_account::Error::Unavailable),
    );
    assert_eq!(f.apply(&event, &order, false), Outcome::UnavailablePause);
    assert_eq!(f.history.head(), before_head);
    assert_eq!(f.history.account_head(), before_account);
    assert_eq!(f.note.state().unwrap(), before_note);
    assert!(!f.history.is_stopped());
    std::fs::rename(&hidden, &dir).unwrap();
    assert_eq!(f.apply(&event, &order, false), Outcome::Accepted);
    assert_eq!(f.history.head(), order.head());
    assert_eq!(f.history.account_head(), original.head());
    assert!(!f.history.is_stopped());
    drop(journal);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn signed_inner_unknown_account_version_pauses_but_a_bad_inner_event_is_rejected() {
    let mut f = Fixture::new();
    let (prior, _) = note_delta("prior");
    let (first, order) = f.content(&f.first, NOTE, &prior);
    assert_eq!(f.apply(&first, &order, true), Outcome::Accepted);
    let note_before = f.note.state().unwrap();
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
    assert_eq!(f.note.state().unwrap(), note_before);
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
    assert_eq!(f.apply(&event, &order, false), Outcome::Rejected);
    assert_eq!(f.history.head(), order.head());
    assert_eq!(f.history.account_head(), account_before);
    assert_eq!(f.note.state().unwrap(), note_before);
    assert!(!f.history.is_stopped());
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
    assert_eq!(f.note.state().unwrap(), edited.state().unwrap());
    assert_eq!(f.history.head().position, 2);
}

#[test]
fn malformed_authentic_note_rejects_content_then_accepts_next() {
    let mut f = Fixture::new();
    let (data, mut edited) = note_delta("prior");
    let (event, order) = f.content(&f.first, NOTE, &data);
    assert_eq!(f.apply(&event, &order, true), Outcome::Accepted);
    let before = f.note.state().unwrap();
    let bad = with_writer(&[0xff, 0xff, 0xff]);
    let (event, order) = f.content(&f.first, NOTE, &bad);
    assert_eq!(f.apply(&event, &order, true), Outcome::ContentRejected);
    assert_eq!(f.note.state().unwrap(), before);
    assert_eq!(f.history.head(), order.head());
    assert_eq!(f.history.floor(), 2);
    let next = with_writer(&edited.append_paragraph("later").unwrap());
    let (event, order) = f.content(&f.first, NOTE, &next);
    assert_eq!(f.apply(&event, &order, true), Outcome::Accepted);
    assert_eq!(f.note.state().unwrap(), edited.state().unwrap());
}

#[test]
fn unsupported_semantics_pause_and_ciphertext_tamper_stops_without_losing_note() {
    let mut f = Fixture::new();
    let (data, _) = note_delta("prior");
    let (event, order) = f.content(&f.first, NOTE, &data);
    assert_eq!(f.apply(&event, &order, true), Outcome::Accepted);
    let before = f.note.state().unwrap();
    let head = f.history.head();
    let (unknown, order) = f.content(&f.first, 0xf123, &data);
    assert_eq!(f.apply(&unknown, &order, true), Outcome::UnsupportedPause);
    assert_eq!(f.history.head(), head);
    assert_eq!(f.note.state().unwrap(), before);
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
    let order = Commitment::order(f.base, head, &bad.descriptor, Route::Content).unwrap();
    assert_eq!(f.apply(&bad, &order, true), Outcome::IntegrityStop);
    assert_eq!(f.note.state().unwrap(), before);
    assert_eq!(f.history.head(), head);
    assert!(f.history.is_stopped());
}

#[test]
fn signed_seen_forks_and_original_signature_are_checked_inside_outer_commitment() {
    let f = Fixture::new();
    let (data, _) = note_delta("one");
    let (event, _) = f.content(&f.first, NOTE, &data);
    // `rebind` plays the hosting service: it signs a fresh receipt for the
    // changed seen head. A hosting receipt for another hash at a verified
    // position contradicts that history and stops; every other false claim
    // is the author's and is rejected. An audience this version does not
    // know (offset 37) pauses.
    let expected = |offset: usize| {
        if (245..277).contains(&offset) {
            Outcome::IntegrityStop
        } else if (37..69).contains(&offset) {
            Outcome::UnsupportedPause
        } else {
            Outcome::Rejected
        }
    };
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
        let order = Commitment::order(f.base, f.history.head(), &altered, Route::Content).unwrap();
        let mut history = f.history.clone();
        let mut note = Note::new().unwrap();
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
            expected(mutate),
            "S offset {mutate}"
        );
        assert_eq!(note.state().unwrap(), Note::new().unwrap().state().unwrap());
        if expected(mutate) == Outcome::Rejected {
            assert_eq!(history.head(), order.head());
            assert!(!history.is_stopped());
        } else if expected(mutate) == Outcome::UnsupportedPause {
            assert_eq!(history.head(), f.history.head());
            assert!(!history.is_stopped());
        } else {
            assert_eq!(history.head(), f.history.head());
            assert!(history.is_stopped());
        }
    }
    let altered = rebind(
        &event.descriptor,
        f.base,
        &f.metadata,
        &SigningKey::generate(),
        |_| {},
    );
    let order = Commitment::order(f.base, f.history.head(), &altered, Route::Content).unwrap();
    assert_eq!(
        f.history.inspect(&order, &altered, &f.metadata).err(),
        Some(Outcome::Rejected)
    );
    let wrong = Secret::<32>::random();
    assert_eq!(
        f.history
            .inspect(
                &Commitment::order(f.base, f.history.head(), &event.descriptor, Route::Content)
                    .unwrap(),
                &event.descriptor,
                &wrong
            )
            .err(),
        Some(Outcome::UnavailablePause)
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
    // A valid inner account addition cannot make an ordinary-key outer
    // ACCOUNT_CHANGE valid; only genesis uses the ordinary key for controls.
    let (ordinary, ordinary_order) = f.create(
        binding,
        ACCOUNT_CHANGE,
        add.as_bytes(),
        &f.first.signing,
        None,
    );
    assert_eq!(
        f.history
            .inspect(&ordinary_order, &ordinary.descriptor, &f.metadata)
            .err(),
        Some(Outcome::Rejected)
    );
    let (event, order) = f.create(
        binding,
        ACCOUNT_CHANGE,
        add.as_bytes(),
        &f.first.control,
        None,
    );
    // Correct current predecessor but fabricated seen chain: genuinely
    // re-signed, with a hosting receipt for that other head (`rebind` plays
    // the service), so the service contradicts verified history.
    let fork = rebind(
        &event.descriptor,
        f.base,
        &f.metadata,
        &f.first.control,
        |s| s[245] ^= 1,
    );
    let reordered = Commitment::order(f.base, f.history.head(), &fork, Route::Control).unwrap();
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
    let reordered = Commitment::order(f.base, f.history.head(), &fork, Route::Control).unwrap();
    assert_eq!(
        f.history.inspect(&reordered, &fork, &f.metadata).err(),
        Some(Outcome::Rejected)
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
    let genesis_head =
        Commitment::order(f.base, Head::EMPTY, &f.genesis.descriptor, Route::Control)
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
    let reordered = Commitment::order(f.base, f.history.head(), &fork, Route::Control).unwrap();
    assert_eq!(
        f.history.inspect(&reordered, &fork, &f.metadata).err(),
        Some(Outcome::Rejected)
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
        Some(Outcome::Rejected)
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
        (2usize, [0, 1], Outcome::Rejected),
        (2, [0, 3], Outcome::Accepted),
    ] {
        let changed = rebind(
            &event.descriptor,
            f.base,
            &f.metadata,
            &f.first.signing,
            |s| s[offset..offset + 2].copy_from_slice(&bytes),
        );
        let order = Commitment::order(f.base, f.history.head(), &changed, Route::Content).unwrap();
        let mut state = f.history.clone();
        let mut note = Note::new().unwrap();
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
        // Accepting the first v2 event raises the floor from genesis's v1.
        let floor = if expected == Outcome::Accepted { 2 } else { 1 };
        assert_eq!(state.floor(), floor);
    }
    let mut high = History::new(f.account.id(), &f.account_genesis, f.base, root(), 3).unwrap();
    // Genesis is v1 forever and opens under any remembered floor; a v3 floor
    // then refuses a correctly signed v2 event.
    let first =
        Commitment::order(f.base, Head::EMPTY, &f.genesis.descriptor, Route::Control).unwrap();
    let mut note = Note::new().unwrap();
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
        Outcome::Accepted
    );
    assert_eq!(high.floor(), 3);
    assert_eq!(high.head(), first.head());
    let order = Commitment::order(f.base, high.head(), &event.descriptor, Route::Content).unwrap();
    assert_eq!(
        high.inspect(&order, &event.descriptor, &f.metadata).err(),
        Some(Outcome::Rejected)
    );
    // A signed v3 binding is recognised and paused, not read as v2.
    let upgraded = rebind(
        &event.descriptor,
        f.base,
        &f.metadata,
        &f.first.signing,
        |s| {
            s[..2].copy_from_slice(&3u16.to_be_bytes());
            s[2..4].copy_from_slice(&3u16.to_be_bytes());
        },
    );
    let upgrade_order =
        Commitment::order(f.base, f.history.head(), &upgraded, Route::Content).unwrap();
    assert_eq!(
        f.history
            .inspect(&upgrade_order, &upgraded, &f.metadata)
            .err(),
        Some(Outcome::UnsupportedPause)
    );
    let mut accepted = f.history.clone();
    let mut note = Note::new().unwrap();
    let order =
        Commitment::order(f.base, accepted.head(), &event.descriptor, Route::Content).unwrap();
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
    let repeat =
        Commitment::order(f.base, accepted.head(), &event.descriptor, Route::Content).unwrap();
    assert_eq!(
        accepted
            .inspect(&repeat, &event.descriptor, &f.metadata)
            .err(),
        Some(Outcome::Rejected)
    );
    let mut next = f.binding(&f.first, CLASS_CONTENT);
    next.event_id = event.descriptor.id();
    next.seen = accepted.head();
    next.seen_receipt = receipt_for(f.base, next.seen);
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
    let repeat = Commitment::order(
        f.base,
        accepted.head(),
        &different.descriptor,
        Route::Content,
    )
    .unwrap();
    assert_eq!(
        accepted
            .inspect(&repeat, &different.descriptor, &f.metadata)
            .err(),
        Some(Outcome::Rejected)
    );
}

#[test]
fn body_padding_authenticated_but_noncanonical_is_rejected_at_plaintext_validation() {
    let mut f = Fixture::new();
    let (data, _) = note_delta("padding");
    let (event, _) = f.content(&f.first, NOTE, &data);
    let signed = f
        .history
        .inspect(
            &Commitment::order(f.base, f.history.head(), &event.descriptor, Route::Content)
                .unwrap(),
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
    bind_ad.extend(2u16.to_be_bytes());
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
    to_sign.extend(&bind_plain[..646]);
    bind_plain[646..710].copy_from_slice(&f.first.signing.sign(&to_sign));
    let end = bind_ad.len();
    bind_ad[end - 32..].copy_from_slice(&digest);
    let (nonce, cipher) = aead_seal(&bind_key, &bind_ad, &bind_plain).unwrap();
    bind_plain.fill(0);
    let mut envelope = digest.to_vec();
    envelope.extend(nonce);
    envelope.extend(cipher);
    let descriptor = OpaqueEvent::new(event.descriptor.id(), envelope).unwrap();
    let order = Commitment::order(f.base, f.history.head(), &descriptor, Route::Content).unwrap();
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
        Outcome::Rejected
    );
    assert_eq!(f.history.head(), order.head());
    assert!(!f.history.is_stopped());
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
    let two_order =
        Commitment::order(f.base, f.history.head(), &two.descriptor, Route::Content).unwrap();
    assert_eq!(f.apply(&two, &two_order, true), Outcome::Accepted);
}

#[test]
fn wrong_roots_body_substitution_and_unknown_inner_control_are_distinct() {
    let mut f = Fixture::new();
    let (data, _) = note_delta("first");
    let (event, order) = f.content(&f.first, NOTE, &data);
    // An audience key alone cannot open the independent metadata binding:
    // a caller with only that lacks the metadata root and waits.
    assert_eq!(
        f.history.inspect(&order, &event.descriptor, &f.epoch).err(),
        Some(Outcome::UnavailablePause)
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
        Outcome::UnavailablePause
    );
    assert_eq!(f.history.head().position, 1);
    assert!(!f.history.is_stopped());
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
    let note_before = f.note.state().unwrap();
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
    assert_eq!(f.note.state().unwrap(), note_before);
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
    assert_eq!(f.note.state().unwrap(), note_before);
    assert!(f.history.is_stopped());
}

#[test]
fn prepared_routing_is_authenticated_and_local_target_errors_are_recoverable() {
    let mut f = Fixture::new();
    let mut first = Note::new().unwrap();
    let mut second = Note::new().unwrap();
    for (id, text) in [([7; 32], "first"), ([8; 32], "second")] {
        let mut authored = Note::new().unwrap();
        let mut data = with_writer(&authored.append_paragraph(text).unwrap());
        data[..32].copy_from_slice(&id);
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
        let wrong_before = wrong.state().unwrap();
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
        assert_eq!(wrong.state().unwrap(), wrong_before);
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
        assert_eq!(note.state().unwrap(), authored.state().unwrap());
    }
    assert_ne!(
        first.state().unwrap(),
        Note::new().unwrap().state().unwrap()
    );
    assert_ne!(
        second.state().unwrap(),
        Note::new().unwrap().state().unwrap()
    );
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
    assert_ne!(
        first.state().unwrap(),
        Note::new().unwrap().state().unwrap()
    );
    assert_ne!(
        second.state().unwrap(),
        Note::new().unwrap().state().unwrap()
    );
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
    let mut clone_note = Note::new().unwrap();
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
    let content = f.note.state().unwrap();
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
    assert_eq!(f.note.state().unwrap(), content);
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
                    note: &mut Note::new().unwrap()
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
    assert_eq!(f.note.state().unwrap(), content);
}

#[test]
fn same_head_trust_context_refuses_prepared_genesis() {
    let f = Fixture::new();
    let other = Fixture::new();
    let mut source = History::new(f.account.id(), &f.account_genesis, f.base, root(), 1).unwrap();
    let order =
        Commitment::order(f.base, Head::EMPTY, &f.genesis.descriptor, Route::Control).unwrap();
    let floor_two = History::new(f.account.id(), &f.account_genesis, f.base, root(), 2).unwrap();
    let other_account = History::new(
        other.account.id(),
        &other.account_genesis,
        f.base,
        root(),
        1,
    )
    .unwrap();
    let other_base =
        History::new(f.account.id(), &f.account_genesis, other.base, root(), 1).unwrap();
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
    assert_eq!(f.note.state().unwrap(), edited.state().unwrap());
    let before = (
        f.history.head(),
        f.history.account_head(),
        f.history.floor(),
        f.note.state().unwrap(),
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
            f.note.state().unwrap()
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
            f.note.state().unwrap()
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
            assert_eq!(delta.expose(), &data[bh_event::NOTE_PREFIX..]);
        }
        _ => panic!("expected accepted note"),
    }
    assert_eq!(f.note.state().unwrap(), edited.state().unwrap());
    assert!(!format!("{applied:?}").contains("bound note"));

    let bad = with_writer(&[0xff, 0xff, 0xff]);
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
    assert_eq!(f.note.state().unwrap(), edited.state().unwrap());

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
fn owned_materialization_deferred_publication_keeps_history_unpublished() {
    use bh_event::{OwnedNoteTarget, WorkingNote};
    let mut f = Fixture::new();
    let (data, edited) = note_delta("owned");
    let (event, order) = f.content(&f.first, NOTE, &data);
    let prepare = |f: &mut Fixture| {
        f.history
            .prepare(
                &order,
                &event.descriptor,
                Some(&event.body),
                &f.metadata,
                Some(&f.epoch),
            )
            .unwrap()
    };
    let before = f.history.head();
    let prepared = prepare(&mut f);
    let dropped = f
        .history
        .materialize(
            prepared,
            Some(OwnedNoteTarget {
                id: [7; 32],
                note: Note::new().unwrap(),
            }),
        )
        .unwrap();
    assert!(matches!(dropped.note, Some(WorkingNote::Accepted(_))));
    drop(dropped);
    assert_eq!(f.history.head(), before);
    let prepared = prepare(&mut f);
    let first = f
        .history
        .materialize(
            prepared,
            Some(OwnedNoteTarget {
                id: [7; 32],
                note: Note::new().unwrap(),
            }),
        )
        .unwrap();
    assert_eq!(f.history.head(), before);
    let original = first.transition.applied();
    assert_eq!(original.commitment(), order);
    assert_eq!(original.descriptor_bytes(), event.descriptor.encode());
    assert_eq!(original.body_bytes(), event.body);
    assert!(
        matches!(original.kind(), bh_event::AppliedKind::NoteAccepted { delta, .. } if delta.expose() == &data[bh_event::NOTE_PREFIX..])
    );
    let applied = f.history.publish_committed(first.transition).unwrap();
    assert_eq!(applied.head(), order.head());
    assert_eq!(f.history.head(), order.head());
    match first.note.unwrap() {
        WorkingNote::Accepted(note) => assert_eq!(note.state().unwrap(), edited.state().unwrap()),
        _ => panic!("expected accepted"),
    }
}

#[test]
fn owned_successor_loses_publication_race_without_replacing_winner() {
    let mut f = Fixture::new();
    let first = f
        .account
        .add_device(f.first.keys().id(), f.second.keys())
        .unwrap();
    let first = first
        .finish(f.first.control.sign(first.signing_bytes()))
        .unwrap();
    let third = Device::new();
    let second = f
        .account
        .add_device(f.first.keys().id(), third.keys())
        .unwrap();
    let second = second
        .finish(f.first.control.sign(second.signing_bytes()))
        .unwrap();
    let prepare = |f: &mut Fixture, data: &[u8]| {
        let (event, order) = f.create(
            f.binding(&f.first, CLASS_CONTROL),
            ACCOUNT_CHANGE,
            data,
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
        (f.history.materialize(prepared, None).unwrap(), order)
    };
    let (winner, winner_order) = prepare(&mut f, first.as_bytes());
    let (loser, loser_order) = prepare(&mut f, second.as_bytes());
    assert_ne!(winner_order.head(), loser_order.head());
    assert_eq!(f.history.account_head(), f.account.head());
    f.history.publish_committed(winner.transition).unwrap();
    let after_winner = (
        f.history.head(),
        f.history.account_head(),
        f.history.metadata_id(),
        f.history.epoch_id(),
        f.history.floor(),
        f.history.is_stopped(),
    );
    assert_eq!(after_winner.0, winner_order.head());
    assert_eq!(after_winner.1, first.head());
    assert_eq!(
        f.history.publish_committed(loser.transition).err(),
        Some(bh_event::PublishError::StaleState)
    );
    assert_eq!(
        (
            f.history.head(),
            f.history.account_head(),
            f.history.metadata_id(),
            f.history.epoch_id(),
            f.history.floor(),
            f.history.is_stopped(),
        ),
        after_winner,
    );
}

#[test]
fn owned_wrong_target_and_stale_prestate_return_working_note() {
    use bh_event::{OwnedNoteTarget, WorkingNote};
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
    let mut working = Note::new().unwrap();
    working.append_paragraph("local work").unwrap();
    let identity = working.replica_id();
    let failed = f
        .history
        .materialize(
            prepared,
            Some(OwnedNoteTarget {
                id: [8; 32],
                note: working,
            }),
        )
        .err()
        .unwrap();
    assert_eq!(failed.reason, bh_event::ConsumeError::WrongTarget);
    let working = failed.target.unwrap().note;
    assert_eq!(working.replica_id(), identity);
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
    let result = f
        .history
        .materialize(
            prepared,
            Some(OwnedNoteTarget {
                id: [7; 32],
                note: working,
            }),
        )
        .unwrap();
    f.history.publish_committed(result.transition).unwrap();
    let working = match result.note.unwrap() {
        WorkingNote::Accepted(n) => n,
        _ => panic!("accepted"),
    };
    let failed = f
        .history
        .materialize(
            stale,
            Some(OwnedNoteTarget {
                id: [7; 32],
                note: working,
            }),
        )
        .err()
        .unwrap();
    assert_eq!(failed.reason, bh_event::ConsumeError::StaleState);
    assert_eq!(failed.target.unwrap().note.replica_id(), identity);
    assert_eq!(f.history.head(), order.head());
}

#[test]
fn owned_integrity_stop_blocks_publication() {
    use bh_event::OwnedNoteTarget;
    let mut f = Fixture::new();
    let (data, _) = note_delta("future");
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
    let ready = f
        .history
        .materialize(
            prepared,
            Some(OwnedNoteTarget {
                id: [7; 32],
                note: Note::new().unwrap(),
            }),
        )
        .unwrap();
    let (mut bad, bad_order) = f.content(&f.first, NOTE, &data);
    bad.body[30] ^= 1;
    assert_eq!(
        f.history
            .prepare(
                &bad_order,
                &bad.descriptor,
                Some(&bad.body),
                &f.metadata,
                Some(&f.epoch)
            )
            .err(),
        Some(Outcome::IntegrityStop)
    );
    assert_eq!(
        f.history.publish_committed(ready.transition).err(),
        Some(bh_event::PublishError::StaleState)
    );
    assert!(f.history.is_stopped());
    assert_eq!(f.history.head().position, 1);
}

#[test]
fn owned_decode_rejection_returns_exact_working_note() {
    use bh_event::{OwnedNoteTarget, WorkingNote};
    let mut f = Fixture::new();
    let mut original = Note::new().unwrap();
    original.append_paragraph("retained").unwrap();
    let bytes = original.state().unwrap();
    let bad = with_writer(&[0xff, 0xff, 0xff]);
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
    let result = f
        .history
        .materialize(
            prepared,
            Some(OwnedNoteTarget {
                id: [7; 32],
                note: original,
            }),
        )
        .unwrap();
    assert_eq!(f.history.head().position, 1);
    assert_eq!(
        result.transition.applied().outcome(),
        Outcome::ContentRejected
    );
    match result.note.unwrap() {
        WorkingNote::Untouched(note) => assert_eq!(note.state().unwrap(), bytes),
        _ => panic!("expected untouched"),
    }
    f.history.publish_committed(result.transition).unwrap();
    assert_eq!(f.history.head(), order.head());
}

#[test]
fn owned_control_successor_is_published_only_when_called() {
    let mut f = Fixture::new();
    let request = f
        .account
        .add_device(f.first.keys().id(), f.second.keys())
        .unwrap();
    let add = request
        .finish(f.first.control.sign(request.signing_bytes()))
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
    let result = f.history.materialize(prepared, None).unwrap();
    assert!(result.note.is_none());
    assert_eq!(f.history.account_head(), f.account.head());
    f.history.publish_committed(result.transition).unwrap();
    assert_eq!(f.history.account_head(), add.head());
    assert_eq!(f.history.head(), order.head());
}

#[test]
fn owned_partial_apply_rejects_without_exposing_working_note_and_can_rebuild() {
    use bh_core::note::NoteError;
    use bh_event::{AppliedKind, OwnedNoteTarget, WorkingNote};
    let mut f = Fixture::new();
    // Yjs v1: client 1's String block named "x" is the committed original.
    let valid = [1, 1, 1, 0, 4, 1, 1, b'x', 1, b'a', 0];
    let data = with_writer(&valid);
    let (initial, initial_order) = f.content(&f.first, NOTE, &data);
    let prepared = f
        .history
        .prepare(
            &initial_order,
            &initial.descriptor,
            Some(&initial.body),
            &f.metadata,
            Some(&f.epoch),
        )
        .unwrap();
    let accepted = f
        .history
        .materialize(
            prepared,
            Some(OwnedNoteTarget {
                id: [7; 32],
                note: Note::new().unwrap(),
            }),
        )
        .unwrap();
    let committed_delta = match accepted.transition.applied().kind() {
        AppliedKind::NoteAccepted { delta, .. } => delta.expose().to_vec(),
        _ => panic!("expected initial delta"),
    };
    let note = match accepted.note.unwrap() {
        WorkingNote::Accepted(note) => note,
        _ => panic!("expected accepted note"),
    };
    let committed = note.state().unwrap();
    f.history.publish_committed(accepted.transition).unwrap();
    assert_eq!(f.history.head(), initial_order.head());

    // Client 2 first inserts z at root y, then uses client 1's primitive
    // String as a parent. Core must change its Doc before returning Apply.
    let partial = [1, 2, 2, 0, 4, 1, 1, b'y', 1, b'z', 4, 0, 1, 0, 1, b'b', 0];
    let mut probe = Note::new().unwrap();
    probe.apply_update(&committed_delta).unwrap();
    assert_eq!(probe.state().unwrap(), committed);
    assert!(matches!(
        probe.apply_update(&partial),
        Err(NoteError::Apply(_))
    ));
    assert_ne!(
        probe.state().unwrap(),
        committed,
        "fixture must mutate before error"
    );

    let data = with_writer(&partial);
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
    let result = f
        .history
        .materialize(prepared, Some(OwnedNoteTarget { id: [7; 32], note }))
        .unwrap();
    assert_eq!(
        result.transition.applied().outcome(),
        Outcome::ContentRejected
    );
    assert!(matches!(
        result.transition.applied().kind(),
        AppliedKind::NoteRejected { note_id } if *note_id == [7; 32]
    ));
    assert!(matches!(result.note, Some(WorkingNote::Poisoned)));
    assert_eq!(f.history.head(), initial_order.head());
    let mut rebuilt = Note::new().unwrap();
    rebuilt.apply_update(&committed_delta).unwrap();
    assert_eq!(rebuilt.state().unwrap(), committed);
    f.history.publish_committed(result.transition).unwrap();
    assert_eq!(f.history.head(), order.head());
}

#[test]
fn owned_many_signed_updates_preserve_note_without_disposable_replay() {
    use bh_event::{OwnedNoteTarget, WorkingNote};
    let mut f = Fixture::new();
    let mut author = Note::new().unwrap();
    let mut working = Note::new().unwrap();
    let replica = working.replica_id();
    for i in 0..300 {
        let data = with_writer(
            &author
                .append_paragraph(&format!("paragraph-{i}-{}", "x".repeat(256)))
                .unwrap(),
        );
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
        let materialized = f
            .history
            .materialize(
                prepared,
                Some(OwnedNoteTarget {
                    id: [7; 32],
                    note: working,
                }),
            )
            .unwrap();
        working = match materialized.note.unwrap() {
            WorkingNote::Accepted(note) => note,
            _ => panic!("expected accepted"),
        };
        assert_eq!(
            working.replica_id(),
            replica,
            "each delta must apply to the same owned Doc, not a rebuilt copy"
        );
        assert_eq!(
            materialized.transition.applied().outcome(),
            Outcome::Accepted
        );
        f.history
            .publish_committed(materialized.transition)
            .unwrap();
    }
    assert_eq!(working.state().unwrap(), author.state().unwrap());
    assert_eq!(f.history.head().position, 301);
}

// Manual, narrow cost probe: setup builds real signed account/base controls and
// checks them through History; only the fixed note/clone loops are timed. This
// does not measure throughput or a host deadline.
#[test]
#[ignore = "manual 1000-device signed-account scale probe"]
fn note_account_copy_scale_probe() {
    use std::time::Instant;

    for devices in [1, 1000] {
        let mut f = Fixture::new();
        let setup = Instant::now();
        for _ in 1..devices {
            let keys = DevicePublicKeys::new(
                SigningKey::generate().public(),
                SigningKey::generate().public(),
                KemKey::generate().public(),
            )
            .unwrap();
            let request = f.account.add_device(f.first.keys().id(), keys).unwrap();
            let add = request
                .finish(f.first.control.sign(request.signing_bytes()))
                .unwrap();
            let (event, order) = f.create(
                f.binding(&f.first, CLASS_CONTROL),
                ACCOUNT_CHANGE,
                add.as_bytes(),
                &f.first.control,
                None,
            );
            assert_eq!(f.apply(&event, &order, false), Outcome::Accepted);
            f.account.apply(add.as_bytes()).unwrap();
        }
        assert_eq!(f.history.account_head(), f.account.head());
        let setup_elapsed = setup.elapsed();
        let mut candidates = Vec::with_capacity(32);
        let start = Instant::now();
        for _ in 0..32 {
            candidates.push(f.history.clone());
        }
        let cloned = start.elapsed();
        assert!(
            candidates
                .iter()
                .all(|c| c.account_head() == f.history.account_head())
        );
        drop(candidates);

        let (data, _) = note_delta("probe");
        let events: Vec<_> = (0..32)
            .map(|_| f.content(&f.first, NOTE, &data).0)
            .collect();
        let start = Instant::now();
        for event in events {
            let order =
                Commitment::order(f.base, f.history.head(), &event.descriptor, Route::Content)
                    .unwrap();
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
                f.history
                    .consume(
                        prepared,
                        Some(NoteTarget {
                            id: [7; 32],
                            note: &mut f.note,
                        })
                    )
                    .unwrap()
                    .outcome(),
                Outcome::Accepted
            );
        }
        eprintln!(
            "signed-account devices={devices}: setup={setup_elapsed:?}, clone32={cloned:?}, verify-consume32={:?}",
            start.elapsed()
        );
    }
}

#[test]
fn replay_verifies_records_from_anchors_without_applying_notes() {
    let mut f = Fixture::new();
    let first_order =
        Commitment::order(f.base, Head::EMPTY, &f.genesis.descriptor, Route::Control).unwrap();
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
        root(),
        &[],
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
    let mut note = Note::new().unwrap();
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
            root(),
            &[],
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
    changed[1].0 = Commitment::order(
        f.base,
        records[0].0.head(),
        &other.descriptor,
        Route::Content,
    )
    .unwrap();
    assert_eq!(
        check(changed[..2].to_vec(), f.base),
        Some(Outcome::IntegrityStop)
    );
    // A fresh, correctly signed next record with an already-used EventId is
    // rejected even though its outer commitment and predecessor are valid:
    // it holds its position with no effect, and replay goes on.
    let mut repeated = f.binding(&f.first, CLASS_CONTENT);
    repeated.seen = records[2].0.head();
    repeated.seen_receipt = receipt_for(f.base, repeated.seen);
    repeated.event_id = OpaqueEvent::decode(&records[1].1).unwrap().id();
    let (duplicate, _) = f.create(repeated, NOTE, &data, &f.first.signing, Some(&f.epoch));
    let duplicate_order = Commitment::order(
        f.base,
        records[2].0.head(),
        &duplicate.descriptor,
        Route::Content,
    )
    .unwrap();
    let mut changed = records.clone();
    changed.push((
        duplicate_order,
        duplicate.descriptor.encode(),
        duplicate.body,
    ));
    let replayed = History::replay(
        f.account.id(),
        &f.account_genesis,
        f.base,
        root(),
        &[],
        &f.metadata,
        Some(&f.epoch),
        changed,
    )
    .unwrap();
    assert_eq!(replayed.head(), duplicate_order.head());
    assert_eq!(replayed.account_head(), f.history.account_head());
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
    // Each event is judged under the floor in force at its own position. A
    // floor of 3 for events after position 2 rejects the v2 account addition
    // at position 3; the same rise after position 3 leaves it accepted, as
    // live verification did. Under another pinned hosting root (whose
    // receipts these are not) each later event is rejected.
    let genesis_account = AccountEvent::decode(&f.account_genesis).unwrap().head();
    for (root, rises, account, floor) in [
        (root(), vec![(0, 2)], f.history.account_head(), 2),
        (root(), vec![(2, 3)], genesis_account, 3),
        (root(), vec![(3, 3)], f.history.account_head(), 3),
        (SigningKey::generate().public(), vec![], genesis_account, 1),
    ] {
        let replayed = History::replay(
            f.account.id(),
            &f.account_genesis,
            f.base,
            root,
            &rises,
            &f.metadata,
            Some(&f.epoch),
            records.clone(),
        )
        .unwrap();
        assert_eq!(replayed.head(), records[2].0.head());
        assert_eq!(replayed.account_head(), account);
        assert_eq!(replayed.floor(), floor);
        assert!(!replayed.is_stopped());
    }
    let higher = History::replay(
        f.account.id(),
        &f.account_genesis,
        f.base,
        root(),
        &[(0, 2)],
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
        root(),
        &[],
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

#[test]
fn author_signed_padded_size_other_than_the_body_is_rejected_not_a_stop() {
    let mut f = Fixture::new();
    let (data, _) = note_delta("one");
    let (event, _) = f.content(&f.first, NOTE, &data);
    assert_eq!(event.body.len(), 1024);
    // The author signs a padded size other than the body it staged; the
    // body bytes are exactly what the ordered descriptor names, so the
    // service changed nothing.
    let altered = rebind(
        &event.descriptor,
        f.base,
        &f.metadata,
        &f.first.signing,
        |s| s[310..314].copy_from_slice(&4096u32.to_be_bytes()),
    );
    assert_eq!(
        bh_sync::referenced_body(&altered).unwrap(),
        bh_sync::BodyObject::new(event.body.clone())
            .unwrap()
            .commitment()
    );
    let order = Commitment::order(f.base, f.history.head(), &altered, Route::Content).unwrap();
    let event = Encoded {
        descriptor: altered,
        body: event.body,
    };
    let before = f.note.state().unwrap();
    assert_eq!(f.apply(&event, &order, true), Outcome::Rejected);
    assert!(!f.history.is_stopped());
    assert_eq!(f.history.head(), order.head());
    assert_eq!(f.note.state().unwrap(), before);
    let (data, _) = note_delta("next");
    let (next, order) = f.content(&f.first, NOTE, &data);
    assert_eq!(f.apply(&next, &order, true), Outcome::Accepted);
}

#[test]
fn compatibility_apply_unavailable_pauses_and_identical_retry_succeeds() {
    let mut f = Fixture::new();
    let (data, _) = note_delta("retry unchanged");
    let (event, order) = f.content(&f.first, NOTE, &data);
    let head = f.history.head();
    let state = f.note.state().unwrap();
    assert_eq!(
        bh_core::contained::with_fuel(0, || f.apply(&event, &order, true)),
        Outcome::UnavailablePause
    );
    assert_eq!(f.history.head(), head);
    assert_eq!(f.note.state().unwrap(), state);
    assert!(!f.history.is_stopped());
    assert_eq!(f.apply(&event, &order, true), Outcome::Accepted);
    assert_eq!(f.history.head(), order.head());
    assert_ne!(f.note.state().unwrap(), state);
}

#[test]
fn compatibility_apply_real_contained_trap_never_stops_history() {
    let mut f = Fixture::new();
    // A root Any containing deeply nested singleton arrays traps during apply,
    // under ordinary fuel, after authenticated preparation has succeeded.
    let mut bomb = vec![1, 1, 3, 0, 8, 1, 4, b'b', b'o', b'm', b'b', 1];
    for _ in 0..100_000 {
        bomb.extend_from_slice(&[117, 1]);
    }
    bomb.extend_from_slice(&[126, 0]);
    let (event, order) = f.content(&f.first, NOTE, &with_writer(&bomb));
    assert!(
        f.history
            .prepare(
                &order,
                &event.descriptor,
                Some(&event.body),
                &f.metadata,
                Some(&f.epoch)
            )
            .is_ok()
    );
    let head = f.history.head();
    let state = f.note.state().unwrap();
    for _ in 0..2 {
        assert_eq!(f.apply(&event, &order, true), Outcome::UnavailablePause);
        assert_eq!(f.history.head(), head);
        assert_eq!(f.note.state().unwrap(), state);
        assert!(!f.history.is_stopped());
    }
}

#[test]
fn unavailable_history_operations_do_not_judge_advance_or_stop() {
    for mode in 1..3 {
        let mut f = Fixture::new();
        let update = Note::with_writer(50)
            .unwrap()
            .append_paragraph("retained")
            .unwrap();
        let (event, order) = f.content(&f.first, NOTE, &with_writer(&update));
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
        let before_head = f.history.head();
        let before_state = f.note.state().unwrap();
        let owned =
            Note::from_ordered(&bh_core::note::OrderedState::single(before_state.clone())).unwrap();
        let result = bh_core::contained::with_fuel(0, || match mode {
            0 => f.history.consume_unapplied(prepared).map(|_| ()),
            1 => f
                .history
                .consume(
                    prepared,
                    Some(bh_event::NoteTarget {
                        id: [7; 32],
                        note: &mut f.note,
                    }),
                )
                .map(|_| ()),
            _ => f
                .history
                .materialize(
                    prepared,
                    Some(bh_event::OwnedNoteTarget {
                        id: [7; 32],
                        note: owned,
                    }),
                )
                .map(|_| ())
                .map_err(|e| e.reason),
        });
        assert_eq!(result, Err(bh_event::ConsumeError::Unavailable));
        assert_eq!(f.history.head(), before_head);
        assert!(!f.history.is_stopped());
        assert_eq!(f.note.state().unwrap(), before_state);
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
            f.history.consume_unapplied(prepared).unwrap().outcome(),
            Outcome::Accepted
        );
    }
}

#[test]
fn consume_unapplied_retains_bytes_without_running_the_engine() {
    let mut f = Fixture::new();
    let prepare = |f: &mut Fixture, event: &Encoded, order: &Commitment, content| {
        f.history
            .prepare(
                order,
                &event.descriptor,
                Some(&event.body),
                &f.metadata,
                if content { Some(&f.epoch) } else { None },
            )
            .unwrap()
    };
    let update = Note::new().unwrap().append_paragraph("one").unwrap();
    let (event, order) = f.content(&f.first, NOTE, &with_writer(&update));
    let prepared = prepare(&mut f, &event, &order, true);
    let applied =
        bh_core::contained::with_fuel(0, || f.history.consume_unapplied(prepared)).unwrap();
    match applied.kind() {
        bh_event::AppliedKind::NoteAccepted { note_id, delta } => {
            assert_eq!(*note_id, [7; 32]);
            assert_eq!(delta.expose(), update.as_slice());
        }
        _ => panic!("accepted note expected"),
    }
    assert_eq!(f.history.head(), order.head());
    // An update that decodes is the owner's to judge on accepted state,
    // even one no Note could integrate here (a run that can never attach).
    let mut other = Note::new().unwrap();
    let dangling = {
        let mut sender = Note::new().unwrap();
        sender
            .apply_update(&other.append_paragraph("unseen").unwrap())
            .unwrap();
        sender.append_paragraph("after the unseen one").unwrap()
    };
    let (event, order) = f.content(&f.first, NOTE, &with_writer(&dangling));
    let prepared = prepare(&mut f, &event, &order, true);
    assert_eq!(
        f.history.consume_unapplied(prepared).unwrap().outcome(),
        Outcome::Accepted
    );
    // Even decoding belongs to the note owner, not the history verifier.
    let (event, order) = f.content(&f.first, NOTE, &with_writer(&[0xff, 0xff, 0xff]));
    let prepared = prepare(&mut f, &event, &order, true);
    assert!(matches!(
        f.history.consume_unapplied(prepared).unwrap().kind(),
        bh_event::AppliedKind::NoteAccepted { note_id, .. } if *note_id == [7; 32]
    ));
    assert_eq!(f.history.head(), order.head());
    // A preparation against another predecessor is stale.
    let (event, order) = f.content(&f.first, NOTE, &with_writer(&update));
    let stale = prepare(&mut f, &event, &order, true);
    let fresh = prepare(&mut f, &event, &order, true);
    f.history.consume_unapplied(fresh).unwrap();
    assert!(f.history.consume_unapplied(stale).is_err());
}

/// A store's durable verified rows, as a device keeps them per position and
/// per event ID, read back only by point lookups.
#[derive(Default)]
struct Rows {
    seen: std::sync::Mutex<std::collections::BTreeMap<u64, bh_event::Seen>>,
    ids: std::sync::Mutex<std::collections::BTreeMap<[u8; 32], Digest>>,
    changes: std::sync::Mutex<Vec<Vec<u8>>>,
    reads: std::sync::atomic::AtomicUsize,
    fail: std::sync::atomic::AtomicBool,
}
impl Rows {
    fn record(&self, applied: &bh_event::AppliedEvent) {
        self.seen
            .lock()
            .unwrap()
            .insert(applied.head().position, applied.seen());
        let ordered = applied.commitment();
        self.ids
            .lock()
            .unwrap()
            .entry(ordered.event_id().0)
            .or_insert(ordered.event_digest());
        if let Some(change) = applied.account_change() {
            self.changes.lock().unwrap().push(change.to_vec());
        }
    }
    fn read(&self) -> Result<(), bh_event::LookupError> {
        self.reads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.fail.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(bh_event::LookupError);
        }
        Ok(())
    }
}
impl bh_event::HistoryLookup for Rows {
    fn seen(&self, position: u64) -> Result<Option<bh_event::Seen>, bh_event::LookupError> {
        self.read()?;
        Ok(self.seen.lock().unwrap().get(&position).copied())
    }
    fn event_digest(&self, event_id: [u8; 32]) -> Result<Option<Digest>, bh_event::LookupError> {
        self.read()?;
        Ok(self.ids.lock().unwrap().get(&event_id).copied())
    }
}

/// Verify and consume one event as the device does, keeping its rows.
fn step(
    history: &mut History,
    rows: &Rows,
    f: &Fixture,
    event: &Encoded,
    order: &Commitment,
    content: bool,
) -> Outcome {
    let prepared = match history.prepare(
        order,
        &event.descriptor,
        Some(&event.body),
        &f.metadata,
        if content { Some(&f.epoch) } else { None },
    ) {
        Ok(prepared) => prepared,
        Err(outcome) => return outcome,
    };
    let applied = history.consume_unapplied(prepared).unwrap();
    rows.record(&applied);
    applied.outcome()
}

#[test]
fn resume_continues_from_durable_rows_without_replay() {
    let mut f = Fixture::new();
    let anchor = VerifiedAccount::from_genesis(f.account.id(), &f.account_genesis).unwrap();
    let rows = std::sync::Arc::new(Rows::default());
    // Live verification from genesis, keeping only durable rows.
    f.history = History::with_account(&anchor, f.base, root(), 1).unwrap();
    let genesis = Encoded {
        descriptor: f.genesis.descriptor.clone(),
        body: f.genesis.body.clone(),
    };
    let order =
        Commitment::order(f.base, Head::EMPTY, &genesis.descriptor, Route::Control).unwrap();
    let mut live = f.history.clone();
    assert_eq!(
        step(&mut live, &rows, &f, &genesis, &order, false),
        Outcome::Accepted
    );
    f.history = live.clone();
    let (data, _) = note_delta("first");
    let (first, order) = f.content(&f.first, NOTE, &data);
    assert_eq!(
        step(&mut live, &rows, &f, &first, &order, true),
        Outcome::Accepted
    );
    f.history = live.clone();
    let add = f
        .account
        .add_device(f.first.keys().id(), f.second.keys())
        .unwrap();
    let add = add
        .finish(f.first.control.sign(add.signing_bytes()))
        .unwrap();
    let (change, order) = f.create(
        f.binding(&f.first, CLASS_CONTROL),
        ACCOUNT_CHANGE,
        add.as_bytes(),
        &f.first.control,
        None,
    );
    let prepared = live
        .prepare(
            &order,
            &change.descriptor,
            Some(&change.body),
            &f.metadata,
            None,
        )
        .unwrap();
    let applied = live.consume_unapplied(prepared).unwrap();
    rows.record(&applied);
    let continuation = applied.continuation().unwrap();
    f.control = order.event_digest().0;
    f.account.apply(add.as_bytes()).unwrap();
    f.history = live.clone();
    assert_eq!(rows.changes.lock().unwrap().len(), 1);

    // Everything in memory is dropped; only the rows and the continuation
    // remain. Resuming reads no original and replays nothing.
    let changes = rows.changes.lock().unwrap().clone();
    let mut resumed = History::resume(
        &anchor,
        f.base,
        root(),
        continuation,
        &changes,
        rows.clone(),
        1,
    )
    .unwrap();
    assert_eq!(resumed.head(), live.head());
    assert_eq!(resumed.account_head(), live.account_head());
    assert_eq!(resumed.metadata_id(), live.metadata_id());
    assert_eq!(resumed.epoch_id(), live.epoch_id());
    assert_eq!(resumed.floor(), live.floor());

    // The same events judged live and resumed reach the same outcomes: the
    // new device's note, an old truthful observation, a reused event ID and
    // a hosting receipt contradicting a verified head.
    let reads = rows.reads.load(std::sync::atomic::Ordering::Relaxed);
    let (data, _) = note_delta("from the added device");
    let (added, order) = f.content(&f.second, NOTE, &data);
    let mut old = f.binding(&f.first, CLASS_CONTENT);
    old.seen = Commitment::order(f.base, Head::EMPTY, &genesis.descriptor, Route::Control)
        .unwrap()
        .head();
    old.seen_receipt = receipt_for(f.base, old.seen);
    old.account_head = anchor.head();
    old.seen_control = order_digest(&f, &genesis);
    let mut reused = f.binding(&f.first, CLASS_CONTENT);
    reused.event_id = first.descriptor.id();
    let mut forked = f.binding(&f.first, CLASS_CONTENT);
    forked.seen = Head {
        position: 1,
        hash: Digest([3; 32]),
    };
    forked.seen_receipt = receipt_for(f.base, forked.seen);
    let (data, _) = note_delta("next");
    let scratch = Rows::default();
    assert_eq!(
        step(&mut live, &scratch, &f, &added, &order, true),
        Outcome::Accepted
    );
    assert_eq!(
        step(&mut resumed, &rows, &f, &added, &order, true),
        Outcome::Accepted
    );
    f.history = live.clone();
    for (binding, outcome) in [
        (old, Outcome::Accepted),
        (reused, Outcome::Rejected),
        (forked, Outcome::IntegrityStop),
    ] {
        let (event, order) = f.create(binding, NOTE, &data, &f.first.signing, Some(&f.epoch));
        assert_eq!(step(&mut live, &scratch, &f, &event, &order, true), outcome);
        assert_eq!(step(&mut resumed, &rows, &f, &event, &order, true), outcome);
        assert_eq!(resumed.head(), live.head());
        f.history = live.clone();
    }
    assert!(live.is_stopped() && resumed.is_stopped());
    assert!(
        rows.reads.load(std::sync::atomic::Ordering::Relaxed) > reads,
        "earlier positions and IDs were looked up"
    );

    // Local state that does not reproduce the continuation, or a store
    // that cannot answer, waits: nothing is judged.
    assert_eq!(
        History::resume(
            &anchor,
            f.base,
            root(),
            continuation,
            Vec::<Vec<u8>>::new(),
            rows.clone(),
            1
        )
        .err(),
        Some(Outcome::UnavailablePause)
    );
    let empty = std::sync::Arc::new(Rows::default());
    assert_eq!(
        History::resume(&anchor, f.base, root(), continuation, &changes, empty, 1).err(),
        Some(Outcome::UnavailablePause)
    );
    let mut waiting = History::resume(
        &anchor,
        f.base,
        root(),
        continuation,
        &changes,
        rows.clone(),
        1,
    )
    .unwrap();
    rows.fail.store(true, std::sync::atomic::Ordering::Relaxed);
    f.history = waiting.clone();
    let (event, order) = f.content(&f.first, NOTE, &data);
    assert_eq!(
        step(&mut waiting, &rows, &f, &event, &order, true),
        Outcome::UnavailablePause
    );
    assert!(!waiting.is_stopped());
    assert_eq!(waiting.head(), continuation.seen.head);
}

fn order_digest(f: &Fixture, genesis: &Encoded) -> [u8; 32] {
    Commitment::order(f.base, Head::EMPTY, &genesis.descriptor, Route::Control)
        .unwrap()
        .event_digest()
        .0
}
