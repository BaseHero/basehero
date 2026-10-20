//! Version-2 bindings carry a hosting receipt for the author's observed head.
use bh_account::{AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount};
use bh_core::note::Note;
use bh_crypto::{KemKey, Secret, SigningKey, aead_open, aead_seal, derive_key};
use bh_event::{
    AppliedKind, Binding, CLASS_CONTENT, Encoded, Error, History, NOTE, NoteTarget, Outcome,
    Payload, key_id, note_payload, prepare_genesis, seal, sealed_epoch, verify_genesis,
    writer::DeviceWriterDeclaration,
};
use bh_sync::receipt::{self, CertifiedReceiptKey, RECEIPT_LEN};
use bh_sync::{
    BODY_SIZES, BaseId, BodyObject, Commitment, Digest, ENVELOPE_SIZES, EventId, Head, OpaqueEvent,
    Route,
};

fn seed(byte: u8) -> Secret<32> {
    Secret::from_slice(&[byte; 32]).unwrap()
}
fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}

struct Hosting {
    root: SigningKey,
    certificate: CertifiedReceiptKey,
    key: SigningKey,
}
impl Hosting {
    fn new() -> Self {
        let root = SigningKey::generate();
        let key = SigningKey::generate();
        let certificate =
            receipt::verify_certificate(&root.public(), &receipt::certify(&root, key.public()))
                .unwrap();
        Self {
            root,
            certificate,
            key,
        }
    }
    fn root(&self) -> [u8; 32] {
        self.root.public()
    }
    fn receipt(&self, base: BaseId, head: Head) -> [u8; RECEIPT_LEN] {
        receipt::sign(&self.certificate, &self.key, base, head).unwrap()
    }
}

struct Fixture {
    signing: SigningKey,
    account: VerifiedAccount,
    device: bh_account::DeviceId,
    metadata: Secret<32>,
    content: Secret<32>,
    base: BaseId,
    hosting: Hosting,
    history: History,
    control: [u8; 32],
    genesis: Encoded,
}
impl Fixture {
    fn new() -> Self {
        let signing = SigningKey::generate();
        let control = SigningKey::generate();
        let keys = DevicePublicKeys::new(
            signing.public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        let device = keys.id();
        let draft = AccountEvent::genesis(
            keys,
            RecoveryPublicKeys::new(SigningKey::generate().public(), KemKey::generate().public()),
        );
        let first = draft.finish(control.sign(draft.signing_bytes())).unwrap();
        let id = AccountId::of_genesis(&first).unwrap();
        let account = VerifiedAccount::from_genesis(id, first.as_bytes()).unwrap();
        let metadata = Secret::<32>::random();
        let content = Secret::<32>::random();
        let request = prepare_genesis(&account, device, &metadata, &content).unwrap();
        let signature = signing.sign(request.signing_bytes());
        let (genesis, base) = request.finish(signature).unwrap();
        let hosting = Hosting::new();
        let mut history = History::with_account(&account, base, hosting.root(), 1).unwrap();
        let ordered =
            Commitment::order(base, Head::EMPTY, &genesis.descriptor, Route::Control).unwrap();
        let mut scratch = Note::new().unwrap();
        assert_eq!(
            history.apply(
                &ordered,
                &genesis.descriptor,
                Some(&genesis.body),
                &metadata,
                None,
                NoteTarget {
                    id: [7; 32],
                    note: &mut scratch,
                },
            ),
            Outcome::Accepted
        );
        Self {
            signing,
            account,
            device,
            metadata,
            content,
            base,
            hosting,
            history,
            control: ordered.event_digest().0,
            genesis,
        }
    }
    /// The same verified genesis, under a verifier pinned to another root.
    fn pinned_to(&self, root: [u8; 32]) -> History {
        let mut history = History::with_account(&self.account, self.base, root, 1).unwrap();
        let ordered = Commitment::order(
            self.base,
            Head::EMPTY,
            &self.genesis.descriptor,
            Route::Control,
        )
        .unwrap();
        let mut scratch = Note::new().unwrap();
        assert_eq!(
            history.apply(
                &ordered,
                &self.genesis.descriptor,
                Some(&self.genesis.body),
                &self.metadata,
                None,
                NoteTarget {
                    id: [7; 32],
                    note: &mut scratch,
                },
            ),
            Outcome::Accepted
        );
        history
    }
    fn binding(&self, receipt: [u8; RECEIPT_LEN]) -> Binding {
        Binding {
            version: 2,
            highest: 2,
            mode: 0,
            base: self.base.0,
            audience: [0; 32],
            epoch: key_id(&self.content),
            event_id: EventId(bh_crypto::random()),
            account: self.account.id(),
            device: self.device,
            account_head: self.account.head(),
            seen: self.history.head(),
            seen_control: self.control,
            class: CLASS_CONTENT,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: receipt,
        }
    }
    fn valid_receipt(&self) -> [u8; RECEIPT_LEN] {
        self.hosting.receipt(self.base, self.history.head())
    }
    fn note(&self, receipt: [u8; RECEIPT_LEN], data: &[u8]) -> Encoded {
        seal(
            self.binding(receipt),
            Payload { kind: NOTE, data },
            &self.signing,
            &self.metadata,
            Some(&self.content),
        )
        .unwrap()
    }
    fn apply(&self, history: &mut History, event: &Encoded, note: &mut Note) -> Outcome {
        let ordered =
            Commitment::order(self.base, history.head(), &event.descriptor, Route::Content)
                .unwrap();
        history.apply(
            &ordered,
            &event.descriptor,
            Some(&event.body),
            &self.metadata,
            Some(&self.content),
            NoteTarget { id: [7; 32], note },
        )
    }
    /// Run the event against a fresh copy and require a latched integrity stop
    /// that leaves the verified head and the Note unchanged.
    fn assert_stops(&self, event: &Encoded, why: &str) {
        let mut history = self.history.clone();
        let head = history.head();
        let mut note = Note::new().unwrap();
        assert_eq!(
            self.apply(&mut history, event, &mut note),
            Outcome::IntegrityStop,
            "{why}"
        );
        assert_eq!(history.head(), head, "{why}");
        assert!(history.is_stopped(), "{why}");
        assert_eq!(
            note.state().unwrap(),
            Note::new().unwrap().state().unwrap(),
            "{why}"
        );
        // Nothing more applies from this server.
        let next = self.note(self.valid_receipt(), &note_data("after the stop"));
        assert_eq!(
            self.apply(&mut history, &next, &mut note),
            Outcome::IntegrityStop,
            "{why}"
        );
        assert_eq!(history.head(), head, "{why}");
    }
    /// Run the event against a fresh copy: it is ordered and rejected with no
    /// effect, and a valid event after it still applies.
    fn assert_rejected(&self, event: &Encoded, why: &str) {
        let mut history = self.history.clone();
        let mut note = Note::new().unwrap();
        assert_eq!(
            self.apply(&mut history, event, &mut note),
            Outcome::Rejected,
            "{why}"
        );
        assert_eq!(history.head().position, self.history.head().position + 1);
        assert!(!history.is_stopped(), "{why}");
        assert_eq!(
            note.state().unwrap(),
            Note::new().unwrap().state().unwrap(),
            "{why}"
        );
        assert_eq!(history.floor(), self.history.floor(), "{why}");
        // Its author's observation is still the verified head before it.
        let next = self.note(self.valid_receipt(), &note_data("after it"));
        assert_eq!(
            self.apply(&mut history, &next, &mut note),
            Outcome::Accepted,
            "{why}"
        );
        assert_eq!(note.title_preview().unwrap(), "after it", "{why}");
    }
}

const WRITER: DeviceWriterDeclaration = DeviceWriterDeclaration {
    account: [4; 32],
    device: [5; 32],
    nonce: [6; 32],
};
/// Note 7's payload: its ID, the producing writer's declaration, the update.
fn note_data(text: &str) -> Vec<u8> {
    note_payload(
        [7; 32],
        WRITER,
        &Note::new().unwrap().append_paragraph(text).unwrap(),
    )
}

#[test]
fn genesis_v1_bytes_unchanged() {
    let vector = include_str!("fixtures/genesis-v1.txt");
    let field = |name: &str| {
        unhex(
            vector
                .lines()
                .find_map(|line| line.strip_prefix(name)?.strip_prefix(' '))
                .unwrap(),
        )
    };
    let account_genesis = field("account");
    let descriptor = OpaqueEvent::decode(&field("descriptor")).unwrap();
    let body = field("body");
    let base = BaseId::from_genesis(&descriptor);
    assert_eq!(base.0.to_vec(), field("base"), "pinned genesis digest");
    assert_eq!(descriptor.encode().len(), 1062);
    assert_eq!(body.len(), 1024);
    let first = AccountEvent::decode(&account_genesis).unwrap();
    let account =
        VerifiedAccount::from_genesis(AccountId::of_genesis(&first).unwrap(), &account_genesis)
            .unwrap();
    let verified = verify_genesis(&account, &descriptor, &body, &seed(0x33), 1).unwrap();
    assert_eq!(verified.base, base);
    assert_eq!(verified.metadata_key_id, key_id(&seed(0x33)));
    assert_eq!(verified.content_key_id, key_id(&seed(0x44)));
    // Genesis is fixed v1 bytes: a remembered v2 floor still opens the base.
    for floor in [1, 2] {
        let mut history =
            History::with_account(&account, base, Hosting::new().root(), floor).unwrap();
        let ordered = Commitment::order(base, Head::EMPTY, &descriptor, Route::Control).unwrap();
        let mut note = Note::new().unwrap();
        assert_eq!(
            history.apply(
                &ordered,
                &descriptor,
                Some(&body),
                &seed(0x33),
                None,
                NoteTarget {
                    id: [7; 32],
                    note: &mut note,
                },
            ),
            Outcome::Accepted,
            "floor {floor}"
        );
    }
    // A freshly prepared genesis still signs the 346-byte v1 fields.
    let request = prepare_genesis(&account, verified.device, &seed(0x33), &seed(0x44)).unwrap();
    let domain = b"bh/original-envelope/v1\0";
    assert_eq!(request.signing_bytes().len(), domain.len() + 346);
    assert_eq!(&request.signing_bytes()[..domain.len()], domain);
    assert_eq!(
        &request.signing_bytes()[domain.len()..domain.len() + 4],
        &[0, 1, 0, 1]
    );
}

#[test]
fn v2_requires_receipt() {
    let f = Fixture::new();
    let data = note_data("needs a receipt");
    f.assert_rejected(&f.note([0; RECEIPT_LEN], &data), "zeroed receipt");
    let mut history = f.history.clone();
    let mut note = Note::new().unwrap();
    let event = f.note(f.valid_receipt(), &data);
    assert_eq!(f.apply(&mut history, &event, &mut note), Outcome::Accepted);
    assert_eq!(history.floor(), 2);
}

#[test]
fn v2_receipt_must_match_seen() {
    let f = Fixture::new();
    let data = note_data("observed head");
    let seen = f.history.head();
    let other_hash = Head {
        position: seen.position,
        hash: Digest([9; 32]),
    };
    let later = Head {
        position: seen.position + 1,
        hash: seen.hash,
    };
    let mut bad_signature = f.valid_receipt();
    bad_signature[RECEIPT_LEN - 1] ^= 1;
    // The pinned hosting key signed another head at a verified position:
    // the service contradicts the history this device verified.
    f.assert_stops(
        &f.note(f.hosting.receipt(f.base, other_hash), &data),
        "same position, other hash",
    );
    for (receipt, why) in [
        (f.hosting.receipt(f.base, Head::EMPTY), "empty head"),
        (f.hosting.receipt(f.base, later), "later position"),
        (f.hosting.receipt(BaseId([5; 32]), seen), "other base"),
        (Hosting::new().receipt(f.base, seen), "unpinned root"),
        (bad_signature, "bad receipt signature"),
    ] {
        // Anything else wrong with a receipt is its author's submission.
        f.assert_rejected(&f.note(receipt, &data), why);
    }
    // A receipt that verifies under some root is still refused when the
    // verifier is pinned to another: an unknown key never makes it wait.
    let event = f.note(f.valid_receipt(), &data);
    let mut repinned = f.pinned_to(Hosting::new().root());
    let mut note = Note::new().unwrap();
    assert_eq!(f.apply(&mut repinned, &event, &mut note), Outcome::Rejected);
    assert!(!repinned.is_stopped());
    let mut history = f.history.clone();
    assert_eq!(f.apply(&mut history, &event, &mut note), Outcome::Accepted);
}

#[test]
fn v2_roundtrip_large_body_1mib() {
    assert_eq!(ENVELOPE_SIZES, [1024, 4096, 16384, 65536]);
    assert_eq!(
        BODY_SIZES,
        [1024, 4096, 16384, 65536, 262144, 1048576, 4194304]
    );
    let f = Fixture::new();
    let text = "large body ".repeat(60_000);
    let data = note_data(&text);
    assert!(data.len() > 262144 && data.len() + 46 <= 1048576);
    let event = f.note(f.valid_receipt(), &data);
    assert_eq!(event.body.len(), 1048576);
    assert_eq!(event.descriptor.envelope().len(), 1024);
    let staged = BodyObject::new(event.body.clone()).unwrap();
    assert_eq!(
        bh_sync::referenced_body(&event.descriptor).unwrap(),
        staged.commitment()
    );
    let mut history = f.history.clone();
    let mut note = Note::new().unwrap();
    assert_eq!(f.apply(&mut history, &event, &mut note), Outcome::Accepted);
    let mut expected = Note::new().unwrap();
    expected.apply_update(&data[32 + 99..]).unwrap();
    assert_eq!(note.state().unwrap(), expected.state().unwrap());
    // The largest class holds exactly its payload capacity and nothing more.
    let max = vec![1; 4194304 - 46];
    assert_eq!(
        seal(
            f.binding(f.valid_receipt()),
            Payload {
                kind: NOTE,
                data: &max
            },
            &f.signing,
            &f.metadata,
            Some(&f.content),
        )
        .unwrap()
        .body
        .len(),
        4194304
    );
    assert!(matches!(
        seal(
            f.binding(f.valid_receipt()),
            Payload {
                kind: NOTE,
                data: &max[..]
                    .iter()
                    .chain([1].iter())
                    .copied()
                    .collect::<Vec<_>>()
            },
            &f.signing,
            &f.metadata,
            Some(&f.content),
        ),
        Err(Error::Invalid)
    ));
    // Envelopes stay row-sized; only detached bodies use the larger classes.
    assert!(OpaqueEvent::new(EventId([1; 32]), vec![0; 262144]).is_err());
    assert!(BodyObject::new(vec![0; 4194304]).is_ok());
    assert!(BodyObject::new(vec![0; 2097152]).is_err());
}

#[test]
fn v2_small_edit_envelope_is_one_kib() {
    let f = Fixture::new();
    let event = f.note(f.valid_receipt(), &note_data("a typical small edit"));
    assert_eq!(event.descriptor.envelope().len(), 1024);
    assert_eq!(event.descriptor.encode().len(), 1062);
    assert_eq!(event.body.len(), 1024);
}

#[test]
fn v1_nongenesis_rejected() {
    let f = Fixture::new();
    let data = note_data("old version");
    let mut v1 = f.binding([0; RECEIPT_LEN]);
    v1.version = 1;
    v1.highest = 1;
    assert!(matches!(
        seal(
            v1,
            Payload {
                kind: NOTE,
                data: &data
            },
            &f.signing,
            &f.metadata,
            Some(&f.content),
        ),
        Err(Error::Invalid)
    ));
    // An author-signed v1 binding after genesis is refused, not paused.
    let event = f.note(f.valid_receipt(), &data);
    let downgraded = Encoded {
        descriptor: downgrade_to_v1(&event.descriptor, f.base, &f.metadata, &f.signing),
        body: event.body.clone(),
    };
    f.assert_rejected(&downgraded, "v1 after genesis");
}

/// Re-sign the same author fields as a v1 binding (no receipt) and reseal it.
fn downgrade_to_v1(
    event: &OpaqueEvent,
    base: BaseId,
    metadata: &Secret<32>,
    signer: &SigningKey,
) -> OpaqueEvent {
    let env = event.envelope();
    let aad = |version: u16| {
        let mut ad = b"bh/author-binding-aad/v1\0".to_vec();
        ad.extend(version.to_be_bytes());
        ad.push(0);
        ad.extend(base.0);
        ad.extend(event.id().0);
        ad.extend(&env[..32]);
        ad
    };
    let key = derive_key(metadata, b"bhBind01", 0);
    let plain = aead_open(&key, env[32..56].try_into().unwrap(), &aad(2), &env[56..]).unwrap();
    let mut header = plain.expose()[..346].to_vec();
    header[..4].copy_from_slice(&[0, 1, 0, 1]);
    let mut signed = b"bh/original-envelope/v1\0".to_vec();
    signed.extend(&header);
    let mut v1 = header;
    v1.extend(signer.sign(&signed));
    v1.resize(952, 0);
    let (nonce, cipher) = aead_seal(&key, &aad(1), &v1).unwrap();
    let mut envelope = env[..32].to_vec();
    envelope.extend(nonce);
    envelope.extend(cipher);
    OpaqueEvent::new(event.id(), envelope).unwrap()
}

#[test]
fn note_payload_names_its_writer_and_authenticated_author() {
    let f = Fixture::new();
    let update = Note::new().unwrap().append_paragraph("declared").unwrap();
    let event = f.note(f.valid_receipt(), &note_payload([7; 32], WRITER, &update));
    let mut history = f.history.clone();
    let ordered =
        Commitment::order(f.base, history.head(), &event.descriptor, Route::Content).unwrap();
    let prepared = history
        .prepare(
            &ordered,
            &event.descriptor,
            Some(&event.body),
            &f.metadata,
            Some(&f.content),
        )
        .unwrap();
    let mut note = Note::new().unwrap();
    let applied = history
        .consume(
            prepared,
            Some(NoteTarget {
                id: [7; 32],
                note: &mut note,
            }),
        )
        .unwrap();
    // The declaration is the author's claim; the author is what verified.
    assert_eq!(applied.writer(), Some(WRITER));
    assert_eq!(applied.author(), Some((f.account.id().0, f.device.0)));
    assert!(matches!(
        applied.kind(),
        AppliedKind::NoteAccepted { note_id, delta } if *note_id == [7; 32] && delta.expose() == update.as_slice()
    ));
    let mut expected = Note::new().unwrap();
    expected.apply_update(&update).unwrap();
    assert_eq!(note.state().unwrap(), expected.state().unwrap());
}

#[test]
fn a_recomposed_note_payload_is_byte_identical_to_the_opened_one() {
    let f = Fixture::new();
    let update = Note::new().unwrap().append_paragraph("canonical").unwrap();
    let data = note_payload([7; 32], WRITER, &update);
    let event = f.note(f.valid_receipt(), &data);
    let mut history = f.history.clone();
    let ordered =
        Commitment::order(f.base, history.head(), &event.descriptor, Route::Content).unwrap();
    let prepared = history
        .prepare(
            &ordered,
            &event.descriptor,
            Some(&event.body),
            &f.metadata,
            Some(&f.content),
        )
        .unwrap();
    let mut note = Note::new().unwrap();
    let applied = history
        .consume(
            prepared,
            Some(NoteTarget {
                id: [7; 32],
                note: &mut note,
            }),
        )
        .unwrap();
    // A reader keeps a Note payload only by recomposing it from the opened
    // declaration and delta, so that must reproduce the author's exact bytes.
    let AppliedKind::NoteAccepted { note_id, delta } = applied.kind() else {
        panic!("the stored payload was not accepted as a Note update");
    };
    let writer = DeviceWriterDeclaration::decode(&data[32..131]).unwrap();
    assert_eq!(writer, WRITER);
    assert_eq!(note_payload(*note_id, writer, delta.expose()), data);
}

#[test]
fn note_payload_without_a_whole_declaration_is_rejected_and_a_newer_one_is_retained() {
    let f = Fixture::new();
    // The ID and 98 bytes cannot hold a declaration.
    let mut short = vec![7; 32];
    short.extend([0, 1, 1]);
    short.resize(32 + 98, 0);
    f.assert_rejected(&f.note(f.valid_receipt(), &short), "short declaration");
    let update = Note::new().unwrap().append_paragraph("newer").unwrap();
    // A declaration only a newer version reads names its note, so the event
    // is consumed and retained for that note instead of pausing the base.
    for (offset, value, why) in [(1, 2, "declaration version 2"), (2, 2, "author tag 2")] {
        let mut data = note_payload([7; 32], WRITER, &update);
        data[32 + offset] = value;
        let mut history = f.history.clone();
        let before = history.head();
        let mut note = Note::new().unwrap();
        let empty = note.state().unwrap();
        assert_eq!(
            f.apply(&mut history, &f.note(f.valid_receipt(), &data), &mut note),
            Outcome::Retained,
            "{why}"
        );
        assert_eq!(history.head().position, before.position + 1, "{why}");
        assert_eq!(note.state().unwrap(), empty, "{why}");
        assert!(!history.is_stopped(), "{why}");
    }
}

#[test]
fn forged_originals_are_rejected_and_the_next_valid_event_applies() {
    let f = Fixture::new();
    let data = note_data("forged");
    let seal_with = |binding: Binding, signer: &SigningKey| {
        seal(
            binding,
            Payload {
                kind: NOTE,
                data: &data,
            },
            signer,
            &f.metadata,
            Some(&f.content),
        )
        .unwrap()
    };
    let honest = f.binding(f.valid_receipt());
    let mut false_control = honest;
    false_control.seen_control = [9; 32];
    let mut false_account = honest;
    false_account.account_head.position += 1;
    let mut stranger = honest;
    stranger.device = bh_account::DeviceId([0xee; 32]);
    for (event, why) in [
        (
            seal_with(honest, &SigningKey::generate()),
            "signed by a key that is not the device's",
        ),
        (
            seal_with(false_control, &f.signing),
            "false claim about the control chain",
        ),
        (
            seal_with(false_account, &f.signing),
            "false claim about the account head",
        ),
        (
            seal_with(stranger, &f.signing),
            "a device not in the account",
        ),
    ] {
        f.assert_rejected(&event, why);
    }
}

#[test]
fn verified_receipt_contradicting_remembered_history_stops_and_retains_state() {
    let f = Fixture::new();
    let mut history = f.history.clone();
    let mut note = Note::new().unwrap();
    let first = f.note(f.valid_receipt(), &note_data("kept"));
    assert_eq!(f.apply(&mut history, &first, &mut note), Outcome::Accepted);
    let verified = history.head();
    let kept = note.state().unwrap();
    // The pinned hosting key signed another history at the verified genesis
    // position. Whoever carries that receipt, the service contradicted what
    // this device verified; a member cannot sign their way to one.
    let genesis = f.history.head();
    let forked = Head {
        position: genesis.position,
        hash: Digest([3; 32]),
    };
    let mut binding = f.binding(f.hosting.receipt(f.base, forked));
    binding.seen = forked;
    let carrier = seal(
        binding,
        Payload {
            kind: NOTE,
            data: &note_data("carrier"),
        },
        &f.signing,
        &f.metadata,
        Some(&f.content),
    )
    .unwrap();
    assert_eq!(
        f.apply(&mut history, &carrier, &mut note),
        Outcome::IntegrityStop
    );
    assert!(history.is_stopped());
    assert_eq!(history.head(), verified);
    assert_eq!(note.state().unwrap(), kept, "verified state is retained");
    // Nothing more applies from that server.
    let mut next = f.binding(f.hosting.receipt(f.base, verified));
    next.seen = verified;
    let later = seal(
        next,
        Payload {
            kind: NOTE,
            data: &note_data("later"),
        },
        &f.signing,
        &f.metadata,
        Some(&f.content),
    )
    .unwrap();
    assert_eq!(
        f.apply(&mut history, &later, &mut note),
        Outcome::IntegrityStop
    );
    assert_eq!(history.head(), verified);
    assert_eq!(note.state().unwrap(), kept);
}

#[test]
fn an_unknown_audience_pauses_as_unsupported() {
    let f = Fixture::new();
    let mut binding = f.binding(f.valid_receipt());
    binding.audience = [3; 32];
    let event = seal(
        binding,
        Payload {
            kind: NOTE,
            data: &note_data("for a private audience"),
        },
        &f.signing,
        &f.metadata,
        Some(&f.content),
    )
    .unwrap();
    let mut history = f.history.clone();
    let mut note = Note::new().unwrap();
    assert_eq!(
        f.apply(&mut history, &event, &mut note),
        Outcome::UnsupportedPause
    );
    assert_eq!(history.head(), f.history.head());
    assert!(!history.is_stopped());
    // Another account's author in this account's base is still its lie.
    let mut stranger = f.binding(f.valid_receipt());
    stranger.account = AccountId([0xee; 32]);
    let event = seal(
        stranger,
        Payload {
            kind: NOTE,
            data: &note_data("stranger"),
        },
        &f.signing,
        &f.metadata,
        Some(&f.content),
    )
    .unwrap();
    f.assert_rejected(&event, "another account's author");
}

#[test]
fn sealed_epoch_is_read_back_with_m_only() {
    let f = Fixture::new();
    let event = f.note(f.valid_receipt(), &note_data("sealed"));
    assert_eq!(
        sealed_epoch(&event.descriptor, &f.metadata, f.base),
        Ok(key_id(&f.content))
    );
    assert_eq!(
        sealed_epoch(&event.descriptor, &seed(0x77), f.base),
        Err(Error::Invalid)
    );
    assert_eq!(
        sealed_epoch(&event.descriptor, &f.metadata, BaseId([9; 32])),
        Err(Error::Invalid)
    );
}
