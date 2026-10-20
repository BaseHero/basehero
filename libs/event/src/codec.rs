use bh_account::{AccountId, DeviceId, Head as AccountHead};
use bh_core::note::Note;
use bh_crypto::{
    KemKey, Secret, SecretBytes, SigningKey, aead_open, aead_seal, derive_key, hash, verify,
};
use bh_sync::{BODY_SIZES, EventId, Head, OpaqueEvent, receipt::RECEIPT_LEN, referenced_body};

pub const CLASS_CONTENT: u8 = 0;
pub const CLASS_CONTROL: u8 = 1;
pub const NOTE: u16 = 1;
/// A note payload starts with its 32-byte ID and the producing writer's
/// 99-byte declaration; the Yjs update follows.
pub const NOTE_PREFIX: usize = 32 + 99;

/// A note event's payload: `note || writer.encode() || update`.
pub fn note_payload(
    note: [u8; 32],
    writer: crate::writer::DeviceWriterDeclaration,
    update: &[u8],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(NOTE_PREFIX + update.len());
    data.extend(note);
    data.extend(writer.encode());
    data.extend(update);
    data
}

/// A note event by this device, for its ordinary key to sign outside this
/// library.
pub struct NoteSigningRequest(EventSigningRequest);
impl NoteSigningRequest {
    pub fn signing_bytes(&self) -> &[u8] {
        self.0.signing_bytes()
    }
    pub fn expected_key(&self) -> &[u8; 32] {
        self.0.expected_key()
    }
    pub fn finish(self, signature: [u8; 64]) -> Result<Encoded, Error> {
        self.0.finish(signature)
    }
}

/// One local note update to seal: its event id, note, producing writer and
/// Yjs update.
pub struct NoteDraft<'a> {
    pub event_id: EventId,
    pub note: [u8; 32],
    pub writer: crate::writer::DeviceWriterDeclaration,
    pub update: &'a [u8],
}

/// Prepare the note event carrying `note_payload(note, writer, update)` in
/// the content epoch of `content`. `seen` is what the
/// author's verified history of the base had applied at its head and
/// `receipt` the hosting receipt for that head, which the caller must have
/// verified: sealing cannot check it. `base_account` is the base's copy of
/// the account; the writer must be this account's `device`, active there.
#[allow(clippy::too_many_arguments)] // One note event's exact signed fields.
pub fn prepare_note(
    base: bh_sync::BaseId,
    base_account: &bh_account::VerifiedAccount,
    device: DeviceId,
    seen: crate::Seen,
    receipt: [u8; RECEIPT_LEN],
    draft: NoteDraft<'_>,
    metadata: &Secret<32>,
    content: &Secret<32>,
) -> Result<NoteSigningRequest, Error> {
    let NoteDraft {
        event_id,
        note,
        writer,
        update,
    } = draft;
    if seen.head.position == 0
        || seen.account != base_account.head()
        || writer.account != base_account.id().0
        || writer.device != device.0
    {
        return Err(Error::Invalid);
    }
    let expected = *base_account
        .active_device(device)
        .map_err(|_| Error::Invalid)?
        .signing();
    let data = note_payload(note, writer, update);
    Ok(NoteSigningRequest(prepare_seal(
        Binding {
            version: 2,
            highest: 2,
            mode: 0,
            base: base.0,
            audience: [0; 32],
            epoch: key_id(content),
            event_id,
            account: base_account.id(),
            device,
            account_head: seen.account,
            seen: seen.head,
            seen_control: seen.control,
            class: CLASS_CONTENT,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: receipt,
        },
        Payload {
            kind: NOTE,
            data: &data,
        },
        expected,
        metadata,
        Some(content),
    )?))
}
pub const GENESIS: u16 = 0x0100;
pub const ACCOUNT_CHANGE: u16 = 0x0101;
const SIGNED_DOMAIN: &[u8] = b"bh/original-envelope/v1\0";
const BODY_DOMAIN: &[u8] = b"bh/payload-object/v1\0";
const BODY_AAD: &[u8] = b"bh/payload-aad/v1\0";
const BIND_AAD: &[u8] = b"bh/author-binding-aad/v1\0";
/// Version 1 (genesis only) signs the header; version 2 appends the receipt.
const S_LEN_V1: usize = 346;
const S_LEN_V2: usize = S_LEN_V1 + RECEIPT_LEN;
const BIND_PLAIN: usize = 952;
const MAX_BODY: usize = BODY_SIZES[BODY_SIZES.len() - 1];
static ZERO_PADDING: [u8; MAX_BODY] = [0; MAX_BODY];

/// Fixed classifications contain no names, identities, keys or content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Unsupported,
    Unavailable,
}

/// Author-controlled signed fields. `seal` is a packaging primitive, not an
/// authority grant: the receiver must check every field against verified history.
/// Version 1 is the base genesis only and has no receipt (`seen_receipt` is
/// zero). Every later event is version 2 and signs `seen_receipt`, the hosting
/// receipt for `seen`; the encoder does not check it, the verifier does.
#[derive(Clone, Copy)]
pub struct Binding {
    pub version: u16,
    pub highest: u16,
    pub mode: u8,
    pub base: [u8; 32],
    pub audience: [u8; 32],
    pub epoch: [u8; 32],
    pub event_id: EventId,
    pub account: AccountId,
    pub device: DeviceId,
    pub account_head: AccountHead,
    pub seen: Head,
    pub seen_control: [u8; 32],
    pub class: u8,
    pub padded: u32,
    pub commitment: [u8; 32],
    pub seen_receipt: [u8; RECEIPT_LEN],
}
pub struct Payload<'a> {
    pub kind: u16,
    pub data: &'a [u8],
}
pub struct Encoded {
    pub descriptor: OpaqueEvent,
    pub body: Vec<u8>,
}

/// Signed externally (for example by a platform key store); sealing and signing
/// use exactly the same bytes as `seal`. Neither this request nor the codec owns
/// a device signing key.
pub struct EventSigningRequest {
    signed: Binding,
    bytes: Vec<u8>,
    expected_key: [u8; 32],
    body: Vec<u8>,
    bind_key: Secret<32>,
}
impl EventSigningRequest {
    pub fn signing_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn expected_key(&self) -> &[u8; 32] {
        &self.expected_key
    }
    pub fn finish(self, signature: [u8; 64]) -> Result<Encoded, Error> {
        verify(&self.expected_key, &self.bytes, &signature).map_err(|_| Error::Invalid)?;
        let signed_bytes = self.signed.encode_for_verify();
        let binding_plain = SecretBytes::from_parts(&[
            &signed_bytes,
            &signature,
            &ZERO_PADDING[..BIND_PLAIN - signed_bytes.len() - 64],
        ])
        .map_err(|_| Error::Invalid)?;
        let (bind_nonce, bind_cipher) = aead_seal(
            &self.bind_key,
            &binding_ad(&self.signed, &self.signed.commitment),
            binding_plain.expose(),
        )
        .map_err(|_| Error::Invalid)?;
        let mut envelope = self.signed.commitment.to_vec();
        envelope.extend(bind_nonce);
        envelope.extend(bind_cipher);
        debug_assert_eq!(envelope.len(), 1024);
        Ok(Encoded {
            descriptor: OpaqueEvent::new(self.signed.event_id, envelope)
                .map_err(|_| Error::Invalid)?,
            body: self.body,
        })
    }
}

pub fn key_id(root: &Secret<32>) -> [u8; 32] {
    hash(&KemKey::from_seed(&derive_key(root, b"bhKeyId1", 0)).public())
}
fn body_key(
    class: u8,
    metadata: &Secret<32>,
    content: Option<&Secret<32>>,
) -> Result<Secret<32>, Error> {
    match class {
        CLASS_CONTROL => Ok(derive_key(metadata, b"bhCtrl01", 0)),
        CLASS_CONTENT => Ok(derive_key(
            content.ok_or(Error::Unavailable)?,
            b"bhNote01",
            0,
        )),
        _ => Err(Error::Unsupported),
    }
}
fn body_ad(s: &Binding, size: u32) -> Vec<u8> {
    let mut out = BODY_AAD.to_vec();
    out.extend(s.version.to_be_bytes());
    out.push(s.mode);
    out.extend(s.base);
    out.extend(s.audience);
    out.extend(s.epoch);
    out.extend(s.event_id.0);
    out.extend(size.to_be_bytes());
    out
}
fn binding_ad(s: &Binding, digest: &[u8; 32]) -> Vec<u8> {
    let mut out = BIND_AAD.to_vec();
    out.extend(s.version.to_be_bytes());
    out.push(s.mode);
    out.extend(s.base);
    out.extend(s.event_id.0);
    out.extend(digest);
    out
}
fn signed_len(version: u16) -> usize {
    if version == 1 { S_LEN_V1 } else { S_LEN_V2 }
}
fn commitment(size: u32, body: &[u8]) -> [u8; 32] {
    let mut bytes = BODY_DOMAIN.to_vec();
    bytes.extend(size.to_be_bytes());
    bytes.extend(body);
    hash(&bytes)
}
impl Binding {
    pub(crate) fn encode_for_verify(self) -> Vec<u8> {
        let len = signed_len(self.version);
        let mut out = Vec::with_capacity(len);
        out.extend(self.version.to_be_bytes());
        out.extend(self.highest.to_be_bytes());
        out.push(self.mode);
        for id in [
            self.base,
            self.audience,
            self.epoch,
            self.event_id.0,
            self.account.0,
            self.device.0,
        ] {
            out.extend(id);
        }
        out.extend(self.account_head.position.to_be_bytes());
        out.extend(self.account_head.hash);
        out.extend(self.seen.position.to_be_bytes());
        out.extend(self.seen.hash.0);
        out.extend(self.seen_control);
        out.push(self.class);
        out.extend(self.padded.to_be_bytes());
        out.extend(self.commitment);
        if len == S_LEN_V2 {
            out.extend(self.seen_receipt);
        }
        assert_eq!(out.len(), len);
        out
    }
    fn decode(bytes: &[u8], version: u16) -> Result<Self, Error> {
        if bytes.len() != signed_len(version) {
            return Err(Error::Invalid);
        }
        let mut r = Reader(bytes);
        let value = Self {
            version: u16::from_be_bytes(r.take()?),
            highest: u16::from_be_bytes(r.take()?),
            mode: r.take::<1>()?[0],
            base: r.take()?,
            audience: r.take()?,
            epoch: r.take()?,
            event_id: EventId(r.take()?),
            account: AccountId(r.take()?),
            device: DeviceId(r.take()?),
            account_head: AccountHead {
                position: u64::from_be_bytes(r.take()?),
                hash: r.take()?,
            },
            seen: Head {
                position: u64::from_be_bytes(r.take()?),
                hash: bh_sync::Digest(r.take()?),
            },
            seen_control: r.take()?,
            class: r.take::<1>()?[0],
            padded: u32::from_be_bytes(r.take()?),
            commitment: r.take()?,
            seen_receipt: if version == 1 {
                [0; RECEIPT_LEN]
            } else {
                r.take()?
            },
        };
        if !r.0.is_empty() {
            return Err(Error::Invalid);
        }
        Ok(value)
    }
}
struct Reader<'a>(&'a [u8]);
impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (first, rest) = self.0.split_at_checked(N).ok_or(Error::Invalid)?;
        self.0 = rest;
        first.try_into().map_err(|_| Error::Invalid)
    }
}

/// Generates fresh nonce per layer; a resend must reuse the returned exact bytes.
/// The caller provides locally authenticated account/history fields and random roots.
pub fn seal(
    signed: Binding,
    payload: Payload<'_>,
    signer: &SigningKey,
    metadata: &Secret<32>,
    content: Option<&Secret<32>>,
) -> Result<Encoded, Error> {
    let request = prepare_seal(signed, payload, signer.public(), metadata, content)?;
    let signature = signer.sign(request.signing_bytes());
    request.finish(signature)
}

pub(crate) fn prepare_seal(
    mut signed: Binding,
    payload: Payload<'_>,
    expected_key: [u8; 32],
    metadata: &Secret<32>,
    content: Option<&Secret<32>>,
) -> Result<EventSigningRequest, Error> {
    // Genesis writes (1,1); every later event writes (2,2) with its receipt.
    let version = if signed.mode == 1 { 1 } else { 2 };
    if signed.version != version
        || signed.highest != version
        || (version == 1 && signed.seen_receipt != [0; RECEIPT_LEN])
        || signed.class > 1
        || signed.mode > 1
        || signed.event_id.0 == [0; 32]
        || signed.padded != 0
        || signed.commitment != [0; 32]
    {
        return Err(Error::Invalid);
    }
    if signed.mode == 1
        && (signed.class != CLASS_CONTROL || signed.base != [0; 32] || payload.kind != GENESIS)
    {
        return Err(Error::Invalid);
    }
    if signed.mode == 0 && signed.base == [0; 32] {
        return Err(Error::Invalid);
    }
    let size = *BODY_SIZES
        .iter()
        .find(|&&p| payload.data.len().checked_add(46).is_some_and(|n| n <= p))
        .ok_or(Error::Invalid)?;
    signed.padded = size as u32;
    // Resolve availability before copying any caller plaintext. The sole
    // encoder-owned padded copy is wiped on all exits by SecretBytes::drop.
    let key = body_key(signed.class, metadata, content)?;
    let kind = payload.kind.to_be_bytes();
    let length = (payload.data.len() as u32).to_be_bytes(); // bounded by BODY_SIZES
    let padding = size - 46 - payload.data.len();
    let plain = SecretBytes::from_parts(&[&kind, &length, payload.data, &ZERO_PADDING[..padding]])
        .map_err(|_| Error::Invalid)?;
    let (nonce, cipher) = aead_seal(&key, &body_ad(&signed, signed.padded), plain.expose())
        .map_err(|_| Error::Invalid)?;
    let mut body = nonce.to_vec();
    body.extend(cipher);
    signed.commitment = commitment(signed.padded, &body);
    let signed_bytes = signed.encode_for_verify();
    let mut to_sign = SIGNED_DOMAIN.to_vec();
    to_sign.extend(&signed_bytes);
    Ok(EventSigningRequest {
        signed,
        bytes: to_sign,
        expected_key,
        body,
        bind_key: derive_key(metadata, b"bhBind01", 0),
    })
}

/// External context is known before opening the binding. Genesis is the ONLY
/// zero-base exception. Caller checks the returned signature and history.
pub(crate) fn open_binding(
    descriptor: &OpaqueEvent,
    metadata: &Secret<32>,
    expected_base: [u8; 32],
    genesis: bool,
) -> Result<(Binding, [u8; 64]), Error> {
    let env = descriptor.envelope();
    if env.len() != 1024 {
        return Err(Error::Invalid);
    }
    let digest: [u8; 32] = env[..32].try_into().map_err(|_| Error::Invalid)?;
    let probe = Binding {
        version: 1,
        highest: 1,
        mode: u8::from(genesis),
        base: expected_base,
        audience: [0; 32],
        epoch: [0; 32],
        event_id: descriptor.id(),
        account: AccountId([0; 32]),
        device: DeviceId([0; 32]),
        account_head: AccountHead {
            position: 0,
            hash: [0; 32],
        },
        seen: Head::EMPTY,
        seen_control: [0; 32],
        class: 0,
        padded: 0,
        commitment: digest,
        seen_receipt: [0; RECEIPT_LEN],
    };
    let key = derive_key(metadata, b"bhBind01", 0);
    let nonce: &[u8; 24] = env[32..56].try_into().map_err(|_| Error::Invalid)?;
    // Recognise the next version's authenticated header, read with the v2
    // layout, as unsupported without interpreting its content. This does not
    // implement v3 algorithms or upgrade.
    let (ad_version, plaintext) = [1u16, 2, 3]
        .into_iter()
        .find_map(|version| {
            let mut candidate = probe;
            candidate.version = version;
            aead_open(&key, nonce, &binding_ad(&candidate, &digest), &env[56..])
                .ok()
                .map(|plain| (version, plain))
        })
        .ok_or(Error::Invalid)?;
    let bytes = plaintext.expose();
    let len = signed_len(ad_version);
    if bytes.len() != BIND_PLAIN || bytes[len + 64..].iter().any(|&b| b != 0) {
        return Err(Error::Invalid);
    }
    let signed = Binding::decode(&bytes[..len], ad_version)?;
    if signed.version != ad_version
        || signed.mode != probe.mode
        || signed.base != expected_base
        || signed.event_id != descriptor.id()
        || signed.commitment != digest
        || signed.class > 1
        || !BODY_SIZES.contains(&(signed.padded as usize))
    {
        return Err(Error::Invalid);
    }
    let sig = bytes[len..len + 64]
        .try_into()
        .map_err(|_| Error::Invalid)?;
    Ok((signed, sig))
}

/// The content epoch a sealed event's author bound it to, read back from its
/// own descriptor with M. Nothing else about the event is checked: this is
/// for a device naming the epoch of a package it sealed itself.
pub fn sealed_epoch(
    descriptor: &OpaqueEvent,
    metadata: &Secret<32>,
    base: bh_sync::BaseId,
) -> Result<[u8; 32], Error> {
    open_binding(descriptor, metadata, base.0, false).map(|(binding, _)| binding.epoch)
}

pub(crate) struct OpenPayload {
    plaintext: SecretBytes,
    len: usize,
    pub kind: u16,
}
impl OpenPayload {
    pub fn data(&self) -> &[u8] {
        &self.plaintext.expose()[6..6 + self.len]
    }
}
/// Whether these are exactly the bytes the descriptor names, whatever its
/// author signed about them.
pub(crate) fn body_named(descriptor: &OpaqueEvent, body: &[u8]) -> bool {
    u32::try_from(body.len()).is_ok_and(|size| {
        referenced_body(descriptor).is_ok_and(|named| named.0 == commitment(size, body))
    })
}
/// Whether these are exactly the bytes the binding committed to.
pub(crate) fn body_committed(s: &Binding, body: &[u8]) -> bool {
    body.len() == s.padded as usize && commitment(s.padded, body) == s.commitment
}

pub(crate) fn open_body(
    s: &Binding,
    body: &[u8],
    metadata: &Secret<32>,
    content: Option<&Secret<32>>,
) -> Result<OpenPayload, Error> {
    if body.len() != s.padded as usize || commitment(s.padded, body) != s.commitment {
        return Err(Error::Invalid);
    }
    let key = body_key(s.class, metadata, content)?;
    let nonce = body[..24].try_into().map_err(|_| Error::Invalid)?;
    let plaintext =
        aead_open(&key, nonce, &body_ad(s, s.padded), &body[24..]).map_err(|_| Error::Invalid)?;
    let bytes = plaintext.expose();
    if bytes.len() != body.len() - 40 {
        return Err(Error::Invalid);
    }
    let kind = u16::from_be_bytes(bytes[..2].try_into().map_err(|_| Error::Invalid)?);
    let len = u32::from_be_bytes(bytes[2..6].try_into().map_err(|_| Error::Invalid)?) as usize;
    if len > bytes.len() - 6 || bytes[6 + len..].iter().any(|&b| b != 0) {
        return Err(Error::Invalid);
    }
    Ok(OpenPayload {
        plaintext,
        kind,
        len,
    })
}

/// Replay a committed Note into a disposable instance; yrs errors may leave the
/// disposable transaction changed. Never publish it after failure.
pub(crate) fn apply_note(prior: &Note, delta: &[u8]) -> Result<Note, bh_core::note::NoteError> {
    let mut copy = Note::new()?;
    copy.apply_update(&prior.state()?)?;
    copy.apply_update(delta)?;
    Ok(copy)
}
