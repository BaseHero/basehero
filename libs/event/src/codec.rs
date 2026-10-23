use bh_account::{AccountId, DeviceId, Head as AccountHead};
use bh_core::note::Note;
use bh_crypto::{
    AeadSealNonce, Secret, SecretBytes, SigningKey, aead_open, aead_seal, derive_key, hash, verify,
};
use bh_sync::{BODY_SIZES, EventId, Head, OpaqueEvent, receipt::RECEIPT_LEN, referenced_body};

pub const CLASS_CONTENT: u8 = 0;
pub const CLASS_CONTROL: u8 = 1;
/// The Note-core content kind. A future Note-core change must use a new NOTE
/// writer-declaration version, never another outer content kind: a reader
/// retains an unknown content kind without applying it, so changed Note
/// semantics sent under a new kind would never reach the readers that already
/// exist.
pub const NOTE: u16 = 1;
/// Typed data owned by the shared record layer. The event layer keeps its
/// bytes opaque.
///
/// A future typed-data change must use a new inner payload version or
/// operation kind inside this outer kind, never another outer content kind,
/// for the same reason as the Note core: a reader retains an unknown content
/// kind without applying it, so its changes would never reach the readers
/// that already exist.
pub const TYPED_DATA: u16 = 0x0002;
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

/// A content event by this device, for its ordinary key to sign outside this
/// library. Notes and typed data are sealed the same way; only their content
/// kind and payload differ.
pub struct ContentSigningRequest(EventSigningRequest);
impl ContentSigningRequest {
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

/// One local typed payload to seal: its event id and the exact bytes this
/// layer carries without parsing.
pub struct TypedDraft<'a> {
    pub event_id: EventId,
    pub payload: &'a [u8],
}

/// Prepare a content event carrying `kind` and `data` in the content epoch of
/// `content`, bound to the same seen head, account copy and receipt as a note
/// event. `seen` is what the author's verified history of the base had
/// applied at its head and `receipt` the hosting receipt for that head, which
/// the caller must have verified: sealing cannot check it. `base_account` is
/// the base's copy of the account; `device` must be this account's and active
/// there.
#[allow(clippy::too_many_arguments)] // One content event's exact signed fields.
fn content_request(
    base: bh_sync::BaseId,
    base_account: &bh_account::VerifiedAccount,
    device: DeviceId,
    seen: crate::Seen,
    receipt: [u8; RECEIPT_LEN],
    event_id: EventId,
    kind: u16,
    data: &[u8],
    metadata: &Secret<32>,
    content: &Secret<32>,
) -> Result<ContentSigningRequest, Error> {
    if seen.head.position == 0 || seen.account != base_account.head() {
        return Err(Error::Invalid);
    }
    let expected = *base_account
        .active_device(device)
        .map_err(|_| Error::Invalid)?
        .signing();
    Ok(ContentSigningRequest(prepare_seal(
        Binding {
            version: 3,
            highest: 3,
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
        Payload { kind, data },
        expected,
        metadata,
        Some(content),
    )?))
}

/// Prepare the note event carrying `note_payload(note, writer, update)`. The
/// writer must be this account's `device`, active in the base's copy.
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
) -> Result<ContentSigningRequest, Error> {
    let NoteDraft {
        event_id,
        note,
        writer,
        update,
    } = draft;
    if writer.account != base_account.id().0 || writer.device != device.0 {
        return Err(Error::Invalid);
    }
    let data = note_payload(note, writer, update);
    content_request(
        base,
        base_account,
        device,
        seen,
        receipt,
        event_id,
        NOTE,
        &data,
        metadata,
        content,
    )
}

/// Prepare the typed-data event carrying `draft.payload` exactly as given.
/// This layer neither parses nor signs any meaning into those bytes.
#[allow(clippy::too_many_arguments)] // One content event's exact signed fields.
pub fn prepare_typed(
    base: bh_sync::BaseId,
    base_account: &bh_account::VerifiedAccount,
    device: DeviceId,
    seen: crate::Seen,
    receipt: [u8; RECEIPT_LEN],
    draft: TypedDraft<'_>,
    metadata: &Secret<32>,
    content: &Secret<32>,
) -> Result<ContentSigningRequest, Error> {
    let TypedDraft { event_id, payload } = draft;
    content_request(
        base,
        base_account,
        device,
        seen,
        receipt,
        event_id,
        TYPED_DATA,
        payload,
        metadata,
        content,
    )
}
pub const GENESIS: u16 = 0x0100;
pub const ACCOUNT_CHANGE: u16 = 0x0101;
/// A base's new content key after a personal-key rotation: the only control
/// signed with an ordinary key, under binding mode [`MODE_ORDINARY`].
pub const ACCOUNT_REKEY: u16 = 0x0102;
/// A run of confirmed account events copied into a base.
pub const ACCOUNT_CHANGE_V2: u16 = 0x0103;
/// Binding mode of a control its author signs with the ordinary key; valid
/// only with [`ACCOUNT_REKEY`]. Mode 0 is every other event after genesis
/// and mode 1 the genesis.
pub(crate) const MODE_ORDINARY: u8 = 2;
pub(crate) const SIGNED_DOMAIN: &[u8] = b"bh/original-envelope/v1\0";
const BODY_DOMAIN: &[u8] = b"bh/payload-object/v1\0";
const BODY_AAD: &[u8] = b"bh/payload-aad/v1\0";
const BIND_AAD: &[u8] = b"bh/author-binding-aad/v1\0";
/// Version 1 (genesis only) signs the header; version 2 appends the receipt;
/// version 3 appends the binding-encryption nonce for both genesis and later events.
const S_LEN_V1: usize = 346;
const S_LEN_V2: usize = S_LEN_V1 + RECEIPT_LEN;
const S_LEN_V3: usize = S_LEN_V2 + 24;
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
/// zero). Legacy later events use version 2 and sign `seen_receipt`, the hosting
/// receipt for `seen`; the encoder does not check it, the verifier does.
/// Version 3 additionally signs a nonce generated by preparation, for genesis
/// or later events. Production helpers continue emitting legacy versions.
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
    bind_nonce: AeadSealNonce,
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
        let signed_bytes = &self.bytes[SIGNED_DOMAIN.len()..];
        let binding_plain = SecretBytes::from_parts(&[
            signed_bytes,
            &signature,
            &ZERO_PADDING[..BIND_PLAIN - signed_bytes.len() - 64],
        ])
        .map_err(|_| Error::Invalid)?;
        let bind_nonce = *self.bind_nonce.bytes();
        let bind_cipher = self
            .bind_nonce
            .seal(
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
    bh_crypto::committed_key_id(root)
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
    match version {
        1 => S_LEN_V1,
        2 => S_LEN_V2,
        _ => S_LEN_V3,
    }
}
fn commitment(size: u32, body: &[u8]) -> [u8; 32] {
    let mut bytes = BODY_DOMAIN.to_vec();
    bytes.extend(size.to_be_bytes());
    bytes.extend(body);
    hash(&bytes)
}
impl Binding {
    pub(crate) fn encode_for_verify(self, binding_nonce: Option<&[u8; 24]>) -> Vec<u8> {
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
        if self.version >= 2 {
            out.extend(self.seen_receipt);
        }
        if self.version >= 3 {
            out.extend(binding_nonce.expect("version 3 binding has a prepared or opened nonce"));
        }
        assert_eq!(out.len(), len);
        out
    }
    fn decode(bytes: &[u8], version: u16) -> Result<Self, Error> {
        if bytes.len() != if version == 1 { S_LEN_V1 } else { S_LEN_V2 } {
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
    // Legacy genesis writes (1,1), later events (2,2). Version 3 supports both.
    let legacy_version = if signed.mode == 1 { 1 } else { 2 };
    if ![legacy_version, 3].contains(&signed.version)
        || signed.highest != signed.version
        || (signed.mode == 1 && signed.seen_receipt != [0; RECEIPT_LEN])
        || signed.class > 1
        || signed.mode > MODE_ORDINARY
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
    // Only a control has an ordinary-key mode. Which kinds may use it is
    // the verifier's rule.
    if signed.mode == MODE_ORDINARY && signed.class != CLASS_CONTROL {
        return Err(Error::Invalid);
    }
    if signed.mode != 1 && signed.base == [0; 32] {
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
    let bind_nonce = AeadSealNonce::new();
    let signed_bytes = signed.encode_for_verify(Some(bind_nonce.bytes()));
    let mut to_sign = SIGNED_DOMAIN.to_vec();
    to_sign.extend(&signed_bytes);
    Ok(EventSigningRequest {
        signed,
        bytes: to_sign,
        expected_key,
        body,
        bind_key: derive_key(metadata, b"bhBind01", 0),
        bind_nonce,
    })
}

pub(crate) struct OpenedBinding {
    pub binding: Binding,
    pub signature: [u8; 64],
    pub binding_nonce: Option<[u8; 24]>,
}

/// External context is known before opening the binding. Genesis is the ONLY
/// zero-base exception. Caller checks the returned signature and history.
pub(crate) fn open_binding(
    descriptor: &OpaqueEvent,
    metadata: &Secret<32>,
    expected_base: [u8; 32],
    genesis: bool,
) -> Result<OpenedBinding, Error> {
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
        event_id: descriptor.nonce(),
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
    // After genesis an event is in the ordinary mode or, for a rekey, the
    // ordinary-key mode; the authenticated data names which.
    let modes: &[u8] = if genesis { &[1] } else { &[0, MODE_ORDINARY] };
    // Recognise the next version's authenticated header with the v3 layout.
    // Only a verified signature by an established author can cause a pause;
    // recognizing its AD alone does not grant authority or implement v4.
    let (ad_version, mode, plaintext) = modes
        .iter()
        .flat_map(|&mode| [1u16, 2, 3, 4].map(|version| (mode, version)))
        .find_map(|(mode, version)| {
            let mut candidate = probe;
            candidate.version = version;
            candidate.mode = mode;
            aead_open(&key, nonce, &binding_ad(&candidate, &digest), &env[56..])
                .ok()
                .map(|plain| (version, mode, plain))
        })
        .ok_or(Error::Invalid)?;
    let bytes = plaintext.expose();
    let len = signed_len(ad_version);
    if bytes.len() != BIND_PLAIN || bytes[len + 64..].iter().any(|&b| b != 0) {
        return Err(Error::Invalid);
    }
    let binding_nonce = if ad_version >= 3 {
        let signed_nonce: [u8; 24] = bytes[S_LEN_V2..len]
            .try_into()
            .map_err(|_| Error::Invalid)?;
        if signed_nonce != *nonce {
            return Err(Error::Invalid);
        }
        Some(signed_nonce)
    } else {
        None
    };
    let fields_len = if ad_version == 1 { S_LEN_V1 } else { S_LEN_V2 };
    let signed = Binding::decode(&bytes[..fields_len], ad_version)?;
    if signed.version != ad_version
        || signed.mode != mode
        || signed.base != expected_base
        || signed.event_id != descriptor.nonce()
        || signed.commitment != digest
        || signed.class > 1
        || !BODY_SIZES.contains(&(signed.padded as usize))
    {
        return Err(Error::Invalid);
    }
    let sig = bytes[len..len + 64]
        .try_into()
        .map_err(|_| Error::Invalid)?;
    Ok(OpenedBinding {
        binding: signed,
        signature: sig,
        binding_nonce,
    })
}

/// The content epoch a sealed event's author bound it to, read back from its
/// own descriptor with M. Nothing else about the event is checked: this is
/// for a device naming the epoch of a package it sealed itself.
pub fn sealed_epoch(
    descriptor: &OpaqueEvent,
    metadata: &Secret<32>,
    base: bh_sync::BaseId,
) -> Result<[u8; 32], Error> {
    open_binding(descriptor, metadata, base.0, false).map(|opened| opened.binding.epoch)
}

/// The base head a sealed event's author claims to have seen, read back
/// from its own descriptor with M. As `sealed_epoch`, nothing else about the
/// event is checked: this is for a device reading a control it signed.
pub fn sealed_seen(
    descriptor: &OpaqueEvent,
    metadata: &Secret<32>,
    base: bh_sync::BaseId,
) -> Result<Head, Error> {
    open_binding(descriptor, metadata, base.0, false).map(|opened| opened.binding.seen)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_v3_signs_the_exact_nonce_used_by_finish_in_every_mode() {
        let metadata = Secret::random();
        let signer = SigningKey::generate();
        for mode in [0, 1, MODE_ORDINARY] {
            let binding = Binding {
                version: 3,
                highest: 3,
                mode,
                base: if mode == 1 { [0; 32] } else { [1; 32] },
                audience: [0; 32],
                epoch: key_id(&metadata),
                event_id: EventId([2; 32]),
                account: AccountId([3; 32]),
                device: DeviceId([4; 32]),
                account_head: AccountHead {
                    position: 1,
                    hash: [5; 32],
                },
                seen: Head::EMPTY,
                seen_control: [0; 32],
                class: CLASS_CONTROL,
                padded: 0,
                commitment: [0; 32],
                seen_receipt: [0; RECEIPT_LEN],
            };
            let request = prepare_seal(
                binding,
                Payload {
                    kind: if mode == 1 { GENESIS } else { ACCOUNT_REKEY },
                    data: b"payload",
                },
                signer.public(),
                &metadata,
                None,
            )
            .unwrap();
            assert_eq!(request.expected_key(), &signer.public());
            assert_eq!(
                request.signing_bytes().len(),
                SIGNED_DOMAIN.len() + S_LEN_V2 + 24
            );
            let signed_nonce = request.signing_bytes()[SIGNED_DOMAIN.len() + S_LEN_V2..].to_vec();
            let signature = signer.sign(request.signing_bytes());
            let encoded = request.finish(signature).unwrap();
            assert_eq!(&encoded.descriptor.envelope()[32..56], signed_nonce);
            assert!(open_binding(&encoded.descriptor, &metadata, binding.base, mode == 1).is_ok());
        }
    }
}
