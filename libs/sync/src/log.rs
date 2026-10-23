use std::fmt;

/// Fixed framing version; it never negotiates an inner signature's version.
pub const VERSION: u16 = 1;
/// Padded event envelope sizes. Envelopes are stored inline with ordering, so
/// they stay at most 64 KiB.
pub const ENVELOPE_SIZES: [usize; 4] = [1024, 4096, 16384, 65536];
/// Padded detached body sizes. Bodies are stored as separate objects.
pub const BODY_SIZES: [usize; 7] = [1024, 4096, 16384, 65536, 262144, 1048576, 4194304];

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Digest(pub [u8; 32]);
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BaseId(pub [u8; 32]);
/// The binding's random nonce or a route-derived public publication identity.
/// Never use an account, device, audience or session identifier here.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct EventId(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Head {
    pub position: u64,
    pub hash: Digest,
}
impl Head {
    pub const EMPTY: Self = Self {
        position: 0,
        hash: Digest([0; 32]),
    };
}

/// Fixed errors are safe to classify; adapters must not attach request text.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    Version,
    Encoding,
    Size,
    GenesisMismatch,
    HistoryMismatch,
    BodyMismatch,
    Exhausted,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}

/// Already-encrypted, already-padded envelope. Construction validates framing,
/// not encryption or signatures. No identity-bearing header is stored outside it.
#[derive(Clone, PartialEq, Eq)]
pub struct OpaqueEvent {
    nonce: EventId,
    envelope: Vec<u8>,
}
impl fmt::Debug for OpaqueEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueEvent")
            .field("bytes", &self.envelope.len())
            .finish_non_exhaustive()
    }
}
impl OpaqueEvent {
    pub fn new(nonce: EventId, envelope: Vec<u8>) -> Result<Self, Error> {
        if !ENVELOPE_SIZES.contains(&envelope.len()) {
            return Err(Error::Size);
        }
        Ok(Self { nonce, envelope })
    }
    pub fn nonce(&self) -> EventId {
        self.nonce
    }
    pub fn publication_id(&self, route: Route) -> EventId {
        crate::canonical::publication_id(route, self.digest())
    }
    pub fn envelope(&self) -> &[u8] {
        &self.envelope
    }
    pub fn digest(&self) -> Digest {
        hash(b"bh/event/v1\0", &[&self.encode()])
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(38 + self.envelope.len());
        out.extend(VERSION.to_be_bytes());
        out.extend(self.nonce.0);
        out.extend((self.envelope.len() as u32).to_be_bytes());
        out.extend(&self.envelope);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut input = Input(bytes);
        input.version()?;
        let nonce = EventId(input.array()?);
        let len = u32::from_be_bytes(input.array()?) as usize;
        if !ENVELOPE_SIZES.contains(&len) {
            return Err(Error::Size);
        }
        if input.0.len() != len {
            return Err(Error::Encoding);
        }
        Self::new(nonce, input.0.to_vec())
    }
}
impl BaseId {
    pub fn from_genesis(event: &OpaqueEvent) -> Self {
        Self(event.digest().0)
    }
}

/// Opaque padded ciphertext body (a detached payload-object). Construction checks
/// the padded size only; the commitment is computed here from the exact bytes and
/// is never accepted from a caller.
#[derive(Clone, PartialEq, Eq)]
pub struct BodyObject {
    bytes: Vec<u8>,
}
impl fmt::Debug for BodyObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyObject")
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
impl BodyObject {
    pub fn new(bytes: Vec<u8>) -> Result<Self, Error> {
        if !BODY_SIZES.contains(&bytes.len()) {
            return Err(Error::Size);
        }
        Ok(Self { bytes })
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// `H("bh/payload-object/v1\0" || P:u32 || B)`, the same commitment the
    /// encrypted-envelope codec writes as the first 32 descriptor bytes.
    pub fn commitment(&self) -> Digest {
        let size = (self.bytes.len() as u32).to_be_bytes();
        hash(b"bh/payload-object/v1\0", &[&size, &self.bytes])
    }
}

/// The detached body commitment an event's descriptor references: exactly its
/// first 32 envelope bytes. This reads no other byte and exposes no audience or
/// author field. The codec writes the body commitment here; an event that is not
/// such a descriptor still has its first 32 bytes treated as the reference.
pub fn referenced_body(event: &OpaqueEvent) -> Result<Digest, Error> {
    let first: [u8; 32] = event
        .envelope()
        .get(..32)
        .ok_or(Error::Size)?
        .try_into()
        .map_err(|_| Error::Size)?;
    Ok(Digest(first))
}

/// Which permit the sequencer ordered an event under: a membership or key
/// change, or content. It is committed in the chain, so a device can refuse an
/// event whose sealed class differs. A genesis is always a control.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[repr(u8)]
pub enum Route {
    Content = 0,
    Control = 1,
}

/// Common body-free record. It exposes no content kind, epoch, author or audience
/// beyond its route. An untrusted sequencer can construct this: callers MUST also
/// verify the original encrypted author binding and controls before applying a body.
/// The sole production commitment: the canonical opening is encoded inline.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Commitment(crate::canonical::CanonicalCommitment);
impl Commitment {
    pub const LEN: usize = crate::canonical::CanonicalCommitment::LEN;
    pub fn order(
        base: BaseId,
        before: crate::canonical::OrderState,
        event: &OpaqueEvent,
        route: Route,
    ) -> Result<Self, Error> {
        Ok(Self(crate::canonical::CanonicalCommitment::order(
            base,
            before,
            event.digest(),
            route,
        )?))
    }
    pub fn base(&self) -> BaseId {
        self.0.base()
    }
    pub fn head(&self) -> Head {
        self.0.head()
    }
    pub fn previous(&self) -> Head {
        self.0.previous()
    }
    pub fn before(&self) -> crate::canonical::OrderState {
        self.0.before()
    }
    pub fn after(&self) -> crate::canonical::OrderState {
        self.0.after()
    }
    pub fn event_id(&self) -> EventId {
        self.0.event_id()
    }
    pub fn event_digest(&self) -> Digest {
        self.0.event_digest()
    }
    pub fn route(&self) -> Route {
        self.0.route()
    }
    pub fn verify_next(&self, base: BaseId, previous: Head) -> Result<Head, Error> {
        self.0.verify_next(base, previous)
    }
    pub(crate) fn verify_integrity(&self) -> Result<(), Error> {
        self.verify_next(self.base(), self.previous()).map(|_| ())
    }
    pub fn verify_body(&self, event: &OpaqueEvent) -> Result<(), Error> {
        self.0.verify_body(event)
    }
    pub fn encode(&self) -> Vec<u8> {
        self.0.encode().to_vec()
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(crate::canonical::CanonicalCommitment::decode(bytes)?))
    }
}

pub(crate) fn hash(domain: &[u8], fields: &[&[u8]]) -> Digest {
    let mut bytes = domain.to_vec();
    for field in fields {
        bytes.extend_from_slice(field);
    }
    Digest(bh_crypto::hash(&bytes))
}
pub(crate) struct Input<'a>(pub &'a [u8]);
impl Input<'_> {
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let (prefix, rest) = self.0.split_at_checked(N).ok_or(Error::Encoding)?;
        self.0 = rest;
        prefix.try_into().map_err(|_| Error::Encoding)
    }
    pub fn version(&mut self) -> Result<(), Error> {
        if u16::from_be_bytes(self.array()?) != VERSION {
            return Err(Error::Version);
        }
        Ok(())
    }
}
