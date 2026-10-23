use indexed::{Indexed, KeyUse, Recent};
use std::{collections::BTreeMap, sync::Arc};

#[cfg(test)]
thread_local! {
    static OVERLAP_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SIGNATURE_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

use crate::crypto::{hash, verify};
use crate::trust::{ConfirmedTime, Effect, REMOVAL_WAIT_MS, RotationReason, Timeline};

const DOMAIN: &[u8] = b"BaseHero account event\0";
const DEVICE_DOMAIN: &[u8] = b"BaseHero device keys\0";
const COSIGN_DOMAIN: &[u8] = b"BaseHero account cosign\0";
const RECOVERY_AUTHOR_DOMAIN: &[u8] = b"BaseHero recovery author\0";
/// Device-signed setup, additions and self-removal; their bytes are unchanged.
const VERSION: u16 = 1;
/// Trust controls and anything the recovery key signs. Version-one readers
/// refuse it as unsupported before reading its tag, and pause.
const TRUST_VERSION: u16 = 2;
/// Signer roles: a version-two event's byte after its tag, and the role byte
/// in each signature of a cosigned event.
pub(crate) const ROLE_DEVICE: u8 = 1;
pub(crate) const ROLE_RECOVERY: u8 = 2;
const SIGNATURE_LEN: usize = 64;
const DEVICE_LEN: usize = 32 + 32 + 1216;
const RECOVERY_LEN: usize = 32 + 1216;
const HEADER_LEN: usize = DOMAIN.len() + 2 + 2 + 8 + 32 + 32 + 32 + 1;
pub const MAX_EVENT_LEN: usize = HEADER_LEN + DEVICE_LEN + RECOVERY_LEN + SIGNATURE_LEN;
// Genesis stays the largest event: version-two events add a signer byte.
const _: () = assert!(
    HEADER_LEN + 1 + RECOVERY_LEN + 32 + 32 + SIGNATURE_LEN <= MAX_EVENT_LEN
        && HEADER_LEN + 1 + 8 + 1216 + 32 + 32 + SIGNATURE_LEN <= MAX_EVENT_LEN
        && HEADER_LEN + 1 + 32 + 2 * SIGNATURE_LEN <= MAX_EVENT_LEN
);

/// An identity at the account home or within protected authority verification.
/// This is not an ordinary base-service routing or tracking identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountId(pub [u8; 32]);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeviceId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub position: u64,
    pub hash: [u8; 32],
}

/// Errors contain no identity, key, or input bytes and are safe to count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Malformed,
    UnsupportedVersion,
    UnsupportedControl,
    BadSignature,
    WrongAccount,
    /// Not the next position, or a genesis naming a predecessor.
    WrongPredecessor,
    /// Authenticated history contradicting this history: a signed event at
    /// the next position naming another predecessor, or a replay holding
    /// another head at the remembered position.
    Fork,
    TruncatedHistory,
    DuplicateDevice,
    KeyReuse,
    NotActive,
    Stopped,
    PositionOverflow,
    IncompleteMaterials,
    InvalidSetup,
    InvalidCredentials,
    CryptoFailure,
    /// The signer may not make this change, such as a device removing itself
    /// through a removal request, or cancelling one that targets it.
    NotPermitted,
    /// The signing device has not been in the log long enough to act at once.
    NotMature,
    /// The change this event follows has not yet taken effect.
    TooEarly,
    /// This event needs a confirmed time and none was given.
    MissingTime,
    /// A confirmed time is earlier than the previous confirmed entry's.
    TimeRegressed,
    /// Local evidence is unavailable. Retry the same view after a transient read
    /// failure; reload after an epoch reset or container closure. Never a stop.
    Unavailable,
}

#[derive(Clone, PartialEq, Eq)]
pub struct DevicePublicKeys {
    signing: [u8; 32],
    control: [u8; 32],
    receiving: [u8; 1216],
}

// Avoid putting account/device identifiers in automatic diagnostics.
impl std::fmt::Debug for DevicePublicKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DevicePublicKeys(..)")
    }
}

impl DevicePublicKeys {
    pub fn new(signing: [u8; 32], control: [u8; 32], receiving: [u8; 1216]) -> Result<Self, Error> {
        if signing == control {
            return Err(Error::KeyReuse);
        }
        Ok(Self {
            signing,
            control,
            receiving,
        })
    }
    pub fn signing(&self) -> &[u8; 32] {
        &self.signing
    }
    pub fn control(&self) -> &[u8; 32] {
        &self.control
    }
    pub fn receiving(&self) -> &[u8; 1216] {
        &self.receiving
    }
    pub fn id(&self) -> DeviceId {
        let mut bytes = DEVICE_DOMAIN.to_vec();
        self.encode(&mut bytes);
        DeviceId(hash(&bytes))
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend(self.signing);
        out.extend(self.control);
        out.extend(self.receiving);
    }
    fn decode(input: &mut Reader<'_>) -> Result<Self, Error> {
        Self::new(input.array()?, input.array()?, input.array()?)
    }
    #[cfg(test)] // regression sentinel for accidental historic-key scans
    fn overlaps(&self, other: &Self) -> bool {
        #[cfg(test)]
        OVERLAP_CHECKS.with(|checks| checks.set(checks.get() + 1));
        self.signing == other.signing
            || self.signing == other.control
            || self.control == other.signing
            || self.control == other.control
            || self.receiving == other.receiving
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryPublicKeys {
    signing: [u8; 32],
    receiving: [u8; 1216],
}
impl RecoveryPublicKeys {
    /// Public halves of independent random recovery pairs, not password-derived keys.
    pub fn new(signing: [u8; 32], receiving: [u8; 1216]) -> Self {
        Self { signing, receiving }
    }
    pub fn signing(&self) -> &[u8; 32] {
        &self.signing
    }
    pub fn receiving(&self) -> &[u8; 1216] {
        &self.receiving
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend(self.signing);
        out.extend(self.receiving);
    }
    fn decode(input: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self::new(input.array()?, input.array()?))
    }
    fn overlaps(&self, device: &DevicePublicKeys) -> bool {
        self.signing == device.signing
            || self.signing == device.control
            || self.receiving == device.receiving
    }
    /// The author id of events this recovery key signs; it differs from every
    /// device id, and a replaced recovery key's author can no longer sign.
    pub(crate) fn author(&self) -> DeviceId {
        let mut bytes = RECOVERY_AUTHOR_DOMAIN.to_vec();
        bytes.extend(self.signing);
        bytes.extend(self.receiving);
        DeviceId(hash(&bytes))
    }
}

/// Which key signs an event: its author device's, or the current recovery key.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Signer {
    Device,
    Recovery,
}

#[derive(Clone)]
pub(crate) enum Control {
    Genesis {
        first: Box<DevicePublicKeys>,
        recovery: Box<RecoveryPublicKeys>,
    },
    AddDevice(Box<DevicePublicKeys>),
    RemoveSelf,
    RecoveryRecord([u8; 32]),
    PersonalKey(Box<PersonalPublication>),
    RemoveRequest(DeviceId),
    /// Cosigned by the author's second key and the recovery key.
    RemoveNow(DeviceId),
    Cancel(u64),
    ReplaceRecovery {
        recovery: Box<RecoveryPublicKeys>,
        record_digest: [u8; 32],
        recovery_seal_digest: [u8; 32],
    },
    /// `reason` is the position of the event whose effect this rotation follows.
    RotatePersonal {
        reason: u64,
        publication: Box<PersonalPublication>,
    },
}
impl Control {
    fn tag(&self) -> u8 {
        match self {
            Self::Genesis { .. } => 0,
            Self::AddDevice(_) => 1,
            Self::RemoveSelf => 2,
            Self::RecoveryRecord(_) => 3,
            Self::PersonalKey(_) => 4,
            Self::RemoveRequest(_) => 5,
            Self::RemoveNow(_) => 6,
            Self::Cancel(_) => 7,
            Self::ReplaceRecovery { .. } => 8,
            Self::RotatePersonal { .. } => 9,
        }
    }
    fn version(&self, signer: Signer) -> u16 {
        if signer == Signer::Recovery || self.tag() >= 5 {
            TRUST_VERSION
        } else {
            VERSION
        }
    }
    fn allows(&self, signer: Signer) -> bool {
        signer == Signer::Device
            || matches!(
                self,
                Self::AddDevice(_) | Self::RemoveRequest(_) | Self::Cancel(_)
            )
    }
    fn signatures(&self) -> usize {
        if matches!(self, Self::RemoveNow(_)) {
            2
        } else {
            1
        }
    }
    fn encode_body(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::Genesis { first, recovery } => {
                first.encode(bytes);
                recovery.encode(bytes);
            }
            Self::AddDevice(keys) => keys.encode(bytes),
            Self::RemoveSelf => {}
            Self::RecoveryRecord(digest) => bytes.extend(digest),
            Self::PersonalKey(publication) => publication.encode(bytes),
            Self::RemoveRequest(target) | Self::RemoveNow(target) => bytes.extend(target.0),
            Self::Cancel(request) => bytes.extend(request.to_be_bytes()),
            Self::ReplaceRecovery {
                recovery,
                record_digest,
                recovery_seal_digest,
            } => {
                recovery.encode(bytes);
                bytes.extend(record_digest);
                bytes.extend(recovery_seal_digest);
            }
            Self::RotatePersonal {
                reason,
                publication,
            } => {
                bytes.extend(reason.to_be_bytes());
                publication.encode(bytes);
            }
        }
    }
    fn decode_body(tag: u8, input: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(match tag {
            0 => Self::Genesis {
                first: Box::new(DevicePublicKeys::decode(input)?),
                recovery: Box::new(RecoveryPublicKeys::decode(input)?),
            },
            1 => Self::AddDevice(Box::new(DevicePublicKeys::decode(input)?)),
            2 => Self::RemoveSelf,
            3 => Self::RecoveryRecord(input.array()?),
            4 => Self::PersonalKey(Box::new(PersonalPublication::decode(input)?)),
            5 => Self::RemoveRequest(DeviceId(input.array()?)),
            6 => Self::RemoveNow(DeviceId(input.array()?)),
            7 => Self::Cancel(u64::from_be_bytes(input.array()?)),
            8 => Self::ReplaceRecovery {
                recovery: Box::new(RecoveryPublicKeys::decode(input)?),
                record_digest: input.array()?,
                recovery_seal_digest: input.array()?,
            },
            9 => Self::RotatePersonal {
                reason: u64::from_be_bytes(input.array()?),
                publication: Box::new(PersonalPublication::decode(input)?),
            },
            _ => return Err(Error::UnsupportedControl),
        })
    }
}

#[derive(Clone)]
pub struct PersonalPublication {
    public: [u8; 1216],
    device_digest: [u8; 32],
    recovery_digest: [u8; 32],
}
impl PersonalPublication {
    pub fn public(&self) -> &[u8; 1216] {
        &self.public
    }
    pub fn device_digest(&self) -> &[u8; 32] {
        &self.device_digest
    }
    pub fn recovery_digest(&self) -> &[u8; 32] {
        &self.recovery_digest
    }
    pub(crate) fn new(
        public: [u8; 1216],
        device_digest: [u8; 32],
        recovery_digest: [u8; 32],
    ) -> Self {
        Self {
            public,
            device_digest,
            recovery_digest,
        }
    }
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend(self.public);
        out.extend(self.device_digest);
        out.extend(self.recovery_digest);
    }
    fn decode(input: &mut Reader<'_>) -> Result<Self, Error> {
        Ok(Self::new(input.array()?, input.array()?, input.array()?))
    }
}

/// Strictly decoded, unsigned first-device setup request for the app-gated Mac store.
/// This describes the message, not authorization to sign it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SignupKind {
    Genesis,
    RecoveryRecord,
    PersonalKey,
}

#[derive(Clone, Copy)]
pub struct SignupMessage {
    pub kind: SignupKind,
    pub account: AccountId,
    pub author: DeviceId,
    pub previous: [u8; 32],
}

/// Canonical signed account control. Decoding is not verification.
#[derive(Clone)]
pub struct AccountEvent {
    bytes: Vec<u8>,
    pub(crate) position: u64,
    previous: [u8; 32],
    account: AccountId,
    pub(crate) author: DeviceId,
    pub(crate) signer: Signer,
    pub(crate) control: Control,
}

/// Exact bytes requiring one key: the existing device's second (control) key,
/// its ordinary key for a rotation, or the recovery key, per `expected_key`.
/// Completing this request verifies the signature but does not order or apply it.
/// The caller submits through its authority/order lane, then applies verified history.
pub struct SigningRequest {
    bytes: Vec<u8>,
    expected_key: [u8; 32],
}
impl SigningRequest {
    pub(crate) fn into_unsigned(self) -> Vec<u8> {
        self.bytes
    }
    pub fn signing_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn expected_key(&self) -> &[u8; 32] {
        &self.expected_key
    }
    pub fn finish(&self, signature: [u8; 64]) -> Result<AccountEvent, Error> {
        verify(&self.expected_key, &self.bytes, &signature).map_err(|_| Error::BadSignature)?;
        let mut bytes = self.bytes.clone();
        bytes.extend(signature);
        AccountEvent::decode(&bytes)
    }
}

impl AccountEvent {
    /// Parse the exact unsigned signing bytes using the canonical event decoder.
    /// The placeholder signature is never verified or used as authority; the
    /// signing key is checked against the genesis's actual first device.
    pub fn signup_message(message: &[u8], key: &[u8; 32]) -> Option<SignupMessage> {
        if message.len() < HEADER_LEN || message.len() > MAX_EVENT_LEN - SIGNATURE_LEN {
            return None;
        }
        let mut complete = Vec::with_capacity(message.len() + SIGNATURE_LEN);
        complete.extend_from_slice(message);
        complete.extend_from_slice(&[0; SIGNATURE_LEN]);
        let event = Self::decode(&complete).ok()?;
        let kind = match &event.control {
            Control::Genesis { first, .. }
                if event.position == 1
                    && event.previous == [0; 32]
                    && event.account == AccountId([0; 32])
                    && event.author == first.id()
                    && first.control() == key =>
            {
                SignupKind::Genesis
            }
            Control::RecoveryRecord(_) if event.position == 2 => SignupKind::RecoveryRecord,
            Control::PersonalKey(_) if event.position == 3 => SignupKind::PersonalKey,
            _ => return None,
        };
        Some(SignupMessage {
            kind,
            account: event.account,
            author: event.author,
            previous: event.previous,
        })
    }
    /// Genesis is self-certified by the first device's control key. Its hash must
    /// arrive over a trusted introduction, never be replaced with a server's id.
    pub fn genesis(first: DevicePublicKeys, recovery: RecoveryPublicKeys) -> SigningRequest {
        let expected_key = first.control;
        let author = first.id();
        Self::draft(
            1,
            [0; 32],
            AccountId([0; 32]),
            author,
            Signer::Device,
            Control::Genesis {
                first: Box::new(first),
                recovery: Box::new(recovery),
            },
            expected_key,
        )
    }
    fn draft(
        position: u64,
        previous: [u8; 32],
        account: AccountId,
        author: DeviceId,
        signer: Signer,
        control: Control,
        expected_key: [u8; 32],
    ) -> SigningRequest {
        let version = control.version(signer);
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(version.to_be_bytes());
        bytes.extend(version.to_be_bytes()); // highest protocol version the event needs
        bytes.extend(position.to_be_bytes());
        bytes.extend(previous);
        bytes.extend(account.0);
        bytes.extend(author.0);
        bytes.push(control.tag());
        if version == TRUST_VERSION {
            bytes.push(match signer {
                Signer::Device => ROLE_DEVICE,
                Signer::Recovery => ROLE_RECOVERY,
            });
        }
        control.encode_body(&mut bytes);
        SigningRequest {
            bytes,
            expected_key,
        }
    }
    /// Bounded strict parser: fixed-width integers, no trailing data, and no
    /// unknown controls silently ignored. No allocation follows an input length.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_LEN + SIGNATURE_LEN || bytes.len() > MAX_EVENT_LEN {
            return Err(Error::Malformed);
        }
        let mut input = Reader(bytes);
        if input.take(DOMAIN.len())? != DOMAIN {
            return Err(Error::Malformed);
        }
        let version = u16::from_be_bytes(input.array()?);
        let supported = u16::from_be_bytes(input.array()?);
        if !matches!(version, VERSION | TRUST_VERSION) || supported < version {
            return Err(Error::UnsupportedVersion);
        }
        let position = u64::from_be_bytes(input.array()?);
        let previous = input.array()?;
        let account = AccountId(input.array()?);
        let author = DeviceId(input.array()?);
        let tag = input.array::<1>()?[0];
        let signer = if version == TRUST_VERSION {
            match input.array::<1>()?[0] {
                ROLE_DEVICE => Signer::Device,
                ROLE_RECOVERY => Signer::Recovery,
                _ => return Err(Error::Malformed),
            }
        } else {
            Signer::Device
        };
        let control = Control::decode_body(tag, &mut input)?;
        // Each tag and signer has exactly one version: no re-encoding of an
        // existing control under another version, and no new signer roles.
        if !control.allows(signer) || control.version(signer) != version {
            return Err(Error::Malformed);
        }
        input.take(SIGNATURE_LEN * control.signatures())?;
        if !input.0.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            position,
            previous,
            account,
            author,
            signer,
            control,
        })
    }
    /// The public keys carried by a device-addition original. This is decoded
    /// data, not proof that the addition has been accepted; the caller must
    /// verify its signing request or ordered history before trusting it.
    pub fn added_device_keys(&self) -> Option<&DevicePublicKeys> {
        match &self.control {
            Control::AddDevice(keys) => Some(keys),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// The predecessor named inside these exact decoded original bytes.
    /// Decoding alone does not verify the author's signature or this history.
    pub fn previous_head(&self) -> Head {
        Head {
            position: self.position.saturating_sub(1),
            hash: self.previous,
        }
    }
    pub fn head(&self) -> Head {
        Head {
            position: self.position,
            hash: hash(&self.bytes),
        }
    }
    fn verify_signature(&self, key: &[u8; 32]) -> Result<(), Error> {
        #[cfg(test)]
        SIGNATURE_CHECKS.with(|checks| checks.set(checks.get() + 1));
        if self.control.signatures() != 1 {
            return Err(Error::BadSignature);
        }
        let split = self.bytes.len() - SIGNATURE_LEN;
        let sig = self.bytes[split..]
            .try_into()
            .map_err(|_| Error::Malformed)?;
        verify(key, &self.bytes[..split], sig).map_err(|_| Error::BadSignature)
    }
    /// Both signatures cover the same unsigned event under distinct roles;
    /// neither covers the other.
    fn verify_cosigned(&self, device: &[u8; 32], recovery: &[u8; 32]) -> Result<(), Error> {
        #[cfg(test)]
        SIGNATURE_CHECKS.with(|checks| checks.set(checks.get() + 2));
        if self.control.signatures() != 2 {
            return Err(Error::BadSignature);
        }
        let split = self.bytes.len() - 2 * SIGNATURE_LEN;
        let (unsigned, signatures) = self.bytes.split_at(split);
        let (first, second) = signatures.split_at(SIGNATURE_LEN);
        for (role, key, signature) in [
            (ROLE_DEVICE, device, first),
            (ROLE_RECOVERY, recovery, second),
        ] {
            let signature = signature.try_into().map_err(|_| Error::Malformed)?;
            verify(key, &cosign_bytes(role, unsigned), signature)
                .map_err(|_| Error::BadSignature)?;
        }
        Ok(())
    }
}

pub(crate) fn cosign_bytes(role: u8, unsigned: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(COSIGN_DOMAIN.len() + 1 + unsigned.len());
    bytes.extend_from_slice(COSIGN_DOMAIN);
    bytes.push(role);
    bytes.extend_from_slice(unsigned);
    bytes
}
impl AccountId {
    /// Only local creation may adopt this value without an independent anchor.
    pub fn of_genesis(event: &AccountEvent) -> Result<Self, Error> {
        if !matches!(event.control, Control::Genesis { .. }) {
            return Err(Error::Malformed);
        }
        Ok(Self(hash(event.as_bytes())))
    }
}

/// Whether an authenticated, well-formed entry's signer still had authority
/// once the removal deadlines its confirmed time reaches were resolved. Both
/// are history at the entry's position. Never decide an entry's effects from
/// its control alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlOutcome {
    /// The signer's authority held and the control's own rules ran. That is
    /// not proof its change happened: a cancel confirmed at or after its
    /// request's deadline is applied and cancels nothing. A cancellation took
    /// effect only if `request_state` was pending before the entry and is
    /// `Cancelled` after it.
    Applied,
    /// A deadline this entry reached removed the signing device, or the
    /// device a removal names, first; the entry changed nothing. Unlike
    /// `RequestState::Lapsed`, a removal request abandoned because its
    /// requester or target left.
    Lapsed,
}

/// An active device's keys and the position of the event that added it.
#[derive(Clone)]
pub(crate) struct Member {
    pub keys: DevicePublicKeys,
    pub added: u64,
}

/// Original-signature verifier. This is verified history, not proof that an
/// untrusted server disclosed its latest head, nor a hosted access approval.
/// Store the head and accepted events atomically in protected durable state.
/// Invalid input stops further verification while preserving the previous state.
#[derive(Clone)]
pub struct VerifiedAccount {
    id: AccountId,
    head: Head,
    recent: Recent,
    indexed: Option<Indexed>,
    active: BTreeMap<DeviceId, Member>,
    recovery: RecoveryPublicKeys,
    first: DeviceId,
    record_digest: Option<[u8; 32]>,
    personal: Option<PersonalPublication>,
    pub(crate) timeline: Timeline,
    stopped: bool,
}
impl VerifiedAccount {
    pub fn from_genesis(anchor: AccountId, bytes: &[u8]) -> Result<Self, Error> {
        let event = AccountEvent::decode(bytes)?;
        if AccountId::of_genesis(&event)? != anchor {
            return Err(Error::WrongAccount);
        }
        if event.position != 1 || event.previous != [0; 32] || event.account != AccountId([0; 32]) {
            return Err(Error::WrongPredecessor);
        }
        let Control::Genesis {
            ref first,
            ref recovery,
        } = event.control
        else {
            return Err(Error::Malformed);
        };
        if event.author != first.id() {
            return Err(Error::NotActive);
        }
        if recovery.overlaps(first) {
            return Err(Error::KeyReuse);
        }
        event.verify_signature(&first.control)?;
        let devices = BTreeMap::from([(
            first.id(),
            Member {
                keys: first.as_ref().clone(),
                added: 1,
            },
        )]);
        Ok(Self {
            id: anchor,
            head: event.head(),
            recent: Recent {
                heads: BTreeMap::from([(1, event.head().hash)]),
                added: BTreeMap::from([(first.id(), (first.as_ref().clone(), 1))]),
                removed: BTreeMap::new(),
                used_signing: BTreeMap::from([
                    (first.signing, 1),
                    (first.control, 1),
                    (recovery.signing, 1),
                ]),
                used_receiving: BTreeMap::from([(first.receiving, 1), (recovery.receiving, 1)]),
                times: BTreeMap::new(),
            },
            indexed: None,
            active: devices,
            recovery: recovery.as_ref().clone(),
            first: first.id(),
            record_digest: None,
            personal: None,
            timeline: Timeline::default(),
            stopped: false,
        })
    }
    /// Reconstruct from original signed bytes, requiring the durable remembered
    /// head to occur unchanged. Never replace that checkpoint with a remote value.
    pub fn replay(anchor: AccountId, history: &[&[u8]], remembered: Head) -> Result<Self, Error> {
        let timed: Vec<_> = history.iter().map(|bytes| (*bytes, None)).collect();
        Self::replay_timed(anchor, &timed, remembered)
    }
    /// `replay` with each entry's confirmed time, if any.
    pub fn replay_timed(
        anchor: AccountId,
        history: &[(&[u8], Option<ConfirmedTime>)],
        remembered: Head,
    ) -> Result<Self, Error> {
        let (first, time) = history.first().ok_or(Error::TruncatedHistory)?;
        let mut state = Self::from_genesis(anchor, first)?;
        state.timeline.confirm(1, *time, true)?;
        if let Some(time) = time {
            state.recent.times.insert(1, *time);
        }
        for (bytes, time) in &history[1..] {
            state.apply_one(bytes, *time)?;
        }
        match state.recent.heads.get(&remembered.position) {
            None => Err(Error::TruncatedHistory),
            Some(hash) if hash != &remembered.hash => Err(Error::Fork),
            Some(_) => Ok(state),
        }
    }
    pub fn id(&self) -> AccountId {
        self.id
    }
    pub fn head(&self) -> Head {
        self.head
    }
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }
    pub fn recovery_keys(&self) -> Result<&RecoveryPublicKeys, Error> {
        self.running()?;
        Ok(&self.recovery)
    }
    /// The author id under which the current recovery key signs.
    pub fn recovery_author(&self) -> Result<DeviceId, Error> {
        Ok(self.recovery_keys()?.author())
    }
    /// The digest of the current recovery record: the initial one, or the
    /// latest replacement's.
    pub fn record_digest(&self) -> Result<[u8; 32], Error> {
        self.running()?;
        self.record_digest.ok_or(Error::IncompleteMaterials)
    }
    pub fn active_device(&self, id: DeviceId) -> Result<&DevicePublicKeys, Error> {
        self.running()?;
        self.active
            .get(&id)
            .map(|member| &member.keys)
            .ok_or(Error::NotActive)
    }
    /// Whether `device` was a member at `position`: added at or before it and
    /// not removed at or before it. A removal at a deadline counts from its
    /// request's position. A position before this view's index cut that only
    /// the index could answer is `Unavailable`; one beyond the head is
    /// `TruncatedHistory`.
    pub fn active_at(&self, device: DeviceId, position: u64) -> Result<bool, Error> {
        self.running()?;
        if position > self.head.position {
            return Err(Error::TruncatedHistory);
        }
        let cut = self.indexed.as_ref().map_or(0, |i| i.cut.position);
        let added = self
            .added_position(device)
            .or_else(|| self.recent.added.get(&device).map(|(_, added)| *added));
        match (added, self.recent.removed.get(&device).copied()) {
            (Some(added), removed) => Ok(added <= position && removed.is_none_or(|r| position < r)),
            // Added before the cut and removed after it.
            (None, Some(removed)) if position >= cut => Ok(position < removed),
            // Removed before the cut, or never a member.
            (None, None) if position >= cut => Ok(false),
            _ => Err(Error::Unavailable),
        }
    }
    pub(crate) fn added_position(&self, id: DeviceId) -> Option<u64> {
        self.active.get(&id).map(|member| member.added)
    }
    /// The confirmed time of an entry this view has verified, when known locally.
    pub(crate) fn confirmed_time(&self, position: u64) -> Result<Option<ConfirmedTime>, Error> {
        if let Some(time) = self.recent.times.get(&position) {
            return Ok(Some(*time));
        }
        match &self.indexed {
            Some(i) if position <= i.cut.position => i.index.confirmed_time(i.cut, position),
            _ => Ok(None),
        }
    }
    /// Compatibility hint, not an authoritative status API: unavailable evidence
    /// conservatively counts as seen. Use `seen_device` to distinguish failure.
    pub fn has_seen_device(&self, id: DeviceId) -> bool {
        self.seen_device(id).unwrap_or(true)
    }
    pub fn seen_device(&self, id: DeviceId) -> Result<bool, Error> {
        if self.recent.added.contains_key(&id) {
            return Ok(true);
        }
        self.indexed
            .as_ref()
            .map_or(Ok(false), |i| i.index.device_seen(i.cut, &id))
    }
    /// Compare an original signed event with this projection's verified chain.
    /// Useful for reconciling a staged event without replaying its entire prefix.
    pub(crate) fn verified_event_at(&self, position: u64, bytes: &[u8]) -> Result<bool, Error> {
        if let Some(head) = self.recent.heads.get(&position) {
            return Ok(*head == hash(bytes));
        }
        self.indexed
            .as_ref()
            .map_or(Ok(false), |i| i.index.event_matches(i.cut, position, bytes))
    }
    /// The verified head hash at `position` where this view holds it: entries
    /// applied since its index cut, and the cut itself. `None` before the cut.
    pub(crate) fn verified_head_at(&self, position: u64) -> Option<[u8; 32]> {
        if let Some(hash) = self.recent.heads.get(&position) {
            return Some(*hash);
        }
        self.indexed
            .as_ref()
            .filter(|i| i.cut.position == position)
            .map(|i| i.cut.hash)
    }
    pub fn active_devices(&self) -> Result<impl Iterator<Item = &DevicePublicKeys>, Error> {
        self.running()?;
        Ok(self.active.values().map(|member| &member.keys))
    }
    /// Complete local verification is necessary, not proof of a current home head.
    pub fn materials_ready(&self) -> Result<bool, Error> {
        self.running()?;
        Ok(self.record_digest.is_some() && self.personal.is_some())
    }
    /// The current verified publication: the initial one or the latest
    /// rotation's. Never infer it from a home-supplied object.
    pub fn personal_public(&self) -> Result<&[u8; 1216], Error> {
        Ok(self.personal_publication()?.public())
    }

    /// The current signed personal-key publication, including its committed
    /// device and recovery seal digests. Requires a complete verified history;
    /// home-supplied seal bytes must match these digests before use.
    pub fn personal_publication(&self) -> Result<&PersonalPublication, Error> {
        self.running()?;
        self.personal.as_ref().ok_or(Error::IncompleteMaterials)
    }
    pub(crate) fn initial_materials(&self) -> Result<(&[u8; 32], &PersonalPublication), Error> {
        if !self.materials_ready()? {
            return Err(Error::IncompleteMaterials);
        }
        Ok((
            self.record_digest
                .as_ref()
                .ok_or(Error::IncompleteMaterials)?,
            self.personal.as_ref().ok_or(Error::IncompleteMaterials)?,
        ))
    }
    pub(crate) fn preparing_record(&self) -> Result<(), Error> {
        self.running()?;
        if self.head.position != 1 || self.record_digest.is_some() {
            return Err(Error::InvalidSetup);
        }
        Ok(())
    }
    pub(crate) fn preparing_publication(&self) -> Result<(), Error> {
        self.running()?;
        if self.head.position != 2 || self.record_digest.is_none() || self.personal.is_some() {
            return Err(Error::InvalidSetup);
        }
        Ok(())
    }
    pub(crate) fn first_device(&self) -> Result<&DevicePublicKeys, Error> {
        self.active_device(self.first)
    }
    pub fn prepare_recovery_record(
        &self,
        author: DeviceId,
        digest: [u8; 32],
    ) -> Result<SigningRequest, Error> {
        self.preparing_record()?;
        if author != self.first {
            return Err(Error::InvalidSetup);
        }
        let signer = self.first_device()?;
        self.prepare(author, Control::RecoveryRecord(digest), signer.control)
    }
    pub fn publish_personal_key(
        &self,
        author: DeviceId,
        public: [u8; 1216],
        device_digest: [u8; 32],
        recovery_digest: [u8; 32],
    ) -> Result<SigningRequest, Error> {
        self.preparing_publication()?;
        if author != self.first
            || public == *self.recovery.receiving()
            || self.key_used(KeyUse::Receiving(&public))?
        {
            return Err(Error::InvalidSetup);
        }
        let signer = self.first_device()?;
        self.prepare(
            author,
            Control::PersonalKey(Box::new(PersonalPublication {
                public,
                device_digest,
                recovery_digest,
            })),
            signer.control,
        )
    }
    pub fn add_device(
        &self,
        author: DeviceId,
        keys: DevicePublicKeys,
    ) -> Result<SigningRequest, Error> {
        let signer = self.active_device(author)?;
        self.check_new_device(&keys)?;
        self.prepare(author, Control::AddDevice(Box::new(keys)), signer.control)
    }
    pub fn remove_self(&self, author: DeviceId) -> Result<SigningRequest, Error> {
        let signer = self.active_device(author)?;
        self.prepare(author, Control::RemoveSelf, signer.control)
    }
    pub(crate) fn prepare(
        &self,
        author: DeviceId,
        control: Control,
        expected_key: [u8; 32],
    ) -> Result<SigningRequest, Error> {
        self.prepare_as(author, Signer::Device, control, expected_key)
    }
    pub(crate) fn prepare_as(
        &self,
        author: DeviceId,
        signer: Signer,
        control: Control,
        expected_key: [u8; 32],
    ) -> Result<SigningRequest, Error> {
        let position = self
            .head
            .position
            .checked_add(1)
            .ok_or(Error::PositionOverflow)?;
        Ok(AccountEvent::draft(
            position,
            self.head.hash,
            self.id,
            author,
            signer,
            control,
            expected_key,
        ))
    }
    pub(crate) fn running(&self) -> Result<(), Error> {
        if self.stopped {
            Err(Error::Stopped)
        } else {
            Ok(())
        }
    }
    /// A replacement recovery key shares no key with any device, recovery key
    /// or personal key the account has used.
    pub(crate) fn check_new_recovery(&self, keys: &RecoveryPublicKeys) -> Result<(), Error> {
        if self.key_used(KeyUse::Signing(keys.signing()))?
            || self.key_used(KeyUse::Receiving(keys.receiving()))?
            || self
                .personal
                .as_ref()
                .is_some_and(|p| p.public == *keys.receiving())
        {
            return Err(Error::KeyReuse);
        }
        Ok(())
    }
    pub(crate) fn check_new_device(&self, keys: &DevicePublicKeys) -> Result<(), Error> {
        if self.seen_device(keys.id())? {
            return Err(Error::DuplicateDevice);
        }
        if self.key_used(KeyUse::Signing(keys.signing()))?
            || self.key_used(KeyUse::Signing(keys.control()))?
            || self.key_used(KeyUse::Receiving(keys.receiving()))?
        {
            return Err(Error::KeyReuse);
        }
        Ok(())
    }
    /// Apply one already ordered event to an owned candidate without copying its
    /// projection. For shared views use `Arc::unwrap_or_clone(view).applied(bytes)?`,
    /// which copies only when shared. It sets no stop: on error the candidate is
    /// discarded. Invalid events require the caller to record a stop; unavailable
    /// local evidence permits retry from the unchanged accepted view.
    pub fn applied(mut self, bytes: &[u8]) -> Result<VerifiedAccount, Error> {
        self.running()?;
        self.apply_one(bytes, None)?;
        Ok(self)
    }
    /// `applied_batch_timed` with each entry's outcome, in order.
    pub fn applied_batch_timed_with_outcomes(
        mut self,
        events: &[(&[u8], Option<ConfirmedTime>)],
    ) -> Result<(Self, Vec<ControlOutcome>), Error> {
        self.running()?;
        let outcomes = events
            .iter()
            .map(|(bytes, time)| self.apply_one(bytes, *time))
            .collect::<Result<_, _>>()?;
        Ok((self, outcomes))
    }
    /// Apply one already ordered event. A retry of an already-applied event is
    /// not a successor; transport deduplication must reconcile it before replay.
    pub fn apply(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.apply_batch(&[bytes])
    }
    /// Apply one ordered event with the time bounds of its ordering
    /// confirmation, which the caller has already verified. `None` is legacy
    /// history, accepted only before the account's first confirmed entry.
    pub fn apply_timed(&mut self, bytes: &[u8], time: Option<ConfirmedTime>) -> Result<(), Error> {
        self.apply_timed_with_outcome(bytes, time).map(drop)
    }
    /// `apply_timed`, reporting whether the entry took effect or lapsed.
    pub fn apply_timed_with_outcome(
        &mut self,
        bytes: &[u8],
        time: Option<ConfirmedTime>,
    ) -> Result<ControlOutcome, Error> {
        Ok(self.apply_batch_timed(&[(bytes, time)])?[0])
    }
    /// All-or-nothing in-memory verification. The storage adapter must commit
    /// this candidate together with original events/checkpoint before publishing it.
    pub fn apply_batch(&mut self, events: &[&[u8]]) -> Result<(), Error> {
        let timed: Vec<_> = events.iter().map(|bytes| (*bytes, None)).collect();
        self.apply_batch_timed(&timed).map(drop)
    }
    /// A missing confirmation or unavailable local evidence leaves the
    /// account running to retry; any other refusal stops it.
    fn apply_batch_timed(
        &mut self,
        events: &[(&[u8], Option<ConfirmedTime>)],
    ) -> Result<Vec<ControlOutcome>, Error> {
        self.running()?;
        match self.clone().applied_batch_timed_with_outcomes(events) {
            Ok((candidate, outcomes)) => {
                *self = candidate;
                Ok(outcomes)
            }
            Err(error) => {
                if !matches!(error, Error::Unavailable | Error::MissingTime) {
                    self.stopped = true;
                }
                Err(error)
            }
        }
    }
    /// Resolve every removal request due by `at_ms`.
    pub(crate) fn advance_to(&mut self, at_ms: u64) {
        for (target, request) in self.timeline.advance(at_ms) {
            self.drop_member(target, request);
        }
    }
    fn drop_member(&mut self, device: DeviceId, position: u64) {
        self.active.remove(&device);
        self.recent.removed.insert(device, position);
    }
    /// Remove a device at once; its pending requests, and those against it, lapse.
    fn remove_member(&mut self, device: DeviceId, position: u64) {
        self.drop_member(device, position);
        self.timeline
            .lapse(|p| p.by == Some(device) || p.target == device);
    }
    /// An effect established now, at the entry's confirmed `latest_ms`.
    fn effect_now(&mut self, reason: RotationReason, time: ConfirmedTime) {
        self.timeline.effects.insert(
            reason.position(),
            Effect {
                reason,
                established_ms: time.latest_ms,
            },
        );
    }
    fn use_receiving(&mut self, key: &[u8; 1216], position: u64) {
        self.recent.used_receiving.entry(*key).or_insert(position);
    }
    /// The one transition every apply and replay uses.
    fn apply_one(
        &mut self,
        bytes: &[u8],
        time: Option<ConfirmedTime>,
    ) -> Result<ControlOutcome, Error> {
        let event = AccountEvent::decode(bytes)?;
        if event.account != self.id {
            return Err(Error::WrongAccount);
        }
        if event.position
            != self
                .head
                .position
                .checked_add(1)
                .ok_or(Error::PositionOverflow)?
        {
            return Err(Error::WrongPredecessor);
        }
        // Authenticate against the predecessor's members: a signature made
        // while its author was one stays authentic whenever it is confirmed.
        self.verify_signer(&event)?;
        // Checked after the signature, so only authenticated history reports
        // a fork: a current signer signed another successor of this head.
        if event.previous != self.head.hash {
            return Err(Error::Fork);
        }
        self.check_fixed(&event)?;
        // A regressing checker confirmation is a contradiction only after
        // the original itself has authenticated; garbage must not stop sync.
        // Device-signed setup, additions and self-removal may be legacy history.
        let untimed = event.signer == Signer::Device && event.control.tag() <= 4;
        self.timeline.confirm(event.position, time, untimed)?;
        // Judge the entry against membership as of its earliest time.
        if let Some(c) = time {
            self.advance_to(c.earliest_ms);
            self.recent.times.insert(event.position, c);
        }
        // Only a deadline can end a predecessor member's authority, or remove
        // the member a removal names, here.
        let gone = |device| !self.active.contains_key(device);
        let lapsed = (event.signer == Signer::Device && gone(&event.author))
            || matches!(&event.control,
                Control::RemoveRequest(target) | Control::RemoveNow(target) if gone(target));
        let outcome = if lapsed {
            ControlOutcome::Lapsed
        } else {
            self.take_effect(&event, time)?;
            ControlOutcome::Applied
        };
        self.head = event.head();
        self.recent.heads.insert(self.head.position, self.head.hash);
        Ok(outcome)
    }
    /// Requirements that do not depend on time, judged against the
    /// predecessor, which a lapse never excuses. What the deadlines this entry
    /// reaches change is judged once they are resolved.
    fn check_fixed(&self, event: &AccountEvent) -> Result<(), Error> {
        let device = event.signer == Signer::Device;
        match &event.control {
            Control::Genesis { .. } => return Err(Error::UnsupportedControl),
            Control::AddDevice(keys) => self.check_new_device(keys)?,
            Control::RemoveSelf => {}
            Control::RecoveryRecord(_) => {
                if event.position != 2 || event.author != self.first || self.record_digest.is_some()
                {
                    return Err(Error::InvalidSetup);
                }
            }
            Control::PersonalKey(publication) => {
                if event.position != 3
                    || event.author != self.first
                    || self.record_digest.is_none()
                    || self.personal.is_some()
                    || publication.public == *self.recovery.receiving()
                    || self.key_used(KeyUse::Receiving(&publication.public))?
                {
                    return Err(Error::InvalidSetup);
                }
            }
            Control::RemoveRequest(target) | Control::RemoveNow(target) => {
                if device && event.author == *target {
                    return Err(Error::NotPermitted);
                }
                // A member before this entry; a deadline it reaches may still
                // remove the target first, and then it lapses.
                self.active_device(*target)?;
            }
            Control::Cancel(request) => {
                if *request == 0 || *request > self.head.position {
                    return Err(Error::NotPermitted);
                }
                // No device cancels its own pending removal.
                if device
                    && self
                        .timeline
                        .pending
                        .get(request)
                        .is_some_and(|p| p.target == event.author)
                {
                    return Err(Error::NotPermitted);
                }
            }
            Control::ReplaceRecovery { recovery, .. } => {
                if self.record_digest.is_none() || self.personal.is_none() {
                    return Err(Error::InvalidSetup);
                }
                self.check_new_recovery(recovery)?;
            }
            Control::RotatePersonal {
                reason,
                publication,
            } => {
                // An effect still due, or a request that may become one.
                if !self.timeline.effects.contains_key(reason)
                    && !self.timeline.pending.contains_key(reason)
                {
                    return Err(Error::NotPermitted);
                }
                let Some(current) = self.personal.as_ref().map(|p| p.public) else {
                    return Err(Error::InvalidSetup);
                };
                if publication.public == current
                    || self.key_used(KeyUse::Receiving(&publication.public))?
                {
                    return Err(Error::KeyReuse);
                }
            }
        }
        Ok(())
    }
    /// The entry's requested change, once its author still has authority.
    fn take_effect(
        &mut self,
        event: &AccountEvent,
        time: Option<ConfirmedTime>,
    ) -> Result<(), Error> {
        match &event.control {
            Control::Genesis { .. } => return Err(Error::UnsupportedControl),
            Control::AddDevice(keys) => {
                self.recent
                    .used_signing
                    .insert(*keys.signing(), event.position);
                self.recent
                    .used_signing
                    .insert(*keys.control(), event.position);
                self.recent
                    .used_receiving
                    .insert(*keys.receiving(), event.position);
                self.recent
                    .added
                    .insert(keys.id(), (keys.as_ref().clone(), event.position));
                self.active.insert(
                    keys.id(),
                    Member {
                        keys: keys.as_ref().clone(),
                        added: event.position,
                    },
                );
            }
            Control::RemoveSelf => {
                self.remove_member(event.author, event.position);
                // Legacy self-removals predate rotation and leave none due.
                if let Some(c) = time {
                    let reason = RotationReason::RemovedSelf {
                        position: event.position,
                        device: event.author,
                    };
                    self.effect_now(reason, c);
                }
            }
            Control::RecoveryRecord(digest) => self.record_digest = Some(*digest),
            Control::PersonalKey(publication) => {
                self.use_receiving(&publication.public, event.position);
                self.personal = Some(publication.as_ref().clone());
            }
            Control::RemoveRequest(target) => {
                let c = time.ok_or(Error::MissingTime)?;
                let by = (event.signer == Signer::Device).then_some(event.author);
                // One pending request per requester and target, so pending
                // requests are bounded by membership, not history. About
                // active² pairs at most is an accepted known limit.
                if self
                    .timeline
                    .pending
                    .values()
                    .any(|p| p.by == by && p.target == *target)
                {
                    return Err(Error::NotPermitted);
                }
                // The wait starts once the request is confirmed saved: a late
                // confirmation starts it later, never earlier.
                self.timeline.pending.insert(
                    event.position,
                    crate::trust::PendingRemoval {
                        request: event.position,
                        target: *target,
                        by,
                        deadline_ms: c.latest_ms.saturating_add(REMOVAL_WAIT_MS),
                    },
                );
            }
            Control::RemoveNow(target) => {
                let c = time.ok_or(Error::MissingTime)?;
                if !self.mature(event.author, c.earliest_ms)? {
                    return Err(Error::NotMature);
                }
                self.remove_member(*target, event.position);
                let reason = RotationReason::RemovedNow {
                    position: event.position,
                    target: *target,
                };
                self.effect_now(reason, c);
            }
            Control::Cancel(request) => {
                let c = time.ok_or(Error::MissingTime)?;
                // Naming anything but a pending request is a valid no-op.
                let pending = self.timeline.pending.get(request).copied();
                if event.signer == Signer::Device && !self.mature(event.author, c.earliest_ms)? {
                    return Err(Error::NotMature);
                }
                // Counts only if surely saved before the deadline; otherwise
                // a valid no-op, and the request stays on course.
                if let Some(p) = pending.filter(|p| c.latest_ms < p.deadline_ms) {
                    self.timeline.pending.remove(&p.request);
                    self.timeline
                        .resolved
                        .insert(p.request, crate::trust::RequestState::Cancelled);
                }
            }
            Control::ReplaceRecovery {
                recovery,
                record_digest,
                recovery_seal_digest,
            } => {
                self.recent
                    .used_signing
                    .insert(*recovery.signing(), event.position);
                self.recent
                    .used_receiving
                    .insert(*recovery.receiving(), event.position);
                self.recovery = recovery.as_ref().clone();
                self.record_digest = Some(*record_digest);
                if let Some(personal) = &mut self.personal {
                    // The current personal key, now sealed to the new recovery key.
                    personal.recovery_digest = *recovery_seal_digest;
                }
                // Requests the old recovery key signed lapse with it.
                self.timeline.lapse(|p| p.by.is_none());
                // The rotation seals to the latest kit only, so at most one
                // kit change is ever outstanding.
                self.timeline
                    .effects
                    .retain(|_, e| !matches!(e.reason, RotationReason::RecoveryReplaced { .. }));
                if let Some(c) = time {
                    let reason = RotationReason::RecoveryReplaced {
                        position: event.position,
                    };
                    self.effect_now(reason, c);
                }
            }
            // Fulfils the established effects up to its reason's; membership
            // is unchanged.
            Control::RotatePersonal {
                reason,
                publication,
            } => {
                self.timeline.fulfil(*reason)?;
                let Some(current) = self.personal.as_ref().map(|p| p.public) else {
                    return Err(Error::InvalidSetup);
                };
                // Indexes from before personal keys were recorded lack the current one.
                if !self.key_used(KeyUse::Receiving(&current))? {
                    self.use_receiving(&current, event.position);
                }
                self.use_receiving(&publication.public, event.position);
                self.personal = Some(publication.as_ref().clone());
            }
        }
        Ok(())
    }
    /// The author's key for this tag, or the current recovery key; a cosigned
    /// removal needs both the author's second key and the recovery key.
    fn verify_signer(&self, event: &AccountEvent) -> Result<(), Error> {
        if event.signer == Signer::Recovery {
            if event.author != self.recovery.author() {
                return Err(Error::NotActive);
            }
            return event.verify_signature(&self.recovery.signing);
        }
        let device = self.active_device(event.author)?;
        match event.control {
            Control::RemoveNow(_) => event.verify_cosigned(&device.control, &self.recovery.signing),
            Control::RotatePersonal { .. } => event.verify_signature(&device.signing),
            _ => event.verify_signature(&device.control),
        }
    }
}

pub(crate) mod indexed;

#[cfg(test)]
pub(crate) fn signature_checks() -> usize {
    SIGNATURE_CHECKS.with(|checks| checks.get())
}
#[cfg(test)]
pub(crate) fn reset_signature_checks() {
    SIGNATURE_CHECKS.with(|checks| checks.set(0));
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if self.0.len() < len {
            return Err(Error::Malformed);
        }
        let (head, tail) = self.0.split_at(len);
        self.0 = tail;
        Ok(head)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Malformed)
    }
}

#[cfg(test)]
mod cost_tests {
    use super::*;
    use crate::crypto::SigningKey;

    #[test]
    fn thousand_devices_do_not_scan_prior_keys() {
        let signer = SigningKey::generate();
        let first =
            DevicePublicKeys::new(SigningKey::generate().public(), signer.public(), [1; 1216])
                .unwrap();
        let recovery = RecoveryPublicKeys::new(SigningKey::generate().public(), [2; 1216]);
        let draft = AccountEvent::genesis(first.clone(), recovery);
        let genesis = draft.finish(signer.sign(draft.signing_bytes())).unwrap();
        let mut account = VerifiedAccount::from_genesis(
            AccountId::of_genesis(&genesis).unwrap(),
            genesis.as_bytes(),
        )
        .unwrap();
        assert!(first.overlaps(&first));
        assert_eq!(OVERLAP_CHECKS.with(|checks| checks.get()), 1);
        OVERLAP_CHECKS.with(|checks| checks.set(0));
        for i in 0..1000u32 {
            let mut receiving = [0u8; 1216];
            receiving[..4].copy_from_slice(&i.to_be_bytes());
            receiving[4] = 3;
            let keys = DevicePublicKeys::new(
                SigningKey::generate().public(),
                SigningKey::generate().public(),
                receiving,
            )
            .unwrap();
            let draft = account.add_device(first.id(), keys).unwrap();
            let event = draft.finish(signer.sign(draft.signing_bytes())).unwrap();
            account.apply(event.as_bytes()).unwrap();
        }
        let scans = OVERLAP_CHECKS.with(|checks| checks.get());
        assert_eq!(account.head().position, 1001);
        assert_eq!(scans, 0, "historic device overlap scans: {scans}");
        assert_eq!(account.recent.added.len(), 1001);
        assert_eq!(account.recent.heads.len(), 1001);
        assert!(account.summary().len() < 2700);
    }
}

#[cfg(test)]
mod active_at_tests {
    use super::*;
    use crate::crypto::{KemKey, SigningKey};
    use indexed::HistoryIndex;

    struct NoIndex;
    impl HistoryIndex for NoIndex {
        fn event_matches(&self, _: Head, _: u64, _: &[u8]) -> Result<bool, Error> {
            Ok(false)
        }
        fn device_seen(&self, _: Head, _: &DeviceId) -> Result<bool, Error> {
            Ok(false)
        }
        fn key_used(&self, _: Head, _: KeyUse<'_>) -> Result<bool, Error> {
            Ok(false)
        }
        fn confirmed_time(&self, _: Head, _: u64) -> Result<Option<ConfirmedTime>, Error> {
            Ok(None)
        }
    }

    fn device() -> (SigningKey, DevicePublicKeys) {
        let control = SigningKey::generate();
        let keys = DevicePublicKeys::new(
            SigningKey::generate().public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        (control, keys)
    }

    #[test]
    fn membership_at_a_position_is_unavailable_only_before_the_cut() {
        let (mac_key, mac) = device();
        let (fold_key, fold) = device();
        let (_, phone) = device();
        let (_, tablet) = device();
        let recovery = RecoveryPublicKeys::new(SigningKey::generate().public(), [9; 1216]);
        let draft = AccountEvent::genesis(mac.clone(), recovery);
        let genesis = draft.finish(mac_key.sign(draft.signing_bytes())).unwrap();
        let mut full = VerifiedAccount::from_genesis(
            AccountId::of_genesis(&genesis).unwrap(),
            genesis.as_bytes(),
        )
        .unwrap();
        for keys in [&fold, &phone] {
            let draft = full.add_device(mac.id(), keys.clone()).unwrap();
            full.apply(
                draft
                    .finish(mac_key.sign(draft.signing_bytes()))
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap();
        }
        // Cut at 3, then the Fold leaves at 4 and the Tablet joins at 5.
        let mut cut = full.clone().rebase(1, Arc::new(NoIndex));
        for view in [&mut full, &mut cut] {
            let draft = view.remove_self(fold.id()).unwrap();
            let left = draft.finish(fold_key.sign(draft.signing_bytes())).unwrap();
            view.apply(left.as_bytes()).unwrap();
            let draft = view.add_device(mac.id(), tablet.clone()).unwrap();
            let added = draft.finish(mac_key.sign(draft.signing_bytes())).unwrap();
            view.apply(added.as_bytes()).unwrap();
        }
        let unknown = DeviceId([7; 32]);
        for view in [&full, &cut] {
            assert_eq!(view.active_at(mac.id(), 1), Ok(true));
            assert_eq!(view.active_at(fold.id(), 3), Ok(true));
            assert_eq!(view.active_at(fold.id(), 4), Ok(false));
            assert_eq!(view.active_at(tablet.id(), 4), Ok(false));
            assert_eq!(view.active_at(tablet.id(), 5), Ok(true));
            assert_eq!(view.active_at(unknown, 4), Ok(false));
            assert_eq!(view.active_at(mac.id(), 6), Err(Error::TruncatedHistory));
        }
        assert_eq!(full.active_at(fold.id(), 2), Ok(true));
        assert_eq!(full.active_at(fold.id(), 1), Ok(false));
        assert_eq!(full.active_at(unknown, 2), Ok(false));
        // Only the index could say whether the Fold or another device was a
        // member before the cut.
        assert_eq!(cut.active_at(fold.id(), 2), Err(Error::Unavailable));
        assert_eq!(cut.active_at(unknown, 2), Err(Error::Unavailable));
        assert_eq!(cut.active_at(phone.id(), 2), Ok(false));
        assert_eq!(cut.active_at(phone.id(), 3), Ok(true));
    }
}
