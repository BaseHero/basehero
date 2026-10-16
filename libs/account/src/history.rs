use indexed::{Indexed, KeyUse, Recent};
use std::{collections::BTreeMap, sync::Arc};

#[cfg(test)]
thread_local! {
    static OVERLAP_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static SIGNATURE_CHECKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

use crate::crypto::{hash, verify};

const DOMAIN: &[u8] = b"BaseHero account event\0";
const DEVICE_DOMAIN: &[u8] = b"BaseHero device keys\0";
const VERSION: u16 = 1;
const SIGNATURE_LEN: usize = 64;
const DEVICE_LEN: usize = 32 + 32 + 1216;
const RECOVERY_LEN: usize = 32 + 1216;
const HEADER_LEN: usize = DOMAIN.len() + 2 + 2 + 8 + 32 + 32 + 32 + 1;
pub const MAX_EVENT_LEN: usize = HEADER_LEN + DEVICE_LEN + RECOVERY_LEN + SIGNATURE_LEN;

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
    WrongPredecessor,
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
    fn overlaps(&self, device: &DevicePublicKeys) -> bool {
        self.signing == device.signing
            || self.signing == device.control
            || self.receiving == device.receiving
    }
}

#[derive(Clone)]
enum Control {
    Genesis {
        first: Box<DevicePublicKeys>,
        recovery: Box<RecoveryPublicKeys>,
    },
    AddDevice(Box<DevicePublicKeys>),
    RemoveSelf,
    RecoveryRecord([u8; 32]),
    PersonalKey(Box<PersonalPublication>),
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
}

/// Canonical signed account control. Decoding is not verification.
#[derive(Clone)]
pub struct AccountEvent {
    bytes: Vec<u8>,
    position: u64,
    previous: [u8; 32],
    account: AccountId,
    author: DeviceId,
    control: Control,
}

/// Exact bytes requiring the existing device's second (control) key.
/// Completing this request verifies the signature but does not order or apply it.
/// The caller submits through its authority/order lane, then applies verified history.
pub struct SigningRequest {
    bytes: Vec<u8>,
    expected_key: [u8; 32],
}
impl SigningRequest {
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
        control: Control,
        expected_key: [u8; 32],
    ) -> SigningRequest {
        let mut bytes = DOMAIN.to_vec();
        bytes.extend(VERSION.to_be_bytes());
        bytes.extend(VERSION.to_be_bytes()); // highest supported protocol version
        bytes.extend(position.to_be_bytes());
        bytes.extend(previous);
        bytes.extend(account.0);
        bytes.extend(author.0);
        match control {
            Control::Genesis { first, recovery } => {
                bytes.push(0);
                first.encode(&mut bytes);
                bytes.extend(recovery.signing);
                bytes.extend(recovery.receiving);
            }
            Control::AddDevice(keys) => {
                bytes.push(1);
                keys.encode(&mut bytes);
            }
            Control::RemoveSelf => bytes.push(2),
            Control::RecoveryRecord(digest) => {
                bytes.push(3);
                bytes.extend(digest);
            }
            Control::PersonalKey(publication) => {
                bytes.push(4);
                bytes.extend(publication.public);
                bytes.extend(publication.device_digest);
                bytes.extend(publication.recovery_digest);
            }
        }
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
        if version != VERSION || supported < version {
            return Err(Error::UnsupportedVersion);
        }
        let position = u64::from_be_bytes(input.array()?);
        let previous = input.array()?;
        let account = AccountId(input.array()?);
        let author = DeviceId(input.array()?);
        let control = match input.array::<1>()?[0] {
            0 => Control::Genesis {
                first: Box::new(DevicePublicKeys::decode(&mut input)?),
                recovery: Box::new(RecoveryPublicKeys::new(input.array()?, input.array()?)),
            },
            1 => Control::AddDevice(Box::new(DevicePublicKeys::decode(&mut input)?)),
            2 => Control::RemoveSelf,
            3 => Control::RecoveryRecord(input.array()?),
            4 => Control::PersonalKey(Box::new(PersonalPublication {
                public: input.array()?,
                device_digest: input.array()?,
                recovery_digest: input.array()?,
            })),
            _ => return Err(Error::UnsupportedControl),
        };
        let _signature = input.array::<SIGNATURE_LEN>()?;
        if !input.0.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            position,
            previous,
            account,
            author,
            control,
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
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
        let split = self.bytes.len() - SIGNATURE_LEN;
        let sig = self.bytes[split..]
            .try_into()
            .map_err(|_| Error::Malformed)?;
        verify(key, &self.bytes[..split], sig).map_err(|_| Error::BadSignature)
    }
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
    active: BTreeMap<DeviceId, DevicePublicKeys>,
    recovery: RecoveryPublicKeys,
    first: DeviceId,
    record_digest: Option<[u8; 32]>,
    personal: Option<PersonalPublication>,
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
        let devices = BTreeMap::from([(first.id(), first.as_ref().clone())]);
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
            },
            indexed: None,
            active: devices,
            recovery: recovery.as_ref().clone(),
            first: first.id(),
            record_digest: None,
            personal: None,
            stopped: false,
        })
    }
    /// Reconstruct from original signed bytes, requiring the durable remembered
    /// head to occur unchanged. Never replace that checkpoint with a remote value.
    pub fn replay(anchor: AccountId, history: &[&[u8]], remembered: Head) -> Result<Self, Error> {
        let first = history.first().ok_or(Error::TruncatedHistory)?;
        let mut state = Self::from_genesis(anchor, first)?;
        for bytes in &history[1..] {
            state.apply_one(bytes)?;
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
    pub fn active_device(&self, id: DeviceId) -> Result<&DevicePublicKeys, Error> {
        self.running()?;
        self.active.get(&id).ok_or(Error::NotActive)
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
    pub fn active_devices(&self) -> Result<impl Iterator<Item = &DevicePublicKeys>, Error> {
        self.running()?;
        Ok(self.active.values())
    }
    /// Complete local verification is necessary, not proof of a current home head.
    pub fn materials_ready(&self) -> Result<bool, Error> {
        self.running()?;
        Ok(self.record_digest.is_some() && self.personal.is_some())
    }
    /// The current verified publication (the initial one until rotation is
    /// implemented). Never infer it from a home-supplied object.
    pub fn personal_public(&self) -> Result<&[u8; 1216], Error> {
        Ok(self.personal_publication()?.public())
    }

    pub(crate) fn personal_publication(&self) -> Result<&PersonalPublication, Error> {
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
    fn prepare(
        &self,
        author: DeviceId,
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
            control,
            expected_key,
        ))
    }
    fn running(&self) -> Result<(), Error> {
        if self.stopped {
            Err(Error::Stopped)
        } else {
            Ok(())
        }
    }
    fn check_new_device(&self, keys: &DevicePublicKeys) -> Result<(), Error> {
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
        self.apply_one(bytes)?;
        Ok(self)
    }
    /// Apply one already ordered event. A retry of an already-applied event is
    /// not a successor; transport deduplication must reconcile it before replay.
    pub fn apply(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.apply_batch(&[bytes])
    }
    /// All-or-nothing in-memory verification. The storage adapter must commit
    /// this candidate together with original events/checkpoint before publishing it.
    pub fn apply_batch(&mut self, events: &[&[u8]]) -> Result<(), Error> {
        self.running()?;
        let mut candidate = self.clone();
        for bytes in events {
            if let Err(error) = candidate.apply_one(bytes) {
                if error != Error::Unavailable {
                    self.stopped = true;
                }
                return Err(error);
            }
        }
        *self = candidate;
        Ok(())
    }
    fn apply_one(&mut self, bytes: &[u8]) -> Result<(), Error> {
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
            || event.previous != self.head.hash
        {
            return Err(Error::WrongPredecessor);
        }
        let signer = self.active_device(event.author)?;
        event.verify_signature(&signer.control)?;
        match &event.control {
            Control::Genesis { .. } => return Err(Error::UnsupportedControl),
            Control::AddDevice(keys) => {
                self.check_new_device(keys)?;
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
                self.active.insert(keys.id(), keys.as_ref().clone());
            }
            Control::RemoveSelf => {
                self.active.remove(&event.author);
                self.recent.removed.insert(event.author, event.position);
            }
            Control::RecoveryRecord(digest) => {
                if event.position != 2 || event.author != self.first || self.record_digest.is_some()
                {
                    return Err(Error::InvalidSetup);
                }
                self.record_digest = Some(*digest);
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
                self.personal = Some(publication.as_ref().clone());
            }
        }
        self.head = event.head();
        self.recent.heads.insert(self.head.position, self.head.hash);
        Ok(())
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
