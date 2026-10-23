//! Personal-seed envelopes: the two initial ones, deliveries to an added
//! device, a replacement kit's seal and a rotation's seals.
use crate::crypto::{self, KemKey, Secret, SecretBytes};
use crate::history::Control;
use crate::recovery::RecoveryKeys;
use crate::trust::RotationReason;
use crate::{
    AccountEvent, DeviceId, DevicePublicKeys, Error, RecoveryPublicKeys, SigningRequest,
    VerifiedAccount,
    platform::{DeviceKeyStore, StoredDevice},
};
use std::collections::BTreeSet;

const PREFIX: &[u8; 8] = b"BHPERS01";
const SIZE: usize = 1299;
const DELIVERY_PREFIX: &[u8; 8] = b"BHPDEL01";
const DELIVERY_SIZE: usize = 8 + SIZE + 32 + 64;
const ROTATION_PREFIX: &[u8; 8] = b"BHROTB01";
const ROTATION_ENTRY: usize = 32 + SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealPurpose {
    FirstDevice,
    Recovery,
    Device,
    /// A rotated personal key, sealed to a remaining device in the body the
    /// rotation commits to.
    Rotation,
}
impl SealPurpose {
    fn tag(self) -> u8 {
        match self {
            Self::FirstDevice => 1,
            Self::Recovery => 2,
            Self::Device => 3,
            Self::Rotation => 4,
        }
    }
}

pub struct PersonalKey(KemKey);
impl PersonalKey {
    pub fn generate() -> Self {
        Self(KemKey::generate())
    }
    pub fn public(&self) -> [u8; 1216] {
        self.0.public()
    }

    /// Scoped receiver use without exporting its reconstructable seed.
    pub fn decapsulate(&self, ciphertext: &[u8; 1120]) -> Result<Secret<32>, Error> {
        crypto::decapsulate(&self.0, ciphertext).map_err(|_| Error::InvalidCredentials)
    }
    pub(crate) fn seed(&self) -> Secret<32> {
        self.0.export_seed()
    }
}

pub struct PreparedPublication {
    public: [u8; 1216],
    device_seal: Vec<u8>,
    recovery_seal: Vec<u8>,
    device_digest: [u8; 32],
    recovery_digest: [u8; 32],
}
impl PreparedPublication {
    pub fn public(&self) -> [u8; 1216] {
        self.public
    }
    pub fn device_digest(&self) -> [u8; 32] {
        self.device_digest
    }
    pub fn recovery_digest(&self) -> [u8; 32] {
        self.recovery_digest
    }
    pub fn device_seal(&self) -> &[u8] {
        &self.device_seal
    }
    pub fn recovery_seal(&self) -> &[u8] {
        &self.recovery_seal
    }
}

pub(crate) fn id(public: &[u8; 1216]) -> [u8; 32] {
    crypto::hash(&[b"BH personal key id v1\0".as_slice(), public].concat())
}
fn recipient_hash(public: &[u8; 1216]) -> [u8; 32] {
    crypto::hash(&[b"BH personal recipient v1\0".as_slice(), public].concat())
}
pub(crate) fn commitment(seal: &[u8]) -> [u8; 32] {
    crypto::hash(&[b"BH personal seal commit v1\0".as_slice(), seal].concat())
}
/// The digest an account event signs for one seal: a recovery seal named by
/// a recovery replacement or a rotation.
pub fn seal_digest(seal: &[u8]) -> [u8; 32] {
    commitment(seal)
}
pub(crate) fn body_digest(body: &[u8]) -> [u8; 32] {
    crypto::hash(&[b"BH personal rotation body v1\0".as_slice(), body].concat())
}
fn ad(
    purpose: SealPurpose,
    account: &[u8; 32],
    personal_id: &[u8; 32],
    recipient: &[u8; 32],
) -> Vec<u8> {
    [
        b"BH personal seed seal v1\0".as_slice(),
        &1u16.to_be_bytes(),
        &[purpose.tag()],
        account,
        personal_id,
        recipient,
    ]
    .concat()
}
fn seal(
    state: &VerifiedAccount,
    key: &PersonalKey,
    purpose: SealPurpose,
    recipient: &[u8; 1216],
    seed: &Secret<32>,
) -> Result<Vec<u8>, Error> {
    let key_id = id(&key.public());
    let recipient_id = recipient_hash(recipient);
    let (ct, shared) = crypto::encapsulate(recipient).map_err(|_| Error::CryptoFailure)?;
    let encryption = crypto::derive_key(&shared, b"BHPSEA01", 1);
    let (nonce, ciphertext) = crypto::aead_seal(
        &encryption,
        &ad(purpose, &state.id().0, &key_id, &recipient_id),
        seed.expose(),
    )
    .map_err(|_| Error::CryptoFailure)?;
    let mut bytes = Vec::with_capacity(SIZE);
    bytes.extend_from_slice(PREFIX);
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.push(purpose.tag());
    bytes.extend_from_slice(&state.id().0);
    bytes.extend_from_slice(&key_id);
    bytes.extend_from_slice(&recipient_id);
    bytes.extend_from_slice(&ct);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);
    debug_assert_eq!(bytes.len(), SIZE);
    Ok(bytes)
}

pub fn prepare_publication(
    state: &VerifiedAccount,
    key: &PersonalKey,
) -> Result<PreparedPublication, Error> {
    state.preparing_publication()?;
    let first = state.first_device()?;
    let recovery = state.recovery_keys()?;
    if key.public() == *first.receiving() || key.public() == *recovery.receiving() {
        return Err(Error::InvalidSetup);
    }
    let seed = key.seed();
    let device_seal = seal(
        state,
        key,
        SealPurpose::FirstDevice,
        first.receiving(),
        &seed,
    )?;
    let recovery_seal = seal(
        state,
        key,
        SealPurpose::Recovery,
        recovery.receiving(),
        &seed,
    )?;
    Ok(PreparedPublication {
        public: key.public(),
        device_digest: commitment(&device_seal),
        recovery_digest: commitment(&recovery_seal),
        device_seal,
        recovery_seal,
    })
}

// Check the complete signed envelope and intended recipient before exposing its
// encapsulation to either the native store or the reconstructed recovery receiver.
struct Checked<'a> {
    ciphertext: [u8; 1120],
    nonce: [u8; 24],
    recipient_hash: [u8; 32],
    key_id: [u8; 32],
    public: &'a [u8; 1216],
}
fn checked<'a>(
    state: &'a VerifiedAccount,
    envelope: &[u8],
    purpose: SealPurpose,
    recipient: &[u8; 1216],
) -> Result<Checked<'a>, Error> {
    let publication = state.personal_publication()?;
    header(envelope, purpose)?;
    let expected = match purpose {
        SealPurpose::FirstDevice => state.first_device()?.receiving(),
        SealPurpose::Recovery => state.recovery_keys()?.receiving(),
        SealPurpose::Device | SealPurpose::Rotation => recipient,
    };
    if recipient != expected {
        return Err(Error::InvalidCredentials);
    }
    // Device delivery is signed in its domain-separated outer frame, and a
    // rotation's seals by the body digest, not one of the committed slots.
    let signed_digest = match purpose {
        SealPurpose::FirstDevice => Some(publication.device_digest()),
        SealPurpose::Recovery => Some(publication.recovery_digest()),
        SealPurpose::Device | SealPurpose::Rotation => None,
    };
    if signed_digest.is_some_and(|digest| !crypto::constant_time_eq(&commitment(envelope), digest))
    {
        return Err(Error::InvalidCredentials);
    }
    let key_id = id(publication.public());
    let recipient_hash = recipient_hash(expected);
    if envelope[11..43] != state.id().0
        || envelope[43..75] != key_id
        || envelope[75..107] != recipient_hash
    {
        return Err(Error::InvalidCredentials);
    }
    Ok(Checked {
        ciphertext: envelope[107..1227]
            .try_into()
            .map_err(|_| Error::Malformed)?,
        nonce: envelope[1227..1251]
            .try_into()
            .map_err(|_| Error::Malformed)?,
        recipient_hash,
        key_id,
        public: publication.public(),
    })
}
fn header(envelope: &[u8], purpose: SealPurpose) -> Result<(), Error> {
    if envelope.len() != SIZE
        || &envelope[..8] != PREFIX
        || &envelope[8..10] != 1u16.to_be_bytes().as_slice()
        || envelope[10] != purpose.tag()
    {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn finish(
    state: &VerifiedAccount,
    envelope: &[u8],
    purpose: SealPurpose,
    checked: &Checked<'_>,
    shared: &Secret<32>,
) -> Result<PersonalKey, Error> {
    let encryption = crypto::derive_key(shared, b"BHPSEA01", 1);
    let plaintext: SecretBytes = crypto::aead_open(
        &encryption,
        &checked.nonce,
        &ad(
            purpose,
            &state.id().0,
            &checked.key_id,
            &checked.recipient_hash,
        ),
        &envelope[1251..],
    )
    .map_err(|_| Error::InvalidCredentials)?;
    let seed = Secret::<32>::from_slice(plaintext.expose()).map_err(|_| Error::Malformed)?;
    let restored = PersonalKey(KemKey::from_seed(&seed));
    if restored.public() != *checked.public {
        return Err(Error::InvalidCredentials);
    }
    Ok(restored)
}

/// The initial first-device seal opens only through the native receiver. This
/// does not authorize a newly paired device or prove current home authority.
pub async fn open_for_receiver(
    state: &VerifiedAccount,
    envelope: &[u8],
    device: &StoredDevice,
    store: &mut impl DeviceKeyStore,
) -> Result<PersonalKey, Error> {
    open_initial_fenced(state, envelope, device, store, || true).await
}

pub(crate) async fn open_initial_fenced(
    state: &VerifiedAccount,
    envelope: &[u8],
    device: &StoredDevice,
    store: &mut impl DeviceKeyStore,
    current: impl Fn() -> bool,
) -> Result<PersonalKey, Error> {
    if !current() {
        return Err(Error::InvalidCredentials);
    }
    let checked = checked(
        state,
        envelope,
        SealPurpose::FirstDevice,
        device.keys.receiving(),
    )?;
    if device.keys != *state.first_device()? {
        return Err(Error::InvalidCredentials);
    }
    store
        .load_matching(device)
        .await
        .map_err(|_| Error::InvalidCredentials)?;
    if !current() {
        return Err(Error::InvalidCredentials);
    }
    let shared = store
        .decapsulate(device.handle.clone(), checked.ciphertext)
        .await
        .map_err(|_| Error::InvalidCredentials)?;
    if !current() {
        return Err(Error::InvalidCredentials);
    }
    finish(state, envelope, SealPurpose::FirstDevice, &checked, &shared)
}

/// Recovery uses the independently reconstructed recovery receiver; only an
/// authorized home release may supply these private bytes to a real caller.
/// Accepts the current recovery seal: the initial one, a replacement kit's,
/// or the latest rotation's.
pub fn open_for_recovery(
    state: &VerifiedAccount,
    envelope: &[u8],
    receiver: &KemKey,
) -> Result<PersonalKey, Error> {
    let checked = checked(state, envelope, SealPurpose::Recovery, &receiver.public())?;
    let shared = crypto::decapsulate(receiver, &checked.ciphertext)
        .map_err(|_| Error::InvalidCredentials)?;
    finish(state, envelope, SealPurpose::Recovery, &checked, &shared)
}

/// Sign an account-private delivery of the CURRENT ordinary personal key to a
/// device named by the exact signed *pending* add. The native ordinary signer is
/// not a control approval; the home serves the object only after it orders that
/// add. A caller must fence late asynchronous results.
pub async fn seal_for_device(
    state: &VerifiedAccount,
    key: &PersonalKey,
    sender: &StoredDevice,
    recipient: &DevicePublicKeys,
    admission: &AccountEvent,
    store: &mut impl DeviceKeyStore,
) -> Result<Vec<u8>, Error> {
    if *state.personal_publication()?.public() != key.public() {
        return Err(Error::InvalidCredentials);
    }
    if state.active_device(sender.keys.id())? != &sender.keys {
        return Err(Error::InvalidCredentials);
    }
    // Stage before home ordering, but only for keys committed by the exact
    // authenticated pending add. It must be a successor of this verified view.
    exact_admission(
        &state.add_device(sender.keys.id(), recipient.clone())?,
        admission,
    )?;
    store
        .load_matching(sender)
        .await
        .map_err(|_| Error::InvalidCredentials)?;
    let seed = key.seed();
    let envelope = seal(
        state,
        key,
        SealPurpose::Device,
        recipient.receiving(),
        &seed,
    )?;
    let mut frame = Vec::with_capacity(DELIVERY_SIZE);
    frame.extend_from_slice(DELIVERY_PREFIX);
    frame.extend_from_slice(&envelope);
    frame.extend_from_slice(&sender.keys.id().0);
    let signature = store
        .sign_content(sender.handle.clone(), frame.clone())
        .await
        .map_err(|_| Error::InvalidCredentials)?;
    crypto::verify(sender.keys.signing(), &frame, &signature)
        .map_err(|_| Error::InvalidCredentials)?;
    frame.extend_from_slice(&signature);
    Ok(frame)
}

// `admission` is exactly `draft`, signed by its expected key.
fn exact_admission(draft: &SigningRequest, admission: &AccountEvent) -> Result<(), Error> {
    let raw = admission.as_bytes();
    if raw.len() != draft.signing_bytes().len() + 64 || !raw.starts_with(draft.signing_bytes()) {
        return Err(Error::InvalidCredentials);
    }
    let signature: [u8; 64] = raw[raw.len() - 64..]
        .try_into()
        .map_err(|_| Error::Malformed)?;
    draft.finish(signature)?;
    Ok(())
}

/// Seal the current personal key to a device the recovery key adds, signed
/// by the recovery key as the recovery author. Only for the exact signed
/// recovery addition of `recipient`, a successor of this verified view; the
/// recovering device opened the key from the recovery seal.
pub fn seal_for_device_by_recovery(
    state: &VerifiedAccount,
    key: &PersonalKey,
    recovery: &RecoveryKeys,
    recipient: &DevicePublicKeys,
    admission: &AccountEvent,
) -> Result<Vec<u8>, Error> {
    if *state.personal_publication()?.public() != key.public() {
        return Err(Error::InvalidCredentials);
    }
    let current = state.recovery_keys()?;
    let public = recovery.public();
    if current.signing() != public.signing() || current.receiving() != public.receiving() {
        return Err(Error::InvalidCredentials);
    }
    exact_admission(&state.add_device_by_recovery(recipient.clone())?, admission)?;
    let envelope = seal(
        state,
        key,
        SealPurpose::Device,
        recipient.receiving(),
        &key.seed(),
    )?;
    let mut frame = Vec::with_capacity(DELIVERY_SIZE);
    frame.extend_from_slice(DELIVERY_PREFIX);
    frame.extend_from_slice(&envelope);
    frame.extend_from_slice(&state.recovery_author()?.0);
    let signature = recovery.sign(&frame);
    frame.extend_from_slice(&signature);
    Ok(frame)
}

/// Seal the current personal key to a replacement recovery key, for the
/// ReplaceRecovery event that names its digest.
pub fn seal_for_new_recovery(
    state: &VerifiedAccount,
    key: &PersonalKey,
    recovery: &RecoveryPublicKeys,
) -> Result<Vec<u8>, Error> {
    if *state.personal_publication()?.public() != key.public() {
        return Err(Error::InvalidCredentials);
    }
    state.check_new_recovery(recovery)?;
    seal(
        state,
        key,
        SealPurpose::Recovery,
        recovery.receiving(),
        &key.seed(),
    )
}

// The signed frame's checks, shared by public verification and opening: exact
// framing, a signature by a device active in this history or by its current
// recovery key, then the envelope's
// account, current publication, purpose and recipient. No secret key is used.
fn checked_delivery<'a>(
    state: &'a VerifiedAccount,
    frame: &[u8],
    recipient: &DevicePublicKeys,
) -> Result<(DeviceId, Checked<'a>), Error> {
    if frame.len() != DELIVERY_SIZE || &frame[..8] != DELIVERY_PREFIX {
        return Err(Error::Malformed);
    }
    if state.active_device(recipient.id())? != recipient {
        return Err(Error::InvalidCredentials);
    }
    let sender = DeviceId(
        frame[8 + SIZE..8 + SIZE + 32]
            .try_into()
            .map_err(|_| Error::Malformed)?,
    );
    let signer = if sender == state.recovery_author()? {
        state.recovery_keys()?.signing()
    } else {
        state.active_device(sender)?.signing()
    };
    let signature: [u8; 64] = frame[DELIVERY_SIZE - 64..]
        .try_into()
        .map_err(|_| Error::Malformed)?;
    crypto::verify(signer, &frame[..DELIVERY_SIZE - 64], &signature)
        .map_err(|_| Error::BadSignature)?;
    let checked = checked(
        state,
        &frame[8..8 + SIZE],
        SealPurpose::Device,
        recipient.receiving(),
    )?;
    Ok((sender, checked))
}

/// Check a signed device-delivery frame without opening it: exact framing, a
/// signature by a device active in `state` or by its current recovery key
/// (returned as the recovery author), this account, its current personal
/// publication, the Device purpose, and `recipient` as an active device whose
/// receiving key the frame names. Returns the signing device. This is what a
/// verifier holding no secret key can establish; it does not prove the sealed
/// seed is the personal key, which only opening checks.
pub fn verify_device_delivery(
    state: &VerifiedAccount,
    frame: &[u8],
    recipient: &DevicePublicKeys,
) -> Result<DeviceId, Error> {
    checked_delivery(state, frame, recipient).map(|(sender, _)| sender)
}

/// Verify the complete signed device-delivery frame against this history before
/// asking the native key store to open its X-Wing encapsulation. Not a recovery
/// or first-device bootstrap opener; never fall back to their slots.
pub async fn open_for_device(
    state: &VerifiedAccount,
    frame: &[u8],
    device: &StoredDevice,
    store: &mut impl DeviceKeyStore,
) -> Result<PersonalKey, Error> {
    let (_, checked) = checked_delivery(state, frame, &device.keys)?;
    let envelope = &frame[8..8 + SIZE];
    store
        .load_matching(device)
        .await
        .map_err(|_| Error::InvalidCredentials)?;
    let shared = store
        .decapsulate(device.handle.clone(), checked.ciphertext)
        .await
        .map_err(|_| Error::InvalidCredentials)?;
    finish(state, envelope, SealPurpose::Device, &checked, &shared)
}

/// A new personal key sealed to every device active in the view it was
/// prepared from and to the current recovery key. `body` holds the device
/// seals; the rotation event signs both digests.
pub struct PreparedRotation {
    pub public: [u8; 1216],
    pub body: Vec<u8>,
    pub recovery_seal: Vec<u8>,
    pub device_seals_digest: [u8; 32],
    pub recovery_seal_digest: [u8; 32],
}

/// `after` is the account advanced to the time the rotation is made.
pub fn prepare_rotation(
    after: &VerifiedAccount,
    new: &PersonalKey,
) -> Result<PreparedRotation, Error> {
    let recovery = after.recovery_keys()?;
    if new.public() == *after.personal_publication()?.public()
        || new.public() == *recovery.receiving()
    {
        return Err(Error::KeyReuse);
    }
    let seed = new.seed();
    let devices: Vec<_> = after.active_devices()?.collect();
    let count = u16::try_from(devices.len()).map_err(|_| Error::Malformed)?;
    let mut body = Vec::with_capacity(10 + devices.len() * ROTATION_ENTRY);
    body.extend_from_slice(ROTATION_PREFIX);
    body.extend_from_slice(&count.to_be_bytes());
    // Active devices iterate in id order, the order the body requires.
    for keys in devices {
        body.extend_from_slice(&keys.id().0);
        body.extend(seal(
            after,
            new,
            SealPurpose::Rotation,
            keys.receiving(),
            &seed,
        )?);
    }
    let recovery_seal = seal(
        after,
        new,
        SealPurpose::Recovery,
        recovery.receiving(),
        &seed,
    )?;
    Ok(PreparedRotation {
        public: new.public(),
        device_seals_digest: body_digest(&body),
        recovery_seal_digest: commitment(&recovery_seal),
        body,
        recovery_seal,
    })
}

// Exact framing: a count, then that many (device id, seal) in strictly
// increasing id order.
fn rotation_entries(body: &[u8]) -> Result<Vec<(DeviceId, &[u8])>, Error> {
    if body.len() < 10 || &body[..8] != ROTATION_PREFIX {
        return Err(Error::Malformed);
    }
    let count = usize::from(u16::from_be_bytes([body[8], body[9]]));
    let rest = &body[10..];
    if rest.len() != count * ROTATION_ENTRY {
        return Err(Error::Malformed);
    }
    let mut entries: Vec<(DeviceId, &[u8])> = Vec::with_capacity(count);
    for entry in rest.as_chunks::<ROTATION_ENTRY>().0 {
        let device = DeviceId(entry[..32].try_into().map_err(|_| Error::Malformed)?);
        if entries.last().is_some_and(|(last, _)| *last >= device) {
            return Err(Error::Malformed);
        }
        entries.push((device, &entry[32..]));
    }
    Ok(entries)
}

/// Check a rotation's device seals against `after`, the account advanced to
/// the rotation's time and not yet holding it: the body is the one `rotation`
/// commits to; every device active in `after` is a recipient; no target of
/// an effect this rotation fulfils is; any other recipient is the target of
/// an effect still due after it (a deadline that passed after the body was
/// made), which the next rotation replaces. A refusal here leaves the effect
/// due; it is not a reason to stop the account.
pub fn verify_rotation_body(
    after: &VerifiedAccount,
    rotation: &AccountEvent,
    body: &[u8],
) -> Result<(), Error> {
    let Control::RotatePersonal {
        reason,
        publication,
    } = &rotation.control
    else {
        return Err(Error::Malformed);
    };
    after.running()?;
    let mut remaining = after.timeline.clone();
    remaining.fulfil(*reason)?;
    let target = |reason: RotationReason| match reason {
        RotationReason::Removal { target, .. } | RotationReason::RemovedNow { target, .. } => {
            Some(target)
        }
        RotationReason::RemovedSelf { device, .. } => Some(device),
        RotationReason::RecoveryReplaced { .. } => None,
    };
    let still_due: BTreeSet<DeviceId> = remaining
        .effects
        .values()
        .filter_map(|e| target(e.reason))
        .collect();
    if !crypto::constant_time_eq(&body_digest(body), publication.device_digest()) {
        return Err(Error::InvalidCredentials);
    }
    let key_id = id(publication.public());
    let entries = rotation_entries(body)?;
    for (device, envelope) in &entries {
        header(envelope, SealPurpose::Rotation)?;
        if envelope[11..43] != after.id().0 || envelope[43..75] != key_id {
            return Err(Error::InvalidCredentials);
        }
        match after.active_device(*device) {
            Ok(keys) if envelope[75..107] == recipient_hash(keys.receiving()) => {}
            Ok(_) => return Err(Error::InvalidCredentials),
            // A fulfilled effect's target is never in `still_due`.
            Err(_) if still_due.contains(device) => {}
            Err(_) => return Err(Error::InvalidCredentials),
        }
    }
    let sealed: BTreeSet<DeviceId> = entries.iter().map(|(device, _)| *device).collect();
    if after
        .active_devices()?
        .any(|keys| !sealed.contains(&keys.id()))
    {
        return Err(Error::InvalidCredentials);
    }
    Ok(())
}

/// Open this device's seal from the body the account's current rotation
/// commits to; `after` holds that rotation. A device not active in `after`
/// is refused.
pub async fn open_rotation_for_device(
    after: &VerifiedAccount,
    body: &[u8],
    device: &StoredDevice,
    store: &mut impl DeviceKeyStore,
) -> Result<PersonalKey, Error> {
    let publication = after.personal_publication()?;
    if !crypto::constant_time_eq(&body_digest(body), publication.device_digest()) {
        return Err(Error::InvalidCredentials);
    }
    if after.active_device(device.keys.id())? != &device.keys {
        return Err(Error::InvalidCredentials);
    }
    let envelope = rotation_entries(body)?
        .into_iter()
        .find(|(id, _)| *id == device.keys.id())
        .map(|(_, envelope)| envelope)
        .ok_or(Error::InvalidCredentials)?;
    let checked = checked(
        after,
        envelope,
        SealPurpose::Rotation,
        device.keys.receiving(),
    )?;
    store
        .load_matching(device)
        .await
        .map_err(|_| Error::InvalidCredentials)?;
    let shared = store
        .decapsulate(device.handle.clone(), checked.ciphertext)
        .await
        .map_err(|_| Error::InvalidCredentials)?;
    finish(after, envelope, SealPurpose::Rotation, &checked, &shared)
}

/// A rotation's recovery seal is the account's current recovery seal once
/// `state` holds the rotation, so this is `open_for_recovery`.
pub fn open_rotation_for_recovery(
    state: &VerifiedAccount,
    recovery_seal: &[u8],
    receiver: &KemKey,
) -> Result<PersonalKey, Error> {
    open_for_recovery(state, recovery_seal, receiver)
}
