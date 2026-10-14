//! Two authenticated initial personal-seed envelopes, not later QR/rotation delivery.
use crate::crypto::{self, KemKey, Secret, SecretBytes};
use crate::{
    Error, VerifiedAccount,
    platform::{DeviceKeyStore, StoredDevice},
};

const PREFIX: &[u8; 8] = b"BHPERS01";
const SIZE: usize = 1299;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealPurpose {
    FirstDevice,
    Recovery,
}
impl SealPurpose {
    fn tag(self) -> u8 {
        match self {
            Self::FirstDevice => 1,
            Self::Recovery => 2,
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

fn id(public: &[u8; 1216]) -> [u8; 32] {
    crypto::hash(&[b"BH personal key id v1\0".as_slice(), public].concat())
}
fn recipient_hash(public: &[u8; 1216]) -> [u8; 32] {
    crypto::hash(&[b"BH personal recipient v1\0".as_slice(), public].concat())
}
fn commitment(seal: &[u8]) -> [u8; 32] {
    crypto::hash(&[b"BH personal seal commit v1\0".as_slice(), seal].concat())
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
    let seed = key.0.export_seed();
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
    let (_, publication) = state.initial_materials()?;
    if envelope.len() != SIZE
        || &envelope[..8] != PREFIX
        || &envelope[8..10] != 1u16.to_be_bytes().as_slice()
        || envelope[10] != purpose.tag()
    {
        return Err(Error::Malformed);
    }
    let expected = match purpose {
        SealPurpose::FirstDevice => state.first_device()?.receiving(),
        SealPurpose::Recovery => state.recovery_keys()?.receiving(),
    };
    if recipient != expected {
        return Err(Error::InvalidCredentials);
    }
    let signed_digest = match purpose {
        SealPurpose::FirstDevice => publication.device_digest(),
        SealPurpose::Recovery => publication.recovery_digest(),
    };
    if !crypto::constant_time_eq(&commitment(envelope), signed_digest) {
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
    let shared = store
        .decapsulate(device.handle.clone(), checked.ciphertext)
        .await
        .map_err(|_| Error::InvalidCredentials)?;
    finish(state, envelope, SealPurpose::FirstDevice, &checked, &shared)
}

/// Recovery uses the independently reconstructed recovery receiver; only an
/// authorized home release may supply these private bytes to a real caller.
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
