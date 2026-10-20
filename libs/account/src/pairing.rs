//! Portable QR proof and volatile showing session. Nothing here orders an add or
//! authorizes a scanner from a relay status. The only durable admission is signed
//! account history; the device journal stages exact signed bytes before send.
use std::sync::Mutex;

use crate::crypto::{self, Secret};
use crate::journal::{AccountJournal, JournalError, JournaledDevice, PendingSetupProtector};
use crate::owner::{AccountCapability, AccountOwner, OwnerError};
use crate::platform::{ControlKeyPolicy, DeviceKeyStore, KeyStoreError};
use crate::{AccountId, DeviceId, DevicePublicKeys, Error, Head, SigningRequest, VerifiedAccount};

const DOMAIN: &[u8; 8] = b"BHPAIR01";
const PROOF_DOMAIN: &[u8] = b"BaseHero QR proof v1\0";
const REPLY_DOMAIN: &[u8; 8] = b"BHPRPL01";
const SHOW_DOMAIN: &[u8] = b"BaseHero pairing show message v1\0";
const JOIN_DOMAIN: &[u8] = b"BaseHero pairing join message v1\0";
/// Subkeys of the QR secret under the pairing context: 1 authenticates the
/// scanner's reply, 2 and 4 seal the showing and the scanning device's relay
/// messages, 3 is the relay name.
const SHOW_KEY: u64 = 2;
const RELAY_NAME: u64 = 3;
const JOIN_KEY: u64 = 4;
const VERSION: u16 = 1;
const QR_LEN: usize = 122;
const PROOF_LEN: usize = 40;
const MAX_LABEL: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairError {
    Malformed,
    UnsupportedVersion,
    History,
    Unavailable,
    InvalidReply,
    CompetingReply,
    Ended,
    NoReply,
    WrongContext,
    ChangedRequest,
    StageFailed,
    AlreadyAdded,
    Journal(JournalError),
    Device(KeyStoreError),
    Owner(OwnerError),
}
impl From<OwnerError> for PairError {
    fn from(value: OwnerError) -> Self {
        Self::Owner(value)
    }
}

/// The secret is wiped on drop; never log, persist, or relay this QR payload.
pub struct QrCode {
    pub account: AccountId,
    pub showing: DeviceId,
    pub session: [u8; 16],
    secret: Secret<32>,
}
impl QrCode {
    pub fn encode(&self) -> [u8; QR_LEN] {
        let mut out = [0; QR_LEN];
        out[..8].copy_from_slice(DOMAIN);
        out[8..10].copy_from_slice(&VERSION.to_be_bytes());
        out[10..42].copy_from_slice(&self.account.0);
        out[42..74].copy_from_slice(&self.showing.0);
        out[74..90].copy_from_slice(&self.session);
        out[90..].copy_from_slice(self.secret.expose());
        out
    }
    pub fn decode(raw: &[u8]) -> Result<Self, PairError> {
        if raw.len() != QR_LEN || &raw[..8] != DOMAIN {
            return Err(PairError::Malformed);
        }
        if raw[8..10] != VERSION.to_be_bytes() {
            return Err(PairError::UnsupportedVersion);
        }
        Ok(Self {
            account: AccountId(raw[10..42].try_into().unwrap()),
            showing: DeviceId(raw[42..74].try_into().unwrap()),
            session: raw[74..90].try_into().unwrap(),
            secret: Secret::from_slice(&raw[90..]).map_err(|_| PairError::Malformed)?,
        })
    }
}

/// The relay's name for one pairing and the keys for each side's relay
/// messages, all derived from the QR secret. The relay sees only the name, a
/// keyed hash of the secret it cannot invert, and sealed messages; it never
/// sees the secret, and none of these is ever logged or persisted.
pub struct RelayKeys {
    name: [u8; 32],
    show: Secret<32>,
    join: Secret<32>,
}
impl RelayKeys {
    fn of(secret: &Secret<32>) -> Self {
        Self {
            name: *crypto::derive_key(secret, DOMAIN, RELAY_NAME).expose(),
            show: crypto::derive_key(secret, DOMAIN, SHOW_KEY),
            join: crypto::derive_key(secret, DOMAIN, JOIN_KEY),
        }
    }
    /// The relay object's name: `/v1/pair/<hex of this>`.
    pub fn name(&self) -> [u8; 32] {
        self.name
    }
    fn seal(
        &self,
        key: &Secret<32>,
        domain: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, PairError> {
        let ad = [domain, &self.name].concat();
        let (nonce, ciphertext) =
            crypto::aead_seal(key, &ad, plaintext).map_err(|_| PairError::Malformed)?;
        Ok([nonce.as_slice(), &ciphertext].concat())
    }
    fn open(
        &self,
        key: &Secret<32>,
        domain: &[u8],
        sealed: &[u8],
    ) -> Result<crate::crypto::SecretBytes, PairError> {
        if sealed.len() < 24 {
            return Err(PairError::InvalidReply);
        }
        let nonce: [u8; 24] = sealed[..24].try_into().expect("fixed nonce");
        crypto::aead_open(key, &nonce, &[domain, &self.name].concat(), &sealed[24..])
            .map_err(|_| PairError::InvalidReply)
    }
    /// Seal one message from the showing device: nonce (24) then ciphertext.
    pub fn seal_show(&self, plaintext: &[u8]) -> Result<Vec<u8>, PairError> {
        self.seal(&self.show, SHOW_DOMAIN, plaintext)
    }
    /// Open a message sealed by the showing device of this pairing. It is
    /// authenticated, not authority: admission is only verified history.
    pub fn open_show(&self, sealed: &[u8]) -> Result<crate::crypto::SecretBytes, PairError> {
        self.open(&self.show, SHOW_DOMAIN, sealed)
    }
    /// Seal one message from the scanning device, so that the relay sees
    /// neither its keys nor its label. A reply still carries its own proof.
    pub fn seal_join(&self, plaintext: &[u8]) -> Result<Vec<u8>, PairError> {
        self.seal(&self.join, JOIN_DOMAIN, plaintext)
    }
    pub fn open_join(&self, sealed: &[u8]) -> Result<crate::crypto::SecretBytes, PairError> {
        self.open(&self.join, JOIN_DOMAIN, sealed)
    }
}

impl QrCode {
    /// The relay keys of the session this code shows.
    pub fn relay(&self) -> RelayKeys {
        RelayKeys::of(&self.secret)
    }
}

/// Keep one journaled scanner identity across attempts, including a refused or
/// cancelled QR session. A missing native key is an error, never a cue to make a
/// replacement that could strand an already-admitted identity.
pub async fn scanner_identity(
    journal: &mut impl AccountJournal,
    store: &mut impl DeviceKeyStore,
    policy: ControlKeyPolicy,
) -> Result<JournaledDevice, PairError> {
    if let Some(existing) = journal.device().map_err(PairError::Journal)? {
        if scanner_status(journal)? != ScannerStatus::Pending {
            return Err(PairError::AlreadyAdded);
        }
        store
            .load_matching(&crate::platform::StoredDevice {
                handle: existing.handle.clone(),
                keys: existing.keys.clone(),
                policy: existing.policy,
                kind: existing.kind,
            })
            .await
            .map_err(PairError::Device)?;
        return Ok(existing);
    }
    if journal.has_account().map_err(PairError::Journal)? {
        return Err(PairError::WrongContext);
    }
    let device = store.create(policy).await.map_err(PairError::Device)?;
    let identity = JournaledDevice {
        handle: device.handle,
        keys: device.keys,
        policy: device.policy,
        kind: device.kind,
    };
    journal
        .commit_device(&identity)
        .map_err(PairError::Journal)?;
    Ok(identity)
}

/// Status is derived from the journal, not from an unauthenticated relay hint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScannerStatus {
    Pending,
    Added,
    ReadyForDelivery,
}
pub fn scanner_status(journal: &impl AccountJournal) -> Result<ScannerStatus, PairError> {
    let device = journal
        .device()
        .map_err(PairError::Journal)?
        .ok_or(PairError::WrongContext)?;
    if let Some(view) = journal.load_projection().map_err(PairError::Journal)? {
        if view.stopped {
            return Err(PairError::History);
        }
        if view.account.head() != view.target {
            return Err(PairError::Unavailable);
        }
        return scanner_status_verified(&view.account, &device.keys);
    }
    if !journal.has_account().map_err(PairError::Journal)? {
        return Ok(ScannerStatus::Pending);
    }
    // Memory-only journals have no native index; verify original signed bytes.
    let record = journal
        .load()
        .map_err(PairError::Journal)?
        .ok_or(PairError::Unavailable)?;
    if record.stopped {
        return Err(PairError::History);
    }
    let original: Vec<&[u8]> = record.history.iter().map(Vec::as_slice).collect();
    let state = VerifiedAccount::replay(record.anchor, &original, record.head)
        .map_err(|_| PairError::History)?;
    scanner_status_verified(&state, &device.keys)
}

/// An already-active owner can answer scanner status from its verified in-process
/// projection and its loaded device. Fresh scanner flows still verify the
/// original signed history above.
pub(crate) fn scanner_status_verified(
    state: &VerifiedAccount,
    keys: &DevicePublicKeys,
) -> Result<ScannerStatus, PairError> {
    if state.is_stopped() {
        return Err(PairError::History);
    }
    if !state.seen_device(keys.id()).map_err(account_status_error)? {
        return Ok(ScannerStatus::Pending);
    }
    state
        .active_device(keys.id())
        .map_err(account_status_error)?;
    if state.materials_ready().map_err(account_status_error)? {
        Ok(ScannerStatus::ReadyForDelivery)
    } else {
        Ok(ScannerStatus::Added)
    }
}

fn account_status_error(error: Error) -> PairError {
    match error {
        Error::Unavailable => PairError::Unavailable,
        _ => PairError::History,
    }
}

/// A fresh scanner must obtain original signed history; a home-supplied state
/// cache or self-reported account id cannot establish the QR anchor.
pub fn verify_showing(
    qr: &QrCode,
    history: &[&[u8]],
    remembered: Head,
) -> Result<DevicePublicKeys, PairError> {
    let state =
        VerifiedAccount::replay(qr.account, history, remembered).map_err(|_| PairError::History)?;
    state
        .active_device(qr.showing)
        .cloned()
        .map_err(|_| PairError::History)
}

#[derive(Clone, PartialEq, Eq)]
pub struct Reply {
    pub session: [u8; 16],
    pub keys: DevicePublicKeys,
    pub label: Vec<u8>,
    /// Random nonce (24) followed by AEAD tag (16), no plaintext.
    pub proof: [u8; PROOF_LEN],
}
fn transcript(
    account: AccountId,
    showing: DeviceId,
    session: [u8; 16],
    keys: &DevicePublicKeys,
    label: &[u8],
) -> Result<Vec<u8>, PairError> {
    if label.len() > MAX_LABEL {
        return Err(PairError::Malformed);
    }
    let mut out =
        Vec::with_capacity(PROOF_DOMAIN.len() + 2 + 32 + 32 + 16 + 1280 + 2 + label.len());
    out.extend_from_slice(PROOF_DOMAIN);
    out.extend_from_slice(&VERSION.to_be_bytes());
    out.extend_from_slice(&account.0);
    out.extend_from_slice(&showing.0);
    out.extend_from_slice(&session);
    out.extend_from_slice(keys.signing());
    out.extend_from_slice(keys.control());
    out.extend_from_slice(keys.receiving());
    out.extend_from_slice(&(label.len() as u16).to_be_bytes());
    out.extend_from_slice(label);
    Ok(out)
}
impl Reply {
    /// The relay form: domain (8), session (16), the three public keys
    /// (1280), label length (u16) and label (at most 64), then the proof (40).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 16 + 1280 + 2 + self.label.len() + PROOF_LEN);
        out.extend_from_slice(REPLY_DOMAIN);
        out.extend_from_slice(&self.session);
        out.extend_from_slice(self.keys.signing());
        out.extend_from_slice(self.keys.control());
        out.extend_from_slice(self.keys.receiving());
        out.extend_from_slice(&(self.label.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.label);
        out.extend_from_slice(&self.proof);
        out
    }
    /// Decoding is not verification; `ShowingSession::receive` checks the proof.
    pub fn decode(raw: &[u8]) -> Result<Self, PairError> {
        const FIXED: usize = 8 + 16 + 1280 + 2;
        if raw.len() < FIXED + PROOF_LEN || &raw[..8] != REPLY_DOMAIN {
            return Err(PairError::Malformed);
        }
        let label_len = u16::from_be_bytes(raw[FIXED - 2..FIXED].try_into().unwrap()) as usize;
        if label_len > MAX_LABEL || raw.len() != FIXED + label_len + PROOF_LEN {
            return Err(PairError::Malformed);
        }
        let keys = DevicePublicKeys::new(
            raw[24..56].try_into().unwrap(),
            raw[56..88].try_into().unwrap(),
            raw[88..FIXED - 2].try_into().unwrap(),
        )
        .map_err(|_| PairError::Malformed)?;
        Ok(Self {
            session: raw[8..24].try_into().unwrap(),
            keys,
            label: raw[FIXED..FIXED + label_len].to_vec(),
            proof: raw[FIXED + label_len..].try_into().unwrap(),
        })
    }
    pub fn make(qr: &QrCode, keys: DevicePublicKeys, label: &[u8]) -> Result<Self, PairError> {
        let ad = transcript(qr.account, qr.showing, qr.session, &keys, label)?;
        let key = crypto::derive_key(&qr.secret, b"BHPAIR01", 1);
        let (nonce, tag) =
            crypto::aead_seal(&key, &ad, b"").map_err(|_| PairError::InvalidReply)?;
        let mut proof = [0; PROOF_LEN];
        proof[..24].copy_from_slice(&nonce);
        proof[24..].copy_from_slice(&tag);
        Ok(Self {
            session: qr.session,
            keys,
            label: label.to_vec(),
            proof,
        })
    }
}

struct Candidate {
    reply: Reply,
    request: Option<(Vec<u8>, [u8; 32])>,
}
enum State {
    Live {
        secret: Secret<32>,
        candidate: Option<Box<Candidate>>,
    },
    Ended,
}
/// Mutex protects cancellation/approval without holding a lock across OS prompts.
/// `AccountGeneration` is not advanced by pairing cancellation.
pub struct ShowingSession {
    account: AccountId,
    showing: DeviceId,
    session: [u8; 16],
    state: Mutex<State>,
}
impl ShowingSession {
    pub fn new(account: AccountId, showing: DeviceId) -> Self {
        Self {
            account,
            showing,
            session: crypto::random(),
            state: Mutex::new(State::Live {
                secret: Secret::random(),
                candidate: None,
            }),
        }
    }
    pub fn qr(&self) -> Result<QrCode, PairError> {
        let state = self.state.lock().expect("session lock poisoned");
        let State::Live { secret, .. } = &*state else {
            return Err(PairError::Ended);
        };
        Ok(QrCode {
            account: self.account,
            showing: self.showing,
            session: self.session,
            secret: Secret::from_slice(secret.expose()).expect("secret length"),
        })
    }
    /// The relay keys while the session is live; none once it ended.
    pub fn relay(&self) -> Result<RelayKeys, PairError> {
        let state = self.state.lock().expect("session lock poisoned");
        let State::Live { secret, .. } = &*state else {
            return Err(PairError::Ended);
        };
        Ok(RelayKeys::of(secret))
    }
    pub fn receive(&self, reply: &Reply) -> Result<DevicePublicKeys, PairError> {
        let mut state = self.state.lock().expect("session lock poisoned");
        let State::Live { secret, candidate } = &mut *state else {
            return Err(PairError::Ended);
        };
        if reply.session != self.session {
            return Err(PairError::InvalidReply);
        }
        let ad = transcript(
            self.account,
            self.showing,
            self.session,
            &reply.keys,
            &reply.label,
        )?;
        let key = crypto::derive_key(secret, b"BHPAIR01", 1);
        let nonce: [u8; 24] = reply.proof[..24].try_into().expect("fixed proof");
        if crypto::aead_open(&key, &nonce, &ad, &reply.proof[24..])
            .map(|b| !b.expose().is_empty())
            .unwrap_or(true)
        {
            return Err(PairError::InvalidReply);
        }
        if let Some(first) = candidate {
            if first.reply.keys == reply.keys && first.reply.label == reply.label {
                return Ok(reply.keys.clone());
            }
            *state = State::Ended;
            return Err(PairError::CompetingReply);
        }
        *candidate = Some(Box::new(Candidate {
            reply: reply.clone(),
            request: None,
        }));
        Ok(reply.keys.clone())
    }
    pub fn cancel(&self) {
        *self.state.lock().expect("session lock poisoned") = State::Ended;
    }
    /// Construct the existing second-key request under owner authority; no prompt
    /// is held under the session mutex. The caller signs via `owner.sign_control`.
    pub fn prepare<J: AccountJournal, S: DeviceKeyStore, P: PendingSetupProtector>(
        &self,
        owner: &AccountOwner<J, S, P>,
        capability: &AccountCapability,
    ) -> Result<SigningRequest, PairError> {
        let mut state = self.state.lock().expect("session lock poisoned");
        let State::Live {
            candidate: Some(candidate),
            ..
        } = &mut *state
        else {
            return Err(PairError::NoReply);
        };
        if self.account != capability.account_id() || self.showing != capability.device_id() {
            return Err(PairError::WrongContext);
        }
        let request = match owner.prepare_add_device(capability, candidate.reply.keys.clone()) {
            Err(OwnerError::Invalid(crate::history::Error::DuplicateDevice)) => {
                return Err(PairError::AlreadyAdded);
            }
            result => result?,
        };
        candidate.request = Some((request.signing_bytes().to_vec(), *request.expected_key()));
        Ok(request)
    }
    /// Invoke the caller's synchronous durable stage only while the session is
    /// live. A cancelled or competing reply fences late OS signatures. No network
    /// send is permitted until the stage commits exact signed add and seal bytes.
    /// Persist through the journal while the session is still live. The
    /// callback is synchronous under the session lock; cancellation after this
    /// point ends the QR, not the already-staged admission.
    pub fn stage_journal<J: AccountJournal, S: DeviceKeyStore, P: PendingSetupProtector>(
        &self,
        owner: &mut AccountOwner<J, S, P>,
        capability: &AccountCapability,
        signed: &[u8],
        delivery: &[u8],
    ) -> Result<(), PairError> {
        let recipient = {
            let state = self.state.lock().expect("session lock poisoned");
            let State::Live {
                candidate: Some(candidate),
                ..
            } = &*state
            else {
                return Err(PairError::Ended);
            };
            candidate.reply.keys.clone()
        };
        self.stage(signed, delivery, |event, seal| {
            owner.stage_signed_admission(capability, &recipient, event, seal)
        })
    }

    pub fn stage<E>(
        &self,
        signed: &[u8],
        delivery: &[u8],
        persist: impl FnOnce(&[u8], &[u8]) -> Result<(), E>,
    ) -> Result<(), PairError> {
        let mut state = self.state.lock().expect("session lock poisoned");
        let State::Live {
            candidate: Some(candidate),
            ..
        } = &mut *state
        else {
            return Err(PairError::Ended);
        };
        let (request, key) = candidate.request.as_ref().ok_or(PairError::NoReply)?;
        if signed.len() != request.len() + 64 || !signed.starts_with(request) {
            return Err(PairError::ChangedRequest);
        }
        let signature: [u8; 64] = signed[request.len()..]
            .try_into()
            .map_err(|_| PairError::ChangedRequest)?;
        crypto::verify(key, request, &signature).map_err(|_| PairError::ChangedRequest)?;
        persist(signed, delivery).map_err(|_| PairError::StageFailed)?;
        *state = State::Ended;
        Ok(())
    }
}
