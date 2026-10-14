//! Portable QR proof and volatile showing session. Nothing here orders an add or
//! authorizes a scanner from a relay status. The only durable admission is signed
//! account history; a future storage adapter stages exact signed bytes before send.
use std::sync::Mutex;

use crate::crypto::{self, Secret};
use crate::journal::{AccountJournal, PendingSetupProtector};
use crate::owner::{AccountCapability, AccountOwner, OwnerError};
use crate::platform::DeviceKeyStore;
use crate::{AccountId, DeviceId, DevicePublicKeys, Head, SigningRequest, VerifiedAccount};

const DOMAIN: &[u8; 8] = b"BHPAIR01";
const PROOF_DOMAIN: &[u8] = b"BaseHero QR proof v1\0";
const VERSION: u16 = 1;
const QR_LEN: usize = 122;
const PROOF_LEN: usize = 40;
const MAX_LABEL: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairError {
    Malformed,
    UnsupportedVersion,
    History,
    InvalidReply,
    CompetingReply,
    Ended,
    NoReply,
    WrongContext,
    ChangedRequest,
    StageFailed,
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
        let request = owner.prepare_add_device(capability, candidate.reply.keys.clone())?;
        candidate.request = Some((request.signing_bytes().to_vec(), *request.expected_key()));
        Ok(request)
    }
    /// Invoke the caller's synchronous durable stage only while the session is
    /// live. A cancelled or competing reply fences late OS signatures. No network
    /// send is permitted until the stage commits exact signed add and seal bytes.
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
