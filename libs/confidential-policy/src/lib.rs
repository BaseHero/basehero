//! Exact-byte signed release policies for confidential services.
//!
//! This crate checks release-policy constraints, **not** hardware attestation,
//! transport authentication, account authority or permission to release keys.
//! See the crate README for the wire format and the caller's trust obligations.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"basehero.confidential-policy.v1\0";
const MAX_PAYLOAD_BYTES: usize = 65_536;

/// App-bound relay releases deliberately do not belong to this policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Checker,
    KeyService,
    Runner,
}

/// Expected measured build. Each boot value is exactly 48 bytes, in order:
/// MRTD, RTMR0, RTMR1, RTMR2. The hardware adapter must separately replay the
/// complete RTMR3 event log to establish the measured Compose SHA-256 digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Build {
    pub role: Role,
    pub compose_sha256: [u8; 32],
    pub boot: [Vec<u8>; 4],
}

/// Closed policy payload. No account, audience or job authority belongs here.
/// Empty allowlists withdraw all corresponding permission.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub generation: u64,
    /// Absolute seconds in the same epoch as the trusted time adapter.
    pub issued_at: u64,
    pub expires_at: u64,
    pub builds: Vec<Build>,
    /// SHA-256 of PPID bytes from authenticated Intel PCK collateral, not a
    /// machine name, deployment setting, or unauthenticated quote field.
    pub machines: Vec<[u8; 32]>,
}

/// Deployment-specific bounds supplied by trusted code, not by a peer or feed.
/// There is intentionally no default production lease or assumed clock bound.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_lifetime_secs: u64,
    pub max_uncertainty_secs: u64,
}

/// Conservative absolute time from a trusted adapter. Merely constructing this
/// value does not establish trusted time; system wall time is not a substitute.
#[derive(Clone, Copy, Debug)]
pub struct TimeBounds {
    pub earliest: u64,
    pub latest: u64,
}

/// Fixed, content-free failures: never carries payloads or dependency messages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Configuration,
    TooLarge,
    Signature,
    Encoding,
    PolicyRollback,
    GenerationConflict,
    PolicyUnavailable,
    Version,
    Lifetime,
    Measurements,
    TimeUnavailable,
    TimeUncertain,
    TimeRollback,
    NotYetValid,
    Expired,
    RoleDenied,
    BuildDenied,
    MachineDenied,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Every variant is data-free; Debug cannot include untrusted content.
        write!(f, "confidential policy: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Frame exact policy bytes for signing or verification; does not parse or
/// establish that the policy is usable.
pub fn signing_message(payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(Error::TooLarge);
    }
    let mut message = Vec::with_capacity(DOMAIN.len() + payload.len());
    message.extend_from_slice(DOMAIN);
    message.extend_from_slice(payload);
    Ok(message)
}

impl Policy {
    /// Offline structural checks only. Empty allowlists are valid withdrawals;
    /// currentness, availability and measured identity require a live gate.
    pub fn validate_structure(&self, limits: Limits) -> Result<(), Error> {
        if limits.max_lifetime_secs == 0 {
            return Err(Error::Configuration);
        }
        if self.version != 1 {
            return Err(Error::Version);
        }
        if self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > limits.max_lifetime_secs
        {
            return Err(Error::Lifetime);
        }
        if self
            .builds
            .iter()
            .any(|b| b.boot.iter().any(|m| m.len() != 48))
        {
            return Err(Error::Measurements);
        }
        Ok(())
    }
}

struct Accepted {
    policy: Policy,
    snapshot: Snapshot,
}

/// Exact signed, bounded durable record, bound to the app trust root.
#[derive(Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub root: [u8; 32],
    pub payload: Vec<u8>,
    pub signature: [u8; 64],
}
impl Snapshot {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

/// A gate-produced, one-use candidate. No caller can construct or duplicate it.
pub struct Candidate {
    accepted: Accepted,
    gate_id: [u8; 32],
    revision: u64,
    advancing: bool,
}
impl Candidate {
    pub fn snapshot(&self) -> &Snapshot {
        &self.accepted.snapshot
    }
    pub fn advancing(&self) -> bool {
        self.advancing
    }
}

/// Volatile policy and time high-water marks. Restart loses these marks.
///
/// An old unexpired policy cannot reveal an unseen withdrawal. This verifier is
/// therefore NOT sufficient to establish current authorization after recovery.
/// It returns no attested-peer or key-release capability, and has no disk,
/// network, environment, wall-clock, logging or signing-key access.
pub struct PolicyGate {
    root: [u8; 32],
    limits: Limits,
    accepted: Option<Accepted>,
    available: bool,
    greatest_earliest: Option<u64>,
    clock_failed: bool,
    gate_id: [u8; 32],
    revision: u64,
}

impl PolicyGate {
    /// `root` and `limits` must come from the app or measured service build, not
    /// the policy response or operator-controlled environment.
    pub fn new(root: [u8; 32], limits: Limits) -> Result<Self, Error> {
        if limits.max_lifetime_secs == 0 {
            return Err(Error::Configuration);
        }
        Ok(Self {
            root,
            limits,
            accepted: None,
            available: false,
            greatest_earliest: None,
            clock_failed: false,
            gate_id: bh_crypto::random(),
            revision: 0,
        })
    }

    /// Verify the signature of `DOMAIN || payload` over the exact received bytes
    /// before parsing. The payload is bounded UTF-8 JSON with no unknown or
    /// duplicate fields. Generation equality requires byte-for-byte identity.
    ///
    /// A newer authenticated, parseable document replaces the previous one even
    /// when unusable (withdrawn, expired, future, unsupported version or invalid
    /// measurements). `Ok` here means delivered, not currently usable. There is
    /// no fallback to the older document. Failed signatures leave state untouched.
    /// Authenticated but undecodable input disables availability, retaining the
    /// previous generation floor; known feed failures require `mark_unavailable`.
    pub fn push(&mut self, payload: &[u8], signature: &[u8]) -> Result<(), Error> {
        let candidate = self.prepare_delivery(payload, signature)?;
        self.publish_delivery(candidate)
    }

    /// Authenticate and compare against the current floor, without accepting it.
    /// Authenticated undecodable bytes alone disable availability.
    pub fn prepare_delivery(
        &mut self,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<Candidate, Error> {
        let message = signing_message(payload)?;
        let signature: &[u8; 64] = signature.try_into().map_err(|_| Error::Signature)?;
        bh_crypto::verify(&self.root, &message, signature).map_err(|_| Error::Signature)?;
        let policy: Policy = serde_json::from_slice(payload).map_err(|_| {
            self.mark_unavailable();
            Error::Encoding
        })?;
        let advancing = match &self.accepted {
            Some(current) => {
                if policy.generation < current.policy.generation {
                    return Err(Error::PolicyRollback);
                }
                if policy.generation == current.policy.generation {
                    if payload != current.snapshot.payload {
                        return Err(Error::GenerationConflict);
                    }
                    false
                } else {
                    true
                }
            }
            None => true,
        };
        Ok(Candidate {
            accepted: Accepted {
                policy,
                snapshot: Snapshot {
                    root: self.root,
                    payload: payload.to_vec(),
                    signature: *signature,
                },
            },
            gate_id: self.gate_id,
            revision: self.revision,
            advancing,
        })
    }

    /// Publish only a candidate from this unchanged gate. A stale candidate
    /// cannot reverse an outage or overwrite a newer accepted generation.
    pub fn publish_delivery(&mut self, candidate: Candidate) -> Result<(), Error> {
        if candidate.gate_id != self.gate_id || candidate.revision != self.revision {
            return Err(Error::GenerationConflict);
        }
        let next_revision = self
            .revision
            .checked_add(1)
            .ok_or(Error::GenerationConflict)?;
        self.accepted = Some(candidate.accepted);
        self.available = true;
        self.revision = next_revision;
        Ok(())
    }

    pub fn snapshot(&self) -> Option<Snapshot> {
        self.accepted.as_ref().map(|a| a.snapshot.clone())
    }

    /// Authenticating a durable record restores its generation floor, never its
    /// availability. A fresh delivery is required for use.
    pub fn restore_unavailable(
        root: [u8; 32],
        limits: Limits,
        snapshot: &Snapshot,
    ) -> Result<Self, Error> {
        let mut gate = Self::new(root, limits)?;
        if snapshot.root != root {
            return Err(Error::Signature);
        }
        let candidate = gate.prepare_delivery(&snapshot.payload, &snapshot.signature)?;
        gate.publish_delivery(candidate)?;
        gate.mark_unavailable();
        Ok(gate)
    }

    /// Report a known delivery outage. Keep the generation floor, but stop
    /// matching until an authenticated non-regressing document is delivered.
    /// Silent withholding is bounded only by the original signed expiry.
    pub fn mark_unavailable(&mut self) {
        self.available = false;
        if let Some(next) = self.revision.checked_add(1) {
            self.revision = next;
        } else {
            self.gate_id = bh_crypto::random();
            self.revision = 0;
        }
    }

    /// Check a measured identity against the current signed policy.
    ///
    /// `build` and `machine` MUST come from full independent hardware verification
    /// with fresh service-key binding, not a peer's assertions. This method does
    /// not perform that verification. It also does not check job/account authority
    /// or establish an encrypted channel. Success alone authorizes no operation.
    /// Call on every policy-dependent operation; do not cache success.
    /// `None` reports unavailable trusted time and always refuses.
    pub fn check_measurements(
        &mut self,
        role: Role,
        build: &Build,
        machine: &[u8; 32],
        time: Option<TimeBounds>,
    ) -> Result<(), Error> {
        if self.clock_failed {
            return Err(Error::TimeRollback);
        }
        let TimeBounds { earliest, latest } = time.ok_or(Error::TimeUnavailable)?;
        if latest < earliest || latest - earliest > self.limits.max_uncertainty_secs {
            return Err(Error::TimeUncertain);
        }
        if self
            .greatest_earliest
            .is_some_and(|previous| latest < previous)
        {
            self.clock_failed = true;
            return Err(Error::TimeRollback);
        }
        self.greatest_earliest = Some(self.greatest_earliest.map_or(earliest, |p| p.max(earliest)));
        if !self.available {
            return Err(Error::PolicyUnavailable);
        }
        let policy = &self
            .accepted
            .as_ref()
            .ok_or(Error::PolicyUnavailable)?
            .policy;
        policy.validate_structure(self.limits)?;
        if earliest < policy.issued_at {
            return Err(Error::NotYetValid);
        }
        if latest >= policy.expires_at {
            return Err(Error::Expired);
        }
        if build.role != role {
            return Err(Error::RoleDenied);
        }
        if !policy.builds.contains(build) {
            return Err(Error::BuildDenied);
        }
        if !policy.machines.contains(machine) {
            return Err(Error::MachineDenied);
        }
        Ok(())
    }
}
