//! Offline provider-scoped, exact-byte signed admission. The app supplies the
//! root, key identifier, provider/model ceiling, build date and lifetime bound;
//! this library never fetches, stores or signs production approvals.
use crate::{near_gateway, near_model};
use bh_confidential_attestation::Time;

const MAGIC: &[u8; 8] = b"BHPOL001";
const DOMAIN: &[u8] = b"BaseHero provider-admission v1\0";
pub const MAX_ENVELOPE_BYTES: usize = 262_144;
pub const MAX_ENTRIES: usize = 1_024;
const HEADER: usize = 8 + 8 + 4;
const SIGNATURE: usize = 64;

/// Release-owned ceiling. All fields must come from the app release, not a feed.
#[derive(Clone, Copy)]
pub struct Trust<'a> {
    pub root: [u8; 32],
    pub key_id: [u8; 8],
    pub provider: &'a str,
    pub models: &'a [&'a str],
    pub app_build_date: u64,
    pub max_lifetime_secs: u64,
}
/// Fixed, content-free errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    TooLarge,
    Encoding,
    Schema,
    Provider,
    Signature,
    Rollback,
    Equivocation,
    Time,
    Lifetime,
    Expired,
    Denied,
}
impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "provider policy: {self:?}")
    }
}
impl std::error::Error for Reject {}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Entry {
    Gateway([u8; 32], [u8; 32]),
    Model(String, [u8; 32]),
}
/// Immutable accepted deployment set; no public constructor or mutable fields.
/// ```compile_fail
/// fn overwrite(snapshot: &mut basehero_models::provider_policy::Snapshot) {
///     snapshot.version = 1;
/// }
/// ```
#[derive(Clone, Debug)]
pub struct Snapshot {
    provider: String,
    version: u64,
    digest: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    app_build_date: u64,
    max_lifetime_secs: u64,
    entries: Vec<Entry>,
}
impl Snapshot {
    pub fn provider(&self) -> &str {
        &self.provider
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    pub fn provider_entries(&self) -> usize {
        self.entries.len()
    }
    pub(crate) fn model_hashes(&self, model: &str) -> Vec<[u8; 32]> {
        self.entries
            .iter()
            .filter_map(|e| match e {
                Entry::Model(m, h) if m == model => Some(*h),
                _ => None,
            })
            .collect()
    }
    // Status for install, not admission to a particular gateway or model route.
    fn usable_now(&self, time: Option<Time>) -> bool {
        !self.entries.is_empty() && self.usable(time).is_ok()
    }
    fn usable(&self, time: Option<Time>) -> Result<(), Reject> {
        let time = time.ok_or(Reject::Time)?;
        if time.latest != time.earliest || time.max_uncertainty_secs != 0 {
            return Err(Reject::Time);
        }
        if self.expires_at <= self.issued_at
            || self.expires_at - self.issued_at > self.max_lifetime_secs
        {
            return Err(Reject::Lifetime);
        }
        if time.earliest < self.app_build_date {
            return Err(Reject::Time);
        }
        if time.earliest >= self.expires_at {
            return Err(Reject::Expired);
        }
        Ok(())
    }
}
/// Exactly the signed bytes; reauthenticate with `restore` on every load.
#[derive(Clone, Debug)]
pub struct State {
    bytes: Vec<u8>,
    snapshot: Snapshot,
}
impl State {
    pub fn signed_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }
}
/// `usable_now` means in the policy window with at least one supported entry;
/// it does not mean that any particular route may dispatch.
#[derive(Debug)]
pub enum Install {
    Installed { state: State, usable_now: bool },
    Same { usable_now: bool },
    Reject(Reject),
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Reject> {
        let end = self.at.checked_add(n).ok_or(Reject::Encoding)?;
        let result = self.bytes.get(self.at..end).ok_or(Reject::Encoding)?;
        self.at = end;
        Ok(result)
    }
    fn u8(&mut self) -> Result<u8, Reject> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, Reject> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| Reject::Encoding)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, Reject> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Reject::Encoding)?,
        ))
    }
    fn hash(&mut self) -> Result<[u8; 32], Reject> {
        self.take(32)?.try_into().map_err(|_| Reject::Encoding)
    }
    fn id(&mut self, model: bool) -> Result<&'a str, Reject> {
        let n = self.u8()? as usize;
        if n == 0 || n > 64 {
            return Err(Reject::Encoding);
        }
        let s = std::str::from_utf8(self.take(n)?).map_err(|_| Reject::Encoding)?;
        if !s.bytes().all(|b| {
            if model {
                b.is_ascii_graphic()
            } else {
                b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.'
            }
        }) {
            return Err(Reject::Encoding);
        }
        Ok(s)
    }
}
fn parse(bytes: &[u8], trust: &Trust<'_>) -> Result<Snapshot, Reject> {
    if bytes.len() > MAX_ENVELOPE_BYTES {
        return Err(Reject::TooLarge);
    }
    if bytes.len() < HEADER + SIGNATURE || &bytes[..8] != MAGIC || bytes[8..16] != trust.key_id {
        return Err(Reject::Schema);
    }
    let n = u32::from_be_bytes(bytes[16..20].try_into().map_err(|_| Reject::Encoding)?) as usize;
    if n.checked_add(HEADER + SIGNATURE) != Some(bytes.len()) {
        return Err(Reject::Encoding);
    }
    let payload = &bytes[HEADER..HEADER + n];
    // Cheap unauthenticated preflight: refuse a claimed oversized entry count
    // before signature verification or any entry allocation. Parse again after
    // authentication; these bytes are never treated as authority here.
    let mut preflight = Cursor {
        bytes: payload,
        at: 0,
    };
    preflight.u8()?;
    preflight.id(false)?;
    preflight.take(24)?;
    if preflight.u16()? as usize > MAX_ENTRIES {
        return Err(Reject::TooLarge);
    }
    let signature: &[u8; 64] = bytes[HEADER + n..]
        .try_into()
        .map_err(|_| Reject::Encoding)?;
    let mut signed = Vec::with_capacity(DOMAIN.len() + n);
    signed.extend_from_slice(DOMAIN);
    signed.extend_from_slice(payload);
    bh_crypto::verify(&trust.root, &signed, signature).map_err(|_| Reject::Signature)?;
    let mut c = Cursor {
        bytes: payload,
        at: 0,
    };
    if c.u8()? != 1 {
        return Err(Reject::Schema);
    }
    if c.id(false)? != trust.provider {
        return Err(Reject::Provider);
    }
    let version = c.u64()?;
    if version == 0 {
        return Err(Reject::Schema);
    }
    let issued_at = c.u64()?;
    let expires_at = c.u64()?;
    let count = c.u16()? as usize;
    if count > MAX_ENTRIES {
        return Err(Reject::TooLarge);
    }
    let mut entries = Vec::with_capacity(count);
    let mut previous: Option<&[u8]> = None;
    for _ in 0..count {
        let start = c.at;
        let entry = match c.u8()? {
            1 => Some(Entry::Gateway(c.hash()?, c.hash()?)),
            2 => {
                let model = c.id(true)?;
                let hash = c.hash()?;
                trust
                    .models
                    .contains(&model)
                    .then(|| Entry::Model(model.to_owned(), hash))
            }
            _ => return Err(Reject::Schema),
        };
        let raw = &payload[start..c.at];
        if previous.is_some_and(|p| p >= raw) {
            return Err(Reject::Encoding);
        }
        previous = Some(raw);
        if let Some(entry) = entry {
            entries.push(entry);
        }
    }
    if c.at != payload.len() {
        return Err(Reject::Encoding);
    }
    Ok(Snapshot {
        provider: trust.provider.to_owned(),
        version,
        digest: bh_crypto::sha256(payload),
        issued_at,
        expires_at,
        app_build_date: trust.app_build_date,
        max_lifetime_secs: trust.max_lifetime_secs,
        entries,
    })
}
/// Pure time-independent version floor. Invalid time/lifetime does not stop a
/// structurally valid signed higher version replacing the old floor.
pub fn install(
    current: Option<&State>,
    bytes: &[u8],
    trust: &Trust<'_>,
    time: Option<Time>,
) -> Install {
    let snapshot = match parse(bytes, trust) {
        Ok(v) => v,
        Err(e) => return Install::Reject(e),
    };
    if let Some(old) = current {
        if snapshot.provider != old.snapshot.provider {
            return Install::Reject(Reject::Provider);
        }
        if snapshot.version < old.snapshot.version {
            return Install::Reject(Reject::Rollback);
        }
        if snapshot.version == old.snapshot.version {
            if snapshot.digest != old.snapshot.digest || bytes != old.bytes {
                return Install::Reject(Reject::Equivocation);
            }
            return Install::Same {
                usable_now: snapshot.usable_now(time),
            };
        }
    }
    let usable_now = snapshot.usable_now(time);
    Install::Installed {
        state: State {
            bytes: bytes.to_vec(),
            snapshot,
        },
        usable_now,
    }
}
/// Reauthenticate exact bytes on load, including expired and withdrawn bytes.
pub fn restore(bytes: &[u8], trust: &Trust<'_>) -> Result<State, Reject> {
    let snapshot = parse(bytes, trust)?;
    Ok(State {
        bytes: bytes.to_vec(),
        snapshot,
    })
}
/// Derive an expectation holding all complete signer/compose pairs, not a cross product.
pub fn expected_gateway(
    snapshot: &Snapshot,
    nonce: [u8; 32],
    time: Option<Time>,
) -> Result<near_gateway::Expected, Reject> {
    if snapshot.provider != "near" {
        return Err(Reject::Provider);
    }
    snapshot.usable(time)?;
    let pairs: Vec<_> = snapshot
        .entries
        .iter()
        .filter_map(|e| match e {
            Entry::Gateway(s, c) => Some((*s, *c)),
            _ => None,
        })
        .collect();
    if pairs.is_empty() {
        return Err(Reject::Denied);
    }
    Ok(near_gateway::Expected::from_policy(pairs, nonce))
}
/// Derive an exact model/hash expectation for the fixed GLM request route.
/// Other canonical model entries still advance the floor, but cannot mint a key
/// for this route until a separate model-specific verifier/request path exists.
pub fn expected_model<'a>(
    snapshot: &'a Snapshot,
    model: &str,
    nonce: [u8; 32],
    time: Option<Time>,
) -> Result<near_model::Expected<'a>, Reject> {
    if snapshot.provider != "near" {
        return Err(Reject::Provider);
    }
    if model != near_model::MODEL {
        return Err(Reject::Denied);
    }
    snapshot.usable(time)?;
    if !snapshot
        .entries
        .iter()
        .any(|e| matches!(e, Entry::Model(m, _) if m == model))
    {
        return Err(Reject::Denied);
    }
    Ok(near_model::Expected::from_policy(nonce, snapshot, model))
}
/// Only already-verified identities may be checked at dispatch handoff.
pub enum RouteEvidence<'a> {
    Gateway(&'a near_gateway::VerifiedGateway),
    Model(&'a near_model::VerifiedModelKey),
}
pub fn check_current(
    snapshot: &Snapshot,
    evidence: RouteEvidence<'_>,
    time: Option<Time>,
) -> Result<(), Reject> {
    if snapshot.provider != "near" {
        return Err(Reject::Provider);
    }
    snapshot.usable(time)?;
    let time = time.ok_or(Reject::Time)?;
    let found = match evidence {
        RouteEvidence::Gateway(g) => {
            if time.earliest >= g.valid_until() {
                return Err(Reject::Expired);
            }
            snapshot.entries.iter().any(|e| matches!(e, Entry::Gateway(s,c) if s == g.signer().public_key() && c == g.compose_sha256()))
        }
        RouteEvidence::Model(key) => {
            if time.earliest >= key.valid_until() {
                return Err(Reject::Expired);
            }
            snapshot.entries.iter().any(
                |e| matches!(e, Entry::Model(m,c) if m == key.model() && c == key.compose_sha256()),
            )
        }
    };
    if found { Ok(()) } else { Err(Reject::Denied) }
}

#[cfg(test)]
mod tests;
