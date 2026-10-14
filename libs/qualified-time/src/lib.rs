//! Pure Google-Roughtime v1 verification and boot-local qualified time. No wall
//! clock, I/O, TSC implementation or default oscillator/policy limits live here.
//! The caller pins independent server keys, generates fresh 64-byte nonces,
//! stamps send/receipt with one monotonic counter, and establishes its rate,
//! drift, smear allowance and maximum age/width for this particular host.
#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable {
    Cold,
    Configuration,
    Packet,
    Signature,
    Inclusion,
    Server,
    Counter,
    Stale,
    Width,
    Range,
    Replay,
}
impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "qualified time: {self:?}")
    }
}
impl std::error::Error for Unavailable {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerRoot {
    pub key: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reading {
    pub midpoint_us: u64,
    pub radius_us: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub earliest_ms: u64,
    pub latest_ms: u64,
}
impl Bounds {
    /// The deadline passed only if the entire interval is on/after it.
    pub fn deadline_passed_ms(self, deadline: u64) -> bool {
        self.earliest_ms >= deadline
    }
    /// A pre-deadline action requires the entire interval strictly before it.
    pub fn before_ms(self, deadline: u64) -> bool {
        self.latest_ms < deadline
    }
    /// Half-open expiry likewise requires latest < expires_at.
    pub fn to_policy_time(self) -> bh_confidential_policy::TimeBounds {
        bh_confidential_policy::TimeBounds {
            earliest: self.earliest_ms / 1000,
            latest: self.latest_ms.div_ceil(1000),
        }
    }
    pub fn to_attestation_time(
        self,
        max_uncertainty_secs: u64,
    ) -> bh_confidential_attestation::Time {
        let t = self.to_policy_time();
        bh_confidential_attestation::Time {
            earliest: t.earliest,
            latest: t.latest,
            max_uncertainty_secs,
        }
    }
}
/// Every parameter is supplied by trusted caller code; `hz` is nominal ticks/s.
/// `smear_us` is an outward allowance for the server time scale to POSIX time.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub hz: u64,
    pub drift_ppm: u32,
    pub smear_us: u64,
    pub max_age_ticks: u64,
    pub max_width_ms: u64,
}
pub trait Counter {
    fn ticks(&self) -> u64;
}
/// Nonces must belong to this specific send. The caller must ensure the
/// timestamps actually surround the transport operation; this crate cannot.
pub struct Sample<'a> {
    pub server: ServerRoot,
    pub nonce: &'a [u8; 64],
    pub reply: &'a [u8],
    pub sent: u64,
    pub received: u64,
}

const fn tag(s: &[u8; 4]) -> u32 {
    u32::from_le_bytes(*s)
}
const SIG: u32 = tag(b"SIG\0");
const CERT: u32 = tag(b"CERT");
const DELE: u32 = tag(b"DELE");
const PUBK: u32 = tag(b"PUBK");
const MINT: u32 = tag(b"MINT");
const MAXT: u32 = tag(b"MAXT");
const SREP: u32 = tag(b"SREP");
const ROOT: u32 = tag(b"ROOT");
const MIDP: u32 = tag(b"MIDP");
const RADI: u32 = tag(b"RADI");
const INDX: u32 = tag(b"INDX");
const PATH: u32 = tag(b"PATH");
const MAX_REPLY: usize = 4096;

// Offset words and tag words follow the count; all values are 4-byte aligned.
fn decode(bytes: &[u8]) -> Result<Vec<(u32, &[u8])>, Unavailable> {
    if bytes.len() < 4 || bytes.len() > MAX_REPLY || !bytes.len().is_multiple_of(4) {
        return Err(Unavailable::Packet);
    }
    let word = |i: usize| -> Result<u32, Unavailable> {
        let data = bytes.get(i..i + 4).ok_or(Unavailable::Packet)?;
        Ok(u32::from_le_bytes(
            data.try_into().map_err(|_| Unavailable::Packet)?,
        ))
    };
    let n = word(0)? as usize;
    if n == 0 || n > 64 || bytes.len() < 8 * n {
        return Err(Unavailable::Packet);
    }
    let payload = &bytes[8 * n..];
    let mut out = Vec::with_capacity(n);
    let mut start = 0;
    for i in 0..n {
        let t = word(4 * n + 4 * i)?;
        let end = if i + 1 < n {
            word(4 + 4 * i)? as usize
        } else {
            payload.len()
        };
        if end % 4 != 0
            || end < start
            || end > payload.len()
            || out.last().is_some_and(|(last, _)| t <= *last)
        {
            return Err(Unavailable::Packet);
        }
        out.push((t, &payload[start..end]));
        start = end;
    }
    Ok(out)
}
fn get<'a>(fields: &[(u32, &'a [u8])], t: u32) -> Result<&'a [u8], Unavailable> {
    fields
        .iter()
        .find(|(key, _)| *key == t)
        .map(|(_, v)| *v)
        .ok_or(Unavailable::Packet)
}
fn u64_field(fields: &[(u32, &[u8])], t: u32) -> Result<u64, Unavailable> {
    Ok(u64::from_le_bytes(
        get(fields, t)?
            .try_into()
            .map_err(|_| Unavailable::Packet)?,
    ))
}
fn u32_field(fields: &[(u32, &[u8])], t: u32) -> Result<u32, Unavailable> {
    Ok(u32::from_le_bytes(
        get(fields, t)?
            .try_into()
            .map_err(|_| Unavailable::Packet)?,
    ))
}
fn signed(
    key: &[u8; 32],
    domain: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), Unavailable> {
    let sig: &[u8; 64] = signature.try_into().map_err(|_| Unavailable::Packet)?;
    let mut bytes = Vec::with_capacity(domain.len() + payload.len());
    bytes.extend_from_slice(domain);
    bytes.extend_from_slice(payload);
    bh_crypto::verify(key, &bytes, sig).map_err(|_| Unavailable::Signature)
}
/// Authenticate delegation and signed response, then prove this nonce is a
/// SHA-512 Merkle leaf of its signed root. Accept no unbounded tags or paths.
pub fn verify(root: &ServerRoot, nonce: &[u8; 64], reply: &[u8]) -> Result<Reading, Unavailable> {
    let top = decode(reply)?;
    let cert = decode(get(&top, CERT)?)?;
    let delegation = get(&cert, DELE)?;
    signed(
        &root.key,
        b"RoughTime v1 delegation signature--\0",
        delegation,
        get(&cert, SIG)?,
    )?;
    let dele = decode(delegation)?;
    let online: &[u8; 32] = get(&dele, PUBK)?
        .try_into()
        .map_err(|_| Unavailable::Packet)?;
    let response = get(&top, SREP)?;
    signed(
        online,
        b"RoughTime v1 response signature\0",
        response,
        get(&top, SIG)?,
    )?;
    let srep = decode(response)?;
    let reading = Reading {
        midpoint_us: u64_field(&srep, MIDP)?,
        radius_us: u32_field(&srep, RADI)?,
    };
    if !(u64_field(&dele, MINT)?..=u64_field(&dele, MAXT)?).contains(&reading.midpoint_us) {
        return Err(Unavailable::Packet);
    }
    let path = get(&top, PATH)?;
    if path.len() > 64 * 32 || path.len() % 64 != 0 {
        return Err(Unavailable::Packet);
    }
    let mut index = u32_field(&top, INDX)?;
    let mut leaf = [0; 65];
    leaf[1..].copy_from_slice(nonce);
    let mut hash = bh_crypto::sha512(&leaf);
    for sibling in path.as_chunks::<64>().0 {
        let mut node = [0; 129];
        node[0] = 1;
        if index & 1 == 0 {
            node[1..65].copy_from_slice(&hash);
            node[65..].copy_from_slice(sibling);
        } else {
            node[1..65].copy_from_slice(sibling);
            node[65..].copy_from_slice(&hash);
        }
        hash = bh_crypto::sha512(&node);
        index >>= 1;
    }
    if index != 0 || !bh_crypto::constant_time_eq(&hash, get(&srep, ROOT)?) {
        return Err(Unavailable::Inclusion);
    }
    Ok(reading)
}

#[derive(Clone, Copy)]
struct Anchor {
    reading: Reading,
    sent: u64,
    received: u64,
}
pub struct QualifiedClock {
    roots: [ServerRoot; 2],
    config: Config,
    anchors: Option<[Anchor; 2]>,
    last: Option<u64>,
    rollback: bool,
    used_nonces: std::collections::HashSet<[u8; 64]>,
}
impl QualifiedClock {
    pub fn new(roots: [ServerRoot; 2], config: Config) -> Result<Self, Unavailable> {
        if roots[0] == roots[1]
            || config.hz == 0
            || config.drift_ppm >= 1_000_000
            || config.max_width_ms == 0
            || config.max_age_ticks == 0
        {
            return Err(Unavailable::Configuration);
        }
        Ok(Self {
            roots,
            config,
            anchors: None,
            last: None,
            rollback: false,
            used_nonces: Default::default(),
        })
    }
    /// A failed refresh invalidates the old anchor: outage must not serve stale time.
    /// Reused nonces (including across refreshes in this boot) refuse; after 4096
    /// nonces construct a fresh clock rather than growing replay state without bound.
    pub fn update(
        &mut self,
        samples: &[Sample<'_>],
        counter: &impl Counter,
    ) -> Result<Bounds, Unavailable> {
        self.anchors = None;
        if self.rollback {
            return Err(Unavailable::Counter);
        }
        let now = counter.ticks();
        let previous = self.last;
        if previous.is_some_and(|last| now < last) {
            self.rollback = true;
            return Err(Unavailable::Counter);
        }
        self.last = Some(now);
        if samples.len() != 2 {
            return Err(Unavailable::Server);
        }
        if self.used_nonces.len() > 4094 {
            return Err(Unavailable::Replay);
        }
        let mut anchors = Vec::with_capacity(2);
        for (expected, sample) in self.roots.iter().zip(samples) {
            if sample.server != *expected {
                return Err(Unavailable::Server);
            }
            if sample.sent > sample.received || sample.received > now {
                self.rollback = true;
                return Err(Unavailable::Counter);
            }
            if self.used_nonces.contains(sample.nonce) || samples[0].nonce == samples[1].nonce {
                return Err(Unavailable::Replay);
            }
            let reading = verify(expected, sample.nonce, sample.reply)?;
            anchors.push(Anchor {
                reading,
                sent: sample.sent,
                received: sample.received,
            });
        }
        let anchors: [Anchor; 2] = anchors.try_into().map_err(|_| Unavailable::Server)?;
        let bounds = self.compute(&anchors, now)?;
        for sample in samples {
            self.used_nonces.insert(*sample.nonce);
        }
        self.anchors = Some(anchors);
        Ok(bounds)
    }
    pub fn now(&mut self, counter: &impl Counter) -> Result<Bounds, Unavailable> {
        if self.rollback {
            return Err(Unavailable::Counter);
        }
        let now = counter.ticks();
        if self.last.is_some_and(|last| now < last) {
            self.rollback = true;
            self.anchors = None;
            return Err(Unavailable::Counter);
        }
        self.last = Some(now);
        self.compute(&self.anchors.ok_or(Unavailable::Cold)?, now)
    }
    fn compute(&self, anchors: &[Anchor; 2], now: u64) -> Result<Bounds, Unavailable> {
        let mut hull = (u128::MAX, 0u128);
        let mut overlap = (0u128, u128::MAX);
        for a in anchors {
            if now < a.received {
                return Err(Unavailable::Counter);
            }
            if now - a.received > self.config.max_age_ticks {
                return Err(Unavailable::Stale);
            }
            let elapsed = |ticks: u64, ppm: u32, ceil: bool| -> Result<u128, Unavailable> {
                // Convert ticks to microseconds once; floor early and ceil late.
                let n = u128::from(ticks)
                    .checked_mul(1_000_000_000_000)
                    .ok_or(Unavailable::Range)?;
                let d = u128::from(self.config.hz) * u128::from(ppm);
                Ok(if ceil { n.div_ceil(d) } else { n / d })
            };
            let radius = u128::from(a.reading.radius_us) + u128::from(self.config.smear_us);
            let mid = u128::from(a.reading.midpoint_us);
            let earliest = mid
                .checked_sub(radius)
                .and_then(|v| {
                    v.checked_add(
                        elapsed(now - a.received, 1_000_000 + self.config.drift_ppm, false).ok()?,
                    )
                })
                .ok_or(Unavailable::Range)?;
            let latest = mid
                .checked_add(radius)
                .and_then(|v| {
                    v.checked_add(
                        elapsed(now - a.sent, 1_000_000 - self.config.drift_ppm, true).ok()?,
                    )
                })
                .ok_or(Unavailable::Range)?;
            hull = (hull.0.min(earliest), hull.1.max(latest));
            overlap = (overlap.0.max(earliest), overlap.1.min(latest));
        }
        if overlap.0 > overlap.1 {
            return Err(Unavailable::Server);
        }
        let earliest_ms = u64::try_from(hull.0 / 1000).map_err(|_| Unavailable::Range)?;
        let latest_ms = u64::try_from(hull.1.div_ceil(1000)).map_err(|_| Unavailable::Range)?;
        if latest_ms - earliest_ms > self.config.max_width_ms {
            return Err(Unavailable::Width);
        }
        Ok(Bounds {
            earliest_ms,
            latest_ms,
        })
    }
}
