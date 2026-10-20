//! Offline Intel TDX quote and dstack runtime-log verification. A measured value
//! is neither current policy authorization nor a possession proof for the bound
//! keys. Caller must own nonce issuance/replay, trusted time, signed policy,
//! authenticated channel and job authority separately.
#![forbid(unsafe_code)]

use bh_confidential_policy::{Build, Role};
use cc_eventlog::{TdxEvent, replay_events, tdx::validate_v2_preimages};
use dcap_qvl::{
    QuoteClaims, QuoteCollateralV3, QuotePolicy, quote::TDReport10, verify::QuoteVerifier,
};

/// Max raw bytes before any untrusted JSON or quote parser. The archived quote
/// is 5006 bytes, collateral 16072, and separate dstack log fixture < 19 KiB.
/// 1 MiB per input permits larger real logs/collateral without unbounded parsing;
/// the caller must also bound transport bytes. No live host size proof yet.
pub const MAX_INPUT_BYTES: usize = 1_048_576;
const MAX_EVENTS: usize = 4096;
const MAX_RUNTIME_PAYLOAD: usize = 65_536;
const DOMAIN: &[u8] = b"basehero.tdx-report.v1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    Encoding,
    TimeUnavailable,
    TimeUncertain,
    Quote,
    Binding,
    EventLog,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "confidential attestation: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Serialized QVL `QuoteCollateralV3` and dstack JSON array of TDX events.
/// They are untrusted, and never fetched by this crate.
pub struct Evidence<'a> {
    pub quote: &'a [u8],
    pub collateral: &'a [u8],
    pub event_log: &'a [u8],
}
/// Expected public keys and a fresh verifier-owned nonce. Never derive these
/// from the quote or trust an issuer-supplied expected key/nonce.
pub struct Expected {
    pub signing: [u8; 32],
    pub receiving: [u8; 1216],
    pub nonce: [u8; 32],
    pub role: Role,
}
/// Absolute seconds from a trusted caller adapter. `None` means unavailable;
/// max uncertainty is a trusted caller limit, not an untrusted proof field.
#[derive(Clone, Copy)]
pub struct Time {
    pub earliest: u64,
    pub latest: u64,
    pub max_uncertainty_secs: u64,
}

/// Only `verify` can construct this value. Immutable, and deliberately not a
/// readiness/authorization token. Feed build + machine separately to the signed
/// policy gate, with the same intended role and trusted time bounds; success there
/// alone still authorizes no key release or job operation.
#[derive(Debug, PartialEq, Eq)]
pub struct Measured {
    signing: [u8; 32],
    receiving: [u8; 1216],
    build: Build,
    machine: [u8; 32],
}
impl Measured {
    pub fn signing(&self) -> &[u8; 32] {
        &self.signing
    }
    pub fn receiving(&self) -> &[u8; 1216] {
        &self.receiving
    }
    pub fn build(&self) -> &Build {
        &self.build
    }
    pub fn machine(&self) -> &[u8; 32] {
        &self.machine
    }
}

/// Immutable strict-worker evidence, not current policy authorization or key possession.
/// No snapshot/claims constructor exists. Recheck time and current signed policy on use.
///
/// ```compile_fail
/// use bh_confidential_attestation::VerifiedEvidence;
/// fn forge(evidence: &mut VerifiedEvidence) { evidence.valid_until = u64::MAX; }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedEvidence {
    measured: Measured,
    nonce: [u8; 32],
    valid_from: u64,
    valid_until: u64,
}
impl VerifiedEvidence {
    pub fn measured(&self) -> &Measured {
        &self.measured
    }
    /// Inclusive lower and exclusive upper bound, in POSIX seconds.
    pub fn validity(&self) -> (u64, u64) {
        (self.valid_from, self.valid_until)
    }
    pub fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }
    pub fn check_time(&self, time: Option<Time>) -> Result<(), Error> {
        let time = checked_time(time)?;
        if time.earliest < self.valid_from || time.latest >= self.valid_until {
            return Err(Error::Quote);
        }
        Ok(())
    }
}

/// One production-Ring QVL appraisal, followed by complete binding/log assembly.
/// Only this strict-worker API supports retained evidence; provider policies do not.
pub fn verify_evidence(
    evidence: Evidence<'_>,
    expected: &Expected,
    time: Option<Time>,
) -> Result<VerifiedEvidence, Error> {
    check_size(evidence.quote)?;
    check_size(evidence.collateral)?;
    check_size(evidence.event_log)?;
    let time = checked_time(time)?;
    let claims = quote_claims(
        evidence.quote,
        evidence.collateral,
        Time {
            latest: time.earliest,
            ..time
        },
    )?;
    verified_from_claims(&claims, evidence.event_log, expected, time)
}

fn verified_from_claims(
    claims: &QuoteClaims,
    log: &[u8],
    expected: &Expected,
    time: Time,
) -> Result<VerifiedEvidence, Error> {
    // Pinned dcap-qvl 0.7.0 verify.rs:147-225,1565-1634 aggregates only
    // authenticated JSON/CRLs and verified cert paths (+ pinned root). WebPKI
    // 0.103.15+dcap.1 crl/types.rs:166 rejects now >= nextUpdate, whereas certs
    // and JSON have inclusive expiry. [L,E) is intentionally conservative.
    // Strict UpToDate excludes both time-dependent out-of-date grace branches
    // (policy/simple.rs:245-285; tcb_info.rs:172-212). All other proof checks
    // are immutable. Revisit this argument on QVL/worker-policy changes; it is
    // NOT valid for arbitrary provider policies or evidence of latest collateral.
    let verified = VerifiedEvidence {
        measured: assemble(claims, log, expected)?,
        nonce: expected.nonce,
        valid_from: time.earliest.max(claims.latest_issue_date),
        valid_until: claims.earliest_expiration_date,
    };
    verified.check_time(Some(time))?;
    Ok(verified)
}

#[cfg(test)]
thread_local! { pub(crate) static QVL_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

/// Issuer/verifier convention: SHA-256 of ASCII `basehero.tdx-report.v1`, NUL,
/// then exactly 32 signing-key bytes, 1216 X-Wing receiving-key bytes, 32 nonce
/// bytes (no variable-length framing). Raw report_data is the digest followed by
/// 32 zero bytes. This binds bytes, not private-key possession or nonce freshness.
pub fn report_data(signing: &[u8; 32], receiving: &[u8; 1216], nonce: &[u8; 32]) -> [u8; 64] {
    let mut hash = bh_crypto::Sha256::new();
    hash.update(DOMAIN);
    hash.update(signing);
    hash.update(receiving);
    hash.update(nonce);
    let mut report = [0; 64];
    report[..32].copy_from_slice(&hash.finalize());
    report
}

fn check_size(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        Err(Error::TooLarge)
    } else {
        Ok(())
    }
}
fn checked_time(time: Option<Time>) -> Result<Time, Error> {
    let time = time.ok_or(Error::TimeUnavailable)?;
    if time.latest < time.earliest || time.latest - time.earliest > time.max_uncertainty_secs {
        return Err(Error::TimeUncertain);
    }
    Ok(time)
}
/// Bounded QVL appraisal using the pinned production ring config and the
/// caller's policy at **both** ends of `time`. `policy` must build a strict
/// policy from each trusted instant; this helper supplies no default. It returns
/// unbound QVL claims: no report_data binding, measurement acceptance, key
/// possession or authority. The caller owns all of those separately.
pub fn quote_claims_with_policy<F>(
    quote: &[u8],
    collateral: &[u8],
    time: Time,
    policy: F,
) -> Result<QuoteClaims, Error>
where
    F: Fn(u64) -> QuotePolicy,
{
    let time = checked_time(Some(time))?;
    check_size(quote)?;
    check_size(collateral)?;
    let collateral: QuoteCollateralV3 =
        serde_json::from_slice(collateral).map_err(|_| Error::Encoding)?;
    // Explicit ring config, even if another dependency enables QVL's rustcrypto
    // feature via Cargo feature unification. No report/PCCS network feature.
    let verifier = QuoteVerifier::new_prod().with_config::<dcap_qvl::configs::RingConfig>();
    // Check both ends: latest alone would accept a not-yet-valid certificate at
    // earliest. QVL checks Intel signatures, chains, CRLs, TCB and time at each.
    #[cfg(test)]
    QVL_CALLS.with(|n| n.set(n.get() + 1));
    let first = verifier
        .verify_with_policy(quote, &collateral, time.earliest, &policy(time.earliest))
        .map_err(|_| Error::Quote)?;
    if time.latest != time.earliest {
        #[cfg(test)]
        QVL_CALLS.with(|n| n.set(n.get() + 1));
        verifier
            .verify_with_policy(quote, &collateral, time.latest, &policy(time.latest))
            .map_err(|_| Error::Quote)?;
    }
    Ok(first)
}

/// This crate's own runner policy: strict UpToDate at both ends, accepting the
/// platform flags, as the reference SDK does.
fn worker_policy(now: u64) -> QuotePolicy {
    QuotePolicy::strict(now)
        .allow_smt(true)
        .allow_dynamic_platform(true)
        .allow_cached_keys(true)
}
fn quote_claims(quote: &[u8], collateral: &[u8], time: Time) -> Result<QuoteClaims, Error> {
    quote_claims_with_policy(quote, collateral, time, worker_policy)
}

/// Reject a report that is not TD1.0/1.5, a PPID that is not 16 bytes, or TD
/// attributes that enable debug or migration. Returns the TD1.0/1.5 body so the
/// caller can bind its own keys and measurements. The returned report is an
/// authenticated QVL claim, not an accepted measurement or authority.
pub fn check_td10(claims: &QuoteClaims) -> Result<&TDReport10, Error> {
    let td = claims.report.as_td10().ok_or(Error::Quote)?;
    if claims.platform.pck.ppid.len() != 16 {
        return Err(Error::Quote);
    }
    if td.td_attributes[0] != 0 || td.td_attributes[3] & 0x20 != 0 {
        return Err(Error::Quote);
    }
    Ok(td)
}
/// Bounded dstack RTMR3 replay. Returns only the one `compose-hash` payload after
/// folding the imr-3 log into `rtmr3`; it performs no report_data binding,
/// measurement acceptance, image policy or authority of its own.
pub fn compose(log: &[u8], rtmr3: &[u8; 48]) -> Result<[u8; 32], Error> {
    check_size(log)?;
    let events: Vec<TdxEvent> = serde_json::from_slice(log).map_err(|_| Error::Encoding)?;
    if events.len() > MAX_EVENTS
        || events.iter().any(|e| {
            e.event_payload.len() > MAX_RUNTIME_PAYLOAD
                || e.event.len() > 256
                || e.digest.len() > 48
                || e.preimage.as_ref().is_some_and(|p| p.len() > 131_072)
        })
    {
        return Err(Error::TooLarge);
    }
    validate_v2_preimages(&events).map_err(|_| Error::EventLog)?;
    let mut runtime = Vec::new();
    let mut compose = None;
    for event in &events {
        if event.is_runtime_event() && event.imr != 3 {
            return Err(Error::EventLog);
        }
        if event.imr != 3 {
            continue;
        }
        let entry = event.to_runtime_event().ok_or(Error::EventLog)?;
        // V1 runtime digests may be stripped by dstack; RTMR3 replay below
        // still binds the recomputed digest to the authenticated register.
        if event.digest.as_slice() != entry.sha384_digest()
            && !(event.version == cc_eventlog::EventLogVersion::V1 && event.digest.is_empty())
        {
            return Err(Error::EventLog);
        }
        if entry.event == "compose-hash" {
            let hash: [u8; 32] = entry
                .payload
                .as_slice()
                .try_into()
                .map_err(|_| Error::EventLog)?;
            if compose.replace(hash).is_some() {
                return Err(Error::EventLog);
            }
        }
        runtime.push(entry);
    }
    if replay_events::<ez_hash::Sha384>(&runtime, None) != *rtmr3 {
        return Err(Error::EventLog);
    }
    compose.ok_or(Error::EventLog)
}

/// Full offline verifier. Validation bounds precede parsing/cloning; all errors
/// are fixed and content-free. No successful archived fixture matches a newly
/// issued key/nonce and the separate log; that combined proof awaits a host test.
pub fn verify(
    evidence: Evidence<'_>,
    expected: &Expected,
    time: Option<Time>,
) -> Result<Measured, Error> {
    check_size(evidence.quote)?;
    check_size(evidence.collateral)?;
    check_size(evidence.event_log)?;
    let time = checked_time(time)?;
    let claims = quote_claims(evidence.quote, evidence.collateral, time)?;
    assemble(&claims, evidence.event_log, expected)
}

// Accept only claims returned by QVL in `verify`; private so there is no
// consumer-facing route from a parsed/self-asserted quote to a measured value.
fn assemble(
    claims: &QuoteClaims,
    event_log: &[u8],
    expected: &Expected,
) -> Result<Measured, Error> {
    let td10 = check_td10(claims)?;
    if td10.report_data != report_data(&expected.signing, &expected.receiving, &expected.nonce) {
        return Err(Error::Binding);
    }
    let compose_sha256 = compose(event_log, &td10.rt_mr3)?;
    Ok(Measured {
        signing: expected.signing,
        receiving: expected.receiving,
        build: Build {
            role: expected.role,
            compose_sha256,
            boot: [
                td10.mr_td.to_vec(),
                td10.rt_mr0.to_vec(),
                td10.rt_mr1.to_vec(),
                td10.rt_mr2.to_vec(),
            ],
        },
        machine: bh_crypto::sha256(&claims.platform.pck.ppid),
    })
}

/// Local-only synthetic attestation, compiled only with the
/// `synthetic-attestation` feature, which no release build enables. Its
/// "quote" is a fixed label and the exact report data: it is NOT hardware
/// evidence and proves nothing about where the peer runs. It still requires the
/// server's fresh keys and the client's nonce, and the signed policy must list
/// its fixed build and machine like any other.
#[cfg(feature = "synthetic-attestation")]
pub mod synthetic {
    use super::{
        Build, Error, Evidence, Expected, Measured, Role, Time, VerifiedEvidence, checked_time,
        report_data,
    };

    const QUOTE_DOMAIN: &[u8] = b"basehero.synthetic-quote.v1\0";

    /// The labelled synthetic quote for this report data.
    pub fn quote(report_data: &[u8; 64]) -> Vec<u8> {
        [QUOTE_DOMAIN, report_data].concat()
    }
    /// The fixed build every synthetic quote claims for `role`.
    pub fn build(role: Role) -> Build {
        Build {
            role,
            compose_sha256: bh_crypto::sha256(b"basehero synthetic compose"),
            boot: std::array::from_fn(|_| vec![0x5a; 48]),
        }
    }
    /// The fixed machine every synthetic quote claims.
    pub fn machine() -> [u8; 32] {
        bh_crypto::sha256(b"basehero synthetic machine")
    }
    /// The synthetic counterpart of `verify_evidence`: the quote must be exactly
    /// the label and the report data for the expected keys and nonce.
    pub fn verify_evidence(
        evidence: Evidence<'_>,
        expected: &Expected,
        time: Option<Time>,
    ) -> Result<VerifiedEvidence, Error> {
        let time = checked_time(time)?;
        let report = report_data(&expected.signing, &expected.receiving, &expected.nonce);
        if evidence.quote != quote(&report) {
            return Err(Error::Binding);
        }
        Ok(VerifiedEvidence {
            measured: Measured {
                signing: expected.signing,
                receiving: expected.receiving,
                build: build(expected.role),
                machine: machine(),
            },
            nonce: expected.nonce,
            valid_from: time.earliest,
            valid_until: u64::MAX,
        })
    }
}

// Crate-private synthetic full assembly. Also source-included by channel unit
// tests: no production feature or consumer-facing route to fabricate evidence.
#[cfg(test)]
pub(crate) fn synthetic_evidence(
    expected: &Expected,
    time: Time,
    legacy: Option<(Build, [u8; 32])>,
) -> Result<VerifiedEvidence, Error> {
    let (mut claims, log, _) = tests::synthetic_inputs();
    let dcap_qvl::quote::Report::TD10(td) = &mut claims.report else {
        unreachable!()
    };
    td.report_data = report_data(&expected.signing, &expected.receiving, &expected.nonce);
    if legacy.is_some() {
        // Old state-machine fixtures use a toy epoch. Only their fixture dates
        // and measurements change; all binding/log assembly still executes.
        claims.latest_issue_date = 100;
        claims.earliest_expiration_date = u64::MAX;
    }
    let mut verified = verified_from_claims(&claims, &log, expected, time)?;
    if let Some((build, machine)) = legacy {
        verified.measured.build = build;
        verified.measured.machine = machine;
    }
    Ok(verified)
}

#[cfg(test)]
mod validity_tests;
#[cfg(test)]
mod tests {
    use super::*;
    use dcap_qvl::quote::Quote;
    use dcap_qvl::{Policy as _, TcbStatus};
    use parity_scale_codec::Decode;
    pub(super) const QUOTE: &[u8] = include_bytes!("../tests/fixtures/tdx_quote");
    pub(super) const COLLATERAL: &[u8] =
        include_bytes!("../tests/fixtures/tdx_quote_collateral.json");
    const DSTACK: &[u8] = include_bytes!("../tests/fixtures/tdx-lite-getquote.json");
    pub(super) fn interval(a: u64, b: u64) -> Time {
        Time {
            earliest: a,
            latest: b,
            max_uncertainty_secs: 60,
        }
    }
    #[test]
    fn archived_intel_path_is_real_but_expired_now() {
        let claims =
            quote_claims(QUOTE, COLLATERAL, interval(1_751_328_000, 1_751_328_001)).unwrap();
        assert!(claims.report.as_td10().is_some());
        assert_eq!(claims.platform.pck.ppid.len(), 16);
        // At each boundary a verdict at the opposite end must not substitute
        // for an interval verdict. QVL sees both the valid and invalid endpoint.
        let spanning_expiry = Time {
            earliest: 1_751_328_000,
            latest: claims.earliest_expiration_date + 1,
            max_uncertainty_secs: u64::MAX,
        };
        assert_eq!(
            quote_claims(QUOTE, COLLATERAL, spanning_expiry).err(),
            Some(Error::Quote)
        );
        let spanning_issuance = Time {
            earliest: claims.latest_issue_date.saturating_sub(86400 * 365),
            latest: 1_751_328_000,
            max_uncertainty_secs: u64::MAX,
        };
        assert_eq!(
            quote_claims(QUOTE, COLLATERAL, spanning_issuance).err(),
            Some(Error::Quote)
        );
        assert!(quote_claims(QUOTE, COLLATERAL, interval(1_791_849_600, 1_791_849_601)).is_err());
        let mut tampered = QUOTE.to_vec();
        tampered[120] ^= 1;
        assert!(
            quote_claims(
                &tampered,
                COLLATERAL,
                interval(1_751_328_000, 1_751_328_001)
            )
            .is_err()
        );
        assert!(
            quote_claims(
                QUOTE,
                COLLATERAL,
                interval(1_751_328_000 - 86400 * 365, 1_751_328_000)
            )
            .is_err()
        );
    }
    fn log_and_register() -> (Vec<TdxEvent>, [u8; 48]) {
        let fixture: serde_json::Value = serde_json::from_slice(DSTACK).unwrap();
        let raw = hex::decode(fixture["quote"].as_str().unwrap()).unwrap();
        let quote = Quote::decode(&mut raw.as_slice()).unwrap(); // parse only; NEVER authenticate
        let register = quote.report.as_td10().unwrap().rt_mr3;
        let events = serde_json::from_str(fixture["event_log"].as_str().unwrap()).unwrap();
        (events, register)
    }
    fn replay(events: &[TdxEvent], register: &[u8; 48]) -> Result<[u8; 32], Error> {
        compose(&serde_json::to_vec(events).unwrap(), register)
    }
    #[test]
    fn distinct_dstack_log_replays_but_is_not_verified_quote() {
        let (events, register) = log_and_register();
        assert_eq!(
            hex::encode(replay(&events, &register).unwrap()),
            "60618cd0c23d15d921b788b8fc3a0d024ac72295185da3ba41d5a065bc7aa833"
        );
        let mut bad = register;
        bad[0] ^= 1;
        assert_eq!(replay(&events, &bad), Err(Error::EventLog));
        assert_eq!(compose(b"[]", &register), Err(Error::EventLog));
        assert_eq!(compose(b"not json", &register), Err(Error::Encoding));
    }
    #[test]
    fn stripped_v1_runtime_digests_replay_to_same_compose_hash() {
        let (events, register) = log_and_register();
        let expected = replay(&events, &register).unwrap();
        let mut stripped = events;
        for event in &mut stripped {
            if event.imr == 3 {
                assert_eq!(event.version, cc_eventlog::EventLogVersion::V1);
                event.digest.clear();
            }
        }
        assert_eq!(replay(&stripped, &register), Ok(expected));
    }
    #[test]
    fn stripped_v1_runtime_digest_cannot_hide_changed_payload() {
        let (mut events, register) = log_and_register();
        for event in &mut events {
            if event.imr == 3 {
                event.digest.clear();
            }
        }
        let compose = events
            .iter_mut()
            .find(|e| e.imr == 3 && e.event == "compose-hash")
            .unwrap();
        compose.event_payload[0] ^= 1;
        assert_eq!(replay(&events, &register), Err(Error::EventLog));
    }
    #[test]
    fn nonempty_wrong_v1_runtime_digest_is_rejected() {
        let (mut events, register) = log_and_register();
        let runtime = events.iter_mut().find(|e| e.imr == 3).unwrap();
        runtime.digest[0] ^= 1;
        assert_eq!(replay(&events, &register), Err(Error::EventLog));
    }
    #[test]
    fn v2_runtime_requires_canonical_digest_preimage() {
        let (mut events, _) = log_and_register();
        let pos = events
            .iter()
            .position(|e| e.event == "compose-hash")
            .unwrap();
        events[pos].version = cc_eventlog::EventLogVersion::V2;
        events[pos].digest = events[pos].digest();
        events[pos].fill_preimage();
        let runtime: Vec<_> = events
            .iter()
            .filter_map(TdxEvent::to_runtime_event)
            .collect();
        let register = replay_events::<ez_hash::Sha384>(&runtime, None);
        // This register is synthetic and never a verified TDX quote.
        assert!(replay(&events, &register).is_ok());
        let mut bad = events.clone();
        bad[pos].digest.clear();
        assert_eq!(replay(&bad, &register), Err(Error::EventLog));
        let mut bad = events.clone();
        bad[pos].preimage = None;
        assert_eq!(replay(&bad, &register), Err(Error::EventLog));
        let mut bad = events;
        bad[pos].preimage = Some("bad hex".into());
        assert_eq!(replay(&bad, &register), Err(Error::EventLog));
    }
    // Synthetic post-QVL test: start from a real archived QVL verdict, then
    // replace report fields and PPID in memory. This is NOT an Intel-signed
    // quote for our fresh keys and cannot be used as a full attestation proof.
    pub(super) fn synthetic_inputs() -> (QuoteClaims, Vec<u8>, Expected) {
        let mut claims =
            quote_claims(QUOTE, COLLATERAL, interval(1_751_328_000, 1_751_328_000)).unwrap();
        let (events, register) = log_and_register();
        let expected = Expected {
            signing: [1; 32],
            receiving: [2; 1216],
            nonce: [3; 32],
            role: Role::Runner,
        };
        let dcap_qvl::quote::Report::TD10(td) = &mut claims.report else {
            panic!("archived TD10 fixture changed")
        };
        td.rt_mr3 = register;
        td.report_data = report_data(&expected.signing, &expected.receiving, &expected.nonce);
        td.mr_td = [0x11; 48];
        td.rt_mr0 = [0x22; 48];
        td.rt_mr1 = [0x33; 48];
        td.rt_mr2 = [0x44; 48];
        claims.platform.pck.ppid = (0..16).collect();
        (claims, serde_json::to_vec(&events).unwrap(), expected)
    }
    #[test]
    fn synthetic_post_qvl_assembly_binds_every_key_and_maps_all_measurements() {
        let (claims, log, expected) = synthetic_inputs();
        let measured = assemble(&claims, &log, &expected).unwrap();
        assert_eq!(measured.signing(), &expected.signing);
        assert_eq!(measured.receiving(), &expected.receiving);
        assert_eq!(measured.build().role, Role::Runner);
        assert_eq!(
            measured.build().boot,
            [
                [0x11; 48].to_vec(),
                [0x22; 48].to_vec(),
                [0x33; 48].to_vec(),
                [0x44; 48].to_vec()
            ]
        );
        assert_eq!(
            hex::encode(measured.build().compose_sha256),
            "60618cd0c23d15d921b788b8fc3a0d024ac72295185da3ba41d5a065bc7aa833"
        );
        assert_eq!(
            hex::encode(measured.machine()),
            "be45cb2605bf36bebde684841a28f0fd43c69850a3dce5fedba69928ee3a8991"
        );
        // Binding comparisons must survive even though every other field has a
        // matching synthetic register and otherwise valid measurement.
        let mut altered = Expected {
            signing: expected.signing,
            receiving: expected.receiving,
            nonce: expected.nonce,
            role: expected.role,
        };
        altered.signing[0] ^= 1;
        assert_eq!(assemble(&claims, &log, &altered), Err(Error::Binding));
        altered.signing = expected.signing;
        altered.receiving[0] ^= 1;
        assert_eq!(assemble(&claims, &log, &altered), Err(Error::Binding));
        altered.receiving = expected.receiving;
        altered.nonce[0] ^= 1;
        assert_eq!(assemble(&claims, &log, &altered), Err(Error::Binding));
        let mut bad = claims.clone();
        if let dcap_qvl::quote::Report::TD10(td) = &mut bad.report {
            td.report_data[63] = 1;
        }
        assert_eq!(assemble(&bad, &log, &expected), Err(Error::Binding));
    }
    #[test]
    fn synthetic_post_qvl_attributes_and_ppid_refuse() {
        let (claims, log, expected) = synthetic_inputs();
        for (index, bit) in [(0, 1), (0, 0x80), (3, 0x20)] {
            let mut bad = claims.clone();
            if let dcap_qvl::quote::Report::TD10(td) = &mut bad.report {
                td.td_attributes[index] |= bit;
            }
            assert_eq!(assemble(&bad, &log, &expected), Err(Error::Quote));
        }
        let mut bad = claims.clone();
        bad.platform.pck.ppid.pop();
        assert_eq!(assemble(&bad, &log, &expected), Err(Error::Quote));
        let mut other_role = Expected {
            signing: expected.signing,
            receiving: expected.receiving,
            nonce: expected.nonce,
            role: Role::Checker,
        };
        assert_eq!(
            assemble(&claims, &log, &other_role).unwrap().build().role,
            Role::Checker
        );
        other_role.role = Role::KeyService;
        assert_eq!(
            assemble(&claims, &log, &other_role).unwrap().build().role,
            Role::KeyService
        );
    }
    #[test]
    fn synthetic_matching_register_still_requires_exactly_one_compose_event() {
        let (events, register) = log_and_register();
        assert!(replay(&events, &register).is_ok());
        let pos = events
            .iter()
            .position(|e| e.imr == 3 && e.event == "compose-hash")
            .unwrap();
        let mut missing = events.clone();
        missing.remove(pos);
        let register_for = |items: &[TdxEvent]| {
            let runtime: Vec<_> = items
                .iter()
                .filter_map(TdxEvent::to_runtime_event)
                .collect();
            replay_events::<ez_hash::Sha384>(&runtime, None)
        };
        let missing_register = register_for(&missing);
        assert_eq!(replay(&missing, &missing_register), Err(Error::EventLog));
        let mut duplicate = events;
        duplicate.push(duplicate[pos].clone());
        let duplicate_register = register_for(&duplicate);
        assert_eq!(
            replay(&duplicate, &duplicate_register),
            Err(Error::EventLog)
        );
        // Both registers above were recomputed, not taken from a signed quote.
    }
    #[test]
    fn public_qvl_helper_takes_the_caller_policy_and_keeps_both_time_ends() {
        let lenient = |now: u64| {
            QuotePolicy::strict(now)
                .allow_smt(true)
                .allow_dynamic_platform(true)
                .allow_cached_keys(true)
        };
        let claims = quote_claims_with_policy(
            QUOTE,
            COLLATERAL,
            interval(1_751_328_000, 1_751_328_001),
            lenient,
        )
        .unwrap();
        assert!(claims.report.as_td10().is_some());
        // There is no default relaxed policy: plain strict rejects the archived
        // quote, so the caller's builder is what decides.
        assert_eq!(
            quote_claims_with_policy(
                QUOTE,
                COLLATERAL,
                interval(1_751_328_000, 1_751_328_001),
                QuotePolicy::strict,
            )
            .err(),
            Some(Error::Quote)
        );
        // The caller's policy is applied at each end, not only the latest: the
        // earliest instant is valid but the latest is past collateral expiry, so
        // a helper that appraised only the earliest end would wrongly return Ok.
        let spanning = Time {
            earliest: 1_751_328_000,
            latest: claims.earliest_expiration_date + 1,
            max_uncertainty_secs: u64::MAX,
        };
        assert_eq!(
            quote_claims_with_policy(QUOTE, COLLATERAL, spanning, lenient).err(),
            Some(Error::Quote)
        );
        // Bounds stay inside the public helper.
        assert_eq!(
            quote_claims_with_policy(
                &vec![0u8; MAX_INPUT_BYTES + 1],
                COLLATERAL,
                interval(1_751_328_000, 1_751_328_001),
                lenient,
            )
            .err(),
            Some(Error::TooLarge)
        );
        // The helper itself bounds trusted time, so a direct public caller
        // cannot smuggle in an inverted or over-wide interval.
        for uncertain in [interval(1_751_328_001, 1_751_328_000), interval(0, 61)] {
            assert_eq!(
                quote_claims_with_policy(QUOTE, COLLATERAL, uncertain, lenient).err(),
                Some(Error::TimeUncertain)
            );
        }
    }

    #[test]
    fn worker_policy_rejects_real_out_of_date_levels() {
        let claims =
            quote_claims(QUOTE, COLLATERAL, interval(1_751_328_000, 1_751_328_001)).unwrap();
        let now = 1_751_328_000;

        // A real merged `OutOfDate` verdict converges with an `OutOfDate`
        // platform level whose Intel `tcb_date_tag` is in the past. The worker
        // policy still requires UpToDate; only the gateway policy accepts it.
        let mut platform = claims.clone();
        platform.tcb.status = TcbStatus::OutOfDate;
        platform.platform.tcb_level.tcb_status = TcbStatus::OutOfDate;
        assert!(platform.platform.tcb_date_tag < now);
        assert!(worker_policy(now).validate(&platform).is_err());

        // Separately, a real `OutOfDate` QE level with a real past `tcb_date`.
        let mut qe = claims.clone();
        qe.tcb.status = TcbStatus::OutOfDate;
        qe.qe.tcb_level.tcb_status = TcbStatus::OutOfDate;
        assert!(worker_policy(now).validate(&qe).is_err());
    }

    #[test]
    fn shared_td10_check_rejects_debug_migration_and_wrong_ppid_and_compose_is_public() {
        fn td10(claims: &QuoteClaims) -> &dcap_qvl::quote::TDReport10 {
            check_td10(claims).unwrap()
        }
        let claims =
            quote_claims(QUOTE, COLLATERAL, interval(1_751_328_000, 1_751_328_001)).unwrap();
        assert_eq!(td10(&claims).rt_mr3.len(), 48);
        for (index, bit) in [(0, 1u8), (3, 0x20u8)] {
            let mut bad = claims.clone();
            if let dcap_qvl::quote::Report::TD10(td) = &mut bad.report {
                td.td_attributes[index] |= bit;
            }
            assert_eq!(check_td10(&bad).err(), Some(Error::Quote));
        }
        let mut bad = claims.clone();
        bad.platform.pck.ppid.pop();
        assert_eq!(check_td10(&bad).err(), Some(Error::Quote));
        let (events, register) = log_and_register();
        assert!(compose(&serde_json::to_vec(&events).unwrap(), &register).is_ok());
    }

    #[test]
    fn runtime_preimages_digests_composition_and_count_fail_closed() {
        let (events, register) = log_and_register();
        let pos = events
            .iter()
            .position(|e| e.imr == 3 && e.event == "compose-hash")
            .unwrap();
        let mut bad = events.clone();
        bad[pos].event_payload[0] ^= 1;
        assert_eq!(replay(&bad, &register), Err(Error::EventLog));
        let mut bad = events.clone();
        bad[pos].digest[0] ^= 1;
        assert_eq!(replay(&bad, &register), Err(Error::EventLog));
        let mut bad = events.clone();
        bad.push(events[pos].clone());
        assert_eq!(replay(&bad, &register), Err(Error::EventLog));
        let mut bad = events.clone();
        bad.remove(pos);
        assert_eq!(replay(&bad, &register), Err(Error::EventLog));
        let mut bad = events.clone();
        bad[pos].event_type = 123;
        assert_eq!(replay(&bad, &register), Err(Error::EventLog));
        let mut bad = events.clone();
        bad[pos].imr = 2;
        assert_eq!(replay(&bad, &register), Err(Error::EventLog));
        let mut bad = events.clone();
        bad[pos].event_payload = vec![3; MAX_RUNTIME_PAYLOAD + 1];
        assert_eq!(replay(&bad, &register), Err(Error::TooLarge));
        let many = vec![events[pos].clone(); MAX_EVENTS + 1];
        assert_eq!(replay(&many, &register), Err(Error::TooLarge));
    }
}
