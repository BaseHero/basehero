//! Offline NEAR Cloud Gateway attestation verification.
//!
//! This adapter verifies the gateway's Intel TDX quote and dstack RTMR3 event log
//! with NEAR's own report-data and measured-configuration conventions, then is
//! the **only** constructor of [`GatewaySigner`], which in turn is the only key
//! [`crate::near_route::verify_key_config`] accepts. It binds the Ed25519 OHTTP
//! key-configuration signer to the quote-verified service identity.
//!
//! It performs no network I/O, fetches no collateral and reads no wall clock:
//! the caller supplies bounded raw evidence, a verifier-owned fresh nonce and a
//! trusted time interval. Model metadata, CPU/GPU/NRAS evidence, transport and
//! accounting are later increments.
//!
//! NEAR's gateway report-data layout is `signer (32) || nonce (32)` (the SDK's
//! `verify_report_data_binding`, used when no SPKI fingerprint is requested). It
//! is deliberately not the worker verifier's domain-separated `report_data`.
//! The TCB policy here accepts `OutOfDate` for this gateway by product policy;
//! it records the status and never turns a failed appraisal into success.

use crate::near_route::{self, GatewayKeyConfig, NearError};
use bh_confidential_attestation::{
    Error as AttestationError, MAX_INPUT_BYTES, Time, check_td10, compose, quote_claims_with_policy,
};
use core::time::Duration;
use dcap_qvl::{QuoteClaims, QuotePolicy, TcbStatus};

/// Gateway service signing identity observed in NEAR's attestation report for
/// the reviewed deployment: the Ed25519 public key the quote must bind and the
/// OHTTP key configuration must be signed by. Archived test fixture only;
/// production expectations come exclusively from signed policy.
#[cfg(test)]
pub const GATEWAY_SIGNING_IDENTITY: [u8; 32] = [
    0x40, 0x59, 0x9f, 0xb2, 0x84, 0xf4, 0x39, 0x53, 0xbb, 0x35, 0x6b, 0x09, 0x08, 0x0f, 0xd8, 0x03,
    0xc9, 0x60, 0xfc, 0x10, 0x28, 0x5a, 0xd9, 0x0e, 0xca, 0x46, 0x2c, 0xa7, 0x11, 0xad, 0x4a, 0xcb,
];
/// SHA-256 of the measured dstack app-compose observed in NEAR's attestation
/// report for the reviewed deployment. Archived test fixture only;
/// production expectations come exclusively from signed policy.
#[cfg(test)]
pub const GATEWAY_COMPOSE_SHA256: [u8; 32] = [
    0x41, 0xe1, 0x8f, 0x38, 0x97, 0x8b, 0x03, 0x14, 0x31, 0xdf, 0xc8, 0xa4, 0xfc, 0xf6, 0xd8, 0xc3,
    0x8d, 0xa6, 0x2b, 0x1b, 0x09, 0x3f, 0xd1, 0xd0, 0xe3, 0x9e, 0x26, 0xee, 0x6f, 0xad, 0x03, 0x0c,
];
/// Test-fixture container image digest; not a production approval.
#[cfg(test)]
pub const GATEWAY_IMAGE: &str =
    "nearaidev/cloud-api@sha256:79ea161fe2cef0dd4b17c2014f9276056b077469f8b97da15f410a9778aaf45c";
/// Archived source commit for test fixtures; not a deployment approval or device pin.
#[cfg(test)]
pub const GATEWAY_SOURCE_COMMIT: &str = "e8a534ffba3edf7f51bfe8b207ccdbb2f284a491";

/// All failures are fixed, content-free kinds; never include evidence bytes,
/// decrypted content, upstream text or caller input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    Encoding,
    TimeUnavailable,
    TimeUncertain,
    Quote,
    Binding,
    EventLog,
    Configuration,
    KeyConfig,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "near gateway: {self:?}")
    }
}
impl std::error::Error for Error {}

/// A gateway Ed25519 signing key whose bytes the verified quote bound. Only
/// [`verify`] constructs it; there is no public byte constructor, so a caller
/// cannot fabricate the trusted signer for an OHTTP key configuration. The raw
/// key field is closed to production callers and must not compile outside the
/// crate:
///
/// ```compile_fail
/// use basehero_models::near_gateway::GatewaySigner;
/// let _ = GatewaySigner { public_key: [0u8; 32] };
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewaySigner {
    public_key: [u8; 32],
}
impl GatewaySigner {
    /// The raw Ed25519 public key. Reading is public; constructing is not.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    #[cfg(test)]
    pub(crate) fn for_tests(public_key: [u8; 32]) -> Self {
        Self { public_key }
    }
}

/// Verifier-owned expected complete pairs from a signed policy and a fresh
/// nonce. No production caller can nominate an arbitrary pair.
///
/// ```compile_fail
/// use basehero_models::near_gateway::Expected;
/// let _ = Expected { pairs: vec![([0u8; 32], [1u8; 32])], nonce: [0u8; 32] };
/// ```
/// ```compile_fail
/// let _ = basehero_models::near_gateway::Expected::from_policy(vec![([0; 32], [1; 32])], [0; 32]);
/// ```
/// ```compile_fail
/// let _ = basehero_models::near_gateway::Expected::pinned([0; 32]);
/// ```
pub struct Expected {
    pairs: Vec<([u8; 32], [u8; 32])>,
    nonce: [u8; 32],
}
impl Expected {
    pub(crate) fn from_policy(pairs: Vec<([u8; 32], [u8; 32])>, nonce: [u8; 32]) -> Self {
        Self { pairs, nonce }
    }
    #[cfg(test)]
    pub(crate) fn has_pair(&self, signer: [u8; 32], compose: [u8; 32]) -> bool {
        self.pairs.contains(&(signer, compose))
    }
    /// Archived deployment tuple is only a test fixture.
    #[cfg(test)]
    pub fn pinned(nonce: [u8; 32]) -> Self {
        Self::for_tests(GATEWAY_SIGNING_IDENTITY, nonce, GATEWAY_COMPOSE_SHA256)
    }
    #[cfg(test)]
    pub(crate) fn for_tests(signer: [u8; 32], nonce: [u8; 32], compose_sha256: [u8; 32]) -> Self {
        Self::from_policy(vec![(signer, compose_sha256)], nonce)
    }
}

/// Bounded raw gateway evidence. It is untrusted; this adapter never fetches it
/// and never accepts a peer's TLS assertion in its place. The caller must request
/// the gateway report without a TLS SPKI fingerprint: a report with one uses
/// NEAR's `sha256(signer || spki)` report-data layout, which this adapter does
/// not support and which fails the binding closed.
pub struct Evidence<'a> {
    pub quote: &'a [u8],
    pub collateral: &'a [u8],
    pub event_log: &'a [u8],
    pub app_compose: &'a [u8],
    /// The nonce the attested response advertised; must equal the verifier's.
    pub advertised_nonce: [u8; 32],
    /// NEAR's `reportedQuoteData`, when present; must equal the quoted bytes.
    pub advertised_report_data: Option<[u8; 64]>,
    /// The `ohttp_attestation.signing_key`; must equal the quote-bound signer.
    pub ohttp_signing_key: [u8; 32],
    pub ohttp_key_config: &'a [u8],
    pub ohttp_signature: &'a [u8],
}

/// The verified gateway identity and OHTTP recipient. Only [`verify`] builds it;
/// it is not a readiness, authorization or billing token.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedGateway {
    signer: GatewaySigner,
    key_config: GatewayKeyConfig,
    tcb_status: TcbStatus,
    advisory_ids: Vec<String>,
    compose_sha256: [u8; 32],
    valid_until: u64,
}
impl VerifiedGateway {
    /// Exclusive authenticated QVL collateral validity end (Unix seconds).
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
    pub fn signer(&self) -> &GatewaySigner {
        &self.signer
    }
    pub fn key_config(&self) -> &GatewayKeyConfig {
        &self.key_config
    }
    /// The actual QVL verdict, including `OutOfDate` under product policy.
    pub fn tcb_status(&self) -> TcbStatus {
        self.tcb_status
    }
    pub fn advisory_ids(&self) -> &[String] {
        &self.advisory_ids
    }
    pub fn out_of_date(&self) -> bool {
        self.tcb_status == TcbStatus::OutOfDate
    }
    /// The `compose-hash` replayed from the dstack log.
    pub fn compose_sha256(&self) -> &[u8; 32] {
        &self.compose_sha256
    }
}

/// NEAR's gateway TCB policy: the merged `OutOfDate` status and the platform
/// flags are accepted for this gateway by product policy. dcap-qvl derives a
/// merged `OutOfDate` verdict from an `OutOfDate` platform or QE level, whose
/// Intel `tcb_date` is always in the past, so with dcap-qvl 0.7.0's default zero
/// grace `allow_status(OutOfDate)` would reject every real quote; the SDK's
/// dcap-qvl 0.6.6 path applies no freshness bound and this gateway sets none.
/// The platform flags are accepted, as the reference SDK does. `Revoked` is
/// rejected unconditionally by dcap-qvl and has no policy bit.
fn gateway_policy(now: u64) -> QuotePolicy {
    QuotePolicy::strict(now)
        .allow_status(TcbStatus::OutOfDate)
        .platform_grace_period(Duration::from_secs(u64::MAX))
        .qe_grace_period(Duration::from_secs(u64::MAX))
        .allow_smt(true)
        .allow_dynamic_platform(true)
        .allow_cached_keys(true)
}

fn trusted_time(time: Option<Time>) -> Result<Time, Error> {
    let time = time.ok_or(Error::TimeUnavailable)?;
    if time.latest < time.earliest || time.latest - time.earliest > time.max_uncertainty_secs {
        return Err(Error::TimeUncertain);
    }
    Ok(time)
}

fn map_attestation(error: AttestationError) -> Error {
    match error {
        AttestationError::TooLarge => Error::TooLarge,
        AttestationError::Encoding => Error::Encoding,
        AttestationError::TimeUnavailable => Error::TimeUnavailable,
        AttestationError::TimeUncertain => Error::TimeUncertain,
        AttestationError::Quote => Error::Quote,
        AttestationError::Binding => Error::Binding,
        AttestationError::EventLog => Error::EventLog,
    }
}

fn map_key_config(error: NearError) -> Error {
    match error {
        NearError::InvalidSigner | NearError::InvalidKeyConfig | NearError::Unsupported => {
            Error::KeyConfig
        }
        NearError::TooLarge => Error::TooLarge,
        NearError::InvalidRequest
        | NearError::Encryption
        | NearError::Decryption
        | NearError::Response => Error::KeyConfig,
    }
}

/// Verify the gateway quote, nonce/report-data binding, measured configuration
/// and dstack RTMR3 replay, then the OHTTP key configuration against the
/// resulting signer. Every error is fixed and content-free.
pub fn verify(
    evidence: Evidence<'_>,
    expected: &Expected,
    time: Option<Time>,
) -> Result<VerifiedGateway, Error> {
    let time = trusted_time(time)?;
    let claims =
        quote_claims_with_policy(evidence.quote, evidence.collateral, time, gateway_policy)
            .map_err(map_attestation)?;
    assemble(&claims, &evidence, expected)
}

// Accept only claims returned by the public helper; private so there is no
// consumer-facing route from a parsed or self-asserted quote to a signer.
fn assemble(
    claims: &QuoteClaims,
    evidence: &Evidence<'_>,
    expected: &Expected,
) -> Result<VerifiedGateway, Error> {
    let td = check_td10(claims).map_err(map_attestation)?;

    // NEAR's `verify_reported_nonce` and `verify_advertised_report_data`.
    if evidence.advertised_nonce != expected.nonce {
        return Err(Error::Binding);
    }
    if td.report_data[32..] != expected.nonce || evidence.ohttp_signing_key != td.report_data[..32]
    {
        return Err(Error::Binding);
    }
    if !expected
        .pairs
        .iter()
        .any(|(signer, _)| signer == &td.report_data[..32])
    {
        return Err(Error::Binding);
    }
    let pair = expected.pairs.iter().find(|(signer, compose)| {
        signer == &td.report_data[..32] && compose == &td.mr_config_id[1..33]
    });
    let Some((signer_key, compose_hash)) = pair else {
        return Err(Error::Configuration);
    };
    if let Some(advertised) = evidence.advertised_report_data
        && advertised != td.report_data
    {
        return Err(Error::Binding);
    }

    // NEAR's `verify_app_compose_mrconfig_binding`, pinned to the reviewed
    // deployment's measured app-compose rather than any caller-supplied bytes:
    // version 1 and the app-compose SHA-256 must both equal the pin. The real
    // app-compose bytes are not stored, so this binds the supplied bytes without
    // trusting them to be the reviewed compose.
    if evidence.app_compose.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    if td.mr_config_id[0] != 1
        || td.mr_config_id[1..33] != *compose_hash
        || bh_crypto::sha256(evidence.app_compose) != *compose_hash
    {
        return Err(Error::Configuration);
    }

    // Reuse the shared bounded dstack replay and compose-hash extraction, then
    // bind the replayed value to the quoted `mr_config_id` (and so to the pin).
    // `mr_config_id` is supplied by the host, while `compose-hash` is extended
    // by the measured guest, so the replay is the stronger of the two.
    let compose_sha256 = compose(evidence.event_log, &td.rt_mr3).map_err(map_attestation)?;
    if compose_sha256 != td.mr_config_id[1..33] {
        return Err(Error::Configuration);
    }

    // NEAR's `verify_ohttp_key_config` signer check, then the Ed25519 signature
    // over the raw bytes against the quote-bound identity only.
    if evidence.ohttp_signing_key != *signer_key {
        return Err(Error::Binding);
    }
    let signer = GatewaySigner {
        public_key: *signer_key,
    };
    let key_config =
        near_route::verify_key_config(evidence.ohttp_key_config, evidence.ohttp_signature, &signer)
            .map_err(map_key_config)?;

    Ok(VerifiedGateway {
        signer,
        key_config,
        tcb_status: claims.tcb.status,
        advisory_ids: claims.tcb.advisory_ids.clone(),
        compose_sha256,
        valid_until: claims.earliest_expiration_date,
    })
}

#[cfg(test)]
#[path = "near_gateway_tests.rs"]
mod tests;
