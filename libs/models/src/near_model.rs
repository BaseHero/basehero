//! Offline fixed-model attestation verification. Inputs must come from the
//! authenticated gateway OHTTP channel; neither that authentication nor the
//! online Intel collateral/NRAS/JWKS/provenance fetch is done here. The caller
//! owns the fresh nonce, policy snapshot and trusted NVIDIA JWKS origin.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bh_confidential_attestation::{
    Error as AttestationError, MAX_INPUT_BYTES, Time, check_td10, compose, quote_claims_with_policy,
};
use dcap_qvl::{QuoteClaims, QuotePolicy, TcbStatus};
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use serde::Deserialize;

pub const MODEL: &str = "z-ai/glm-5.3-flash";
const NVIDIA_ISSUER: &str = "https://nras.attestation.nvidia.com";
const MAX_CANDIDATES: usize = 32;
const MAX_JWT_BYTES: usize = 16_384;

/// Redacted fixed error kinds; no untrusted body, JWT or key text is returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    TooLarge,
    Encoding,
    Metadata,
    Evidence,
    Time,
    Quote,
    Binding,
    EventLog,
    Configuration,
    Gpu,
    Key,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "near model: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Policy-derived hashes; no outside caller may nominate an arbitrary hash.
/// ```compile_fail
/// let _ = basehero_models::near_model::Expected::new([0; 32], &[[1; 32]]);
/// ```
pub struct Expected<'a> {
    nonce: [u8; 32],
    approved_compose_hashes: std::borrow::Cow<'a, [[u8; 32]]>,
    model: String,
}
impl<'a> Expected<'a> {
    pub(crate) fn from_policy(
        nonce: [u8; 32],
        snapshot: &crate::provider_policy::Snapshot,
        model: &str,
    ) -> Self {
        Self {
            nonce,
            approved_compose_hashes: std::borrow::Cow::Owned(snapshot.model_hashes(model)),
            model: model.to_owned(),
        }
    }
    #[cfg(test)]
    pub fn new(nonce: [u8; 32], approved_compose_hashes: &'a [[u8; 32]]) -> Self {
        Self {
            nonce,
            approved_compose_hashes: std::borrow::Cow::Borrowed(approved_compose_hashes),
            model: MODEL.to_owned(),
        }
    }
}

/// Already-obtained NVIDIA NRAS response token and NVIDIA-origin JWKS, one
/// pair per model candidate (same order as `model_attestations`). The transport
/// must fetch NRAS with that candidate's exact `nvidia_payload`, then obtain
/// JWKS from the pinned NVIDIA HTTPS origin, not from untrusted JWT headers.
pub struct NrasEvidence<'a> {
    pub token: &'a str,
    pub jwks: &'a [u8],
}

/// A model key can only be built by `verify`. Reading bytes does not grant
/// permission to skip transport authentication, authorization or signature
/// verification of a later response.
/// ```compile_fail
/// let _ = basehero_models::near_model::VerifiedModelKey {
///     public_key: [0; 32], compose_sha256: [0; 32],
///     model: String::from("z-ai/glm-5.3-flash"), valid_until: u64::MAX
/// };
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedModelKey {
    public_key: [u8; 32],
    compose_sha256: [u8; 32],
    model: String,
    valid_until: u64,
}
impl VerifiedModelKey {
    pub fn model(&self) -> &str {
        &self.model
    }
    /// Exclusive authenticated minimum of QVL collateral and NRAS validity (Unix seconds).
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
    pub fn compose_sha256(&self) -> &[u8; 32] {
        &self.compose_sha256
    }
    #[cfg(test)]
    pub(crate) fn for_tests(public_key: [u8; 32]) -> Self {
        Self {
            public_key,
            compose_sha256: [0; 32],
            model: MODEL.to_owned(),
            valid_until: u64::MAX,
        }
    }
}

#[derive(Deserialize)]
struct MetadataResponse {
    metadata: Metadata,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    provider_type: String,
    attestation_supported: bool,
}
#[derive(Deserialize)]
struct Reports {
    model_attestations: Vec<Report>,
}
#[derive(Deserialize)]
struct Report {
    request_nonce: String,
    signing_algo: String,
    signing_address: String,
    intel_quote: String,
    report_data: Option<String>,
    event_log: serde_json::Value,
    info: Info,
    nvidia_payload: Option<String>,
    signing_public_key: Option<String>,
    tls_cert_fingerprint: Option<String>,
}
#[derive(Deserialize)]
struct Info {
    tcb_info: TcbInfoWire,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum TcbInfoWire {
    Object(TcbInfo),
    Json(String),
}
#[derive(Deserialize)]
struct TcbInfo {
    app_compose: String,
}

fn map_attestation(error: AttestationError) -> Error {
    match error {
        AttestationError::TooLarge => Error::TooLarge,
        AttestationError::Encoding => Error::Encoding,
        AttestationError::TimeUnavailable | AttestationError::TimeUncertain => Error::Time,
        AttestationError::Quote => Error::Quote,
        AttestationError::Binding => Error::Binding,
        AttestationError::EventLog => Error::EventLog,
    }
}
fn model_policy(now: u64) -> QuotePolicy {
    QuotePolicy::strict(now)
        .allow_smt(true)
        .allow_dynamic_platform(true)
        .allow_cached_keys(true)
}
fn hex_exact<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let mut out = [0u8; N];
    hex::decode_to_slice(value, &mut out).map_err(|_| Error::Encoding)?;
    Ok(out)
}
fn bounded(input: &[u8]) -> Result<(), Error> {
    if input.len() > MAX_INPUT_BYTES {
        Err(Error::TooLarge)
    } else {
        Ok(())
    }
}

/// Check bounded metadata and count all returned reports before fetching any
/// per-candidate collateral or NRAS/JWKS. No returned report is inventory of
/// replicas. The caller must still pass the same bytes to `verify`, which
/// reparses and rechecks them; this preflight grants no authorization.
pub fn preflight_reports(metadata: &[u8], reports: &[u8]) -> Result<usize, Error> {
    Ok(parse_reports(metadata, reports)?.model_attestations.len())
}
fn parse_reports(metadata: &[u8], reports: &[u8]) -> Result<Reports, Error> {
    bounded(metadata)?;
    bounded(reports)?;
    let metadata: MetadataResponse =
        serde_json::from_slice(metadata).map_err(|_| Error::Metadata)?;
    if metadata.metadata.provider_type != "vllm" || !metadata.metadata.attestation_supported {
        return Err(Error::Metadata);
    }
    let reports: Reports = serde_json::from_slice(reports).map_err(|_| Error::Evidence)?;
    if reports.model_attestations.is_empty() || reports.model_attestations.len() > MAX_CANDIDATES {
        return Err(Error::Evidence);
    }
    Ok(reports)
}

/// Verify every candidate, returning no key if any one is bad. Inputs are
/// decoded from NEAR's actual metadata/report JSON layout; QVL collateral and
/// NRAS results are caller-provided, not embedded in that response. This
/// function neither fetches evidence nor checks Sigstore provenance: the
/// approved compose hashes come only from a signed policy snapshot.
pub fn verify(
    metadata: &[u8],
    reports: &[u8],
    collateral: &[&[u8]],
    nras: &[NrasEvidence<'_>],
    expected: &Expected<'_>,
    time: Option<Time>,
) -> Result<Vec<VerifiedModelKey>, Error> {
    verify_with(
        metadata,
        reports,
        collateral,
        nras,
        expected,
        time,
        |quote, collateral| {
            quote_claims_with_policy(quote, collateral, time.ok_or(Error::Time)?, model_policy)
                .map_err(map_attestation)
        },
    )
}

// Private appraisal seam: tests exercise the exact public parse/count/zip/collect
// path using synthetic quote claims. Only `verify` can be called by consumers,
// and it always appraises signed quotes with QVL.
fn verify_with(
    metadata: &[u8],
    reports: &[u8],
    collateral: &[&[u8]],
    nras: &[NrasEvidence<'_>],
    expected: &Expected<'_>,
    time: Option<Time>,
    appraise: impl Fn(&[u8], &[u8]) -> Result<QuoteClaims, Error>,
) -> Result<Vec<VerifiedModelKey>, Error> {
    let reports = parse_reports(metadata, reports)?;
    let count = reports.model_attestations.len();
    if count != collateral.len()
        || count != nras.len()
        || expected.approved_compose_hashes.is_empty()
    {
        return Err(Error::Evidence);
    }
    let time = time.ok_or(Error::Time)?;
    if time.latest < time.earliest || time.latest - time.earliest > time.max_uncertainty_secs {
        return Err(Error::Time);
    }
    reports
        .model_attestations
        .iter()
        .zip(collateral)
        .zip(nras)
        .map(|((report, collateral), nras)| {
            let quote = hex::decode(&report.intel_quote).map_err(|_| Error::Encoding)?;
            let claims = appraise(&quote, collateral)?;
            assemble(report, &claims, nras, expected, time)
        })
        .collect()
}

// Private: tests may alter an already-QVL-appraised archived quote, but no
// production caller can turn unverified claims into a model key.
fn assemble(
    report: &Report,
    claims: &QuoteClaims,
    nras: &NrasEvidence<'_>,
    expected: &Expected<'_>,
    time: Time,
) -> Result<VerifiedModelKey, Error> {
    let td = check_td10(claims).map_err(map_attestation)?;
    if claims.tcb.status != TcbStatus::UpToDate {
        return Err(Error::Quote);
    }
    if report.signing_algo != "ed25519" || report.tls_cert_fingerprint.is_some() {
        return Err(Error::Binding);
    }
    let signer: [u8; 32] = hex_exact(&report.signing_address)?;
    let nonce: [u8; 32] = hex_exact(&report.request_nonce)?;
    if nonce != expected.nonce || td.report_data[..32] != signer || td.report_data[32..] != nonce {
        return Err(Error::Binding);
    }
    if let Some(advertised) = &report.report_data
        && hex_exact::<64>(advertised)? != td.report_data
    {
        return Err(Error::Binding);
    }
    let key: [u8; 32] = hex_exact(report.signing_public_key.as_deref().ok_or(Error::Key)?)?;
    if key != signer {
        return Err(Error::Key);
    }
    let app_compose = match &report.info.tcb_info {
        TcbInfoWire::Object(info) => info.app_compose.clone(),
        TcbInfoWire::Json(json) => {
            serde_json::from_str::<TcbInfo>(json)
                .map_err(|_| Error::Encoding)?
                .app_compose
        }
    };
    bounded(app_compose.as_bytes())?;
    let hash = bh_crypto::sha256(app_compose.as_bytes());
    if td.mr_config_id[0] != 1
        || td.mr_config_id[1..33] != hash
        || !expected.approved_compose_hashes.contains(&hash)
    {
        return Err(Error::Configuration);
    }
    let log = match &report.event_log {
        serde_json::Value::String(value) => value.as_bytes().to_vec(),
        serde_json::Value::Array(_) => {
            serde_json::to_vec(&report.event_log).map_err(|_| Error::Encoding)?
        }
        _ => return Err(Error::EventLog),
    };
    let replayed = compose(&log, &td.rt_mr3).map_err(map_attestation)?;
    if replayed != hash {
        return Err(Error::Configuration);
    }
    let payload = report.nvidia_payload.as_deref().ok_or(Error::Gpu)?;
    bounded(payload.as_bytes())?;
    let payload: serde_json::Value = serde_json::from_str(payload).map_err(|_| Error::Gpu)?;
    let payload_nonce = payload
        .get("nonce")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::Gpu)?;
    if hex_exact::<32>(payload_nonce).map_err(|_| Error::Gpu)? != expected.nonce {
        return Err(Error::Gpu);
    }
    let nras_exp = verify_nras(nras, expected, time)?;
    Ok(VerifiedModelKey {
        public_key: key,
        compose_sha256: hash,
        model: expected.model.clone(),
        valid_until: claims.earliest_expiration_date.min(nras_exp),
    })
}

fn decode_part(raw: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD.decode(raw).map_err(|_| Error::Gpu)
}
fn claim_time(claims: &serde_json::Value, name: &str) -> Result<u64, Error> {
    claims
        .get(name)
        .and_then(serde_json::Value::as_u64)
        .ok_or(Error::Gpu)
}
/// Verify an already-obtained NRAS overall JWT. Do not fetch keys from `jku`,
/// `x5u` or a URL in the token. Only ES384 / P-384 keys in the trusted JWKS
/// are accepted; NRAS detached device claims are not consumed by the SDK.
fn verify_nras(nras: &NrasEvidence<'_>, expected: &Expected<'_>, time: Time) -> Result<u64, Error> {
    if nras.token.len() > MAX_JWT_BYTES || nras.jwks.len() > MAX_INPUT_BYTES {
        return Err(Error::TooLarge);
    }
    let mut parts = nras.token.split('.');
    let (Some(header), Some(claims), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Gpu);
    };
    let header_json: serde_json::Value =
        serde_json::from_slice(&decode_part(header)?).map_err(|_| Error::Gpu)?;
    if header_json.get("alg").and_then(serde_json::Value::as_str) != Some("ES384") {
        return Err(Error::Gpu);
    }
    let kid = header_json
        .get("kid")
        .and_then(serde_json::Value::as_str)
        .ok_or(Error::Gpu)?;
    let jwks: serde_json::Value = serde_json::from_slice(nras.jwks).map_err(|_| Error::Gpu)?;
    let keys = jwks
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .ok_or(Error::Gpu)?;
    // Duplicate key IDs or a mismatched key algorithm are not a trust choice.
    let matches: Vec<_> = keys
        .iter()
        .filter(|key| key.get("kid").and_then(serde_json::Value::as_str) == Some(kid))
        .collect();
    if matches.len() != 1 {
        return Err(Error::Gpu);
    }
    let key = matches[0];
    if key.get("kty").and_then(serde_json::Value::as_str) != Some("EC")
        || key.get("crv").and_then(serde_json::Value::as_str) != Some("P-384")
        || key
            .get("alg")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|a| a != "ES384")
        || key
            .get("use")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|u| u != "sig")
        || key.get("key_ops").is_some_and(|ops| {
            !ops.as_array()
                .is_some_and(|values| values.iter().any(|value| value.as_str() == Some("verify")))
        })
    {
        return Err(Error::Gpu);
    }
    let coordinate = |name| -> Result<[u8; 48], Error> {
        let value = key
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or(Error::Gpu)?;
        decode_part(value)?.try_into().map_err(|_| Error::Gpu)
    };
    let x = coordinate("x")?;
    let y = coordinate("y")?;
    let mut point = [0u8; 97];
    point[0] = 4;
    point[1..49].copy_from_slice(&x);
    point[49..].copy_from_slice(&y);
    let verifier = VerifyingKey::from_sec1_bytes(&point).map_err(|_| Error::Gpu)?;
    let sig = decode_part(signature)?;
    let sig = Signature::from_slice(&sig).map_err(|_| Error::Gpu)?;
    verifier
        .verify(format!("{header}.{claims}").as_bytes(), &sig)
        .map_err(|_| Error::Gpu)?;
    let claims: serde_json::Value =
        serde_json::from_slice(&decode_part(claims)?).map_err(|_| Error::Gpu)?;
    if claims.get("iss").and_then(serde_json::Value::as_str) != Some(NVIDIA_ISSUER)
        || claims
            .get("x-nvidia-overall-att-result")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
        || hex_exact::<32>(
            claims
                .get("eat_nonce")
                .and_then(serde_json::Value::as_str)
                .ok_or(Error::Gpu)?,
        )
        .map_err(|_| Error::Gpu)?
            != expected.nonce
    {
        return Err(Error::Gpu);
    }
    let exp = claim_time(&claims, "exp")?;
    let nbf = claim_time(&claims, "nbf")?;
    let iat = claim_time(&claims, "iat")?;
    // NRAS may mint the nonce-bound JWT within the trusted time interval.
    // Reject claims beyond its far end and expiry at or before that end.
    if iat > time.latest || nbf > time.latest || exp <= time.latest || exp <= iat {
        return Err(Error::Gpu);
    }
    Ok(exp)
}

#[cfg(test)]
#[path = "near_model_tests.rs"]
mod tests;
