//! Local public-request validation and exact-wire issuance. The caller independently
//! pins source, tree, authority role/root and request digest, and owns an immutable
//! snapshot of referenced artifacts. This is not a release approval or custody system.
use std::{
    collections::HashSet,
    fs::{self, File},
    io::Read,
    path::Path,
};

use bh_confidential_policy::{Limits, Policy, PolicyGate, signing_message};
use bh_crypto::{Secret, Sha256, SigningKey, sha256, verify as verify_signature};
use bh_sync::{permit, receipt};
use serde::{Deserialize, Serialize};

use crate::decode_hex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Policy,
    Receipt,
    Permit,
}
impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Receipt => "receipt",
            Self::Permit => "permit",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "policy" => Some(Self::Policy),
            "receipt" => Some(Self::Receipt),
            "permit" => Some(Self::Permit),
            _ => None,
        }
    }
}

/// Values supplied independently by the approval caller; none may be sourced
/// from the untrusted request. Root roles are selected by that caller.
pub struct Expected {
    pub request_sha256: [u8; 32],
    pub public_commit: String,
    pub product_tree: String,
    pub root: [u8; 32],
    pub kind: Kind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    path: String,
    sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bounds {
    max_lifetime_secs: u64,
    max_uncertainty_secs: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Predecessor {
    payload_hex: String,
    signature_hex: String,
}
// A non-Option enum requires the field even when the value is null.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
enum RequiredPredecessor {
    Null(()),
    Value(Predecessor),
}
impl RequiredPredecessor {
    fn as_ref(&self) -> Option<&Predecessor> {
        match self {
            Self::Null(()) => None,
            Self::Value(value) => Some(value),
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Initial,
    Advance,
    Retry,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum Operation {
    Policy {
        payload_hex: String,
        generation: u64,
        limits: Bounds,
        mode: Mode,
        predecessor: RequiredPredecessor,
    },
    Receipt {
        leaf_public_key: String,
    },
    Permit {
        leaf_public_key: String,
    },
}
impl Operation {
    fn kind(&self) -> Kind {
        match self {
            Self::Policy { .. } => Kind::Policy,
            Self::Receipt { .. } => Kind::Receipt,
            Self::Permit { .. } => Kind::Permit,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    format: u32,
    public_commit: String,
    product_tree: String,
    root: String,
    artifacts: Vec<Artifact>,
    operation: Operation,
}

/// No raw input, dependency diagnostic, secret or file path in errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidRequest,
    Mismatch,
    InvalidArtifact,
    InvalidPolicy,
    InvalidSignature,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidRequest => "invalid authorization request",
            Self::Mismatch => "authorization expectation mismatch",
            Self::InvalidArtifact => "invalid authorization artifact",
            Self::InvalidPolicy => "invalid authorization policy",
            Self::InvalidSignature => "invalid authorization signature",
        })
    }
}
impl std::error::Error for Error {}

/// Opaque validated input retaining exact request and policy bytes, not artifact bodies.
pub struct CheckedRequest {
    raw: Vec<u8>,
    digest: [u8; 32],
    request: Request,
    root: [u8; 32],
    policy: Option<Vec<u8>>,
    leaf: Option<[u8; 32]>,
}
impl CheckedRequest {
    pub fn raw_request(&self) -> &[u8] {
        &self.raw
    }
    pub fn summary(&self) -> String {
        let mut text = format!(
            "request sha256: {}\npublic commit: {}\nproduct tree: {}\nroot: {}\noperation: {}\n",
            hex(&self.digest),
            self.request.public_commit,
            self.request.product_tree,
            self.request.root,
            self.request.operation.kind().as_str()
        );
        for item in &self.request.artifacts {
            text.push_str(&format!(
                "artifact: {} sha256: {}\n",
                serde_json::to_string(&item.path).expect("UTF-8 artifact path"),
                item.sha256
            ));
        }
        match &self.request.operation {
            Operation::Policy {
                generation,
                limits,
                mode,
                predecessor,
                ..
            } => {
                let policy: Policy =
                    serde_json::from_slice(self.policy.as_ref().expect("checked policy"))
                        .expect("checked policy");
                text.push_str(&format!("generation: {generation}\nmode: {mode:?}\npredecessor: {}\nissued_at: {}\nexpires_at: {}\nmax_lifetime_secs: {}\nmax_uncertainty_secs: {}\nbuilds: {}\nmachines: {}\npayload sha256: {}\n",
                    if predecessor.as_ref().is_some() {"present"} else {"none"}, policy.issued_at, policy.expires_at, limits.max_lifetime_secs, limits.max_uncertainty_secs, policy.builds.len(), policy.machines.len(), hex(&sha256(self.policy.as_ref().expect("checked policy")))));
                // The full public fields are shown for human review, not verified as hardware.
                text.push_str(&format!(
                    "policy: {}\n",
                    String::from_utf8_lossy(self.policy.as_ref().expect("checked policy"))
                ));
            }
            Operation::Receipt { leaf_public_key } | Operation::Permit { leaf_public_key } => {
                text.push_str(&format!("leaf public key: {leaf_public_key}\n"));
            }
        }
        text
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn artifact_hash(root: &Path, item: &Artifact) -> Result<(), Error> {
    let path = &item.path;
    if path.is_empty()
        || path.contains(['\\', ':'])
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::InvalidArtifact);
    }
    let desired = decode_hex::<32>(&item.sha256).ok_or(Error::InvalidArtifact)?;
    if !fs::symlink_metadata(root)
        .map_err(|_| Error::InvalidArtifact)?
        .file_type()
        .is_dir()
    {
        return Err(Error::InvalidArtifact);
    }
    let mut current = root.to_path_buf();
    let parts: Vec<_> = path.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        current.push(part);
        let kind = fs::symlink_metadata(&current)
            .map_err(|_| Error::InvalidArtifact)?
            .file_type();
        if (index + 1 == parts.len() && !kind.is_file())
            || (index + 1 != parts.len() && !kind.is_dir())
        {
            return Err(Error::InvalidArtifact);
        }
    }
    let mut file = File::open(current).map_err(|_| Error::InvalidArtifact)?;
    if !file
        .metadata()
        .map_err(|_| Error::InvalidArtifact)?
        .is_file()
    {
        return Err(Error::InvalidArtifact);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer).map_err(|_| Error::InvalidArtifact)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    if digest.finalize() != desired {
        return Err(Error::InvalidArtifact);
    }
    Ok(())
}
fn validate_policy(
    payload: &[u8],
    generation: u64,
    limits: &Bounds,
    mode: Mode,
    predecessor: Option<&Predecessor>,
    root: [u8; 32],
) -> Result<(), Error> {
    let bounds = Limits {
        max_lifetime_secs: limits.max_lifetime_secs,
        max_uncertainty_secs: limits.max_uncertainty_secs,
    };
    signing_message(payload).map_err(|_| Error::InvalidPolicy)?;
    let policy: Policy = serde_json::from_slice(payload).map_err(|_| Error::InvalidPolicy)?;
    policy
        .validate_structure(bounds)
        .map_err(|_| Error::InvalidPolicy)?;
    if policy.generation != generation {
        return Err(Error::InvalidPolicy);
    }
    match (mode, predecessor) {
        (Mode::Initial, None) if generation == 1 => Ok(()),
        (Mode::Advance | Mode::Retry, Some(previous)) => {
            let bytes = decode_payload(&previous.payload_hex)?;
            let signature =
                decode_hex::<64>(&previous.signature_hex).ok_or(Error::InvalidPolicy)?;
            let mut gate = PolicyGate::new(root, bounds).map_err(|_| Error::InvalidPolicy)?;
            gate.push(&bytes, &signature)
                .map_err(|_| Error::InvalidPolicy)?;
            let prior: Policy = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidPolicy)?;
            prior
                .validate_structure(bounds)
                .map_err(|_| Error::InvalidPolicy)?;
            if (matches!(mode, Mode::Advance) && generation > prior.generation)
                || (matches!(mode, Mode::Retry)
                    && generation == prior.generation
                    && payload == bytes)
            {
                Ok(())
            } else {
                Err(Error::InvalidPolicy)
            }
        }
        _ => Err(Error::InvalidPolicy),
    }
}
fn decode_payload(value: &str) -> Result<Vec<u8>, Error> {
    if value.len() > 65536 * 2
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::InvalidPolicy);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| {
            u8::from_str_radix(
                std::str::from_utf8(chunk).map_err(|_| Error::InvalidPolicy)?,
                16,
            )
            .map_err(|_| Error::InvalidPolicy)
        })
        .collect()
}

/// Checks independently pinned identities and exact bytes before any result.
pub fn inspect(
    raw_request: &[u8],
    expected: &Expected,
    artifacts: &Path,
) -> Result<CheckedRequest, Error> {
    if raw_request.len() > 1024 * 1024
        || !commit(&expected.public_commit)
        || !commit(&expected.product_tree)
    {
        return Err(Error::InvalidRequest);
    }
    let digest = sha256(raw_request);
    if digest != expected.request_sha256 {
        return Err(Error::Mismatch);
    }
    let req: Request = serde_json::from_slice(raw_request).map_err(|_| Error::InvalidRequest)?;
    if req.format != 1
        || !commit(&req.public_commit)
        || !commit(&req.product_tree)
        || decode_hex::<32>(&req.root).is_none()
    {
        return Err(Error::InvalidRequest);
    }
    if req.public_commit != expected.public_commit
        || req.product_tree != expected.product_tree
        || decode_hex::<32>(&req.root) != Some(expected.root)
        || req.operation.kind() != expected.kind
    {
        return Err(Error::Mismatch);
    }
    let mut paths = HashSet::new();
    for item in &req.artifacts {
        if !paths.insert(&item.path) {
            return Err(Error::InvalidArtifact);
        }
        artifact_hash(artifacts, item)?;
    }
    let (policy, leaf) = match &req.operation {
        Operation::Policy {
            payload_hex,
            generation,
            limits,
            mode,
            predecessor,
        } => {
            let bytes = decode_payload(payload_hex)?;
            validate_policy(
                &bytes,
                *generation,
                limits,
                *mode,
                predecessor.as_ref(),
                expected.root,
            )?;
            (Some(bytes), None)
        }
        Operation::Receipt { leaf_public_key } | Operation::Permit { leaf_public_key } => (
            None,
            Some(decode_hex::<32>(leaf_public_key).ok_or(Error::InvalidRequest)?),
        ),
    };
    Ok(CheckedRequest {
        raw: raw_request.to_vec(),
        digest,
        request: req,
        root: expected.root,
        policy,
        leaf,
    })
}

/// Public result: provenance wrapper is NOT in the existing wire signature domain.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAuthorization {
    pub format: u32,
    pub request_sha256: String,
    pub value: SignedValue,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum SignedValue {
    Policy {
        payload_hex: String,
        signature_hex: String,
    },
    Receipt {
        certificate_hex: String,
    },
    Permit {
        certificate_hex: String,
    },
}

pub fn sign(request: &CheckedRequest, seed: &Secret<32>) -> Result<SignedAuthorization, Error> {
    let key = SigningKey::from_seed(seed);
    if key.public() != request.root {
        return Err(Error::Mismatch);
    }
    let value = match request.request.operation.kind() {
        Kind::Policy => {
            let payload = request.policy.as_ref().ok_or(Error::InvalidRequest)?;
            SignedValue::Policy {
                payload_hex: hex(payload),
                signature_hex: hex(
                    &key.sign(&signing_message(payload).map_err(|_| Error::InvalidPolicy)?)
                ),
            }
        }
        Kind::Receipt => SignedValue::Receipt {
            certificate_hex: hex(&receipt::certify(
                &key,
                request.leaf.ok_or(Error::InvalidRequest)?,
            )),
        },
        Kind::Permit => SignedValue::Permit {
            certificate_hex: hex(&permit::certify(
                &key,
                request.leaf.ok_or(Error::InvalidRequest)?,
            )),
        },
    };
    let result = SignedAuthorization {
        format: 1,
        request_sha256: hex(&request.digest),
        value,
    };
    verify(request, &result)?;
    Ok(result)
}

pub fn verify(request: &CheckedRequest, signed: &SignedAuthorization) -> Result<(), Error> {
    if signed.format != 1 || decode_hex::<32>(&signed.request_sha256) != Some(request.digest) {
        return Err(Error::Mismatch);
    }
    match (&request.request.operation, &signed.value) {
        (
            Operation::Policy { .. },
            SignedValue::Policy {
                payload_hex,
                signature_hex,
            },
        ) => {
            let payload = request.policy.as_ref().ok_or(Error::InvalidRequest)?;
            if payload_hex != &hex(payload) {
                return Err(Error::Mismatch);
            }
            let signature = decode_hex::<64>(signature_hex).ok_or(Error::InvalidSignature)?;
            verify_signature(
                &request.root,
                &signing_message(payload).map_err(|_| Error::InvalidPolicy)?,
                &signature,
            )
            .map_err(|_| Error::InvalidSignature)?;
            // Real gate verifies signature, framing and strict policy decoding.
            PolicyGate::new(
                request.root,
                match &request.request.operation {
                    Operation::Policy { limits, .. } => Limits {
                        max_lifetime_secs: limits.max_lifetime_secs,
                        max_uncertainty_secs: limits.max_uncertainty_secs,
                    },
                    _ => unreachable!(),
                },
            )
            .map_err(|_| Error::InvalidPolicy)?
            .push(payload, &signature)
            .map_err(|_| Error::InvalidSignature)?;
        }
        (Operation::Receipt { .. }, SignedValue::Receipt { certificate_hex }) => {
            let certificate = decode_hex::<{ receipt::CERTIFICATE_LEN }>(certificate_hex)
                .ok_or(Error::InvalidSignature)?;
            receipt::verify_certificate(&request.root, &certificate)
                .map_err(|_| Error::InvalidSignature)?;
            if certificate[34..66] != request.leaf.ok_or(Error::InvalidRequest)? {
                return Err(Error::Mismatch);
            }
        }
        (Operation::Permit { .. }, SignedValue::Permit { certificate_hex }) => {
            let certificate = decode_hex::<{ receipt::CERTIFICATE_LEN }>(certificate_hex)
                .ok_or(Error::InvalidSignature)?;
            permit::verify_certificate(&request.root, &certificate)
                .map_err(|_| Error::InvalidSignature)?;
            if certificate[34..66] != request.leaf.ok_or(Error::InvalidRequest)? {
                return Err(Error::Mismatch);
            }
        }
        _ => return Err(Error::Mismatch),
    }
    Ok(())
}
