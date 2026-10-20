//! Verification of release metadata and the exact artifact before desktop installation.
//!
//! A caller supplies the app-embedded release key, expected platform/channel and
//! installed version. No URL, filename, HTTP header or updater feed is an authority
//! for those values. The file reader must refer to the same staged file later
//! installed; keep it private and immutable between verification and installation.
//! Local SQLite compatibility belongs to `bh-core::check_local_data_version` and
//! `bh-storage::DeviceDatabase::open`, not to release metadata.

#[cfg(feature = "authorization-tools")]
pub mod authorization;
pub mod download;
// Linux builds carry the same exchange so the app's update coordinator tests
// run real bundle replacement on fixture directories; only macOS wires it.
#[cfg(any(target_os = "macos", target_os = "linux", test))]
pub mod mac_installer;

use std::io::{self, Read};

use bh_crypto::{Sha256, verify};
use serde::{Deserialize, Serialize};

const DOMAIN: &[u8] = b"BaseHero release v1\0";

/// One signed artifact, not an unauthenticated feed's description of a release.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRelease {
    pub metadata: Metadata,
    /// Lowercase hex encoding of an Ed25519 signature over `Metadata::signing_bytes`.
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    /// Strictly increasing integer for a given platform and channel.
    pub version: u64,
    pub platform: String,
    pub channel: String,
    /// Public source commit named by this artifact (40 or 64 lowercase hex digits).
    pub source_commit: String,
    /// Published artifact basename, not a path or download URL.
    pub file_name: String,
    /// SHA-256 of the exact published file, in lowercase hex.
    pub sha256: String,
    pub whats_new: String,
}

impl Metadata {
    /// Stable, domain-separated byte encoding shared by the release signer and
    /// verifier. The encoding is independent of JSON order and formatting.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, ReleaseError> {
        if self.version == 0
            || !token(&self.platform)
            || !token(&self.channel)
            || (!lower_hex(&self.source_commit, 40) && !lower_hex(&self.source_commit, 64))
            || !safe_basename(&self.file_name)
            || !lower_hex(&self.sha256, 64)
            || self.whats_new.len() > 64 * 1024
        {
            return Err(ReleaseError::InvalidMetadata);
        }
        let mut bytes = Vec::with_capacity(DOMAIN.len() + 128 + self.whats_new.len());
        bytes.extend_from_slice(DOMAIN);
        bytes.extend_from_slice(&self.version.to_be_bytes());
        for field in [
            self.platform.as_bytes(),
            self.channel.as_bytes(),
            self.source_commit.as_bytes(),
            self.file_name.as_bytes(),
            self.sha256.as_bytes(),
            self.whats_new.as_bytes(),
        ] {
            bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
            bytes.extend_from_slice(field);
        }
        Ok(bytes)
    }
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn safe_basename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

fn lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Decode a canonical lowercase hex value of exactly N bytes.
pub fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if !lower_hex(value, 2 * N) {
        return None;
    }
    let mut result = [0; N];
    for (index, byte) in result.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[2 * index..2 * index + 2], 16).ok()?;
    }
    Some(result)
}

/// Expectations supplied by the already installed application, never by the feed.
pub struct VerifyFor<'a> {
    pub release_key: &'a [u8; 32],
    pub platform: &'a str,
    pub channel: &'a str,
    pub running_version: u64,
}

#[derive(Debug)]
pub enum ReleaseError {
    InvalidMetadata,
    BadSignature,
    WrongPlatform,
    WrongChannel,
    NotNewer,
    HashMismatch,
    Read(io::Error),
}

impl std::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::InvalidMetadata => "invalid release metadata",
                Self::BadSignature => "release signature not trusted",
                Self::WrongPlatform => "release is for another platform",
                Self::WrongChannel => "release is for another channel",
                Self::NotNewer => "release is not newer",
                Self::HashMismatch => "release file does not match signed hash",
                Self::Read(_) => "cannot read release file",
            }
        )
    }
}

impl std::error::Error for ReleaseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(e) => Some(e),
            _ => None,
        }
    }
}

/// A signed description that can safely be shown before an update download.
/// It does not attest that the file later downloaded matches the signed hash.
pub struct AvailableRelease {
    metadata: Metadata,
}

impl AvailableRelease {
    pub fn version(&self) -> u64 {
        self.metadata.version
    }
    pub fn whats_new(&self) -> &str {
        &self.metadata.whats_new
    }

    /// Call only on the staged file obtained *after* the person's Install update
    /// choice. The caller must keep the verified file immutable until installation.
    pub fn verify_staged(&self, mut artifact: impl Read) -> Result<VerifiedRelease, ReleaseError> {
        let wanted =
            decode_hex::<32>(&self.metadata.sha256).ok_or(ReleaseError::InvalidMetadata)?;
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = match artifact.read(&mut buffer) {
                Ok(count) => count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(ReleaseError::Read(error)),
            };
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
        }
        if digest.finalize() != wanted {
            return Err(ReleaseError::HashMismatch);
        }
        Ok(VerifiedRelease {
            version: self.metadata.version,
            whats_new: self.metadata.whats_new.clone(),
        })
    }
}

/// A verified description. It does not attest that an installer later uses the
/// same file; the platform adapter must preserve that identity until install.
pub struct VerifiedRelease {
    version: u64,
    whats_new: String,
}

impl VerifiedRelease {
    pub fn version(&self) -> u64 {
        self.version
    }
    pub fn whats_new(&self) -> &str {
        &self.whats_new
    }
}

/// Authenticate the announcement before showing What's new. Never download
/// merely because a new version was found; only the app's Install update action
/// should start `AvailableRelease::verify_staged` on the downloaded file.
pub fn check_available(
    release: &SignedRelease,
    expected: VerifyFor<'_>,
) -> Result<AvailableRelease, ReleaseError> {
    let bytes = release.metadata.signing_bytes()?;
    let signature = decode_hex::<64>(&release.signature).ok_or(ReleaseError::InvalidMetadata)?;
    verify(expected.release_key, &bytes, &signature).map_err(|_| ReleaseError::BadSignature)?;
    if release.metadata.platform != expected.platform {
        return Err(ReleaseError::WrongPlatform);
    }
    if release.metadata.channel != expected.channel {
        return Err(ReleaseError::WrongChannel);
    }
    if release.metadata.version <= expected.running_version {
        return Err(ReleaseError::NotNewer);
    }

    Ok(AvailableRelease {
        metadata: release.metadata.clone(),
    })
}

/// Verifies both BaseHero's signature and the bytes of a staged artifact.
/// Never treat a successful feed check alone as permission to install.
pub fn verify_release(
    release: &SignedRelease,
    artifact: impl Read,
    expected: VerifyFor<'_>,
) -> Result<VerifiedRelease, ReleaseError> {
    check_available(release, expected)?.verify_staged(artifact)
}
