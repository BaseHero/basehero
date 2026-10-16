use std::io::{self, Cursor, Read, Write};

use bh_crypto::{Secret, SigningKey, sha256};
use bh_release::{
    Metadata, ReleaseError, SignedRelease, VerifyFor, check_available, download::StagedArtifact,
    verify_release,
};

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_seed(&Secret::<32>::from_slice(&[seed; 32]).unwrap())
}

fn signed_release(file: &[u8]) -> ([u8; 32], SignedRelease) {
    let key = signing_key(7);
    let metadata = Metadata {
        version: 12,
        platform: "macos-aarch64".into(),
        channel: "stable".into(),
        source_commit: "abcdef0123456789abcdef0123456789abcdef01".into(),
        file_name: "BaseHero-macos-aarch64.dmg".into(),
        sha256: hex(&sha256(file)),
        whats_new: "Improved notes".into(),
    };
    let signature = key.sign(&metadata.signing_bytes().unwrap());
    (
        key.public(),
        SignedRelease {
            metadata,
            signature: hex(&signature),
        },
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn bytes(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn expected<'a>(key: &'a [u8; 32]) -> VerifyFor<'a> {
    VerifyFor {
        release_key: key,
        platform: "macos-aarch64",
        channel: "stable",
        running_version: 11,
    }
}

#[test]
fn a_held_file_is_staged_only_when_it_matches_the_signed_hash() {
    let file = b"actual installer bytes";
    let (key, release) = signed_release(file);
    let available = check_available(&release, expected(&key)).unwrap();
    // Left positioned at its end: staging hashes and then reads from the start.
    let mut held = tempfile::tempfile().unwrap();
    held.write_all(file).unwrap();
    let mut staged = StagedArtifact::verify(held, &available).unwrap();
    assert_eq!(staged.version(), 12);
    let mut read = Vec::new();
    staged.reader().read_to_end(&mut read).unwrap();
    assert_eq!(read, file);

    let mut altered = tempfile::tempfile().unwrap();
    altered.write_all(b"actual installer bytez").unwrap();
    assert!(matches!(
        StagedArtifact::verify(altered, &available),
        Err(ReleaseError::HashMismatch)
    ));
}

#[test]
fn exact_file_and_signed_metadata_pass() {
    let file = b"actual installer bytes";
    let (key, release) = signed_release(file);
    let verified = verify_release(&release, Cursor::new(file), expected(&key)).unwrap();
    assert_eq!(verified.version(), 12);
    assert_eq!(verified.whats_new(), "Improved notes");
}

#[test]
fn file_or_signed_field_change_fails() {
    let file = b"actual installer bytes";
    let (key, mut release) = signed_release(file);
    assert!(matches!(
        verify_release(&release, Cursor::new(b"changed file"), expected(&key)),
        Err(ReleaseError::HashMismatch)
    ));
    release.metadata.whats_new = "untrusted announcement".into();
    assert!(matches!(
        verify_release(&release, Cursor::new(file), expected(&key)),
        Err(ReleaseError::BadSignature)
    ));
}

#[test]
fn different_key_platform_channel_and_older_version_fail() {
    let file = b"installer";
    let (key, release) = signed_release(file);
    let wrong = signing_key(8);
    assert!(matches!(
        verify_release(&release, Cursor::new(file), expected(&wrong.public())),
        Err(ReleaseError::BadSignature)
    ));
    let mut platform = expected(&key);
    platform.platform = "android-arm64";
    assert!(matches!(
        verify_release(&release, Cursor::new(file), platform),
        Err(ReleaseError::WrongPlatform)
    ));
    let mut channel = expected(&key);
    channel.channel = "beta";
    assert!(matches!(
        verify_release(&release, Cursor::new(file), channel),
        Err(ReleaseError::WrongChannel)
    ));
    let mut old = expected(&key);
    old.running_version = 12;
    assert!(matches!(
        verify_release(&release, Cursor::new(file), old),
        Err(ReleaseError::NotNewer)
    ));
}

#[test]
fn malformed_or_ambiguous_metadata_is_refused() {
    let file = b"installer";
    let (key, mut release) = signed_release(file);
    release.metadata.sha256 = "00".into();
    assert!(matches!(
        verify_release(&release, Cursor::new(file), expected(&key)),
        Err(ReleaseError::InvalidMetadata)
    ));
    release.metadata.sha256 = hex(&sha256(file));
    release.metadata.file_name = "../escape.dmg".into();
    assert!(matches!(
        verify_release(&release, Cursor::new(file), expected(&key)),
        Err(ReleaseError::InvalidMetadata)
    ));
    let json = serde_json::to_string(&release).unwrap();
    let duplicate = json.replacen("\"version\":12", "\"version\":12,\"version\":13", 1);
    assert!(serde_json::from_str::<SignedRelease>(&duplicate).is_err());
    let extra = json.replacen("\"version\":12", "\"version\":12,\"unexpected\":true", 1);
    assert!(serde_json::from_str::<SignedRelease>(&extra).is_err());
}

#[test]
fn available_update_is_authenticated_without_downloading_and_staged_bytes_are_checked_later() {
    let file = b"installer";
    let (key, mut release) = signed_release(file);
    let available = check_available(&release, expected(&key)).unwrap();
    assert_eq!(available.whats_new(), "Improved notes");
    assert!(matches!(
        available.verify_staged(Cursor::new(b"different bytes")),
        Err(ReleaseError::HashMismatch)
    ));
    assert_eq!(
        available
            .verify_staged(Cursor::new(file))
            .unwrap()
            .version(),
        12
    );

    release.metadata.whats_new = "fake news".into();
    assert!(matches!(
        check_available(&release, expected(&key)),
        Err(ReleaseError::BadSignature)
    ));
}

#[test]
fn signed_message_has_stable_unambiguous_encoding() {
    let (_, release) = signed_release(b"file");
    let bytes = release.metadata.signing_bytes().unwrap();
    assert!(bytes.starts_with(b"BaseHero release v1\0"));
    // Every text field has a length prefix, so delimiter bytes in What's new cannot
    // change the interpretation of any subsequent field.
    let mut changed = release.metadata.clone();
    changed.whats_new.push('\0');
    assert_ne!(bytes, changed.signing_bytes().unwrap());
}

#[test]
fn every_signed_field_rejects_valid_but_unauthorized_substitution() {
    let original = b"installer";
    let substitute = b"attacker installer";
    let (key, release) = signed_release(original);
    let mut cases = Vec::new();
    let mut edited = release.clone();
    edited.metadata.version += 1;
    cases.push((edited, "macos-aarch64", "stable", original.as_slice()));
    let mut edited = release.clone();
    edited.metadata.platform = "android-arm64".into();
    cases.push((edited, "android-arm64", "stable", original.as_slice()));
    let mut edited = release.clone();
    edited.metadata.channel = "beta".into();
    cases.push((edited, "macos-aarch64", "beta", original.as_slice()));
    let mut edited = release.clone();
    edited.metadata.source_commit = "0123456789abcdef0123456789abcdef01234567".into();
    cases.push((edited, "macos-aarch64", "stable", original.as_slice()));
    let mut edited = release.clone();
    edited.metadata.file_name = "Other-macos-aarch64.dmg".into();
    cases.push((edited, "macos-aarch64", "stable", original.as_slice()));
    let mut edited = release.clone();
    edited.metadata.sha256 = hex(&sha256(substitute));
    cases.push((edited, "macos-aarch64", "stable", substitute.as_slice()));
    let mut edited = release.clone();
    edited.metadata.whats_new = "Untrusted news".into();
    cases.push((edited, "macos-aarch64", "stable", original.as_slice()));

    for (edited, platform, channel, artifact) in cases {
        assert!(
            matches!(
                verify_release(
                    &edited,
                    Cursor::new(artifact),
                    VerifyFor {
                        release_key: &key,
                        platform,
                        channel,
                        running_version: 1,
                    }
                ),
                Err(ReleaseError::BadSignature)
            ),
            "accepted unsigned change to {edited:?}"
        );
    }
}

#[test]
fn complete_encoding_and_signature_match_independent_fixed_vector() {
    // Constructed independently with big-endian length prefixes and libsodium
    // crypto_sign_ed25519_seed_keypair/detached, seed [7;32], file b"file".
    let (key, release) = signed_release(b"file");
    let fixed_bytes = bytes(concat!(
        "426173654865726f2072656c6561736520763100000000000000000c",
        "0000000d6d61636f732d61617263683634",
        "00000006737461626c65",
        "0000002861626364656630313233343536373839616263646566303132333435363738396162636465663031",
        "0000001a426173654865726f2d6d61636f732d616172636836342e646d67",
        "0000004033623963333538663336663061333162366164336531346633303963376366313938616339323436653833313666396365353433643562313961633032623830",
        "0000000e496d70726f766564206e6f746573"
    ));
    assert_eq!(release.metadata.signing_bytes().unwrap(), fixed_bytes);
    assert_eq!(
        hex(&key),
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"
    );
    assert_eq!(
        release.signature,
        "874dae2342c5f10f67c9faab743bdbed120fc9a3119ece8393c9417e77d0ca17026ebb8b021380eb7b610743925e8989302461ce2068dee343f94071c75ecd03"
    );
}

#[test]
fn large_artifact_is_hashed_through_short_reads_and_an_interrupted_read() {
    struct ShortRead {
        inner: Cursor<Vec<u8>>,
        successful_reads: usize,
        interrupted: bool,
    }
    impl Read for ShortRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.successful_reads == 1 && !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            let limit = buf.len().min(1000);
            let count = self.inner.read(&mut buf[..limit])?;
            if count > 0 {
                self.successful_reads += 1;
            }
            Ok(count)
        }
    }

    let file: Vec<u8> = (0..153_601).map(|i| ((i * 31 + 7) % 251) as u8).collect();
    let (key, release) = signed_release(&file);
    let reader = |bytes: Vec<u8>| ShortRead {
        inner: Cursor::new(bytes),
        successful_reads: 0,
        interrupted: false,
    };
    assert_eq!(
        verify_release(&release, reader(file.clone()), expected(&key))
            .unwrap()
            .version(),
        12
    );

    let mut changed = file;
    changed[128 * 1024 + 17] ^= 1;
    assert!(matches!(
        verify_release(&release, reader(changed), expected(&key)),
        Err(ReleaseError::HashMismatch)
    ));
}

#[test]
fn android_artifact_and_error_after_successful_read() {
    let file = b"android apk";
    let (key, mut release) = signed_release(file);
    let signer = signing_key(7);
    release.metadata.platform = "android-arm64".into();
    release.metadata.file_name = "BaseHero-android-arm64.apk".into();
    release.signature = hex(&signer.sign(&release.metadata.signing_bytes().unwrap()));
    let expected = VerifyFor {
        release_key: &key,
        platform: "android-arm64",
        channel: "stable",
        running_version: 11,
    };
    assert_eq!(
        verify_release(&release, Cursor::new(file), expected)
            .unwrap()
            .version(),
        12
    );

    struct FailingAfterFirstRead(bool);
    impl Read for FailingAfterFirstRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0 {
                Err(io::Error::other("partial download"))
            } else {
                self.0 = true;
                buf[0] = b'x';
                Ok(1)
            }
        }
    }
    assert!(matches!(
        verify_release(
            &release,
            FailingAfterFirstRead(false),
            VerifyFor {
                release_key: &key,
                platform: "android-arm64",
                channel: "stable",
                running_version: 11,
            }
        ),
        Err(ReleaseError::Read(_))
    ));
}
