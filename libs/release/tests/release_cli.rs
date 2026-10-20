//! End-to-end public release verification with disposable signing material.
use std::{
    fs,
    path::Path,
    process::{Command, Output, Stdio},
};

const VERSION: &str = "43";
const PLATFORM: &str = "linux-x86-64";
const CHANNEL: &str = "stable";
const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
// The public key for this disposable seed is obtained from the real signer.

fn cli(args: &[&str], stdin: Stdio) -> Output {
    Command::new(env!("CARGO_BIN_EXE_release-sign"))
        .args(args)
        .stdin(stdin)
        .output()
        .unwrap()
}

fn verify(
    version: &str,
    platform: &str,
    channel: &str,
    source: &str,
    key: &str,
    metadata: &Path,
    artifact: &Path,
) -> Output {
    cli(
        &[
            "verify",
            version,
            platform,
            channel,
            source,
            key,
            metadata.to_str().unwrap(),
            artifact.to_str().unwrap(),
        ],
        Stdio::null(),
    )
}

#[test]
fn signed_disposable_artifact_requires_exact_expected_metadata_and_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let artifact = temp.path().join("release.tar.gz");
    let notes = temp.path().join("notes.txt");
    let metadata = temp.path().join("release.json");
    fs::write(&artifact, b"disposable artifact").unwrap();
    fs::write(&notes, "notes").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_release-sign"))
        .args([
            "sign",
            VERSION,
            PLATFORM,
            CHANNEL,
            SOURCE,
            artifact.to_str().unwrap(),
            notes.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{}\n", "2a".repeat(32)).as_bytes())
        .unwrap();
    let signed = child.wait_with_output().unwrap();
    assert!(
        signed.status.success(),
        "{}",
        String::from_utf8_lossy(&signed.stderr)
    );
    let stderr = String::from_utf8_lossy(&signed.stderr);
    let key = stderr.split("Release public key: ").nth(1).unwrap().trim();
    assert_eq!(key.len(), 64);
    let value: serde_json::Value = serde_json::from_slice(&signed.stdout).unwrap();
    assert_eq!(value["metadata"]["file_name"], "release.tar.gz");
    fs::write(&metadata, &signed.stdout).unwrap();
    let check = |version, platform, channel, source, key, path: &Path, file: &Path| {
        verify(version, platform, channel, source, key, path, file)
    };
    let good = check(
        VERSION, PLATFORM, CHANNEL, SOURCE, key, &metadata, &artifact,
    );
    assert!(
        good.status.success(),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    assert_eq!(good.stdout, b"release verified\n");
    assert!(good.stderr.is_empty());

    let wrong_key = "00".repeat(32);
    for (version, platform, channel, source, root) in [
        ("0", PLATFORM, CHANNEL, SOURCE, key),
        ("44", PLATFORM, CHANNEL, SOURCE, key),
        (VERSION, "macos-aarch64", CHANNEL, SOURCE, key),
        (VERSION, PLATFORM, "beta", SOURCE, key),
        (
            VERSION,
            PLATFORM,
            CHANNEL,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            key,
        ),
        (VERSION, PLATFORM, CHANNEL, SOURCE, wrong_key.as_str()),
    ] {
        let result = check(
            version, platform, channel, source, root, &metadata, &artifact,
        );
        assert!(
            !result.status.success(),
            "accepted {version}/{platform}/{channel}/{source}/{root}"
        );
        assert!(result.stdout.is_empty());
        assert_eq!(result.stderr, b"release verification failed\n");
    }
    let renamed = temp.path().join("renamed.tar.gz");
    fs::copy(&artifact, &renamed).unwrap();
    let mut tampered = value.clone();
    tampered["signature"] = "00".repeat(64).into();
    let bad_signature = temp.path().join("bad-signature.json");
    fs::write(&bad_signature, serde_json::to_vec(&tampered).unwrap()).unwrap();
    let malformed = temp.path().join("malformed.json");
    fs::write(&malformed, b"{").unwrap();
    let oversized = temp.path().join("oversized.json");
    fs::write(&oversized, vec![b' '; 1024 * 1024 + 1]).unwrap();
    for (path, file) in [
        (&metadata, &renamed),
        (&bad_signature, &artifact),
        (&malformed, &artifact),
        (&oversized, &artifact),
    ] {
        let result = check(VERSION, PLATFORM, CHANNEL, SOURCE, key, path, file);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert_eq!(result.stderr, b"release verification failed\n");
    }
    let missing = cli(&["verify", VERSION], Stdio::null());
    assert!(!missing.status.success());
    assert!(missing.stdout.is_empty());
    assert_eq!(missing.stderr, b"release verification failed\n");
    fs::write(&artifact, b"changed artifact").unwrap();
    let result = check(
        VERSION, PLATFORM, CHANNEL, SOURCE, key, &metadata, &artifact,
    );
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert_eq!(result.stderr, b"release verification failed\n");
}
