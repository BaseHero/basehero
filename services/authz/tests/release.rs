//! A build without the `synthetic-attestation` feature, as every release
//! build is, has no synthetic attestation: the library types are absent (see
//! the crate's compile-fail examples) and the binary refuses the flag.
#![cfg(not(feature = "synthetic-attestation"))]

use std::process::Command;

#[test]
fn release_build_has_no_synthetic() {
    let output = Command::new(env!("CARGO_BIN_EXE_bh-authz"))
        .arg("--synthetic-attestation")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains("unknown flag --synthetic-attestation"),
        "{stderr}"
    );
}
