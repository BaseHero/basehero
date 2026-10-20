#![cfg(feature = "authorization-tools")]
use bh_confidential_policy::{Limits, PolicyGate, Role, TimeBounds};
use bh_crypto::{Secret, SigningKey, sha256};
use bh_release::authorization::{Expected, Kind, SignedAuthorization, inspect, sign, verify};
use serde_json::{Value, json};
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn seed() -> Secret<32> {
    Secret::from_slice(&[42; 32]).unwrap()
}
fn root() -> [u8; 32] {
    SigningKey::from_seed(&seed()).public()
}
fn payload(generation: u64, issued: u64, expires: u64, builds: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"version":1,"generation":generation,"issued_at":issued,"expires_at":expires,"builds":builds,"machines":[]})).unwrap()
}
fn request(operation: Value) -> Value {
    json!({"format":1,"public_commit":"a".repeat(40),"product_tree":"b".repeat(40),"root":hex(&root()),"artifacts":[],"operation":operation})
}
fn policy_op(payload: &[u8], generation: u64, mode: &str, predecessor: Value) -> Value {
    json!({"kind":"policy","payload_hex":hex(payload),"generation":generation,"limits":{"max_lifetime_secs":100,"max_uncertainty_secs":2},"mode":mode,"predecessor":predecessor})
}
fn checked(raw: &[u8], kind: Kind, dir: &Path) -> bh_release::authorization::CheckedRequest {
    inspect(
        raw,
        &Expected {
            request_sha256: sha256(raw),
            public_commit: "a".repeat(40),
            product_tree: "b".repeat(40),
            root: root(),
            kind,
        },
        dir,
    )
    .unwrap()
}
fn raw(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

#[test]
fn exact_policy_roundtrip_and_live_gate_distinguish_issuance_from_current_permission() {
    let dir = tempfile::tempdir().unwrap();
    let payload = payload(1, 1000, 1050, json!([])); // empty withdrawal remains signable
    let req = raw(&request(policy_op(&payload, 1, "initial", Value::Null)));
    let admitted = checked(&req, Kind::Policy, dir.path());
    assert_eq!(admitted.raw_request(), req);
    assert!(admitted.summary().contains("generation: 1"));
    let signed = sign(&admitted, &seed()).unwrap();
    verify(&admitted, &signed).unwrap();
    let result = serde_json::to_value(&signed).unwrap();
    assert_eq!(result["format"], 1);
    assert_eq!(result["request_sha256"], hex(&sha256(&req)));
    assert_eq!(result["value"]["payload_hex"], hex(&payload));
    let mut gate = PolicyGate::new(
        root(),
        Limits {
            max_lifetime_secs: 100,
            max_uncertainty_secs: 2,
        },
    )
    .unwrap();
    let signature =
        bh_release::decode_hex::<64>(result["value"]["signature_hex"].as_str().unwrap()).unwrap();
    gate.push(&payload, &signature).unwrap();
    let build = bh_confidential_policy::Build {
        role: Role::Checker,
        compose_sha256: [0; 32],
        boot: std::array::from_fn(|_| vec![0; 48]),
    };
    assert_eq!(
        gate.check_measurements(
            Role::Checker,
            &build,
            &[0; 32],
            Some(TimeBounds {
                earliest: 999,
                latest: 999
            })
        ),
        Err(bh_confidential_policy::Error::NotYetValid)
    );
    assert_eq!(
        gate.check_measurements(
            Role::Checker,
            &build,
            &[0; 32],
            Some(TimeBounds {
                earliest: 1050,
                latest: 1050
            })
        ),
        Err(bh_confidential_policy::Error::Expired)
    );
    gate.mark_unavailable();
    assert_eq!(
        gate.check_measurements(
            Role::Checker,
            &build,
            &[0; 32],
            Some(TimeBounds {
                earliest: 1051,
                latest: 1051
            })
        ),
        Err(bh_confidential_policy::Error::PolicyUnavailable)
    );
    assert_eq!(
        gate.check_measurements(Role::Checker, &build, &[0; 32], None),
        Err(bh_confidential_policy::Error::TimeUnavailable)
    );
}

#[test]
fn predecessor_modes_authenticate_and_enforce_progress_or_identical_retry() {
    let dir = tempfile::tempdir().unwrap();
    let first = payload(1, 1000, 1050, json!([]));
    let initial = sign(
        &checked(
            &raw(&request(policy_op(&first, 1, "initial", Value::Null))),
            Kind::Policy,
            dir.path(),
        ),
        &seed(),
    )
    .unwrap();
    let value = serde_json::to_value(initial).unwrap();
    let pred = json!({"payload_hex":hex(&first),"signature_hex":value["value"]["signature_hex"]});
    let next = payload(2, 1000, 1050, json!([]));
    for (mode, bytes, generation, good) in [
        ("advance", next.as_slice(), 2, true),
        ("retry", first.as_slice(), 1, true),
        ("advance", first.as_slice(), 1, false),
        ("retry", next.as_slice(), 2, false),
        ("advance", first.as_slice(), 0, false),
    ] {
        let req = raw(&request(policy_op(bytes, generation, mode, pred.clone())));
        let outcome = inspect(
            &req,
            &Expected {
                request_sha256: sha256(&req),
                public_commit: "a".repeat(40),
                product_tree: "b".repeat(40),
                root: root(),
                kind: Kind::Policy,
            },
            dir.path(),
        );
        assert_eq!(outcome.is_ok(), good, "{mode} {generation}");
        if let Ok(admitted) = outcome {
            verify(&admitted, &sign(&admitted, &seed()).unwrap()).unwrap();
        }
    }
    let mut forged = pred.clone();
    forged["signature_hex"] = json!("00".repeat(64));
    let req = raw(&request(policy_op(&next, 2, "advance", forged)));
    assert!(
        inspect(
            &req,
            &Expected {
                request_sha256: sha256(&req),
                public_commit: "a".repeat(40),
                product_tree: "b".repeat(40),
                root: root(),
                kind: Kind::Policy
            },
            dir.path()
        )
        .is_err()
    );
}

#[test]
fn certificates_use_separate_real_verifiers_and_reject_cross_role_or_root() {
    let dir = tempfile::tempdir().unwrap();
    for kind in [Kind::Receipt, Kind::Permit] {
        let req = raw(&request(
            json!({"kind":kind.as_str(),"leaf_public_key":"cd".repeat(32)}),
        ));
        let admitted = checked(&req, kind, dir.path());
        let signed = sign(&admitted, &seed()).unwrap();
        verify(&admitted, &signed).unwrap();
        let value = serde_json::to_value(&signed).unwrap();
        let cert =
            bh_release::decode_hex::<130>(value["value"]["certificate_hex"].as_str().unwrap())
                .unwrap();
        match kind {
            Kind::Receipt => {
                bh_sync::receipt::verify_certificate(&root(), &cert).unwrap();
                assert!(bh_sync::permit::verify_certificate(&root(), &cert).is_err());
            }
            Kind::Permit => {
                bh_sync::permit::verify_certificate(&root(), &cert).unwrap();
                assert!(bh_sync::receipt::verify_certificate(&root(), &cert).is_err());
            }
            Kind::Policy => unreachable!(),
        }
        let mut swapped = serde_json::to_value(&signed).unwrap();
        swapped["value"]["kind"] = json!(if kind == Kind::Receipt {
            "permit"
        } else {
            "receipt"
        });
        assert!(verify(&admitted, &serde_json::from_value(swapped).unwrap()).is_err());
        let mut altered = serde_json::to_value(&signed).unwrap();
        altered["request_sha256"] = json!("00".repeat(32));
        assert!(verify(&admitted, &serde_json::from_value(altered).unwrap()).is_err());
    }
}

#[test]
fn request_expectations_closed_schema_and_artifact_bytes_are_mandatory() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("evidence"), b"public evidence").unwrap();
    let op = json!({"kind":"receipt","leaf_public_key":"cd".repeat(32)});
    let mut doc = request(op);
    doc["artifacts"] = json!([{"path":"evidence","sha256":hex(&sha256(b"public evidence"))}]);
    let base = raw(&doc);
    assert!(
        checked(&base, Kind::Receipt, dir.path())
            .summary()
            .contains("evidence")
    );
    for change in ["public_commit", "product_tree", "root"] {
        let mut bad = doc.clone();
        bad[change] = json!(if change == "root" {
            "00".repeat(32)
        } else {
            "f".repeat(40)
        });
        let bytes = raw(&bad);
        assert!(
            inspect(
                &bytes,
                &Expected {
                    request_sha256: sha256(&bytes),
                    public_commit: "a".repeat(40),
                    product_tree: "b".repeat(40),
                    root: root(),
                    kind: Kind::Receipt
                },
                dir.path()
            )
            .is_err(),
            "{change}"
        );
    }
    assert!(
        inspect(
            &base,
            &Expected {
                request_sha256: [0; 32],
                public_commit: "a".repeat(40),
                product_tree: "b".repeat(40),
                root: root(),
                kind: Kind::Receipt
            },
            dir.path()
        )
        .is_err()
    );
    assert!(
        inspect(
            &base,
            &Expected {
                request_sha256: sha256(&base),
                public_commit: "a".repeat(40),
                product_tree: "b".repeat(40),
                root: root(),
                kind: Kind::Permit
            },
            dir.path()
        )
        .is_err()
    );
    fs::write(dir.path().join("evidence"), b"changed").unwrap();
    assert!(
        inspect(
            &base,
            &Expected {
                request_sha256: sha256(&base),
                public_commit: "a".repeat(40),
                product_tree: "b".repeat(40),
                root: root(),
                kind: Kind::Receipt
            },
            dir.path()
        )
        .is_err()
    );
    fs::remove_file(dir.path().join("evidence")).unwrap();
    assert!(
        inspect(
            &base,
            &Expected {
                request_sha256: sha256(&base),
                public_commit: "a".repeat(40),
                product_tree: "b".repeat(40),
                root: root(),
                kind: Kind::Receipt
            },
            dir.path()
        )
        .is_err()
    );
    for path in ["../escape", "/tmp/escape", ".", "sub//evidence"] {
        let mut bad = doc.clone();
        bad["artifacts"][0]["path"] = json!(path);
        let bytes = raw(&bad);
        assert!(
            inspect(
                &bytes,
                &Expected {
                    request_sha256: sha256(&bytes),
                    public_commit: "a".repeat(40),
                    product_tree: "b".repeat(40),
                    root: root(),
                    kind: Kind::Receipt
                },
                dir.path()
            )
            .is_err(),
            "{path}"
        );
    }
    let mut duplicate = doc.clone();
    duplicate["artifacts"][0]["sha256"] = json!("00".repeat(32));
    let second = duplicate["artifacts"][0].clone();
    duplicate["artifacts"].as_array_mut().unwrap().push(second);
    let bytes = raw(&duplicate);
    assert!(
        inspect(
            &bytes,
            &Expected {
                request_sha256: sha256(&bytes),
                public_commit: "a".repeat(40),
                product_tree: "b".repeat(40),
                root: root(),
                kind: Kind::Receipt
            },
            dir.path()
        )
        .is_err()
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("evidence")).unwrap();
        assert!(
            inspect(
                &base,
                &Expected {
                    request_sha256: sha256(&base),
                    public_commit: "a".repeat(40),
                    product_tree: "b".repeat(40),
                    root: root(),
                    kind: Kind::Receipt
                },
                dir.path()
            )
            .is_err()
        );
    }
}

#[cfg(unix)]
#[test]
fn inspect_quotes_real_control_character_artifact_name_on_one_line() {
    let dir = tempfile::tempdir().unwrap();
    let name = "evidence\n\u{1b}[2Jroot=forged";
    fs::write(dir.path().join(name), b"public evidence").unwrap();
    let mut doc = request(json!({"kind":"receipt","leaf_public_key":"cd".repeat(32)}));
    doc["artifacts"] = json!([{"path":name,"sha256":hex(&sha256(b"public evidence"))}]);
    let raw = raw(&doc);
    let summary = checked(&raw, Kind::Receipt, dir.path()).summary();
    assert!(summary.contains("artifact: \"evidence\\n\\u001b[2Jroot=forged\" sha256: "));
    assert!(!summary.contains(name));
    assert_eq!(
        summary
            .lines()
            .filter(|line| line.starts_with("artifact: "))
            .count(),
        1
    );
    assert_eq!(
        summary
            .lines()
            .filter(|line| line.starts_with("root: "))
            .count(),
        1
    );
    let file = dir.path().join("request.json");
    fs::write(&file, &raw).unwrap();
    let output = cli(
        "inspect",
        &file,
        dir.path(),
        None,
        b"",
        &hex(&sha256(&raw)),
        &hex(&root()),
        "receipt",
    );
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .filter(|line| line.starts_with("artifact: "))
            .count(),
        1
    );
}

#[test]
fn malformed_duplicate_unknown_and_bounded_policy_or_request_fail() {
    let dir = tempfile::tempdir().unwrap();
    let p = payload(1, 1000, 1050, json!([]));
    let doc = request(policy_op(&p, 1, "initial", Value::Null));
    let mut unknown_request = doc.clone();
    unknown_request["secret"] = json!("forbidden");
    let mut unknown_operation = doc.clone();
    unknown_operation["operation"]["secret"] = json!("forbidden");
    let mut unknown_limits = doc.clone();
    unknown_limits["operation"]["limits"]["extra"] = json!(true);
    let mut unknown_policy = doc.clone();
    unknown_policy["operation"]["payload_hex"] = json!(hex(&serde_json::to_vec(&json!({"version":1,"generation":1,"issued_at":1000,"expires_at":1050,"builds":[],"machines":[],"extra":true})).unwrap()));
    let mut wrong_generation = doc.clone();
    wrong_generation["operation"]["generation"] = json!(2);
    let mut missing_predecessor = doc.clone();
    missing_predecessor["operation"]
        .as_object_mut()
        .unwrap()
        .remove("predecessor");
    for bad in [
        unknown_request,
        unknown_operation,
        unknown_limits,
        unknown_policy,
        wrong_generation,
        missing_predecessor,
    ]
    .into_iter()
    .enumerate()
    {
        let (case, bad) = bad;
        let bytes = raw(&bad);
        assert!(
            inspect(
                &bytes,
                &Expected {
                    request_sha256: sha256(&bytes),
                    public_commit: "a".repeat(40),
                    product_tree: "b".repeat(40),
                    root: root(),
                    kind: Kind::Policy
                },
                dir.path()
            )
            .is_err(),
            "case {case}"
        );
    }
    let original = String::from_utf8(raw(&doc)).unwrap();
    let duplicate_request = original
        .replacen("\"format\":1", "\"format\":1,\"format\":1", 1)
        .into_bytes();
    let duplicate_operation = original
        .replacen(
            "\"kind\":\"policy\"",
            "\"kind\":\"policy\",\"kind\":\"policy\"",
            1,
        )
        .into_bytes();
    for bytes in [
        duplicate_request,
        duplicate_operation,
        vec![b' '; 1024 * 1024 + 1],
    ] {
        assert!(
            inspect(
                &bytes,
                &Expected {
                    request_sha256: sha256(&bytes),
                    public_commit: "a".repeat(40),
                    product_tree: "b".repeat(40),
                    root: root(),
                    kind: Kind::Policy
                },
                dir.path()
            )
            .is_err()
        );
    }
    let duplicate_payload = String::from_utf8(p.clone()).unwrap().replacen(
        "\"generation\":1",
        "\"generation\":1,\"generation\":1",
        1,
    );
    let duplicate_payload = duplicate_payload.into_bytes();
    for malformed in [
        b"{\"version\":1,\"version\":1}".as_slice(),
        b"not json",
        &duplicate_payload,
        &vec![b'x'; 65537],
    ] {
        let bad = request(policy_op(malformed, 1, "initial", Value::Null));
        let bytes = raw(&bad);
        assert!(
            inspect(
                &bytes,
                &Expected {
                    request_sha256: sha256(&bytes),
                    public_commit: "a".repeat(40),
                    product_tree: "b".repeat(40),
                    root: root(),
                    kind: Kind::Policy
                },
                dir.path()
            )
            .is_err()
        );
    }
    let mut bad = doc.clone();
    bad["operation"]["limits"]["max_lifetime_secs"] = json!(0);
    let bytes = raw(&bad);
    assert!(
        inspect(
            &bytes,
            &Expected {
                request_sha256: sha256(&bytes),
                public_commit: "a".repeat(40),
                product_tree: "b".repeat(40),
                root: root(),
                kind: Kind::Policy
            },
            dir.path()
        )
        .is_err()
    );
}

#[test]
fn policy_cli_roundtrip_rejects_altered_result_and_unpinned_expectations() {
    let dir = tempfile::tempdir().unwrap();
    let payload = payload(1, 1000, 1050, json!([]));
    let req = raw(&request(policy_op(&payload, 1, "initial", Value::Null)));
    let request_file = dir.path().join("request.json");
    fs::write(&request_file, &req).unwrap();
    let digest = hex(&sha256(&req));
    let key = hex(&root());
    let issued = cli(
        "sign",
        &request_file,
        dir.path(),
        None,
        format!("{}\n", "2a".repeat(32)).as_bytes(),
        &digest,
        &key,
        "policy",
    );
    assert!(issued.status.success(), "{:?}", issued.stderr);
    let signed_file = dir.path().join("signed.json");
    fs::write(&signed_file, &issued.stdout).unwrap();
    assert!(
        cli(
            "verify",
            &request_file,
            dir.path(),
            Some(&signed_file),
            b"",
            &digest,
            &key,
            "policy"
        )
        .status
        .success()
    );
    let mut tampered: Value = serde_json::from_slice(&issued.stdout).unwrap();
    tampered["value"]["signature_hex"] = json!("00".repeat(64));
    fs::write(&signed_file, raw(&tampered)).unwrap();
    let bad = cli(
        "verify",
        &request_file,
        dir.path(),
        Some(&signed_file),
        b"",
        &digest,
        &key,
        "policy",
    );
    assert!(!bad.status.success());
    assert!(bad.stdout.is_empty());
    let absent = Command::new(env!("CARGO_BIN_EXE_authorization-sign"))
        .args([
            "inspect",
            request_file.to_str().unwrap(),
            "--artifacts",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!absent.status.success());
    assert!(absent.stdout.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn cli_terminal_failures_are_fixed_and_restore_real_pty() {
    let output = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/authorization_pty.py"
        ))
        .arg(env!("CARGO_BIN_EXE_authorization-sign"))
        .arg(env!("CARGO_BIN_EXE_release-sign"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "PTY test: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn cli_sign_finishes_after_one_newline_without_waiting_for_stdin_eof() {
    let dir = tempfile::tempdir().unwrap();
    let req = raw(&request(
        json!({"kind":"receipt","leaf_public_key":"cd".repeat(32)}),
    ));
    let request_file = dir.path().join("request.json");
    fs::write(&request_file, &req).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_authorization-sign"))
        .arg("sign")
        .arg(&request_file)
        .args([
            "--request-sha256",
            &hex(&sha256(&req)),
            "--expected-root",
            &hex(&root()),
            "--public-commit",
            &"a".repeat(40),
            "--product-tree",
            &"b".repeat(40),
            "--kind",
            "receipt",
            "--artifacts",
        ])
        .arg(dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut held_stdin = child.stdin.take().unwrap();
    held_stdin
        .write_all(format!("{}\n", "2a".repeat(32)).as_bytes())
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while child.try_wait().unwrap().is_none() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let finished = child.try_wait().unwrap().is_some();
    if !finished {
        child.kill().unwrap();
    }
    drop(held_stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        finished && output.status.success(),
        "sign must not wait for EOF"
    );
    assert!(serde_json::from_slice::<SignedAuthorization>(&output.stdout).is_ok());
}

#[allow(clippy::too_many_arguments)] // Explicit CLI expectations are deliberate in test cases.
fn cli(
    command: &str,
    request: &Path,
    dir: &Path,
    signed: Option<&Path>,
    input: &[u8],
    hash: &str,
    root_hex: &str,
    kind: &str,
) -> std::process::Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_authorization-sign"));
    cmd.arg(command)
        .arg(request)
        .args([
            "--request-sha256",
            hash,
            "--expected-root",
            root_hex,
            "--public-commit",
            &"a".repeat(40),
            "--product-tree",
            &"b".repeat(40),
            "--kind",
            kind,
            "--artifacts",
        ])
        .arg(dir);
    if let Some(path) = signed {
        cmd.arg("--signed").arg(path);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}
#[test]
fn cli_inspect_sign_verify_and_seed_failures_are_content_free() {
    let dir = tempfile::tempdir().unwrap();
    let req = raw(&request(
        json!({"kind":"permit","leaf_public_key":"cd".repeat(32)}),
    ));
    let file = dir.path().join("request.json");
    fs::write(&file, &req).unwrap();
    let digest = hex(&sha256(&req));
    let root_hex = hex(&root());
    let inspected = cli(
        "inspect",
        &file,
        dir.path(),
        None,
        b"",
        &digest,
        &root_hex,
        "permit",
    );
    assert!(inspected.status.success(), "{:?}", inspected.stderr);
    assert!(String::from_utf8_lossy(&inspected.stdout).contains("permit"));
    let secret = format!("{}\n", "2a".repeat(32));
    let issued = cli(
        "sign",
        &file,
        dir.path(),
        None,
        secret.as_bytes(),
        &digest,
        &root_hex,
        "permit",
    );
    assert!(issued.status.success(), "{:?}", issued.stderr);
    let result: SignedAuthorization = serde_json::from_slice(&issued.stdout).unwrap();
    verify(&checked(&req, Kind::Permit, dir.path()), &result).unwrap();
    let signed_file = dir.path().join("signed.json");
    fs::write(&signed_file, &issued.stdout).unwrap();
    let verified = cli(
        "verify",
        &file,
        dir.path(),
        Some(&signed_file),
        b"",
        &digest,
        &root_hex,
        "permit",
    );
    assert!(verified.status.success(), "{:?}", verified.stderr);
    for input in [b"".as_slice(), b"NO_SECRET_LEAK\n", &vec![b'a'; 8192]] {
        let failed = cli(
            "sign",
            &file,
            dir.path(),
            None,
            input,
            &digest,
            &root_hex,
            "permit",
        );
        assert!(!failed.status.success());
        assert!(failed.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&failed.stderr).contains("NO_SECRET_LEAK"));
        assert!(!String::from_utf8_lossy(&failed.stderr).contains(&"a".repeat(256)));
    }
    let failed = cli(
        "sign",
        &file,
        dir.path(),
        None,
        secret.as_bytes(),
        &"00".repeat(32),
        &root_hex,
        "permit",
    );
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    let failed = cli(
        "sign",
        &file,
        dir.path(),
        None,
        secret.as_bytes(),
        &digest,
        &"00".repeat(32),
        "permit",
    );
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
}
