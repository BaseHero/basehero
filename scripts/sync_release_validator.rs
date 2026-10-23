//! Local packaging validation using the app's parser and existing authorities.
//! This executable is not part of the authorization service image.
#[path = "../libs/host/src/endpoint.rs"]
mod endpoint;

fn file(input: &serde_json::Value, name: &str) -> Result<Vec<u8>, &'static str> {
    let path = input[name]
        .as_str()
        .ok_or("runtime file reference required")?;
    std::fs::read(path).map_err(|_| "cannot read runtime file")
}

fn hex_file(input: &serde_json::Value, name: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = file(input, name)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "hex runtime file required")?;
    hex::decode(text.trim()).map_err(|_| "hex runtime file required")
}

fn validate_prepare(input: &serde_json::Value) -> Result<(), &'static str> {
    let text = serde_json::to_string(&input["endpoint"]).map_err(|_| "endpoint required")?;
    endpoint::built(Some(&text), false)
        .map_err(|_| "app endpoint rejected")?
        .ok_or("app endpoint required")?;
    Ok(())
}

fn validate_with_compose(
    input: &serde_json::Value,
    expected: &[u8; 32],
) -> Result<String, &'static str> {
    let receipt = validate(input)?;
    let policy_bytes = hex::decode(
        input["endpoint"]["policy"]
            .as_str()
            .ok_or("policy required")?,
    )
    .map_err(|_| "policy encoding")?;
    let policy: bh_confidential_policy::Policy =
        serde_json::from_slice(&policy_bytes).map_err(|_| "policy encoding")?;
    if !policy.builds.iter().any(|build| {
        build.role == bh_confidential_policy::Role::Checker && build.compose_sha256 == *expected
    }) {
        return Err("signed checker build differs from prepared compose");
    }
    Ok(receipt)
}

fn validate(input: &serde_json::Value) -> Result<String, &'static str> {
    use bh_confidential_policy::{Limits, PolicyGate};
    use bh_crypto::{KemKey, Secret, SigningKey};
    let text = serde_json::to_string(&input["endpoint"]).map_err(|_| "endpoint required")?;
    let fields = endpoint::built(Some(&text), false)
        .map_err(|_| "app endpoint rejected")?
        .ok_or("app endpoint required")?;
    let files = &input["authz"]["files"];
    let seed = hex_file(files, "permit_key")?;
    if seed.len() != 32 {
        return Err("permit seed must be 32 bytes");
    }
    let key = SigningKey::from_seed(&Secret::from_slice(&seed).map_err(|_| "permit seed")?);
    let certificate: [u8; bh_sync::receipt::CERTIFICATE_LEN] = hex_file(files, "permit_cert")?
        .try_into()
        .map_err(|_| "permit certificate length")?;
    let keys = bh_authz::PermitKeys::new(key, certificate)
        .map_err(|_| "permit key/certificate mismatch")?;
    if keys.root() != fields.hosting_root {
        return Err("permit certificate/root/version mismatch");
    }
    bh_sync::permit::verify_certificate(&fields.hosting_root, &certificate)
        .map_err(|_| "permit certificate/root/version/signature mismatch")?;
    let recovery_seed = hex_file(files, "recovery_key")?;
    if recovery_seed.len() != 32 {
        return Err("recovery seed must be 32 bytes");
    }
    let recovery_key =
        KemKey::from_seed(&Secret::from_slice(&recovery_seed).map_err(|_| "recovery seed")?);
    let recovery_bytes = hex_file(files, "recovery_cert")?;
    let recovery_cert = bh_sync::evidence::RecoveryKeyCertificate::decode(&recovery_bytes)
        .map_err(|_| "recovery certificate encoding/length/version")?;
    bh_authz::RecoveryHomeKey::new(recovery_key, recovery_cert, &fields.hosting_root)
        .map_err(|_| "recovery key/certificate/root mismatch")?;
    if recovery_bytes != fields.recovery_key {
        return Err("runtime recovery certificate differs from app endpoint");
    }
    let receipt = hex_file(&input["cloudflare"], "receipt_cert_file")?;
    bh_sync::receipt::verify_certificate(&fields.hosting_root, &receipt)
        .map_err(|_| "receipt certificate/root mismatch")?;
    if file(files, "policy")? != fields.policy
        || hex_file(files, "policy_signature")? != fields.policy_signature
    {
        return Err("runtime policy differs from app endpoint");
    }
    if fields.policy.is_empty() {
        return Err("signed hardware policy required");
    }
    let mut gate = PolicyGate::new(
        fields.app_root,
        Limits {
            max_lifetime_secs: fields.max_lifetime_secs,
            max_uncertainty_secs: fields.max_uncertainty_secs,
        },
    )
    .map_err(|_| "policy limits")?;
    gate.push(&fields.policy, &fields.policy_signature)
        .map_err(|_| "signed policy rejected")?;
    let policy: bh_confidential_policy::Policy =
        serde_json::from_slice(&fields.policy).map_err(|_| "policy encoding")?;
    if policy
        .validate_structure(Limits {
            max_lifetime_secs: fields.max_lifetime_secs,
            max_uncertainty_secs: fields.max_uncertainty_secs,
        })
        .is_err()
        || policy.machines.is_empty()
        || policy.builds.is_empty()
    {
        return Err("complete hardware policy and bounded lifetime required");
    }
    // Availability/currentness and quote collateral are checked by the running
    // hardware path with qualified time, never by this offline packaging tool.
    Ok(hex::encode(receipt))
}

fn main() {
    let result = (|| {
        let mut args = std::env::args().skip(1);
        let mode = args.next().ok_or("validation mode required")?;
        if mode != "prepare" && mode != "final" {
            return Err("validation mode required");
        }
        let path = args.next().ok_or("operator input file required")?;
        let expected = if mode == "final" {
            let bytes = hex::decode(args.next().ok_or("prepared compose hash required")?)
                .map_err(|_| "prepared compose hash required")?;
            Some(<[u8; 32]>::try_from(bytes).map_err(|_| "prepared compose hash required")?)
        } else {
            None
        };
        if args.next().is_some() {
            return Err("unexpected validation argument");
        }
        let text = if path == "-" {
            use std::io::Read;
            let mut bytes = Vec::new();
            std::io::stdin()
                .read_to_end(&mut bytes)
                .map_err(|_| "cannot read operator inputs")?;
            bytes
        } else {
            std::fs::read(path).map_err(|_| "cannot read operator inputs")?
        };
        let input = serde_json::from_slice(&text).map_err(|_| "invalid operator JSON")?;
        if let Some(hash) = expected {
            validate_with_compose(&input, &hash)
        } else {
            validate_prepare(&input)?;
            Ok(String::new())
        }
    })();
    match result {
        Ok(receipt_certificate) => println!("{receipt_certificate}"),
        Err(message) => {
            eprintln!("release validation: {message}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(dir: &std::path::Path) -> serde_json::Value {
        use bh_crypto::{KemKey, Secret, SigningKey};
        let key = |byte| SigningKey::from_seed(&Secret::from_slice(&[byte; 32]).unwrap());
        let hosting = key(31);
        let app = key(32);
        let permit = key(33);
        let receipt = key(34);
        let recovery = KemKey::from_seed(&Secret::from_slice(&[38; 32]).unwrap());
        let policy = serde_json::json!({
            "version": 1, "generation": 1, "issued_at": 1, "expires_at": 100,
            "builds": [{"role": "checker", "compose_sha256": vec![35; 32],
                        "boot": vec![vec![36; 48]; 4]}], "machines": [vec![37; 32]]
        })
        .to_string()
        .into_bytes();
        let signature =
            app.sign(&[b"basehero.confidential-policy.v1\0".as_slice(), &policy].concat());
        let recovery_cert = hex::encode(
            bh_sync::evidence::certify_recovery_key(&hosting, &recovery.public()).encode(),
        );
        let mut files = serde_json::Map::new();
        for (name, bytes) in [
            ("permit_key", hex::encode([33; 32]).into_bytes()),
            ("recovery_key", hex::encode([38; 32]).into_bytes()),
            ("recovery_cert", recovery_cert.clone().into_bytes()),
            (
                "permit_cert",
                hex::encode(bh_sync::permit::certify(&hosting, permit.public())).into_bytes(),
            ),
            ("policy", policy.clone()),
            ("policy_signature", hex::encode(signature).into_bytes()),
            (
                "collateral",
                b"THROWAWAY TEST COLLATERAL; NOT HARDWARE EVIDENCE".to_vec(),
            ),
            (
                "receipt_cert_file",
                hex::encode(bh_sync::receipt::certify(&hosting, receipt.public())).into_bytes(),
            ),
        ] {
            let path = dir.join(name);
            std::fs::write(&path, bytes).unwrap();
            files.insert(name.into(), path.to_str().unwrap().into());
        }
        let receipt_path = files.remove("receipt_cert_file").unwrap();
        serde_json::json!({
            "cloudflare": {"account_id": "a".repeat(32), "name": "throwaway-sync", "bucket": "throwaway-bodies",
                "route": {"pattern": "edge.invalid", "custom_domain": true},
                "receipt_key_binding": "RECEIPT_KEY", "receipt_cert_file": receipt_path},
            "authz": {"files": files, "backends": [{"url": "https://authz.invalid/v1/channel", "ready": true}],
                "image": "bh-authz:fixture", "image_id": format!("sha256:{}", "1".repeat(64)),
                "archive_sha256": "2".repeat(64), "registry_manifest_file": null, "protected_mount": "/fixture/protected", "uid": 1000, "gid": 1000,
                "quote_socket": "/fixture/quote.sock", "roughtime": [
                    {"address": "192.0.2.1:2002", "key": "11".repeat(32)},
                    {"address": "192.0.2.2:2002", "key": "22".repeat(32)}],
                "time_config": [1000000000u64, 100, 1000000, 120000000000u64, 1000]},
            "endpoint": {"edge_url": "https://edge.invalid", "hosting_root": hex::encode(hosting.public()),
                "app_root": hex::encode(app.public()), "policy": hex::encode(policy), "policy_signature": hex::encode(signature),
                "recovery_key": recovery_cert, "max_lifetime_secs": 1000, "max_uncertainty_secs": 30, "build_floor": 1, "appraisal": "hardware"}
        })
    }

    #[test]
    fn signed_public_inputs_and_runtime_key_agree_or_fail_closed() {
        use bh_crypto::{Secret, SigningKey};
        let temp = tempfile::tempdir().unwrap();
        let good = fixture(temp.path());
        assert_eq!(
            validate(&good).unwrap(),
            std::fs::read_to_string(temp.path().join("receipt_cert_file")).unwrap()
        );
        for (field, value) in [
            ("hosting_root", "11".repeat(32)),
            ("app_root", "22".repeat(32)),
            ("policy", "00".into()),
            ("policy_signature", "ff".repeat(64)),
            ("appraisal", "synthetic".into()),
        ] {
            let mut bad = good.clone();
            bad["endpoint"][field] = value.into();
            assert!(validate(&bad).is_err(), "{field}");
        }
        std::fs::write(temp.path().join("permit_key"), hex::encode([99; 32])).unwrap();
        assert!(validate(&good).is_err());
        let good = fixture(temp.path());
        let cert = temp.path().join("permit_cert");
        let mut bytes = std::fs::read_to_string(&cert).unwrap().into_bytes();
        bytes[259] = if bytes[259] == b'0' { b'1' } else { b'0' };
        std::fs::write(cert, bytes).unwrap();
        assert!(validate(&good).is_err(), "corrupt certificate signature");
        let good = fixture(temp.path());
        let hosting = SigningKey::from_seed(&Secret::from_slice(&[31; 32]).unwrap());
        let leaf = SigningKey::from_seed(&Secret::from_slice(&[33; 32]).unwrap());
        std::fs::write(
            temp.path().join("permit_cert"),
            hex::encode(bh_sync::receipt::certify(&hosting, leaf.public())),
        )
        .unwrap();
        assert!(
            validate(&good).is_err(),
            "receipt-domain certificate is not a permit certificate"
        );
    }

    #[test]
    fn recovery_certificate_matches_runtime_key_and_pinned_root() {
        use bh_crypto::{KemKey, Secret, SigningKey};
        let temp = tempfile::tempdir().unwrap();
        let good = fixture(temp.path());
        assert!(validate(&good).is_ok());
        let cert = temp.path().join("recovery_cert");
        let seed = temp.path().join("recovery_key");
        std::fs::write(&seed, hex::encode([39; 32])).unwrap();
        assert!(validate(&good).is_err(), "wrong recovery seed");
        std::fs::write(&seed, hex::encode([38; 32])).unwrap();
        let other_root = SigningKey::from_seed(&Secret::from_slice(&[40; 32]).unwrap());
        let recovery = KemKey::from_seed(&Secret::from_slice(&[38; 32]).unwrap());
        std::fs::write(
            &cert,
            hex::encode(
                bh_sync::evidence::certify_recovery_key(&other_root, &recovery.public()).encode(),
            ),
        )
        .unwrap();
        assert!(validate(&good).is_err(), "wrong recovery certificate root");
        let hosting = SigningKey::from_seed(&Secret::from_slice(&[31; 32]).unwrap());
        let other_key = KemKey::from_seed(&Secret::from_slice(&[39; 32]).unwrap());
        std::fs::write(
            &cert,
            hex::encode(
                bh_sync::evidence::certify_recovery_key(&hosting, &other_key.public()).encode(),
            ),
        )
        .unwrap();
        assert!(
            validate(&good).is_err(),
            "mismatched recovery certificate key"
        );
        std::fs::write(&cert, "00").unwrap();
        assert!(
            validate(&good).is_err(),
            "invalid recovery certificate length"
        );
        std::fs::remove_file(&seed).unwrap();
        assert!(validate(&good).is_err(), "missing recovery seed");
        // The app's endpoint names another key the root certified.
        let good = fixture(temp.path());
        let mut bad = good.clone();
        bad["endpoint"]["recovery_key"] = hex::encode(
            bh_sync::evidence::certify_recovery_key(&hosting, &other_key.public()).encode(),
        )
        .into();
        assert!(validate_prepare(&bad).is_ok());
        assert!(validate(&bad).is_err(), "endpoint recovery key differs");
    }

    #[test]
    fn offline_packaging_requires_structure_and_deployment_allowlists_not_current_time() {
        use bh_crypto::{Secret, SigningKey};
        let temp = tempfile::tempdir().unwrap();
        let app = SigningKey::from_seed(&Secret::from_slice(&[32; 32]).unwrap());
        let mut input = fixture(temp.path());
        let original = hex::decode(input["endpoint"]["policy"].as_str().unwrap()).unwrap();
        let mut policy: serde_json::Value = serde_json::from_slice(&original).unwrap();
        // Signed but long expired at actual wall time: offline packaging has no currentness claim.
        assert!(validate(&input).is_ok());
        for mutation in ["version", "lifetime", "boot", "builds", "machines"] {
            let original_policy = policy.clone();
            match mutation {
                "version" => policy["version"] = 2.into(),
                "lifetime" => policy["expires_at"] = 1002.into(),
                "boot" => policy["builds"][0]["boot"][3] = vec![0; 47].into(),
                "builds" => policy["builds"] = serde_json::json!([]),
                "machines" => policy["machines"] = serde_json::json!([]),
                _ => unreachable!(),
            }
            let bytes = serde_json::to_vec(&policy).unwrap();
            let signature = app.sign(&bh_confidential_policy::signing_message(&bytes).unwrap());
            input["endpoint"]["policy"] = hex::encode(&bytes).into();
            input["endpoint"]["policy_signature"] = hex::encode(signature).into();
            std::fs::write(temp.path().join("policy"), bytes).unwrap();
            std::fs::write(temp.path().join("policy_signature"), hex::encode(signature)).unwrap();
            assert!(validate(&input).is_err(), "{mutation}");
            policy = original_policy;
        }
    }

    #[test]
    fn configure_emitted_bundle_with_throwaway_inputs_when_requested() {
        use bh_crypto::{Secret, SigningKey};
        let Ok(bundle) = std::env::var("BH_RELEASE_TEST_BUNDLE") else {
            return;
        };
        let temp = tempfile::tempdir().unwrap();
        let mut input = fixture(temp.path());
        let bundle = std::path::Path::new(&bundle);
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(bundle.join("manifest.json")).unwrap()).unwrap();
        input["authz"]["image_id"] = manifest["image"]["image_id"].clone();
        input["authz"]["archive_sha256"] = manifest["image"]["archive_sha256"].clone();
        let raw = serde_json::json!({"schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": manifest["image"]["image_id"]}, "layers": []})
        .to_string();
        let registry = temp.path().join("public-registry-manifest.json");
        std::fs::write(&registry, &raw).unwrap();
        input["authz"]["image"] = format!(
            "registry.invalid/throwaway/authz@sha256:{}",
            hex::encode(bh_crypto::sha256(raw.as_bytes()))
        )
        .into();
        input["authz"]["registry_manifest_file"] = registry.to_str().unwrap().into();
        input["endpoint"]["policy"] = "".into();
        input["endpoint"]["policy_signature"] = "".into();
        let final_files = input["authz"]["files"].clone();
        let final_receipt = input["cloudflare"]["receipt_cert_file"].clone();
        for (name, path) in input["authz"]["files"].as_object_mut().unwrap() {
            *path = temp
                .path()
                .join(format!("absent-{name}"))
                .to_str()
                .unwrap()
                .into();
        }
        input["cloudflare"]["receipt_cert_file"] =
            temp.path().join("absent-receipt").to_str().unwrap().into();
        let inputs = temp.path().join("inputs.json");
        let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/prepare-sync-release.py");
        let run = |command: &str, output: &std::path::Path, extra: &[&str]| {
            let result = std::process::Command::new("python3")
                .arg(&script)
                .arg(command)
                .arg("--bundle")
                .arg(bundle)
                .arg("--inputs")
                .arg(&inputs)
                .args(extra)
                .arg("--output")
                .arg(output)
                .output()
                .unwrap();
            result
        };
        std::fs::write(&inputs, input.to_string()).unwrap();
        let deployment = temp.path().join("deployment");
        let prepared = run("prepare-deployment", &deployment, &[]);
        assert!(
            prepared.status.success(),
            "{}",
            String::from_utf8_lossy(&prepared.stderr)
        );
        assert!(!deployment.join("deployment/endpoint.json").exists());
        assert!(!deployment.join("deployment/worker").exists());
        let app_compose: serde_json::Value = serde_json::from_slice(
            &std::fs::read(deployment.join("deployment/app-compose.json")).unwrap(),
        )
        .unwrap();
        let compose_bytes = app_compose["docker_compose_file"]
            .as_str()
            .unwrap()
            .as_bytes();
        assert_eq!(
            std::fs::read(deployment.join("deployment/compose.json")).unwrap(),
            compose_bytes
        );
        let prepared_manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(deployment.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(
            prepared_manifest["registry_manifest_sha256"],
            hex::encode(bh_crypto::sha256(raw.as_bytes()))
        );
        // The registry pathname is a local read location, not part of the
        // measured deployment. Raw bytes, immutable reference and config still bind.
        let relocated = temp.path().join("relocated-registry.json");
        std::fs::copy(&registry, &relocated).unwrap();
        input["authz"]["registry_manifest_file"] = relocated.to_str().unwrap().into();
        input["authz"]["files"] = final_files;
        input["cloudflare"]["receipt_cert_file"] = final_receipt;
        let hash = hex::decode(
            prepared_manifest["compose_sha256_candidate"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let policy = serde_json::json!({"version": 1, "generation": 1,
            "issued_at": 1, "expires_at": 100,
            "builds": [{"role": "checker", "compose_sha256": hash,
                        "boot": vec![vec![36; 48]; 4]},
                       {"role": "runner", "compose_sha256": vec![42; 32],
                        "boot": vec![vec![43; 48]; 4]}], "machines": [vec![37; 32]]})
        .to_string();
        let app = SigningKey::from_seed(&Secret::from_slice(&[32; 32]).unwrap());
        let signature = app.sign(
            &[
                b"basehero.confidential-policy.v1\0".as_slice(),
                policy.as_bytes(),
            ]
            .concat(),
        );
        std::fs::write(temp.path().join("policy"), &policy).unwrap();
        std::fs::write(temp.path().join("policy_signature"), hex::encode(signature)).unwrap();
        input["endpoint"]["policy"] = hex::encode(&policy).into();
        input["endpoint"]["policy_signature"] = hex::encode(signature).into();
        std::fs::write(&inputs, input.to_string()).unwrap();
        let extra = ["--deployment", deployment.to_str().unwrap()];
        let output = temp.path().join("configured");
        let configured = run("configure", &output, &extra);
        assert!(
            configured.status.success(),
            "{}",
            String::from_utf8_lossy(&configured.stderr)
        );
        // Still valid JSON/config, but the raw digest no longer matches the reference.
        let configured_manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(
            configured_manifest["compose_sha256_candidate"],
            prepared_manifest["compose_sha256_candidate"]
        );
        assert_eq!(
            configured_manifest["registry_manifest_sha256"],
            prepared_manifest["registry_manifest_sha256"]
        );
        std::fs::write(&relocated, format!("{raw}\n")).unwrap();
        let changed_registry = run("configure", &temp.path().join("changed-registry"), &extra);
        assert!(!changed_registry.status.success());
        assert!(!temp.path().join("changed-registry").exists());
        std::fs::copy(&registry, &relocated).unwrap();
        assert_eq!(
            std::fs::read(output.join("config/compose.json")).unwrap(),
            compose_bytes
        );
        for name in ["endpoint.json", "compose.json", "wrangler.json"] {
            let rendered = std::fs::read_to_string(output.join("config").join(name)).unwrap();
            for (seed, label) in [([33; 32], "permit"), ([38; 32], "recovery")] {
                assert!(
                    !rendered.contains(&hex::encode(seed)),
                    "{label} seed leaked into {name}"
                );
            }
        }
        let checked = std::process::Command::new("python3")
            .arg(&script)
            .arg("verify-config")
            .arg("--config")
            .arg(&output)
            .output()
            .unwrap();
        assert!(checked.status.success());
        assert_eq!(
            String::from_utf8_lossy(&checked.stdout).trim(),
            output.join("config/endpoint.json").to_str().unwrap()
        );
        let checker = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/check-sync-release-config.mjs");
        let checked = std::process::Command::new("node")
            .arg(checker)
            .arg(output.join("config/wrangler.json"))
            .output()
            .unwrap();
        assert!(
            checked.status.success(),
            "{}",
            String::from_utf8_lossy(&checked.stderr)
        );
        // Signed wrong checker hash still verifies cryptographically, but cannot configure.
        let mut wrong_policy: serde_json::Value = serde_json::from_str(&policy).unwrap();
        wrong_policy["builds"][0]["compose_sha256"] = serde_json::json!(vec![99; 32]);
        let wrong = wrong_policy.to_string();
        let wrong_signature = app.sign(
            &[
                b"basehero.confidential-policy.v1\0".as_slice(),
                wrong.as_bytes(),
            ]
            .concat(),
        );
        input["endpoint"]["policy"] = hex::encode(&wrong).into();
        input["endpoint"]["policy_signature"] = hex::encode(wrong_signature).into();
        std::fs::write(temp.path().join("policy"), &wrong).unwrap();
        std::fs::write(
            temp.path().join("policy_signature"),
            hex::encode(wrong_signature),
        )
        .unwrap();
        std::fs::write(&inputs, input.to_string()).unwrap();
        assert!(
            !run("configure", &temp.path().join("wrong"), &extra)
                .status
                .success(),
            "{wrong}"
        );
        input["endpoint"]["policy"] = hex::encode(&policy).into();
        input["endpoint"]["policy_signature"] = hex::encode(signature).into();
        std::fs::write(temp.path().join("policy"), &policy).unwrap();
        std::fs::write(temp.path().join("policy_signature"), hex::encode(signature)).unwrap();
        input["authz"]["protected_mount"] = "/changed/path".into();
        std::fs::write(&inputs, input.to_string()).unwrap();
        assert!(
            !run("configure", &temp.path().join("changed-input"), &extra)
                .status
                .success()
        );
        input["authz"]["protected_mount"] = "/fixture/protected".into();
        std::fs::write(&inputs, input.to_string()).unwrap();
        std::fs::write(deployment.join("deployment/compose.json"), "tamper").unwrap();
        assert!(
            !run("configure", &temp.path().join("tampered"), &extra)
                .status
                .success()
        );
    }

    #[test]
    fn preparation_uses_app_parser_without_opening_unavailable_runtime_files() {
        let temp = tempfile::tempdir().unwrap();
        let mut input = fixture(temp.path());
        input["endpoint"]["policy"] = "".into();
        input["endpoint"]["policy_signature"] = "".into();
        for path in input["authz"]["files"].as_object().unwrap().values() {
            std::fs::remove_file(path.as_str().unwrap()).unwrap();
        }
        std::fs::remove_file(input["cloudflare"]["receipt_cert_file"].as_str().unwrap()).unwrap();
        assert!(validate_prepare(&input).is_ok());
        input["endpoint"]["hosting_root"] = "00".repeat(32).into();
        assert!(validate_prepare(&input).is_err());
    }

    #[test]
    fn final_signed_checker_must_match_prepared_hash_not_just_a_valid_policy() {
        let temp = tempfile::tempdir().unwrap();
        let input = fixture(temp.path());
        assert!(validate_with_compose(&input, &[35; 32]).is_ok());
        assert!(validate_with_compose(&input, &[36; 32]).is_err());
    }

    #[test]
    fn incomplete_and_synthetic_endpoints_fail_closed() {
        assert!(validate(&serde_json::json!({})).is_err());
        assert!(validate(&serde_json::json!({"endpoint": {"appraisal": "synthetic"}})).is_err());
    }
}
