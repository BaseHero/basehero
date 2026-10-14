//! Archived Intel quote/collateral are real (expired); successful assemblies
//! alter QVL claims in memory. Model report follows NEAR's published shape;
//! event log and NVIDIA-shaped NRAS JWT/JWKS are synthetic.
use super::*;
use dcap_qvl::quote::Report as QuoteReport;
use p384::ecdsa::{SigningKey, signature::Signer as _};
use sha2::{Digest as _, Sha384};

const QUOTE: &[u8] = include_bytes!("../../confidential-attestation/tests/fixtures/tdx_quote");
const COLLATERAL: &[u8] =
    include_bytes!("../../confidential-attestation/tests/fixtures/tdx_quote_collateral.json");
const META: &[u8] = br#"{"metadata":{"providerType":"vllm","attestationSupported":true}}"#;
const NONCE: [u8; 32] = [0x5a; 32];
const SIGNER: [u8; 32] = [0x31; 32];
const APP_COMPOSE: &str = "{\"docker_compose_file\":\"services: {}\\n\"}";
fn time() -> Time {
    Time {
        earliest: 1_751_328_000,
        latest: 1_751_328_010,
        max_uncertainty_secs: 60,
    }
}
fn archived_claims() -> QuoteClaims {
    quote_claims_with_policy(QUOTE, COLLATERAL, time(), |now| {
        QuotePolicy::strict(now)
            .allow_smt(true)
            .allow_dynamic_platform(true)
            .allow_cached_keys(true)
    })
    .unwrap()
}
fn td(claims: &mut QuoteClaims) -> &mut dcap_qvl::quote::TDReport10 {
    match &mut claims.report {
        QuoteReport::TD10(td) => td,
        _ => panic!("fixture not TD10"),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn digest(parts: &[&[u8]]) -> [u8; 48] {
    let mut sha = Sha384::new();
    for part in parts {
        sha.update(part);
    }
    sha.finalize().into()
}
fn log_and_register(compose_hash: &[u8; 32]) -> (serde_json::Value, [u8; 48]) {
    // dstack RTMR3 event names/order; bodies, hashes and quoted register are
    // synthetic.
    const NAMES: [&str; 14] = [
        "system-preparing",
        "app-id",
        "compose-hash",
        "instance-id",
        "boot-mr-done",
        "mr-kms",
        "os-image-hash",
        "key-provider",
        "storage-fs",
        "system-ready",
        "nearai-replica-report-key-v1",
        "nearai-replica-report-key-v1",
        "nearai-replica-report-key-v1",
        "nearai-replica-report-key-v1",
    ];
    let mut register = [0; 48];
    let mut events = Vec::new();
    for name in NAMES {
        let payload = if name == "compose-hash" {
            compose_hash.as_slice()
        } else {
            b"synthetic"
        };
        let mut preimage = 0x08000001u32.to_le_bytes().to_vec();
        preimage.push(b':');
        preimage.extend_from_slice(name.as_bytes());
        preimage.push(b':');
        preimage.extend_from_slice(payload);
        let event_digest = digest(&[&preimage]);
        register = digest(&[&register, &event_digest]);
        events.push(serde_json::json!({
            "imr": 3, "event_type": 134217729, "digest": hex(&event_digest),
            "event": name, "event_payload": hex(payload)
        }));
    }
    (serde_json::Value::Array(events), register)
}
fn report_fixture(claims: &mut QuoteClaims) -> (serde_json::Value, [u8; 32]) {
    let hash = bh_crypto::sha256(APP_COMPOSE.as_bytes());
    let (log, register) = log_and_register(&hash);
    let td = td(claims);
    td.report_data[..32].copy_from_slice(&SIGNER);
    td.report_data[32..].copy_from_slice(&NONCE);
    td.rt_mr3 = register;
    td.mr_config_id = [0; 48];
    td.mr_config_id[0] = 1;
    td.mr_config_id[1..33].copy_from_slice(&hash);
    let report = serde_json::json!({
        "request_nonce": hex(&NONCE), "signing_algo": "ed25519",
        "signing_address": hex(&SIGNER), "intel_quote": hex(QUOTE),
        "report_data": hex(&td.report_data), "event_log": log,
        "info": {"tcb_info": {"app_compose": APP_COMPOSE}},
        "nvidia_payload": serde_json::json!({"nonce": hex(&NONCE), "evidence": []}).to_string(),
        "signing_public_key": hex(&SIGNER)
    });
    (report, hash)
}
fn token(claims: serde_json::Value, kid: &str) -> (String, Vec<u8>) {
    token_with_header(
        claims,
        serde_json::json!({"alg":"ES384","kid":kid,"typ":"JWT"}),
        kid,
    )
}
fn token_with_header(
    claims: serde_json::Value,
    header: serde_json::Value,
    kid: &str,
) -> (String, Vec<u8>) {
    let key = SigningKey::from_bytes((&[3u8; 48]).into()).unwrap();
    let point = key.verifying_key().to_encoded_point(false);
    let jwks = serde_json::to_vec(&serde_json::json!({"keys": [{
        "kty": "EC", "crv": "P-384", "alg": "ES384", "use": "sig", "kid": kid,
        "x": URL_SAFE_NO_PAD.encode(point.x().unwrap()), "y": URL_SAFE_NO_PAD.encode(point.y().unwrap())
    }]})).unwrap();
    let header = URL_SAFE_NO_PAD.encode(header.to_string());
    let body = URL_SAFE_NO_PAD.encode(claims.to_string());
    let message = format!("{header}.{body}");
    let sig: Signature = key.sign(message.as_bytes());
    (
        format!("{message}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes())),
        jwks,
    )
}
fn claims() -> serde_json::Value {
    // NVIDIA's public NRAS overall-claims samples have no aud claim.
    serde_json::json!({"sub": "GPU", "x-nvidia-ver": "2.0",
        "iss": "https://nras.attestation.nvidia.com", "jti": "synthetic-id",
        "eat_nonce": hex(&NONCE), "x-nvidia-overall-att-result": true,
        "submods": {}, "iat": 1_751_328_002u64, "nbf": 1_751_328_002u64,
        "exp": 1_751_329_000u64})
}
fn model(report: &serde_json::Value) -> Report {
    serde_json::from_value(report.clone()).unwrap()
}
fn nras<'a>(token: &'a str, jwks: &'a [u8]) -> NrasEvidence<'a> {
    NrasEvidence { token, jwks }
}
fn expected<'a>(hashes: &'a [[u8; 32]]) -> Expected<'a> {
    Expected::new(NONCE, hashes)
}

#[test]
fn metadata_and_missing_evidence_fail_closed() {
    let hashes = [[9; 32]];
    let expected = expected(&hashes);
    assert_eq!(
        verify(b"{}", b"{}", &[], &[], &expected, None),
        Err(Error::Metadata)
    );
    for metadata in [
        br#"{"metadata":{"providerType":"other","attestationSupported":true}}"#.as_slice(),
        br#"{"metadata":{"providerType":"vllm","attestationSupported":false}}"#,
        br#"{"metadata":{"provider_type":"vllm","attestation_supported":true}}"#,
    ] {
        assert_eq!(
            verify(metadata, b"{}", &[], &[], &expected, None),
            Err(Error::Metadata)
        );
    }
    assert_eq!(
        verify(
            META,
            br#"{"model_attestations":[]}"#,
            &[],
            &[],
            &expected,
            Some(time())
        ),
        Err(Error::Evidence)
    );
    assert_eq!(
        verify(
            META,
            br#"{"model_attestations":[{}]}"#,
            &[],
            &[],
            &expected,
            Some(time())
        ),
        Err(Error::Evidence)
    );
}

#[test]
fn public_verifier_requires_one_collateral_and_one_nras_per_candidate() {
    let mut evidence = archived_claims();
    let (report, hash) = report_fixture(&mut evidence);
    let raw =
        serde_json::to_vec(&serde_json::json!({"model_attestations": [report.clone(), report]}))
            .unwrap();
    let (jwt, jwks) = token(claims(), "synthetic-key-1");
    let hashes = [hash];
    let expected = expected(&hashes);
    assert_eq!(
        verify(
            META,
            &raw,
            &[COLLATERAL],
            &[nras(&jwt, &jwks), nras(&jwt, &jwks)],
            &expected,
            Some(time())
        ),
        Err(Error::Evidence)
    );
    assert_eq!(
        verify(
            META,
            &raw,
            &[COLLATERAL, COLLATERAL],
            &[nras(&jwt, &jwks)],
            &expected,
            Some(time())
        ),
        Err(Error::Evidence)
    );
}

#[test]
fn public_candidate_pipeline_rejects_bad_second_candidate() {
    let mut evidence = archived_claims();
    let (report, hash) = report_fixture(&mut evidence);
    let mut bad = report.clone();
    bad["signing_public_key"] = serde_json::json!(hex(&[0x47; 32]));
    let raw =
        serde_json::to_vec(&serde_json::json!({"model_attestations": [report, bad]})).unwrap();
    let (jwt, jwks) = token(claims(), "synthetic-key-1");
    let hashes = [hash];
    let expected = expected(&hashes);
    assert_eq!(
        verify_with(
            META,
            &raw,
            &[COLLATERAL, COLLATERAL],
            &[nras(&jwt, &jwks), nras(&jwt, &jwks)],
            &expected,
            Some(time()),
            |_, _| Ok(evidence.clone())
        ),
        Err(Error::Key)
    );
}

#[test]
fn public_verifier_rejects_tampered_quote_before_key_construction() {
    let mut evidence = archived_claims();
    let (mut report, hash) = report_fixture(&mut evidence);
    let (jwt, jwks) = token(claims(), "synthetic-key-1");
    let hashes = [hash];
    let expected = expected(&hashes);
    // This is the archived original quote, not the synthetic claims above.
    // Its report_data doesn't match our model key even when QVL passes.
    let raw =
        serde_json::to_vec(&serde_json::json!({"model_attestations": [report.clone()]})).unwrap();
    assert_eq!(
        verify(
            META,
            &raw,
            &[COLLATERAL],
            &[nras(&jwt, &jwks)],
            &expected,
            Some(time())
        ),
        Err(Error::Binding)
    );
    let mut changed = QUOTE.to_vec();
    // The fixed quote body is signed; the last byte may be an unused extension.
    changed[120] ^= 1;
    report["intel_quote"] = serde_json::json!(hex(&changed));
    let raw = serde_json::to_vec(&serde_json::json!({"model_attestations": [report]})).unwrap();
    assert_eq!(
        verify(
            META,
            &raw,
            &[COLLATERAL],
            &[nras(&jwt, &jwks)],
            &expected,
            Some(time())
        ),
        Err(Error::Quote)
    );
}

#[test]
fn model_quote_bindings_and_each_candidate_fail_closed() {
    let mut evidence = archived_claims();
    let (report, hash) = report_fixture(&mut evidence);
    let hashes = [hash];
    let expected = expected(&hashes);
    let (jwt, jwks) = token(claims(), "synthetic-key-1");
    let nras = nras(&jwt, &jwks);
    let parsed = model(&report);
    let key = assemble(&parsed, &evidence, &nras, &expected, time()).unwrap();
    assert_eq!(key.public_key(), &SIGNER);
    assert_eq!(key.compose_sha256(), &hash);
    // The SDK accepts both JSON-array and JSON-string eventLog, and object or
    // JSON-string tcb_info. Neither format is a different trust path.
    let mut encoded = report.clone();
    encoded["event_log"] = serde_json::json!(report["event_log"].to_string());
    encoded["info"]["tcb_info"] = serde_json::json!(report["info"]["tcb_info"].to_string());
    assert!(assemble(&model(&encoded), &evidence, &nras, &expected, time()).is_ok());
    let mut changed = report.clone();
    changed["request_nonce"] = serde_json::json!(hex(&[0x44; 32]));
    assert_eq!(
        assemble(&model(&changed), &evidence, &nras, &expected, time()),
        Err(Error::Binding)
    );
    let mut changed = report.clone();
    changed["tls_cert_fingerprint"] = serde_json::json!(hex(&[0x44; 32]));
    assert_eq!(
        assemble(&model(&changed), &evidence, &nras, &expected, time()),
        Err(Error::Binding)
    );
    let mut changed = report.clone();
    changed["report_data"] = serde_json::json!(hex(&[0x44; 64]));
    assert_eq!(
        assemble(&model(&changed), &evidence, &nras, &expected, time()),
        Err(Error::Binding)
    );
    let mut changed = report.clone();
    changed["signing_public_key"] = serde_json::json!(hex(&[0x47; 32]));
    assert_eq!(
        assemble(&model(&changed), &evidence, &nras, &expected, time()),
        Err(Error::Key)
    );
    let mut changed = report.clone();
    changed["signing_public_key"] = serde_json::Value::Null;
    assert_eq!(
        assemble(&model(&changed), &evidence, &nras, &expected, time()),
        Err(Error::Key)
    );
    let mut changed = report.clone();
    changed["nvidia_payload"] = serde_json::Value::Null;
    assert_eq!(
        assemble(&model(&changed), &evidence, &nras, &expected, time()),
        Err(Error::Gpu)
    );
    let mut changed = report.clone();
    changed["nvidia_payload"] =
        serde_json::json!(serde_json::json!({"nonce": hex(&[0x44; 32])}).to_string());
    assert_eq!(
        assemble(&model(&changed), &evidence, &nras, &expected, time()),
        Err(Error::Gpu)
    );
    let mut changed = report.clone();
    changed["event_log"][0]["event_payload"] = serde_json::json!(hex(&[0x55; 32]));
    assert_eq!(
        assemble(&model(&changed), &evidence, &nras, &expected, time()),
        Err(Error::EventLog)
    );
    let mut changed = report.clone();
    changed["info"]["tcb_info"]["app_compose"] = serde_json::json!("changed compose");
    assert_eq!(
        assemble(&model(&changed), &evidence, &nras, &expected, time()),
        Err(Error::Configuration)
    );
    let no_approved_hash = Expected::new(NONCE, &[[0x22; 32]]);
    assert_eq!(
        assemble(&model(&report), &evidence, &nras, &no_approved_hash, time()),
        Err(Error::Configuration)
    );
    let mut altered = evidence.clone();
    td(&mut altered).rt_mr3[0] ^= 1;
    assert_eq!(
        assemble(&model(&report), &altered, &nras, &expected, time()),
        Err(Error::EventLog)
    );
    let mut altered = evidence.clone();
    altered.tcb.status = TcbStatus::OutOfDate;
    assert_eq!(
        assemble(&model(&report), &altered, &nras, &expected, time()),
        Err(Error::Quote)
    );
    let mut altered = evidence.clone();
    td(&mut altered).td_attributes[0] = 1;
    assert_eq!(
        assemble(&model(&report), &altered, &nras, &expected, time()),
        Err(Error::Quote)
    );
    let mut altered = evidence.clone();
    td(&mut altered).report_data[0] ^= 1;
    let mut no_advertised = report.clone();
    no_advertised["report_data"] = serde_json::Value::Null;
    assert_eq!(
        assemble(&model(&no_advertised), &altered, &nras, &expected, time()),
        Err(Error::Binding)
    );
}

#[test]
fn nras_signature_issuer_nonce_freshness_and_verdict_are_required() {
    let hashes = [[0; 32]];
    let expected = expected(&hashes);
    let (jwt, jwks) = token(claims(), "synthetic-key-1");
    assert_eq!(verify_nras(&nras(&jwt, &jwks), &expected, time()), Ok(()));
    for missing in [
        "exp",
        "nbf",
        "iat",
        "iss",
        "eat_nonce",
        "x-nvidia-overall-att-result",
    ] {
        let mut value = claims();
        value.as_object_mut().unwrap().remove(missing);
        let (jwt, jwks) = token(value, "synthetic-key-1");
        assert_eq!(
            verify_nras(&nras(&jwt, &jwks), &expected, time()),
            Err(Error::Gpu),
            "{missing}"
        );
    }
    for (field, bad) in [
        ("iss", serde_json::json!("https://attacker.test")),
        ("eat_nonce", serde_json::json!(hex(&[9; 32]))),
        ("x-nvidia-overall-att-result", serde_json::json!(false)),
        ("iat", serde_json::json!(1_751_328_011u64)),
        ("nbf", serde_json::json!(1_751_328_011u64)),
        ("exp", serde_json::json!(1_751_328_010u64)),
    ] {
        let mut claims = claims();
        claims[field] = bad;
        let (jwt, jwks) = token(claims, "synthetic-key-1");
        assert_eq!(
            verify_nras(&nras(&jwt, &jwks), &expected, time()),
            Err(Error::Gpu),
            "{field}"
        );
    }
    let mut wrong_usage: serde_json::Value = serde_json::from_slice(&jwks).unwrap();
    wrong_usage["keys"][0]["key_ops"] = serde_json::json!(["decrypt"]);
    assert_eq!(
        verify_nras(
            &nras(&jwt, &serde_json::to_vec(&wrong_usage).unwrap()),
            &expected,
            time()
        ),
        Err(Error::Gpu)
    );
    let (other, _) = token(claims(), "other-key");
    assert_eq!(
        verify_nras(&nras(&other, &jwks), &expected, time()),
        Err(Error::Gpu)
    );
    let mut corrupt = jwt.clone().into_bytes();
    let last = corrupt.len() - 1;
    corrupt[last] = if corrupt[last] == b'A' { b'B' } else { b'A' };
    assert_eq!(
        verify_nras(
            &nras(std::str::from_utf8(&corrupt).unwrap(), &jwks),
            &expected,
            time()
        ),
        Err(Error::Gpu)
    );
    // The RS256-labelled header is itself ES384-signed: only the alg gate rejects it.
    let (wrong_alg, _) = token_with_header(
        claims(),
        serde_json::json!({"alg":"RS256","kid":"synthetic-key-1","typ":"JWT"}),
        "synthetic-key-1",
    );
    assert_eq!(
        verify_nras(&nras(&wrong_alg, &jwks), &expected, time()),
        Err(Error::Gpu)
    );
    let mut duplicate: serde_json::Value = serde_json::from_slice(&jwks).unwrap();
    let copy = duplicate["keys"][0].clone();
    duplicate["keys"].as_array_mut().unwrap().push(copy);
    assert_eq!(
        verify_nras(
            &nras(&jwt, &serde_json::to_vec(&duplicate).unwrap()),
            &expected,
            time()
        ),
        Err(Error::Gpu)
    );
}
