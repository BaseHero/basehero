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
fn returned_report_count_is_bounded_before_appraisal_and_every_last_candidate_checked() {
    use std::cell::Cell;
    let mut evidence = archived_claims();
    let (report, hash) = report_fixture(&mut evidence);
    let (jwt, jwks) = token(claims(), "synthetic-key-1");
    let hashes = [hash];
    let expected = expected(&hashes);
    for count in [0, 1, 32, 33, 256] {
        let raw = serde_json::to_vec(
            &serde_json::json!({"model_attestations": vec![report.clone(); count]}),
        )
        .unwrap();
        if (1..=32).contains(&count) && raw.len() <= MAX_INPUT_BYTES {
            assert_eq!(preflight_reports(META, &raw), Ok(count));
        } else {
            assert!(matches!(
                preflight_reports(META, &raw),
                Err(Error::Evidence | Error::TooLarge)
            ));
        }
        let collateral = vec![COLLATERAL; count];
        let nras = (0..count).map(|_| nras(&jwt, &jwks)).collect::<Vec<_>>();
        let appraisals = Cell::new(0);
        let result = verify_with(
            META,
            &raw,
            &collateral,
            &nras,
            &expected,
            Some(time()),
            |_, _| {
                appraisals.set(appraisals.get() + 1);
                Ok(evidence.clone())
            },
        );
        if (1..=32).contains(&count) && raw.len() <= MAX_INPUT_BYTES {
            assert_eq!(result.unwrap().len(), count);
            assert_eq!(appraisals.get(), count);
        } else {
            assert!(matches!(result, Err(Error::Evidence | Error::TooLarge)));
            assert_eq!(appraisals.get(), 0);
        }
    }
    let mut bad = report.clone();
    bad["signing_public_key"] = serde_json::json!(hex(&[0x44; 32]));
    let mut reports = vec![report; 32];
    reports[31] = bad;
    let raw = serde_json::to_vec(&serde_json::json!({"model_attestations": reports})).unwrap();
    let collateral = vec![COLLATERAL; 32];
    let nras = (0..32).map(|_| nras(&jwt, &jwks)).collect::<Vec<_>>();
    let appraisals = Cell::new(0);
    assert_eq!(
        verify_with(
            META,
            &raw,
            &collateral,
            &nras,
            &expected,
            Some(time()),
            |_, _| {
                appraisals.set(appraisals.get() + 1);
                Ok(evidence.clone())
            }
        ),
        Err(Error::Key)
    );
    assert_eq!(appraisals.get(), 32);
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
fn signed_policy_model_hash_drives_real_assembly() {
    use crate::provider_policy::{self, Install, Trust};
    let mut evidence = archived_claims();
    let (report, hash) = report_fixture(&mut evidence);
    let key = bh_crypto::SigningKey::from_seed(&bh_crypto::Secret::from_slice(&[7; 32]).unwrap());
    let trust = Trust {
        root: key.public(),
        key_id: *b"TESTKEY1",
        provider: "near",
        models: &[MODEL],
        app_build_date: 1_751_328_000,
        max_lifetime_secs: 10_000,
    };
    let mut payload = vec![1, 4];
    payload.extend(b"near");
    payload.extend(11u64.to_be_bytes());
    payload.extend(1_751_327_999u64.to_be_bytes());
    payload.extend(1_751_337_000u64.to_be_bytes());
    payload.extend(1u16.to_be_bytes());
    payload.push(2);
    payload.push(MODEL.len() as u8);
    payload.extend(MODEL.as_bytes());
    payload.extend(hash);
    let mut bytes = b"BHPOL001TESTKEY1".to_vec();
    bytes.extend((payload.len() as u32).to_be_bytes());
    bytes.extend(&payload);
    let mut signed = b"BaseHero provider-admission v1\0".to_vec();
    signed.extend(&payload);
    bytes.extend(key.sign(&signed));
    let policy_time = Time {
        earliest: time().earliest,
        latest: time().earliest,
        max_uncertainty_secs: 0,
    };
    let state = match provider_policy::install(None, &bytes, &trust, Some(policy_time)) {
        Install::Installed {
            state,
            usable_now: true,
        } => state,
        _ => panic!("signed fixture rejected"),
    };
    let expected =
        provider_policy::expected_model(state.snapshot(), MODEL, NONCE, Some(policy_time)).unwrap();
    let (jwt, jwks) = token(claims(), "synthetic-key-1");
    evidence.earliest_expiration_date = 1_751_328_500;
    let result = assemble(
        &model(&report),
        &evidence,
        &nras(&jwt, &jwks),
        &expected,
        time(),
    )
    .unwrap();
    assert_eq!(result.compose_sha256(), &hash);
    assert_eq!(result.model(), MODEL);
    assert_eq!(result.valid_until(), 1_751_328_500);
    assert_eq!(
        provider_policy::check_current(
            state.snapshot(),
            provider_policy::RouteEvidence::Model(&result),
            Some(policy_time)
        ),
        Ok(())
    );
    let at = |earliest| {
        Some(Time {
            earliest,
            latest: earliest,
            max_uncertainty_secs: 0,
        })
    };
    assert_eq!(
        provider_policy::check_current(
            state.snapshot(),
            provider_policy::RouteEvidence::Model(&result),
            at(1_751_328_499)
        ),
        Ok(())
    );
    assert_eq!(
        provider_policy::check_current(
            state.snapshot(),
            provider_policy::RouteEvidence::Model(&result),
            at(1_751_328_500)
        ),
        Err(provider_policy::Reject::Expired)
    );
    let mut long_claims = evidence.clone();
    long_claims.earliest_expiration_date = 1_751_339_000;
    let mut long_jwt_claims = claims();
    long_jwt_claims["exp"] = serde_json::json!(1_751_338_000u64);
    let (long_jwt, long_jwks) = token(long_jwt_claims, "synthetic-key-1");
    let long_key = assemble(
        &model(&report),
        &long_claims,
        &nras(&long_jwt, &long_jwks),
        &expected,
        time(),
    )
    .unwrap();
    assert_eq!(
        provider_policy::check_current(
            state.snapshot(),
            provider_policy::RouteEvidence::Model(&long_key),
            at(1_751_337_000)
        ),
        Err(provider_policy::Reject::Expired)
    );
    let make = |version: u64, entries: &[u8], count: u16| {
        let mut p = payload[..32].to_vec();
        p[6..14].copy_from_slice(&version.to_be_bytes());
        p[30..32].copy_from_slice(&count.to_be_bytes());
        p.extend(entries);
        let mut b = b"BHPOL001TESTKEY1".to_vec();
        b.extend((p.len() as u32).to_be_bytes());
        b.extend(&p);
        let mut signed = b"BaseHero provider-admission v1\0".to_vec();
        signed.extend(&p);
        b.extend(key.sign(&signed));
        b
    };
    let other_hash = [0x44; 32];
    let mut other_model = payload[32..].to_vec();
    let hash_start = other_model.len() - 32;
    other_model[hash_start..].copy_from_slice(&other_hash);
    let retired = match provider_policy::install(
        Some(&state),
        &make(12, &other_model, 1),
        &trust,
        Some(policy_time),
    ) {
        Install::Installed { state, .. } => state,
        _ => panic!("retirement rejected"),
    };
    assert_eq!(
        provider_policy::check_current(
            retired.snapshot(),
            provider_policy::RouteEvidence::Model(&result),
            Some(policy_time)
        ),
        Err(provider_policy::Reject::Denied)
    );
    let withdrawal = match provider_policy::install(
        Some(&state),
        &make(12, &[], 0),
        &trust,
        Some(policy_time),
    ) {
        Install::Installed {
            state,
            usable_now: false,
        } => state,
        _ => panic!("withdrawal rejected"),
    };
    assert_eq!(
        provider_policy::check_current(
            withdrawal.snapshot(),
            provider_policy::RouteEvidence::Model(&result),
            Some(policy_time)
        ),
        Err(provider_policy::Reject::Denied)
    );
    let mut early = claims();
    early["exp"] = serde_json::json!(1_751_328_250u64);
    let (early_jwt, early_jwks) = token(early, "synthetic-key-1");
    let short = assemble(
        &model(&report),
        &evidence,
        &nras(&early_jwt, &early_jwks),
        &expected,
        time(),
    )
    .unwrap();
    assert_eq!(short.valid_until(), 1_751_328_250);
    assert_eq!(
        provider_policy::check_current(
            state.snapshot(),
            provider_policy::RouteEvidence::Model(&short),
            at(1_751_328_250)
        ),
        Err(provider_policy::Reject::Expired)
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
    assert_eq!(
        verify_nras(&nras(&jwt, &jwks), &expected, time()),
        Ok(1_751_329_000)
    );
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
