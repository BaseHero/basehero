//! Offline NEAR Cloud Gateway quote tests.
//!
//! The QVL appraisal runs on the archived Intel quote/collateral shipped with
//! the shared attestation crate, which is
//! real but expired and bound to no service key. Every successful assembly here
//! mutates that QVL verdict (or supplies a synthetic event log) in memory, so it
//! proves ordering, binding and policy, never a fresh hardware attestation or a
//! live gateway. The OHTTP keys, compose and event bytes are synthetic.

use super::*;
use crate::near_route::verify_key_config;
use bh_confidential_attestation::quote_claims_with_policy;
use bh_crypto::SigningKey;
use dcap_qvl::{PckCertFlag, Policy as _, QuotePolicy, TcbStatus};

const QUOTE: &[u8] = include_bytes!("../../confidential-attestation/tests/fixtures/tdx_quote");
const COLLATERAL: &[u8] =
    include_bytes!("../../confidential-attestation/tests/fixtures/tdx_quote_collateral.json");

fn archived_time() -> Time {
    Time {
        earliest: 1_751_328_000,
        latest: 1_751_328_001,
        max_uncertainty_secs: 60,
    }
}

/// Lenient flags because the archived Intel quote carries platform flags that a
/// strict policy rejects; this only reaches the QVL appraisal, not our assembly.
fn archived_claims() -> dcap_qvl::QuoteClaims {
    quote_claims_with_policy(QUOTE, COLLATERAL, archived_time(), |now| {
        QuotePolicy::strict(now)
            .allow_smt(true)
            .allow_dynamic_platform(true)
            .allow_cached_keys(true)
    })
    .unwrap()
}

fn td10_mut(claims: &mut dcap_qvl::QuoteClaims) -> &mut dcap_qvl::quote::TDReport10 {
    match &mut claims.report {
        dcap_qvl::quote::Report::TD10(td) => td,
        _ => panic!("archived fixture must be a TD10 report"),
    }
}

fn sha384(parts: &[&[u8]]) -> [u8; 48] {
    use sha2::{Digest as _, Sha384};
    let mut hasher = Sha384::new();
    for part in parts {
        hasher.update(part);
    }
    let mut out = [0u8; 48];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// One synthetic V1 dstack `compose-hash` event, independently digested and
/// folded into a register the way the replay must. Returns the JSON log and the
/// register the quote would need to carry.
fn synthetic_log(payload: [u8; 32]) -> (Vec<u8>, [u8; 48]) {
    let event_type: u32 = 0x0800_0001;
    let mut preimage = event_type.to_le_bytes().to_vec();
    preimage.push(b':');
    preimage.extend_from_slice(b"compose-hash");
    preimage.push(b':');
    preimage.extend_from_slice(&payload);
    let digest = sha384(&[&preimage]);
    let register = sha384(&[&[0u8; 48], &digest]);
    let hex = |bytes: &[u8]| -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() };
    let json = serde_json::json!([{
        "imr": 3,
        "event_type": event_type,
        "digest": hex(&digest),
        "event": "compose-hash",
        "event_payload": hex(&payload),
    }]);
    (serde_json::to_vec(&json).unwrap(), register)
}

/// The reviewed deployment's `app_compose` is the dstack app-compose JSON; the
/// docker-compose YAML is the `docker_compose_file` string inside it, so the
/// pinned image and its newlines are JSON-escaped on the wire.
fn pinned_compose(tag: &str) -> Vec<u8> {
    let yaml = format!("services:\n  cloud-api:\n    image: {GATEWAY_IMAGE}\n    tag: {tag}\n");
    serde_json::to_vec(&serde_json::json!({
        "manifest_version": 2,
        "name": "cloud-api",
        "runner": "docker-compose",
        "docker_compose_file": yaml,
    }))
    .unwrap()
}

fn key_config_bytes() -> Vec<u8> {
    let mut raw = vec![1u8, 0x00, 0x20];
    raw.extend_from_slice(&[0x42u8; 32]);
    raw.extend_from_slice(&4u16.to_be_bytes());
    raw.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    raw
}

/// Owns the byte buffers `Evidence` borrows.
struct Owned {
    log: Vec<u8>,
    compose: Vec<u8>,
    alt_compose: Vec<u8>,
    truncated_config: Vec<u8>,
    bad_signature: Vec<u8>,
}

struct Synthetic {
    claims: dcap_qvl::QuoteClaims,
    config: Vec<u8>,
    signature: Vec<u8>,
    expected: Expected,
    owned: Owned,
}

impl Synthetic {
    fn new() -> Self {
        let signing = SigningKey::generate();
        let signer = signing.public();
        let nonce = [0x5au8; 32];
        let compose = pinned_compose("v1");
        let compose_sha256 = bh_crypto::sha256(&compose);
        // The synthetic RTMR3 log must carry the same replayed `compose-hash`
        // as the quoted `mr_config_id`; the register is derived from it.
        let (log, register) = synthetic_log(compose_sha256);
        let alt_compose = pinned_compose("v2");
        let mut claims = archived_claims();
        let td = td10_mut(&mut claims);
        td.report_data = [0u8; 64];
        td.report_data[..32].copy_from_slice(&signer);
        td.report_data[32..].copy_from_slice(&nonce);
        td.rt_mr3 = register;
        td.mr_config_id = [0u8; 48];
        td.mr_config_id[0] = 1;
        td.mr_config_id[1..33].copy_from_slice(&compose_sha256);

        let config = key_config_bytes();
        let signature = signing.sign(&config).to_vec();
        let mut truncated_config = config.clone();
        truncated_config.pop();
        let mut bad_signature = signature.clone();
        bad_signature[0] ^= 1;
        Synthetic {
            claims,
            config,
            signature,
            expected: Expected::for_tests(signer, nonce, compose_sha256),
            owned: Owned {
                log,
                compose,
                alt_compose,
                truncated_config,
                bad_signature,
            },
        }
    }

    fn evidence(&self) -> Evidence<'_> {
        Evidence {
            quote: &[],
            collateral: &[],
            event_log: &self.owned.log,
            app_compose: &self.owned.compose,
            advertised_nonce: self.expected.nonce,
            advertised_report_data: None,
            ohttp_signing_key: self.expected.signer,
            ohttp_key_config: &self.config,
            ohttp_signature: &self.signature,
        }
    }

    fn assemble(&self) -> Result<VerifiedGateway, Error> {
        assemble(&self.claims, &self.evidence(), &self.expected)
    }
}

#[test]
fn synthetic_gateway_evidence_verifies_and_binds_the_ohttp_signer() {
    let fixture = Synthetic::new();
    let verified = fixture.assemble().unwrap();
    assert_eq!(verified.signer().public_key(), &fixture.expected.signer);
    assert!(!verified.out_of_date());
    assert_eq!(verified.compose_sha256(), &fixture.expected.compose_sha256);
    let parsed = verify_key_config(
        &fixture.config,
        &fixture.signature,
        &GatewaySigner::for_tests(fixture.expected.signer),
    )
    .unwrap();
    assert_eq!(verified.key_config(), &parsed);

    let mut evidence = fixture.evidence();
    evidence.ohttp_signing_key = [0x99u8; 32];
    assert_eq!(
        assemble(&fixture.claims, &evidence, &fixture.expected),
        Err(Error::Binding)
    );

    let mut evidence = fixture.evidence();
    evidence.ohttp_key_config = &fixture.owned.truncated_config;
    assert_eq!(
        assemble(&fixture.claims, &evidence, &fixture.expected),
        Err(Error::KeyConfig)
    );

    let mut evidence = fixture.evidence();
    evidence.ohttp_signature = &fixture.owned.bad_signature;
    assert_eq!(
        assemble(&fixture.claims, &evidence, &fixture.expected),
        Err(Error::KeyConfig)
    );
}

#[test]
fn report_data_nonce_and_advertised_bindings_fail_closed() {
    let fixture = Synthetic::new();

    let mut claims = fixture.claims.clone();
    td10_mut(&mut claims).report_data[63] ^= 1;
    assert_eq!(
        assemble(&claims, &fixture.evidence(), &fixture.expected),
        Err(Error::Binding)
    );

    let mut evidence = fixture.evidence();
    evidence.advertised_report_data = Some([0x11u8; 64]);
    assert_eq!(
        assemble(&fixture.claims, &evidence, &fixture.expected),
        Err(Error::Binding)
    );

    let mut evidence = fixture.evidence();
    evidence.advertised_nonce = [0x22u8; 32];
    assert_eq!(
        assemble(&fixture.claims, &evidence, &fixture.expected),
        Err(Error::Binding)
    );

    // A different expected signer must not accept the quote-bound key.
    let other = Expected::for_tests(
        [0x77u8; 32],
        fixture.expected.nonce,
        fixture.expected.compose_sha256,
    );
    assert_eq!(
        assemble(&fixture.claims, &fixture.evidence(), &other),
        Err(Error::Binding)
    );
}

#[test]
fn measured_compose_pin_and_mrconfig_and_replay_fail_closed() {
    let fixture = Synthetic::new();

    // Bytes that are not a JSON app-compose at all refuse against the pin.
    let mut evidence = fixture.evidence();
    evidence.app_compose = b"services: {}\n";
    assert_eq!(
        assemble(&fixture.claims, &evidence, &fixture.expected),
        Err(Error::Configuration)
    );

    // A genuine JSON app-compose that is simply not the pinned one refuses.
    let mut evidence = fixture.evidence();
    evidence.app_compose = &fixture.owned.alt_compose;
    assert_eq!(
        assemble(&fixture.claims, &evidence, &fixture.expected),
        Err(Error::Configuration)
    );

    // The quoted mr_config_id must be version 1.
    let mut claims = fixture.claims.clone();
    td10_mut(&mut claims).mr_config_id[0] = 2;
    assert_eq!(
        assemble(&claims, &fixture.evidence(), &fixture.expected),
        Err(Error::Configuration)
    );

    // A quoted mr_config_id that is not the pin refuses, even when the supplied
    // app-compose bytes hash to it.
    let mut claims = fixture.claims.clone();
    td10_mut(&mut claims).mr_config_id[1..33]
        .copy_from_slice(&bh_crypto::sha256(&fixture.owned.alt_compose));
    let mut evidence = fixture.evidence();
    evidence.app_compose = &fixture.owned.alt_compose;
    assert_eq!(
        assemble(&claims, &evidence, &fixture.expected),
        Err(Error::Configuration)
    );

    // The strongest binding: the caller may supply the pinned compose bytes,
    // but the attested guest must actually have measured them. Here the quoted
    // mr_config_id and the replayed compose-hash agree on a different compose,
    // so every other check passes and only the pin refuses.
    let (log, register) = synthetic_log([0x55u8; 32]);
    let mut claims = fixture.claims.clone();
    td10_mut(&mut claims).mr_config_id[1..33].copy_from_slice(&[0x55u8; 32]);
    td10_mut(&mut claims).rt_mr3 = register;
    let mut evidence = fixture.evidence();
    evidence.event_log = &log;
    assert_eq!(
        assemble(&claims, &evidence, &fixture.expected),
        Err(Error::Configuration)
    );

    // The replayed RTMR3 compose-hash must equal the quoted mr_config_id: a log
    // that replays a different compose-hash refuses even though it replays.
    let (log, register) = synthetic_log([0x44u8; 32]);
    let mut claims = fixture.claims.clone();
    td10_mut(&mut claims).rt_mr3 = register;
    let mut evidence = fixture.evidence();
    evidence.event_log = &log;
    assert_eq!(
        assemble(&claims, &evidence, &fixture.expected),
        Err(Error::Configuration)
    );
}

#[test]
fn event_log_replay_binding_fails_closed() {
    let fixture = Synthetic::new();

    let mut claims = fixture.claims.clone();
    td10_mut(&mut claims).rt_mr3[0] ^= 1;
    assert_eq!(
        assemble(&claims, &fixture.evidence(), &fixture.expected),
        Err(Error::EventLog)
    );

    let (log, register) = synthetic_log([0x44u8; 32]);
    // Flip a payload nibble so the stored digest no longer matches.
    let mutated = String::from_utf8(log)
        .unwrap()
        .replacen("\"event_payload\":\"44", "\"event_payload\":\"45", 1)
        .into_bytes();
    let mut claims = fixture.claims.clone();
    td10_mut(&mut claims).rt_mr3 = register;
    let mut evidence = fixture.evidence();
    evidence.event_log = &mutated;
    assert_eq!(
        assemble(&claims, &evidence, &fixture.expected),
        Err(Error::EventLog)
    );
}

#[test]
fn td10_attributes_and_ppid_fail_closed() {
    let fixture = Synthetic::new();
    for (index, bit) in [(0usize, 1u8), (0, 0x80), (3, 0x20)] {
        let mut claims = fixture.claims.clone();
        td10_mut(&mut claims).td_attributes[index] |= bit;
        assert_eq!(
            assemble(&claims, &fixture.evidence(), &fixture.expected),
            Err(Error::Quote)
        );
    }
    let mut claims = fixture.claims.clone();
    claims.platform.pck.ppid.pop();
    assert_eq!(
        assemble(&claims, &fixture.evidence(), &fixture.expected),
        Err(Error::Quote)
    );
}

#[test]
fn gateway_policy_accepts_real_out_of_date_levels_but_never_revoked() {
    let fixture = Synthetic::new();
    let now = archived_time().earliest;
    let policy = gateway_policy(now);

    // A real merged `OutOfDate` verdict converges with an `OutOfDate` platform
    // level, whose Intel `tcb_date_tag` is genuinely in the past. QVL cannot
    // produce an `OutOfDate` verdict with an in-date platform level.
    let mut platform = fixture.claims.clone();
    platform.tcb.status = TcbStatus::OutOfDate;
    platform.platform.tcb_level.tcb_status = TcbStatus::OutOfDate;
    assert!(platform.platform.tcb_date_tag < now);
    policy.validate(&platform).unwrap();
    // Plain strict, which is the basis of the worker policy, rejects it.
    assert!(QuotePolicy::strict(now).validate(&platform).is_err());

    // Separately, a real `OutOfDate` QE level with a real past `tcb_date`.
    let mut qe = fixture.claims.clone();
    qe.tcb.status = TcbStatus::OutOfDate;
    qe.qe.tcb_level.tcb_status = TcbStatus::OutOfDate;
    policy.validate(&qe).unwrap();
    assert!(QuotePolicy::strict(now).validate(&qe).is_err());

    // The platform flags the reviewed deployment carried are accepted too.
    let mut flags = fixture.claims.clone();
    flags.platform.pck.smt_enabled = PckCertFlag::True;
    flags.platform.pck.dynamic_platform = PckCertFlag::True;
    flags.platform.pck.cached_keys = PckCertFlag::True;
    policy.validate(&flags).unwrap();
    assert!(QuotePolicy::strict(now).validate(&flags).is_err());

    // Revoked is never acceptable, whatever the grace periods.
    let mut revoked = fixture.claims.clone();
    revoked.tcb.status = TcbStatus::Revoked;
    assert!(!policy.is_status_acceptable(TcbStatus::Revoked));
    assert!(policy.validate(&revoked).is_err());
}

#[test]
fn verify_runs_qvl_with_the_candidate_policy_and_rejects_bad_time() {
    let fixture = Synthetic::new();
    let mut evidence = fixture.evidence();
    evidence.quote = QUOTE;
    evidence.collateral = COLLATERAL;
    // The archived quote passes QVL and TD10, then fails on its own old
    // report_data: proof the public path really appraises before binding.
    assert_eq!(
        verify(evidence, &fixture.expected, Some(archived_time())),
        Err(Error::Binding)
    );

    let mut evidence = fixture.evidence();
    evidence.quote = QUOTE;
    evidence.collateral = COLLATERAL;
    assert_eq!(
        verify(evidence, &fixture.expected, None),
        Err(Error::TimeUnavailable)
    );

    // An interval wider than the caller's uncertainty limit is refused before
    // any QVL appraisal, even with both ends inside the collateral window.
    let uncertain = Time {
        earliest: 1_751_328_000,
        latest: 1_751_328_001,
        max_uncertainty_secs: 0,
    };
    let mut evidence = fixture.evidence();
    evidence.quote = QUOTE;
    evidence.collateral = COLLATERAL;
    assert_eq!(
        verify(evidence, &fixture.expected, Some(uncertain)),
        Err(Error::TimeUncertain)
    );
    let reversed = Time {
        earliest: 1_751_328_001,
        latest: 1_751_328_000,
        max_uncertainty_secs: 60,
    };
    let mut evidence = fixture.evidence();
    evidence.quote = QUOTE;
    evidence.collateral = COLLATERAL;
    assert_eq!(
        verify(evidence, &fixture.expected, Some(reversed)),
        Err(Error::TimeUncertain)
    );

    let far = Time {
        earliest: 1_791_849_600,
        latest: 1_791_849_601,
        max_uncertainty_secs: 60,
    };
    let mut evidence = fixture.evidence();
    evidence.quote = QUOTE;
    evidence.collateral = COLLATERAL;
    assert_eq!(
        verify(evidence, &fixture.expected, Some(far)),
        Err(Error::Quote)
    );
}

#[test]
fn pinned_candidate_constants_match_the_reviewed_deployment() {
    assert_eq!(
        GATEWAY_IMAGE,
        "nearaidev/cloud-api@sha256:79ea161fe2cef0dd4b17c2014f9276056b077469f8b97da15f410a9778aaf45c"
    );
    assert_eq!(
        GATEWAY_SOURCE_COMMIT,
        "e8a534ffba3edf7f51bfe8b207ccdbb2f284a491"
    );
    assert_eq!(
        GATEWAY_SIGNING_IDENTITY,
        [
            0x40, 0x59, 0x9f, 0xb2, 0x84, 0xf4, 0x39, 0x53, 0xbb, 0x35, 0x6b, 0x09, 0x08, 0x0f,
            0xd8, 0x03, 0xc9, 0x60, 0xfc, 0x10, 0x28, 0x5a, 0xd9, 0x0e, 0xca, 0x46, 0x2c, 0xa7,
            0x11, 0xad, 0x4a, 0xcb
        ]
    );
    assert_eq!(
        GATEWAY_COMPOSE_SHA256,
        [
            0x41, 0xe1, 0x8f, 0x38, 0x97, 0x8b, 0x03, 0x14, 0x31, 0xdf, 0xc8, 0xa4, 0xfc, 0xf6,
            0xd8, 0xc3, 0x8d, 0xa6, 0x2b, 0x1b, 0x09, 0x3f, 0xd1, 0xd0, 0xe3, 0x9e, 0x26, 0xee,
            0x6f, 0xad, 0x03, 0x0c
        ]
    );
    let pinned = Expected::pinned([1u8; 32]);
    assert_eq!(pinned.signer, GATEWAY_SIGNING_IDENTITY);
    assert_eq!(pinned.compose_sha256, GATEWAY_COMPOSE_SHA256);
}
