use bh_confidential_attestation::{Error, Evidence, Expected, Time, report_data, verify};
use bh_confidential_policy::Role;
use std::sync::OnceLock;

const QUOTE: &[u8] = include_bytes!("fixtures/tdx_quote");
const COLLATERAL: &[u8] = include_bytes!("fixtures/tdx_quote_collateral.json");
const SEPARATE_VECTOR: &[u8] = include_bytes!("fixtures/tdx-lite-getquote.json");

fn expected() -> Expected {
    Expected {
        signing: [1; 32],
        receiving: [2; 1216],
        nonce: [3; 32],
        role: Role::Runner,
    }
}
fn archived() -> Evidence<'static> {
    static LOG: OnceLock<Vec<u8>> = OnceLock::new();
    let event_log = LOG.get_or_init(|| {
        let fixture: serde_json::Value = serde_json::from_slice(SEPARATE_VECTOR).unwrap();
        fixture["event_log"].as_str().unwrap().as_bytes().to_vec()
    });
    Evidence {
        quote: QUOTE,
        collateral: COLLATERAL,
        event_log,
    }
}
fn time() -> Option<Time> {
    Some(Time {
        earliest: 1_751_328_000,
        latest: 1_751_328_001,
        max_uncertainty_secs: 10,
    })
}

#[test]
fn binding_vector_and_substitution() {
    let binding = report_data(
        &expected().signing,
        &expected().receiving,
        &expected().nonce,
    );
    assert_eq!(
        &binding[..32],
        &[
            0x9c, 0x50, 0xa0, 0x28, 0xd5, 0x11, 0x43, 0x8d, 0x2c, 0xd2, 0xe7, 0xe6, 0x1d, 0x90,
            0xde, 0x1f, 0x18, 0x11, 0x86, 0x50, 0xd4, 0xee, 0x38, 0x3a, 0x3f, 0x19, 0x38, 0xff,
            0x34, 0x81, 0xa8, 0x66,
        ]
    );
    assert_eq!(&binding[32..], &[0; 32]);
    let mut changed = expected();
    changed.signing[0] ^= 1;
    assert_ne!(
        binding,
        report_data(&changed.signing, &changed.receiving, &changed.nonce)
    );
    let mut changed = expected();
    changed.receiving[0] ^= 1;
    assert_ne!(
        binding,
        report_data(&changed.signing, &changed.receiving, &changed.nonce)
    );
    let mut changed = expected();
    changed.nonce[0] ^= 1;
    assert_ne!(
        binding,
        report_data(&changed.signing, &changed.receiving, &changed.nonce)
    );
}

#[test]
fn rejects_untrusted_time_and_oversize_before_parsing() {
    assert_eq!(
        verify(archived(), &expected(), None),
        Err(Error::TimeUnavailable)
    );
    for time in [
        Time {
            earliest: 2,
            latest: 1,
            max_uncertainty_secs: 10,
        },
        Time {
            earliest: 1,
            latest: 20,
            max_uncertainty_secs: 10,
        },
    ] {
        assert_eq!(
            verify(archived(), &expected(), Some(time)),
            Err(Error::TimeUncertain)
        );
    }
    let oversize = vec![0; 1_048_577];
    let mut evidence = archived();
    evidence.event_log = &oversize;
    assert_eq!(verify(evidence, &expected(), time()), Err(Error::TooLarge));
    let mut evidence = archived();
    evidence.quote = &oversize;
    assert_eq!(verify(evidence, &expected(), time()), Err(Error::TooLarge));
    let mut evidence = archived();
    evidence.collateral = &oversize;
    assert_eq!(verify(evidence, &expected(), time()), Err(Error::TooLarge));
}

#[test]
fn unrelated_valid_archived_quote_and_separate_log_are_not_combined_proof() {
    assert_eq!(verify(archived(), &expected(), time()), Err(Error::Binding));
    let mut wrong_key = expected();
    wrong_key.signing[0] ^= 1;
    assert_eq!(verify(archived(), &wrong_key, time()), Err(Error::Binding));
    let mut wrong_nonce = expected();
    wrong_nonce.nonce[0] ^= 1;
    assert_eq!(
        verify(archived(), &wrong_nonce, time()),
        Err(Error::Binding)
    );
    let later = Some(Time {
        earliest: 1_791_849_600,
        latest: 1_791_849_601,
        max_uncertainty_secs: 10,
    });
    assert!(verify(archived(), &expected(), later).is_err());
    let mut evidence = archived();
    evidence.collateral = b"not json";
    assert_eq!(verify(evidence, &expected(), time()), Err(Error::Encoding));
}
