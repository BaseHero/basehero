use super::tests::{interval, synthetic_inputs};
use super::*;

#[test]
fn authenticated_horizon_is_conservative_and_half_open() {
    let (claims, log, expected) = synthetic_inputs();
    let admission = interval(1_751_328_000, 1_751_328_001);
    let proof = verified_from_claims(&claims, &log, &expected, admission).unwrap();
    let l = proof.valid_from;
    let e = proof.valid_until;
    assert_eq!(l, admission.earliest.max(claims.latest_issue_date));
    assert_eq!(e, claims.earliest_expiration_date);
    for t in [l, e - 1] {
        proof.check_time(Some(interval(t, t))).unwrap();
        // Sufficient, not necessary: root/CRL issue dates and exclusive expiry
        // deliberately make the new window narrower than legacy strict QVL.
        quote_claims(tests::QUOTE, tests::COLLATERAL, interval(t, t)).unwrap();
    }
    for (a, b) in [(l - 1, l), (e - 1, e), (e, e)] {
        assert_eq!(proof.check_time(Some(interval(a, b))), Err(Error::Quote));
    }
    assert_eq!(proof.check_time(None), Err(Error::TimeUnavailable));
    assert_eq!(
        proof.check_time(Some(interval(e, l))),
        Err(Error::TimeUncertain)
    );
    assert_eq!(
        proof.check_time(Some(interval(l, l + 61))),
        Err(Error::TimeUncertain)
    );
    assert!(verified_from_claims(&claims, &log, &expected, interval(e, e)).is_err());
    assert_eq!(proof.nonce(), &expected.nonce);
    assert_eq!(proof.measured().receiving(), &expected.receiving);
    let synthetic = synthetic_evidence(&expected, admission, None).unwrap();
    synthetic.check_time(Some(admission)).unwrap();
}

#[test]
fn new_heavy_path_calls_real_qvl_once_before_binding_refusal() {
    let (_, log, expected) = synthetic_inputs();
    QVL_CALLS.with(|n| n.set(0));
    let error = verify_evidence(
        Evidence {
            quote: tests::QUOTE,
            collateral: tests::COLLATERAL,
            event_log: &log,
        },
        &expected,
        Some(interval(1_751_328_000, 1_751_328_001)),
    )
    .err();
    assert_eq!(error, Some(Error::Binding)); // genuine archived quote, not fresh keys
    assert_eq!(QVL_CALLS.with(|n| n.get()), 1);
    assert_eq!(
        verify(
            Evidence {
                quote: tests::QUOTE,
                collateral: tests::COLLATERAL,
                event_log: &log
            },
            &expected,
            Some(interval(1_751_328_000, 1_751_328_000))
        )
        .err(),
        Some(Error::Binding)
    );
    let mut quote = tests::QUOTE.to_vec();
    quote[120] ^= 1;
    assert_eq!(
        verify_evidence(
            Evidence {
                quote: &quote,
                collateral: tests::COLLATERAL,
                event_log: &log
            },
            &expected,
            Some(interval(1_751_328_000, 1_751_328_000))
        )
        .err(),
        Some(Error::Quote)
    );
}
