use bh_crypto::{Secret, SigningKey};
use bh_sync::evidence::{
    self, AcceptedHead, ConfirmationClaim, EvidenceError, OrderingConfirmation,
    RecoveryKeyCertificate, TimeBounds,
};
use bh_sync::permit::{self, LogId, LogKind};
use bh_sync::{Digest, Head};

fn key(n: u8) -> SigningKey {
    SigningKey::from_seed(&Secret::from_slice(&[n; 32]).unwrap())
}
fn log() -> LogId {
    LogId {
        kind: LogKind::Account,
        id: [5; 32],
    }
}
fn head(n: u8) -> Head {
    Head {
        position: n as u64,
        hash: Digest([n; 32]),
    }
}
fn claim() -> ConfirmationClaim {
    ConfirmationClaim {
        log: log(),
        original: evidence::original_digest(b"orig"),
        original_previous: head(1),
        original_head: head(2),
        body: Some(Digest([3; 32])),
        ordered: head(4),
        bounds: TimeBounds {
            earliest_ms: 100,
            latest_ms: 104,
        },
    }
}
fn confirmation() -> OrderingConfirmation {
    OrderingConfirmation::sign(&key(2), &permit::certify(&key(1), key(2).public()), claim())
}

#[test]
fn confirmation_verifies_only_for_its_original_body_and_root() {
    let c = confirmation();
    assert_eq!(
        c.verify_for(&key(1).public(), b"orig", Some(Digest([3; 32])))
            .unwrap()
            .bounds
            .latest_ms,
        104
    );
    assert_eq!(
        c.verify_for(&key(1).public(), b"other", Some(Digest([3; 32])))
            .err(),
        Some(EvidenceError::Binding)
    );
    assert_eq!(
        c.verify_for(&key(1).public(), b"orig", None).err(),
        Some(EvidenceError::Binding)
    );
    assert_eq!(
        c.verify_for(&key(9).public(), b"orig", Some(Digest([3; 32])))
            .err(),
        Some(EvidenceError::Certificate)
    );
    assert_eq!(c.commitment(), bh_crypto::hash(&c.encode()));
}
#[test]
fn every_confirmation_field_is_signed() {
    let encoded = confirmation().encode();
    for offset in [3, 35, 67, 107, 147, 180, 220, 228] {
        let mut bytes = encoded;
        bytes[offset] ^= 1;
        if let Ok(changed) = OrderingConfirmation::decode(&bytes) {
            assert_eq!(
                changed.verify(&key(1).public()).err(),
                Some(EvidenceError::Signature),
                "offset {offset}"
            );
        }
    }
}
#[test]
fn confirmation_refuses_inverted_bounds_and_base_logs() {
    let mut c = claim();
    c.bounds.earliest_ms = 105;
    let bytes =
        OrderingConfirmation::sign(&key(2), &permit::certify(&key(1), key(2).public()), c).encode();
    assert_eq!(
        OrderingConfirmation::decode(&bytes).err(),
        Some(EvidenceError::Encoding)
    );
    let mut c = claim();
    c.log.kind = LogKind::Base;
    let bytes =
        OrderingConfirmation::sign(&key(2), &permit::certify(&key(1), key(2).public()), c).encode();
    assert_eq!(
        OrderingConfirmation::decode(&bytes).err(),
        Some(EvidenceError::Encoding)
    );
}
#[test]
fn accepted_head_binds_the_requesters_challenge() {
    let cert = permit::certify(&key(1), key(2).public());
    let bytes = AcceptedHead::sign(
        &key(2),
        &cert,
        log(),
        [7; 32],
        head(2),
        [8; 32],
        TimeBounds {
            earliest_ms: 100,
            latest_ms: 104,
        },
    );
    let result = AcceptedHead::verify(&bytes, &key(1).public(), log(), &[7; 32]).unwrap();
    assert_eq!(result.evidence, [8; 32]);
    assert_eq!(
        AcceptedHead::verify(&bytes, &key(1).public(), log(), &[8; 32]).err(),
        Some(EvidenceError::Signature)
    );
    assert_eq!(
        AcceptedHead::verify(
            &bytes,
            &key(1).public(),
            LogId {
                id: [6; 32],
                ..log()
            },
            &[7; 32]
        )
        .err(),
        Some(EvidenceError::Binding)
    );
}
#[test]
fn recovery_key_certificate_verifies_under_its_root_only() {
    let cert = evidence::certify_recovery_key(&key(1), &[7; 1216]);
    assert_eq!(cert.public, [7; 1216]);
    assert_eq!(cert.verify(&key(1).public()), Ok(()));
    assert_eq!(
        cert.verify(&key(2).public()),
        Err(EvidenceError::Certificate)
    );
    let mut encoded = cert.encode();
    encoded[40] ^= 1;
    assert_eq!(
        RecoveryKeyCertificate::decode(&encoded)
            .unwrap()
            .verify(&key(1).public()),
        Err(EvidenceError::Signature)
    );
}
#[test]
fn evidence_round_trips_strictly() {
    let bytes = confirmation().encode();
    assert_eq!(
        OrderingConfirmation::decode(&bytes).unwrap().encode(),
        bytes
    );
    for cut in 0..bytes.len() {
        assert_eq!(
            OrderingConfirmation::decode(&bytes[..cut]).err(),
            Some(EvidenceError::Encoding)
        );
    }
    assert_eq!(
        OrderingConfirmation::decode(&[bytes.as_slice(), &[0]].concat()).err(),
        Some(EvidenceError::Encoding)
    );
    let cert = evidence::certify_recovery_key(&key(1), &[7; 1216]);
    let bytes = cert.encode();
    assert_eq!(
        RecoveryKeyCertificate::decode(&bytes).unwrap().encode(),
        bytes
    );
    assert_eq!(
        RecoveryKeyCertificate::decode(&[bytes.as_slice(), &[0]].concat()).err(),
        Some(EvidenceError::Encoding)
    );
    let bytes = AcceptedHead::sign(
        &key(2),
        &permit::certify(&key(1), key(2).public()),
        log(),
        [7; 32],
        head(2),
        [0; 32],
        TimeBounds {
            earliest_ms: 1,
            latest_ms: 2,
        },
    );
    assert_eq!(
        AcceptedHead::verify(
            &[bytes.as_slice(), &[0]].concat(),
            &key(1).public(),
            log(),
            &[7; 32]
        )
        .err(),
        Some(EvidenceError::Encoding)
    );
    assert_eq!(
        AcceptedHead::verify(&bytes[..bytes.len() - 1], &key(1).public(), log(), &[7; 32]).err(),
        Some(EvidenceError::Encoding)
    );
}
