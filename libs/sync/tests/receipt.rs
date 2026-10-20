use bh_crypto::{Secret, SigningKey, hash, verify as verify_signature};
use bh_sync::receipt::{self, CERTIFICATE_LEN, Error, RECEIPT_LEN};
use bh_sync::{BaseId, Digest, Head};

const CERT_DOMAIN: &[u8] = b"bh/hosting-receipt-certificate/v1\0";
const CERT_ID_DOMAIN: &[u8] = b"bh/hosting-receipt-certificate-id/v1\0";
const RECEIPT_DOMAIN: &[u8] = b"bh/observed-head-receipt/v1\0";

fn key(byte: u8) -> SigningKey {
    SigningKey::from_seed(&Secret::from_slice(&[byte; 32]).unwrap())
}

fn head(position: u64, byte: u8) -> Head {
    Head {
        position,
        hash: Digest([byte; 32]),
    }
}

fn signed(
    authority: &SigningKey,
    signer: &SigningKey,
    base: BaseId,
    head: Head,
) -> [u8; RECEIPT_LEN] {
    let certificate = receipt::certify(authority, signer.public());
    let certified = receipt::verify_certificate(&authority.public(), &certificate).unwrap();
    receipt::sign(&certified, signer, base, head).unwrap()
}

// Catches misplaced offsets, little-endian positions, incorrect domains and per-reader variance.
#[test]
fn exact_transcripts_and_shared_receipt() {
    let authority = key(1);
    let signer = key(2);
    let base = BaseId([3; 32]);
    let head = head(0x0102_0304_0506_0708, 4);
    let certificate = receipt::certify(&authority, signer.public());
    assert_eq!(CERTIFICATE_LEN, 130);
    assert_eq!(certificate.len(), 130);
    assert_eq!(&certificate[..2], &[0, 1]);
    assert_eq!(&certificate[2..34], &authority.public());
    assert_eq!(&certificate[34..66], &signer.public());
    let cert_message = [CERT_DOMAIN, &certificate[..66]].concat();
    assert_eq!(&certificate[66..], &authority.sign(&cert_message));
    verify_signature(
        &authority.public(),
        &cert_message,
        &certificate[66..130].try_into().unwrap(),
    )
    .unwrap();

    let certified = receipt::verify_certificate(&authority.public(), &certificate).unwrap();
    assert_eq!(certified.as_bytes(), &certificate);
    let frame = receipt::sign(&certified, &signer, base, head).unwrap();
    assert_eq!(RECEIPT_LEN, 300);
    assert_eq!(frame.len(), 300);
    assert_eq!(&frame[..130], &certificate);
    assert_eq!(&frame[130..132], &[0, 1]);
    assert_eq!(
        &frame[132..164],
        &hash(&[CERT_ID_DOMAIN, &certificate].concat())
    );
    assert_eq!(&frame[164..196], &base.0);
    assert_eq!(&frame[196..204], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&frame[204..236], &head.hash.0);
    let receipt_message = [RECEIPT_DOMAIN, &frame[130..236]].concat();
    assert_eq!(&frame[236..], &signer.sign(&receipt_message));
    verify_signature(
        &signer.public(),
        &receipt_message,
        &frame[236..300].try_into().unwrap(),
    )
    .unwrap();
    // No audience or nonce enters the interface: signing the same common head is deterministic.
    assert_eq!(
        receipt::sign(&certified, &signer, base, head).unwrap(),
        frame
    );
    let verified = receipt::verify(&authority.public(), base, &frame).unwrap();
    assert_eq!(verified.base(), base);
    assert_eq!(verified.head(), head);
    assert_eq!(verified.authority(), authority.public());
    assert_eq!(verified.as_bytes(), &frame);
}

// Catches trusting the self-declared root and accepting another base's signed head.
#[test]
fn pinned_authority_is_required() {
    let genuine = key(1);
    let attacker = key(2);
    let signer = key(3);
    let base = BaseId([4; 32]);
    let counterfeit = signed(&attacker, &signer, base, head(2, 5));
    assert_eq!(
        receipt::verify_certificate(&genuine.public(), &counterfeit[..130]).err(),
        Some(Error::WrongAuthority)
    );
    assert_eq!(
        receipt::verify(&genuine.public(), base, &counterfeit).err(),
        Some(Error::WrongAuthority)
    );
    let genuine_frame = signed(&genuine, &signer, base, head(2, 5));
    assert_eq!(
        receipt::verify(&genuine.public(), BaseId([9; 32]), &genuine_frame).err(),
        Some(Error::WrongBase)
    );
}

// Catches using a noncertified signer or rebinding an old signature to a rotated certificate.
#[test]
fn certificate_binding_is_exact() {
    let root = key(1);
    let signer = key(2);
    let replacement = key(3);
    let base = BaseId([4; 32]);
    let cert =
        receipt::verify_certificate(&root.public(), &receipt::certify(&root, signer.public()))
            .unwrap();
    assert_eq!(
        receipt::sign(&cert, &replacement, base, head(7, 5)).err(),
        Some(Error::WrongSigningKey)
    );
    let original = receipt::sign(&cert, &signer, base, head(7, 5)).unwrap();
    let other_cert = receipt::certify(&root, replacement.public());
    let mut substituted = original;
    substituted[..130].copy_from_slice(&other_cert);
    assert_eq!(
        receipt::verify(&root.public(), base, &substituted).err(),
        Some(Error::CertificateMismatch)
    );
    substituted[132..164].copy_from_slice(&hash(&[CERT_ID_DOMAIN, &other_cert].concat()));
    assert_eq!(
        receipt::verify(&root.public(), base, &substituted).err(),
        Some(Error::BadSignature)
    );
}

// Catches invalidating historical frames on key rotation or calling two identical heads a fork.
#[test]
fn rotation_preserves_history() {
    let root = key(1);
    let base = BaseId([3; 32]);
    let first = signed(&root, &key(2), base, head(8, 4));
    let second = signed(&root, &key(5), base, head(8, 4));
    assert_ne!(first, second);
    let old = receipt::verify(&root.public(), base, &first).unwrap();
    let new = receipt::verify(&root.public(), base, &second).unwrap();
    assert_eq!(old.head(), new.head());
    assert_eq!(old.base(), new.base());
    assert!(!receipt::conflicts_at_same_position(&old, &new));
    assert_eq!(old.as_bytes(), &first);
}

// Catches loose lengths/versions, field tampering, domain confusion or rejecting EMPTY as a signed statement.
#[test]
fn strict_frames_and_tampering() {
    let root = key(1);
    let signer = key(2);
    let base = BaseId([3; 32]);
    let frame = signed(&root, &signer, base, head(6, 4));
    let cert = &frame[..CERTIFICATE_LEN];
    for len in 0..CERTIFICATE_LEN {
        assert_eq!(
            receipt::verify_certificate(&root.public(), &cert[..len]).err(),
            Some(Error::Encoding),
            "cert len {len}"
        );
    }
    for len in 0..RECEIPT_LEN {
        assert_eq!(
            receipt::verify(&root.public(), base, &frame[..len]).err(),
            Some(Error::Encoding),
            "receipt len {len}"
        );
    }
    let mut extra = cert.to_vec();
    extra.push(0);
    assert_eq!(
        receipt::verify_certificate(&root.public(), &extra).err(),
        Some(Error::Encoding)
    );
    let mut extra = frame.to_vec();
    extra.push(0);
    assert_eq!(
        receipt::verify(&root.public(), base, &extra).err(),
        Some(Error::Encoding)
    );

    let mut bad_cert = cert.to_vec();
    bad_cert[1] = 2;
    assert_eq!(
        receipt::verify_certificate(&root.public(), &bad_cert).err(),
        Some(Error::Version)
    );
    bad_cert.copy_from_slice(cert);
    bad_cert[34] ^= 1;
    assert_eq!(
        receipt::verify_certificate(&root.public(), &bad_cert).err(),
        Some(Error::BadCertificate)
    );
    bad_cert.copy_from_slice(cert);
    bad_cert[66] ^= 1;
    assert_eq!(
        receipt::verify_certificate(&root.public(), &bad_cert).err(),
        Some(Error::BadCertificate)
    );

    let mut changed = frame;
    changed[131] = 2;
    assert_eq!(
        receipt::verify(&root.public(), base, &changed).err(),
        Some(Error::Version)
    );
    for (offset, expected) in [
        (132, Error::CertificateMismatch),
        (164, Error::WrongBase),
        (196, Error::BadSignature),
        (204, Error::BadSignature),
        (236, Error::BadSignature),
    ] {
        let mut changed = frame;
        changed[offset] ^= 1;
        assert_eq!(
            receipt::verify(&root.public(), base, &changed).err(),
            Some(expected),
            "offset {offset}"
        );
    }
    let mut changed = frame;
    changed[66] ^= 1;
    assert_eq!(
        receipt::verify(&root.public(), base, &changed).err(),
        Some(Error::BadCertificate)
    );
    let mut wrong_domain = frame;
    let message = [b"bh/other-domain/v1\0".as_slice(), &frame[130..236]].concat();
    wrong_domain[236..].copy_from_slice(&signer.sign(&message));
    assert_eq!(
        receipt::verify(&root.public(), base, &wrong_domain).err(),
        Some(Error::BadSignature)
    );

    let empty = signed(&root, &signer, base, Head::EMPTY);
    assert_eq!(
        receipt::verify(&root.public(), base, &empty)
            .unwrap()
            .head(),
        Head::EMPTY
    );
}

// Catches false-positive conflicts across roots, bases or positions and false evidence from invalid bytes.
#[test]
fn only_authenticated_same_position_conflicts() {
    let root = key(1);
    let other_root = key(9);
    let signer = key(2);
    let base = BaseId([3; 32]);
    let a = signed(&root, &signer, base, head(7, 4));
    let b = signed(&root, &signer, base, head(7, 5));
    let va = receipt::verify(&root.public(), base, &a).unwrap();
    let vb = receipt::verify(&root.public(), base, &b).unwrap();
    assert!(receipt::conflicts_at_same_position(&va, &vb));
    assert_eq!(va.as_bytes(), &a);
    assert_eq!(vb.as_bytes(), &b);
    assert!(!receipt::conflicts_at_same_position(&va, &va.clone()));
    let later = signed(&root, &signer, base, head(8, 5));
    assert!(!receipt::conflicts_at_same_position(
        &va,
        &receipt::verify(&root.public(), base, &later).unwrap()
    ));
    let different_base = BaseId([8; 32]);
    let other_base = signed(&root, &signer, different_base, head(7, 5));
    assert!(!receipt::conflicts_at_same_position(
        &va,
        &receipt::verify(&root.public(), different_base, &other_base).unwrap()
    ));
    let other = signed(&other_root, &signer, base, head(7, 5));
    assert!(!receipt::conflicts_at_same_position(
        &va,
        &receipt::verify(&other_root.public(), base, &other).unwrap()
    ));
    let mut tampered = b;
    tampered[204] ^= 1;
    assert_eq!(
        receipt::verify(&root.public(), base, &tampered).err(),
        Some(Error::BadSignature)
    );
}

// Catches leaking whole authenticated frames through Debug or dynamic input-bearing errors.
#[test]
fn diagnostics_are_redacted() {
    let root = key(1);
    let signer = key(2);
    let base = BaseId([3; 32]);
    let certificate = receipt::certify(&root, signer.public());
    let certified = receipt::verify_certificate(&root.public(), &certificate).unwrap();
    let frame = receipt::sign(&certified, &signer, base, head(5, 7)).unwrap();
    let verified = receipt::verify(&root.public(), base, &frame).unwrap();
    assert_eq!(format!("{certified:?}"), "CertifiedReceiptKey");
    assert_eq!(format!("{verified:?}"), "VerifiedHeadReceipt");
    assert_eq!(format!("{:?}", Error::BadSignature), "BadSignature");
}
