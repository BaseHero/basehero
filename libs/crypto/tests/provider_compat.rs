//! Independent RFC 7748 and PyNaCl/cryptography synthetic vectors. No provider I/O.
use bh_crypto::{Secret, SigningKey, provider_compat as near};

fn bytes<const N: usize>(value: &str) -> [u8; N] {
    let mut out = [0; N];
    assert_eq!(value.len(), N * 2);
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}
#[test]
fn rfc7748_alice_and_bob_agree() {
    // RFC 7748 §6.1, independent published Curve25519 keys and shared secret.
    let alice = Secret::from_slice(&bytes::<32>(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ))
    .unwrap();
    let bob = Secret::from_slice(&bytes::<32>(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ))
    .unwrap();
    let alice_pub = bytes::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_pub = bytes::<32>("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared = bytes::<32>("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(near::x25519_base(&alice).unwrap(), alice_pub);
    assert_eq!(near::x25519_base(&bob).unwrap(), bob_pub);
    assert_eq!(near::x25519(&alice, &bob_pub).unwrap().expose(), &shared);
    assert_eq!(near::x25519(&bob, &alice_pub).unwrap().expose(), &shared);
}
#[test]
fn pynacl_ed25519_conversion_and_python_hkdf_no_salt() {
    // PyNaCl 1.5 libsodium conversion and cryptography HKDF-SHA256(None),
    // seed 00..1f. Independent of the product encryption implementation.
    let seed = Secret::from_slice(&std::array::from_fn::<_, 32, _>(|i| i as u8)).unwrap();
    let key = SigningKey::from_seed(&seed);
    let expected_ed =
        bytes::<32>("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
    let curve_public =
        bytes::<32>("4701d08488451f545a409fb58ae3e58581ca40ac3f7f114698cd71deac73ca01");
    let curve_secret =
        bytes::<32>("3894eea49c580aef816935762be049559d6d1440dede12e6a125f1841fff8e6f");
    assert_eq!(key.public(), expected_ed);
    assert_eq!(
        near::ed25519_public_to_curve25519(&key.public()).unwrap(),
        curve_public
    );
    let converted = near::ed25519_secret_to_curve25519(&key).unwrap();
    assert_eq!(converted.expose(), &curve_secret);
    assert_eq!(near::x25519_base(&converted).unwrap(), curve_public);
    let ikm = Secret::from_slice(&std::array::from_fn::<_, 32, _>(|i| i as u8)).unwrap();
    // RFC 5869 extract(empty salt) + expand, independently checked by Python
    // cryptography 45.x; the pinned SDK's exact protocol info literal.
    assert_eq!(
        near::hkdf_sha256_no_salt(&ikm, b"ed25519_encryption")
            .unwrap()
            .expose(),
        &bytes::<32>("780f73cfeb81fdbb1a0f0f51c56219edc5d13349c177894184326f4942624ef5")
    );
}
#[test]
fn invalid_ed_point_and_low_order_dh_are_rejected() {
    let scalar = Secret::<32>::random();
    assert!(near::ed25519_public_to_curve25519(&[0xff; 32]).is_err());
    assert!(near::x25519(&scalar, &[0; 32]).is_err());
    assert!(
        near::x25519(
            &scalar,
            &[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0
            ]
        )
        .is_err()
    );
}
