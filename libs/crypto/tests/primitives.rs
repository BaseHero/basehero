use bh_crypto::{
    Secret, aead_open, aead_seal, constant_time_eq, derive_key, hash_secret, pwhash_argon2id13,
};

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), 2 * N);
    std::array::from_fn(|i| u8::from_str_radix(&value[2 * i..2 * i + 2], 16).unwrap())
}

#[test]
fn secret_hash_nonempty_reference_and_input_change() {
    // Independent direct-libsodium 1.0.22 crypto_generichash reference.
    let mut input = b"BH ordinary code proof v1\0".to_vec();
    input.extend(0u8..16);
    assert_eq!(
        *hash_secret(&input).expose(),
        hex::<32>("f829fe1de1ccb7b45dea9fb79aae4c4c47219ad46ad061437a28c00b078d738e")
    );
    input[26] ^= 1;
    assert_ne!(
        *hash_secret(&input).expose(),
        hex::<32>("f829fe1de1ccb7b45dea9fb79aae4c4c47219ad46ad061437a28c00b078d738e")
    );
}

// Expected values produced independently by calling libsodium 1.0.22 directly
// from ctypes (not via this Rust FFI): master=00..1f, salt=00..0f.
#[test]
fn kdf_separates_context_and_subkey_id() {
    let key = Secret::<32>::from_slice(&(0..32).collect::<Vec<_>>()).unwrap();
    for (ctx, id, expected) in [
        (
            *b"BHtest01",
            7,
            "5848bfac427a283681b9073c5dff94853e3a4e5777c07d1a21b7f1fdd7233881",
        ),
        (
            *b"BHtest01",
            8,
            "da60b4d3b7f6d7719035be2f9332911717864971147cca4f4e79670ec3fdb0d5",
        ),
        (
            *b"BHtest02",
            7,
            "acad7a4293e3f8222a3e940c0aa238d2d4505895497e76289c652d6542380882",
        ),
    ] {
        assert_eq!(*derive_key(&key, &ctx, id).expose(), hex::<32>(expected));
    }
}

#[test]
fn argon2id13_is_length_aware_and_validates_costs() {
    let salt = std::array::from_fn(|i| i as u8);
    assert_eq!(
        *pwhash_argon2id13(b"\0p\xc3\xa9\0", &salt, 2, 8 * 1024 * 1024)
            .unwrap()
            .expose(),
        hex::<32>("7ce742b3a5dba5c8aadf5b9d3c59595e2abafd2e4566430a8ca80741c37b4365")
    );
    assert_eq!(
        *pwhash_argon2id13(b"\0p\xc3\xa9\x01", &salt, 2, 8 * 1024 * 1024)
            .unwrap()
            .expose(),
        hex::<32>("d73ecaff21bbc5280b7b81966674bb433b15fc62855f5f5e4c82a5fbb0dad45d")
    );
    // Independent direct-libsodium answers for changing one valid cost at a
    // time. These are synthetic test inputs, not account protocol parameters.
    assert_eq!(
        *pwhash_argon2id13(b"\0p\xc3\xa9\0", &salt, 3, 8 * 1024 * 1024)
            .unwrap()
            .expose(),
        hex::<32>("2f5e0523516c47de5ef5a9b351f6dddd7dcde09de3a726526990775e1ba791bb")
    );
    assert_eq!(
        *pwhash_argon2id13(b"\0p\xc3\xa9\0", &salt, 2, 16 * 1024 * 1024)
            .unwrap()
            .expose(),
        hex::<32>("96b3ca221ef65a162187dd36586496812814d1d5eb87fccb74f1676a22f9011f")
    );
    assert_ne!(
        pwhash_argon2id13(b"\0p\xc3\xa9\0", &[1; 16], 2, 8 * 1024 * 1024)
            .unwrap()
            .expose(),
        &hex::<32>("7ce742b3a5dba5c8aadf5b9d3c59595e2abafd2e4566430a8ca80741c37b4365")
    );
    for (ops, mem) in [
        (0, 8 * 1024 * 1024),
        (2, 0),
        (u64::MAX, 8 * 1024 * 1024),
        (2, usize::MAX),
    ] {
        assert!(pwhash_argon2id13(b"p", &salt, ops, mem).is_err());
    }
}

#[test]
fn aead_checks_nonce_ad_key_tag_and_length() {
    let key = Secret::<32>::from_slice(&[7; 32]).unwrap();
    let other = Secret::<32>::from_slice(&[8; 32]).unwrap();
    let (nonce, mut ct) = aead_seal(&key, b"scope/account", b"\0secret\xff").unwrap();
    let (second_nonce, second_ct) = aead_seal(&key, b"scope/account", b"\0secret\xff").unwrap();
    assert_ne!(
        nonce, second_nonce,
        "fresh seals under one key must not reuse a nonce"
    );
    assert_eq!(
        aead_open(&key, &second_nonce, b"scope/account", &second_ct)
            .unwrap()
            .expose(),
        b"\0secret\xff"
    );
    assert_eq!(
        aead_open(&key, &nonce, b"scope/account", &ct)
            .unwrap()
            .expose(),
        b"\0secret\xff"
    );
    assert!(aead_open(&other, &nonce, b"scope/account", &ct).is_err());
    assert!(aead_open(&key, &nonce, b"scope/other", &ct).is_err());
    let mut changed = nonce;
    changed[0] ^= 1;
    assert!(aead_open(&key, &changed, b"scope/account", &ct).is_err());
    ct[0] ^= 1;
    assert!(aead_open(&key, &nonce, b"scope/account", &ct).is_err());
    ct[0] ^= 1;
    let last = ct.len() - 1;
    ct[last] ^= 1;
    assert!(aead_open(&key, &nonce, b"scope/account", &ct).is_err());
    assert!(aead_open(&key, &nonce, b"scope/account", &[0; 15]).is_err());
    let (empty_nonce, empty_ct) = aead_seal(&key, b"", b"").unwrap();
    assert_eq!(empty_ct.len(), 16);
    assert!(
        aead_open(&key, &empty_nonce, b"", &empty_ct)
            .unwrap()
            .expose()
            .is_empty()
    );
}

#[test]
fn secure_compare_handles_mismatch_without_content_diagnostics() {
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"ab"));
    assert!(constant_time_eq(b"", b""));
}
