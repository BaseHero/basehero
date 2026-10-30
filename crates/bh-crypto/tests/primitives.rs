use bh_crypto::{
    KemKey, Secret, XWING_CIPHERTEXT_BYTES, aead_open, aead_seal, argon2id, constant_time_eq,
    decapsulate, encapsulate, generichash, kdf, random, sha256,
};

#[test]
fn generichash_matches_blake2b_256() {
    assert_eq!(
        hex::encode(generichash(None, &[b"abc"])),
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
    );
}

#[test]
fn generichash_hashes_parts_in_order_and_uses_key() {
    assert_eq!(
        generichash(None, &[&b"ab"[..], &b"c"[..]]),
        generichash(None, &[b"abc"])
    );
    assert_ne!(
        generichash(None, &[&b"ab"[..], &b"c"[..]]),
        generichash(None, &[&b"c"[..], &b"ab"[..]])
    );
    assert_ne!(
        generichash(Some(&[7u8; 32]), &[b"abc"]),
        generichash(None, &[b"abc"])
    );
}

#[test]
fn sha256_matches_known_answer() {
    assert_eq!(
        hex::encode(sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn aead_round_trips_and_refuses_changed_ad_or_ciphertext() {
    let key = Secret::<32>::random();
    let (nonce, ct) = aead_seal(&key, b"ad", b"hello");
    assert_eq!(&*aead_open(&key, &nonce, b"ad", &ct).unwrap(), b"hello");
    assert!(aead_open(&key, &nonce, b"other", &ct).is_err());
    let mut bad = ct.clone();
    bad[0] ^= 1;
    assert!(aead_open(&key, &nonce, b"ad", &bad).is_err());
    assert!(aead_open(&key, &nonce, b"ad", &ct[..15]).is_err());
}

#[test]
fn kdf_differs_by_context_and_id() {
    let k = Secret::<32>::random();
    assert_ne!(
        kdf(&k, b"bhlogin1", 1).expose(),
        kdf(&k, b"bhactiv1", 1).expose()
    );
    assert_ne!(
        kdf(&k, b"bhcntnt1", 1).expose(),
        kdf(&k, b"bhcntnt1", 2).expose()
    );
}

#[test]
fn argon2id_is_deterministic_for_salt_and_params() {
    let salt = [7u8; 16];
    let a = argon2id(b"pw", &salt, 3, 64 << 20).unwrap();
    assert_eq!(
        a.expose(),
        argon2id(b"pw", &salt, 3, 64 << 20).unwrap().expose()
    );
    assert_ne!(
        a.expose(),
        argon2id(b"pw2", &salt, 3, 64 << 20).unwrap().expose()
    );
}

#[test]
fn xwing_round_trips() {
    let recipient = KemKey::generate();
    let (ciphertext, shared) = encapsulate(&recipient.public()).unwrap();
    assert_eq!(
        decapsulate(&recipient, &ciphertext).unwrap().expose(),
        shared.expose()
    );
    // A KEM may implicitly reject with a different secret instead of an
    // error. Neither wrong recipient nor changed KEM component may recover
    // the secret agreed for the original recipient/ciphertext.
    if let Ok(other) = decapsulate(&KemKey::generate(), &ciphertext) {
        assert_ne!(
            other.expose(),
            shared.expose(),
            "wrong recipient recovered the secret"
        );
    }
    for offset in [0, XWING_CIPHERTEXT_BYTES - 1] {
        let mut changed = ciphertext;
        changed[offset] ^= 1;
        if let Ok(other) = decapsulate(&recipient, &changed) {
            assert_ne!(
                other.expose(),
                shared.expose(),
                "changed ciphertext recovered the secret"
            );
        }
    }
}

#[test]
fn a_seed_restores_the_same_xwing_recipient() {
    let seed = Secret::<32>::from_slice(&[42; 32]).unwrap();
    let first = KemKey::from_seed(&seed);
    let second = KemKey::from_seed(&seed);
    assert_eq!(first.public(), second.public());
    let (ct, shared) = encapsulate(&first.public()).unwrap();
    assert_eq!(decapsulate(&second, &ct).unwrap().expose(), shared.expose());
}

#[test]
fn secret_enforces_length_and_random_and_constant_time_eq_work() {
    assert!(Secret::<32>::from_slice(&[1; 31]).is_err());
    assert_eq!(
        Secret::<32>::from_slice(&[1; 32]).unwrap().expose(),
        &[1; 32]
    );
    let r: [u8; 32] = random();
    assert_eq!(r.len(), Secret::<32>::random().expose().len());
    assert!(constant_time_eq(b"ab", b"ab"));
    assert!(!constant_time_eq(b"ab", b"ac"));
    assert!(!constant_time_eq(b"ab", b"abc"));
}
