use bh_crypto::SecretBytes;

#[test]
fn takes_existing_secret_allocation_without_another_raw_vec() {
    let raw = vec![0u8, 1, 2, 3, 4];
    let ptr = raw.as_ptr();
    let secret = SecretBytes::from_vec(raw);
    assert_eq!(secret.expose().as_ptr(), ptr);
    assert_eq!(secret.expose(), &[0, 1, 2, 3, 4]);
    // Its sodium_memzero Drop, not this test, wipes owned bytes before release.
}
