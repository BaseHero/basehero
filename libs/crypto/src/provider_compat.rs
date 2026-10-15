//! NEAR's standard Ed25519-v2 field protocol only. These libsodium primitives
//! are not BaseHero seals, account keys, storage formats or a fallback KEM.
//! Native-only entry points are checked lazily: Worker hash/Ed25519 verification
//! must not acquire scalarmult/HKDF imports.
use super::{Error, Secret, SigningKey, init_native_primitives};
use std::{ffi::c_char, sync::OnceLock};

#[link(name = "sodium")]
unsafe extern "C" {
    fn crypto_sign_ed25519_pk_to_curve25519(out: *mut u8, public: *const u8) -> i32;
    fn crypto_sign_ed25519_sk_to_curve25519(out: *mut u8, secret: *const u8) -> i32;
    fn crypto_scalarmult_base(out: *mut u8, scalar: *const u8) -> i32;
    fn crypto_scalarmult(out: *mut u8, scalar: *const u8, public: *const u8) -> i32;
    fn crypto_scalarmult_bytes() -> usize;
    fn crypto_scalarmult_scalarbytes() -> usize;
    fn crypto_sign_ed25519_publickeybytes() -> usize;
    fn crypto_sign_ed25519_secretkeybytes() -> usize;
    fn crypto_kdf_hkdf_sha256_keybytes() -> usize;
    fn crypto_kdf_hkdf_sha256_extract(
        out: *mut u8,
        salt: *const u8,
        salt_len: usize,
        ikm: *const u8,
        ikm_len: usize,
    ) -> i32;
    fn crypto_kdf_hkdf_sha256_expand(
        out: *mut u8,
        out_len: usize,
        context: *const c_char,
        context_len: usize,
        prk: *const u8,
    ) -> i32;
}
fn native_init() {
    static CHECK: OnceLock<()> = OnceLock::new();
    CHECK.get_or_init(|| {
        init_native_primitives();
        // SAFETY: these are parameterless size queries on initialized libsodium.
        unsafe {
            assert_eq!(crypto_scalarmult_bytes(), 32);
            assert_eq!(crypto_scalarmult_scalarbytes(), 32);
            assert_eq!(crypto_sign_ed25519_publickeybytes(), 32);
            assert_eq!(crypto_sign_ed25519_secretkeybytes(), 64);
            assert_eq!(crypto_kdf_hkdf_sha256_keybytes(), 32);
        }
    });
}

/// Validate an attested Ed25519 signing point and convert it to the model's
/// X25519 encryption point. An untrusted candidate cannot supply arbitrary
/// Curve25519 bytes in lieu of a quote-verified Ed25519 key.
pub fn ed25519_public_to_curve25519(public: &[u8; 32]) -> Result<[u8; 32], Error> {
    native_init();
    let mut out = [0; 32];
    // SAFETY: libsodium was initialized and both fixed buffers have checked sizes.
    if unsafe { crypto_sign_ed25519_pk_to_curve25519(out.as_mut_ptr(), public.as_ptr()) } != 0 {
        return Err(Error::InvalidParameters);
    }
    Ok(out)
}

/// Convert the fresh Ed25519 response key's owned secret directly into a
/// wiped X25519 secret, without exporting the 64-byte signing secret. This
/// provider-only operation is deliberately not a method on shared SigningKey.
pub fn ed25519_secret_to_curve25519(key: &SigningKey) -> Result<Secret<32>, Error> {
    native_init();
    let mut out = Secret::<32>::from_slice(&[0; 32])?;
    // SAFETY: input is the live 64-byte owned Ed25519 secret; output has 32
    // bytes and is disjoint. Its owner wipes output on all paths.
    if unsafe {
        crypto_sign_ed25519_sk_to_curve25519(out.0.as_mut_ptr(), key.secret.expose().as_ptr())
    } != 0
    {
        return Err(Error::InvalidParameters);
    }
    Ok(out)
}

/// Ephemeral X25519 public key for a freshly generated private scalar.
pub fn x25519_base(scalar: &Secret<32>) -> Result<[u8; 32], Error> {
    native_init();
    let mut out = [0; 32];
    // SAFETY: fixed input/output lengths checked at lazy initialization.
    if unsafe { crypto_scalarmult_base(out.as_mut_ptr(), scalar.expose().as_ptr()) } != 0 {
        return Err(Error::KemFailure);
    }
    if out == [0; 32] {
        return Err(Error::KemFailure);
    }
    Ok(out)
}

/// X25519 DH; libsodium rejects low-order points. Reject all-zero output as
/// an additional fail-closed condition; neither error exposes input bytes.
pub fn x25519(scalar: &Secret<32>, peer: &[u8; 32]) -> Result<Secret<32>, Error> {
    native_init();
    let mut out = Secret::<32>::from_slice(&[0; 32])?;
    // SAFETY: fixed buffers checked at lazy initialization, live and disjoint.
    if unsafe { crypto_scalarmult(out.0.as_mut_ptr(), scalar.expose().as_ptr(), peer.as_ptr()) }
        != 0
        || out.expose().iter().all(|byte| *byte == 0)
    {
        return Err(Error::KemFailure);
    }
    Ok(out)
}

/// RFC 5869 HKDF-SHA256 with no salt (32 zero bytes) and caller-supplied fixed
/// protocol info. Used only with NEAR's literal `ed25519_encryption` label.
pub fn hkdf_sha256_no_salt(ikm: &Secret<32>, info: &[u8]) -> Result<Secret<32>, Error> {
    native_init();
    let mut prk = Secret::<32>::from_slice(&[0; 32])?;
    let mut out = Secret::<32>::from_slice(&[0; 32])?;
    // SAFETY: libsodium HKDF accepts a null salt with zero length. Input and
    // outputs are fixed owned secrets; info is readable for its given length.
    let extracted = unsafe {
        crypto_kdf_hkdf_sha256_extract(
            prk.0.as_mut_ptr(),
            std::ptr::null(),
            0,
            ikm.expose().as_ptr(),
            32,
        )
    };
    if extracted != 0 {
        return Err(Error::InvalidParameters);
    }
    // SAFETY: the PRK and output are live disjoint 32-byte secret owners;
    // context bytes are borrowed and valid for their checked slice length.
    let expanded = unsafe {
        crypto_kdf_hkdf_sha256_expand(
            out.0.as_mut_ptr(),
            32,
            info.as_ptr().cast::<c_char>(),
            info.len(),
            prk.expose().as_ptr(),
        )
    };
    if expanded != 0 {
        return Err(Error::InvalidParameters);
    }
    Ok(out)
}
