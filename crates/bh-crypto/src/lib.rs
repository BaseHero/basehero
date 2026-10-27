//! Shared libsodium primitives for BaseHero. No classical-only X-Wing fallback.
//!
//! `Secret` owns heap-allocated bytes and wipes them on drop. This does not
//! lock memory or promise to erase copies made by the allocator, OS or compiler.

use std::{ffi::c_void, mem, sync::OnceLock};
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidLength,
    InvalidParameters,
    ResourceFailure,
    AuthenticationFailed,
    KemFailure,
}

pub const XWING_PUBLIC_BYTES: usize = 1216;
pub const XWING_CIPHERTEXT_BYTES: usize = 1120;
const KEY_BYTES: usize = 32;
const KEM_SECRET_BYTES: usize = 32;
const AEAD_NONCE: usize = 24;
const AEAD_TAG: usize = 16;
const PWHASH_SALT: usize = 16;

// build.rs selects the linked libsodium, including static-only mobile/Mac targets.
unsafe extern "C" {
    fn sodium_init() -> i32;
    fn sodium_memzero(ptr: *mut c_void, len: usize);
    fn sodium_memcmp(a: *const c_void, b: *const c_void, len: usize) -> i32;
    fn randombytes_buf(buf: *mut c_void, len: usize);

    fn crypto_generichash_bytes_min() -> usize;
    fn crypto_generichash_bytes_max() -> usize;
    fn crypto_generichash_keybytes_min() -> usize;
    fn crypto_generichash_keybytes_max() -> usize;
    fn crypto_generichash_statebytes() -> usize;
    fn crypto_generichash_init(
        state: *mut c_void,
        key: *const u8,
        key_len: usize,
        out_len: usize,
    ) -> i32;
    fn crypto_generichash_update(state: *mut c_void, data: *const u8, len: u64) -> i32;
    fn crypto_generichash_final(state: *mut c_void, out: *mut u8, out_len: usize) -> i32;
    fn crypto_hash_sha256_bytes() -> usize;
    fn crypto_hash_sha256(out: *mut u8, data: *const u8, len: u64) -> i32;

    fn crypto_kdf_keybytes() -> usize;
    fn crypto_kdf_contextbytes() -> usize;
    fn crypto_kdf_derive_from_key(
        out: *mut u8,
        len: usize,
        id: u64,
        context: *const u8,
        key: *const u8,
    ) -> i32;
    fn crypto_aead_xchacha20poly1305_ietf_keybytes() -> usize;
    fn crypto_aead_xchacha20poly1305_ietf_npubbytes() -> usize;
    fn crypto_aead_xchacha20poly1305_ietf_abytes() -> usize;
    fn crypto_aead_xchacha20poly1305_ietf_messagebytes_max() -> usize;
    fn crypto_aead_xchacha20poly1305_ietf_encrypt(
        ciphertext: *mut u8,
        ciphertext_len: *mut u64,
        plaintext: *const u8,
        plaintext_len: u64,
        ad: *const u8,
        ad_len: u64,
        nsec: *const u8,
        nonce: *const u8,
        key: *const u8,
    ) -> i32;
    fn crypto_aead_xchacha20poly1305_ietf_decrypt(
        plaintext: *mut u8,
        plaintext_len: *mut u64,
        nsec: *mut u8,
        ciphertext: *const u8,
        ciphertext_len: u64,
        ad: *const u8,
        ad_len: u64,
        nonce: *const u8,
        key: *const u8,
    ) -> i32;

    fn crypto_pwhash_alg_argon2id13() -> i32;
    fn crypto_pwhash_saltbytes() -> usize;
    fn crypto_pwhash_bytes_min() -> usize;
    fn crypto_pwhash_bytes_max() -> usize;
    fn crypto_pwhash_passwd_min() -> usize;
    fn crypto_pwhash_passwd_max() -> usize;
    fn crypto_pwhash_opslimit_min() -> usize;
    fn crypto_pwhash_opslimit_max() -> usize;
    fn crypto_pwhash_memlimit_min() -> usize;
    fn crypto_pwhash_memlimit_max() -> usize;
    fn crypto_pwhash(
        out: *mut u8,
        out_len: u64,
        password: *const u8,
        password_len: u64,
        salt: *const u8,
        ops: u64,
        mem: usize,
        algorithm: i32,
    ) -> i32;

    fn crypto_kem_xwing_seedbytes() -> usize;
    fn crypto_kem_xwing_publickeybytes() -> usize;
    fn crypto_kem_xwing_secretkeybytes() -> usize;
    fn crypto_kem_xwing_ciphertextbytes() -> usize;
    fn crypto_kem_xwing_sharedsecretbytes() -> usize;
    fn crypto_kem_xwing_seed_keypair(pk: *mut u8, sk: *mut u8, seed: *const u8) -> i32;
    fn crypto_kem_xwing_enc(ct: *mut u8, shared: *mut u8, pk: *const u8) -> i32;
    fn crypto_kem_xwing_dec(shared: *mut u8, ct: *const u8, sk: *const u8) -> i32;
}

fn init() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        // SAFETY: sodium_init is thread-safe; size functions have no pointer arguments.
        unsafe {
            assert!(sodium_init() >= 0, "libsodium initialization failed");
            assert!(crypto_generichash_bytes_min() <= KEY_BYTES);
            assert!(crypto_generichash_bytes_max() >= KEY_BYTES);
            assert_eq!(crypto_generichash_statebytes(), mem::size_of::<HashState>());
            assert_eq!(crypto_hash_sha256_bytes(), KEY_BYTES);
            assert_eq!(crypto_kdf_keybytes(), KEY_BYTES);
            assert_eq!(crypto_kdf_contextbytes(), 8);
            assert_eq!(crypto_aead_xchacha20poly1305_ietf_keybytes(), KEY_BYTES);
            assert_eq!(crypto_aead_xchacha20poly1305_ietf_npubbytes(), AEAD_NONCE);
            assert_eq!(crypto_aead_xchacha20poly1305_ietf_abytes(), AEAD_TAG);
            assert_eq!(crypto_pwhash_saltbytes(), PWHASH_SALT);
            assert_eq!(crypto_pwhash_alg_argon2id13(), 2);
            assert!(
                crypto_pwhash_bytes_min() <= KEY_BYTES && crypto_pwhash_bytes_max() >= KEY_BYTES
            );
            assert_eq!(crypto_kem_xwing_seedbytes(), KEY_BYTES);
            assert_eq!(crypto_kem_xwing_publickeybytes(), XWING_PUBLIC_BYTES);
            assert_eq!(crypto_kem_xwing_secretkeybytes(), KEM_SECRET_BYTES);
            assert_eq!(crypto_kem_xwing_ciphertextbytes(), XWING_CIPHERTEXT_BYTES);
            assert_eq!(crypto_kem_xwing_sharedsecretbytes(), KEY_BYTES);
        }
    });
}

fn input_len(len: usize) -> u64 {
    u64::try_from(len).expect("input exceeds libsodium length limit")
}

pub fn random<const N: usize>() -> [u8; N] {
    init();
    let mut out = [0; N];
    // SAFETY: initialized libsodium; out is writable for N bytes.
    unsafe { randombytes_buf(out.as_mut_ptr().cast(), N) };
    out
}

/// Owned, non-clonable secret, wiped on drop. Do not log `expose`.
pub struct Secret<const N: usize>(Box<[u8; N]>);

impl<const N: usize> Secret<N> {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != N {
            return Err(Error::InvalidLength);
        }
        let mut out = Self(Box::new([0; N]));
        out.0.copy_from_slice(bytes);
        Ok(out)
    }

    pub fn random() -> Self {
        init();
        let mut out = Self(Box::new([0; N]));
        // SAFETY: initialized libsodium; heap allocation is writable for N bytes.
        unsafe { randombytes_buf(out.0.as_mut_ptr().cast(), N) };
        out
    }

    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        // SAFETY: owns N writable bytes; sodium_memzero resists elision.
        unsafe { sodium_memzero(self.0.as_mut_ptr().cast(), N) };
    }
}

/// Constant-time for equal-length buffers; reject length mismatch first.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    init();
    // SAFETY: both slices contain at least a.len() readable bytes.
    unsafe { sodium_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) == 0 }
}

pub fn kdf(key: &Secret<32>, context: &[u8; 8], id: u64) -> Secret<32> {
    init();
    let mut out = Secret::<32>(Box::new([0; 32]));
    // SAFETY: runtime sizes checked; buffers are live and disjoint.
    let result = unsafe {
        crypto_kdf_derive_from_key(
            out.0.as_mut_ptr(),
            32,
            id,
            context.as_ptr(),
            key.expose().as_ptr(),
        )
    };
    assert_eq!(result, 0, "libsodium KDF failed");
    out
}

// Matches libsodium's crypto_generichash_blake2b_state: 384 opaque bytes
// at 64-byte alignment. The runtime statebytes check catches library drift.
#[repr(C, align(64))]
struct HashState([u8; 384]);

impl Drop for HashState {
    fn drop(&mut self) {
        // SAFETY: self owns 384 initialized writable bytes; memzero resists elision.
        unsafe { sodium_memzero(self.0.as_mut_ptr().cast(), mem::size_of::<Self>()) };
    }
}

/// BLAKE2b-256 of the concatenated parts, optionally keyed. Keyed BLAKE2b
/// requires a 16–64 byte key; invalid key lengths panic rather than silently
/// hashing without a key.
pub fn generichash(key: Option<&[u8]>, parts: &[&[u8]]) -> [u8; 32] {
    init();
    let mut state = HashState([0; 384]);
    let (key_ptr, key_len) = match key {
        Some(key) => {
            // SAFETY: queries are valid after init.
            let valid = unsafe {
                (crypto_generichash_keybytes_min()..=crypto_generichash_keybytes_max())
                    .contains(&key.len())
            };
            assert!(valid, "invalid libsodium generichash key length");
            (key.as_ptr(), key.len())
        }
        None => (std::ptr::null(), 0),
    };
    // SAFETY: state is live, 64-byte aligned, and matches the runtime size.
    let result =
        unsafe { crypto_generichash_init(state.0.as_mut_ptr().cast(), key_ptr, key_len, 32) };
    assert_eq!(result, 0);
    for part in parts {
        // SAFETY: state is initialized and part has input_len readable bytes.
        let result = unsafe {
            crypto_generichash_update(
                state.0.as_mut_ptr().cast(),
                part.as_ptr(),
                input_len(part.len()),
            )
        };
        assert_eq!(result, 0);
    }
    let mut out = [0; 32];
    // SAFETY: state is initialized and out holds 32 writable bytes.
    let result = unsafe {
        crypto_generichash_final(state.0.as_mut_ptr().cast(), out.as_mut_ptr(), out.len())
    };
    assert_eq!(result, 0);
    out
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    init();
    let mut out = [0; 32];
    // SAFETY: runtime output size checked; input is readable for input_len bytes.
    let result =
        unsafe { crypto_hash_sha256(out.as_mut_ptr(), data.as_ptr(), input_len(data.len())) };
    assert_eq!(result, 0);
    out
}

/// Raw-byte Argon2id13; the caller owns the password buffer and its cleanup.
pub fn argon2id(
    password: &[u8],
    salt: &[u8; 16],
    ops: u64,
    mem_bytes: usize,
) -> Result<Secret<32>, Error> {
    init();
    // SAFETY: size queries take no pointers after initialization.
    let valid = unsafe {
        (crypto_pwhash_passwd_min()..=crypto_pwhash_passwd_max()).contains(&password.len())
            && (crypto_pwhash_opslimit_min() as u64..=crypto_pwhash_opslimit_max() as u64)
                .contains(&ops)
            && (crypto_pwhash_memlimit_min()..=crypto_pwhash_memlimit_max()).contains(&mem_bytes)
    };
    if !valid || u64::try_from(password.len()).is_err() {
        return Err(Error::InvalidParameters);
    }
    let mut out = Secret::<32>(Box::new([0; 32]));
    // SAFETY: all sizes validated; disjoint live buffers; algorithm explicitly Argon2id13.
    let result = unsafe {
        crypto_pwhash(
            out.0.as_mut_ptr(),
            32,
            password.as_ptr(),
            input_len(password.len()),
            salt.as_ptr(),
            ops,
            mem_bytes,
            crypto_pwhash_alg_argon2id13(),
        )
    };
    if result != 0 {
        return Err(Error::ResourceFailure);
    }
    Ok(out)
}

/// Generate a fresh nonce for each encryption. The caller binds identities and
/// purpose in AD and protects any plaintext copies it supplies.
pub fn aead_seal(key: &Secret<32>, ad: &[u8], plaintext: &[u8]) -> ([u8; 24], Vec<u8>) {
    init();
    // SAFETY: size query requires only initialized libsodium.
    let max = unsafe { crypto_aead_xchacha20poly1305_ietf_messagebytes_max() };
    assert!(plaintext.len() <= max, "AEAD plaintext too large");
    let length = plaintext
        .len()
        .checked_add(AEAD_TAG)
        .expect("AEAD length overflow");
    let nonce = random::<AEAD_NONCE>();
    let mut ciphertext = vec![0; length];
    let mut written = 0;
    // SAFETY: output holds plaintext length + tag; all inputs are live,
    // disjoint, checked-size buffers; null nsec is permitted by libsodium.
    let result = unsafe {
        crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.as_mut_ptr(),
            &mut written,
            plaintext.as_ptr(),
            input_len(plaintext.len()),
            ad.as_ptr(),
            input_len(ad.len()),
            std::ptr::null(),
            nonce.as_ptr(),
            key.expose().as_ptr(),
        )
    };
    if result != 0 || written != input_len(length) {
        // SAFETY: ciphertext owns length initialized, writable bytes.
        unsafe { sodium_memzero(ciphertext.as_mut_ptr().cast(), ciphertext.len()) };
        panic!("libsodium AEAD encryption failed");
    }
    (nonce, ciphertext)
}

/// Authenticate before returning plaintext. Zeroizing wipes even partial
/// plaintext on failed authentication.
pub fn aead_open(
    key: &Secret<32>,
    nonce: &[u8; 24],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    init();
    if ciphertext.len() < AEAD_TAG {
        return Err(Error::InvalidLength);
    }
    let length = ciphertext.len() - AEAD_TAG;
    // SAFETY: size query requires only initialized libsodium.
    if length > unsafe { crypto_aead_xchacha20poly1305_ietf_messagebytes_max() }
        || u64::try_from(ciphertext.len()).is_err()
        || u64::try_from(ad.len()).is_err()
    {
        return Err(Error::InvalidLength);
    }
    let mut plaintext = Zeroizing::new(vec![0; length]);
    let mut written = 0;
    // SAFETY: output holds ciphertext length minus tag; pointers refer to live
    // disjoint buffers; on failure Zeroizing wipes any partially written output.
    let result = unsafe {
        crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.as_mut_ptr(),
            &mut written,
            std::ptr::null_mut(),
            ciphertext.as_ptr(),
            input_len(ciphertext.len()),
            ad.as_ptr(),
            input_len(ad.len()),
            nonce.as_ptr(),
            key.expose().as_ptr(),
        )
    };
    if result != 0 || written != input_len(length) {
        return Err(Error::AuthenticationFailed);
    }
    Ok(plaintext)
}

/// X-Wing secret and public key. Secret remains in a wiping owner.
pub struct KemKey {
    public: [u8; XWING_PUBLIC_BYTES],
    secret: Secret<KEM_SECRET_BYTES>,
}

impl KemKey {
    pub fn generate() -> Self {
        init();
        let seed = Secret::<32>::random();
        let mut key = Self {
            public: [0; XWING_PUBLIC_BYTES],
            secret: Secret(Box::new([0; KEM_SECRET_BYTES])),
        };
        // SAFETY: runtime sizes checked; seed, secret and public are disjoint live buffers.
        let result = unsafe {
            crypto_kem_xwing_seed_keypair(
                key.public.as_mut_ptr(),
                key.secret.0.as_mut_ptr(),
                seed.expose().as_ptr(),
            )
        };
        assert_eq!(result, 0, "libsodium X-Wing key generation failed");
        assert_eq!(
            key.secret.expose(),
            seed.expose(),
            "X-Wing secret is not its seed"
        );
        key
    }

    pub fn public(&self) -> [u8; XWING_PUBLIC_BYTES] {
        self.public
    }
}

pub fn encapsulate(
    public: &[u8; XWING_PUBLIC_BYTES],
) -> Result<([u8; XWING_CIPHERTEXT_BYTES], Secret<32>), Error> {
    init();
    let mut ct = [0; XWING_CIPHERTEXT_BYTES];
    let mut shared = Secret::<32>(Box::new([0; 32]));
    // SAFETY: runtime key/output sizes checked and buffers are disjoint.
    if unsafe { crypto_kem_xwing_enc(ct.as_mut_ptr(), shared.0.as_mut_ptr(), public.as_ptr()) } != 0
    {
        return Err(Error::KemFailure);
    }
    Ok((ct, shared))
}

pub fn decapsulate(key: &KemKey, ct: &[u8; XWING_CIPHERTEXT_BYTES]) -> Result<Secret<32>, Error> {
    init();
    let mut shared = Secret::<32>(Box::new([0; 32]));
    // SAFETY: runtime sizes checked; ciphertext, secret and output are disjoint.
    if unsafe {
        crypto_kem_xwing_dec(
            shared.0.as_mut_ptr(),
            ct.as_ptr(),
            key.secret.expose().as_ptr(),
        )
    } != 0
    {
        return Err(Error::KemFailure);
    }
    Ok(shared)
}

#[cfg(test)]
mod hash_state_tests {
    use super::HashState;

    #[test]
    fn state_has_libsodium_layout_and_alignment() {
        assert_eq!(std::mem::size_of::<HashState>(), 384);
        assert_eq!(std::mem::align_of::<HashState>(), 64);
    }
}
