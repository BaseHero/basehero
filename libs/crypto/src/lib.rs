//! Shared libsodium primitives for BaseHero. No classical-only X-Wing fallback.
//!
//! Secret bytes live in heap allocations and are wiped on drop. This does not
//! lock memory or promise to erase copies made by the allocator, OS or compiler.

use std::{ffi::c_void, mem, ptr::NonNull, sync::OnceLock};

pub type Hash = [u8; 32];

/// Isolated native-only provider wire compatibility; not BaseHero seals.
pub mod provider_compat;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidLength,
    InvalidSignature,
    KemFailure,
    InvalidParameters,
    ResourceFailure,
    AuthenticationFailed,
}

const SEED: usize = 32;
const ED_PUBLIC: usize = 32;
const ED_SECRET: usize = 64;
const SIGNATURE: usize = 64;
const KEM_PUBLIC: usize = 1216;
const KEM_SECRET: usize = 32;
const KEM_CIPHERTEXT: usize = 1120;
const KEM_SHARED: usize = 32;
const SHA256_BYTES: usize = 32;
const SHA512_BYTES: usize = 64;
const AEAD_NONCE: usize = 24;
const AEAD_TAG: usize = 16;
const KDF_CONTEXT: usize = 8;
const PWHASH_SALT: usize = 16;

// Matches the crypto_hash_sha256_state declaration checked in build.rs. The
// runtime statebytes check below catches a mismatched shared library before use.
// C and Rust use the target's uint64_t alignment for this repr(C) layout.
#[repr(C)]
struct Sha256State {
    _state: [u32; 8],
    _count: u64,
    _buf: [u8; 64],
}

#[link(name = "sodium")]
unsafe extern "C" {
    fn sodium_init() -> i32;
    fn sodium_memzero(ptr: *mut c_void, len: usize);
    fn sodium_malloc(size: usize) -> *mut c_void;
    fn sodium_free(ptr: *mut c_void);
    fn sodium_memcmp(a: *const c_void, b: *const c_void, len: usize) -> i32;
    fn randombytes_buf(buf: *mut c_void, len: usize);
    fn crypto_hash_sha256_bytes() -> usize;
    fn crypto_hash_sha512_bytes() -> usize;
    fn crypto_hash_sha512(out: *mut u8, data: *const u8, len: u64) -> i32;
    fn crypto_hash_sha256_statebytes() -> usize;
    fn crypto_hash_sha256_init(state: *mut Sha256State) -> i32;
    fn crypto_hash_sha256_update(state: *mut Sha256State, data: *const u8, len: u64) -> i32;
    fn crypto_hash_sha256_final(state: *mut Sha256State, out: *mut u8) -> i32;
    fn crypto_generichash_bytes_min() -> usize;
    fn crypto_generichash_bytes_max() -> usize;
    fn crypto_generichash(
        out: *mut u8,
        out_len: usize,
        data: *const u8,
        data_len: u64,
        key: *const u8,
        key_len: usize,
    ) -> i32;
    fn crypto_sign_ed25519_seedbytes() -> usize;
    fn crypto_sign_ed25519_publickeybytes() -> usize;
    fn crypto_sign_ed25519_secretkeybytes() -> usize;
    fn crypto_sign_ed25519_bytes() -> usize;
    fn crypto_sign_ed25519_seed_keypair(pk: *mut u8, sk: *mut u8, seed: *const u8) -> i32;
    fn crypto_sign_ed25519_sk_to_seed(seed: *mut u8, sk: *const u8) -> i32;
    fn crypto_sign_ed25519_detached(
        sig: *mut u8,
        sig_len: *mut u64,
        data: *const u8,
        data_len: u64,
        sk: *const u8,
    ) -> i32;
    fn crypto_sign_ed25519_verify_detached(
        sig: *const u8,
        data: *const u8,
        data_len: u64,
        pk: *const u8,
    ) -> i32;
    fn crypto_kem_xwing_seedbytes() -> usize;
    fn crypto_kem_xwing_publickeybytes() -> usize;
    fn crypto_kem_xwing_secretkeybytes() -> usize;
    fn crypto_kem_xwing_ciphertextbytes() -> usize;
    fn crypto_kem_xwing_sharedsecretbytes() -> usize;
    fn crypto_kem_xwing_seed_keypair(pk: *mut u8, sk: *mut u8, seed: *const u8) -> i32;
    fn crypto_kem_xwing_enc(ct: *mut u8, shared: *mut u8, pk: *const u8) -> i32;
    fn crypto_kem_xwing_dec(shared: *mut u8, ct: *const u8, sk: *const u8) -> i32;
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
}

fn init() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        // SAFETY: sodium_init is thread-safe; size functions take no pointers.
        unsafe {
            assert!(sodium_init() >= 0, "libsodium initialization failed");
            assert_eq!(crypto_hash_sha256_bytes(), SHA256_BYTES);
            assert_eq!(crypto_hash_sha512_bytes(), SHA512_BYTES);
            assert_eq!(
                crypto_hash_sha256_statebytes(),
                mem::size_of::<Sha256State>()
            );
            assert!(crypto_generichash_bytes_min() <= SEED);
            assert!(crypto_generichash_bytes_max() >= SEED);
            assert_eq!(crypto_sign_ed25519_seedbytes(), SEED);
            assert_eq!(crypto_sign_ed25519_publickeybytes(), ED_PUBLIC);
            assert_eq!(crypto_sign_ed25519_secretkeybytes(), ED_SECRET);
            assert_eq!(crypto_sign_ed25519_bytes(), SIGNATURE);
            assert_eq!(crypto_kem_xwing_seedbytes(), SEED);
            assert_eq!(crypto_kem_xwing_publickeybytes(), KEM_PUBLIC);
            assert_eq!(crypto_kem_xwing_secretkeybytes(), KEM_SECRET);
            assert_eq!(crypto_kem_xwing_ciphertextbytes(), KEM_CIPHERTEXT);
            assert_eq!(crypto_kem_xwing_sharedsecretbytes(), KEM_SHARED);
        }
    });
}

// Keep native-only primitive size functions off the Worker hash/verify path.
// Referencing Argon2id's size queries from init() would link pwhash into Wasm
// even though the Worker verifier never calls it.
fn init_native_primitives() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        init();
        // SAFETY: initialized libsodium; every function below reads only constants.
        unsafe {
            assert_eq!(crypto_kdf_keybytes(), SEED);
            assert_eq!(crypto_kdf_contextbytes(), KDF_CONTEXT);
            assert_eq!(crypto_aead_xchacha20poly1305_ietf_keybytes(), SEED);
            assert_eq!(crypto_aead_xchacha20poly1305_ietf_npubbytes(), AEAD_NONCE);
            assert_eq!(crypto_aead_xchacha20poly1305_ietf_abytes(), AEAD_TAG);
            assert_eq!(crypto_pwhash_saltbytes(), PWHASH_SALT);
            assert_eq!(crypto_pwhash_alg_argon2id13(), 2);
            assert!(crypto_pwhash_bytes_min() <= SEED && crypto_pwhash_bytes_max() >= SEED);
        }
    });
}

fn input_len(len: usize) -> u64 {
    u64::try_from(len).expect("input exceeds libsodium length limit")
}

pub fn hash(data: &[u8]) -> Hash {
    init();
    let mut out = [0; 32];
    // SAFETY: the output has 32 bytes, data is valid for its length, and a
    // null key with zero key length selects unkeyed BLAKE2b.
    let result = unsafe {
        crypto_generichash(
            out.as_mut_ptr(),
            out.len(),
            data.as_ptr(),
            input_len(data.len()),
            std::ptr::null(),
            0,
        )
    };
    assert_eq!(result, 0);
    out
}

/// Hash sensitive input directly into a wiped owner (no public stack output).
/// Caller-supplied input and any copies outside this owner remain its responsibility.
pub fn hash_secret(data: &[u8]) -> Secret<32> {
    init();
    let mut out = Secret::<32>(Box::new([0; 32]));
    // SAFETY: initialized libsodium, non-overlapping live input and 32-byte output.
    let result = unsafe {
        crypto_generichash(
            out.0.as_mut_ptr(),
            32,
            data.as_ptr(),
            input_len(data.len()),
            std::ptr::null(),
            0,
        )
    };
    assert_eq!(result, 0);
    out
}

/// Incremental libsodium SHA-256, suitable for hashing input a chunk at a time.
/// Owns the C state; it is freed on drop even if `finalize` is not called.
pub struct Sha256 {
    state: NonNull<Sha256State>,
}

impl Sha256 {
    pub fn new() -> Self {
        init();
        // SAFETY: libsodium is initialized and statebytes was checked against
        // the header's repr(C) layout. sodium_malloc returns owned writable
        // storage or null; no Rust reference to uninitialized state is made.
        let raw = unsafe { sodium_malloc(mem::size_of::<Sha256State>()) };
        let state = NonNull::new(raw.cast::<Sha256State>())
            .expect("libsodium SHA-256 state allocation failed");
        // sodium_malloc places the buffer before a guard page. Check actual
        // alignment rather than assuming its returned address is aligned for
        // this struct (which includes uint64_t), before passing it to C.
        if state.as_ptr().addr() % mem::align_of::<Sha256State>() != 0 {
            // SAFETY: this is the exact live pointer returned by sodium_malloc.
            unsafe { sodium_free(raw) };
            panic!("libsodium SHA-256 state allocation is misaligned");
        }
        let state = Self { state };
        // SAFETY: state is live, correctly sized and aligned for the C layout
        // verified at build time; init fills it before update/final can read it.
        let result = unsafe { crypto_hash_sha256_init(state.state.as_ptr()) };
        assert_eq!(result, 0);
        state
    }

    pub fn update(&mut self, data: &[u8]) {
        // SAFETY: state was initialized and remains exclusively owned by self;
        // data points to a readable slice of the supplied length (including
        // zero length). Its length is checked for C's unsigned long long.
        let result = unsafe {
            crypto_hash_sha256_update(self.state.as_ptr(), data.as_ptr(), input_len(data.len()))
        };
        assert_eq!(result, 0);
    }

    pub fn finalize(self) -> [u8; SHA256_BYTES] {
        let mut out = [0; SHA256_BYTES];
        // SAFETY: self owns the live, initialized state and out has the
        // runtime-checked SHA-256 output size. Drop frees the state afterwards.
        let result = unsafe { crypto_hash_sha256_final(self.state.as_ptr(), out.as_mut_ptr()) };
        assert_eq!(result, 0);
        out
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        // SAFETY: state is the original sodium_malloc pointer, freed exactly
        // once; it is never exposed or copied into another owning Sha256.
        unsafe { sodium_free(self.state.as_ptr().cast()) };
    }
}

pub fn sha256(data: &[u8]) -> [u8; SHA256_BYTES] {
    let mut state = Sha256::new();
    state.update(data);
    state.finalize()
}

/// SHA-512 for Roughtime's signed Merkle inclusion proof.
pub fn sha512(data: &[u8]) -> [u8; SHA512_BYTES] {
    init();
    let mut out = [0; SHA512_BYTES];
    // SAFETY: libsodium is initialized, the output has the checked 64-byte
    // size and data is readable for the checked input length.
    let result =
        unsafe { crypto_hash_sha512(out.as_mut_ptr(), data.as_ptr(), input_len(data.len())) };
    assert_eq!(result, 0);
    out
}

pub fn random<const N: usize>() -> [u8; N] {
    init();
    let mut out = [0; N];
    // SAFETY: out is writable for N bytes; libsodium is initialized.
    unsafe { randombytes_buf(out.as_mut_ptr().cast(), N) };
    out
}

/// An owned, non-clonable secret, wiped on drop. `expose` must not be logged.
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

    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    pub fn random() -> Self {
        init();
        let mut out = Self(Box::new([0; N]));
        // SAFETY: the heap allocation is writable for N bytes.
        unsafe { randombytes_buf(out.0.as_mut_ptr().cast(), N) };
        out
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        // SAFETY: sodium_memzero accepts a writable N-byte allocation and
        // does not require sodium_init. It is designed to resist elision.
        unsafe { sodium_memzero(self.0.as_mut_ptr().cast(), N) };
    }
}

/// Owned variable-length plaintext, wiped on drop (including failed decryption).
/// Neither the input borrowed from a caller nor other caller-made copies are owned here.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Take immediate ownership of a returned secret Vec without creating another
    /// raw Vec. Its initialized bytes are wiped on every exit, including errors.
    /// This cannot wipe copies held by the returning library or OS.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Copies borrowed parts into one wiped owner; borrowers remain the caller's responsibility.
    pub fn from_parts(parts: &[&[u8]]) -> Result<Self, Error> {
        let len = parts
            .iter()
            .try_fold(0usize, |size, part| size.checked_add(part.len()))
            .ok_or(Error::InvalidLength)?;
        let mut owned = Self(Vec::new());
        owned
            .0
            .try_reserve_exact(len)
            .map_err(|_| Error::ResourceFailure)?;
        for part in parts {
            owned.0.extend_from_slice(part);
        }
        Ok(owned)
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // SAFETY: the vector owns len initialized writable bytes, until it is dropped.
        unsafe { sodium_memzero(self.0.as_mut_ptr().cast(), self.0.len()) };
    }
}

/// Constant-time for equal-length buffers; a length mismatch is rejected first.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    init();
    // SAFETY: both slices contain at least a.len() readable bytes.
    unsafe { sodium_memcmp(a.as_ptr().cast(), b.as_ptr().cast(), a.len()) == 0 }
}

/// Derive one 32-byte subkey. The protocol caller fixes the distinct eight-byte
/// context and numeric id for each use; neither is chosen by a remote peer.
pub fn derive_key(key: &Secret<32>, context: &[u8; KDF_CONTEXT], id: u64) -> Secret<32> {
    init_native_primitives();
    let mut out = Secret::<32>(Box::new([0; 32]));
    // SAFETY: libsodium sizes checked at initialization; buffers do not overlap.
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

/// A base root's committed id: the hash of the X-Wing public key derived from
/// it. Base genesis and rekeys commit to it; holders re-derive it from the root.
pub fn committed_key_id(root: &Secret<32>) -> Hash {
    hash(&KemKey::from_seed(&derive_key(root, b"bhKeyId1", 0)).public())
}

/// Raw-byte Argon2id13, not an account password/code encoding. The protocol
/// caller pins salt, input encoding and costs per signed version and never takes
/// parameters from a server. Borrowed password storage is the caller's to wipe.
/// A valid request may still fail when the machine cannot supply its memory.
pub fn pwhash_argon2id13(
    password: &[u8],
    salt: &[u8; PWHASH_SALT],
    ops: u64,
    mem: usize,
) -> Result<Secret<32>, Error> {
    init_native_primitives();
    // SAFETY: these size functions take no pointers after sodium_init.
    let valid = unsafe {
        (crypto_pwhash_passwd_min()..=crypto_pwhash_passwd_max()).contains(&password.len())
            && (crypto_pwhash_opslimit_min() as u64..=crypto_pwhash_opslimit_max() as u64)
                .contains(&ops)
            && (crypto_pwhash_memlimit_min()..=crypto_pwhash_memlimit_max()).contains(&mem)
    };
    if !valid || u64::try_from(password.len()).is_err() {
        return Err(Error::InvalidParameters);
    }
    let mut out = Secret::<32>(Box::new([0; 32]));
    // SAFETY: all buffers have validated sizes and live independently; algorithm
    // is explicitly Argon2id13, never a moving default.
    let result = unsafe {
        crypto_pwhash(
            out.0.as_mut_ptr(),
            32,
            password.as_ptr(),
            input_len(password.len()),
            salt.as_ptr(),
            ops,
            mem,
            crypto_pwhash_alg_argon2id13(),
        )
    };
    if result != 0 {
        return Err(Error::ResourceFailure);
    }
    Ok(out)
}

/// A generated AEAD nonce that can be inspected before signing and consumed
/// exactly once for encryption. There is no caller-chosen nonce constructor.
///
/// ```compile_fail
/// let nonce = bh_crypto::AeadSealNonce::new();
/// let key = bh_crypto::Secret::random();
/// nonce.seal(&key, b"ad", b"first").unwrap();
/// nonce.seal(&key, b"ad", b"second").unwrap(); // consumed
/// ```
pub struct AeadSealNonce([u8; AEAD_NONCE]);

impl AeadSealNonce {
    pub fn new() -> Self {
        init_native_primitives();
        Self(random())
    }

    pub fn bytes(&self) -> &[u8; AEAD_NONCE] {
        &self.0
    }

    pub fn seal(self, key: &Secret<32>, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let length = aead_seal_length(ad, plaintext)?;
        aead_seal_with_nonce(key, &self.0, ad, plaintext, length)
    }
}

impl Default for AeadSealNonce {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a fresh 24-byte nonce and encrypt caller-owned plaintext with
/// authenticated associated data. The nonce must accompany the ciphertext for
/// opening; these are primitives, not a signed seal or account wire format.
/// The caller must bind all protocol identities/purpose in AD and protect any
/// plaintext copies it supplied. Maximum single message size is libsodium's.
pub fn aead_seal(
    key: &Secret<32>,
    ad: &[u8],
    plaintext: &[u8],
) -> Result<([u8; AEAD_NONCE], Vec<u8>), Error> {
    let nonce = AeadSealNonce::new();
    let bytes = *nonce.bytes();
    Ok((bytes, nonce.seal(key, ad, plaintext)?))
}

fn aead_seal_length(ad: &[u8], plaintext: &[u8]) -> Result<usize, Error> {
    init_native_primitives();
    let length = plaintext
        .len()
        .checked_add(AEAD_TAG)
        .ok_or(Error::InvalidLength)?;
    // SAFETY: messagebytes_max is a size query requiring initialized libsodium.
    if plaintext.len() > unsafe { crypto_aead_xchacha20poly1305_ietf_messagebytes_max() }
        || u64::try_from(length).is_err()
        || u64::try_from(ad.len()).is_err()
    {
        return Err(Error::InvalidLength);
    }
    Ok(length)
}

// Kept private: callers cannot accidentally reuse an explicit nonce with a key.
// Deterministic test vectors exercise this path with a fixed synthetic nonce.
fn aead_seal_with_nonce(
    key: &Secret<32>,
    nonce: &[u8; AEAD_NONCE],
    ad: &[u8],
    plaintext: &[u8],
    length: usize,
) -> Result<Vec<u8>, Error> {
    let mut ciphertext = Vec::new();
    ciphertext
        .try_reserve_exact(length)
        .map_err(|_| Error::ResourceFailure)?;
    ciphertext.resize(length, 0);
    let mut written = 0;
    // SAFETY: output is plaintext length plus checked tag, input/AD and nonce/key
    // are live disjoint allocations; a null nsec is supported by this API.
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
    if result != 0 || written != length as u64 {
        // Encryption failure is unexpected, but don't return partial output.
        // SAFETY: ciphertext owns all length writable bytes.
        unsafe { sodium_memzero(ciphertext.as_mut_ptr().cast(), ciphertext.len()) };
        return Err(Error::ResourceFailure);
    }
    Ok(ciphertext)
}

/// Authenticate before releasing plaintext; a failed decrypt wipes its output.
/// Untrusted ciphertext must be bounded by the enclosing protocol before this
/// call; this primitive also rejects anything over libsodium's message limit.
pub fn aead_open(
    key: &Secret<32>,
    nonce: &[u8; AEAD_NONCE],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<SecretBytes, Error> {
    init_native_primitives();
    if ciphertext.len() < AEAD_TAG {
        return Err(Error::InvalidLength);
    }
    let length = ciphertext.len() - AEAD_TAG;
    // SAFETY: size query after sodium_init.
    if length > unsafe { crypto_aead_xchacha20poly1305_ietf_messagebytes_max() }
        || u64::try_from(ciphertext.len()).is_err()
        || u64::try_from(ad.len()).is_err()
    {
        return Err(Error::InvalidLength);
    }
    let mut plaintext = SecretBytes(Vec::new());
    plaintext
        .0
        .try_reserve_exact(length)
        .map_err(|_| Error::ResourceFailure)?;
    plaintext.0.resize(length, 0);
    let mut written = 0;
    // SAFETY: output has ciphertext.len() - tag bytes, and all other pointers
    // refer to live disjoint buffers. An error may modify output, which is wiped
    // by SecretBytes::drop before returning.
    let result = unsafe {
        crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.0.as_mut_ptr(),
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
    if result != 0 || written != length as u64 {
        return Err(Error::AuthenticationFailed);
    }
    Ok(plaintext)
}

pub struct SigningKey {
    public: [u8; ED_PUBLIC],
    secret: Secret<ED_SECRET>,
}

impl SigningKey {
    pub fn generate() -> Self {
        Self::from_seed(&Secret::random())
    }

    pub fn from_seed(seed: &Secret<SEED>) -> Self {
        init();
        let mut key = Self {
            public: [0; ED_PUBLIC],
            secret: Secret(Box::new([0; ED_SECRET])),
        };
        // SAFETY: runtime sizes were checked; all three pointers refer to
        // disjoint, correctly sized, live allocations.
        let result = unsafe {
            crypto_sign_ed25519_seed_keypair(
                key.public.as_mut_ptr(),
                key.secret.0.as_mut_ptr(),
                seed.expose().as_ptr(),
            )
        };
        assert_eq!(result, 0);
        key
    }

    pub fn public(&self) -> [u8; ED_PUBLIC] {
        self.public
    }

    pub fn sign(&self, data: &[u8]) -> [u8; SIGNATURE] {
        init();
        let mut sig = [0; SIGNATURE];
        let mut written = 0;
        // SAFETY: buffers have the checked sizes and data is readable for its length.
        let result = unsafe {
            crypto_sign_ed25519_detached(
                sig.as_mut_ptr(),
                &mut written,
                data.as_ptr(),
                input_len(data.len()),
                self.secret.expose().as_ptr(),
            )
        };
        assert_eq!(result, 0);
        assert_eq!(written, SIGNATURE as u64);
        sig
    }

    pub fn export_seed(&self) -> Secret<SEED> {
        init();
        let mut seed = Secret(Box::new([0; SEED]));
        // SAFETY: both buffers have their runtime-checked sizes and are disjoint.
        let result = unsafe {
            crypto_sign_ed25519_sk_to_seed(seed.0.as_mut_ptr(), self.secret.expose().as_ptr())
        };
        assert_eq!(result, 0);
        seed
    }
}

pub fn verify(public: &[u8; ED_PUBLIC], data: &[u8], sig: &[u8; SIGNATURE]) -> Result<(), Error> {
    init();
    // SAFETY: key/signature sizes were checked; data is valid for its length.
    if unsafe {
        crypto_sign_ed25519_verify_detached(
            sig.as_ptr(),
            data.as_ptr(),
            input_len(data.len()),
            public.as_ptr(),
        )
    } == 0
    {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

pub struct KemKey {
    public: [u8; KEM_PUBLIC],
    secret: Secret<KEM_SECRET>,
}

impl KemKey {
    pub fn generate() -> Self {
        // Seeded generation makes the exported key independently restorable.
        Self::from_seed(&Secret::random())
    }

    pub fn from_seed(seed: &Secret<SEED>) -> Self {
        init();
        let mut key = Self {
            public: [0; KEM_PUBLIC],
            secret: Secret(Box::new([0; KEM_SECRET])),
        };
        // SAFETY: runtime sizes were checked; all buffers are live and disjoint.
        let result = unsafe {
            crypto_kem_xwing_seed_keypair(
                key.public.as_mut_ptr(),
                key.secret.0.as_mut_ptr(),
                seed.expose().as_ptr(),
            )
        };
        assert_eq!(result, 0);
        // libsodium X-Wing's 32-byte secret is its seed. Fail closed if a
        // different implementation ever breaks the export/restore contract.
        assert!(
            key.secret.expose() == seed.expose(),
            "X-Wing secret is not its seed"
        );
        key
    }

    pub fn public(&self) -> [u8; KEM_PUBLIC] {
        self.public
    }

    pub fn export_seed(&self) -> Secret<SEED> {
        Secret::from_slice(self.secret.expose()).expect("X-Wing seed size checked at init")
    }
}

pub fn encapsulate(
    public: &[u8; KEM_PUBLIC],
) -> Result<([u8; KEM_CIPHERTEXT], Secret<KEM_SHARED>), Error> {
    init();
    let mut ct = [0; KEM_CIPHERTEXT];
    let mut shared = Secret(Box::new([0; KEM_SHARED]));
    // SAFETY: public and output sizes were checked at init; buffers are disjoint.
    if unsafe { crypto_kem_xwing_enc(ct.as_mut_ptr(), shared.0.as_mut_ptr(), public.as_ptr()) } != 0
    {
        return Err(Error::KemFailure);
    }
    Ok((ct, shared))
}

pub fn decapsulate(key: &KemKey, ct: &[u8; KEM_CIPHERTEXT]) -> Result<Secret<KEM_SHARED>, Error> {
    init();
    let mut shared = Secret(Box::new([0; KEM_SHARED]));
    // SAFETY: ciphertext, secret and output have runtime-checked sizes and
    // refer to disjoint live allocations.
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
mod tests {
    use super::*;

    #[test]
    fn generated_seal_nonce_is_the_nonce_used_for_encryption() {
        let key = Secret::random();
        let nonce = AeadSealNonce::new();
        let bytes = *nonce.bytes();
        let ciphertext = nonce.seal(&key, b"binding AD", b"signed nonce").unwrap();
        assert_eq!(
            aead_open(&key, &bytes, b"binding AD", &ciphertext)
                .unwrap()
                .expose(),
            b"signed nonce"
        );
        let mut wrong = bytes;
        wrong[0] ^= 1;
        assert!(aead_open(&key, &wrong, b"binding AD", &ciphertext).is_err());
        assert!(aead_open(&key, &bytes, b"other AD", &ciphertext).is_err());
    }

    #[test]
    fn hash_is_blake2b_256() {
        assert_eq!(
            hash(b""),
            [
                0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2, 0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99,
                0xda, 0xa1, 0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87, 0xfa, 0xab, 0x45, 0xcd,
                0xf1, 0x2f, 0xe3, 0xa8,
            ]
        );
        assert_eq!(
            Secret::<32>::from_slice(&[0; 31]).err(),
            Some(Error::InvalidLength)
        );
    }

    #[test]
    fn sha256_standard_vectors() {
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn sha512_fips_180_4_vectors() {
        let hex = |bytes: [u8; 64]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex(sha512(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            hex(sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn sha256_chunked_matches_single_input() {
        let mut state = Sha256::new();
        state.update(b"a");
        state.update(b"");
        state.update(b"bc");
        assert_eq!(state.finalize(), sha256(b"abc"));
    }

    #[test]
    fn sha256_large_repeated_chunks_match_single_input() {
        let chunk = [0x5a; 257];
        let mut state = Sha256::new();
        let mut whole = Vec::new();
        for _ in 0..8192 {
            state.update(&chunk);
            whole.extend_from_slice(&chunk);
        }
        assert_eq!(state.finalize(), sha256(&whole));
    }

    #[test]
    fn signatures_reject_changes_and_restore() {
        let key = SigningKey::generate();
        let restored = SigningKey::from_seed(&key.export_seed());
        assert_eq!(restored.public(), key.public());
        let sig = key.sign(b"message");
        assert_eq!(sig, restored.sign(b"message"));
        assert_eq!(verify(&key.public(), b"message", &sig), Ok(()));
        assert_eq!(
            verify(&key.public(), b"other", &sig),
            Err(Error::InvalidSignature)
        );
        let mut forged = sig;
        forged[0] ^= 1;
        assert_eq!(
            verify(&key.public(), b"message", &forged),
            Err(Error::InvalidSignature)
        );
        assert_eq!(
            verify(&SigningKey::generate().public(), b"message", &sig),
            Err(Error::InvalidSignature)
        );
    }

    #[test]
    fn xchacha_fixed_independent_libsodium_vector() {
        // Direct libsodium 1.0.22 ctypes reference, not our wrapper:
        // key 00..1f, nonce 00..17, AD "account-AD", plaintext 00 68 65 6c 6c 6f ff.
        let key = Secret::<32>::from_slice(&std::array::from_fn::<_, 32, _>(|i| i as u8)).unwrap();
        let nonce = std::array::from_fn(|i| i as u8);
        let encrypted =
            aead_seal_with_nonce(&key, &nonce, b"account-AD", b"\0hello\xff", 7 + AEAD_TAG)
                .unwrap();
        assert_eq!(
            encrypted,
            [
                0x9e, 0xaa, 0x6a, 0x13, 0xfc, 0xbd, 0x72, 0x91, 0x5a, 0xf8, 0xda, 0xe4, 0x02, 0xc6,
                0x13, 0x76, 0x18, 0xd9, 0x07, 0x47, 0x5f, 0x72, 0x4d
            ]
        );
        assert_eq!(
            aead_open(&key, &nonce, b"account-AD", &encrypted)
                .unwrap()
                .expose(),
            b"\0hello\xff"
        );
    }

    #[test]
    fn xwing_secret_binds_recipient_and_ciphertext() {
        let recipient = KemKey::generate();
        let (ciphertext, shared) = encapsulate(&recipient.public()).unwrap();
        assert!(decapsulate(&recipient, &ciphertext).unwrap().expose() == shared.expose());
        // A KEM may implicitly reject with a different secret instead of an
        // error. Neither wrong recipient nor changed KEM component may recover
        // the secret agreed for the original recipient/ciphertext.
        if let Ok(other) = decapsulate(&KemKey::generate(), &ciphertext) {
            assert!(
                other.expose() != shared.expose(),
                "wrong recipient recovered the secret"
            );
        }
        for offset in [0, KEM_CIPHERTEXT - 1] {
            let mut changed = ciphertext;
            changed[offset] ^= 1;
            if let Ok(other) = decapsulate(&recipient, &changed) {
                assert!(
                    other.expose() != shared.expose(),
                    "changed ciphertext recovered the secret"
                );
            }
        }
    }

    #[test]
    fn xwing_roundtrip_and_restore() {
        let key = KemKey::generate();
        let restored = KemKey::from_seed(&key.export_seed());
        assert_eq!(restored.public(), key.public());
        let (ct, shared) = encapsulate(&key.public()).unwrap();
        assert_eq!(decapsulate(&key, &ct).unwrap().expose(), shared.expose());
        assert_eq!(
            decapsulate(&restored, &ct).unwrap().expose(),
            shared.expose()
        );
    }
}
