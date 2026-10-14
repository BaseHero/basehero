# Shared cryptographic primitives

`bh-crypto` is the shared safe Rust boundary over libsodium. Protocol libraries
own canonical encoding, domain separation, authority and key-release policy;
this crate owns primitive calls and their memory-safety invariants.

- BLAKE2b-256 through `hash`.
- Ed25519 through `SigningKey` and `verify`.
- X-Wing key generation/restoration and encapsulation/decapsulation.
- Streaming SHA-256 through `Sha256` for exact artifact digests.
- XChaCha20-Poly1305 through `aead_seal` (fresh random 24-byte nonce) and
  `aead_open` (authenticated AD and ciphertext, 16-byte tag). A nonce and
  ciphertext are returned separately; no seal/account wire encoding or signed
  sender identity is implied. The enclosing protocol must bind purpose, account,
  recipient and other relevant identities in AD and bound untrusted message sizes.
- `derive_key`: libsodium `crypto_kdf` with a 32-byte root, caller-specified
  eight-byte context and numeric subkey id, yielding a secret 32-byte subkey.
- `pwhash_argon2id13`: raw length-aware byte input, 16-byte salt and explicitly
  supplied ops/memory costs within libsodium's supported bounds; a 32-byte secret
  output. A failing allocation/derivation returns `ResourceFailure`, not a weaker
  algorithm. The **protocol**, not this primitive, must fix the salt, input
  encoding and costs per version; never use server-chosen crypto parameters.
  No account-password/code construction or retry policy is implemented here.
- `constant_time_eq`: `sodium_memcmp` for equal-length secret slices, with length
  mismatch rejected before comparison.

`SecretBytes::from_parts` fallibly copies borrowed parts into one wiped owned
buffer for framed protocol secrets. `hash_secret` hashes sensitive input directly
into a wiped `Secret<32>` output rather than returning a public stack array.
Neither helper erases the original borrowed input or incidental OS/compiler copies.

Keys are deliberately neither `Debug` nor `Clone`. Secret heap allocations are
zeroized with `sodium_memzero` on drop. They are not locked memory, hardware keys
or a substitute for native key storage. Explicit seed export is for trusted
platform adapters; callers must protect exported seeds and any copies they make.
Decrypted variable-length plaintext is returned in `SecretBytes`, wiped on drop
including an authentication failure; the borrowed plaintext and password supplied
by the caller, and any copies made outside the owner, remain the caller's
responsibility. Neither `Secret` nor `SecretBytes` promises locked memory,
compiler-wide erasure or device/hardware key protection. AEAD output allocation
uses checked lengths and a fallible reservation; very large requests may still
exhaust resources elsewhere, so the enclosing protocol must impose size bounds.
No allocation/initialization/ABI failure permits a weaker primitive fallback.

## Native build

Install pkg-config and libsodium development headers/library **1.0.22 or later
with X-Wing**. Older distributions' 1.0.20 packages are insufficient. Build-time
header and runtime size checks refuse an incompatible API; these checks are not
a substitute for pinning the actual library build. Target pkg-config metadata
must select the target's library when cross-compiling. The product-root
`flake.nix` builds a static PIC Android arm64 libsodium from the same pinned
upstream source as native libsodium, using NDK 29/API 24. Its Android shell
sets target-scoped pkg-config metadata, not the native library. Mac builds
must supply and qualify their library separately; a cross-build does not
establish runtime behaviour.

The product-root `flake.nix` and committed `flake.lock` provide compatible
libsodium for native development.

From the product root:

```sh
nix develop --command cargo test --locked -p bh-crypto
nix develop .#android --command bash scripts/check.sh android-crypto
```

The companion account library's `check.sh` runs both libraries' format, tests
and Clippy checks. All build inputs are contained in this product tree or fetched
from the declared pinned upstream sources; no external project checkout is needed.

## Worker verifier target (narrow)

From the product root, `bash scripts/check.sh wasm-crypto` builds a static archive
from the **same** root-pinned libsodium C source using the root-pinned Emscripten,
links the unchanged Rust `bh-crypto` FFI for `wasm32-unknown-unknown`, and runs a
fixed hash/signature fixture in local workerd. It uses a dedicated Nix
`.#cryptoWorker` shell and target pkg-config file; native builds retain their
own library. `libs/crypto/worker-host.mjs` permits only the four observed
host imports. It maps libsodium's two exact Emscripten randombytes snippets to
Worker Web Crypto `getRandomValues`, throws on unknown imports/glue, and fails
without secure entropy. The fixture imports a compiled Wasm module, not a Wasm
binding or a browser-only test.

Only BLAKE2b-256 `hash` and Ed25519 `verify` are qualified by this Worker
check. The additional native AEAD/KDF/Argon2id/compare bindings do not expand
its host imports, exported capabilities or tested Wasm call surface.
`sodium_init` and all runtime size checks, including X-Wing constants, run;
**X-Wing operations, SHA-256's sodium_malloc/free, signing, random keys
and seals are not qualified for Worker Wasm**. Native key/sign/seal paths are
unchanged. Fixed-size `verify` cannot test malformed signature lengths; callers
must reject those when decoding. This is local runtime evidence, not a hosted
checker, account admission or Cloudflare deployment.
