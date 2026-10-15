# Confidential-service policy verification

Portable verification of signed release policies for the hosted checker, key
service and runner. This library has no service listener, hardware adapter,
account authority, content keys or signing key. It performs no I/O.

## Contract

`PolicyGate::push(payload, signature)` is the legacy **volatile** convenience
wrapper; it verifies exact signed bytes and remembers the highest authenticated
generation. A device channel must instead use `prepare_delivery` → atomic durable
`save(candidate.snapshot())` → `publish_delivery(candidate)` through one shared
`PolicyContext`. A candidate is bound to the originating gate's root and current
revision and is consumed on publication. `snapshot()` returns bounded exact signed
bytes plus the root; `restore_unavailable` re-authenticates and restores only the
floor, never feed availability. A new authenticated delivery is required after
restart. Save failures must poison all users until the exact pending candidate is
committed; the gate alone does not implement persistence or recovery.
Delivery is not authorization:
`check_measurements` must run for each policy-dependent operation using fresh
trusted time and independently verified hardware measurements. A successful
check is only a release-policy match; it is not an attested-peer capability and
must never by itself release a key or approve a hosted operation.

The host must additionally establish:

- A fresh hardware proof binding service public keys and challenge to the
  measured code and authenticated machine. Independently verify Intel collateral,
  production TCB, non-debug/non-migratable TD attributes, the complete RTMR3 event
  log and its unique Compose event; match MRTD and RTMR0–2 separately. Do not build
  the allowlist from the quote being checked.
- An authenticated encrypted channel to those same bound keys.
- Current signed account/audience/job authority, including removal order and
  remembered heads. Release policies deliberately contain none of that authority.
  The checker role gets no content keys.
- Freshness after restart or recovery. Retaining a disk or replaying a signed
  document does not establish current authority or preserve a live key root.

The web relay is **not** a policy role. Its builds and machines remain pinned by
the app's signed release. Sharing a VM does not make policy approval of the
runner permission to replace the relay. A combined measured deployment change
may need a coordinated app release.

## Wire format

A signature is 64 raw Ed25519 bytes, verified strictly with the app/build-rooted
32-byte release public key through the shared `bh-crypto` libsodium binding. The signed message is this concatenation:

```
UTF8("basehero.confidential-policy.v1") || 0x00 || payload
```

The payload is at most 65,536 bytes of UTF-8 JSON. Sign and distribute exactly
the same bytes; there is no canonicalization or reserialization during signature
verification. Unknown fields, duplicate fields, missing fields and trailing
values are rejected. Version 1's fields are:

| Field | Type and meaning |
| --- | --- |
| `version` | Unsigned 32-bit format version, currently 1 |
| `generation` | Unsigned 64-bit increasing publication number |
| `issued_at`, `expires_at` | Unsigned 64-bit absolute seconds; half-open validity interval |
| `builds` | Array of complete build entries; an empty array withdraws all builds |
| `machines` | Array of 32-byte SHA-256 hashes of authenticated Intel PCK PPID bytes |

Each build contains `role` (`checker`, `key-service` or `runner`),
`compose_sha256` (32-byte array), and `boot` (four 48-byte arrays ordered MRTD,
RTMR0, RTMR1, RTMR2). All byte arrays are JSON arrays of integers 0–255.
The machine list applies to the listed builds. Approval of a measurement must
come from release authority, never environment values or freshly observed quotes.

An equal generation must contain the identical payload (direct byte comparison),
including whitespace. Lower generations and different bytes at an equal
generation refuse. Newer parseable documents replace the previous policy even
when expired, future-dated, withdrawn, an unsupported version or otherwise
unusable. Such a document cannot fall back to the older generation. Validly
signed but undecodable input disables availability and retains the previous
floor; another decodable non-regressing delivery is required. An invalid
signature cannot change the floor or disable a still-valid cached policy.

## Freshness and recovery boundary

There is no default policy lifetime, production renewal cadence or assumed
clock error. Trusted code supplies maximum lifetime and time uncertainty in
`Limits`; a policy sender must not control those limits. Time bounds use the
same absolute epoch as the policy. The earliest time must be at or after issue,
and the latest strictly before expiry. Unavailable or overly uncertain time
refuses. A definite backwards jump latches refusal for the verifier's lifetime;
overlapping intervals do not imply rollback.

Call `mark_unavailable` for a known feed outage. It retains the generation floor
but stops checks until authenticated non-regressing delivery. Silent withheld
withdrawals cannot be detected before the original signed expiry. Re-delivery
never renews expiry. Already released keys cannot be erased by withdrawal.

Standalone `PolicyGate::push` state is deliberately volatile; the device channel
requires the durable wrapper described above. Even with a stored floor, a restarted
process may receive an old **unexpired** identical signed policy without learning
an unseen withdrawal. A saved snapshot cannot itself reopen unavailable state.
This library alone is not recovery authorization, protected durable checker state
or a solution to host pause/time-source qualification. Host authority must not
use wall time or a caller-supplied 'current' head to fill those gaps.

Errors have only fixed enum variants and never retain input or dependency error
strings. That constrains this API's diagnostics; it is not a platform-log canary
result. Real host output/capture checks belong to service release testing.

## Checks

From the product workspace root, with its documented Rust prerequisites and
the shared `bh-crypto` workspace member and its libsodium dependency installed:

```sh
cargo test --locked -p bh-confidential-policy
bash libs/confidential-policy/check.sh
bash scripts/check.sh
```

The affected script runs workspace formatting, package Clippy and package tests;
the root script runs the full default product check. Keep the root `Cargo.lock`
current, including this crate and its shared crypto dependency, before using
`--locked` or checking an exported tree. Tests use synthetic measurements and
times with real libsodium Ed25519 signatures; they perform no network or
provider calls. Cargo may need to download dependencies before the first run.
Native checks do not establish hardware or hosted-service behavior.
