# Account history

`bh-account` verifies account controls with `bh-crypto`, independently of the UI,
network, database and hosting SDK. It has no server credentials or content keys.

## Supported boundary

This library verifies device-signed genesis, existing-device admission,
immediate self-removal and two initial ordinary account-material controls. It
prepares a private password/code-wrapped recovery record and a random personal
X-Wing key sealed to the first device and recovery receiver. Other lifecycle
controls are rejected, not ignored. This is **not** complete signup, hosted
recovery, QR pairing, delayed removal, native key release or hosted admission.

Account ids and device keys belong on devices, at the account home, and inside
protected access checking. Do not put them in ordinary base-service requests,
logs, metrics or stable replacement tracking handles. An account verifier does
not hold personal/base content keys and does not authorize a hosted operation.

## Verification and persistence

1. Obtain a trusted account-id anchor through local creation or an authenticated
   introduction. Never adopt a remote history's self-reported id as an existing
   account's anchor.
2. `VerifiedAccount::from_genesis` verifies the signed genesis against that id.
   `replay` additionally requires a previously remembered head to occur unchanged
   in the original signed history; a fork or truncated history is refused.
3. Create an exact `SigningRequest` from that state. Use the existing device's
   platform-held **second key**, not its ordinary content-signing key. A completed
   request is only a signature, not successful submission or admission.
4. Submit mutations through the same protected execution lane as access checks.
   Ordering, freshness, uncertain outcomes and removal deadlines are the caller's
   responsibility. This library performs no network commit or synchronization.
5. `apply_batch` verifies an ordered successor history atomically in memory. Store
   its original bytes and resulting head together before exposing the result.
   Never advance a durable checkpoint solely from a server/checker acknowledgement.
   For an owned single-event candidate, `applied` avoids copying the projection. It sets no stop, so on error the caller must record the stop itself and not continue from a retained view.

Invalid remote input leaves the previous projection/head unchanged and sets a
sticky stopped state. Active-key access then fails with `Stopped`, not
`NotActive`: invalid history is **not** a verified removal. Preserve the integrity
stop durably and retain the last verified local content. Replaying older history
must not clear a stop or replace a remembered head. Network unavailability alone
must not invoke the verifier with invented empty history or erase anything.

`apply` expects a successor, not a duplicate. A transport retry must first reconcile
its original ordered result rather than apply it twice. All accepted controls
bind the exact previous account head; since these are membership controls, this
also binds the newest control the author had seen. Account history freshness is
not implied by valid signatures: a server can withhold a newer valid event.

For new preparation, generate independent recovery Ed25519 and X-Wing pairs
and a raw 16-byte code before signing genesis. Its signed hash yields the account
id; only then can the private record bind that id. Sign tag 3 (record digest) at
position 2 and tag 4 (personal public key plus two full-envelope digests) at
position 3, both with the first device's control key. `materials_ready` means only
that this exact prefix is locally verified; old partial histories remain
verifiable but do not acquire materials. `open_record` and `open_for_receiver`
require complete, running verified history, not a caller's untrusted hashes.
Neither local readiness nor a signature proves current home authority, kit save,
or recovery-check release. The first-device seal is refused after verified
removal. A later QR-added device needs its own authenticated delivery and
commitment, not these two initial slots. Ordinary recovery or personal-key
opening cannot unlock a hidden base without its extra password.

The async platform `DeviceKeyStore` interface requires three independently generated
keys, durable local handles, an exact-request second-key release policy, and X-Wing
decapsulation returning only a zeroizing shared secret, never a receiver seed.
`load_matching` compares the durable handle, keys, store kind and policy before
account signing or initial device opening; an account owner must separately check
verified active history and current home authority. Native identity loads read
handle-bound, authenticated control-public metadata without releasing the control
seed. Missing or corrupt metadata fails the load; creation must finish
writing it before returning a handle, and there is no load-time migration. The Mac
M1 login-keychain
adapter records `MacLoginKeychainV1` + `AppEnforcedOwnerConfirmation` and asks
LocalAuthentication for a fresh standard macOS owner confirmation before each
control action. This is an **M1 app-enforced UI gate**, not
cryptographically bound to the software control seed and not a passcode-release
guarantee; code running as the Mac
user can bypass it. macOS `deviceOwnerAuthentication` can accept Touch ID, the
user's password, or an eligible paired Apple Watch. The distinct, currently
unused M2 data-protection-keychain adapter records `MacDataProtectionKeychainV1`
and requires a signed/provisioned app for biometric-set item protection. The recovery receiver instead comes from the
reconstructed recovery keys. It provides no production software-store fallback.
Native persistence, biometric-set binding, no-passcode fallback and key
invalidation must be qualified by each adapter. Synthetic test stores establish
no OS behavior. A session/account generation and its stale-after-await checks
belong to the later account owner, not this primitive account library.

## Journal, owner and first-device setup

`journal::AccountJournal` is the durable state an account owner needs, stated as
domain operations: the trusted anchor; the original signed event bytes, the
resulting verified head and the sticky integrity stop committed together; the
recorded device identity; and a versioned, opaque, native-protected pending-setup
blob with its stage. It is not a key-value store, and a head is never durable
without the bytes that produced it.

`owner::AccountOwner` loads a fixed-size current summary and current active
devices, bound to the trusted account anchor, projection epoch and verified cut.
Historical device/key evidence remains in indexed SQLite rows; original events
are the positional evidence. Views pin their epoch/cut, so later additions and
removals do not change their answers. The reader handle is weak: closure, an
epoch reset or a read failure returns `Error::Unavailable`, never absence.
A transient failure leaves the accepted view, head, generation and stop unchanged;
retry that view after recovery, or reload if its epoch/container became obsolete.
`seen_device` is fallible; the compatibility `has_seen_device` conservatively
returns true on unavailable evidence and is not an authoritative status API.

Missing/corrupt projections rebuild in persisted batches of at most 256 original
events, with no capability until the coherent current target is reached.
Reset advances the epoch; maintenance deletes at most 256 obsolete rows per table
per pass. A successor transaction writes only affected device/key rows and the
fixed summary, together with its original bytes and head. Accepted views then
rebase to the committed indexed cut, dropping the recent candidate overlay.

`AccountJournal::history_prefix(None, limit)` captures an original-history cut.
Follow its `HistoryCursor` to export contiguous pages bounded by that same cut,
even across later appends. Limits are 1..=256; the codec bounds each original to
2724 bytes (697344 encoded bytes per full page). Missing gaps, changed cuts or
accounts, and oversized stored payloads fail the entire page. A cursor carries
no authority: native callers must still check capability/generation around export.
Pending setup checks only its exact initial prefix, not the lifetime tail.

The owner honours a persisted stop (retaining the last verified state and never clearing remembered
heads), loads the native device with
`load_matching`, requires those keys to be an active device in verified history
with `materials_ready`, and only then mints an opaque generation-bound
`AccountCapability`. That capability is offline, last-verified authority; it is
not a current home or checker verdict. A verified removal, stop, key invalidation
or explicit lock advances the shared generation, and operations recheck it after
every await. A missing or mismatched native key, or restored state without it,
returns a typed admission-required result and never regenerates identity or
resets a remembered head.

Incoming history is verified in memory and then persisted as original bytes plus
the resulting head in one commit; invalid input persists the stop and keeps the
last good head. The first-device setup state machine stages the exact signed
bytes and protected pending material, resumes at `Prepared`, `HomePending` or
`HomeOrdered` without regenerating genesis or code, and never infers home
ordering from locally committed history. An explicit kit-save confirmation
replaces the code-bearing blob under a distinct per-setup wrapping key,
retires its old Keychain wrapping key once the replacement is durable, and
commits the signed prefix locally, so the first device works before a production
home exists. After a crash between the SQLite replacement and Keychain deletion,
opening saved setup retires the lingering old key first; a failed local commit
retries from the no-code staged blob without making a second account. The three encrypted private objects and exact signed bytes stay
pending for future home submission. Only a home acknowledgement for both the
ordered events and the three private objects permits clearing that pending
submission. An opened save destination is not success.

Before pending setup can be deleted, `retain_initial_bootstrap` checks or copies
the immutable recovery-record and two personal-seal ciphertexts, bound to the
initial three-event head/hash and anchor, in the same transaction as deletion.
This retained record has no recovery code, recovery private key, or opened seed.
The encrypted initial-device seal remains available after home acknowledgement.

`AccountOwner::initial_prefix(cap)` reads and verifies exactly those three signed
originals at the recorded cut, not the current history length.
`initial_bootstrap(cap)` returns that public `InitialAccountPrefix` and a separate
`PendingHomeObjects` value after authenticating **all three** encrypted objects
against their signed digests. Do not serialize the latter into public account
history. Both APIs are native-only; no roots are exported.
`open_personal(cap)` opens only the initial-device seal, checking current device
admission separately from the historical prefix and fencing native awaits.
It does not fall back to a pairing delivery. `PersonalKey::decapsulate` returns
a zeroizing shared secret, never the receiver seed. `sign_content(cap, bytes)`
uses the ordinary native signing key, validates the returned signature, and
checks the capability around each native await; it is not control approval.

`device_auth::prepare(account, device, context)` builds a fixed v1 sync-device
possession message from a verified account head and its active ordinary signing
key. `SigningRequest::finish` checks the native signature before yielding exact
proof bytes; `verify_at(account, expected, bytes)` verifies at the supplied head
only. Native `AccountOwner::prove_sync_device(cap, context)` uses the fenced
`sign_content` path so a lock or removal during native work discards the result.
The protected protocol must establish the channel binding and fresh server
challenge, keep identity-bearing bytes inside its encrypted session, enforce
challenge consumption/session lifetime and check live account/base/audience
authority independently. Possession at an old projection is not currentness,
hosted admission or key-release permission. No WebView signing surface is added.

`storage::DeviceJournal` implements the contract over the device-local SQLite
journal (`libs/storage`), which stores only typed opaque rows and keeps no
dependency on this library. Production still needs a native pending-blob
private-object delivery and a real home/checker lane. The Mac login-Keychain
protector is native-only; the portable identity protector is test-only. As a
known limit, linking `DeviceJournal` makes every consumer of this library link
the bundled SQLite device store, including verifiers that never touch it;
revisit by hiding it behind a feature or moving it to the client before hosted
consumers are added.

## Portable QR pairing increment

`pairing` supplies a bounded 122-byte QR codec, a one-message secret-keyed
scanner proof and an in-memory showing session. The fresh scanner verifies the showing
`DeviceId` against signed history replayed from the QR anchor. An already
activated owner's `scanner_status` uses its verified in-process projection;
the journal-only status path for a fresh scanner still replays signed history. Only a verified
reply can enter the showing device's owner-controlled `add_device` request; two
distinct valid replies end the session. Session cancellation fences a late
second-key signature without invalidating the entire account capability. A
synchronous staging callback runs only while the session remains live; no
persistent admission row or host ordering is implemented yet.

A separate, domain-prefixed account-private `personal::SealPurpose::Device`
delivery is X-Wing-sealed to the recipient and signed with the sender's ordinary
native key. It requires an exact signed pending add on creation and complete
verified active-recipient/active-sender history on opening; it cannot reuse the
two first-device/recovery slots. This does not persist the current personal
holder or establish freshness of an unseen newer home view. No camera, relay,
private-object service or actual platform pairing has been tested here. Pairing
only delivers the ordinary personal key, never hidden-base material.

## Account-control encoding, version 1

All integers are unsigned big-endian. Keys/signatures are their fixed-width raw
libsodium representations. There is no JSON normalization or optional trailing
extension. Parsers reject unsupported versions/controls and trailing bytes.

| Signed field | Bytes |
| --- | ---: |
| ASCII `BaseHero account event` followed by NUL | 23 |
| Protocol version (`1`) | 2 |
| Highest supported version (at least the protocol version) | 2 |
| Position, beginning at `1` | 8 |
| Previous signed-event BLAKE2b-256 hash | 32 |
| Account id (zero only in genesis) | 32 |
| Author device id | 32 |
| Control tag | 1 |
| Control body | fixed by tag |
| Ed25519 control-key signature over all preceding bytes | 64 |

The account id is BLAKE2b-256 of the complete signed genesis. A device id is
BLAKE2b-256 of ASCII `BaseHero device keys` + NUL + its ordinary Ed25519 key (32),
control Ed25519 key (32), and X-Wing receiver key (1216), in that order.

- Tag `0`: first device keys as above, then random recovery Ed25519 (32) and
  X-Wing (1216) public keys. Position is 1, previous/account are zero, and the
  author matches the first device. Its control key signs. Recovery secret
  construction and records are separate; public recovery keys are not derived
  from a password.
- Tag `1`: new device keys (1280 bytes). An active existing device's control key
  signs. Reusing any historic device key or a recovery key is refused.
- Tag `2`: empty body, removing only the signing device immediately. Its control
  key signs. No timing rule for removing another device is implied.
- Tag `3`: private recovery-record digest (32 bytes), position 2 only, signed
  by the first device. No private record/token/proof hashes appear in public events.
- Tag `4`: personal X-Wing public key (1216 bytes), first-device and recovery
  full-envelope digests (32 bytes each), position 3 only after tag 3, signed by
  the first device. Duplicate/reordered bootstrap controls are rejected.

The kit renders the 16 raw code bytes as 26 uppercase base32 characters
plus two checksum characters, grouped into seven four-character sections
separated by dashes (34 characters). The grouping and checksum are presentation,
not extra recovery entropy; the password/code KDF still uses the raw bytes.

The private recovery record is exactly 242 bytes: eight-byte `BHREC01` with NUL,
version 1 (u16), account id (32), recovery-key id (32), nonce (24), encrypted
independent Ed25519/X-Wing seeds (80 including tag), token hash (32) and proof
hash (32). Password UTF-8 (1–1024 bytes; no normalization) is length-framed
with the raw 16-byte code. The ordinary-recovery Argon2id13 candidate uses
fixed salt `BaseHeroRecovV01`, ops 2, 64 MiB and distinct KDF contexts
`BHRWRA01` and `BHRTOK01`; code-only proof has its own domain. Mac/Fold cost
timings are required before real kits. The 1299-byte private personal envelopes
bind purpose, account, personal key id and recipient public-key hash in AD,
using X-Wing → `BHPSEA01` KDF → XChaCha. Test `KemKey` is not a native
receiver fallback; platform storage, gated home release and ordered receipts
remain outside this library.

The entire event is at most 2724 bytes. Algorithms are fixed by the protocol
version; the signed highest-supported value advertises capability, not permission
to downgrade or an implementation of a future-version upgrade. These are account
controls, **not** the outer encrypted base-event format.

## Checks

From the product root:

```sh
nix develop --command bash libs/account/check.sh
```

An affected test run is `cargo test --locked -p bh-account` in that
environment. Tests cover trusted genesis, canonical decoding, second-key
admission, tampering, account/head substitution, rollback, atomic failure,
self-removal, key reuse and denied platform authentication. No host/device access
or paid service is needed.
