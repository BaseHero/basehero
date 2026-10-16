# Native device ownership and initial base keys

`bh-device` owns local account containers and coordinates native account/base
authority above `bh-account`, `bh-event` and `bh-storage`. Account history does
not depend on event history. No keys or capabilities are WebView objects.

## Create-once own base

`own_base::create_or_open(account, Arc<AccountCapability>, database)` creates a
signup base at the authenticated **initial three-event account cut**, before
later controls and before native Ready. A missing base after later controls is
an error, never permission to create a replacement. Generic event genesis
verification still supports other historical cuts for future base creation.

Creation signs genesis using the ordinary native device key, derives its BaseId,
and then signs M and K seals containing that BaseId. Genesis commits key ids,
not seal hashes. There is no request or certificate back-reference. The complete
verified candidate is persisted with a create-if-absent transaction bound to the
account anchor and current generation. Concurrent candidates converge on the
persisted winner. No candidate is exported before that commit. A restart or
export never reconstructs or re-signs the durable originals.

On reopen, verify historical account, signer, head and recipient/context before
decapsulation. Open M provisionally, verify the exact genesis descriptor/body and
its M/K ids, then open K and verify its id. Only then publish `OwnBase`. Current
requester admission and capability are checked separately; historical creator
proof does not authorize a removed device.

`OwnBase` is non-cloneable. `with_keys` checks the capability before and after
synchronous native use of zeroizing M/K. It is not a writer fence. Native key
operations hold no database guard. Session transfer moves this owner and its
capability together; stopping drops the roots.

`bootstrap_export` returns exact signed initial account events separately from
`ProtectedBootstrap` (encrypted home objects and the exact `OwnBaseRecord`).
There is no serialization implementation and no root export. The protected
objects must never become public log/header fields or WebView output. Retained
initial account ciphertexts survive pending-setup deletion and kit-key retirement.
Additional account controls can be read using captured, bounded journal cursors,
without a lifetime-long database transaction.

An unregistered base stores no ordered head or synthetic receipt. Local writing
remains unsealed pending deltas; no signed successor is authored against the
introduction's locally constructed verification commitment. Actual registration,
current requester checks, installation requests and authenticated receipts are
separate consumers, not implemented by this library.

## Base key seal, version 1

All integer fields are unsigned big-endian; all byte arrays are exact raw bytes.
This 1499-byte **protected, identity-bearing** frame is not a service header.

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 8 | ASCII `BHBKSL01` |
| 8 | 2 | version = 1 |
| 10 | 1 | purpose: metadata M = 1, content K = 2 |
| 11 | 32 | genesis-derived BaseId |
| 43 | 32 | audience (all zero for shared base) |
| 75 | 32 | root key id |
| 107 | 32 | BLAKE2b-256 of exact recipient personal public key (1216 bytes) |
| 139 | 32 | sender account |
| 171 | 32 | sender device |
| 203 | 8 | historical account head position |
| 211 | 32 | historical account head hash |
| 243 | 1120 | X-Wing KEM ciphertext |
| 1363 | 24 | XChaCha20-Poly1305 nonce |
| 1387 | 48 | encrypted 32-byte root plus 16-byte authentication tag |
| 1435 | 64 | ordinary-device Ed25519 signature |

The AEAD key is `crypto_kdf` of the X-Wing shared secret with eight-byte context
`BHBKEY01` and subkey id equal to the purpose. Associated data is the **complete
243-byte header**. The signature covers ASCII
`BH base key seal signature v1`, one actual NUL byte, and the first 1435 frame
bytes. The root id uses the event protocol's existing `key_id`: derive a seed
under `bhKeyId1`, subkey 0, and hash the derived X-Wing public key.

`PreparedBaseKeySeal::{signing_bytes,expected_key,finish}` supports native signing;
`finish` validates the supplied signature. `SealHeader::decode` and package
parsing validate framing, not authority. `open_seal` checks the independently
expected context, exact verified historical signer/head and published personal
recipient before decapsulation, then checks the decrypted root id.

## Initial base key package

Exact encoding:

```text
BHBKPK01 || u16be(1) ||
u32be(1499) || exact metadata seal ||
u32be(1499) || exact content seal
```

Total: **3016 bytes**. Inner versions, purposes, sizes and shared bindings must
match. Swapped purposes, altered lengths, different contexts and trailing bytes
are refused. Signatures are subsequently verified before opening; parsing alone
does not authenticate encrypted bytes.

`InitialBaseKeyPackage::{as_bytes,metadata_seal,content_seal}` returns retained
bytes. `digest()` is BLAKE2b-256 of ASCII
`BH initial base key package v1`, one actual NUL byte, and the complete canonical
package. A later creator-signed installation request must bind that whole digest.

The complete independent libsodium vector is in
`tests/fixtures/base-key-package-v1.hex`. Public synthetic inputs: signing seed
`11` repeated 32 times, recipient seed `22`, M=`33`, K=`44`; base/account/device/
head hash are repeated `a1/a2/a3/a4`, audience zero and position 3. Encapsulation
seeds are each purpose repeated 64 times; nonce bytes begin at the purpose and
increment for 24 bytes. Its package digest is
`173e71dd4c05db092c3cb666735393ded283e9020a621c9a3e5b62a355982bcf`.
Tests exercise the complete bytes, domain-separated signatures/KDF/AEAD,
ciphertext tampering, root-id substitution and malformed package boundaries.
