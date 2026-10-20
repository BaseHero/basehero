# Content-blind sync kernel

This library implements ordinary-record framing, common commitments and exact
operation-approval consumption. It is **not a hosted sync service**, an account
verifier or a complete encrypted-event protocol. It exposes no network endpoint.
A passing hash-chain check is not permission to apply content. Account admission,
original-author verification, attested channels, protected current-authority
storage and storage adapters must be integrated before serving real data.

## Components and trust

- Devices produce an encrypted, padded envelope containing the original author
  signature and its audience/epoch/version/seen-head/control bindings (and base
  binding after genesis; genesis derives its own base id). The
  detailed inner envelope codec is outside this kernel. Devices verify those
  originals and current authority before applying content; a checker signature
  cannot substitute for them.
- The confidential checker authenticates the requesting device and verifies
  current account and audience authority. It has no content keys. Identity-bearing
  inputs stay inside its attested encrypted channel and protected storage.
- The ordinary sequencer assigns positions, stores opaque bytes and consumes a
  checker approval for an exact operation. It sees the containing base, sizes,
  ordering, timing, per-operation commitments and individual immutable objects,
  but no member/device/private-audience handle.
- The storage adapter owns the atomic transaction, replay index and durable-commit
  acknowledgement. This library returns plans; producing a plan writes nothing.

Commitments use the shared cryptographic library's libsodium BLAKE2b-256.
Approvals use its Ed25519 verification. These algorithms and encodings are fixed
for framing version 1. Changing transport framing must never negotiate away an
inner signed version or a device's remembered version floor.

## Values and framing

All integers are unsigned, big-endian. Decoders reject unsupported versions,
truncation and trailing bytes. Identifiers and digests are 32 bytes.

`EventId` is freshly random **per event**, persisted before first submission and
reused unchanged for retries. It is not a device sequence, account key, audience
id or session token. The crypto/outbox adapter creates it; the framing library
cannot establish randomness from received bytes.

An `OpaqueEvent` is:

```
u16 version = 1
32  event_id
u32 envelope_length
N   encrypted_padded_envelope
```

The entire envelope length, including its internal cryptographic overhead, is
one of 1024, 4096, 16384 or 65536 bytes. No content kind, author, audience, epoch
or identity-bearing signature appears outside it. Construction checks size only;
it does not certify that arbitrary bytes really are encrypted.

The event digest is `H("bh/event/v1\0" || encoded_event)`. A containing base's id
is its genesis event digest. The empty head is position 0 and a zero digest.
Ordering the first event checks that its digest equals the base id and that it is
on the control route: a genesis is always a control.

A body-free `Commitment` is 179 bytes:

```
u16 version = 1
32  base_id
u64 previous_position
32  previous_chain_hash
32  event_id
32  event_digest
u8  route (0 content, 1 control)
u64 assigned_position
32  assigned_chain_hash
```

The route is the kind of permit the sequencer ordered the event under: a
membership or key change (control) or content. Decoders refuse any other route
byte. The assigned position must be the previous position plus one, without
overflow. The assigned hash is `H("bh/chain/v1\0" || preceding_147_bytes)`, so
the route is committed in the chain. A device that opens the event's sealed
binding can refuse one whose class differs from its route; the sequencer learns
nothing from the route it did not already know from the permit.
A follower can verify this common chain without fetching any audience's body.
Fetching a body additionally checks its exact event id and digest. A compromised
sequencer can build an internally consistent chain: original-author/control and
remembered-head verification remain indispensable.

## Exact operation approvals

The implemented operations are append of one opaque event, read of 1–64 **exact
immutable ciphertext commitments**, staging one detached padded body, and reading
1–64 exact stored bodies. A read selection cannot contain repeated objects. Its
order is part of the request. No reusable download URL or connection-wide
authority follows from a read approval. Common-header range transport, presence
and attachment publication are not implemented here.

```
append_digest = H("bh/append/v1\0" || event_digest)
read_digest   = H("bh/read/v1\0" || u16 count || object_digests_in_order)
```

The checker must authorize every selected body, not just its containing base.
A signed approval has a 226-byte body and 64-byte signature:

```
u16 version = 1
32  base_id
u64 expected_position
32  expected_chain_hash
32  checker_incarnation
u64 access_sequence
32  one_operation_nonce
32  operation_digest
32  response_binding
u64 not_before
u64 expires
64  signature
```

The signature covers `"bh/access-approval/v1\0" || body`. The response binding
commits to a fresh one-operation encrypted response channel or receiver key; the
adapter must derive it from that actual channel/key, not accept a caller's hash
without binding delivery to it. Consumption compares it with the signed field.
A copied approval cannot redirect the response to another channel. A response
channel binding is never reused as a persistent device/member handle.

Time values are milliseconds in the host's agreed absolute time domain. Storage
supplies a conservative trusted time interval; the planner accepts an approval
only if that interval is at or after `not_before` and strictly before `expires`.
Client time and arbitrary HTTP headers are never that trusted source. Expiry is
capped by the earliest possible pending authority change; it is not a revocation
strategy by itself. The native adapter samples time *before* its SQLite commit
and imposes no maximum remaining transaction duration. A stalled commit can
finish after expiry: exact hosted removal deadlines require separately validated
host timing/serialization guarantees, not an arbitrary margin.

The incarnation is fresh for a recovered checker/storage session and scoped to
the base, not a member or audience. The sequence counts **all access operations**,
including reads, separately from common-log positions. Storage accepts only its
next sequence, expected head, incarnation and pinned checker key. This avoids an
unbounded spent-nonce table. It deliberately serializes operations within the
single-base execution lane; throughput/batching is not claimed here.

## Detached bodies and descriptor closure

An encrypted event's first 32 envelope bytes commit its detached padded body `B`:
`body_commitment = H("bh/payload-object/v1\0" || P:u32 || B)`, where `P` is one of
1024, 4096, 16384, 65536, 262144, 1048576 or 4194304 bytes (`BODY_SIZES`; envelopes
use the smaller `ENVELOPE_SIZES`). The kernel computes that commitment from the
exact bytes handed to it and never accepts a caller-supplied commitment. It reads
only those first 32 envelope bytes, no other descriptor field, so this path
exposes no audience, author, epoch or content kind.

Two further operations use the same approval, one access sequence, response
binding and trusted time window, under their own domains:

```
stage_digest     = H("bh/body-stage/v1\0" || body_commitment)
body_read_digest = H("bh/body-read/v1\0" || u16 count || body_commitments_in_order)
```

Staging persists one immutable body; staging the exact bytes again is idempotent
and does not fork. A body read selects 1–64 exact commitments and returns the
stored bytes; its selection is bounded and repeat-free, and corrupt stored bytes
refuse. Event append/read approvals are never reused for body operations, and the
reverse; each requires its own approval.

A descriptor append fails closed unless the adapter found the exact body its first
32 envelope bytes name already durably staged, and it acknowledges only after the
descriptor's durable commit. An unreferenced staged body left by a failed append
is an acceptable orphan; an acknowledged descriptor with no durable body is not.
Bodies stay in the ordinary store until archival is designed; this interface does
not choose where they are archived or when they are deleted.

## Ordering, removal and uncertain outcomes

The complete hosted path must share one protected execution lane between an
account's own-base access and account authority changes. Merely protecting
approval issuance with a mutex is insufficient: an account removal could commit
while an old approval remained usable at an unchanged base head.

The required sequence is:

1. Authenticate the request privately. Establish current verified account and base
   authority, including timed changes. Catch up required account-change controls
   into the base before further content writes; affected old epochs are closed.
2. Select exact request bytes and validity bounds. Persist the outstanding
   approval in protected storage **before releasing it**. Hold the lane through
   consumption and outcome reconciliation.
3. At the sequencer, verify the checker signature and operation binding, expected
   head, incarnation, next access sequence and conservative consumption time.
4. In one transaction, compare the complete prior gate state, consume the sequence,
   append or find the original committed event, and persist the resulting head
   and receipt. Release an Ack or selected read bytes only after durable commit.
5. Authenticate the exact receipt in the protected lane before advancing it or
   allowing the next authority change/access operation.

Account mutation submission must use this same lane. A verified account snapshot
is necessary but does not implement serialization. A lane cannot postpone a
removal deadline: consumption-time checks must reject a pre-deadline approval
held until after its authority ceases. Remaining devices may need to supply fresh
epoch keys; the checker cannot create them.

A lost Ack does not mean an append failed. Reconcile its exact operation first.
A subsequent authorized append retry uses the original event id/bytes but a new
operation approval and access sequence. The replay index returns its original
commitment, never another position. Different bytes for the same event id are
rejected. Looking up an old Ack also needs fresh authority; removal does not leave
an authorization-free replay path.

An archival lookup outage is not proof that an event id is absent. The adapter
must fail closed rather than create a second append. Archival and bounding that
index are outside this kernel.

`ExecutionLane` models unavailable, ready and pending states. It has no method
that clears pending work on timeout. An unresolved operation must be reconciled
or durably fenced at storage before the lane can resume. An abandoned grant may
also be resolved when authenticated storage shows its sequence unconsumed **after**
any in-flight consumption transaction has finished or been excluded, and trusted
time under a validated host timing contract proves the approval can never be
consumed later. Expiry alone cannot clear uncertainty; this resolution has no
current `ExecutionLane` API. Every cold construction starts unavailable. Its
`establish`, `committed` and `fence` methods are **trusted host integration
boundaries**, not parsers accepting untrusted claims; adapters must authenticate
receipts and establish current state before calling them. The native SQLite
adapter supplies a last-outcome reconciliation record but no incarnation-fence
operation. This local state machine is not itself a distributed lock, persistent
storage, account-authority verifier or freshness proof.

## Recovery and client integrity

Durable storage handles ordinary process restarts, not coordinated malicious
rollback. Attestation, encrypted disk and correctly signed historical heads alone
do not prove that a snapshot is the latest. Recovery needs live protected
continuity or another qualified freshness source and reconciliation of outstanding
operations. Without it, the checker stays unavailable. A random new incarnation
by itself cannot rehabilitate an old permission snapshot.

Invalid remote history must stop client application and preserve the last
verified local state and outbox; never clear remembered heads to continue. Apply
verified incoming content and advance its local cursor in one local transaction.
A checker outage pauses new hosted access, not local reading or editing. A verified
device removal has its own account-data removal behavior; a service failure or
unverified removal claim cannot trigger that action.

No diagnostics should include request bytes, identity-bearing inputs, IPs or a
stable substitute actor/audience handle. Fixed refusal classes are available;
logging arbitrary error context is not part of this interface.

## Permissions

The hosted permit codec (`permit.rs`) is separate from the older exact-operation
approval lane. All integers are big-endian; every version is `u16 = 1`. An
independently pinned root certifies a permit-signing public key in a 130-byte
certificate: `version:2 || root:32 || permit_key:32 || Ed25519_root_signature:64`.
The root signs `"bh/permit-key/v1\0" || first_66_bytes`. Receipt certificates
have a different signing domain and cannot authorize permits.

A signed permit is `certificate:130 || permit_body || Ed25519_signature:64`.
The permit key signs `"bh/permit/v1\0" || permit_body`. The body is:

```
version:u16 = 1 || scope_tag:u8 || log_kind:u8 || log_id:32
|| scope_fields || issued_ms:u64 || deadline_ms:u64 || batch:16
```

Log kind 1 is a base and 2 an account-home log. Scope tags and fields are:

| Tag | Scope | Fields |
| --- | --- | --- |
| 1 | ReadEvents | first:u64, last:u64 (inclusive, 1–64 positions, first ≥ 1) |
| 2 | ReadBodies | count:u16 (1–64), count × commitment:32 |
| 3 | Stage | body_commitment:32, exact_length:u32 |
| 4 | Append | event_digest:32, body_present:u8 (0 or 1), optional body_commitment:32, epoch:32, after_present:u8 (0 or 1), optional predecessor (`position:u64 || hash:32`) |
| 5 | Subscribe | none |
| 6 | ReadControls | after:u64 |
| 7 | StoreHomeObjects | prefix_digest:32, bundle_digest:32 (account-home logs only) |

An Append with a predecessor is a control, ordered on the control route; its
predecessor is the log's **control head**, the last control-route event (the
empty head before genesis), not the log head. Its `epoch` is the epoch in effect
once it is ordered, and all zero means the epoch is closed. An Append without a
predecessor is content, on the content route; its `epoch` is the epoch the log
must be in. ReadControls selects up to 64 control-route events after position
`after`; `after = 0` is the empty head, so that read starts at the genesis.
The caller must bind the signed scope to the actual operation and enforce the
predecessor at use. Verification requires the caller's pinned root and trusted
`now_ms`; permits are valid only from issuance until strictly before deadline,
with `0 < deadline_ms - issued_ms ≤ 30_000`. The authorization service chooses
`batch`; it is not a reusable read grant. All framing is exact and rejects extra
bytes. An append acknowledgement is `version:2 || log_kind:1 || log_id:32 ||
event_id:32 || position:u64 || chain_hash:32 || receipt_present:u8 ||
optional_receipt:300`. The optional receipt must be verified separately against
the pinned hosting root and head; Ack framing is not an authenticity proof.

### Private initial home objects

StoreHomeObjects permits exactly one immutable signup bundle at the authenticated
account's home, not a history append or permission to retrieve recovery material.
The prefix digest is the verified original signup account-chain head hash, **not**
the outer account-log head. The service requires the three-event prefix already
ordered, refreshes current device authority, and checks all three ciphertexts
against that historical prefix's signed commitments.

The bundle is big-endian `version:u16 = 1`, then three `length:u32 || bytes`
fields: recovery record (242 bytes), device seal (1299), recovery seal (1299).
Exactly 2854 bytes, no padding or trailing bytes. Its transport digest is
`H("bh/home-objects/v1\0" || bundle)`, independent of the existing signed
record and seal commitments. The account home inserts only if absent, refuses
any changed digest or bytes under that prefix as Conflict, and awaits storage
sync before acknowledgement, including on exact retries. It takes no append
position, has no public read path, and does not use body staging or its cleanup.

## Data wire

This unshipped transport requires matching producers and consumers; the Events
receipt option is mandatory framing, not negotiated with older builds. Signed
originals, genesis bytes and stored commitments are unchanged.

Each WebSocket message is exactly one binary frame (`wire.rs`) no larger than
4 MiB + 64 KiB, with `version:u16 = 1 || tag:u8 || request_id:u32 || fields`.
All variable byte strings are `length:u32 || bytes`; count fields are `u16`.
Request tags: 1 Read (`permit`); 2 Stage (`permit, body`); 3 Append (`permit,
event`); 4 Subscribe (`permit, after:u64`); 5 Credit (`bytes:u32`, at least 1);
6 StoreHomeObjects (`permit, bundle`).
Credit answers no request, so its request id is always 0. Read's actual
selection is in its signed permit. Response tags: 1 Events (`count:u16,
receipt_present:u8, optional_receipt:300, count × (commitment, event)`); 2 Body (`index:u8, last:u8, bytes`); 3 Staged (no fields);
4 Acked (`ack`); 5 Head (`position:u64, hash:32, receipt_present:u8,
optional receipt`); 6 Refused (`reason:u8`); 7 HomeObjectsStored
(`prefix_digest:32, bundle_digest:32`, exactly 71 bytes including framing).
Event response count cannot exceed
64. Body index is 0–63 and `last` is exactly 0 or 1. For a body read the edge
sends one Body frame for each selected commitment, in the permit's order, with
index equal to its zero-based position and `last = 1` only on the final frame.
A missing body instead produces `Refused { id, reason: Missing }`, ending the
stream for that request id; no more Body frames follow. Each body gets its own
frame so a maximum-size 4 MiB body fits with its framing overhead. Events remain
in one frame because at most 64 fixed-size envelopes fit. Refusal reasons 1–10 are
Expired, Scope, Epoch, Predecessor, Conflict, NotStaged, Reclaiming, Missing,
Malformed and Unavailable, in that order. Encoders preflight total size with
checked arithmetic before copying payloads. Decoders refuse truncation, unknown
tags, unsupported versions, oversize frames, trailing bytes, and a Credit with a
nonzero request id or zero bytes. Transport framing does not verify permission,
event authors, receipts or durable outcomes; those checks belong to the consumers.

An Events receipt flag is exactly 0 or 1; when present the receipt is exactly
300 bytes, without a length prefix. Nonempty base ReadEvents and ReadControls
responses carry a receipt for the exact **last returned** commitment, including
historical and short reads. Empty and account-log responses carry None. The log
object captures immutable rows then awaits storage sync before returning them;
a failed sync returns Unavailable, never rows for the edge to sign. The edge
checks the stored tail commitment and its descriptor against the permitted base
and uses its existing hosting receipt key, not a requester-supplied head. A
receipt proves ordering only: clients still verify the full extension, originals
and bodies before atomic application, and match the receipt to the reached head.
At 64 maximum envelopes, an Events frame including its receipt is
`7 + 2 + 1 + 300 + 64 × (4 + 179 + 4 + 65574) = 4,209,014` bytes,
within the unchanged 4,259,840-byte frame limit. Credit covers every received byte.

The edge checks a request's permit deadline before sending **each** of its data
frames (Events, Body, Staged, Acked, Head and HomeObjectsStored). Past the deadline it withholds the
frame and sends `Refused { id, reason: Expired }` for that request id only; other
requests and the socket continue, and nothing more is sent for that id. A
withheld Staged, Acked or HomeObjectsStored does not undo the stage, commit or
immutable write; an exact retry under a fresh permit learns its outcome.
A subscription ends the same way at its permit's deadline, unless a newer
Subscribe for the same log on that socket has replaced it first.

Data frames are flow-controlled per socket. Each socket starts with a send window
of 8 MiB + 64 KiB: one largest frame plus 4 MiB. Every data frame takes its
encoded length from the window; Refused frames take none. A frame the window does
not cover waits, in arrival order, and the edge reads no stored body for it until
the window covers it. A waiting frame still ends `Expired` at its deadline. A
Credit frame adds `bytes` to the window, and a device keeps data flowing by
granting back each data frame's length once it has processed that frame. A grant
that takes the unused window above 64 MiB is a protocol violation; the edge
closes the socket with 1008.

## Checks and integration limits

In the product workspace run `cargo test --locked -p bh-sync`,
`cargo clippy --locked -p bh-sync --all-targets -- -D warnings`, and
`cargo fmt --all --check`. The native SQLite consumption adapter lives in
`services/sync/` and has separate tests; it is not a hosted endpoint. A standalone
product checkout includes the shared cryptographic library and its documented
libsodium build requirements.

The tests cover strict framing, mutations, common history, exact operation
binding, replay, conservative expiry, lost-Ack planning and unavailable/pending
lane transitions. They do not establish real account removal, attested transport,
rollback-resistant recovery, SQLite/R2 atomicity, workerd behavior, native-client
convergence or hosted deployment. Those require the corresponding real adapters
and cross-component tests; this library deliberately provides no fake account or
hardware verifier for a hosted entry point to select.
