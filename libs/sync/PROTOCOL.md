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
Ordering the first event checks that its digest equals the base id.

A body-free `Commitment` is 178 bytes:

```
u16 version = 1
32  base_id
u64 previous_position
32  previous_chain_hash
32  event_id
32  event_digest
u64 assigned_position
32  assigned_chain_hash
```

The assigned position must be the previous position plus one, without overflow.
The assigned hash is `H("bh/chain/v1\0" || preceding_146_bytes)`.
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
1024, 4096, 16384 or 65536 bytes. The kernel computes that commitment from the
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
