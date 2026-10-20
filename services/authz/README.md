# Authorization service

`bh-authz` authenticates devices and issues the short permits the edge and
log objects check (`../../libs/sync/PROTOCOL.md`, Permissions). Devices reach
it through the edge's `/v1/authz` WebSocket proxy, inside the attested channel
(`../../libs/confidential-channel`); the service answers on `/v1/channel`.

It sees no note content and no content keys. The one key it receives is a
base's metadata root M, inside the attested channel, to verify that base's
genesis and controls; it is held for that request only and never stored or
logged. It orders nothing: an account change is an ordinary append to the
account's log, and a base control an append to the base's log, each made with
a permit the service issues after verifying the original. Messages are defined in
`../../libs/authz-proto` (`bh-authz-proto`), one message per channel record
(at most 65,536 bytes).

## Protocol

After the channel handshake the service sends `Challenge`, fresh for the
connection. Then:

- `Authenticate { proof, account, device, genesis }`. `proof` is
  `bh_account::device_auth` possession over the channel's binding and that
  challenge, made at an account head the service has verified: the current
  head, or an earlier one if the device is behind. `genesis` is the account's
  original genesis; it must hash to `account` and names the account's log.
  The challenge is spent by any attempt. The answer is `Authenticated
  { account_head }` with the current head, or `Refused` (`Unauthenticated`,
  `NotActive`).
- `Permits { items }`: 1–64 requests, at most 1,024 bodies in all, answered in
  order, each a signed permit or a refusal. The session's account log may be
  read (`ReadEvents`) and watched (`Subscribe`), and its bodies read
  (`ReadBodies`) only if each is a body an ordered, verified event of that log
  carries; any other digest is `Unknown`. A base registered to the session's
  account may also be read (`ReadEvents`, `ReadBodies`), watched and staged
  to. An `Append` carries the exact event bytes and the base's epoch; the
  permit binds that event, the body its first 32 envelope bytes commit to and
  no predecessor, which makes it content. It is refused unless, in this
  order: the device is active in the base's copy of the account
  (`NotActive`); the epoch is the base's current one and open (`Epoch`); and
  the base has copied every account event the account has (`AccountChangePending`:
  copy the account's changes first). A base whose control record the service
  cannot account for is `Resync`. Other logs are `Unknown`.
- `SubmitControl { log, event, delivery }`: `event` is an original account
  event for the session's own account log. It is checked against the current
  verified history, then answered with one append permit for its wrapped
  event (`account_log_wrap`) after the current log head. A new account's first
  control is its genesis, after the empty head. An invalid control is
  `Invalid` and gets no permit. A base log is `Unsupported`: base controls
  arrive as `SubmitBaseControl`.
  - `delivery: Some(Delivery { recipient, frame })` carries the signed
    personal-key delivery (`bh_account::personal::seal_for_device`) for a
    device addition. `recipient` must be exactly the device the addition
    introduces (absent before it, active after), and the frame must verify
    against the account with the addition applied
    (`personal::verify_device_delivery`), from a device active before and
    after. Nothing is opened. The answer is then a stage permit for the
    padded body `delivery_body(frame)` and an append permit naming that body's
    commitment; otherwise `Invalid`.
- `RegisterBase { descriptor, body, creator_head, metadata }` carries a new
  base's exact genesis descriptor and body, the creator account head it
  names, and its metadata root M. The service rebuilds the session account's
  verified view at that head from its own retained history, checks the
  session device is active now, and verifies the genesis with
  `bh_event::verify_genesis`; its creator must be the session's account. Only
  then does it record the base, with its content epoch: the genesis's content
  key id (`VerifiedGenesis::content_key_id`), never M's. If the base's log
  already holds controls, it reads them (`ReadControls` from the start, 64 at
  a time, with their bodies) and judges each with M as devices do
  (`bh_event::ControlSpine`), rebuilding the base's control record. It
  answers a stage permit for the body (its exact length) and an append permit
  for the genesis after the empty head. Repeating the same registration is
  idempotent; a genesis that does not verify, from any account, is `Invalid`
  and records nothing. This is also how a device answers `Resync`.
- `SubmitBaseControl { log, descriptor, body, metadata }` carries a base
  control's exact descriptor and body, and the base's M. `log` must be a base
  registered to the session's account (else `Unknown`), and the session's
  device active now. The service first reads the base's controls after its
  control head; one it cannot account for is `Resync`. It then judges the
  control with M against the base's control record
  (`ControlSpine::check_submission`): a wrong M or an invalid control is
  `Invalid`, a kind this version cannot judge `Unsupported`. A copy of an
  account event must be, byte for byte, the account's own ordered event after
  the base's copy of the account; anything else is `Invalid`. One control is
  pending per base: the same bytes get fresh permits for the same
  predecessor, and different bytes are `Conflict` until a minute after the
  pending control's permits expire. The pending control is stored before the
  answer: a stage permit for the body and an append permit after the base's
  control head, whose epoch is the epoch once the control applies, all zeros
  once a removal closes it.

Every request first reads the account's log from the edge past the last
verified position, under a read permit the service issues itself, and verifies
the chain and each original. That read is the head lookup: its start time is
the issued time of every permit the request yields, and each deadline is 30 s
later. If the read or its verification fails, the answer is `Unavailable` and
nothing is issued. A device removed since its session began is refused
`NotActive` on its next request. Requests for one account wait for each other;
other accounts do not wait.

`account_log_wrap(original, body)` makes an account-log event: envelope
`body:32 || length:u32 || original || zeros` in the smallest envelope size,
with `body` the carried body's commitment or all zeros for none, so the log
object's body reference (the first 32 envelope bytes) is that body. The event
id is `H("bh/account-log-event/v2\0" || body:32 || length:u32 || original)`.
`account_log_unwrap` returns the untouched original and the body, and accepts
only that exact wrapping. `account_log_id(genesis)` is the digest of the
wrapped genesis, which carries no body. `delivery_body(frame)` is the body
object `purpose:u8 = 1 || length:u32 || frame || zeros` in the smallest body
size; `delivery_frame` accepts only that exact encoding.

## Base control records

A base's control record follows the base's controls without content or K:
its metadata key id, its epoch (or closed), version floor, last valid control
and control head, and the base's copy of the account, as its head and the
exact account events copied into the base. In memory it also keeps that copy
as a verified account, updated as controls apply, so a content permit costs no
replay. The record is read against the log (`ReadControls` after its control
head) before every `SubmitBaseControl`, on every request while a control is
pending, and once per base after the record is loaded; a permitted control
is confirmed when it appears there by its event id and digest, applying the
effect judged when it was submitted, without M. A pending control not ordered
by a minute after its permits' deadline is dropped. Any other control is one
the service cannot account for: `Resync`, which `RegisterBase` with M
repairs.

Known limits:

- A removal copy closes the base's epoch, and no control reopens it yet, so a
  base takes no content after a removal until a later version adds epoch
  replacement.
- The service relies on the log object to list a base's controls completely;
  withholding them is within its power.
- The version floor follows the versions of controls only.
- Base-level membership has no per-request check of the base's controls: own
  bases need none, because the account is the current authority.
- The record is one instance's state on its disk. A lost or rolled-back disk
  means `Resync` for each base, which its devices answer with M.

## Storage and restart

SQLite at `--db` holds `accounts` (log and verified head), `account_events`
(verified originals and the body each carries), `bases` (the verified
genesis's account and content epoch), and each base's control record:
`base_controls`, `base_account_changes` and `base_pending`; `meta` names the
schema, 3. A disk with another schema is refused. Account history is a cache:
after a restart nothing is issued until the request's own read from the edge
has refreshed the account, and an unreachable edge means `Unavailable`. The
base registry and control records are the only state the edge cannot rebuild,
and a control record can be rebuilt from the log with M.

## Running

```
bh-authz --listen ADDR --db PATH --edge wss://…/v1/data --hosting-root HEX
  --permit-key FILE --permit-cert FILE --app-root HEX --policy FILE --policy-signature FILE
  --quote-socket PATH --collateral FILE
  --roughtime ADDR=KEYHEX --roughtime ADDR=KEYHEX
  --time-config HZ,DRIFT_PPM,SMEAR_US,MAX_AGE_TICKS,MAX_WIDTH_MS
```

The permit key file holds a 32-byte hex seed and the certificate file the
130-byte hex certificate from `bh_sync::permit::certify` under the hosting
root. The policy file is the signed confidential policy devices check, with
its hex signature and the hex root that signs it. Evidence is the dstack
guest agent's quote over each handshake's report data, with collateral the
operator keeps current in `--collateral`. Time is the earliest bound of two
pinned Roughtime servers, refreshed every minute; without qualified time
nothing is issued. The monotonic counter counts nanoseconds, so
`--time-config`'s HZ must be 1000000000; any other value is refused.

A connection must finish its WebSocket upgrade within 5 s, and its device
must authenticate within 30 s of connecting (channel handshake and
attestation included); refused requests do not extend that. After that a
session ends when idle for 10 minutes or when its channel session ends. Up to
1,024 connections are served at once; accept errors back off up to 1 s.

The service reads account logs, and bases' controls and their bodies, through
the edge's `/v1/data` socket (`EdgeClient`): independent reads share at most 4
sockets, up to 8 in flight on each, matched to their answers by request id,
and each Events or Body frame is granted back as credit once taken. Opening a socket gives up after 5 s. A
read whose socket closes, or whose socket could not open, is retried once on
another; a read that times out retires its socket, and one that times out
while its socket is opening frees that socket's place.

A build with the `synthetic-attestation` feature also accepts
`--synthetic-attestation` in place of the hardware and time flags, for local
use: the service presents a labelled synthetic quote that only a device's
synthetic appraisal (`accept_synthetic_proof`) accepts, and uses the local
wall clock. Release builds never enable the feature, and
`bash scripts/check.sh` checks that no release dependency graph does.

## Tests

`cargo test -p bh-authz --features synthetic-attestation` runs the service
against an in-memory edge that checks permits and orders like the real log
object (control head, route and closed epoch), and over a real WebSocket and
attested channel with synthetic attestation. Base controls in the tests come
from the device's own producer (`bh_device::Owner::prepare_account_change_copy`).
`cargo test -p bh-authz` checks that a build without the feature has neither
the synthetic types nor the flag.
