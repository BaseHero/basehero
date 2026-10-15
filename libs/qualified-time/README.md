# bh-qualified-time

Pure, boot-local Google-Roughtime v1 verification and two-server UTC/POSIX
intervals. It does not read a clock, generate nonces, send UDP or persist an
anchor. A new `QualifiedClock` is **Unavailable** until `update` receives both
signed replies. Loss of either reply invalidates the previous anchor. Supply
two independently operated, pinned Ed25519 root keys, different fresh 64-byte
nonces, original raw replies and monotonic send/receipt counter readings for
each request. The caller is responsible for actually stamping transport,
secure nonce generation/uniqueness (including failed sends) and confirming
both servers' independence. This crate detects reuse of previously accepted
nonces within its boot-local bounded state. The native Unix host's
`bh-confidential-host::TimeSampler` supplies the UDP transport, new nonces and
send/receipt stamps; it still requires trusted configuration and a qualified
caller-supplied counter. `mark_unavailable` clears the anchor before that
adapter starts I/O, so cancellation cannot preserve previously qualified time.

`Config` is mandatory: nominal ticks/s, measured conservative drift in ppm,
server leap-smear-to-POSIX margin in microseconds, maximum anchor age in ticks,
and maximum acceptable interval width in milliseconds. **No** host TSC
frequency, drift, pause guarantee, leap-smear margin or production threshold is
asserted here. If the counter pauses while real time advances, these bounds do
not hold. The host must substantiate those assumptions before using the
interval for authority. Bounds account for server radius, time anywhere between
send and receipt, fastest/slowest oscillator, and the caller's smear margin.
The two intervals must overlap; the result is their **hull**, never their
intersection. Outage, disagreement, rollback, replay, overflow, staleness or
excessive width is unavailable. Re-anchor with new nonces when stale or wide;
construct a new clock after a counter rollback/restart, never restore old
anchors. The bounded nonce history refuses after 4096 accepted nonces, so
processes must rotate this in-memory clock instance before then using freshly
generated nonces; no claim of cross-instance replay protection is made.

`Bounds` is inclusive milliseconds. A deadline passed only when `earliest_ms >=
deadline`; an action before it (including a half-open expiry) requires
`latest_ms < deadline`. Conversion to confidential-policy `TimeBounds` or
confidential-attestation `Time` rounds earliest down and latest up to seconds;
attestation's permitted uncertainty remains an explicit caller parameter.
There is no checker integration or device-side clock here. Genuine replies
recorded from the public Cloudflare and int08h Roughtime servers on 2026-10-13
are verified offline against their published keys; the adversarial fixtures
are signed with synthetic test keys.
