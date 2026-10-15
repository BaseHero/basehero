# Checker attested channel (native library)

Portable checker-only five-frame session and bounded ordered records. No transport,
checker service, real device-policy storage adapter, device authentication, tickets,
job authority or key release. Use ordinary hybrid-first rustls outside the channel;
identity appears only in encrypted Data. The caller must persist a single app-rooted
`PolicyContext` and supply a genuinely atomic, crash-durable `PolicyStore`: `Fresh`
means a deliberate new-install initialization, never a missing established record.
`Missing` and corrupt committed data refuse startup. A feed outage reported while
a save is pending remains unavailable after the exact candidate commits, until a
fresh authenticated delivery. Outage is volatile but restart is always unavailable
until an explicit authenticated policy delivery.

The verifier checks Intel signatures/certificates/TCB, nonce/key binding and the
complete dstack event log once per new Proof, outside the app-root policy mutex.
It retains opaque `VerifiedEvidence`, not raw quote/collateral/log buffers. On
reentry it freshly samples and checks the authenticated half-open validity horizon
and the **current** policy before publishing ProofChecked. KEM, Finish, every client
send and plaintext delivery recheck that horizon and current policy under the same
lock as their actual action. A concurrent withdrawal, outage or pending failed save
cannot be bypassed by previously verified evidence. No authorization is cached.

`PolicyContext::new` owns a trusted `Clock` adapter returning system POSIX seconds
and monotonic milliseconds. All client operations sample it **under** the shared
lock; there is no pre-sampled client API. The sampler must be nonblocking/local,
not fetch network time or return stale observations. Build-date/high-water checks
refuse real backwards observations without mistaking thread scheduling for clock
rollback. Local deadlines use that same locked sample. Zero uncertainty represents
system-clock trust, not proven accuracy. Server pending states use separate
monotonic readings; confirmed server sessions own a clock used only for disposal,
not VM authority. Callers must expire idle sessions and bound
outstanding quote acquisition. Each handshake has fresh private signing/KEM keys;
no resumption or replay after transport loss. A Close is not acknowledgement of work.

Tests source-include the verifier to keep synthetic full-measurement assembly
crate-private, with no production test feature or public claims constructor.
They run archived genuine QVL then alter fixture claims for fresh keys/log binding;
that synthetic assembly is not an Intel-signed fresh proof. Archived QVL fixtures do not
match fresh report_data and do not prove a successful live handshake. Before using
this library in the app, provide and test a real durable adapter, fresh matched
hardware evidence, native runtime time checks, transport lifecycle and integrated workload capacity.
An explicit Linux release probe runs both record directions with 1/8/32 sessions:
`cargo test --release -p bh-confidential-channel --lib release_scale_matrix -- --ignored --nocapture --test-threads=1`.
It measures synthetic records separately from 100 genuine archived QVL calls;
record paths perform zero QVL calls. Timings include opt-in test-only lock probes,
not production telemetry or a hardware-throughput claim. The protocol's signed policy authenticates an approved checker
role and measured machine, not a particular URL and never a device.
