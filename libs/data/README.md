# bh-data

Shared typed-record identities, JSON field paths, value limits, schema models and query metadata for BaseHero apps. Consumers use these contracts to define and work with shared records.

## Host boundaries

`session::Authority` supplies verified identity/read/write authority. Its default `confirm_rule_change` refuses management changes. A host confirms the exact `admission::Confirmation` (operation including exact definition bytes, scope, actor and applicable prior rules), not merely a device identity. Unconfirmed session/tool mutations return a proposal, never a publishable local save. `approve` rechecks that trusted evidence; invoking it does not create confirmation.

Incoming management operations use `apply_payload_with_admission` / `apply_ordered_with_admission`, and parked replay uses `retry_parked_with_admission`. The original entry points default to unavailable evidence and reject unconfirmed management changes. A production host must verify authentication, current authority and exact own-device approval at the supplied log position, including after restart. `pending::submit_with_admission` supports the same boundary for host-owned local writes. Real credentials remain host-owned; this library defines no competing signature format. `testkit::AssumedAdmission` is only a fixture assumption, never a production verifier.

Adoption verifies source readership and exact accepted source definition bytes and app provenance before the adoption position in the **same containing base's common ordered log**. Missing source coverage waits; complete evidence of absence rejects. The source's current rules never replace the pinned adopted contract.

Negative identity decisions require complete scope coverage, including canonical Note identities. Local creations remain durable waiting proposals while coverage is incomplete. Hosts must not claim complete coverage while a relevant Note identity/projection is missing.

## Derived work

A search mapping change atomically queues only that scoped concrete type in `data_text_mapping`. Hosts commit bounded `text::reproject_step` turns until it returns true; queries expose lag while work remains. Foreground hooks and reconstruction use the current effective mapping without changing a record's schema revision. Body extraction remains separate. The scope's core initialization marker is independent of whether an earlier reference created its identity.

`UndoRemove` reverses creation/restoration only while the existence and field clocks still belong to the named mutation **and ordered position**. Deliberate `Delete` is separate. Unknown operation kinds remain parked on older executables.
