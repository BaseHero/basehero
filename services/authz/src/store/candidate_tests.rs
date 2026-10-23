//! BASE candidate generations: staged rows authorize nothing, publication is
//! one full conditional save, stops pin streamed raw paths, and every write
//! commits whole or not at all.
use super::candidate::{BaseWrite, Candidate};
use super::projection::{Pin, ProjectionHeader, ProjectionWrite, Source, SourceKey};
use super::*;
use bh_account::{DeviceId, VerifiedAccount, projection as account_projection};
use bh_sync::canonical::CanonicalCommitment;
use std::sync::Arc;

/// A HOME log of two signed originals (genesis, then a device addition) at
/// generation 1; a base whose genesis named the HOME head at genesis.
struct Fixture {
    dir: tempfile::TempDir,
    store: Arc<Store>,
    root_key: bh_crypto::SigningKey,
    root: [u8; 32],
    genesis_original: Vec<u8>,
    /// The HOME view at the anchor, as an exact historical HOME view.
    view: VerifiedAccount,
    anchor: Pin,
    home: Pin,
    base: BaseId,
    genesis: Commitment,
    /// The HOME addition, copied into the base as a legacy copy.
    copy: AccountCopy,
    owner: VerifiedBase,
}

fn fixture() -> Fixture {
    use bh_sync::{
        evidence::{ConfirmationClaim, OrderingConfirmation, TimeBounds, original_digest},
        permit,
    };
    let dir = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(&dir.path().join("authz.sqlite")).unwrap());
    let (key, genesis_original, previous, mut first, signer, _) =
        super::projection_tests::seed_on_with_signer();
    let root_key = bh_crypto::SigningKey::generate();
    let root = root_key.public();
    let service = bh_crypto::SigningKey::generate();
    let certificate = permit::certify(&root_key, service.public());
    first.header.root = root;
    let Source::Home(log) = key.source else {
        unreachable!()
    };
    store
        .extend_projected(
            &key.account.0,
            &log.id,
            OrderState::EMPTY,
            previous,
            &[StoredEvent {
                original: genesis_original.clone(),
                body: None,
            }],
            ConfirmedPage {
                confirmations: &[],
                activations: &[],
            },
            &first,
            &[],
        )
        .unwrap();
    let Record::Canonical(current) = store.current_projection(key).unwrap().unwrap() else {
        panic!()
    };
    let anchor = current.header.pin;
    let view = store
        .restore_projection(current, key, root, &genesis_original)
        .unwrap();
    let new_keys = bh_account::DevicePublicKeys::new(
        bh_crypto::SigningKey::generate().public(),
        bh_crypto::SigningKey::generate().public(),
        bh_crypto::KemKey::generate().public(),
    )
    .unwrap();
    let owner_id = view.active_devices().unwrap().next().unwrap().id();
    let draft = view.add_device(owner_id, new_keys).unwrap();
    let original = draft
        .finish(signer.sign(draft.signing_bytes()))
        .unwrap()
        .as_bytes()
        .to_vec();
    let bounds = TimeBounds {
        earliest_ms: 100,
        latest_ms: 100,
    };
    let next = view
        .clone()
        .applied_batch_timed(&[(&original, Some(crate::confirm::time(bounds)))])
        .unwrap();
    let wrapper = bh_authz_proto::account_log_wrap(&original, None).unwrap();
    let after =
        CanonicalCommitment::order(BaseId(log.id), previous, wrapper.digest(), Route::Control)
            .unwrap()
            .after();
    let proof = OrderingConfirmation::sign(
        &service,
        &certificate,
        ConfirmationClaim {
            log,
            original: original_digest(&original),
            original_previous: crate::confirm::head(view.head()),
            original_head: crate::confirm::head(next.head()),
            body: None,
            ordered: after.head(BaseId(log.id)),
            bounds,
        },
    )
    .encode()
    .to_vec();
    let write = ProjectionWrite {
        header: ProjectionHeader {
            pin: Pin {
                key,
                generation: 1,
                cut: next.head(),
            },
            root,
            opening: after,
            prefix: None,
        },
        checkpoint: account_projection::capture(&next),
        delta: account_projection::delta(&next),
        snapshots: vec![],
    };
    let home = store
        .extend_projected(
            &key.account.0,
            &log.id,
            previous,
            after,
            &[StoredEvent {
                original: original.clone(),
                body: None,
            }],
            ConfirmedPage {
                confirmations: &[(2, proof)],
                activations: &[],
            },
            &write,
            &[],
        )
        .unwrap();
    let base = BaseId([0x42; 32]);
    Fixture {
        dir,
        store,
        root_key,
        root,
        genesis_original,
        view,
        anchor,
        home,
        base,
        genesis: commit(
            CanonicalCommitment::order(base, OrderState::EMPTY, Digest(base.0), Route::Control)
                .unwrap(),
        ),
        copy: AccountCopy {
            original,
            confirmation: None,
        },
        owner: VerifiedBase {
            account: key.account.0,
            epoch: [5; 32],
        },
    }
}

/// Receipts signed under the fixture's real hosting root.
fn receipts(f: &Fixture) -> impl Fn(Head) -> [u8; 300] + '_ {
    let signer = bh_crypto::SigningKey::generate();
    let certified =
        receipt::verify_certificate(&f.root, &receipt::certify(&f.root_key, signer.public()))
            .unwrap();
    move |head| receipt::sign(&certified, &signer, f.base, head).unwrap()
}

fn commit(ordered: CanonicalCommitment) -> Commitment {
    Commitment::decode(&ordered.encode()).unwrap()
}
fn control(base: BaseId, before: OrderState, fill: u8) -> Commitment {
    commit(CanonicalCommitment::order(base, before, Digest([fill; 32]), Route::Control).unwrap())
}

/// The spine after `last`, the last raw control: accepted at `accepted`.
fn state(
    f: &Fixture,
    accepted: &Commitment,
    last: &Commitment,
    account: AccountHead,
) -> ControlState {
    ControlState {
        base: f.base,
        creator: f.anchor.key.account,
        hosting_root: f.root,
        metadata_id: [4; 32],
        epoch: Some([5; 32]),
        floor: 3,
        control: accepted.head(),
        control_digest: accepted.event_digest().0,
        control_head: last.head(),
        order: last.after(),
        account,
    }
}

fn write_for(
    f: &Fixture,
    pin: Pin,
    view: &VerifiedAccount,
    opening: OrderState,
) -> ProjectionWrite {
    ProjectionWrite {
        header: ProjectionHeader {
            pin: Pin {
                cut: view.head(),
                ..pin
            },
            root: f.root,
            opening,
            prefix: Some(f.anchor),
        },
        checkpoint: account_projection::capture(view),
        delta: account_projection::delta(view),
        snapshots: vec![],
    }
}

/// A staged candidate: genesis, then one accepted control copying the
/// addition. Returns it, its rebased view and spine.
struct Staged {
    candidate: Candidate,
    view: VerifiedAccount,
    state: ControlState,
    copied: Commitment,
}

fn begin(f: &Fixture) -> (Candidate, VerifiedAccount) {
    let candidate = f
        .store
        .begin_candidate(
            f.base,
            f.anchor,
            f.root,
            &f.genesis,
            &account_projection::capture(&f.view),
        )
        .unwrap();
    let view = account_projection::rebase(
        f.view.clone(),
        f.anchor.cut,
        candidate.pin.generation,
        f.store.history_index(candidate.pin),
    )
    .unwrap();
    (candidate, view)
}

fn stage(f: &Fixture) -> Staged {
    let (mut candidate, view) = begin(f);
    let genesis_state = state(f, &f.genesis, &f.genesis, f.anchor.cut);
    let write = write_for(f, candidate.pin, &view, f.genesis.after());
    candidate.pin = f
        .store
        .stage_candidate(&candidate, &genesis_state, &[], &write, &[f.genesis])
        .unwrap();
    let mut copied_view = view.clone();
    copied_view.apply(&f.copy.original).unwrap();
    let copied = control(f.base, f.genesis.after(), 9);
    let state = state(f, &copied, &copied, copied_view.head());
    let write = write_for(f, candidate.pin, &copied_view, copied.after());
    candidate.pin = f
        .store
        .stage_candidate(
            &candidate,
            &state,
            std::slice::from_ref(&f.copy),
            &write,
            &[copied],
        )
        .unwrap();
    let view = account_projection::rebase(
        copied_view,
        candidate.pin.cut,
        candidate.pin.generation,
        f.store.history_index(candidate.pin),
    )
    .unwrap();
    Staged {
        candidate,
        view,
        state,
        copied,
    }
}

fn publish(f: &Fixture, staged: &Staged, previous: Option<Pin>, expected: Option<Prior>) -> Saved {
    let write = write_for(f, staged.candidate.pin, &staged.view, staged.state.order);
    f.store
        .save_controls_if(
            Some(f.owner),
            Status::Accepted,
            &staged.state,
            None,
            &[],
            expected,
            &BaseWrite {
                candidate: Some(&staged.candidate),
                previous,
                projection: &write,
                copies: &[],
                anchor: f.anchor,
                expected_home: f.home,
            },
        )
        .unwrap()
}

/// Every row of every table, byte for byte.
fn dump(path: &std::path::Path) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    let db = Connection::open(path).unwrap();
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let mut statement = db.prepare(&format!("SELECT * FROM {table}")).unwrap();
            let width = statement.column_count();
            let mut rows: Vec<Vec<rusqlite::types::Value>> = statement
                .query_map([], |r| (0..width).map(|i| r.get(i)).collect())
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap();
            rows.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
            (table, rows)
        })
        .collect()
}
fn path(f: &Fixture) -> std::path::PathBuf {
    f.dir.path().join("authz.sqlite")
}
fn key(f: &Fixture) -> SourceKey {
    SourceKey {
        account: f.anchor.key.account,
        source: Source::Base(f.base),
    }
}

#[test]
fn candidate_rows_are_never_selected_authority() {
    let f = fixture();
    let staged = stage(&f);
    // Staged rows exist, but nothing reads them as the base's authority.
    assert!(f.store.base_snapshot(f.base).unwrap().is_none());
    assert!(f.store.current_projection(key(&f)).unwrap().is_none());
    assert!(f.store.while_running(&[f.base.0], || ()).unwrap().is_some());
    assert!(
        f.store
            .candidate_id_used(&staged.candidate, u64::MAX >> 1, staged.copied.event_id())
            .unwrap()
    );
    // Published, it is the base's one authority, restorable over its pin.
    assert!(matches!(publish(&f, &staged, None, None), Saved::Written));
    let Some(Record::Canonical(snapshot)) = f.store.base_snapshot(f.base).unwrap() else {
        panic!("snapshot")
    };
    assert!(snapshot.pin == staged.candidate.pin && snapshot.anchor == f.anchor);
    assert!(snapshot.projection.state == staged.state);
    let Record::Canonical(stored) = f.store.current_projection(key(&f)).unwrap().unwrap() else {
        panic!()
    };
    let restored = f
        .store
        .restore_projection(stored, key(&f), f.root, &f.genesis_original)
        .unwrap();
    assert_eq!(restored.head(), staged.state.account);
    assert!(
        f.store
            .base_id_used(snapshot.pin, staged.copied.event_id())
            .unwrap()
    );
    // A later candidate's staged rows change nothing a reader sees.
    let before = dump(&path(&f));
    let (next, view) = begin(&f);
    let genesis_state = state(&f, &f.genesis, &f.genesis, f.anchor.cut);
    let extra = control(f.base, f.genesis.after(), 11);
    let mut candidate = next;
    candidate.pin = f
        .store
        .stage_candidate(
            &candidate,
            &genesis_state,
            &[],
            &write_for(&f, candidate.pin, &view, f.genesis.after()),
            &[f.genesis],
        )
        .unwrap();
    let rejected = state(&f, &f.genesis, &extra, f.anchor.cut);
    f.store
        .stage_candidate(
            &candidate,
            &rejected,
            &[],
            &write_for(&f, candidate.pin, &view, extra.after()),
            &[extra],
        )
        .unwrap();
    let Some(Record::Canonical(again)) = f.store.base_snapshot(f.base).unwrap() else {
        panic!()
    };
    assert!(again.pin == snapshot.pin && again.projection.state == snapshot.projection.state);
    assert!(
        !f.store
            .base_id_used(snapshot.pin, extra.event_id())
            .unwrap()
    );
    // The selected generation's rows are byte-for-byte as they were.
    let selected = |dump: &[(String, Vec<Vec<rusqlite::types::Value>>)]| {
        dump.iter()
            .filter(|(t, _)| {
                !matches!(
                    t.as_str(),
                    "base_raw"
                        | "base_ids"
                        | "base_generations"
                        | "projection_sources"
                        | "projection_current"
                        | "projection_active"
                )
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(selected(&dump(&path(&f))), selected(&before));
}

#[test]
fn base_suffix_write_checks_exact_predecessor() {
    let f = fixture();
    let (mut candidate, view) = begin(&f);
    let genesis_state = state(&f, &f.genesis, &f.genesis, f.anchor.cut);
    let write = write_for(&f, candidate.pin, &view, f.genesis.after());
    // The first staged raw control must be this base's exact genesis.
    let other = control(f.base, f.genesis.after(), 3);
    let wrong = state(&f, &other, &other, f.anchor.cut);
    let before = dump(&path(&f));
    assert!(
        f.store
            .stage_candidate(
                &candidate,
                &wrong,
                &[],
                &write_for(&f, candidate.pin, &view, other.after()),
                &[other]
            )
            .is_err()
    );
    assert_eq!(dump(&path(&f)), before);
    candidate.pin = f
        .store
        .stage_candidate(&candidate, &genesis_state, &[], &write, &[f.genesis])
        .unwrap();
    // A raw control that does not extend the staged raw head: refused.
    let gap = control(f.base, control(f.base, f.genesis.after(), 7).after(), 8);
    let gapped = state(&f, &gap, &gap, f.anchor.cut);
    let before = dump(&path(&f));
    assert!(
        f.store
            .stage_candidate(
                &candidate,
                &gapped,
                &[],
                &write_for(&f, candidate.pin, &view, gap.after()),
                &[gap]
            )
            .is_err()
    );
    // A copy at a position other than right after the candidate's cut.
    let mut copied = view.clone();
    copied.apply(&f.copy.original).unwrap();
    let next = control(f.base, f.genesis.after(), 9);
    let next_state = state(&f, &next, &next, copied.head());
    let mut stale = write_for(&f, candidate.pin, &copied, next.after());
    stale.delta.expected = (0, [0; 32]);
    assert!(
        f.store
            .stage_candidate(
                &candidate,
                &next_state,
                std::slice::from_ref(&f.copy),
                &stale,
                &[next]
            )
            .is_err()
    );
    // An earlier handle whose cut the store moved past cannot stage twice.
    let write = write_for(&f, candidate.pin, &copied, next.after());
    let moved = f
        .store
        .stage_candidate(
            &candidate,
            &next_state,
            std::slice::from_ref(&f.copy),
            &write,
            &[next],
        )
        .unwrap();
    let after = dump(&path(&f));
    let next2 = control(f.base, next.after(), 10);
    // Consistent with that older cut and linked to the staged raw head: the
    // stored cut refuses it, and so does the active set, which the copy
    // since staged has changed.
    let again = state(&f, &f.genesis, &next2, f.anchor.cut);
    assert!(
        f.store
            .stage_candidate(
                &candidate,
                &again,
                &[],
                &write_for(&f, candidate.pin, &view, next2.after()),
                &[next2]
            )
            .is_err(),
        "a stale candidate cut must not stage"
    );
    assert_eq!(dump(&path(&f)), after);
    drop(before);
    // Once published, the generation is frozen: neither a stage nor an
    // ordinary save may move it from a stale predecessor.
    candidate.pin = moved;
    let view = account_projection::rebase(
        copied,
        moved.cut,
        moved.generation,
        f.store.history_index(moved),
    )
    .unwrap();
    let staged = Staged {
        candidate,
        view,
        state: next_state.clone(),
        copied: next,
    };
    assert!(matches!(publish(&f, &staged, None, None), Saved::Written));
    let frozen = dump(&path(&f));
    let reject = control(f.base, next.after(), 12);
    assert!(
        f.store
            .stage_candidate(
                &candidate,
                &state(&f, &next, &reject, moved.cut),
                &[],
                &write_for(&f, moved, &staged.view, reject.after()),
                &[reject]
            )
            .is_err()
    );
    let prior = Prior::of(Status::Accepted, &next_state, None);
    let stale_previous = Pin {
        cut: f.anchor.cut,
        ..moved
    };
    let pending_only = write_for(&f, moved, &staged.view, next_state.order);
    assert!(matches!(
        f.store
            .save_controls_if(
                None,
                Status::Accepted,
                &next_state,
                None,
                &[],
                Some(prior.clone()),
                &BaseWrite {
                    candidate: None,
                    previous: Some(stale_previous),
                    projection: &pending_only,
                    copies: &[],
                    anchor: f.anchor,
                    expected_home: f.home,
                },
            )
            .unwrap(),
        Saved::Changed
    ));
    assert_eq!(dump(&path(&f)), frozen);
    // The exact predecessor writes.
    assert!(matches!(
        f.store
            .save_controls_if(
                None,
                Status::Accepted,
                &next_state,
                None,
                &[],
                Some(prior),
                &BaseWrite {
                    candidate: None,
                    previous: Some(moved),
                    projection: &pending_only,
                    copies: &[],
                    anchor: f.anchor,
                    expected_home: f.home,
                },
            )
            .unwrap(),
        Saved::Written
    ));
}

#[test]
fn candidate_publication_full_cas_and_stop_fence() {
    let f = fixture();
    // An accepted record with a pending control at generation 1.
    let first = stage(&f);
    assert!(matches!(publish(&f, &first, None, None), Saved::Written));
    let effect = ControlEffect {
        digest: Digest([12; 32]),
        epoch_after: None,
        account_head_after: first.state.account,
        change: ControlChange::AddDevice,
        account_copies: vec![f.copy.clone()],
        seal_set: None,
        floor_after: first.state.floor,
        seen_position: 1,
        judged_control_digest: first.state.control_digest,
        judged_account_head: first.state.account,
    };
    let pending = Pending {
        event_id: [13; 32],
        after: first.state.control_head,
        deadline_ms: 100,
        effect,
    };
    let noop = write_for(&f, first.candidate.pin, &first.view, first.state.order);
    let ordinary = |pending: Option<&Pending>, expected| {
        f.store
            .save_controls_if(
                None,
                Status::Accepted,
                &first.state,
                pending,
                &[],
                expected,
                &BaseWrite {
                    candidate: None,
                    previous: Some(first.candidate.pin),
                    projection: &noop,
                    copies: &[],
                    anchor: f.anchor,
                    expected_home: f.home,
                },
            )
            .unwrap()
    };
    assert!(matches!(
        ordinary(
            Some(&pending),
            Some(Prior::of(Status::Accepted, &first.state, None))
        ),
        Saved::Written
    ));
    let held = Prior::of(Status::Accepted, &first.state, Some(&pending));
    // A replay candidate staged against that record.
    let replay = stage(&f);
    let path = path(&f);
    let refuses =
        |label: &str, saved: Result<Saved, ServiceError>, expect_changed: bool, before| {
            match saved {
                Ok(Saved::Changed) if expect_changed => {}
                Err(_) if !expect_changed => {}
                Ok(Saved::Stopped) if !expect_changed => {}
                other => panic!("{label}: {:?}", other.map(|s| matches!(s, Saved::Written))),
            }
            assert_eq!(dump(&path), before, "{label}");
        };
    let publication =
        |state: &ControlState, expected: Option<Prior>, previous: Option<Pin>, home: Pin| {
            let write = write_for(&f, replay.candidate.pin, &replay.view, state.order);
            f.store.save_controls_if(
                Some(f.owner),
                Status::Accepted,
                state,
                None,
                &[],
                expected,
                &BaseWrite {
                    candidate: Some(&replay.candidate),
                    previous,
                    projection: &write,
                    copies: &[],
                    anchor: f.anchor,
                    expected_home: home,
                },
            )
        };
    // Stale pending with the same event ID: full Prior equality, not the ID.
    let stale = Prior::of(
        Status::Accepted,
        &first.state,
        Some(&Pending {
            deadline_ms: 101,
            ..pending.clone()
        }),
    );
    let before = dump(&path);
    refuses(
        "stale pending",
        publication(
            &replay.state,
            Some(stale),
            Some(first.candidate.pin),
            f.home,
        ),
        true,
        before.clone(),
    );
    let other_effect = Prior::of(
        Status::Accepted,
        &first.state,
        Some(&Pending {
            effect: ControlEffect {
                digest: Digest([14; 32]),
                ..pending.effect.clone()
            },
            ..pending.clone()
        }),
    );
    refuses(
        "stale pending effect",
        publication(
            &replay.state,
            Some(other_effect),
            Some(first.candidate.pin),
            f.home,
        ),
        true,
        before.clone(),
    );
    // A HOME pin other than the account's current one.
    refuses(
        "changed HOME cut",
        publication(
            &replay.state,
            Some(held.clone()),
            Some(first.candidate.pin),
            f.anchor,
        ),
        true,
        before.clone(),
    );
    // Another generation replaced the selection it expected.
    refuses(
        "generation replacement",
        publication(
            &replay.state,
            Some(held.clone()),
            Some(Pin {
                generation: 9,
                ..first.candidate.pin
            }),
            f.home,
        ),
        true,
        before.clone(),
    );
    // A spine past the staged raw head is not the staged generation.
    let beyond = control(f.base, replay.copied.after(), 21);
    let claimed = state(&f, &replay.copied, &beyond, replay.state.account);
    refuses(
        "terminal raw",
        publication(
            &claimed,
            Some(held.clone()),
            Some(first.candidate.pin),
            f.home,
        ),
        false,
        before.clone(),
    );
    // Future-ID contamination: the selected generation's later IDs are not
    // the candidate's first uses, and the candidate's are not the selected.
    f.store
        .with(|db| {
            db.execute(
                "INSERT INTO base_ids(base,generation,id,position) VALUES(?1,?2,?3,99)",
                params![
                    f.base.0.as_slice(),
                    first.candidate.pin.generation as i64,
                    [77u8; 32].as_slice()
                ],
            )
        })
        .unwrap();
    assert!(
        !f.store
            .candidate_id_used(&replay.candidate, 100, EventId([77; 32]))
            .unwrap()
    );
    let before = dump(&path);
    // A durable stop is the final fence.
    f.store
        .stop(
            &f.base.0,
            f.root,
            first.state.order,
            first.state.order,
            &[7; 300],
            None,
        )
        .unwrap();
    let stopped = dump(&path);
    match publication(
        &replay.state,
        Some(held.clone()),
        Some(first.candidate.pin),
        f.home,
    )
    .unwrap()
    {
        Saved::Stopped => {}
        _ => panic!("stopped scope published"),
    }
    assert_eq!(dump(&path), stopped);
    assert_ne!(stopped, before);
    // Reopened, the stop and the old selection stand.
    let reopened = Store::open(&path).unwrap();
    assert!(
        reopened
            .while_running(&[f.base.0], || ())
            .unwrap()
            .is_none()
    );
    let Some(Record::Canonical(kept)) = reopened.base_snapshot(f.base).unwrap() else {
        panic!()
    };
    assert!(kept.pin == first.candidate.pin && kept.projection.pending == Some(pending));
}

#[test]
fn a_matching_publication_replaces_the_generation_which_is_then_discarded() {
    let f = fixture();
    let first = stage(&f);
    assert!(matches!(publish(&f, &first, None, None), Saved::Written));
    let replay = stage(&f);
    let prior = Prior::of(Status::Accepted, &first.state, None);
    assert!(matches!(
        publish(&f, &replay, Some(first.candidate.pin), Some(prior)),
        Saved::Written
    ));
    let Some(Record::Canonical(snapshot)) = f.store.base_snapshot(f.base).unwrap() else {
        panic!()
    };
    assert!(snapshot.pin == replay.candidate.pin);
    assert_ne!(
        replay.candidate.pin.generation,
        first.candidate.pin.generation
    );
    // The selected generation is kept; the replaced one is unreachable once
    // its first batch commits, then every row of it goes.
    let kept = dump(&path(&f));
    assert!(
        !f.store
            .discard_generation(replay.candidate.pin, 64)
            .unwrap()
    );
    assert_eq!(dump(&path(&f)), kept);
    assert!(f.store.discard_generation(first.candidate.pin, 1).unwrap());
    assert!(
        f.store
            .with(|db| projection::validate(db, first.candidate.pin))
            .is_err()
    );
    while f.store.discard_generation(first.candidate.pin, 1).unwrap() {}
    let rows = |generation: u64| -> i64 {
        let tables = [
            "base_raw",
            "base_ids",
            "projection_copies",
            "projection_times",
            "projection_devices",
            "projection_keys",
            "projection_active",
            "projection_current",
            "projection_sources",
        ];
        tables
            .iter()
            .map(|table| {
                let scope = match table.starts_with("base_") {
                    true => "base=?1",
                    false => "kind=2 AND source=?1",
                };
                f.store
                    .with(|db| {
                        db.query_row(
                            &format!(
                                "SELECT COUNT(*) FROM {table} WHERE {scope} AND generation=?2"
                            ),
                            params![f.base.0.as_slice(), generation as i64],
                            |r| r.get::<_, i64>(0),
                        )
                    })
                    .unwrap()
            })
            .sum()
    };
    assert_eq!(rows(first.candidate.pin.generation), 0);
    assert!(rows(replay.candidate.pin.generation) > 0);
    let Some(Record::Canonical(again)) = f.store.base_snapshot(f.base).unwrap() else {
        panic!()
    };
    assert!(again.pin == replay.candidate.pin);
}

#[test]
fn streamed_stop_path_survives_candidate_cleanup() {
    let f = fixture();
    let sign = receipts(&f);
    let mut staged = stage(&f);
    // An early witness, then later rejected raw controls streamed into the
    // candidate without bodies: the path ends at the authenticated endpoint.
    let later = control(f.base, staged.copied.after(), 31);
    let last = control(f.base, later.after(), 32);
    let tail = state(&f, &staged.copied, &last, staged.state.account);
    staged.candidate.pin = f
        .store
        .stage_candidate(
            &staged.candidate,
            &tail,
            &[],
            &write_for(&f, staged.candidate.pin, &staged.view, last.after()),
            &[later, last],
        )
        .unwrap();
    let known = staged.copied.head();
    let observed = Head {
        position: known.position,
        hash: Digest([66; 32]),
    };
    let witness = SeenReceiptConflict {
        base: f.base,
        root: f.root,
        known,
        observed,
        receipt: sign(observed),
    };
    let endpoint = last.after();
    let proof = sign(endpoint.head(f.base));
    // A path that misses the endpoint, or a witness the path never held,
    // is not evidence: nothing is stored.
    let before = dump(&path(&f));
    let short = later.after();
    assert!(
        f.store
            .stop_seen(
                witness,
                Some((short, &sign(short.head(f.base)), &staged.candidate))
            )
            .is_err()
    );
    let elsewhere = SeenReceiptConflict {
        known: Head {
            position: 77,
            hash: Digest([1; 32]),
        },
        observed: Head {
            position: 77,
            hash: Digest([2; 32]),
        },
        receipt: sign(Head {
            position: 77,
            hash: Digest([2; 32]),
        }),
        ..witness
    };
    assert!(
        f.store
            .stop_seen(elsewhere, Some((endpoint, &proof, &staged.candidate)))
            .is_err()
    );
    assert_eq!(dump(&path(&f)), before);
    f.store
        .stop_seen(witness, Some((endpoint, &proof, &staged.candidate)))
        .unwrap();
    let generation: i64 = f
        .store
        .with(|db| {
            db.query_row(
                "SELECT path_generation FROM base_stops WHERE base=?1",
                [f.base.0.as_slice()],
                |r| r.get(0),
            )
        })
        .unwrap();
    assert_eq!(generation as u64, staged.candidate.pin.generation);
    // Cleanup keeps the stop-referenced path and every staged row of it.
    let kept = dump(&path(&f));
    assert!(
        !f.store
            .discard_generation(staged.candidate.pin, 64)
            .unwrap()
    );
    assert_eq!(dump(&path(&f)), kept);
    // An unreferenced abandoned candidate is cleaned in bounded batches.
    let other = stage(&f);
    let mut batches = 0;
    while f.store.discard_generation(other.candidate.pin, 1).unwrap() {
        batches += 1;
        assert!(batches < 64);
    }
    assert!(batches > 2, "{batches}");
    // Reopened, the stop blocks the base and its path reads back, rooted and
    // linked from the empty raw head through the witness to the endpoint.
    let reopened = Store::open(&path(&f)).unwrap();
    assert!(
        reopened
            .while_running(&[f.base.0], || ())
            .unwrap()
            .is_none()
    );
    let page = reopened
        .candidate_raw_page(&staged.candidate, 0, 64)
        .unwrap();
    assert_eq!(page.len(), 4);
    assert_eq!(page[0], f.genesis);
    assert!(page.iter().any(|c| c.head() == known));
    assert_eq!(page.last().unwrap().after(), endpoint);
    assert!(
        reopened
            .candidate_raw_page(&other.candidate, 0, 64)
            .unwrap()
            .is_empty()
    );
    // A stopped candidate cannot be extended.
    let more = control(f.base, last.after(), 33);
    assert!(
        reopened
            .stage_candidate(
                &staged.candidate,
                &state(&f, &staged.copied, &more, staged.state.account),
                &[],
                &write_for(&f, staged.candidate.pin, &staged.view, more.after()),
                &[more],
            )
            .is_err()
    );
}

#[test]
fn candidate_callbacks_do_not_reenter_writer() {
    let f = fixture();
    let (mut candidate, view) = begin(&f);
    let genesis_state = state(&f, &f.genesis, &f.genesis, f.anchor.cut);
    candidate.pin = f
        .store
        .stage_candidate(
            &candidate,
            &genesis_state,
            &[],
            &write_for(&f, candidate.pin, &view, f.genesis.after()),
            &[f.genesis],
        )
        .unwrap();
    let mut copied = view.clone();
    copied.apply(&f.copy.original).unwrap();
    let next = control(f.base, f.genesis.after(), 9);
    let next_state = state(&f, &next, &next, copied.head());
    let write = write_for(&f, candidate.pin, &copied, next.after());
    // Preparation runs before the writer: the callback reads the store and
    // a BASE index lookup completes, with no lock held.
    let (store, pin) = (f.store.clone(), candidate.pin);
    let ran = std::rc::Rc::new(std::cell::Cell::new(false));
    let seen = ran.clone();
    let index = f.store.history_index(pin);
    let device = DeviceId([3; 32]);
    projection::validation_hook(move || {
        assert!(
            store.db.try_lock().is_ok(),
            "writer lock held during callback"
        );
        assert!(!index.device_seen(pin.cut, &device).unwrap());
        seen.set(true);
        Ok(())
    });
    candidate.pin = f
        .store
        .stage_candidate(
            &candidate,
            &next_state,
            std::slice::from_ref(&f.copy),
            &write,
            &[next],
        )
        .unwrap();
    assert!(ran.get());
    // A failing callback refuses before any write.
    let before = dump(&path(&f));
    projection::validation_hook(|| Err(rusqlite::Error::InvalidQuery));
    let after = control(f.base, next.after(), 10);
    assert!(
        f.store
            .stage_candidate(
                &candidate,
                &state(&f, &next, &after, copied.head()),
                &[],
                &write_for(&f, candidate.pin, &copied, after.after()),
                &[after],
            )
            .is_err()
    );
    assert_eq!(dump(&path(&f)), before);
    // A BASE index whose evidence is gone is unavailable, never absent.
    let index = f.store.history_index(candidate.pin);
    f.store
        .with(|db| db.execute("DROP TABLE projection_copies", []))
        .unwrap();
    assert!(matches!(
        index.device_seen(candidate.pin.cut, &device),
        Err(bh_account::Error::Unavailable)
    ));
}

/// Make `table`'s `event` fail, or with `commit` fail only at commit through
/// a deferred foreign key it leaves behind.
fn inject(store: &Store, table: &str, event: &str, commit: bool) {
    let body = if commit {
        "INSERT INTO commit_guard(parent) VALUES(99);"
    } else {
        "SELECT RAISE(ABORT, 'injected');"
    };
    store
        .with(|db| {
            db.execute_batch(&format!(
                "PRAGMA foreign_keys=ON;
                 CREATE TABLE IF NOT EXISTS commit_parent(id INTEGER PRIMARY KEY);
                 CREATE TABLE IF NOT EXISTS commit_guard(parent INTEGER REFERENCES commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
                 CREATE TRIGGER fault AFTER {event} ON {table} BEGIN {body} END;"
            ))
        })
        .unwrap();
}
fn clear(store: &Store) {
    store
        .with(|db| {
            db.execute_batch(
                "DROP TRIGGER fault; DROP TABLE commit_guard; DROP TABLE commit_parent;",
            )
        })
        .unwrap();
}
fn without_guards(
    dump: Vec<(String, Vec<Vec<rusqlite::types::Value>>)>,
) -> Vec<(String, Vec<Vec<rusqlite::types::Value>>)> {
    dump.into_iter()
        .filter(|(t, _)| !t.starts_with("commit_"))
        .collect()
}

/// With each listed write failing, `op` fails and a reopened disk holds the
/// whole old state; without the fault the same `op` succeeds and changes it.
fn whole_or_nothing(
    label: &str,
    faults: &[(&str, &str)],
    setup: impl Fn() -> (Fixture, Box<dyn Fn(&Fixture) -> bool>),
) {
    for (table, event) in faults
        .iter()
        .map(|(t, e)| (*t, *e, false))
        .chain(faults.last().map(|(t, e)| (*t, *e, true)))
        .map(|(t, e, c)| ((t, e), c))
        .map(|((t, e), c)| (t, (e, c)))
    {
        let (f, op) = setup();
        let before = without_guards(dump(&path(&f)));
        inject(&f.store, table, event.0, event.1);
        assert!(
            !op(&f),
            "{label}: {table} {} succeeded under its fault",
            event.0
        );
        drop(Store::open(&path(&f)).unwrap());
        assert_eq!(
            without_guards(dump(&path(&f))),
            before,
            "{label}: {table} {} (commit {}) left a partial write",
            event.0,
            event.1
        );
        clear(&f.store);
        assert!(op(&f), "{label}: {table} retry");
        assert_ne!(without_guards(dump(&path(&f))), before, "{label}");
    }
}

#[test]
fn every_candidate_suffix_publication_and_stop_write_is_whole_or_nothing() {
    whole_or_nothing(
        "begin",
        &[
            ("base_generations", "INSERT"),
            ("projection_sources", "INSERT"),
            ("projection_current", "INSERT"),
            ("projection_active", "INSERT"),
        ],
        || {
            (
                fixture(),
                Box::new(|f: &Fixture| {
                    f.store
                        .begin_candidate(
                            f.base,
                            f.anchor,
                            f.root,
                            &f.genesis,
                            &account_projection::capture(&f.view),
                        )
                        .is_ok()
                }),
            )
        },
    );
    // A staged copy: suffix rows, times, index delta, current, raw and IDs.
    let staged_genesis = || {
        let f = fixture();
        let (mut candidate, view) = begin(&f);
        candidate.pin = f
            .store
            .stage_candidate(
                &candidate,
                &state(&f, &f.genesis, &f.genesis, f.anchor.cut),
                &[],
                &write_for(&f, candidate.pin, &view, f.genesis.after()),
                &[f.genesis],
            )
            .unwrap();
        (f, candidate, view)
    };
    whole_or_nothing(
        "stage",
        &[
            ("projection_copies", "INSERT"),
            ("projection_times", "INSERT"),
            ("projection_devices", "INSERT"),
            ("projection_keys", "INSERT"),
            ("projection_active", "INSERT"),
            ("projection_current", "UPDATE"),
            ("base_raw", "INSERT"),
            ("base_ids", "INSERT"),
            ("base_generations", "UPDATE"),
        ],
        || {
            let (f, candidate, view) = staged_genesis();
            (
                f,
                Box::new(move |f: &Fixture| {
                    let mut copied = view.clone();
                    copied.apply(&f.copy.original).unwrap();
                    let next = control(f.base, f.genesis.after(), 9);
                    f.store
                        .stage_candidate(
                            &candidate,
                            &state(f, &next, &next, copied.head()),
                            std::slice::from_ref(&f.copy),
                            &write_for(f, candidate.pin, &copied, next.after()),
                            &[next],
                        )
                        .is_ok()
                }),
            )
        },
    );
    // Publication of a genesis-only candidate, and an ordinary save that
    // then appends the copy its consumed effect carries.
    let published = || {
        let (f, candidate, view) = staged_genesis();
        let genesis_state = state(&f, &f.genesis, &f.genesis, f.anchor.cut);
        let view = account_projection::rebase(
            view,
            candidate.pin.cut,
            candidate.pin.generation,
            f.store.history_index(candidate.pin),
        )
        .unwrap();
        (f, candidate, view, genesis_state)
    };
    whole_or_nothing(
        "publish",
        &[
            ("bases", "INSERT"),
            ("projection_current", "UPDATE"),
            ("projection_selected", "INSERT"),
            ("base_generations", "UPDATE"),
            // Its staged IDs are already the generation's: none is new here.
            ("base_controls", "INSERT"),
        ],
        || {
            let (f, candidate, view, genesis_state) = published();
            (
                f,
                Box::new(move |f: &Fixture| {
                    let write = write_for(f, candidate.pin, &view, genesis_state.order);
                    matches!(
                        f.store.save_controls_if(
                            Some(f.owner),
                            Status::Accepted,
                            &genesis_state,
                            None,
                            &[(f.genesis.event_id().0, 1)],
                            None,
                            &BaseWrite {
                                candidate: Some(&candidate),
                                previous: None,
                                projection: &write,
                                copies: &[],
                                anchor: f.anchor,
                                expected_home: f.home,
                            },
                        ),
                        Ok(Saved::Written)
                    )
                }),
            )
        },
    );
    whole_or_nothing(
        "ordinary save",
        &[
            ("projection_copies", "INSERT"),
            ("projection_times", "INSERT"),
            ("projection_devices", "INSERT"),
            ("projection_keys", "INSERT"),
            ("projection_active", "INSERT"),
            ("projection_current", "UPDATE"),
            ("base_controls", "INSERT"),
            ("base_ids", "INSERT"),
        ],
        || {
            let (f, candidate, view, genesis_state) = published();
            let write = write_for(&f, candidate.pin, &view, genesis_state.order);
            assert!(matches!(
                f.store
                    .save_controls_if(
                        Some(f.owner),
                        Status::Accepted,
                        &genesis_state,
                        None,
                        &[],
                        None,
                        &BaseWrite {
                            candidate: Some(&candidate),
                            previous: None,
                            projection: &write,
                            copies: &[],
                            anchor: f.anchor,
                            expected_home: f.home,
                        }
                    )
                    .unwrap(),
                Saved::Written
            ));
            (
                f,
                Box::new(move |f: &Fixture| {
                    let mut copied = view.clone();
                    copied.apply(&f.copy.original).unwrap();
                    let next = control(f.base, f.genesis.after(), 9);
                    let next_state = state(f, &next, &next, copied.head());
                    let write = write_for(f, candidate.pin, &copied, next.after());
                    matches!(
                        f.store.save_controls_if(
                            None,
                            Status::Accepted,
                            &next_state,
                            None,
                            &[(next.event_id().0, next.head().position)],
                            Some(Prior::of(Status::Accepted, &genesis_state, None)),
                            &BaseWrite {
                                candidate: None,
                                previous: Some(candidate.pin),
                                projection: &write,
                                copies: std::slice::from_ref(&f.copy),
                                anchor: f.anchor,
                                expected_home: f.home,
                            },
                        ),
                        Ok(Saved::Written)
                    )
                }),
            )
        },
    );
    whole_or_nothing("stop", &[("base_stops", "INSERT")], || {
        let f = fixture();
        let staged = stage(&f);
        (
            f,
            Box::new(move |f: &Fixture| {
                let sign = receipts(f);
                let known = staged.copied.head();
                let observed = Head {
                    position: known.position,
                    hash: Digest([66; 32]),
                };
                let endpoint = staged.copied.after();
                f.store
                    .stop_seen(
                        SeenReceiptConflict {
                            base: f.base,
                            root: f.root,
                            known,
                            observed,
                            receipt: sign(observed),
                        },
                        Some((endpoint, &sign(endpoint.head(f.base)), &staged.candidate)),
                    )
                    .is_ok()
            }),
        )
    });
}

/// An ordinary save over the staged pin with `state`, no copies.
fn save_at(
    f: &Fixture,
    staged: &Staged,
    state: &ControlState,
    pending: Option<&Pending>,
    ids: &[([u8; 32], u64)],
    expected: Option<Prior>,
) -> Saved {
    let write = write_for(f, staged.candidate.pin, &staged.view, state.order);
    f.store
        .save_controls_if(
            None,
            Status::Accepted,
            state,
            pending,
            ids,
            expected,
            &BaseWrite {
                candidate: None,
                previous: Some(staged.candidate.pin),
                projection: &write,
                copies: &[],
                anchor: f.anchor,
                expected_home: f.home,
            },
        )
        .unwrap()
}

#[test]
fn a_stop_between_check_and_ordinary_save_preserves_projection() {
    let f = fixture();
    let staged = stage(&f);
    assert!(matches!(publish(&f, &staged, None, None), Saved::Written));
    let prior = Prior::of(Status::Accepted, &staged.state, None);
    let before = dump(&path(&f));
    // This save was prepared against `prior` before the stop.
    f.store
        .stop(
            &f.base.0,
            f.root,
            staged.state.order,
            staged.state.order,
            &[7; 300],
            None,
        )
        .unwrap();
    let stopped = dump(&path(&f));
    assert_ne!(stopped, before);
    assert!(matches!(
        save_at(
            &f,
            &staged,
            &staged.state,
            None,
            &[([8; 32], 3)],
            Some(prior)
        ),
        Saved::Stopped
    ));
    assert_eq!(dump(&path(&f)), stopped);
    assert!(f.store.while_running(&[f.base.0], || ()).unwrap().is_none());
    assert!(f.store.while_running(&[[9; 32]], || ()).unwrap().is_some());
    let reopened = Store::open(&path(&f)).unwrap();
    assert!(
        reopened
            .while_running(&[f.base.0], || ())
            .unwrap()
            .is_none()
    );
    assert_eq!(dump(&path(&f)), stopped);
}

#[test]
fn a_provisional_genesis_is_promoted_once_and_never_demoted() {
    let f = fixture();
    let (candidate, view) = begin(&f);
    let genesis = state(&f, &f.genesis, &f.genesis, f.anchor.cut);
    // Not yet ordered: nothing staged, the verified genesis provisional.
    let provisional_write = write_for(&f, candidate.pin, &view, genesis.order);
    assert!(matches!(
        f.store
            .save_controls_if(
                Some(f.owner),
                Status::Provisional,
                &genesis,
                None,
                &[],
                None,
                &BaseWrite {
                    candidate: Some(&candidate),
                    previous: None,
                    projection: &provisional_write,
                    copies: &[],
                    anchor: f.anchor,
                    expected_home: f.home,
                },
            )
            .unwrap(),
        Saved::Written
    ));
    let Some(Record::Canonical(stored)) = f.store.base_snapshot(f.base).unwrap() else {
        panic!()
    };
    assert_eq!(stored.projection.status, Status::Provisional);
    assert!(stored.projection.state == genesis && stored.pin == candidate.pin);
    assert!(
        !f.store
            .base_id_used(stored.pin, f.genesis.event_id())
            .unwrap()
    );
    let held = Prior::of(Status::Provisional, &genesis, None);
    // Another owner's verified genesis for the same base conflicts.
    let (other, other_view) = begin(&f);
    let other_write = write_for(&f, other.pin, &other_view, genesis.order);
    assert!(matches!(
        f.store
            .save_controls_if(
                Some(VerifiedBase {
                    account: [9; 32],
                    ..f.owner
                }),
                Status::Provisional,
                &genesis,
                None,
                &[],
                Some(held.clone()),
                &BaseWrite {
                    candidate: Some(&other),
                    previous: Some(stored.pin),
                    projection: &other_write,
                    copies: &[],
                    anchor: f.anchor,
                    expected_home: f.home,
                },
            )
            .unwrap(),
        Saved::Conflict
    ));
    // A staged candidate never publishes as provisional.
    let staged_genesis = stage(&f);
    let before = dump(&path(&f));
    let write = write_for(
        &f,
        staged_genesis.candidate.pin,
        &staged_genesis.view,
        staged_genesis.state.order,
    );
    assert!(
        f.store
            .save_controls_if(
                Some(f.owner),
                Status::Provisional,
                &staged_genesis.state,
                None,
                &[],
                Some(held.clone()),
                &BaseWrite {
                    candidate: Some(&staged_genesis.candidate),
                    previous: Some(stored.pin),
                    projection: &write,
                    copies: &[],
                    anchor: f.anchor,
                    expected_home: f.home,
                },
            )
            .is_err()
    );
    assert_eq!(dump(&path(&f)), before);
    // Promotion records the ordered genesis's routed ID with it.
    let promoted = Staged {
        candidate: Candidate {
            pin: stored.pin,
            ..candidate
        },
        view,
        state: genesis.clone(),
        copied: f.genesis,
    };
    let ids = [(f.genesis.event_id().0, 1)];
    assert!(matches!(
        save_at(&f, &promoted, &genesis, None, &ids, Some(held.clone())),
        Saved::Written
    ));
    assert!(
        f.store
            .base_id_used(stored.pin, f.genesis.event_id())
            .unwrap()
    );
    let accepted = Prior::of(Status::Accepted, &genesis, None);
    let rows = dump(&path(&f));
    // A stale expectation, or a provisional retry, changes nothing.
    assert!(matches!(
        save_at(&f, &promoted, &genesis, None, &[], Some(held)),
        Saved::Changed
    ));
    let retry = |expected| {
        let (again, again_view) = begin(&f);
        let write = write_for(&f, again.pin, &again_view, genesis.order);
        let saved = f
            .store
            .save_controls_if(
                Some(f.owner),
                Status::Provisional,
                &genesis,
                None,
                &[],
                expected,
                &BaseWrite {
                    candidate: Some(&again),
                    previous: Some(stored.pin),
                    projection: &write,
                    copies: &[],
                    anchor: f.anchor,
                    expected_home: f.home,
                },
            )
            .unwrap();
        while f.store.discard_generation(again.pin, 64).unwrap() {}
        saved
    };
    assert!(matches!(retry(Some(accepted)), Saved::Changed));
    assert!(matches!(retry(None), Saved::Changed));
    // Only the discarded attempts' tombstones differ.
    let without = |d: Vec<(String, Vec<Vec<rusqlite::types::Value>>)>| {
        d.into_iter()
            .filter(|(t, _)| t != "base_generations")
            .collect::<Vec<_>>()
    };
    assert_eq!(without(dump(&path(&f))), without(rows));
}

#[test]
fn a_projection_never_moves_behind_its_raw_checkpoint() {
    let f = fixture();
    let staged = stage(&f);
    assert!(matches!(publish(&f, &staged, None, None), Saved::Written));
    let rows = dump(&path(&f));
    let at_later = Prior::of(Status::Accepted, &staged.state, None);
    // The genesis raw state, at the copy's account head, is behind the
    // durable raw checkpoint: nothing changes.
    let earlier = state(&f, &f.genesis, &f.genesis, staged.state.account);
    assert!(matches!(
        save_at(&f, &staged, &earlier, None, &[], Some(at_later)),
        Saved::Changed
    ));
    assert_eq!(dump(&path(&f)), rows);
}

#[test]
fn equal_heads_do_not_alias_base_sources() {
    let f = fixture();
    let staged = stage(&f);
    assert!(matches!(publish(&f, &staged, None, None), Saved::Written));
    let home_key = f.anchor.key;
    let Record::Canonical(base) = f.store.current_projection(key(&f)).unwrap().unwrap() else {
        panic!()
    };
    let Record::Canonical(home) = f.store.current_projection(home_key).unwrap().unwrap() else {
        panic!()
    };
    // Both are at the same account head, yet neither restores as the other.
    assert!(base.header.pin.cut == home.header.pin.cut);
    assert!(
        f.store
            .restore_projection(base, home_key, f.root, &f.genesis_original)
            .is_err()
    );
    assert!(
        f.store
            .restore_projection(home, key(&f), f.root, &f.genesis_original)
            .is_err()
    );
    // Another base of the same account at that head is its own source: its
    // copy, index and generation never answer for this one.
    let other = SourceKey {
        source: Source::Base(BaseId([0x43; 32])),
        ..key(&f)
    };
    assert!(f.store.current_projection(other).unwrap().is_none());
    let foreign = f.store.history_index(Pin {
        key: other,
        ..staged.candidate.pin
    });
    assert!(matches!(
        foreign.device_seen(staged.candidate.pin.cut, &DeviceId([3; 32])),
        Err(bh_account::Error::Unavailable)
    ));
    // A stored BASE projection claimed for another base or account refuses.
    let Record::Canonical(base) = f.store.current_projection(key(&f)).unwrap().unwrap() else {
        panic!()
    };
    let mut renamed = base;
    renamed.header.pin.key = other;
    assert!(
        f.store
            .restore_projection(renamed, other, f.root, &f.genesis_original)
            .is_err()
    );
}

#[test]
fn base_prefix_is_one_pinned_home_plus_local_suffix() {
    let f = fixture();
    let (candidate, view) = begin(&f);
    // The HOME log already holds the addition at position 2, past the
    // anchor: the BASE index, clamped to its prefix cut, has not seen it.
    let added = bh_account::AccountEvent::decode(&f.copy.original).unwrap();
    let bh_account::AccountChange::DeviceAdded { device, .. } = added.change() else {
        panic!("not an addition")
    };
    let index = f.store.history_index(candidate.pin);
    let home_index = f.store.history_index(f.home);
    assert!(home_index.device_seen(f.home.cut, &device).unwrap());
    projection::begin_work();
    assert!(!index.device_seen(candidate.pin.cut, &device).unwrap());
    assert!(
        index
            .event_matches(candidate.pin.cut, 1, &f.genesis_original)
            .unwrap()
    );
    assert!(matches!(
        index.event_matches(candidate.pin.cut, 2, &f.copy.original),
        Err(bh_account::Error::Unavailable)
    ));
    let work = projection::end_work();
    assert!(
        work.sources
            .iter()
            .all(|k| *k == candidate.pin.key || *k == f.anchor.key)
    );
    assert!(work.sources.contains(&f.anchor.key) && work.sources.contains(&candidate.pin.key));
    assert_eq!(work.transitions, 0);
    // Once the copy is staged it is the BASE suffix's own row at position 2.
    let mut candidate = candidate;
    let genesis_state = state(&f, &f.genesis, &f.genesis, f.anchor.cut);
    candidate.pin = f
        .store
        .stage_candidate(
            &candidate,
            &genesis_state,
            &[],
            &write_for(&f, candidate.pin, &view, f.genesis.after()),
            &[f.genesis],
        )
        .unwrap();
    let mut copied = view.clone();
    copied.apply(&f.copy.original).unwrap();
    let next = control(f.base, f.genesis.after(), 9);
    candidate.pin = f
        .store
        .stage_candidate(
            &candidate,
            &state(&f, &next, &next, copied.head()),
            std::slice::from_ref(&f.copy),
            &write_for(&f, candidate.pin, &copied, next.after()),
            &[next],
        )
        .unwrap();
    let index = f.store.history_index(candidate.pin);
    assert!(index.device_seen(candidate.pin.cut, &device).unwrap());
    assert!(
        index
            .event_matches(candidate.pin.cut, 2, &f.copy.original)
            .unwrap()
    );
    // A legacy copy is known untimed; the HOME prefix keeps HOME's times.
    assert_eq!(index.confirmed_time(candidate.pin.cut, 2).unwrap(), None);
    assert_eq!(index.confirmed_time(candidate.pin.cut, 1).unwrap(), None);
    let home_time = home_index.confirmed_time(f.home.cut, 2).unwrap();
    assert!(home_time.is_some());
    // The HOME prefix row it reads is the anchor's: removing HOME's later
    // row changes nothing the BASE copy answers, only HOME's own index.
    f.store
        .with(|db| {
            db.execute(
                "DELETE FROM projection_devices WHERE kind=1 AND first_position=2",
                [],
            )
        })
        .unwrap();
    assert!(index.device_seen(candidate.pin.cut, &device).unwrap());
    assert!(!home_index.device_seen(f.home.cut, &device).unwrap());
}

#[test]
fn only_candidate_staging_commits_without_its_own_sync() {
    let f = fixture();
    // Each write records the connection's synchronous level as it runs.
    f.store
        .with(|db| {
            db.execute_batch("CREATE TEMP TABLE seen(name TEXT, level INTEGER);")?;
            for table in [
                "base_generations",
                "base_raw",
                "base_controls",
                "projection_selected",
                "base_stops",
            ] {
                db.execute_batch(&format!(
                    "CREATE TEMP TRIGGER seen_{table} BEFORE INSERT ON main.{table} BEGIN
                       INSERT INTO seen SELECT '{table}', synchronous FROM pragma_synchronous;
                     END;"
                ))?;
            }
            Ok(())
        })
        .unwrap();
    let level = || -> i64 {
        f.store
            .with(|db| db.query_row("PRAGMA synchronous", [], |r| r.get(0)))
            .unwrap()
    };
    let staged = stage(&f);
    assert_eq!(level(), 2);
    // A refused stage restores FULL too.
    assert!(
        f.store
            .stage_candidate(
                &staged.candidate,
                &staged.state,
                &[],
                &write_for(&f, staged.candidate.pin, &staged.view, staged.state.order),
                &[staged.copied],
            )
            .is_err()
    );
    assert_eq!(level(), 2);
    assert!(matches!(publish(&f, &staged, None, None), Saved::Written));
    f.store
        .stop(
            &f.base.0,
            f.root,
            staged.state.order,
            staged.state.order,
            &[7; 300],
            None,
        )
        .unwrap();
    assert_eq!(level(), 2);
    let seen: Vec<(String, i64)> = f
        .store
        .with(|db| {
            db.prepare("SELECT DISTINCT name, level FROM seen ORDER BY name")?
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect()
        })
        .unwrap();
    let seen: Vec<_> = seen.iter().map(|(n, l)| (n.as_str(), *l)).collect();
    // NORMAL (1) for begin and stage; FULL (2) for publication and the stop.
    assert_eq!(
        seen,
        [
            ("base_controls", 2),
            ("base_generations", 1),
            ("base_raw", 1),
            ("base_stops", 2),
            ("projection_selected", 2),
        ]
    );
}
