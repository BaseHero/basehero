use std::future::Future;
use std::path::PathBuf;

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => panic!("synthetic adapter unexpectedly pending"),
    }
}

#[path = "support/indexed_journal.rs"]
mod indexed_journal;

#[path = "support/protector.rs"]
mod protector;
#[path = "support/store.rs"]
mod store;

use bh_account::journal::{AccountJournal, JournaledAccount, SetupStage};
use bh_account::owner::{
    AccountCapability, AccountGeneration, AccountLoad, AdmissionReason, Authority, OwnerError,
    SetupError, SetupStatus,
};
use bh_account::platform::{ControlKeyPolicy, KeyStoreError};
use bh_account::recovery::Password;
use bh_account::storage::DeviceJournal;
use bh_account::{AccountEvent, Head};
use protector::PlainProtector;
use rusqlite::{Connection, params};
use store::FakeStore;

type Owner = bh_account::owner::AccountOwner<DeviceJournal, FakeStore, PlainProtector>;

#[test]
fn retained_initial_bootstrap_opens_after_home_ack_and_later_controls() {
    let h = Harness::new();
    let mut owner = h.owner();
    let setup = begin(&mut owner);
    let originals = owner.pending_home_objects().unwrap();
    owner.confirm_kit_saved().unwrap();
    owner.confirm_home_ordered(setup.head).unwrap();
    assert!(h.journal().pending_setup().unwrap().is_none());
    drop(owner);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    append_devices(&mut owner, &cap, 2);
    let (prefix, objects) = owner.initial_bootstrap(&cap).unwrap();
    assert!(prefix.anchor == setup.anchor);
    assert_eq!(prefix.head, setup.head);
    assert_eq!(prefix.events, setup.submission);
    assert!(objects == originals);
    let personal = ready(owner.open_personal(&cap)).unwrap();
    let (ct, shared) = bh_account::crypto::encapsulate(&personal.public()).unwrap();
    assert_eq!(personal.decapsulate(&ct).unwrap().expose(), shared.expose());
    let signature = ready(owner.sign_content(&cap, b"native content")).unwrap();
    bh_account::crypto::verify(
        owner
            .verified(&cap)
            .unwrap()
            .active_device(cap.device_id())
            .unwrap()
            .signing(),
        b"native content",
        &signature,
    )
    .unwrap();
}

#[test]
fn retained_bootstrap_survives_failed_pending_clear_and_refuses_private_tampering() {
    let h = Harness::new();
    let mut owner = h.owner();
    let setup = begin(&mut owner);
    owner.confirm_kit_saved().unwrap();
    let cap = activate(&mut owner);
    let before = owner.initial_bootstrap(&cap).unwrap();
    h.raw().execute_batch("CREATE TRIGGER prevent_clear BEFORE DELETE ON account_pending_setup BEGIN SELECT RAISE(FAIL,'interrupted clear'); END;").unwrap();
    assert!(owner.confirm_home_ordered(setup.head).is_err());
    drop(owner);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    assert!(owner.initial_bootstrap(&cap).unwrap() == before);
    h.raw().execute_batch("DROP TRIGGER prevent_clear").unwrap();
    owner.confirm_home_ordered(setup.head).unwrap();
    for column in ["recovery_record", "device_seal", "recovery_seal"] {
        let raw = h.raw();
        let bytes: Vec<u8> = raw
            .query_row(
                &format!("SELECT {column} FROM account_initial_bootstrap"),
                [],
                |r| r.get(0),
            )
            .unwrap();
        let mut changed = bytes.clone();
        let index = changed.len() / 2;
        changed[index] ^= 1;
        raw.execute(
            &format!("UPDATE account_initial_bootstrap SET {column}=?1"),
            [&changed],
        )
        .unwrap();
        assert!(
            owner.initial_bootstrap(&cap).is_err(),
            "accepted altered {column}"
        );
        assert!(ready(owner.open_personal(&cap)).is_err());
        raw.execute(
            &format!("UPDATE account_initial_bootstrap SET {column}=?1"),
            [&bytes],
        )
        .unwrap();
    }
    h.raw()
        .execute(
            "UPDATE account_initial_bootstrap SET head_hash=zeroblob(32)",
            [],
        )
        .unwrap();
    assert!(owner.initial_bootstrap(&cap).is_err());
}

#[test]
fn retained_ciphertexts_are_not_overwritten_by_a_pending_retry() {
    let h = Harness::new();
    let mut owner = h.owner();
    let setup = begin(&mut owner);
    owner.confirm_kit_saved().unwrap();
    let raw = h.raw();
    let mut bytes: Vec<u8> = raw
        .query_row(
            "SELECT device_seal FROM account_initial_bootstrap",
            [],
            |r| r.get(0),
        )
        .unwrap();
    bytes[800] ^= 1;
    raw.execute(
        "UPDATE account_initial_bootstrap SET device_seal=?1",
        [&bytes],
    )
    .unwrap();
    assert!(owner.confirm_home_ordered(setup.head).is_err());
    assert!(h.journal().pending_setup().unwrap().is_some());
    let after: Vec<u8> = raw
        .query_row(
            "SELECT device_seal FROM account_initial_bootstrap",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(
        after, bytes,
        "never silently replace retained originals on retry"
    );
}

#[test]
fn native_sync_proof_uses_ordinary_path() {
    use bh_account::{
        Error,
        device_auth::{self, Context},
    };
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let context = Context {
        channel_binding: [41; 32],
        challenge: [42; 32],
    };
    let before_control = h.store.state().sign_calls;
    let before_content = h.store.state().content_sign_calls;
    let proof = ready(owner.prove_sync_device(&cap, context)).unwrap();
    let at =
        device_auth::verify_at(owner.verified(&cap).unwrap(), context, proof.as_bytes()).unwrap();
    assert!(at.account() == cap.account_id());
    assert!(at.device() == cap.device_id());
    assert_eq!(at.head(), cap.head());
    assert_eq!(h.store.state().sign_calls, before_control);
    assert_eq!(h.store.state().content_sign_calls, before_content + 1);

    h.store.state_mut().wrong_content_signature = true;
    assert!(matches!(
        ready(owner.prove_sync_device(&cap, context)),
        Err(OwnerError::Invalid(Error::BadSignature))
    ));
    h.store.state_mut().wrong_content_signature = false;
    h.store.state_mut().content_error = Some(KeyStoreError::AuthenticationCancelled);
    assert!(matches!(
        ready(owner.prove_sync_device(&cap, context)),
        Err(OwnerError::Device(KeyStoreError::AuthenticationCancelled))
    ));
    h.store.state_mut().content_error = None;
    h.store.state_mut().wrong_public = true;
    assert!(matches!(
        ready(owner.prove_sync_device(&cap, context)),
        Err(OwnerError::Device(KeyStoreError::WrongKey))
    ));
    assert_eq!(h.store.state().sign_calls, before_control);
    assert_eq!(h.store.state().content_sign_calls, before_content + 3);
}

#[test]
fn prove_at_refuses_future_head_and_inactive_device() {
    use bh_account::{
        Error,
        device_auth::{self, Context},
        journal::JournaledDevice,
        platform::DeviceKeyStore,
    };
    let context = Context {
        channel_binding: [41; 32],
        challenge: [42; 32],
    };
    // The first device signs up, then adds a second device at position 4.
    let h = Harness::new();
    complete(&h);
    let joined = Harness::new();
    let second = ready(
        joined
            .store
            .clone()
            .create(ControlKeyPolicy::AppEnforcedOwnerConfirmation),
    )
    .unwrap();
    let mut first = h.owner();
    let cap = activate(&mut first);
    let request = first.prepare_add_device(&cap, second.keys.clone()).unwrap();
    let addition = ready(first.sign_control(&cap, &request)).unwrap();
    first.apply_incoming(&[addition.as_bytes()]).unwrap();
    let cap = activate(&mut first);
    let history = h.stored().history;
    assert_eq!(history.len(), 4);

    // Proofs at each earlier verified head the first device was active at.
    let views: Vec<_> = (1..=4)
        .map(|n| {
            let events: Vec<&[u8]> = history[..n].iter().map(Vec::as_slice).collect();
            let mut view =
                bh_account::VerifiedAccount::from_genesis(cap.account_id(), events[0]).unwrap();
            view.apply_batch(&events[1..]).unwrap();
            view
        })
        .collect();
    for (n, view) in views.iter().enumerate() {
        let position = n as u64 + 1;
        let proof = ready(first.prove_sync_device_at(&cap, position, context)).unwrap();
        let at = device_auth::verify_at(view, context, proof.as_bytes()).unwrap();
        assert_eq!(at.head(), view.head());
        assert!(at.device() == cap.device_id());
    }
    for position in [0, 5] {
        assert!(matches!(
            ready(first.prove_sync_device_at(&cap, position, context)),
            Err(OwnerError::Invalid(Error::InvalidCredentials))
        ));
    }

    // The second device holds the same history; it was not active before 4.
    let mut journal = joined.journal();
    journal
        .commit_device(&JournaledDevice {
            handle: second.handle.clone(),
            keys: second.keys.clone(),
            policy: second.policy,
            kind: second.kind,
        })
        .unwrap();
    let events: Vec<&[u8]> = history.iter().map(Vec::as_slice).collect();
    journal
        .commit_verified(cap.account_id(), &events, views[3].head(), false)
        .unwrap();
    let mut other = joined.owner();
    let joined_cap = activate(&mut other);
    let signed = joined.store.state().content_sign_calls;
    for position in 1..=3 {
        assert!(matches!(
            ready(other.prove_sync_device_at(&joined_cap, position, context)),
            Err(OwnerError::Invalid(Error::NotActive))
        ));
    }
    assert_eq!(
        joined.store.state().content_sign_calls,
        signed,
        "nothing signed"
    );
    let proof = ready(other.prove_sync_device_at(&joined_cap, 4, context)).unwrap();
    let at = device_auth::verify_at(&views[3], context, proof.as_bytes()).unwrap();
    assert!(at.device() == joined_cap.device_id());
}

#[test]
fn late_sync_proof_is_discarded() {
    use bh_account::device_auth::Context;
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let context = Context {
        channel_binding: [41; 32],
        challenge: [42; 32],
    };
    h.store.state_mut().advance_generation_on_load = true;
    assert!(matches!(
        ready(owner.prove_sync_device(&cap, context)),
        Err(OwnerError::Stale)
    ));
    assert_eq!(h.store.state().content_sign_calls, 0);
    h.store.state_mut().advance_generation_on_load = false;
    let cap = activate(&mut owner);
    h.store.state_mut().advance_generation_on_sign = true;
    assert!(matches!(
        ready(owner.prove_sync_device(&cap, context)),
        Err(OwnerError::Stale)
    ));
    assert_eq!(h.store.state().content_sign_calls, 1);
    h.store.state_mut().advance_generation_on_sign = false;
    let before = h.store.state().content_sign_calls;
    assert!(matches!(
        ready(owner.prove_sync_device(&cap, context)),
        Err(OwnerError::Stale)
    ));
    assert_eq!(h.store.state().content_sign_calls, before);
    let cap = activate(&mut owner);
    owner.lock().unwrap();
    assert!(matches!(
        ready(owner.prove_sync_device(&cap, context)),
        Err(OwnerError::NotActive)
    ));
    assert_eq!(h.store.state().content_sign_calls, before);
}

#[test]
fn late_native_content_and_personal_results_are_discarded() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    h.store.state_mut().advance_generation_on_load = true;
    assert!(matches!(
        ready(owner.open_personal(&cap)),
        Err(OwnerError::Stale)
    ));
    h.store.state_mut().advance_generation_on_load = false;
    let cap = activate(&mut owner);
    h.store.state_mut().advance_generation_on_sign = true;
    assert!(matches!(
        ready(owner.sign_content(&cap, b"discard")),
        Err(OwnerError::Stale)
    ));
}

#[test]
fn ephemeral_journal_accepts_two_successors_without_projection_cursor() {
    let generation = AccountGeneration::new();
    let store = FakeStore::new(generation.clone());
    let database = std::sync::Arc::new(std::sync::Mutex::new(
        bh_storage::DeviceDatabase::open(":memory:").unwrap(),
    ));
    let journal = DeviceJournal::from_shared(database.clone());
    let mut owner =
        bh_account::owner::AccountOwner::new(journal, store, PlainProtector, generation);
    ready(owner.begin_first_device(
        ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        &Password::new("ephemeral successor test").unwrap(),
    ))
    .unwrap();
    owner.confirm_kit_saved().unwrap();
    let cap = activate(&mut owner);
    for tag in [30, 40] {
        let keys =
            bh_account::DevicePublicKeys::new([tag; 32], [tag + 1; 32], [tag + 2; 1216]).unwrap();
        let request = owner.prepare_add_device(&cap, keys).unwrap();
        let event = ready(owner.sign_control(&cap, &request)).unwrap();
        owner.apply_incoming(&[event.as_bytes()]).unwrap();
    }
    assert_eq!(owner.verified(&cap).unwrap().head().position, 5);
    assert_eq!(
        database
            .lock()
            .unwrap()
            .account_state()
            .unwrap()
            .unwrap()
            .head_position,
        5
    );
}

#[test]
fn successor_writes_only_current_summary_and_changed_index_rows() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let old = owner.verified(&cap).unwrap().clone();
    let raw = h.raw();
    raw.execute_batch(
        "CREATE TABLE writes(kind TEXT, size INTEGER);
        CREATE TRIGGER summary_write AFTER UPDATE ON account_projection BEGIN
          INSERT INTO writes VALUES ('summary',length(NEW.summary)); END;
        CREATE TRIGGER device_write AFTER INSERT ON account_devices BEGIN
          INSERT INTO writes VALUES ('device',length(NEW.keys)); END;
        CREATE TRIGGER key_write AFTER INSERT ON account_key_use BEGIN
          INSERT INTO writes VALUES ('key',length(NEW.key)); END;",
    )
    .unwrap();
    for i in 0..300u32 {
        let mut receiver = [9; 1216];
        receiver[..4].copy_from_slice(&i.to_be_bytes());
        let keys = bh_account::DevicePublicKeys::new(
            bh_account::crypto::SigningKey::generate().public(),
            bh_account::crypto::SigningKey::generate().public(),
            receiver,
        )
        .unwrap();
        let request = owner.prepare_add_device(&cap, keys.clone()).unwrap();
        let event = ready(owner.sign_control(&cap, &request)).unwrap();
        raw.execute("DELETE FROM writes", []).unwrap();
        owner.apply_incoming(&[event.as_bytes()]).unwrap();
        let (rows, bytes): (i64, i64) = raw
            .query_row("SELECT count(*),sum(size) FROM writes", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(rows, 5);
        assert!(bytes < 5000, "one addition rewrote {bytes} bytes");
        assert!(!old.seen_device(keys.id()).unwrap());
        assert!(
            owner
                .verified(&cap)
                .unwrap()
                .seen_device(keys.id())
                .unwrap()
        );
    }
}

#[test]
fn captured_history_pages_do_not_follow_later_appends() {
    use bh_account::journal::HistoryCursor;
    let h = Harness::new();
    let setup = complete(&h);
    let journal = h.journal();
    assert!(journal.has_account().unwrap());
    assert!(journal.history_prefix(None, 0).is_err());
    assert!(journal.history_prefix(None, 257).is_err());
    let first = journal.history_prefix(None, 1).unwrap().unwrap();
    assert_eq!(first.events, setup.submission[..1]);
    assert_eq!(first.events[0].len(), 2724);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let request = owner.prepare_remove_self(&cap).unwrap();
    let event = ready(owner.sign_control(&cap, &request)).unwrap();
    owner.apply_incoming(&[event.as_bytes()]).unwrap();
    let page = journal.history_prefix(first.next, 256).unwrap().unwrap();
    assert_eq!(page.cut, setup.head);
    assert_eq!(page.events, setup.submission[1..]);
    assert!(page.next.is_none());
    assert_eq!(page.first_position, 2);
    let cursor = Some(HistoryCursor {
        anchor: setup.anchor,
        cut: setup.head,
        next_position: 1,
    });
    h.raw()
        .execute(
            "UPDATE account_events SET bytes=zeroblob(1000000) WHERE id=2",
            [],
        )
        .unwrap();
    assert!(journal.history_prefix(cursor, 256).is_err());
    h.raw()
        .execute("DELETE FROM account_events WHERE id=2", [])
        .unwrap();
    assert!(journal.history_prefix(cursor, 256).is_err());
}

#[test]
fn evidence_unavailable_preserves_head_generation_and_allows_same_view_retry() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let keys = bh_account::DevicePublicKeys::new([71; 32], [72; 32], [73; 1216]).unwrap();
    let request = owner.prepare_add_device(&cap, keys.clone()).unwrap();
    let event = ready(owner.sign_control(&cap, &request)).unwrap();
    let before = owner.verified(&cap).unwrap().head();
    let generation = h.generation.current();
    h.raw()
        .execute("ALTER TABLE account_key_use RENAME TO hidden_keys", [])
        .unwrap();
    assert!(matches!(
        owner.apply_incoming(&[event.as_bytes()]),
        Err(OwnerError::Invalid(bh_account::Error::Unavailable))
    ));
    assert_eq!(owner.verified(&cap).unwrap().head(), before);
    assert_eq!(h.generation.current(), generation);
    assert!(!h.stored().stopped);
    h.raw()
        .execute("ALTER TABLE hidden_keys RENAME TO account_key_use", [])
        .unwrap();
    owner.apply_incoming(&[event.as_bytes()]).unwrap();
    assert_eq!(owner.verified(&cap).unwrap().head(), event.head());
}

fn append_devices(owner: &mut Owner, cap: &AccountCapability, count: u32) {
    for i in 0..count {
        let mut receiver = [44; 1216];
        receiver[..4].copy_from_slice(&i.to_be_bytes());
        let keys = bh_account::DevicePublicKeys::new(
            bh_account::crypto::SigningKey::generate().public(),
            bh_account::crypto::SigningKey::generate().public(),
            receiver,
        )
        .unwrap();
        let request = owner.prepare_add_device(cap, keys).unwrap();
        let event = ready(owner.sign_control(cap, &request)).unwrap();
        owner.apply_incoming(&[event.as_bytes()]).unwrap();
    }
}

#[test]
fn interrupted_rebuild_resumes_verified_cut_without_rereading_its_prefix() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    append_devices(&mut owner, &cap, 600);
    let expected = owner.verified(&cap).unwrap().head();
    let old_view = owner.verified(&cap).unwrap().clone();
    let raw = h.raw();
    raw.execute("DELETE FROM account_projection", []).unwrap();
    raw.execute_batch(
        "CREATE TRIGGER interrupt_rebuild BEFORE UPDATE ON account_projection
        WHEN NEW.through_position>257 BEGIN SELECT RAISE(FAIL,'interrupted'); END;",
    )
    .unwrap();
    let mut resumed = h.owner();
    assert!(matches!(
        ready(resumed.activate()),
        Err(OwnerError::Journal(_))
    ));
    let (epoch, through): (i64, i64) = raw
        .query_row(
            "SELECT epoch,through_position FROM account_projection",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(through, 257);
    assert!(epoch > 1);
    assert!(matches!(
        old_view.seen_device(bh_account::DeviceId([99; 32])),
        Err(bh_account::Error::Unavailable)
    ));
    assert!(old_view.has_seen_device(bh_account::DeviceId([99; 32])));
    raw.execute_batch("DROP TRIGGER interrupt_rebuild; UPDATE account_events SET bytes=42 WHERE id>=2 AND id<257;").unwrap();
    assert_eq!(activate(&mut resumed).head(), expected);
    assert_eq!(
        raw.query_row("SELECT through_position FROM account_projection", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        603
    );
}

#[test]
fn epoch_cleanup_is_bounded_and_active_corruption_repairs_without_reusing_an_epoch() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    append_devices(&mut owner, &cap, 300);
    let old = owner.verified(&cap).unwrap().clone();
    let raw = h.raw();
    raw.execute_batch("CREATE TABLE reclaimed(kind INTEGER);
        CREATE TRIGGER deleted_device AFTER DELETE ON account_devices BEGIN INSERT INTO reclaimed VALUES(0); END;
        CREATE TRIGGER deleted_key AFTER DELETE ON account_key_use BEGIN INSERT INTO reclaimed VALUES(1); END;
        PRAGMA ignore_check_constraints=ON;
        UPDATE account_devices SET keys=42 WHERE added=4;").unwrap();
    let mut journal = h.journal();
    let first = journal.load_projection().unwrap().unwrap();
    assert_eq!(first.account.head().position, 1);
    assert!(matches!(
        old.seen_device(bh_account::DeviceId([99; 32])),
        Err(bh_account::Error::Unavailable)
    ));
    let epoch: i64 = raw
        .query_row("SELECT epoch FROM account_projection", [], |r| r.get(0))
        .unwrap();
    assert_eq!(epoch, 2);
    for _ in 0..3 {
        raw.execute("DELETE FROM reclaimed", []).unwrap();
        let p = journal.load_projection().unwrap().unwrap();
        let removed: Vec<i64> = raw
            .prepare("SELECT count(*) FROM reclaimed GROUP BY kind")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(removed.iter().all(|n| *n <= 256));
        if p.account.head() == p.target {
            break;
        }
        let page = journal
            .history_prefix(
                Some(bh_account::journal::HistoryCursor {
                    anchor: p.account.id(),
                    cut: p.target,
                    next_position: p.account.head().position + 1,
                }),
                256,
            )
            .unwrap()
            .unwrap();
        assert!(page.events.len() <= 256);
        assert!(page.events.iter().map(Vec::len).sum::<usize>() <= 697344);
        let refs: Vec<_> = page.events.iter().map(Vec::as_slice).collect();
        let candidate = p.account.applied_batch(&refs).unwrap();
        journal.advance_projection(&candidate).unwrap();
    }
    assert_eq!(activate(&mut h.owner()).head().position, 303);
}

#[test]
fn rebuild_extends_a_captured_target_only_with_verified_appends() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    append_devices(&mut owner, &cap, 300);
    let before = owner.verified(&cap).unwrap().head();
    let request = owner
        .prepare_add_device(
            &cap,
            bh_account::DevicePublicKeys::new([77; 32], [78; 32], [79; 1216]).unwrap(),
        )
        .unwrap();
    let extra = ready(owner.sign_control(&cap, &request)).unwrap();
    let expected = extra.head();
    let anchor = cap.account_id();
    let mut once = Some(extra);
    h.raw()
        .execute("DELETE FROM account_projection", [])
        .unwrap();
    let journal = indexed_journal::HookJournal {
        inner: h.journal(),
        pages: Default::default(),
        after_advance: Box::new(move |j| {
            if let Some(event) = once.take() {
                j.commit_verified(anchor, &[event.as_bytes()], event.head(), false)
                    .unwrap();
            }
        }),
    };
    let mut resumed = bh_account::owner::AccountOwner::new(
        journal,
        h.store.clone(),
        PlainProtector,
        h.generation.clone(),
    );
    let AccountLoad::Active(cap) = ready(resumed.activate()).unwrap() else {
        panic!("complete authority required")
    };
    assert_eq!(cap.head(), expected);
    assert_eq!(cap.head().position, before.position + 1);
}

#[test]
fn generation_change_during_rebuild_keeps_progress_but_publishes_no_capability() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    append_devices(&mut owner, &cap, 300);
    h.raw()
        .execute("DELETE FROM account_projection", [])
        .unwrap();
    let generation = h.generation.clone();
    let journal = indexed_journal::HookJournal {
        inner: h.journal(),
        pages: Default::default(),
        after_advance: Box::new(move |_| {
            generation.advance();
        }),
    };
    let mut resumed = bh_account::owner::AccountOwner::new(
        journal,
        h.store.clone(),
        PlainProtector,
        h.generation.clone(),
    );
    assert!(matches!(ready(resumed.activate()), Err(OwnerError::Stale)));
    assert_eq!(
        h.raw()
            .query_row("SELECT through_position FROM account_projection", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        257
    );
    h.raw()
        .execute(
            "UPDATE account_events SET bytes=42 WHERE id>1 AND id<257",
            [],
        )
        .unwrap();
    assert_eq!(activate(&mut h.owner()).head().position, 303);
}

#[test]
fn stale_rebuild_candidate_cannot_commit_after_an_epoch_reset() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    append_devices(&mut owner, &cap, 2);
    h.raw()
        .execute("DELETE FROM account_projection", [])
        .unwrap();
    let mut journal = h.journal();
    let p = journal.load_projection().unwrap().unwrap();
    let page = journal
        .history_prefix(
            Some(bh_account::journal::HistoryCursor {
                anchor: p.account.id(),
                cut: p.target,
                next_position: 2,
            }),
            256,
        )
        .unwrap()
        .unwrap();
    let refs: Vec<_> = page.events.iter().map(Vec::as_slice).collect();
    let candidate = p.account.applied_batch(&refs).unwrap();
    h.raw()
        .execute("UPDATE account_projection SET summary=x'00'", [])
        .unwrap();
    let reset = journal.load_projection().unwrap().unwrap();
    assert_eq!(reset.account.head().position, 1);
    assert!(journal.advance_projection(&candidate).is_err());
    assert_eq!(activate(&mut h.owner()).head().position, 5);
}

#[test]
fn removed_keys_remain_indexed_while_old_views_observe_only_their_cut() {
    use bh_account::crypto::SigningKey;
    use bh_account::{DevicePublicKeys, Error};
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let before = owner.verified(&cap).unwrap().clone();
    let control = SigningKey::generate();
    let keys = DevicePublicKeys::new([80; 32], control.public(), [82; 1216]).unwrap();
    let draft = owner.prepare_add_device(&cap, keys.clone()).unwrap();
    let add = ready(owner.sign_control(&cap, &draft)).unwrap();
    owner.apply_incoming(&[add.as_bytes()]).unwrap();
    let with_child = owner.verified(&cap).unwrap().clone();
    let draft = with_child.remove_self(keys.id()).unwrap();
    let remove = draft.finish(control.sign(draft.signing_bytes())).unwrap();
    owner.apply_incoming(&[remove.as_bytes()]).unwrap();
    assert!(with_child.active_device(keys.id()).is_ok());
    assert!(before.add_device(cap.device_id(), keys.clone()).is_ok());
    assert!(!before.seen_device(keys.id()).unwrap());
    assert!(
        owner
            .verified(&cap)
            .unwrap()
            .seen_device(keys.id())
            .unwrap()
    );
    let mut reopened = h.owner();
    let cap = activate(&mut reopened);
    assert_eq!(
        reopened
            .prepare_add_device(
                &cap,
                DevicePublicKeys::new([83; 32], [84; 32], [82; 1216]).unwrap()
            )
            .err(),
        Some(OwnerError::Invalid(Error::KeyReuse))
    );
    assert_eq!(
        reopened.prepare_add_device(&cap, keys).err(),
        Some(OwnerError::Invalid(Error::DuplicateDevice))
    );
    drop(owner);
    assert_eq!(
        before.seen_device(bh_account::DeviceId([99; 32])),
        Err(Error::Unavailable)
    );
}

#[test]
fn captured_history_refuses_changed_cut_account_and_invalid_cursor() {
    use bh_account::journal::HistoryCursor;
    let h = Harness::new();
    let setup = complete(&h);
    let journal = h.journal();
    let cursor = HistoryCursor {
        anchor: setup.anchor,
        cut: setup.head,
        next_position: 2,
    };
    assert!(
        journal
            .history_prefix(
                Some(HistoryCursor {
                    next_position: 0,
                    ..cursor
                }),
                1
            )
            .is_err()
    );
    assert!(
        journal
            .history_prefix(
                Some(HistoryCursor {
                    next_position: 4,
                    ..cursor
                }),
                1
            )
            .is_err()
    );
    h.raw()
        .execute(
            "UPDATE account_state SET head_hash=?1",
            [[88u8; 32].as_slice()],
        )
        .unwrap();
    assert!(journal.history_prefix(Some(cursor), 1).is_err());
    h.raw()
        .execute(
            "UPDATE account_state SET head_hash=?1",
            [setup.head.hash.as_slice()],
        )
        .unwrap();
    h.raw()
        .execute("UPDATE account_events SET bytes=x'00' WHERE id=3", [])
        .unwrap();
    assert!(journal.history_prefix(Some(cursor), 1).is_err());
    h.raw()
        .execute(
            "UPDATE account_events SET bytes=?1 WHERE id=3",
            [&setup.submission[2]],
        )
        .unwrap();
    h.raw()
        .execute(
            "UPDATE account_state SET anchor=?1",
            [[99u8; 32].as_slice()],
        )
        .unwrap();
    assert!(journal.history_prefix(Some(cursor), 1).is_err());
}

#[test]
fn native_absent_account_does_not_enter_full_history_fallback() {
    let h = Harness::new();
    let journal = indexed_journal::HookJournal {
        inner: h.journal(),
        pages: Default::default(),
        after_advance: Box::new(|_| {}),
    };
    let mut owner = bh_account::owner::AccountOwner::new(
        journal,
        h.store.clone(),
        PlainProtector,
        h.generation.clone(),
    );
    assert!(matches!(
        ready(owner.activate()).unwrap(),
        AccountLoad::Uninitialized
    ));
}

#[test]
fn projection_reopen_does_not_replay_all_history() {
    let h = Harness::new();
    let status = complete(&h);
    assert!(h.journal().load_projection().unwrap().is_some());
    // Corrupt an interior event only after a verified snapshot has committed.
    // Reopening checks signed edges and bounded projection, not the interior log.
    h.raw()
        .execute("UPDATE account_events SET bytes=x'00' WHERE id=2", [])
        .unwrap();
    let mut reopened = h.owner();
    assert!(activate(&mut reopened).account_id() == status.anchor);
}

#[test]
fn wrong_projection_head_falls_back_to_signed_replay() {
    let h = Harness::new();
    complete(&h);
    h.raw()
        .execute(
            "UPDATE account_projection SET through_hash=?1",
            [[21u8; 32].as_slice()],
        )
        .unwrap();
    h.raw()
        .execute("UPDATE account_events SET bytes=x'00' WHERE id=2", [])
        .unwrap();
    let mut owner = h.owner();
    assert!(matches!(
        ready(owner.activate()).unwrap(),
        AccountLoad::AdmissionRequired(AdmissionReason::CorruptHistory)
    ));
}

#[test]
fn shared_journal_uses_the_exact_container_connection_and_poison_is_storage() {
    use std::sync::{Arc, Mutex};
    let db = Arc::new(Mutex::new(
        bh_storage::DeviceDatabase::open(":memory:").unwrap(),
    ));
    let mut journal = DeviceJournal::from_shared(Arc::clone(&db));
    assert!(journal.load().unwrap().is_none());
    let device = bh_account::journal::JournaledDevice {
        handle: bh_account::platform::KeyHandle([7; 32]),
        keys: bh_account::DevicePublicKeys::new([1; 32], [2; 32], [3; 1216]).unwrap(),
        policy: ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        kind: bh_account::platform::DeviceKeyStoreKind::MacLoginKeychainV1,
    };
    journal.commit_device(&device).unwrap();
    assert!(db.lock().unwrap().device_identity().unwrap().is_some());
    assert!(journal.device().unwrap().is_some());
    let poison = Arc::clone(&db);
    assert!(
        std::thread::spawn(move || {
            let _guard = poison.lock().unwrap();
            panic!("poison database guard");
        })
        .join()
        .is_err()
    );
    assert!(matches!(
        journal.load(),
        Err(bh_account::journal::JournalError::Storage)
    ));
    assert!(matches!(
        journal.commit_device(&device),
        Err(bh_account::journal::JournalError::Storage)
    ));
}

#[test]
fn verified_commit_fence_stays_under_guard_even_when_storage_fails() {
    use std::sync::{Arc, Mutex};
    let h = Harness::new();
    let status = complete(&h);
    let db = Arc::new(Mutex::new(
        bh_storage::DeviceDatabase::open(&h.path).unwrap(),
    ));
    let mut journal = DeviceJournal::from_shared(Arc::clone(&db));
    let seen = Arc::clone(&db);
    journal
        .commit_verified_fenced(status.anchor, &[], status.head, false, |success| {
            assert!(success);
            assert!(seen.try_lock().is_err(), "fence must precede guard release");
        })
        .unwrap();
    h.raw().execute_batch("CREATE TRIGGER fail_stop BEFORE UPDATE ON account_state BEGIN SELECT RAISE(FAIL, 'no space'); END;").unwrap();
    assert!(matches!(
        journal.commit_verified_fenced(status.anchor, &[], status.head, true, |success| {
            assert!(!success);
            assert!(
                seen.try_lock().is_err(),
                "failed write must still fence under guard"
            );
        }),
        Err(bh_account::journal::JournalError::Storage)
    ));
}

#[test]
fn poisoned_guard_still_fences_but_reports_storage() {
    use std::sync::{Arc, Mutex, TryLockError};
    let db = Arc::new(Mutex::new(
        bh_storage::DeviceDatabase::open(":memory:").unwrap(),
    ));
    let poisoned = Arc::clone(&db);
    let _ = std::thread::spawn(move || {
        let _guard = poisoned.lock().unwrap();
        panic!("poison database guard");
    })
    .join();
    let mut journal = DeviceJournal::from_shared(Arc::clone(&db));
    let generation = AccountGeneration::new();
    let before = generation.current();
    assert!(matches!(
        journal.fence(|| {
            assert!(matches!(db.try_lock(), Err(TryLockError::WouldBlock)));
            generation.advance();
        }),
        Err(bh_account::journal::JournalError::Storage)
    ));
    assert_ne!(before, generation.current());
    let before = generation.current();
    assert!(matches!(
        journal.commit_verified_fenced(
            bh_account::AccountId([4; 32]),
            &[],
            Head {
                position: 1,
                hash: [5; 32]
            },
            true,
            |success| {
                assert!(!success);
                assert!(matches!(db.try_lock(), Err(TryLockError::WouldBlock)));
                generation.advance();
            }
        ),
        Err(bh_account::journal::JournalError::Storage)
    ));
    assert_ne!(before, generation.current());
}

#[test]
fn writer_guard_orders_capability_check_and_lock_in_both_directions() {
    use std::sync::{Arc, Mutex, mpsc};
    let h = Harness::new();
    complete(&h);
    let db = Arc::new(Mutex::new(
        bh_storage::DeviceDatabase::open(&h.path).unwrap(),
    ));
    let mut owner = Owner::new(
        DeviceJournal::from_shared(Arc::clone(&db)),
        h.store.clone(),
        PlainProtector,
        h.generation.clone(),
    );
    let capability = activate(&mut owner);
    assert!(capability.is_current());
    let checked = Arc::clone(&db);
    DeviceJournal::from_shared(Arc::clone(&db))
        .fence(|| {
            assert!(
                checked.try_lock().is_err(),
                "generation advance must hold writer guard"
            )
        })
        .unwrap();
    let guard = db.lock().unwrap();
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let thread_db = Arc::clone(&db);
    let generation = h.generation.clone();
    let task = std::thread::spawn(move || {
        let store = FakeStore::new(generation.clone());
        let mut other_owner = Owner::new(
            DeviceJournal::from_shared(thread_db),
            store,
            PlainProtector,
            generation,
        );
        started_tx.send(()).unwrap();
        other_owner.lock().unwrap();
        finished_tx.send(()).unwrap();
    });
    started_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    assert!(
        capability.is_current(),
        "writer can commit while holding the guard"
    );
    assert!(
        finished_rx
            .recv_timeout(std::time::Duration::from_millis(50))
            .is_err(),
        "lock must wait for writer"
    );
    drop(guard);
    finished_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap();
    task.join().unwrap();
    let _guard = db.lock().unwrap();
    assert!(
        !capability.is_current(),
        "writer starting after lock observes revocation"
    );
}

#[test]
fn verified_removal_and_failed_writes_fence_with_the_shared_guard() {
    use std::sync::{Arc, Mutex};
    let h = Harness::new();
    complete(&h);
    let db = Arc::new(Mutex::new(
        bh_storage::DeviceDatabase::open(&h.path).unwrap(),
    ));
    let mut owner = Owner::new(
        DeviceJournal::from_shared(Arc::clone(&db)),
        h.store.clone(),
        PlainProtector,
        h.generation.clone(),
    );
    let capability = activate(&mut owner);
    let request = owner.prepare_remove_self(&capability).unwrap();
    let event = ready(owner.sign_control(&capability, &request)).unwrap();
    owner.apply_incoming(&[event.as_bytes()]).unwrap();
    let _guard = db.lock().unwrap();
    assert!(!capability.is_current());
    drop(_guard);

    // A failed durable verified commit must invalidate a previously minted writer.
    let h = Harness::new();
    complete(&h);
    let db = Arc::new(Mutex::new(
        bh_storage::DeviceDatabase::open(&h.path).unwrap(),
    ));
    let mut owner = Owner::new(
        DeviceJournal::from_shared(Arc::clone(&db)),
        h.store.clone(),
        PlainProtector,
        h.generation.clone(),
    );
    let capability = activate(&mut owner);
    h.raw().execute_batch("CREATE TRIGGER fail_event BEFORE INSERT ON account_events BEGIN SELECT RAISE(FAIL, 'no space'); END;").unwrap();
    let request = owner
        .prepare_add_device(
            &capability,
            bh_account::DevicePublicKeys::new([9; 32], [10; 32], [11; 1216]).unwrap(),
        )
        .unwrap();
    let event = ready(owner.sign_control(&capability, &request)).unwrap();
    assert!(matches!(
        owner.apply_incoming(&[event.as_bytes()]),
        Err(OwnerError::Journal(_))
    ));
    assert!(!capability.is_current());
}

/// One temp database path plus shared native-key state across "restarts".
struct Harness {
    dir: tempfile::TempDir,
    path: PathBuf,
    generation: AccountGeneration,
    store: FakeStore,
}

impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("account.sqlite");
        let generation = AccountGeneration::new();
        let store = FakeStore::new(generation.clone());
        Self {
            dir,
            path,
            generation,
            store,
        }
    }

    fn owner(&self) -> Owner {
        let journal = DeviceJournal::open(&self.path).expect("open device journal");
        bh_account::owner::AccountOwner::new(
            journal,
            self.store.clone(),
            PlainProtector,
            self.generation.clone(),
        )
    }

    fn journal(&self) -> DeviceJournal {
        DeviceJournal::open(&self.path).expect("open device journal")
    }

    fn raw(&self) -> Connection {
        Connection::open(&self.path).unwrap()
    }

    fn stored(&self) -> JournaledAccount {
        self.journal().load().unwrap().expect("journaled account")
    }
}

#[test]
fn qr_proof_for_another_account_cannot_prepare_this_owners_admission() {
    use bh_account::crypto::{KemKey, SigningKey};
    use bh_account::pairing::{PairError, Reply, ShowingSession, verify_showing};
    let a = Harness::new();
    let a_setup = complete(&a);
    let a_journal = a.stored();
    let b = Harness::new();
    let b_setup = complete(&b);
    let mut b_owner = b.owner();
    let b_capability = activate(&mut b_owner);
    let a_showing = a.journal().device().unwrap().unwrap().keys;
    let session = ShowingSession::new(a_setup.anchor, a_showing.id());
    let qr = session.qr().unwrap();
    let original: Vec<&[u8]> = a_journal.history.iter().map(Vec::as_slice).collect();
    assert!(verify_showing(&qr, &original, a_journal.head).unwrap() == a_showing);
    let scanner = bh_account::DevicePublicKeys::new(
        SigningKey::generate().public(),
        SigningKey::generate().public(),
        KemKey::generate().public(),
    )
    .unwrap();
    session
        .receive(&Reply::make(&qr, scanner, b"Fold").unwrap())
        .unwrap();
    let before_signs = b.store.state().sign_calls;
    assert_eq!(
        session.prepare(&b_owner, &b_capability).err(),
        Some(PairError::WrongContext)
    );
    assert_eq!(
        b.store.state().sign_calls,
        before_signs,
        "never asked B's key to sign"
    );
    assert_eq!(b.stored().head, b_setup.head, "nothing admitted in B");
    assert_eq!(
        session.stage(b"unsigned", b"seal", |_, _| Ok::<_, ()>(())),
        Err(PairError::NoReply)
    );
}

#[test]
fn qr_for_another_active_showing_device_cannot_prepare_local_owners_admission() {
    use bh_account::crypto::{KemKey, SigningKey};
    use bh_account::pairing::{PairError, Reply, ShowingSession, verify_showing};
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    let other = bh_account::DevicePublicKeys::new(
        SigningKey::generate().public(),
        SigningKey::generate().public(),
        KemKey::generate().public(),
    )
    .unwrap();
    let add = owner
        .prepare_add_device(&capability, other.clone())
        .unwrap();
    let signed = ready(owner.sign_control(&capability, &add)).unwrap();
    owner.apply_incoming(&[signed.as_bytes()]).unwrap();
    let stored = h.stored();
    let original: Vec<&[u8]> = stored.history.iter().map(Vec::as_slice).collect();
    let session = ShowingSession::new(stored.anchor, other.id());
    let qr = session.qr().unwrap();
    assert!(verify_showing(&qr, &original, stored.head).unwrap() == other);
    let scanner = bh_account::DevicePublicKeys::new(
        SigningKey::generate().public(),
        SigningKey::generate().public(),
        KemKey::generate().public(),
    )
    .unwrap();
    session
        .receive(&Reply::make(&qr, scanner, b"Fold").unwrap())
        .unwrap();
    let before_signs = h.store.state().sign_calls;
    assert_eq!(
        session.prepare(&owner, &capability).err(),
        Some(PairError::WrongContext)
    );
    assert_eq!(h.store.state().sign_calls, before_signs);
    assert_eq!(h.stored().head, stored.head, "no second admission");
    assert_eq!(
        session.stage(b"unsigned", b"seal", |_, _| Ok::<_, ()>(())),
        Err(PairError::NoReply)
    );
}

#[test]
fn showing_owner_signs_add_and_seals_current_personal_before_any_ordering() {
    use bh_account::crypto::{KemKey, SigningKey};
    use bh_account::pairing::{Reply, ShowingSession};
    let h = Harness::new();
    let mut owner = h.owner();
    let status = begin(&mut owner);
    let initial_seal = owner.pending_home_objects().unwrap().device_seal;
    owner.confirm_home_ordered(status.head).unwrap();
    owner.confirm_kit_saved().unwrap();
    let state = bh_account::VerifiedAccount::replay(
        status.anchor,
        &status
            .submission
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>(),
        status.head,
    )
    .unwrap();
    let native = h.journal().device().unwrap().unwrap();
    let first = bh_account::platform::StoredDevice {
        handle: native.handle,
        keys: native.keys,
        policy: native.policy,
        kind: native.kind,
    };
    let personal = ready(bh_account::personal::open_for_receiver(
        &state,
        &initial_seal,
        &first,
        &mut h.store.clone(),
    ))
    .unwrap();
    let capability = activate(&mut owner);
    let session = ShowingSession::new(status.anchor, first.keys.id());
    let scanner = bh_account::DevicePublicKeys::new(
        SigningKey::generate().public(),
        SigningKey::generate().public(),
        KemKey::generate().public(),
    )
    .unwrap();
    session
        .receive(&Reply::make(&session.qr().unwrap(), scanner.clone(), b"Fold").unwrap())
        .unwrap();
    let request = session.prepare(&owner, &capability).unwrap();
    let admission = ready(owner.sign_control(&capability, &request)).unwrap();
    let delivery =
        ready(owner.seal_personal_for_device(&capability, &personal, &scanner, &admission))
            .unwrap();
    assert_eq!(delivery.len(), 1403);
    let mut staged = None;
    session
        .stage(admission.as_bytes(), &delivery, |add, seal| {
            staged = Some((add.to_vec(), seal.to_vec()));
            Ok::<_, ()>(())
        })
        .unwrap();
    assert_eq!(staged.unwrap(), (admission.as_bytes().to_vec(), delivery));
    assert_eq!(
        h.stored().head,
        status.head,
        "neither callback nor signatures order an admission"
    );
}

#[test]
fn pairing_approval_uses_the_real_owner_and_cancellation_fences_late_native_signature() {
    use bh_account::crypto::{KemKey, SigningKey};
    use bh_account::pairing::{PairError, Reply, ShowingSession};
    let h = Harness::new();
    let status = complete(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    let stored = h.journal().device().unwrap().unwrap();
    let session = ShowingSession::new(status.anchor, stored.keys.id());
    let scanner = bh_account::DevicePublicKeys::new(
        SigningKey::generate().public(),
        SigningKey::generate().public(),
        KemKey::generate().public(),
    )
    .unwrap();
    session
        .receive(&Reply::make(&session.qr().unwrap(), scanner.clone(), b"Fold").unwrap())
        .unwrap();
    let request = session.prepare(&owner, &capability).unwrap();
    let event = ready(owner.sign_control(&capability, &request)).unwrap();
    let mut forged = event.as_bytes().to_vec();
    let last = forged.len() - 1;
    forged[last] ^= 1;
    assert_eq!(
        session.stage(&forged, b"fixture seal", |_, _| Ok::<_, ()>(())),
        Err(PairError::ChangedRequest)
    );
    assert_eq!(
        session.stage(event.as_bytes(), b"fixture seal", |_, _| Err::<(), _>(())),
        Err(PairError::StageFailed),
        "a failed durable stage leaves the session live for retry"
    );
    let mut captured = Vec::new();
    session
        .stage(event.as_bytes(), b"fixture seal", |add, seal| {
            captured = [add, seal].concat();
            Ok::<_, ()>(())
        })
        .unwrap();
    assert!(captured.starts_with(event.as_bytes()));
    assert_eq!(h.stored().head, status.head, "only staging, not ordering");
    assert_eq!(
        session.stage(event.as_bytes(), b"fixture seal", |_, _| Ok::<_, ()>(())),
        Err(PairError::Ended)
    );

    let session = ShowingSession::new(status.anchor, stored.keys.id());
    session
        .receive(&Reply::make(&session.qr().unwrap(), scanner, b"Fold").unwrap())
        .unwrap();
    let request = session.prepare(&owner, &capability).unwrap();
    let generation = h.generation.current();
    session.cancel();
    let late = ready(owner.sign_control(&capability, &request)).unwrap();
    assert_eq!(
        generation,
        h.generation.current(),
        "cancel is not account-wide lock"
    );
    assert_eq!(
        session.stage(late.as_bytes(), b"seal", |_, _| Ok::<_, ()>(())),
        Err(PairError::Ended)
    );
}

fn stage_pairing(h: &Harness) -> (Vec<u8>, Vec<u8>, bh_account::DevicePublicKeys) {
    use bh_account::{
        crypto::{KemKey, SigningKey},
        pairing::{Reply, ShowingSession},
    };
    let mut owner = h.owner();
    let setup = begin(&mut owner);
    let seal = owner.pending_home_objects().unwrap().device_seal;
    owner.confirm_home_ordered(setup.head).unwrap();
    owner.confirm_kit_saved().unwrap();
    let native = h.journal().device().unwrap().unwrap();
    let state = bh_account::VerifiedAccount::replay(
        setup.anchor,
        &setup
            .submission
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>(),
        setup.head,
    )
    .unwrap();
    let personal = ready(bh_account::personal::open_for_receiver(
        &state,
        &seal,
        &bh_account::platform::StoredDevice {
            handle: native.handle,
            keys: native.keys.clone(),
            policy: native.policy,
            kind: native.kind,
        },
        &mut h.store.clone(),
    ))
    .unwrap();
    let capability = activate(&mut owner);
    let session = ShowingSession::new(setup.anchor, native.keys.id());
    let scanner = bh_account::DevicePublicKeys::new(
        SigningKey::generate().public(),
        SigningKey::generate().public(),
        KemKey::generate().public(),
    )
    .unwrap();
    session
        .receive(&Reply::make(&session.qr().unwrap(), scanner.clone(), b"Fold").unwrap())
        .unwrap();
    let request = session.prepare(&owner, &capability).unwrap();
    let signed = ready(owner.sign_control(&capability, &request)).unwrap();
    let delivery =
        ready(owner.seal_personal_for_device(&capability, &personal, &scanner, &signed)).unwrap();
    session
        .stage_journal(&mut owner, &capability, signed.as_bytes(), &delivery)
        .unwrap();
    session.cancel(); // cancellation after staging cannot discard the durable row
    (signed.as_bytes().to_vec(), delivery, scanner)
}

#[test]
fn staged_admission_restarts_and_retries_exact_bytes_without_a_second_signature() {
    use bh_account::owner::AdmissionResolution;
    let h = Harness::new();
    let (event, delivery, _) = stage_pairing(&h);
    let before_signs = h.store.state().sign_calls;
    let row = h.journal().staged_admission().unwrap().unwrap();
    assert_eq!(row.event, event);
    assert_eq!(row.delivery, delivery);
    let mut owner = h.owner(); // actual SQLite close/reopen between staging and send
    activate(&mut owner);
    assert_eq!(
        owner.reconcile_staged_admission(None).unwrap(),
        AdmissionResolution::Checking {
            event: event.clone()
        }
    );
    assert_eq!(
        owner.reconcile_staged_admission(Some(&[])).unwrap(),
        AdmissionResolution::Checking {
            event: event.clone()
        }
    );
    assert_eq!(h.store.state().sign_calls, before_signs);
    assert_eq!(
        h.journal().staged_admission().unwrap().unwrap().event,
        event
    );
    assert_eq!(
        owner
            .reconcile_staged_admission(Some(&[event.as_slice()]))
            .unwrap(),
        AdmissionResolution::Admitted { delivery }
    );
    assert!(h.journal().staged_admission().unwrap().is_none());
    assert_eq!(
        h.stored().head,
        AccountEvent::decode(&event).unwrap().head()
    );
    assert_eq!(h.store.state().sign_calls, before_signs);
}

#[test]
fn different_verified_successor_is_not_added_and_clears_row() {
    use bh_account::owner::AdmissionResolution;
    let h = Harness::new();
    let (event, _, _) = stage_pairing(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    let request = owner.prepare_remove_self(&capability).unwrap();
    let other = ready(owner.sign_control(&capability, &request)).unwrap();
    assert_ne!(other.as_bytes(), event);
    assert_eq!(
        owner
            .reconcile_staged_admission(Some(&[other.as_bytes()]))
            .unwrap(),
        AdmissionResolution::NotAdded
    );
    assert_eq!(h.stored().head, other.head());
    assert!(h.journal().staged_admission().unwrap().is_none());
}

#[test]
fn reconcile_keeps_exact_row_when_verified_history_commit_fails() {
    use bh_account::owner::AdmissionResolution;
    for admitted in [true, false] {
        let h = Harness::new();
        let (event, delivery, _) = stage_pairing(&h);
        let original = h.journal().staged_admission().unwrap();
        let before = h.stored();
        let mut owner = h.owner();
        let capability = activate(&mut owner);
        let successor = if admitted {
            event
        } else {
            let request = owner.prepare_remove_self(&capability).unwrap();
            ready(owner.sign_control(&capability, &request))
                .unwrap()
                .as_bytes()
                .to_vec()
        };
        h.raw()
            .execute_batch("CREATE TRIGGER fail_history BEFORE INSERT ON account_events BEGIN SELECT RAISE(ABORT, 'injected write failure'); END;")
            .unwrap();
        assert!(matches!(
            owner.reconcile_staged_admission(Some(&[successor.as_slice()])),
            Err(OwnerError::Journal(
                bh_account::journal::JournalError::Storage
            ))
        ));
        assert!(
            matches!(
                owner.reconcile_staged_admission(Some(&[successor.as_slice()])),
                Err(OwnerError::Stopped)
            ),
            "the same owner cannot release a delivery from its uncommitted projection"
        );
        assert!(matches!(
            owner.prepare_remove_self(&capability),
            Err(OwnerError::Stopped)
        ));
        assert_eq!(h.journal().staged_admission().unwrap(), original);
        drop(owner);

        // Open again with the refusal still installed: neither event nor head
        // nor staged bytes may have been retired by the failed transaction.
        let mut resumed = h.owner();
        activate(&mut resumed);
        let reopened = h.stored();
        assert_eq!(reopened.head, before.head);
        assert_eq!(reopened.history, before.history);
        assert_eq!(h.journal().staged_admission().unwrap(), original);

        h.raw().execute_batch("DROP TRIGGER fail_history").unwrap();
        assert_eq!(
            resumed
                .reconcile_staged_admission(Some(&[successor.as_slice()]))
                .unwrap(),
            if admitted {
                AdmissionResolution::Admitted { delivery }
            } else {
                AdmissionResolution::NotAdded
            }
        );
        assert_eq!(
            h.stored().head,
            AccountEvent::decode(&successor).unwrap().head()
        );
        assert_eq!(h.stored().history.len(), before.history.len() + 1);
        assert!(h.journal().staged_admission().unwrap().is_none());
    }
}

#[test]
fn reconcile_keeps_exact_row_on_forged_successor() {
    let h = Harness::new();
    let (mut event, _, _) = stage_pairing(&h);
    let original = h.journal().staged_admission().unwrap();
    let before = h.stored();
    let mut owner = h.owner();
    activate(&mut owner);
    *event.last_mut().unwrap() ^= 1;
    // Unauthenticated bytes are refused without a stop.
    assert!(matches!(
        owner.reconcile_staged_admission(Some(&[event.as_slice()])),
        Err(OwnerError::Refused(bh_account::Error::BadSignature))
    ));
    assert!(!h.stored().stopped);
    assert_eq!(h.stored().head, before.head);
    assert_eq!(h.stored().history, before.history);
    assert_eq!(h.journal().staged_admission().unwrap(), original);
}

#[test]
fn interrupted_clear_is_reconciled_after_restart_from_durable_history() {
    use bh_account::owner::AdmissionResolution;
    for admitted in [true, false] {
        let h = Harness::new();
        let (event, delivery, _) = stage_pairing(&h);
        let mut owner = h.owner();
        let capability = activate(&mut owner);
        let outcome = if admitted {
            event.clone()
        } else {
            let request = owner.prepare_remove_self(&capability).unwrap();
            ready(owner.sign_control(&capability, &request))
                .unwrap()
                .as_bytes()
                .to_vec()
        };
        owner.apply_incoming(&[outcome.as_slice()]).unwrap(); // crash before clear
        assert!(h.journal().staged_admission().unwrap().is_some());
        drop(owner);
        let mut resumed = h.owner();
        let _ = ready(resumed.activate()).unwrap();
        assert_eq!(
            resumed
                .reconcile_staged_admission(Some(&[outcome.as_slice()]))
                .unwrap(),
            if admitted {
                AdmissionResolution::Admitted { delivery }
            } else {
                AdmissionResolution::NotAdded
            }
        );
        assert!(h.journal().staged_admission().unwrap().is_none());
    }
}

#[test]
fn scanner_status_uses_verified_sqlite_facts_not_relay_hints() {
    use bh_account::pairing::{ScannerStatus, scanner_identity, scanner_status};
    let showing = Harness::new();
    let setup = complete(&showing);
    let mut scanner = Harness::new();
    let mut journal = scanner.journal();
    let identity = ready(scanner_identity(
        &mut journal,
        &mut scanner.store,
        ControlKeyPolicy::AppEnforcedOwnerConfirmation,
    ))
    .unwrap();
    assert_eq!(scanner_status(&journal).unwrap(), ScannerStatus::Pending);
    let showing_record = showing.stored();
    let original: Vec<&[u8]> = showing_record.history.iter().map(Vec::as_slice).collect();
    journal
        .commit_verified(setup.anchor, &original, setup.head, false)
        .unwrap();
    assert_eq!(
        scanner_status(&journal),
        Err(bh_account::pairing::PairError::Unavailable)
    );
    let partial = journal.load_projection().unwrap().unwrap();
    let checked = partial.account.applied_batch(&original[1..]).unwrap();
    journal.advance_projection(&checked).unwrap();
    assert_eq!(scanner_status(&journal).unwrap(), ScannerStatus::Pending);
    let mut owner = showing.owner();
    let capability = activate(&mut owner);
    let request = owner
        .prepare_add_device(&capability, identity.keys.clone())
        .unwrap();
    let event = ready(owner.sign_control(&capability, &request)).unwrap();
    journal
        .commit_verified(setup.anchor, &[event.as_bytes()], event.head(), false)
        .unwrap();
    assert_eq!(
        scanner_status(&journal),
        Err(bh_account::pairing::PairError::Unavailable)
    );
    let partial = journal.load_projection().unwrap().unwrap();
    let checked = partial.account.applied_batch(&[event.as_bytes()]).unwrap();
    journal.advance_projection(&checked).unwrap();
    drop(journal);
    let journal = scanner.journal();
    assert_eq!(
        scanner_status(&journal).unwrap(),
        ScannerStatus::ReadyForDelivery
    );
    drop(journal);
    let mut journal = scanner.journal();
    assert!(matches!(
        ready(scanner_identity(
            &mut journal,
            &mut scanner.store,
            ControlKeyPolicy::AppEnforcedOwnerConfirmation
        )),
        Err(bh_account::pairing::PairError::AlreadyAdded)
    ));
    assert_eq!(scanner.store.state().create_calls, 1);
    assert_eq!(
        showing.stored().head,
        setup.head,
        "only scanner journal received the verified add"
    );
}

#[test]
fn later_scan_of_an_already_admitted_identity_never_signs_again() {
    use bh_account::pairing::{PairError, Reply, ShowingSession};
    let h = Harness::new();
    let (event, _, scanner) = stage_pairing(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    assert!(matches!(
        owner.prepare_add_device(&capability, scanner.clone()),
        Err(OwnerError::Journal(
            bh_account::journal::JournalError::StagedAdmissionExists
        ))
    ));
    owner.apply_incoming(&[event.as_slice()]).unwrap();
    owner.reconcile_staged_admission(None).unwrap();
    let next = ShowingSession::new(h.stored().anchor, capability.device_id());
    next.receive(&Reply::make(&next.qr().unwrap(), scanner, b"Fold").unwrap())
        .unwrap();
    let before = h.store.state().sign_calls;
    assert!(matches!(
        next.prepare(&owner, &capability),
        Err(PairError::AlreadyAdded)
    ));
    assert_eq!(h.store.state().sign_calls, before);
}

fn password() -> Password {
    Password::new("correct horse battery staple").unwrap()
}

fn begin(owner: &mut Owner) -> SetupStatus {
    ready(owner.begin_first_device(ControlKeyPolicy::AppEnforcedOwnerConfirmation, &password()))
        .expect("first device setup")
}

/// A complete, kit-saved first device, returned at rest.
fn complete(h: &Harness) -> SetupStatus {
    let mut owner = h.owner();
    let status = begin(&mut owner);
    owner
        .confirm_home_ordered(status.head)
        .expect("home ordered");
    owner.confirm_kit_saved().expect("kit saved");
    status
}

fn activate(owner: &mut Owner) -> AccountCapability {
    match ready(owner.activate()).expect("journal load") {
        AccountLoad::Active(capability) => capability,
        other => panic!("expected active account, got {other:?}"),
    }
}

#[test]
fn setup_resumes_at_each_stage_without_duplicate_genesis() {
    let h = Harness::new();
    let mut owner = h.owner();
    assert!(matches!(
        ready(owner.activate()).unwrap(),
        AccountLoad::Uninitialized
    ));

    let status = begin(&mut owner);
    assert_eq!(status.stage, SetupStage::Prepared);
    assert!(!status.kit_saved);
    assert_eq!(status.submission.len(), 3, "genesis + record + publication");
    let genesis = status.submission[0].clone();
    let code = owner.pending_kit_code().expect("pending code");
    assert!(
        h.journal().load().unwrap().is_none(),
        "not yet home-ordered"
    );
    assert_eq!(h.store.state().create_calls, 1);

    // Restart at Prepared: exact genesis and code survive, nothing regenerates.
    drop(owner);
    let mut owner = h.owner();
    let resumed = owner.setup_status().expect("resume").expect("setup");
    assert_eq!(resumed.stage, SetupStage::Prepared);
    assert_eq!(resumed.submission[0], genesis);
    assert!(resumed.anchor == status.anchor);
    assert_eq!(owner.pending_kit_code().unwrap().expose(), code.expose());
    assert_eq!(h.store.state().create_calls, 1, "no second genesis");

    // A retry while setup is pending must not start over.
    assert!(matches!(
        ready(
            owner.begin_first_device(ControlKeyPolicy::AppEnforcedOwnerConfirmation, &password())
        ),
        Err(SetupError::AlreadyStarted)
    ));
    assert_eq!(h.store.state().create_calls, 1);

    // Restart at HomePending, then confirm the exact head.
    owner.mark_home_pending().expect("submitted");
    drop(owner);
    let mut owner = h.owner();
    assert_eq!(
        owner.setup_status().unwrap().unwrap().stage,
        SetupStage::HomePending
    );
    assert!(h.journal().load().unwrap().is_none());
    owner
        .confirm_home_ordered(status.head)
        .expect("home ordered");
    assert_eq!(h.stored().head, status.head);

    // Restart, then finish only on explicit save confirmation.
    drop(owner);
    let mut owner = h.owner();
    assert!(owner.setup_status().unwrap().is_some(), "kit not saved yet");
    owner.confirm_kit_saved().expect("kit saved");
    drop(owner);
    let mut owner = h.owner();
    assert!(owner.setup_status().unwrap().is_none());
    assert!(h.journal().pending_setup().unwrap().is_none());
    assert!(
        h.journal().load().unwrap().is_some(),
        "account survives setup"
    );
    let capability = activate(&mut owner);
    assert!(capability.account_id() == status.anchor);
}

#[test]
fn home_order_is_idempotent_over_real_storage() {
    let h = Harness::new();
    let mut owner = h.owner();
    let status = begin(&mut owner);
    owner.mark_home_pending().unwrap();
    owner
        .confirm_home_ordered(status.head)
        .expect("home ordered");
    // A resumed/retried confirmation must not append the same bytes twice.
    owner
        .confirm_home_ordered(status.head)
        .expect("idempotent retry");
    let stored = h.stored();
    assert_eq!(stored.history.len(), 3, "no duplicate events");
    assert_eq!(stored.head, status.head);
}

#[test]
fn kit_saved_before_ordering_survives_restart_and_deletes_after_ordering() {
    let h = Harness::new();
    let mut owner = h.owner();
    let status = begin(&mut owner);
    let code = owner.pending_kit_code().unwrap().expose().to_owned();
    let objects_before = owner.pending_home_objects().unwrap();

    // The person confirms the kit while no production home exists. The
    // account becomes locally usable without keeping the recoverable code.
    owner
        .confirm_kit_saved()
        .expect("confirmed before ordering");
    let resumed = owner.setup_status().unwrap().unwrap();
    assert!(resumed.kit_saved);
    assert_eq!(h.stored().head, status.head);
    assert!(matches!(
        owner.pending_kit_code(),
        Err(SetupError::NotStarted)
    ));
    let pending = h.journal().pending_setup().unwrap().unwrap();
    assert!(
        !pending.blob.windows(code.len()).any(|bytes| bytes == code),
        "kit code must not survive in the protected pending material"
    );
    let objects_after = owner.pending_home_objects().unwrap();
    assert_eq!(objects_before.record, objects_after.record);
    assert_eq!(objects_before.device_seal, objects_after.device_seal);
    assert_eq!(objects_before.recovery_seal, objects_after.recovery_seal);
    assert!(activate(&mut owner).account_id() == status.anchor);
    assert_ne!(code, [0; 16]);

    // The confirmation survives a restart, and ordering then deletes the blob.
    drop(owner);
    let mut owner = h.owner();
    assert!(owner.setup_status().unwrap().unwrap().kit_saved);
    assert!(matches!(
        owner.pending_kit_code(),
        Err(SetupError::NotStarted)
    ));
    owner
        .confirm_home_ordered(status.head)
        .expect("home ordered");
    assert!(owner.setup_status().unwrap().is_none());
    assert!(h.journal().pending_setup().unwrap().is_none());
    assert!(matches!(
        owner.pending_kit_code(),
        Err(SetupError::NotStarted)
    ));
    assert!(h.journal().load().unwrap().is_some());
}

#[test]
fn saved_kit_makes_old_sqlite_backup_unopenable_even_if_it_kept_the_original_blob() {
    use bh_account::journal::PendingSetupProtector;
    let h = Harness::new();
    let protector = protector::RotatingProtector::default();
    let mut owner = bh_account::owner::AccountOwner::new(
        h.journal(),
        h.store.clone(),
        protector.clone(),
        h.generation.clone(),
    );
    let status = ready(
        owner.begin_first_device(ControlKeyPolicy::AppEnforcedOwnerConfirmation, &password()),
    )
    .unwrap();
    let backup = h.dir.path().join("before-kit-save.sqlite");
    h.raw()
        .execute("VACUUM INTO ?1", [backup.to_str().unwrap()])
        .unwrap();
    let old = DeviceJournal::open(&backup)
        .unwrap()
        .pending_setup()
        .unwrap()
        .unwrap();
    assert!(
        protector.clone().open(&old.blob).is_ok(),
        "backup was readable before save"
    );
    owner.confirm_kit_saved().unwrap();
    assert!(
        matches!(
            protector.clone().open(&old.blob),
            Err(bh_account::journal::ProtectorError::Unavailable)
        ),
        "old WAL or backup ciphertext must not remain decryptable with retained Keychain keys"
    );
    assert!(matches!(
        owner.pending_kit_code(),
        Err(SetupError::NotStarted)
    ));
    assert_eq!(h.stored().head, status.head);
    drop(owner);
    let mut resumed = bh_account::owner::AccountOwner::new(
        h.journal(),
        h.store.clone(),
        protector,
        h.generation.clone(),
    );
    assert!(resumed.setup_status().unwrap().unwrap().kit_saved);
    match ready(resumed.activate()).unwrap() {
        AccountLoad::Active(capability) => assert!(capability.account_id() == status.anchor),
        other => panic!("expected active account, got {other:?}"),
    }
}

#[test]
fn home_ack_retries_retirement_before_clearing_its_only_reference() {
    use bh_account::journal::PendingSetupProtector;
    let h = Harness::new();
    let protector = protector::RotatingProtector::default();
    let mut owner = bh_account::owner::AccountOwner::new(
        h.journal(),
        h.store.clone(),
        protector.clone(),
        h.generation.clone(),
    );
    let status = ready(
        owner.begin_first_device(ControlKeyPolicy::AppEnforcedOwnerConfirmation, &password()),
    )
    .unwrap();
    let old = h.journal().pending_setup().unwrap().unwrap();
    protector.fail_next_retirement();
    assert!(owner.confirm_kit_saved().is_err());
    protector.fail_next_retirement();
    assert!(owner.confirm_home_ordered(status.head).is_err());
    assert!(h.journal().pending_setup().unwrap().is_some());
    assert!(protector.clone().open(&old.blob).is_ok());
    owner.confirm_home_ordered(status.head).unwrap();
    assert!(h.journal().pending_setup().unwrap().is_none());
    assert!(protector.clone().open(&old.blob).is_err());
    assert_eq!(h.stored().history, status.submission);
}

#[test]
fn restart_after_no_code_commit_retires_lingering_old_key_before_activation() {
    use bh_account::journal::PendingSetupProtector;
    let h = Harness::new();
    let protector = protector::RotatingProtector::default();
    let mut owner = bh_account::owner::AccountOwner::new(
        h.journal(),
        h.store.clone(),
        protector.clone(),
        h.generation.clone(),
    );
    let _ = ready(
        owner.begin_first_device(ControlKeyPolicy::AppEnforcedOwnerConfirmation, &password()),
    )
    .unwrap();
    let backup = h.dir.path().join("old-code-backup.sqlite");
    h.raw()
        .execute("VACUUM INTO ?1", [backup.to_str().unwrap()])
        .unwrap();
    let old = DeviceJournal::open(&backup)
        .unwrap()
        .pending_setup()
        .unwrap()
        .unwrap();
    protector.fail_next_retirement();
    assert!(matches!(
        owner.confirm_kit_saved(),
        Err(SetupError::Protector(_))
    ));
    let saved = h.journal().pending_setup().unwrap().unwrap();
    assert!(
        saved.kit_saved,
        "no-code replacement must commit before deleting old key"
    );
    assert!(
        protector.clone().open(&old.blob).is_ok(),
        "injected deletion failure retains old key"
    );
    drop(owner);
    let mut owner = bh_account::owner::AccountOwner::new(
        h.journal(),
        h.store.clone(),
        protector.clone(),
        h.generation.clone(),
    );
    // Reading status has no hidden Keychain deletion. Activation explicitly
    // retires the key before granting any capability, including after a crash.
    assert!(owner.setup_status().unwrap().unwrap().kit_saved);
    assert!(protector.clone().open(&old.blob).is_ok());
    protector.fail_next_retirement();
    assert!(matches!(
        ready(owner.activate()),
        Err(bh_account::owner::OwnerError::Protector(_))
    ));
    assert!(protector.clone().open(&old.blob).is_ok());
    assert!(matches!(
        ready(owner.activate()).unwrap(),
        AccountLoad::Uninitialized
    ));
    assert!(matches!(
        protector.clone().open(&old.blob),
        Err(bh_account::journal::ProtectorError::Unavailable)
    ));
    owner.confirm_kit_saved().unwrap();
    assert!(matches!(
        ready(owner.activate()).unwrap(),
        AccountLoad::Active(_)
    ));
}

#[test]
fn failed_local_commit_after_kit_confirmation_resumes_without_code_or_new_account() {
    let h = Harness::new();
    let mut owner = h.owner();
    let status = begin(&mut owner);
    let code = owner.pending_kit_code().unwrap().expose().to_owned();
    h.raw().execute_batch("CREATE TRIGGER fail_local BEFORE INSERT ON account_events BEGIN SELECT RAISE(FAIL, 'disk full'); END;").unwrap();
    assert!(matches!(
        owner.confirm_kit_saved(),
        Err(SetupError::Journal(_))
    ));
    assert!(h.journal().load().unwrap().is_none());
    assert!(matches!(
        owner.pending_kit_code(),
        Err(SetupError::NotStarted)
    ));
    let pending = h.journal().pending_setup().unwrap().unwrap();
    assert!(!pending.blob.windows(code.len()).any(|bytes| bytes == code));
    assert!(matches!(
        ready(
            owner.begin_first_device(ControlKeyPolicy::AppEnforcedOwnerConfirmation, &password())
        ),
        Err(SetupError::AlreadyStarted)
    ));
    h.raw().execute_batch("DROP TRIGGER fail_local").unwrap();
    drop(owner);
    let mut resumed = h.owner();
    assert!(resumed.setup_status().unwrap().unwrap().kit_saved);
    resumed.confirm_kit_saved().unwrap();
    assert_eq!(h.stored().history.len(), 3);
    assert_eq!(h.stored().head, status.head);
    assert!(activate(&mut resumed).account_id() == status.anchor);
}

#[test]
fn kit_confirmation_is_explicit_and_order_alone_keeps_the_code() {
    let h = Harness::new();
    let mut owner = h.owner();
    let status = begin(&mut owner);
    let code = owner.pending_kit_code().unwrap().expose().to_owned();

    // Ordering alone deletes nothing: the person has not confirmed a save.
    owner
        .confirm_home_ordered(status.head)
        .expect("home ordered");
    assert!(h.journal().pending_setup().unwrap().is_some());
    let status = owner.setup_status().unwrap().unwrap();
    assert!(!status.kit_saved);
    assert_eq!(owner.pending_kit_code().unwrap().expose(), &code);

    owner.confirm_kit_saved().expect("explicit save");
    assert!(owner.setup_status().unwrap().is_none());
    assert!(matches!(
        owner.pending_kit_code(),
        Err(SetupError::NotStarted)
    ));
}

#[test]
fn begin_after_setup_is_refused_without_touching_the_device() {
    let h = Harness::new();
    let status = complete(&h);
    let creates = h.store.state().create_calls;
    let stored = h.stored();

    let mut owner = h.owner();
    assert!(matches!(
        ready(
            owner.begin_first_device(ControlKeyPolicy::AppEnforcedOwnerConfirmation, &password())
        ),
        Err(SetupError::AlreadyStarted)
    ));
    assert_eq!(h.store.state().create_calls, creates, "no second device");
    assert!(h.stored().anchor == stored.anchor);
    assert_eq!(h.stored().head, stored.head);
    // The existing account still activates.
    match ready(owner.activate()).unwrap() {
        AccountLoad::Active(capability) => assert!(capability.account_id() == status.anchor),
        other => panic!("expected active account, got {other:?}"),
    }
}

#[test]
fn uncertain_home_head_does_not_advance_or_bless_bytes() {
    let h = Harness::new();
    let mut owner = h.owner();
    let status = begin(&mut owner);
    let wrong = Head {
        position: status.head.position + 7,
        hash: [9; 32],
    };
    assert!(matches!(
        owner.confirm_home_ordered(wrong),
        Err(SetupError::HomeMismatch)
    ));
    assert_eq!(
        owner.setup_status().unwrap().unwrap().stage,
        SetupStage::Prepared
    );
    assert!(
        h.journal().load().unwrap().is_none(),
        "an uncertain head is never a verified head"
    );

    owner.mark_home_pending().unwrap();
    assert!(matches!(
        owner.confirm_home_ordered(wrong),
        Err(SetupError::HomeMismatch)
    ));
    assert_eq!(
        owner.setup_status().unwrap().unwrap().stage,
        SetupStage::HomePending
    );
    assert!(h.journal().load().unwrap().is_none());
}

fn test_keys(seed: u8) -> bh_account::DevicePublicKeys {
    bh_account::DevicePublicKeys::new([seed; 32], [seed + 1; 32], [seed + 2; 1216]).unwrap()
}

/// Authenticated history contradicting the owner's: it applies one signed
/// successor, and returns another active-device-signed event at the next
/// position that extends a different successor of the same head.
fn fork_successor(owner: &mut Owner, capability: &AccountCapability) -> Vec<u8> {
    let taken = owner.prepare_add_device(capability, test_keys(81)).unwrap();
    let taken = ready(owner.sign_control(capability, &taken)).unwrap();
    let other = owner.prepare_add_device(capability, test_keys(91)).unwrap();
    let other = ready(owner.sign_control(capability, &other)).unwrap();
    let mut branch = owner.verified(capability).unwrap().clone();
    branch.apply(other.as_bytes()).unwrap();
    let next = branch
        .add_device(capability.device_id(), test_keys(101))
        .unwrap();
    let next = ready(owner.sign_control(capability, &next)).unwrap();
    owner.apply_incoming(&[taken.as_bytes()]).unwrap();
    next.as_bytes().to_vec()
}

#[test]
fn unauthenticated_or_unsupported_history_is_refused_without_a_stop() {
    let h = Harness::new();
    let _ = complete(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    let before = h.stored();
    let request = owner
        .prepare_add_device(&capability, test_keys(71))
        .unwrap();
    let valid = ready(owner.sign_control(&capability, &request))
        .unwrap()
        .as_bytes()
        .to_vec();
    let mut bad_signature = valid.clone();
    *bad_signature.last_mut().unwrap() ^= 1;
    // Version and supported version follow the 23-byte domain.
    let mut newer = valid.clone();
    newer[23..27].copy_from_slice(&[0, 2, 0, 2]);
    // The control tag ends the fixed header.
    let mut unknown_control = valid.clone();
    unknown_control[23 + 2 + 2 + 8 + 32 + 32 + 32] = 9;
    // A signed event of this account, but not the next one.
    let replayed = before.history[1].clone();

    for (bytes, refused) in [
        (
            b"not an account event".to_vec(),
            bh_account::Error::Malformed,
        ),
        (bad_signature, bh_account::Error::BadSignature),
        (replayed, bh_account::Error::WrongPredecessor),
    ] {
        assert_eq!(
            owner.apply_incoming(&[bytes.as_slice()]).err(),
            Some(OwnerError::Refused(refused))
        );
    }
    for (bytes, unsupported) in [
        (newer, bh_account::Error::UnsupportedVersion),
        (unknown_control, bh_account::Error::UnsupportedControl),
    ] {
        assert_eq!(
            owner.apply_incoming(&[bytes.as_slice()]).err(),
            Some(OwnerError::Unsupported(unsupported))
        );
    }
    // Nothing applied, nothing latched: the session and its writer stay
    // usable, and the valid successor still applies.
    let after = h.stored();
    assert!(!after.stopped);
    assert_eq!(after.head, before.head);
    assert_eq!(after.history, before.history, "no unverified bytes stored");
    assert!(capability.is_current());
    let head = owner.apply_incoming(&[valid.as_slice()]).unwrap();
    assert_eq!(head, AccountEvent::decode(&valid).unwrap().head());
    assert!(capability.is_current());
}

#[test]
fn authenticated_fork_persists_stop_with_unchanged_head() {
    let h = Harness::new();
    let _ = complete(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    let fork = fork_successor(&mut owner, &capability);
    let before = h.stored();

    assert_eq!(
        owner.apply_incoming(&[fork.as_slice()]).err(),
        Some(OwnerError::Invalid(bh_account::Error::Fork))
    );
    let after = h.stored();
    assert!(after.stopped, "a fork must sticky-stop");
    assert_eq!(after.head, before.head);
    assert_eq!(after.history, before.history, "no unverified bytes stored");

    // The stop is sticky: more input never revives the account or moves the head.
    assert!(matches!(
        owner.apply_incoming(&[b"more"]),
        Err(OwnerError::Stopped)
    ));
    assert_eq!(h.stored().head, before.head);
}

#[test]
fn sticky_stop_survives_restart_and_keeps_remembered_head() {
    let h = Harness::new();
    let _ = complete(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    let fork = fork_successor(&mut owner, &capability);
    let before = h.stored().head;
    assert!(owner.apply_incoming(&[fork.as_slice()]).is_err());

    drop(owner);
    let mut owner = h.owner();
    assert!(matches!(
        ready(owner.activate()).unwrap(),
        AccountLoad::Stopped
    ));
    let stored = h.stored();
    assert!(stored.stopped);
    assert_eq!(stored.head, before);
    assert_eq!(
        owner.scanner_status(),
        Err(bh_account::pairing::PairError::History)
    );
}

#[test]
fn replay_rollback_and_fork_are_refused() {
    let h = Harness::new();
    let _ = complete(&h);
    let mut owner = h.owner();
    let _ = activate(&mut owner);
    let original = h.stored();

    // Rollback: the remembered head points past the stored history.
    h.raw()
        .execute("UPDATE account_state SET head_position=4 WHERE id=1", [])
        .unwrap();
    let rolled_back = h.stored();
    match ready(owner.activate()).unwrap() {
        AccountLoad::AdmissionRequired(AdmissionReason::CorruptHistory) => {}
        other => panic!("expected corrupt history, got {other:?}"),
    }
    assert_eq!(
        h.stored().head,
        rolled_back.head,
        "a refused replay must not clear or replace the remembered head"
    );
    assert_eq!(h.stored().history, rolled_back.history);

    // Fork: different bytes at a remembered position.
    h.raw()
        .execute(
            "UPDATE account_state SET head_position=3, head_hash=?1 WHERE id=1",
            params![original.head.hash.as_slice()],
        )
        .unwrap();
    let mut forked = original.history[2].clone();
    forked[0] ^= 1;
    h.raw()
        .execute(
            "UPDATE account_events SET bytes=?1 WHERE id=3",
            params![forked.as_slice()],
        )
        .unwrap();
    match ready(owner.activate()).unwrap() {
        AccountLoad::AdmissionRequired(AdmissionReason::CorruptHistory) => {}
        other => panic!("expected corrupt history, got {other:?}"),
    }
}

#[test]
fn missing_or_wrong_native_key_requires_fresh_admission() {
    let h = Harness::new();
    let _ = complete(&h);
    let before = h.stored();
    let creates = h.store.state().create_calls;

    h.store.state_mut().fail_load = true;
    let mut owner = h.owner();
    match ready(owner.activate()).unwrap() {
        AccountLoad::AdmissionRequired(AdmissionReason::KeyUnavailable) => {}
        other => panic!("expected key unavailable, got {other:?}"),
    }
    assert_eq!(h.store.state().create_calls, creates, "never regenerate");
    assert_eq!(h.stored().head, before.head);
    assert_eq!(h.stored().history, before.history);

    h.store.state_mut().fail_load = false;
    h.store.state_mut().wrong_public = true;
    let mut owner = h.owner();
    match ready(owner.activate()).unwrap() {
        AccountLoad::AdmissionRequired(AdmissionReason::KeyUnavailable) => {}
        other => panic!("expected key mismatch, got {other:?}"),
    }
}

#[test]
fn transient_store_failure_is_not_a_lost_key() {
    let h = Harness::new();
    let _ = complete(&h);
    let before = h.stored();

    for error in [
        KeyStoreError::AuthenticationCancelled,
        KeyStoreError::StorageFailure,
    ] {
        h.store.state_mut().load_error = Some(error);
        let mut owner = h.owner();
        assert!(matches!(
            ready(owner.activate()),
            Err(OwnerError::Device(reported)) if reported == error
        ));
        assert_eq!(
            h.stored().head,
            before.head,
            "a cancelled prompt is not a reset"
        );
    }
    h.store.state_mut().load_error = Some(KeyStoreError::Unavailable);
    let mut owner = h.owner();
    assert!(matches!(
        ready(owner.activate()).unwrap(),
        AccountLoad::AdmissionRequired(AdmissionReason::KeyUnavailable)
    ));
}

#[test]
fn activate_rejects_a_generation_change_during_the_native_load() {
    let h = Harness::new();
    let _ = complete(&h);

    h.store.state_mut().advance_generation_on_load = true;
    let mut owner = h.owner();
    assert!(matches!(ready(owner.activate()), Err(OwnerError::Stale)));
    // A fresh generation can activate normally.
    h.store.state_mut().advance_generation_on_load = false;
    let mut owner = h.owner();
    let _ = activate(&mut owner);
}

#[test]
fn activation_requires_ready_materials() {
    for events in 1..=2 {
        let h = Harness::new();
        let mut setup = h.owner();
        let status = begin(&mut setup);
        drop(setup);

        // Keep only the device identity and the first `events` signed events.
        let mut journal = h.journal();
        journal.clear_pending_setup().unwrap();
        let head = AccountEvent::decode(&status.submission[events - 1])
            .unwrap()
            .head();
        let committed: Vec<&[u8]> = status.submission[..events]
            .iter()
            .map(Vec::as_slice)
            .collect();
        journal
            .commit_verified(status.anchor, &committed, head, false)
            .unwrap();
        drop(journal);

        let mut owner = h.owner();
        match ready(owner.activate()).unwrap() {
            AccountLoad::AdmissionRequired(AdmissionReason::IncompleteMaterials) => {}
            other => panic!("expected incomplete materials for {events} events, got {other:?}"),
        }
    }
}

#[test]
fn native_key_invalidation_and_integrity_stop_fence_previous_capabilities() {
    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    h.store.state_mut().fail_load = true;
    assert!(matches!(
        ready(owner.activate()),
        Ok(AccountLoad::AdmissionRequired(
            AdmissionReason::KeyUnavailable
        ))
    ));
    assert!(
        !capability.is_current(),
        "native key invalidation revokes old writer"
    );

    let h = Harness::new();
    complete(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    let fork = fork_successor(&mut owner, &capability);
    assert!(capability.is_current());
    assert!(matches!(
        owner.apply_incoming(&[fork.as_slice()]),
        Err(OwnerError::Invalid(bh_account::Error::Fork))
    ));
    assert!(
        !capability.is_current(),
        "integrity stop revokes old writer"
    );
}

#[test]
fn a_failed_stop_write_still_stops_the_session() {
    let h = Harness::new();
    let _ = complete(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    let fork = fork_successor(&mut owner, &capability);
    // The durable stop write fails after the in-memory stop is set.
    h.raw()
        .execute_batch(
            "CREATE TRIGGER fail_stop BEFORE UPDATE ON account_state \
             BEGIN SELECT RAISE(FAIL, 'no space'); END;",
        )
        .unwrap();
    assert!(matches!(
        owner.apply_incoming(&[fork.as_slice()]),
        Err(OwnerError::Journal(_))
    ));
    assert!(
        !capability.is_current(),
        "failed integrity stop still revokes"
    );
    assert!(matches!(
        owner.prepare_remove_self(&capability),
        Err(OwnerError::Stopped)
    ));
}

#[test]
fn removed_device_denies_the_old_capability() {
    let h = Harness::new();
    let _ = complete(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    let request = owner.prepare_remove_self(&capability).unwrap();
    let event = ready(owner.sign_control(&capability, &request)).unwrap();
    let head = owner.apply_incoming(&[event.as_bytes()]).unwrap();
    assert_eq!(head, event.head());
    assert!(!capability.is_current());

    assert!(ready(owner.sign_control(&capability, &request)).is_err());
    drop(owner);
    let mut owner = h.owner();
    match ready(owner.activate()).unwrap() {
        AccountLoad::AdmissionRequired(AdmissionReason::DeviceNotActive) => {}
        other => panic!("expected removed device, got {other:?}"),
    }
}

#[test]
fn stale_generation_after_await_is_rejected() {
    let h = Harness::new();
    let _ = complete(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    let request = owner.prepare_remove_self(&capability).unwrap();

    h.store.state_mut().advance_generation_on_sign = true;
    assert!(matches!(
        ready(owner.sign_control(&capability, &request)),
        Err(OwnerError::Stale)
    ));
    h.store.state_mut().advance_generation_on_sign = false;

    let capability = activate(&mut owner);
    ready(owner.sign_control(&capability, &request)).unwrap();
}

#[test]
fn lock_revokes_the_capability_even_when_the_shared_writer_is_poisoned() {
    use std::sync::{Arc, Mutex};
    let h = Harness::new();
    complete(&h);
    let db = Arc::new(Mutex::new(
        bh_storage::DeviceDatabase::open(&h.path).unwrap(),
    ));
    let mut owner = Owner::new(
        DeviceJournal::from_shared(Arc::clone(&db)),
        h.store.clone(),
        PlainProtector,
        h.generation.clone(),
    );
    let capability = activate(&mut owner);
    assert!(capability.is_current());
    let poisoned = Arc::clone(&db);
    assert!(
        std::thread::spawn(move || {
            let _guard = poisoned.lock().unwrap();
            panic!("poison database guard");
        })
        .join()
        .is_err()
    );
    assert!(matches!(
        owner.lock(),
        Err(OwnerError::Journal(
            bh_account::journal::JournalError::Storage
        ))
    ));
    assert!(!capability.is_current());
}

#[test]
fn lock_invalidates_the_generation_and_the_capability() {
    let h = Harness::new();
    let _ = complete(&h);
    let mut owner = h.owner();
    let capability = activate(&mut owner);
    assert_eq!(capability.authority(), Authority::OfflineLastVerified);
    let request = owner.prepare_remove_self(&capability).unwrap();
    owner.lock().unwrap();
    assert!(!capability.is_current());
    assert!(matches!(
        ready(owner.sign_control(&capability, &request)),
        Err(OwnerError::NotActive)
    ));
    let _ = activate(&mut owner);
    let _ = &h.dir;
}

#[test]
fn base_control_signing_uses_the_control_key_for_base_originals_only() {
    let h = Harness::new();
    let mut owner = h.owner();
    let setup = begin(&mut owner);
    owner.confirm_kit_saved().unwrap();
    owner.confirm_home_ordered(setup.head).unwrap();
    let cap = activate(&mut owner);
    let message = b"bh/original-envelope/v1\0a base copy".to_vec();
    let expected = *owner
        .verified(&cap)
        .unwrap()
        .active_device(cap.device_id())
        .unwrap()
        .control();
    let before = h.store.state().sign_calls;
    assert!(matches!(
        ready(owner.sign_base_control(&cap, &[0; 32], &message)),
        Err(OwnerError::Device(KeyStoreError::WrongKey))
    ));
    assert_eq!(h.store.state().sign_calls, before, "no prompt on wrong key");
    let signature = ready(owner.sign_base_control(&cap, &expected, &message)).unwrap();
    let keys = owner
        .verified(&cap)
        .unwrap()
        .active_device(cap.device_id())
        .unwrap()
        .clone();
    bh_account::crypto::verify(keys.control(), &message, &signature).unwrap();
    assert!(bh_account::crypto::verify(keys.signing(), &message, &signature).is_err());
    // An account event's bytes are not a base original.
    let request = owner.prepare_remove_self(&cap).unwrap();
    assert!(matches!(
        ready(owner.sign_base_control(&cap, &expected, request.signing_bytes())),
        Err(OwnerError::Invalid(_))
    ));
    // A lock or removal that lands while the prompt is open discards it.
    h.store.state_mut().advance_generation_on_sign = true;
    assert!(matches!(
        ready(owner.sign_base_control(&cap, &expected, &message)),
        Err(OwnerError::Stale)
    ));
}

/// A joining device's own owner, before it has any account: its journaled
/// scanner identity proves possession at the head the showing device names,
/// and it commits only original history, verified from the code's anchor,
/// that admits exactly its keys. It then opens the delivery its addition
/// carried against that verified history.
#[test]
fn joining_device_proves_named_head_and_adopts_only_history_admitting_it() {
    use bh_account::device_auth::{Context, verify_at};
    use bh_account::pairing::{Reply, ScannerStatus, ShowingSession, scanner_identity};
    let showing = Harness::new();
    let setup = complete(&showing);
    let joiner = Harness::new();
    let identity = ready(scanner_identity(
        &mut joiner.journal(),
        &mut joiner.store.clone(),
        ControlKeyPolicy::AppEnforcedOwnerConfirmation,
    ))
    .unwrap();

    // The first device approves the joining device's reply and its addition
    // is ordered.
    let mut first = showing.owner();
    let cap = activate(&mut first);
    let personal = ready(first.open_personal(&cap)).unwrap();
    let session = ShowingSession::new(setup.anchor, cap.device_id());
    session
        .receive(&Reply::make(&session.qr().unwrap(), identity.keys.clone(), b"Fold").unwrap())
        .unwrap();
    let request = session.prepare(&first, &cap).unwrap();
    let added = ready(first.sign_control(&cap, &request)).unwrap();
    let delivery =
        ready(first.seal_personal_for_device(&cap, &personal, &identity.keys, &added)).unwrap();
    let head = first.apply_incoming(&[added.as_bytes()]).unwrap();
    let history = showing.stored().history;
    let refs: Vec<&[u8]> = history.iter().map(Vec::as_slice).collect();
    let view = bh_account::VerifiedAccount::replay(setup.anchor, &refs, head).unwrap();

    // Possession at that head, with the journaled ordinary key.
    let mut owner = joiner.owner();
    let context = Context {
        channel_binding: [3; 32],
        challenge: [4; 32],
    };
    let proof = ready(owner.prove_joining(setup.anchor, head, context)).unwrap();
    let possession = verify_at(&view, context, proof.as_bytes()).unwrap();
    assert!(possession.device() == identity.keys.id());

    // History without its addition, from another anchor, or altered: refused,
    // and nothing is kept.
    assert!(matches!(
        owner.adopt_joined(setup.anchor, &refs[..3]),
        Err(OwnerError::Invalid(_))
    ));
    let other = bh_account::AccountId([9; 32]);
    assert!(owner.adopt_joined(other, &refs).is_err());
    let mut altered = history.clone();
    let last = altered[3].len() - 1;
    altered[3][last] ^= 1;
    let altered: Vec<&[u8]> = altered.iter().map(Vec::as_slice).collect();
    assert!(owner.adopt_joined(setup.anchor, &altered).is_err());
    assert!(joiner.journal().load().unwrap().is_none());

    assert_eq!(owner.adopt_joined(setup.anchor, &refs).unwrap(), head);
    // Repeating it after a restart keeps what was committed.
    assert_eq!(owner.adopt_joined(setup.anchor, &refs).unwrap(), head);
    assert!(owner.adopt_joined(other, &refs).is_err());
    let joined = activate(&mut owner);
    assert_eq!(
        owner.scanner_status().unwrap(),
        ScannerStatus::ReadyForDelivery
    );
    let opened = ready(owner.open_delivered_personal(&joined, &delivery, 4)).unwrap();
    assert_eq!(opened.public(), personal.public());
    let mut tampered = delivery.clone();
    tampered[100] ^= 1;
    assert!(ready(owner.open_delivered_personal(&joined, &tampered, 4)).is_err());
    assert!(ready(owner.open_delivered_personal(&joined, &delivery, 3)).is_err());
    assert_eq!(
        owner.verified_at(&joined, 3).unwrap().head(),
        setup.head,
        "the signup head the own base names"
    );
    assert!(ready(owner.prove_joining(other, head, context)).is_err());
}
