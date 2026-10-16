use bh_account::{
    VerifiedAccount,
    journal::AccountJournal,
    owner::{AccountCapability, AccountGeneration, AccountLoad, AccountOwner},
    platform::ControlKeyPolicy,
    recovery::Password,
    storage::DeviceJournal,
};
use bh_core::note::Note;
use bh_device::{ContainerId, Owner, OwnerError};
use bh_storage::{NoteKey, ViewRecord};
use std::{
    future::Future,
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};

#[allow(dead_code)]
#[path = "../../account/tests/support/protector.rs"]
mod protector;
#[path = "../../account/tests/support/store.rs"]
mod store;
use protector::PlainProtector;
use store::FakeStore;

type Account = AccountOwner<DeviceJournal, FakeStore, PlainProtector>;
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(value) => value,
        std::task::Poll::Pending => panic!("test store unexpectedly pending"),
    }
}
fn setup(path: &std::path::Path) -> (Owner, ContainerId, Account, Arc<AccountCapability>) {
    let owner = Owner::default();
    let (id, account, capability) = add_account(&owner, path);
    (owner, id, account, capability)
}
fn add_account(
    owner: &Owner,
    path: &std::path::Path,
) -> (ContainerId, Account, Arc<AccountCapability>) {
    let id = owner.create_container(path).unwrap();
    let db = owner.shared_database(id).unwrap();
    let generation = AccountGeneration::new();
    let mut account = Account::new(
        DeviceJournal::from_shared(Arc::clone(&db)),
        FakeStore::new(generation.clone()),
        PlainProtector,
        generation,
    );
    let status = ready(account.begin_first_device(
        ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        &Password::new("correct horse battery staple").unwrap(),
    ))
    .unwrap();
    account.confirm_home_ordered(status.head).unwrap();
    account.confirm_kit_saved().unwrap();
    let record = DeviceJournal::from_shared(db).load().unwrap().unwrap();
    let signed: Vec<_> = record.history.iter().map(Vec::as_slice).collect();
    let verified = VerifiedAccount::replay(record.anchor, &signed, record.head).unwrap();
    owner.anchor(id, &verified).unwrap();
    let capability = match ready(account.activate()).unwrap() {
        AccountLoad::Active(cap) => Arc::new(cap),
        other => panic!("{other:?}"),
    };
    owner
        .shared_database(id)
        .unwrap()
        .lock()
        .unwrap()
        .create_own_base_if_absent(
            &bh_storage::own_base::OwnBaseRecord {
                account: capability.account_id().0,
                base: BASE,
                genesis_descriptor: vec![1],
                genesis_body: vec![2],
                initial_key_package: vec![3],
            },
            || capability.is_current(),
        )
        .unwrap();
    (id, account, capability)
}
// Synthetic native argument; the app supplies its verified OwnBase id.
const BASE: [u8; 32] = [71; 32];
fn key(note: [u8; 32]) -> NoteKey {
    NoteKey {
        base: BASE,
        audience: [0; 32],
        note,
    }
}
fn frontier(owner: &Owner, id: ContainerId, key: NoteKey) -> i64 {
    owner
        .shared_database(id)
        .unwrap()
        .lock()
        .unwrap()
        .local_frontier(key)
        .unwrap()
}

#[test]
fn authority_requires_anchor_matching_current_capability_and_catalogue_presence() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, mut account, cap) = setup(dir.path());
    let unanchored = owner.create_container(dir.path()).unwrap();
    assert!(matches!(
        owner.authorize(unanchored, Arc::clone(&cap), BASE),
        Err(OwnerError::Unbound)
    ));
    assert!(matches!(owner.create_note(id), Err(OwnerError::Unbound)));
    owner.authorize(id, Arc::clone(&cap), BASE).unwrap();
    let note = owner.create_note(id).unwrap();
    assert!(matches!(
        owner.show_note("w", id, [5; 32]),
        Err(OwnerError::Unbound)
    ));
    owner.show_note("w", id, note).unwrap();
    let opened = owner.open_leased("w", note).unwrap();
    assert_eq!(owner.bound_note("w"), Some(note));
    assert_eq!(owner.bound_container("w"), Some(id));
    let delta = Owner::core_author(&opened)
        .unwrap()
        .append_paragraph("hello");
    owner
        .commit_leased(
            "w",
            opened.generation,
            opened.writer.unwrap().token,
            [1; 16],
            &delta,
        )
        .unwrap();
    assert_eq!(frontier(&owner, id, key(note)), 1);
    let listed = owner.list_notes(id, None, 50).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].note, note);
    assert!(owner.deauthorize(id).unwrap().contains(&"w".to_owned()));
    assert_eq!(owner.bound_note("w"), None);
    assert_eq!(owner.bound_container("w"), None);
    assert!(owner.list_notes(id, None, 50).is_err());
    account.lock().unwrap();
    assert!(!cap.is_current());
    assert!(matches!(
        owner.authorize(id, cap, BASE),
        Err(OwnerError::Unbound)
    ));
}

#[test]
fn reauthorizing_the_same_capability_keeps_windows_but_a_fresh_one_needs_new_loads() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, mut account, cap) = setup(dir.path());
    owner.authorize(id, Arc::clone(&cap), BASE).unwrap();
    let note = owner.home_note(id).unwrap();
    owner.show_note("w", id, note).unwrap();
    let old = owner.open_leased("w", note).unwrap().generation;
    // A second window opening its notes must not reload the first one.
    owner.authorize(id, Arc::clone(&cap), BASE).unwrap();
    assert!(owner.bound_work_key("w", old).is_some());
    // A fresh activation is a new authority: every old load is refused.
    account.lock().unwrap();
    let fresh = match ready(account.activate()).unwrap() {
        AccountLoad::Active(cap) => Arc::new(cap),
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        owner.commit_queued("w", old, [1; 16], &Note::new().append_paragraph("stale")),
        Err(OwnerError::Unbound)
    ));
    owner.authorize(id, Arc::clone(&fresh), BASE).unwrap();
    assert_eq!(owner.bound_note("w"), None);
    assert!(matches!(
        owner.open_leased("w", note),
        Err(OwnerError::Unbound)
    ));
    owner.show_note("w", id, note).unwrap();
    assert!(matches!(
        owner.commit_queued("w", old, [1; 16], &Note::new().append_paragraph("stale")),
        Err(OwnerError::Unbound)
    ));
    let opened = owner.open_leased("w", note).unwrap();
    let new = opened.generation;
    assert!(new > old);
    owner
        .commit_leased(
            "w",
            new,
            opened.writer.unwrap().token,
            [2; 16],
            &Owner::core_author(&opened)
                .unwrap()
                .append_paragraph("fresh"),
        )
        .unwrap();
    assert_eq!(frontier(&owner, id, key(note)), 1);
}

#[test]
fn account_lock_after_scope_check_before_writer_refuses_commit() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, mut account, cap) = setup(dir.path());
    owner.authorize(id, cap, BASE).unwrap();
    let note = owner.create_note(id).unwrap();
    owner.show_note("w", id, note).unwrap();
    let opened = owner.open_leased("w", note).unwrap();
    let owner = Arc::new(owner);
    let (arrived_tx, arrived_rx) = mpsc::channel();
    let (continue_tx, continue_rx) = mpsc::channel();
    let save_owner = Arc::clone(&owner);
    let save = thread::spawn(move || {
        save_owner.commit_with_writer_hook(
            "w",
            opened.generation,
            [8; 16],
            &Note::new().append_paragraph("not committed"),
            || {
                arrived_tx.send(()).unwrap();
                continue_rx.recv().unwrap();
            },
        )
    });
    arrived_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    account.lock().unwrap(); // Same DeviceJournal writer, not a generation advance outside it.
    continue_tx.send(()).unwrap();
    assert!(matches!(save.join().unwrap(), Err(OwnerError::Unbound)));
    assert_eq!(frontier(&owner, id, key(note)), 0);
}

#[test]
fn replacement_serializes_with_commit_even_when_old_arc_is_current() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, cap) = setup(dir.path());
    owner.authorize(id, Arc::clone(&cap), BASE).unwrap();
    let note = owner.home_note(id).unwrap();
    owner.show_note("w", id, note).unwrap();
    let opened = owner.open_leased("w", note).unwrap();
    let generation = opened.generation;
    let owner = Arc::new(owner);
    let (arrived_tx, arrived_rx) = mpsc::channel();
    let (continue_tx, continue_rx) = mpsc::channel();
    let save_owner = Arc::clone(&owner);
    let save = thread::spawn(move || {
        save_owner.commit_leased_with_writer_hooks(
            "w",
            generation,
            opened.writer.unwrap().token,
            [1; 16],
            &Owner::core_author(&opened)
                .unwrap()
                .append_paragraph("first"),
            (
                || {
                    arrived_tx.send(()).unwrap();
                    continue_rx.recv().unwrap();
                },
                || {},
            ),
        )
    });
    arrived_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let replacing = Arc::clone(&owner);
    let (done_tx, done_rx) = mpsc::channel();
    let replace = thread::spawn(move || done_tx.send(replacing.deauthorize(id)).unwrap());
    assert!(done_rx.recv_timeout(Duration::from_millis(40)).is_err());
    continue_tx.send(()).unwrap();
    assert!(!save.join().unwrap().unwrap().replayed);
    assert_eq!(
        done_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap(),
        vec!["w"]
    );
    replace.join().unwrap();
    assert!(
        cap.is_current(),
        "deauthorization is independent of account generation"
    );
    assert!(matches!(
        owner.commit_queued(
            "w",
            generation,
            [2; 16],
            &Note::new().append_paragraph("late")
        ),
        Err(OwnerError::Unbound)
    ));
}

#[test]
fn reverse_order_account_lock_waits_for_note_commit() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, account, cap) = setup(dir.path());
    owner.authorize(id, Arc::clone(&cap), BASE).unwrap();
    let note = owner.home_note(id).unwrap();
    owner.show_note("w", id, note).unwrap();
    let opened = owner.open_leased("w", note).unwrap();
    let generation = opened.generation;
    let db = owner.shared_database(id).unwrap();
    let account_generation = account.generation();
    let (started_tx, started_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let mut locker = None;
    let ack = owner
        .commit_leased_with_writer_hooks(
            "w",
            generation,
            opened.writer.unwrap().token,
            [9; 16],
            &Owner::core_author(&opened)
                .unwrap()
                .append_paragraph("committed before lock"),
            (
                || {},
                || {
                    let db = Arc::clone(&db);
                    let generation = account_generation.clone();
                    locker = Some(thread::spawn(move || {
                        let mut owner = Account::new(
                            DeviceJournal::from_shared(db),
                            FakeStore::new(generation.clone()),
                            PlainProtector,
                            generation,
                        );
                        started_tx.send(()).unwrap();
                        owner.lock().unwrap();
                        done_tx.send(()).unwrap();
                    }));
                    started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                    assert!(cap.is_current());
                    assert!(
                        done_rx.recv_timeout(Duration::from_millis(40)).is_err(),
                        "lock must wait for the note writer"
                    );
                },
            ),
        )
        .unwrap();
    assert!(!ack.replayed);
    done_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    locker.unwrap().join().unwrap();
    assert!(!cap.is_current());
    assert_eq!(frontier(&owner, id, key(note)), 1);
}

#[test]
fn concurrent_home_reuses_one_note_and_new_notes_list_most_recent_first() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, cap) = setup(dir.path());
    owner.authorize(id, cap, BASE).unwrap();
    let owner = Arc::new(owner);
    let second = Arc::clone(&owner);
    let thread = thread::spawn(move || second.home_note(id).unwrap());
    let home = owner.home_note(id).unwrap();
    assert_eq!(home, thread.join().unwrap());
    assert_eq!(owner.list_notes(id, None, 50).unwrap().len(), 1);
    let next = owner.create_note(id).unwrap();
    assert_ne!(home, next);
    let notes: Vec<_> = owner
        .list_notes(id, None, 50)
        .unwrap()
        .into_iter()
        .map(|entry| entry.note)
        .collect();
    assert_eq!(notes, vec![next, home]);
    assert!(matches!(
        owner.list_notes(id, None, 51),
        Err(OwnerError::Store(_))
    ));
}

#[test]
fn wrong_account_and_absent_full_key_are_refused_without_affecting_another_account() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, a, _account_a, cap_a) = setup(dir.path());
    let (b, _account_b, cap_b) = add_account(&owner, dir.path());
    assert!(matches!(
        owner.authorize(a, Arc::clone(&cap_b), BASE),
        Err(OwnerError::Unbound)
    ));
    owner.authorize(a, Arc::clone(&cap_a), BASE).unwrap();
    owner.authorize(b, cap_b, BASE).unwrap();
    let note_a = owner.create_note(a).unwrap();
    let private_note = owner
        .shared_database(b)
        .unwrap()
        .lock()
        .unwrap()
        .create_note(BASE, [3; 32])
        .unwrap();
    assert!(matches!(
        owner.show_note("b", b, private_note),
        Err(OwnerError::Unbound)
    ));
    assert!(matches!(
        owner.show_note("b", b, note_a),
        Err(OwnerError::Unbound)
    ));
    assert!(
        owner
            .list_notes(b, None, 50)
            .unwrap()
            .iter()
            .all(|entry| entry.note != note_a && entry.note != private_note)
    );
    assert!(owner.has_note(a, note_a).unwrap());
    assert!(!owner.has_note(b, note_a).unwrap());
    assert!(!owner.has_note(b, private_note).unwrap());
    let note_b = owner.create_note(b).unwrap();
    owner.show_note("b", b, note_b).unwrap();
    let opened = owner.open_leased("b", note_b).unwrap();
    owner.deauthorize(a).unwrap();
    assert!(matches!(
        owner.has_note(a, note_a),
        Err(OwnerError::Unbound)
    ));
    assert!(
        !owner
            .commit_leased(
                "b",
                opened.generation,
                opened.writer.unwrap().token,
                [4; 16],
                &Owner::core_author(&opened)
                    .unwrap()
                    .append_paragraph("B unaffected")
            )
            .unwrap()
            .0
            .replayed
    );
}

#[test]
fn switching_window_to_other_container_before_writer_refuses_old_write() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, a, _a_account, a_cap) = setup(dir.path());
    let (b, _b_account, b_cap) = add_account(&owner, dir.path());
    owner.authorize(a, a_cap, BASE).unwrap();
    owner.authorize(b, b_cap, BASE).unwrap();
    let a_note = owner.create_note(a).unwrap();
    let b_note = owner.create_note(b).unwrap();
    owner.show_note("w", a, a_note).unwrap();
    let a_generation = owner.open_leased("w", a_note).unwrap().generation;
    let update = Note::new().append_paragraph("old route");
    let result = owner.commit_with_writer_hook("w", a_generation, [11; 16], &update, || {
        owner.show_note("w", b, b_note).unwrap();
    });
    assert!(matches!(result, Err(OwnerError::Unbound)));
    assert_eq!(frontier(&owner, a, key(a_note)), 0);
    assert_eq!(owner.bound_note("w"), Some(b_note));
    assert!(matches!(owner.bind("w", a), Err(OwnerError::Unbound)));
    assert!(owner.open_leased("w", b_note).is_ok());
}

#[test]
fn two_windows_share_one_core_note_and_each_receives_the_others_commit() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, cap) = setup(dir.path());
    owner.authorize(id, cap, BASE).unwrap();
    let note = owner.home_note(id).unwrap();
    owner.show_note("main", id, note).unwrap();
    owner.show_note("note-1", id, note).unwrap();
    let opened = owner.open_leased("main", note).unwrap();
    let left = opened.generation;
    let token = opened.writer.unwrap().token;
    let mut author = Owner::core_author(&opened).unwrap();
    let right = owner.open_leased("note-1", note).unwrap().generation;
    let delta = author.append_paragraph("from main");
    let (_, targets) = owner
        .commit_leased("main", left, token, [1; 16], &delta)
        .unwrap();
    assert_eq!(targets, vec!["note-1".to_owned()]);
    let mut delivered = Vec::new();
    owner.drain_surface("note-1", &mut |item| delivered.push(item));
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].generation, right);
    assert_eq!(delivered[0].update, delta);
    // Opening another note in the second window ends its delivery.
    let other = owner.create_note(id).unwrap();
    owner.show_note("note-1", id, other).unwrap();
    let (_, targets) = owner
        .commit_leased(
            "main",
            left,
            token,
            [2; 16],
            &author.append_paragraph("more"),
        )
        .unwrap();
    assert!(targets.is_empty());
}

#[test]
fn restore_records_remain_until_authorize_then_only_ordinary_existing_notes_return() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, mut account, cap) = setup(dir.path());
    let db = owner.shared_database(id).unwrap();
    let first = db.lock().unwrap().create_note(BASE, [0; 32]).unwrap();
    let other = db.lock().unwrap().create_note([42; 32], [0; 32]).unwrap();
    let view = |base, note| ViewRecord {
        version: 1,
        key: NoteKey {
            base,
            audience: [0; 32],
            note,
        },
        anchor: cap.account_id().0.to_vec(),
        head: cap.head().hash.to_vec(),
        cursor_offset: 4.0,
        frame: [0.0, 0.0, 900.0, 700.0],
    };
    db.lock()
        .unwrap()
        .replace_view_records(&[
            view(BASE, first),
            view([42; 32], other),
            view(BASE, [99; 32]),
        ])
        .unwrap();
    assert!(matches!(
        owner.take_authorized_view_records(id),
        Err(OwnerError::Unbound)
    ));
    owner.authorize(id, Arc::clone(&cap), BASE).unwrap();
    assert_eq!(
        owner.take_authorized_view_records(id).unwrap(),
        vec![view(BASE, first)]
    );
    assert!(owner.take_authorized_view_records(id).unwrap().is_empty());
    db.lock()
        .unwrap()
        .replace_view_records(&[view(BASE, first)])
        .unwrap();
    account.lock().unwrap();
    assert!(matches!(
        owner.take_authorized_view_records(id),
        Err(OwnerError::Unbound)
    ));
    assert_eq!(
        db.lock().unwrap().take_view_records().unwrap(),
        vec![view(BASE, first)],
        "failed authority check must not consume rows"
    );
}

// ---- Close/Quit/update drain fences (native lifecycle barrier) ----

fn opened_note(
    owner: &Owner,
    id: ContainerId,
    window: &str,
) -> ([u8; 32], bh_device::coordinator::Opened) {
    let note = owner.home_note(id).unwrap();
    owner.show_note(window, id, note).unwrap();
    (note, owner.open_leased(window, note).unwrap())
}
fn type_into(opened: &bh_device::coordinator::Opened, text: &str) -> Vec<u8> {
    Owner::core_author(opened).unwrap().append_paragraph(text)
}

#[test]
fn drain_fence_finishes_prior_saves_then_refuses_new_loads_and_post_reply_writes() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, cap) = setup(dir.path());
    owner.authorize(id, cap, BASE).unwrap();
    let (note, opened) = opened_note(&owner, id, "w");
    let token = opened.writer.unwrap().token;
    let fence = owner.begin_drain().unwrap();
    assert!(matches!(owner.begin_drain(), Err(OwnerError::Busy)));
    assert!(matches!(
        owner.begin_window_drain("w"),
        Err(OwnerError::Busy)
    ));
    // No new surface, route or load may start while every window drains.
    assert!(matches!(
        owner.show_note("new", id, note),
        Err(OwnerError::Busy)
    ));
    assert!(matches!(
        owner.open_leased("w", note),
        Err(OwnerError::Busy)
    ));
    // Writing accepted before this window's reply still saves.
    let mut author = Owner::core_author(&opened).unwrap();
    owner
        .commit_leased(
            "w",
            opened.generation,
            token,
            [1; 16],
            &author.append_paragraph("before"),
        )
        .unwrap();
    assert_eq!(
        owner.mark_drained("w", fence).unwrap(),
        Some((id, key(note)))
    );
    let late = author.append_paragraph("after");
    assert!(
        owner
            .commit_leased("w", opened.generation, token, [2; 16], &late)
            .is_err()
    );
    assert_eq!(
        frontier(&owner, id, key(note)),
        1,
        "no write after the reply"
    );
    owner.end_drain(fence);
    owner
        .commit_leased("w", opened.generation, token, [2; 16], &late)
        .unwrap();
    assert_eq!(frontier(&owner, id, key(note)), 2);
}

#[test]
fn a_stale_fence_cannot_release_mark_or_end_a_newer_drain() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, cap) = setup(dir.path());
    owner.authorize(id, cap, BASE).unwrap();
    let (note, _opened) = opened_note(&owner, id, "w");
    let old = owner.begin_drain().unwrap();
    owner.end_drain(old);
    let current = owner.begin_drain().unwrap();
    assert_ne!(old, current);
    owner.end_drain(old);
    assert!(matches!(
        owner.open_leased("w", note),
        Err(OwnerError::Busy)
    ));
    assert!(matches!(
        owner.mark_drained("w", old),
        Err(OwnerError::Unbound)
    ));
    owner.mark_drained("w", current).unwrap();
    owner.end_drain(current);
    owner.open_leased("w", note).unwrap();
}

#[test]
fn drain_reply_waits_for_a_commit_already_inside_the_note_lease() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, cap) = setup(dir.path());
    owner.authorize(id, cap, BASE).unwrap();
    let (note, opened) = opened_note(&owner, id, "w");
    let token = opened.writer.unwrap().token;
    let owner = Arc::new(owner);
    let fence = owner.begin_drain().unwrap();
    let (entered_tx, entered) = mpsc::channel();
    let (resume, resumed) = mpsc::channel::<()>();
    let saving = {
        let owner = Arc::clone(&owner);
        let delta = type_into(&opened, "in flight");
        thread::spawn(move || {
            owner.commit_leased_with_work_hook(
                "w",
                opened.generation,
                token,
                [1; 16],
                &delta,
                || {
                    entered_tx.send(()).unwrap();
                    resumed.recv().unwrap();
                },
            )
        })
    };
    entered.recv_timeout(Duration::from_secs(2)).unwrap();
    let (done_tx, done) = mpsc::channel();
    let replying = {
        let owner = Arc::clone(&owner);
        thread::spawn(move || done_tx.send(owner.mark_drained("w", fence)).unwrap())
    };
    assert!(
        done.recv_timeout(Duration::from_millis(50)).is_err(),
        "reply waits for the save"
    );
    resume.send(()).unwrap();
    saving.join().unwrap().unwrap();
    assert!(done.recv_timeout(Duration::from_secs(2)).unwrap().is_ok());
    replying.join().unwrap();
    assert_eq!(frontier(&owner, id, key(note)), 1);
}

#[test]
fn closing_one_window_holds_only_that_window() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, cap) = setup(dir.path());
    let (other, _other_account, other_cap) = add_account(&owner, dir.path());
    owner.authorize(id, cap, BASE).unwrap();
    owner.authorize(other, other_cap, BASE).unwrap();
    let (note, closing) = opened_note(&owner, id, "closing");
    owner.show_note("open", id, note).unwrap();
    let fence = owner.begin_window_drain("closing").unwrap();
    assert!(matches!(
        owner.begin_window_drain("closing"),
        Err(OwnerError::Busy)
    ));
    assert!(
        matches!(owner.begin_drain(), Err(OwnerError::Busy)),
        "Quit waits for the close"
    );
    let open = owner.open_leased("open", note).unwrap();
    owner
        .commit_leased(
            "open",
            open.generation,
            open.writer.unwrap().token,
            [1; 16],
            &type_into(&open, "beside"),
        )
        .unwrap();
    let (other_note, _) = opened_note(&owner, other, "elsewhere");
    assert_ne!(other_note, [0; 32]);
    owner.mark_drained("closing", fence).unwrap();
    assert!(
        owner
            .commit_leased(
                "closing",
                closing.generation,
                closing.writer.unwrap().token,
                [2; 16],
                &type_into(&closing, "late")
            )
            .is_err()
    );
    owner.end_drain(fence);
}

#[test]
fn a_loading_or_unbound_surface_that_claimed_empty_cannot_start_writing_while_held() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, cap) = setup(dir.path());
    owner.authorize(id, cap, BASE).unwrap();
    let note = owner.home_note(id).unwrap();
    owner.show_note("loading", id, note).unwrap();
    let fence = owner.begin_drain().unwrap();
    assert_eq!(owner.mark_drained("loading", fence).unwrap(), None);
    assert_eq!(owner.mark_drained("setup", fence).unwrap(), None);
    assert!(matches!(
        owner.open_leased("loading", note),
        Err(OwnerError::Busy)
    ));
    assert!(matches!(
        owner.show_note("setup", id, note),
        Err(OwnerError::Busy)
    ));
    owner.end_drain(fence);
    owner.open_leased("loading", note).unwrap();
    owner.show_note("setup", id, note).unwrap();
}

#[test]
fn restart_records_carry_selection_bytes_and_return_two_windows_after_real_authority() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, cap) = setup(dir.path());
    let db = owner.shared_database(id).unwrap();
    let first = db.lock().unwrap().create_note(BASE, [0; 32]).unwrap();
    let second = db.lock().unwrap().create_note(BASE, [0; 32]).unwrap();
    // Encoded Yjs relative positions, never the account ID.
    let selection = |client: u8| vec![1, client, 7, 0];
    let view = |note, client, x| ViewRecord {
        version: 1,
        key: NoteKey {
            base: BASE,
            audience: [0; 32],
            note,
        },
        anchor: selection(client),
        head: selection(client + 1),
        cursor_offset: 120.5,
        frame: [x, 40.0, 900.0, 700.0],
    };
    let records = vec![view(first, 3, 10.0), view(second, 5, 60.0)];
    assert_ne!(records[0].anchor.as_slice(), cap.account_id().0.as_slice());
    db.lock().unwrap().replace_view_records(&records).unwrap();
    assert!(matches!(
        owner.take_authorized_view_records(id),
        Err(OwnerError::Unbound)
    ));
    owner.authorize(id, cap, BASE).unwrap();
    assert_eq!(owner.take_authorized_view_records(id).unwrap(), records);
    assert!(
        owner.take_authorized_view_records(id).unwrap().is_empty(),
        "restored once"
    );
    // Oversized selection bytes are presentation input, not trusted: dropped.
    let mut oversized = view(first, 3, 10.0);
    oversized.anchor = vec![0; 1025];
    db.lock()
        .unwrap()
        .replace_view_records(&[oversized])
        .unwrap();
    assert!(owner.take_authorized_view_records(id).unwrap().is_empty());
}

#[test]
fn a_closed_or_revoked_load_has_nothing_left_to_write_and_drains_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, mut account, cap) = setup(dir.path());
    owner.authorize(id, cap, BASE).unwrap();
    let (note, closing) = opened_note(&owner, id, "switching");
    let (_, revoked) = opened_note(&owner, id, "revoked");
    // The page closed its editor (a note switch) before native asked.
    owner.close_generation("switching", closing.generation);
    let fence = owner.begin_drain().unwrap();
    assert_eq!(owner.mark_drained("switching", fence).unwrap(), None);
    account.lock().unwrap();
    assert_eq!(owner.mark_drained("revoked", fence).unwrap(), None);
    assert!(
        owner
            .commit_leased(
                "revoked",
                revoked.generation,
                revoked.writer.unwrap().token,
                [1; 16],
                &type_into(&revoked, "x")
            )
            .is_err()
    );
    assert!(owner.show_note("switching", id, note).is_err());
    owner.end_drain(fence);
}
