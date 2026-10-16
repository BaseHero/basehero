use bh_account::{
    VerifiedAccount,
    journal::AccountJournal,
    owner::{AccountCapability, AccountGeneration, AccountLoad, AccountOwner},
    platform::ControlKeyPolicy,
    recovery::Password,
    storage::DeviceJournal,
};
use bh_core::note::Note;
use bh_device::{
    ContainerId, Owner,
    writers::{AcceptedBindings, BindingRead, WriterUnavailable},
};
use bh_storage::{DeviceDatabase, NoteKey, own_base::OwnBaseRecord};
use std::{future::Future, sync::Arc};
#[allow(dead_code)]
#[path = "../../account/tests/support/protector.rs"]
mod protector;
#[path = "../../account/tests/support/store.rs"]
mod store;
fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(v) => v,
        _ => panic!("unexpected async platform"),
    }
}
type Account = AccountOwner<DeviceJournal, store::FakeStore, protector::PlainProtector>;
const BASE: [u8; 32] = [71; 32];
fn setup(
    path: &std::path::Path,
) -> (
    Owner,
    ContainerId,
    Account,
    Arc<AccountCapability>,
    [u8; 32],
) {
    let owner = Owner::default();
    let id = owner.create_container(path).unwrap();
    let db = owner.shared_database(id).unwrap();
    let generation = AccountGeneration::new();
    let mut account = Account::new(
        DeviceJournal::from_shared(db.clone()),
        store::FakeStore::new(generation.clone()),
        protector::PlainProtector,
        generation,
    );
    let status = ready(account.begin_first_device(
        ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        &Password::new("correct horse battery staple").unwrap(),
    ))
    .unwrap();
    account.confirm_home_ordered(status.head).unwrap();
    account.confirm_kit_saved().unwrap();
    let record = DeviceJournal::from_shared(db.clone())
        .load()
        .unwrap()
        .unwrap();
    let history = record.history.iter().map(Vec::as_slice).collect::<Vec<_>>();
    owner
        .anchor(
            id,
            &VerifiedAccount::replay(record.anchor, &history, record.head).unwrap(),
        )
        .unwrap();
    let cap = match ready(account.activate()).unwrap() {
        AccountLoad::Active(c) => Arc::new(c),
        _ => panic!(),
    };
    db.lock()
        .unwrap()
        .create_own_base_if_absent(
            &OwnBaseRecord {
                account: cap.account_id().0,
                base: BASE,
                genesis_descriptor: vec![1],
                genesis_body: vec![2],
                initial_key_package: vec![3],
            },
            || cap.is_current(),
        )
        .unwrap();
    owner.authorize(id, cap.clone(), BASE).unwrap();
    let note = owner.create_note(id).unwrap();
    owner.show_note("one", id, note).unwrap();
    owner.show_note("two", id, note).unwrap();
    (owner, id, account, cap, note)
}
#[test]
fn separate_live_producers_reuse_idle_slot_with_new_token_and_atomic_proof() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, cap, note) = setup(dir.path());
    let one = owner.open_leased("one", note).unwrap();
    let two = owner.open_leased("two", note).unwrap();
    let a = one.writer.unwrap();
    let b = two.writer.unwrap();
    assert_ne!(a.client_id, b.client_id);
    let mut author = Note::with_writer(a.client_id).unwrap();
    author.apply_update(&one.state).unwrap();
    let update = author.append_paragraph("safe");
    owner
        .commit_leased("one", one.generation, a.token, [1; 16], &update)
        .unwrap();
    assert!(
        owner
            .commit_leased("one", one.generation, a.token, [1; 16], &update)
            .unwrap()
            .0
            .replayed
    );
    assert!(
        owner
            .commit_leased("one", one.generation, a.token, [2; 16], &update)
            .is_err()
    );
    let pending = owner
        .shared_database(id)
        .unwrap()
        .lock()
        .unwrap()
        .pending_note_updates()
        .unwrap();
    let proof = bh_device::writers::pending_declaration(&pending[0])
        .unwrap()
        .unwrap();
    assert_eq!(proof.account, cap.account_id().0);
    assert_eq!(proof.device, cap.device_id().0);
    owner.close_generation("one", one.generation);
    let reopened = owner.open_leased("one", note).unwrap();
    let c = reopened.writer.unwrap();
    assert_eq!(a.client_id, c.client_id);
    assert_ne!(a.token, c.token);
    assert!(
        owner
            .commit_leased(
                "one",
                one.generation,
                a.token,
                [3; 16],
                &author.append_paragraph("stale")
            )
            .is_err()
    );
    let mut random = Note::new();
    random.apply_update(&reopened.state).unwrap();
    assert!(
        owner
            .commit_leased(
                "one",
                reopened.generation,
                c.token,
                [4; 16],
                &random.append_paragraph("random")
            )
            .is_err()
    );
}
#[test]
fn delete_only_save_uses_deleting_producers_declaration_not_referenced_writer() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, _cap, note) = setup(dir.path());
    let first = owner.open_leased("one", note).unwrap();
    let a = first.writer.unwrap();
    owner
        .commit_leased(
            "one",
            first.generation,
            a.token,
            [1; 16],
            &Owner::core_author(&first)
                .unwrap()
                .append_paragraph("delete this"),
        )
        .unwrap();
    let second = owner.open_leased("two", note).unwrap();
    let b = second.writer.unwrap();
    let mut delete = vec![0, 1];
    let mut client = a.client_id;
    while client >= 128 {
        delete.push((client as u8 & 127) | 128);
        client >>= 7;
    }
    delete.push(client as u8);
    delete.extend([1, 0, 1]); // delete a's first Item; no inserted structs
    owner
        .commit_leased("two", second.generation, b.token, [2; 16], &delete)
        .unwrap();
    let db = owner.shared_database(id).unwrap();
    let pending = db.lock().unwrap().pending_note_updates().unwrap();
    assert_eq!(pending[1].bytes, delete);
    let proof = bh_device::writers::pending_declaration(&pending[1])
        .unwrap()
        .unwrap();
    assert_eq!(
        proof.client_id(bh_event::writer::WriterScope {
            base: BASE,
            audience: [0; 32],
            note
        }),
        b.client_id
    );
    assert_ne!(a.client_id, b.client_id);
    let mut durable = Note::new();
    durable.apply_update(&second.state).unwrap();
    durable.apply_writer_update(&delete, b.client_id).unwrap();
    assert_eq!(durable.writer_end(b.client_id), Some(0));
}
fn var(mut n: u64, out: &mut Vec<u8>) {
    while n >= 128 {
        out.push((n as u8 & 127) | 128);
        n >>= 7;
    }
    out.push(n as u8);
}
fn key(note: [u8; 32]) -> NoteKey {
    NoteKey {
        base: BASE,
        audience: [0; 32],
        note,
    }
}
#[test]
fn pending_prefix_is_kept_unleased_until_its_dependency_arrives() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, cap, note) = setup(dir.path());
    let first = owner.open_leased("one", note).unwrap();
    let c = first.writer.unwrap().client_id;
    owner.close_generation("one", first.generation);
    // c:0 inserts "b" after 1:2, which has not arrived on this device yet.
    let mut pending = vec![1, 1];
    var(c, &mut pending);
    pending.extend([0, 132, 1, 2, 1, 98, 0]);
    let db = owner.shared_database(id).unwrap();
    db.lock()
        .unwrap()
        .apply_local_update(key(note), [9; 16], &pending)
        .unwrap();
    let waiting = owner.open_leased("one", note).unwrap();
    let other = waiting.writer.unwrap();
    assert_ne!(other.client_id, c);
    let mut author = Owner::core_author(&waiting).unwrap();
    owner
        .commit_leased(
            "one",
            waiting.generation,
            other.token,
            [1; 16],
            &author.append_paragraph("meanwhile"),
        )
        .unwrap();
    let slots = db
        .lock()
        .unwrap()
        .writer_slots(key(note), cap.account_id().0, cap.device_id().0)
        .unwrap();
    assert!(!slots[0].retired, "pending work must not burn its writer");
    owner.close_generation("one", waiting.generation);

    // Writer 1's "abc" in root text t, ending at the missing origin 1:2.
    db.lock()
        .unwrap()
        .apply_local_update(
            key(note),
            [8; 16],
            &[1, 1, 1, 0, 4, 1, 1, 116, 3, 97, 98, 99, 0],
        )
        .unwrap();
    let resumed = owner.open_leased("one", note).unwrap();
    let lease = resumed.writer.unwrap();
    assert_eq!(lease.client_id, c);
    let mut author = Owner::core_author(&resumed).unwrap();
    let next = author.append_paragraph("after");
    owner
        .commit_leased("one", resumed.generation, lease.token, [2; 16], &next)
        .unwrap();
    let mut durable = Note::new();
    durable
        .apply_update(&owner.open_leased("two", note).unwrap().state)
        .unwrap();
    assert_eq!(durable.writer_end(c), Some(8)); // b, element, text, "after"
}
#[test]
fn leased_saves_reach_the_terminal_clock_then_continue_on_a_new_slot() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, cap, note) = setup(dir.path());
    let opened = owner.open_leased("one", note).unwrap();
    let lease = opened.writer.unwrap();
    let c = lease.client_id;
    let save = |request: u8, bytes: &[u8]| {
        owner.commit_leased("one", opened.generation, lease.token, [request; 16], bytes)
    };
    // Real leased progress: c's run 0..MAX-2 as one GC struct.
    let mut bulk = vec![1, 1];
    var(c, &mut bulk);
    bulk.push(0);
    bulk.push(0);
    var(u64::from(u32::MAX - 2), &mut bulk);
    bulk.push(0);
    save(1, &bulk).unwrap();
    let mut author = Owner::core_author(&opened).unwrap();
    author.apply_update(&bulk).unwrap();
    // A three-clock paragraph does not fit; it is refused before authoring.
    let before = author.state();
    assert!(author.try_append_paragraph("a").is_err());
    assert_eq!(author.state(), before);
    let penultimate = author.try_append_paragraph("").unwrap(); // to MAX-1
    save(2, &penultimate).unwrap();
    // The next one-clock operation ends exactly at u32::MAX.
    let last = author.try_append_paragraph("").unwrap();
    save(3, &last).unwrap();
    assert!(author.try_append_paragraph("").is_err());
    // The live writer has no capacity left: nothing more under it, not even a
    // delete, but its exact terminal request still has its receipt.
    assert!(save(5, &[0, 0]).is_err());
    assert!(save(3, &last).unwrap().0.replayed);
    owner.close_generation("one", opened.generation);

    let next = owner.open_leased("one", note).unwrap();
    let d = next.writer.unwrap();
    assert_ne!(d.client_id, c);
    let db = owner.shared_database(id).unwrap();
    let slots = db
        .lock()
        .unwrap()
        .writer_slots(key(note), cap.account_id().0, cap.device_id().0)
        .unwrap();
    assert_eq!(
        slots
            .iter()
            .map(|s| (s.slot, s.retired))
            .collect::<Vec<_>>(),
        [(0, true), (1, false)]
    );
    let mut continued = Owner::core_author(&next).unwrap();
    assert_eq!(continued.writer_end(c), Some(u32::MAX));
    let after = continued.try_append_paragraph("after").unwrap();
    owner
        .commit_leased("one", next.generation, d.token, [4; 16], &after)
        .unwrap();
    let pending = db.lock().unwrap().pending_note_updates().unwrap();
    let proofs = pending
        .iter()
        .map(|p| {
            bh_device::writers::pending_declaration(p)
                .unwrap()
                .unwrap()
                .client_id(bh_event::writer::WriterScope {
                    base: BASE,
                    audience: [0; 32],
                    note,
                })
        })
        .collect::<Vec<_>>();
    assert_eq!(proofs, [c, c, c, d.client_id]);
    assert_eq!(
        pending.iter().map(|p| p.bytes.clone()).collect::<Vec<_>>(),
        [bulk, penultimate, last, after]
    );
}
fn bulk_to(c: u64, end: u32) -> Vec<u8> {
    let mut bulk = vec![1, 1];
    var(c, &mut bulk);
    bulk.push(0);
    bulk.push(0);
    var(u64::from(end), &mut bulk);
    bulk.push(0);
    bulk
}
#[test]
fn capacity_rollover_retires_only_the_callers_live_writer_for_a_fresh_one() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, cap, note) = setup(dir.path());
    let db = owner.shared_database(id).unwrap();
    let slots = || {
        db.lock()
            .unwrap()
            .writer_slots(key(note), cap.account_id().0, cap.device_id().0)
            .unwrap()
            .iter()
            .map(|s| (s.slot, s.retired))
            .collect::<Vec<_>>()
    };
    // Two near-end slots, both written through real leases.
    let one = owner.open_leased("one", note).unwrap();
    let two = owner.open_leased("two", note).unwrap();
    let (a, b) = (one.writer.unwrap(), two.writer.unwrap());
    let a_bulk = bulk_to(a.client_id, u32::MAX - 2);
    let b_bulk = bulk_to(b.client_id, u32::MAX - 2);
    owner
        .commit_leased("one", one.generation, a.token, [1; 16], &a_bulk)
        .unwrap();
    owner
        .commit_leased("two", two.generation, b.token, [2; 16], &b_bulk)
        .unwrap();
    // Another window's live token retires nothing and leaves both generations.
    assert!(owner.open_leased_retiring("one", note, b.token).is_err());
    owner
        .commit_leased("one", one.generation, a.token, [3; 16], &[0, 0])
        .unwrap();
    owner
        .commit_leased("two", two.generation, b.token, [4; 16], &[0, 0])
        .unwrap();
    assert_eq!(slots(), [(0, false), (1, false)]);
    owner.close_generation("two", two.generation);

    // An ordinary reopen stays stable; the replaced token is stale.
    let again = owner.open_leased("one", note).unwrap();
    let a2 = again.writer.unwrap();
    assert_eq!(a2.client_id, a.client_id);
    assert!(owner.open_leased_retiring("one", note, a.token).is_err());
    let other = owner.create_note(id).unwrap();
    assert!(owner.open_leased_retiring("one", other, a2.token).is_err());
    owner
        .commit_leased("one", again.generation, a2.token, [5; 16], &[0, 0])
        .unwrap();
    assert_eq!(slots(), [(0, false), (1, false)]);

    // A failed allocation leaves the data alone, and its retry can proceed.
    let raw = raw_db(dir.path());
    raw.execute_batch("CREATE TRIGGER fail_slot BEFORE INSERT ON note_writer_slots BEGIN SELECT RAISE(ABORT,'disk'); END;").unwrap();
    assert!(owner.open_leased_retiring("one", note, a2.token).is_err());
    raw.execute_batch("DROP TRIGGER fail_slot;").unwrap();
    assert_eq!(slots().len(), 2);

    // The caller's own slot retires; the idle near-end slot 1 is not offered.
    let fresh = owner.open_leased_retiring("one", note, a2.token).unwrap();
    let f = fresh.writer.unwrap();
    assert!(![a.client_id, b.client_id].contains(&f.client_id));
    assert_eq!(slots(), [(0, true), (1, false), (2, false)]);
    let mut author = Owner::core_author(&fresh).unwrap();
    assert_eq!(author.writer_end(f.client_id), Some(0));
    let ab = author.try_append_paragraph("ab").unwrap();
    owner
        .commit_leased("one", fresh.generation, f.token, [6; 16], &ab)
        .unwrap();
    assert!(
        owner
            .commit_leased("one", again.generation, a2.token, [7; 16], &[0, 0])
            .is_err()
    );
    assert!(owner.open_leased_retiring("one", note, a2.token).is_err());
    assert_eq!(slots().len(), 3);

    // Original proofs and bytes stay retrievable after retirement.
    let pending = db.lock().unwrap().pending_note_updates().unwrap();
    let scope = bh_event::writer::WriterScope {
        base: BASE,
        audience: [0; 32],
        note,
    };
    let proofs = pending
        .iter()
        .map(|p| {
            bh_device::writers::pending_declaration(p)
                .unwrap()
                .unwrap()
                .client_id(scope)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        proofs,
        [
            a.client_id,
            b.client_id,
            a.client_id,
            b.client_id,
            a.client_id,
            f.client_id
        ]
    );
    assert_eq!(pending[0].bytes, a_bulk);
    assert_eq!(pending[5].bytes, ab);

    // A writer whose terminal save already ended its lease reopens normally.
    let spent = owner.open_leased("two", note).unwrap();
    let s = spent.writer.unwrap();
    assert_eq!(s.client_id, b.client_id);
    let mut last = Owner::core_author(&spent).unwrap();
    for request in [8, 9] {
        let bytes = last.try_append_paragraph("").unwrap();
        owner
            .commit_leased("two", spent.generation, s.token, [request; 16], &bytes)
            .unwrap();
    }
    assert!(owner.open_leased_retiring("two", note, s.token).is_err());
    assert_eq!(slots(), [(0, true), (1, false), (2, false)]);
    let reopened = owner.open_leased("two", note).unwrap();
    assert!(![a.client_id, b.client_id, f.client_id].contains(&reopened.writer.unwrap().client_id));
    assert_eq!(slots(), [(0, true), (1, true), (2, false), (3, false)]);
}
#[test]
fn leased_save_titles_its_note_in_the_same_commit_without_list_document_reads() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, _cap, note) = setup(dir.path());
    let db = owner.shared_database(id).unwrap();
    let pool = db.lock().unwrap().read_pool().unwrap();
    let listed = || {
        let before = pool.replayed_rows();
        let rows = owner.list_notes(id, None, 50).unwrap();
        assert_eq!(pool.replayed_rows(), before, "listing loads no note");
        rows
    };
    let pending = || db.lock().unwrap().pending_note_updates().unwrap().len();
    let one = owner.open_leased("one", note).unwrap();
    let a = one.writer.unwrap();
    let mut author = Owner::core_author(&one).unwrap();
    let first = author.try_append_paragraph(" <b>First</b> title ").unwrap();
    let untitled = listed();
    assert_eq!(untitled[0].title, "");

    // A failed COMMIT leaves the prior title and no delta.
    let raw = raw_db(dir.path());
    raw.execute_batch("CREATE TRIGGER fail_title BEFORE UPDATE OF title ON notes BEGIN SELECT RAISE(ABORT,'disk'); END;").unwrap();
    assert!(
        owner
            .commit_leased("one", one.generation, a.token, [1; 16], &first)
            .is_err()
    );
    assert_eq!(listed(), untitled);
    assert_eq!(pending(), 0);
    raw.execute_batch("DROP TRIGGER fail_title;").unwrap();

    owner
        .commit_leased("one", one.generation, a.token, [1; 16], &first)
        .unwrap();
    let titled = listed();
    assert_eq!(titled[0].title, "<b>First</b> title");
    assert!(titled[0].touched > untitled[0].touched);
    assert_eq!(pending(), 1);
    // The exact retry is the same commit: no touch, title or second delta.
    assert!(
        owner
            .commit_leased("one", one.generation, a.token, [1; 16], &first)
            .unwrap()
            .0
            .replayed
    );
    assert_eq!(listed(), titled);
    assert_eq!(pending(), 1);
    // A later block leaves the title; the commit still touches the note.
    let later = author.try_append_paragraph("later").unwrap();
    owner
        .commit_leased("one", one.generation, a.token, [2; 16], &later)
        .unwrap();
    let touched = listed();
    assert_eq!(touched[0].title, "<b>First</b> title");
    assert!(touched[0].touched > titled[0].touched);
}
fn raw_db(path: &std::path::Path) -> rusqlite::Connection {
    let path = std::fs::read_dir(path.join("accounts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "sqlite"))
        .unwrap();
    rusqlite::Connection::open(path).unwrap()
}
struct Projection(std::sync::Mutex<BindingRead>);
impl AcceptedBindings for Projection {
    fn binding(
        &self,
        _db: &DeviceDatabase,
        _key: NoteKey,
        id: u64,
    ) -> Result<BindingRead, WriterUnavailable> {
        let mut read = *self.0.lock().unwrap();
        read.binding = read.binding.filter(|b| b.client_id == id);
        Ok(read)
    }
}
#[test]
fn revision_change_during_an_attempt_refuses_it_and_identical_retry_uses_the_current_revision() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, _cap, note) = setup(dir.path());
    raw_db(dir.path())
        .execute("UPDATE base_writer_phase SET phase=1", [])
        .unwrap();
    let reader = Arc::new(Projection(std::sync::Mutex::new(BindingRead {
        revision: 1,
        binding: None,
    })));
    owner.install_binding_reader(id, reader.clone());
    let opened = owner.open_leased("one", note).unwrap();
    let lease = opened.writer.unwrap();
    let mut author = Owner::core_author(&opened).unwrap();
    let first = author.append_paragraph("first");
    owner
        .commit_leased("one", opened.generation, lease.token, [1; 16], &first)
        .unwrap();
    let second = author.append_paragraph("retained");
    assert!(
        owner
            .commit_leased_with_work_hook(
                "one",
                opened.generation,
                lease.token,
                [2; 16],
                &second,
                || reader.0.lock().unwrap().revision = 2
            )
            .is_err()
    );
    let db = owner.shared_database(id).unwrap();
    let pending = db.lock().unwrap().pending_note_updates().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].bytes, first);
    assert!(
        owner
            .commit_leased("one", opened.generation, lease.token, [1; 16], &first)
            .unwrap()
            .0
            .replayed
    );
    owner
        .commit_leased("one", opened.generation, lease.token, [2; 16], &second)
        .unwrap();
    let pending = db.lock().unwrap().pending_note_updates().unwrap();
    assert_eq!(pending[1].bytes, second);
}
#[test]
fn benign_binding_changes_between_saves_keep_the_live_writer() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, cap, note) = setup(dir.path());
    let opened = owner.open_leased("one", note).unwrap();
    let lease = opened.writer.unwrap();
    let mut author = Owner::core_author(&opened).unwrap();
    let save = |request: u8, bytes: &[u8]| {
        owner.commit_leased("one", opened.generation, lease.token, [request; 16], bytes)
    };
    save(1, &author.append_paragraph("unregistered")).unwrap();
    // Registration lands while the window stays open: verified absent first.
    raw_db(dir.path())
        .execute("UPDATE base_writer_phase SET phase=1", [])
        .unwrap();
    let reader = Arc::new(Projection(std::sync::Mutex::new(BindingRead {
        revision: 1,
        binding: None,
    })));
    owner.install_binding_reader(id, reader.clone());
    save(2, &author.append_paragraph("registered")).unwrap();
    // Our own first event is acknowledged, then another binding in this note.
    let slot = owner
        .shared_database(id)
        .unwrap()
        .lock()
        .unwrap()
        .writer_slots(key(note), cap.account_id().0, cap.device_id().0)
        .unwrap()[0];
    let own = bh_device::writers::VerifiedWriterBinding {
        account: slot.account,
        device: slot.device,
        nonce: slot.nonce,
        client_id: slot.client_id,
        accepted_end: 14,
    };
    *reader.0.lock().unwrap() = BindingRead {
        revision: 2,
        binding: Some(own),
    };
    save(3, &author.append_paragraph("acknowledged")).unwrap();
    reader.0.lock().unwrap().revision = 3;
    save(4, &author.append_paragraph("another binding")).unwrap();
    let db = owner.shared_database(id).unwrap();
    assert_eq!(db.lock().unwrap().pending_note_updates().unwrap().len(), 4);
}
#[test]
fn conflicting_binding_for_used_writer_pauses_the_note_across_reopens_and_live_windows() {
    for principal in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (owner, id, _account, cap, note) = setup(dir.path());
        let one = owner.open_leased("one", note).unwrap();
        let a = one.writer.unwrap();
        let work = Owner::core_author(&one).unwrap().append_paragraph("work");
        owner
            .commit_leased("one", one.generation, a.token, [1; 16], &work)
            .unwrap();
        let two = owner.open_leased("two", note).unwrap();
        let b = two.writer.unwrap();
        let mut other = Owner::core_author(&two).unwrap();
        let db = owner.shared_database(id).unwrap();
        let slot = db
            .lock()
            .unwrap()
            .writer_slots(key(note), cap.account_id().0, cap.device_id().0)
            .unwrap()[0];
        assert_eq!(slot.client_id, a.client_id);
        // Accepted state assigns our used ID to another principal or nonce.
        let conflict = bh_device::writers::VerifiedWriterBinding {
            account: if principal { [9; 32] } else { slot.account },
            device: slot.device,
            nonce: if principal { slot.nonce } else { [9; 32] },
            client_id: slot.client_id,
            accepted_end: 0,
        };
        raw_db(dir.path())
            .execute("UPDATE base_writer_phase SET phase=1", [])
            .unwrap();
        owner.install_binding_reader(
            id,
            Arc::new(Projection(std::sync::Mutex::new(BindingRead {
                revision: 1,
                binding: Some(conflict),
            }))),
        );
        // The other live window's slot is verified absent, but the note is not
        // safe to extend: its parents may be the conflicting structs.
        assert!(
            owner
                .commit_leased(
                    "two",
                    two.generation,
                    b.token,
                    [2; 16],
                    &other.append_paragraph("refused")
                )
                .is_err()
        );
        owner.close_generation("one", one.generation);
        owner.close_generation("two", two.generation);
        assert!(owner.open_leased("one", note).is_err());
        assert!(owner.open_leased("one", note).is_err());
        // Retiring the reservation must not erase the refusal either.
        owner.retire_restored_writers(id, key(note)).unwrap();
        assert!(owner.open_leased("two", note).is_err());
        let pending = db.lock().unwrap().pending_note_updates().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].bytes, work);
        assert_eq!(
            bh_device::writers::pending_declaration(&pending[0])
                .unwrap()
                .unwrap()
                .nonce,
            slot.nonce
        );
    }
}
#[test]
fn accepted_end_requires_durable_prefix_and_local_save_does_not_advance_it() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, cap, note) = setup(dir.path());
    let opened = owner.open_leased("one", note).unwrap();
    let lease = opened.writer.unwrap();
    let mut author = Owner::core_author(&opened).unwrap();
    owner
        .commit_leased(
            "one",
            opened.generation,
            lease.token,
            [1; 16],
            &author.append_paragraph("hi"),
        )
        .unwrap();
    let key = NoteKey {
        base: BASE,
        audience: [0; 32],
        note,
    };
    let db = owner.shared_database(id).unwrap();
    let slot = db
        .lock()
        .unwrap()
        .writer_slots(key, cap.account_id().0, cap.device_id().0)
        .unwrap()[0];
    owner.close_generation("one", opened.generation);
    raw_db(dir.path())
        .execute("UPDATE base_writer_phase SET phase=1", [])
        .unwrap();
    let binding = bh_device::writers::VerifiedWriterBinding {
        account: slot.account,
        device: slot.device,
        nonce: slot.nonce,
        client_id: slot.client_id,
        accepted_end: 4,
    };
    let reader = Arc::new(Projection(std::sync::Mutex::new(BindingRead {
        revision: 1,
        binding: Some(binding),
    })));
    owner.install_binding_reader(id, reader.clone());
    let reuse = owner.open_leased("one", note).unwrap();
    assert_eq!(reuse.writer.unwrap().client_id, lease.client_id);
    let mut core = Owner::core_author(&reuse).unwrap();
    owner
        .commit_leased(
            "one",
            reuse.generation,
            reuse.writer.unwrap().token,
            [2; 16],
            &core.append_paragraph("next"),
        )
        .unwrap();
    assert_eq!(reader.0.lock().unwrap().binding.unwrap().accepted_end, 4);
    owner.close_generation("one", reuse.generation);
    reader
        .0
        .lock()
        .unwrap()
        .binding
        .as_mut()
        .unwrap()
        .accepted_end = 11; // durable end is 10
    let fresh = owner.open_leased("one", note).unwrap();
    assert_ne!(fresh.writer.unwrap().client_id, lease.client_id);
    assert_eq!(db.lock().unwrap().pending_note_updates().unwrap().len(), 2);
}
#[test]
fn recognized_restore_retires_lineage_without_changing_pending_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, _cap, note) = setup(dir.path());
    let opened = owner.open_leased("one", note).unwrap();
    let lease = opened.writer.unwrap();
    let mut author = Owner::core_author(&opened).unwrap();
    let bytes = author.append_paragraph("keep original");
    owner
        .commit_leased("one", opened.generation, lease.token, [1; 16], &bytes)
        .unwrap();
    let key = NoteKey {
        base: BASE,
        audience: [0; 32],
        note,
    };
    owner.retire_restored_writers(id, key).unwrap();
    assert!(
        owner
            .commit_leased(
                "one",
                opened.generation,
                lease.token,
                [2; 16],
                &author.append_paragraph("stale")
            )
            .is_err()
    );
    let next = owner.open_leased("one", note).unwrap();
    assert_ne!(next.writer.unwrap().client_id, lease.client_id);
    let db = owner.shared_database(id).unwrap();
    let pending = db.lock().unwrap().pending_note_updates().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].bytes, bytes);
    assert_eq!(
        bh_device::writers::pending_declaration(&pending[0])
            .unwrap()
            .unwrap()
            .client_id(bh_event::writer::WriterScope {
                base: BASE,
                audience: [0; 32],
                note
            }),
        lease.client_id
    );
}
#[test]
fn real_prehost_genesis_first_note_reopens_same_nonce_and_id_with_fresh_token() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Owner::default();
    let id = owner.create_container(dir.path()).unwrap();
    let db = owner.shared_database(id).unwrap();
    let generation = AccountGeneration::new();
    let keys = store::FakeStore::new(generation.clone());
    let mut account = Account::new(
        DeviceJournal::from_shared(db.clone()),
        keys.clone(),
        protector::PlainProtector,
        generation.clone(),
    );
    let status = ready(account.begin_first_device(
        ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        &Password::new("correct horse battery staple").unwrap(),
    ))
    .unwrap();
    account.confirm_home_ordered(status.head).unwrap();
    account.confirm_kit_saved().unwrap();
    let cap = match ready(account.activate()).unwrap() {
        AccountLoad::Active(c) => Arc::new(c),
        _ => panic!(),
    };
    let record = DeviceJournal::from_shared(db.clone())
        .load()
        .unwrap()
        .unwrap();
    let history = record.history.iter().map(Vec::as_slice).collect::<Vec<_>>();
    let proof = VerifiedAccount::replay(record.anchor, &history, record.head).unwrap();
    owner.anchor(id, &proof).unwrap();
    let own = ready(bh_device::own_base::create_or_open(
        &mut account,
        cap.clone(),
        db.clone(),
    ))
    .unwrap();
    let base = own.id().0;
    owner.authorize(id, cap.clone(), base).unwrap();
    let note = owner.create_note(id).unwrap();
    owner.show_note("one", id, note).unwrap();
    let opened = owner.open_leased("one", note).unwrap();
    let lease = opened.writer.unwrap();
    let bytes = Owner::core_author(&opened)
        .unwrap()
        .append_paragraph("durable before hosting");
    owner
        .commit_leased("one", opened.generation, lease.token, [1; 16], &bytes)
        .unwrap();
    let original = bh_device::writers::pending_declaration(
        &db.lock().unwrap().pending_note_updates().unwrap()[0],
    )
    .unwrap()
    .unwrap();
    drop(own);
    drop(cap);
    drop(account);
    drop(db);
    drop(owner);
    let owner = Owner::default();
    // Same-process restart waits for the old owner's asynchronous compaction
    // workers to release their file lock. An actual process exit drops them.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let id = loop {
        match owner.open_containers(dir.path()).unwrap().pop().unwrap().1 {
            Ok(id) => break id,
            Err(bh_device::OwnerError::Busy) if std::time::Instant::now() < deadline => {
                std::thread::yield_now()
            }
            Err(e) => panic!("restart: {e:?}"),
        }
    };
    let db = owner.shared_database(id).unwrap();
    let mut account = Account::new(
        DeviceJournal::from_shared(db.clone()),
        keys,
        protector::PlainProtector,
        generation,
    );
    let cap = match ready(account.activate()).unwrap() {
        AccountLoad::Active(c) => Arc::new(c),
        _ => panic!(),
    };
    owner.anchor(id, &proof).unwrap();
    owner.authorize(id, cap, base).unwrap();
    owner.show_note("one", id, note).unwrap();
    let reopened = owner.open_leased("one", note).unwrap();
    assert_eq!(reopened.writer.unwrap().client_id, lease.client_id);
    assert_ne!(reopened.writer.unwrap().token, lease.token);
    assert_eq!(
        original,
        bh_device::writers::pending_declaration(
            &db.lock().unwrap().pending_note_updates().unwrap()[0]
        )
        .unwrap()
        .unwrap()
    );
    assert_eq!(reopened.state, opened_state(&bytes));
}
fn opened_state(bytes: &[u8]) -> Vec<u8> {
    let mut n = Note::new();
    n.apply_update(bytes).unwrap();
    n.state()
}
struct Unavailable;
impl AcceptedBindings for Unavailable {
    fn binding(
        &self,
        _db: &DeviceDatabase,
        _key: NoteKey,
        _id: u64,
    ) -> Result<BindingRead, WriterUnavailable> {
        Err(WriterUnavailable)
    }
}
#[test]
fn missing_phase_and_registered_without_producer_never_fall_back() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, id, _account, _cap, note) = setup(dir.path());
    let path = std::fs::read_dir(dir.path().join("accounts"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|x| x == "sqlite"))
        .unwrap();
    let raw = rusqlite::Connection::open(path).unwrap();
    raw.execute("DELETE FROM base_writer_phase", []).unwrap();
    assert!(owner.open_leased("one", note).is_err());
    raw.execute(
        "INSERT INTO base_writer_phase(base,phase) VALUES (?1,1)",
        [BASE],
    )
    .unwrap();
    assert!(owner.open_leased("one", note).is_err());
    owner.install_binding_reader(id, Arc::new(Unavailable));
    assert!(owner.open_leased("one", note).is_err());
}
