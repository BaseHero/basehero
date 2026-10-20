//! A note's pending keystrokes publish as runs: each package covers the
//! contiguous updates one writer made since the note's previous package,
//! merged into one update, and is keyed by the run's last update. Test-only
//! identities and keys.
use bh_account::{AccountId, DeviceId, Head as AccountHead};
use bh_crypto::{Secret, SigningKey};
use bh_event::{Binding, CLASS_CONTENT, NOTE, Payload, key_id, seal};
use bh_storage::{
    DeviceDatabase, NoteKey, PackagePreparation, StoreError, StoredNotePackage,
    note_writers::WriterSlot,
    own_base::OwnBaseRecord,
    sync_state::{IncomingCommit, LOG_BASE, OwnOutcome, PackageOutcome, SeenRow, VerifiedRecord},
};
use bh_sync::{BaseId, BodyObject, Commitment, Digest, EventId, Head, OpaqueEvent, Route};
use yrs::{Text, Transact, WriteTxn, XmlElementPrelim, XmlFragment, XmlTextPrelim};

const ACCOUNT: [u8; 32] = [1; 32];
const BASE: [u8; 32] = [2; 32];

fn key(note: u8) -> NoteKey {
    NoteKey {
        base: BASE,
        audience: [0; 32],
        note: [note; 32],
    }
}
fn slot(note: u8, slot: u32, client_id: u64) -> WriterSlot {
    WriterSlot {
        key: key(note),
        account: ACCOUNT,
        device: [4; 32],
        slot,
        nonce: [slot as u8 + 5; 32],
        client_id,
        retired: false,
    }
}

fn open(path: &std::path::Path) -> DeviceDatabase {
    let mut db = DeviceDatabase::open(path).unwrap();
    if db.own_base().unwrap().is_none() {
        db.commit_account_verified(ACCOUNT, &[b"original"], 1, [6; 32], false)
            .unwrap();
        db.create_own_base_if_absent(
            &OwnBaseRecord {
                account: ACCOUNT,
                base: BASE,
                genesis_descriptor: vec![1],
                genesis_body: vec![2],
                initial_key_package: vec![3],
            },
            || true,
        )
        .unwrap();
        db.record_registration(BASE, None, [7; 32]).unwrap();
        rusqlite::Connection::open(path).unwrap().execute(
            "UPDATE log_progress SET position=1,account_position=1,account_hash=zeroblob(32),metadata_id=zeroblob(32)", [],
        ).unwrap();
    }
    db
}

/// One writer typing into its own paragraph, a keystroke per update.
struct Keyboard {
    doc: yrs::Doc,
    text: yrs::XmlTextRef,
    slot: WriterSlot,
    requests: u8,
}
impl Keyboard {
    fn new(db: &mut DeviceDatabase, slot: WriterSlot) -> Self {
        db.insert_writer_slot(&slot).unwrap();
        let doc = yrs::Doc::with_client_id(slot.client_id);
        let text = {
            let mut txn = doc.transact_mut();
            let fragment = txn.get_or_insert_xml_fragment(bh_core::note::FRAGMENT);
            let paragraph = fragment.insert(&mut txn, 0, XmlElementPrelim::empty("paragraph"));
            paragraph.insert(&mut txn, 0, XmlTextPrelim::new(""))
        };
        Self {
            doc,
            text,
            slot,
            requests: slot.slot as u8 * 100,
        }
    }
    /// Commit `typed` as one update; its bytes and update id.
    fn key(&mut self, db: &mut DeviceDatabase, typed: &str) -> (Vec<u8>, i64) {
        let bytes = {
            let mut txn = self.doc.transact_mut();
            let end = self.text.len(&txn);
            self.text.insert(&mut txn, end, typed);
            txn.encode_update_v1()
        };
        let id = self.commit(db, &bytes);
        (bytes, id)
    }
    fn commit(&mut self, db: &mut DeviceDatabase, bytes: &[u8]) -> i64 {
        self.requests += 1;
        let frontier = db.local_frontier(self.slot.key).unwrap();
        let commit = db
            .commit_writer_update(frontier, ACCOUNT, [self.requests; 16], bytes, &self.slot)
            .unwrap();
        assert!(!commit.replayed);
        commit.update_id
    }
}

fn sealed(key: NoteKey, id: EventId, delta: &[u8]) -> (OpaqueEvent, BodyObject) {
    let metadata = Secret::from_slice(&[4; 32]).unwrap();
    let content = Secret::from_slice(&[5; 32]).unwrap();
    let mut data = key.note.to_vec();
    data.extend(delta);
    let encoded = seal(
        Binding {
            version: 2,
            highest: 2,
            mode: 0,
            base: key.base,
            audience: key.audience,
            epoch: key_id(&content),
            event_id: id,
            account: AccountId(ACCOUNT),
            device: DeviceId([4; 32]),
            account_head: AccountHead {
                position: 0,
                hash: [0; 32],
            },
            seen: Head::EMPTY,
            seen_control: [0; 32],
            class: CLASS_CONTENT,
            padded: 0,
            commitment: [0; 32],
            seen_receipt: [0; bh_sync::receipt::RECEIPT_LEN],
        },
        Payload {
            kind: NOTE,
            data: &data,
        },
        &SigningKey::generate(),
        &metadata,
        Some(&content),
    )
    .unwrap();
    (encoded.descriptor, BodyObject::new(encoded.body).unwrap())
}

/// Seal the note's next run as the publisher does: its head, prepared, then
/// persisted. Returns the update the package is keyed by and its bytes.
fn seal_next(db: &mut DeviceDatabase, note: u8) -> (i64, Vec<u8>, StoredNotePackage) {
    let head = db
        .outbox_heads(0, 256)
        .unwrap()
        .into_iter()
        .find(|h| h.key == key(note))
        .expect("the note has a head");
    match db.prepare_note_package(head.update_id).unwrap() {
        PackagePreparation::Existing(_) => panic!("the head has no package yet"),
        PackagePreparation::Candidate(candidate) => {
            let id = candidate.pending.update_id;
            let bytes = candidate.pending.bytes.clone();
            let (descriptor, body) = sealed(key(note), candidate.event_id, &bytes);
            let stored = db
                .publish_note_package(candidate, descriptor, body)
                .unwrap();
            (id, bytes, stored)
        }
    }
}

fn heads(db: &DeviceDatabase) -> Vec<(u8, i64)> {
    db.outbox_heads(0, 256)
        .unwrap()
        .into_iter()
        .map(|h| (h.key.note[0], h.update_id))
        .collect()
}

/// The package ordered at `position`, after the log's current head.
fn ordered(db: &DeviceDatabase, stored: &StoredNotePackage, position: u64) -> Commitment {
    let progress = db.log_progress(LOG_BASE, BASE).unwrap().unwrap();
    assert_eq!(progress.position + 1, position);
    Commitment::order(
        BaseId(BASE),
        Head {
            position: progress.position,
            hash: Digest(progress.head_hash),
        },
        &stored.descriptor,
        Route::Content,
    )
    .unwrap()
}

/// Commit the verified echo of `stored` with this outcome.
fn echo(
    db: &mut DeviceDatabase,
    update_id: i64,
    stored: &StoredNotePackage,
    outcome: PackageOutcome,
) {
    let progress = db.log_progress(LOG_BASE, BASE).unwrap().unwrap();
    let position = progress.position + 1;
    let ordered = ordered(db, stored, position);
    db.commit_incoming(
        &IncomingCommit {
            log_kind: LOG_BASE,
            log_id: BASE,
            hosting_root: [7; 32],
            after: (progress.position, progress.head_hash),
            receipt: [0; bh_sync::receipt::RECEIPT_LEN],
            records: vec![VerifiedRecord {
                seen: SeenRow {
                    position,
                    head_hash: ordered.head().hash.0,
                    control_digest: [0; 32],
                    account_position: 1,
                    account_hash: [0; 32],
                },
                event_id: stored.event_id.0,
                digest: [9; 32],
                account_change: None,
                judged_floor: 1,
                floor: 1,
            }],
            metadata_id: [0; 32],
            epoch_id: None,
            notes: Vec::new(),
            own: vec![OwnOutcome {
                update_id,
                ordered,
                outcome,
                publishing_stopped: false,
            }],
            held: Vec::new(),
        },
        |_| Ok(()),
    )
    .unwrap();
}

#[test]
fn a_notes_typed_run_seals_once_as_one_merged_package_keyed_by_its_last_update() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("runs.sqlite");
    let mut db = open(&path);
    let mut keyboard = Keyboard::new(&mut db, slot(3, 0, 42));
    let typed: Vec<(Vec<u8>, i64)> = "Hi, t"
        .chars()
        .map(|c| keyboard.key(&mut db, &c.to_string()))
        .collect();
    assert!(typed[0].1 < typed[4].1);
    let last = typed[4].1;
    assert_eq!(heads(&db), vec![(3, last)]);

    let (id, bytes, stored) = seal_next(&mut db, 3);
    assert_eq!(id, last, "keyed by the run's last update");
    let parts: Vec<Vec<u8>> = typed.iter().map(|(b, _)| b.clone()).collect();
    assert_eq!(bytes, bh_core::note::merge_updates(&parts).unwrap());

    // The package now stands for the run: its head is the package, and every
    // covered update finds the same exact bytes, also after a reopen (a
    // crash between sealing and sending).
    assert_eq!(heads(&db), vec![(3, last)]);
    drop(db);
    let mut db = open(&path);
    for (_, update) in &typed {
        match db.prepare_note_package(*update).unwrap() {
            PackagePreparation::Existing(existing) => {
                assert_eq!(existing.descriptor.encode(), stored.descriptor.encode());
                assert_eq!(existing.body, stored.body);
            }
            PackagePreparation::Candidate(_) => panic!("a covered update is never sealed again"),
        }
    }

    // Keystrokes made while it is in flight wait for its Ack, then form the
    // next run on their own.
    let more: Vec<i64> = "his"
        .chars()
        .map(|c| keyboard.key(&mut db, &c.to_string()).1)
        .collect();
    assert_eq!(
        heads(&db),
        vec![(3, last)],
        "one package per note in flight"
    );
    let ack = ordered(&db, &stored, 2);
    assert!(db.acknowledge_note_update(last, &ack).unwrap());
    assert_eq!(heads(&db), vec![(3, more[2])]);
    let (next, _, _) = seal_next(&mut db, 3);
    assert_eq!(next, more[2]);
    assert_eq!(db.pending_count(key(3)).unwrap(), 8);
}

#[test]
fn a_run_stops_at_a_writer_change_and_at_its_size_bound() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir.path().join("bounds.sqlite"));
    let mut first = Keyboard::new(&mut db, slot(3, 0, 42));
    let a = first.key(&mut db, "a").1;
    let b = first.key(&mut db, "b").1;
    // The writer changed (its slot was retired and another taken).
    let mut second = Keyboard::new(&mut db, slot(3, 1, 43));
    let c = second.key(&mut db, "c").1;
    let d = second.key(&mut db, "d").1;
    assert_eq!(heads(&db), vec![(3, b)]);
    assert!(a < b);
    let (id, _, stored) = seal_next(&mut db, 3);
    assert_eq!(id, b);
    let ack = ordered(&db, &stored, 2);
    db.acknowledge_note_update(b, &ack).unwrap();
    assert_eq!(heads(&db), vec![(3, d)]);
    assert!(c < d);
    assert_eq!(seal_next(&mut db, 3).0, d);

    // Large updates: a run takes what fits in its bound, and one update
    // larger than the bound is a run of its own.
    let mut big = Keyboard::new(&mut db, slot(4, 0, 44));
    let chunk = "x".repeat(100 * 1024);
    let ids: Vec<i64> = (0..3).map(|_| big.key(&mut db, &chunk).1).collect();
    let huge = big.key(&mut db, &"y".repeat(300 * 1024)).1;
    let (id, bytes, stored) = seal_next(&mut db, 4);
    assert_eq!(id, ids[1], "two of three fit");
    assert!(bytes.len() < 256 * 1024);
    let position = db.log_progress(LOG_BASE, BASE).unwrap().unwrap().position + 1;
    let ack = ordered(&db, &stored, position);
    db.acknowledge_note_update(id, &ack).unwrap();
    assert_eq!(seal_next(&mut db, 4).0, ids[2]);
    let pending = db
        .unaccepted_packages(key(4), 0, 256)
        .unwrap()
        .into_iter()
        .filter(|p| !p.packaged)
        .map(|p| p.update_id)
        .collect::<Vec<_>>();
    assert_eq!(pending, vec![huge]);
}

#[test]
fn an_accepted_echo_retires_the_whole_run_and_its_outcome_covers_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir.path().join("retire.sqlite"));
    let mut keyboard = Keyboard::new(&mut db, slot(3, 0, 42));
    let ids: Vec<i64> = "abc"
        .chars()
        .map(|c| keyboard.key(&mut db, &c.to_string()).1)
        .collect();
    let (id, _, stored) = seal_next(&mut db, 3);
    let later = keyboard.key(&mut db, "d").1;

    // While it waits, each covered update reports its package's state.
    let states = db.unaccepted_packages(key(3), 0, 256).unwrap();
    assert_eq!(states.len(), 4);
    assert!(
        states[..3]
            .iter()
            .all(|p| p.packaged && p.outcome.is_none())
    );
    assert!(!states[3].packaged);
    let summary = db.outbox_summary().unwrap();
    assert_eq!((summary.unaccepted, summary.unaccepted_notes), (4, 1));

    let ack = ordered(&db, &stored, 2);
    db.acknowledge_note_update(id, &ack).unwrap();
    let states = db.unaccepted_packages(key(3), 0, 256).unwrap();
    assert!(
        states[..3]
            .iter()
            .all(|p| p.outcome == Some(PackageOutcome::Acked) && p.position == Some(2))
    );
    assert_eq!(
        db.package_progress(ids[0]).unwrap().unwrap().position,
        Some(2)
    );

    echo(&mut db, id, &stored, PackageOutcome::Accepted);
    let left: Vec<i64> = db
        .unaccepted_packages(key(3), 0, 256)
        .unwrap()
        .into_iter()
        .map(|p| p.update_id)
        .collect();
    assert_eq!(left, vec![later], "the whole run retired at once");
    assert_eq!(db.pending_count(key(3)).unwrap(), 1);
    let summary = db.outbox_summary().unwrap();
    assert_eq!((summary.unaccepted, summary.unaccepted_notes), (1, 1));
    assert_eq!(heads(&db), vec![(3, later)]);
}

#[test]
fn an_unsuccessful_run_holds_its_note_alone() {
    for outcome in [
        PackageOutcome::Rejected,
        PackageOutcome::Refused(2),
        PackageOutcome::Conflicted,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut db = open(&dir.path().join("rejected.sqlite"));
        let mut held = Keyboard::new(&mut db, slot(3, 0, 42));
        let mut other = Keyboard::new(&mut db, slot(5, 0, 45));
        for c in "abc".chars() {
            held.key(&mut db, &c.to_string());
        }
        let (id, _, stored) = seal_next(&mut db, 3);
        let after = held.key(&mut db, "d").1;
        let o = other.key(&mut db, "o").1;
        echo(&mut db, id, &stored, outcome);
        assert_eq!(
            heads(&db),
            vec![(5, o)],
            "the rejected note waits; others go on"
        );
        let states = db.unaccepted_packages(key(3), 0, 256).unwrap();
        assert_eq!(states.len(), 4, "nothing retired");
        assert!(states[..3].iter().all(|p| p.outcome == Some(outcome)));
        assert_eq!(states[3].update_id, after);
        let summary = db.outbox_summary().unwrap();
        assert_eq!(
            (summary.not_accepted_notes, summary.unaccepted_notes),
            (1, 2)
        );
    }
}

#[test]
fn replaying_a_keystroke_after_its_run_was_sealed_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir.path().join("replay.sqlite"));
    let mut keyboard = Keyboard::new(&mut db, slot(3, 0, 42));
    let (bytes, first) = keyboard.key(&mut db, "a");
    keyboard.key(&mut db, "b");
    let (id, _, _) = seal_next(&mut db, 3);
    let frontier = db.local_frontier(key(3)).unwrap();
    let replay = db
        .commit_writer_update(frontier, ACCOUNT, [1; 16], &bytes, &keyboard.slot)
        .unwrap();
    assert!(replay.replayed);
    assert_eq!(replay.update_id, first);
    assert!(matches!(
        db.commit_writer_update(frontier, ACCOUNT, [1; 16], b"other", &keyboard.slot),
        Err(StoreError::RequestConflict)
    ));
    assert_eq!(heads(&db), vec![(3, id)]);
    assert_eq!(db.pending_count(key(3)).unwrap(), 2);
}

#[test]
fn a_candidate_whose_run_was_sealed_meanwhile_returns_that_package() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = open(&dir.path().join("race.sqlite"));
    let mut keyboard = Keyboard::new(&mut db, slot(3, 0, 42));
    let first = keyboard.key(&mut db, "a").1;
    keyboard.key(&mut db, "b");
    let head = heads(&db)[0].1;
    assert!(first < head);
    let PackagePreparation::Candidate(late) = db.prepare_note_package(head).unwrap() else {
        panic!("no package yet");
    };
    let (sealed_id, _, stored) = seal_next(&mut db, 3);
    let (descriptor, body) = sealed(key(3), late.event_id, &late.pending.bytes);
    let again = db.publish_note_package(late, descriptor, body).unwrap();
    assert_eq!(again.event_id, stored.event_id);
    // A later keystroke does not change a prepared run: it seals as prepared.
    keyboard.key(&mut db, "c");
    let ack = ordered(&db, &stored, 2);
    db.acknowledge_note_update(sealed_id, &ack).unwrap();
    let head = heads(&db)[0].1;
    let PackagePreparation::Candidate(next) = db.prepare_note_package(head).unwrap() else {
        panic!("no package yet");
    };
    keyboard.key(&mut db, "d");
    let covered = next.pending.update_id;
    let (descriptor, body) = sealed(key(3), next.event_id, &next.pending.bytes);
    db.publish_note_package(next, descriptor, body).unwrap();
    assert_eq!(covered, head);
    assert_eq!(heads(&db), vec![(3, head)]);
}
