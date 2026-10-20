//! A base control (the copy of an account change) is kept byte for byte
//! before it is first sent, and only verified history settles it.
use bh_account::{AccountId, DeviceId, Head as AccountHead};
use bh_crypto::{Secret, SigningKey};
use bh_event::{Binding, CLASS_CONTENT, Encoded, NOTE, Payload, key_id, seal};
use bh_storage::{
    DeviceDatabase, StoreError,
    sync_state::{BaseControl, ControlOutcome},
};
use bh_sync::{EventId, Head};

const BASE: [u8; 32] = [1; 32];

/// Test-only sealed bytes: storage keeps them opaque and never judges them.
fn sealed(id: u8) -> Encoded {
    let metadata = Secret::from_slice(&[4; 32]).unwrap();
    let content = Secret::from_slice(&[5; 32]).unwrap();
    seal(
        Binding {
            version: 2,
            highest: 2,
            mode: 0,
            base: BASE,
            audience: [0; 32],
            epoch: key_id(&content),
            event_id: EventId([id; 32]),
            account: AccountId([6; 32]),
            device: DeviceId([7; 32]),
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
            data: &[9; 40],
        },
        &SigningKey::generate(),
        &metadata,
        Some(&content),
    )
    .unwrap()
}

fn control(position: u64, id: u8) -> BaseControl {
    let encoded = sealed(id);
    BaseControl {
        base: BASE,
        account_position: position,
        event_id: [id; 32],
        descriptor: encoded.descriptor.encode(),
        body: encoded.body,
    }
}

#[test]
fn exact_control_survives_reopen_and_is_never_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controls.db");
    let first = control(4, 0x41);
    {
        let mut db = DeviceDatabase::open(&path).unwrap();
        assert_eq!(db.pending_base_control(BASE).unwrap(), None);
        assert_eq!(db.stage_base_control(&first).unwrap(), first);
        // A second signing for the same successor never replaces the first.
        assert_eq!(db.stage_base_control(&control(4, 0x42)).unwrap(), first);
    }
    let mut db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(db.pending_base_control(BASE).unwrap(), Some(first.clone()));
    assert_eq!(db.pending_base_control([2; 32]).unwrap(), None);
    // Settled only by its own event id.
    assert!(matches!(
        db.settle_base_control(BASE, 4, [0x42; 32], ControlOutcome::Committed),
        Err(StoreError::CorruptOutbox)
    ));
    db.settle_base_control(BASE, 4, first.event_id, ControlOutcome::Committed)
        .unwrap();
    // Idempotent for the same verdict; another verdict is refused.
    db.settle_base_control(BASE, 4, first.event_id, ControlOutcome::Committed)
        .unwrap();
    assert!(matches!(
        db.settle_base_control(BASE, 4, first.event_id, ControlOutcome::Superseded),
        Err(StoreError::CorruptOutbox)
    ));
    assert_eq!(db.pending_base_control(BASE).unwrap(), None);
    assert_eq!(
        db.base_control_outcome(BASE, 4).unwrap(),
        Some(Some(ControlOutcome::Committed))
    );
    // A settled row stays as evidence; the same successor is not staged again.
    assert_eq!(db.stage_base_control(&control(4, 0x43)).unwrap(), first);
    assert_eq!(db.pending_base_control(BASE).unwrap(), None);
}

#[test]
fn next_pending_is_the_lowest_successor() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = DeviceDatabase::open(dir.path().join("order.db")).unwrap();
    let later = control(5, 0x51);
    let next = control(4, 0x52);
    db.stage_base_control(&later).unwrap();
    db.stage_base_control(&next).unwrap();
    assert_eq!(db.pending_base_control(BASE).unwrap(), Some(next.clone()));
    db.settle_base_control(BASE, 4, next.event_id, ControlOutcome::Superseded)
        .unwrap();
    assert_eq!(db.pending_base_control(BASE).unwrap(), Some(later));
    assert_eq!(
        db.base_control_outcome(BASE, 4).unwrap(),
        Some(Some(ControlOutcome::Superseded))
    );
    assert_eq!(db.base_control_outcome(BASE, 9).unwrap(), None);
}

#[test]
fn malformed_control_is_refused_before_persisting() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = DeviceDatabase::open(dir.path().join("bad.db")).unwrap();
    let mut wrong_id = control(4, 0x61);
    wrong_id.event_id = [0x62; 32];
    let mut wrong_body = control(4, 0x63);
    wrong_body.body = sealed(0x64).body;
    let mut first = control(1, 0x65);
    first.account_position = 1;
    for bad in [wrong_id, wrong_body, first] {
        assert!(matches!(
            db.stage_base_control(&bad),
            Err(StoreError::InvalidPackage)
        ));
    }
    assert_eq!(db.pending_base_control(BASE).unwrap(), None);
}

#[test]
fn unaccepted_counts_acked_work_until_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let mut db = DeviceDatabase::open(dir.path().join("summary.db")).unwrap();
    let key = bh_storage::NoteKey {
        base: BASE,
        audience: [0; 32],
        note: [3; 32],
    };
    let mut note = bh_core::note::Note::new().unwrap();
    let delta = note.append_paragraph("test-only note").unwrap();
    let id = db
        .apply_local_update(key, [8; 16], &delta)
        .unwrap()
        .update_id;
    let summary = db.outbox_summary().unwrap();
    assert_eq!((summary.unacknowledged, summary.unaccepted), (1, 1));
    let raw = rusqlite::Connection::open(dir.path().join("summary.db")).unwrap();
    // An Ack without its package row: only the summary's counting is tested.
    raw.pragma_update(None, "foreign_keys", false).unwrap();
    raw.execute(
        "INSERT INTO note_outbox_progress(update_id,staged,acked_position,outcome) VALUES (?1,1,2,1)",
        [id],
    )
    .unwrap();
    let summary = db.outbox_summary().unwrap();
    assert_eq!((summary.unacknowledged, summary.unaccepted), (0, 1));
}
