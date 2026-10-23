use bh_storage::{
    DeviceDatabase,
    sync_state::{LOG_ACCOUNT, LOG_BASE},
};
use bh_sync::{BaseId, Commitment, EventId, OpaqueEvent, OrderState, Route};
use rusqlite::Connection;

#[test]
fn account_outer_checkpoint_is_pinned_durable_and_cannot_go_backwards() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device.db");
    let root = [7; 32];
    let event = OpaqueEvent::new(EventId([1; 32]), vec![4; 1024]).unwrap();
    let id = BaseId::from_genesis(&event).0;
    let first = Commitment::order(BaseId(id), OrderState::EMPTY, &event, Route::Control).unwrap();
    let mut db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(
        db.account_outer_progress(id, root).unwrap().order,
        OrderState::EMPTY
    );
    db.advance_account_outer(id, root, OrderState::EMPTY, first.after())
        .unwrap();
    drop(db);
    let mut db = DeviceDatabase::open(&path).unwrap();
    assert_eq!(
        db.account_outer_progress(id, root).unwrap().order,
        first.after()
    );
    assert!(
        db.advance_account_outer(id, root, OrderState::EMPTY, first.after())
            .is_err()
    );
    assert!(db.account_outer_progress(id, [8; 32]).is_err());
    assert_eq!(
        db.account_outer_progress(id, root).unwrap().order,
        first.after()
    );
    let sql = Connection::open(&path).unwrap();
    sql.execute_batch(
        "CREATE TRIGGER reject_checkpoint BEFORE UPDATE ON account_outer_progress
        BEGIN SELECT RAISE(FAIL, 'no write'); END;",
    )
    .unwrap();
    let next = Commitment::order(BaseId(id), first.after(), &event, Route::Control).unwrap();
    assert!(
        db.advance_account_outer(id, root, first.after(), next.after())
            .is_err()
    );
    assert_eq!(
        db.account_outer_progress(id, root).unwrap().order,
        first.after()
    );
    sql.execute_batch("DROP TRIGGER reject_checkpoint").unwrap();
    sql.execute(
        "UPDATE account_outer_progress SET order_format=1 WHERE log_id=?1",
        [id.as_slice()],
    )
    .unwrap();
    assert!(
        db.account_outer_progress(id, root).is_err(),
        "legacy state must not be reinitialised"
    );
    sql.execute(
        "UPDATE account_outer_progress SET order_format=2,opening=?2 WHERE log_id=?1",
        rusqlite::params![id.as_slice(), next.after().encode().as_slice()],
    )
    .unwrap();
    assert!(
        db.account_outer_progress(id, root).is_err(),
        "a valid-looking opening must not silently replace the stored head"
    );
}

#[test]
fn an_outer_checkpoint_alone_is_not_an_empty_account_container() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    assert!(db.account_container_empty().unwrap());
    db.account_outer_progress([3; 32], [4; 32]).unwrap();
    assert!(!db.account_container_empty().unwrap());
}

#[test]
fn populated_legacy_account_log_cannot_be_initialised_as_empty_outer_scope() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device.db");
    let mut db = DeviceDatabase::open(&path).unwrap();
    let sql = Connection::open(&path).unwrap();
    let id = [3; 32];
    let root = [4; 32];
    sql.execute("INSERT INTO log_progress(log_kind,log_id,position,head_hash,control_digest,hosting_root,floor,account_position,account_hash,metadata_id) VALUES(2,?1,1,zeroblob(32),zeroblob(32),?2,1,1,zeroblob(32),zeroblob(32))", rusqlite::params![id.as_slice(),root.as_slice()]).unwrap();
    assert!(db.account_outer_progress(id, root).is_err());
    let count: i64 = sql
        .query_row("SELECT COUNT(*) FROM account_outer_progress", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn new_empty_log_has_a_canonical_opening_and_populated_markerless_log_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device.db");
    let base = [9; 32];
    let root = [7; 32];
    let mut db = DeviceDatabase::open(&path).unwrap();
    db.record_registration(base, None, root).unwrap();
    let progress = db.log_progress(LOG_BASE, base).unwrap().unwrap();
    assert_eq!(progress.order, OrderState::EMPTY);
    assert_eq!(progress.order_format, 2);
    drop(db);
    let sql = Connection::open(&path).unwrap();
    sql.execute(
        "UPDATE log_progress SET order_format=NULL WHERE log_kind=1 AND log_id=?1",
        [base.as_slice()],
    )
    .unwrap();
    drop(sql);
    let mut db = DeviceDatabase::open(&path).unwrap();
    assert!(db.log_progress(LOG_BASE, base).is_err());
    assert!(db.record_registration(base, None, root).is_err());
    let sql = Connection::open(&path).unwrap();
    let marker: Option<i64> = sql
        .query_row(
            "SELECT order_format FROM log_progress WHERE log_kind=1 AND log_id=?1",
            [base.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(marker, None);
    sql.execute("INSERT INTO log_progress(log_kind,log_id,position,head_hash,control_digest,hosting_root,floor,account_position,account_hash,metadata_id) VALUES(2,?1,1,zeroblob(32),zeroblob(32),?2,1,1,zeroblob(32),zeroblob(32))", rusqlite::params![base.as_slice(),root.as_slice()]).unwrap();
    drop(sql);
    assert!(db.log_progress(LOG_ACCOUNT, base).is_err());
}
