use bh_storage::{DeviceDatabase, StoreError, own_base::OwnBaseRecord};

fn record(account: u8, base: u8) -> OwnBaseRecord {
    OwnBaseRecord {
        account: [account; 32],
        base: [base; 32],
        genesis_descriptor: b"exact signed descriptor".to_vec(),
        genesis_body: b"exact encrypted body".to_vec(),
        initial_key_package: b"exact sealed package".to_vec(),
    }
}

#[test]
fn own_base_create_once_preserves_original_bytes_and_rejects_stale_generation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("account.sqlite");
    let mut db = DeviceDatabase::open(&path).unwrap();
    db.commit_account_verified([3; 32], &[b"signed account"], 1, [4; 32], false)
        .unwrap();
    let first = record(3, 5);
    assert!(matches!(
        db.create_own_base_if_absent(&first, || false),
        Err(StoreError::AuthorityChanged)
    ));
    assert_eq!(db.own_base().unwrap(), None);
    assert_eq!(
        db.create_own_base_if_absent(&first, || true).unwrap(),
        first
    );
    assert_eq!(
        db.create_own_base_if_absent(&record(3, 6), || true)
            .unwrap(),
        first
    );
    // Even direct SQL cannot put a second account/base into this container.
    let raw = rusqlite::Connection::open(&path).unwrap();
    assert!(raw.execute("INSERT INTO own_base(account,base,genesis_descriptor,genesis_body,initial_key_package) VALUES (?1,?2,x'01',x'02',x'03')", rusqlite::params![[7u8; 32], [8u8; 32]]).is_err());
    assert!(matches!(
        db.create_own_base_if_absent(&record(7, 8), || true),
        Err(StoreError::AuthorityChanged)
    ));
    drop(db);
    assert_eq!(
        DeviceDatabase::open(&path).unwrap().own_base().unwrap(),
        Some(first)
    );
}

#[test]
fn own_base_requires_verified_account_anchor_and_does_not_write_on_failure() {
    let mut db = DeviceDatabase::open(":memory:").unwrap();
    assert!(matches!(
        db.create_own_base_if_absent(&record(3, 5), || true),
        Err(StoreError::AuthorityChanged)
    ));
    assert_eq!(db.own_base().unwrap(), None);
}
