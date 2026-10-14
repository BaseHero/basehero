use bh_core::LOCAL_DATA_VERSION;
use bh_storage::{DeviceDatabase, OpenError};
use rusqlite::Connection;

#[test]
fn new_database_initializes_and_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device.sqlite3");
    for phase in ["initial open", "reopen"] {
        let database = DeviceDatabase::open(&path).unwrap();
        assert_eq!(database.data_version(), LOCAL_DATA_VERSION);
        drop(database);

        let connection = Connection::open(&path).unwrap();
        let stored_version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(stored_version, LOCAL_DATA_VERSION, "after {phase}");
    }
}

#[test]
fn newer_database_is_refused_without_changing_any_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("future.sqlite3");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "PRAGMA user_version = 999; CREATE TABLE future_data (value TEXT);
         INSERT INTO future_data VALUES ('pending local work');",
        )
        .unwrap();
    drop(connection);
    let before = std::fs::read(&path).unwrap();
    assert!(matches!(
        DeviceDatabase::open(&path),
        Err(OpenError::NewerData { found: 999, .. })
    ));
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(!path.with_extension("sqlite3-wal").exists());
}

#[test]
fn reopen_preserves_existing_tables_and_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device.sqlite3");
    drop(DeviceDatabase::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE retained_work (value BLOB);
         INSERT INTO retained_work VALUES (X'010203');",
        )
        .unwrap();
    drop(connection);
    drop(DeviceDatabase::open(&path).unwrap());
    let connection = Connection::open(&path).unwrap();
    let bytes: Vec<u8> = connection
        .query_row("SELECT value FROM retained_work", [], |row| row.get(0))
        .unwrap();
    assert_eq!(bytes, [1, 2, 3]);
}

#[test]
fn file_database_uses_wal() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("device.sqlite3");
    let database = DeviceDatabase::open(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    let mode: String = connection
        .pragma_query_value(None, "journal_mode", |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    drop(database);
}

#[test]
fn malformed_database_is_not_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken.sqlite3");
    let before = b"not a sqlite database; do not delete me";
    std::fs::write(&path, before).unwrap();
    assert!(DeviceDatabase::open(&path).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
}
