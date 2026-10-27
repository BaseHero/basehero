#[test]
fn an_unkeyed_database_beside_the_core_is_plain_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("app.db");
    let db = rusqlite::Connection::open(&path).unwrap();
    let cipher: String = db
        .query_row("PRAGMA cipher_version", [], |r| r.get(0))
        .unwrap();
    assert!(!cipher.is_empty());
    db.execute_batch("CREATE TABLE t(x); INSERT INTO t VALUES (1);")
        .unwrap();
    drop(db);
    assert_eq!(&std::fs::read(&path).unwrap()[..16], b"SQLite format 3\0");
}
