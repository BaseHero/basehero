#![allow(dead_code)]
//! Test-only historical layouts. A current open creates v13 tables; a fixture
//! for an older layout removes every v13 addition before setting its marker.
use bh_storage::DeviceDatabase;
use rusqlite::{Connection, types::Value};
use std::path::Path;

/// Remove the typed-data layout from a current database, leaving the
/// pre-v13 rows and schema. Callers then write the historical marker.
pub fn drop_data_tables(conn: &Connection) {
    conn.execute_batch(
        "DROP TABLE IF EXISTS data_fts;
         DROP TABLE IF EXISTS note_projection_repair;
         DROP TABLE IF EXISTS typed_alarm;
         DROP TABLE IF EXISTS typed_outbox;",
    )
    .unwrap();
    loop {
        let names: Vec<String> = conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'data_%' ORDER BY name",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        if names.is_empty() {
            break;
        }
        for name in names {
            conn.execute_batch(&format!("DROP TABLE IF EXISTS \"{name}\""))
                .unwrap();
        }
    }
    if table_exists(conn, "sqlite_sequence") {
        conn.execute("DELETE FROM sqlite_sequence", []).unwrap();
    }
}

/// A connection to a real pre-v13 layout: the current migration chain first,
/// then every v13 table and marker removed.
pub fn v12(path: &Path) -> Connection {
    drop(DeviceDatabase::open(path).unwrap());
    let conn = Connection::open(path).unwrap();
    drop_data_tables(&conn);
    conn.pragma_update(None, "user_version", 12u32).unwrap();
    conn
}

pub fn version(conn: &Connection) -> u32 {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap()
}

pub fn table_exists(conn: &Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)",
        [name],
        |row| row.get::<_, bool>(0),
    )
    .unwrap()
}

pub fn dump(conn: &Connection, table: &str) -> Vec<Vec<Value>> {
    let mut stmt = conn
        .prepare(&format!("SELECT * FROM \"{table}\" ORDER BY 1"))
        .unwrap();
    let columns = stmt.column_count();
    stmt.query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}
