#![allow(dead_code)]
//! Test-only historical layouts. A current open creates v13/v14 tables; a fixture
//! for an older layout removes later additions before setting its marker.
use bh_storage::DeviceDatabase;
use rusqlite::{Connection, types::Value};
use std::path::Path;

/// Remove post-v12 layouts from a current database, leaving the
/// pre-v13 rows and schema. Callers then write the historical marker.
pub fn drop_data_tables(conn: &Connection) {
    conn.execute_batch(
        "DROP TABLE IF EXISTS data_fts;
         DROP TABLE IF EXISTS note_projection_repair;
         DROP TABLE IF EXISTS typed_alarm;
         DROP TABLE IF EXISTS typed_outbox;
         DROP TABLE IF EXISTS security_alerts;
         DROP TABLE IF EXISTS security_alert_cursor;
         DROP TABLE IF EXISTS staged_account_control;
         DROP TABLE IF EXISTS account_confirmations;
         DROP TABLE IF EXISTS account_directory_versions;
         DROP TABLE IF EXISTS base_epoch_keys;
         DROP TABLE IF EXISTS account_personal_delivery;
         DROP TABLE IF EXISTS account_directory_state;
         DROP TABLE IF EXISTS account_outer_progress;
         DROP TABLE IF EXISTS base_control_fact;
         DROP TABLE IF EXISTS base_control_cursor;
         DROP TABLE IF EXISTS base_seal_wait;
         DROP TABLE IF EXISTS base_control_seal_set;",
    )
    .unwrap();
    let has_floor: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('account_state') WHERE name='observed_earliest_ms')", [], |r| r.get(0)).unwrap();
    if has_floor {
        conn.execute_batch("ALTER TABLE account_state DROP COLUMN observed_earliest_ms;")
            .unwrap();
    }
    let has_order: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM pragma_table_info('log_progress') WHERE name='order_format')", [], |r| r.get(0)).unwrap();
    if has_order {
        conn.execute_batch(
            "ALTER TABLE log_progress DROP COLUMN order_format;
                            ALTER TABLE log_progress DROP COLUMN opening;
                            ALTER TABLE log_progress DROP COLUMN floor_opening;",
        )
        .unwrap();
    }
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
    // Snapshot only historical columns when comparing pre-v14 rows against a
    // migrated table that now has the canonical opening columns.
    let query = if table == "log_progress" {
        "SELECT log_kind,log_id,position,head_hash,receipt,control_digest,stopped_reason,hosting_root,account_position,account_hash,metadata_id,epoch_id,floor FROM log_progress ORDER BY 1".to_owned()
    } else {
        format!("SELECT * FROM \"{table}\" ORDER BY 1")
    };
    let mut stmt = conn.prepare(&query).unwrap();
    let columns = stmt.column_count();
    stmt.query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}
