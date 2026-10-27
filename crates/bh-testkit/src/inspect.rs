//! Direct inspection of encrypted local stores and on-disk test artifacts.

use rusqlite::{Connection, OpenFlags, types::ValueRef};
use std::path::{Path, PathBuf};

/// Opens a SQLCipher store with its actual key and prints all rows of all tables,
/// including SQLite's FTS shadow tables. Blobs appear as both hex and lossy UTF-8.
/// A wrong key or unreadable table panics instead of silently returning an empty dump.
pub fn dump_store(path: &Path, key: &[u8]) -> String {
    assert_eq!(key.len(), 32, "SQLCipher key must be 32 bytes");
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .expect("open encrypted store for inspection");
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    db.execute_batch(&format!("PRAGMA key = \"x'{hex}'\";"))
        .expect("set inspection key");
    let mut tables = db
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
        .expect("read encrypted schema");
    let names: Vec<String> = tables
        .query_map([], |row| row.get(0))
        .expect("list encrypted tables")
        .map(|row| row.expect("read table name"))
        .collect();
    assert!(!names.is_empty(), "encrypted store has no tables");
    let mut out = String::new();
    for name in names {
        // Names come from SQLite's own schema; quote embedded double quotes.
        let escaped = name.replace('"', "\"\"");
        let mut statement = db
            .prepare(&format!("SELECT * FROM \"{escaped}\""))
            .unwrap_or_else(|error| panic!("read table {name}: {error}"));
        out.push_str(&format!("table {name}\n"));
        let columns = statement.column_count();
        let mut rows = statement.query([]).expect("query encrypted table");
        while let Some(row) = rows.next().expect("read encrypted row") {
            for column in 0..columns {
                match row.get_ref(column).expect("read encrypted value") {
                    ValueRef::Null => out.push_str("NULL"),
                    ValueRef::Integer(v) => out.push_str(&v.to_string()),
                    ValueRef::Real(v) => out.push_str(&v.to_string()),
                    ValueRef::Text(v) => out.push_str(&String::from_utf8_lossy(v)),
                    ValueRef::Blob(v) => {
                        out.push_str("hex:");
                        for byte in v {
                            out.push_str(&format!("{byte:02x}"));
                        }
                        out.push_str(" utf8:");
                        out.push_str(&String::from_utf8_lossy(v));
                    }
                }
                out.push('\n');
            }
        }
    }
    out
}

/// Lists every regular file under `dir` containing the raw bytes `needle`.
/// A missing directory is empty; other I/O failures panic so a scan never passes silently.
pub fn files_containing(dir: &Path, needle: &[u8]) -> Vec<PathBuf> {
    assert!(!needle.is_empty(), "a trace needle must not be empty");
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("scan {}: {error}", dir.display()),
        };
        for entry in entries {
            let entry = entry.expect("read directory entry");
            let kind = entry.file_type().expect("read file type");
            let path = entry.path();
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                let bytes = std::fs::read(&path).expect("read scanned file");
                if bytes.windows(needle.len()).any(|part| part == needle) {
                    found.push(path);
                }
            }
        }
    }
    found.sort();
    found
}
