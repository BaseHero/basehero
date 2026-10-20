/// Exact durable rows, including note bytes, titles, pending links and writer
/// proofs. Ignore only the independently scheduled legacy-backfill cursor.
pub fn snapshot(conn: &rusqlite::Connection) -> Vec<(String, Vec<String>)> {
    let tables: Vec<String> = conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name != 'pending_scope_backfill' ORDER BY name")
        .unwrap().query_map([], |r| r.get(0)).unwrap()
        .collect::<rusqlite::Result<_>>().unwrap();
    tables
        .into_iter()
        .map(|table| {
            let mut stmt = conn
                .prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))
                .unwrap();
            let count = stmt.column_count();
            let mut rows: Vec<String> = stmt
                .query_map([], |row| {
                    let values = (0..count)
                        .map(|i| row.get::<_, rusqlite::types::Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    Ok(format!("{values:?}"))
                })
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            rows.sort();
            (table, rows)
        })
        .collect()
}
