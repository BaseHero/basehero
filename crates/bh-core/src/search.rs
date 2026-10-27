//! FTS5 search over locally decrypted titles, note bodies and Text fields.

use crate::Error;
use crate::store::BaseDb;
use crate::types::TypeRef;
use bh_proto::ObjectId;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// A matching object, with a short excerpt from its searchable text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct SearchHit {
    /// Matching object's ID.
    #[ts(type = "string")]
    pub id: ObjectId,
    /// Matching object's type and version.
    pub ty: TypeRef,
    /// The object's title.
    pub title: String,
    /// At most 160 characters of searchable text around the match.
    pub snippet: String,
}

pub(crate) fn search(db: &BaseDb, text: &str, limit: usize) -> Result<Vec<SearchHit>, Error> {
    if text.trim().is_empty() || limit == 0 {
        return Ok(Vec::new());
    }
    // A user's text is a literal phrase, not FTS query syntax.
    let phrase = format!("\"{}\"", text.replace('"', "\"\""));
    let mut stmt = db.connection().prepare(
        "SELECT o.object_id, o.type, o.type_version, o.title,
                snippet(object_search, -1, '', '', '…', 24)
         FROM object_search JOIN objects o ON o.object_id = object_search.object_id
         WHERE object_search MATCH ?1 AND o.deleted = 0
           AND o.type NOT IN ('core.chat', 'core.message', 'core.type', 'core.base')
         ORDER BY rank LIMIT ?2",
    )?;
    let rows = stmt.query_map(
        params![phrase, i64::try_from(limit).unwrap_or(i64::MAX)],
        |r| {
            let id: String = r.get(0)?;
            Ok((
                id,
                r.get::<_, String>(1)?,
                r.get::<_, u32>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        },
    )?;
    rows.map(|row| {
        let (id, name, version, title, snippet) = row?;
        // A single long token before the match can exceed SQLite's token
        // budget. Keep the matching part, not just the prefix.
        let at = snippet
            .to_lowercase()
            .find(&text.to_lowercase())
            .and_then(|byte| snippet.get(..byte).map(|prefix| prefix.chars().count()))
            .unwrap_or(0);
        let start = at.saturating_sub(60);
        let snippet = snippet.chars().skip(start).take(160).collect();
        Ok(SearchHit {
            id: id
                .parse()
                .map_err(|_| Error::Storage("unreadable search ID".into()))?,
            ty: TypeRef::new(name, version),
            title,
            snippet,
        })
    })
    .collect()
}
