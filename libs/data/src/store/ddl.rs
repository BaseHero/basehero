use rusqlite::Transaction;

use super::sql;
use crate::DataError;

// Shared entry tables avoid per-index DDL: changing indexes neither takes SQLite's
// schema lock nor invalidates prepared readers. Record AUTOINCREMENT prevents rowid
// reuse (including rowids used by FTS and other derived state).
// Entries for index ix only reference records whose scope equals data_index.scope;
// enforced by the index maintainer. Entry tables carry ix, not a second scope.
// FTS5 virtual tables cannot declare NOT NULL; the text maintainer supplies the
// scope token, and search predicates match that token before returning rowids.
// data_ordered holds each scope's last applied position; a redelivered position is a
// no-op. Mutation ids are not tracked, so a snapshot-bootstrapped replica reaches the same verdicts.
// data_type_at and data_app_at keep each registry change with its position, so
// replaying parked work reads the definitions in force at its own position.
// data_record_revision finds records still on a given revision, so planning a
// migration batch never scans records already migrated; deleted records are left out.
// data_record.hidden is set only by the note lifecycle: a removed Note's row keeps its
// ordered state but stays out of every view, and `records::put` keeps `deleted` set with it.
// data_note_gap names the Notes whose content this replica cannot fully show: a held
// Note body, Note content kept for a newer executable, or a missing first projection.
// It is a gap in the record, never in the scope: unrelated ordered work continues, while
// ordered decisions about that record wait and a Note-family listing reports incomplete.
// Coverage uses WITHOUT ROWID: SQLite's rowid-alias INTEGER PRIMARY KEY silently
// replaces an explicit NULL with an allocated id even if declared NOT NULL.
const DDL: &[&str] = &[
    "CREATE TABLE data_scope(id INTEGER PRIMARY KEY, base BLOB NOT NULL, audience BLOB NOT NULL, core_ready INTEGER NOT NULL DEFAULT 0, UNIQUE(base,audience))",
    "CREATE TABLE data_app(scope INTEGER NOT NULL, app BLOB, name TEXT, active INTEGER, changed_at INTEGER, PRIMARY KEY(scope,app)) WITHOUT ROWID",
    "CREATE TABLE data_app_at(scope INTEGER NOT NULL, app BLOB, since INTEGER, active INTEGER NOT NULL, PRIMARY KEY(scope,app,since)) WITHOUT ROWID",
    "CREATE TABLE data_definition(scope INTEGER NOT NULL, revision BLOB, type BLOB, app BLOB, bytes BLOB NOT NULL, compiled TEXT NOT NULL, accepted_at INTEGER, PRIMARY KEY(scope,revision)) WITHOUT ROWID",
    "CREATE TABLE data_type(scope INTEGER NOT NULL, type BLOB, current BLOB, permitted TEXT, PRIMARY KEY(scope,type)) WITHOUT ROWID",
    "CREATE TABLE data_type_at(scope INTEGER NOT NULL, type BLOB, since INTEGER, current BLOB NOT NULL, permitted TEXT NOT NULL, PRIMARY KEY(scope,type,since)) WITHOUT ROWID",
    "CREATE TABLE data_family(scope INTEGER NOT NULL, type BLOB, ancestor BLOB, PRIMARY KEY(scope,ancestor,type)) WITHOUT ROWID",
    "CREATE TABLE data_seq(id INTEGER PRIMARY KEY CHECK (id = 1), next INTEGER NOT NULL)",
    "INSERT INTO data_seq(id,next) VALUES(1,1)",
    "CREATE TABLE data_record(id INTEGER PRIMARY KEY AUTOINCREMENT, scope INTEGER NOT NULL, record BLOB NOT NULL, type BLOB NOT NULL, revision BLOB NOT NULL, accepted TEXT, doc TEXT, deleted INTEGER NOT NULL DEFAULT 0, hidden INTEGER NOT NULL DEFAULT 0, pending INTEGER NOT NULL DEFAULT 0, changed_at INTEGER, changed INTEGER NOT NULL, text_rev INTEGER NOT NULL DEFAULT 0, UNIQUE(scope,record))",
    "CREATE INDEX data_record_type ON data_record(scope,type,id)",
    "CREATE INDEX data_record_logical ON data_record(scope,type,record)",
    "CREATE INDEX data_record_revision ON data_record(scope,type,revision,id) WHERE accepted IS NOT NULL",
    "CREATE INDEX data_record_text_rev ON data_record(scope,text_rev)",
    "CREATE TABLE data_field_clock(rec INTEGER, path TEXT, position INTEGER, mutation BLOB, PRIMARY KEY(rec,path)) WITHOUT ROWID",
    "CREATE TABLE data_actor(id INTEGER PRIMARY KEY, actor BLOB NOT NULL UNIQUE)",
    "CREATE TABLE data_history(rec INTEGER, position INTEGER, mutation BLOB, actor INTEGER NOT NULL REFERENCES data_actor(id), path TEXT, old TEXT, new TEXT, PRIMARY KEY(rec,position,path)) WITHOUT ROWID",
    "CREATE INDEX data_history_mutation ON data_history(mutation)",
    "CREATE TABLE data_pending(seq INTEGER PRIMARY KEY, scope INTEGER NOT NULL, mutation BLOB UNIQUE, rec_id BLOB, payload BLOB NOT NULL, state TEXT NOT NULL, rejection TEXT, actor INTEGER REFERENCES data_actor(id))",
    "CREATE INDEX data_pending_rec ON data_pending(scope,rec_id,seq)",
    "CREATE TABLE data_index(id INTEGER PRIMARY KEY, scope INTEGER NOT NULL, family BLOB, name TEXT, keys TEXT, unique_ INTEGER, origin TEXT, local_claim INTEGER NOT NULL DEFAULT 0, state TEXT, cursor_type BLOB, cursor_id INTEGER, built INTEGER NOT NULL DEFAULT 0, estimate INTEGER, UNIQUE(scope,family,keys,unique_))",
    // Pending work is found through its markers alone: a host probing after
    // each write visits building, retiring and clearing rows, not idle ones.
    "CREATE INDEX data_index_pending ON data_index(id) WHERE state IN ('building','retiring','clearing')",
    "CREATE TABLE data_index_entry(ix INTEGER NOT NULL, k1, k2, k3, k4, rec INTEGER NOT NULL, record BLOB NOT NULL CHECK(length(record)=32))",
    "CREATE INDEX data_index_entry_key ON data_index_entry(ix,k1,k2,k3,k4,record)",
    "CREATE INDEX data_index_entry_rec ON data_index_entry(rec,ix)",
    "CREATE TABLE data_unique(ix INTEGER NOT NULL, k1, k2, k3, k4, rec INTEGER NOT NULL)",
    "CREATE INDEX data_unique_key ON data_unique(ix,k1,k2,k3,k4)",
    "CREATE INDEX data_unique_rec ON data_unique(rec,ix)",
    "CREATE TABLE data_ref(src INTEGER NOT NULL, path TEXT NOT NULL, dst_scope INTEGER NOT NULL, dst BLOB NOT NULL, scope INTEGER NOT NULL)",
    "CREATE INDEX data_ref_src ON data_ref(src,path)",
    "CREATE INDEX data_ref_dst ON data_ref(dst_scope,dst,scope)",
    "CREATE VIRTUAL TABLE data_fts USING fts5(scope, title, body, content='', contentless_delete=1, tokenize='unicode61 remove_diacritics 2 categories ''L* N* M* Co''')",
    "CREATE TABLE data_text_job(rec INTEGER PRIMARY KEY, scope INTEGER NOT NULL, wanted INTEGER NOT NULL, since INTEGER NOT NULL)",
    "CREATE INDEX data_text_job_order ON data_text_job(wanted,rec)",
    "CREATE TABLE data_text_extract_cursor(id INTEGER PRIMARY KEY CHECK(id=1), wanted INTEGER NOT NULL, rec INTEGER NOT NULL)",
    "INSERT INTO data_text_extract_cursor(id,wanted,rec) VALUES(1,0,0)",
    "CREATE TABLE data_text_state(rec INTEGER PRIMARY KEY, scope INTEGER NOT NULL, title TEXT NOT NULL, body BLOB)",
    "CREATE TABLE data_text_mapping(scope INTEGER NOT NULL, type BLOB NOT NULL, revision BLOB NOT NULL, cursor INTEGER NOT NULL, since INTEGER NOT NULL, PRIMARY KEY(scope,type)) WITHOUT ROWID",
    "CREATE TABLE data_text_rebuild(id INTEGER PRIMARY KEY CHECK(id=1), phase TEXT NOT NULL, cursor INTEGER NOT NULL)",
    "CREATE INDEX data_text_job_since ON data_text_job(scope,since)",
    "CREATE TABLE data_coverage(scope INTEGER PRIMARY KEY NOT NULL, through INTEGER, complete INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE TABLE data_note_gap(scope INTEGER NOT NULL, record BLOB NOT NULL CHECK(length(record)=32), PRIMARY KEY(scope,record)) WITHOUT ROWID",
    "CREATE TABLE data_parked(scope INTEGER NOT NULL, position INTEGER, affects TEXT, payload BLOB, actor INTEGER REFERENCES data_actor(id), reason TEXT, mutation BLOB, type BLOB, record BLOB, uniques TEXT, app BLOB, holds INTEGER NOT NULL, unresolved_type INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(scope,position)) WITHOUT ROWID",
    "CREATE INDEX data_parked_affects ON data_parked(scope,affects,position)",
    // Wait is JSON encoded by insert_park; a targeted replay need only revisit
    // rows queued behind a row it decided, not all other parked dependencies.
    "CREATE INDEX data_parked_queued ON data_parked(scope,position) WHERE reason='\"Queued\"'",
    "CREATE INDEX data_parked_unsupported ON data_parked(scope) WHERE reason='\"Unsupported\"'",
    "CREATE INDEX data_parked_record ON data_parked(scope,record)",
    "CREATE INDEX data_parked_type ON data_parked(scope,type,position)",
    // Classify once at parking, then clear by scoped type when its lineage is known.
    // Family queries must not scan unrelated parked types to prove absence.
    "CREATE INDEX data_parked_unresolved ON data_parked(scope,type) WHERE unresolved_type=1",
    // A queued paged replay pass per scope: the last position it settled, the
    // last parked position it covers, and whether it decided anything yet.
    "CREATE TABLE data_replay(scope INTEGER PRIMARY KEY NOT NULL, cursor INTEGER NOT NULL, upper INTEGER NOT NULL, decided INTEGER NOT NULL) WITHOUT ROWID",
    "CREATE TABLE data_ordered(scope INTEGER PRIMARY KEY NOT NULL, position INTEGER NOT NULL) WITHOUT ROWID",
];

pub(super) fn migrate(tx: &Transaction<'_>) -> Result<(), DataError> {
    migrate_steps(tx, None)
}

fn migrate_steps(tx: &Transaction<'_>, fail_after: Option<usize>) -> Result<(), DataError> {
    for (i, statement) in DDL.iter().enumerate() {
        if fail_after == Some(i) {
            return Err(DataError::Sql("injected migration failure".into()));
        }
        tx.execute_batch(statement).map_err(sql)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{DDL, migrate_steps};
    use rusqlite::Connection;

    #[test]
    fn text_jobs_have_read_side_and_bounded_extraction_indexes() {
        let mut conn = Connection::open_in_memory().unwrap();
        let tx = conn.transaction().unwrap();
        migrate_steps(&tx, None).unwrap();
        let names: Vec<String> = tx.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'data_text_job_%' ORDER BY name").unwrap()
            .query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
        assert_eq!(names, ["data_text_job_order", "data_text_job_since"]);
    }

    #[test]
    fn migrate_is_atomic_on_injected_failure() {
        let mut conn = Connection::open_in_memory().unwrap();
        {
            let tx = conn.transaction().unwrap();
            assert!(migrate_steps(&tx, Some(DDL.len() / 2)).is_err());
        }
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name LIKE 'data_%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}
