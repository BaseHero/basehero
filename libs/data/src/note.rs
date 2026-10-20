//! The core Note adapter. A Note's body and title stay in the core's
//! rich-text store and change only through its note writer. Each Note also
//! has a typed record, of type `core:note` or of the Note specialisation an
//! ordered `BindNote` made it, so typed consumers can find, query, reference
//! and specialise Notes without a second editable copy. That record's
//! `/title` is a derived projection, refreshed by the host inside every note
//! commit and incoming apply. It is this replica's own state: never ordered,
//! without field clocks or history (the Note keeps its own). A
//! specialisation's fields are ordinary ordered fields.
//!
//! The host:
//! - calls [`upsert_projection`] with the Note's current title in the
//!   transaction of every committed change to the Note, and to restore a
//!   removed Note;
//! - after a projection is created, replays the parked work waiting on that
//!   record ([`apply::retry_parked_for`]) before applying later positions,
//!   since a binding of that Note may be waiting for it;
//! - calls [`remove_projection`] when the Note is removed;
//! - isolates projection changes with a savepoint. On failure it rolls back
//!   partial derived effects and atomically persists repair work with the
//!   successful Note commit; logging and continuing alone is insufficient.
//!   A missing canonical identity is a gap in that record until repaired, so
//!   ordered decisions about it wait instead of deciding on a partial view;
//! - implements [`BodyText`] as [`NOTE_BODY_SOURCE`] describes and runs
//!   [`text::extract_step`] outside write transactions.
//!
//! Removal only hides: the record leaves every view, index entry,
//! reference and searchable text, but keeps its ordered state (a
//! specialisation's fields, their clocks and history), and ordered work on
//! it is judged exactly as before. Ordered verdicts so never depend on when
//! this replica heard of the removal, and a restore returns the record with
//! the same identity and fields.
//!
//! Known limits:
//! - whether a projection exists is read from this replica's current state,
//!   not as of a binding's position;
//! - a binding of a Note that never reaches this replica waits for good,
//!   holding later work on that record, its specialisation's unique families
//!   and its definitions; causing that needs write authority in the
//!   audience. Every replica today holds all of its audience's Notes; work
//!   that lets a replica hold only some (selective sync) must supply Note
//!   coverage, or such bindings park there with their holds;
//! - coverage includes canonical Note identities: while this replica cannot show
//!   a Note's content it marks that record unavailable ([`mark_unavailable`]), so
//!   ordered decisions about the record wait and a Note-family listing reports
//!   [`Gap::NoteUnavailable`](crate::query::Gap::NoteUnavailable). The gap is the
//!   record's, never the scope's: unrelated ordered work and listings continue.
//! - ordered work other than a `BindNote` naming a plain (unbound) Note is
//!   refused as a derived field where the Note is projected and as missing
//!   where it is not: the codes differ, the state does not.
//!
//! [`apply::retry_parked_for`]: crate::mutation::apply::retry_parked_for
//! [`BodyText`]: crate::text::BodyText
use rusqlite::{Connection, Transaction, params};
use serde_json::{Map, Value};

use crate::{
    CompiledType, DataError, FieldPath, KeyRef, RecordId, Scope, TypeId,
    catalogue::{self, Shipped},
    index, mutation,
    store::{
        id,
        records::{self, RecordRow},
        registry, sql,
    },
    text,
};

/// The longest Note title the Note contract holds, in characters.
pub const MAX_TITLE_CHARS: usize = 200;

/// What a host's [`BodyText`](crate::text::BodyText) returns for a Note.
pub const NOTE_BODY_SOURCE: &str = "For a Note, BodyText::body_text(scope, note) returns the plain \
text of the Note's current body, read from its canonical rich-text document (bh_core::Note) in \
the note store, outside any write transaction. None means the body is not available on this \
device yet; its extraction job stays queued for a later step. Only the first \
text::MAX_INDEXED_BODY_BYTES bytes are indexed. Typed records never hold the body: the derived \
/title is the only Note content in them. The host keeps the walk bounded, and so does the core: \
content nested deeper than sixteen levels is skipped, the walk stops after about four source \
items per indexed byte (a much-edited Note's tombstones count), and an engine failure is treated \
like an unavailable body. A Note beyond those limits contributes a shorter literal prefix and no \
more, never an error that blocks its queue.";

/// Creates or refreshes `note`'s typed record with its current `title` and
/// returns the text revision it assigned (search at least this fresh
/// includes the body once extracted). Only the derived title changes, in
/// accepted state and in any pending overlay; a specialisation's fields stay
/// as they are and are not validated again. The record's recency
/// (`$changed`) is renewed and its body is queued for extraction. Costs one
/// record write, the index entries keyed by recency or title, and one text
/// job. A removed Note is restored: it shows again, with its identity and
/// fields, and its derived state is rebuilt.
pub fn upsert_projection(
    tx: &Transaction<'_>,
    scope: Scope,
    note: RecordId,
    title: &str,
) -> Result<u64, DataError> {
    if title.chars().count() > MAX_TITLE_CHARS {
        return Err(DataError::Limit(format!(
            "a Note title is at most {MAX_TITLE_CHARS} characters"
        )));
    }
    let sid = records::scope_id(tx, scope, &Shipped)?;
    let mut row = match records::get(tx, sid, note)? {
        Some(row) => row,
        None => {
            let (type_id, revision) = catalogue::baseline_note();
            RecordRow {
                id: 0,
                scope: sid,
                record: note,
                type_id,
                revision,
                accepted: Some(Value::Object(Map::new())),
                doc: None,
                deleted: false,
                pending: false,
                changed_at: None,
                changed: 0,
                text_rev: 0,
            }
        }
    };
    // A pending generic creation is a proposal, not an accepted identity.
    // Canonical Note acquisition may prove that identity was already occupied.
    // Preserve its exact pending payload for rejection/recovery; never replace
    // accepted (including tombstoned) typed state by this repair.
    let provisional = !row.exists_accepted() && row.type_id != TypeId::core("note");
    if provisional {
        for statement in [
            "DELETE FROM data_index_entry WHERE rec=?1",
            "DELETE FROM data_unique WHERE rec=?1",
            "DELETE FROM data_ref WHERE src=?1",
            "DELETE FROM data_text_state WHERE rec=?1",
            "DELETE FROM data_fts WHERE rowid=?1",
        ] {
            tx.execute(statement, [row.id]).map_err(sql)?;
        }
        (row.type_id, row.revision) = catalogue::baseline_note();
        row.accepted = Some(Value::Object(Map::new()));
        row.doc = None;
        row.deleted = false;
    }
    let lineage = note_lineage(tx, sid, &row)?;
    let accepted = row
        .accepted
        .as_mut()
        .ok_or_else(|| DataError::Corrupt("a Note record has no accepted state".into()))?;
    set_title(accepted, title)?;
    if let Some(doc) = row.doc.as_mut() {
        set_title(doc, title)?;
    }
    // Only the note lifecycle hides a Note's row (nothing deletes one).
    let restored = row.deleted;
    if restored {
        tx.execute("UPDATE data_record SET hidden=0 WHERE id=?1", [row.id])
            .map_err(sql)?;
        row.deleted = false;
    }
    if row.id != 0 && !restored && !provisional && row.type_id == TypeId::core("note") {
        records::put_note_in_place(tx, &mut row)?;
    } else {
        row.text_rev = records::next_seq(tx)?;
        records::put(tx, &mut row)?;
    }
    if restored || provisional {
        // Restore all scalar/ref entries, but let note_projected alone queue
        // the final revision above. Generic text hooks allocate another revision.
        index::on_record_changed(tx, &row, &note_type(tx, sid, &row)?)?;
    } else {
        let title_path = FieldPath::parse("/title")?;
        index::on_keys_changed(tx, &row, &lineage, &|key| match key {
            KeyRef::Changed => true,
            KeyRef::Field(path) => path.is_prefix_of(&title_path) || title_path.is_prefix_of(path),
        })?;
    }
    text::note_projected(tx, &row, title)?;
    Ok(row.text_rev)
}

/// Marks `note` as a record whose content this replica cannot fully show: a
/// held body, Note content kept for a readable-by-a-newer-executable event, or
/// a missing first projection. Ordered decisions about the record then wait for
/// it instead of deciding on this replica's partial view, and a Note-family
/// listing reports a gap. The scope's typed coverage is untouched: unrelated
/// ordered work continues. Idempotent.
pub fn mark_unavailable(
    tx: &Transaction<'_>,
    scope: Scope,
    note: RecordId,
) -> Result<(), DataError> {
    let sid = records::scope_id(tx, scope, &Shipped)?;
    tx.execute(
        "INSERT INTO data_note_gap(scope,record) VALUES(?1,?2)
         ON CONFLICT(scope,record) DO NOTHING",
        params![sid, note.0.as_slice()],
    )
    .map_err(sql)?;
    Ok(())
}

/// Clears the gap once this replica can show `note`'s content again. Returns
/// whether a gap row was removed, so the host can replay work parked on the
/// record.
pub fn clear_unavailable(
    tx: &Transaction<'_>,
    scope: Scope,
    note: RecordId,
) -> Result<bool, DataError> {
    let Some(sid) = records::lookup_scope(tx, scope)? else {
        return Ok(false);
    };
    let removed = tx
        .execute(
            "DELETE FROM data_note_gap WHERE scope=?1 AND record=?2",
            params![sid, note.0.as_slice()],
        )
        .map_err(sql)?;
    Ok(removed > 0)
}

/// Whether any Note in the scope is a gap: one indexed probe, for a listing's
/// completeness.
pub(crate) fn any_unavailable(conn: &Connection, sid: i64) -> Result<bool, DataError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM data_note_gap WHERE scope=?1)",
        [sid],
        |r| r.get(0),
    )
    .map_err(sql)
}

/// Whether `note` itself is a gap in the scope: one primary-key probe, for an
/// ordered decision about that record.
pub(crate) fn unavailable(conn: &Connection, sid: i64, note: RecordId) -> Result<bool, DataError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM data_note_gap WHERE scope=?1 AND record=?2)",
        params![sid, note.0.as_slice()],
        |r| r.get(0),
    )
    .map_err(sql)
}

/// Hides `note`'s typed record from every view, for the note lifecycle: its
/// index entries, references and searchable text go. Its ordered state
/// stays, and ordered work on it is judged as before; [`upsert_projection`]
/// restores it.
pub fn remove_projection(
    tx: &Transaction<'_>,
    scope: Scope,
    note: RecordId,
) -> Result<(), DataError> {
    let Some(sid) = records::lookup_scope(tx, scope)? else {
        return Ok(());
    };
    let Some(mut row) = records::get(tx, sid, note)? else {
        return Ok(());
    };
    note_lineage(tx, sid, &row)?;
    if row.deleted {
        return Ok(());
    }
    tx.execute("UPDATE data_record SET hidden=1 WHERE id=?1", [row.id])
        .map_err(sql)?;
    records::put(tx, &mut row)?;
    mutation::hooks(tx, &row, &note_type(tx, sid, &row)?)
}

fn note_type(tx: &Transaction<'_>, sid: i64, row: &RecordRow) -> Result<CompiledType, DataError> {
    registry::current(tx, sid, row.type_id, &Shipped)?
        .ok_or_else(|| DataError::Corrupt("a Note's type is not defined".into()))
}

/// The record's type and its ancestors; an error unless it is a Note.
fn note_lineage(tx: &Transaction<'_>, sid: i64, row: &RecordRow) -> Result<Vec<TypeId>, DataError> {
    let mut lineage = vec![row.type_id];
    let mut stmt = tx
        .prepare_cached("SELECT ancestor FROM data_family WHERE scope=?1 AND type=?2")
        .map_err(sql)?;
    let ancestors = stmt
        .query_map(params![sid, row.type_id.0.as_slice()], |r| {
            r.get::<_, Vec<u8>>(0)
        })
        .map_err(sql)?;
    for ancestor in ancestors {
        lineage.push(TypeId(id(ancestor.map_err(sql)?)?));
    }
    if !lineage.contains(&TypeId::core("note")) {
        return Err(DataError::Value(format!(
            "record {} is not a Note",
            mutation::hex(&row.record.0)
        )));
    }
    Ok(lineage)
}

fn set_title(doc: &mut Value, title: &str) -> Result<(), DataError> {
    doc.as_object_mut()
        .ok_or_else(|| DataError::Corrupt("a Note record is not an object".into()))?
        .insert("title".into(), Value::String(title.to_owned()));
    Ok(())
}
