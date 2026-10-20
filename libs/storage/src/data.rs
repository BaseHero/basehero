//! Bind the device database's local notes to the shared typed-record layout.
//!
//! The v13 step creates that layout and projects every catalogue note from the
//! catalogue rows alone: no Yjs decode, no history replay. Note commits keep
//! the projection inside their own transaction; a projection failure rolls
//! back only its savepoint and records durable repair work, never the Note.
use std::sync::Arc;

use bh_data::{
    Actor, DataError, Position, RecordId, Scope,
    catalogue::Shipped,
    mutation, note,
    store::{coverage, records},
    text::{self, BodyText, MAX_INDEXED_BODY_BYTES},
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use crate::{NoteKey, ReadPool, StoreError, sync_state::LOG_BASE};

/// The audience every member of a base reads. Content events in this layout
/// are always ordered in it, so a batch's typed effects belong to this scope.
pub(crate) const ORDINARY_AUDIENCE: [u8; 32] = [0; 32];

/// One base log's ordinary typed scope.
pub(crate) fn ordinary_scope(base: [u8; 32]) -> Scope {
    Scope {
        base,
        audience: ORDINARY_AUDIENCE,
    }
}

fn sql(error: DataError) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

/// Test-only injection point for a failure part-way through seeding. It is
/// thread-local so parallel migration tests never observe another's failure.
#[cfg(feature = "testkit")]
pub mod testkit {
    use std::cell::Cell;

    thread_local! {
        static FAIL_SEEDING_AFTER: Cell<Option<usize>> = const { Cell::new(None) };
    }

    pub fn fail_seeding_after(notes: Option<usize>) {
        FAIL_SEEDING_AFTER.with(|value| value.set(notes));
    }

    pub(crate) fn should_fail(seeded: usize) -> bool {
        FAIL_SEEDING_AFTER.with(|value| value.get() == Some(seeded))
    }
}

fn scope(key: NoteKey) -> Scope {
    Scope {
        base: key.base,
        audience: key.audience,
    }
}

/// The scope a Note key reads and writes.
pub(crate) fn note_scope(key: NoteKey) -> Scope {
    scope(key)
}

/// The base log's verified position, or zero while this replica has none.
fn log_position(tx: &Transaction<'_>, base: [u8; 32]) -> Result<Position, StoreError> {
    let position: Option<i64> = tx
        .query_row(
            "SELECT position FROM log_progress WHERE log_kind=?1 AND log_id=?2",
            params![LOG_BASE, base.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    match position {
        None => Ok(Position(0)),
        Some(position) => Ok(Position(
            u64::try_from(position).map_err(|_| StoreError::CorruptSyncState)?,
        )),
    }
}

/// Whether this Note has engine-held candidates here.
fn has_held_note(conn: &Connection, key: NoteKey) -> Result<bool, StoreError> {
    let layout: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='held_note_event')",
        [],
        |row| row.get(0),
    )?;
    if !layout {
        return Ok(false);
    }
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM held_note_event WHERE base=?1 AND audience=?2 AND note=?3)",
        params![
            key.base.as_slice(),
            key.audience.as_slice(),
            key.note.as_slice()
        ],
        |row| row.get(0),
    )?)
}

/// Whether a missing first projection still awaits repair.
fn has_repair(conn: &Connection, key: NoteKey) -> Result<bool, StoreError> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM note_projection_repair WHERE base=?1 AND audience=?2 AND note=?3)",
        params![
            key.base.as_slice(),
            key.audience.as_slice(),
            key.note.as_slice()
        ],
        |row| row.get(0),
    )?)
}

/// The coverage a scope starts with once its Note identity set is known.
/// `complete` states only that the typed log is applied through `through`; a
/// Note this replica cannot fully show is a gap in that record, never in the
/// scope. A consumer advances `through` as ordered work arrives.
pub(crate) fn seed_scope_coverage(tx: &Transaction<'_>, scope: Scope) -> Result<(), StoreError> {
    let sid = records::scope_id(tx, scope, &Shipped).map_err(StoreError::Data)?;
    coverage::set(tx, sid, log_position(tx, scope.base)?, true).map_err(StoreError::Data)
}

/// Advance a scope's typed coverage to a batch's committed log position. Every
/// verified typed payload was applied at its position (parked work included),
/// so the typed log is complete through `through`; Note gaps and retained
/// content are per-record facts that ordered decisions and listings consult
/// directly.
pub(crate) fn advance_coverage(
    tx: &Transaction<'_>,
    scope: Scope,
    through: Position,
) -> Result<(), StoreError> {
    let sid = records::scope_id(tx, scope, &Shipped).map_err(StoreError::Data)?;
    coverage::set(tx, sid, through, true).map_err(StoreError::Data)
}

/// Whether this scope's typed coverage was complete before a batch is applied.
/// A scope with no coverage row yet is not: the first batch that applies typed
/// work there supplies it, and work that waited for that proof replays once.
pub(crate) fn covered(tx: &Transaction<'_>, scope: Scope) -> Result<bool, StoreError> {
    match records::lookup_scope(tx, scope).map_err(StoreError::Data)? {
        Some(sid) => Ok(coverage::get(tx, sid).map_err(StoreError::Data)?.complete),
        None => Ok(false),
    }
}

/// Mark `note` as a record whose content this replica cannot show yet: ordered
/// decisions about it wait and Note listings report a gap. The scope's typed
/// coverage is untouched.
pub(crate) fn mark_note_gap(
    tx: &Transaction<'_>,
    scope: Scope,
    note: [u8; 32],
) -> Result<(), StoreError> {
    note::mark_unavailable(tx, scope, RecordId(note)).map_err(StoreError::Data)
}

/// Recompute one Note's gap from its durable reasons: engine-held candidates,
/// Note content kept for a newer build, or a repair for a missing first
/// projection. Returns whether a gap row was removed.
pub(crate) fn refresh_note_gap(
    tx: &Transaction<'_>,
    scope: Scope,
    note: [u8; 32],
) -> Result<bool, StoreError> {
    let key = NoteKey {
        base: scope.base,
        audience: scope.audience,
        note,
    };
    let missing_projection = note_projection_missing(tx, key)?;
    let gap = has_held_note(tx, key)?
        || crate::retained::note_has_any(tx, key)?
        || (missing_projection && has_repair(tx, key)?);
    if gap {
        mark_note_gap(tx, scope, note)?;
        return Ok(false);
    }
    note::clear_unavailable(tx, scope, RecordId(note)).map_err(StoreError::Data)
}

/// Whether this replica has no typed record for the Note yet: a commit that
/// supplies one is the projection dependency parked work may wait for.
pub(crate) fn note_projection_missing(conn: &Connection, key: NoteKey) -> Result<bool, StoreError> {
    let Some(sid) = records::lookup_scope(conn, scope(key)).map_err(StoreError::Data)? else {
        return Ok(true);
    };
    Ok(!records::exists(conn, sid, RecordId(key.note)).map_err(StoreError::Data)?)
}

/// Apply one verified typed payload at its ordered position, inside the
/// batch's transaction. The scope and actor come from the authenticated
/// event; no caller-supplied verification flag reaches the materializer. The
/// Ordered admission takes the author and position from the verified event,
/// not from the plaintext operation.
/// Returns the ordered verdict; an accepted definition is a dependency for
/// parked work.
pub(crate) fn apply_typed(
    tx: &Transaction<'_>,
    scope: Scope,
    position: Position,
    actor: &Actor,
    payload: &[u8],
) -> Result<mutation::apply::Outcome, StoreError> {
    mutation::apply::apply_payload_with_admission(
        tx,
        &Shipped,
        scope,
        position,
        actor,
        payload,
        &OrderedAdmission::received(position, actor),
    )
    .map_err(StoreError::Data)
}

/// The original event was authenticated by the history verifier before its
/// author, position and exact payload entered the ordered transaction. Parked
/// rows retain that authenticated tuple for replay. This boundary answers
/// only whether a device authored the operation at this position; bh-data
/// separately compares the signed payload's confirmation to its computed
/// prior rules. A job key never confirms.
/// Reading an adoption source from another audience is a later member/audience
/// concern, so this admission deliberately never grants it here.
struct OrderedAdmission<'a> {
    received: Option<(Position, &'a Actor)>,
}
impl<'a> OrderedAdmission<'a> {
    fn received(position: Position, actor: &'a Actor) -> Self {
        Self {
            received: Some((position, actor)),
        }
    }
    fn replay() -> Self {
        Self { received: None }
    }
}
impl bh_data::admission::HostAdmission for OrderedAdmission<'_> {
    fn confirms(
        &self,
        request: &bh_data::admission::Confirmation,
        at: Option<Position>,
    ) -> Result<bool, bh_data::DataError> {
        Ok(matches!(request.actor, Actor::Device { .. })
            && at.is_some()
            && self
                .received
                .is_none_or(|(position, actor)| at == Some(position) && &request.actor == actor))
    }
}

#[cfg(test)]
mod ordered_admission_tests {
    use super::*;
    use crate::DeviceDatabase;
    use bh_data::{
        AppId,
        admission::{Confirmation, HostAdmission, PriorRules},
        mutation::ops::Operation,
    };

    #[test]
    fn ordered_device_author_must_match_the_verified_position() {
        let actor = Actor::Device {
            account: [1; 32],
            device: [2; 32],
        };
        let request = Confirmation {
            scope: Scope {
                base: [3; 32],
                audience: [0; 32],
            },
            actor: actor.clone(),
            operation: Operation::SetAppState {
                app: AppId([4; 32]),
                active: false,
            },
            prior: PriorRules::App {
                app: AppId([4; 32]),
                since: None,
                active: Some(true),
            },
        };
        assert!(
            OrderedAdmission::received(Position(17), &actor)
                .confirms(&request, Some(Position(17)))
                .unwrap()
        );
        assert!(
            !OrderedAdmission::received(Position(18), &actor)
                .confirms(&request, Some(Position(17)))
                .unwrap()
        );
        assert!(
            !OrderedAdmission::received(
                Position(17),
                &Actor::Device {
                    account: [1; 32],
                    device: [5; 32]
                }
            )
            .confirms(&request, Some(Position(17)))
            .unwrap()
        );
        assert!(
            !OrderedAdmission::received(Position(17), &actor)
                .confirms(&request, None)
                .unwrap()
        );
    }

    #[test]
    fn ordered_job_management_is_rejected_after_a_device_defines_the_app() {
        use bh_data::{MutationId, RejectCode, mutation::apply::Outcome, payload};
        let mut db = DeviceDatabase::open(":memory:").unwrap();
        let scope = Scope {
            base: [3; 32],
            audience: [0; 32],
        };
        let device = Actor::Device {
            account: [1; 32],
            device: [2; 32],
        };
        let job = Actor::Job {
            account: [1; 32],
            delegation: [4; 32],
            action: None,
        };
        let app = AppId([5; 32]);
        db.with_data_write(|tx| {
            let sid = bh_data::store::records::scope_id(tx, scope, &Shipped)?;
            bh_data::store::coverage::set(tx, sid, Position(0), true)?;
            let define = payload::encode(MutationId([1; 16]), &Operation::DefineApp { app, name: "Reading".into() })?;
            assert!(matches!(
                mutation::apply::apply_payload_with_admission(tx, &Shipped, scope, Position(1), &device, &define, &OrderedAdmission::received(Position(1), &device))?,
                Outcome::Accepted { .. }
            ));
            let change = payload::encode_with_confirmation(MutationId([2; 16]), &Operation::SetAppState { app, active: false }, Some(PriorRules::App { app, since: Some(Position(1)), active: Some(true) }))?;
            assert!(matches!(
                mutation::apply::apply_payload_with_admission(tx, &Shipped, scope, Position(2), &job, &change, &OrderedAdmission::received(Position(2), &job))?,
                Outcome::Rejected(rejection) if rejection.code == RejectCode::DeviceOnly
            ));
            Ok(())
        }).unwrap();
    }

    #[test]
    fn authenticated_device_publication_without_explicit_confirmation_is_rejected() {
        use bh_data::{MutationId, RejectCode, mutation::apply::Outcome, payload, store::records};
        let mut db = DeviceDatabase::open(":memory:").unwrap();
        let scope = Scope {
            base: [3; 32],
            audience: [0; 32],
        };
        let actor = Actor::Device {
            account: [1; 32],
            device: [2; 32],
        };
        let app = AppId([5; 32]);
        db.with_data_write(|tx| {
            let sid = records::scope_id(tx, scope, &Shipped)?;
            bh_data::store::coverage::set(tx, sid, Position(0), true)?;
            let define = bh_data::payload::encode(MutationId([1; 16]), &Operation::DefineApp { app, name: "Reading".into() })?;
            assert!(matches!(apply_typed(tx, scope, Position(1), &actor, &define).unwrap(), Outcome::Accepted { .. }));
            let unconfirmed = payload::encode(MutationId([2; 16]), &Operation::SetAppState { app, active: false })?;
            assert!(matches!(apply_typed(tx, scope, Position(2), &actor, &unconfirmed).unwrap(), Outcome::Rejected(r) if r.code == RejectCode::Unauthorized));
            assert_eq!(bh_data::store::registry::app_active(tx, sid, app)?, Some(true));
            let wrong = payload::encode_with_confirmation(MutationId([3; 16]),
                &Operation::SetAppState { app, active: false },
                Some(PriorRules::App { app, since: None, active: Some(true) }))?;
            assert!(matches!(apply_typed(tx, scope, Position(3), &actor, &wrong).unwrap(),
                Outcome::Rejected(r) if r.code == RejectCode::Unauthorized));
            assert_eq!(bh_data::store::registry::app_active(tx, sid, app)?, Some(true));
            Ok(())
        }).unwrap();
    }

    #[test]
    fn accepted_device_management_survives_reopen_and_exact_replay() {
        use bh_data::{MutationId, mutation::apply::Outcome, payload, store::records};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("account.sqlite");
        let scope = Scope {
            base: [3; 32],
            audience: [0; 32],
        };
        let actor = Actor::Device {
            account: [1; 32],
            device: [2; 32],
        };
        let app = AppId([5; 32]);
        let define = payload::encode(
            MutationId([1; 16]),
            &Operation::DefineApp {
                app,
                name: "Reading".into(),
            },
        )
        .unwrap();
        let change = payload::encode_with_confirmation(
            MutationId([2; 16]),
            &Operation::SetAppState { app, active: false },
            Some(PriorRules::App {
                app,
                since: Some(Position(1)),
                active: Some(true),
            }),
        )
        .unwrap();
        {
            let mut db = DeviceDatabase::open(&path).unwrap();
            db.with_data_write(|tx| {
                let sid = records::scope_id(tx, scope, &Shipped)?;
                bh_data::store::coverage::set(tx, sid, Position(0), true)?;
                assert!(matches!(
                    apply_typed(tx, scope, Position(1), &actor, &define).unwrap(),
                    Outcome::Accepted { .. }
                ));
                assert!(matches!(
                    apply_typed(tx, scope, Position(2), &actor, &change).unwrap(),
                    Outcome::Accepted { .. }
                ));
                Ok(())
            })
            .unwrap();
        }
        let mut db = DeviceDatabase::open(&path).unwrap();
        db.with_data_write(|tx| {
            let sid = records::lookup_scope(tx, scope)?.unwrap();
            assert_eq!(
                bh_data::store::registry::app_active(tx, sid, app)?,
                Some(false)
            );
            assert!(matches!(
                apply_typed(tx, scope, Position(2), &actor, &change).unwrap(),
                Outcome::Duplicate
            ));
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn replay_never_confirms_job_management() {
        let request = Confirmation {
            scope: Scope {
                base: [3; 32],
                audience: [0; 32],
            },
            actor: Actor::Job {
                account: [1; 32],
                delegation: [2; 32],
                action: None,
            },
            operation: Operation::SetAppState {
                app: AppId([4; 32]),
                active: false,
            },
            prior: PriorRules::App {
                app: AppId([4; 32]),
                since: None,
                active: Some(true),
            },
        };
        assert!(
            !OrderedAdmission::replay()
                .confirms(&request, Some(Position(17)))
                .unwrap()
        );
        assert!(
            !OrderedAdmission::replay()
                .may_read_source(&request.actor, request.scope, Some(Position(17)))
                .unwrap()
        );
    }
}

/// Whether the scope has parked ordered work (one probe).
pub(crate) fn has_parked(tx: &Transaction<'_>, scope: Scope) -> Result<bool, StoreError> {
    mutation::apply::has_parked(tx, scope).map_err(StoreError::Data)
}

/// Replay the scope's parked ordered work once, in position order. A host
/// calls this only when a dependency can unblock work anywhere in the scope (an
/// accepted definition, or the coverage this batch supplied), at most once per
/// incoming batch: it costs one pass over that scope's parked rows. A record's
/// own dependency uses [`replay_parked_for`] instead.
pub(crate) fn replay_parked(tx: &Transaction<'_>, scope: Scope) -> Result<(), StoreError> {
    let decided = mutation::apply::retry_parked_with_admission(
        tx,
        &Shipped,
        scope,
        &OrderedAdmission::replay(),
    )
    .map_err(StoreError::Data)?;
    crate::typed_outbox::settle_decided(tx, scope, &decided)
}

/// Replay only the parked work waiting on one record's key, in position order.
/// A Note's projection arriving, its gap clearing or its held candidates being
/// released names one record, so this costs one pass over the rows waiting on
/// that key instead of the whole scope's queue.
pub(crate) fn replay_parked_for(
    tx: &Transaction<'_>,
    scope: Scope,
    note: [u8; 32],
) -> Result<(), StoreError> {
    let decided = mutation::apply::retry_parked_for_with_admission(
        tx,
        &Shipped,
        scope,
        mutation::apply::Key::Record(RecordId(note)),
        &OrderedAdmission::replay(),
    )
    .map_err(StoreError::Data)?;
    crate::typed_outbox::settle_decided(tx, scope, &decided)
}

/// Rows and stored payload bytes one replay page may settle; see
/// [`mutation::apply::ReplayLimits`] for the work bound.
const REPLAY_PAGE_ROWS: usize = 16;
const REPLAY_PAGE_BYTES: usize = 256 * 1024;

/// Settle one page of a queued replay pass through the ordered admission
/// incoming work uses, then settle our packages it decided, in the caller's
/// transaction.
pub(crate) fn replay_page(tx: &Transaction<'_>, vm_steps: u64) -> Result<(), StoreError> {
    let limits = mutation::apply::ReplayLimits {
        rows: REPLAY_PAGE_ROWS,
        bytes: REPLAY_PAGE_BYTES,
        vm_steps,
    };
    let page = mutation::apply::replay_page_with_admission(
        tx,
        &Shipped,
        limits,
        &OrderedAdmission::replay(),
    )
    .map_err(StoreError::Data)?;
    match page {
        Some(page) => crate::typed_outbox::settle_decided(tx, page.scope, &page.decided),
        None => Ok(()),
    }
}

fn store(error: StoreError) -> rusqlite::Error {
    match error {
        StoreError::Database(error) => error,
        other => rusqlite::Error::ToSqlConversionFailure(Box::new(other)),
    }
}

/// The v13 step: the shared layout, then one projection per existing
/// catalogue note in `touched` order. Coverage starts at the base log's
/// verified position; a Note held here or missing its first projection becomes
/// a gap in that record. Bounded by the catalogue's own rows.
pub(crate) fn migrate(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    bh_data::store::migrate(tx).map_err(sql)?;
    crate::typed_outbox::migrate(tx)?;
    tx.execute_batch(
        "CREATE TABLE note_projection_repair (
            base BLOB NOT NULL CHECK(length(base)=32),
            audience BLOB NOT NULL CHECK(length(audience)=32),
            note BLOB NOT NULL CHECK(length(note)=32),
            reason TEXT NOT NULL DEFAULT '',
            PRIMARY KEY(base,audience,note)
        ) WITHOUT ROWID;",
    )?;
    crate::retained::create_table(tx)?;
    #[cfg(feature = "testkit")]
    let mut seeded = 0usize;
    let scopes: Vec<(Vec<u8>, Vec<u8>)> = tx
        .prepare("SELECT DISTINCT base,audience FROM notes ORDER BY base,audience")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (base, audience) in scopes {
        let base: [u8; 32] = base.try_into().map_err(|_| corrupt_scope())?;
        let audience: [u8; 32] = audience.try_into().map_err(|_| corrupt_scope())?;
        let scope = Scope { base, audience };
        let mut stmt = tx.prepare(
            "SELECT note,title FROM notes WHERE base=?1 AND audience=?2 ORDER BY touched,note",
        )?;
        let mut rows = stmt.query(params![base.as_slice(), audience.as_slice()])?;
        while let Some(row) = rows.next()? {
            let note: Vec<u8> = row.get(0)?;
            let note: [u8; 32] = note.try_into().map_err(|_| corrupt_scope())?;
            let title: String = row.get(1)?;
            note::upsert_projection(tx, scope, RecordId(note), &title).map_err(sql)?;
            #[cfg(feature = "testkit")]
            {
                seeded += 1;
                if testkit::should_fail(seeded) {
                    return Err(rusqlite::Error::SqliteFailure(
                        rusqlite::ffi::Error::new(1),
                        Some("injected migration failure".into()),
                    ));
                }
            }
        }
        drop(rows);
        drop(stmt);
        seed_scope_coverage(tx, scope).map_err(store)?;
    }
    // A Note this build cannot show is a gap in that record, so carry the
    // existing reasons into the v13 table.
    seed_note_gaps(tx)?;
    // The own base's ordinary audience is listable before its first Note, so
    // an empty base reports complete-empty rather than unknown coverage.
    if let Some(base) = own_base(tx)? {
        seed_coverage_if_unset(tx, ordinary_scope(base))?;
    }
    Ok(())
}

/// Seeds a scope's coverage over the position verified here unless it already
/// has one: migration reaches a scope before its first incoming batch does.
fn seed_coverage_if_unset(tx: &Transaction<'_>, scope: Scope) -> rusqlite::Result<()> {
    let sid = records::scope_id(tx, scope, &Shipped)
        .map_err(StoreError::Data)
        .map_err(store)?;
    let seeded = coverage::get(tx, sid)
        .map_err(StoreError::Data)
        .map_err(store)?
        .through
        .is_some();
    if !seeded {
        seed_scope_coverage(tx, scope).map_err(store)?;
    }
    Ok(())
}

/// One pass over the pre-v13 reasons a Note is not fully shown here. A layout
/// without the held-note table holds none. Bounded by those rows.
fn seed_note_gaps(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    let held: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='held_note_event')",
        [],
        |row| row.get(0),
    )?;
    let mut sources = vec!["SELECT base,audience,note FROM note_projection_repair".to_owned()];
    if held {
        sources.push("SELECT base,audience,note FROM held_note_event".to_owned());
    }
    for source in sources {
        let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = tx
            .prepare(&source)?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (base, audience, note) in rows {
            let scope = Scope {
                base: base.try_into().map_err(|_| corrupt_scope())?,
                audience: audience.try_into().map_err(|_| corrupt_scope())?,
            };
            mark_note_gap(tx, scope, note.try_into().map_err(|_| corrupt_scope())?)
                .map_err(store)?;
            seed_coverage_if_unset(tx, scope)?;
        }
    }
    Ok(())
}

fn own_base(conn: &Connection) -> rusqlite::Result<Option<[u8; 32]>> {
    let base: Option<Vec<u8>> = conn
        .query_row("SELECT base FROM own_base WHERE id=1", [], |row| row.get(0))
        .optional()?;
    base.map(|base| base.try_into().map_err(|_| corrupt_scope()))
        .transpose()
}

fn corrupt_scope() -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        0,
        rusqlite::types::Type::Blob,
        Box::new(std::io::Error::other("scope has a non-32-byte identifier")),
    )
}

/// A Note commit's final catalogue title, after every catalogue write in the
/// same transaction.
pub(crate) fn catalogued_title(tx: &Transaction<'_>, key: NoteKey) -> Result<String, StoreError> {
    Ok(tx
        .query_row(
            "SELECT title FROM notes WHERE base=?1 AND audience=?2 AND note=?3",
            params![
                key.base.as_slice(),
                key.audience.as_slice(),
                key.note.as_slice()
            ],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or_default())
}

/// Refresh a Note's derived projection inside its commit. A failure rolls back
/// only the projection's savepoint and leaves durable repair work in the same
/// transaction; the Note's own save still commits. The first Note in a scope
/// also seeds that scope's coverage. A Note whose first projection is missing
/// is a gap in that record until a repair supplies it.
pub(crate) fn project_note(
    tx: &Transaction<'_>,
    key: NoteKey,
    title: &str,
) -> Result<(), StoreError> {
    let scope = scope(key);
    let sid = records::lookup_scope(tx, scope).map_err(StoreError::Data)?;
    let first_scope = sid.is_none();
    let missing_identity = match sid {
        Some(sid) => !records::exists(tx, sid, RecordId(key.note)).map_err(StoreError::Data)?,
        None => true,
    };
    tx.execute_batch("SAVEPOINT note_projection")?;
    match note::upsert_projection(tx, scope, RecordId(key.note), title) {
        Ok(_) => {
            // A later success makes an earlier repair record stale, and with
            // no other reason left the record's gap closes.
            let cleared = tx
                .prepare_cached(
                    "DELETE FROM note_projection_repair WHERE base=?1 AND audience=?2 AND note=?3",
                )?
                .execute(params![
                    key.base.as_slice(),
                    key.audience.as_slice(),
                    key.note.as_slice()
                ])?;
            if first_scope {
                seed_scope_coverage(tx, scope)?;
            }
            let closed = cleared > 0 && refresh_note_gap(tx, scope, key.note)?;
            tx.execute_batch("RELEASE note_projection")?;
            if closed {
                // This save supplied the projection a missing identity was
                // waiting for: replay just that record's queue, outside the
                // projection's savepoint so a replay failure cannot undo the
                // Note's own writes by halves.
                replay_parked_for(tx, scope, key.note)?;
            }
        }
        Err(error) => {
            tx.execute_batch("ROLLBACK TO note_projection; RELEASE note_projection")?;
            tx.execute(
                "INSERT INTO note_projection_repair(base,audience,note,reason) VALUES(?1,?2,?3,?4)
                 ON CONFLICT(base,audience,note) DO UPDATE SET reason=excluded.reason",
                params![
                    key.base.as_slice(),
                    key.audience.as_slice(),
                    key.note.as_slice(),
                    error.to_string()
                ],
            )?;
            if first_scope {
                seed_scope_coverage(tx, scope)?;
            }
            if missing_identity {
                mark_note_gap(tx, scope, key.note)?;
            }
        }
    }
    Ok(())
}

/// Canonical Note text for search extraction, read through the existing read
/// pool outside every write transaction. Bodies are the literal document text.
/// The walk is bounded: content nested deeper than sixteen levels is skipped,
/// the walk stops after roughly four source items per indexed byte, and an
/// engine failure is treated like an unavailable body, so a long or degraded
/// Note indexes a shorter prefix rather than blocking its queue.
#[derive(Clone)]
pub struct NoteBodyText {
    readers: Arc<ReadPool>,
}

impl NoteBodyText {
    fn key(scope: Scope, record: RecordId) -> NoteKey {
        NoteKey {
            base: scope.base,
            audience: scope.audience,
            note: record.0,
        }
    }

    /// The next bounded extraction batch, selected through the read pool and
    /// decoded outside every write transaction. Callers pass the batch to a
    /// short guarded write ([`text::store_batch_bounded`]) afterwards.
    pub fn next_batch(&self, max_jobs: usize) -> Result<Vec<text::DecodedJob>, StoreError> {
        let jobs = self
            .readers
            .with_connection(|conn| text::next_batch(conn, max_jobs).map_err(StoreError::Data))?;
        let mut batch = Vec::with_capacity(jobs.len());
        for job in jobs {
            let body = self
                .body_text(job.scope, job.record)
                .map_err(StoreError::Data)?;
            batch.push(text::DecodedJob { job, body });
        }
        Ok(batch)
    }
}

impl BodyText for NoteBodyText {
    fn body_text(&self, scope: Scope, record: RecordId) -> Result<Option<String>, DataError> {
        let loaded = match self.readers.load_note(Self::key(scope, record)) {
            Ok(loaded) => loaded,
            Err(StoreError::NoteUnavailable | StoreError::InvalidUpdate) => return Ok(None),
            Err(error) => return Err(DataError::Sql(error.to_string())),
        };
        Ok(loaded.note.body_text(MAX_INDEXED_BODY_BYTES).ok())
    }
}

/// Replay the durable repair queue in bounded attempts. Each transaction uses
/// the Note's catalogue title, so a repair never decodes the Note. A successful
/// repair clears its record, closes the record's gap once nothing else keeps it
/// open, and replays the work parked on that record; a failed one stays, with
/// the newest reason, for a later turn.
pub(crate) fn repair_step(conn: &mut Connection, max_repairs: usize) -> Result<usize, StoreError> {
    if max_repairs == 0 {
        return Ok(0);
    }
    let keys: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = conn
        .prepare(
            "SELECT base,audience,note FROM note_projection_repair
             ORDER BY base,audience,note LIMIT ?1",
        )?
        .query_map([max_repairs as i64], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    let mut repaired = 0;
    for (base, audience, note) in keys {
        let scope = Scope {
            base: base.try_into().map_err(|_| StoreError::CorruptSyncState)?,
            audience: audience
                .try_into()
                .map_err(|_| StoreError::CorruptSyncState)?,
        };
        let record = RecordId(note.try_into().map_err(|_| StoreError::CorruptSyncState)?);
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let title = catalogued_title(&tx, NoteBodyText::key(scope, record))?;
        match note::upsert_projection(&tx, scope, record, &title) {
            Ok(_) => {
                tx.execute(
                    "DELETE FROM note_projection_repair WHERE base=?1 AND audience=?2 AND note=?3",
                    params![
                        scope.base.as_slice(),
                        scope.audience.as_slice(),
                        record.0.as_slice()
                    ],
                )?;
                if refresh_note_gap(&tx, scope, record.0)? {
                    replay_parked_for(&tx, scope, record.0)?;
                }
                tx.commit()?;
                repaired += 1;
            }
            Err(error) => {
                tx.execute(
                    "UPDATE note_projection_repair SET reason=?4
                     WHERE base=?1 AND audience=?2 AND note=?3",
                    params![
                        scope.base.as_slice(),
                        scope.audience.as_slice(),
                        record.0.as_slice(),
                        error.to_string()
                    ],
                )?;
                tx.commit()?;
            }
        }
    }
    Ok(repaired)
}

impl NoteBodyText {
    /// Read-only access for one bounded turn, without borrowing the writer.
    pub(crate) fn for_pool(readers: Arc<ReadPool>) -> Self {
        Self { readers }
    }
}
