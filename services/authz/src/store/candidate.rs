//! Unselected BASE projection generations, and the BASE copy's suffix writer.
//!
//! Registration replays a base's raw controls from its genesis into a fresh
//! generation: each staged batch appends exact raw commitments, their routed
//! first uses, the control state they reached and at most one effect's
//! copied originals. Nothing staged is authority until the final conditional
//! save selects that whole generation. Ordinary saves append only the copies
//! of the effect they consume to the selected generation.
use super::{
    Projection, Record, ServiceError, Status, Store, array, pending,
    projection::{
        Pin, ProjectionWrite, Source, SourceKey, apply_delta, identity, number, source_row, sql,
        validate, validate_pin,
    },
    storage,
};
use bh_account::projection::Checkpoint;
use bh_authz_proto::LogKind;
use bh_event::{AccountCopy, ControlState};
use bh_sync::{BaseId, Commitment, Digest, EventId, OrderState, RawControlHead, Route};
use rusqlite::{OptionalExtension, Transaction, params};

pub(super) fn schema(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    tx.execute_batch(
        "CREATE TABLE base_generations(
           base BLOB NOT NULL, generation INTEGER NOT NULL, account BLOB NOT NULL,
           genesis BLOB NOT NULL, phase INTEGER NOT NULL,
           raw_position INTEGER NOT NULL, raw_hash BLOB NOT NULL, control BLOB,
           PRIMARY KEY(base, generation));
         CREATE TABLE base_raw(
           base BLOB NOT NULL, generation INTEGER NOT NULL, position INTEGER NOT NULL,
           commitment BLOB NOT NULL, PRIMARY KEY(base, generation, position));
         CREATE TABLE base_ids(
           base BLOB NOT NULL, generation INTEGER NOT NULL, id BLOB NOT NULL,
           position INTEGER NOT NULL, PRIMARY KEY(base, generation, id));
         CREATE TABLE projection_copies(
           account BLOB NOT NULL, kind INTEGER NOT NULL, source BLOB NOT NULL,
           generation INTEGER NOT NULL, position INTEGER NOT NULL, bytes BLOB NOT NULL,
           confirmation BLOB, PRIMARY KEY(account, kind, source, generation, position));
         ALTER TABLE base_stops ADD COLUMN path_generation INTEGER;",
    )
}

/// A generation's phase: still staging, selected once (then frozen, never
/// extended as a candidate again), or abandoned or replaced, then cleaned.
const STAGING: i64 = 0;
const PUBLISHED: i64 = 1;
const DISCARDED: i64 = 2;

/// An opaque handle to an unselected BASE generation. It authorizes nothing.
#[derive(Clone, Copy)]
pub(crate) struct Candidate {
    pub pin: Pin,
    pub prefix: Pin,
    pub base: BaseId,
}

/// A base's compact durable record: its control projection, the BASE copy's
/// selected pin and the one HOME prefix it extends. No copy is loaded.
pub(crate) struct BaseSnapshot {
    pub projection: Projection,
    pub pin: Pin,
    pub anchor: Pin,
}

/// The BASE copy a conditional save writes with its control record: a
/// candidate to select (registration), or the selected `previous` pin the
/// exact consumed effect's `copies` extend. `expected_home` is the HOME pin
/// the operation ran under.
pub(crate) struct BaseWrite<'a> {
    pub candidate: Option<&'a Candidate>,
    pub previous: Option<Pin>,
    pub projection: &'a ProjectionWrite,
    pub copies: &'a [AccountCopy],
    pub anchor: Pin,
    pub expected_home: Pin,
}

/// Exact control state, for comparison only.
fn encode_state(state: &ControlState) -> Vec<u8> {
    let mut out = Vec::with_capacity(400);
    out.extend(state.base.0);
    out.extend(state.creator.0);
    out.extend(state.hosting_root);
    out.extend(state.metadata_id);
    out.push(u8::from(state.epoch.is_some()));
    out.extend(state.epoch.unwrap_or([0; 32]));
    out.extend(state.floor.to_be_bytes());
    for head in [state.control, state.control_head] {
        out.extend(head.position.to_be_bytes());
        out.extend(head.hash.0);
    }
    out.extend(state.control_digest);
    out.extend(state.order.encode());
    out.extend(state.account.position.to_be_bytes());
    out.extend(state.account.hash);
    out
}

fn base_key(account: bh_account::AccountId, base: BaseId) -> SourceKey {
    SourceKey {
        account,
        source: Source::Base(base),
    }
}

/// Each copy's verified confirmed bounds, or None for a legacy copy, checked
/// before any writer lock: exact original, predecessor and head positions
/// after `previous`, under the write's pinned hosting root.
pub(super) fn prepare_copies(
    write: &ProjectionWrite,
    copies: &[AccountCopy],
    previous: Pin,
) -> rusqlite::Result<Vec<Option<(i64, i64)>>> {
    if copies.len() > 64 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut before = previous.cut;
    let mut bounds = Vec::with_capacity(copies.len());
    for copy in copies {
        let position = before.position + 1;
        let hash = bh_crypto::hash(&copy.original);
        bounds.push(match &copy.confirmation {
            None => None,
            Some(bytes) => {
                let confirmation = bh_sync::evidence::OrderingConfirmation::decode(bytes)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let claim = confirmation
                    .verify(&write.header.root)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let head = |position, hash| bh_sync::Head {
                    position,
                    hash: Digest(hash),
                };
                if claim.original != bh_sync::evidence::original_digest(&copy.original)
                    || claim.original_head != head(position, hash)
                    || claim.original_previous != head(before.position, before.hash)
                    || claim.bounds.earliest_ms > claim.bounds.latest_ms
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                Some((sql(claim.bounds.earliest_ms)?, sql(claim.bounds.latest_ms)?))
            }
        });
        before = bh_account::Head { position, hash };
    }
    // No callback, including test instrumentation, runs inside the writer.
    #[cfg(test)]
    super::projection::run_validation_hook()?;
    Ok(bounds)
}

/// Append exactly `copies` after `previous` to a BASE generation, with their
/// original confirmations unchanged, their times and the bounded delta, in
/// the caller's transaction. The generation's stored cut must be `previous`.
pub(super) fn write_base_projection(
    tx: &Transaction<'_>,
    write: &ProjectionWrite,
    bounds: &[Option<(i64, i64)>],
    copies: &[AccountCopy],
    previous: Pin,
) -> rusqlite::Result<()> {
    let pin = write.header.pin;
    let (kind, source) = identity(pin.key.source);
    let d = &write.delta;
    let added = pin.cut.position.checked_sub(previous.cut.position);
    if kind != 2
        || pin.key != previous.key
        || pin.generation != previous.generation
        || pin.generation == 0
        || write.checkpoint.account != pin.key.account
        || write.checkpoint.head != pin.cut
        || d.expected != (previous.cut.position, previous.cut.hash)
        || d.through != (pin.cut.position, pin.cut.hash)
        || d.summary != write.checkpoint.summary
        || d.epoch != Some(pin.generation)
        || added != Some(copies.len() as u64)
        || bounds.len() != copies.len()
        || !write.snapshots.is_empty()
        || copies
            .last()
            .is_some_and(|c| bh_crypto::hash(&c.original) != pin.cut.hash)
        || (copies.is_empty() && pin.cut != previous.cut)
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let (root, prefix) = source_row(tx, pin.key, pin.generation)?;
    let stored: (u64, Vec<u8>) = tx.query_row(
        "SELECT position, hash FROM projection_current WHERE account=?1 AND kind=2 AND source=?2 AND generation=?3",
        params![pin.key.account.0.as_slice(), source.as_slice(), sql(pin.generation)?],
        |r| Ok((number(r, 0)?, r.get(1)?)),
    )?;
    if root != write.header.root
        || prefix.is_none()
        || prefix != write.header.prefix
        || stored != (previous.cut.position, previous.cut.hash.to_vec())
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    for (i, (copy, bounds)) in copies.iter().zip(bounds).enumerate() {
        let position = sql(previous.cut.position + 1 + i as u64)?;
        tx.execute(
            "INSERT INTO projection_copies(account,kind,source,generation,position,bytes,confirmation)
             VALUES(?1,2,?2,?3,?4,?5,?6)",
            params![
                pin.key.account.0.as_slice(),
                source.as_slice(),
                sql(pin.generation)?,
                position,
                copy.original,
                copy.confirmation
            ],
        )?;
        tx.execute(
            "INSERT INTO projection_times(account,kind,source,generation,position,earliest,latest)
             VALUES(?1,2,?2,?3,?4,?5,?6)",
            params![
                pin.key.account.0.as_slice(),
                source.as_slice(),
                sql(pin.generation)?,
                position,
                bounds.map(|b| b.0),
                bounds.map(|b| b.1)
            ],
        )?;
    }
    apply_delta(tx, write)
}

/// One generation's staging row.
struct Generation {
    phase: i64,
    raw: RawControlHead,
    control: Option<Vec<u8>>,
    genesis: Vec<u8>,
}

/// The generation's phase, staged raw head and control state, if it is this
/// base's and account's.
fn generation_row(tx: &Transaction<'_>, candidate: &Candidate) -> rusqlite::Result<Generation> {
    generation_at(tx, candidate.base, candidate.pin)
}

fn generation_at(tx: &Transaction<'_>, base: BaseId, pin: Pin) -> rusqlite::Result<Generation> {
    let (account, row) = tx.query_row(
        "SELECT account, phase, raw_position, raw_hash, control, genesis FROM base_generations
         WHERE base=?1 AND generation=?2",
        params![base.0.as_slice(), sql(pin.generation)?],
        |r| {
            Ok((
                r.get::<_, Vec<u8>>(0)?,
                Generation {
                    phase: r.get(1)?,
                    raw: RawControlHead {
                        position: number(r, 2)?,
                        node_hash: Digest(array(r.get(3)?)?),
                    },
                    control: r.get(4)?,
                    genesis: r.get(5)?,
                },
            ))
        },
    )?;
    if account != pin.key.account.0 || pin.key != base_key(pin.key.account, base) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(row)
}

fn stop_referenced(tx: &Transaction<'_>, base: BaseId, generation: u64) -> rusqlite::Result<bool> {
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM base_stops WHERE base=?1 AND path_generation=?2)",
        params![base.0.as_slice(), sql(generation)?],
        |r| r.get(0),
    )
}

fn selected(tx: &rusqlite::Connection, key: SourceKey) -> rusqlite::Result<Option<u64>> {
    let (kind, source) = identity(key.source);
    tx.query_row(
        "SELECT generation FROM projection_selected WHERE account=?1 AND kind=?2 AND source=?3",
        params![key.account.0.as_slice(), kind, source.as_slice()],
        |r| number(r, 0),
    )
    .optional()
}

fn current_cut(
    tx: &rusqlite::Connection,
    key: SourceKey,
    generation: u64,
) -> rusqlite::Result<Option<bh_account::Head>> {
    let (kind, source) = identity(key.source);
    tx.query_row(
        "SELECT position, hash FROM projection_current WHERE account=?1 AND kind=?2 AND source=?3 AND generation=?4",
        params![key.account.0.as_slice(), kind, source.as_slice(), sql(generation)?],
        |r| {
            Ok(bh_account::Head {
                position: number(r, 0)?,
                hash: array(r.get(1)?)?,
            })
        },
    )
    .optional()
}

/// Stream a candidate's staged raw path inside `tx`: every row links from
/// the empty raw head under this base and root, on the control route.
/// Returns the terminal raw head and whether `witness` matched any control.
pub(super) fn staged_path(
    tx: &Transaction<'_>,
    candidate: &Candidate,
    root: [u8; 32],
    mut witness: impl FnMut(&Commitment) -> bool,
) -> rusqlite::Result<(RawControlHead, bool)> {
    let Generation {
        phase, raw: staged, ..
    } = generation_row(tx, candidate)?;
    if phase == DISCARDED || source_row(tx, candidate.pin.key, candidate.pin.generation)?.0 != root
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut statement = tx.prepare(
        "SELECT commitment FROM base_raw WHERE base=?1 AND generation=?2 ORDER BY position",
    )?;
    let mut rows = statement.query(params![
        candidate.base.0.as_slice(),
        sql(candidate.pin.generation)?
    ])?;
    let (mut raw, mut found) = (RawControlHead::EMPTY, false);
    while let Some(row) = rows.next()? {
        let control = Commitment::decode(&row.get::<_, Vec<u8>>(0)?)
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
        if control.base() != candidate.base
            || control.route() != Route::Control
            || control.before().raw_control() != raw
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        raw = control.after().raw_control();
        found |= witness(&control);
    }
    if raw != staged {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok((raw, found))
}

/// Select a candidate, or extend the selected BASE generation, under the
/// final conditional save's transaction. `Ok(None)`: the selection, its cut
/// or the HOME pin moved since the operation began (nothing written).
/// `no_record`: the base has no durable control record.
pub(super) fn save_projected_base(
    tx: &Transaction<'_>,
    status: Status,
    state: &ControlState,
    write: &BaseWrite<'_>,
    bounds: &[Option<(i64, i64)>],
    no_record: bool,
) -> rusqlite::Result<Option<u64>> {
    let key = base_key(state.creator, state.base);
    let home = write.expected_home;
    let anchor = write.anchor;
    if !matches!(home.key.source, Source::Home(log) if log.kind == LogKind::Account)
        || home.key.account != state.creator
        || anchor.key != home.key
        || anchor.cut.position > home.cut.position
        || write.projection.header.pin.key != key
        || write.projection.header.pin.cut != state.account
        || write.projection.header.opening != state.order
        || write.projection.header.prefix != Some(anchor)
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    // The HOME pin the operation ran under is still the account's own.
    if selected(tx, home.key)? != Some(home.generation)
        || current_cut(tx, home.key, home.generation)? != Some(home.cut)
    {
        return Ok(None);
    }
    validate_pin(tx, anchor)?;
    let chosen = selected(tx, key)?;
    let unchanged = |previous: Pin| -> rusqlite::Result<bool> {
        Ok(previous.key == key
            && chosen == Some(previous.generation)
            && current_cut(tx, key, previous.generation)? == Some(previous.cut))
    };
    match (write.candidate, write.previous) {
        (Some(candidate), previous) => {
            if candidate.base != state.base
                || candidate.pin.key != key
                || candidate.prefix != anchor
                || !write.copies.is_empty()
                || write.projection.header.pin != candidate.pin
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            // A base with no record has no selection a reader can use; a
            // stale one left by a deleted record is replaced, never extended.
            match previous {
                None if !no_record => return Ok(None),
                Some(_) if no_record => return Ok(None),
                Some(previous) if !unchanged(previous)? => return Ok(None),
                _ => {}
            }
            let Generation {
                phase,
                raw,
                control,
                ..
            } = generation_row(tx, candidate)?;
            let staged = match status {
                Status::Accepted => {
                    raw == state.order.raw_control() && control == Some(encode_state(state))
                }
                // Not yet ordered: nothing staged, the exact verified genesis
                // state only.
                Status::Provisional => raw == RawControlHead::EMPTY && control.is_none(),
            };
            if phase != STAGING
                || stop_referenced(tx, state.base, candidate.pin.generation)?
                || !staged
                || current_cut(tx, key, candidate.pin.generation)? != Some(candidate.pin.cut)
                || source_row(tx, key, candidate.pin.generation)?.1 != Some(anchor)
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            // The candidate's own current checkpoint is published unchanged.
            write_base_projection(tx, write.projection, &[], &[], candidate.pin)?;
            tx.execute(
                "INSERT INTO projection_selected(account,kind,source,generation) VALUES(?1,2,?2,?3)
                 ON CONFLICT(account,kind,source) DO UPDATE SET generation=excluded.generation",
                params![
                    state.creator.0.as_slice(),
                    state.base.0.as_slice(),
                    sql(candidate.pin.generation)?
                ],
            )?;
            tx.execute(
                "UPDATE base_generations SET phase=?3 WHERE base=?1 AND generation=?2",
                params![
                    state.base.0.as_slice(),
                    sql(candidate.pin.generation)?,
                    PUBLISHED
                ],
            )?;
            Ok(Some(candidate.pin.generation))
        }
        (None, Some(previous)) => {
            if no_record || !unchanged(previous)? {
                return Ok(None);
            }
            if source_row(tx, key, previous.generation)?.1 != Some(anchor) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            write_base_projection(tx, write.projection, bounds, write.copies, previous)?;
            Ok(Some(previous.generation))
        }
        (None, None) => Err(rusqlite::Error::InvalidQuery),
    }
}

impl Store {
    /// Start an unselected BASE generation for `base`, seeded with one exact
    /// verified HOME view at `prefix`, its checkpoint `initial`. Nothing of
    /// that HOME history is copied: the generation reads it through the pin.
    pub(crate) fn begin_candidate(
        &self,
        base: BaseId,
        prefix: Pin,
        root: [u8; 32],
        genesis: &Commitment,
        initial: &Checkpoint,
    ) -> Result<Candidate, ServiceError> {
        let Source::Home(log) = prefix.key.source else {
            return Err(ServiceError::Storage);
        };
        if log.kind != LogKind::Account
            || prefix.cut.position == 0
            || initial.account != prefix.key.account
            || initial.head != prefix.cut
            || initial.stopped
            || genesis.base() != base
            || genesis.before() != OrderState::EMPTY
            || genesis.route() != Route::Control
        {
            return Err(ServiceError::Storage);
        }
        let account = prefix.key.account;
        self.staging(|db| {
            let tx = db.transaction()?;
            if validate_pin(&tx, prefix)? != root {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let generation: u64 = tx.query_row(
                "SELECT COALESCE(MAX(generation), 0) + 1 FROM base_generations WHERE base=?1",
                [base.0.as_slice()],
                |r| number(r, 0),
            )?;
            let g = sql(generation)?;
            tx.execute(
                "INSERT INTO base_generations(base,generation,account,genesis,phase,raw_position,raw_hash,control)
                 VALUES(?1,?2,?3,?4,?5,0,?6,NULL)",
                params![
                    base.0.as_slice(),
                    g,
                    account.0.as_slice(),
                    genesis.encode().as_slice(),
                    STAGING,
                    [0u8; 32].as_slice()
                ],
            )?;
            tx.execute(
                "INSERT INTO projection_sources(account,kind,source,generation,root,prefix_account,
                   prefix_kind,prefix_source,prefix_generation,prefix_position,prefix_hash)
                 VALUES(?1,2,?2,?3,?4,?1,1,?5,?6,?7,?8)",
                params![
                    account.0.as_slice(),
                    base.0.as_slice(),
                    g,
                    root.as_slice(),
                    log.id.as_slice(),
                    sql(prefix.generation)?,
                    sql(prefix.cut.position)?,
                    prefix.cut.hash.as_slice()
                ],
            )?;
            tx.execute(
                "INSERT INTO projection_current(account,kind,source,generation,position,hash,summary,stopped,opening)
                 VALUES(?1,2,?2,?3,?4,?5,?6,0,?7)",
                params![
                    account.0.as_slice(),
                    base.0.as_slice(),
                    g,
                    sql(prefix.cut.position)?,
                    prefix.cut.hash.as_slice(),
                    initial.summary,
                    OrderState::EMPTY.encode().as_slice()
                ],
            )?;
            for row in &initial.active {
                if row.added == 0 || row.added > prefix.cut.position {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                tx.execute(
                    "INSERT INTO projection_active(account,kind,source,generation,device,keys,added)
                     VALUES(?1,2,?2,?3,?4,?5,?6)",
                    params![
                        account.0.as_slice(),
                        base.0.as_slice(),
                        g,
                        row.device.as_slice(),
                        row.keys,
                        sql(row.added)?
                    ],
                )?;
            }
            tx.commit()?;
            Ok(Candidate {
                pin: Pin {
                    key: base_key(account, base),
                    generation,
                    cut: prefix.cut,
                },
                prefix,
                base,
            })
        })
    }

    /// Stage one verified raw batch in its candidate: one control's effect
    /// with at most 64 copies (its raw commitment last), or at most 64
    /// rejected raw controls. `state` is the spine after them and `write`
    /// the copy's checkpoint and delta. Returns the candidate's new pin.
    pub(crate) fn stage_candidate(
        &self,
        candidate: &Candidate,
        state: &ControlState,
        copies: &[AccountCopy],
        write: &ProjectionWrite,
        raw: &[Commitment],
    ) -> Result<Pin, ServiceError> {
        let base = candidate.base;
        let pin = write.header.pin;
        if raw.is_empty()
            || raw.len() > 64
            || state.base != base
            || state.creator != candidate.pin.key.account
            || state.order.head(base) != state.control_head
            || raw.last().map(Commitment::after) != Some(state.order)
            || pin.key != candidate.pin.key
            || pin.generation != candidate.pin.generation
            || pin.cut != state.account
            || write.header.prefix != Some(candidate.prefix)
            || write.header.opening != state.order
            || raw
                .iter()
                .any(|c| c.base() != base || c.route() != Route::Control)
            || raw
                .windows(2)
                .any(|pair| pair[1].before().raw_control() != pair[0].after().raw_control())
        {
            return Err(ServiceError::Storage);
        }
        let bounds = prepare_copies(write, copies, candidate.pin).map_err(storage)?;
        self.staging(|db| {
            let tx = db.transaction()?;
            let Generation {
                phase,
                raw: staged,
                genesis,
                ..
            } = generation_row(&tx, candidate)?;
            if phase != STAGING
                || stop_referenced(&tx, base, pin.generation)?
                || selected(&tx, pin.key)? == Some(pin.generation)
                || raw[0].before().raw_control() != staged
                || (staged == RawControlHead::EMPTY && raw[0].encode().as_slice() != genesis)
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            write_base_projection(&tx, write, &bounds, copies, candidate.pin)?;
            let g = sql(pin.generation)?;
            for control in raw {
                let position = sql(control.head().position)?;
                tx.execute(
                    "INSERT INTO base_raw(base,generation,position,commitment) VALUES(?1,?2,?3,?4)",
                    params![base.0.as_slice(), g, position, control.encode().as_slice()],
                )?;
                tx.execute(
                    "INSERT OR IGNORE INTO base_ids(base,generation,id,position) VALUES(?1,?2,?3,?4)",
                    params![base.0.as_slice(), g, control.event_id().0.as_slice(), position],
                )?;
            }
            let terminal = state.order.raw_control();
            tx.execute(
                "UPDATE base_generations SET raw_position=?3, raw_hash=?4, control=?5
                 WHERE base=?1 AND generation=?2",
                params![
                    base.0.as_slice(),
                    g,
                    sql(terminal.position)?,
                    terminal.node_hash.0.as_slice(),
                    encode_state(state)
                ],
            )?;
            tx.commit()
        })?;
        Ok(pin)
    }

    /// Whether this candidate's already-staged prefix first used `id` before
    /// global position `before`. Never the selected generation's IDs.
    pub(crate) fn candidate_id_used(
        &self,
        candidate: &Candidate,
        before: u64,
        id: EventId,
    ) -> Result<bool, ServiceError> {
        self.with(|db| {
            db.query_row(
                "SELECT EXISTS(SELECT 1 FROM base_ids WHERE base=?1 AND generation=?2 AND id=?3 AND position<?4)",
                params![
                    candidate.base.0.as_slice(),
                    sql(candidate.pin.generation)?,
                    id.0.as_slice(),
                    sql(before)?
                ],
                |r| r.get(0),
            )
        })
    }

    /// Whether `id` was first used in the base generation `pin` selects.
    pub(crate) fn base_id_used(&self, pin: Pin, id: EventId) -> Result<bool, ServiceError> {
        let Source::Base(base) = pin.key.source else {
            return Err(ServiceError::Storage);
        };
        self.with(|db| {
            db.query_row(
                "SELECT EXISTS(SELECT 1 FROM base_ids WHERE base=?1 AND generation=?2 AND id=?3)",
                params![base.0.as_slice(), sql(pin.generation)?, id.0.as_slice()],
                |r| r.get(0),
            )
        })
    }

    /// Up to `limit` (at most 64) of the candidate's staged raw commitments
    /// after global position `after`, in order: a stop-pinned path read back
    /// a page at a time. Nothing in the service reads one back yet.
    #[cfg(test)]
    pub(crate) fn candidate_raw_page(
        &self,
        candidate: &Candidate,
        after: u64,
        limit: u16,
    ) -> Result<Vec<Commitment>, ServiceError> {
        if limit > 64 {
            return Err(ServiceError::Storage);
        }
        self.with(|db| {
            let mut statement = db.prepare(
                "SELECT commitment FROM base_raw WHERE base=?1 AND generation=?2 AND position>?3
                 ORDER BY position LIMIT ?4",
            )?;
            statement
                .query_map(
                    params![
                        candidate.base.0.as_slice(),
                        sql(candidate.pin.generation)?,
                        sql(after)?,
                        i64::from(limit)
                    ],
                    |r| {
                        Commitment::decode(&r.get::<_, Vec<u8>>(0)?)
                            .map_err(|_| rusqlite::Error::InvalidQuery)
                    },
                )?
                .collect()
        })
    }

    /// Delete at most `limit` rows of an abandoned candidate or a replaced
    /// published generation: never a selected or stop-referenced one, one
    /// another source reads as its prefix, or the HOME rows it read. The
    /// first call makes it unreachable (no pin of it validates), then rows
    /// go in batches. Returns whether anything changed; false once nothing
    /// is left (or it must be kept).
    pub(crate) fn discard_generation(&self, pin: Pin, limit: u16) -> Result<bool, ServiceError> {
        let Source::Base(base) = pin.key.source else {
            return Err(ServiceError::Storage);
        };
        self.with(|db| {
            let tx = db.transaction()?;
            let key = pin.key;
            let g = sql(pin.generation)?;
            let (account, base) = (key.account.0, base.0);
            let mut changed = false;
            if generation_at(&tx, BaseId(base), pin)?.phase != DISCARDED {
                let prefix: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM projection_sources WHERE prefix_account=?1
                       AND prefix_kind=2 AND prefix_source=?2 AND prefix_generation=?3)",
                    params![account.as_slice(), base.as_slice(), g],
                    |r| r.get(0),
                )?;
                if stop_referenced(&tx, BaseId(base), pin.generation)?
                    || selected(&tx, key)? == Some(pin.generation)
                    || prefix
                {
                    return Ok(false);
                }
                for table in ["projection_current", "projection_sources"] {
                    tx.execute(
                        &format!("DELETE FROM {table} WHERE account=?1 AND kind=2 AND source=?2 AND generation=?3"),
                        params![account.as_slice(), base.as_slice(), g],
                    )?;
                }
                tx.execute(
                    "UPDATE base_generations SET phase=?3 WHERE base=?1 AND generation=?2",
                    params![base.as_slice(), g, DISCARDED],
                )?;
                changed = true;
            }
            let mut left = i64::from(limit);
            for (table, scope) in [
                ("base_raw", "base=?1 AND generation=?2"),
                ("base_ids", "base=?1 AND generation=?2"),
                ("projection_copies", "account=?3 AND kind=2 AND source=?1 AND generation=?2"),
                ("projection_times", "account=?3 AND kind=2 AND source=?1 AND generation=?2"),
                ("projection_devices", "account=?3 AND kind=2 AND source=?1 AND generation=?2"),
                ("projection_keys", "account=?3 AND kind=2 AND source=?1 AND generation=?2"),
                ("projection_active", "account=?3 AND kind=2 AND source=?1 AND generation=?2"),
            ] {
                if left == 0 {
                    break;
                }
                left -= tx.execute(
                    &format!(
                        "DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {scope} LIMIT ?4)"
                    ),
                    params![base.as_slice(), g, account.as_slice(), left],
                )? as i64;
            }
            changed |= left < i64::from(limit);
            tx.commit()?;
            Ok(changed)
        })
    }

    /// The base's compact durable record: control projection, pending control
    /// and its selected BASE copy's pin and HOME anchor. A canonical record
    /// without a selected BASE copy predates it: never a new empty base.
    pub(crate) fn base_snapshot(
        &self,
        base: BaseId,
    ) -> Result<Option<Record<BaseSnapshot>>, ServiceError> {
        self.with(|db| {
            let Some(found) = db
                .query_row(
                    "SELECT creator, hosting_root, metadata_id, epoch, floor,
                       control_position, control_hash, control_digest,
                       head_position, head_hash, account_position, account_hash,
                       format, status, raw_order
                     FROM base_controls WHERE base=?1",
                    [base.0.as_slice()],
                    |r| super::projection(base.0, r),
                )
                .optional()?
            else {
                return Ok(None);
            };
            let Record::Canonical((status, state)) = found else {
                return Ok(Some(Record::Legacy));
            };
            let key = base_key(state.creator, base);
            let Some(generation) = selected(db, key)? else {
                return Ok(Some(Record::Legacy));
            };
            let pin = Pin {
                key,
                generation,
                cut: current_cut(db, key, generation)?.ok_or(rusqlite::Error::InvalidQuery)?,
            };
            #[cfg(test)]
            super::projection::source_work(key);
            let (_, anchor) = validate(db, pin)?;
            if pin.cut != state.account {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let pending = db
                .query_row(
                    "SELECT event_id, after_position, after_hash, deadline, digest, epoch_after,
                       account_position, account_hash, change, account_event, floor,
                       seen_position, judged_control, judged_account_position,
                       judged_account_hash, seal_set
                     FROM base_pending WHERE base=?1",
                    [base.0.as_slice()],
                    pending,
                )
                .optional()?;
            Ok(Some(Record::Canonical(BaseSnapshot {
                projection: Projection {
                    status,
                    state,
                    pending,
                },
                pin,
                anchor: anchor.ok_or(rusqlite::Error::InvalidQuery)?,
            })))
        })
    }
}
