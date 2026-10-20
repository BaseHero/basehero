//! An in-process ordered log and replicas over plain SQLite, for tests and
//! demonstrations. A replica behaves as the host contract requires: it
//! applies the log in order through [`apply::apply_payload`], treats
//! redelivered positions as no-ops, runs index backfills to completion, and
//! calls [`apply::retry_parked`] after every accepted definition, coverage
//! change and finished backfill.
use std::path::Path;

use rusqlite::{Connection, Transaction};
use serde_json::Value;

use crate::{
    Actor, DataError, MutationId, Position, Scope, WritePolicy,
    catalogue::Shipped,
    index,
    mutation::{
        apply::{self, Key, Outcome},
        ops::Operation,
        pending::{self, LocalSaved, SubmitError},
    },
    payload::{self, Decoded},
    store::{self, coverage, records, registry, sql},
    value,
};

/// Assumed device confirmations/read grants ONLY for isolated fixtures.
/// Not a production verifier; exact negative tests use the default boundary.
pub struct AssumedAdmission;
impl crate::admission::HostAdmission for AssumedAdmission {
    fn confirms(
        &self,
        request: &crate::admission::Confirmation,
        _at: Option<Position>,
    ) -> Result<bool, DataError> {
        Ok(matches!(request.actor, Actor::Device { .. }))
    }
    fn may_read_source(
        &self,
        _actor: &Actor,
        _source: Scope,
        _at: Option<Position>,
    ) -> Result<bool, DataError> {
        Ok(true)
    }
}
/// Fixture-only synthetic approval: discover the exact prior rules using a
/// rolled-back local evaluation, then place them in the typed payload. This is
/// not device signing and must never be used in a production host.
fn assumed_prior(
    tx: &Transaction<'_>,
    core: &dyn crate::CoreCatalogue,
    scope: Scope,
    actor: &Actor,
    op: &Operation,
) -> Result<Option<crate::admission::PriorRules>, DataError> {
    if op.record().is_some() {
        return Ok(None);
    }
    tx.execute_batch("SAVEPOINT assumed_prior").map_err(sql)?;
    let result = pending::submit_with_admission(
        tx,
        core,
        scope,
        actor,
        op.clone(),
        &crate::admission::Unavailable,
    );
    tx.execute_batch("ROLLBACK TO assumed_prior; RELEASE assumed_prior")
        .map_err(sql)?;
    Ok(match result {
        Err(SubmitError::ConfirmationRequired(request)) => Some(request.prior),
        _ => None,
    })
}
pub fn assumed_payload(
    tx: &Transaction<'_>,
    core: &dyn crate::CoreCatalogue,
    scope: Scope,
    actor: &Actor,
    mutation: MutationId,
    op: &Operation,
) -> Result<Vec<u8>, DataError> {
    payload::encode_with_confirmation(mutation, op, assumed_prior(tx, core, scope, actor, op)?)
}
/// Fixture wrappers retain real production evaluation; only host evidence is assumed.
pub fn apply_ordered(
    tx: &Transaction<'_>,
    core: &dyn crate::CoreCatalogue,
    ev: &apply::Ordered<'_>,
) -> Result<Outcome, DataError> {
    let bytes = assumed_payload(tx, core, ev.scope, ev.actor, ev.mutation, ev.op)?;
    apply::apply_payload_with_admission(
        tx,
        core,
        ev.scope,
        ev.position,
        ev.actor,
        &bytes,
        &AssumedAdmission,
    )
}
pub fn apply_payload(
    tx: &Transaction<'_>,
    core: &dyn crate::CoreCatalogue,
    scope: Scope,
    position: Position,
    actor: &Actor,
    bytes: &[u8],
) -> Result<Outcome, DataError> {
    apply::apply_payload_with_admission(tx, core, scope, position, actor, bytes, &AssumedAdmission)
}
pub fn retry_parked(
    tx: &Transaction<'_>,
    core: &dyn crate::CoreCatalogue,
    scope: Scope,
) -> Result<Vec<(Position, Outcome)>, DataError> {
    apply::retry_parked_with_admission(tx, core, scope, &AssumedAdmission)
}
pub fn retry_parked_for(
    tx: &Transaction<'_>,
    core: &dyn crate::CoreCatalogue,
    scope: Scope,
    key: Key,
) -> Result<Vec<(Position, Outcome)>, DataError> {
    apply::retry_parked_for_with_admission(tx, core, scope, key, &AssumedAdmission)
}
pub fn submit(
    tx: &Transaction<'_>,
    core: &dyn crate::CoreCatalogue,
    scope: Scope,
    actor: &Actor,
    op: Operation,
) -> Result<LocalSaved, SubmitError> {
    let prior = assumed_prior(tx, core, scope, actor, &op)?;
    pending::submit_with_confirmation(
        tx,
        core,
        scope,
        actor,
        op,
        &AssumedAdmission,
        MutationId::random(),
        prior,
    )
}

/// One ordered entry, as the service stores it: opaque payload bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub position: Position,
    pub scope: Scope,
    pub actor: Actor,
    pub payload: Vec<u8>,
}

/// A single server order shared by every scope; positions start at 1.
#[derive(Clone, Debug, Default)]
pub struct OrderedLog {
    entries: Vec<Entry>,
}

impl OrderedLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, scope: Scope, actor: &Actor, payload: Vec<u8>) -> Position {
        let position = Position(self.entries.len() as u64 + 1);
        self.entries.push(Entry {
            position,
            scope,
            actor: actor.clone(),
            payload,
        });
        position
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
}

/// How one [`Replica::sync_from`] receives the entries it has not applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Delivery {
    InOrder,
    /// Every entry arrives twice, and the last entry already applied arrives again.
    Duplicated,
    /// The listed positions are withheld: the replica applies the entries
    /// before the first of them and receives the rest, in order, at a later sync.
    Delayed(Vec<usize>),
}

pub struct Replica {
    conn: Connection,
    /// Log entries received so far.
    received: usize,
    host: Host,
}

/// The host behaviour around the connection.
#[derive(Default)]
struct Host {
    hold_backfill: bool,
    /// Operation kinds read as unsupported, as an older executable would.
    unknown_kinds: Vec<String>,
}

impl Replica {
    pub fn new_in_memory() -> Result<Self, DataError> {
        Self::open(Connection::open_in_memory().map_err(sql)?)
    }

    /// Opens or creates a replica file. A reopened replica receives the log
    /// from its start again; positions it already applied are no-ops.
    pub fn new_file(path: &Path) -> Result<Self, DataError> {
        Self::open(Connection::open(path).map_err(sql)?)
    }

    fn open(mut conn: Connection) -> Result<Self, DataError> {
        let tx = conn.transaction().map_err(sql)?;
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='data_scope')",
                [],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if !exists {
            store::migrate(&tx)?;
        }
        tx.commit().map_err(sql)?;
        Ok(Self {
            conn,
            received: 0,
            host: Host::default(),
        })
    }

    /// How many log entries this replica has received.
    pub fn received(&self) -> usize {
        self.received
    }

    /// The connection, for reads and queries.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Saves local work; the caller publishes `payload` to the log.
    pub fn submit(
        &mut self,
        scope: Scope,
        actor: &Actor,
        op: Operation,
    ) -> Result<LocalSaved, SubmitError> {
        let tx = self.conn.transaction().map_err(sql)?;
        let saved = submit(&tx, &Shipped, scope, actor, op)?;
        tx.commit().map_err(sql)?;
        Ok(saved)
    }

    /// Fixture-only approval bytes, against this replica's current rules.
    pub fn assumed_payload(
        &mut self,
        scope: Scope,
        actor: &Actor,
        mutation: MutationId,
        op: &Operation,
    ) -> Result<Vec<u8>, DataError> {
        let tx = self.conn.transaction().map_err(sql)?;
        assumed_payload(&tx, &Shipped, scope, actor, mutation, op)
    }

    /// Applies the entries this replica has not received, as `deliver`
    /// describes, and returns every delivery's outcome in arrival order.
    pub fn sync_from(
        &mut self,
        log: &OrderedLog,
        deliver: Delivery,
    ) -> Result<Vec<(Position, Outcome)>, DataError> {
        let fresh = &log.entries()[self.received..];
        let mut arrivals: Vec<&Entry> = Vec::new();
        match &deliver {
            Delivery::InOrder => arrivals.extend(fresh),
            Delivery::Duplicated => {
                arrivals.extend(self.received.checked_sub(1).map(|i| &log.entries()[i]));
                for entry in fresh {
                    arrivals.extend([entry, entry]);
                }
            }
            Delivery::Delayed(withheld) => arrivals.extend(
                fresh
                    .iter()
                    .take_while(|e| !withheld.contains(&(e.position.0 as usize))),
            ),
        }
        let mut outcomes = Vec::new();
        for entry in arrivals {
            outcomes.push((entry.position, self.deliver(entry)?));
            self.received = self.received.max(entry.position.0 as usize);
        }
        Ok(outcomes)
    }

    fn deliver(&mut self, entry: &Entry) -> Result<Outcome, DataError> {
        let decoded = self.host.decode(&entry.payload);
        let tx = self.conn.transaction().map_err(sql)?;
        // This replica receives the log from its start, so it covers every scope.
        let sid = records::scope_id(&tx, entry.scope, &Shipped)?;
        let before = coverage::get(&tx, sid)?;
        if !before.complete || before.through < Some(entry.position) {
            coverage::set(&tx, sid, entry.position, true)?;
        }
        let outcome = apply::apply_decoded(
            &tx,
            &Shipped,
            entry.scope,
            entry.position,
            &entry.actor,
            &entry.payload,
            decoded,
            &AssumedAdmission,
        )?;
        let definition = matches!(outcome, Outcome::Accepted { record: None, .. });
        if definition || !before.complete {
            self.host.maintain(&tx)?;
        }
        tx.commit().map_err(sql)?;
        Ok(outcome)
    }

    /// Leaves new indexes building until [`Replica::release_backfill`].
    pub fn hold_backfill(&mut self) {
        self.host.hold_backfill = true;
    }

    /// Finishes every building index, then replays parked work.
    pub fn release_backfill(&mut self) -> Result<(), DataError> {
        self.host.hold_backfill = false;
        self.write_maintained()
    }

    /// Acts as an older executable that cannot read these operation kinds
    /// (`"edit"`, `"undo"`, …): their payloads park as unsupported.
    pub fn without_kinds(&mut self, kinds: &[&str]) {
        self.host.unknown_kinds = kinds.iter().map(|k| (*k).to_owned()).collect();
    }

    /// Becomes the current executable and replays what the older one parked.
    pub fn upgrade(&mut self) -> Result<(), DataError> {
        self.host.unknown_kinds.clear();
        self.write_maintained()
    }

    fn write_maintained(&mut self) -> Result<(), DataError> {
        let tx = self.conn.transaction().map_err(sql)?;
        self.host.maintain(&tx)?;
        tx.commit().map_err(sql)
    }

    pub fn state_digest(&self, scope: Scope) -> Result<[u8; 32], DataError> {
        state_digest(&self.conn, scope)
    }
}

/// A digest of `scope`'s replicated record state: each record's type,
/// revision, last ordered position and accepted document
/// (`value::canonical`, without fields a builtin derives), and its field
/// clocks. Replica-local state (pending work, `$changed`, derived indexes,
/// Note projections no ordered operation has changed) is excluded, so
/// replicas that applied the same log agree.
pub fn state_digest(conn: &Connection, scope: Scope) -> Result<[u8; 32], DataError> {
    let mut state = Vec::new();
    if let Some(sid) = records::lookup_scope(conn, scope)? {
        let mut stmt = conn
            .prepare(
                "SELECT id,record FROM data_record WHERE scope=?1
                 AND (accepted IS NOT NULL OR changed_at IS NOT NULL) ORDER BY record",
            )
            .map_err(sql)?;
        let rows = stmt
            .query_map([sid], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(sql)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql)?;
        for (rec, record) in rows {
            let row = records::get(conn, sid, crate::RecordId(store::id(record)?))?
                .ok_or_else(|| DataError::Corrupt("record row vanished".into()))?;
            let derived = match builtin_derived(conn, sid, &row)? {
                // A Note's own projection is not ordered state.
                Some(_) if row.changed_at.is_none() => continue,
                Some(derived) => derived,
                None => Vec::new(),
            };
            let mut doc = row.accepted.clone();
            if let Some(doc) = doc.as_mut() {
                for path in &derived {
                    path.remove(doc);
                }
            }
            state.push(serde_json::json!({
                "record": row.record,
                "type": row.type_id,
                "revision": row.revision,
                "at": row.changed_at.map(|p| p.0),
                "doc": doc,
                "clocks": clocks(conn, rec, &derived)?,
            }));
        }
    }
    Ok(bh_crypto::hash(
        value::canonical(&Value::Array(state)).as_bytes(),
    ))
}

/// The fields a builtin derives, or `None` when the record's type has no builtin.
fn builtin_derived(
    conn: &Connection,
    sid: i64,
    row: &records::RecordRow,
) -> Result<Option<Vec<crate::FieldPath>>, DataError> {
    let ct = match registry::compiled(conn, sid, row.revision)? {
        Some(ct) => Some(ct),
        None => crate::CoreCatalogue::core_type(&Shipped, row.type_id)
            .filter(|ct| ct.revision == row.revision),
    };
    Ok(ct.filter(|ct| ct.builtin.is_some()).map(|ct| {
        ct.fields
            .into_iter()
            .filter(|f| f.write == WritePolicy::Derived)
            .map(|f| f.path)
            .collect()
    }))
}

fn clocks(
    conn: &Connection,
    rec: i64,
    derived: &[crate::FieldPath],
) -> Result<Vec<Value>, DataError> {
    let mut stmt = conn
        .prepare(
            "SELECT path,position,hex(mutation) FROM data_field_clock WHERE rec=?1 ORDER BY path",
        )
        .map_err(sql)?;
    let clocks = stmt
        .query_map([rec], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .map_err(sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(sql)?;
    Ok(clocks
        .into_iter()
        .filter(|(path, _, _)| !derived.iter().any(|d| d.as_pointer() == *path))
        .map(|(path, position, mutation)| serde_json::json!([path, position, mutation]))
        .collect())
}

impl crate::session::Store for Replica {
    fn read<R>(&self, f: impl FnOnce(&Connection) -> Result<R, DataError>) -> Result<R, DataError> {
        f(&self.conn)
    }

    fn write<R>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> Result<R, DataError>,
    ) -> Result<R, DataError> {
        let tx = self.conn.unchecked_transaction().map_err(sql)?;
        let result = f(&tx)?;
        self.host.maintain(&tx)?;
        tx.commit().map_err(sql)?;
        Ok(result)
    }

    fn core(&self) -> &dyn crate::CoreCatalogue {
        &Shipped
    }
}

impl Host {
    /// Runs backfills (unless held) and replays every scope's parked work,
    /// until replay changes nothing (a replayed definition may add indexes).
    fn maintain(&self, tx: &Transaction<'_>) -> Result<(), DataError> {
        loop {
            if !self.hold_backfill {
                for ix in index::pending_work(tx)? {
                    while !index::backfill_step(tx, ix, index::BACKFILL_BATCH)?.ready {}
                }
            }
            let scopes = tx
                .prepare("SELECT DISTINCT s.base,s.audience FROM data_parked p JOIN data_scope s ON s.id=p.scope")
                .map_err(sql)?
                .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?)))
                .map_err(sql)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sql)?;
            let mut applied = 0u64;
            for (base, audience) in scopes {
                let scope = Scope {
                    base: store::id(base)?,
                    audience: store::id(audience)?,
                };
                applied += apply::retry_with(
                    tx,
                    &Shipped,
                    scope,
                    &|bytes| self.decode(bytes),
                    &AssumedAdmission,
                )?
                .len() as u64;
            }
            if applied == 0 {
                return Ok(());
            }
        }
    }

    fn decode(&self, bytes: &[u8]) -> Decoded {
        match payload::decode(bytes) {
            Decoded::Op(_, op) if self.unknown_kinds.iter().any(|k| k == op.kind()) => {
                Decoded::Unsupported {
                    version: payload::PAYLOAD_VERSION,
                    affects: payload::affects_of(&op),
                    reason: format!("operation kind {}", op.kind()),
                }
            }
            decoded => decoded,
        }
    }
}
