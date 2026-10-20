//! SQLite on the service's protected disk: verified account histories (a
//! cache the edge can always rebuild), the base registry of verified geneses
//! (the only state the edge cannot), and each base's control record, which a
//! device rebuilds with M when it is lost. The connection lock is never held
//! across an await. No key is ever stored here.
use crate::ServiceError;
use bh_account::{AccountId, Head as AccountHead};
use bh_event::{ControlChange, ControlEffect, ControlState};
use bh_sync::{BaseId, Digest, Head};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use std::{path::Path, sync::Mutex};

const SCHEMA: i64 = 3;

pub(crate) struct Store {
    db: Mutex<Connection>,
}

/// One verified original account event and the body its wrapper carries.
pub(crate) struct StoredEvent {
    pub original: Vec<u8>,
    pub body: Option<Digest>,
}

/// An account's verified events in order and its account-log head.
pub(crate) struct StoredAccount {
    pub log: [u8; 32],
    pub head: Head,
    pub events: Vec<StoredEvent>,
}

/// What a base's verified genesis established: the creator account and the
/// content epoch (its content key's id). This is the base's state at its
/// genesis only; its control record follows the controls after it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerifiedBase {
    pub account: [u8; 32],
    pub epoch: [u8; 32],
}

/// A base control the service permitted and has not yet seen ordered: the
/// exact event, the control head it must follow, its permits' deadline and
/// its effect, judged with M before the permits were signed.
#[derive(Clone)]
pub(crate) struct Pending {
    pub event_id: [u8; 32],
    pub after: Head,
    pub deadline_ms: u64,
    pub effect: ControlEffect,
}

/// The durable base authority a conditional save expects to find unchanged:
/// the control head and the pending control's event, if any.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Prior {
    pub control_head: Head,
    pub pending: Option<[u8; 32]>,
}

fn storage<E>(_: E) -> ServiceError {
    ServiceError::Storage
}
fn array<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], rusqlite::Error> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, ServiceError> {
        let db = Connection::open(path).map_err(storage)?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS accounts(
               account BLOB PRIMARY KEY, log BLOB NOT NULL,
               position INTEGER NOT NULL, log_hash BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS account_events(
               account BLOB NOT NULL, position INTEGER NOT NULL, bytes BLOB NOT NULL,
               body BLOB, PRIMARY KEY(account, position));
             CREATE TABLE IF NOT EXISTS bases(
               base BLOB PRIMARY KEY, account BLOB NOT NULL, epoch BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS base_controls(
               base BLOB PRIMARY KEY, creator BLOB NOT NULL, hosting_root BLOB NOT NULL,
               metadata_id BLOB NOT NULL, epoch BLOB, floor INTEGER NOT NULL,
               control_position INTEGER NOT NULL, control_hash BLOB NOT NULL,
               control_digest BLOB NOT NULL,
               head_position INTEGER NOT NULL, head_hash BLOB NOT NULL,
               account_position INTEGER NOT NULL, account_hash BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS base_account_changes(
               base BLOB NOT NULL, position INTEGER NOT NULL, bytes BLOB NOT NULL,
               PRIMARY KEY(base, position));
             CREATE TABLE IF NOT EXISTS base_pending(
               base BLOB PRIMARY KEY, event_id BLOB NOT NULL,
               after_position INTEGER NOT NULL, after_hash BLOB NOT NULL,
               deadline INTEGER NOT NULL, digest BLOB NOT NULL, epoch_after BLOB,
               account_position INTEGER NOT NULL, account_hash BLOB NOT NULL,
               change INTEGER NOT NULL, account_event BLOB NOT NULL, floor INTEGER NOT NULL,
               seen_position INTEGER NOT NULL, judged_control BLOB NOT NULL,
               judged_account_position INTEGER NOT NULL, judged_account_hash BLOB NOT NULL);",
        )
        .map_err(storage)?;
        let schema: Option<i64> = db
            .query_row("SELECT value FROM meta WHERE key='schema'", [], |r| {
                r.get(0)
            })
            .optional()
            .map_err(storage)?;
        match schema {
            None => {
                db.execute(
                    "INSERT INTO meta(key, value) VALUES('schema', ?1)",
                    [SCHEMA],
                )
                .map_err(storage)?;
            }
            Some(SCHEMA) => {}
            Some(_) => return Err(ServiceError::Storage),
        }
        Ok(Self { db: Mutex::new(db) })
    }

    fn with<R>(
        &self,
        run: impl FnOnce(&mut Connection) -> rusqlite::Result<R>,
    ) -> Result<R, ServiceError> {
        let mut db = self.db.lock().map_err(storage)?;
        run(&mut db).map_err(storage)
    }

    pub fn account(&self, account: &[u8; 32]) -> Result<Option<StoredAccount>, ServiceError> {
        self.with(|db| {
            let Some((log, position, hash)) = db
                .query_row(
                    "SELECT log, position, log_hash FROM accounts WHERE account=?1",
                    [account.as_slice()],
                    |r| {
                        Ok((
                            r.get::<_, Vec<u8>>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, Vec<u8>>(2)?,
                        ))
                    },
                )
                .optional()?
            else {
                return Ok(None);
            };
            let mut statement = db.prepare(
                "SELECT bytes, body FROM account_events WHERE account=?1 ORDER BY position",
            )?;
            let events = statement
                .query_map([account.as_slice()], |r| {
                    Ok(StoredEvent {
                        original: r.get(0)?,
                        body: r
                            .get::<_, Option<Vec<u8>>>(1)?
                            .map(array)
                            .transpose()?
                            .map(Digest),
                    })
                })?
                .collect::<Result<Vec<_>, _>>()?;
            if events.len() as i64 != position {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(Some(StoredAccount {
                log: array(log)?,
                head: Head {
                    position: position as u64,
                    hash: Digest(array(hash)?),
                },
                events,
            }))
        })
    }

    /// Append verified originals after `previous`, in one transaction, only if
    /// the stored head is still `previous`.
    pub fn extend(
        &self,
        account: &[u8; 32],
        log: &[u8; 32],
        previous: Head,
        head: Head,
        events: &[StoredEvent],
    ) -> Result<(), ServiceError> {
        self.with(|db| {
            let tx = db.transaction()?;
            let stored: Option<(i64, Vec<u8>)> = tx
                .query_row(
                    "SELECT position, log_hash FROM accounts WHERE account=?1",
                    [account.as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            let expected = (previous.position as i64, previous.hash.0.to_vec());
            if stored.unwrap_or((0, [0; 32].to_vec())) != expected {
                return Err(rusqlite::Error::InvalidQuery);
            }
            for (i, event) in events.iter().enumerate() {
                tx.execute(
                    "INSERT INTO account_events(account, position, bytes, body)
                     VALUES(?1, ?2, ?3, ?4)",
                    params![
                        account.as_slice(),
                        (previous.position as i64) + 1 + i as i64,
                        event.original,
                        event.body.map(|b| b.0.to_vec()),
                    ],
                )?;
            }
            tx.execute(
                "INSERT INTO accounts(account, log, position, log_hash) VALUES(?1, ?2, ?3, ?4)
                 ON CONFLICT(account) DO UPDATE SET position=?3, log_hash=?4",
                params![
                    account.as_slice(),
                    log.as_slice(),
                    head.position as i64,
                    head.hash.0.as_slice()
                ],
            )?;
            tx.commit()
        })
    }

    /// The verified original at `position` of the account's history.
    pub fn account_event(
        &self,
        account: &[u8; 32],
        position: u64,
    ) -> Result<Option<Vec<u8>>, ServiceError> {
        self.with(|db| {
            db.query_row(
                "SELECT bytes FROM account_events WHERE account=?1 AND position=?2",
                params![account.as_slice(), position as i64],
                |r| r.get(0),
            )
            .optional()
        })
    }

    pub fn base(&self, base: &[u8; 32]) -> Result<Option<VerifiedBase>, ServiceError> {
        self.with(|db| {
            db.query_row(
                "SELECT account, epoch FROM bases WHERE base=?1",
                [base.as_slice()],
                |r| {
                    Ok(VerifiedBase {
                        account: array(r.get(0)?)?,
                        epoch: array(r.get(1)?)?,
                    })
                },
            )
            .optional()
        })
    }

    /// Record `base`'s verified genesis unless it is recorded; returns the
    /// record that stands. Call only after verifying that genesis.
    pub fn bind_base(
        &self,
        base: &[u8; 32],
        owner: VerifiedBase,
    ) -> Result<VerifiedBase, ServiceError> {
        self.with(|db| {
            db.execute(
                "INSERT OR IGNORE INTO bases(base, account, epoch) VALUES(?1, ?2, ?3)",
                params![
                    base.as_slice(),
                    owner.account.as_slice(),
                    owner.epoch.as_slice()
                ],
            )?;
            Ok(())
        })?;
        self.base(base)?.ok_or(ServiceError::Storage)
    }
}

fn head(position: i64, hash: Vec<u8>) -> Result<Head, rusqlite::Error> {
    Ok(Head {
        position: position as u64,
        hash: Digest(array(hash)?),
    })
}
fn account_head(position: i64, hash: Vec<u8>) -> Result<AccountHead, rusqlite::Error> {
    Ok(AccountHead {
        position: position as u64,
        hash: array(hash)?,
    })
}

impl Store {
    /// A base's control record and its pending control, if it has one.
    pub fn controls(
        &self,
        base: &[u8; 32],
    ) -> Result<Option<(ControlState, Option<Pending>)>, ServiceError> {
        self.with(|db| {
            let Some(mut state) = db
                .query_row(
                    "SELECT creator, hosting_root, metadata_id, epoch, floor,
                       control_position, control_hash, control_digest,
                       head_position, head_hash, account_position, account_hash
                     FROM base_controls WHERE base=?1",
                    [base.as_slice()],
                    |r| state(*base, r),
                )
                .optional()?
            else {
                return Ok(None);
            };
            let mut statement = db.prepare(
                "SELECT bytes FROM base_account_changes WHERE base=?1 ORDER BY position",
            )?;
            state.account_changes = statement
                .query_map([base.as_slice()], |r| r.get(0))?
                .collect::<Result<_, _>>()?;
            let pending = db
                .query_row(
                    "SELECT event_id, after_position, after_hash, deadline, digest, epoch_after,
                       account_position, account_hash, change, account_event, floor,
                       seen_position, judged_control, judged_account_position,
                       judged_account_hash
                     FROM base_pending WHERE base=?1",
                    [base.as_slice()],
                    pending,
                )
                .optional()?;
            Ok(Some((state, pending)))
        })
    }

    /// The durable control head and pending control a replay started from.
    pub fn prior(&self, base: &[u8; 32]) -> Result<Option<Prior>, ServiceError> {
        self.with(|db| {
            let Some(control_head) = db
                .query_row(
                    "SELECT control_position, control_hash FROM base_controls WHERE base=?1",
                    [base.as_slice()],
                    |r| head(r.get(0)?, r.get(1)?),
                )
                .optional()?
            else {
                return Ok(None);
            };
            let pending = db
                .query_row(
                    "SELECT event_id FROM base_pending WHERE base=?1",
                    [base.as_slice()],
                    |r| array(r.get(0)?),
                )
                .optional()?;
            Ok(Some(Prior {
                control_head,
                pending,
            }))
        })
    }

    /// Replace a base's control record and its pending control, in one
    /// transaction.
    pub fn save_controls(
        &self,
        state: &ControlState,
        pending: Option<&Pending>,
    ) -> Result<(), ServiceError> {
        self.with(|db| {
            let tx = db.transaction()?;
            save(&tx, state, pending)?;
            tx.commit()
        })
    }

    /// Replace a base's control record and pending control only if the
    /// durable control head and pending control are still `expected` (None:
    /// no control record). Returns whether it wrote. A replay that began
    /// before a newer durable state must not replace it.
    pub fn save_controls_if(
        &self,
        state: &ControlState,
        pending: Option<&Pending>,
        expected: Option<Prior>,
    ) -> Result<bool, ServiceError> {
        self.with(|db| {
            let tx = db.transaction()?;
            let base = state.base.0;
            let stored = tx
                .query_row(
                    "SELECT control_position, control_hash FROM base_controls WHERE base=?1",
                    [base.as_slice()],
                    |r| head(r.get(0)?, r.get(1)?),
                )
                .optional()?;
            let stored_pending = tx
                .query_row(
                    "SELECT event_id FROM base_pending WHERE base=?1",
                    [base.as_slice()],
                    |r| array(r.get(0)?),
                )
                .optional()?;
            let current = stored.map(|control_head| Prior {
                control_head,
                pending: stored_pending,
            });
            if current != expected {
                return Ok(false);
            }
            save(&tx, state, pending)?;
            tx.commit()?;
            Ok(true)
        })
    }
}

/// Replace a base's control row, its copied account events and its pending
/// control, in the caller's transaction.
fn save(tx: &Transaction, state: &ControlState, pending: Option<&Pending>) -> rusqlite::Result<()> {
    let base = state.base.0;
    tx.execute(
        "INSERT OR REPLACE INTO base_controls(base, creator, hosting_root, metadata_id,
           epoch, floor, control_position, control_hash, control_digest,
           head_position, head_hash, account_position, account_hash)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            base.as_slice(),
            state.creator.0.as_slice(),
            state.hosting_root.as_slice(),
            state.metadata_id.as_slice(),
            state.epoch.map(|e| e.to_vec()),
            state.floor,
            state.control.position as i64,
            state.control.hash.0.as_slice(),
            state.control_digest.as_slice(),
            state.control_head.position as i64,
            state.control_head.hash.0.as_slice(),
            state.account.position as i64,
            state.account.hash.as_slice(),
        ],
    )?;
    save_changes(tx, &base, &state.account_changes)?;
    tx.execute("DELETE FROM base_pending WHERE base=?1", [base.as_slice()])?;
    if let Some(p) = pending {
        let e = &p.effect;
        tx.execute(
            "INSERT INTO base_pending(base, event_id, after_position, after_hash,
               deadline, digest, epoch_after, account_position, account_hash, change,
               account_event, floor, seen_position, judged_control,
               judged_account_position, judged_account_hash)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                base.as_slice(),
                p.event_id.as_slice(),
                p.after.position as i64,
                p.after.hash.0.as_slice(),
                p.deadline_ms as i64,
                e.digest.0.as_slice(),
                e.epoch_after.map(|e| e.to_vec()),
                e.account_head_after.position as i64,
                e.account_head_after.hash.as_slice(),
                match e.change {
                    ControlChange::AddDevice => 1,
                    ControlChange::RemoveSelf => 2,
                },
                e.account_event,
                e.floor_after,
                e.seen_position as i64,
                e.judged_control_digest.as_slice(),
                e.judged_account_head.position as i64,
                e.judged_account_head.hash.as_slice(),
            ],
        )?;
    }
    Ok(())
}

/// Replace the base's copied account events, in order.
fn save_changes(tx: &Transaction, base: &[u8; 32], changes: &[Vec<u8>]) -> rusqlite::Result<()> {
    tx.execute(
        "DELETE FROM base_account_changes WHERE base=?1",
        [base.as_slice()],
    )?;
    for (i, change) in changes.iter().enumerate() {
        tx.execute(
            "INSERT INTO base_account_changes(base, position, bytes) VALUES(?1, ?2, ?3)",
            params![base.as_slice(), i as i64, change],
        )?;
    }
    Ok(())
}

fn state(base: [u8; 32], r: &Row) -> rusqlite::Result<ControlState> {
    Ok(ControlState {
        base: BaseId(base),
        creator: AccountId(array(r.get(0)?)?),
        hosting_root: array(r.get(1)?)?,
        metadata_id: array(r.get(2)?)?,
        epoch: r.get::<_, Option<Vec<u8>>>(3)?.map(array).transpose()?,
        floor: r.get(4)?,
        control: head(r.get(5)?, r.get(6)?)?,
        control_digest: array(r.get(7)?)?,
        control_head: head(r.get(8)?, r.get(9)?)?,
        account: account_head(r.get(10)?, r.get(11)?)?,
        account_changes: vec![],
    })
}

fn pending(r: &Row) -> rusqlite::Result<Pending> {
    Ok(Pending {
        event_id: array(r.get(0)?)?,
        after: head(r.get(1)?, r.get(2)?)?,
        deadline_ms: r.get::<_, i64>(3)? as u64,
        effect: ControlEffect {
            digest: Digest(array(r.get(4)?)?),
            epoch_after: r.get::<_, Option<Vec<u8>>>(5)?.map(array).transpose()?,
            account_head_after: account_head(r.get(6)?, r.get(7)?)?,
            change: match r.get::<_, u8>(8)? {
                1 => ControlChange::AddDevice,
                2 => ControlChange::RemoveSelf,
                _ => return Err(rusqlite::Error::InvalidQuery),
            },
            account_event: r.get(9)?,
            floor_after: r.get(10)?,
            seen_position: r.get::<_, i64>(11)? as u64,
            judged_control_digest: array(r.get(12)?)?,
            judged_account_head: account_head(r.get(13)?, r.get(14)?)?,
        },
    })
}
