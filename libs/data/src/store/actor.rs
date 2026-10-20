//! Compact, canonical author identity shared by local history and queued work.
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{id, sql};
use crate::{Actor, DataError};

fn bytes(actor: &Actor) -> Vec<u8> {
    let mut out = Vec::with_capacity(65);
    match actor {
        Actor::Device { account, device } => {
            out.push(0);
            out.extend_from_slice(account);
            out.extend_from_slice(device);
        }
        Actor::Job {
            account,
            delegation,
            action,
        } => {
            out.push(if action.is_some() { 2 } else { 1 });
            out.extend_from_slice(account);
            out.extend_from_slice(delegation);
            if let Some(action) = action {
                out.extend_from_slice(action.as_bytes());
            }
        }
    }
    out
}

pub(crate) fn intern(tx: &Transaction<'_>, actor: &Actor) -> Result<i64, DataError> {
    let bytes = bytes(actor);
    tx.execute(
        "INSERT OR IGNORE INTO data_actor(actor) VALUES(?1)",
        [bytes.as_slice()],
    )
    .map_err(sql)?;
    tx.query_row("SELECT id FROM data_actor WHERE actor=?1", [bytes], |r| {
        r.get(0)
    })
    .map_err(sql)
}

pub(crate) fn find(conn: &Connection, actor: &Actor) -> Result<Option<i64>, DataError> {
    conn.query_row(
        "SELECT id FROM data_actor WHERE actor=?1",
        [bytes(actor)],
        |r| r.get(0),
    )
    .optional()
    .map_err(sql)
}

/// Compare a saved actor id to an authenticated author without exposing the
/// database's encoding to the storage host. An absent pending row is not ours.
pub fn matches(conn: &Connection, actor_id: Option<i64>, actor: &Actor) -> Result<bool, DataError> {
    let Some(actor_id) = actor_id else {
        return Ok(false);
    };
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM data_actor WHERE id=?1 AND actor=?2)",
        params![actor_id, bytes(actor)],
        |r| r.get(0),
    )
    .map_err(sql)
}

pub(crate) fn get(conn: &Connection, actor_id: i64) -> Result<Actor, DataError> {
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT actor FROM data_actor WHERE id=?1",
            params![actor_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?
        .ok_or_else(|| DataError::Corrupt("missing actor".into()))?;
    if bytes.len() < 65 {
        return Err(DataError::Corrupt("short actor".into()));
    }
    let account = id(bytes[1..33].to_vec())?;
    let other = id(bytes[33..65].to_vec())?;
    match bytes[0] {
        0 if bytes.len() == 65 => Ok(Actor::Device {
            account,
            device: other,
        }),
        1 if bytes.len() == 65 => Ok(Actor::Job {
            account,
            delegation: other,
            action: None,
        }),
        2 => Ok(Actor::Job {
            account,
            delegation: other,
            action: Some(String::from_utf8(bytes[65..].to_vec()).map_err(super::corrupt)?),
        }),
        _ => Err(DataError::Corrupt("invalid actor encoding".into())),
    }
}
