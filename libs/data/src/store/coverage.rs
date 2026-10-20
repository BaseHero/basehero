use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::{integer, sql, unsigned};
use crate::{DataError, Position};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Coverage {
    pub through: Option<Position>,
    pub complete: bool,
}

pub fn set(
    tx: &Transaction<'_>,
    scope: i64,
    through: Position,
    complete: bool,
) -> Result<(), DataError> {
    tx.execute(
        "INSERT INTO data_coverage(scope,through,complete) VALUES(?1,?2,?3)
        ON CONFLICT(scope) DO UPDATE SET through=excluded.through,complete=excluded.complete",
        params![scope, integer(through.0)?, complete],
    )
    .map_err(sql)?;
    Ok(())
}

pub fn get(conn: &Connection, scope: i64) -> Result<Coverage, DataError> {
    let row: Option<(Option<i64>, bool)> = conn
        .query_row(
            "SELECT through,complete FROM data_coverage WHERE scope=?1",
            [scope],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    match row {
        None => Ok(Coverage::default()),
        Some((through, complete)) => Ok(Coverage {
            through: through.map(|v| unsigned(v).map(Position)).transpose()?,
            complete,
        }),
    }
}
