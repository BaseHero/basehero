use super::{Cursor, QueryError};
use crate::RecordId;
use rusqlite::types::Value as Sql;
use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
struct State {
    shape: String,
    keys: Vec<serde_json::Value>,
    record: [u8; 32],
}
pub(crate) fn encode(keys: &[Sql], record: RecordId, shape: &str) -> Cursor {
    let state = State {
        shape: shape.to_owned(),
        keys: keys
            .iter()
            .map(|v| match v {
                Sql::Null => serde_json::Value::Null,
                Sql::Integer(n) => (*n).into(),
                Sql::Real(n) => serde_json::json!(n),
                Sql::Text(s) => s.clone().into(),
                Sql::Blob(b) => serde_json::json!(b),
            })
            .collect(),
        record: record.0,
    };
    let bytes = serde_json::to_vec(&state).expect("cursor serialization");
    Cursor(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
pub(crate) fn decode(
    cursor: &Cursor,
    len: usize,
    shape: &str,
) -> Result<(Vec<Sql>, RecordId), QueryError> {
    let invalid = || QueryError::not_queryable(None, "invalid cursor");
    let hex = cursor.0.as_bytes();
    if hex.len() > 8192 || !hex.len().is_multiple_of(2) {
        return Err(invalid());
    }
    let raw = hex
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let s = std::str::from_utf8(pair).map_err(|_| invalid())?;
            u8::from_str_radix(s, 16).map_err(|_| invalid())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let state: State = serde_json::from_slice(&raw).map_err(|_| invalid())?;
    if state.shape != shape || state.keys.len() != len {
        return Err(invalid());
    }
    let keys = state
        .keys
        .into_iter()
        .map(|v| match v {
            serde_json::Value::Null => Ok(Sql::Null),
            serde_json::Value::String(s) => Ok(Sql::Text(s)),
            serde_json::Value::Number(n) if n.is_i64() => Ok(Sql::Integer(n.as_i64().unwrap())),
            serde_json::Value::Number(n) => n.as_f64().map(Sql::Real).ok_or_else(invalid),
            serde_json::Value::Array(bytes) => bytes
                .into_iter()
                .map(|b| {
                    b.as_u64()
                        .and_then(|n| u8::try_from(n).ok())
                        .ok_or_else(invalid)
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Sql::Blob),
            _ => Err(invalid()),
        })
        .collect::<Result<_, _>>()?;
    Ok((keys, RecordId(state.record)))
}
