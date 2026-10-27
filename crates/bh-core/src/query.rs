//! Typed record queries over the encrypted local object summaries.

use crate::store::{BaseDb, SUMMARY};
use crate::{Error, ObjectSummary};
use rusqlite::types::Value as SqlValue;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A query of live objects of one type, with optional field filters, order and limit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Query {
    /// The type name (all stored versions of it).
    pub ty: String,
    /// Conditions that must all match.
    pub filters: Vec<Filter>,
    /// A JSON field and ascending or descending order.
    pub order_by: Option<(String, Order)>,
    /// Maximum number of matching objects.
    pub limit: Option<usize>,
}

/// A comparison against one JSON field.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Filter {
    /// The JSON field name.
    pub field: String,
    /// Comparison operator.
    pub op: Op,
    /// The value to compare.
    pub value: Value,
}

/// A field comparison.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Op {
    /// Equal.
    Eq,
    /// Less than.
    Lt,
    /// Less than or equal.
    Lte,
    /// Greater than.
    Gt,
    /// Greater than or equal.
    Gte,
}

/// Sort direction for a field.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Order {
    /// Ascending.
    Asc,
    /// Descending.
    Desc,
}

fn path(field: &str) -> Result<String, Error> {
    // SQLite JSON paths cannot represent a quoted key; reject it rather than
    // accidentally querying another field. Everything else stays bound data.
    if field.contains('"') || field.contains('\0') {
        return Err(Error::invalid("invalid query field"));
    }
    Ok(format!("$.\"{field}\""))
}

fn sql_value(value: &Value) -> SqlValue {
    match value {
        Value::Null => SqlValue::Null,
        Value::Bool(v) => SqlValue::Integer(i64::from(*v)),
        Value::Number(v) => v
            .as_i64()
            .map(SqlValue::Integer)
            .or_else(|| v.as_f64().map(SqlValue::Real))
            .unwrap_or(SqlValue::Null),
        Value::String(v) => SqlValue::Text(v.clone()),
        _ => SqlValue::Text(value.to_string()),
    }
}

pub(crate) fn run(db: &BaseDb, q: &Query) -> Result<Vec<ObjectSummary>, Error> {
    let mut sql = format!("SELECT {SUMMARY} FROM objects WHERE type = ? AND deleted = 0");
    let mut args = vec![SqlValue::Text(q.ty.clone())];
    for filter in &q.filters {
        let operator = match filter.op {
            Op::Eq => "=",
            Op::Lt => "<",
            Op::Lte => "<=",
            Op::Gt => ">",
            Op::Gte => ">=",
        };
        sql.push_str(&format!(" AND json_extract(fields, ?) {operator} ?"));
        args.push(SqlValue::Text(path(&filter.field)?));
        args.push(sql_value(&filter.value));
    }
    if let Some((field, order)) = &q.order_by {
        sql.push_str(" ORDER BY json_extract(fields, ?) ");
        sql.push_str(match order {
            Order::Asc => "ASC",
            Order::Desc => "DESC",
        });
        args.push(SqlValue::Text(path(field)?));
        sql.push_str(", object_id");
    } else {
        sql.push_str(" ORDER BY object_id");
    }
    if let Some(limit) = q.limit {
        sql.push_str(" LIMIT ?");
        args.push(SqlValue::Integer(i64::try_from(limit).unwrap_or(i64::MAX)));
    }
    db.summaries(&sql, rusqlite::params_from_iter(args))
}
