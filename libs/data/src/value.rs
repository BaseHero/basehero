use serde_json::Value;

use crate::DataError;

pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;
pub const MAX_VALUE_DEPTH: usize = 32;
pub const MAX_RECORD_BYTES: usize = 49_152;

/// RFC 8785 JSON, independent of the active serde_json map-order features.
pub fn canonical(v: &Value) -> String {
    serde_jcs::to_string(v).expect("serde_json::Value is serializable as JSON")
}

pub fn check(v: &Value) -> Result<(), DataError> {
    fn visit(v: &Value, depth: usize) -> Result<(), DataError> {
        if depth > MAX_VALUE_DEPTH {
            return Err(DataError::Value("maximum value depth exceeded".into()));
        }
        match v {
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    if !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&i) {
                        return Err(DataError::Value(
                            "integer outside interoperable range".into(),
                        ));
                    }
                } else if let Some(u) = n.as_u64() {
                    if u > MAX_SAFE_INTEGER as u64 {
                        return Err(DataError::Value(
                            "integer outside interoperable range".into(),
                        ));
                    }
                } else if let Some(f) = n.as_f64()
                    && (!f.is_finite() || (f.fract() == 0.0 && f.abs() > MAX_SAFE_INTEGER as f64))
                {
                    return Err(DataError::Value("non-finite or unsafe number".into()));
                }
            }
            Value::Array(items) => {
                for item in items {
                    visit(item, depth + 1)?;
                }
            }
            Value::Object(items) => {
                for item in items.values() {
                    visit(item, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    visit(v, 0)?;
    if canonical(v).len() > MAX_RECORD_BYTES {
        return Err(DataError::Limit(
            "record exceeds the maximum canonical size".into(),
        ));
    }
    Ok(())
}
