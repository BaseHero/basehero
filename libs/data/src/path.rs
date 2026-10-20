use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use serde_json::{Map, Value};

use crate::DataError;

pub const MAX_PATH_DEPTH: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FieldPath(Vec<String>);

impl FieldPath {
    pub fn parse(pointer: &str) -> Result<Self, DataError> {
        let Some(rest) = pointer.strip_prefix('/') else {
            return Err(DataError::Path("expected nonempty JSON Pointer".into()));
        };
        let parts: Vec<_> = rest.split('/').collect();
        if parts.len() > MAX_PATH_DEPTH {
            return Err(DataError::Path("path exceeds maximum depth".into()));
        }
        let mut decoded = Vec::with_capacity(parts.len());
        for part in parts {
            let mut chars = part.chars();
            let mut token = String::new();
            while let Some(c) = chars.next() {
                if c == '~' {
                    match chars.next() {
                        Some('0') => token.push('~'),
                        Some('1') => token.push('/'),
                        _ => {
                            return Err(DataError::Path("invalid JSON Pointer escape".into()));
                        }
                    }
                } else {
                    token.push(c);
                }
            }
            decoded.push(token);
        }
        Ok(Self(decoded))
    }

    pub fn as_pointer(&self) -> String {
        let mut result = String::new();
        for part in &self.0 {
            result.push('/');
            result.push_str(&part.replace('~', "~0").replace('/', "~1"));
        }
        result
    }

    pub fn is_prefix_of(&self, other: &Self) -> bool {
        other.0.starts_with(&self.0)
    }

    /// Traverses object keys only: numeric tokens are not array indices.
    pub fn get<'a>(&self, value: &'a Value) -> Option<&'a Value> {
        self.0
            .iter()
            .try_fold(value, |node, key| node.as_object()?.get(key))
    }

    pub fn set(&self, value: &mut Value, replacement: Value) -> Result<(), DataError> {
        let mut node = value;
        for key in &self.0[..self.0.len() - 1] {
            let object = node
                .as_object_mut()
                .ok_or_else(|| DataError::Path("non-object intermediate".into()))?;
            node = object
                .entry(key)
                .or_insert_with(|| Value::Object(Map::new()));
        }
        let object = node
            .as_object_mut()
            .ok_or_else(|| DataError::Path("non-object intermediate".into()))?;
        object.insert(self.0.last().expect("nonempty path").clone(), replacement);
        Ok(())
    }

    pub fn remove(&self, value: &mut Value) {
        let mut node = value;
        for key in &self.0[..self.0.len() - 1] {
            let Some(child) = node.as_object_mut().and_then(|object| object.get_mut(key)) else {
                return;
            };
            node = child;
        }
        if let Some(object) = node.as_object_mut() {
            object.remove(self.0.last().expect("nonempty path"));
        }
    }
}

impl Serialize for FieldPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.as_pointer())
    }
}

impl<'de> Deserialize<'de> for FieldPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let pointer = String::deserialize(deserializer)?;
        Self::parse(&pointer).map_err(D::Error::custom)
    }
}
