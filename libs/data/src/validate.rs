//! Compile a bounded profile and validate resulting record values locally.
use std::collections::BTreeMap;

use jsonschema::{Draft, Resource, Retrieve, Uri, Validator};
use serde_json::Value;

use crate::{DataError, FieldPath, RejectCode, Rejection, profile, value};

struct Offline;

impl Retrieve for Offline {
    fn retrieve(
        &self,
        uri: &Uri<String>,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        Err(format!("unregistered schema resource: {uri}").into())
    }
}

pub struct Compiled {
    validator: Validator,
    expansion: u64,
}

impl Compiled {
    pub fn new(effective: &Value, resources: &[(String, Value)]) -> Result<Self, DataError> {
        // Charge annotation data and encoded URI keys before graph/validator work.
        // Borrow while deduplicating: no unbounded cloned closure or encoded buffer.
        let mut bytes = profile::CompilationBytes::new("schema resources");
        bytes.add(effective)?;
        profile::check(effective)?;
        let mut unique = BTreeMap::new();
        let mut ordered = Vec::new();
        for (uri, schema) in resources {
            if let Some(existing) = unique.get(uri.as_str()) {
                if *existing != schema {
                    return Err(DataError::Definition("conflicting pinned resource".into()));
                }
                continue;
            }
            bytes.add(uri)?;
            bytes.add(schema)?;
            profile::check(schema)?;
            unique.insert(uri.as_str(), schema);
            // The map is only for conflict lookup; retain first-occurrence order.
            ordered.push((uri.as_str(), schema));
        }
        let resources = ordered;
        let expansion = crate::schema_work::expansion(effective, &resources)?;
        let mut options = jsonschema::options()
            .with_draft(Draft::Draft202012)
            .should_validate_formats(false)
            .with_retriever(Offline);
        for (uri, schema) in resources {
            let resource = Resource::from_contents((*schema).clone())
                .map_err(|e| DataError::Definition(format!("invalid resource {uri}: {e}")))?;
            options = options.with_resource(uri.to_owned(), resource);
        }
        let validator = options
            .build(effective)
            .map_err(|e| DataError::Definition(format!("invalid schema: {e}")))?;
        Ok(Self {
            validator,
            expansion,
        })
    }

    pub fn validate(&self, doc: &Value) -> Result<(), Rejection> {
        if let Err(error) = value::check(doc) {
            let pointer = invalid_value_pointer(doc, "");
            return Err(Rejection {
                code: RejectCode::Schema,
                path: FieldPath::parse(&pointer).ok(),
                detail: detail_at(&pointer, &error.to_string()),
            });
        }
        if self
            .expansion
            .saturating_mul(crate::schema_work::record_shape(doc))
            > crate::schema_work::MAX_RECORD_WORK
        {
            return Err(Rejection {
                code: RejectCode::Schema,
                path: None,
                detail: "record validation work exceeds 16777216".into(),
            });
        }
        self.validator.validate(doc).map_err(|error| {
            let pointer = error.instance_path.to_string();
            Rejection {
                code: RejectCode::Schema,
                path: FieldPath::parse(&pointer).ok(),
                detail: detail_at(&pointer, &error.to_string()),
            }
        })
    }
}

fn detail_at(pointer: &str, message: &str) -> String {
    let location = if pointer.is_empty() {
        "(root)"
    } else {
        pointer
    };
    format!("at {location}: {message}")
}

// Called only for a rejected value, so the extra walk does not affect successful writes.
fn invalid_value_pointer(node: &Value, pointer: &str) -> String {
    let children: Vec<_> = match node {
        Value::Object(items) => items.iter().map(|(name, v)| (name.clone(), v)).collect(),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(i, v)| (i.to_string(), v))
            .collect(),
        _ => Vec::new(),
    };
    for (name, child) in children {
        if value::check(child).is_err() {
            let escaped = name.replace('~', "~0").replace('/', "~1");
            let child_pointer = format!("{pointer}/{escaped}");
            return invalid_value_pointer(child, &child_pointer);
        }
    }
    pointer.to_owned()
}
