//! The bounded JSON Schema 2020-12 vocabulary accepted for record data.
use serde_json::Value;

use crate::{DataError, value};

pub const PROFILE_VERSION: &str = "bh-schema-profile/1";
pub const MAX_SCHEMA_BYTES: usize = 32_768;
pub const MAX_COMPILATION_BYTES: usize = 1_048_576;

/// A streaming JSON byte counter, not an encoded-output buffer. Each compilation
/// phase gets the same ceiling; repeated additions charge cumulative input work.
/// Use serde_json's encoding, matching registry CompiledType persistence exactly.
pub(crate) struct CompilationBytes {
    remaining: usize,
    phase: &'static str,
}
impl CompilationBytes {
    pub(crate) fn new(phase: &'static str) -> Self {
        Self {
            remaining: MAX_COMPILATION_BYTES,
            phase,
        }
    }

    pub(crate) fn add<T: serde::Serialize + ?Sized>(&mut self, value: &T) -> Result<(), DataError> {
        struct Counter<'a> {
            remaining: &'a mut usize,
            exceeded: bool,
        }
        impl std::io::Write for Counter<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let Some(left) = self.remaining.checked_sub(bytes.len()) else {
                    self.exceeded = true;
                    return Err(std::io::Error::other("compilation byte limit"));
                };
                *self.remaining = left;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut counter = Counter {
            remaining: &mut self.remaining,
            exceeded: false,
        };
        let result = serde_json::to_writer(&mut counter, value);
        if counter.exceeded {
            return Err(DataError::Limit(format!(
                "{} exceeds {MAX_COMPILATION_BYTES} compilation bytes",
                self.phase
            )));
        }
        result.map_err(|e| DataError::Definition(format!("cannot encode {}: {e}", self.phase)))
    }
}
const MAX_SCHEMA_DEPTH: usize = 32;
const MAX_SUBSCHEMAS: usize = 512;
const MAX_BRANCHES: usize = 16;
const MAX_ENUM_VALUES: usize = 256;
const MAX_STRING_LENGTH: u64 = 16_384;
const MAX_ARRAY_ITEMS: u64 = 1_024;

fn invalid(keyword: &str, pointer: &str) -> DataError {
    DataError::Profile {
        keyword: keyword.into(),
        pointer: pointer.into(),
    }
}

fn child(pointer: &str, key: &str) -> String {
    format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"))
}

fn pinned_ref(reference: &str) -> bool {
    if let Some((rev, name)) = reference
        .strip_prefix("bh:defs:")
        .and_then(|r| r.split_once("#/$defs/"))
    {
        return rev.len() == 64
            && rev.bytes().all(|b| b.is_ascii_hexdigit())
            && local_ref(&format!("#/$defs/{name}"));
    }
    let Some((id, rev)) = reference
        .strip_prefix("bh:value:")
        .and_then(|r| r.split_once('@'))
    else {
        return false;
    };
    !id.is_empty()
        && !rev.is_empty()
        && id.bytes().all(|b| b.is_ascii_hexdigit())
        && rev.bytes().all(|b| b.is_ascii_hexdigit())
}

fn local_ref(reference: &str) -> bool {
    let Some(segment) = reference.strip_prefix("#/$defs/") else {
        return false;
    };
    // URI percent decoding must not alias the JSON Pointer graph used by the
    // work bound. This profile requires literal names with only ~0/~1 escapes.
    if segment.is_empty() || segment.contains('/') || segment.contains('%') {
        return false;
    }
    let mut chars = segment.chars();
    while let Some(c) = chars.next() {
        if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}

fn json_depth(node: &Value, depth: usize) -> Result<(), DataError> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(DataError::Limit("schema depth exceeds 32".into()));
    }
    match node {
        Value::Array(items) => {
            for item in items {
                json_depth(item, depth + 1)?;
            }
        }
        Value::Object(items) => {
            for item in items.values() {
                json_depth(item, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Reject unsupported vocabulary and resource-intensive schemas before compilation.
pub fn check(schema: &Value) -> Result<(), DataError> {
    if value::canonical(schema).len() > MAX_SCHEMA_BYTES {
        return Err(DataError::Limit("schema exceeds 32768 bytes".into()));
    }
    json_depth(schema, 0)?;
    value::check(schema)?;
    let mut count = 0;
    visit(schema, "", true, &mut count)
}

fn visit(schema: &Value, pointer: &str, root: bool, count: &mut usize) -> Result<(), DataError> {
    *count += 1;
    if *count > MAX_SUBSCHEMAS {
        return Err(DataError::Limit("schema exceeds 512 subschemas".into()));
    }
    let Some(object) = schema.as_object() else {
        return Err(invalid("schema", pointer));
    };
    for (key, val) in object {
        let location = child(pointer, key);
        match key.as_str() {
            "$schema"
                if root && val.as_str() == Some("https://json-schema.org/draft/2020-12/schema") => {
            }
            "$schema" => return Err(invalid(key, &location)),
            "$id" if root && val.is_string() => {}
            "$id" => return Err(invalid(key, &location)),
            "$ref" if val.as_str().is_some_and(|s| local_ref(s) || pinned_ref(s)) => {}
            "$ref" => return Err(invalid(key, &location)),
            "type"
                if val.as_str().is_some_and(|s| {
                    matches!(
                        s,
                        "null" | "boolean" | "object" | "array" | "number" | "integer" | "string"
                    )
                }) || val.as_array().is_some_and(|items| {
                    !items.is_empty()
                        && items.iter().all(|v| {
                            v.as_str().is_some_and(|s| {
                                matches!(
                                    s,
                                    "null"
                                        | "boolean"
                                        | "object"
                                        | "array"
                                        | "number"
                                        | "integer"
                                        | "string"
                                )
                            })
                        })
                }) => {}
            "type" => return Err(invalid(key, &location)),
            "enum"
                if val
                    .as_array()
                    .is_some_and(|items| !items.is_empty() && items.len() <= MAX_ENUM_VALUES) => {}
            "enum" => return Err(invalid(key, &location)),
            "const" | "default" | "examples" | "$comment" | "title" | "description"
            | "deprecated" | "readOnly" | "writeOnly" | "format" => {}
            "required"
                if val
                    .as_array()
                    .is_some_and(|items| items.iter().all(Value::is_string)) => {}
            "required" => return Err(invalid(key, &location)),
            "additionalProperties" if val.is_boolean() => {}
            "additionalProperties" => return Err(invalid(key, &location)),
            "uniqueItems" if val.is_boolean() => {}
            "uniqueItems" => return Err(invalid(key, &location)),
            "minItems" | "maxItems" | "minLength" | "maxLength" | "minProperties"
            | "maxProperties"
                if val.as_u64().is_some() => {}
            "minItems" | "maxItems" | "minLength" | "maxLength" | "minProperties"
            | "maxProperties" => return Err(invalid(key, &location)),
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" if val.is_number() => {}
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => {
                return Err(invalid(key, &location));
            }
            "multipleOf"
                if val
                    .as_u64()
                    .is_some_and(|n| n > 0 && n <= value::MAX_SAFE_INTEGER as u64) => {}
            "multipleOf" => return Err(invalid(key, &location)),
            "$defs" | "properties" if val.is_object() => {
                for (name, subschema) in val.as_object().expect("checked object") {
                    visit(subschema, &child(&location, name), false, count)?;
                }
            }
            "$defs" | "properties" => return Err(invalid(key, &location)),
            "items" => visit(val, &location, false, count)?,
            "prefixItems" | "anyOf" | "oneOf" | "allOf"
                if val.as_array().is_some_and(|items| !items.is_empty()) =>
            {
                let items = val.as_array().expect("checked array");
                if matches!(key.as_str(), "anyOf" | "oneOf" | "allOf") && items.len() > MAX_BRANCHES
                {
                    return Err(invalid(key, &location));
                }
                for (index, subschema) in items.iter().enumerate() {
                    visit(
                        subschema,
                        &child(&location, &index.to_string()),
                        false,
                        count,
                    )?;
                }
            }
            "prefixItems" | "anyOf" | "oneOf" | "allOf" => return Err(invalid(key, &location)),
            _ => return Err(invalid(key, &location)),
        }
    }
    let types = object.get("type");
    let includes = |name| {
        types.is_some_and(|v| {
            v.as_str() == Some(name)
                || v.as_array()
                    .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(name)))
        })
    };
    if includes("string")
        && !object.contains_key("const")
        && !object.contains_key("enum")
        && !object
            .get("maxLength")
            .and_then(Value::as_u64)
            .is_some_and(|n| n <= MAX_STRING_LENGTH)
    {
        return Err(invalid("maxLength", &child(pointer, "maxLength")));
    }
    if includes("array")
        && !object
            .get("maxItems")
            .and_then(Value::as_u64)
            .is_some_and(|n| n <= MAX_ARRAY_ITEMS)
    {
        return Err(invalid("maxItems", &child(pointer, "maxItems")));
    }
    if object
        .get("maxLength")
        .and_then(Value::as_u64)
        .is_some_and(|n| n > MAX_STRING_LENGTH)
    {
        return Err(invalid("maxLength", &child(pointer, "maxLength")));
    }
    if object
        .get("maxItems")
        .and_then(Value::as_u64)
        .is_some_and(|n| n > MAX_ARRAY_ITEMS)
    {
        return Err(invalid("maxItems", &child(pointer, "maxItems")));
    }
    Ok(())
}
