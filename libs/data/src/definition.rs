//! Parse immutable, documented type contracts without re-serializing their revision bytes.
use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

use crate::{
    ActionDecl, AppId, DataError, FieldKind, FieldPath, IndexDecl, KeyRef, QueryDecl, RefSpec,
    RevisionId, SearchMap, TypeId, TypeKind, UniqueDecl, WritePolicy, profile,
};

pub const MAX_DEFINITION_BYTES: usize = 57_344;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedType {
    #[serde(rename = "type", deserialize_with = "type_id")]
    pub type_id: TypeId,
    pub revision: RevisionId,
}

fn type_id<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<TypeId, D::Error> {
    use serde::de::Error;
    let text = String::deserialize(deserializer)?;
    if text == "core:note" {
        Ok(TypeId::core("note"))
    } else {
        serde_json::from_value(Value::String(text)).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldDeclaration {
    pub meaning: String,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default)]
    pub absent: Option<String>,
    pub write: String,
    pub kind: String,
    #[serde(default, rename = "ref")]
    pub reference: Option<ReferenceDeclaration>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceDeclaration {
    #[serde(deserialize_with = "type_ids")]
    pub targets: Vec<TypeId>,
    #[serde(default)]
    pub family: bool,
}
fn type_ids<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<TypeId>, D::Error> {
    let values = Vec::<String>::deserialize(deserializer)?;
    values
        .into_iter()
        .map(|text| type_id(serde::de::value::StringDeserializer::<D::Error>::new(text)))
        .collect()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evolution {
    pub previous: Option<RevisionId>,
    pub migration: String,
    /// The declarative content migration from earlier revisions of the type;
    /// an unknown or misspelled step makes the definition invalid.
    #[serde(default)]
    pub migration_ops: Vec<crate::evolve::Migration>,
    pub examples: Examples,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Examples {
    pub valid: Vec<Value>,
    pub invalid: Vec<Value>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    format: String,
    local: String,
    app: AppId,
    kind: String,
    name: String,
    description: String,
    extends: Option<PinnedType>,
    uses: Vec<PinnedType>,
    schema: Value,
    fields: BTreeMap<FieldPath, FieldDeclaration>,
    actions: Vec<ActionDeclRaw>,
    indexes: Vec<RawKeyDecl>,
    unique: Vec<RawKeyDecl>,
    search: SearchRaw,
    queries: Vec<QueryDecl>,
    evolution: Evolution,
    rationale: Vec<String>,
    #[serde(default)]
    builtin: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActionDeclRaw {
    name: String,
    effects: Vec<FieldPath>,
    source: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKeyDecl {
    name: String,
    keys: Vec<KeyRef>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SearchRaw {
    #[serde(default)]
    title: Option<FieldPath>,
    #[serde(default)]
    text: Vec<FieldPath>,
    #[serde(default)]
    builtin_body: bool,
}

/// A parsed contract retains the original signed bytes: revisions never hash a serialization.
#[derive(Clone, Debug)]
pub struct Definition {
    pub bytes: Vec<u8>,
    pub type_id: TypeId,
    pub app: Option<AppId>,
    pub kind: TypeKind,
    pub name: String,
    pub description: String,
    pub extends: Option<PinnedType>,
    pub uses: Vec<PinnedType>,
    pub schema: Value,
    pub fields: BTreeMap<FieldPath, FieldDeclaration>,
    pub actions: Vec<ActionDecl>,
    pub indexes: Vec<IndexDecl>,
    pub uniques: Vec<UniqueDecl>,
    pub search: SearchMap,
    pub queries: Vec<QueryDecl>,
    pub evolution: Evolution,
    pub rationale: Vec<String>,
    pub(crate) core_note: bool,
}

pub fn parse(bytes: &[u8]) -> Result<Definition, DataError> {
    parse_inner(bytes, false)
}

pub(crate) fn parse_core_note(bytes: &[u8]) -> Result<Definition, DataError> {
    parse_inner(bytes, true)
}

fn invalid(message: impl Into<String>) -> DataError {
    DataError::Definition(message.into())
}

fn parse_inner(bytes: &[u8], core_note: bool) -> Result<Definition, DataError> {
    if bytes.len() > MAX_DEFINITION_BYTES {
        return Err(DataError::Limit("definition exceeds 57344 bytes".into()));
    }
    let raw: Document = serde_json::from_slice(bytes).map_err(|e| invalid(e.to_string()))?;
    if raw.format != "bh-type/1" {
        return Err(invalid("expected bh-type/1"));
    }
    let local_bytes = decode_local(&raw.local)?;
    if raw.name.trim().is_empty() || raw.description.trim().is_empty() {
        return Err(invalid("name and description must be nonempty"));
    }
    let kind = match raw.kind.as_str() {
        "record" => TypeKind::Record,
        "value" => TypeKind::Value,
        _ => return Err(invalid("kind must be record or value")),
    };
    if core_note {
        if raw.builtin.as_deref() != Some("Note")
            || !matches!(kind, TypeKind::Record)
            || raw.extends.is_some()
        {
            return Err(invalid("invalid core Note binding"));
        }
    } else if raw.builtin.is_some() {
        return Err(invalid("app cannot declare a built-in contract"));
    }
    if matches!(kind, TypeKind::Value) && raw.extends.is_some() {
        return Err(invalid("value cannot extend a record"));
    }
    profile::check(&raw.schema)?;
    let root = raw
        .schema
        .as_object()
        .ok_or_else(|| invalid("schema must be an object"))?;
    if root.get("type").and_then(Value::as_str) != Some("object")
        || !root.contains_key("properties")
    {
        return Err(invalid("definition root must declare object properties"));
    }
    // The closed root also keeps a builtin's derived fields (a Note's title)
    // out of a specialisation's constraints: no root applicator, `$ref`,
    // `const` or `enum` reaches them, and compose refuses redefining them,
    // so no ordered verdict reads this replica's projection.
    for key in root.keys() {
        if !matches!(
            key.as_str(),
            "type"
                | "properties"
                | "required"
                | "$defs"
                | "title"
                | "description"
                | "$comment"
                | "default"
                | "examples"
                | "deprecated"
                | "readOnly"
                | "writeOnly"
                | "format"
        ) {
            return Err(invalid(format!("unsupported root keyword: {key}")));
        }
    }
    let properties = root["properties"].as_object().expect("checked profile");
    for name in properties.keys() {
        let pointer =
            FieldPath::parse(&format!("/{}", name.replace('~', "~0").replace('/', "~1")))?;
        if !raw.fields.contains_key(&pointer) {
            return Err(invalid(format!(
                "missing field declaration: {}",
                pointer.as_pointer()
            )));
        }
    }
    for (path, declaration) in &raw.fields {
        if declaration.meaning.trim().is_empty() {
            return Err(invalid(format!("missing meaning: {}", path.as_pointer())));
        }
        if schema_at(&raw.schema, path).is_none() {
            return Err(invalid(format!(
                "undeclared schema path: {}",
                path.as_pointer()
            )));
        }
        declaration.field_kind()?;
        declaration.write_policy()?;
    }
    for dep in &raw.uses {
        if dep.type_id == TypeId::for_app(raw.app, local_bytes) {
            return Err(invalid("self dependency"));
        }
    }
    let type_identity = if core_note {
        TypeId::core("note")
    } else {
        TypeId::for_app(raw.app, local_bytes)
    };
    Ok(Definition {
        bytes: bytes.to_vec(),
        type_id: type_identity,
        app: if core_note { None } else { Some(raw.app) },
        kind,
        name: raw.name,
        description: raw.description,
        extends: raw.extends,
        uses: raw.uses,
        schema: raw.schema,
        fields: raw.fields,
        actions: raw
            .actions
            .into_iter()
            .map(|a| ActionDecl {
                name: a.name,
                effects: a.effects,
                source: a.source,
            })
            .collect(),
        indexes: raw
            .indexes
            .into_iter()
            .map(|i| IndexDecl {
                name: i.name,
                keys: i.keys,
                declared_by: type_identity,
            })
            .collect(),
        uniques: raw
            .unique
            .into_iter()
            .map(|u| UniqueDecl {
                name: u.name,
                keys: u.keys,
                declared_by: type_identity,
            })
            .collect(),
        search: SearchMap {
            title: raw.search.title,
            text: raw.search.text,
            builtin_body: raw.search.builtin_body,
        },
        queries: raw.queries,
        evolution: raw.evolution,
        rationale: raw.rationale,
        core_note,
    })
}

fn decode_local(text: &str) -> Result<[u8; 16], DataError> {
    if text.len() != 32
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(invalid("local must be 32 lowercase hex characters"));
    }
    let mut out = [0; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("checked hex");
    }
    Ok(out)
}

/// Only declared object-property paths are field paths; arrays and definitions are not fields.
pub(crate) fn schema_at<'a>(schema: &'a Value, path: &FieldPath) -> Option<&'a Value> {
    let pointer = path.as_pointer();
    let mut node = schema;
    for part in pointer[1..].split('/') {
        let part = part.replace("~1", "/").replace("~0", "~");
        node = node.get("properties")?.get(&part)?;
    }
    Some(node)
}
impl FieldDeclaration {
    pub(crate) fn write_policy(&self) -> Result<WritePolicy, DataError> {
        match self.write.as_str() {
            "direct" => Ok(WritePolicy::Direct),
            "action" => Ok(WritePolicy::ActionOnly),
            "derived" => Ok(WritePolicy::Derived),
            _ => Err(invalid("unknown write policy")),
        }
    }
    pub(crate) fn field_kind(&self) -> Result<FieldKind, DataError> {
        match self.kind.as_str() {
            "string" => Ok(FieldKind::String),
            "integer" => Ok(FieldKind::Integer),
            "number" => Ok(FieldKind::Number),
            "boolean" => Ok(FieldKind::Boolean),
            "timestamp" => Ok(FieldKind::Timestamp),
            "atomic" => Ok(FieldKind::Atomic),
            "container" => Ok(FieldKind::Container),
            "enum" => Ok(FieldKind::Enum(Vec::new())),
            "reference" => {
                let r = self
                    .reference
                    .as_ref()
                    .ok_or_else(|| invalid("reference targets required"))?;
                if r.targets.is_empty() {
                    return Err(invalid("empty reference targets"));
                }
                Ok(FieldKind::Reference(RefSpec {
                    targets: r.targets.clone(),
                    family: r.family,
                }))
            }
            _ => Err(invalid("unknown field kind")),
        }
    }
}
