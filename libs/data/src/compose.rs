//! Pinned, single-base record inheritance and reusable value resources.
use std::{
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

use serde_json::{Map, Value};

use crate::{
    Builtin, CompiledType, DataError, FieldKind, FieldSpec, KeyRef, RevisionId, TypeDocs, TypeId,
    TypeKind, WritePolicy,
    definition::{self, Definition},
    profile, validate,
};

#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    #[error("missing pinned type {0:?} at {1:?}")]
    Missing(TypeId, RevisionId),
    #[error(transparent)]
    Invalid(#[from] DataError),
}
fn invalid(message: impl Into<String>) -> ComposeError {
    ComposeError::Invalid(DataError::Definition(message.into()))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub(crate) fn value_uri(id: TypeId, rev: RevisionId) -> String {
    format!("bh:value:{}@{}", hex(&id.0), hex(&rev.0))
}
fn defs_uri(rev: RevisionId) -> String {
    format!("bh:defs:{}", hex(&rev.0))
}

/// Compile an inspectable, closed effective schema and prove all references resolve offline.
pub fn compile(
    def: &Definition,
    revision: RevisionId,
    deps: &dyn Fn(TypeId, RevisionId) -> Option<CompiledType>,
) -> Result<CompiledType, ComposeError> {
    if revision != RevisionId::of(&def.bytes) {
        return Err(invalid("revision does not match definition bytes"));
    }
    profile::check(&def.schema)?;
    let mut schema = def.schema.clone();
    let mut resources = Vec::new();
    let mut resource_bytes = profile::CompilationBytes::new("schema resources");
    isolate_defs(&mut schema, revision, &mut resources, &mut resource_bytes)?;
    // Charge each exact dependency's full stored representation before merging it.
    // Common transitive resources in DISTINCT inputs still cost decoding work.
    let mut dependency_bytes = profile::CompilationBytes::new("dependency inputs");
    let mut cache = BTreeMap::new();
    let mut resolve = |id, rev| -> Result<Rc<CompiledType>, ComposeError> {
        if let Some(found) = cache.get(&(id, rev)) {
            return Ok(Rc::clone(found));
        }
        let found = deps(id, rev).ok_or(ComposeError::Missing(id, rev))?;
        if found.type_id != id || found.revision != rev {
            return Err(invalid("dependency identity/revision mismatch"));
        }
        dependency_bytes.add(&found)?;
        let found = Rc::new(found);
        cache.insert((id, rev), Rc::clone(&found));
        Ok(found)
    };
    let mut lineage = vec![(def.type_id, revision)];
    let mut fields = Vec::new();
    let mut indexes = Vec::new();
    let mut uniques = Vec::new();
    let mut actions = Vec::new();
    let mut queries = Vec::new();
    let mut search = def.search.clone();
    let mut builtin = None;
    let base = def
        .extends
        .as_ref()
        .map(|parent| resolve(parent.type_id, parent.revision))
        .transpose()?;
    if let Some(base) = &base {
        if !matches!(base.kind, TypeKind::Record) {
            return Err(invalid("cannot extend value type"));
        }
        if base.lineage.iter().any(|(id, _)| *id == def.type_id) || base.lineage.is_empty() {
            return Err(invalid("extends cycle"));
        }
        lineage.extend(base.lineage.iter().copied());
        fields = base.fields.clone();
        indexes = base.indexes.clone();
        uniques = base.uniques.clone();
        actions = base.actions.clone();
        queries = base.queries.clone();
        if search.title.is_none() {
            search.title = base.search.title.clone();
        }
        search.builtin_body |= base.search.builtin_body;
        for path in &base.search.text {
            if !search.text.contains(path) {
                search.text.push(path.clone());
            }
        }
        builtin = base.builtin.clone();
        let old = base
            .effective_schema
            .as_object()
            .ok_or_else(|| invalid("base schema is not object"))?;
        let root = schema.as_object_mut().expect("parsed object");
        let props = root
            .get_mut("properties")
            .and_then(Value::as_object_mut)
            .expect("parsed properties");
        for (name, property) in old
            .get("properties")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("base properties missing"))?
        {
            if props.contains_key(name) {
                return Err(invalid(format!("inherited property redefined: {name}")));
            }
            props.insert(name.clone(), property.clone());
        }
        let required = root
            .entry("required")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| invalid("required is not an array"))?;
        for name in old
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if !required.contains(name) {
                required.push(name.clone());
            }
        }
    }
    if def.search.builtin_body && !lineage.iter().any(|(id, _)| *id == TypeId::core("note")) {
        return Err(invalid("built-in body search requires the Note lineage"));
    }
    // Close the root now so incremental closure accounting includes its final bytes.
    schema
        .as_object_mut()
        .expect("parsed object")
        .insert("additionalProperties".into(), Value::Bool(false));
    resource_bytes.add(&schema)?;
    if let Some(base) = &base {
        for (uri, resource) in &base.resources {
            insert_resource(&mut resources, uri, resource, &mut resource_bytes)?;
        }
    }
    let mut imported = BTreeSet::new();
    for use_type in &def.uses {
        let value = resolve(use_type.type_id, use_type.revision)?;
        // Cache hits still require the context's kind check (a record base is
        // never a valid value import). Only fetch/byte/merge work is deduplicated.
        if !matches!(value.kind, TypeKind::Value) {
            return Err(invalid("use must pin a value contract"));
        }
        if !imported.insert((use_type.type_id, use_type.revision)) {
            continue;
        }
        for (uri, resource) in &value.resources {
            insert_resource(&mut resources, uri, resource, &mut resource_bytes)?;
        }
        insert_resource(
            &mut resources,
            &value_uri(value.type_id, value.revision),
            &value.effective_schema,
            &mut resource_bytes,
        )?;
    }
    for (path, decl) in &def.fields {
        let prop = definition::schema_at(&def.schema, path)
            .ok_or_else(|| invalid("undeclared field path"))?;
        let mut kind = decl.field_kind()?;
        let write = decl.write_policy()?;
        let resolved = resolve_local_schema(prop, &def.schema)?;
        if !kind_matches_schema(&kind, resolved) {
            return Err(invalid(format!(
                "field kind does not match schema: {}",
                path.as_pointer()
            )));
        }
        if matches!(kind, FieldKind::Reference(_)) && !reference_shape(prop) {
            return Err(invalid(format!(
                "invalid record reference shape: {}",
                path.as_pointer()
            )));
        }
        if matches!(kind, FieldKind::Container)
            && (!matches!(write, WritePolicy::Derived)
                || !def.fields.keys().any(|p| path != p && path.is_prefix_of(p)))
        {
            return Err(invalid(
                "container must have declared children and cannot be writable",
            ));
        }
        if def.fields.keys().any(|p| path != p && path.is_prefix_of(p))
            && !matches!(kind, FieldKind::Container)
        {
            return Err(invalid("declared parent must be an uneditable container"));
        }
        if matches!(kind, FieldKind::Enum(_)) {
            let strings = prop
                .get("enum")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("enum field must have schema enum"))?;
            kind = FieldKind::Enum(
                strings
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| invalid("enum field requires string values"))
                    })
                    .collect::<Result<_, _>>()?,
            );
        }
        let is_required = path_required(&def.schema, path);
        let nullable = prop.get("type").is_some_and(|v| {
            v == "null" || v.as_array().is_some_and(|a| a.iter().any(|t| t == "null"))
        }) || prop
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|a| a.contains(&Value::Null));
        if fields.iter().any(|f: &FieldSpec| f.path == *path) {
            return Err(invalid("inherited field redefined"));
        }
        fields.push(FieldSpec {
            path: path.clone(),
            kind,
            write,
            required: is_required,
            nullable,
            declared_by: def.type_id,
            meaning: decl.meaning.clone(),
            unit: decl.unit.clone(),
            absent: decl.absent.clone(),
        });
    }
    if def.core_note {
        builtin = Some(Builtin::Note);
    }
    if matches!(def.kind, TypeKind::Record) {
        indexes.extend(def.indexes.clone());
        // A new subtype constraint must not invalidate an inherited operation.
        for unique in &def.uniques {
            if unique.keys.iter().any(|key| {
                matches!(key, KeyRef::Field(path)
                if fields.iter().any(|f| f.path == *path && f.declared_by != def.type_id
                    && f.write != WritePolicy::Derived))
            }) {
                return Err(invalid(
                    "subtype uniqueness cannot constrain inherited writable fields",
                ));
            }
        }
        uniques.extend(def.uniques.clone());
        actions.extend(def.actions.clone());
        queries.extend(def.queries.clone());
        for index in &indexes {
            validate_keys(&index.keys, &fields, false)?;
        }
        for unique in &uniques {
            validate_keys(&unique.keys, &fields, true)?;
        }
        for p in search.title.iter().chain(&search.text) {
            if !fields.iter().any(|f| f.path == *p) {
                return Err(invalid("search field not declared"));
            }
        }
        for action in &actions {
            for p in &action.effects {
                if !fields.iter().any(|f| f.path == *p) {
                    return Err(invalid("action effect not declared"));
                }
            }
        }
    } else if !def.indexes.is_empty()
        || !def.uniques.is_empty()
        || !def.actions.is_empty()
        || !def.queries.is_empty()
        || def.search.title.is_some()
        || !def.search.text.is_empty()
        || def.search.builtin_body
    {
        return Err(invalid("value type cannot declare record operations"));
    }
    if matches!(def.kind, TypeKind::Value) {
        insert_resource(
            &mut resources,
            &value_uri(def.type_id, revision),
            &schema,
            &mut resource_bytes,
        )?;
    }
    let compiled = CompiledType {
        type_id: def.type_id,
        revision,
        kind: def.kind.clone(),
        app: def.app,
        name: def.name.clone(),
        lineage,
        effective_schema: schema,
        resources,
        fields: if matches!(def.kind, TypeKind::Value) {
            Vec::new()
        } else {
            fields
        },
        indexes,
        uniques,
        queries,
        search,
        actions,
        builtin,
        previous: def.evolution.previous,
        docs: TypeDocs {
            description: def.description.clone(),
            rationale: def.rationale.clone(),
            examples_valid: def.evolution.examples.valid.clone(),
            examples_invalid: def.evolution.examples.invalid.clone(),
            migration: Some(def.evolution.migration.clone()),
        },
    };
    // Includes inherited metadata and documentation, not just validator inputs.
    // Reject before validator construction or the caller's registry writes.
    profile::CompilationBytes::new("compiled type").add(&compiled)?;
    validate::Compiled::new(&compiled.effective_schema, &compiled.resources)?;
    Ok(compiled)
}
fn insert_resource(
    resources: &mut Vec<(String, Value)>,
    uri: &str,
    resource: &Value,
    bytes: &mut profile::CompilationBytes,
) -> Result<(), ComposeError> {
    if let Some((_, existing)) = resources.iter().find(|(key, _)| key == uri) {
        if existing != resource {
            return Err(invalid("conflicting pinned resource"));
        }
        return Ok(());
    }
    bytes.add(uri)?;
    bytes.add(resource)?;
    resources.push((uri.to_owned(), resource.clone()));
    Ok(())
}
fn validate_keys(keys: &[KeyRef], fields: &[FieldSpec], unique: bool) -> Result<(), ComposeError> {
    if keys.is_empty() || keys.len() > 4 {
        return Err(invalid("index must have one to four keys"));
    }
    let mut seen = BTreeSet::new();
    for key in keys {
        let name = match key {
            KeyRef::Changed => "$changed".to_owned(),
            KeyRef::Field(p) => p.as_pointer(),
        };
        if !seen.insert(name) {
            return Err(invalid("duplicate key"));
        }
        match key {
            KeyRef::Changed if unique => return Err(invalid("change position cannot be unique")),
            KeyRef::Changed => {}
            KeyRef::Field(p) => {
                let field = fields
                    .iter()
                    .find(|f| f.path == *p)
                    .ok_or_else(|| invalid("index key field not declared"))?;
                if matches!(field.kind, FieldKind::Container | FieldKind::Atomic) {
                    return Err(invalid("index key must be scalar"));
                }
                if unique && (!field.required || field.nullable) {
                    return Err(invalid("unique key must be required and non-nullable"));
                }
                // A derived value (a Note's title) changes outside ordered
                // writes, so nothing could refuse a duplicate.
                if unique && field.write == WritePolicy::Derived {
                    return Err(invalid("unique key cannot be a derived field"));
                }
            }
        }
    }
    Ok(())
}
fn path_required(schema: &Value, path: &crate::FieldPath) -> bool {
    let mut node = schema;
    let pointer = path.as_pointer();
    for part in pointer[1..].split('/') {
        let name = part.replace("~1", "/").replace("~0", "~");
        if !node
            .get("required")
            .and_then(Value::as_array)
            .is_some_and(|keys| keys.iter().any(|key| key.as_str() == Some(&name)))
        {
            return false;
        }
        let Some(next) = node.get("properties").and_then(|o| o.get(&name)) else {
            return false;
        };
        node = next;
    }
    true
}
fn resolve_local_schema<'a>(schema: &'a Value, root: &'a Value) -> Result<&'a Value, ComposeError> {
    let mut node = schema;
    for _ in 0..32 {
        let Some(reference) = node.get("$ref").and_then(Value::as_str) else {
            return Ok(node);
        };
        let Some(name) = reference.strip_prefix("#/$defs/") else {
            return Ok(node);
        };
        let name = name.replace("~1", "/").replace("~0", "~");
        node = root
            .get("$defs")
            .and_then(|d| d.get(&name))
            .ok_or_else(|| invalid("missing local definition"))?;
    }
    Err(invalid("cyclic local field reference"))
}
fn kind_matches_schema(kind: &FieldKind, schema: &Value) -> bool {
    let ty = schema.get("type").and_then(|types| {
        types.as_str().or_else(|| {
            let types = types.as_array()?;
            if types.len() != 2 || !types.iter().any(|v| v == "null") {
                return None;
            }
            types.iter().find(|v| *v != "null").and_then(Value::as_str)
        })
    });
    match kind {
        FieldKind::String | FieldKind::Enum(_) => ty == Some("string"),
        FieldKind::Integer | FieldKind::Timestamp => ty == Some("integer"),
        FieldKind::Number => ty == Some("number"),
        FieldKind::Boolean => ty == Some("boolean"),
        FieldKind::Container | FieldKind::Reference(_) => ty == Some("object"),
        FieldKind::Atomic => matches!(ty, Some("object" | "array")) || schema.get("$ref").is_some(),
    }
}
fn reference_shape(schema: &Value) -> bool {
    let Some(obj) = schema.as_object() else {
        return false;
    };
    obj.get("type") == Some(&Value::String("object".into()))
        && obj.get("additionalProperties") == Some(&Value::Bool(false))
        && obj.get("required") == Some(&serde_json::json!(["record"]))
        && obj
            .get("properties")
            .and_then(Value::as_object)
            .is_some_and(|p| {
                p.len() == 2
                    && ["audience", "record"].iter().all(|name| {
                        p.get(*name).is_some_and(|v| {
                            v == &serde_json::json!({"type":"string","minLength":64,"maxLength":64})
                        })
                    })
            })
}
/// Rewrite only actual schema positions: annotation values and property names are untouched.
fn rewrite_refs(schema: &mut Value, uri: &str) {
    let Some(obj) = schema.as_object_mut() else {
        return;
    };
    if let Some(reference) = obj.get("$ref").and_then(Value::as_str).map(str::to_owned)
        && reference.starts_with("#/$defs/")
    {
        obj.insert("$ref".into(), Value::String(format!("{uri}{reference}")));
    }
    for key in ["properties", "$defs"] {
        if let Some(children) = obj.get_mut(key).and_then(Value::as_object_mut) {
            for child in children.values_mut() {
                rewrite_refs(child, uri);
            }
        }
    }
    if let Some(items) = obj.get_mut("items") {
        rewrite_refs(items, uri);
    }
    for key in ["prefixItems", "anyOf", "oneOf", "allOf"] {
        if let Some(items) = obj.get_mut(key).and_then(Value::as_array_mut) {
            for item in items {
                rewrite_refs(item, uri);
            }
        }
    }
}
fn isolate_defs(
    schema: &mut Value,
    revision: RevisionId,
    resources: &mut Vec<(String, Value)>,
    bytes: &mut profile::CompilationBytes,
) -> Result<(), ComposeError> {
    let uri = defs_uri(revision);
    rewrite_refs(schema, &uri);
    if let Some(defs) = schema.as_object_mut().and_then(|o| o.remove("$defs")) {
        let mut resource = Map::new();
        resource.insert("$defs".into(), defs);
        insert_resource(resources, &uri, &Value::Object(resource), bytes)?;
    }
    Ok(())
}
