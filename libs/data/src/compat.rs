//! Compare accepted revisions without mistaking a wider schema for old-client safety.
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use crate::{CompiledType, FieldKind, WritePolicy};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub compatible: bool,
    pub rule_change: bool,
    pub index_change: bool,
    pub doc_only: bool,
    pub reasons: Vec<String>,
}

pub fn classify(prev: &CompiledType, next: &CompiledType) -> Change {
    let mut change = Change {
        compatible: true,
        rule_change: false,
        index_change: false,
        doc_only: false,
        reasons: Vec::new(),
    };
    let mut other = false;
    if prev.type_id != next.type_id
        || prev.kind != next.kind
        || prev.lineage.iter().skip(1).collect::<Vec<_>>()
            != next.lineage.iter().skip(1).collect::<Vec<_>>()
        || prev.builtin != next.builtin
    {
        breaking(&mut change, "identity, kind or record base changed");
    }
    for old in &prev.fields {
        match next.field(&old.path) {
            None => breaking(
                &mut change,
                format!("field removed: {}", old.path.as_pointer()),
            ),
            Some(new) => {
                if old.kind != new.kind
                    || old.declared_by != new.declared_by
                    || old.nullable != new.nullable && !old.nullable
                {
                    breaking(
                        &mut change,
                        format!(
                            "field kind or representation changed: {}",
                            old.path.as_pointer()
                        ),
                    );
                }
                if old.write != new.write {
                    change.rule_change = true;
                    other = true;
                    change
                        .reasons
                        .push(format!("write policy changed: {}", old.path.as_pointer()));
                }
                if !old.required && new.required {
                    breaking(
                        &mut change,
                        format!("required field added: {}", old.path.as_pointer()),
                    );
                }
                if old.required && !new.required {
                    change.rule_change = true;
                    other = true;
                }
                for (label, changed) in [
                    ("meaning", old.meaning != new.meaning),
                    ("unit", old.unit != new.unit),
                    ("absent", old.absent != new.absent),
                ] {
                    if changed {
                        change.reasons.push(format!(
                            "field {} {label} documentation changed",
                            old.path.as_pointer()
                        ));
                    }
                }
            }
        }
    }
    for new in &next.fields {
        if prev.field(&new.path).is_none() {
            other = true;
            if new.required {
                breaking(
                    &mut change,
                    format!("new required field: {}", new.path.as_pointer()),
                );
            } else if new.write != WritePolicy::Direct || matches!(new.kind, FieldKind::Container) {
                change.rule_change = true;
            }
        }
    }
    let before = normalized_schema(&prev.effective_schema, prev.revision);
    let after = normalized_schema(&next.effective_schema, next.revision);
    let mut before_resources = normalized_resources(prev);
    let mut after_resources = normalized_resources(next);
    before_resources.sort_by(|a, b| a.0.cmp(&b.0));
    after_resources.sort_by(|a, b| a.0.cmp(&b.0));
    let old_resources: BTreeMap<_, _> = before_resources.into_iter().collect();
    let new_resources: BTreeMap<_, _> = after_resources.into_iter().collect();
    let mut allowed = AllowedDependencies::default();
    for field in &next.fields {
        if prev.field(&field.path).is_none()
            && !field.required
            && field.write == WritePolicy::Direct
            && let Some(schema) = crate::definition::schema_at(&after, &field.path)
        {
            collect_dependencies(schema, &new_resources, &mut allowed);
        }
    }
    compare_schema(&before, &after, "", &mut change, &mut other, &allowed);
    for (uri, resource) in &old_resources {
        if let Some(updated) = new_resources.get(uri) {
            compare_schema(resource, updated, uri, &mut change, &mut other, &allowed);
        } else {
            breaking(
                &mut change,
                format!("pinned schema resource removed: {uri}"),
            );
            other = true;
        }
    }
    for uri in new_resources.keys() {
        if !old_resources.contains_key(uri) {
            other = true;
            let unreferenced_definition = new_resources[uri]
                .get("$defs")
                .and_then(Value::as_object)
                .is_some_and(|defs| {
                    defs.keys()
                        .any(|name| !allowed.definitions.contains(&(uri.clone(), name.clone())))
                });
            if !allowed.resources.contains(uri) || unreferenced_definition {
                change.rule_change = true;
            }
            change
                .reasons
                .push(format!("pinned schema resource added: {uri}"));
        }
    }
    if prev.uniques != next.uniques || prev.actions != next.actions {
        if prev.uniques != next.uniques {
            change.index_change = true;
        }
        change.rule_change = true;
        other = true;
        change
            .reasons
            .push("unique or action declaration changed".into());
    }
    if prev.indexes != next.indexes || prev.search != next.search || prev.queries != next.queries {
        change.index_change = true;
        other = true;
    }
    if prev.docs != next.docs || prev.name != next.name {
        change.reasons.push("type documentation changed".into());
    }
    change.doc_only = !other && !change.reasons.is_empty();
    change
}
fn normalized_resources(contract: &CompiledType) -> Vec<(String, Value)> {
    let own = format!("bh:defs:{}", hex(&contract.revision.0));
    let value_self = format!(
        "bh:value:{}@{}",
        hex(&contract.type_id.0),
        hex(&contract.revision.0)
    );
    contract
        .resources
        .iter()
        .map(|(uri, value)| {
            let uri = if uri == &own {
                "bh:defs:self".to_owned()
            } else if uri == &value_self && matches!(contract.kind, crate::TypeKind::Value) {
                "bh:value:self".to_owned()
            } else {
                uri.clone()
            };
            (uri, normalized_schema(value, contract.revision))
        })
        .collect()
}
#[derive(Default)]
struct AllowedDependencies {
    resources: BTreeSet<String>,
    definitions: BTreeSet<(String, String)>,
}
/// Only references reachable from a newly added optional Direct field share its exception.
fn collect_dependencies(
    schema: &Value,
    resources: &BTreeMap<String, Value>,
    allowed: &mut AllowedDependencies,
) {
    let Some(object) = schema.as_object() else {
        return;
    };
    if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
        let (uri, name) = match reference.split_once("#/$defs/") {
            Some((uri, name)) => (uri, Some(name)),
            None => (reference, None),
        };
        if let Some(resource) = resources.get(uri) {
            let newly_seen = allowed.resources.insert(uri.to_owned());
            if let Some(name) = name {
                let decoded = name.replace("~1", "/").replace("~0", "~");
                if allowed
                    .definitions
                    .insert((uri.to_owned(), decoded.clone()))
                    && let Some(definition) =
                        resource.get("$defs").and_then(|defs| defs.get(decoded))
                {
                    collect_dependencies(definition, resources, allowed);
                }
            } else if newly_seen {
                collect_dependencies(resource, resources, allowed);
            }
        }
    }
    for key in ["properties", "$defs"] {
        if let Some(children) = object.get(key).and_then(Value::as_object) {
            for child in children.values() {
                collect_dependencies(child, resources, allowed);
            }
        }
    }
    for key in ["items", "additionalProperties"] {
        if let Some(child) = object.get(key).filter(|v| v.is_object()) {
            collect_dependencies(child, resources, allowed);
        }
    }
    for key in ["prefixItems", "anyOf", "oneOf", "allOf"] {
        if let Some(items) = object.get(key).and_then(Value::as_array) {
            for child in items {
                collect_dependencies(child, resources, allowed);
            }
        }
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn normalized_schema(value: &Value, revision: crate::RevisionId) -> Value {
    let mut value = value.clone();
    replace_own_refs(&mut value, &format!("bh:defs:{}#", hex(&revision.0)));
    value
}
fn replace_own_refs(value: &mut Value, own: &str) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    if let Some(reference) = object.get_mut("$ref")
        && let Some(rest) = reference.as_str().and_then(|r| r.strip_prefix(own))
    {
        *reference = Value::String(format!("bh:defs:self#{rest}"));
    }
    for key in ["properties", "$defs"] {
        if let Some(properties) = object.get_mut(key).and_then(Value::as_object_mut) {
            for child in properties.values_mut() {
                replace_own_refs(child, own);
            }
        }
    }
    if let Some(item) = object.get_mut("items") {
        replace_own_refs(item, own);
    }
    for key in ["prefixItems", "anyOf", "oneOf", "allOf"] {
        if let Some(items) = object.get_mut(key).and_then(Value::as_array_mut) {
            for item in items {
                replace_own_refs(item, own);
            }
        }
    }
}
fn breaking(change: &mut Change, reason: impl Into<String>) {
    change.compatible = false;
    change.rule_change = true;
    change.reasons.push(reason.into());
}
#[derive(Clone, Copy)]
enum EntryMode {
    TopLevel,
    Nested,
    Definition,
}
fn compare_schema_entries(
    before: &serde_json::Map<String, Value>,
    after: &serde_json::Map<String, Value>,
    path: &str,
    change: &mut Change,
    other: &mut bool,
    mode: EntryMode,
    allowed: &AllowedDependencies,
) {
    for (name, prior) in before {
        if let Some(updated) = after.get(name) {
            compare_schema(
                prior,
                updated,
                &format!("{path}/{name}"),
                change,
                other,
                allowed,
            );
        } else {
            breaking(change, format!("schema property removed: {path}/{name}"));
            *other = true;
        }
    }
    for name in after.keys() {
        if !before.contains_key(name) {
            if matches!(mode, EntryMode::TopLevel) {
                continue;
            }
            if matches!(mode, EntryMode::Definition) {
                if !allowed
                    .definitions
                    .contains(&(path.to_owned(), name.clone()))
                {
                    change.rule_change = true;
                }
                change
                    .reasons
                    .push(format!("reusable definition added: {path}/{name}"));
            } else {
                breaking(
                    change,
                    format!("nested schema property added: {path}/{name}"),
                );
            }
            *other = true;
        }
    }
}
fn compare_schema(
    old: &Value,
    new: &Value,
    path: &str,
    change: &mut Change,
    other: &mut bool,
    allowed: &AllowedDependencies,
) {
    if old == new {
        return;
    }
    let (Some(before), Some(after)) = (old.as_object(), new.as_object()) else {
        breaking(change, format!("schema representation changed at {path}"));
        *other = true;
        return;
    };
    for (key, value) in before {
        let next = after.get(key);
        match key.as_str() {
            "properties" => {
                if let (Some(a), Some(b)) = (value.as_object(), next.and_then(Value::as_object)) {
                    compare_schema_entries(
                        a,
                        b,
                        path,
                        change,
                        other,
                        if path.is_empty() {
                            EntryMode::TopLevel
                        } else {
                            EntryMode::Nested
                        },
                        allowed,
                    );
                } else {
                    breaking(change, "properties changed shape");
                    *other = true;
                }
            }
            "$defs" => {
                if let (Some(a), Some(b)) = (value.as_object(), next.and_then(Value::as_object)) {
                    compare_schema_entries(
                        a,
                        b,
                        path,
                        change,
                        other,
                        EntryMode::Definition,
                        allowed,
                    );
                } else {
                    breaking(change, format!("reusable schemas removed at {path}"));
                    *other = true;
                }
            }
            "required" => {
                let old_names = value.as_array();
                let new_names = next.and_then(Value::as_array);
                if let (Some(a), Some(b)) = (old_names, new_names) {
                    for name in b {
                        if !a.contains(name) {
                            breaking(change, format!("required property added at {path}"));
                            *other = true;
                        }
                    }
                    if a.iter().any(|v| !b.contains(v)) {
                        change.rule_change = true;
                        *other = true;
                    }
                } else if next.is_none() {
                    change.rule_change = true;
                    *other = true;
                    change.reasons.push(format!("required loosened at {path}"));
                } else {
                    breaking(change, "required declaration changed");
                    *other = true;
                }
            }
            "items" => {
                if let Some(updated) = next {
                    compare_schema(
                        value,
                        updated,
                        &format!("{path}/items"),
                        change,
                        other,
                        allowed,
                    );
                } else {
                    breaking(change, format!("items removed at {path}"));
                    *other = true;
                }
            }
            "prefixItems" | "anyOf" | "oneOf" | "allOf" => {
                if let (Some(before_items), Some(after_items)) =
                    (value.as_array(), next.and_then(Value::as_array))
                {
                    if before_items.len() != after_items.len() {
                        breaking(change, format!("{key} branches changed at {path}"));
                        *other = true;
                    } else if key == "oneOf" {
                        let mut branch = Change {
                            compatible: true,
                            rule_change: false,
                            index_change: false,
                            doc_only: false,
                            reasons: Vec::new(),
                        };
                        let mut branch_other = false;
                        for (i, (old_item, new_item)) in
                            before_items.iter().zip(after_items).enumerate()
                        {
                            compare_schema(
                                old_item,
                                new_item,
                                &format!("{path}/{key}/{i}"),
                                &mut branch,
                                &mut branch_other,
                                allowed,
                            );
                        }
                        // Widening one branch may introduce overlap and invalidate an old oneOf result.
                        if branch_other {
                            breaking(change, format!("oneOf assertion changed at {path}"));
                            *other = true;
                        }
                        change.reasons.extend(branch.reasons);
                    } else {
                        for (i, (old_item, new_item)) in
                            before_items.iter().zip(after_items).enumerate()
                        {
                            compare_schema(
                                old_item,
                                new_item,
                                &format!("{path}/{key}/{i}"),
                                change,
                                other,
                                allowed,
                            );
                        }
                    }
                } else {
                    breaking(change, format!("{key} changed shape at {path}"));
                    *other = true;
                }
            }
            "enum" | "const" | "type" | "$ref" => {
                if next != Some(value) {
                    breaking(change, format!("{key} changed at {path}"));
                    *other = true;
                }
            }
            "minimum" | "exclusiveMinimum" | "minLength" | "minItems" | "minProperties"
            | "maximum" | "exclusiveMaximum" | "maxLength" | "maxItems" | "maxProperties" => {
                if next != Some(value) {
                    let loosened = next
                        .and_then(Value::as_f64)
                        .zip(value.as_f64())
                        .is_some_and(|(n, o)| {
                            if key.starts_with("min") || key == "exclusiveMinimum" {
                                n <= o
                            } else {
                                n >= o
                            }
                        });
                    if !loosened && next.is_some() {
                        breaking(change, format!("{key} tightened at {path}"));
                    } else {
                        change.rule_change = true;
                        change.reasons.push(format!("{key} loosened at {path}"));
                    }
                    *other = true;
                }
            }
            "additionalProperties" => {
                if let Some(updated) = next
                    && value.is_object()
                    && updated.is_object()
                {
                    compare_schema(
                        value,
                        updated,
                        &format!("{path}/additionalProperties"),
                        change,
                        other,
                        allowed,
                    );
                } else if value.is_object() || next.is_some_and(Value::is_object) {
                    breaking(
                        change,
                        format!("additionalProperties changed shape at {path}"),
                    );
                    *other = true;
                } else if next != Some(value) {
                    if next == Some(&Value::Bool(false)) {
                        breaking(change, format!("additionalProperties tightened at {path}"));
                    } else {
                        change.rule_change = true;
                        change
                            .reasons
                            .push(format!("additionalProperties loosened at {path}"));
                    }
                    *other = true;
                }
            }
            "uniqueItems" => {
                if next != Some(value) {
                    if next == Some(&Value::Bool(true)) {
                        breaking(change, format!("uniqueItems tightened at {path}"));
                    } else {
                        change.rule_change = true;
                        change
                            .reasons
                            .push(format!("uniqueItems loosened at {path}"));
                    }
                    *other = true;
                }
            }
            "multipleOf" => {
                if next != Some(value) {
                    let relaxed = next
                        .and_then(Value::as_u64)
                        .zip(value.as_u64())
                        .is_some_and(|(n, o)| o % n == 0);
                    if next.is_some() && !relaxed {
                        breaking(change, format!("multipleOf changed at {path}"));
                    } else {
                        change.rule_change = true;
                        change
                            .reasons
                            .push(format!("multipleOf loosened at {path}"));
                    }
                    *other = true;
                }
            }
            "description" | "title" | "$comment" | "default" | "examples" | "deprecated"
            | "readOnly" | "writeOnly" | "format" => {
                if next != Some(value) {
                    change
                        .reasons
                        .push(format!("schema {key} documentation changed at {path}"));
                }
            }
            _ => {
                if next != Some(value) {
                    change.rule_change = true;
                    *other = true;
                    change.reasons.push(format!("{key} changed at {path}"));
                }
            }
        }
    }
    for (key, value) in after {
        if before.contains_key(key) {
            continue;
        }
        match key.as_str() {
            "description" | "title" | "$comment" | "default" | "examples" | "deprecated"
            | "readOnly" | "writeOnly" | "format" => {
                change
                    .reasons
                    .push(format!("schema {key} documentation added at {path}"));
            }
            "required" => {
                if value.as_array().is_some_and(|items| !items.is_empty()) {
                    breaking(change, format!("required property added at {path}"));
                } else {
                    change.rule_change = true;
                    change
                        .reasons
                        .push(format!("empty required assertion added at {path}"));
                }
                *other = true;
            }
            "uniqueItems" if value == &Value::Bool(false) => {
                change.rule_change = true;
                *other = true;
                change
                    .reasons
                    .push(format!("nonrestrictive uniqueItems added at {path}"));
            }
            "additionalProperties" if value == &Value::Bool(true) => {
                change.rule_change = true;
                *other = true;
                change.reasons.push(format!(
                    "nonrestrictive additionalProperties added at {path}"
                ));
            }
            "enum"
            | "const"
            | "uniqueItems"
            | "multipleOf"
            | "type"
            | "$ref"
            | "additionalProperties"
            | "items"
            | "prefixItems"
            | "anyOf"
            | "oneOf"
            | "allOf"
            | "properties"
            | "$defs" => {
                breaking(change, format!("assertion {key} added at {path}"));
                *other = true;
            }
            "maximum" | "maxLength" | "maxItems" | "maxProperties" | "minimum" | "minLength"
            | "minItems" | "minProperties" | "exclusiveMinimum" | "exclusiveMaximum" => {
                let _ = value;
                breaking(change, format!("new bound {key} at {path}"));
                *other = true;
            }
            _ => {
                change.rule_change = true;
                *other = true;
                change
                    .reasons
                    .push(format!("assertion {key} added at {path}"));
            }
        }
    }
}
