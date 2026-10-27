//! Type references and definitions, the core types, and record validation.

use crate::Error;
use crate::base::BaseKey;
use bh_proto::ObjectId;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use ts_rs::TS;

pub(crate) const BASE: &str = "core.base";
pub(crate) const NOTE: &str = "core.note";
pub(crate) const FILE: &str = "core.file";
pub(crate) const FOLDER: &str = "core.folder";
pub(crate) const PROJECT: &str = "core.project";
pub(crate) const TYPE: &str = "core.type";
pub(crate) const CHAT: &str = "core.chat";
pub(crate) const MESSAGE: &str = "core.message";

/// A type's name and version, such as `core.note` version 1.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct TypeRef {
    /// Fully qualified type name, including its namespace.
    pub name: String,
    /// Version of that type; versions are stored alongside one another.
    pub version: u32,
}

impl TypeRef {
    /// Constructs a reference without checking whether the type is defined.
    pub fn new(name: impl Into<String>, version: u32) -> Self {
        Self {
            name: name.into(),
            version,
        }
    }
}

/// A record type. A definition with an existing name and version may only add
/// optional fields or change `doc` text; anything else is a new version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct TypeDef {
    /// Fully qualified name for records of this type.
    pub name: String,
    /// Definition version used when writing new records.
    pub version: u32,
    /// Description of the type, also available to Hero.
    #[serde(default)]
    pub doc: String,
    /// Field used as the object's display title, if any.
    #[serde(default)]
    pub title_field: Option<String>,
    /// Fields checked on local edits; unknown fields are retained.
    pub fields: Vec<FieldDef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
/// Declares how one field is checked on local edits. Fields not declared by a
/// definition remain in stored records unchanged.
pub struct FieldDef {
    /// JSON key in the object's fields.
    pub name: String,
    /// Expected JSON value kind.
    pub kind: FieldKind,
    /// Whether a non-null value must be supplied.
    #[serde(default)]
    pub required: bool,
    /// Measurement unit, when applicable; part of the field's meaning.
    #[serde(default)]
    pub unit: Option<String>,
    /// Description of the field, also available to Hero.
    #[serde(default)]
    pub doc: String,
}

/// `Date` is `YYYY-MM-DD`, `DateTime` RFC 3339 with an offset, and `Ref` an
/// object ID in hex.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum FieldKind {
    /// A JSON string.
    Text,
    /// A JSON number.
    Number,
    /// A JSON integer.
    Integer,
    /// A JSON boolean.
    Bool,
    /// A real calendar day as `YYYY-MM-DD`.
    Date,
    /// An RFC 3339 timestamp with offset.
    DateTime,
    /// A lowercase hexadecimal object ID.
    Ref,
    /// Any JSON value.
    Json,
    /// Encrypted field that is never indexed by search or exposed by Hero's tools.
    Secret,
}

fn field(name: &str, kind: FieldKind, required: bool) -> FieldDef {
    FieldDef {
        name: name.into(),
        kind,
        required,
        unit: None,
        doc: String::new(),
    }
}

/// The definition of a core type this version knows. All are version 1.
pub(crate) fn core_def(ty: &TypeRef) -> Option<TypeDef> {
    let named = |doc: &'static str| {
        (
            doc,
            Some("name"),
            vec![field("name", FieldKind::Text, false)],
        )
    };
    let (doc, title_field, fields) = match ty.name.as_str() {
        BASE => named("A base's own information"),
        NOTE => ("A note", None, vec![]),
        FILE => (
            "An encrypted file",
            Some("name"),
            vec![
                field("name", FieldKind::Text, true),
                field("mime", FieldKind::Text, true),
                field("size", FieldKind::Integer, true),
                field("key", FieldKind::Secret, true),
                field("uploaded", FieldKind::Bool, false),
            ],
        ),
        FOLDER => named("A folder"),
        PROJECT => named("A project"),
        CHAT => (
            "A Hero chat",
            Some("title"),
            vec![
                field("title", FieldKind::Text, false),
                field("project", FieldKind::Ref, false),
                field("allowed", FieldKind::Json, false),
                field("denied", FieldKind::Json, false),
            ],
        ),
        MESSAGE => (
            "A message in a Hero chat",
            None,
            vec![
                field("role", FieldKind::Text, true),
                field("text", FieldKind::Text, false),
                field("at", FieldKind::DateTime, true),
                field("device", FieldKind::Text, false),
                field("state", FieldKind::Text, true),
                field("error", FieldKind::Text, false),
                field("focus", FieldKind::Ref, false),
                field("steps", FieldKind::Json, false),
                field("created", FieldKind::Json, false),
                field("ask", FieldKind::Json, false),
            ],
        ),
        TYPE => (
            "A record type's definition",
            None,
            vec![field("def", FieldKind::Json, true)],
        ),
        _ => return None,
    };
    (ty.version == 1).then(|| TypeDef {
        name: ty.name.clone(),
        version: 1,
        doc: doc.into(),
        title_field: title_field.map(Into::into),
        fields,
    })
}

pub(crate) fn is_core(name: &str) -> bool {
    name.starts_with("core.")
}

/// Checks the fields a definition names. Fields it doesn't name are kept as
/// they are, and a `null` counts as absent.
pub(crate) fn validate(def: &TypeDef, fields: &Map<String, Value>) -> Result<(), Error> {
    for f in &def.fields {
        match fields.get(&f.name) {
            None | Some(Value::Null) if f.required => {
                return Err(Error::invalid("a required field is missing"));
            }
            None | Some(Value::Null) => {}
            Some(value) if !matches_kind(f.kind, value) => {
                return Err(Error::invalid("a field has the wrong kind of value"));
            }
            Some(_) => {}
        }
    }
    if def.name == MESSAGE
        && (!matches!(
            fields.get("role").and_then(Value::as_str),
            Some("user" | "hero")
        ) || !matches!(
            fields.get("state").and_then(Value::as_str),
            Some("done" | "working" | "stopped" | "failed" | "asking")
        ))
    {
        return Err(Error::invalid("invalid Hero message role or state"));
    }
    Ok(())
}

fn matches_kind(kind: FieldKind, value: &Value) -> bool {
    match kind {
        FieldKind::Text => value.is_string(),
        FieldKind::Number => value.is_number(),
        FieldKind::Integer => value.is_i64() || value.is_u64(),
        FieldKind::Bool => value.is_boolean(),
        FieldKind::Date => value.as_str().is_some_and(is_date),
        FieldKind::DateTime => value.as_str().is_some_and(is_date_time),
        FieldKind::Ref => value.as_str().is_some_and(|s| {
            s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        }),
        FieldKind::Json => true,
        FieldKind::Secret => value.is_string(),
    }
}

fn digits(s: &str) -> Option<u32> {
    (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .then(|| s.parse().ok())
        .flatten()
}

/// `YYYY-MM-DD`, a real calendar date.
fn is_date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return false;
    }
    let (Some(year), Some(month), Some(day)) = (digits(&s[..4]), digits(&s[5..7]), digits(&s[8..]))
    else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day)
}

/// RFC 3339: `YYYY-MM-DDTHH:MM:SS`, optional fraction, then `Z` or `±HH:MM`.
fn is_date_time(s: &str) -> bool {
    let time = |t: &str, seconds: bool| {
        let b = t.as_bytes();
        let len = if seconds { 8 } else { 5 };
        b.len() == len
            && b[2] == b':'
            && digits(&t[..2]).is_some_and(|h| h < 24)
            && digits(&t[3..5]).is_some_and(|m| m < 60)
            && (!seconds || (b[5] == b':' && digits(&t[6..]).is_some_and(|s| s <= 60)))
    };
    if s.len() < 20 || !s.is_ascii() || !is_date(&s[..10]) || !matches!(&s[10..11], "T" | "t") {
        return false;
    }
    let rest = &s[11..];
    if !time(&rest[..8], true) {
        return false;
    }
    let mut rest = &rest[8..];
    if let Some(fraction) = rest.strip_prefix('.') {
        let end = fraction
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(fraction.len());
        if end == 0 {
            return false;
        }
        rest = &fraction[end..];
    }
    match rest {
        "Z" | "z" => true,
        _ => rest.len() == 6 && matches!(&rest[..1], "+" | "-") && time(&rest[1..], false),
    }
}

/// Checks a definition before it's stored. `core.` names belong to BaseHero.
pub(crate) fn check_def(def: &TypeDef) -> Result<(), Error> {
    let name_ok = !def.name.is_empty()
        && def.name.len() <= 100
        && def
            .name
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'));
    if !name_ok {
        return Err(Error::invalid(
            "a type name is lowercase letters, digits, '.', '_' and '-'",
        ));
    }
    if is_core(&def.name) {
        return Err(Error::invalid("core types can't be redefined"));
    }
    if def.version == 0 {
        return Err(Error::invalid("type versions start at 1"));
    }
    let mut names = std::collections::HashSet::new();
    if def
        .fields
        .iter()
        .any(|f| f.name.is_empty() || !names.insert(f.name.as_str()))
    {
        return Err(Error::invalid("field names must be unique and not empty"));
    }
    if let Some(title) = &def.title_field
        && !def
            .fields
            .iter()
            .any(|f| &f.name == title && f.kind == FieldKind::Text)
    {
        return Err(Error::invalid("the title field must be a text field"));
    }
    Ok(())
}

/// A definition with the same name and version may only add optional fields
/// or change `doc` text.
pub(crate) fn check_redefinition(old: &TypeDef, new: &TypeDef) -> Result<(), Error> {
    let refused = || Err(Error::invalid("a changed definition needs a new version"));
    if old.title_field != new.title_field {
        return refused();
    }
    for f in &old.fields {
        match new.fields.iter().find(|n| n.name == f.name) {
            Some(n) if n.kind == f.kind && n.required == f.required && n.unit == f.unit => {}
            _ => return refused(),
        }
    }
    if new
        .fields
        .iter()
        .any(|n| n.required && !old.fields.iter().any(|f| f.name == n.name))
    {
        return refused();
    }
    Ok(())
}

/// The first 16 bytes of `generichash(key = kdf(BK, "bhtypeid", 1), name ‖ 0x00 ‖ version BE)`:
/// devices defining the same type write the same object, and the server
/// can't guess type names from IDs.
pub(crate) fn type_object_id(base_key: &BaseKey, name: &str, version: u32) -> ObjectId {
    let key = bh_crypto::kdf(base_key.secret(), b"bhtypeid", 1);
    let hash = bh_crypto::generichash(
        Some(key.expose()),
        &[name.as_bytes(), &[0], &version.to_be_bytes()],
    );
    ObjectId(hash[..16].try_into().expect("16 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn trip() -> TypeDef {
        TypeDef {
            name: "demo.trip".into(),
            version: 1,
            doc: String::new(),
            title_field: None,
            fields: vec![
                field("start", FieldKind::Date, true),
                field("nights", FieldKind::Integer, false),
            ],
        }
    }

    fn map(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn kinds_are_checked() {
        let cases = [
            (FieldKind::Text, json!("x"), json!(1)),
            (FieldKind::Number, json!(1.5), json!("1")),
            (FieldKind::Integer, json!(-3), json!(1.5)),
            (FieldKind::Bool, json!(true), json!(0)),
            (FieldKind::Date, json!("2024-02-29"), json!("2023-02-29")),
            (
                FieldKind::DateTime,
                json!("2026-11-01T09:30:00.25+09:00"),
                json!("2026-11-01T24:00:00Z"),
            ),
            (
                FieldKind::Ref,
                json!("00112233445566778899aabbccddeeff"),
                json!("00112233445566778899AABBCCDDEEFF"),
            ),
        ];
        for (kind, good, bad) in cases {
            assert!(matches_kind(kind, &good), "{kind:?} {good}");
            assert!(!matches_kind(kind, &bad), "{kind:?} {bad}");
        }
        assert!(matches_kind(FieldKind::Json, &json!({ "a": [1] })));
        for bad in [
            "2026-11-01T09:30:00",
            "2026-11-01T09:30:00.Z",
            "2026-1-01T09:30:00Z",
        ] {
            assert!(!is_date_time(bad), "{bad}");
        }
        assert!(is_date_time("2026-11-01t09:30:00z"));
        assert!(!is_date("2026-13-01") && !is_date("2026-04-31") && !is_date("26-04-01"));
    }

    #[test]
    fn validation_requires_fields_and_keeps_unknown_ones() {
        let def = trip();
        assert!(validate(&def, &map(json!({ "start": "2026-11-01", "x": 1 }))).is_ok());
        assert!(validate(&def, &map(json!({ "start": null }))).is_err());
        assert!(
            validate(
                &def,
                &map(json!({ "start": "2026-11-01", "nights": "two" }))
            )
            .is_err()
        );
        assert!(validate(&def, &map(json!({ "start": "2026-11-01", "nights": null }))).is_ok());
    }

    #[test]
    fn definitions_are_checked() {
        assert!(check_def(&trip()).is_ok());
        for bad in [
            TypeDef {
                name: "core.trip".into(),
                ..trip()
            },
            TypeDef {
                name: "Demo Trip".into(),
                ..trip()
            },
            TypeDef {
                version: 0,
                ..trip()
            },
            TypeDef {
                title_field: Some("nights".into()),
                ..trip()
            },
            TypeDef {
                fields: vec![
                    field("a", FieldKind::Text, false),
                    field("a", FieldKind::Text, false),
                ],
                ..trip()
            },
        ] {
            assert!(check_def(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_definition_round_trips_as_camel_case_json() {
        let def = TypeDef {
            title_field: Some("start".into()),
            ..trip()
        };
        let value = serde_json::to_value(&def).unwrap();
        assert_eq!(value["titleField"], "start");
        assert_eq!(value["fields"][0]["kind"], "date");
        assert_eq!(serde_json::from_value::<TypeDef>(value).unwrap(), def);
        assert_eq!(
            serde_json::to_value(FieldKind::DateTime).unwrap(),
            "dateTime"
        );
    }

    #[test]
    fn type_object_ids_follow_the_documented_derivation() {
        let key = BaseKey::new(&[3; 32]).unwrap();
        let derived = bh_crypto::kdf(key.secret(), b"bhtypeid", 1);
        let mut input = b"demo.trip\0".to_vec();
        input.extend_from_slice(&1u32.to_be_bytes());
        let hash = bh_crypto::generichash(Some(derived.expose()), &[&input]);
        let id = type_object_id(&key, "demo.trip", 1);
        assert_eq!(id.0, hash[..16]);
        assert_ne!(id, type_object_id(&key, "demo.trip", 2));
        let other = BaseKey::new(&[4; 32]).unwrap();
        assert_ne!(id, type_object_id(&other, "demo.trip", 1));
    }

    #[test]
    fn core_types_are_version_1() {
        assert!(core_def(&TypeRef::new(NOTE, 1)).is_some());
        assert!(core_def(&TypeRef::new(NOTE, 2)).is_none());
        assert!(core_def(&TypeRef::new("core.chat", 1)).is_some());
        assert!(core_def(&TypeRef::new("core.message", 1)).is_some());
        assert_eq!(
            core_def(&TypeRef::new(FOLDER, 1)).unwrap().title_field,
            Some("name".into())
        );
    }
}
