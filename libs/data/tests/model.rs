use bh_crypto::hash;
use bh_data::{
    AppId, Builtin, CompiledType, FieldKind, FieldPath, FieldSpec, IndexDecl, KeyRef, MutationId,
    Position, RecordId, RecordRef, RevisionId, Scope, SearchMap, TypeDocs, TypeId, TypeKind,
    UniqueDecl, WritePolicy, value,
};
use serde_json::json;

#[test]
fn core_type_id_is_domain_separated() {
    let note = TypeId::core("note");
    assert_ne!(note, TypeId(hash(b"note")));
    assert_eq!(
        serde_json::to_value(note).unwrap(),
        json!("1962d917be93624f2f030c096c883ab0c1efdc59809be60814b107fecc9d7f7a")
    );
    assert!(note.is_reserved_core());
    assert!(!TypeId::core("other").is_reserved_core());
}

#[test]
fn ids_serialize_as_lowercase_hex_and_reject_invalid_forms() {
    let id = RecordId([0xab; 32]);
    let encoded = serde_json::to_string(&id).unwrap();
    assert_eq!(encoded, format!("\"{}\"", "ab".repeat(32)));
    assert_eq!(serde_json::from_str::<RecordId>(&encoded).unwrap(), id);
    assert!(serde_json::from_str::<RecordId>(&format!("\"{}\"", "AB".repeat(32))).is_err());
    assert!(serde_json::from_str::<RecordId>("\"abcd\"").is_err());
    assert_eq!(serde_json::to_value(Position(42)).unwrap(), json!(42));
    assert_eq!(
        serde_json::to_value(Scope {
            base: [1; 32],
            audience: [2; 32]
        })
        .unwrap()["base"],
        json!(vec![1; 32])
    );
}

#[test]
fn field_path_round_trips() {
    let path = FieldPath::parse("/a~1b/c~0d").unwrap();
    assert_eq!(path.as_pointer(), "/a~1b/c~0d");
    assert_eq!(serde_json::to_value(&path).unwrap(), json!("/a~1b/c~0d"));
    assert_eq!(
        serde_json::from_value::<FieldPath>(json!("/a~1b/c~0d")).unwrap(),
        path
    );
    assert!(FieldPath::parse("/a~1b").unwrap().is_prefix_of(&path));
    assert!(!path.is_prefix_of(&FieldPath::parse("/a~1b").unwrap()));
    let mut record = json!({});
    path.set(&mut record, json!(7)).unwrap();
    assert_eq!(path.get(&record), Some(&json!(7)));
    path.remove(&mut record);
    assert_eq!(path.get(&record), None);
}

#[test]
fn field_path_rejects_depth_9_and_empty() {
    assert!(FieldPath::parse("").is_err());
    assert!(FieldPath::parse("/a/b/c/d/e/f/g/h/i").is_err());
    assert!(FieldPath::parse("/a~2b").is_err());
    assert!(FieldPath::parse("a").is_err());
    let mut record = json!({"a": 3});
    assert!(
        FieldPath::parse("/a/b")
            .unwrap()
            .set(&mut record, json!(4))
            .is_err()
    );
    assert_eq!(record, json!({"a": 3}));
}

#[test]
fn value_rejects_unsafe_integer() {
    assert!(value::check(&json!(9_007_199_254_740_992_i64)).is_err());
    assert!(value::check(&json!(-9_007_199_254_740_992_i64)).is_err());
    assert!(value::check(&json!(-9_007_199_254_740_991_i64)).is_ok());
}

#[test]
fn value_rejects_depth_33() {
    let nested = (0..33).fold(json!(null), |v, _| json!([v]));
    assert!(value::check(&nested).is_err());
    let allowed = (0..32).fold(json!(null), |v, _| json!([v]));
    assert!(value::check(&allowed).is_ok());
}

#[test]
fn value_rejects_49153_bytes() {
    assert!(value::check(&json!("x".repeat(49_150))).is_ok()); // 49,152 bytes with quotes
    assert!(value::check(&json!("x".repeat(49_151))).is_err());
}

#[test]
fn canonical_json_ignores_insertion_order() {
    let first: serde_json::Value =
        serde_json::from_str(r#"{"z":{"b":2,"a":1},"a":[{"y":true,"x":false}],"num":1.25}"#)
            .unwrap();
    let second: serde_json::Value =
        serde_json::from_str(r#"{"num":1.25,"a":[{"x":false,"y":true}],"z":{"a":1,"b":2}}"#)
            .unwrap();
    let expected = r#"{"a":[{"x":false,"y":true}],"num":1.25,"z":{"a":1,"b":2}}"#;
    assert_eq!(value::canonical(&first), expected);
    assert_eq!(value::canonical(&second), expected);
    assert_eq!(
        value::canonical(&json!({"integer": 9_007_199_254_740_991_i64})),
        r#"{"integer":9007199254740991}"#
    );
    // RFC 8785 sorts property names by UTF-16 code units, not UTF-8 bytes.
    assert_eq!(
        value::canonical(&json!({"\u{e000}": 1, "\u{10000}": 2})),
        "{\"𐀀\":2,\"\":1}"
    );
}

#[test]
fn value_size_uses_canonical_number_format() {
    assert_eq!(value::canonical(&json!(0.000001)), "0.000001");
    let empty = json!({"n": 0.000001, "s": ""});
    let count = value::MAX_RECORD_BYTES - value::canonical(&empty).len();
    assert!(value::check(&json!({"n": 0.000001, "s": "x".repeat(count)})).is_ok());
    assert!(value::check(&json!({"n": 0.000001, "s": "x".repeat(count + 1)})).is_err());
}

#[test]
fn integral_float_beyond_safe_range_rejected() {
    let exponential: serde_json::Value = serde_json::from_str("1e20").unwrap();
    assert!(value::check(&exponential).is_err());
    assert!(value::check(&serde_json::from_str::<serde_json::Value>("-1e20").unwrap()).is_err());
    assert!(value::check(&json!(1.25)).is_ok());
}

#[test]
fn app_type_id_cannot_equal_core_id() {
    let id = TypeId::for_app(AppId([3; 32]), [7; 16]);
    assert_eq!(
        serde_json::to_value(id).unwrap(),
        json!("e48fa90bc933ad2f613024cef189027e5a5abc1d4b49e86a5ab2a40148d9a68e")
    );
    assert_ne!(id, TypeId::core("note"));
    assert!(!id.is_reserved_core());
    assert_eq!(MutationId::random().0.len(), 16);
}

#[test]
fn record_ref_serde_omits_same_scope_audience() {
    let record = RecordId([0xab; 32]);
    let same_scope = RecordRef {
        audience: None,
        record,
    };
    let encoded = serde_json::to_value(same_scope).unwrap();
    assert_eq!(encoded, json!({"record": "ab".repeat(32)}));
    assert_eq!(
        serde_json::from_value::<RecordRef>(encoded).unwrap(),
        same_scope
    );
    let cross_scope = RecordRef {
        audience: Some([0xcd; 32]),
        record,
    };
    let encoded = serde_json::to_value(cross_scope).unwrap();
    assert_eq!(encoded["audience"], json!("cd".repeat(32)));
    assert_eq!(
        serde_json::from_value::<RecordRef>(encoded).unwrap(),
        cross_scope
    );
}

#[test]
fn key_ref_serde_round_trip() {
    let field = KeyRef::Field(FieldPath::parse("/a~1b").unwrap());
    assert_eq!(serde_json::to_value(&field).unwrap(), json!("/a~1b"));
    assert_eq!(
        serde_json::from_value::<KeyRef>(json!("/a~1b")).unwrap(),
        field
    );
    assert_eq!(
        serde_json::to_value(KeyRef::Changed).unwrap(),
        json!("$changed")
    );
    assert_eq!(
        serde_json::from_value::<KeyRef>(json!("$changed")).unwrap(),
        KeyRef::Changed
    );
    assert!(serde_json::from_value::<KeyRef>(json!("invalid")).is_err());
    let index = IndexDecl {
        name: "changed".into(),
        keys: vec![KeyRef::Changed, field.clone()],
        declared_by: TypeId::core("note"),
    };
    let unique = UniqueDecl {
        name: "field".into(),
        keys: vec![field],
        declared_by: TypeId::core("note"),
    };
    assert_eq!(
        serde_json::from_value::<IndexDecl>(serde_json::to_value(&index).unwrap()).unwrap(),
        index
    );
    assert_eq!(
        serde_json::from_value::<UniqueDecl>(serde_json::to_value(&unique).unwrap()).unwrap(),
        unique
    );
}

#[test]
fn compiled_type_serde_round_trip() {
    let id = TypeId::core("note");
    let revision = RevisionId::of(b"note-v1");
    let path = FieldPath::parse("/title").unwrap();
    let compiled = CompiledType {
        type_id: id,
        revision,
        kind: TypeKind::Record,
        app: Some(AppId([3; 32])),
        name: "Note".into(),
        lineage: vec![(id, revision)],
        effective_schema: json!({"type":"object"}),
        resources: vec![("metadata".into(), json!({"version": 1}))],
        fields: vec![FieldSpec {
            path: path.clone(),
            kind: FieldKind::String,
            write: WritePolicy::Direct,
            required: true,
            nullable: false,
            declared_by: id,
            meaning: "Heading".into(),
            unit: None,
            absent: Some("Untitled".into()),
        }],
        indexes: vec![],
        uniques: vec![],
        queries: vec![],
        search: SearchMap {
            title: Some(path.clone()),
            text: vec![],
            builtin_body: true,
        },
        actions: vec![],
        builtin: Some(Builtin::Note),
        previous: None,
        docs: TypeDocs {
            description: "A note".into(),
            rationale: vec![],
            examples_valid: vec![json!({"title": "Hello"})],
            examples_invalid: vec![],
            migration: None,
        },
    };
    assert_eq!(compiled.field(&path), Some(&compiled.fields[0]));
    assert!(compiled.is_family_member_of(id));
    assert!(!compiled.is_family_member_of(TypeId([4; 32])));
    let encoded = serde_json::to_string(&compiled).unwrap();
    assert_eq!(
        serde_json::from_str::<CompiledType>(&encoded).unwrap(),
        compiled
    );
}
