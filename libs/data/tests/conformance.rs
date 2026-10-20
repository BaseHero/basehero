use std::{fs, path::PathBuf};

use bh_data::{
    RejectCode,
    error::DataError,
    profile,
    validate::Compiled,
    value::{self, MAX_SAFE_INTEGER},
};
use serde_json::{Value, json};

#[test]
fn reference_graph_cycles_and_pinned_fanout_are_bounded() {
    let cycle = json!({"$defs":{"x":{"$ref":"#/$defs/x"}},"$ref":"#/$defs/x"});
    assert!(matches!(
        Compiled::new(&cycle, &[]),
        Err(DataError::Limit(_))
    ));
    let mut resources = vec![("bh:value:00@00".into(), json!({"type":"object"}))];
    for n in 1..=6 {
        resources.push((
            format!("bh:value:{n:02x}@00"),
            json!({"allOf":vec![json!({"$ref":format!("bh:value:{:02x}@00",n-1)});8]}),
        ));
    }
    assert!(matches!(
        Compiled::new(&json!({"$ref":"bh:value:06@00"}), &resources),
        Err(DataError::Limit(_))
    ));
    assert!(Compiled::new(&json!({"$ref":"bh:value:02@00"}), &resources[..3]).is_ok());
    let near = vec![
        ("bh:value:00@00".into(), json!({"type":"object"})),
        (
            "bh:value:01@00".into(),
            json!({"allOf":vec![json!({"$ref":"bh:value:00@00"});16]}),
        ),
        (
            "bh:value:02@00".into(),
            json!({"allOf":vec![json!({"$ref":"bh:value:01@00"});16]}),
        ),
    ];
    // 7,678 expanded units accepted; one more fan-out branch exceeds 8,192.
    assert!(
        Compiled::new(
            &json!({"allOf":vec![json!({"$ref":"bh:value:02@00"});13]}),
            &near
        )
        .is_ok()
    );
    assert!(matches!(
        Compiled::new(
            &json!({"allOf":vec![json!({"$ref":"bh:value:02@00"});14]}),
            &near
        ),
        Err(DataError::Limit(_))
    ));
}
#[test]
fn encoded_fragments_in_supplied_resources_fail_before_validator_construction() {
    for cycle in [false, true] {
        let mut resource = json!({"$defs":{"x0":{"type":"object"}}, "$ref":"#/$defs/x8"});
        for n in 1..=8 {
            resource["$defs"][format!("x{n}")] =
                json!({"allOf":vec![json!({"$ref":format!("#/$defs/x%3{}", n-1)});8]});
            resource["$defs"][format!("x%3{}", n - 1)] = json!({"type":"object"});
        }
        if cycle {
            resource["$defs"]["x0"] = json!({"$ref":"#/$defs/x%30"});
        }
        for uri in [
            "bh:value:00@00".to_owned(),
            format!("bh:defs:{}", "0".repeat(64)),
        ] {
            let root_ref = if uri.starts_with("bh:defs:") {
                format!("{uri}#/$defs/x8")
            } else {
                uri.clone()
            };
            let result = Compiled::new(&json!({"$ref":root_ref}), &[(uri, resource.clone())]);
            assert!(
                matches!(result, Err(DataError::Profile { keyword, .. }) if keyword == "$ref"),
                "encoded resource accepted or rejected for a different reason, cycle={cycle}"
            );
        }
    }
}
#[test]
fn actual_array_shape_bounds_unique_items_work_deterministically() {
    let schema = json!({"type":"array","maxItems":1024,"items":{"type":"integer"},"uniqueItems":true,
        "allOf":vec![json!({"type":"array","maxItems":1024,"items":{"type":"integer"},"uniqueItems":true});16]});
    let compiled = Compiled::new(&schema, &[]).unwrap();
    assert!(
        compiled
            .validate(&json!((0..10).collect::<Vec<_>>()))
            .is_ok()
    );
    let rejected = compiled
        .validate(&json!((0..1024).collect::<Vec<_>>()))
        .unwrap_err();
    assert!(rejected.detail.contains("validation work"));
}
fn fixtures(group: &str) -> Vec<(PathBuf, Value)> {
    let manifest_dir = std::env::var_os("BH_DATA_TEST_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
    let dir = manifest_dir.join("tests/conformance").join(group);
    let mut paths: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    assert!(!paths.is_empty());
    paths
        .into_iter()
        .map(|path| {
            let fixture = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            (path, fixture)
        })
        .collect()
}

#[test]
fn all_fixtures_pass() {
    for (path, fixture) in fixtures("profile") {
        let result = profile::check(&fixture["schema"]);
        if fixture["accept"] == true {
            assert!(result.is_ok(), "{}: {result:?}", path.display());
        } else {
            match result {
                Err(DataError::Profile { keyword, .. }) => {
                    assert_eq!(keyword, fixture["keyword"], "{}", path.display());
                }
                other => panic!(
                    "{}: expected profile rejection, got {other:?}",
                    path.display()
                ),
            }
        }
    }
    for (path, fixture) in fixtures("records") {
        let resources: Vec<(String, Value)> = fixture["resources"]
            .as_object()
            .map(|items| items.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        let validator = Compiled::new(&fixture["schema"], &resources)
            .unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        for doc in fixture["valid"].as_array().unwrap() {
            assert!(
                validator.validate(doc).is_ok(),
                "{} valid: {doc}",
                path.display()
            );
        }
        for doc in fixture["invalid"].as_array().unwrap() {
            let result = validator.validate(doc);
            assert!(result.is_err(), "{} invalid: {doc}", path.display());
            assert_eq!(result.unwrap_err().code, RejectCode::Schema);
        }
        if let Some(raw) = fixture.get("invalid_raw").and_then(Value::as_array) {
            for text in raw {
                let parsed = serde_json::from_str::<Value>(text.as_str().unwrap());
                assert!(
                    parsed.is_err() || value::check(&parsed.unwrap()).is_err(),
                    "{} invalid raw: {text}",
                    path.display()
                );
            }
        }
    }
}

#[test]
fn no_network_on_unknown_ref() {
    let schema = json!({"$ref": "bh:value:deadbeef@cafe"});
    assert!(Compiled::new(&schema, &[]).is_err());
}

#[test]
fn property_named_like_keyword_accepted() {
    let schema = json!({
        "type":"object", "properties": {
            "pattern": {"enum": [{"pattern": 1, "not": 2}], "default": {"not": 5}, "examples": [{"if": 6}], "const": {"pattern": 1, "not": 2}}
        }
    });
    profile::check(&schema).unwrap();
    assert!(
        Compiled::new(&schema, &[])
            .unwrap()
            .validate(&json!({"pattern": {"pattern": 1, "not": 2}}))
            .is_ok()
    );
}

#[test]
fn integral_float_integer_beyond_range_rejected() {
    let validator = Compiled::new(&json!({"type":"integer"}), &[]).unwrap();
    let result = validator.validate(&json!(1e20));
    assert_eq!(result.unwrap_err().code, RejectCode::Schema);
    assert!(validator.validate(&json!(MAX_SAFE_INTEGER)).is_ok());
}

#[test]
fn schema_limits_and_fragments_are_enforced() {
    for schema in [
        json!({"description": "x".repeat(33_000)}),
        json!({"type":"array"}),
        json!({"type":["null", "string"]}),
        json!({"type":"string", "maxLength":16_385}),
        json!({"type":"array", "maxItems":1_025}),
        json!({"multipleOf":0}),
        json!({"multipleOf":0.5}),
        json!({"minimum":9_007_199_254_740_992_u64}),
        json!({"properties":{"x":{"$id":"https://example.com/fragment"}}}),
    ] {
        assert!(profile::check(&schema).is_err(), "accepted {schema}");
    }
    let mut schema = json!({"type":"object"});
    for _ in 0..33 {
        schema = json!({"properties":{"x":schema}});
    }
    assert!(profile::check(&schema).is_err());
    let many = json!({"$defs":(0..513).map(|n| (n.to_string(), json!({}))).collect::<serde_json::Map<String, Value>>()});
    assert!(profile::check(&many).is_err());
}

#[test]
fn nested_profile_rejection_points_to_keyword() {
    let schema = json!({"properties":{"x":{"pattern":"bad"}}});
    match profile::check(&schema) {
        Err(DataError::Profile { keyword, pointer }) => {
            assert_eq!(keyword, "pattern");
            assert_eq!(pointer, "/properties/x/pattern");
        }
        other => panic!("expected rejected keyword, got {other:?}"),
    }
}

#[test]
fn escaped_local_definition_reference_resolves() {
    let schema = json!({"$defs":{"part/name":{"type":"integer"}},"$ref":"#/$defs/part~1name"});
    let validator = Compiled::new(&schema, &[]).unwrap();
    assert!(validator.validate(&json!(2)).is_ok());
    assert!(validator.validate(&json!("2")).is_err());
}

#[test]
fn unsafe_nested_number_reports_instance_pointer() {
    let validator = Compiled::new(
        &json!({"type":"object","properties":{"amount":{"type":"integer"}}}),
        &[],
    )
    .unwrap();
    let error = validator.validate(&json!({"amount":1e20})).unwrap_err();
    assert_eq!(error.path.unwrap().as_pointer(), "/amount");
}

#[test]
fn annotations_leave_the_record_unchanged() {
    let validator = Compiled::new(&json!({"type":"object","properties":{"link":{"type":"string","maxLength":50,"format":"uri","default":"https://example.com"}}}), &[]).unwrap();
    let doc = json!({"link":"not a uri"});
    validator.validate(&doc).unwrap();
    assert_eq!(doc, json!({"link":"not a uri"}));
    let missing = json!({});
    validator.validate(&missing).unwrap();
    assert_eq!(missing, json!({}));
}

#[test]
fn root_error_preserves_instance_location_in_detail() {
    let validator = Compiled::new(&json!({"type":"integer"}), &[]).unwrap();
    let error = validator.validate(&json!("wrong")).unwrap_err();
    assert_eq!(error.path, None);
    assert!(error.detail.starts_with("at (root): "), "{}", error.detail);
}

#[test]
fn deep_errors_preserve_full_instance_pointer_in_detail() {
    let mut schema = json!({"type":"integer"});
    let mut invalid_type = json!("wrong");
    let mut invalid_value = json!(1e20);
    for _ in 0..9 {
        schema = json!({"type":"object","properties":{"a":schema}});
        invalid_type = json!({"a":invalid_type});
        invalid_value = json!({"a":invalid_value});
    }
    let validator = Compiled::new(&schema, &[]).unwrap();
    for doc in [&invalid_type, &invalid_value] {
        let error = validator.validate(doc).unwrap_err();
        assert_eq!(error.path, None);
        assert!(
            error.detail.starts_with("at /a/a/a/a/a/a/a/a/a: "),
            "{}",
            error.detail
        );
    }
}

#[test]
fn nested_error_reports_instance_pointer() {
    let validator = Compiled::new(
        &json!({"type":"object","properties":{"item":{"type":"string","maxLength":2}}}),
        &[],
    )
    .unwrap();
    let error = validator.validate(&json!({"item": "long"})).unwrap_err();
    assert_eq!(error.path.unwrap().as_pointer(), "/item");
    assert!(error.detail.starts_with("at /item: "), "{}", error.detail);
}
