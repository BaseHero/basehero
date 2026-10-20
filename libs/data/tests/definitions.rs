use bh_data::{
    AppId, FieldKind, FieldPath, KeyRef, RevisionId, TypeId, WritePolicy, catalogue, compat,
    compose, definition, validate,
};
use serde_json::{Value, json};

fn doc() -> Value {
    json!({"format":"bh-type/1","local":"01010101010101010101010101010101","app":"0202020202020202020202020202020202020202020202020202020202020202","kind":"record","name":"Article","description":"A published article","extends":null,"uses":[],"schema":{"type":"object","properties":{"title":{"type":"string","maxLength":200}},"required":["title"]},"fields":{"/title":{"meaning":"Article headline","write":"direct","kind":"string"}},"actions":[],"indexes":[],"unique":[],"search":{"title":"/title","text":[]},"queries":[],"evolution":{"previous":null,"migration":"","migration_ops":[],"examples":{"valid":[],"invalid":[]}},"rationale":[]})
}
fn parse(v: &Value) -> definition::Definition {
    definition::parse(&serde_json::to_vec(v).unwrap()).unwrap()
}
fn compile(v: &Value) -> bh_data::CompiledType {
    let d = parse(v);
    compose::compile(&d, RevisionId::of(&d.bytes), &|_, _| None).unwrap()
}
fn field(v: &mut Value, name: &str, schema: Value, spec: Value) {
    v["schema"]["properties"][name] = schema;
    v["fields"][format!("/{name}")] = spec;
}
fn spec(meaning: &str) -> Value {
    json!({"meaning":meaning,"write":"direct","kind":"string"})
}
fn path(s: &str) -> FieldPath {
    FieldPath::parse(s).unwrap()
}

fn fixture(name: &str) -> Value {
    let text = match name {
        "Article" => include_str!("fixtures/types/Article.json"),
        "Article.v2" => include_str!("fixtures/types/Article.v2.json"),
        "Article.v3" => include_str!("fixtures/types/Article.v3.json"),
        "SourceSelection" => include_str!("fixtures/types/SourceSelection.json"),
        "JournalEntry" => include_str!("fixtures/types/JournalEntry.json"),
        "Address" => include_str!("fixtures/types/Address.json"),
        "Recipe" => include_str!("fixtures/types/Recipe.json"),
        "SpecialArticle" => include_str!("fixtures/types/SpecialArticle.json"),
        _ => panic!("unknown fixture"),
    };
    serde_json::from_str(text).unwrap()
}
#[test]
fn fixture_contracts_compile_and_classify() {
    for name in [
        "Article",
        "Address",
        "SourceSelection",
        "JournalEntry",
        "Recipe",
        "SpecialArticle",
        "Article.v2",
        "Article.v3",
    ] {
        let contract = fixture(name);
        let d = parse(&contract);
        let article = compile(&fixture("Article"));
        let address = compile(&fixture("Address"));
        let result = compose::compile(&d, RevisionId::of(&d.bytes), &|id, rev| {
            catalogue::Shipped.core_type(id).or_else(|| {
                [article.clone(), address.clone()]
                    .into_iter()
                    .find(|c| c.type_id == id && c.revision == rev)
            })
        });
        assert!(result.is_ok(), "{name}: {result:?}");
    }
    let article = compile(&fixture("Article"));
    let v2 = compile(&fixture("Article.v2"));
    let v3 = compile(&fixture("Article.v3"));
    assert!(compat::classify(&article, &v2).compatible);
    assert!(!compat::classify(&article, &v3).compatible);
}
#[test]
fn revision_must_hash_exact_definition_bytes() {
    let a = serde_json::to_vec_pretty(&doc()).unwrap();
    let d = definition::parse(&a).unwrap();
    assert_eq!(
        compose::compile(&d, RevisionId::of(&a), &|_, _| None)
            .unwrap()
            .revision,
        RevisionId::of(&a)
    );
    assert!(matches!(
        compose::compile(&d, RevisionId::of(b"different bytes"), &|_, _| None),
        Err(compose::ComposeError::Invalid(_))
    ));
}
#[test]
fn article_compiles_with_docs() {
    let d = parse(&doc());
    let compiled = compose::compile(&d, RevisionId::of(&d.bytes), &|_, _| None).unwrap();
    assert_eq!(compiled.type_id, TypeId::for_app(AppId([2; 32]), [1; 16]));
    assert_eq!(compiled.docs.description, "A published article");
    assert_eq!(
        compiled.field(&path("/title")).unwrap().meaning,
        "Article headline"
    );
    assert!(compiled.effective_schema["additionalProperties"] == false);
}
#[test]
fn field_without_meaning_rejected() {
    let mut v = doc();
    v["fields"]["/title"]["meaning"] = json!("");
    assert!(definition::parse(&serde_json::to_vec(&v).unwrap()).is_err());
}
#[test]
fn unknown_top_level_key_rejected() {
    let mut v = doc();
    v["unexpected"] = json!(true);
    assert!(definition::parse(&serde_json::to_vec(&v).unwrap()).is_err());
}
#[test]
fn note_specialisation_keeps_its_builtin_search_mapping() {
    let d = parse(&fixture("JournalEntry"));
    let subtype = compose::compile(&d, RevisionId::of(&d.bytes), &|id, rev| {
        catalogue::Shipped
            .core_type(id)
            .filter(|c| c.revision == rev)
    })
    .unwrap();
    assert_eq!(subtype.search.title, Some(path("/title")));
    assert!(subtype.search.builtin_body);
}
#[test]
fn index_declared_by_tracks_declaring_type() {
    let mut v = fixture("JournalEntry");
    v["indexes"] = json!([{"name":"by_mood","keys":["/mood"]}]);
    let d = parse(&v);
    let c = compose::compile(&d, RevisionId::of(&d.bytes), &|id, rev| {
        catalogue::Shipped
            .core_type(id)
            .filter(|note| note.revision == rev)
    })
    .unwrap();
    assert_eq!(
        c.indexes
            .iter()
            .find(|i| i.name == "by_mood")
            .unwrap()
            .declared_by,
        c.type_id
    );
    assert_eq!(
        c.indexes
            .iter()
            .find(|i| i.name == "recent")
            .unwrap()
            .declared_by,
        TypeId::core("note")
    );
}
#[test]
fn journal_entry_extends_note() {
    let (id, rev) = catalogue::baseline_note();
    let mut v = doc();
    v["extends"] = json!({"type":"core:note","revision":hex(rev.0)});
    v["schema"]["properties"] =
        json!({"date":{"type":"integer"},"mood":{"type":"string","maxLength":30}});
    v["schema"]["required"] = json!(["date"]);
    v["fields"] = json!({"/date":{"meaning":"Entry date","kind":"timestamp","write":"direct"},"/mood":{"meaning":"Mood","kind":"string","write":"direct"}});
    let d = parse(&v);
    let t = compose::compile(&d, RevisionId::of(&d.bytes), &|t, r| {
        catalogue::Shipped.core_type(t).filter(|c| c.revision == r)
    })
    .unwrap();
    assert_eq!(t.lineage.len(), 2);
    assert_eq!(t.field(&path("/title")).unwrap().declared_by, id);
    assert!(t.field(&path("/date")).is_some());
    assert!(t.field(&path("/mood")).is_some());
}
use bh_data::CoreCatalogue;
fn hex(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
#[test]
fn extension_redefining_inherited_field_rejected() {
    let (id, rev) = catalogue::baseline_note();
    let mut v = doc();
    v["extends"] = json!({"type":"core:note","revision":hex(rev.0)});
    let d = parse(&v);
    assert!(matches!(
        compose::compile(&d, RevisionId::of(&d.bytes), &|t, r| catalogue::Shipped
            .core_type(t)
            .filter(|c| c.revision == r)),
        Err(compose::ComposeError::Invalid(_))
    ));
    assert_ne!(id, d.type_id);
}
#[test]
fn missing_dependency_is_missing_not_invalid() {
    let mut v = doc();
    v["extends"] = json!({"type":hex([3;32]),"revision":hex([4;32])});
    let d = parse(&v);
    assert!(matches!(
        compose::compile(&d, RevisionId::of(&d.bytes), &|_, _| None),
        Err(compose::ComposeError::Missing(_, _))
    ));
}
#[test]
fn extends_cycle_rejected() {
    let a = compile(&doc());
    let mut v = doc();
    v["local"] = json!("03030303030303030303030303030303");
    let b = compile(&v);
    let mut root = doc();
    root["extends"] = json!({"type":hex(b.type_id.0),"revision":hex(b.revision.0)});
    let mut cyclic = b.clone();
    cyclic
        .lineage
        .push((TypeId::for_app(AppId([2; 32]), [1; 16]), a.revision));
    let d = parse(&root);
    assert!(matches!(
        compose::compile(&d, RevisionId::of(&d.bytes), &|_, _| Some(cyclic.clone())),
        Err(compose::ComposeError::Invalid(_))
    ));
}
#[test]
fn effective_schema_is_closed() {
    let c = compile(&doc());
    let validator = validate::Compiled::new(&c.effective_schema, &c.resources).unwrap();
    assert!(
        validator
            .validate(&json!({"title":"ok","surprise":1}))
            .is_err()
    );
}
#[test]
fn compat_add_optional_is_compatible() {
    let a = compile(&doc());
    let mut v = doc();
    field(
        &mut v,
        "summary",
        json!({"type":"string","maxLength":500}),
        spec("Summary"),
    );
    let change = compat::classify(&a, &compile(&v));
    assert!(change.compatible);
    assert!(!change.rule_change);
    assert!(!change.doc_only);
}
#[test]
fn compat_add_required_is_breaking() {
    let a = compile(&doc());
    let mut v = doc();
    field(
        &mut v,
        "summary",
        json!({"type":"string","maxLength":500}),
        spec("Summary"),
    );
    v["schema"]["required"] = json!(["title", "summary"]);
    assert!(!compat::classify(&a, &compile(&v)).compatible);
}
#[test]
fn newly_introduced_assertions_are_breaking_rule_changes() {
    let cases = [
        (
            "enum",
            json!({"type":"string","maxLength":200,"enum":["A"]}),
            spec("Headline"),
        ),
        (
            "const",
            json!({"type":"string","maxLength":200,"const":"A"}),
            spec("Headline"),
        ),
        (
            "uniqueItems",
            json!({"type":"array","maxItems":10,"uniqueItems":true}),
            json!({"meaning":"Items","write":"direct","kind":"atomic"}),
        ),
        (
            "multipleOf",
            json!({"type":"integer","multipleOf":2}),
            json!({"meaning":"Count","write":"direct","kind":"integer"}),
        ),
        (
            "anyOf",
            json!({"type":"string","maxLength":200,"anyOf":[{"const":"A"}]}),
            spec("Headline"),
        ),
        (
            "oneOf",
            json!({"type":"string","maxLength":200,"oneOf":[{"const":"A"}]}),
            spec("Headline"),
        ),
        (
            "allOf",
            json!({"type":"string","maxLength":200,"allOf":[{"maxLength":3}]}),
            spec("Headline"),
        ),
        (
            "nested required",
            json!({"type":"object","properties":{"city":{"type":"string","maxLength":30}},"required":["city"]}),
            json!({"meaning":"Address","write":"direct","kind":"atomic"}),
        ),
    ];
    for (name, restricted, field_decl) in cases {
        let mut v = doc();
        let original = match name {
            "uniqueItems" => json!({"type":"array","maxItems":10}),
            "multipleOf" => json!({"type":"integer"}),
            "nested required" => {
                json!({"type":"object","properties":{"city":{"type":"string","maxLength":30}}})
            }
            _ => json!({"type":"string","maxLength":200}),
        };
        v["schema"]["properties"]["title"] = original;
        v["fields"]["/title"] = field_decl;
        let old = compile(&v);
        v["schema"]["properties"]["title"] = restricted;
        let change = compat::classify(&old, &compile(&v));
        assert!(
            !change.compatible && change.rule_change,
            "{name}: {change:?}"
        );
        assert!(!change.reasons.is_empty(), "{name}: reason missing");
    }
}
#[test]
fn added_nonrestrictive_assertions_do_not_break_existing_records() {
    let mut v = doc();
    v["schema"]["properties"]["title"] = json!({"type":"array","maxItems":10});
    v["fields"]["/title"] = json!({"meaning":"Items","kind":"atomic","write":"direct"});
    let old = compile(&v);
    v["schema"]["properties"]["title"]["uniqueItems"] = json!(false);
    let change = compat::classify(&old, &compile(&v));
    assert!(change.compatible && change.rule_change, "{change:?}");
    let mut v = doc();
    v["schema"]["properties"]["title"] = json!({"type":"object","properties":{}});
    v["fields"]["/title"]["kind"] = json!("atomic");
    let old = compile(&v);
    v["schema"]["properties"]["title"]["additionalProperties"] = json!(true);
    let change = compat::classify(&old, &compile(&v));
    assert!(change.compatible && change.rule_change, "{change:?}");
}
#[test]
fn compat_enum_widen_is_breaking() {
    let mut v = doc();
    v["schema"]["properties"]["title"]["enum"] = json!(["A"]);
    let a = compile(&v);
    v["schema"]["properties"]["title"]["enum"] = json!(["A", "B"]);
    assert!(!compat::classify(&a, &compile(&v)).compatible);
}
#[test]
fn a_changed_reusable_definition_changes_rules() {
    let mut v = doc();
    v["schema"]["$defs"] = json!({"headline":{"type":"string","maxLength":200}});
    v["schema"]["properties"]["title"] = json!({"$ref":"#/$defs/headline"});
    let a = compile(&v);
    v["schema"]["$defs"]["headline"]["maxLength"] = json!(100);
    let change = compat::classify(&a, &compile(&v));
    assert!(change.rule_change && !change.compatible, "{change:?}");
}
#[test]
fn value_docs_do_not_change_rules() {
    let mut v = fixture("Address");
    let old = compile(&v);
    v["description"] = json!("Updated description");
    let change = compat::classify(&old, &compile(&v));
    assert!(
        change.doc_only && !change.rule_change && change.compatible,
        "{change:?}"
    );
}
#[test]
fn optional_direct_field_with_new_reusable_definition_is_compatible() {
    let old = compile(&doc());
    let mut v = doc();
    v["schema"]["$defs"] = json!({"summary":{"type":"string","maxLength":200}});
    field(
        &mut v,
        "summary",
        json!({"$ref":"#/$defs/summary"}),
        spec("Summary"),
    );
    let change = compat::classify(&old, &compile(&v));
    assert!(
        change.compatible && !change.rule_change && !change.doc_only,
        "{change:?}"
    );
}
#[test]
fn reusable_definition_added_without_a_field_changes_rules() {
    let old = compile(&doc());
    let mut v = doc();
    v["schema"]["$defs"] = json!({"unused":{"type":"string","maxLength":50}});
    let change = compat::classify(&old, &compile(&v));
    assert!(
        change.compatible && change.rule_change && !change.doc_only,
        "{change:?}"
    );
}
#[test]
fn reusable_definition_annotation_is_documentation_only() {
    let mut v = doc();
    v["schema"]["$defs"] =
        json!({"headline":{"type":"string","maxLength":200,"description":"Original"}});
    v["schema"]["properties"]["title"] = json!({"$ref":"#/$defs/headline"});
    let old = compile(&v);
    v["schema"]["$defs"]["headline"]["description"] = json!("Updated");
    let change = compat::classify(&old, &compile(&v));
    assert!(
        change.doc_only && change.compatible && !change.rule_change,
        "{change:?}"
    );
    assert!(
        change
            .reasons
            .iter()
            .any(|reason| reason.contains("description")),
        "{change:?}"
    );
}
#[test]
fn nested_item_annotations_and_bounds_in_properties_and_defs() {
    for inside_defs in [false, true] {
        let mut v = doc();
        let list = json!({"type":"array","maxItems":10,"items":{"type":"string","maxLength":10,"description":"Original"}});
        if inside_defs {
            v["schema"]["$defs"] = json!({"list":list});
            v["schema"]["properties"]["title"] = json!({"$ref":"#/$defs/list"});
        } else {
            v["schema"]["properties"]["title"] = list;
        }
        v["fields"]["/title"]["kind"] = json!("atomic");
        let old = compile(&v);
        let items = if inside_defs {
            &mut v["schema"]["$defs"]["list"]["items"]
        } else {
            &mut v["schema"]["properties"]["title"]["items"]
        };
        items["description"] = json!("Updated");
        let documented = compile(&v);
        let doc_change = compat::classify(&old, &documented);
        assert!(
            doc_change.doc_only && doc_change.compatible && !doc_change.rule_change,
            "inside_defs={inside_defs}: {doc_change:?}"
        );
        let items = if inside_defs {
            &mut v["schema"]["$defs"]["list"]["items"]
        } else {
            &mut v["schema"]["properties"]["title"]["items"]
        };
        items["maxLength"] = json!(20);
        let loosened = compat::classify(&old, &compile(&v));
        assert!(
            loosened.compatible && loosened.rule_change && !loosened.doc_only,
            "inside_defs={inside_defs}: {loosened:?}"
        );
    }
}
#[test]
fn nested_subschema_positions_compare_without_wholesale_breakage() {
    for location in ["prefixItems", "anyOf", "allOf", "oneOf"] {
        let mut v = doc();
        let child = json!({"type":"string","maxLength":10,"description":"Original"});
        if location == "prefixItems" {
            v["schema"]["properties"]["title"] =
                json!({"type":"array","maxItems":10,"prefixItems":[child]});
        } else {
            v["schema"]["properties"]["title"] =
                json!({"type":"string","maxLength":200,location:[child]});
        }
        if location == "prefixItems" {
            v["fields"]["/title"]["kind"] = json!("atomic");
        }
        let old = compile(&v);
        v["schema"]["properties"]["title"][location][0]["description"] = json!("Updated");
        let annotation = compat::classify(&old, &compile(&v));
        assert!(
            annotation.doc_only && annotation.compatible,
            "{location}: {annotation:?}"
        );
        v["schema"]["properties"]["title"][location][0]["maxLength"] = json!(20);
        let bound = compat::classify(&old, &compile(&v));
        if location == "oneOf" {
            assert!(!bound.compatible, "oneOf widening may overlap: {bound:?}");
        } else {
            assert!(
                bound.compatible && bound.rule_change,
                "{location}: {bound:?}"
            );
        }
    }
}
#[test]
fn optional_field_exempts_only_its_reachable_reusable_definition() {
    let old = compile(&doc());
    let mut v = doc();
    field(
        &mut v,
        "summary",
        json!({"$ref":"#/$defs/summary"}),
        spec("Summary"),
    );
    v["schema"]["$defs"] = json!({"summary":{"type":"string","maxLength":100},"unused":{"type":"string","maxLength":20}});
    let change = compat::classify(&old, &compile(&v));
    assert!(change.compatible && change.rule_change, "{change:?}");
}
#[test]
fn unrelated_unused_definition_remains_a_rule_change_when_adding_optional_field() {
    let old = compile(&doc());
    let mut v = doc();
    field(
        &mut v,
        "summary",
        json!({"type":"string","maxLength":100}),
        spec("Summary"),
    );
    v["schema"]["$defs"] = json!({"unused":{"type":"string","maxLength":20}});
    let change = compat::classify(&old, &compile(&v));
    assert!(change.compatible && change.rule_change, "{change:?}");
}
#[test]
fn reusable_definition_bound_loosening_is_compatible_rule_change() {
    let mut v = doc();
    v["schema"]["$defs"] = json!({"headline":{"type":"string","maxLength":100}});
    v["schema"]["properties"]["title"] = json!({"$ref":"#/$defs/headline"});
    let old = compile(&v);
    v["schema"]["$defs"]["headline"]["maxLength"] = json!(200);
    let change = compat::classify(&old, &compile(&v));
    assert!(
        change.compatible && change.rule_change && !change.doc_only,
        "{change:?}"
    );
    assert!(
        change
            .reasons
            .iter()
            .any(|reason| reason.contains("maxLength")),
        "{change:?}"
    );
}
#[test]
fn docs_on_a_type_with_defs_do_not_change_rules() {
    let mut v = doc();
    v["schema"]["$defs"] = json!({"headline":{"type":"string","maxLength":200}});
    v["schema"]["properties"]["title"] = json!({"$ref":"#/$defs/headline"});
    let a = compile(&v);
    v["description"] = json!("New documentation");
    let result = compat::classify(&a, &compile(&v));
    assert!(
        result.doc_only && result.compatible && !result.rule_change,
        "{result:?}"
    );
}
#[test]
fn field_documentation_changes_alone_are_doc_only() {
    for (key, value) in [
        ("meaning", json!("Updated headline")),
        ("unit", json!("Display text")),
        ("absent", json!("Not yet named")),
    ] {
        let old = compile(&doc());
        let mut v = doc();
        v["fields"]["/title"][key] = value;
        let change = compat::classify(&old, &compile(&v));
        assert!(
            change.doc_only && change.compatible && !change.rule_change && !change.index_change,
            "{key}: {change:?}"
        );
        assert!(
            change.reasons.iter().any(|reason| reason.contains(key)),
            "{key}: {change:?}"
        );
    }
}
#[test]
fn schema_annotations_alone_are_doc_only() {
    for (key, value) in [
        ("description", json!("New docs")),
        ("title", json!("Headline")),
        ("examples", json!(["A"])),
        ("$comment", json!("Source field")),
        ("deprecated", json!(true)),
    ] {
        let old = compile(&doc());
        let mut v = doc();
        v["schema"]["properties"]["title"][key] = value;
        let change = compat::classify(&old, &compile(&v));
        assert!(
            change.doc_only && change.compatible && !change.rule_change,
            "{key}: {change:?}"
        );
        assert!(
            change.reasons.iter().any(|reason| reason.contains(key)),
            "{key}: {change:?}"
        );
    }
}
#[test]
fn compat_doc_only_flags_doc_only_and_no_index_change() {
    let a = compile(&doc());
    let mut v = doc();
    v["description"] = json!("New documentation");
    let c = compat::classify(&a, &compile(&v));
    assert!(c.doc_only && c.compatible && !c.rule_change && !c.index_change);
}
#[test]
fn compat_write_policy_change_is_rule_change() {
    let a = compile(&doc());
    let mut v = doc();
    v["fields"]["/title"]["write"] = json!("action");
    assert!(compat::classify(&a, &compile(&v)).rule_change);
}
#[test]
fn core_note_revision_is_stable() {
    let (id, r) = catalogue::baseline_note();
    assert_eq!(id, TypeId::core("note"));
    assert_eq!(
        hex(r.0),
        "10e12447ed29f6b680298dec1c1baed2b2763d3116ea1ea5154570c45f8e9e91"
    );
}
#[test]
fn app_cannot_claim_core_type_id() {
    let mut v = doc();
    v["builtin"] = json!("Note");
    assert!(definition::parse(&serde_json::to_vec(&v).unwrap()).is_err());
}
#[test]
fn nested_writable_paths_rejected() {
    let mut v = doc();
    field(
        &mut v,
        "addr",
        json!({"type":"object","properties":{"city":{"type":"string","maxLength":30}}}),
        json!({"meaning":"Address","kind":"atomic","write":"direct"}),
    );
    v["fields"]["/addr/city"] = spec("City");
    assert!(
        compose::compile(
            &parse(&v),
            RevisionId::of(&serde_json::to_vec(&v).unwrap()),
            &|_, _| None
        )
        .is_err()
    );
}
#[test]
fn container_with_leaf_fields_edits_leaves_independently() {
    let mut v = doc();
    field(
        &mut v,
        "addr",
        json!({"type":"object","properties":{"city":{"type":"string","maxLength":30},"zip":{"type":"string","maxLength":12}}}),
        json!({"meaning":"Address","kind":"container","write":"derived"}),
    );
    v["fields"]["/addr/city"] = spec("City");
    v["fields"]["/addr/zip"] = spec("ZIP code");
    let c = compile(&v);
    assert!(matches!(
        c.field(&path("/addr")).unwrap().kind,
        FieldKind::Container
    ));
    assert_eq!(
        c.field(&path("/addr/city")).unwrap().write,
        WritePolicy::Direct
    );
}
#[test]
fn field_kind_must_match_its_schema() {
    let mut v = doc();
    v["schema"]["properties"]["title"] = json!({"type":"integer"});
    let d = parse(&v);
    assert!(compose::compile(&d, RevisionId::of(&d.bytes), &|_, _| None).is_err());
}
#[test]
fn nullable_scalar_field_compiles_but_cannot_be_unique() {
    let mut v = doc();
    v["schema"]["properties"]["title"]["type"] = json!(["string", "null"]);
    let compiled = compile(&v);
    assert!(compiled.field(&path("/title")).unwrap().nullable);
    v["unique"] = json!([{"name":"title","keys":["/title"]}]);
    let d = parse(&v);
    assert!(compose::compile(&d, RevisionId::of(&d.bytes), &|_, _| None).is_err());
}
#[test]
fn nested_unique_key_requires_the_nested_property() {
    let mut v = doc();
    field(
        &mut v,
        "addr",
        json!({"type":"object","properties":{"city":{"type":"string","maxLength":30}},"required":[]}),
        json!({"meaning":"Address","kind":"container","write":"derived"}),
    );
    v["fields"]["/addr/city"] = spec("City");
    v["schema"]["required"] = json!(["title", "addr"]);
    v["unique"] = json!([{"name":"city","keys":["/addr/city"]}]);
    let d = parse(&v);
    assert!(compose::compile(&d, RevisionId::of(&d.bytes), &|_, _| None).is_err());
}
#[test]
fn unique_key_must_be_required() {
    let mut v = doc();
    v["unique"] = json!([{"name":"title","keys":["/title"]}]);
    assert_eq!(
        compile(&v).uniques[0].keys,
        vec![KeyRef::Field(path("/title"))]
    );
    v["schema"]["required"] = json!([]);
    let d = parse(&v);
    assert!(compose::compile(&d, RevisionId::of(&d.bytes), &|_, _| None).is_err());
}
#[test]
fn defs_collision_between_base_and_extension_isolated() {
    let mut base = doc();
    base["schema"]["$defs"] = json!({"code":{"type":"string","maxLength":3}});
    base["schema"]["properties"]["title"] = json!({"$ref":"#/$defs/code"});
    let parent = compile(&base);
    let mut extension = doc();
    extension["local"] = json!("04040404040404040404040404040404");
    extension["extends"] = json!({"type":hex(parent.type_id.0),"revision":hex(parent.revision.0)});
    extension["schema"]["properties"] = json!({"short":{"$ref":"#/$defs/code"}});
    extension["schema"]["required"] = json!(["short"]);
    extension["schema"]["$defs"] = json!({"code":{"type":"integer","minimum":0}});
    extension["fields"] =
        json!({"/short":{"meaning":"Sequence","kind":"integer","write":"direct"}});
    extension["search"] = json!({"title":null,"text":[]});
    let d = parse(&extension);
    let child =
        compose::compile(&d, RevisionId::of(&d.bytes), &|_, _| Some(parent.clone())).unwrap();
    assert_eq!(child.resources.len(), 2);
    let check = validate::Compiled::new(&child.effective_schema, &child.resources).unwrap();
    assert!(check.validate(&json!({"title":"abc","short":1})).is_ok());
    assert!(check.validate(&json!({"title":"abcd","short":1})).is_err());
    assert!(check.validate(&json!({"title":"abc","short":"1"})).is_err());
}
#[test]
fn value_contract_exposes_its_pinned_resource() {
    let value = compile(&fixture("Address"));
    let uri = format!(
        "bh:value:{}@{}",
        hex(value.type_id.0),
        hex(value.revision.0)
    );
    assert!(
        value
            .resources
            .iter()
            .any(|(key, schema)| key == &uri && schema == &value.effective_schema)
    );
    assert!(value.fields.is_empty());
}
#[test]
fn recipe_embeds_address_value_and_note_ref() {
    let mut address = doc();
    address["kind"] = json!("value");
    address["local"] = json!("05050505050505050505050505050505");
    address["search"] = json!({"title":null,"text":[]});
    let addr = compile(&address);
    let mut recipe = doc();
    recipe["local"] = json!("06060606060606060606060606060606");
    recipe["uses"] = json!([{"type":hex(addr.type_id.0),"revision":hex(addr.revision.0)}]);
    field(
        &mut recipe,
        "place",
        json!({"$ref":format!("bh:value:{}@{}",hex(addr.type_id.0),hex(addr.revision.0))}),
        json!({"meaning":"Cooking location","kind":"atomic","write":"direct"}),
    );
    field(
        &mut recipe,
        "instructions",
        json!({"type":"object","properties":{"audience":{"type":"string","minLength":64,"maxLength":64},"record":{"type":"string","minLength":64,"maxLength":64}},"required":["record"],"additionalProperties":false}),
        json!({"meaning":"Note with instructions","kind":"reference","write":"direct","ref":{"targets":["core:note"],"family":true}}),
    );
    let d = parse(&recipe);
    let c = compose::compile(&d, RevisionId::of(&d.bytes), &|_, _| Some(addr.clone())).unwrap();
    assert!(
        matches!(&c.field(&path("/instructions")).unwrap().kind,FieldKind::Reference(r) if r.targets == vec![TypeId::core("note")])
    );
    let check = validate::Compiled::new(&c.effective_schema, &c.resources).unwrap();
    assert!(check.validate(&json!({"title":"Dinner","place":{"title":"Where"},"instructions":{"record":hex([8;32])}})).is_ok());
    assert!(
        check
            .validate(&json!({"title":"Dinner","place":{"title":4}}))
            .is_err()
    );
}
#[test]
fn non_note_cannot_claim_builtin_body() {
    let mut v = doc();
    v["search"]["builtin_body"] = json!(true);
    let d = parse(&v);
    assert!(compose::compile(&d, RevisionId::of(&d.bytes), &|_, _| None).is_err());
    v["kind"] = json!("value");
    v["search"] = json!({"title":null,"text":[],"builtin_body":true});
    let d = parse(&v);
    assert!(compose::compile(&d, RevisionId::of(&d.bytes), &|_, _| None).is_err());
}
#[test]
fn root_dialect_and_id_controls_rejected() {
    for (key, value) in [
        ("$id", json!("bh:untrusted")),
        (
            "$schema",
            json!("https://json-schema.org/draft/2020-12/schema"),
        ),
    ] {
        let mut v = doc();
        v["schema"][key] = value;
        assert!(
            definition::parse(&serde_json::to_vec(&v).unwrap()).is_err(),
            "{key}"
        );
    }
}
#[test]
fn root_combinator_rejected() {
    let mut v = doc();
    v["schema"]["allOf"] = json!([{"type":"object"}]);
    assert!(definition::parse(&serde_json::to_vec(&v).unwrap()).is_err());
}
#[test]
fn removing_a_bound_is_compatible_but_changes_rules() {
    let mut v = doc();
    v["schema"]["properties"]["title"]["minLength"] = json!(2);
    let old = compile(&v);
    v["schema"]["properties"]["title"]
        .as_object_mut()
        .unwrap()
        .remove("minLength");
    let result = compat::classify(&old, &compile(&v));
    assert!(result.compatible && result.rule_change, "{result:?}");
}
#[test]
fn new_unique_constraint_changes_index_and_rules() {
    let old = compile(&doc());
    let mut v = doc();
    v["unique"] = json!([{"name":"title","keys":["/title"]}]);
    let change = compat::classify(&old, &compile(&v));
    assert!(change.index_change && change.rule_change, "{change:?}");
}
#[test]
fn new_saved_query_changes_index_declarations_not_record_rules() {
    let old = compile(&doc());
    let mut v = doc();
    v["queries"] = json!([{"name":"recent","query":{"sort":["$changed"]}}]);
    let change = compat::classify(&old, &compile(&v));
    assert!(
        change.compatible && change.index_change && !change.rule_change && !change.doc_only,
        "{change:?}"
    );
}
#[test]
fn compat_loosened_bound_is_rule_change_but_compatible() {
    let a = compile(&doc());
    let mut v = doc();
    v["schema"]["properties"]["title"]["maxLength"] = json!(300);
    let change = compat::classify(&a, &compile(&v));
    assert!(change.compatible && change.rule_change);
}
