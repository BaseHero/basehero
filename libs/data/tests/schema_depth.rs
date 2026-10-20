use bh_data::{DataError, profile, validate};
use serde_json::{Value, json};

fn nested(mut schema: Value, edges: usize) -> Value {
    for _ in 0..edges {
        schema = json!({"allOf": [schema]});
    }
    schema
}

// Each resource contributes its nesting edges, plus one reference edge except
// at the leaf. Even fourteen allOf edges keep source JSON depth below 32.
fn chain(nesting: &[usize], reversed_names: bool) -> Vec<(String, Value)> {
    let name = |i| {
        let n = if reversed_names {
            nesting.len() - 1 - i
        } else {
            i
        };
        format!("bh:value:{n:02x}@a")
    };
    nesting
        .iter()
        .enumerate()
        .map(|(i, edges)| {
            let leaf = if i + 1 == nesting.len() {
                json!({})
            } else {
                json!({"$ref": name(i + 1)})
            };
            let schema = nested(leaf, *edges);
            profile::check(&schema).expect("each source document satisfies the bounded profile");
            (name(i), schema)
        })
        .collect()
}

fn accepted(root: &Value, resources: &[(String, Value)]) -> bool {
    profile::check(root).unwrap();
    match validate::Compiled::new(root, resources) {
        Ok(compiled) => {
            compiled.validate(&json!({})).unwrap();
            true
        }
        Err(DataError::Limit(detail)) => {
            assert_eq!(detail, "cyclic or excessively deep schema graph");
            false
        }
        Err(other) => panic!("unexpected rejection: {other:?}"),
    }
}

fn check_permutations(nesting: &[usize], expected: bool, expected_bytes: Option<usize>) {
    let root = json!({"type": "object"});
    let mut mismatches = Vec::new();
    for reversed_names in [false, true] {
        let resources = chain(nesting, reversed_names);
        if let Some(bytes) = expected_bytes {
            let actual = serde_json::to_vec(&root).unwrap().len()
                + resources
                    .iter()
                    .map(|(uri, schema)| {
                        serde_json::to_vec(uri).unwrap().len()
                            + serde_json::to_vec(schema).unwrap().len()
                    })
                    .sum::<usize>();
            assert_eq!(actual, bytes);
        }
        for reversed_order in [false, true] {
            for rotation in 0..resources.len() {
                let mut ordered = resources.clone();
                if reversed_order {
                    ordered.reverse();
                }
                ordered.rotate_left(rotation);
                if accepted(&root, &ordered) != expected {
                    mismatches.push((reversed_names, reversed_order, rotation));
                }
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "wrong admission for (reversed names, reversed order, rotation): {mismatches:?}"
    );
}

#[test]
fn small_149_edge_closure_rejects_in_every_resource_order() {
    // Ten sets of fourteen nesting edges and nine references: 149, not 128.
    check_permutations(&[14; 10], false, Some(2065));
}

#[test]
fn exactly_128_edges_accept_in_every_resource_order() {
    // 8 * 14 + 8 + 8 reference edges = 128.
    check_permutations(&[14, 14, 14, 14, 14, 14, 14, 14, 8], true, None);
}

#[test]
fn exactly_129_edges_reject_in_every_resource_order() {
    check_permutations(&[14, 14, 14, 14, 14, 14, 14, 14, 9], false, None);
}

#[test]
fn cached_subtree_cannot_bypass_depth_through_a_deeper_prefix() {
    let mut mismatches = Vec::new();
    for (leaf_edges, expected) in [(5, true), (6, false)] {
        // Subtree heights 125 and 126. The shallow route adds two edges;
        // the deeper route adds three, so only the former fits 128 overall.
        for reversed_names in [false, true] {
            let resources = chain(
                &[14, 14, 14, 14, 14, 14, 14, 14, leaf_edges],
                reversed_names,
            );
            let reference = json!({"$ref": resources[0].0});
            for deeper_first in [false, true] {
                let mut branches = vec![reference.clone(), nested(reference.clone(), 1)];
                if deeper_first {
                    branches.reverse();
                }
                let root = json!({"allOf": branches});
                for reversed_order in [false, true] {
                    let mut ordered = resources.clone();
                    if reversed_order {
                        ordered.reverse();
                    }
                    if accepted(&root, &ordered) != expected {
                        mismatches.push((leaf_edges, reversed_names, deeper_first, reversed_order));
                    }
                }
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "wrong admission for (leaf edges, reversed names, deeper first, reversed resources): {mismatches:?}"
    );
}
