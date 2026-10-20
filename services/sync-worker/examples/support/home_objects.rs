//! Synthetic ciphertext-only fixtures for the private immutable store.
use bh_sync::{
    Digest, home_objects,
    permit::{LogId, Scope},
};
use serde_json::{Map, Value, json};

pub fn fixtures(
    account: LogId,
    base: LogId,
    mut sign: impl FnMut(Scope) -> String,
) -> Map<String, Value> {
    let bundle = home_objects::encode(&[1; 242], &[2; 1299], &[3; 1299]).unwrap();
    let conflict = home_objects::encode(&[4; 242], &[2; 1299], &[3; 1299]).unwrap();
    let prefix_digest = Digest([6; 32]);
    let scope = |log, bytes: &[u8]| Scope::StoreHomeObjects {
        log,
        prefix_digest,
        bundle_digest: home_objects::digest(bytes).unwrap(),
    };
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    [
        ("home_bundle", json!(hex(&bundle))),
        ("home_conflict", json!(hex(&conflict))),
        ("home_prefix", json!(hex(&prefix_digest.0))),
        (
            "home_digest",
            json!(hex(&home_objects::digest(&bundle).unwrap().0)),
        ),
        ("home_store", json!(sign(scope(account, &bundle)))),
        (
            "home_store_conflict",
            json!(sign(scope(account, &conflict))),
        ),
        ("home_store_base", json!(sign(scope(base, &bundle)))),
        (
            "home_read_events",
            json!(sign(Scope::ReadEvents {
                log: account,
                first: 1,
                last: 3
            })),
        ),
        (
            "home_read_controls",
            json!(sign(Scope::ReadControls {
                log: account,
                after: 0
            })),
        ),
        (
            "home_read_body",
            json!(sign(Scope::ReadBodies {
                log: account,
                bodies: vec![home_objects::digest(&bundle).unwrap()]
            })),
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v))
    .collect()
}
