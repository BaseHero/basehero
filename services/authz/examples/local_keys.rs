//! Disposable local stack keys and a synthetic-only signed checker policy.
//! Invoke only from local-stack.sh with a private, untracked directory.
use bh_confidential_attestation::synthetic;
use bh_confidential_policy::{Policy, Role};
use bh_crypto::{Secret, SigningKey};
use bh_sync::{permit, receipt};
use std::{
    env, fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

fn save(dir: &Path, name: &str, value: &[u8]) {
    fs::write(dir.join(name), value).unwrap();
}
fn seed(dir: &Path, name: &str) -> SigningKey {
    let bytes: [u8; 32] = bh_crypto::random();
    save(dir, name, hex::encode(bytes).as_bytes());
    SigningKey::from_seed(&Secret::from_slice(&bytes).unwrap())
}
fn main() {
    let mut args = env::args().skip(1);
    let dir = args.next().expect("keys directory");
    let dir = Path::new(&dir);
    let (app, generation) = if args.next().as_deref() == Some("renew") {
        let prior: Policy =
            serde_json::from_slice(&fs::read(dir.join("policy.json")).unwrap()).unwrap();
        let generation = prior
            .generation
            .checked_add(1)
            .expect("policy generation exhausted");
        let bytes = hex::decode(fs::read_to_string(dir.join("app-root.seed")).unwrap()).unwrap();
        let app = SigningKey::from_seed(&Secret::from_slice(&bytes).unwrap());
        assert_eq!(
            hex::encode(app.public()),
            fs::read_to_string(dir.join("app-root.pub")).unwrap()
        );
        (app, generation)
    } else {
        fs::create_dir_all(dir).unwrap();
        let root = seed(dir, "hosting-root.seed");
        save(
            dir,
            "hosting-root.pub",
            hex::encode(root.public()).as_bytes(),
        );
        let receipt_key = seed(dir, "receipt.seed");
        save(
            dir,
            "receipt.cert",
            hex::encode(receipt::certify(&root, receipt_key.public())).as_bytes(),
        );
        let permit_key = seed(dir, "permit.seed");
        save(
            dir,
            "permit.cert",
            hex::encode(permit::certify(&root, permit_key.public())).as_bytes(),
        );
        let app = seed(dir, "app-root.seed");
        save(dir, "app-root.pub", hex::encode(app.public()).as_bytes());
        (app, 1)
    };
    let build = synthetic::build(Role::Checker);
    let machine = synthetic::machine();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Debug on fixed byte arrays is JSON's integer-array syntax. This policy
    // is intentionally restricted to the local checker and synthetic machine.
    let policy = format!(
        "{{\"version\":1,\"generation\":{generation},\"issued_at\":{},\"expires_at\":{},\"builds\":[{{\"role\":\"checker\",\"compose_sha256\":{:?},\"boot\":[{:?},{:?},{:?},{:?}]}}],\"machines\":[{:?}]}}",
        now.saturating_sub(60),
        now + 86_340,
        build.compose_sha256,
        build.boot[0],
        build.boot[1],
        build.boot[2],
        build.boot[3],
        machine,
    );
    save(dir, "policy.json", policy.as_bytes());
    save(
        dir,
        "policy.sig",
        hex::encode(
            app.sign(
                &[
                    b"basehero.confidential-policy.v1\0".as_slice(),
                    policy.as_bytes(),
                ]
                .concat(),
            ),
        )
        .as_bytes(),
    );
}
