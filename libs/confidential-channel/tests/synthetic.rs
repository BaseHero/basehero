//! The labelled local-only appraisal: a synthetic quote must bind the server's
//! fresh keys and nonce, the signed policy must list the synthetic build, and
//! the production appraisal never accepts one.
#![cfg(feature = "synthetic-attestation")]

use bh_confidential_attestation::synthetic;
use bh_confidential_channel::{
    Error,
    appraisal::{PolicyContext, PolicyStore, Sample, StoredState},
    handshake::{ClientHello, ServerPending},
    record::Opened,
};
use bh_confidential_policy::{Build, Limits, Policy, Role, Snapshot};
use bh_crypto::{SecretBytes, SigningKey};
use std::sync::LazyLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

struct Memory(Option<Snapshot>);
impl PolicyStore for Memory {
    type Error = ();
    fn load(&mut self) -> Result<StoredState, ()> {
        Ok(self
            .0
            .clone()
            .map_or(StoredState::Fresh, StoredState::Committed))
    }
    fn save(&mut self, snapshot: &Snapshot) -> Result<(), ()> {
        self.0 = Some(snapshot.clone());
        Ok(())
    }
}

fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
static START: LazyLock<Instant> = LazyLock::new(Instant::now);
fn monotonic() -> u64 {
    START.elapsed().as_millis() as u64
}
fn clock() -> impl Fn() -> Sample + Send + Sync + 'static {
    || Sample {
        system_seconds: Some(seconds()),
        monotonic_ms: monotonic(),
    }
}
fn policy(root: &SigningKey, builds: Vec<Build>) -> (Vec<u8>, [u8; 64]) {
    let payload = serde_json::to_vec(&Policy {
        version: 1,
        generation: 1,
        issued_at: seconds() - 60,
        expires_at: seconds() + 3600,
        builds,
        machines: vec![synthetic::machine()],
    })
    .unwrap();
    let signature =
        root.sign(&[b"basehero.confidential-policy.v1\0".as_slice(), &payload].concat());
    (payload, signature)
}
fn client(root: &SigningKey) -> ClientHello<Memory> {
    let limits = Limits {
        max_lifetime_secs: 86_400,
        max_uncertainty_secs: 0,
    };
    let context = PolicyContext::new(root.public(), limits, 1, Memory(None), clock()).unwrap();
    ClientHello::new(context).unwrap()
}
/// The server's proof frame for this hello, with the quote `make` builds from
/// the server's report data.
fn proof(
    root: &SigningKey,
    hello: &ClientHello<Memory>,
    builds: Vec<Build>,
    make: impl FnOnce([u8; 64]) -> Vec<u8>,
) -> (
    Vec<u8>,
    bh_confidential_channel::handshake::ServerAwaitEncapsulation<Memory>,
) {
    let server =
        ServerPending::<Memory>::accept_hello(hello.frame(), root.public(), monotonic()).unwrap();
    let quote = make(server.report_data());
    let (payload, signature) = policy(root, builds);
    server
        .attach_evidence(
            &payload,
            &signature,
            &quote,
            b"synthetic",
            b"synthetic",
            monotonic(),
        )
        .unwrap()
}

#[test]
fn synthetic_quote_completes_an_attested_channel() {
    let root = SigningKey::generate();
    let hello = client(&root);
    let (frame, server) = proof(
        &root,
        &hello,
        vec![synthetic::build(Role::Checker)],
        |report| synthetic::quote(&report),
    );
    let (encapsulation, client) = hello
        .accept_synthetic_proof(&frame)
        .unwrap()
        .encapsulate()
        .unwrap();
    let (finish, server) = server
        .accept_encapsulation(&encapsulation, monotonic())
        .unwrap();
    let (confirm, mut device) = client.accept_finish(&finish).unwrap();
    let mut service = server.accept_finish(&confirm, clock()).unwrap();
    assert_eq!(device.binding().unwrap(), service.binding().unwrap());
    let sealed = device
        .seal(SecretBytes::from_vec(b"ping".to_vec()))
        .unwrap();
    let Opened::Data(plain) = service.open(&sealed).unwrap() else {
        panic!("data record")
    };
    assert_eq!(plain.expose(), b"ping");
}

#[test]
fn synthetic_quote_must_bind_the_server_keys_and_nonce() {
    let root = SigningKey::generate();
    let hello = client(&root);
    let (frame, _) = proof(
        &root,
        &hello,
        vec![synthetic::build(Role::Checker)],
        |mut report| {
            report[0] ^= 1;
            synthetic::quote(&report)
        },
    );
    assert_eq!(
        hello.accept_synthetic_proof(&frame).err(),
        Some(Error::Attestation(
            bh_confidential_attestation::Error::Binding
        ))
    );
}

#[test]
fn the_signed_policy_must_list_the_synthetic_build() {
    let root = SigningKey::generate();
    let hello = client(&root);
    let other = Build {
        role: Role::Checker,
        compose_sha256: [9; 32],
        boot: std::array::from_fn(|_| vec![9; 48]),
    };
    let (frame, _) = proof(&root, &hello, vec![other], |report| {
        synthetic::quote(&report)
    });
    assert!(matches!(
        hello.accept_synthetic_proof(&frame).err(),
        Some(Error::Policy(_))
    ));
}

#[test]
fn the_production_appraisal_refuses_a_synthetic_quote() {
    let root = SigningKey::generate();
    let hello = client(&root);
    let (frame, _) = proof(
        &root,
        &hello,
        vec![synthetic::build(Role::Checker)],
        |report| synthetic::quote(&report),
    );
    assert!(matches!(
        hello.accept_proof(&frame).err(),
        Some(Error::Attestation(_))
    ));
}
