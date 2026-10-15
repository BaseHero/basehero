use super::*;
use crate::appraisal::Sample;
use crate::appraisal::{PolicyStore, StoredState};
use crate::test_clock::At;
use bh_confidential_policy::Snapshot;
struct UnusedStore;
impl PolicyStore for UnusedStore {
    type Error = ();
    fn load(&mut self) -> Result<StoredState, Self::Error> {
        unreachable!()
    }
    fn save(&mut self, _: &Snapshot) -> Result<(), Self::Error> {
        unreachable!()
    }
}
fn keys() -> Keys {
    Keys {
        c: bh_crypto::Secret::random(),
        s: bh_crypto::Secret::random(),
    }
}
fn client(keys: Keys, signing: [u8; 32], t: [u8; 32]) -> ClientAwaitServer<UnusedStore> {
    ClientAwaitServer {
        appraisal: Appraisal::Server(Box::new(crate::test_clock::read)),
        keys,
        t,
        signing,
        start: 0,
        last: 0,
    }
}
#[test]
fn independent_signature_and_kem_confirmation_failures() {
    let signing = SigningKey::generate();
    let t = [8; 32];
    let server_keys = keys();
    let sig = signing.sign(&signature_message(&t));
    let valid = seal_finish(&server_keys, &t, 4, 1, Some(&sig)).unwrap();
    // Fully valid server confirmation; only the Ed25519 signature changes.
    let mut bad_sig = valid.clone();
    bad_sig[11] ^= 1;
    assert_eq!(
        client(server_keys, signing.public(), t)
            .at(Sample {
                system_seconds: None,
                monotonic_ms: 1
            })
            .accept_finish(&bad_sig)
            .err(),
        Some(Error::Authentication)
    );
    // The signature is valid, but an independent KEM-derived S cannot open
    // even though the AEAD confirmation is well-formed and valid for its key.
    assert_eq!(
        client(keys(), signing.public(), t)
            .at(Sample {
                system_seconds: None,
                monotonic_ms: 1
            })
            .accept_finish(&valid)
            .err(),
        Some(Error::Authentication)
    );
}
