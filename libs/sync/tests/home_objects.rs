use bh_crypto::SigningKey;
use bh_sync::{
    Digest,
    home_objects::{self, Bundle},
    permit::{self, LogId, LogKind, Permit, Scope},
    wire::{Request, Response},
};

#[test]
fn bundle_has_one_exact_bounded_encoding_and_domain() {
    let (r, d, s) = (vec![1; 242], vec![2; 1299], vec![3; 1299]);
    let encoded = home_objects::encode(&r, &d, &s).unwrap();
    let mut expected = vec![0, 1];
    for bytes in [&r, &d, &s] {
        expected.extend((bytes.len() as u32).to_be_bytes());
        expected.extend(bytes);
    }
    assert_eq!(encoded, expected);
    let decoded = Bundle::decode(&encoded).unwrap();
    assert_eq!(
        (decoded.record, decoded.device_seal, decoded.recovery_seal),
        (r.as_slice(), d.as_slice(), s.as_slice())
    );
    assert_eq!(
        home_objects::digest(&encoded).unwrap(),
        Digest(bh_crypto::hash(
            &[b"bh/home-objects/v1\0".as_slice(), &expected].concat()
        ))
    );
    for n in 0..encoded.len() {
        assert!(Bundle::decode(&encoded[..n]).is_err());
    }
    let mut extra = encoded.clone();
    extra.push(0);
    assert!(Bundle::decode(&extra).is_err());
    let mut version = encoded.clone();
    version[1] = 2;
    assert!(Bundle::decode(&version).is_err());
    let mut wrong_len = encoded.clone();
    wrong_len[5] -= 1;
    assert!(Bundle::decode(&wrong_len).is_err());
    for slot in 0..3 {
        let mut objects = [r.clone(), d.clone(), s.clone()];
        objects[slot].pop();
        assert!(home_objects::encode(&objects[0], &objects[1], &objects[2]).is_err());
    }
}

#[test]
fn store_permission_binds_account_prefix_bundle_and_deadline() {
    let root = SigningKey::generate();
    let key = SigningKey::generate();
    let cert = permit::certify(&root, key.public());
    let mut p = Permit {
        scope: Scope::StoreHomeObjects {
            log: LogId {
                kind: LogKind::Account,
                id: [1; 32],
            },
            prefix_digest: Digest([2; 32]),
            bundle_digest: Digest([3; 32]),
        },
        issued_ms: 10,
        deadline_ms: 30010,
        batch: [0; 16],
    };
    let bytes = permit::sign(&key, &cert, &p);
    assert_eq!(permit::verify(root.public(), &bytes, 11).unwrap(), p);
    assert!(permit::verify(root.public(), &bytes, 30010).is_err());
    p.deadline_ms += 1;
    assert!(permit::verify(root.public(), &permit::sign(&key, &cert, &p), 11).is_err());
    p.deadline_ms -= 1;
    if let Scope::StoreHomeObjects { log, .. } = &mut p.scope {
        log.kind = LogKind::Base;
    }
    assert!(permit::verify(root.public(), &permit::sign(&key, &cert, &p), 11).is_err());
}

#[test]
fn storage_wire_is_strict_and_does_not_carry_an_append_position() {
    let bundle = home_objects::encode(&[1; 242], &[2; 1299], &[3; 1299]).unwrap();
    let request = Request::StoreHomeObjects {
        id: 42,
        permit: vec![4; 200],
        bundle,
    };
    let bytes = request.encode().unwrap();
    assert_eq!(Request::decode(&bytes).unwrap(), request);
    assert_eq!(request.encoded_len().unwrap(), bytes.len());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Request::decode(&trailing).is_err());
    assert!(
        Request::StoreHomeObjects {
            id: 42,
            permit: vec![],
            bundle: vec![0; 3000]
        }
        .encode()
        .is_err()
    );
    let response = Response::HomeObjectsStored {
        id: 42,
        prefix_digest: Digest([5; 32]),
        bundle_digest: Digest([6; 32]),
    };
    let bytes = response.encode().unwrap();
    assert_eq!(Response::decode(&bytes).unwrap(), response);
    assert_eq!(bytes.len(), 71);
    let mut trailing = bytes;
    trailing.push(0);
    assert!(Response::decode(&trailing).is_err());
}
