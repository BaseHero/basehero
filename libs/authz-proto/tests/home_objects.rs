use bh_account::Head;
use bh_authz_proto::{FromService, ToService};

#[test]
fn private_objects_and_durable_answer_have_bounded_redacted_encodings() {
    let prefix = Head {
        position: 3,
        hash: [7; 32],
    };
    let request = ToService::StoreHomeObjects {
        prefix,
        record: vec![1; 242],
        device_seal: vec![2; 1299],
        recovery_seal: vec![3; 1299],
    };
    assert_eq!(format!("{request:?}"), "StoreHomeObjects");
    let bytes = request.encode().unwrap();
    assert_eq!(ToService::decode(&bytes).unwrap(), request);
    for n in 0..bytes.len() {
        assert!(ToService::decode(&bytes[..n]).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(ToService::decode(&trailing).is_err());
    assert!(
        ToService::StoreHomeObjects {
            prefix,
            record: vec![],
            device_seal: vec![0; 1299],
            recovery_seal: vec![0; 1299]
        }
        .encode()
        .is_err()
    );
    let answer = FromService::HomeObjectsStored {
        prefix,
        digest: [8; 32],
    };
    assert_eq!(format!("{answer:?}"), "HomeObjectsStored");
    let bytes = answer.encode().unwrap();
    assert_eq!(FromService::decode(&bytes).unwrap(), answer);
    assert!(FromService::decode(&bytes[..bytes.len() - 1]).is_err());
}
