use bh_authz_proto::{Error, LogId, LogKind, ToService, Want};
use bh_sync::Head;

#[test]
fn presence_want_has_exact_legacy_encoding_and_strict_bounds() {
    let log = LogId {
        kind: LogKind::Base,
        id: [0x41; 32],
    };
    let want = Want::Presence {
        log,
        epoch: [0x72; 32],
    };
    let message = ToService::Permits {
        items: vec![want.clone()],
    };
    let mut expected = vec![0, 1, 2, 0, 1, 6, 1];
    expected.extend([0x41; 32]);
    expected.extend([0x72; 32]);
    assert_eq!(expected.len(), 71);
    assert_eq!(message.encode().unwrap(), expected);
    assert_eq!(ToService::decode(&expected), Ok(message));
    assert_eq!(format!("{want:?}"), "Presence");
    for cut in 0..expected.len() {
        assert!(ToService::decode(&expected[..cut]).is_err(), "cut {cut}");
    }
    let mut trailing = expected.clone();
    trailing.push(0);
    assert_eq!(ToService::decode(&trailing), Err(Error::Encoding));
    let mut bad_kind = expected.clone();
    bad_kind[6] = 3;
    assert_eq!(ToService::decode(&bad_kind), Err(Error::Encoding));
    let mut wrong_version = expected.clone();
    wrong_version[1] = 2;
    assert_eq!(ToService::decode(&wrong_version), Err(Error::Version));
    let oversized = ToService::Permits {
        items: vec![want; 65],
    };
    assert_eq!(oversized.encode(), Err(Error::Size));
}

#[test]
fn presence_want_is_not_a_read_batch_request() {
    let want = Want::Presence {
        log: LogId {
            kind: LogKind::Base,
            id: [0x41; 32],
        },
        epoch: [0x72; 32],
    };
    assert_eq!(ToService::ReadBatch { want }.encode(), Err(Error::Encoding));
    let mut v2 = vec![0, 2, 33, 6, 1];
    v2.extend([0x41; 32]);
    v2.extend([0x72; 32]);
    assert_eq!(ToService::decode(&v2), Err(Error::Encoding));
    let legacy = ToService::ReadBatch {
        want: Want::ReadBatch {
            log: LogId {
                kind: LogKind::Base,
                id: [0x41; 32],
            },
            after: Head::EMPTY,
            max_events: 1,
        },
    }
    .encode()
    .unwrap();
    assert_eq!(legacy[0..4], [0, 2, 33, 7]);
}
