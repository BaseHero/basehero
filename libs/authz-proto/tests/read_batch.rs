use bh_authz_proto::{
    Error, FromService, LogId, LogKind, MAX_MESSAGE, ReadBatchResult, ToService, Want,
};
use bh_sync::{BaseId, Commitment, Digest, EventId, Head, OpaqueEvent, Route};

// A v2 read-batch frame must be accepted as a read rather than treated as an
// unknown legacy request. The log is a Base and the cursor is canonical empty.
#[test]
fn v2_read_batch_is_a_separate_request() {
    let mut bytes = vec![0, 2, 33, 7, 1];
    bytes.extend([9; 32]);
    bytes.extend([0; 40]);
    bytes.extend(48u16.to_be_bytes());
    assert!(ToService::decode(&bytes).is_ok(), "v2 read request refused");
    assert_eq!(ToService::decode(&[0, 1, 2, 0, 1, 7]), Err(Error::Encoding));
}

#[test]
fn bounded_reply_is_encoded_or_rejected_without_truncating_a_tail() {
    let event = OpaqueEvent::new(EventId([2; 32]), vec![3; 1024]).unwrap();
    let log = LogId {
        kind: LogKind::Base,
        id: BaseId::from_genesis(&event).0,
    };
    let commitment = Commitment::order(
        BaseId(log.id),
        bh_sync::OrderState::EMPTY,
        &event,
        Route::Control,
    )
    .unwrap();
    let pair = (commitment.encode(), event.encode());
    let reply = |n| FromService::ReadBatch {
        log,
        after: Head::EMPTY,
        issued_ms: 1000,
        deadline_ms: 31_000,
        result: ReadBatchResult::Selected {
            items: vec![pair.clone(); n],
            receipt: Some([5; 300]),
            body_permit: Some(vec![6; 264 + 32 * n]),
            possibly_more: true,
        },
    };
    let small = reply(48).encode().unwrap();
    assert!(
        small.len() < MAX_MESSAGE,
        "actual encoding: {}",
        small.len()
    );
    assert_eq!(FromService::decode(&small).unwrap(), reply(48));
    assert_eq!(reply(64).encode(), Err(Error::Size));
}

#[test]
fn cursor_bounds_and_legacy_permits_cannot_admit_read_batch() {
    let log = LogId {
        kind: LogKind::Account,
        id: [8; 32],
    };
    let want = |after, max_events| Want::ReadBatch {
        log,
        after,
        max_events,
    };
    let valid = want(Head::EMPTY, 48);
    let encoded = ToService::ReadBatch {
        want: valid.clone(),
    }
    .encode()
    .unwrap();
    assert_eq!(encoded.len(), 79);
    assert_eq!(
        ToService::decode(&encoded).unwrap(),
        ToService::ReadBatch {
            want: valid.clone()
        }
    );
    assert_eq!(
        ToService::Permits { items: vec![valid] }.encode(),
        Err(Error::Encoding)
    );
    for count in [0, 65] {
        assert_eq!(
            ToService::ReadBatch {
                want: want(Head::EMPTY, count)
            }
            .encode(),
            Err(Error::Size)
        );
    }
    assert_eq!(
        ToService::ReadBatch {
            want: want(
                Head {
                    position: 0,
                    hash: Digest([1; 32])
                },
                1
            )
        }
        .encode(),
        Err(Error::Size)
    );
    assert_eq!(
        ToService::ReadBatch {
            want: want(
                Head {
                    position: (1 << 53) - 1,
                    hash: Digest([1; 32])
                },
                1
            )
        }
        .encode(),
        Err(Error::Size)
    );
    let mut wrong_tag = encoded.clone();
    wrong_tag[3] = 6;
    assert_eq!(ToService::decode(&wrong_tag), Err(Error::Encoding));
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(ToService::decode(&trailing), Err(Error::Encoding));
    let mut old = encoded;
    old[1] = 1;
    assert_eq!(ToService::decode(&old), Err(Error::Encoding));
    assert_eq!(ToService::decode(&[0, 2, 32]), Err(Error::Version));
}

#[test]
fn reply_rejects_noncanonical_flags_unknown_result_and_oversize() {
    let log = LogId {
        kind: LogKind::Account,
        id: [9; 32],
    };
    let reply = FromService::ReadBatch {
        log,
        after: Head::EMPTY,
        issued_ms: 10,
        deadline_ms: 30_010,
        result: ReadBatchResult::Selected {
            items: vec![],
            receipt: None,
            body_permit: None,
            possibly_more: false,
        },
    };
    let bytes = reply.encode().unwrap();
    assert_eq!(FromService::decode(&bytes).unwrap(), reply);
    assert_eq!(bytes.len(), 3 + 33 + 40 + 8 + 8 + 1 + 2 + 1 + 1 + 1);
    let mut unknown_result = bytes.clone();
    unknown_result[92] = 2;
    assert_eq!(FromService::decode(&unknown_result), Err(Error::Encoding));
    let mut noncanonical = bytes.clone();
    noncanonical[95] = 2;
    assert_eq!(FromService::decode(&noncanonical), Err(Error::Encoding));
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(FromService::decode(&trailing), Err(Error::Encoding));
    assert_eq!(
        FromService::decode(&vec![0; MAX_MESSAGE + 1]),
        Err(Error::Size)
    );
}
