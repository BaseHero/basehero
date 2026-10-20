use bh_account::{
    AccountId, DeviceId, DevicePublicKeys, Head as AccountHead, device_auth::PROOF_LEN,
};
use bh_authz_proto::{
    Delivery, Error, FromService, LogId, LogKind, MAX_BODIES, MAX_MESSAGE, MetadataKey, Refusal,
    ToService, Want, WrapError, account_log_id, account_log_unwrap, account_log_wrap,
    delivery_body, delivery_frame,
};
use bh_crypto::Secret;
use bh_sync::{BODY_SIZES, BaseId, BodyObject, Digest, ENVELOPE_SIZES, EventId, OpaqueEvent};

fn base(n: u8) -> LogId {
    LogId {
        kind: LogKind::Base,
        id: [n; 32],
    }
}
fn account_log(n: u8) -> LogId {
    LogId {
        kind: LogKind::Account,
        id: [n; 32],
    }
}
fn keys(n: u8) -> DevicePublicKeys {
    DevicePublicKeys::new([n; 32], [n + 1; 32], [n + 2; 1216]).unwrap()
}
fn register(descriptor: usize, body: usize) -> ToService {
    ToService::RegisterBase {
        descriptor: vec![3; descriptor],
        body: vec![4; body],
        creator_head: AccountHead {
            position: 2,
            hash: [5; 32],
        },
        metadata: MetadataKey::new(&Secret::from_slice(&[0x6d; 32]).unwrap()),
    }
}
fn to_round_trip(message: ToService) {
    let bytes = message.encode().unwrap();
    assert!(bytes.len() <= MAX_MESSAGE);
    assert!(ToService::decode(&bytes).unwrap() == message);
    for cut in 0..bytes.len() {
        assert!(
            ToService::decode(&bytes[..cut]).is_err(),
            "truncated at {cut}"
        );
    }
    assert_eq!(
        ToService::decode(&[bytes.as_slice(), &[0]].concat()).err(),
        Some(Error::Encoding)
    );
}
fn from_round_trip(message: FromService) {
    let bytes = message.encode().unwrap();
    assert!(FromService::decode(&bytes).unwrap() == message);
    for cut in 0..bytes.len() {
        assert!(
            FromService::decode(&bytes[..cut]).is_err(),
            "truncated at {cut}"
        );
    }
    assert_eq!(
        FromService::decode(&[bytes.as_slice(), &[0]].concat()).err(),
        Some(Error::Encoding)
    );
}

#[test]
fn every_message_round_trips_strictly() {
    to_round_trip(ToService::Authenticate {
        proof: Box::new([7; PROOF_LEN]),
        account: AccountId([1; 32]),
        device: DeviceId([2; 32]),
        genesis: vec![3; 2600],
    });
    to_round_trip(ToService::Permits {
        items: vec![
            Want::ReadEvents {
                log: base(1),
                first: 1,
                last: 64,
            },
            Want::ReadBodies {
                log: base(1),
                bodies: vec![Digest([4; 32]), Digest([5; 32])],
            },
            Want::Stage {
                log: base(1),
                body: Digest([6; 32]),
                len: 4096,
            },
            Want::Append {
                log: base(1),
                event: vec![8; 1062],
                epoch: [9; 32],
            },
            Want::Subscribe {
                log: account_log(2),
            },
        ],
    });
    to_round_trip(ToService::SubmitControl {
        log: account_log(2),
        event: vec![1; 300],
        delivery: None,
    });
    to_round_trip(ToService::SubmitControl {
        log: account_log(2),
        event: vec![1; 300],
        delivery: Some(Box::new(Delivery {
            recipient: keys(3),
            frame: vec![2; 1403],
        })),
    });
    to_round_trip(register(1062, 1024));
    from_round_trip(FromService::Challenge { challenge: [5; 32] });
    from_round_trip(FromService::Authenticated {
        account_head: AccountHead {
            position: 3,
            hash: [6; 32],
        },
    });
    from_round_trip(FromService::Permits {
        items: vec![Ok(vec![7; 400]), Err(Refusal::Epoch), Ok(vec![8; 278])],
    });
    from_round_trip(FromService::Refused {
        reason: Refusal::NotActive,
    });
    from_round_trip(FromService::Unavailable);
}

#[test]
fn requests_are_bounded_to_one_channel_record() {
    let read = |n: usize| Want::ReadBodies {
        log: base(1),
        bodies: vec![Digest([1; 32]); n],
    };
    // 1-64 items, each read 1-64 positions or bodies, and at most MAX_BODIES
    // bodies in one request, so the largest answer also fits one record.
    for items in [vec![], vec![read(1); 65]] {
        let bytes = encode_unchecked(&ToService::Permits { items });
        assert_eq!(ToService::decode(&bytes).err(), Some(Error::Size));
    }
    assert!(
        ToService::Permits {
            items: vec![read(65)]
        }
        .encode()
        .is_err()
    );
    let full = ToService::Permits {
        items: vec![read(64); MAX_BODIES / 64],
    };
    let bytes = full.encode().unwrap();
    assert!(ToService::decode(&bytes).unwrap() == full);
    let over = ToService::Permits {
        items: vec![read(64); MAX_BODIES / 64 + 1],
    };
    assert_eq!(over.encode().err(), Some(Error::Size));
    for (first, last) in [(0, 1), (2, 1), (1, 65)] {
        let message = ToService::Permits {
            items: vec![Want::ReadEvents {
                log: base(1),
                first,
                last,
            }],
        };
        assert_eq!(message.encode().err(), Some(Error::Size), "{first}..{last}");
    }
    assert_eq!(
        register(MAX_MESSAGE, 1024).encode().err(),
        Some(Error::Size)
    );
    // The worst-case answer to the largest request still fits one record.
    let answer = FromService::Permits {
        items: (0..64)
            .map(|i| Ok(vec![0; if i < 16 { 264 + 32 * 64 } else { 400 }]))
            .collect(),
    };
    assert!(answer.encode().unwrap().len() <= MAX_MESSAGE);
}

// The encoder refuses out-of-bounds requests, so build one by hand: version,
// Permits tag, count, then each ReadBodies item.
fn encode_unchecked(message: &ToService) -> Vec<u8> {
    let ToService::Permits { items } = message else {
        unreachable!()
    };
    let mut out = vec![0, 1, 2];
    out.extend((items.len() as u16).to_be_bytes());
    for item in items {
        let Want::ReadBodies { log, bodies } = item else {
            unreachable!()
        };
        out.push(2);
        out.push(log.kind as u8);
        out.extend(log.id);
        out.extend((bodies.len() as u16).to_be_bytes());
        for body in bodies {
            out.extend(body.0);
        }
    }
    out
}

#[test]
fn unknown_tags_and_versions_are_refused() {
    let bytes = FromService::Unavailable.encode().unwrap();
    assert_eq!(
        FromService::decode(&[&[0, 2], &bytes[2..]].concat()).err(),
        Some(Error::Version)
    );
    assert_eq!(
        FromService::decode(&[0, 1, 99]).err(),
        Some(Error::Encoding)
    );
    assert_eq!(ToService::decode(&[0, 1, 99]).err(), Some(Error::Encoding));
    // Recipient keys that are no device's keys (signing equal to control).
    let mut bad = ToService::SubmitControl {
        log: account_log(2),
        event: vec![1; 3],
        delivery: Some(Box::new(Delivery {
            recipient: keys(3),
            frame: vec![2; 3],
        })),
    }
    .encode()
    .unwrap();
    let at = 3 + 33 + 4 + 3 + 1;
    bad[at + 32..at + 64].copy_from_slice(&[3; 32]);
    assert_eq!(ToService::decode(&bad).err(), Some(Error::Encoding));
    let refused = FromService::Refused {
        reason: Refusal::Invalid,
    }
    .encode()
    .unwrap();
    let mut bad = refused.clone();
    *bad.last_mut().unwrap() = 0;
    assert_eq!(FromService::decode(&bad).err(), Some(Error::Encoding));
}

#[test]
fn debug_shows_no_identities_or_bytes() {
    let message = ToService::Authenticate {
        proof: Box::new([0xab; PROOF_LEN]),
        account: AccountId([0xcd; 32]),
        device: DeviceId([0xef; 32]),
        genesis: vec![0x12; 10],
    };
    let text = format!("{message:?}");
    assert!(!text.contains("171") && !text.contains("ab") && !text.contains("cd"));
    assert_eq!(text, "Authenticate");
    // The metadata key never appears in diagnostics.
    let message = register(1062, 1024);
    let text = format!("{message:?}");
    assert_eq!(text, "RegisterBase");
    let ToService::RegisterBase { metadata, .. } = &message else {
        unreachable!()
    };
    assert_eq!(format!("{metadata:?}"), "MetadataKey(..)");
}

#[test]
fn account_log_events_wrap_into_the_smallest_envelope() {
    let original = vec![0x42; 2600];
    let event = account_log_wrap(&original, None).unwrap();
    assert_eq!(event.envelope().len(), 4096);
    assert_eq!(&event.envelope()[..32], &[0; 32]);
    assert_eq!(&event.envelope()[32..36], &2600u32.to_be_bytes());
    assert_eq!(&event.envelope()[36..2636], original.as_slice());
    assert!(event.envelope()[2636..].iter().all(|b| *b == 0));
    let id = bh_crypto::hash(
        &[
            b"bh/account-log-event/v2\0".as_slice(),
            &[0; 32],
            &2600u32.to_be_bytes(),
            &original,
        ]
        .concat(),
    );
    assert_eq!(event.id(), EventId(id));
    assert!(account_log_unwrap(&event).unwrap() == (original.as_slice(), None));
    // The log object's body reference reads the wrapper's first 32 bytes.
    assert_eq!(bh_sync::referenced_body(&event).unwrap(), Digest([0; 32]));
    // Deterministic: the same original always gives the same event.
    assert!(account_log_wrap(&original, None).unwrap() == event);
    assert_eq!(
        account_log_wrap(&[1; 1024 - 36], None)
            .unwrap()
            .envelope()
            .len(),
        ENVELOPE_SIZES[0]
    );
    assert_eq!(
        account_log_wrap(&[1; 1024 - 35], None)
            .unwrap()
            .envelope()
            .len(),
        ENVELOPE_SIZES[1]
    );
    let largest = *ENVELOPE_SIZES.last().unwrap();
    assert_eq!(
        account_log_wrap(&vec![1; largest - 35], None).err(),
        Some(WrapError::Size)
    );
    assert_eq!(account_log_wrap(&[], None).err(), Some(WrapError::Size));
    // An all-zero commitment would read as no body.
    assert_eq!(
        account_log_wrap(&original, Some(Digest([0; 32]))).err(),
        Some(WrapError::Encoding)
    );
}

#[test]
fn a_wrapped_body_commitment_is_bound_into_the_event_id() {
    let original = vec![0x42; 300];
    let body = Digest([7; 32]);
    let with = account_log_wrap(&original, Some(body)).unwrap();
    let without = account_log_wrap(&original, None).unwrap();
    assert_eq!(&with.envelope()[..32], &[7; 32]);
    assert_eq!(bh_sync::referenced_body(&with).unwrap(), body);
    assert!(account_log_unwrap(&with).unwrap() == (original.as_slice(), Some(body)));
    // The same original with another body, or none, is another event.
    assert_ne!(with.id(), without.id());
    let other = account_log_wrap(&original, Some(Digest([8; 32]))).unwrap();
    assert_ne!(with.id(), other.id());
    // Swapping the commitment under the original's id is refused.
    let mut swapped = with.envelope().to_vec();
    swapped[..32].copy_from_slice(&[8; 32]);
    let swapped = OpaqueEvent::new(with.id(), swapped).unwrap();
    assert_eq!(
        account_log_unwrap(&swapped).err(),
        Some(WrapError::Encoding)
    );
}

#[test]
fn account_log_unwrap_is_strict() {
    let original = vec![0x42; 100];
    let good = account_log_wrap(&original, None).unwrap();
    let rebuild = |id: EventId, envelope: Vec<u8>| OpaqueEvent::new(id, envelope).unwrap();
    // Nonzero padding, a length past the envelope, a non-minimal size class
    // and another event id are each refused.
    let mut padded = good.envelope().to_vec();
    padded[200] = 1;
    let mut long = good.envelope().to_vec();
    long[32..36].copy_from_slice(&2000u32.to_be_bytes());
    let mut roomy = vec![0; 4096];
    roomy[..136].copy_from_slice(&good.envelope()[..136]);
    for event in [
        rebuild(good.id(), padded),
        rebuild(good.id(), long),
        rebuild(good.id(), roomy),
        rebuild(EventId([0; 32]), good.envelope().to_vec()),
    ] {
        assert_eq!(account_log_unwrap(&event).err(), Some(WrapError::Encoding));
    }
}

#[test]
fn account_log_id_is_the_wrapped_genesis_digest() {
    let genesis = vec![0x55; 2600];
    let wrapped = account_log_wrap(&genesis, None).unwrap();
    assert_eq!(
        account_log_id(&genesis).unwrap(),
        BaseId::from_genesis(&wrapped).0
    );
    assert_ne!(
        account_log_id(&genesis).unwrap(),
        bh_crypto::hash(&genesis),
        "the log id is not the account id"
    );
}

#[test]
fn a_delivery_body_is_its_exact_frame_padded() {
    let frame = vec![0x5a; 1403];
    let body = delivery_body(&frame).unwrap();
    assert_eq!(body.bytes().len(), 4096);
    assert_eq!(body.bytes()[0], 1, "personal-key delivery");
    assert_eq!(&body.bytes()[1..5], &1403u32.to_be_bytes());
    assert_eq!(&body.bytes()[5..1408], frame.as_slice());
    assert!(body.bytes()[1408..].iter().all(|b| *b == 0));
    assert_eq!(delivery_frame(body.bytes()).unwrap(), frame.as_slice());
    assert!(delivery_body(&frame).unwrap() == body, "stable on retry");
    // Delivery bodies use the larger body classes; account event envelopes do not.
    let large = vec![0x5a; 65536];
    let padded_large = delivery_body(&large).unwrap();
    assert_eq!(padded_large.bytes().len(), 262144);
    assert_eq!(delivery_frame(padded_large.bytes()).unwrap(), large);
    assert_eq!(
        delivery_body(&[1; 1019]).unwrap().bytes().len(),
        BODY_SIZES[0]
    );
    assert_eq!(delivery_body(&[]).err(), Some(WrapError::Size));
    // Nonzero padding, a wrong length, another purpose or a non-minimal size
    // class are each refused.
    let mut padded = body.bytes().to_vec();
    padded[2000] = 1;
    let mut long = body.bytes().to_vec();
    long[1..5].copy_from_slice(&5000u32.to_be_bytes());
    // A length taking in a padding zero names another frame, one byte longer,
    // which is another body object with another commitment.
    let mut zero = body.bytes().to_vec();
    zero[1..5].copy_from_slice(&1404u32.to_be_bytes());
    assert_eq!(
        delivery_frame(&zero).unwrap(),
        [frame.as_slice(), &[0]].concat()
    );
    assert_ne!(
        BodyObject::new(zero).unwrap().commitment(),
        body.commitment()
    );
    let mut short = body.bytes().to_vec();
    short[1..5].copy_from_slice(&1402u32.to_be_bytes());
    let mut purpose = body.bytes().to_vec();
    purpose[0] = 2;
    let small = delivery_body(&[1; 10]).unwrap();
    let mut roomy = vec![0; 4096];
    roomy[..15].copy_from_slice(&small.bytes()[..15]);
    for bytes in [padded, long, short, purpose, roomy, vec![0; 1000]] {
        assert_eq!(delivery_frame(&bytes).err(), Some(WrapError::Encoding));
    }
    // It is an ordinary body object.
    assert!(BodyObject::new(body.bytes().to_vec()).unwrap() == body);
}

fn base_control(descriptor: usize, body: usize) -> ToService {
    ToService::SubmitBaseControl {
        log: base(7),
        descriptor: vec![3; descriptor],
        body: vec![4; body],
        metadata: MetadataKey::new(&Secret::from_slice(&[0x6d; 32]).unwrap()),
    }
}

#[test]
fn base_control_and_new_refusals_round_trip_strictly() {
    to_round_trip(base_control(1062, 1024));
    // version || tag 5 || log || descriptor || body || M
    let bytes = base_control(5, 6).encode().unwrap();
    let mut expected = vec![0, 1, 5, 1];
    expected.extend([7; 32]);
    expected.extend(5u32.to_be_bytes());
    expected.extend([3; 5]);
    expected.extend(6u32.to_be_bytes());
    expected.extend([4; 6]);
    expected.extend([0x6d; 32]);
    assert_eq!(bytes, expected);
    assert_eq!(
        base_control(MAX_MESSAGE, 1024).encode().err(),
        Some(Error::Size)
    );
    let mut unknown_log = bytes.clone();
    unknown_log[3] = 3;
    assert_eq!(ToService::decode(&unknown_log).err(), Some(Error::Encoding));
    // The metadata key never appears in diagnostics.
    let message = base_control(1062, 1024);
    assert_eq!(format!("{message:?}"), "SubmitBaseControl");
    let ToService::SubmitBaseControl { metadata, .. } = &message else {
        unreachable!()
    };
    assert_eq!(format!("{metadata:?}"), "MetadataKey(..)");

    for (reason, code) in [(Refusal::AccountChangePending, 9), (Refusal::Resync, 10)] {
        from_round_trip(FromService::Refused { reason });
        from_round_trip(FromService::Permits {
            items: vec![Ok(vec![7; 400]), Err(reason)],
        });
        let bytes = FromService::Refused { reason }.encode().unwrap();
        assert_eq!(bytes, [0, 1, 4, code]);
    }
    assert_eq!(
        FromService::decode(&[0, 1, 4, 11]).err(),
        Some(Error::Encoding)
    );
}
