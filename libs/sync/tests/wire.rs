use bh_sync::wire::{self, Refusal, Request, Response};
use bh_sync::{Digest, Head};

#[test]
fn wire_roundtrip_each_variant() {
    let requests = [
        Request::Read {
            id: 1,
            permit: vec![1, 2],
        },
        Request::Stage {
            id: 2,
            permit: vec![3],
            body: vec![4, 5],
        },
        Request::Append {
            id: 3,
            permit: vec![6],
            event: vec![7, 8],
        },
        Request::Subscribe {
            id: 4,
            permit: vec![9],
            after: 0x0102_0304_0506_0708,
        },
        Request::Credit { bytes: 1 },
        Request::Credit { bytes: u32::MAX },
    ];
    for request in requests {
        assert_eq!(Request::decode(&request.encode().unwrap()), Ok(request));
    }
    let head = Head {
        position: 9,
        hash: Digest([10; 32]),
    };
    let responses = [
        Response::Events {
            id: 1,
            items: vec![(vec![1; 178], vec![2; 1062])],
            receipt: None,
        },
        Response::Body {
            id: 2,
            index: 0,
            last: true,
            bytes: vec![3; 1024],
        },
        Response::Body {
            id: 2,
            index: 1,
            last: false,
            bytes: vec![4; 4096],
        },
        Response::Staged { id: 3 },
        Response::Acked {
            id: 4,
            ack: vec![5; 408],
        },
        Response::Head {
            id: 5,
            head,
            receipt: Some(vec![6; 300]),
        },
        Response::Head {
            id: 6,
            head,
            receipt: None,
        },
    ];
    for response in responses {
        assert_eq!(Response::decode(&response.encode().unwrap()), Ok(response));
    }
    for reason in [
        Refusal::Expired,
        Refusal::Scope,
        Refusal::Epoch,
        Refusal::Predecessor,
        Refusal::Conflict,
        Refusal::NotStaged,
        Refusal::Reclaiming,
        Refusal::Missing,
        Refusal::Malformed,
        Refusal::Unavailable,
    ] {
        let response = Response::Refused { id: 17, reason };
        assert_eq!(Response::decode(&response.encode().unwrap()), Ok(response));
    }
}

#[test]
fn legacy_stage_append_and_ack_vectors_remain_version_one() {
    assert_eq!(
        Request::Stage {
            id: 1,
            permit: vec![0xaa],
            body: vec![0xbb]
        }
        .encode()
        .unwrap(),
        [0, 1, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0xaa, 0, 0, 0, 1, 0xbb]
    );
    assert_eq!(
        Request::Append {
            id: 1,
            permit: vec![0xaa],
            event: vec![0xbb]
        }
        .encode()
        .unwrap(),
        [0, 1, 3, 0, 0, 0, 1, 0, 0, 0, 1, 0xaa, 0, 0, 0, 1, 0xbb]
    );
    assert_eq!(
        Response::Staged { id: 1 }.encode().unwrap(),
        [0, 1, 3, 0, 0, 0, 1]
    );
    assert_eq!(
        Response::Acked {
            id: 1,
            ack: vec![0xab]
        }
        .encode()
        .unwrap(),
        [0, 1, 4, 0, 0, 0, 1, 0, 0, 0, 1, 0xab]
    );
}

#[test]
fn compound_frames_are_v2_tag32_only_and_bounded() {
    let publish = Request::Publish {
        id: 0x01020304,
        stage_permit: vec![0xaa],
        append_permit: vec![0xbb, 0xcc],
        event: vec![0xdd],
        body: vec![0xee, 0xff],
    };
    let frame = publish.encode().unwrap();
    assert_eq!(
        frame,
        [
            0, 2, 32, 1, 2, 3, 4, 0, 0, 0, 1, 0xaa, 0, 0, 0, 2, 0xbb, 0xcc, 0, 0, 0, 1, 0xdd, 0, 0,
            0, 2, 0xee, 0xff
        ]
    );
    assert_eq!(Request::decode(&frame), Ok(publish.clone()));
    let published = Response::Published {
        id: 0x01020304,
        ack: vec![0xab],
        commitment: vec![0x5a; bh_sync::Commitment::LEN],
    };
    let answer = published.encode().unwrap();
    assert_eq!(&answer[..12], &[0, 2, 32, 1, 2, 3, 4, 0, 0, 0, 1, 0xab]);
    assert_eq!(&answer[12..], &[0x5a; bh_sync::Commitment::LEN]);
    assert_eq!(Response::decode(&answer), Ok(published.clone()));
    for n in 0..frame.len() {
        assert!(Request::decode(&frame[..n]).is_err());
    }
    for n in 0..answer.len() {
        assert!(Response::decode(&answer[..n]).is_err());
    }
    for (bad_version, bad_tag) in [(1, 32), (2, 1), (2, 33)] {
        let mut invalid = frame.clone();
        invalid[1] = bad_version;
        invalid[2] = bad_tag;
        assert!(Request::decode(&invalid).is_err());
        let mut invalid = answer.clone();
        invalid[1] = bad_version;
        invalid[2] = bad_tag;
        assert!(Response::decode(&invalid).is_err());
    }
    let mut trailing = frame.clone();
    trailing.push(0);
    assert_eq!(Request::decode(&trailing), Err(wire::Error::Encoding));
    let mut trailing = answer.clone();
    trailing.push(0);
    assert_eq!(Response::decode(&trailing), Err(wire::Error::Encoding));
    assert_eq!(
        Request::Publish {
            id: 1,
            stage_permit: vec![],
            append_permit: vec![],
            event: vec![],
            body: vec![0; wire::MAX_FRAME_LEN]
        }
        .encode(),
        Err(wire::Error::Size)
    );
    assert_eq!(
        Response::Published {
            commitment: vec![0; bh_sync::Commitment::LEN - 1],
            id: 1,
            ack: vec![]
        }
        .encode(),
        Err(wire::Error::Encoding)
    );
    assert!(!format!("{published:?}").contains("5a"));
}

#[test]
fn events_require_a_strict_fixed_width_receipt_option() {
    // Empty Events: header, count, mandatory option flag. Old framing must
    // not be silently accepted as the new transport response.
    let old = vec![0, 1, 1, 0, 0, 0, 7, 0, 0];
    assert_eq!(Response::decode(&old), Err(wire::Error::Encoding));
    let mut none = old.clone();
    none.push(0);
    assert_eq!(Response::decode(&none).unwrap().encode().unwrap(), none);
    let mut present = old.clone();
    present.push(1);
    present.extend([0x5a; 300]);
    assert_eq!(
        Response::decode(&present).unwrap().encode().unwrap(),
        present
    );
    for n in 0..present.len() {
        assert_eq!(Response::decode(&present[..n]), Err(wire::Error::Encoding));
    }
    for flag in [2, 255] {
        let mut bad = none.clone();
        bad[9] = flag;
        assert_eq!(Response::decode(&bad), Err(wire::Error::Encoding));
    }
    for mut frame in [none, present] {
        frame.push(0);
        assert_eq!(Response::decode(&frame), Err(wire::Error::Encoding));
    }
}

#[test]
fn credit_frame_has_request_id_zero_and_a_positive_grant() {
    let frame = Request::Credit { bytes: 0x0102_0304 }.encode().unwrap();
    assert_eq!(frame, [0, 1, 5, 0, 0, 0, 0, 1, 2, 3, 4]);
    assert_eq!(Request::Credit { bytes: 9 }.encoded_len(), Ok(11));
    assert_eq!(
        Request::Credit { bytes: 0 }.encode(),
        Err(wire::Error::Encoding)
    );
    assert_eq!(
        Request::Credit { bytes: 0 }.encoded_len(),
        Err(wire::Error::Encoding)
    );
    let mut zero = frame.clone();
    zero[7..].fill(0);
    assert_eq!(Request::decode(&zero), Err(wire::Error::Encoding));
    let mut with_id = frame.clone();
    with_id[6] = 1;
    assert_eq!(Request::decode(&with_id), Err(wire::Error::Encoding));
    for n in 0..frame.len() {
        assert_eq!(Request::decode(&frame[..n]), Err(wire::Error::Encoding));
    }
    let mut extra = frame.clone();
    extra.push(0);
    assert_eq!(Request::decode(&extra), Err(wire::Error::Encoding));
    let mut version = frame.clone();
    version[1] = 2;
    assert_eq!(Request::decode(&version), Err(wire::Error::Version));
    // A credit grant is never a response.
    assert_eq!(Response::decode(&frame), Err(wire::Error::Encoding));
    assert_eq!(
        format!("{:?}", Request::Credit { bytes: 7 }),
        "Credit { bytes: 7 }"
    );
}

#[test]
fn sixty_four_maximum_envelopes_and_receipt_fit_and_count_is_bounded() {
    let descriptor = bh_sync::OpaqueEvent::new(bh_sync::EventId([1; 32]), vec![2; 65536])
        .unwrap()
        .encode();
    let mut response = Response::Events {
        id: 5,
        items: vec![(vec![0; bh_sync::Commitment::LEN], descriptor); 64],
        receipt: Some([0x5a; 300]),
    };
    let frame = response.encode().unwrap();
    assert_eq!(frame.len(), 4_209_014);
    assert!(frame.len() <= wire::MAX_FRAME_LEN);
    assert_eq!(Response::decode(&frame), Ok(response.clone()));
    if let Response::Events { items, .. } = &mut response {
        items.push(items[0].clone());
    }
    assert_eq!(response.encoded_len(), Err(wire::Error::Size));
    assert_eq!(response.encode(), Err(wire::Error::Size));
    let mut count = frame;
    count[8] = 65;
    assert_eq!(Response::decode(&count), Err(wire::Error::Size));
}

#[test]
fn maximum_size_body_frame_roundtrips() {
    let response = Response::Body {
        id: 39,
        index: 63,
        last: true,
        bytes: vec![0x5a; 4 * 1024 * 1024],
    };
    let frame = response.encode().unwrap();
    assert_eq!(frame.len(), 7 + 1 + 1 + 4 + 4 * 1024 * 1024);
    assert_eq!(&frame[..13], &[0, 1, 2, 0, 0, 0, 39, 63, 1, 0, 64, 0, 0]);
    assert_eq!(Response::decode(&frame), Ok(response));
    let mut invalid = frame;
    invalid[7] = 64;
    assert_eq!(Response::decode(&invalid), Err(wire::Error::Encoding));
    invalid[7] = 0;
    invalid[8] = 2;
    assert_eq!(Response::decode(&invalid), Err(wire::Error::Encoding));
}

#[test]
fn oversize_encode_preflight_refuses_payload() {
    let huge = vec![0x5a; wire::MAX_FRAME_LEN];
    let request = Request::Stage {
        id: 1,
        permit: vec![1],
        body: huge.clone(),
    };
    let body = Response::Body {
        id: 1,
        index: 0,
        last: true,
        bytes: huge.clone(),
    };
    let events = Response::Events {
        id: 1,
        items: vec![(vec![0; 178], huge)],
        receipt: Some([0x5a; 300]),
    };
    for result in [
        request.encoded_len(),
        body.encoded_len(),
        events.encoded_len(),
    ] {
        assert_eq!(result, Err(wire::Error::Size));
    }
    assert_eq!(request.encode(), Err(wire::Error::Size));
    assert_eq!(body.encode(), Err(wire::Error::Size));
    assert_eq!(events.encode(), Err(wire::Error::Size));
}

#[test]
fn wire_debug_hides_frame_bytes() {
    let request = Request::Stage {
        id: 7,
        permit: vec![21, 22, 23],
        body: vec![31, 32, 33],
    };
    let response = Response::Body {
        id: 8,
        index: 0,
        last: true,
        bytes: vec![41, 42, 43],
    };
    for output in [format!("{request:?}"), format!("{response:?}")] {
        assert!(!output.contains("21, 22, 23"));
        assert!(!output.contains("31, 32, 33"));
        assert!(!output.contains("41, 42, 43"));
    }
}

#[test]
fn wire_rejects_trailing_and_oversize() {
    let request = Request::Read {
        id: 1,
        permit: vec![2],
    };
    let bytes = request.encode().unwrap();
    for n in 0..bytes.len() {
        assert_eq!(Request::decode(&bytes[..n]), Err(wire::Error::Encoding));
    }
    let mut extra = bytes;
    extra.push(0);
    assert_eq!(Request::decode(&extra), Err(wire::Error::Encoding));
    let response = Response::Staged { id: 1 };
    let mut extra = response.encode().unwrap();
    extra.push(0);
    assert_eq!(Response::decode(&extra), Err(wire::Error::Encoding));
    assert_eq!(
        Request::decode(&vec![0; wire::MAX_FRAME_LEN + 1]),
        Err(wire::Error::Size)
    );
    assert_eq!(
        Response::decode(&vec![0; wire::MAX_FRAME_LEN + 1]),
        Err(wire::Error::Size)
    );
    assert_eq!(
        Request::Stage {
            id: 1,
            permit: vec![1],
            body: vec![0; wire::MAX_FRAME_LEN]
        }
        .encode(),
        Err(wire::Error::Size)
    );
    assert_eq!(
        Response::Body {
            id: 1,
            index: 0,
            last: true,
            bytes: vec![0; wire::MAX_FRAME_LEN]
        }
        .encode(),
        Err(wire::Error::Size)
    );
}
