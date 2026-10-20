use bh_crypto::{Secret, SigningKey};
use bh_sync::{
    permit::{self, LogId, LogKind, Permit, Scope},
    wire::{self, Request, Response},
};

#[test]
fn presence_permit_has_signed_scope_tag_eight_and_exact_bytes() {
    let root = SigningKey::from_seed(&Secret::from_slice(&[1; 32]).unwrap());
    let signer = SigningKey::from_seed(&Secret::from_slice(&[2; 32]).unwrap());
    let permit = Permit {
        scope: Scope::Presence {
            log: LogId {
                kind: LogKind::Base,
                id: [3; 32],
            },
            epoch: [4; 32],
        },
        issued_ms: 1000,
        deadline_ms: 31_000,
        batch: [5; 16],
    };
    let signed = permit::sign(&signer, &permit::certify(&root, signer.public()), &permit);
    assert_eq!(signed.len(), 130 + 2 + 1 + 33 + 32 + 8 + 8 + 16 + 64);
    assert_eq!(
        &signed[130..198],
        &[&[0, 1, 8, 1][..], &[3; 32], &[4; 32]].concat()
    );
    assert_eq!(
        permit::verify(root.public(), &signed, 1000),
        Ok(permit.clone())
    );
    assert_eq!(format!("{:?}", permit.scope), "Presence");
    let mut extra = signed.clone();
    extra.push(0);
    assert!(permit::verify(root.public(), &extra, 1000).is_err());
    let mut wrong = signed;
    wrong[132] = 9;
    assert!(permit::verify(root.public(), &wrong, 1000).is_err());
}

#[test]
fn presence_frames_use_v2_new_tags_and_exact_layout() {
    let cases = [
        (
            Request::PresenceJoin {
                id: 7,
                permit: vec![0xca, 0xfe],
            },
            vec![0, 2, 33, 0, 0, 0, 7, 0, 0, 0, 2, 0xca, 0xfe],
            "PresenceJoin { id: 7, .. }",
        ),
        (
            Request::Presence {
                id: 7,
                sealed: vec![0xca, 0xfe],
            },
            vec![0, 2, 34, 0, 0, 0, 7, 0, 0, 0, 2, 0xca, 0xfe],
            "Presence { id: 7, .. }",
        ),
    ];
    for (request, expected, expected_debug) in cases {
        assert_eq!(request.encode().unwrap(), expected);
        assert_eq!(Request::decode(&expected), Ok(request.clone()));
        assert_eq!(request.encoded_len(), Ok(expected.len()));
        assert_eq!(format!("{request:?}"), expected_debug);
        let mut bad = expected.clone();
        bad.push(0);
        assert_eq!(Request::decode(&bad), Err(wire::Error::Encoding));
        bad = expected.clone();
        bad[1] = 1;
        assert_eq!(Request::decode(&bad), Err(wire::Error::Version));
        bad[1] = 2;
        bad[2] = 37;
        assert_eq!(Request::decode(&bad), Err(wire::Error::Version));
    }
    let cases = [
        (
            Response::Presence {
                id: 7,
                from: 0x0102_0304,
                sealed: vec![0xca, 0xfe],
            },
            vec![0, 2, 35, 0, 0, 0, 7, 1, 2, 3, 4, 0, 0, 0, 2, 0xca, 0xfe],
            "Presence { id: 7, .. }",
        ),
        (
            Response::Peers {
                id: 7,
                others: 2,
                event: 1,
                slot: 0x0102_0304,
            },
            vec![0, 2, 36, 0, 0, 0, 7, 0, 2, 1, 1, 2, 3, 4],
            "Peers { id: 7, .. }",
        ),
    ];
    for (response, expected, expected_debug) in cases {
        assert_eq!(response.encode().unwrap(), expected);
        assert_eq!(Response::decode(&expected), Ok(response.clone()));
        assert_eq!(response.encoded_len(), Ok(expected.len()));
        assert_eq!(format!("{response:?}"), expected_debug);
        let mut bad = expected.clone();
        bad.push(0);
        assert_eq!(Response::decode(&bad), Err(wire::Error::Encoding));
        bad = expected.clone();
        bad[1] = 1;
        assert_eq!(Response::decode(&bad), Err(wire::Error::Version));
    }
    assert_eq!(wire::MAX_PRESENCE, 512);
}

#[test]
fn presence_sealed_size_cap_is_checked_before_copying() {
    for n in [512, 513] {
        let request = Request::Presence {
            id: 3,
            sealed: vec![8; n],
        };
        let response = Response::Presence {
            id: 3,
            from: 4,
            sealed: vec![8; n],
        };
        let expected = if n == 512 {
            Ok(())
        } else {
            Err(wire::Error::Size)
        };
        assert_eq!(request.encode().map(|_| ()), expected);
        assert_eq!(response.encode().map(|_| ()), expected);
        let mut request_bytes = vec![0, 2, 34, 0, 0, 0, 3];
        request_bytes.extend((n as u32).to_be_bytes());
        request_bytes.extend(vec![8; n]);
        let mut response_bytes = vec![0, 2, 35, 0, 0, 0, 3, 0, 0, 0, 4];
        response_bytes.extend((n as u32).to_be_bytes());
        response_bytes.extend(vec![8; n]);
        assert_eq!(Request::decode(&request_bytes).map(|_| ()), expected);
        assert_eq!(Response::decode(&response_bytes).map(|_| ()), expected);
    }
    let mut invalid = vec![0, 2, 34, 0, 0, 0, 3];
    invalid.extend(513_u32.to_be_bytes());
    assert_eq!(Request::decode(&invalid), Err(wire::Error::Size));
    for event in [3, 255] {
        let mut invalid = Response::Peers {
            id: 1,
            others: 0,
            event: 0,
            slot: 0,
        }
        .encode()
        .unwrap();
        invalid[9] = event;
        assert_eq!(Response::decode(&invalid), Err(wire::Error::Encoding));
        assert_eq!(
            Response::Peers {
                id: 1,
                others: 0,
                event,
                slot: 0
            }
            .encode(),
            Err(wire::Error::Encoding)
        );
    }
}
