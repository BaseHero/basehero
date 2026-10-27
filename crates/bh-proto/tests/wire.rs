use bh_proto::*;

#[test]
fn ids_are_lowercase_hex() {
    let id = BaseId([0xab; 16]);
    assert_eq!(
        serde_json::to_string(&id).unwrap(),
        "\"abababababababababababababababab\""
    );
    assert_eq!(
        "ABABABABABABABABABABABABABABABAB"
            .parse::<BaseId>()
            .unwrap(),
        id
    );
    assert_eq!(
        serde_json::from_str::<BaseId>("\"abababababababababababababababab\"").unwrap(),
        id
    );
    // Wire JSON must be lowercase hex; only CLI-style `FromStr` accepts uppercase.
    assert!(serde_json::from_str::<BaseId>("\"ABABABABABABABABABABABABABABABAB\"").is_err());
    assert!(serde_json::from_str::<BaseId>("\"Abababababababababababababababab\"").is_err());
    assert!("abab".parse::<BaseId>().is_err());
    assert!(
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"
            .parse::<BaseId>()
            .is_err()
    );
    assert_ne!(BaseId::random(), BaseId([0; 16]));
}

#[test]
fn bytes_are_unpadded_base64url() {
    let bytes = Bytes(vec![0xff, 0x00]);
    assert_eq!(serde_json::to_string(&bytes).unwrap(), "\"_wA\"");
    assert_eq!(serde_json::from_str::<Bytes>("\"_wA\"").unwrap(), bytes);
    assert!(serde_json::from_str::<Bytes>("\"_wA=\"").is_err());
}

#[test]
fn change_request_matches_the_protocol() {
    let r = ChangesRequest {
        changes: vec![Change {
            change_id: ChangeId([1; 16]),
            object_id: ObjectId([2; 16]),
            kind: ChangeKind::State,
            body: Bytes(vec![0xff]),
            covers: Some(7),
            keep: Some(true),
        }],
    };
    assert_eq!(
        serde_json::to_value(&r).unwrap(),
        serde_json::json!({ "changes": [{
        "changeId": "01010101010101010101010101010101", "objectId": "02020202020202020202020202020202",
        "kind": "state", "body": "_w", "covers": 7, "keep": true }] })
    );
    let empty = ChangesRequest {
        changes: vec![Change {
            change_id: ChangeId([1; 16]),
            object_id: ObjectId([2; 16]),
            kind: ChangeKind::Update,
            body: Bytes(vec![]),
            covers: None,
            keep: None,
        }],
    };
    let v = serde_json::to_value(empty).unwrap();
    assert!(v["changes"][0].get("covers").is_none());
    assert!(v["changes"][0].get("keep").is_none());
}

#[test]
fn live_change_omits_missing_body() {
    let m = LiveMessage::Change {
        seq: 9,
        object_id: ObjectId([3; 16]),
        prev_head: 4,
        kind: ChangeKind::Update,
        change_id: ChangeId([5; 16]),
        device_id: DeviceId([6; 16]),
        body: None,
    };
    let v = serde_json::to_value(&m).unwrap();
    assert_eq!(v["t"], "change");
    assert!(v.get("body").is_none());
    assert_eq!(v["prevHead"], 4);
    assert_eq!(
        serde_json::to_value(LiveMessage::Revoked).unwrap(),
        serde_json::json!({"t":"revoked"})
    );
}

#[test]
fn responses_preserve_nullable_and_optional_fields() {
    let change_id = ChangeId([1; 16]);
    let response = ChangesResponse {
        results: vec![ChangeResult {
            change_id,
            seq: None,
            prev_head: 4,
            tail: 2,
            stale: true,
        }],
        head: 7,
    };
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        serde_json::json!({"results":[{"changeId":"01010101010101010101010101010101", "seq":null, "prevHead":4, "tail":2, "stale":true}],"head":7})
    );
    let account = AccountResponse {
        devices: vec![],
        bases: vec![],
        data: None,
        account_key_envelope: Bytes(vec![1, 2]),
    };
    assert_eq!(
        serde_json::to_value(account).unwrap(),
        serde_json::json!({"devices":[],"bases":[],"data":null,"accountKeyEnvelope":"AQI"})
    );
    let fetch = FetchResponse {
        objects: vec![FetchObject {
            object_id: ObjectId([2; 16]),
            head: 0,
            state: None,
            updates: vec![],
        }],
        more: vec![],
    };
    assert_eq!(
        serde_json::to_value(fetch).unwrap()["objects"][0]["state"],
        serde_json::Value::Null
    );
}

#[test]
fn signup_and_grant_wire_fields_are_camel_case() {
    let signup = SignupRequest {
        invite: "invite".into(),
        email: "person@example.org".into(),
        account_id: AccountId([1; 16]),
        salt: Bytes(vec![0xff]),
        kdf: KdfParams {
            ops_limit: 3,
            mem_limit_kib: 65536,
        },
        login_key: Bytes(vec![2]),
        account_key_envelope: Bytes(vec![3]),
        activation_hash: Bytes(vec![4]),
        device_id: DeviceId([5; 16]),
    };
    let value = serde_json::to_value(&signup).unwrap();
    assert_eq!(
        value["kdf"],
        serde_json::json!({"opsLimit":3,"memLimitKib":65536})
    );
    assert_eq!(value["accountId"], "01010101010101010101010101010101");
    assert_eq!(value["salt"], "_w");
    assert_eq!(value["activationHash"], "BA");
    assert_eq!(
        serde_json::from_value::<SignupRequest>(value).unwrap(),
        signup
    );
    assert_eq!(serde_json::to_value(GrantMode::ReadOnly).unwrap(), "ro");
    assert_eq!(serde_json::to_value(GrantMode::ReadWrite).unwrap(), "rw");
    assert_eq!(serde_json::to_value(AppDeviceKind::App).unwrap(), "app");
    assert_eq!(
        serde_json::to_value(SinceRequest {
            after: 1,
            limit: None
        })
        .unwrap(),
        serde_json::json!({"after":1})
    );
}

#[test]
fn protocol_constants_and_empty_bodies() {
    assert_eq!(PROTOCOL, 1);
    assert_eq!(
        serde_json::to_value(ActivateResponse {}).unwrap(),
        serde_json::json!({})
    );
    assert_eq!(
        serde_json::to_value(HealthResponse {
            ok: true,
            protocol: PROTOCOL
        })
        .unwrap(),
        serde_json::json!({"ok":true,"protocol":1})
    );
    assert_eq!(
        serde_json::to_value(ErrorBody {
            error: "needs_update".into(),
            message: "update".into()
        })
        .unwrap(),
        serde_json::json!({"error":"needs_update","message":"update"})
    );
}

#[test]
fn approval_messages_match_the_relay() {
    let ended = ApprovalStateResponse {
        state: ApprovalState::Ended,
        response: None,
        reveal: None,
        transfer: None,
        end_reason: Some(ApprovalEndReason::WrongDigits),
    };
    let json = serde_json::json!({"state":"ended","endReason":"wrong_digits"});
    assert_eq!(serde_json::to_value(&ended).unwrap(), json);
    assert_eq!(
        serde_json::from_value::<ApprovalStateResponse>(json).unwrap(),
        ended
    );
    assert_eq!(
        serde_json::to_value(ApprovalLiveMessage::Approval {
            approval_id: ApprovalId([0xab; 16]),
            state: ApprovalState::Responded,
            end_reason: None,
        })
        .unwrap(),
        serde_json::json!({"t":"approval","approvalId":"abababababababababababababababab","state":"responded"})
    );
}
