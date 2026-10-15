use super::*;
fn key() -> bh_crypto::SigningKey {
    bh_crypto::SigningKey::from_seed(&bh_crypto::Secret::from_slice(&[7; 32]).unwrap())
}
fn trust() -> Trust<'static> {
    Trust {
        root: key().public(),
        key_id: *b"TESTKEY1",
        provider: "near",
        models: &["z-ai/glm-5.3-flash"],
        app_build_date: 100,
        max_lifetime_secs: 1000,
    }
}
fn time(t: u64) -> Option<Time> {
    Some(Time {
        earliest: t,
        latest: t,
        max_uncertainty_secs: 0,
    })
}
fn gateway(s: u8, c: u8) -> Vec<u8> {
    let mut b = vec![1];
    b.extend([s; 32]);
    b.extend([c; 32]);
    b
}
fn named_model(name: &str, c: u8) -> Vec<u8> {
    let mut b = vec![2, name.len() as u8];
    b.extend(name.as_bytes());
    b.extend([c; 32]);
    b
}
fn model(c: u8) -> Vec<u8> {
    let mut b = vec![2, 18];
    b.extend(b"z-ai/glm-5.3-flash");
    b.extend([c; 32]);
    b
}
fn policy(version: u64, issue: u64, expiry: u64, mut entries: Vec<Vec<u8>>) -> Vec<u8> {
    entries.sort();
    let mut payload = vec![1, 4];
    payload.extend(b"near");
    payload.extend(version.to_be_bytes());
    payload.extend(issue.to_be_bytes());
    payload.extend(expiry.to_be_bytes());
    payload.extend((entries.len() as u16).to_be_bytes());
    for entry in entries {
        payload.extend(entry);
    }
    sign(payload, DOMAIN, &key())
}
fn sign(payload: Vec<u8>, domain: &[u8], key: &bh_crypto::SigningKey) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend(b"TESTKEY1");
    bytes.extend((payload.len() as u32).to_be_bytes());
    bytes.extend(&payload);
    let mut message = domain.to_vec();
    message.extend(payload);
    bytes.extend(key.sign(&message));
    bytes
}
fn installed(current: Option<&State>, bytes: &[u8], at: u64) -> State {
    match install(current, bytes, &trust(), time(at)) {
        Install::Installed { state, .. } => state,
        x => panic!("{x:?}"),
    }
}
#[test]
fn authentication_encoding_and_ceiling() {
    let good = policy(10, 90, 500, vec![gateway(1, 2), model(3)]);
    assert!(matches!(
        install(None, &good, &trust(), time(110)),
        Install::Installed {
            usable_now: true,
            ..
        }
    ));
    let mut wrong = trust();
    wrong.root = [0; 32];
    assert!(matches!(
        install(None, &good, &wrong, time(110)),
        Install::Reject(Reject::Signature)
    ));
    let bad_domain = sign(
        good[HEADER..good.len() - SIGNATURE].to_vec(),
        b"other\0",
        &key(),
    );
    assert!(matches!(
        install(None, &bad_domain, &trust(), time(110)),
        Install::Reject(Reject::Signature)
    ));
    wrong = trust();
    wrong.provider = "other";
    assert!(matches!(
        install(None, &good, &wrong, time(110)),
        Install::Reject(Reject::Provider)
    ));
    let mut payload = good[HEADER..good.len() - SIGNATURE].to_vec();
    payload[0] = 2;
    assert!(matches!(
        install(None, &sign(payload, DOMAIN, &key()), &trust(), time(110)),
        Install::Reject(Reject::Schema)
    ));
    let mut payload = good[HEADER..good.len() - SIGNATURE].to_vec();
    payload.push(0);
    assert!(matches!(
        install(None, &sign(payload, DOMAIN, &key()), &trust(), time(110)),
        Install::Reject(Reject::Encoding)
    ));
    assert!(matches!(
        install(None, &vec![0; MAX_ENVELOPE_BYTES + 1], &trust(), time(110)),
        Install::Reject(Reject::TooLarge)
    ));
    let too_many = policy(10, 90, 500, vec![gateway(1, 2); MAX_ENTRIES + 1]);
    assert!(matches!(
        install(None, &too_many, &trust(), time(110)),
        Install::Reject(Reject::TooLarge)
    ));
    let unordered = {
        let mut p = good[HEADER..good.len() - SIGNATURE].to_vec();
        let start = 2 + 4 + 8 + 8 + 8 + 2;
        p[start] = 2;
        sign(p, DOMAIN, &key())
    };
    assert!(matches!(
        install(None, &unordered, &trust(), time(110)),
        Install::Reject(Reject::Encoding | Reject::Provider)
    ));
}
#[test]
fn floor_lifetime_withdrawal_and_load_order() {
    let v10 = policy(10, 90, 500, vec![gateway(1, 2), model(3)]);
    let v11 = policy(
        11,
        95,
        600,
        vec![gateway(1, 2), gateway(4, 5), model(3), model(6)],
    );
    let v12 = policy(12, 95, 600, vec![gateway(4, 5), model(6)]);
    let first = installed(None, &v10, 110);
    assert_eq!(first.signed_bytes(), v10);
    let restored = restore(first.signed_bytes(), &trust()).unwrap();
    assert!(matches!(
        install(Some(&restored), &v10, &trust(), time(110)),
        Install::Same { usable_now: true }
    ));
    assert!(matches!(
        install(
            Some(&restored),
            &policy(10, 90, 501, vec![]),
            &trust(),
            time(110)
        ),
        Install::Reject(Reject::Equivocation)
    ));
    let overlap = installed(Some(&restored), &v11, 110);
    assert!(expected_gateway(overlap.snapshot(), [9; 32], time(110)).is_ok());
    let retired = installed(Some(&overlap), &v12, 110);
    assert!(matches!(
        install(Some(&retired), &v11, &trust(), time(110)),
        Install::Reject(Reject::Rollback)
    ));
    assert_eq!(retired.snapshot().provider_entries(), 2);
    // Stored state wins same-version equivocation; shipped higher is an ordinary install.
    assert!(matches!(
        install(
            Some(&retired),
            &policy(12, 96, 600, vec![]),
            &trust(),
            time(110)
        ),
        Install::Reject(Reject::Equivocation)
    ));
    assert_eq!(installed(Some(&restored), &v12, 110).signed_bytes(), v12);
    let empty = installed(Some(&retired), &policy(13, 90, 600, vec![]), 110);
    assert!(matches!(
        expected_gateway(empty.snapshot(), [9; 32], time(110)),
        Err(Reject::Denied)
    ));
    let bad_lifetime = policy(14, 900, 899, vec![gateway(4, 5)]);
    let advanced = installed(Some(&empty), &bad_lifetime, 110);
    assert!(matches!(
        expected_gateway(advanced.snapshot(), [9; 32], time(110)),
        Err(Reject::Lifetime)
    ));
    assert!(matches!(
        install(Some(&advanced), &v12, &trust(), time(110)),
        Install::Reject(Reject::Rollback)
    ));
    let overlong = installed(
        Some(&advanced),
        &policy(15, 1, 1002, vec![gateway(4, 5)]),
        110,
    );
    assert!(matches!(
        expected_gateway(overlong.snapshot(), [9; 32], time(110)),
        Err(Reject::Lifetime)
    ));
    let expired = installed(
        Some(&overlong),
        &policy(16, 1, 90, vec![gateway(4, 5)]),
        110,
    );
    assert!(matches!(
        expected_gateway(expired.snapshot(), [9; 32], time(110)),
        Err(Reject::Expired)
    ));
    assert!(matches!(
        expected_gateway(first.snapshot(), [9; 32], time(99)),
        Err(Reject::Time)
    ));
    assert!(expected_gateway(first.snapshot(), [9; 32], time(100)).is_ok());
    assert!(matches!(
        expected_gateway(first.snapshot(), [9; 32], time(500)),
        Err(Reject::Expired)
    ));
    assert!(matches!(
        expected_gateway(first.snapshot(), [9; 32], None),
        Err(Reject::Time)
    ));
}
#[test]
fn correlated_gateway_and_model_expectations() {
    let state = installed(
        None,
        &policy(11, 90, 600, vec![gateway(1, 2), gateway(4, 5), model(3)]),
        110,
    );
    let expected = expected_gateway(state.snapshot(), [9; 32], time(110)).unwrap();
    assert!(expected.has_pair([1; 32], [2; 32]));
    assert!(expected.has_pair([4; 32], [5; 32]));
    assert!(!expected.has_pair([1; 32], [5; 32]));
    assert!(expected_model(state.snapshot(), "z-ai/glm-5.3-flash", [9; 32], time(110)).is_ok());
    assert!(matches!(
        expected_model(state.snapshot(), "wrong", [9; 32], time(110)),
        Err(Reject::Denied)
    ));
}
#[test]
fn unknown_but_canonical_model_advances_retirement_and_survives_narrow_restore() {
    let old = installed(
        None,
        &policy(11, 90, 500, vec![gateway(1, 2), model(3)]),
        110,
    );
    let newer = policy(
        12,
        90,
        500,
        vec![gateway(4, 5), named_model("Qwen/Model_2:fast", 7)],
    );
    let next = installed(Some(&old), &newer, 110);
    assert_eq!(next.snapshot().version(), 12);
    assert_eq!(next.signed_bytes(), newer);
    assert_eq!(next.snapshot().provider_entries(), 1);
    let changed_unknown = policy(
        12,
        90,
        500,
        vec![gateway(4, 5), named_model("Qwen/Model_2:fast", 8)],
    );
    assert_ne!(
        next.snapshot().digest(),
        restore(&changed_unknown, &trust())
            .unwrap()
            .snapshot()
            .digest()
    );
    assert!(matches!(
        install(Some(&next), &changed_unknown, &trust(), time(110)),
        Install::Reject(Reject::Equivocation)
    ));
    let mut newer_release = trust();
    newer_release.models = &["Qwen/Model_2:fast"];
    let supported = restore(&newer, &newer_release).unwrap();
    assert_eq!(supported.snapshot().provider_entries(), 2);
    assert_eq!(supported.signed_bytes(), newer);
    assert_eq!(supported.snapshot().digest(), next.snapshot().digest());
    assert_eq!(
        expected_model(
            supported.snapshot(),
            "Qwen/Model_2:fast",
            [0; 32],
            time(110)
        )
        .err(),
        Some(Reject::Denied)
    );
    assert!(
        !expected_gateway(next.snapshot(), [0; 32], time(110))
            .unwrap()
            .has_pair([1; 32], [2; 32])
    );
    assert_eq!(
        expected_model(next.snapshot(), "Qwen/Model_2:fast", [0; 32], time(110)).err(),
        Some(Reject::Denied)
    );
    let mut narrower = trust();
    narrower.models = &[];
    let restored = restore(next.signed_bytes(), &narrower).unwrap();
    assert_eq!(restored.snapshot().version(), 12);
    assert_eq!(restored.snapshot().provider_entries(), 1);
    assert_eq!(restored.signed_bytes(), newer);
    assert!(matches!(
        install(Some(&restored), old.signed_bytes(), &narrower, time(110)),
        Install::Reject(Reject::Rollback)
    ));
    // Even unretained entries must be well-formed, unique and correctly ordered.
    let unknown_kind = policy(13, 90, 500, vec![vec![3]]);
    assert!(matches!(
        install(Some(&next), &unknown_kind, &trust(), time(110)),
        Install::Reject(Reject::Schema)
    ));
    let duplicate = policy(13, 90, 500, vec![named_model("Qwen/Model_2:fast", 7); 2]);
    assert!(matches!(
        install(Some(&next), &duplicate, &trust(), time(110)),
        Install::Reject(Reject::Encoding)
    ));
    assert!(matches!(
        install(
            Some(&next),
            &policy(13, 90, 500, vec![named_model("bad model", 7)]),
            &trust(),
            time(110)
        ),
        Install::Reject(Reject::Encoding)
    ));
}
#[test]
fn signed_future_model_cannot_be_used_by_fixed_glm_route() {
    let mut ceiling = trust();
    ceiling.models = &[near_model::MODEL, "other/Model_2:fast"];
    let signed = policy(12, 90, 500, vec![named_model("other/Model_2:fast", 7)]);
    let state = match install(None, &signed, &ceiling, time(110)) {
        Install::Installed {
            state,
            usable_now: true,
        } => state,
        other => panic!("signed future model was not stored: {other:?}"),
    };
    assert_eq!(state.signed_bytes(), signed);
    assert_eq!(state.snapshot().provider_entries(), 1);
    assert_eq!(
        expected_model(state.snapshot(), near_model::MODEL, [9; 32], time(110)).err(),
        Some(Reject::Denied)
    );
    // This fixed verifier cannot mint a key for another model, even when the
    // release ceiling and signed policy both include its measured hash.
    assert_eq!(
        expected_model(state.snapshot(), "other/Model_2:fast", [9; 32], time(110)).err(),
        Some(Reject::Denied)
    );
}
#[test]
fn same_status_and_provider_scoping() {
    let withdrawn = policy(1, 90, 500, vec![]);
    let state = installed(None, &withdrawn, 110);
    assert!(matches!(
        install(Some(&state), &withdrawn, &trust(), time(110)),
        Install::Same { usable_now: false }
    ));
    let model_only = policy(2, 90, 500, vec![model(3)]);
    let state = installed(Some(&state), &model_only, 110);
    assert!(matches!(
        install(Some(&state), &model_only, &trust(), time(110)),
        Install::Same { usable_now: true }
    ));
    let mut other = trust();
    other.provider = "tinfoil";
    assert!(matches!(
        install(Some(&state), &withdrawn, &other, time(110)),
        Install::Reject(Reject::Provider)
    ));
    // A valid signed policy for a different provider must not share a version floor.
    let mut foreign_payload = vec![1, 7];
    foreign_payload.extend(b"tinfoil");
    foreign_payload.extend(3u64.to_be_bytes());
    foreign_payload.extend(90u64.to_be_bytes());
    foreign_payload.extend(500u64.to_be_bytes());
    foreign_payload.extend(0u16.to_be_bytes());
    let foreign = sign(foreign_payload, DOMAIN, &key());
    assert!(matches!(
        install(Some(&state), &foreign, &other, time(110)),
        Install::Reject(Reject::Provider)
    ));
    let foreign_state = restore(&foreign, &other).unwrap();
    assert_eq!(foreign_state.snapshot().provider(), "tinfoil");
    assert_eq!(
        expected_gateway(foreign_state.snapshot(), [0; 32], time(110)).err(),
        Some(Reject::Provider)
    );
    assert_eq!(
        expected_model(
            foreign_state.snapshot(),
            "z-ai/glm-5.3-flash",
            [0; 32],
            time(110)
        )
        .err(),
        Some(Reject::Provider)
    );
}
#[test]
fn synthetic_fixture_matches() {
    let bytes = policy(10, 90, 500, vec![gateway(1, 2), model(3)]);
    let fixture = include_str!("../../fixtures/provider-policy-synthetic.hex").trim();
    assert_eq!(hex::encode(&bytes), fixture);
    assert!(matches!(
        install(None, &hex::decode(fixture).unwrap(), &trust(), time(110)),
        Install::Installed {
            usable_now: true,
            ..
        }
    ));
}
