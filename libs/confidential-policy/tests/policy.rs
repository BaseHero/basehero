use bh_confidential_policy::{Build, Error, Limits, Policy, PolicyGate, Role, TimeBounds};
use bh_crypto::{Secret, SigningKey};

// Synthetic measurements and times; signatures exercise the real verification path.
fn signing() -> SigningKey {
    SigningKey::from_seed(&Secret::from_slice(&[7; 32]).unwrap())
}
fn build() -> Build {
    Build {
        role: Role::Runner,
        compose_sha256: [1; 32],
        boot: std::array::from_fn(|i| vec![i as u8; 48]),
    }
}
fn policy(generation: u64) -> Policy {
    Policy {
        version: 1,
        generation,
        issued_at: 100,
        expires_at: 200,
        builds: vec![build()],
        machines: vec![[2; 32]],
    }
}
fn gate() -> PolicyGate {
    PolicyGate::new(
        signing().public(),
        Limits {
            max_lifetime_secs: 100,
            max_uncertainty_secs: 5,
        },
    )
    .unwrap()
}
fn sign(bytes: &[u8]) -> Vec<u8> {
    signing()
        .sign(&[b"basehero.confidential-policy.v1\0".as_slice(), bytes].concat())
        .to_vec()
}
fn push(gate: &mut PolicyGate, policy: &Policy) -> Result<(), Error> {
    let bytes = serde_json::to_vec(policy).unwrap();
    gate.push(&bytes, &sign(&bytes))
}
fn check_at(gate: &mut PolicyGate, earliest: u64, latest: u64) -> Result<(), Error> {
    gate.check_measurements(
        Role::Runner,
        &build(),
        &[2; 32],
        Some(TimeBounds { earliest, latest }),
    )
}
fn check(gate: &mut PolicyGate) -> Result<(), Error> {
    check_at(gate, 120, 121)
}

#[test]
fn signed_policy_matches_only_exact_role_build_and_machine() {
    let mut g = gate();
    assert_eq!(check(&mut g), Err(Error::PolicyUnavailable));
    push(&mut g, &policy(1)).unwrap();
    assert_eq!(check(&mut g), Ok(()));
    let time = Some(TimeBounds {
        earliest: 120,
        latest: 121,
    });
    assert_eq!(
        g.check_measurements(Role::KeyService, &build(), &[2; 32], time),
        Err(Error::RoleDenied)
    );
    let mut altered = build();
    altered.compose_sha256[0] ^= 1;
    assert_eq!(
        g.check_measurements(Role::Runner, &altered, &[2; 32], time),
        Err(Error::BuildDenied)
    );
    for index in 0..4 {
        let mut altered = build();
        altered.boot[index][0] ^= 1;
        assert_eq!(
            g.check_measurements(Role::Runner, &altered, &[2; 32], time),
            Err(Error::BuildDenied)
        );
    }
    assert_eq!(
        g.check_measurements(Role::Runner, &build(), &[3; 32], time),
        Err(Error::MachineDenied)
    );
}

#[test]
fn signature_binds_exact_payload_domain_and_root() {
    let bytes = serde_json::to_vec(&policy(1)).unwrap();
    let signature = sign(&bytes);
    let mut altered = bytes.clone();
    altered.push(b' ');
    assert_eq!(gate().push(&altered, &signature), Err(Error::Signature));
    let wrong_domain = signing().sign(&bytes);
    assert_eq!(gate().push(&bytes, &wrong_domain), Err(Error::Signature));
    let other = SigningKey::from_seed(&Secret::from_slice(&[8; 32]).unwrap());
    let mut g = PolicyGate::new(
        other.public(),
        Limits {
            max_lifetime_secs: 100,
            max_uncertainty_secs: 5,
        },
    )
    .unwrap();
    assert_eq!(g.push(&bytes, &signature), Err(Error::Signature));
    assert_eq!(gate().push(&bytes, &signature[..63]), Err(Error::Signature));
}

#[test]
fn parser_rejects_ambiguous_and_unknown_data_without_echoing_it() {
    let bytes = serde_json::to_string(&policy(1)).unwrap();
    for invalid in [
        bytes.replacen('{', "{\"generation\":1,", 1),
        bytes.replacen('{', "{\"secret_CANARY_member_ip_chat\":1,", 1),
        bytes.replacen("\"role\"", "\"extra\":1,\"role\"", 1),
        bytes.replace("runner", "relay"),
        format!("{bytes} null"),
        "CANARY_prompt_url_token".into(),
    ] {
        let err = gate()
            .push(invalid.as_bytes(), &sign(invalid.as_bytes()))
            .unwrap_err();
        assert_eq!(err, Error::Encoding);
        assert!(!format!("{err:?} {err}").contains("CANARY"));
    }
    let oversized = vec![b' '; 65537];
    assert_eq!(gate().push(&oversized, &[]), Err(Error::TooLarge));
}

#[test]
fn authenticated_unknown_schema_disables_cached_policy_until_redelivered() {
    let mut g = gate();
    push(&mut g, &policy(1)).unwrap();
    let unsupported = b"{\"version\":2,\"future-format\":true}";
    assert_eq!(
        g.push(unsupported, &sign(unsupported)),
        Err(Error::Encoding)
    );
    assert_eq!(check(&mut g), Err(Error::PolicyUnavailable));
    // The old floor is not discarded, even when the new schema is unreadable.
    assert_eq!(push(&mut g, &policy(0)), Err(Error::PolicyRollback));
    assert_eq!(check(&mut g), Err(Error::PolicyUnavailable));
    push(&mut g, &policy(2)).unwrap();
    assert_eq!(check(&mut g), Ok(()));
}

#[test]
fn same_generation_requires_identical_bytes_not_reserialized_equivalence() {
    let mut g = gate();
    let p = policy(9);
    push(&mut g, &p).unwrap();
    push(&mut g, &p).unwrap();
    let mut bytes = serde_json::to_vec(&p).unwrap();
    bytes.push(b' ');
    assert_eq!(
        g.push(&bytes, &sign(&bytes)),
        Err(Error::GenerationConflict)
    );
    assert_eq!(push(&mut g, &policy(8)), Err(Error::PolicyRollback));
    assert_eq!(check(&mut g), Ok(()));
}

#[test]
fn delivered_withdrawal_never_falls_back_to_an_older_policy() {
    let mut g = gate();
    push(&mut g, &policy(1)).unwrap();
    let mut withdrawn = policy(2);
    withdrawn.builds.clear();
    push(&mut g, &withdrawn).unwrap();
    assert_eq!(check(&mut g), Err(Error::BuildDenied));
    assert_eq!(push(&mut g, &policy(1)), Err(Error::PolicyRollback));
    assert_eq!(check(&mut g), Err(Error::BuildDenied));
}

#[test]
fn unusable_authenticated_successor_also_blocks_fallback() {
    let mut successors = vec![];
    let mut p = policy(2);
    p.version = 2;
    successors.push((p, Error::Version));
    let mut p = policy(2);
    p.issued_at = 130;
    successors.push((p, Error::NotYetValid));
    let mut p = policy(2);
    p.expires_at = 120;
    successors.push((p, Error::Expired));
    let mut p = policy(2);
    p.expires_at = 201;
    successors.push((p, Error::Lifetime));
    let mut p = policy(2);
    p.expires_at = 100;
    successors.push((p, Error::Lifetime));
    let mut p = policy(2);
    p.builds[0].boot[0].pop();
    successors.push((p, Error::Measurements));
    for (p, want) in successors {
        let mut g = gate();
        push(&mut g, &policy(1)).unwrap();
        push(&mut g, &p).unwrap();
        assert_eq!(check(&mut g), Err(want));
        assert_eq!(push(&mut g, &policy(1)), Err(Error::PolicyRollback));
        assert_eq!(check(&mut g), Err(want));
    }
}

#[test]
fn unauthenticated_updates_cannot_poison_the_generation_floor() {
    let mut g = gate();
    push(&mut g, &policy(1)).unwrap();
    let bytes = serde_json::to_vec(&policy(u64::MAX)).unwrap();
    assert_eq!(g.push(&bytes, &[0; 64]), Err(Error::Signature));
    assert_eq!(check(&mut g), Ok(()));
    assert_eq!(push(&mut g, &policy(2)), Ok(()));
    assert_eq!(check(&mut g), Ok(()));
}

#[test]
fn conservative_time_interval_checks_every_boundary() {
    for (earliest, latest, want) in [
        (100, 100, Ok(())),
        (199, 199, Ok(())),
        (99, 100, Err(Error::NotYetValid)),
        (199, 200, Err(Error::Expired)),
        (120, 126, Err(Error::TimeUncertain)),
        (121, 120, Err(Error::TimeUncertain)),
        (0, u64::MAX, Err(Error::TimeUncertain)),
        (u64::MAX, u64::MAX, Err(Error::Expired)),
    ] {
        let mut g = gate();
        push(&mut g, &policy(1)).unwrap();
        assert_eq!(check_at(&mut g, earliest, latest), want);
    }
}

#[test]
fn definite_time_rollback_is_sticky_but_overlap_is_not_rollback() {
    let mut g = gate();
    push(&mut g, &policy(1)).unwrap();
    assert_eq!(check_at(&mut g, 120, 125), Ok(()));
    assert_eq!(check_at(&mut g, 119, 121), Ok(()));
    assert_eq!(check_at(&mut g, 118, 119), Err(Error::TimeRollback));
    push(&mut g, &policy(2)).unwrap();
    assert_eq!(check_at(&mut g, 130, 131), Err(Error::TimeRollback));
}

#[test]
fn known_feed_and_time_outages_fail_closed_without_extending_expiry() {
    let mut g = gate();
    push(&mut g, &policy(1)).unwrap();
    g.mark_unavailable();
    assert_eq!(check(&mut g), Err(Error::PolicyUnavailable));
    // Failed input cannot restore availability.
    assert_eq!(g.push(b"{}", &[0; 64]), Err(Error::Signature));
    assert_eq!(check(&mut g), Err(Error::PolicyUnavailable));
    push(&mut g, &policy(1)).unwrap();
    assert_eq!(
        g.check_measurements(Role::Runner, &build(), &[2; 32], None),
        Err(Error::TimeUnavailable)
    );
    assert_eq!(check(&mut g), Ok(()));
    assert_eq!(check_at(&mut g, 200, 200), Err(Error::Expired));
    push(&mut g, &policy(1)).unwrap();
    assert_eq!(check_at(&mut g, 200, 200), Err(Error::Expired));
}

#[test]
fn restored_old_policy_is_rejected_after_expiry_even_with_no_memory() {
    let mut fresh_process = gate();
    push(&mut fresh_process, &policy(1)).unwrap();
    assert_eq!(check_at(&mut fresh_process, 200, 200), Err(Error::Expired));
    // Deliberately records the limit: a reset process cannot learn an unseen
    // withdrawal from an old but still-valid signature. Not recovery authority.
    let mut reset_process = gate();
    push(&mut reset_process, &policy(1)).unwrap();
    assert_eq!(check(&mut reset_process), Ok(()));
}

#[test]
fn configured_lifetime_is_required_and_extreme_intervals_do_not_overflow() {
    assert!(matches!(
        PolicyGate::new(
            signing().public(),
            Limits {
                max_lifetime_secs: 0,
                max_uncertainty_secs: 5
            }
        ),
        Err(Error::Configuration)
    ));
    let mut g = gate();
    let mut p = policy(1);
    p.expires_at = u64::MAX;
    push(&mut g, &p).unwrap();
    assert_eq!(check(&mut g), Err(Error::Lifetime));
}

#[test]
fn policy_has_no_implicit_machine_or_role_permissions() {
    let mut g = gate();
    let mut p = policy(1);
    p.machines.clear();
    push(&mut g, &p).unwrap();
    assert_eq!(check(&mut g), Err(Error::MachineDenied));
    for role in [Role::Checker, Role::KeyService] {
        let mut g = gate();
        let mut p = policy(1);
        p.builds[0].role = role;
        push(&mut g, &p).unwrap();
        assert_eq!(check(&mut g), Err(Error::BuildDenied));
        assert_eq!(
            g.check_measurements(
                role,
                &p.builds[0],
                &[2; 32],
                Some(TimeBounds {
                    earliest: 120,
                    latest: 120
                })
            ),
            Ok(())
        );
    }
}
