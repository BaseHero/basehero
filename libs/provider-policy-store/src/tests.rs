use super::*;
use bh_crypto::{Secret, SigningKey};
// Fork before exec briefly inherits the parent's flock open-file description.
// A parallel subprocess spawn can make a just-dropped owner transiently Busy
// on reopen; serialize filesystem fixtures around the subprocess lock probe.
pub(super) static IO_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn key() -> SigningKey {
    SigningKey::from_seed(&Secret::<32>::from_slice(&[7; 32]).unwrap())
}
pub(super) fn trust<'a>(provider: &'a str) -> Trust<'a> {
    Trust {
        root: key().public(),
        key_id: *b"TESTKEY1",
        provider,
        models: &["z-ai/glm-5.3-flash"],
        app_build_date: 100,
        max_lifetime_secs: 1000,
    }
}
pub(super) fn time() -> Option<Time> {
    Some(Time {
        earliest: 110,
        latest: 110,
        max_uncertainty_secs: 0,
    })
}
pub(super) fn signed(provider: &str, version: u64) -> Vec<u8> {
    signed_with_expiry(provider, version, 500)
}
fn signed_with_expiry(provider: &str, version: u64, expiry: u64) -> Vec<u8> {
    let mut payload = vec![1, provider.len() as u8];
    payload.extend(provider.as_bytes());
    payload.extend(version.to_be_bytes());
    payload.extend(90u64.to_be_bytes());
    payload.extend(expiry.to_be_bytes());
    payload.extend(0u16.to_be_bytes());
    let mut message = b"BaseHero provider-admission v1\0".to_vec();
    message.extend(&payload);
    let mut envelope = b"BHPOL001TESTKEY1".to_vec();
    envelope.extend((payload.len() as u32).to_be_bytes());
    envelope.extend(payload);
    envelope.extend(key().sign(&message));
    envelope
}
fn signed_entries(
    provider: &str,
    version: u64,
    expiry: u64,
    pairs: &[(u8, u8)],
    models: &[u8],
) -> Vec<u8> {
    let mut entries = Vec::new();
    for &(signer, compose) in pairs {
        let mut entry = vec![1];
        entry.extend([signer; 32]);
        entry.extend([compose; 32]);
        entries.push(entry);
    }
    for &compose in models {
        let mut entry = vec![2, 18];
        entry.extend(b"z-ai/glm-5.3-flash");
        entry.extend([compose; 32]);
        entries.push(entry);
    }
    entries.sort();
    let mut payload = vec![1, provider.len() as u8];
    payload.extend(provider.as_bytes());
    payload.extend(version.to_be_bytes());
    payload.extend(90u64.to_be_bytes());
    payload.extend(expiry.to_be_bytes());
    payload.extend((entries.len() as u16).to_be_bytes());
    for entry in entries {
        payload.extend(entry);
    }
    let mut message = b"BaseHero provider-admission v1\0".to_vec();
    message.extend(&payload);
    let mut envelope = b"BHPOL001TESTKEY1".to_vec();
    envelope.extend((payload.len() as u32).to_be_bytes());
    envelope.extend(payload);
    envelope.extend(key().sign(&message));
    envelope
}

#[test]
fn rollout_snapshot_from_real_store_is_fresh_and_provider_scoped() {
    let _guard = IO_TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let device = dir.path().join("device");
    let accounts = dir.path().join("accounts/a/cache");
    std::fs::create_dir_all(&accounts).unwrap();
    let v10 = signed_entries("near", 10, 500, &[(1, 2)], &[3]);
    let v11 = signed_entries("near", 11, 500, &[(1, 2), (4, 5)], &[3, 6]);
    let v12 = signed_entries("near", 12, 500, &[(4, 5)], &[6]);
    let mut near = Owner::open(&device, &trust("near"), &v10, time()).unwrap();
    let other_bytes = signed_entries("tinfoil", 2, 500, &[], &[]);
    let other = Owner::open(&device, &trust("tinfoil"), &other_bytes, time()).unwrap();
    let reader = near.reader();
    let nonce = [9; 32];
    let pairs = |snapshot: &Snapshot| provider_policy::expected_gateway(snapshot, nonce, time());
    assert!(pairs(&reader.snapshot().unwrap()).is_ok());
    assert_eq!(reader.snapshot().unwrap().provider_entries(), 2);
    let held_old = reader.snapshot().unwrap();
    assert!(matches!(
        near.install(&v11, time()),
        Ok(Change::Installed { .. })
    ));
    let overlap = reader.snapshot().unwrap();
    assert!(pairs(&overlap).is_ok());
    assert_eq!(overlap.provider_entries(), 4);
    assert!(provider_policy::expected_model(&overlap, "z-ai/glm-5.3-flash", nonce, time()).is_ok());
    assert!(matches!(
        near.install(&v12, time()),
        Ok(Change::Installed { .. })
    ));
    assert_eq!(held_old.version(), 10);
    assert_eq!(reader.snapshot().unwrap().version(), 12);
    assert_ne!(held_old.digest(), reader.snapshot().unwrap().digest());
    assert_eq!(reader.snapshot().unwrap().provider_entries(), 2);
    std::fs::remove_dir_all(dir.path().join("accounts")).unwrap();
    assert_eq!(reader.snapshot().unwrap().version(), 12);
    assert_eq!(other.reader().snapshot().unwrap().version(), 2);
    assert_eq!(
        provider_policy::expected_gateway(&other.reader().snapshot().unwrap(), nonce, time()).err(),
        Some(Reject::Provider)
    );
    drop(near);
    let mut near = Owner::open(&device, &trust("near"), &v10, time()).unwrap();
    assert_eq!(near.signed_bytes(), v12);
    assert_eq!(near.reader().snapshot().unwrap().version(), 12);
    assert!(matches!(
        near.install(&v11, time()),
        Ok(Change::Rejected(Reject::Rollback))
    ));
    assert_eq!(other.reader().snapshot().unwrap().version(), 2);
    let expired = signed_entries("near", 13, 105, &[(1, 2)], &[3]);
    assert!(matches!(
        near.install(&expired, time()),
        Ok(Change::Installed { usable_now: false })
    ));
    assert_eq!(
        provider_policy::expected_gateway(&near.reader().snapshot().unwrap(), nonce, time()).err(),
        Some(Reject::Expired)
    );
    drop(near);
    let mut near = Owner::open(&device, &trust("near"), &v10, time()).unwrap();
    assert_eq!(near.reader().snapshot().unwrap().version(), 13);
    assert!(matches!(
        near.install(&v12, time()),
        Ok(Change::Rejected(Reject::Rollback))
    ));
    let withdrawn = signed_entries("near", 14, 500, &[], &[]);
    assert!(matches!(
        near.install(&withdrawn, time()),
        Ok(Change::Installed { usable_now: false })
    ));
    assert_eq!(
        provider_policy::expected_gateway(&near.reader().snapshot().unwrap(), nonce, time()).err(),
        Some(Reject::Denied)
    );
    drop(near);
    let near = Owner::open(&device, &trust("near"), &v10, time()).unwrap();
    assert_eq!(near.reader().snapshot().unwrap().version(), 14);
    assert_eq!(other.reader().snapshot().unwrap().version(), 2);
}

#[test]
fn restart_floor_shipped_rollback_corruption_and_provider_isolation() {
    let _guard = IO_TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let v10 = signed("near", 10);
    let v12 = signed("near", 12);
    let other = signed("tinfoil", 2);
    {
        let mut near = Owner::open(dir.path(), &trust("near"), &v10, time()).unwrap();
        let tinfoil = Owner::open(dir.path(), &trust("tinfoil"), &other, time()).unwrap();
        assert_eq!(near.snapshot().unwrap().version(), 10);
        assert_eq!(tinfoil.snapshot().unwrap().version(), 2);
        assert!(matches!(
            near.install(&v12, time()),
            Ok(Change::Installed { .. })
        ));
        assert_eq!(near.snapshot().unwrap().version(), 12);
        assert!(matches!(
            near.install(&v10, time()),
            Ok(Change::Rejected(Reject::Rollback))
        ));
    }
    let near = Owner::open(dir.path(), &trust("near"), &v10, time()).unwrap();
    assert_eq!(near.snapshot().unwrap().version(), 12);
    assert_eq!(near.signed_bytes(), v12);
    drop(near);
    std::fs::write(dir.path().join("near.policy"), b"partial").unwrap();
    let near = Owner::open(dir.path(), &trust("near"), &v10, time()).unwrap();
    assert_eq!(near.snapshot().unwrap().version(), 10);
    assert_eq!(
        Owner::open(dir.path(), &trust("tinfoil"), &other, time())
            .unwrap()
            .snapshot()
            .unwrap()
            .version(),
        2
    );
}
#[test]
fn second_owner_refused_and_each_write_fault_quarantines_without_publishing() {
    let _guard = IO_TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let v10 = signed("near", 10);
    let v11 = signed("near", 11);
    let v12 = signed("near", 12);
    for stage in [
        Stage::Write,
        Stage::FileSync,
        Stage::Rename,
        Stage::DirectorySync,
    ] {
        let mut owner = Owner::open(dir.path(), &trust("near"), &v10, time()).unwrap();
        assert!(matches!(
            Owner::open(dir.path(), &trust("near"), &v10, time()),
            Err(Error::Busy)
        ));
        let result = owner.install_with_fault(&v11, time(), Some(stage));
        assert!(
            matches!(result, Err(Error::Storage(_))),
            "{stage:?}: {result:?}"
        );
        assert!(owner.is_quarantined());
        assert!(owner.snapshot().is_none());
        assert!(matches!(
            owner.install(&v10, time()),
            Err(Error::Quarantined)
        ));
        assert!(owner.snapshot().is_none());
        assert!(matches!(
            owner.install(&v12, time()),
            Ok(Change::Installed { .. })
        ));
        assert!(!owner.is_quarantined());
        assert_eq!(owner.snapshot().unwrap().version(), 12);
        drop(owner);
        let mut restored = Owner::open(dir.path(), &trust("near"), &v10, time()).unwrap();
        // A rename that completed may have advanced the floor; neither outcome
        // may permit older bytes to overwrite it after restart.
        assert_eq!(restored.snapshot().unwrap().version(), 12);
        assert!(matches!(
            restored.install(&v11, time()),
            Ok(Change::Rejected(Reject::Rollback))
        ));
        drop(restored);
        std::fs::remove_file(dir.path().join("near.policy")).unwrap();
    }
}

#[test]
fn schedule_persists_attempts_across_restart_and_counts_suspend_wall_time() {
    let _guard = IO_TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let owner = Owner::open(dir.path(), &trust("near"), &signed("near", 10), time()).unwrap();
    let mut schedule = Schedule::new(&owner).unwrap();
    assert!(schedule.begin(10_000, false).unwrap());
    assert!(!schedule.begin(10_000 + 8 * 3600, true).unwrap());
    schedule.finish();
    let mut restarted = Schedule::new(&owner).unwrap();
    let (_, due, _) = restarted.last.unwrap();
    assert!((10_000 + 6 * 3600..10_000 + 7 * 3600).contains(&due));
    assert!(!restarted.begin(due - 1, false).unwrap());
    assert!(restarted.begin(due, false).unwrap());
    restarted.finish();
    // Wall time advances while the process is suspended, without a timer firing.
    assert!(restarted.begin(10_000 + 15 * 3600, false).unwrap());
    restarted.finish();
    // A backwards clock jump cannot defer another check indefinitely.
    assert!(restarted.begin(9_000, false).unwrap());
}

#[test]
fn schedule_unknown_refresh_is_shorter_coalesced_and_persistent() {
    let _guard = IO_TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let owner = Owner::open(dir.path(), &trust("near"), &signed("near", 10), time()).unwrap();
    let mut schedule = Schedule::new(&owner).unwrap();
    assert!(schedule.begin(100_000, false).unwrap());
    schedule.finish();
    assert!(!schedule.begin(100_001, true).unwrap());
    assert!(schedule.begin(100_000 + 3600, true).unwrap());
    assert!(!schedule.begin(100_000 + 3601, true).unwrap());
    schedule.finish();
    let mut restarted = Schedule::new(&owner).unwrap();
    let (_, _, due) = restarted.last.unwrap();
    assert!((100_000 + 3600 + 1800..100_000 + 3600 + 3600).contains(&due));
    assert!(!restarted.begin(due - 1, true).unwrap());
    assert!(restarted.begin(due, true).unwrap());
}

#[test]
fn quarantine_reconciles_renamed_bytes_before_equivocation_or_same() {
    let _guard = IO_TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let v10 = signed("near", 10);
    let v11 = signed("near", 11);
    let alternative = signed_with_expiry("near", 11, 501);
    let mut owner = Owner::open(dir.path(), &trust("near"), &v10, time()).unwrap();
    assert!(matches!(
        owner.install_with_fault(&v11, time(), Some(Stage::DirectorySync)),
        Err(Error::Storage(_))
    ));
    assert!(matches!(
        owner.install(&alternative, time()),
        Err(Error::Quarantined)
    ));
    assert_eq!(std::fs::read(dir.path().join("near.policy")).unwrap(), v11);
    assert!(matches!(
        owner.install(&v11, time()),
        Err(Error::Quarantined)
    ));
    drop(owner);
    let mut reopened = Owner::open(dir.path(), &trust("near"), &v10, time()).unwrap();
    assert!(matches!(
        reopened.install(&v11, time()),
        Ok(Change::Same { .. })
    ));
}

#[test]
fn restart_after_each_failed_io_boundary_never_adopts_a_partial_temp_file() {
    let _guard = IO_TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let old = signed("near", 10);
    let new = signed("near", 11);
    for stage in [
        Stage::Write,
        Stage::FileSync,
        Stage::Rename,
        Stage::DirectorySync,
    ] {
        {
            let mut owner = Owner::open(dir.path(), &trust("near"), &old, time()).unwrap();
            assert!(matches!(
                owner.install_with_fault(&new, time(), Some(stage)),
                Err(Error::Storage(_))
            ));
            assert!(owner.snapshot().is_none());
        }
        // A crashed process can leave an incomplete same-directory temp behind.
        std::fs::write(dir.path().join(".tmp-partial"), &new[..new.len() / 2]).unwrap();
        let owner = Owner::open(dir.path(), &trust("near"), &old, time()).unwrap();
        let expected = if stage == Stage::DirectorySync {
            11
        } else {
            10
        };
        assert_eq!(owner.snapshot().unwrap().version(), expected, "{stage:?}");
        drop(owner);
        std::fs::remove_file(dir.path().join("near.policy")).unwrap();
    }
}

#[test]
fn fixture_bootstrap_rejects_oversized_store_and_account_cleanup_is_independent() {
    let _guard = IO_TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let fixture =
        hex::decode(include_str!("../../models/fixtures/provider-policy-synthetic.hex").trim())
            .unwrap();
    let account_cache = dir.path().join("accounts/a/cache");
    std::fs::create_dir_all(&account_cache).unwrap();
    let policy_dir = dir.path().join("device/policy");
    let mut owner = Owner::open(&policy_dir, &trust("near"), &fixture, time()).unwrap();
    assert_eq!(owner.snapshot().unwrap().version(), 10);
    assert_eq!(owner.signed_bytes(), fixture);
    std::fs::remove_dir_all(dir.path().join("accounts")).unwrap();
    assert_eq!(owner.snapshot().unwrap().version(), 10);
    assert!(matches!(
        owner.install(&vec![0; MAX_ENVELOPE_BYTES + 1], time()),
        Ok(Change::Rejected(Reject::TooLarge))
    ));
    drop(owner);
    std::fs::write(
        policy_dir.join("near.policy"),
        vec![0; MAX_ENVELOPE_BYTES + 1],
    )
    .unwrap();
    let owner = Owner::open(&policy_dir, &trust("near"), &fixture, time()).unwrap();
    assert_eq!(owner.snapshot().unwrap().version(), 10);
    assert_eq!(
        std::fs::read(policy_dir.join("near.policy")).unwrap(),
        fixture
    );
}

#[test]
fn failed_quarantine_restore_reports_storage_not_shipped() {
    let _guard = IO_TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let mut owner = Owner::open(dir.path(), &trust("near"), &signed("near", 10), time()).unwrap();
    assert!(matches!(
        owner.install_with_fault(&signed("near", 11), time(), Some(Stage::DirectorySync)),
        Err(Error::Storage(_))
    ));
    std::fs::write(dir.path().join("near.policy"), b"corrupt").unwrap();
    assert!(matches!(
        owner.install(&signed("near", 12), time()),
        Err(Error::Storage(_))
    ));
    assert!(owner.reader().snapshot().is_none());
}

#[cfg(unix)]
#[test]
fn unreadable_store_returns_storage_error_without_overwriting_it() {
    let _guard = IO_TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("near.policy");
    std::os::unix::fs::symlink("near.policy", &path).unwrap();
    assert!(matches!(
        Owner::open(dir.path(), &trust("near"), &signed("near", 10), time()),
        Err(Error::Storage(_))
    ));
    assert_eq!(std::fs::read_link(&path).unwrap(), Path::new("near.policy"));
}

#[test]
fn reader_sees_only_durable_transitions_and_quarantine() {
    let _guard = IO_TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let mut owner = Owner::open(dir.path(), &trust("near"), &signed("near", 10), time()).unwrap();
    let reader = owner.reader();
    assert_eq!(reader.snapshot().unwrap().version(), 10);
    assert!(matches!(
        owner.install_with_fault(&signed("near", 11), time(), Some(Stage::DirectorySync)),
        Err(Error::Storage(_))
    ));
    assert!(reader.snapshot().is_none());
    assert!(matches!(
        owner.install(&signed("near", 12), time()),
        Ok(Change::Installed { .. })
    ));
    assert_eq!(reader.snapshot().unwrap().version(), 12);
}

#[test]
fn corrupt_or_missing_attempt_record_is_due() {
    let _guard = IO_TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let owner = Owner::open(dir.path(), &trust("near"), &signed("near", 10), time()).unwrap();
    let path = dir.path().join("near.attempt");
    std::fs::write(&path, vec![b'x'; 1024]).unwrap();
    let mut schedule = Schedule::new(&owner).unwrap();
    assert!(schedule.begin(50_000, false).unwrap());
    schedule.finish();
    std::fs::remove_file(path).unwrap();
    assert!(Schedule::new(&owner).unwrap().begin(50_001, false).unwrap());
}

#[test]
fn second_process_cannot_own_policy() {
    if std::env::var_os("BH_LOCK_PROBE").is_some() {
        let directory = std::env::var_os("BH_LOCK_DIR").unwrap();
        let bytes = signed("near", 10);
        assert!(matches!(
            Owner::open(Path::new(&directory), &trust("near"), &bytes, time()),
            Err(Error::Busy)
        ));
        return;
    }
    let _guard = IO_TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    let bytes = signed("near", 10);
    let _owner = Owner::open(dir.path(), &trust("near"), &bytes, time()).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("tests::second_process_cannot_own_policy")
        .env("BH_LOCK_PROBE", "1")
        .env("BH_LOCK_DIR", dir.path())
        .status()
        .unwrap();
    assert!(status.success());
}
