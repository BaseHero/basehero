#[path = "support/account.rs"]
mod account;
#[path = "support/owner_db.rs"]
mod owner_db;
#[allow(dead_code)]
#[path = "support/protector.rs"]
mod protector;
#[path = "support/store.rs"]
mod store;
use account::{Account, Device, account, add, signed, t};
use bh_account::owner::staging::EntryRefused;
use owner_db::{Harness, Other, apply, apply_at, ready};

use bh_account::{
    DeviceId, Error, VerifiedAccount,
    crypto::SigningKey,
    directory::{
        DirectoryEntry, EntrySubject, MAX_KEY_PACKAGE, MAX_METADATA_SEAL, directory_key, entry_id,
        open_entry, prepare_entry,
    },
    personal::PersonalKey,
    recovery::{Password, RecoveryKeys, make_password_check, verify_password},
};

// Offsets in the signed entry: domain, account, personal-key id, entry id,
// version, head position and hash, signer.
const DOMAIN: &[u8] = b"bh/directory-entry/v1\0";
const ID_AT: usize = DOMAIN.len() + 64;
const HEAD_AT: usize = ID_AT + 32 + 8;
const SIGNER_AT: usize = HEAD_AT + 40;

fn name(device: DeviceId, name: &str) -> DirectoryEntry {
    DirectoryEntry::DeviceName {
        device,
        name: name.to_string(),
    }
}

fn write(a: &Account, by: &Device, entry: &DirectoryEntry, version: u64) -> Vec<u8> {
    write_on(&a.acct, &a.personal, by, entry, version)
}

fn write_on(
    acct: &VerifiedAccount,
    personal: &PersonalKey,
    by: &Device,
    entry: &DirectoryEntry,
    version: u64,
) -> Vec<u8> {
    let request = prepare_entry(acct, personal, by.id(), entry, version).unwrap();
    assert_eq!(request.expected_key(), by.public.signing());
    request
        .finish(by.ordinary.sign(request.signing_bytes()))
        .unwrap()
}

/// Re-sign changed entry bytes, as a device with `key` could.
fn resign(bytes: &[u8], edit: impl FnOnce(&mut Vec<u8>), key: &SigningKey) -> Vec<u8> {
    let mut unsigned = bytes[..bytes.len() - 64].to_vec();
    edit(&mut unsigned);
    let signature = key.sign(&unsigned);
    unsigned.extend(signature);
    unsigned
}

#[test]
fn entry_ids_need_the_personal_key() {
    let (p1, p2) = (PersonalKey::generate(), PersonalKey::generate());
    let s = EntrySubject::Base([9; 32]);
    assert_ne!(
        entry_id(&directory_key(&p1), &s),
        entry_id(&directory_key(&p2), &s)
    );
    assert_eq!(
        entry_id(&directory_key(&p1), &s),
        entry_id(&directory_key(&p1), &EntrySubject::Base([9; 32]))
    );
    let key = directory_key(&p1);
    let ids = [
        entry_id(&key, &s),
        entry_id(&key, &EntrySubject::Base([8; 32])),
        entry_id(&key, &EntrySubject::DeviceName(DeviceId([9; 32]))),
        entry_id(&key, &EntrySubject::PasswordCheck),
    ];
    for (i, a) in ids.iter().enumerate() {
        for b in &ids[i + 1..] {
            assert_ne!(a, b);
        }
    }
}

#[test]
fn entry_opens_only_for_its_account_key_and_subject() {
    let mut a = account("correct horse");
    let entry = name(a.mac.id(), "Work Mac");
    let bytes = write(&a, &a.mac, &entry, 3);
    let opened = open_entry(&a.acct, &a.personal, &bytes).unwrap();
    assert_eq!(opened.version, 3);
    assert!(opened.signer == a.mac.id());
    assert_eq!(
        opened.entry_id,
        entry_id(
            &directory_key(&a.personal),
            &EntrySubject::DeviceName(a.mac.id())
        )
    );
    let DirectoryEntry::DeviceName { device, name } = opened.entry else {
        panic!("not a device name");
    };
    assert!(device == a.mac.id());
    assert_eq!(name, "Work Mac");
    // The name is not in the clear.
    assert!(!bytes.windows(8).any(|w| w == b"Work Mac"));

    let b = account("correct horse");
    assert_eq!(
        open_entry(&b.acct, &b.personal, &bytes).err(),
        Some(Error::WrongAccount)
    );
    let next = PersonalKey::generate();
    assert_eq!(
        open_entry(&a.acct, &next, &bytes).err(),
        Some(Error::InvalidCredentials)
    );
    // An id not derived from the sealed subject: another device's name id.
    let other = entry_id(
        &directory_key(&a.personal),
        &EntrySubject::DeviceName(DeviceId([5; 32])),
    );
    let swapped = resign(
        &bytes,
        |b| b[ID_AT..ID_AT + 32].copy_from_slice(&other),
        &a.mac.ordinary,
    );
    assert_eq!(
        open_entry(&a.acct, &a.personal, &swapped).err(),
        Some(Error::InvalidCredentials)
    );
    // Entries under a rotated-away personal key are not opened.
    let replace = signed(
        a.acct
            .replace_recovery(
                a.mac.id(),
                RecoveryKeys::generate().public(),
                [6; 32],
                [7; 32],
            )
            .unwrap(),
        &a.mac.control,
    );
    a.acct.apply_timed(replace.as_bytes(), t(10, 10)).unwrap();
    let reason = a.acct.head().position;
    let rotate = signed(
        a.acct
            .rotate_personal(a.mac.id(), reason, next.public(), [8; 32], [9; 32])
            .unwrap(),
        &a.mac.ordinary,
    );
    a.acct.apply_timed(rotate.as_bytes(), t(20, 20)).unwrap();
    assert_eq!(
        open_entry(&a.acct, &next, &bytes).err(),
        Some(Error::InvalidCredentials)
    );
    assert!(prepare_entry(&a.acct, &a.personal, a.mac.id(), &entry, 4).is_err());
    let rewritten = write_on(&a.acct, &next, &a.mac, &entry, 4);
    assert_eq!(open_entry(&a.acct, &next, &rewritten).unwrap().version, 4);
}

#[test]
fn entry_signed_by_an_inactive_or_unknown_device_is_refused() {
    let mut a = account("correct horse");
    let fold = Device::new();
    let before_fold = a.acct.clone();
    let added = add(&a.acct, &a.mac, &fold);
    a.acct.apply(added.as_bytes()).unwrap();
    let entry = name(fold.id(), "Fold");
    let bytes = write(&a, &fold, &entry, 1);
    assert!(open_entry(&a.acct, &a.personal, &bytes).is_ok());
    // A head this reader has not verified.
    assert_eq!(
        open_entry(&before_fold, &a.personal, &bytes).err(),
        Some(Error::TruncatedHistory)
    );
    // Signed with the wrong key, or changed after signing.
    let request = prepare_entry(&a.acct, &a.personal, fold.id(), &entry, 1).unwrap();
    assert_eq!(
        request
            .finish(fold.control.sign(request.signing_bytes()))
            .err(),
        Some(Error::BadSignature)
    );
    let mut forged = bytes.clone();
    forged[HEAD_AT - 1] ^= 1;
    assert_eq!(
        open_entry(&a.acct, &a.personal, &forged).err(),
        Some(Error::BadSignature)
    );
    // An unknown device's own signature.
    let stranger = Device::new();
    assert_eq!(
        prepare_entry(&a.acct, &a.personal, stranger.id(), &entry, 1).err(),
        Some(Error::NotActive)
    );
    let unknown = resign(
        &bytes,
        |b| b[SIGNER_AT..SIGNER_AT + 32].copy_from_slice(&stranger.id().0),
        &stranger.ordinary,
    );
    assert_eq!(
        open_entry(&a.acct, &a.personal, &unknown).err(),
        Some(Error::NotActive)
    );
    // Naming a head from before the Fold was added.
    let backdated = resign(
        &bytes,
        |b| {
            let position = b[HEAD_AT..HEAD_AT + 8].to_vec();
            let earlier = u64::from_be_bytes(position.try_into().unwrap()) - 1;
            b[HEAD_AT..HEAD_AT + 8].copy_from_slice(&earlier.to_be_bytes());
            b[HEAD_AT + 8..HEAD_AT + 40].copy_from_slice(&before_fold.head().hash);
        },
        &fold.ordinary,
    );
    assert_eq!(
        open_entry(&a.acct, &a.personal, &backdated).err(),
        Some(Error::NotActive)
    );
    // Once the Fold has left, what it signed is refused.
    let left = signed(a.acct.remove_self(fold.id()).unwrap(), &fold.control);
    a.acct.apply_timed(left.as_bytes(), t(10, 10)).unwrap();
    assert_eq!(
        open_entry(&a.acct, &a.personal, &bytes).err(),
        Some(Error::NotActive)
    );
}

#[test]
fn password_check_from_before_a_kit_change_is_refused() {
    let mut a = account("correct horse");
    let check = make_password_check(&a.password).unwrap();
    let digest = a.acct.record_digest().unwrap();
    assert_eq!(
        prepare_entry(
            &a.acct,
            &a.personal,
            a.mac.id(),
            &DirectoryEntry::PasswordCheck {
                check: make_password_check(&a.password).unwrap(),
                record_digest: [0; 32],
            },
            1
        )
        .err(),
        Some(Error::InvalidCredentials)
    );
    let entry = DirectoryEntry::PasswordCheck {
        check,
        record_digest: digest,
    };
    let bytes = write(&a, &a.mac, &entry, 1);
    let opened = open_entry(&a.acct, &a.personal, &bytes).unwrap();
    assert_eq!(
        opened.entry_id,
        entry_id(&directory_key(&a.personal), &EntrySubject::PasswordCheck)
    );
    let DirectoryEntry::PasswordCheck {
        check,
        record_digest,
    } = opened.entry
    else {
        panic!("not a password check");
    };
    assert_eq!(record_digest, digest);
    assert_eq!(verify_password(&check, &a.password), Ok(()));
    assert_eq!(
        verify_password(&check, &Password::new("other").unwrap()),
        Err(Error::InvalidCredentials)
    );

    let replace = signed(
        a.acct
            .replace_recovery(
                a.mac.id(),
                RecoveryKeys::generate().public(),
                [6; 32],
                [7; 32],
            )
            .unwrap(),
        &a.mac.control,
    );
    a.acct.apply_timed(replace.as_bytes(), t(10, 10)).unwrap();
    assert_eq!(
        open_entry(&a.acct, &a.personal, &bytes).err(),
        Some(Error::InvalidCredentials)
    );
}

#[test]
fn base_entry_carries_only_the_current_key_package() {
    let a = account("correct horse");
    let base: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(11));
    let package = vec![0xa5; 1300];
    let metadata = vec![0x5a; 1499];
    let entry = DirectoryEntry::Base {
        base,
        server: "https://home.example".to_string(),
        epoch_id: [2; 32],
        current_key_seal: package.clone(),
        metadata_seal: metadata.clone(),
        own: true,
    };
    let bytes = write(&a, &a.mac, &entry, 1);
    assert!(!bytes.windows(32).any(|w| w == base));
    assert!(!bytes.windows(12).any(|w| w == b"home.example"));
    assert!(!bytes.windows(64).any(|w| w == &metadata[..64]));
    let opened = open_entry(&a.acct, &a.personal, &bytes).unwrap();
    assert_eq!(
        opened.entry_id,
        entry_id(&directory_key(&a.personal), &EntrySubject::Base(base))
    );
    // Exactly these fields: the base's metadata seal and its current epoch's
    // key, no keys for earlier epochs.
    let DirectoryEntry::Base {
        base: opened_base,
        server,
        epoch_id,
        current_key_seal,
        metadata_seal,
        own,
    } = opened.entry
    else {
        panic!("not a base entry");
    };
    assert_eq!(opened_base, base);
    assert_eq!(server, "https://home.example");
    assert_eq!(epoch_id, [2; 32]);
    assert_eq!(current_key_seal, package);
    assert_eq!(metadata_seal, metadata);
    assert!(own);
    // Another base's entry says it is not the own base.
    let other = DirectoryEntry::Base {
        base: [3; 32],
        server: "https://home.example".to_string(),
        epoch_id: [2; 32],
        current_key_seal: package.clone(),
        metadata_seal: metadata.clone(),
        own: false,
    };
    let opened = open_entry(&a.acct, &a.personal, &write(&a, &a.mac, &other, 1)).unwrap();
    assert!(matches!(
        opened.entry,
        DirectoryEntry::Base { own: false, .. }
    ));
    for (current_key_seal, metadata_seal) in [
        (vec![0; MAX_KEY_PACKAGE + 1], metadata.clone()),
        (package.clone(), vec![0; MAX_METADATA_SEAL + 1]),
    ] {
        let oversized = DirectoryEntry::Base {
            base,
            server: "https://home.example".to_string(),
            epoch_id: [2; 32],
            current_key_seal,
            metadata_seal,
            own: false,
        };
        assert_eq!(
            prepare_entry(&a.acct, &a.personal, a.mac.id(), &oversized, 1).err(),
            Some(Error::Malformed)
        );
    }
    // The largest base entry still fits one directory store.
    let largest = DirectoryEntry::Base {
        base,
        server: "h".repeat(255),
        epoch_id: [2; 32],
        current_key_seal: vec![1; MAX_KEY_PACKAGE],
        metadata_seal: vec![1; MAX_METADATA_SEAL],
        own: true,
    };
    let bytes = write(&a, &a.mac, &largest, 1);
    assert!(bytes.len() <= bh_account::directory::MAX_ENTRY && bytes.len() <= 65536);
    assert!(open_entry(&a.acct, &a.personal, &bytes).is_ok());
}

#[test]
fn a_signed_head_other_than_the_verified_one_is_a_fork() {
    let mut a = account("correct horse");
    let fold = Device::new();
    let added = add(&a.acct, &a.mac, &fold);
    a.acct.apply(added.as_bytes()).unwrap();
    let bytes = write(&a, &fold, &name(fold.id(), "Fold"), 1);
    assert!(open_entry(&a.acct, &a.personal, &bytes).is_ok());
    let forked = resign(
        &bytes,
        |b| b[HEAD_AT + 8..HEAD_AT + 40].copy_from_slice(&[9; 32]),
        &fold.ordinary,
    );
    assert_eq!(
        open_entry(&a.acct, &a.personal, &forked).err(),
        Some(Error::Fork)
    );
}

#[test]
fn reopened_reader_refuses_a_removed_signer_and_a_forked_cut() {
    let mut h = Harness::new();
    let (mut owner, cap) = h.signup();
    let fold = Other::new();
    owner_db::add(&mut owner, &cap, &fold, 1_000);
    let personal = ready(owner.open_current_personal(&cap)).unwrap();
    let view = owner.verified(&cap).unwrap().clone();
    let request = prepare_entry(&view, &personal, fold.id(), &name(fold.id(), "Fold"), 1).unwrap();
    let by_fold = request
        .finish(fold.ordinary.sign(request.signing_bytes()))
        .unwrap();
    let left = fold.sign_control(view.remove_self(fold.id()).unwrap());
    apply(&mut owner, &left, 2_000);
    let request = prepare_entry(
        owner.verified(&cap).unwrap(),
        &personal,
        cap.device_id(),
        &name(cap.device_id(), "Mac"),
        1,
    )
    .unwrap();
    let mine = ready(owner.sign_content(&cap, request.signing_bytes())).unwrap();
    let mine = request.finish(mine).unwrap();

    // Reopened, the reader's history is all behind its index cut.
    let (mut owner, cap) = h.restart();
    assert_eq!(
        open_entry(owner.verified(&cap).unwrap(), &personal, &by_fold).err(),
        Some(Error::NotActive)
    );
    let opened = ready(owner.open_directory_entries(&cap, &[&by_fold, &mine])).unwrap();
    assert!(matches!(
        opened[0],
        Err(EntryRefused::Invalid(Error::NotActive))
    ));
    assert!(opened[1].is_ok());
    let forked = DirectoryEntry::DeviceName {
        device: cap.device_id(),
        name: "Mac".to_string(),
    };
    let request = prepare_entry(
        owner.verified(&cap).unwrap(),
        &personal,
        cap.device_id(),
        &forked,
        2,
    )
    .unwrap();
    let mut unsigned = request.signing_bytes().to_vec();
    unsigned[HEAD_AT + 8..HEAD_AT + 40].copy_from_slice(&[9; 32]);
    let signature = ready(owner.sign_content(&cap, &unsigned)).unwrap();
    unsigned.extend(signature);
    let opened = ready(owner.open_directory_entries(&cap, &[&unsigned])).unwrap();
    assert!(matches!(opened[0], Err(EntryRefused::Invalid(Error::Fork))));
}

#[test]
fn a_remembered_directory_version_never_goes_back() {
    let mut h = Harness::new();
    let (mut owner, cap) = h.signup();
    let entry = name(cap.device_id(), "Work Mac");
    let [v1, v2, v3] =
        [1, 2, 3].map(|v| ready(owner.prepare_directory_entry(&cap, &entry, v)).unwrap());
    let opened = ready(owner.open_directory_entries(&cap, &[&v2])).unwrap();
    let opened = opened.into_iter().next().unwrap().ok().unwrap();
    assert_eq!(opened.version, 2);
    assert!(opened.signer == cap.device_id());
    let DirectoryEntry::DeviceName { name, .. } = opened.entry else {
        panic!("not a device name");
    };
    assert_eq!(name, "Work Mac");
    let lower = ready(owner.open_directory_entries(&cap, &[&v1])).unwrap();
    assert!(matches!(
        lower[0],
        Err(EntryRefused::LowerVersion { remembered: 2 })
    ));

    let (mut owner, cap) = h.restart();
    let opened = ready(owner.open_directory_entries(&cap, &[&v1, &v2, &v3, &v2])).unwrap();
    assert!(matches!(
        opened[0],
        Err(EntryRefused::LowerVersion { remembered: 2 })
    ));
    assert_eq!(opened[1].as_ref().ok().unwrap().version, 2);
    assert_eq!(opened[2].as_ref().ok().unwrap().version, 3);
    assert!(matches!(
        opened[3],
        Err(EntryRefused::LowerVersion { remembered: 3 })
    ));
}

#[test]
fn entries_under_a_rotated_away_key_are_ignored() {
    let h = Harness::new();
    let (mut owner, cap) = h.signup();
    let entry = name(cap.device_id(), "Work Mac");
    let old = ready(owner.prepare_directory_entry(&cap, &entry, 1)).unwrap();
    let fold = Other::new();
    owner_db::add(&mut owner, &cap, &fold, 1_000);
    let left = fold.sign_control(
        owner
            .verified(&cap)
            .unwrap()
            .remove_self(fold.id())
            .unwrap(),
    );
    apply(&mut owner, &left, 2_000);
    let staged = ready(owner.stage_rotation(&cap, 2_000)).unwrap();
    let position = apply_at(&mut owner, &staged.event, 2_100, 2_100);
    owner.settle_staged().unwrap().unwrap();
    ready(owner.accept_rotation(&cap, position, staged.body.as_ref().unwrap())).unwrap();
    let opened = ready(owner.open_directory_entries(&cap, &[&old])).unwrap();
    assert!(matches!(
        opened[0],
        Err(EntryRefused::Invalid(Error::InvalidCredentials))
    ));
    let new = ready(owner.prepare_directory_entry(&cap, &entry, 2)).unwrap();
    let opened = ready(owner.open_directory_entries(&cap, &[&new])).unwrap();
    assert_eq!(opened[0].as_ref().ok().unwrap().version, 2);
}

#[test]
fn an_out_of_range_version_is_skipped_not_the_whole_read() {
    let h = Harness::new();
    let (mut owner, cap) = h.signup();
    let entry = name(cap.device_id(), "Work Mac");
    assert_eq!(
        ready(owner.prepare_directory_entry(&cap, &entry, i64::MAX as u64 + 1)).err(),
        Some(bh_account::owner::OwnerError::Invalid(Error::Malformed))
    );
    let good = ready(owner.prepare_directory_entry(&cap, &entry, i64::MAX as u64)).unwrap();
    // The same entry, signed by this active device at a version storage
    // cannot keep.
    let mut huge = good[..good.len() - 64].to_vec();
    huge[ID_AT + 32..ID_AT + 40].copy_from_slice(&u64::MAX.to_be_bytes());
    let signature = ready(owner.sign_content(&cap, &huge)).unwrap();
    huge.extend(signature);
    let opened = ready(owner.open_directory_entries(&cap, &[&huge, &good])).unwrap();
    assert!(matches!(
        opened[0],
        Err(EntryRefused::Invalid(Error::Malformed))
    ));
    assert_eq!(opened[1].as_ref().ok().unwrap().version, i64::MAX as u64);
}

#[test]
fn an_entry_id_is_read_from_its_header_without_the_key() {
    let h = Harness::new();
    let (mut owner, cap) = h.signup();
    let bytes =
        ready(owner.prepare_directory_entry(&cap, &name(cap.device_id(), "Mac"), 3)).unwrap();
    let opened = ready(owner.open_directory_entries(&cap, &[&bytes])).unwrap();
    let opened = opened[0].as_ref().ok().unwrap();
    use bh_account::owner::staging::directory_entry_id;
    assert_eq!(directory_entry_id(&bytes), Some(opened.entry_id));
    assert_eq!(directory_entry_id(&bytes[..ID_AT + 31]), None);
    assert_eq!(directory_entry_id(b"not an entry, but long enough to have an id field at its offset.........................................................."), None);
}
