use bh_account::personal::PersonalKey;
use bh_account::{AccountEvent, AccountId, DevicePublicKeys, RecoveryPublicKeys, VerifiedAccount};
use bh_crypto::{Secret, SigningKey, hash};
use bh_device::base_keys::{
    BaseKeyPurpose, InitialBaseKeyPackage, SealHeader, open_seal, prepare_seal,
};
use bh_event::key_id;
use bh_sync::BaseId;

fn fixture() -> (VerifiedAccount, SigningKey, PersonalKey) {
    let signer = SigningKey::generate();
    let control = SigningKey::generate();
    let device = DevicePublicKeys::new(signer.public(), control.public(), [3; 1216]).unwrap();
    let recovery = RecoveryPublicKeys::new([4; 32], [5; 1216]);
    let request = AccountEvent::genesis(device.clone(), recovery);
    let genesis = request
        .finish(control.sign(request.signing_bytes()))
        .unwrap();
    let mut account =
        VerifiedAccount::from_genesis(AccountId::of_genesis(&genesis).unwrap(), genesis.as_bytes())
            .unwrap();
    let request = account
        .prepare_recovery_record(device.id(), [6; 32])
        .unwrap();
    account
        .apply(
            request
                .finish(control.sign(request.signing_bytes()))
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    let personal = PersonalKey::generate();
    let request = account
        .publish_personal_key(device.id(), personal.public(), [7; 32], [8; 32])
        .unwrap();
    account
        .apply(
            request
                .finish(control.sign(request.signing_bytes()))
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    (account, signer, personal)
}

fn header(
    account: &VerifiedAccount,
    personal: &PersonalKey,
    purpose: BaseKeyPurpose,
    root: &Secret<32>,
) -> SealHeader {
    SealHeader {
        purpose,
        base: BaseId([10; 32]),
        audience: [0; 32],
        key_id: key_id(root),
        recipient: hash(&personal.public()),
        sender: account.id(),
        device: account.active_devices().unwrap().next().unwrap().id(),
        head: account.head(),
    }
}

#[test]
fn authenticated_roots_round_trip_and_package_retains_exact_signed_bytes() {
    let (account, signer, personal) = fixture();
    let m = Secret::random();
    let k = Secret::random();
    let mh = header(&account, &personal, BaseKeyPurpose::Metadata, &m);
    let kh = header(&account, &personal, BaseKeyPurpose::Content, &k);
    let seal = |h, root: &Secret<32>| {
        let request = prepare_seal(&account, h, &personal.public(), root).unwrap();
        assert_eq!(request.expected_key(), &signer.public());
        assert_eq!(
            &request.signing_bytes()[..30],
            b"BH base key seal signature v1\0"
        );
        let signature = signer.sign(request.signing_bytes());
        request.finish(signature).unwrap()
    };
    let ms = seal(mh, &m);
    let ks = seal(kh, &k);
    assert_eq!(ms.len(), 1499);
    assert_eq!(ks.len(), 1499);
    assert_eq!(SealHeader::decode(&ms).unwrap().encode().len(), 243);
    assert_eq!(
        open_seal(&account, &mh, &ms, &personal).unwrap().expose(),
        m.expose()
    );
    assert_eq!(
        open_seal(&account, &kh, &ks, &personal).unwrap().expose(),
        k.expose()
    );
    let package = InitialBaseKeyPackage::new(&ms, &ks).unwrap();
    assert_eq!(package.as_bytes().len(), 3016);
    assert_eq!(package.metadata_seal(), ms);
    assert_eq!(package.content_seal(), ks);
    assert_eq!(
        InitialBaseKeyPackage::decode(package.as_bytes())
            .unwrap()
            .as_bytes(),
        package.as_bytes()
    );
    assert!(InitialBaseKeyPackage::new(&ks, &ms).is_err());
    for index in [8, 10, 13, 1513, 1516] {
        let mut changed = package.as_bytes().to_vec();
        changed[index] ^= 1;
        assert!(
            InitialBaseKeyPackage::decode(&changed).is_err(),
            "accepted framing mutation at {index}"
        );
    }
    let mut trailing = package.as_bytes().to_vec();
    trailing.push(0);
    assert!(InitialBaseKeyPackage::decode(&trailing).is_err());
    // A signature must authenticate even length-preserving ciphertext changes.
    for index in [
        11, 43, 75, 107, 139, 171, 203, 211, 243, 1363, 1387, 1435, 1498,
    ] {
        let mut changed = ms.clone();
        changed[index] ^= 1;
        assert!(
            open_seal(&account, &mh, &changed, &personal).is_err(),
            "accepted mutation at {index}"
        );
    }
    assert!(open_seal(&account, &mh, &ms, &PersonalKey::generate()).is_err());
    let mut wrong = mh;
    wrong.key_id = [9; 32];
    assert!(open_seal(&account, &wrong, &ms, &personal).is_err());
    wrong = mh;
    wrong.audience = [1; 32];
    assert!(open_seal(&account, &wrong, &ms, &personal).is_err());
    // A different historical head is not interchangeable, even with the same key.
    let other = fixture().0;
    assert!(open_seal(&other, &mh, &ms, &personal).is_err());
}

#[test]
fn valid_sender_cannot_seal_a_different_root_under_a_committed_id() {
    let (account, signer, personal) = fixture();
    let root = Secret::random();
    let expected = header(&account, &personal, BaseKeyPurpose::Metadata, &root);
    // Independent malicious producer: valid signature and AEAD, wrong plaintext
    // for the signed id. AEAD alone does not commit to the intended root.
    let (ct, shared) = bh_crypto::encapsulate(&personal.public()).unwrap();
    let encryption = bh_crypto::derive_key(&shared, b"BHBKEY01", 1);
    let mut bytes = expected.encode();
    let (nonce, encrypted) =
        bh_crypto::aead_seal(&encryption, &bytes, Secret::<32>::random().expose()).unwrap();
    bytes.extend(ct);
    bytes.extend(nonce);
    bytes.extend(encrypted);
    let signature = signer.sign(&[b"BH base key seal signature v1\0".as_slice(), &bytes].concat());
    bytes.extend(signature);
    assert!(matches!(
        open_seal(&account, &expected, &bytes, &personal),
        Err(bh_device::base_keys::SealError::Context)
    ));
    let mut changed = expected;
    changed.head.hash[0] ^= 1;
    assert!(prepare_seal(&account, changed, &personal.public(), &root).is_err());
}

#[test]
fn truncated_frames_and_same_length_package_context_swaps_are_refused() {
    let raw = include_str!("fixtures/base-key-package-v1.hex")
        .trim()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    for len in [0, 8, 9, 10, 13, 14, 243, 1498, 1499, 3015] {
        assert!(InitialBaseKeyPackage::decode(&raw[..len]).is_err());
    }
    for offset in [
        14 + 8,
        14 + 10,
        14 + 11,
        14 + 43,
        14 + 107,
        14 + 139,
        14 + 171,
        14 + 203,
        14 + 211,
    ] {
        let mut altered = raw.clone();
        altered[offset] ^= 1;
        assert!(
            InitialBaseKeyPackage::decode(&altered).is_err(),
            "accepted context change at {offset}"
        );
    }
}

#[test]
fn mismatched_root_or_recipient_and_unverified_signature_cannot_be_prepared() {
    let (account, signer, personal) = fixture();
    let root = Secret::random();
    let h = header(&account, &personal, BaseKeyPurpose::Metadata, &root);
    assert!(prepare_seal(&account, h, &personal.public(), &Secret::random()).is_err());
    assert!(prepare_seal(&account, h, &PersonalKey::generate().public(), &root).is_err());
    let other = PersonalKey::generate();
    let mut foreign = h;
    foreign.recipient = hash(&other.public());
    assert!(prepare_seal(&account, foreign, &other.public(), &root).is_err());
    let request = prepare_seal(&account, h, &personal.public(), &root).unwrap();
    assert!(request.finish(signer.sign(b"different domain")).is_err());
}
