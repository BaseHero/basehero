#[path = "support/account.rs"]
mod account;
use account::{account, signed, t};

use bh_account::{
    Error,
    crypto::KemKey,
    personal::{open_for_recovery, seal_digest, seal_for_new_recovery},
    recovery::{
        Password, PasswordCheck, RecoveryCode, RecoveryKeys, account_of_record, claim,
        make_password_check, open_claim, open_current_record, prepare_replacement, record_checks,
        seal_claim, verify_password,
    },
};

#[test]
fn claim_checks_equal_the_record_fields() {
    let a = account("correct horse");
    let record = a.record.as_bytes();
    let claim = claim(&a.password, &a.code).unwrap();
    assert_eq!(claim.token_check().as_slice(), &record[178..210]);
    assert_eq!(claim.proof_check().as_slice(), &record[210..242]);
    let checks = record_checks(record).unwrap();
    assert!(checks.account == a.acct.id());
    assert_eq!(checks.token_check, claim.token_check());
    assert_eq!(checks.proof_check, claim.proof_check());
    assert_eq!(checks.digest, a.record.digest());
    assert_eq!(record_checks(&record[1..]).err(), Some(Error::Malformed));
    let mut prefix = record.to_vec();
    prefix[0] ^= 1;
    assert_eq!(record_checks(&prefix).err(), Some(Error::Malformed));
}

#[test]
fn a_wrong_password_changes_only_the_token() {
    let a = account("correct horse");
    let right = claim(&a.password, &a.code).unwrap();
    let wrong = claim(&Password::new("correct horse!").unwrap(), &a.code).unwrap();
    assert_eq!(wrong.proof_check(), right.proof_check());
    assert_ne!(wrong.token_check(), right.token_check());
    let other_code = claim(&a.password, &RecoveryCode::generate()).unwrap();
    assert_ne!(other_code.proof_check(), right.proof_check());
    assert_ne!(other_code.token_check(), right.token_check());
}

#[test]
fn sealed_claim_opens_only_with_its_nonce_and_purpose() {
    let a = account("correct horse");
    let home = KemKey::generate();
    let made = claim(&a.password, &a.code).unwrap();
    let nonce = [7; 32];
    let sealed = seal_claim(&home.public(), &made, &nonce, 2).unwrap();
    let (opened, purpose) = open_claim(&home, &sealed, &nonce).unwrap();
    assert_eq!(purpose, 2);
    assert_eq!(opened.proof_check(), made.proof_check());
    assert_eq!(opened.token_check(), made.token_check());
    // Nothing about the code or token is visible in the sealed request.
    for check in [made.proof_check(), made.token_check()] {
        assert!(!sealed.windows(32).any(|w| w == check));
    }
    assert_eq!(
        open_claim(&home, &sealed, &[8; 32]).err(),
        Some(Error::InvalidCredentials)
    );
    assert_eq!(
        open_claim(&KemKey::generate(), &sealed, &nonce).err(),
        Some(Error::InvalidCredentials)
    );
    let mut other_purpose = sealed.clone();
    other_purpose[10] = 1;
    assert_eq!(
        open_claim(&home, &other_purpose, &nonce).err(),
        Some(Error::InvalidCredentials)
    );
    let mut tampered = sealed.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert_eq!(
        open_claim(&home, &tampered, &nonce).err(),
        Some(Error::InvalidCredentials)
    );
    assert_eq!(
        open_claim(&home, &sealed[..sealed.len() - 1], &nonce).err(),
        Some(Error::Malformed)
    );
}

#[test]
fn kit_text_variants_parse_and_a_typo_never_leaves_the_device() {
    let code = RecoveryCode::from_raw(&[
        0x3c, 0x91, 0x05, 0xe7, 0x42, 0xaa, 0x18, 0x6d, 0xf0, 0x0b, 0x77, 0x2e, 0xc4, 0x59, 0x81,
        0xd3,
    ]);
    let printed = code.to_kit_text();
    let variants = [
        printed.clone(),
        printed.to_ascii_lowercase(),
        printed.replace('-', " "),
        printed.replace('-', ""),
        printed.replace('-', "  ").to_ascii_lowercase(),
    ];
    for variant in variants {
        assert_eq!(
            RecoveryCode::from_kit_text(&variant).unwrap().expose(),
            code.expose()
        );
    }
    // One changed symbol in the data or the checksum is caught locally, so no
    // claim is ever made from it.
    let symbols: Vec<u8> = printed.bytes().filter(|b| *b != b'-').collect();
    for index in (0..28).filter(|index| *index != 25) {
        let mut typo = symbols.clone();
        typo[index] = if typo[index] == b'K' { b'L' } else { b'K' };
        let typo = String::from_utf8(typo).unwrap();
        assert_eq!(
            RecoveryCode::from_kit_text(&typo).err(),
            Some(Error::InvalidCredentials),
            "symbol {index}"
        );
    }
}

#[test]
fn replacement_record_opens_with_new_kit_and_old_kit_fails() {
    let mut a = account("correct horse");
    let keys = RecoveryKeys::generate();
    let code = RecoveryCode::generate();
    let password = Password::new("battery staple").unwrap();
    // A replacement must be a new recovery key.
    assert_eq!(
        prepare_replacement(&a.acct, &a.recovery, &password, &code).err(),
        Some(Error::KeyReuse)
    );
    let record = prepare_replacement(&a.acct, &keys, &password, &code).unwrap();
    let seal = seal_for_new_recovery(&a.acct, &a.personal, &keys.public()).unwrap();
    // Before the change is applied, the replacement opens nothing.
    assert_eq!(
        open_current_record(&a.acct, record.as_bytes(), &password, &code).err(),
        Some(Error::InvalidCredentials)
    );
    let event = signed(
        a.acct
            .replace_recovery(
                a.mac.id(),
                keys.public(),
                record.digest(),
                seal_digest(&seal),
            )
            .unwrap(),
        &a.mac.control,
    );
    a.acct.apply_timed(event.as_bytes(), t(10, 10)).unwrap();
    assert_eq!(a.acct.record_digest().unwrap(), record.digest());

    let opened = open_current_record(&a.acct, record.as_bytes(), &password, &code).unwrap();
    assert_eq!(opened.public().signing(), keys.public().signing());
    assert_eq!(
        open_for_recovery(&a.acct, &seal, opened.receiver())
            .unwrap()
            .public(),
        a.personal.public()
    );
    // The old record, the old code and the old seal no longer open.
    assert_eq!(
        open_current_record(&a.acct, a.record.as_bytes(), &a.password, &a.code).err(),
        Some(Error::InvalidCredentials)
    );
    assert_eq!(
        open_current_record(&a.acct, record.as_bytes(), &password, &a.code).err(),
        Some(Error::InvalidCredentials)
    );
    assert!(
        open_for_recovery(
            &a.acct,
            a.publication.recovery_seal(),
            a.recovery.receiver()
        )
        .is_err()
    );
    // The same password with a new code is a replacement too.
    let same = prepare_replacement(&a.acct, &RecoveryKeys::generate(), &password, &code).unwrap();
    assert_ne!(same.digest(), record.digest());
}

#[test]
fn released_record_names_its_account() {
    let a = account("correct horse");
    let record = a.record.as_bytes();
    assert!(account_of_record(record, &a.password, &a.code).unwrap() == a.acct.id());
    assert_eq!(
        account_of_record(record, &Password::new("wrong").unwrap(), &a.code).err(),
        Some(Error::InvalidCredentials)
    );
    assert_eq!(
        account_of_record(record, &a.password, &RecoveryCode::generate()).err(),
        Some(Error::InvalidCredentials)
    );
    // A home naming another account in the record cannot redirect the anchor.
    let other = account("correct horse");
    let mut relabelled = record.to_vec();
    relabelled[10..42].copy_from_slice(&other.acct.id().0);
    assert_eq!(
        account_of_record(&relabelled, &a.password, &a.code).err(),
        Some(Error::InvalidCredentials)
    );
    assert_eq!(
        account_of_record(&record[..241], &a.password, &a.code).err(),
        Some(Error::Malformed)
    );
}

#[test]
fn password_check_accepts_only_its_password() {
    let password = Password::new("correct horse").unwrap();
    let check = make_password_check(&password).unwrap();
    assert_eq!(verify_password(&check, &password), Ok(()));
    assert_eq!(
        verify_password(&check, &Password::new("correct horsE").unwrap()),
        Err(Error::InvalidCredentials)
    );
    let encoded = check.encode();
    let decoded = PasswordCheck::decode(encoded.expose()).unwrap();
    assert_eq!(verify_password(&decoded, &password), Ok(()));
    // A random salt: two checks of one password differ.
    let again = make_password_check(&password).unwrap();
    assert_ne!(again.encode().expose(), encoded.expose());
    assert_eq!(
        PasswordCheck::decode(&encoded.expose()[1..]).err(),
        Some(Error::Malformed)
    );
}
