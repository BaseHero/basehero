//! An account with real recovery and personal-key materials, for tests that
//! open what they seal.
// Shared by independent test binaries, so not every helper is used by each.
#![allow(dead_code)]
use bh_account::{
    AccountEvent, AccountId, ConfirmedTime, DeviceId, DevicePublicKeys, SigningRequest,
    VerifiedAccount,
    crypto::{KemKey, SigningKey},
    personal::{PersonalKey, PreparedPublication, prepare_publication},
    recovery::{Password, PreparedRecoveryRecord, RecoveryCode, RecoveryKeys, prepare_record},
};

pub struct Device {
    pub ordinary: SigningKey,
    pub control: SigningKey,
    pub receiver: KemKey,
    pub public: DevicePublicKeys,
}
impl Device {
    pub fn new() -> Self {
        let ordinary = SigningKey::generate();
        let control = SigningKey::generate();
        let receiver = KemKey::generate();
        let public =
            DevicePublicKeys::new(ordinary.public(), control.public(), receiver.public()).unwrap();
        Self {
            ordinary,
            control,
            receiver,
            public,
        }
    }
    pub fn id(&self) -> DeviceId {
        self.public.id()
    }
}

pub struct Account {
    pub mac: Device,
    pub recovery: RecoveryKeys,
    pub password: Password,
    pub code: RecoveryCode,
    pub record: PreparedRecoveryRecord,
    pub personal: PersonalKey,
    pub publication: PreparedPublication,
    pub acct: VerifiedAccount,
}

pub fn t(earliest_ms: u64, latest_ms: u64) -> Option<ConfirmedTime> {
    Some(ConfirmedTime {
        earliest_ms,
        latest_ms,
    })
}

pub fn signed(request: SigningRequest, key: &SigningKey) -> AccountEvent {
    request.finish(key.sign(request.signing_bytes())).unwrap()
}

pub fn add(acct: &VerifiedAccount, by: &Device, new: &Device) -> AccountEvent {
    signed(
        acct.add_device(by.id(), new.public.clone()).unwrap(),
        &by.control,
    )
}

/// The Mac signs up with a real recovery record and personal key, untimed.
pub fn account(password: &str) -> Account {
    let mac = Device::new();
    let recovery = RecoveryKeys::generate();
    let code = RecoveryCode::generate();
    let password = Password::new(password).unwrap();
    let genesis = signed(
        AccountEvent::genesis(mac.public.clone(), recovery.public()),
        &mac.control,
    );
    let mut acct =
        VerifiedAccount::from_genesis(AccountId::of_genesis(&genesis).unwrap(), genesis.as_bytes())
            .unwrap();
    let record = prepare_record(&acct, &recovery, &password, &code).unwrap();
    let draft = acct
        .prepare_recovery_record(mac.id(), record.digest())
        .unwrap();
    acct.apply(signed(draft, &mac.control).as_bytes()).unwrap();
    let personal = PersonalKey::generate();
    let publication = prepare_publication(&acct, &personal).unwrap();
    let draft = acct
        .publish_personal_key(
            mac.id(),
            publication.public(),
            publication.device_digest(),
            publication.recovery_digest(),
        )
        .unwrap();
    acct.apply(signed(draft, &mac.control).as_bytes()).unwrap();
    Account {
        mac,
        recovery,
        password,
        code,
        record,
        personal,
        publication,
        acct,
    }
}
