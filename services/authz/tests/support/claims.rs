//! Recovery claims as a recovering device makes them, against a home that
//! holds an account's recovery objects.
use super::*;
use bh_account::recovery::{self, Password, RecoveryClaim};
use bh_authz::{
    Connection, Service,
    proto::{FromService, RecoverPurpose, RecoveryAnswer, ToService},
};

pub const PASSWORD: &str = "correct horse battery";
pub const HOUR: u64 = 3_600_000;
pub const DAY: u64 = 86_400_000;

/// An account whose home holds its recovery objects, with right and wrong
/// claims made once: each try seals one again for a fresh nonce.
pub struct Home {
    pub signup: Signup,
    pub device: Device,
    pub right: RecoveryClaim,
    pub wrong_password: RecoveryClaim,
}
impl Home {
    pub async fn new(harness: &Harness, service: &Service) -> Self {
        let device = Device::new();
        let signup = Signup::new(&device, PASSWORD);
        harness.publish(&signup.account);
        let mut connection = session(service, &signup.account, &device).await;
        let answer = connection.handle(signup.store.clone()).await;
        assert!(
            matches!(answer, FromService::HomeObjectsStored { .. }),
            "{answer:?}"
        );
        let right = recovery::claim(&Password::new(PASSWORD).unwrap(), &signup.code).unwrap();
        let wrong_password =
            recovery::claim(&Password::new("wrong horse").unwrap(), &signup.code).unwrap();
        Self {
            signup,
            device,
            right,
            wrong_password,
        }
    }
    pub fn released(&self) -> RecoveryAnswer {
        RecoveryAnswer::Released {
            genesis: self.signup.account.genesis.clone(),
            record: self.signup.record.clone(),
            recovery_seal: self.signup.recovery_seal.clone(),
        }
    }
}

/// `claim` sealed to the harness's home key for `nonce` and `purpose`.
pub fn sealed(
    harness: &Harness,
    claim: &RecoveryClaim,
    nonce: [u8; 32],
    purpose: RecoverPurpose,
) -> ToService {
    ToService::Recover {
        sealed: recovery::seal_claim(
            &harness.recovery_certificate().public,
            claim,
            &nonce,
            purpose as u8,
        )
        .unwrap(),
        purpose,
    }
}

/// One claim on `connection`, sealed for its challenge.
pub async fn try_on(
    harness: &Harness,
    connection: &mut Connection,
    challenge: [u8; 32],
    claim: &RecoveryClaim,
    purpose: RecoverPurpose,
) -> FromService {
    connection
        .handle(sealed(harness, claim, challenge, purpose))
        .await
}

/// One AddDevice claim on a fresh connection.
pub async fn try_claim(harness: &Harness, service: &Service, claim: &RecoveryClaim) -> FromService {
    let (mut connection, _, challenge) = connect(service);
    try_on(
        harness,
        &mut connection,
        challenge,
        claim,
        RecoverPurpose::AddDevice,
    )
    .await
}

pub fn mismatch(tries_left: u8, next_try_ms: Option<u64>) -> FromService {
    FromService::Recovery(RecoveryAnswer::PasswordMismatch {
        tries_left,
        next_try_ms,
    })
}
pub fn wait(next_try_ms: u64) -> FromService {
    FromService::Recovery(RecoveryAnswer::Wait { next_try_ms })
}
pub const NOT_RECOGNISED: FromService = FromService::Recovery(RecoveryAnswer::NotRecognised);
