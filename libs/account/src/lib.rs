//! Account history verification and device admission, independent of storage and UI.
//!
//! Account identities belong on devices, at their account home, and within
//! protected authority checking. Never copy these types into ordinary base
//! storage requests or diagnostics.

pub use bh_crypto as crypto;

mod alerts;
pub mod device_auth;
pub mod directory;
mod history;
mod home_objects;
pub mod journal;
pub mod local_seal;
pub mod owner;
pub mod pairing;
pub mod personal;
pub mod platform;
pub mod projection;
pub mod recovery;
pub mod storage;
mod trust;

pub use history::{
    AccountEvent, AccountId, ControlOutcome, DeviceId, DevicePublicKeys, Error, Head,
    PersonalPublication, RecoveryPublicKeys, SigningRequest, SignupKind, SignupMessage,
    VerifiedAccount,
};
pub use trust::{
    AccountChange, ConfirmedTime, CosigningRequest, DeviceState, PendingRemoval, REMOVAL_WAIT_MS,
    RequestState, RotationReason,
};
