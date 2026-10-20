//! Account history verification and device admission, independent of storage and UI.
//!
//! Account identities belong on devices, at their account home, and within
//! protected authority checking. Never copy these types into ordinary base
//! storage requests or diagnostics.

pub use bh_crypto as crypto;

pub mod device_auth;
mod history;
mod home_objects;
pub mod journal;
pub mod owner;
pub mod pairing;
pub mod personal;
pub mod platform;
pub mod recovery;
pub mod storage;

pub use history::{
    AccountEvent, AccountId, DeviceId, DevicePublicKeys, Error, Head, PersonalPublication,
    RecoveryPublicKeys, SigningRequest, SignupKind, SignupMessage, VerifiedAccount,
};
