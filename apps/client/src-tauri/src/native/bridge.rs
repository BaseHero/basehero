//! Mac platform bridge for the first-account screens: the M1 login Keychain
//! device store, the per-setup pending blob protector, and the system kit
//! destinations. The non-macOS build uses `account_stub` instead so the whole
//! crate still compiles and checks on the CI machines.
use super::kit;
pub(crate) use super::kit::Destination;
pub(crate) use super::macos::{
    MacLoginKeyStore as LoginStore, MacPendingSetupProtector as KitProtector,
};

pub(crate) fn email_kit(code: &bh_account::recovery::RecoveryCode) -> Result<Destination, ()> {
    kit::email(code)
}

pub(crate) async fn save_kit_file(
    code: &bh_account::recovery::RecoveryCode,
) -> Result<Destination, ()> {
    kit::save_file(code).await
}
