//! Inactive macOS device-secret adapter. This module is compiled, not run at
//! startup or callable from a WebView. Runtime keychain/authentication policy
//! needs separately authorized testing. The M1 login-keychain route needs no
//! Apple entitlement. The existing M2 data-protection route is kept below but
//! has no caller or runtime selection; it requires a provisioned app identity.
use bh_account::{
    DevicePublicKeys,
    crypto::{self, KemKey, Secret, SecretBytes, SigningKey},
    platform::{
        ControlKeyPolicy, DeviceKeyStore, DeviceKeyStoreKind, KeyHandle, KeyStoreError,
        StoredDevice,
    },
};
use bh_mac_local_auth::{GateError, approve_control};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    passwords::{
        AccessControlOptions, PasswordOptions, delete_generic_password_options, generic_password,
        set_generic_password_options,
    },
};

const SERVICE: &str = "app.basehero.client.device-keys.v1"; // M2 only
const LOGIN_SERVICE: &str = "app.basehero.client.device-keys.login-v1"; // M1 only
const ORDINARY: &str = "ordinary";
const RECEIVER: &str = "receiver";
const CONTROL: &str = "control";
const VERSION: u8 = 1;

/// Only the three roles under one fresh 256-bit namespace can form a device.
/// The caller must persist the returned handle *and* original verified account
/// history; this adapter cannot commit the OS keychain and SQLite atomically.
pub(super) struct MacKeyStore;

fn name(handle: &KeyHandle, role: &str) -> String {
    let mut s = String::with_capacity(64 + role.len() + 1);
    for byte in handle.0 {
        use std::fmt::Write;
        write!(s, "{byte:02x}").expect("writing to String");
    }
    s.push(':');
    s.push_str(role);
    s
}

fn options(handle: &KeyHandle, role: &str) -> PasswordOptions {
    let mut options = PasswordOptions::new_generic_password(SERVICE, &name(handle, role));
    // TN3137: macOS SecItem defaults to the *legacy file-based* keychain.
    // Touch ID access control requires the data-protection implementation.
    options.use_protected_keychain();
    options.set_access_synchronized(Some(false));
    options
}

fn status(error: security_framework::base::Error) -> KeyStoreError {
    status_code(error.code())
}

fn status_code(code: i32) -> KeyStoreError {
    match code {
        -128 => KeyStoreError::AuthenticationCancelled, // errSecUserCanceled
        -25300 => KeyStoreError::Invalidated,           // errSecItemNotFound
        -25293 | -25308 | -34018 => KeyStoreError::Unavailable, // failed auth, interaction, entitlement
        _ => KeyStoreError::StorageFailure,
    }
}

fn tag(policy: ControlKeyPolicy) -> u8 {
    match policy {
        ControlKeyPolicy::CurrentBiometricsOnly => 1,
        ControlKeyPolicy::DevicePasscodeWithoutBiometrics => 2,
        ControlKeyPolicy::AppEnforcedOwnerConfirmation => 3,
    }
}
fn policy(tag: u8) -> Result<ControlKeyPolicy, KeyStoreError> {
    match tag {
        1 => Ok(ControlKeyPolicy::CurrentBiometricsOnly),
        2 => Ok(ControlKeyPolicy::DevicePasscodeWithoutBiometrics),
        3 => Ok(ControlKeyPolicy::AppEnforcedOwnerConfirmation),
        _ => Err(KeyStoreError::StorageFailure),
    }
}

fn read(handle: &KeyHandle, role: &str) -> Result<(ControlKeyPolicy, Secret<32>), KeyStoreError> {
    // Adopt the returned allocation immediately, including every error path.
    // Security.framework's internal CFData copies are outside this owner.
    let item = SecretBytes::from_vec(generic_password(options(handle, role)).map_err(status)?);
    let bytes = item.expose();
    if bytes.len() != 34 || bytes[0] != VERSION {
        return Err(KeyStoreError::StorageFailure);
    }
    let policy = policy(bytes[1])?;
    // This data-protection store only ever holds the OS-bound biometric policy.
    // Refuse the M1 app-enforced policy and the unqualified passcode alternative.
    if policy != ControlKeyPolicy::CurrentBiometricsOnly {
        return Err(KeyStoreError::Unavailable);
    }
    let seed = Secret::from_slice(&bytes[2..]).map_err(|_| KeyStoreError::StorageFailure)?;
    Ok((policy, seed))
}

fn add(
    handle: &KeyHandle,
    role: &str,
    policy: ControlKeyPolicy,
    seed: &Secret<32>,
) -> Result<(), KeyStoreError> {
    let mut options = options(handle, role);
    if role == CONTROL {
        let constraint = match policy {
            // Neither USER_PRESENCE nor OR nor BIOMETRY_ANY: no passcode fallback,
            // and a changed enrolled biometric set invalidates this control item.
            ControlKeyPolicy::CurrentBiometricsOnly => AccessControlOptions::BIOMETRY_CURRENT_SET,
            // The account caller must qualify *absence* of usable biometrics
            // before requesting this alternative. Never downgrade on error.
            ControlKeyPolicy::DevicePasscodeWithoutBiometrics => {
                AccessControlOptions::DEVICE_PASSCODE
            }
            // The M1 app-enforced policy has no item-bound ACL and is never
            // written to this data-protection store; create refuses it first.
            ControlKeyPolicy::AppEnforcedOwnerConfirmation => {
                return Err(KeyStoreError::Unavailable);
            }
        };
        let acl = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            constraint.bits(),
        )
        .map_err(status)?;
        options.set_access_control(acl);
    } else {
        let acl = SecAccessControl::create_with_protection(
            Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
            0,
        )
        .map_err(status)?;
        options.set_access_control(acl);
    }
    let bytes = SecretBytes::from_parts(&[&[VERSION, tag(policy)], seed.expose()])
        .map_err(|_| KeyStoreError::StorageFailure)?;
    // The handle is freshly random and all three slots were probed empty. This
    // wrapper does an update on duplicate; never reuse a previous namespace.
    set_generic_password_options(bytes.expose(), options).map_err(status)
}

fn delete(handle: &KeyHandle, role: &str) -> Result<(), KeyStoreError> {
    delete_generic_password_options(options(handle, role)).map_err(status)
}

impl DeviceKeyStore for MacKeyStore {
    async fn create(&mut self, policy: ControlKeyPolicy) -> Result<StoredDevice, KeyStoreError> {
        // No OS biometric-availability qualifier is wired yet. A caller-supplied
        // request is not evidence that this Mac lacks qualifying biometrics;
        // refusing any other policy prevents an accidental downgrade. The M1
        // app-enforced policy belongs to MacLoginKeyStore, never this store.
        // A later adapter increment must qualify and test it on actual hardware.
        if policy != ControlKeyPolicy::CurrentBiometricsOnly {
            return Err(KeyStoreError::Unavailable);
        }
        let ordinary = SigningKey::generate();
        let control = SigningKey::generate();
        let receiver = KemKey::generate();
        let keys = DevicePublicKeys::new(ordinary.public(), control.public(), receiver.public())
            .map_err(|_| KeyStoreError::WrongKey)?;
        let handle = KeyHandle(crypto::random());
        // Reject an already occupied namespace, never intentionally overwrite an
        // admitted device. Any unexpected read error fails closed, not as empty.
        for role in [ORDINARY, RECEIVER, CONTROL] {
            match generic_password(options(&handle, role)) {
                Err(error) if error.code() == -25300 => {} // errSecItemNotFound
                Ok(bytes) => {
                    drop(SecretBytes::from_vec(bytes));
                    return Err(KeyStoreError::Unavailable);
                }
                Err(_) => return Err(KeyStoreError::Unavailable),
            }
        }
        add(&handle, ORDINARY, policy, &ordinary.export_seed())?;
        if let Err(error) = add(&handle, RECEIVER, policy, &receiver.export_seed()) {
            let _ = delete(&handle, ORDINARY); // inaccessible orphan on cleanup failure
            return Err(error);
        }
        // Write protected control LAST; no half-created returned identity.
        if let Err(error) = add(&handle, CONTROL, policy, &control.export_seed()) {
            let _ = delete(&handle, RECEIVER);
            let _ = delete(&handle, ORDINARY);
            return Err(error);
        }
        Ok(StoredDevice {
            handle,
            keys,
            policy,
            kind: DeviceKeyStoreKind::MacDataProtectionKeychainV1,
        })
    }

    async fn load(&mut self, handle: KeyHandle) -> Result<StoredDevice, KeyStoreError> {
        // Reading control enforces its item ACL, so load may prompt. Never cache a
        // decrypted control seed across requests; account owner must offload
        // interactive calls from the UI thread and recheck generation after await.
        let (ordinary_policy, ordinary) = read(&handle, ORDINARY)?;
        let (receiver_policy, receiver) = read(&handle, RECEIVER)?;
        let (control_policy, control) = read(&handle, CONTROL)?;
        if ordinary_policy != control_policy || receiver_policy != control_policy {
            return Err(KeyStoreError::WrongKey);
        }
        let keys = DevicePublicKeys::new(
            SigningKey::from_seed(&ordinary).public(),
            SigningKey::from_seed(&control).public(),
            KemKey::from_seed(&receiver).public(),
        )
        .map_err(|_| KeyStoreError::WrongKey)?;
        Ok(StoredDevice {
            handle,
            keys,
            policy: control_policy,
            kind: DeviceKeyStoreKind::MacDataProtectionKeychainV1,
        })
    }

    async fn sign_content(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        let (_, seed) = read(&handle, ORDINARY)?;
        Ok(SigningKey::from_seed(&seed).sign(&message))
    }

    async fn sign_control(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        // The protected item retrieval itself enforces the biometric-set (or
        // qualified passcode-only) ACL. A prompt result alone is not authority.
        let (_, seed) = read(&handle, CONTROL)?;
        Ok(SigningKey::from_seed(&seed).sign(&message))
    }

    async fn decapsulate(
        &mut self,
        handle: KeyHandle,
        ciphertext: [u8; 1120],
    ) -> Result<Secret<32>, KeyStoreError> {
        let (_, seed) = read(&handle, RECEIVER)?;
        crypto::decapsulate(&KemKey::from_seed(&seed), &ciphertext)
            .map_err(|_| KeyStoreError::WrongKey)
    }
}

/// M1 only: the ordinary login/file-based keychain. This store is constructed
/// independently from M2, never selected as a fallback from a protected-keychain
/// error. The account owner must persist kind+policy beside its signed history.
///
/// Owner contract: run the synchronous SecItem reads below off the UI thread and
/// hold no account/SQLite lock across the LA prompt; bind every call to the
/// exact request bytes and the account/window generation it was issued for; drop
/// obsolete pending operations and recheck the generation before consuming or
/// dispatching a result. It carries `AppEnforcedOwnerConfirmation`, meaning the
/// LA prompt below is a UI gate, NOT key-bound authentication. Code running as
/// this Mac user can bypass it and use the software control seed. Legacy
/// keychain ACLs may prompt again across unsigned/ad-hoc app updates.
pub(super) struct MacLoginKeyStore;

fn login_options(handle: &KeyHandle, role: &str) -> PasswordOptions {
    // No kSecUseDataProtectionKeychain and no synchronizable attribute: on a
    // Mac in user context SecItem defaults to the file-based login keychain.
    // Service differs from M2, so neither path reads the other's items.
    PasswordOptions::new_generic_password(LOGIN_SERVICE, &name(handle, role))
}

fn login_read(handle: &KeyHandle, role: &str) -> Result<Secret<32>, KeyStoreError> {
    let item =
        SecretBytes::from_vec(generic_password(login_options(handle, role)).map_err(status)?);
    let bytes = item.expose();
    if bytes.len() != 34 || bytes[0] != VERSION {
        return Err(KeyStoreError::StorageFailure);
    }
    if policy(bytes[1])? != ControlKeyPolicy::AppEnforcedOwnerConfirmation {
        return Err(KeyStoreError::WrongKey);
    }
    Secret::from_slice(&bytes[2..]).map_err(|_| KeyStoreError::StorageFailure)
}

fn login_add(handle: &KeyHandle, role: &str, seed: &Secret<32>) -> Result<(), KeyStoreError> {
    let bytes = SecretBytes::from_parts(&[
        &[VERSION, tag(ControlKeyPolicy::AppEnforcedOwnerConfirmation)],
        seed.expose(),
    ])
    .map_err(|_| KeyStoreError::StorageFailure)?;
    // macOS file-keychain default SecAccess trusts the creating app only for
    // restricted reads; never grant access to every app. Fresh 256-bit handle
    // and preflight avoid the wrapper's duplicate-item update behavior.
    set_generic_password_options(bytes.expose(), login_options(handle, role)).map_err(status)
}
fn login_delete(handle: &KeyHandle, role: &str) {
    let _ = delete_generic_password_options(login_options(handle, role));
}

impl DeviceKeyStore for MacLoginKeyStore {
    async fn create(&mut self, policy: ControlKeyPolicy) -> Result<StoredDevice, KeyStoreError> {
        if policy != ControlKeyPolicy::AppEnforcedOwnerConfirmation {
            return Err(KeyStoreError::Unavailable);
        }
        let ordinary = SigningKey::generate();
        let control = SigningKey::generate();
        let receiver = KemKey::generate();
        let keys = DevicePublicKeys::new(ordinary.public(), control.public(), receiver.public())
            .map_err(|_| KeyStoreError::WrongKey)?;
        let handle = KeyHandle(crypto::random());
        for role in [ORDINARY, RECEIVER, CONTROL] {
            match generic_password(login_options(&handle, role)) {
                Err(error) if error.code() == -25300 => {} // errSecItemNotFound
                Ok(bytes) => {
                    drop(SecretBytes::from_vec(bytes));
                    return Err(KeyStoreError::Unavailable);
                }
                Err(_) => return Err(KeyStoreError::Unavailable),
            }
        }
        login_add(&handle, ORDINARY, &ordinary.export_seed())?;
        if let Err(error) = login_add(&handle, RECEIVER, &receiver.export_seed()) {
            login_delete(&handle, ORDINARY);
            return Err(error);
        }
        if let Err(error) = login_add(&handle, CONTROL, &control.export_seed()) {
            login_delete(&handle, RECEIVER);
            login_delete(&handle, ORDINARY);
            return Err(error);
        }
        Ok(StoredDevice {
            handle,
            keys,
            policy,
            kind: DeviceKeyStoreKind::MacLoginKeychainV1,
        })
    }

    async fn load(&mut self, handle: KeyHandle) -> Result<StoredDevice, KeyStoreError> {
        // No LocalAuthentication prompt for ordinary content or receiver.
        // Load compares all three derived public halves; it is not authority
        // until the account owner compares them to original verified history.
        let ordinary = login_read(&handle, ORDINARY)?;
        let receiver = login_read(&handle, RECEIVER)?;
        let control = login_read(&handle, CONTROL)?;
        let keys = DevicePublicKeys::new(
            SigningKey::from_seed(&ordinary).public(),
            SigningKey::from_seed(&control).public(),
            KemKey::from_seed(&receiver).public(),
        )
        .map_err(|_| KeyStoreError::WrongKey)?;
        Ok(StoredDevice {
            handle,
            keys,
            policy: ControlKeyPolicy::AppEnforcedOwnerConfirmation,
            kind: DeviceKeyStoreKind::MacLoginKeychainV1,
        })
    }

    async fn sign_control(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        // Fresh context on every use; cancellation never signs. The gate is
        // consciously not cryptographically tied to keychain seed access.
        approve_control().await.map_err(|error| match error {
            GateError::AuthenticationCancelled => KeyStoreError::AuthenticationCancelled,
            GateError::Unavailable => KeyStoreError::Unavailable,
        })?;
        let seed = login_read(&handle, CONTROL)?;
        Ok(SigningKey::from_seed(&seed).sign(&message))
    }
    async fn sign_content(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        let seed = login_read(&handle, ORDINARY)?;
        Ok(SigningKey::from_seed(&seed).sign(&message))
    }
    async fn decapsulate(
        &mut self,
        handle: KeyHandle,
        ciphertext: [u8; 1120],
    ) -> Result<Secret<32>, KeyStoreError> {
        let seed = login_read(&handle, RECEIVER)?;
        crypto::decapsulate(&KemKey::from_seed(&seed), &ciphertext)
            .map_err(|_| KeyStoreError::WrongKey)
    }
}

// Compile-time trait conformance; no keychain call or platform prompt occurs.
const _: fn() = || {
    fn check<T: DeviceKeyStore>() {}
    check::<MacKeyStore>(); // retained M2 route, not selected
    check::<MacLoginKeyStore>(); // M1 route, likewise not wired yet
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn os_statuses_do_not_confuse_failed_auth_with_key_loss() {
        assert_eq!(status_code(-128), KeyStoreError::AuthenticationCancelled);
        assert_eq!(status_code(-25293), KeyStoreError::Unavailable);
        assert_eq!(status_code(-25300), KeyStoreError::Invalidated);
        assert_eq!(status_code(-25308), KeyStoreError::Unavailable);
        assert_eq!(status_code(-34018), KeyStoreError::Unavailable);
    }
}
