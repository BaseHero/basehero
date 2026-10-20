//! Inactive macOS device-secret adapter. This module is compiled, not run at
//! startup or callable from a WebView. Runtime keychain/authentication policy
//! needs separately authorized testing. The M1 login-keychain route needs no
//! Apple entitlement. The existing M2 data-protection route is kept below but
//! has no caller or runtime selection; it requires a provisioned app identity.
use bh_account::{
    DevicePublicKeys,
    crypto::{self, KemKey, Secret, SecretBytes, SigningKey},
    journal::{PendingSetupProtector, ProtectorError, open_pending_setup, seal_pending_setup},
    platform::{
        ControlKeyPolicy, DeviceKeyStore, DeviceKeyStoreKind, KeyHandle, KeyStoreError,
        StoredDevice,
    },
};
use bh_mac_keychain_helper::{HelperError, Item, Request, process::HelperProcess};
use bh_mac_local_auth::{GateError, approve_control};
use security_framework::{
    access_control::{ProtectionMode, SecAccessControl},
    passwords::{
        AccessControlOptions, PasswordOptions, delete_generic_password_options, generic_password,
        set_generic_password_options,
    },
};

const SERVICE: &str = concat!(env!("BH_APP_IDENTIFIER"), ".device-keys.v1"); // M2 only
const ORDINARY: &str = "ordinary";
const RECEIVER: &str = "receiver";
const CONTROL: &str = "control";
const CONTROL_PUBLIC: &str = "control-public";
const VERSION: u8 = 1;
const WRAPPING_KEY_LEN: usize = 32;
const PENDING_KIT: u8 = 1;
const PENDING_HOME: u8 = 2;

/// All four roles under one fresh 256-bit namespace form a device.
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

// A refused login-keychain read is not proof that a key was lost. Surface it
// as a failed unlock, then wait for the person's explicit Try again action.
fn login_status_code(code: i32) -> KeyStoreError {
    match code {
        -25293 | -25308 => KeyStoreError::AuthenticationCancelled,
        other => status_code(other),
    }
}

#[cfg(test)]
mod login_error_tests {
    use super::*;
    #[test]
    fn refused_login_keychain_access_is_retryable_not_lost_identity() {
        for code in [-128, -25293, -25308] {
            assert_eq!(
                login_status_code(code),
                KeyStoreError::AuthenticationCancelled
            );
        }
        assert_eq!(login_status_code(-25300), KeyStoreError::Invalidated);
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
    // The handle is freshly random and all four slots were probed empty. This
    // wrapper does an update on duplicate; never reuse a previous namespace.
    set_generic_password_options(bytes.expose(), options).map_err(status)
}

// Public metadata is in the same handle's keychain namespace but not behind
// the control ACL. The account owner also matches it to signed device history.
fn protected_control_public(handle: &KeyHandle) -> Result<[u8; 32], KeyStoreError> {
    let item =
        SecretBytes::from_vec(generic_password(options(handle, CONTROL_PUBLIC)).map_err(status)?);
    let bytes = item.expose();
    if bytes.len() != 34
        || bytes[0] != VERSION
        || policy(bytes[1])? != ControlKeyPolicy::CurrentBiometricsOnly
    {
        return Err(KeyStoreError::WrongKey);
    }
    bytes[2..].try_into().map_err(|_| KeyStoreError::WrongKey)
}
fn add_protected_public(handle: &KeyHandle, public: &[u8; 32]) -> Result<(), KeyStoreError> {
    let bytes = SecretBytes::from_parts(&[
        &[VERSION, tag(ControlKeyPolicy::CurrentBiometricsOnly)],
        public,
    ])
    .map_err(|_| KeyStoreError::StorageFailure)?;
    set_generic_password_options(bytes.expose(), options(handle, CONTROL_PUBLIC)).map_err(status)
}

fn delete(handle: &KeyHandle, role: &str) -> Result<(), KeyStoreError> {
    delete_generic_password_options(options(handle, role)).map_err(status)
}

// The same load decision is executed with each route's actual Keychain I/O.
// Unit tests inject only that I/O, never a second implementation of load.
trait IdentityIo {
    fn ordinary(&mut self, handle: &KeyHandle) -> Result<[u8; 32], KeyStoreError>;
    fn receiver(&mut self, handle: &KeyHandle) -> Result<[u8; 1216], KeyStoreError>;
    fn control_public(&mut self, handle: &KeyHandle) -> Result<[u8; 32], KeyStoreError>;
    fn control(&mut self, handle: &KeyHandle) -> Result<SigningKey, KeyStoreError>;
}
fn loaded_keys(
    io: &mut impl IdentityIo,
    handle: &KeyHandle,
) -> Result<DevicePublicKeys, KeyStoreError> {
    let ordinary = io.ordinary(handle)?;
    let receiver = io.receiver(handle)?;
    let control_public = io.control_public(handle)?;
    DevicePublicKeys::new(ordinary, control_public, receiver).map_err(|_| KeyStoreError::WrongKey)
}
fn sign_with_control(
    io: &mut impl IdentityIo,
    handle: &KeyHandle,
    message: &[u8],
) -> Result<[u8; 64], KeyStoreError> {
    Ok(io.control(handle)?.sign(message))
}
struct ProtectedIdentityIo;
impl IdentityIo for ProtectedIdentityIo {
    fn ordinary(&mut self, handle: &KeyHandle) -> Result<[u8; 32], KeyStoreError> {
        let (policy, seed) = read(handle, ORDINARY)?;
        if policy != ControlKeyPolicy::CurrentBiometricsOnly {
            return Err(KeyStoreError::WrongKey);
        }
        Ok(SigningKey::from_seed(&seed).public())
    }
    fn receiver(&mut self, handle: &KeyHandle) -> Result<[u8; 1216], KeyStoreError> {
        let (policy, seed) = read(handle, RECEIVER)?;
        if policy != ControlKeyPolicy::CurrentBiometricsOnly {
            return Err(KeyStoreError::WrongKey);
        }
        Ok(KemKey::from_seed(&seed).public())
    }
    fn control_public(&mut self, handle: &KeyHandle) -> Result<[u8; 32], KeyStoreError> {
        protected_control_public(handle)
    }
    fn control(&mut self, handle: &KeyHandle) -> Result<SigningKey, KeyStoreError> {
        let (policy, seed) = read(handle, CONTROL)?;
        if policy != ControlKeyPolicy::CurrentBiometricsOnly {
            return Err(KeyStoreError::WrongKey);
        }
        Ok(SigningKey::from_seed(&seed))
    }
}
struct LoginIdentityIo;
impl IdentityIo for LoginIdentityIo {
    fn ordinary(&mut self, handle: &KeyHandle) -> Result<[u8; 32], KeyStoreError> {
        Ok(SigningKey::from_seed(&login_read(handle, ORDINARY)?).public())
    }
    fn receiver(&mut self, handle: &KeyHandle) -> Result<[u8; 1216], KeyStoreError> {
        Ok(KemKey::from_seed(&login_read(handle, RECEIVER)?).public())
    }
    fn control_public(&mut self, handle: &KeyHandle) -> Result<[u8; 32], KeyStoreError> {
        login_control_public(handle)
    }
    fn control(&mut self, handle: &KeyHandle) -> Result<SigningKey, KeyStoreError> {
        Ok(SigningKey::from_seed(&login_read(handle, CONTROL)?))
    }
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
        for role in [ORDINARY, RECEIVER, CONTROL, CONTROL_PUBLIC] {
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
        // A returned identity needs both control and metadata; failure rolls back.
        if let Err(error) = add(&handle, CONTROL, policy, &control.export_seed()) {
            let _ = delete(&handle, RECEIVER);
            let _ = delete(&handle, ORDINARY);
            return Err(error);
        }
        if let Err(error) = add_protected_public(&handle, &control.public()) {
            let _ = delete(&handle, CONTROL);
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
        let keys = loaded_keys(&mut ProtectedIdentityIo, &handle)?;
        Ok(StoredDevice {
            handle,
            keys,
            policy: ControlKeyPolicy::CurrentBiometricsOnly,
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
        sign_with_control(&mut ProtectedIdentityIo, &handle, &message)
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
/// this Mac user can bypass it and use the software control seed. The legacy
/// keychain asks again only when the Keychain helper's own bytes change.
///
/// One confirmed first-device genesis covers its two chained setup events;
/// a confirmed pairing addition covers its one exact base copy. Every later
/// control action asks again (`bh_host::confirm`). Clones share one gate.
#[derive(Clone, Default)]
pub(crate) struct MacLoginKeyStore {
    gate: bh_host::confirm::ActionGate,
}

async fn approve() -> Result<(), KeyStoreError> {
    approve_control().await.map_err(|error| match error {
        GateError::AuthenticationCancelled => KeyStoreError::AuthenticationCancelled,
        GateError::Unavailable => KeyStoreError::Unavailable,
    })
}

impl bh_host::accounts::HostKeyStore for MacLoginKeyStore {
    const JOIN_POLICY: ControlKeyPolicy = ControlKeyPolicy::AppEnforcedOwnerConfirmation;
    fn action_gate(&self) -> Option<bh_host::confirm::ActionGate> {
        Some(self.gate.clone())
    }
    fn confirm_owner(&mut self) -> impl std::future::Future<Output = Result<(), KeyStoreError>> {
        approve()
    }
}

/// Every M1 login-keychain call goes through the Keychain helper beside the
/// app executable. The helper creates the items, so their access list and
/// partition name the helper, whose bytes stay the same across app updates.
/// It stores them as before: generic passwords in the file-based login
/// keychain, service `<identifier>.device-keys.login-v1` (or
/// `.pending-setup.login-v2`), account `<hex handle>:<role>`.
fn helper() -> &'static HelperProcess {
    static HELPER: std::sync::LazyLock<HelperProcess> = std::sync::LazyLock::new(|| {
        let program = std::env::current_exe()
            .ok()
            .and_then(|exe| Some(exe.parent()?.join("bh-keychain-helper")))
            .unwrap_or_default();
        HelperProcess::new(program, Vec::new())
    });
    &HELPER
}

fn login_item(handle: &KeyHandle, role: &str) -> Item {
    match role {
        ORDINARY => Item::Ordinary(handle.0),
        RECEIVER => Item::Receiver(handle.0),
        CONTROL => Item::Control(handle.0),
        CONTROL_PUBLIC => Item::ControlPublic(handle.0),
        _ => unreachable!("not a device key role"),
    }
}

// The OSStatus from the helper keeps today's meaning; a helper that is
// missing, refuses us or breaks the protocol is a local failure, not key loss.
fn helper_code(error: HelperError, map: fn(i32) -> KeyStoreError) -> KeyStoreError {
    match error {
        HelperError::Status(code) => map(code),
        HelperError::Unavailable => KeyStoreError::StorageFailure,
    }
}

fn helper_read(item: Item) -> Result<SecretBytes, HelperError> {
    // Adopt the returned allocation at once; the helper's buffer is wiped on drop.
    helper()
        .call(&Request::Read(item))
        .map(|value| SecretBytes::from_vec(value.to_vec()))
}

fn helper_add(item: Item, value: &[u8]) -> Result<(), HelperError> {
    let value = bh_mac_keychain_helper::Zeroizing::new(value.to_vec());
    helper().call(&Request::Add(item, value)).map(drop)
}

fn login_read(handle: &KeyHandle, role: &str) -> Result<Secret<32>, KeyStoreError> {
    let item =
        helper_read(login_item(handle, role)).map_err(|e| helper_code(e, login_status_code))?;
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
    // macOS file-keychain default SecAccess trusts the creating code (the
    // helper) only for restricted reads; never grant access to every app. The
    // helper only adds, so an existing item is never replaced.
    helper_add(login_item(handle, role), bytes.expose()).map_err(|e| helper_code(e, status_code))
}
fn login_control_public(handle: &KeyHandle) -> Result<[u8; 32], KeyStoreError> {
    let item = helper_read(login_item(handle, CONTROL_PUBLIC))
        .map_err(|e| helper_code(e, login_status_code))?;
    let bytes = item.expose();
    if bytes.len() != 34
        || bytes[0] != VERSION
        || policy(bytes[1])? != ControlKeyPolicy::AppEnforcedOwnerConfirmation
    {
        return Err(KeyStoreError::WrongKey);
    }
    bytes[2..].try_into().map_err(|_| KeyStoreError::WrongKey)
}
fn login_add_public(handle: &KeyHandle, public: &[u8; 32]) -> Result<(), KeyStoreError> {
    let bytes = SecretBytes::from_parts(&[
        &[VERSION, tag(ControlKeyPolicy::AppEnforcedOwnerConfirmation)],
        public,
    ])
    .map_err(|_| KeyStoreError::StorageFailure)?;
    helper_add(login_item(handle, CONTROL_PUBLIC), bytes.expose())
        .map_err(|e| helper_code(e, status_code))
}
fn login_delete(handle: &KeyHandle, role: &str) {
    let _ = helper().call(&Request::Delete(login_item(handle, role)));
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
        for role in [ORDINARY, RECEIVER, CONTROL, CONTROL_PUBLIC] {
            match helper_read(login_item(&handle, role)) {
                Err(HelperError::Status(-25300)) => {} // errSecItemNotFound
                Ok(bytes) => {
                    drop(bytes);
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
        if let Err(error) = login_add_public(&handle, &control.public()) {
            login_delete(&handle, CONTROL);
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
        // The login route's control seed is app-gated at signing, not at load.
        let keys = loaded_keys(&mut LoginIdentityIo, &handle)?;
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
        // Fresh context on every use except the two strictly chained signup
        // continuations or the exact copy of a confirmed pairing action.
        // The gate is consciously not cryptographically tied to keychain
        // seed access.
        let key = login_control_public(&handle).inspect_err(|_| self.gate.revoke_signups())?;
        bh_host::confirm::sign_control_gated(&self.gate, key, &message, approve(), || {
            sign_with_control(&mut LoginIdentityIo, &handle, &message)
        })
        .await
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

/// M1 only: native protection for the pending first-device setup blob, alongside
/// `MacLoginKeyStore`. The wrapping key is a random 32-byte generic-password item
/// in the ordinary login keychain under its own service, never the
/// data-protection store and never selected as a fallback from M2.
///
/// It guards the staged setup material at rest against another app or a copied
/// device database. It is deliberately NOT bound to Touch ID or a passcode and
/// gives no protection against code running as the same Mac user; that is the
/// stated M1 limit, not a key-release guarantee, so no LocalAuthentication prompt
/// is involved. Opening never creates a key: a missing item is `Unavailable`,
/// because silently generating a replacement would make the staged blob
/// unopenable.
///
/// The code-bearing key belongs to one setup. The no-code home submission
/// has a different key; an old WAL or backup ciphertext cannot be opened with
/// the keys retained after a confirmed save.
#[derive(Clone, Copy, Default)]
pub(crate) struct MacPendingSetupProtector;

fn read_wrapping_key(handle: &[u8; 32]) -> Result<Secret<32>, ProtectorError> {
    // Fresh, independently named ordinary login-keychain item for each stage.
    let item = helper_read(Item::Setup(*handle)).map_err(|error| match error {
        HelperError::Status(-25300) => ProtectorError::Unavailable,
        _ => ProtectorError::Failed,
    })?;
    if item.expose().len() != WRAPPING_KEY_LEN {
        return Err(ProtectorError::Failed);
    }
    Secret::from_slice(item.expose()).map_err(|_| ProtectorError::Failed)
}

fn seal_with_fresh_key(
    kind: u8,
    old: Option<&[u8; 32]>,
    plaintext: &[u8],
) -> Result<Vec<u8>, ProtectorError> {
    let handle: [u8; 32] = crypto::random();
    match helper_read(Item::Setup(handle)) {
        Err(HelperError::Status(-25300)) => {}
        _ => return Err(ProtectorError::Failed), // never overwrite an existing item
    }
    let key = Secret::<32>::random();
    let ciphertext = seal_pending_setup(&key, plaintext)?;
    let bytes = SecretBytes::from_parts(&[key.expose()]).map_err(|_| ProtectorError::Failed)?;
    helper_add(Item::Setup(handle), bytes.expose()).map_err(|_| ProtectorError::Failed)?;
    let mut result = Vec::with_capacity(1 + 32 + old.map_or(0, |_| 32) + ciphertext.len());
    result.push(kind);
    result.extend_from_slice(&handle);
    if let Some(old) = old {
        result.extend_from_slice(old);
    }
    result.extend(ciphertext);
    Ok(result)
}
fn pending_blob(blob: &[u8]) -> Result<(u8, [u8; 32], &[u8]), ProtectorError> {
    if blob.len() < 1 + 32 + 24 + 16 {
        return Err(ProtectorError::Failed);
    }
    let kind = blob[0];
    let offset = match kind {
        PENDING_KIT => 33,
        PENDING_HOME => 65,
        _ => return Err(ProtectorError::Failed),
    };
    let handle = blob[1..33].try_into().map_err(|_| ProtectorError::Failed)?;
    let ciphertext = blob
        .get(offset..)
        .filter(|b| b.len() >= 24 + 16)
        .ok_or(ProtectorError::Failed)?;
    Ok((kind, handle, ciphertext))
}
impl PendingSetupProtector for MacPendingSetupProtector {
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        seal_with_fresh_key(PENDING_KIT, None, plaintext)
    }
    fn open(&mut self, blob: &[u8]) -> Result<SecretBytes, ProtectorError> {
        let (_, handle, ciphertext) = pending_blob(blob)?;
        open_pending_setup(&read_wrapping_key(&handle)?, ciphertext)
    }
    fn reseal_without_code(
        &mut self,
        old: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ProtectorError> {
        let (kind, handle, _) = pending_blob(old)?;
        if kind != PENDING_KIT {
            return Err(ProtectorError::Failed);
        }
        seal_with_fresh_key(PENDING_HOME, Some(&handle), plaintext)
    }
    fn retire_kit_key(&mut self, saved: &[u8]) -> Result<(), ProtectorError> {
        let (kind, _, _) = pending_blob(saved)?;
        if kind != PENDING_HOME {
            return Err(ProtectorError::Failed);
        }
        let old: [u8; 32] = saved[33..65]
            .try_into()
            .map_err(|_| ProtectorError::Failed)?;
        match helper().call(&Request::Delete(Item::Setup(old))) {
            Ok(_) | Err(HelperError::Status(-25300)) => Ok(()),
            Err(_) => Err(ProtectorError::Failed),
        }
    }
}

// Compile-time trait conformance; no keychain call or platform prompt occurs.
const _: fn() = || {
    fn check<T: DeviceKeyStore>() {}
    check::<MacKeyStore>(); // retained M2 route, not selected
    check::<MacLoginKeyStore>(); // native M1 signup route
    fn check_protector<T: PendingSetupProtector>() {}
    check_protector::<MacPendingSetupProtector>(); // native M1 signup route
};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn keychain_services_follow_the_app_identifier_and_keep_production_names() {
        // The login-route names live in the helper, built for the same identifier.
        let id = crate::APP_IDENTIFIER;
        assert_eq!(SERVICE, format!("{id}.device-keys.v1"));
        if id == "app.basehero.client" {
            assert_eq!(SERVICE, "app.basehero.client.device-keys.v1");
        }
    }
    struct TestIo {
        ordinary: SigningKey,
        receiver: KemKey,
        control: SigningKey,
        public: Result<[u8; 32], KeyStoreError>,
        releases: usize,
    }
    impl TestIo {
        fn new() -> Self {
            let control = SigningKey::generate();
            Self {
                ordinary: SigningKey::generate(),
                receiver: KemKey::generate(),
                public: Ok(control.public()),
                control,
                releases: 0,
            }
        }
    }
    impl IdentityIo for TestIo {
        fn ordinary(&mut self, _: &KeyHandle) -> Result<[u8; 32], KeyStoreError> {
            Ok(self.ordinary.public())
        }
        fn receiver(&mut self, _: &KeyHandle) -> Result<[u8; 1216], KeyStoreError> {
            Ok(self.receiver.public())
        }
        fn control_public(&mut self, _: &KeyHandle) -> Result<[u8; 32], KeyStoreError> {
            self.public
        }
        fn control(&mut self, _: &KeyHandle) -> Result<SigningKey, KeyStoreError> {
            self.releases += 1;
            Ok(SigningKey::from_seed(&self.control.export_seed()))
        }
    }
    #[test]
    fn both_keychain_routes_share_tested_load_decision() {
        let handle = KeyHandle([9; 32]);
        for route in [
            DeviceKeyStoreKind::MacDataProtectionKeychainV1,
            DeviceKeyStoreKind::MacLoginKeychainV1,
        ] {
            // Both production route adapters call loaded_keys and sign_with_control;
            // only the Keychain reads/writes differ. The M1 approval precedes signing.
            let mut io = TestIo::new();
            for _ in 0..3 {
                // load, ordinary delivery and ordinary receiving
                assert_eq!(
                    loaded_keys(&mut io, &handle).unwrap().control(),
                    &io.control.public(),
                    "{route:?}"
                );
            }
            assert_eq!(io.releases, 0, "{route:?}");
            let sig = sign_with_control(&mut io, &handle, b"control").unwrap();
            assert!(crypto::verify(&io.control.public(), b"control", &sig).is_ok());
            assert_eq!(io.releases, 1, "{route:?}");
            // A missing record is a lost identity, not permission to read control.
            let mut absent = TestIo::new();
            for failure in [
                KeyStoreError::Invalidated,
                KeyStoreError::StorageFailure,
                KeyStoreError::WrongKey,
            ] {
                absent.public = Err(failure);
                assert!(
                    matches!(loaded_keys(&mut absent, &handle), Err(error) if error == failure),
                    "{route:?}"
                );
                assert_eq!(absent.releases, 0, "{route:?}");
            }
        }
    }
    #[test]
    fn mac_load_entries_do_not_release_control_outside_the_tested_decision() {
        // This checks the real route entries, not TestIo: both must delegate
        // without reading the control seed before loaded_keys runs.
        let source = include_str!("macos.rs");
        for (store, next_method, forbidden_read, delegate) in [
            (
                "MacKeyStore",
                "async fn sign_content(",
                "read(&handle, CONTROL)",
                "loaded_keys(&mut ProtectedIdentityIo, &handle)?",
            ),
            (
                "MacLoginKeyStore",
                "async fn sign_control(",
                "login_read(&handle, CONTROL)",
                "loaded_keys(&mut LoginIdentityIo, &handle)?",
            ),
        ] {
            let entry = source
                .split_once(&format!("impl DeviceKeyStore for {store} {{"))
                .unwrap()
                .1
                .split_once("async fn load(&mut self, handle: KeyHandle)")
                .unwrap()
                .1
                .split_once(next_method)
                .unwrap()
                .0;
            assert!(
                entry.contains(delegate),
                "{store} must use the tested load decision"
            );
            assert!(
                !entry.contains(forbidden_read),
                "{store} must not read control outside the tested load decision"
            );
        }
    }
    #[test]
    fn both_creation_routes_require_metadata_and_clean_on_failure() {
        // Keep the native keychain calls under each create branch in the tested
        // sequence: a failed metadata write must not return a usable handle.
        let source = include_str!("macos.rs");
        for (store, add_public, cleanup) in [
            (
                "MacKeyStore",
                "add_protected_public(&handle, &control.public())",
                "delete(&handle, CONTROL)",
            ),
            (
                "MacLoginKeyStore",
                "login_add_public(&handle, &control.public())",
                "login_delete(&handle, CONTROL)",
            ),
        ] {
            let creation = source
                .split_once(&format!("impl DeviceKeyStore for {store} {{"))
                .unwrap()
                .1
                .split_once("async fn load(&mut self, handle: KeyHandle)")
                .unwrap()
                .0;
            let metadata = creation.find(add_public).unwrap();
            let after_metadata = &creation[metadata..];
            let rollback = after_metadata.find(cleanup).unwrap();
            let returned = after_metadata.find("Ok(StoredDevice {").unwrap();
            assert!(
                rollback < returned,
                "{store} must roll back before returning"
            );
            assert!(after_metadata[..returned].contains("return Err(error)"));
            for role in ["RECEIVER", "ORDINARY"] {
                assert!(after_metadata[..returned].contains(&format!(
                    "{cleanup_prefix}(&handle, {role})",
                    cleanup_prefix = if store == "MacKeyStore" {
                        "delete"
                    } else {
                        "login_delete"
                    }
                )));
            }
        }
    }
    /// Opt-in real macOS login-keychain check through a packaged helper beside
    /// the test executable. A headless SSH context may not unlock the login
    /// Keychain; never run automatically in CI.
    #[test]
    #[ignore = "requires interactive login Keychain; run explicitly on a logged-in Mac"]
    fn real_login_keychain_separates_device_and_retired_kit_keys() {
        struct Cleanup(KeyHandle);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                for role in [ORDINARY, RECEIVER, CONTROL, CONTROL_PUBLIC] {
                    login_delete(&self.0, role);
                }
            }
        }
        let mut store = MacLoginKeyStore::default();
        let identity = tauri::async_runtime::block_on(
            store.create(ControlKeyPolicy::AppEnforcedOwnerConfirmation),
        )
        .expect("create login Keychain device");
        let _cleanup = Cleanup(identity.handle.clone());
        let loaded = tauri::async_runtime::block_on(store.load(identity.handle.clone()))
            .expect("load same device");
        assert_eq!(identity.keys, loaded.keys);
        let mut protector = MacPendingSetupProtector;
        let kit = protector.seal(b"temporary test code").expect("kit stage");
        let saved = protector
            .reseal_without_code(&kit, b"home ciphertext only")
            .expect("separate home key");
        let (_, home_key, _) = pending_blob(&saved).unwrap();
        protector
            .retire_kit_key(&saved)
            .expect("retire code-bearing key");
        assert!(matches!(
            protector.open(&kit),
            Err(ProtectorError::Unavailable)
        ));
        assert_eq!(
            protector.open(&saved).unwrap().expose(),
            b"home ciphertext only"
        );
        let _ = helper().call(&Request::Delete(Item::Setup(home_key)));
    }

    #[test]
    fn os_statuses_do_not_confuse_failed_auth_with_key_loss() {
        assert_eq!(status_code(-128), KeyStoreError::AuthenticationCancelled);
        assert_eq!(status_code(-25293), KeyStoreError::Unavailable);
        assert_eq!(status_code(-25300), KeyStoreError::Invalidated);
        assert_eq!(status_code(-25308), KeyStoreError::Unavailable);
        assert_eq!(status_code(-34018), KeyStoreError::Unavailable);
    }
}
