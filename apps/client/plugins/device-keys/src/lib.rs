//! Private, inactive Android adapter. The app does not depend on or register this crate.
//! No command is exposed to JavaScript and no operation touches the WebView.

#[cfg(any(target_os = "android", test))]
use bh_account::platform::{ControlKeyPolicy, KeyStoreError};

// This is the authenticated plaintext returned by the native wrapper. Keep the
// format independent of JNI so corrupt/policy-crossed records can be rejected
// by portable tests. The Kotlin store authenticates its version/role/handle as
// AES-GCM associated data before handing the bytes back.
#[cfg(any(target_os = "android", test))]
const RECORD_VERSION: u8 = 1;

#[cfg(any(target_os = "android", test))]
fn encode_record(policy: ControlKeyPolicy, public: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
    let tag = match policy {
        ControlKeyPolicy::CurrentBiometricsOnly => 1,
        _ => return Err(KeyStoreError::Unavailable),
    };
    let mut out = Vec::with_capacity(2 + public.len());
    out.extend_from_slice(&[RECORD_VERSION, tag]);
    out.extend_from_slice(public);
    Ok(out)
}

#[cfg(any(target_os = "android", test))]
fn decode_record(bytes: &[u8], public_len: usize) -> Result<&[u8], KeyStoreError> {
    if public_len == 0
        || bytes.len() != public_len + 2
        || bytes[0] != RECORD_VERSION
        || bytes[1] != 1
    {
        return Err(KeyStoreError::StorageFailure);
    }
    Ok(&bytes[2..])
}

/// T113 may register this empty private Tauri plugin when it packages the
/// Android library. There is deliberately no command handler or JS API: native
/// account code calls the byte-array JNI bridge directly, not Invoke JSON.
#[cfg(target_os = "android")]
pub fn init<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri::plugin::Builder::new("device-keys").build()
}

#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
pub use android::{AndroidKeyStore, AndroidPendingSetupProtector};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_reject_downgrade_truncation_and_future_version() {
        let public = [7; 32];
        let encoded = encode_record(ControlKeyPolicy::CurrentBiometricsOnly, &public).unwrap();
        assert_eq!(decode_record(&encoded, 32).unwrap(), public);
        for malformed in [
            vec![2, 1].into_iter().chain(public).collect::<Vec<_>>(),
            vec![1, 2].into_iter().chain(public).collect(),
            encoded[..encoded.len() - 1].to_vec(),
        ] {
            assert_eq!(
                decode_record(&malformed, 32),
                Err(KeyStoreError::StorageFailure)
            );
        }
        assert_eq!(
            decode_record(&[1, 1], 0),
            Err(KeyStoreError::StorageFailure)
        );
        assert_eq!(
            encode_record(ControlKeyPolicy::DevicePasscodeWithoutBiometrics, &public),
            Err(KeyStoreError::Unavailable)
        );
        assert_eq!(
            encode_record(ControlKeyPolicy::AppEnforcedOwnerConfirmation, &public),
            Err(KeyStoreError::Unavailable)
        );
    }
}
