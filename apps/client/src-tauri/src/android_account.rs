//! Android account platform: the Android Keystore device-key adapter and the
//! account directory under Tauri's app data directory.
//!
//! Every key operation runs on the account host's dedicated blocking worker
//! (`run_account`), never the UI thread or an async executor worker, and holds
//! no account or SQLite lock across a biometric prompt. The control key is
//! released only through a per-use strong-biometric prompt.
//!
//! Android has no first-device signup. "Create my account" asks for the Mac's
//! app-enforced control policy, which the Keystore adapter refuses, so it stays
//! unavailable; an Android account arrives by pairing. Only the labelled
//! `emulator-fixture` test build creates one, and only on an emulator.
use std::sync::Arc;

use bh_account::{
    crypto::Secret,
    platform::{ControlKeyPolicy, DeviceKeyStore, KeyHandle, KeyStoreError, StoredDevice},
};
use bh_device_keys::AndroidKeyStore;
pub(crate) use bh_device_keys::AndroidPendingSetupProtector;

#[derive(Clone, Copy, Default)]
pub(crate) struct AndroidStore;

impl DeviceKeyStore for AndroidStore {
    async fn create(&mut self, policy: ControlKeyPolicy) -> Result<StoredDevice, KeyStoreError> {
        let device = AndroidKeyStore.create(fixture::policy(policy)).await?;
        fixture::identity(&device);
        Ok(device)
    }
    async fn load(&mut self, handle: KeyHandle) -> Result<StoredDevice, KeyStoreError> {
        let device = AndroidKeyStore.load(handle).await?;
        fixture::identity(&device);
        Ok(device)
    }
    async fn sign_control(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        AndroidKeyStore.sign_control(handle, message).await
    }
    async fn sign_content(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        AndroidKeyStore.sign_content(handle, message).await
    }
    async fn decapsulate(
        &mut self,
        handle: KeyHandle,
        ciphertext: [u8; 1120],
    ) -> Result<Secret<32>, KeyStoreError> {
        AndroidKeyStore.decapsulate(handle, ciphertext).await
    }
}

/// Resolves the app data directory once Tauri's path plugin exists and gives
/// it to the account host. Without it the account stays unavailable; no
/// identity is ever created in a temporary or shared location.
pub(crate) fn init() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    let builder = tauri::plugin::Builder::new("android-account").setup(|app, _| {
        use tauri::Manager;
        match app.path().app_data_dir() {
            Ok(directory) => {
                let owner = Arc::clone(app.state::<crate::note_host::NoteHost>().owner());
                // Setup runs before any command can hold the host lock.
                app.state::<crate::account_host::SharedAccountHost>()
                    .blocking_lock()
                    .attach_directory(owner, directory);
            }
            // The error may name a path; the log line does not.
            Err(_) => log("account unavailable: no app data directory"),
        }
        Ok(())
    });
    fixture::install(builder).build()
}

/// One line to logcat under the `BaseHero` tag; stdout and stderr reach no
/// log on Android. Runs the platform `log` tool found on the app's PATH.
fn log(message: &str) {
    let _ = std::process::Command::new("log")
        .args(["-p", "i", "-t", "BaseHero", message])
        .status();
}

#[cfg(not(feature = "emulator-fixture"))]
mod fixture {
    use bh_account::platform::ControlKeyPolicy;

    pub(super) fn policy(requested: ControlKeyPolicy) -> ControlKeyPolicy {
        requested
    }
    pub(super) fn identity(_: &bh_account::platform::StoredDevice) {}
    pub(super) fn install<R: tauri::Runtime>(
        builder: tauri::plugin::Builder<R>,
    ) -> tauri::plugin::Builder<R> {
        builder
    }
}

/// Emulator test builds only: a labelled button creates a test account through
/// the ordinary signup commands, so emulator tests have an account to open.
#[cfg(feature = "emulator-fixture")]
mod fixture {
    use super::log;
    use bh_account::platform::ControlKeyPolicy;

    fn property(name: &str) -> Option<String> {
        let output = std::process::Command::new("getprop")
            .arg(name)
            .output()
            .ok()?;
        Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
    fn emulator() -> bool {
        ["ro.kernel.qemu", "ro.boot.qemu"]
            .into_iter()
            .any(|name| property(name).as_deref() == Some("1"))
    }

    // The device ID hashes ordinary, control and receiver public keys. This
    // labelled fixture-only diagnostic never prints a handle or secret.
    pub(super) fn identity(device: &bh_account::platform::StoredDevice) {
        if emulator() {
            let id = device.keys.id().0;
            let hex: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
            log(&format!("EMULATOR FIXTURE device public keys: {hex}"));
        }
    }

    /// The signup's app-enforced request becomes the strong-biometric control
    /// key, the only policy the Android Keystore adapter offers.
    pub(super) fn policy(requested: ControlKeyPolicy) -> ControlKeyPolicy {
        if requested != ControlKeyPolicy::AppEnforcedOwnerConfirmation || !emulator() {
            return requested;
        }
        log("EMULATOR FIXTURE: creating emulator test account (strong-biometric control key)");
        ControlKeyPolicy::CurrentBiometricsOnly
    }

    pub(super) fn install<R: tauri::Runtime>(
        builder: tauri::plugin::Builder<R>,
    ) -> tauri::plugin::Builder<R> {
        if !emulator() {
            log("EMULATOR FIXTURE build refused: this device is not an emulator");
            return builder;
        }
        log("EMULATOR FIXTURE build: emulator test account creation enabled");
        builder.js_init_script(SCRIPT.to_owned())
    }

    // Injected natively, so the page's script CSP is unchanged. It calls only the
    // ordinary signup commands, then confirms the kit nobody needs to keep.
    const SCRIPT: &str = r#"(() => {
  if (window.top !== window) return;
  const start = () => {
    const invoke = window.__TAURI_INTERNALS__?.invoke;
    if (!invoke || document.getElementById('bh-emulator-fixture')) return;
    const bar = document.createElement('div');
    bar.id = 'bh-emulator-fixture';
    bar.setAttribute('role', 'note');
    Object.assign(bar.style, {
      position: 'fixed', left: '0', right: '0', bottom: '0', zIndex: '2147483647',
      display: 'flex', gap: '8px', alignItems: 'center', justifyContent: 'center',
      padding: '6px 8px', background: '#b00020', color: '#fff',
      font: '600 12px/1.4 system-ui, sans-serif',
    });
    const label = document.createElement('span');
    label.textContent = 'EMULATOR FIXTURE';
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = 'Create emulator test account';
    Object.assign(button.style, {
      background: '#fff', color: '#b00020', border: '0', padding: '4px 8px', font: 'inherit',
    });
    const status = document.createElement('span');
    bar.append(label, button, status);
    document.body.append(bar);
    const sync = () => {
      const welcome = document.querySelector('main .label')?.textContent === 'WELCOME';
      button.hidden = !welcome;
      button.style.display = welcome ? '' : 'none';
    };
    new MutationObserver(sync).observe(document.body, { childList: true, subtree: true, characterData: true });
    sync();
    button.addEventListener('click', async () => {
      button.disabled = true;
      status.textContent = 'creating test account';
      try {
        const { suggested } = await invoke('account_suggest_password');
        const kit = await invoke('account_create', { password: suggested });
        if (kit?.screen !== 'kit') throw new Error('create: ' + kit?.screen);
        const ready = await invoke('account_confirm_kit');
        if (ready?.screen !== 'ready') throw new Error('confirm: ' + ready?.screen);
        location.reload();
      } catch (error) {
        status.textContent = String(error);
        button.disabled = false;
      }
    });
  };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
})();"#;
}
