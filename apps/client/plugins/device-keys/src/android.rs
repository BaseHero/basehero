//! JNI is a private byte-array bridge; never use Tauri Invoke/JSON for seed material.
//! The account owner must run every call on a dedicated blocking worker
//! (e.g. spawn_blocking), NEVER a UI thread or ordinary async executor worker.
//! These async trait methods block up to 120 seconds. Release account/SQLite
//! locks across prompts and discard stale results after the generation check.

use std::{
    collections::HashMap,
    sync::atomic::{AtomicI64, Ordering},
    sync::{Mutex, OnceLock, mpsc},
    time::Duration,
};

use bh_account::{
    DevicePublicKeys,
    crypto::{self, KemKey, Secret, SecretBytes, SigningKey},
    journal::{PendingSetupProtector, ProtectorError},
    platform::{
        ControlKeyPolicy, DeviceKeyStore, DeviceKeyStoreKind, KeyHandle, KeyStoreError,
        StoredDevice,
    },
};
use jni::{
    JNIEnv,
    objects::{JByteArray, JClass, JObject, JValue},
};

use crate::{decode_record, encode_record};

const CLASS: &str = "app.basehero.devicekeys.DeviceKeysBridge";
type Response = Result<SecretBytes, KeyStoreError>;
static PENDING: OnceLock<Mutex<HashMap<i64, mpsc::Sender<Response>>>> = OnceLock::new();
static NEXT: AtomicI64 = AtomicI64::new(1);
fn pending() -> &'static Mutex<HashMap<i64, mpsc::Sender<Response>>> {
    PENDING.get_or_init(Default::default)
}

/// Called only by DeviceKeysBridge; errors never contain bytes from a key or input.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_basehero_devicekeys_DeviceKeysBridge_nativeComplete(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    ticket: i64,
    code: i32,
    bytes: JByteArray<'_>,
) {
    let result = match code {
        0 if !bytes.is_null() => env
            .convert_byte_array(bytes)
            .map(SecretBytes::from_vec)
            .map_err(|_| KeyStoreError::StorageFailure),
        1 => Err(KeyStoreError::Unavailable),
        2 => Err(KeyStoreError::AuthenticationCancelled),
        3 => Err(KeyStoreError::Invalidated),
        _ => Err(KeyStoreError::StorageFailure),
    };
    if let Ok(mut requests) = pending().lock()
        && let Some(tx) = requests.remove(&ticket)
    {
        let _ = tx.send(result);
    }
}

fn handle_name(handle: &KeyHandle) -> String {
    let mut name = String::with_capacity(64);
    for byte in handle.0 {
        use std::fmt::Write;
        write!(name, "{byte:02x}").expect("hex");
    }
    name
}

// Tao gives ndk-context the *Application*, never an Activity. It is used only
// for loading this packaged class. T113 later binds its resumed Activity via
// attachActivity/detachActivity; every operation acquires a fresh local reference.
fn bridge_class<'a>(
    env: &mut JNIEnv<'a>,
    application: &JObject<'_>,
) -> jni::errors::Result<JClass<'a>> {
    // The framework Application class itself has a boot loader; Context's
    // package class loader can resolve this app's packaged plugin class.
    let loader = env
        .call_method(
            application,
            "getClassLoader",
            "()Ljava/lang/ClassLoader;",
            &[],
        )?
        .l()?;
    let name = env.new_string(CLASS)?;
    Ok(JClass::from(
        env.call_method(
            loader,
            "loadClass",
            "(Ljava/lang/String;)Ljava/lang/Class;",
            &[JValue::Object(&name)],
        )?
        .l()?,
    ))
}

enum BridgeError {
    Unavailable,
    Storage,
}
impl From<jni::errors::Error> for BridgeError {
    fn from(_: jni::errors::Error) -> Self {
        Self::Storage
    }
}

#[allow(unsafe_code)]
fn with_vm(
    f: impl FnOnce(&mut JNIEnv<'_>, &JObject<'_>) -> Result<(), BridgeError>,
) -> Result<(), KeyStoreError> {
    let context = ndk_context::android_context();
    // SAFETY: Tauri initialized this VM and Application global reference. The
    // latter is borrowed, not deleted; it is NEVER passed as an Activity.
    let vm = unsafe { jni::JavaVM::from_raw(context.vm().cast()) }
        .map_err(|_| KeyStoreError::Unavailable)?;
    let mut env = vm
        .attach_current_thread()
        .map_err(|_| KeyStoreError::Unavailable)?;
    let application = unsafe { JObject::from_raw(context.context().cast()) };
    env.with_local_frame(32, |env| f(env, &application))
        .map_err(|error| match error {
            BridgeError::Unavailable => KeyStoreError::Unavailable,
            BridgeError::Storage => KeyStoreError::StorageFailure,
        })
}

fn abort_create(id: i64) {
    let _ = with_vm(|env, application| {
        let klass = bridge_class(env, application)?;
        env.call_static_method(klass, "abortCreate", "(J)V", &[JValue::Long(id)])?;
        Ok(())
    });
}

fn call(method: &str, roles: &[&[u8]], handle: Option<&str>, role: Option<&str>) -> Response {
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    let (tx, rx) = mpsc::channel();
    pending()
        .lock()
        .map_err(|_| KeyStoreError::StorageFailure)?
        .insert(id, tx);
    let sent = with_vm(|env, application| {
        let klass = bridge_class(env, application)?;
        let current = env
            .call_static_method(&klass, "currentActivity", "()Landroid/app/Activity;", &[])?
            .l()?;
        if current.is_null() || !env.is_instance_of(&current, "android/app/Activity")? {
            return Err(BridgeError::Unavailable);
        }
        // A fresh GlobalRef is safe across JNI worker/UI threads and lives only
        // for this dispatch. Kotlin holds the Activity during its prompt.
        let activity = env.new_global_ref(current)?;
        let h = env.new_string(handle.unwrap_or(""))?;
        let r = env.new_string(role.unwrap_or(""))?;
        let arrays: Vec<_> = roles
            .iter()
            .map(|bytes| env.byte_array_from_slice(bytes))
            .collect::<Result<_, _>>()?;
        let args = match method {
            "create" => vec![
                JValue::Object(activity.as_obj()),
                JValue::Object(&h),
                JValue::Object(&arrays[0]),
                JValue::Object(&arrays[1]),
                JValue::Object(&arrays[2]),
                JValue::Long(id),
            ],
            "readOrdinary" => vec![
                JValue::Object(activity.as_obj()),
                JValue::Object(&h),
                JValue::Object(&r),
                JValue::Long(id),
            ],
            "readControl" => vec![
                JValue::Object(activity.as_obj()),
                JValue::Object(&h),
                JValue::Long(id),
            ],
            "sealPending" | "openPending" => vec![
                JValue::Object(activity.as_obj()),
                JValue::Object(&arrays[0]),
                JValue::Long(id),
            ],
            _ => return Err(BridgeError::Storage),
        };
        let sig = match method {
            "create" => "(Landroid/app/Activity;Ljava/lang/String;[B[B[BJ)V",
            "readOrdinary" => "(Landroid/app/Activity;Ljava/lang/String;Ljava/lang/String;J)V",
            "readControl" => "(Landroid/app/Activity;Ljava/lang/String;J)V",
            _ => "(Landroid/app/Activity;[BJ)V",
        };
        let result = env.call_static_method(klass, method, sig, &args);
        if result.is_err() {
            let _ = env.exception_clear();
        }
        // Kotlin clones create inputs before returning. The bridge can now
        // wipe these original JNI arrays even while its prompt is outstanding.
        for array in &arrays {
            let zeros = vec![0_i8; env.get_array_length(array)? as usize];
            env.set_byte_array_region(array, 0, &zeros)?;
        }
        result?;
        Ok(())
    });
    if let Err(error) = sent {
        if method == "create" {
            abort_create(id);
        }
        pending()
            .lock()
            .map_err(|_| KeyStoreError::StorageFailure)?
            .remove(&id);
        return Err(error);
    }
    let response = rx.recv_timeout(Duration::from_secs(120));
    if response.is_err() {
        if method == "create" {
            abort_create(id);
        }
        // A late native callback is ignored; Kotlin's attempt still cleans and
        // wipes its callback-owned records on cancellation/its own deadline.
        pending()
            .lock()
            .map_err(|_| KeyStoreError::StorageFailure)?
            .remove(&id);
    }
    response.map_err(|_| KeyStoreError::Unavailable)?
}

fn read(
    handle: &KeyHandle,
    role: &str,
    public_len: usize,
) -> Result<(Vec<u8>, Secret<32>), KeyStoreError> {
    let bytes = call(
        if role == "control" {
            "readControl"
        } else {
            "readOrdinary"
        },
        &[],
        Some(&handle_name(handle)),
        Some(role),
    )?;
    let raw = bytes.expose();
    if raw.len() != 2 + public_len + 32 {
        return Err(KeyStoreError::StorageFailure);
    }
    let public = decode_record(&raw[..raw.len() - 32], public_len)?.to_vec();
    let seed =
        Secret::from_slice(&raw[raw.len() - 32..]).map_err(|_| KeyStoreError::StorageFailure)?;
    Ok((public, seed))
}
fn verified_signing(handle: &KeyHandle, role: &str) -> Result<SigningKey, KeyStoreError> {
    let (expected, seed) = read(handle, role, 32)?;
    let key = SigningKey::from_seed(&seed);
    if key.public() != expected.as_slice() {
        return Err(KeyStoreError::WrongKey);
    }
    Ok(key)
}
fn verified_receiver(handle: &KeyHandle) -> Result<KemKey, KeyStoreError> {
    let (expected, seed) = read(handle, "receiver", 1216)?;
    let key = KemKey::from_seed(&seed);
    if key.public() != expected.as_slice() {
        return Err(KeyStoreError::WrongKey);
    }
    Ok(key)
}

/// Not constructed until T113 integrates and qualifies the packaged plugin.
pub struct AndroidKeyStore;
impl DeviceKeyStore for AndroidKeyStore {
    async fn create(&mut self, policy: ControlKeyPolicy) -> Result<StoredDevice, KeyStoreError> {
        if policy != ControlKeyPolicy::CurrentBiometricsOnly {
            return Err(KeyStoreError::Unavailable);
        }
        let ordinary = SigningKey::generate();
        let control = SigningKey::generate();
        let receiver = KemKey::generate();
        let keys = DevicePublicKeys::new(ordinary.public(), control.public(), receiver.public())
            .map_err(|_| KeyStoreError::WrongKey)?;
        let handle = KeyHandle(crypto::random());
        let records = [
            SecretBytes::from_parts(&[
                &encode_record(policy, &ordinary.public())?,
                ordinary.export_seed().expose(),
            ]),
            SecretBytes::from_parts(&[
                &encode_record(policy, &receiver.public())?,
                receiver.export_seed().expose(),
            ]),
            SecretBytes::from_parts(&[
                &encode_record(policy, &control.public())?,
                control.export_seed().expose(),
            ]),
        ];
        let [a, b, c] = records.map(|result| result.map_err(|_| KeyStoreError::StorageFailure));
        let [a, b, c] = [a?, b?, c?];
        call(
            "create",
            &[a.expose(), b.expose(), c.expose()],
            Some(&handle_name(&handle)),
            None,
        )?;
        Ok(StoredDevice {
            handle,
            keys,
            policy,
            kind: DeviceKeyStoreKind::AndroidKeystoreV1,
        })
    }
    async fn load(&mut self, handle: KeyHandle) -> Result<StoredDevice, KeyStoreError> {
        let signing = verified_signing(&handle, "ordinary")?;
        let receiver = verified_receiver(&handle)?;
        let control = verified_signing(&handle, "control")?;
        let keys = DevicePublicKeys::new(signing.public(), control.public(), receiver.public())
            .map_err(|_| KeyStoreError::WrongKey)?;
        Ok(StoredDevice {
            handle,
            keys,
            policy: ControlKeyPolicy::CurrentBiometricsOnly,
            kind: DeviceKeyStoreKind::AndroidKeystoreV1,
        })
    }
    async fn sign_content(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        Ok(verified_signing(&handle, "ordinary")?.sign(&message))
    }
    async fn sign_control(
        &mut self,
        handle: KeyHandle,
        message: Vec<u8>,
    ) -> Result<[u8; 64], KeyStoreError> {
        Ok(verified_signing(&handle, "control")?.sign(&message))
    }
    async fn decapsulate(
        &mut self,
        handle: KeyHandle,
        ciphertext: [u8; 1120],
    ) -> Result<Secret<32>, KeyStoreError> {
        crypto::decapsulate(&verified_receiver(&handle)?, &ciphertext)
            .map_err(|_| KeyStoreError::WrongKey)
    }
}

pub struct AndroidPendingSetupProtector;
impl PendingSetupProtector for AndroidPendingSetupProtector {
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        call("sealPending", &[plaintext], None, None)
            .map(|v| v.expose().to_vec())
            .map_err(|_| ProtectorError::Failed)
    }
    fn open(&mut self, blob: &[u8]) -> Result<SecretBytes, ProtectorError> {
        call("openPending", &[blob], None, None).map_err(|e| {
            if e == KeyStoreError::Unavailable {
                ProtectorError::Unavailable
            } else {
                ProtectorError::Failed
            }
        })
    }
}
const _: fn() = || {
    fn store<T: DeviceKeyStore>() {}
    fn protector<T: PendingSetupProtector>() {}
    store::<AndroidKeyStore>();
    protector::<AndroidPendingSetupProtector>();
};
