//! The master key comes from `KeysPlugin` (plugins/bh-keys), which keeps it
//! wrapped by an Android Keystore key. It crosses JNI as a byte array, which
//! is wiped once copied, and never reaches the WebView.
use crate::error::CommandError;
use jni::objects::{JByteArray, JClassLoader, JObject};
use jni::{JValue, JavaVM, jni_sig, jni_str};
use zeroize::Zeroizing;

pub fn delete_master_key() -> Result<(), CommandError> {
    let context = ndk_context::android_context();
    // SAFETY: tao owns the JavaVM and Application references for this process.
    let vm = unsafe { JavaVM::from_raw(context.vm().cast()) };
    vm.attach_current_thread(|env| -> jni::errors::Result<()> {
        let application = unsafe { JObject::from_raw(env, context.context().cast()) };
        let loader = env
            .call_method(
                &application,
                jni_str!("getClassLoader"),
                jni_sig!(() -> JClassLoader),
                &[],
            )?
            .l()?;
        let loader = env.cast_local::<JClassLoader>(loader)?;
        let name = env.new_string("app.basehero.keys.KeysPlugin")?;
        let class = loader.load_class(env, name)?;
        let plugin = env.new_object(
            &class,
            jni_sig!("(Landroid/content/Context;)V"),
            &[JValue::Object(&application)],
        )?;
        env.call_method(
            &plugin,
            jni_str!("deleteMasterKey"),
            jni_sig!(() -> ()),
            &[],
        )?;
        Ok(())
    })
    .map_err(|e| CommandError::key_unavailable(format!("Android Keystore: {e}")))
}

pub fn master_key() -> Result<Zeroizing<[u8; 32]>, CommandError> {
    let context = ndk_context::android_context();
    // SAFETY: tao initializes ndk-context with this process's JavaVM before
    // the app runs, and it stays valid for the life of the process.
    let vm = unsafe { JavaVM::from_raw(context.vm().cast()) };
    let mut key = Zeroizing::new([0u8; 32]);
    let length = vm
        .attach_current_thread(|env| -> jni::errors::Result<usize> {
            // SAFETY: tao's global reference to the Application, which it never
            // deletes. This borrows it for the call only.
            let application = unsafe { JObject::from_raw(env, context.context().cast()) };
            // An attached native thread sees only the system class loader.
            let loader = env
                .call_method(
                    &application,
                    jni_str!("getClassLoader"),
                    jni_sig!(() -> JClassLoader),
                    &[],
                )?
                .l()?;
            let loader = env.cast_local::<JClassLoader>(loader)?;
            let name = env.new_string("app.basehero.keys.KeysPlugin")?;
            let class = loader.load_class(env, name)?;
            let plugin = env.new_object(
                &class,
                jni_sig!("(Landroid/content/Context;)V"),
                &[JValue::Object(&application)],
            )?;
            let bytes = env
                .call_method(
                    &plugin,
                    jni_str!("loadOrCreateMasterKey"),
                    jni_sig!("()[B"),
                    &[],
                )?
                .l()?;
            let bytes = env.cast_local::<JByteArray>(bytes)?;
            let length = bytes.len(env)?;
            if length == key.len() {
                let mut copy = Zeroizing::new([0i8; 32]);
                bytes.get_region(env, 0, &mut *copy)?;
                for (to, from) in key.iter_mut().zip(copy.iter()) {
                    *to = *from as u8;
                }
            }
            bytes.set_region(env, 0, &vec![0; length])?;
            Ok(length)
        })
        .map_err(|e| CommandError::key_unavailable(format!("Android Keystore: {e}")))?;
    if length != key.len() {
        return Err(CommandError::key_unavailable(
            "the master key has the wrong length",
        ));
    }
    Ok(key)
}
