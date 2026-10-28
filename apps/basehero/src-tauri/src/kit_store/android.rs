use crate::error::CommandError;
use jni::objects::{JClassLoader, JObject};
use jni::{JValue, JavaVM, jni_sig, jni_str};

pub fn delete_all() -> Result<(), CommandError> {
    let context = ndk_context::android_context();
    // SAFETY: tao owns these references throughout the Android process.
    let vm = unsafe { JavaVM::from_raw(context.vm().cast()) };
    vm.attach_current_thread(|env| {
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
        let name = env.new_string("app.basehero.keys.KitStore")?;
        let class = loader.load_class(env, name)?;
        let store = env.new_object(
            &class,
            jni_sig!("(Landroid/content/Context;)V"),
            &[JValue::Object(&application)],
        )?;
        env.call_method(&store, jni_str!("deleteAll"), jni_sig!("()V"), &[])?;
        Ok::<(), jni::errors::Error>(())
    })
    .map_err(|_| CommandError {
        kind: "Storage".into(),
        message: "Google kit storage unavailable".into(),
    })
}
