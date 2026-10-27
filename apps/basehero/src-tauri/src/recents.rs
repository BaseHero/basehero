// Android owns the task snapshot; a WebView cover dispatched on stop can be too late.
#[cfg(target_os = "android")]
pub fn set_hidden_open(open: bool) {
    use jni::objects::{JClassLoader, JObject};
    use jni::{JValue, JavaVM, jni_sig, jni_str};

    let context = ndk_context::android_context();
    // SAFETY: tao owns the JavaVM and Application reference for this process.
    let vm = unsafe { JavaVM::from_raw(context.vm().cast()) };
    let result = vm.attach_current_thread(|env| -> jni::errors::Result<()> {
        let application = unsafe { JObject::from_raw(env, context.context().cast()) };
        // Native threads cannot find app classes with the system class loader.
        let loader = env
            .call_method(
                &application,
                jni_str!("getClassLoader"),
                jni_sig!(() -> JClassLoader),
                &[],
            )?
            .l()?;
        let loader = env.cast_local::<JClassLoader>(loader)?;
        let name = env.new_string("app.basehero.MainActivity")?;
        let class = loader.load_class(env, name)?;
        env.call_static_method(
            &class,
            jni_str!("setHiddenOpen"),
            jni_sig!((bool) -> ()),
            &[JValue::Bool(open.into())],
        )?;
        Ok(())
    });
    if let Err(error) = result {
        eprintln!("Could not set Android recents privacy: {error}");
    }
}

#[cfg(not(target_os = "android"))]
pub fn set_hidden_open(_open: bool) {}
