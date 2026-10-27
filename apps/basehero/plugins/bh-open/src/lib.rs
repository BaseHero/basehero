//! Open a temporary file only through Android's private, read-granted FileProvider.
use std::path::Path;
use tauri::AppHandle;

/// Ask the system viewer to open one cached file, never a WebView URL.
#[cfg(target_os = "android")]
pub fn open(app: &AppHandle, path: &Path, mime: &str) -> Result<(), String> {
    use jni::objects::{JClassLoader, JObject};
    use jni::{JValue, JavaVM, jni_sig, jni_str};
    use tauri::Manager;

    let root = app
        .path()
        .app_cache_dir()
        .map_err(|e| e.to_string())?
        .join("open");
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let path = path.canonicalize().map_err(|e| e.to_string())?;
    if !path.is_file() || !path.starts_with(&root) || path == root {
        return Err("file is outside the open cache".into());
    }
    let context = ndk_context::android_context();
    // SAFETY: tao owns these references for the lifetime of this process.
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
        let name = env.new_string("app.basehero.open.OpenPlugin")?;
        let class = loader.load_class(env, name)?;
        let plugin = env.new_object(
            &class,
            jni_sig!("(Landroid/content/Context;)V"),
            &[JValue::Object(&application)],
        )?;
        let path = env.new_string(path.to_string_lossy().as_ref())?;
        let mime = env.new_string(mime)?;
        env.call_method(
            &plugin,
            jni_str!("open"),
            jni_sig!("(Ljava/lang/String;Ljava/lang/String;)V"),
            &[JValue::Object(&path), JValue::Object(&mime)],
        )?;
        Ok(())
    })
    .map_err(|e| format!("Cannot open file: {e}"))
}

/// Only Android uses this provider; desktop continues to use the system opener.
#[cfg(not(target_os = "android"))]
pub fn open(_app: &AppHandle, _path: &Path, _mime: &str) -> Result<(), String> {
    Err("Android only".into())
}
