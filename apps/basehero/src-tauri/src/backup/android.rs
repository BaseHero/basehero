//! Android's persisted document trees, with no backup-format logic in Java.
use bh_core::{BackupFolder, DocumentFolders, FolderEntry, FolderError};
use jni::objects::{JByteArray, JClassLoader, JObject, JString};
use jni::{Env, JValue, JavaVM, jni_sig, jni_str};
use std::sync::Arc;
use tauri::plugin::{Builder, PluginHandle, TauriPlugin};
use tauri::{Manager, Runtime};

pub struct FolderPicker<R: Runtime>(PluginHandle<R>);

pub fn plugin<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("bh-folders")
        .setup(|app, api| {
            let handle = api.register_android_plugin("app.basehero.folders", "FoldersPlugin")?;
            app.manage(FolderPicker(handle));
            Ok(())
        })
        .build()
}

#[cfg(debug_assertions)]
pub fn release_for_test(uri_value: &str) -> Result<(), FolderError> {
    with_folder(|env, folder| {
        let value = uri(env, uri_value)?;
        env.call_method(
            folder,
            jni_str!("release"),
            jni_sig!("(Ljava/lang/String;)V"),
            &[JValue::Object(&value)],
        )
        .map_err(|e| failure(env, e))?;
        Ok(())
    })
}

pub async fn pick(app: &tauri::AppHandle) -> Result<Option<(String, String)>, String> {
    #[derive(serde::Deserialize)]
    struct Picked {
        uri: Option<String>,
        label: Option<String>,
    }
    let picked: Picked = app
        .state::<FolderPicker<tauri::Wry>>()
        .0
        .run_mobile_plugin_async("pick", ())
        .await
        .map_err(|e| e.to_string())?;
    Ok(picked.uri.zip(picked.label))
}

pub struct AndroidFolders;

struct AndroidFolder(String);

fn failure(env: &mut Env<'_>, error: jni::errors::Error) -> FolderError {
    let message = env
        .exception_occurred()
        .and_then(|exception| {
            env.exception_clear();
            let result = env
                .call_method(
                    &exception,
                    jni_str!("toString"),
                    jni_sig!(() -> JString),
                    &[],
                )
                .ok()?
                .l()
                .ok()?;
            let result = env.cast_local::<JString>(result).ok()?;
            result.try_to_string(env).ok()
        })
        .unwrap_or_else(|| error.to_string());
    super::android_folder_error(message)
}

fn with_folder<T>(
    operation: impl FnOnce(&mut Env<'_>, &JObject<'_>) -> Result<T, FolderError>,
) -> Result<T, FolderError> {
    let context = ndk_context::android_context();
    // SAFETY: tao owns these references throughout the process, as with KeysPlugin.
    let vm = unsafe { JavaVM::from_raw(context.vm().cast()) };
    vm.attach_current_thread(|env| {
        let application = unsafe { JObject::from_raw(env, context.context().cast()) };
        let folder = (|| -> jni::errors::Result<_> {
            let loader = env
                .call_method(
                    &application,
                    jni_str!("getClassLoader"),
                    jni_sig!(() -> JClassLoader),
                    &[],
                )?
                .l()?;
            let loader = env.cast_local::<JClassLoader>(loader)?;
            let name = env.new_string("app.basehero.folders.DocumentFolder")?;
            let class = loader.load_class(env, name)?;
            env.new_object(
                &class,
                jni_sig!("(Landroid/content/Context;)V"),
                &[JValue::Object(&application)],
            )
        })()?;
        Ok(operation(env, &folder))
    })
    .map_err(|e: jni::errors::Error| FolderError::Other(e.to_string()))?
}

fn uri<'a>(env: &mut Env<'a>, value: &str) -> Result<JString<'a>, FolderError> {
    env.new_string(value).map_err(|e| failure(env, e))
}

fn java_string(env: &mut Env<'_>, object: JObject<'_>) -> Result<String, FolderError> {
    let string = env
        .cast_local::<JString>(object)
        .map_err(|e| failure(env, e))?;
    string.try_to_string(env).map_err(|e| failure(env, e))
}

impl DocumentFolders for AndroidFolders {
    fn open(&self, uri_value: &str) -> Result<Arc<dyn BackupFolder>, FolderError> {
        with_folder(|env, folder| {
            let value = uri(env, uri_value)?;
            let present = env
                .call_method(
                    folder,
                    jni_str!("persisted"),
                    jni_sig!("(Ljava/lang/String;)Z"),
                    &[JValue::Object(&value)],
                )
                .map_err(|e| failure(env, e))?
                .z()
                .map_err(|e| failure(env, e))?;
            if !present {
                return Err(FolderError::PermissionLost);
            }
            let root = uri(env, uri_value)?;
            let empty = uri(env, "")?;
            env.call_method(
                folder,
                jni_str!("list"),
                jni_sig!("(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
                &[JValue::Object(&root), JValue::Object(&empty)],
            )
            .map_err(|e| failure(env, e))?;
            Ok(Arc::new(AndroidFolder(uri_value.to_owned())) as Arc<dyn BackupFolder>)
        })
    }
}

impl BackupFolder for AndroidFolder {
    fn list(&self, dir: &str) -> Result<Vec<FolderEntry>, FolderError> {
        with_folder(|env, folder| {
            let root = uri(env, &self.0)?;
            let dir = uri(env, dir)?;
            let result = env
                .call_method(
                    folder,
                    jni_str!("list"),
                    jni_sig!("(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
                    &[JValue::Object(&root), JValue::Object(&dir)],
                )
                .map_err(|e| failure(env, e))?
                .l()
                .map_err(|e| failure(env, e))?;
            #[derive(serde::Deserialize)]
            struct Entry {
                name: String,
                dir: bool,
                size: u64,
            }
            let entries: Vec<Entry> = serde_json::from_str(&java_string(env, result)?)
                .map_err(|e| FolderError::Other(e.to_string()))?;
            let mut entries: Vec<_> = entries
                .into_iter()
                .map(|e| FolderEntry {
                    name: e.name,
                    dir: e.dir,
                    size: e.size,
                })
                .collect();
            entries.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(entries)
        })
    }

    fn read(&self, path: &str) -> Result<Vec<u8>, FolderError> {
        with_folder(|env, folder| {
            let root = uri(env, &self.0)?;
            let path = uri(env, path)?;
            let result = env
                .call_method(
                    folder,
                    jni_str!("read"),
                    jni_sig!("(Ljava/lang/String;Ljava/lang/String;)[B"),
                    &[JValue::Object(&root), JValue::Object(&path)],
                )
                .map_err(|e| failure(env, e))?
                .l()
                .map_err(|e| failure(env, e))?;
            let result = env
                .cast_local::<JByteArray>(result)
                .map_err(|e| failure(env, e))?;
            env.convert_byte_array(&result).map_err(|e| failure(env, e))
        })
    }

    fn write(&self, path: &str, bytes: &[u8]) -> Result<(), FolderError> {
        with_folder(|env, folder| {
            let root = uri(env, &self.0)?;
            let path = uri(env, path)?;
            let bytes = env
                .byte_array_from_slice(bytes)
                .map_err(|e| failure(env, e))?;
            env.call_method(
                folder,
                jni_str!("write"),
                jni_sig!("(Ljava/lang/String;Ljava/lang/String;[B)V"),
                &[
                    JValue::Object(&root),
                    JValue::Object(&path),
                    JValue::Object(&bytes),
                ],
            )
            .map_err(|e| failure(env, e))?;
            Ok(())
        })
    }

    fn remove(&self, path: &str) -> Result<(), FolderError> {
        with_folder(|env, folder| {
            let root = uri(env, &self.0)?;
            let path = uri(env, path)?;
            env.call_method(
                folder,
                jni_str!("remove"),
                jni_sig!("(Ljava/lang/String;Ljava/lang/String;)V"),
                &[JValue::Object(&root), JValue::Object(&path)],
            )
            .map_err(|e| failure(env, e))?;
            Ok(())
        })
    }
}
