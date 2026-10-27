use crate::error::CommandError;
use jni::objects::{JByteArray, JClassLoader, JObject};
use jni::{JValue, JavaVM, jni_sig, jni_str};
use zeroize::Zeroizing;

fn call<T>(
    f: impl FnOnce(&mut jni::Env<'_>, &JObject<'_>) -> jni::errors::Result<T>,
) -> Result<T, CommandError> {
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
        f(env, &store)
    })
    .map_err(|_| CommandError {
        kind: "Storage".into(),
        message: "Google kit storage unavailable".into(),
    })
}

pub fn save(account: &str, kit: &str) -> Result<(), CommandError> {
    call(|env, store| {
        let account = env.new_string(account)?;
        let data = env.new_byte_array(kit.len())?;
        let copy = Zeroizing::new(kit.as_bytes().iter().map(|b| *b as i8).collect::<Vec<_>>());
        data.set_region(env, 0, &copy)?;
        let result = env.call_method(
            store,
            jni_str!("save"),
            jni_sig!("(Ljava/lang/String;[B)V"),
            &[JValue::Object(&account), JValue::Object(&data)],
        );
        data.set_region(env, 0, &vec![0; kit.len()])?;
        result?;
        Ok(())
    })
}

pub fn load(account: &str) -> Result<Option<Zeroizing<String>>, CommandError> {
    call(|env, store| {
        let account = env.new_string(account)?;
        let value = env
            .call_method(
                store,
                jni_str!("load"),
                jni_sig!("(Ljava/lang/String;)[B"),
                &[JValue::Object(&account)],
            )?
            .l()?;
        if value.is_null() {
            return Ok(None);
        }
        let data = env.cast_local::<JByteArray>(value)?;
        let mut bytes = Zeroizing::new(vec![0i8; data.len(env)?]);
        data.get_region(env, 0, &mut bytes)?;
        data.set_region(env, 0, &vec![0; bytes.len()])?;
        let string = Zeroizing::new(
            String::from_utf8(bytes.iter().map(|b| *b as u8).collect())
                .map_err(|_| jni::errors::Error::ParseFailed("invalid kit encoding".into()))?,
        );
        Ok(Some(string))
    })
}

pub fn delete(account: &str) -> Result<(), CommandError> {
    call(|env, store| {
        let account = env.new_string(account)?;
        env.call_method(
            store,
            jni_str!("delete"),
            jni_sig!("(Ljava/lang/String;)V"),
            &[JValue::Object(&account)],
        )?;
        Ok(())
    })
}
