//! Initialize the Android trust-store verifier before any Rust network request.
use jni::objects::JObject;
use jni::{EnvUnowned, errors::LogErrorAndDefault, jni_sig, jni_str};

#[unsafe(no_mangle)]
pub extern "system" fn Java_app_basehero_sample_SampleApplication_initPlatformTls<'local>(
    mut env: EnvUnowned<'local>,
    _this: JObject<'local>,
    context: JObject<'local>,
) -> bool {
    env.with_env(|env| -> jni::errors::Result<bool> {
        let init = env
            .call_method(
                &context,
                jni_str!("getApplicationContext"),
                jni_sig!(() -> android.content.Context),
                &[],
            )
            .and_then(|app| app.l())
            .and_then(|app| rustls_platform_verifier::android::init_with_env(env, app));
        if init.is_err() {
            env.exception_clear();
        }
        Ok(init.is_ok())
    })
    .resolve::<LogErrorAndDefault>()
}
