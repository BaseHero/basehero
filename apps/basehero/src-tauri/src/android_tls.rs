//! reqwest's rustls, and so the Tinfoil SDK, verifies certificates with
//! Android's trust store through rustls-platform-verifier. That needs the
//! app's Java context once per process, before any Rust networking.
use jni::objects::JObject;
use jni::{EnvUnowned, errors::LogErrorAndDefault, jni_sig, jni_str};

/// `BaseHeroApplication.initPlatformTls`: false if `getApplicationContext` or
/// `getClassLoader` throws. The app keeps running, but the first platform TLS
/// verification then panics at rustls-platform-verifier's `android.rs:90`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_app_basehero_BaseHeroApplication_initPlatformTls<'local>(
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
