//! Narrow macOS LocalAuthentication callback bridge. Never called on startup.
//! This confirms the user's presence for an M1 software key; it is a UI gate,
//! **not cryptographically bound** to the keychain item or libsodium signature.

#[cfg(target_os = "macos")]
mod macos {
    use block2::RcBlock;
    use objc2::runtime::Bool;
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::sync::Mutex;
    use tokio::sync::oneshot;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum GateError {
        Unavailable,
        AuthenticationCancelled,
    }

    /// Each operation gets a fresh context and no reuse of a previous Touch ID
    /// unlock. Apple's deviceOwnerAuthentication on macOS can also accept a
    /// paired Apple Watch, besides Touch ID or the user's Mac password.
    ///
    /// Dropping the returned future drops `rx`; a late callback's `tx.send` then
    /// fails and is ignored, so an approval after the caller gives up yields
    /// nothing and never signs. The retained `LAContext` and reply block stay
    /// alive until the callback (see the SAFETY comment below); releasing the
    /// context cancels a still-pending evaluation.
    pub async fn approve_control() -> Result<(), GateError> {
        // SAFETY: objc2's generated +new selector constructs a retained LAContext.
        let context = unsafe { LAContext::new() };
        // SAFETY: valid retained context; zero disables reuse of prior Touch ID.
        unsafe { context.setTouchIDAuthenticationAllowableReuseDuration(0.0) };
        // SAFETY: read-only preflight on this valid context, not in its reply block.
        unsafe { context.canEvaluatePolicy_error(LAPolicy::DeviceOwnerAuthentication) }
            .map_err(|_| GateError::Unavailable)?;
        let (tx, rx) = oneshot::channel();
        let sender = Mutex::new(Some(tx));
        let reply = RcBlock::new(move |success: Bool, _error: *mut NSError| {
            if let Some(tx) = sender
                .lock()
                .expect("authentication reply mutex poisoned")
                .take()
            {
                let _ = tx.send(success.as_bool());
            }
        });
        let reason = NSString::from_str("approve a change to who is trusted");
        // SAFETY: the block captures only a Send-safe oneshot sender, its reply
        // runs on an unspecified private queue; context and block remain alive
        // until the callback. The Objective-C error pointer is not dereferenced.
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                LAPolicy::DeviceOwnerAuthentication,
                &reason,
                &reply,
            );
        }
        match rx.await {
            Ok(true) => Ok(()),
            _ => Err(GateError::AuthenticationCancelled),
        }
    }
}

#[cfg(target_os = "macos")]
pub use macos::{GateError, approve_control};
