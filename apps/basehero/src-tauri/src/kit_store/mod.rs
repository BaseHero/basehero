use crate::error::CommandError;

#[cfg(target_os = "android")]
mod android;

/// Remove entries left by older Android releases. No kit is stored on the device now.
pub fn delete_all() -> Result<(), CommandError> {
    #[cfg(target_os = "android")]
    android::delete_all()?;
    Ok(())
}
