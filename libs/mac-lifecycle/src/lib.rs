//! macOS app lifecycle helpers for the client, with every Objective-C call
//! confined here: the failed-save sheet, and the hook that brings ordinary
//! Quit (the Quit menu item, Dock, logout, AppleScript) to the app's own
//! asynchronous save drain. Other platforms compile an empty crate.
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{InstallError, TerminateReply, ask_discard, intercept_terminate};
