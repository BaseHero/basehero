//! The two local release signers share only their terminal-echo guard.
use std::{
    io::{self, IsTerminal},
    process::{Command, Stdio},
};

/// Saves the previous terminal mode so a terminal that was already non-echoing
/// remains so. Child diagnostics never enter the caller's public output.
pub struct HiddenEcho(Option<String>);
impl HiddenEcho {
    pub fn for_stdin() -> Result<Self, ()> {
        if !io::stdin().is_terminal() {
            return Ok(Self(None));
        }
        let previous = Command::new("stty")
            .arg("-g")
            .stdin(Stdio::inherit())
            .stderr(Stdio::null())
            .output()
            .map_err(|_| ())?;
        if !previous.status.success() || previous.stdout.len() > 512 {
            return Err(());
        }
        // stty -g is platform-defined (BSD includes named fields). Treat its
        // one-line result as an opaque argument, not an encoding to parse.
        let saved = std::str::from_utf8(&previous.stdout).map_err(|_| ())?;
        let saved = saved.strip_suffix('\n').unwrap_or(saved);
        let saved = saved.strip_suffix('\r').unwrap_or(saved);
        if saved.is_empty() || saved.starts_with('-') || saved.chars().any(char::is_control) {
            return Err(());
        }
        let guard = Self(Some(saved.to_owned()));
        let disabled = Command::new("stty")
            .arg("-echo")
            .stdin(Stdio::inherit())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| ())?;
        if !disabled.success() {
            return Err(());
        }
        Ok(guard)
    }
}
impl Drop for HiddenEcho {
    fn drop(&mut self) {
        if let Some(saved) = &self.0 {
            let _ = Command::new("stty")
                .arg(saved)
                .stdin(Stdio::inherit())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}
