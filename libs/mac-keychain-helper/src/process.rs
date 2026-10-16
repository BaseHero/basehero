//! The app side: one lazily started helper per app process.
use crate::{Client, HelperError, Request};
use std::{
    ffi::OsString,
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::Mutex,
};
use zeroize::Zeroizing;

struct Live {
    child: Child,
    client: Client<ChildStdout, ChildStdin>,
}

impl Drop for Live {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Starts the helper on first use and keeps it for later calls. A helper that
/// fails a call is discarded, so the next call starts a fresh one; a failed
/// call is never repeated, because an add may already have happened.
pub struct HelperProcess {
    program: PathBuf,
    args: Vec<OsString>,
    live: Mutex<Option<Live>>,
}

impl HelperProcess {
    pub fn new(program: PathBuf, args: Vec<OsString>) -> Self {
        Self {
            program,
            args,
            live: Mutex::new(None),
        }
    }

    fn start(&self) -> Result<Live, HelperError> {
        // Nothing from this process's environment reaches the helper.
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| HelperError::Unavailable)?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(HelperError::Unavailable);
        };
        Ok(Live {
            child,
            client: Client::new(stdout, stdin),
        })
    }

    /// Blocking; run it off the UI thread.
    pub fn call(&self, request: &Request) -> Result<Zeroizing<Vec<u8>>, HelperError> {
        let mut live = self
            .live
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if live.is_none() {
            *live = Some(self.start()?);
        }
        let result = live.as_mut().expect("started above").client.call(request);
        if result == Err(HelperError::Unavailable) {
            *live = None;
        }
        result
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::Item;

    fn shell(script: &str, file: &std::path::Path) -> HelperProcess {
        HelperProcess::new(
            "/bin/sh".into(),
            vec!["-c".into(), script.into(), file.into()],
        )
    }
    /// NixOS has no /bin/head; name the test's own tools by absolute path.
    fn tool(name: &str) -> String {
        std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|dir| dir.join(name))
            .find(|path| path.is_file())
            .unwrap()
            .display()
            .to_string()
    }
    fn lines(file: &std::path::Path) -> usize {
        std::fs::read_to_string(file)
            .map(|s| s.lines().count())
            .unwrap_or(0)
    }

    #[test]
    fn a_missing_helper_is_unavailable() {
        let helper = HelperProcess::new("/nonexistent/bh-keychain-helper".into(), vec![]);
        assert_eq!(
            helper.call(&Request::Read(Item::Ordinary([1; 32]))),
            Err(HelperError::Unavailable)
        );
    }

    #[test]
    fn a_live_helper_serves_later_calls() {
        let dir = tempfile::tempdir().unwrap();
        let starts = dir.path().join("starts");
        // Answers two delete requests (36-byte frames) with status 0.
        let script = format!(
            r#"echo start >> "$0"; for i in 1 2; do {head} -c 36 >/dev/null; printf '\000\004\000\000\000\000'; done; {sleep} 5"#,
            head = tool("head"),
            sleep = tool("sleep"),
        );
        let helper = shell(&script, &starts);
        for _ in 0..2 {
            assert_eq!(
                helper
                    .call(&Request::Delete(Item::Ordinary([1; 32])))
                    .map(|v| v.to_vec()),
                Ok(vec![])
            );
        }
        assert_eq!(lines(&starts), 1);
    }

    #[test]
    fn an_exited_helper_is_started_again_on_the_next_call() {
        let dir = tempfile::tempdir().unwrap();
        let starts = dir.path().join("starts");
        let helper = shell(r#"echo start >> "$0""#, &starts);
        for _ in 0..2 {
            assert_eq!(
                helper.call(&Request::Read(Item::Ordinary([1; 32]))),
                Err(HelperError::Unavailable)
            );
        }
        assert_eq!(lines(&starts), 2);
    }

    #[test]
    fn the_helper_starts_with_an_empty_environment() {
        let dir = tempfile::tempdir().unwrap();
        let seen = dir.path().join("env");
        let helper = shell(&format!(r#"{} > "$0""#, tool("env")), &seen);
        let _ = helper.call(&Request::Read(Item::Ordinary([1; 32])));
        let env = std::fs::read_to_string(&seen).unwrap();
        assert!(std::env::var_os("PATH").is_some() && std::env::var_os("HOME").is_some());
        assert!(
            !env.lines()
                .any(|l| l.starts_with("PATH=") || l.starts_with("HOME=")),
            "{env}"
        );
    }
}
