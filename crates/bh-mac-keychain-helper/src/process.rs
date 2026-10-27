//! App-side connection to the dedicated Keychain helper. Call off the UI thread.
use crate::{Client, HelperError, Item, Request, Zeroizing};
use std::{
    io,
    path::Path,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

/// A single helper process; never retries an operation that might have succeeded.
/// After `Unavailable` (reported as `-1`), this Helper is dead: drop it and
/// call `spawn` for the next operation, never retry the failed write. Because
/// an OSStatus may also be `-1`, callers should respawn after any `-1`.
pub struct Helper {
    child: Child,
    client: Client<ChildStdout, ChildStdin>,
    dead: bool,
}

impl Helper {
    pub fn spawn(path: &Path, keychain: Option<&Path>) -> io::Result<Helper> {
        let mut command = Command::new(path);
        if let Some(file) = keychain {
            command.arg("--keychain").arg(file);
        }
        let mut child = command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::other("helper pipes unavailable"));
        };
        Ok(Self {
            child,
            client: Client::new(stdout, stdin),
            dead: false,
        })
    }

    fn call(&mut self, request: &Request) -> Result<Zeroizing<Vec<u8>>, HelperError> {
        if self.dead {
            return Err(HelperError::Unavailable);
        }
        let result = self.client.call(request);
        if result == Err(HelperError::Unavailable) {
            self.dead = true;
        }
        result
    }

    pub fn read(&mut self, item: Item) -> Result<Option<Zeroizing<Vec<u8>>>, i32> {
        match self.call(&Request::Read(item)) {
            Ok(value) => Ok(Some(value)),
            Err(HelperError::Status(-25300)) => Ok(None),
            Err(error) => Err(status(error)),
        }
    }

    pub fn add(&mut self, item: Item, value: &[u8]) -> Result<(), i32> {
        if !(1..=crate::MAX_VALUE).contains(&value.len()) {
            return Err(-1);
        }
        self.call(&Request::Add(item, Zeroizing::new(value.to_vec())))
            .map(|_| ())
            .map_err(status)
    }

    pub fn delete(&mut self, item: Item) -> Result<(), i32> {
        self.call(&Request::Delete(item))
            .map(|_| ())
            .map_err(status)
    }
}

fn status(error: HelperError) -> i32 {
    match error {
        HelperError::Status(code) => code,
        HelperError::Unavailable => -1,
    }
}

impl Drop for Helper {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
