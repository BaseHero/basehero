//! The master key lives in the login Keychain, reached only through the
//! pinned helper beside the app, which checks that its caller is BaseHero.
use crate::error::CommandError;
use bh_mac_keychain_helper::{Item, process::Helper};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub fn master_key(identifier: &str) -> Result<Zeroizing<[u8; 32]>, CommandError> {
    load_or_create(&helper_path()?, None, identifier).map(|(key, _)| key)
}

fn helper_path() -> Result<PathBuf, CommandError> {
    std::env::current_exe()
        .ok()
        .and_then(|exe| Some(exe.parent()?.join("bh-keychain-helper")))
        .ok_or_else(|| CommandError::key_unavailable("can't find the Keychain helper"))
}

/// Reads the master key, or adds 32 random bytes if there is none, and says
/// which. A Keychain that refuses or fails is never answered with a new key.
fn load_or_create(
    helper_path: &Path,
    keychain: Option<&Path>,
    identifier: &str,
) -> Result<(Zeroizing<[u8; 32]>, bool), CommandError> {
    let item = Item::Ordinary(Sha256::digest(format!("{identifier}.master")).into());
    let failed = |status: i32| CommandError::key_unavailable(format!("Keychain status {status}"));
    let spawn = || {
        Helper::spawn(helper_path, keychain)
            .map_err(|e| CommandError::key_unavailable(format!("Keychain helper: {e}")))
    };
    let mut helper = spawn()?;
    // A failed read is safe to repeat. The helper may have exited or refused
    // one request; start a fresh process rather than reuse that connection.
    let value = match helper.read(item) {
        Ok(value) => value,
        Err(_) => {
            drop(helper);
            helper = spawn()?;
            helper.read(item).map_err(failed)?
        }
    };
    let mut key = Zeroizing::new([0u8; 32]);
    if let Some(value) = value {
        if value.len() != key.len() {
            return Err(CommandError::key_unavailable(
                "the master key has the wrong length",
            ));
        }
        key.copy_from_slice(&value);
        return Ok((key, false));
    }
    getrandom::fill(&mut *key)
        .map_err(|_| CommandError::key_unavailable("no randomness for a master key"))?;
    helper.add(item, &*key).map_err(failed)?;
    Ok((key, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    // A fake of the helper's framed stdin/stdout protocol, spawned the same
    // way as the signed helper. Each invocation appends one byte to $2.
    fn fake_helper(dir: &Path) -> PathBuf {
        let path = dir.join("helper");
        std::fs::write(
            &path,
            r#"#!/bin/sh
marker="$2"
printf x >> "$marker"
count=$(wc -c < "$marker")
dd bs=1 count=36 of=/dev/null 2>/dev/null
if [ "${marker##*/}" = add ]; then
    printf '\000\004\377\377\235\054' # item not found (-25300)
    dd bs=1 count=68 of=/dev/null 2>/dev/null # add with 32-byte value
    printf '\000\004\377\377\377\377'
elif [ "$count" -eq 1 ]; then
    printf '\000\004\377\377\377\377' # failed read (-1)
else
    printf '\000\044\000\000\000\000' # successful 32-byte read
    i=0
    while [ "$i" -lt 32 ]; do printf '\001'; i=$((i + 1)); done
fi
"#,
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).unwrap();
        path
    }

    #[test]
    fn failed_read_restarts_helper_once_and_keeps_the_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let helper = fake_helper(dir.path());
        let marker = dir.path().join("read");
        let (key, created) = load_or_create(&helper, Some(&marker), "test").unwrap();
        assert_eq!(*key, [1; 32]);
        assert!(!created);
        assert_eq!(std::fs::read(marker).unwrap(), b"xx");
    }

    #[test]
    fn failed_add_is_not_retried() {
        let dir = tempfile::tempdir().unwrap();
        let helper = fake_helper(dir.path());
        let marker = dir.path().join("add");
        let error = load_or_create(&helper, Some(&marker), "test").unwrap_err();
        assert_eq!(error.kind, "KeyUnavailable");
        assert_eq!(error.message, "Keychain status -1");
        assert_eq!(std::fs::read(marker).unwrap(), b"x");
    }
}

/// `--keychain-check [--keychain FILE]`: the startup read, without a window.
/// Prints `{"ok":true,"created":<bool>}` and never the key. Exits 2 for
/// usage and 5 when the Keychain can't be reached.
pub fn keychain_check(identifier: &str, args: &[String]) -> i32 {
    let keychain = match args {
        [] => None,
        [flag, file] if flag == "--keychain" => Some(Path::new(file)),
        _ => return 2,
    };
    match helper_path().and_then(|helper| load_or_create(&helper, keychain, identifier)) {
        Ok((_, created)) => {
            println!("{}", serde_json::json!({ "ok": true, "created": created }));
            0
        }
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({ "ok": false, "error": error.message })
            );
            5
        }
    }
}
