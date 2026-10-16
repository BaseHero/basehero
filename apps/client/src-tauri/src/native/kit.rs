//! M1 macOS system kit routes. Only trusted native setup passes a code here;
//! no page can choose a path, address, print command or arbitrary file contents.
use std::{
    fs::OpenOptions,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::{Command, Stdio},
};

use bh_account::{crypto, recovery::RecoveryCode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Destination {
    Saved,
    Opened,
    Cancelled,
}

fn kit_text(code: &RecoveryCode) -> String {
    format!(
        "BaseHero recovery kit\n\nRecovery code: {}\n\nKeep this code and your password. You need both if you lose access to your devices. BaseHero cannot reset a forgotten password. Keep the kit somewhere you can reach if this Mac is lost. The password is not in this file.\n",
        code.to_kit_text()
    )
}

/// A native system Save dialog, not merely opening a destination. A cancelled
/// picker or failed write leaves setup on the kit screen. A successful write
/// atomically replaces the destination selected in the system picker.
pub(super) async fn save_file(code: &RecoveryCode) -> Result<Destination, ()> {
    let Some(handle) = rfd::AsyncFileDialog::new()
        .set_title("Save BaseHero recovery kit")
        .set_file_name("BaseHero recovery kit.txt")
        .save_file()
        .await
    else {
        return Ok(Destination::Cancelled);
    };
    let path = handle.path().to_path_buf();
    let text = kit_text(code);
    tauri::async_runtime::spawn_blocking(move || write_text_file(&path, &text))
        .await
        .map_err(|_| ())??;
    Ok(Destination::Saved)
}

fn write_text_file(path: &Path, text: &str) -> Result<(), ()> {
    let parent = path.parent().ok_or(())?;
    let random: [u8; 16] = crypto::random();
    let name = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let temp = parent.join(format!(".basehero-kit-{name}.tmp"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|_| ())?;
    let result = (|| {
        file.write_all(text.as_bytes()).map_err(|_| ())?;
        file.sync_all().map_err(|_| ())?;
        std::fs::rename(&temp, path).map_err(|_| ())
    })();
    drop(file);
    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

fn run_applescript(script: &str) -> Result<bool, ()> {
    let mut child = Command::new("/usr/bin/osascript")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    child
        .stdin
        .take()
        .ok_or(())?
        .write_all(script.as_bytes())
        .map_err(|_| ())?;
    let result = child.wait().map_err(|_| ())?;
    Ok(result.success())
}

fn percent(input: &str) -> String {
    let mut encoded = String::new();
    for byte in input.as_bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(byte) {
            encoded.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            write!(encoded, "%{byte:02X}").expect("write to String");
        }
    }
    encoded
}

/// Opens a draft in the person's default mail app. There is intentionally no
/// recipient: this does not create an account address or send BaseHero mail.
/// Opening a draft is not sending it, so the UI must ask whether it was kept.
pub(super) fn email(code: &RecoveryCode) -> Result<Destination, ()> {
    let body = kit_text(code);
    let uri = format!(
        "mailto:?subject={}&body={}",
        percent("My BaseHero recovery kit"),
        percent(&body)
    );
    // Only percent-encoded ASCII enters a quoted AppleScript string. Feed the
    // script through stdin so the recovery code is never a process argument.
    let script = format!("open location \"{uri}\"\n");
    if run_applescript(&script)? {
        Ok(Destination::Opened)
    } else {
        Ok(Destination::Cancelled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_replaces_selected_destination_atomically_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kit.txt");
        std::fs::write(&path, b"old").unwrap();
        let code = RecoveryCode::from_raw(&[7; 16]);
        write_text_file(&path, &kit_text(&code)).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), kit_text(&code));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }
    #[test]
    fn mail_draft_has_no_to_address_and_kit_file_no_password() {
        let code = RecoveryCode::from_raw(&[7; 16]);
        let text = kit_text(&code);
        assert!(text.contains(&code.to_kit_text()));
        assert!(!text.contains("password:"));
        let uri = format!(
            "mailto:?subject={}&body={}",
            percent("My BaseHero recovery kit"),
            percent(&text)
        );
        assert!(uri.starts_with("mailto:?"));
        assert!(!uri.contains('"'));
        assert!(!uri.contains('\n'));
    }
}
