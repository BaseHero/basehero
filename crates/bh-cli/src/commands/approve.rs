use bh_core::{Account, AccountEvent, ApprovalId, Digits, Error};
use serde_json::{Value, json};
use std::io::{self, Write};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// Render a device label as bounded, inert, single-line terminal text.
/// This is the sole CLI boundary for device names, including JSON output.
pub(crate) fn terminal_device_name(name: &str) -> String {
    let mut rendered = String::new();
    for ch in name.chars() {
        let unsafe_control = ch.is_control()
            || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}' | '\u{2029}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        let part = if unsafe_control {
            format!("\\u{{{:x}}}", ch as u32)
        } else {
            ch.to_string()
        };
        if rendered.len() + part.len() > 256 {
            rendered.push('…');
            break;
        }
        rendered.push_str(&part);
    }
    rendered
}

// poll and read one byte at a time so a partial line cannot keep the prompt
// blocked beyond its deadline. stdin is never placed in a background thread.
fn read_line_until(
    deadline: Instant,
    input_fd: libc::c_int,
    line: &mut Zeroizing<Vec<u8>>,
) -> io::Result<bool> {
    line.zeroize();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }
        let mut fd = libc::pollfd {
            fd: input_fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        // SAFETY: poll receives a valid single pollfd and read writes one byte
        // into an initialized byte. stdin belongs to this process.
        if unsafe { libc::poll(&mut fd, 1, ms) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if fd.revents == 0 {
            continue;
        }
        let mut byte = 0u8;
        // SAFETY: byte is a writable u8; poll reported stdin readable or hung up.
        let count = unsafe { libc::read(input_fd, (&mut byte as *mut u8).cast(), 1) };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "no digits entered",
            ));
        }
        if byte == b'\n' {
            return Ok(true);
        }
        if line.len() < 256 {
            line.push(byte);
        }
    }
}

use crate::{Result, invalid};

/// Lists pending approval requests with their public metadata.
pub async fn list(account: &Account) -> Result<Value> {
    Ok(Value::Array(
        account
            .approval_requests()
            .await?
            .into_iter()
            .map(
                |r| json!({"approvalId": r.id, "deviceId": r.device_id, "createdAt": r.created_at}),
            )
            .collect(),
    ))
}

/// Opens an explicitly selected request, or waits up to two minutes for the sole request.
pub async fn approve(
    account: &Account,
    selected: Option<&str>,
    json_output: bool,
) -> Result<Value> {
    let id = match selected {
        Some(id) => id
            .parse::<ApprovalId>()
            .map_err(|_| invalid("approval ID"))?,
        None => {
            let mut events = account.events();
            let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
            loop {
                let requests = tokio::time::timeout_at(deadline, account.approval_requests())
                    .await
                    .map_err(|_| Error::ApprovalEnded(bh_core::EndReason::Expired))??;
                // Do not select a request returned at or beyond the deadline.
                if tokio::time::Instant::now() >= deadline {
                    return Err(Box::new(Error::ApprovalEnded(bh_core::EndReason::Expired)));
                }
                match requests.len() {
                    1 => break requests[0].id,
                    n if n > 1 => {
                        return Err(invalid(
                            "specify an approval ID when there is more than one request",
                        ));
                    }
                    _ => {}
                }
                match tokio::time::timeout_at(deadline, events.recv()).await {
                    Ok(Ok(AccountEvent::ApprovalRequested(_)))
                    | Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(_))) => {}
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) => {
                        return Err(Box::new(Error::ApprovalEnded(
                            bh_core::EndReason::Cancelled,
                        )));
                    }
                    Err(_) => {
                        return Err(Box::new(Error::ApprovalEnded(bh_core::EndReason::Expired)));
                    }
                }
            }
        }
    };
    let request = account.open_request(id).await?;
    eprint!("Type the six digits shown on the new device: ");
    io::stderr().flush()?;
    let mut typed = Zeroizing::new(Vec::with_capacity(256));
    let deadline = Instant::now() + request.expires_in();
    let digits = loop {
        if !read_line_until(deadline, libc::STDIN_FILENO, &mut typed)?
            || request.expires_in().is_zero()
        {
            return Err(Box::new(Error::ApprovalEnded(bh_core::EndReason::Expired)));
        }
        if let Ok(line) = std::str::from_utf8(&typed)
            && let Ok(digits) = Digits::parse(line)
        {
            break digits;
        }
        eprint!("Type exactly six digits: ");
        io::stderr().flush()?;
    };
    typed.zeroize();
    let device = account.approve(request, &digits).await?;
    if !json_output {
        println!("Approved the new device.");
    }
    Ok(json!({"approved": device}))
}

/// Declines a request without opening it.
pub async fn decline(account: &Account, id: &str) -> Result<Value> {
    let id = id
        .parse::<ApprovalId>()
        .map_err(|_| invalid("approval ID"))?;
    account.decline(id).await?;
    Ok(json!({"declined": id}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_digit_prompt_with_no_time_left_does_not_read_stdin() {
        let mut line = Zeroizing::new(vec![b'1'; 6]);
        assert!(!read_line_until(Instant::now(), libc::STDIN_FILENO, &mut line).unwrap());
        assert!(line.is_empty());
    }
    #[test]
    fn an_incomplete_line_expires_without_waiting_for_eof() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let (mut writer, reader) = std::os::unix::net::UnixStream::pair().unwrap();
        writer.write_all(b"482").unwrap();
        let mut line = Zeroizing::new(Vec::new());
        assert!(
            !read_line_until(
                Instant::now() + Duration::from_millis(30),
                reader.as_raw_fd(),
                &mut line
            )
            .unwrap()
        );
        assert_eq!(line.as_slice(), b"482");
    }
    #[test]
    fn device_name_escapes_controls_and_bounds_rendered_text() {
        assert_eq!(
            terminal_device_name("a\u{85}\u{061c}\u{200e}\u{2028}\u{2029}\u{2069}"),
            "a\\u{85}\\u{61c}\\u{200e}\\u{2028}\\u{2029}\\u{2069}"
        );
        let rendered = terminal_device_name(&"x".repeat(300));
        assert!(rendered.len() <= 259);
        assert!(rendered.ends_with('…'));
    }
}
