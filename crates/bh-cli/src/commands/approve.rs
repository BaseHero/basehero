use bh_core::{
    Account, AccountEvent, AppChoice, AppOffer, ApprovalId, BaseGrantRequest, Digits, EndReason,
    Error, Mode, RequestKind, approval::protocol::is_unsafe_device_name_char,
};
use serde_json::{Value, json};
use std::io::{self, Write};
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

/// Render a device label as bounded, inert, single-line terminal text.
/// This is the sole CLI boundary for device names, including JSON output.
pub(crate) fn terminal_device_name(name: &str) -> String {
    let mut rendered = String::new();
    for ch in name.chars() {
        let part = if is_unsafe_device_name_char(ch) {
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

pub struct AppFlags<'a> {
    pub bases: &'a [String],
    pub new_base: Option<&'a str>,
    pub read_only: bool,
    pub cap_usd: Option<&'a str>,
    pub keep_old: bool,
    pub remove_old: bool,
}

impl AppFlags<'_> {
    fn any(&self) -> bool {
        !self.bases.is_empty()
            || self.new_base.is_some()
            || self.read_only
            || self.cap_usd.is_some()
            || self.keep_old
            || self.remove_old
    }
}

/// Dollars with at most two decimal places, converted exactly to micro-dollars.
pub fn parse_usd(usd: &str) -> Result<u64> {
    let (dollars, cents) = usd.split_once('.').unwrap_or((usd, ""));
    if dollars.is_empty()
        || !dollars.bytes().all(|b| b.is_ascii_digit())
        || cents.len() > 2
        || !cents.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid("USD must have at most two decimal places"));
    }
    let whole = dollars
        .parse::<u64>()
        .map_err(|_| invalid("USD is too large"))?;
    let fractional = match cents.len() {
        0 => 0,
        1 => cents.parse::<u64>()? * 10,
        _ => cents.parse::<u64>()?,
    };
    whole
        .checked_mul(1_000_000)
        .and_then(|v| v.checked_add(fractional * 10_000))
        .ok_or_else(|| invalid("USD is too large"))
}

// Civil date from Unix days; timestamps from the server are milliseconds UTC.
fn date(timestamp_ms: i64) -> String {
    let z = timestamp_ms.div_euclid(86_400_000) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::ReadOnly => "read-only",
        Mode::ReadWrite => "read-write",
    }
}

fn choice(
    account: &Account,
    offer: &AppOffer,
    flags: &AppFlags<'_>,
) -> Result<(AppChoice, Vec<String>)> {
    let mode = if flags.read_only {
        Mode::ReadOnly
    } else {
        Mode::ReadWrite
    };
    let summaries = account.bases();
    let mut bases = Vec::new();
    let mut descriptions = Vec::new();
    let selected = !flags.bases.is_empty() || flags.new_base.is_some();
    if selected {
        for requested in flags.bases {
            let summary = summaries
                .iter()
                .find(|b| b.name == *requested || b.id.to_string() == *requested)
                .ok_or(Error::NotFound)?;
            bases.push(BaseGrantRequest::Existing {
                base: summary.id,
                mode,
            });
            descriptions.push(format!(
                "{} ({})",
                terminal_device_name(&summary.name),
                mode_name(mode)
            ));
        }
        if let Some(name) = flags.new_base {
            bases.push(BaseGrantRequest::New {
                name: name.to_owned(),
                mode,
            });
            descriptions.push(format!(
                "{} ({})",
                terminal_device_name(name),
                mode_name(mode)
            ));
        }
    } else {
        for grant in &offer.bases {
            let chosen_mode = if flags.read_only {
                Mode::ReadOnly
            } else {
                grant.mode
            };
            let summary = summaries
                .iter()
                .find(|b| b.id == grant.base)
                .ok_or(Error::NotFound)?;
            bases.push(BaseGrantRequest::Existing {
                base: grant.base,
                mode: chosen_mode,
            });
            descriptions.push(format!(
                "{} ({})",
                terminal_device_name(&summary.name),
                mode_name(chosen_mode)
            ));
        }
    }
    let cap_micro_usd = flags
        .cap_usd
        .map(parse_usd)
        .transpose()?
        .unwrap_or(offer.cap_micro_usd);
    let remove = !flags.keep_old && (flags.remove_old || offer.remove_old);
    let replaces = if remove {
        offer.old.as_ref().map(|old| old.device_id)
    } else {
        None
    };
    Ok((
        AppChoice {
            bases,
            cap_micro_usd,
            replaces,
        },
        descriptions,
    ))
}

async fn approve_app(
    account: &Account,
    id: ApprovalId,
    json_output: bool,
    flags: &AppFlags<'_>,
) -> Result<Value> {
    let mut request = account.open_app_request(id).await?;
    eprintln!("An app wants to connect. Approve only an app you're setting up right now.");
    eprint!("Type the six digits the app shows: ");
    io::stderr().flush()?;
    let deadline = Instant::now() + request.expires_in();
    let mut typed = Zeroizing::new(Vec::with_capacity(256));
    let digits = loop {
        if !read_line_until(deadline, libc::STDIN_FILENO, &mut typed)?
            || request.expires_in().is_zero()
        {
            return Err(Box::new(Error::ApprovalEnded(EndReason::Expired)));
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
    let offer = request.check_digits(&digits).await?;
    let (choice, descriptions) = match choice(account, &offer, flags) {
        Ok(choice) => choice,
        Err(error) => {
            account.decline(id).await?;
            return Err(error);
        }
    };
    let device_name = terminal_device_name(&offer.device_name);
    eprintln!(
        "{} (not verified) joins as {}.",
        terminal_device_name(&offer.name),
        device_name
    );
    eprintln!("Bases: {}", descriptions.join(", "));
    eprintln!(
        "Cap: ${}.{:02} a month",
        choice.cap_micro_usd / 1_000_000,
        (choice.cap_micro_usd % 1_000_000) / 10_000
    );
    if let Some(old) = &offer.old {
        if choice.replaces.is_some() {
            eprintln!(
                "Removes the old connection {}, last seen {}.",
                terminal_device_name(&old.name),
                date(old.last_seen_at)
            );
        } else {
            eprintln!(
                "Keeps the old connection {}.",
                terminal_device_name(&old.name)
            );
        }
    }
    eprint!("Connect? [y/N] ");
    io::stderr().flush()?;
    let answered = match read_line_until(deadline, libc::STDIN_FILENO, &mut typed) {
        Ok(answered) => answered,
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => false,
        Err(e) => return Err(e.into()),
    };
    if request.expires_in().is_zero() {
        return Err(Box::new(Error::ApprovalEnded(EndReason::Expired)));
    }
    if !answered || !matches!(typed.as_slice(), b"y" | b"Y") {
        account.decline(id).await?;
        return Err(Box::new(Error::ApprovalEnded(EndReason::Declined)));
    }
    let prior_bases: std::collections::HashSet<_> = if flags.new_base.is_some() {
        account.bases().into_iter().map(|base| base.id).collect()
    } else {
        Default::default()
    };
    let old_requested = choice.replaces.is_some();
    let (device, old_removed) = account.approve_app(request, choice).await?;
    // A newly created base's name is an encrypted record; send it before this
    // short-lived CLI shuts its sync workers down.
    if flags.new_base.is_some() {
        for base in account
            .bases()
            .into_iter()
            .filter(|base| !prior_bases.contains(&base.id))
        {
            account.base(base.id)?.flush().await?;
        }
    }
    if json_output {
        eprintln!("Connected {device_name}.");
    } else {
        println!("Connected {device_name}.");
    }
    if old_requested && !old_removed {
        eprintln!("The old connection couldn't be removed; disconnect it in Devices.");
    }
    Ok(json!({"connected": device}))
}

/// Lists pending approval requests with their public metadata.
pub async fn list(account: &Account) -> Result<Value> {
    Ok(Value::Array(
        account
            .approval_requests()
            .await?
            .into_iter()
            .map(
                |r| json!({"approvalId": r.id, "deviceId": r.device_id, "createdAt": r.created_at,
                    "kind": match r.kind { RequestKind::Device => "device", RequestKind::App => "app" }}),
            )
            .collect(),
    ))
}

/// Opens an explicitly selected request, or waits up to two minutes for the sole request.
pub async fn approve(
    account: &Account,
    selected: Option<&str>,
    json_output: bool,
    flags: &AppFlags<'_>,
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
    let kind = account
        .approval_requests()
        .await?
        .into_iter()
        .find(|r| r.id == id)
        .ok_or(Error::NotFound)?
        .kind;
    if kind == RequestKind::App {
        return approve_app(account, id, json_output, flags).await;
    }
    if flags.any() {
        return Err(invalid("app-only flags cannot be used for device requests"));
    }
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
    fn dollars_are_exact_and_reject_extra_decimals() {
        assert_eq!(parse_usd("0").unwrap(), 0);
        assert_eq!(parse_usd("1").unwrap(), 1_000_000);
        assert_eq!(parse_usd("2.5").unwrap(), 2_500_000);
        assert_eq!(parse_usd("2.50").unwrap(), 2_500_000);
        for invalid in [
            "-1",
            "2.501",
            "1e2",
            "1.2.3",
            "",
            ".5",
            "18446744073709551615",
        ] {
            assert!(parse_usd(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn old_connection_date_is_utc() {
        assert_eq!(date(0), "1970-01-01");
        assert_eq!(date(1_767_225_600_000), "2026-01-01");
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
