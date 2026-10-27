use bh_core::{Core, CoreConfig, FileSecretStore, SignIn};
use bh_testkit::LocalServer;
use serde_json::Value;
use std::{
    io::{BufRead, BufReader, Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{Arc, mpsc},
    thread,
    time::Duration,
};
use tempfile::TempDir;

const PASSWORD: &str = "approval test password";

fn text_command(home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("timeout");
    cmd.args(["60s", env!("CARGO_BIN_EXE_bh")])
        .env_clear()
        .env("PATH", std::env::var("PATH").expect("PATH"))
        .env("HOME", home.join("isolated-user"))
        .env("XDG_CONFIG_HOME", home.join("isolated-config"))
        .env("BH_PASSWORD", PASSWORD)
        .args(["--home", home.to_str().expect("home path")])
        .args(args);
    cmd
}

fn command(home: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("timeout");
    cmd.args(["60s", env!("CARGO_BIN_EXE_bh")])
        .env_clear()
        .env("PATH", std::env::var("PATH").expect("PATH"))
        .env("HOME", home.join("isolated-user"))
        .env("XDG_CONFIG_HOME", home.join("isolated-config"))
        .env("BH_PASSWORD", PASSWORD)
        .args(["--home", home.to_str().expect("home path"), "--json"])
        .args(args);
    cmd
}

fn line(reader: &mut BufReader<std::process::ChildStdout>) -> Value {
    let mut buf = String::new();
    assert!(
        reader.read_line(&mut buf).expect("read CLI line") > 0,
        "CLI exited early"
    );
    serde_json::from_str(&buf).expect("JSON line")
}

fn run(home: &Path, args: &[&str]) -> Value {
    let output = command(home, args).output().expect("run CLI");
    assert!(output.status.success(), "CLI exited with {}", output.status);
    serde_json::from_slice(&output.stdout).expect("JSON output")
}

fn setup(server: &LocalServer, home: &Path, email: &str) -> Value {
    let url = server.url().to_string();
    let output = command(home, &["admin", "invite", "--server", &url])
        .env("BH_OPERATOR_TOKEN", server.operator_token())
        .output()
        .expect("invite");
    assert!(output.status.success(), "invite failed");
    let invite: Value = serde_json::from_slice(&output.stdout).expect("invite JSON");
    run(
        home,
        &[
            "signup",
            "--server",
            &url,
            "--invite",
            invite["code"].as_str().unwrap(),
            "--email",
            email,
            "--name",
            "Laptop",
        ],
    )
}

fn spawned(home: &Path, args: &[&str]) -> (Child, BufReader<std::process::ChildStdout>) {
    let mut child = command(home, args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn CLI");
    let stdout = BufReader::new(child.stdout.take().unwrap());
    (child, stdout)
}

fn completed_output(child: Child) -> std::process::Output {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        sender
            .send(child.wait_with_output().expect("wait for CLI"))
            .ok();
    });
    receiver
        .recv_timeout(Duration::from_secs(75))
        .expect("CLI deadline")
}

fn completed(child: Child) -> (std::process::ExitStatus, String) {
    // The timeout wrapper is the hard subprocess deadline; the channel also bounds a stuck wait.
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let output = child.wait_with_output().expect("wait for CLI");
        sender.send(output).ok();
    });
    let output = receiver
        .recv_timeout(Duration::from_secs(75))
        .expect("CLI deadline");
    (
        output.status,
        String::from_utf8(output.stderr).expect("stderr UTF-8"),
    )
}

#[test]
fn text_signin_and_approval_print_exact_messages() {
    let server = LocalServer::start();
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    let email = "text-cli@example.com";
    setup(&server, a.path(), email);
    let url = server.url().to_string();
    let mut a_child = text_command(a.path(), &["approve"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut b_child = text_command(
        b.path(),
        &[
            "signin", "--server", &url, "--email", email, "--name", "Desktop",
        ],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    let mut b_out = BufReader::new(b_child.stdout.take().unwrap());
    let mut digits_line = String::new();
    b_out.read_line(&mut digits_line).unwrap();
    assert!(
        digits_line.starts_with("Type ") && digits_line.ends_with(" on the approving device.\n"),
        "{digits_line}"
    );
    let digits = digits_line
        .trim_start_matches("Type ")
        .trim_end_matches(" on the approving device.\n")
        .replace(' ', "");
    assert_eq!(digits.len(), 6);
    assert!(digits.bytes().all(|byte| byte.is_ascii_digit()));
    assert_eq!(
        digits_line,
        format!(
            "Type {} {} on the approving device.\n",
            &digits[..3],
            &digits[3..]
        )
    );
    writeln!(a_child.stdin.take().unwrap(), "{digits}").unwrap();
    let a_result = completed_output(a_child);
    let mut signed_in_line = String::new();
    b_out.read_line(&mut signed_in_line).unwrap();
    let b_result = completed_output(b_child);
    assert!(a_result.status.success() && b_result.status.success());
    assert_eq!(a_result.stdout, b"Approved the new device.\n");
    assert_eq!(
        a_result.stderr,
        b"Type the six digits shown on the new device: "
    );
    assert_eq!(
        b_result.stderr,
        b"Approve this device on one of your signed-in devices.\n"
    );
    assert_eq!(signed_in_line, "Signed in as text-cli@example.com.\n");
}

fn exchange(wrong: bool) {
    let server = LocalServer::start();
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    let email = "approval-cli@example.com";
    let signup = setup(&server, a.path(), email);
    let url = server.url().to_string();
    // Also exercise `approve` with no request yet: it must wait for the new device.
    let waiting_approver = wrong.then(|| spawned(a.path(), &["approve"]));
    let (b_child, mut b_out) = spawned(
        b.path(),
        &[
            "signin", "--server", &url, "--email", email, "--name", "Desktop",
        ],
    );
    let id = line(&mut b_out)["approvalId"]
        .as_str()
        .expect("approval ID")
        .to_owned();
    if !wrong {
        let listed = run(a.path(), &["approvals"]);
        assert!(
            listed
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["approvalId"] == id
                    && r["deviceId"].is_string()
                    && r["createdAt"].is_number())
        );
    }
    let (mut a_child, mut a_out) =
        waiting_approver.unwrap_or_else(|| spawned(a.path(), &["approve"]));
    let mut input = a_child.stdin.take().unwrap();
    writeln!(input, "48 29").unwrap();
    input.flush().unwrap();
    let digits = line(&mut b_out)["digits"]
        .as_str()
        .expect("digits")
        .to_owned();
    assert_eq!(digits.len(), 6);
    assert!(digits.bytes().all(|byte| byte.is_ascii_digit()));
    if wrong {
        let mut other = digits.clone().into_bytes();
        other[0] = if other[0] == b'0' { b'1' } else { b'0' };
        input.write_all(&other).unwrap();
    } else {
        input.write_all(digits.as_bytes()).unwrap();
    }
    input.write_all(b"\n").unwrap();
    drop(input);
    let (a_status, a_stderr) = completed(a_child);
    let (b_status, b_stderr) = completed(b_child);
    assert!(
        a_stderr.contains("Type exactly six digits: "),
        "malformed input did not re-prompt"
    );
    if wrong {
        assert_eq!(a_status.code(), Some(1));
        assert_eq!(b_status.code(), Some(1));
        assert!(a_stderr.contains("The digits didn't match. Run the sign-in again to start over."));
        assert!(b_stderr.contains("The digits didn't match. Run the sign-in again to start over."));
    } else {
        assert!(a_status.success(), "approver exited with {a_status}");
        assert!(b_status.success(), "pending device exited with {b_status}");
        let approved = line(&mut a_out);
        let signed_in = line(&mut b_out);
        assert_eq!(signed_in["accountId"], signup["accountId"]);
        assert_eq!(approved["approved"], signed_in["deviceId"]);
        let devices = run(b.path(), &["devices"]);
        assert_eq!(devices.as_array().unwrap().len(), 2);
    }
}

#[test]
fn terminal_controls_in_device_names_are_inert_in_devices() {
    let server = LocalServer::start();
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    let email = "control-name@example.com";
    setup(&server, a.path(), email);
    let hostile = "\u{1b}]52;c;NDgyOTEz\u{7}\rOVERWRITE\u{202e}";
    let url = server.url().to_string();
    let mut a_child = text_command(a.path(), &["approve"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut b_child = text_command(
        b.path(),
        &[
            "signin", "--server", &url, "--email", email, "--name", hostile,
        ],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .unwrap();
    let mut b_out = BufReader::new(b_child.stdout.take().unwrap());
    let mut shown = String::new();
    b_out.read_line(&mut shown).unwrap();
    let digits = shown
        .strip_prefix("Type ")
        .unwrap()
        .strip_suffix(" on the approving device.\n")
        .unwrap()
        .replace(' ', "");
    writeln!(a_child.stdin.take().unwrap(), "{digits}").unwrap();
    let a_result = completed_output(a_child);
    let b_result = completed_output(b_child);
    assert!(a_result.status.success() && b_result.status.success());
    let prompt = String::from_utf8(a_result.stderr).unwrap();
    let success = String::from_utf8(a_result.stdout).unwrap();
    assert_eq!(prompt, "Type the six digits shown on the new device: ");
    assert_eq!(success, "Approved the new device.\n");
    let devices = text_command(a.path(), &["devices"]).output().unwrap();
    assert!(devices.status.success());
    let listed = String::from_utf8(devices.stdout).unwrap();
    assert!(!listed.contains('\u{1b}'));
    assert!(!listed.contains('\r'));
    assert!(!listed.contains('\u{202e}'));
    let devices: Value = serde_json::from_str(&listed).unwrap();
    assert!(devices.as_array().unwrap().iter().any(|device| {
        device["name"].as_str().is_some_and(|name| {
            name.contains("\\u{1b}]52;c;NDgyOTEz\\u{7}\\u{d}OVERWRITE\\u{202e}")
        })
    }));
}

#[test]
fn two_homes_approve_a_new_device_with_typed_digits() {
    exchange(false);
}

#[test]
fn wrong_digits_typed_into_the_cli_end_the_exchange() {
    exchange(true);
}

#[tokio::test(flavor = "multi_thread")]
async fn cancelling_from_core_ends_the_cli_approver() {
    let server = LocalServer::start();
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    let email = "cancelled-cli@example.com";
    setup(&server, a.path(), email);
    let core = Core::open(CoreConfig {
        data_dir: b.path().to_path_buf(),
        secrets: Arc::new(FileSecretStore::new(b.path().join("secrets")).unwrap()),
    })
    .unwrap();
    let pending = core
        .sign_in(SignIn {
            server: server.url().clone(),
            email: email.into(),
            password: zeroize::Zeroizing::new(PASSWORD.into()),
            device_name: "Desktop".into(),
        })
        .await
        .unwrap();
    let mut approval = pending.request_approval().await.unwrap();
    let id = approval.id().to_string();
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let pending_device = tokio::spawn(async move {
        let _digits = approval.digits().await.unwrap();
        cancel_rx.await.unwrap();
        approval.cancel().await.unwrap();
    });
    let mut approver = text_command(a.path(), &["approve", &id])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let prompt = b"Type the six digits shown on the new device: ";
    let mut stderr = approver.stderr.take().unwrap();
    let mut seen = vec![0; prompt.len()];
    stderr.read_exact(&mut seen).unwrap();
    assert_eq!(seen, prompt);
    cancel_tx.send(()).unwrap();
    pending_device.await.unwrap();
    writeln!(approver.stdin.take().unwrap(), "482913").unwrap();
    let result = completed_output(approver);
    assert_eq!(result.status.code(), Some(1));
    let mut remainder = String::new();
    stderr.read_to_string(&mut remainder).unwrap();
    assert_eq!(remainder, "The request was cancelled.\n");
}

#[test]
fn decline_by_id_ends_the_pending_sign_in() {
    let server = LocalServer::start();
    let a = TempDir::new().unwrap();
    let b = TempDir::new().unwrap();
    let email = "declined-cli@example.com";
    setup(&server, a.path(), email);
    let url = server.url().to_string();
    let (b_child, mut b_out) = spawned(
        b.path(),
        &[
            "signin", "--server", &url, "--email", email, "--name", "Desktop",
        ],
    );
    let id = line(&mut b_out)["approvalId"].as_str().unwrap().to_owned();
    assert_eq!(run(a.path(), &["decline", &id])["declined"], id);
    let (status, stderr) = completed(b_child);
    assert_eq!(status.code(), Some(1));
    assert!(stderr.contains("The request was declined."));
}
