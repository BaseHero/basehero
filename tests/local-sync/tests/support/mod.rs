//! The test side of the local sync tests: a private local stack per test
//! (its own directory, keys, ports, stored logs and processes), device
//! processes driven by line requests, and read-only views of their stores.
#![allow(dead_code)]

use rusqlite::OptionalExtension as _;
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

pub const PASSWORD: &str = "ripple amber horizon nectar willow";

/// The Cargo target holding this test and the device process.
fn target() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    // <target>/debug/deps/<test>
    exe.parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}
fn checkout() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}
/// Where each test keeps its stack and devices: kept after the run as
/// evidence. Read, never set, by the tests.
fn runs() -> PathBuf {
    std::env::var_os("BH_LOCAL_SYNC_RUNS")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("bh-local-sync-runs"))
}

pub fn until(seconds: u64, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while !done() {
        assert!(Instant::now() < deadline, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub fn log(dir: &Path, line: &str) {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("test.log"))
        .unwrap();
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    writeln!(file, "{ms} {line}").unwrap();
}

/// One private local stack: the real Worker (log objects, R2 bodies, relay)
/// in local workerd and the authorization service with labelled synthetic
/// attestation.
pub struct Stack {
    pub dir: PathBuf,
    pub endpoint: PathBuf,
}

impl Stack {
    pub fn up(name: &str) -> Self {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let dir = runs().join(format!("{name}-{stamp}-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("stack")).unwrap();
        std::fs::create_dir_all(dir.join("home")).unwrap();
        let stack = Self {
            endpoint: dir.join("stack/endpoint.json"),
            dir,
        };
        stack.script(&["up"]);
        stack.write_endpoint();
        log(&stack.dir, &format!("stack up: {}", stack.dir.display()));
        stack
    }
    pub fn stack_dir(&self) -> PathBuf {
        self.dir.join("stack")
    }
    fn script(&self, args: &[&str]) {
        let out = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("stack.log"))
            .unwrap();
        let status = Command::new("bash")
            .args(["--noprofile", "--norc", "scripts/local-stack.sh"])
            .args(args)
            .current_dir(checkout())
            .env("LOCAL_STACK_DIR", self.stack_dir())
            .env("CARGO_TARGET_DIR", target())
            .env("LOCAL_STACK_BIND", "127.0.0.1")
            .env("LOCAL_STACK_PREBUILT", "1")
            .env("HOME", self.dir.join("home"))
            .env("GH_CONFIG_DIR", self.dir.join("home/gh"))
            .env("XDG_CONFIG_HOME", self.dir.join("home/xdg"))
            .env_remove("GH_TOKEN")
            .env_remove("GITHUB_TOKEN")
            .stdout(out.try_clone().unwrap())
            .stderr(out)
            .status()
            .unwrap();
        assert!(status.success(), "local-stack.sh {args:?}: {status}");
    }
    /// The stack's endpoint as an app build's endpoint file.
    fn write_endpoint(&self) {
        let dir = self.stack_dir();
        let env: std::collections::HashMap<String, String> =
            std::fs::read_to_string(dir.join("env"))
                .unwrap()
                .lines()
                .filter_map(|line| line.split_once('='))
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect();
        let policy = std::fs::read(&env["LOCAL_STACK_POLICY"]).unwrap();
        let endpoint = json!({
            "edge_url": env["LOCAL_STACK_HOST_EDGE_URL"],
            "hosting_root": env["LOCAL_STACK_HOSTING_ROOT"],
            "app_root": env["LOCAL_STACK_APP_ROOT"],
            "policy": policy.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            "policy_signature": std::fs::read_to_string(dir.join("keys/policy.sig")).unwrap().trim(),
            "max_lifetime_secs": 86400,
            "max_uncertainty_secs": 0,
            "build_floor": 1,
            "appraisal": "synthetic",
        });
        std::fs::write(&self.endpoint, endpoint.to_string()).unwrap();
    }
    pub fn stop_part(&self, part: &str) {
        log(&self.dir, &format!("stop {part}"));
        self.script(&["stop-part", part]);
    }
    pub fn start_part(&self, part: &str) {
        log(&self.dir, &format!("start {part}"));
        self.script(&["start-part", part]);
    }
    /// One operation on the stopped Worker's stored logs and bodies.
    pub fn storage(&self, op: &str, log_id: &str, args: Value) -> Value {
        let request = json!({"op": op, "log": log_id, "args": args});
        let output = Command::new("node")
            .arg("tests/local-sync/storage-fixture.mjs")
            .env("HOME", self.dir.join("home"))
            .env("GH_CONFIG_DIR", self.dir.join("home/gh"))
            .env("XDG_CONFIG_HOME", self.dir.join("home/xdg"))
            .env_remove("GH_TOKEN")
            .env_remove("GITHUB_TOKEN")
            .arg(self.stack_dir())
            .arg(request.to_string())
            .current_dir(checkout())
            .output()
            .unwrap();
        log(
            &self.dir,
            &format!(
                "storage {request} -> {} {}",
                String::from_utf8_lossy(&output.stdout).trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        );
        assert!(output.status.success(), "storage fixture {op}");
        let text = String::from_utf8(output.stdout).unwrap();
        serde_json::from_str(text.trim().lines().last().unwrap()).unwrap()
    }
    pub fn device(&self, name: &str, gated: bool) -> Device {
        Device::spawn(self, name, gated)
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        let _ = Command::new("bash")
            .args(["--noprofile", "--norc", "scripts/local-stack.sh"])
            .arg("down")
            .current_dir(checkout())
            .env("LOCAL_STACK_DIR", self.stack_dir())
            .env("CARGO_TARGET_DIR", target())
            .env("LOCAL_STACK_BIND", "127.0.0.1")
            .env("HOME", self.dir.join("home"))
            .env("GH_CONFIG_DIR", self.dir.join("home/gh"))
            .env("XDG_CONFIG_HOME", self.dir.join("home/xdg"))
            .env_remove("GH_TOKEN")
            .env_remove("GITHUB_TOKEN")
            .status();
    }
}

/// One device: a test-only process over the production host APIs, with its
/// own directory (container, software test keys, traffic journal).
pub struct Device {
    pub name: String,
    pub dir: PathBuf,
    endpoint: PathBuf,
    gated: bool,
    process: std::process::Child,
    stdin: std::process::ChildStdin,
    replies: mpsc::Receiver<Value>,
    events: Arc<Mutex<Vec<Value>>>,
    seq: u64,
    pub pid: u32,
    log: PathBuf,
}

impl Device {
    fn spawn(stack: &Stack, name: &str, gated: bool) -> Self {
        let dir = stack.dir.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        Self::start(dir, stack.endpoint.clone(), gated, name, stack.dir.clone())
    }
    fn start(dir: PathBuf, endpoint: PathBuf, gated: bool, name: &str, run: PathBuf) -> Self {
        let stderr = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("device.stderr"))
            .unwrap();
        let mut process = Command::new(target().join("debug/examples/local_sync_device"))
            .arg(&dir)
            .arg(&endpoint)
            .arg(if gated { "gated" } else { "plain" })
            .env("HOME", run.join("home"))
            .env("GH_CONFIG_DIR", run.join("home/gh"))
            .env("XDG_CONFIG_HOME", run.join("home/xdg"))
            .env_remove("GH_TOKEN")
            .env_remove("GITHUB_TOKEN")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(stderr)
            .spawn()
            .expect("device process (cargo build --examples)");
        let pid = process.id();
        let stdin = process.stdin.take().unwrap();
        let stdout = process.stdout.take().unwrap();
        let (reply, replies) = mpsc::channel();
        let events = Arc::new(Mutex::new(Vec::new()));
        let seen = events.clone();
        let transcript = dir.join("device.stdout");
        std::thread::spawn(move || {
            let mut copy = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(transcript)
                .unwrap();
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let _ = writeln!(copy, "{line}");
                let Ok(value) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                if value.get("reply").is_some() {
                    let _ = reply.send(value);
                } else {
                    seen.lock().unwrap().push(value);
                }
            }
        });
        let device = Self {
            name: name.to_owned(),
            dir,
            endpoint,
            gated,
            process,
            stdin,
            replies,
            events,
            seq: 0,
            pid,
            log: run,
        };
        device.wait_event("ready", 60);
        log(&device.log, &format!("{name}: process {pid} started"));
        device
    }

    /// One request; its `ok` answer, or the device's error.
    pub fn try_call(&mut self, mut request: Value) -> Result<Value, String> {
        self.seq += 1;
        request["seq"] = json!(self.seq);
        writeln!(self.stdin, "{request}").map_err(|e| format!("{}: stdin: {e}", self.name))?;
        self.stdin.flush().unwrap();
        loop {
            let reply = self
                .replies
                .recv_timeout(Duration::from_secs(330))
                .map_err(|_| format!("{}: no reply to {request}", self.name))?;
            if reply["reply"] != json!(self.seq) {
                continue;
            }
            return match reply.get("ok") {
                Some(value) => Ok(value.clone()),
                None => Err(reply["err"].as_str().unwrap_or("error").to_owned()),
            };
        }
    }
    pub fn call(&mut self, request: Value) -> Value {
        let op = request["op"].clone();
        self.try_call(request)
            .unwrap_or_else(|e| panic!("{} {op}: {e}", self.name))
    }

    pub fn wait_event(&self, name: &str, seconds: u64) -> Value {
        let mut found = None;
        until(seconds, &format!("{}: event {name}", self.name), || {
            found = self
                .events
                .lock()
                .unwrap()
                .iter()
                .find(|e| e["event"] == name || e["name"] == name)
                .cloned();
            found.is_some()
        });
        found.unwrap()
    }
    /// Forget the events seen so far, so a later wait sees only new ones.
    pub fn forget_events(&self) {
        self.events.lock().unwrap().clear();
    }
    pub fn has_event(&self, name: &str) -> bool {
        self.events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e["event"] == name || e["name"] == name)
    }

    /// Kill the process outright (SIGKILL), as a crash or a forced quit.
    pub fn kill(mut self) -> Stopped {
        self.process.kill().unwrap();
        let status = self.process.wait().unwrap();
        log(
            &self.log,
            &format!("{}: process {} killed: {status}", self.name, self.pid),
        );
        Stopped {
            name: self.name,
            dir: self.dir,
            endpoint: self.endpoint,
            gated: self.gated,
            log: self.log,
            status: format!("{status}"),
        }
    }
    /// Quit as the app does: stop sync, then exit.
    pub fn quit(mut self) -> Stopped {
        self.call(json!({"op": "quit"}));
        drop(self.stdin);
        let status = self.process.wait().unwrap();
        log(
            &self.log,
            &format!("{}: process {} quit: {status}", self.name, self.pid),
        );
        Stopped {
            name: self.name,
            dir: self.dir,
            endpoint: self.endpoint,
            gated: self.gated,
            log: self.log,
            status: format!("{status}"),
        }
    }

    pub fn status(&mut self) -> Value {
        self.call(json!({"op": "status"}))
    }
    pub fn state(&mut self) -> String {
        self.status()["view"]["state"]
            .as_str()
            .unwrap_or("")
            .to_owned()
    }
    pub fn wait_state(&mut self, seconds: u64, state: &str) {
        let name = self.name.clone();
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            let status = self.status();
            if status["view"]["state"] == state {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{name}: timed out waiting for {state}: {status}"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    pub fn wait(&mut self, seconds: u64, what: &str, mut done: impl FnMut(&mut Self) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        while !done(self) {
            let status = self.status();
            assert!(
                Instant::now() < deadline,
                "{}: timed out: {what}: {status}",
                self.name
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    pub fn save(&mut self, window: &str, note: &str, text: &str) -> Value {
        let receipt =
            self.call(json!({"op": "save", "window": window, "note": note, "text": text}));
        log(
            &self.log,
            &format!("{}: saved {text:?} locally: {receipt}", self.name),
        );
        receipt
    }
    pub fn note(&mut self, window: &str, note: &str) -> Note {
        let value = self.call(json!({"op": "note", "window": window, "note": note}));
        Note {
            paragraphs: value["paragraphs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_str().unwrap().to_owned())
                .collect(),
            digest: value["digest"].as_str().unwrap().to_owned(),
            accepted: value["accepted_paragraphs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_str().unwrap().to_owned())
                .collect(),
            accepted_digest: value["accepted_digest"].as_str().unwrap().to_owned(),
        }
    }
    pub fn faults(&mut self, plan: Value) {
        let mut request = plan;
        request["op"] = json!("faults");
        self.call(request);
    }
    /// The device's traffic journal so far.
    pub fn frames(&self) -> Vec<Value> {
        frames(&self.dir)
    }
    pub fn db(&self) -> Db {
        Db::open(&self.dir)
    }
}

pub fn frames(dir: &Path) -> Vec<Value> {
    std::fs::read_to_string(dir.join("frames.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

/// A device whose process has ended; its files remain.
pub struct Stopped {
    pub name: String,
    pub dir: PathBuf,
    endpoint: PathBuf,
    gated: bool,
    log: PathBuf,
    pub status: String,
}
impl Stopped {
    /// A new process for the same device: same files, same software keys.
    pub fn restart(self) -> Device {
        Device::start(self.dir, self.endpoint, self.gated, &self.name, self.log)
    }
    pub fn db(&self) -> Db {
        Db::open(&self.dir)
    }
    pub fn frames(&self) -> Vec<Value> {
        frames(&self.dir)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    /// The working note (accepted plus this device's pending work).
    pub paragraphs: Vec<String>,
    pub digest: String,
    pub accepted: Vec<String>,
    pub accepted_digest: String,
}

/// A read-only view of a device's container file, beside (or after) its
/// process. Never written.
pub struct Db(rusqlite::Connection);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Package {
    pub update_id: i64,
    pub event_id: String,
    pub descriptor: Vec<u8>,
    pub body: Vec<u8>,
    pub acked: Option<i64>,
    pub outcome: Option<i64>,
    pub pending: bool,
}

#[derive(Debug)]
pub struct TypedPackage {
    pub event: Option<String>,
    pub position: Option<i64>,
    pub outcome: Option<i64>,
    pub pending: bool,
}

impl Db {
    fn open(dir: &Path) -> Self {
        let file = std::fs::read_dir(dir.join("accounts"))
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|x| x == "sqlite"))
            .expect("one container");
        Self(
            rusqlite::Connection::open_with_flags(
                file,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                    | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            )
            .unwrap(),
        )
    }
    /// Replicated accepted state and clocks in this read-only container.
    pub fn state_digest(&self, scope: bh_data::Scope) -> [u8; 32] {
        bh_data::testkit::state_digest(&self.0, scope).unwrap()
    }
    /// A typed mutation's durable package and its accepted log position.
    pub fn typed(&self, mutation: &str) -> Option<TypedPackage> {
        let bytes: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&mutation[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        self.0
            .query_row(
                "SELECT lower(hex(event_id)),ordered_position,outcome,
                EXISTS(SELECT 1 FROM data_pending p WHERE p.mutation=t.mutation)
             FROM typed_outbox t WHERE mutation=?1",
                [bytes],
                |r| {
                    Ok(TypedPackage {
                        event: r.get(0)?,
                        position: r.get(1)?,
                        outcome: r.get(2)?,
                        pending: r.get(3)?,
                    })
                },
            )
            .optional()
            .unwrap()
    }
    pub fn typed_count(&self) -> i64 {
        self.0
            .query_row("SELECT count(*) FROM typed_outbox", [], |r| r.get(0))
            .unwrap()
    }
    /// Local updates not yet accepted from their verified echo.
    pub fn pending(&self) -> i64 {
        self.0
            .query_row("SELECT COUNT(*) FROM pending_note_work", [], |r| r.get(0))
            .unwrap()
    }
    /// Every sealed package this device kept, with its Ack and outcome.
    pub fn packages(&self) -> Vec<Package> {
        let mut stmt = self
            .0
            .prepare(
                "SELECT o.update_id,o.event_id,o.descriptor,o.body,p.acked_position,p.outcome,
                   EXISTS(SELECT 1 FROM pending_note_work w WHERE w.update_id=o.update_id)
                 FROM note_outbox o LEFT JOIN note_outbox_progress p USING(update_id)
                 ORDER BY o.update_id",
            )
            .unwrap();
        stmt.query_map([], |r| {
            Ok(Package {
                update_id: r.get(0)?,
                event_id: hex(&r.get::<_, Vec<u8>>(1)?),
                descriptor: r.get(2)?,
                body: r.get(3)?,
                acked: r.get(4)?,
                outcome: r.get(5)?,
                pending: r.get(6)?,
            })
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
    }
    /// The kept local update of a local commit receipt's request id: its
    /// delta and whether it is still pending.
    pub fn update(&self, request: &str) -> Option<(Vec<u8>, bool)> {
        let id: Vec<u8> = (0..16)
            .map(|i| u8::from_str_radix(&request[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        self.0
            .query_row(
                "SELECT u.delta, EXISTS(SELECT 1 FROM pending_note_work w WHERE w.update_id=u.id)
                 FROM note_updates u WHERE u.request=?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .unwrap()
    }
    /// The base log's verified progress: position, head hash, stop reason.
    pub fn progress(&self, base: &str) -> (i64, String, Option<i64>, Option<Vec<u8>>) {
        let id: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&base[2 * i..2 * i + 2], 16).unwrap())
            .collect();
        self.0
            .query_row(
                "SELECT position,head_hash,stopped_reason,receipt FROM log_progress
                 WHERE log_kind=1 AND log_id=?1",
                [id],
                |r| {
                    Ok((
                        r.get(0)?,
                        hex(&r.get::<_, Vec<u8>>(1)?),
                        r.get(2)?,
                        r.get(3)?,
                    ))
                },
            )
            .unwrap()
    }
}

pub fn sha(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    // Plain SHA-256 for comparing journal digests, without another crate.
    let digest = bh_crypto::sha256(bytes);
    let mut out = String::new();
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Two genuinely separate devices of one account: the first signs up, the
/// second joins only by the first's QR code over the real relay, the first
/// approves (one confirmation), the account orders the addition, the base
/// gets its copy and the second bootstraps from signed history.
pub struct Pair {
    pub stack: Stack,
    pub mac: Device,
    pub fold: Device,
    /// The account's home note, the same note on both.
    pub note: String,
    pub base: String,
    pub mac_device: String,
    pub fold_device: String,
    pub account: String,
}

pub fn pair(name: &str) -> Pair {
    let stack = Stack::up(name);
    let mut mac = stack.device("mac", true);
    assert_eq!(
        mac.call(json!({"op": "signup", "password": PASSWORD}))["screen"]["screen"],
        "ready"
    );
    let opened = mac.call(json!({"op": "open"}));
    let note = opened["home"].as_str().unwrap().to_owned();
    mac.save("main", &note, "from the mac");
    mac.published(180, &note, "from the mac");
    mac.wait(180, "mac home stored", |d| {
        d.status()["view"]["home"] == "done"
    });
    let mut fold = stack.device("fold", false);
    assert_eq!(
        fold.call(json!({"op": "startup"}))["screen"]["screen"],
        "welcome"
    );
    let shown = mac.call(json!({"op": "show"}));
    let session = shown["session"].as_str().unwrap().to_owned();
    let ticket =
        fold.call(json!({"op": "join", "qr": shown["qr"], "label": "Test fold"}))["ticket"]
            .as_str()
            .unwrap()
            .to_owned();
    mac.wait(120, "candidate", |d| {
        d.call(json!({"op": "pair-status", "session": session}))["state"] == "candidate"
    });
    mac.call(json!({"op": "approve", "session": session}));
    mac.wait(180, "ordered", |d| {
        d.call(json!({"op": "pair-status", "session": session}))["state"] == "ordered"
    });
    fold.wait(180, "fold ready", |d| {
        let status = d.call(json!({"op": "join-status", "ticket": ticket}));
        assert_ne!(status["state"], "failed", "join failed: {status}");
        status["state"] == "ready"
    });
    mac.wait_state(180, "synced");
    let joined = fold.call(json!({"op": "open"}));
    assert_eq!(joined["home"], note, "one account home note");
    assert_eq!(joined["account"], opened["account"], "one account");
    assert_eq!(joined["base"], opened["base"], "one own base");
    assert_ne!(joined["device"], opened["device"], "two device identities");
    assert_ne!(joined["container"], opened["container"]);
    log(
        &stack.dir,
        &format!(
            "paired: account {} mac {} fold {}",
            opened["account"], opened["device"], joined["device"]
        ),
    );
    Pair {
        note,
        base: opened["base"].as_str().unwrap().to_owned(),
        mac_device: opened["device"].as_str().unwrap().to_owned(),
        fold_device: joined["device"].as_str().unwrap().to_owned(),
        account: opened["account"].as_str().unwrap().to_owned(),
        stack,
        mac,
        fold,
    }
}

impl Pair {
    pub fn base_log(&self) -> String {
        format!("01{}", self.base)
    }
}

/// Start a stopped device's next process through the production startup:
/// its account activates from its own container and keys, and its notes
/// open and sync again.
pub fn reopen(stopped: Stopped) -> Device {
    start_up(stopped.restart())
}

/// As `reopen`, with the device's network refused before its startup: no
/// sync task of the new process can connect until the test allows it.
pub fn reopen_offline(stopped: Stopped) -> Device {
    let mut device = stopped.restart();
    device.faults(json!({"offline": true}));
    start_up(device)
}

fn start_up(mut device: Device) -> Device {
    let screen = device.call(json!({"op": "startup"}));
    assert_eq!(
        screen["screen"]["screen"], "ready",
        "{}: {screen}",
        device.name
    );
    device.call(json!({"op": "open"}));
    device
}

/// How many paragraphs are exactly `text`.
pub fn count(paragraphs: &[String], text: &str) -> usize {
    paragraphs.iter().filter(|p| *p == text).count()
}

/// Journal entries matching `key == value`.
pub fn entries<'a>(frames: &'a [Value], key: &str, value: &str) -> Vec<&'a Value> {
    frames.iter().filter(|f| f[key] == value).collect()
}

/// Both devices synced with equal notes; the note as both see it.
pub fn converged(p: &mut Pair, seconds: u64) -> Note {
    let note = p.note.clone();
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        p.mac.wake();
        p.fold.wake();
        let (mac, fold) = (p.mac.note("main", &note), p.fold.note("main", &note));
        let synced = p.mac.state() == "synced" && p.fold.state() == "synced";
        if synced && mac == fold && mac.paragraphs == mac.accepted {
            return mac;
        }
        assert!(
            Instant::now() < deadline,
            "not converged: mac {mac:?} {} fold {fold:?} {}",
            p.mac.status(),
            p.fold.status()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

impl Device {
    /// Until this device's own `text` is accepted from its echo and
    /// nothing of its is unaccepted.
    pub fn published(&mut self, seconds: u64, note: &str, text: &str) {
        let note = note.to_owned();
        self.wait(seconds, &format!("{text:?} published"), |d| {
            count(&d.note("main", &note).accepted, text) == 1
                && d.db().pending() == 0
                && d.state() == "synced"
        });
    }
    pub fn wake(&mut self) {
        let _ = self.try_call(json!({"op": "wake"}));
    }
}
