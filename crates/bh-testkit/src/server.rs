use std::{
    io::{self, BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock, mpsc},
    time::{Duration, Instant},
};
use tempfile::TempDir;
use url::Url;

#[derive(Default)]
pub struct LocalServerOptions {
    pub tinfoil_upstream: Option<Url>,
    pub vars: Vec<(String, String)>,
}

pub struct LocalServer {
    url: Url,
    persist: Option<TempDir>,
    child: Mutex<Option<Child>>,
    birth: Option<String>,
    marker: String,
    vars: Vec<(String, String)>,
    remote_token: Option<String>,
    tinfoil_upstream: Option<Url>,
}

#[cfg(target_os = "linux")]
fn birth(pid: u32) -> Option<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<_> = stat.rsplit_once(") ")?.1.split_whitespace().collect();
    if fields[0] == "Z" {
        return None;
    }
    Some(fields.get(19)?.to_string())
}

#[cfg(target_os = "macos")]
fn child_ps(pid: u32, field: &str) -> Option<String> {
    let output = Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", field])
        .output()
        .ok()?;
    if output.status.success() {
        let value = String::from_utf8(output.stdout).ok()?.trim().to_owned();
        (!value.is_empty()).then_some(value)
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn birth(pid: u32) -> Option<String> {
    child_ps(pid, "lstart=")
}

static EXIT_SERVERS: OnceLock<Mutex<Vec<&'static LocalServer>>> = OnceLock::new();

extern "C" fn clean_exit_servers() {
    if let Some(servers) = EXIT_SERVERS.get() {
        for server in servers.lock().unwrap().iter() {
            server.stop_shared();
            if let Some(dir) = &server.persist {
                let _ = std::fs::remove_dir_all(dir.path());
            }
        }
    }
}

/// Register a static local server for cleanup on normal process exit. A killed
/// process cannot run this hook; check.sh's temporary directory covers its tests.
pub fn register_exit_cleanup(server: &'static LocalServer) {
    let servers = EXIT_SERVERS.get_or_init(|| {
        assert_eq!(unsafe { libc::atexit(clean_exit_servers) }, 0);
        Mutex::new(Vec::new())
    });
    let mut servers = servers.lock().unwrap();
    if !servers
        .iter()
        .any(|registered| std::ptr::eq(*registered, server))
    {
        servers.push(server);
    }
}

impl LocalServer {
    pub fn start() -> Self {
        Self::start_with(LocalServerOptions::default())
    }

    pub fn start_with_vars(vars: &[(&str, &str)]) -> Self {
        Self::start_with(LocalServerOptions {
            vars: vars
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            ..LocalServerOptions::default()
        })
    }

    pub fn start_with(opts: LocalServerOptions) -> Self {
        let persist = tempfile::tempdir().expect("temporary persistence");
        let mut server = Self {
            // On first start Miniflare binds port 0, then reports its actual URL.
            url: Url::parse("http://127.0.0.1/").unwrap(),
            marker: persist.path().to_string_lossy().into_owned(),
            persist: Some(persist),
            child: Mutex::new(None),
            birth: None,
            vars: opts.vars,
            remote_token: None,
            tinfoil_upstream: opts.tinfoil_upstream,
        };
        server.launch();
        server
    }

    fn launch(&mut self) {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut command = Command::new("node");
        command
            .current_dir(self.persist_dir())
            .arg(root.join("scripts/local-server.mjs"))
            .arg("--persist")
            .arg(self.persist_dir());
        if let Some(port) = self.url.port() {
            command.arg("--port").arg(port.to_string());
        }
        for (key, value) in &self.vars {
            command.arg("--var").arg(format!("{key}={value}"));
        }
        if let Some(url) = &self.tinfoil_upstream {
            command.arg("--tinfoil-upstream").arg(url.as_str());
        }
        let home = self.persist_dir().join("home");
        std::fs::create_dir_all(&home).unwrap();
        command
            .env_clear()
            .env("PATH", std::env::var("PATH").expect("PATH"))
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("BH_LOCAL_SERVER_LAUNCH_ID", &self.marker)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().expect("start local Worker");
        let pid = child.id();
        let born = birth(pid).expect("read child birth time");
        let stdout = child.stdout.take().unwrap();
        let stderr = child.stderr.take().unwrap();
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let mut stream = BufReader::new(stdout);
            let mut line = String::new();
            let result = stream.read_line(&mut line).map(|_| line);
            let _ = sender.send(result);
            // The Worker may log after startup; never leave its stdout pipe full.
            let _ = io::copy(&mut stream, &mut io::sink());
        });
        std::thread::spawn(move || {
            let _ = io::copy(&mut BufReader::new(stderr), &mut io::sink());
        });
        *self.child.get_mut().unwrap() = Some(child);
        self.birth = Some(born);
        // Bundling and launching workerd can exceed 30 s when parallel checks
        // contend for CPU; this bounds startup, not any HTTP/test wait.
        let line = receiver
            .recv_timeout(Duration::from_secs(120))
            .expect("Worker did not become ready")
            .expect("Worker stdout failed");
        let observed: serde_json::Value = serde_json::from_str(&line).expect("Worker URL line");
        let url =
            Url::parse(observed["url"].as_str().expect("Worker URL string")).expect("Worker URL");
        assert_eq!(url.host_str(), Some("127.0.0.1"), "Worker bound wrong host");
        assert!(url.port().is_some(), "Worker did not report a bound port");
        if let Some(old_port) = self.url.port() {
            assert_eq!(
                url.port(),
                Some(old_port),
                "Worker bound wrong restart port"
            );
        }
        self.url = url;
    }

    pub fn shared() -> &'static Self {
        static SERVER: OnceLock<LocalServer> = OnceLock::new();
        let server = SERVER.get_or_init(Self::start);
        register_exit_cleanup(server);
        server
    }

    pub fn from_env() -> &'static Self {
        static REMOTE: OnceLock<LocalServer> = OnceLock::new();
        if let Ok(url) = std::env::var("BH_TEST_SERVER") {
            let url = Url::parse(&url).expect("BH_TEST_SERVER URL");
            assert_ne!(
                url.host_str().map(|host| host.trim_end_matches('.')),
                Some("api.basehero.com"),
                "tests must never target production"
            );
            REMOTE.get_or_init(|| Self {
                url,
                remote_token: Some(
                    std::env::var("BH_TEST_OPERATOR_TOKEN").expect("BH_TEST_OPERATOR_TOKEN"),
                ),
                persist: None,
                child: Mutex::new(None),
                birth: None,
                marker: String::new(),
                vars: vec![],
                tinfoil_upstream: None,
            })
        } else {
            Self::shared()
        }
    }

    pub fn url(&self) -> Url {
        self.url.clone()
    }
    pub fn operator_token(&self) -> &str {
        self.remote_token.as_deref().unwrap_or("local-operator")
    }
    pub fn persist_dir(&self) -> &Path {
        self.persist.as_ref().expect("local only").path()
    }
    /// Changes a local Worker's setting for its next restart.
    pub fn set_var(&mut self, key: &str, value: &str) {
        assert!(
            self.persist.is_some(),
            "remote server cannot change settings"
        );
        if let Some((_, current)) = self.vars.iter_mut().find(|(name, _)| name == key) {
            *current = value.to_owned();
        } else {
            self.vars.push((key.to_owned(), value.to_owned()));
        }
    }
    pub fn restart(&mut self) {
        assert!(self.persist.is_some(), "remote server cannot restart");
        self.stop();
        self.launch();
    }

    fn verified(&self, child: &Child) -> bool {
        let Some(expected) = &self.birth else {
            return false;
        };
        let pid = child.id();
        if birth(pid).as_ref() != Some(expected) {
            return false;
        }
        #[cfg(target_os = "linux")]
        {
            std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|cmd| {
                cmd.windows(b"scripts/local-server.mjs".len())
                    .any(|w| w == b"scripts/local-server.mjs")
            }) && std::fs::read(format!("/proc/{pid}/environ")).is_ok_and(|env| {
                let expected = format!("BH_LOCAL_SERVER_LAUNCH_ID={}", self.marker);
                env.split(|b| *b == 0)
                    .any(|entry| entry == expected.as_bytes())
            })
        }
        #[cfg(target_os = "macos")]
        {
            unsafe extern "C" {
                fn kill(pid: i32, signal: i32) -> i32;
            }
            // Both creation time and command must still match this child before
            // closing its stdin or sending a signal to its PID.
            (unsafe { kill(pid as i32, 0) == 0 })
                && child_ps(pid, "command=")
                    .is_some_and(|cmd| cmd.contains("scripts/local-server.mjs"))
        }
    }

    /// Stops the verified local Worker, preserving its port and persisted data for restart.
    pub fn stop(&mut self) {
        self.stop_shared();
    }

    fn stop_shared(&self) {
        let mut guard = self.child.lock().unwrap();
        let Some(child) = guard.as_mut() else { return };
        if !self.verified(child) {
            if child.try_wait().ok().flatten().is_none() {
                eprintln!("local Worker PID could not be verified; refusing to stop it");
            }
            guard.take();
            return;
        }
        child.stdin.take(); // stdin close disposes Miniflare and its workerd child
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if child.try_wait().ok().flatten().is_some() {
                guard.take();
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if self.verified(child) {
            let _ = child.kill();
            let _ = child.wait();
        }
        guard.take();
    }
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[macro_export]
macro_rules! local_only {
    () => {
        if std::env::var_os("BH_TEST_SERVER").is_some() {
            eprintln!("local-only test skipped remotely ({}:{})", file!(), line!());
            return;
        }
    };
}

#[cfg(test)]
mod tests {
    use super::LocalServer;

    #[test]
    fn shared_server_is_cleaned_on_normal_exit() {
        if std::env::var_os("BH_TESTKIT_EXIT_CHILD").is_some() {
            let server = LocalServer::shared();
            println!(
                "BH_TESTKIT_EXIT_TEST {} {}",
                server.persist_dir().display(),
                server.child.lock().unwrap().as_ref().unwrap().id()
            );
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "server::tests::shared_server_is_cleaned_on_normal_exit",
                "--nocapture",
            ])
            .env("BH_TESTKIT_EXIT_CHILD", "1")
            .env_remove("BH_TEST_SERVER")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8(output.stdout).unwrap();
        let marker = text.split("BH_TESTKIT_EXIT_TEST ").nth(1).expect(&text);
        let mut parts = marker.split_whitespace();
        let path = parts.next().unwrap();
        let pid: u32 = parts.next().unwrap().parse().unwrap();
        assert!(
            !std::path::Path::new(path).exists(),
            "left server folder: {path}"
        );
        assert!(super::birth(pid).is_none(), "left server process: {pid}");
    }

    #[test]
    fn from_env_refuses_production_host() {
        // This unit-test executable has no other tests that read these variables.
        for host in ["api.basehero.com", "api.basehero.com."] {
            unsafe {
                std::env::set_var("BH_TEST_SERVER", format!("https://{host}"));
                std::env::set_var("BH_TEST_OPERATOR_TOKEN", "test-token");
            }
            assert!(
                std::panic::catch_unwind(LocalServer::from_env).is_err(),
                "accepted {host}"
            );
        }
    }
}
