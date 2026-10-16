//! Native Mac update coordinator. No page supplies release URLs, signing keys
//! or paths.
//!
//! A check reads signed metadata only. Install update downloads, verifies the
//! exact artifact and extracts and checks the new bundle while the person keeps
//! writing; no lock is held across the download or any OS wait. Only then does
//! the native save barrier hold every window until its writing is committed
//! and its restart records are written. The bundle is exchanged, a waiter
//! reopens it once this process has exited, and the app exits. A refusal at
//! any step leaves the running app usable; an update never discards writing.

#[cfg(any(target_os = "macos", test))]
use crate::lifecycle::Refusal;
#[cfg(any(target_os = "macos", test))]
use bh_release::{decode_hex, download::Transport, mac_installer::PreparedInstall};
use serde::Serialize;
#[cfg(any(target_os = "macos", test))]
use std::{
    future::Future,
    io,
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::{Duration, Instant},
};

/// What the page shows. Carries signed display text only, never a URL, path
/// or key.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    phase: &'static str,
    version: Option<u64>,
    whats_new: Option<String>,
    message: Option<String>,
}
impl Status {
    fn new(phase: &'static str) -> Self {
        Self {
            phase,
            version: None,
            whats_new: None,
            message: None,
        }
    }
}

/// The update channel compiled into the native binary. Invalid or incomplete
/// settings disable updates.
#[cfg(any(target_os = "macos", test))]
struct Channel {
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    transport: Transport,
    key: [u8; 32],
}
#[cfg(any(target_os = "macos", test))]
impl Channel {
    fn from_parts(
        metadata: Option<&str>,
        artifacts: Option<&str>,
        key: Option<&str>,
    ) -> Option<Self> {
        Some(Self {
            transport: Transport::new(
                url::Url::parse(metadata?).ok()?,
                url::Url::parse(artifacts?).ok()?,
                128 * 1024,
                300 * 1024 * 1024,
            )
            .ok()?,
            key: decode_hex(key?)?,
        })
    }
}

/// This app's bundle and its canonical integer CFBundleVersion, when running
/// from a BaseHero.app with `identifier`. Tauri's display semver is not the
/// release number.
#[cfg(any(target_os = "macos", test))]
fn installed_app(exe: &Path, identifier: &str) -> Option<(PathBuf, u64)> {
    let app = exe.parent()?.parent()?.parent()?;
    if app.file_name()? != "BaseHero.app" {
        return None;
    }
    let value = plist::Value::from_file(app.join("Contents/Info.plist")).ok()?;
    let info = value.as_dictionary()?;
    if info.get("CFBundleIdentifier")?.as_string()? != identifier {
        return None;
    }
    let raw = info.get("CFBundleVersion")?.as_string()?;
    let version = raw.parse::<u64>().ok()?;
    (version > 0 && raw == version.to_string()).then(|| (app.to_path_buf(), version))
}

/// Reopen `app` with `launcher` once `old_pid` has exited. Every container
/// holds an exclusive lock for its process's lifetime, so the new process
/// must not start while this one still owns it. A fixed script with
/// positional arguments, detached from this process group, outlives the exit.
#[cfg(any(target_os = "macos", test))]
fn spawn_relaunch_helper(old_pid: u32, app: &Path, launcher: &Path) -> io::Result<()> {
    use std::os::unix::process::CommandExt;
    std::process::Command::new("/bin/sh")
        .args([
            "-c",
            "while kill -0 \"$1\" 2>/dev/null; do sleep 0.1; done; exec \"$2\" \"$3\"",
            "bh-update-relaunch",
        ])
        .arg(old_pid.to_string())
        .arg(launcher)
        .arg(app)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .map(|_| ())
}

/// Which step of an explicit install failed before any save was requested.
#[cfg(any(target_os = "macos", test))]
pub(crate) enum Fetch {
    Download,
    Prepare,
}

/// Where releases come from: the network in the app, fixtures in tests.
#[cfg(any(target_os = "macos", test))]
pub(crate) trait Releases: Send + Sync + 'static {
    type Found: Send + 'static;
    fn version(found: &Self::Found) -> u64;
    fn notes(found: &Self::Found) -> &str;
    /// Signed metadata only, never the artifact. `None`: nothing newer.
    fn check(&self) -> impl Future<Output = Result<Option<Self::Found>, ()>> + Send;
    /// After Install update only: download and verify the exact artifact,
    /// then extract it beside this app and check it is this app's bundle at
    /// the signed version.
    fn fetch(
        &self,
        found: Self::Found,
    ) -> impl Future<Output = Result<PreparedInstall, Fetch>> + Send;
}

/// The native save barrier and the exit that follows a replacement.
#[cfg(any(target_os = "macos", test))]
pub(crate) trait Barrier: Send + Sync + 'static {
    /// Holds every window with its writing committed; dropping it resumes.
    type Ready: Send + 'static;
    fn prepare(
        &self,
        deadline: Instant,
    ) -> impl Future<Output = Result<Self::Ready, Refusal>> + Send;
    /// Start the relaunch, then exit. On error `ready` has been dropped.
    fn exit(&self, ready: Self::Ready) -> io::Result<()>;
}

#[cfg(any(target_os = "macos", test))]
const CHECK_LIMIT: Duration = Duration::from_secs(60);
#[cfg(any(target_os = "macos", test))]
const FETCH_LIMIT: Duration = Duration::from_secs(60 * 60);
/// Typing idle, every window's save and the restart records.
#[cfg(any(target_os = "macos", test))]
const SAVE_LIMIT: Duration = Duration::from_secs(30);
/// A previous hold's release finishes on a worker thread.
#[cfg(any(target_os = "macos", test))]
const BUSY_RETRY: Duration = Duration::from_millis(250);

#[cfg(any(target_os = "macos", test))]
const DOWNLOAD_FAILED: &str = "Couldn't download a verified update. BaseHero stays open.";
#[cfg(any(target_os = "macos", test))]
const PREPARE_FAILED: &str = "Couldn't check the downloaded update. BaseHero stays open.";
#[cfg(any(target_os = "macos", test))]
const INSTALL_FAILED: &str = "Couldn't install the update. BaseHero stays open.";
#[cfg(any(target_os = "macos", test))]
fn refused(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::NotSaved => {
            "Some writing couldn't be saved, so BaseHero didn't restart. Your writing is still here. Try again once it's saved."
        }
        Refusal::TimedOut => {
            "BaseHero waits for a pause in typing and for every window to save. Your writing is still here. Try again in a moment."
        }
        Refusal::Busy => {
            "BaseHero is busy closing or saving a window. Your writing is still here. Try again in a moment."
        }
    }
}

#[cfg(any(target_os = "macos", test))]
struct State<F> {
    status: Status,
    found: Option<F>,
    /// Kept after a refused save so Try again needs no second download.
    prepared: Option<(PreparedInstall, u64)>,
    checking: bool,
    installing: bool,
    /// The bundle was replaced; this process runs the old version.
    installed: bool,
    dismissed: Option<u64>,
}

#[cfg(any(target_os = "macos", test))]
pub(crate) struct Coordinator<R: Releases, B: Barrier> {
    state: Mutex<State<R::Found>>,
    releases: Option<R>,
    barrier: B,
}
#[cfg(any(target_os = "macos", test))]
impl<R: Releases, B: Barrier> Coordinator<R, B> {
    /// `None`: no channel, or not running from a release bundle.
    pub(crate) fn new(releases: Option<R>, barrier: B) -> Self {
        let phase = if releases.is_some() {
            "idle"
        } else {
            "disabled"
        };
        Self {
            state: Mutex::new(State {
                status: Status::new(phase),
                found: None,
                prepared: None,
                checking: false,
                installing: false,
                installed: false,
                dismissed: None,
            }),
            releases,
            barrier,
        }
    }
    fn lock(&self) -> MutexGuard<'_, State<R::Found>> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    pub(crate) fn status(&self) -> Status {
        self.lock().status.clone()
    }
    fn busy(state: &State<R::Found>) -> bool {
        state.installing || state.installed || state.prepared.is_some()
    }
    /// Look for a newer signed release. A failed automatic check is silent.
    pub(crate) async fn check(&self) {
        let Some(releases) = &self.releases else {
            return;
        };
        {
            let mut state = self.lock();
            if state.checking || Self::busy(&state) {
                return;
            }
            state.checking = true;
        }
        let result = tokio::time::timeout(CHECK_LIMIT, releases.check()).await;
        let mut state = self.lock();
        state.checking = false;
        if Self::busy(&state) {
            return;
        }
        match result {
            Ok(Ok(Some(found))) => {
                let version = R::version(&found);
                state.status = Status {
                    phase: if state.dismissed == Some(version) {
                        "dismissed"
                    } else {
                        "available"
                    },
                    version: Some(version),
                    whats_new: Some(R::notes(&found).to_owned()),
                    message: None,
                };
                state.found = Some(found);
            }
            Ok(Ok(None)) => {
                state.found = None;
                // Let the initiating Try again turn an empty recheck into
                // error/Dismiss rather than erasing its retry status here.
                if state.status.phase != "retry" {
                    state.status = Status::new("idle");
                }
            }
            Ok(Err(())) | Err(_) => {}
        }
    }
    fn fail(&self, phase: &'static str, version: u64, message: String) -> Result<(), ()> {
        let mut state = self.lock();
        state.installing = false;
        state.status = Status {
            phase,
            version: Some(version),
            whats_new: None,
            message: Some(message),
        };
        Err(())
    }
    /// The person chose Install update (or Try again).
    pub(crate) async fn install(&self) -> Result<(), ()> {
        let Some(releases) = &self.releases else {
            return Err(());
        };
        // A failed download consumed its verified discovery. Try again does
        // one fresh signed-metadata check before attempting the artifact again.
        let retry_version = {
            let state = self.lock();
            (state.status.phase == "retry"
                && state.found.is_none()
                && state.prepared.is_none()
                && !state.installing
                && !state.installed)
                .then_some(state.status.version)
                .flatten()
        };
        if let Some(version) = retry_version {
            self.check().await;
            let mut state = self.lock();
            if let Some(found) = &state.found {
                // A different release needs its own explicit Install click.
                if R::version(found) != version {
                    return Err(());
                }
            } else {
                // Another window's recheck/install may already own the work.
                // Do not replace its status or clear its installing flag.
                if state.status.phase == "retry" && !state.checking && !state.installing {
                    state.status = Status {
                        phase: "error",
                        version: Some(version),
                        whats_new: None,
                        message: Some(DOWNLOAD_FAILED.into()),
                    };
                }
                return Err(());
            }
        }
        let (fetch, prepared, version) = {
            let mut state = self.lock();
            if state.installing || state.installed {
                return Err(());
            }
            let (fetch, prepared, version) = match (state.prepared.take(), state.found.take()) {
                (Some((prepared, version)), _) => (None, Some(prepared), version),
                (None, Some(found)) => {
                    let version = R::version(&found);
                    (Some(found), None, version)
                }
                (None, None) => return Err(()),
            };
            state.installing = true;
            state.status = Status {
                version: Some(version),
                ..Status::new(if fetch.is_some() {
                    "downloading"
                } else {
                    "saving"
                })
            };
            (fetch, prepared, version)
        };
        let prepared = match (prepared, fetch) {
            (Some(prepared), _) => prepared,
            (None, Some(found)) => {
                match tokio::time::timeout(FETCH_LIMIT, releases.fetch(found)).await {
                    Ok(Ok(prepared)) => prepared,
                    Ok(Err(Fetch::Prepare)) => {
                        return self.fail("error", version, PREPARE_FAILED.into());
                    }
                    Ok(Err(Fetch::Download)) | Err(_) => {
                        return self.fail("retry", version, DOWNLOAD_FAILED.into());
                    }
                }
            }
            (None, None) => unreachable!("one install source"),
        };
        self.lock().status = Status {
            version: Some(version),
            ..Status::new("saving")
        };
        let ready = match self.ready().await {
            Ok(ready) => ready,
            Err(refusal) => {
                self.lock().prepared = Some((prepared, version));
                return self.fail("retry", version, refused(refusal).into());
            }
        };
        // A failed exchange drops `ready`, which resumes every window.
        let exchanged = tokio::task::spawn_blocking(move || prepared.commit(|| Ok(ready))).await;
        let Ok(Ok(ready)) = exchanged else {
            return self.fail("error", version, INSTALL_FAILED.into());
        };
        self.lock().installed = true;
        if self.barrier.exit(ready).is_err() {
            return self.fail(
                "restart",
                version,
                format!(
                    "BaseHero {version} is installed, but couldn't restart. Quit and reopen BaseHero to finish."
                ),
            );
        }
        Ok(())
    }
    /// Readiness, retrying while another hold is still being released.
    async fn ready(&self) -> Result<B::Ready, Refusal> {
        let deadline = Instant::now() + SAVE_LIMIT;
        loop {
            match self.barrier.prepare(deadline).await {
                Err(Refusal::Busy) if Instant::now() + BUSY_RETRY < deadline => {
                    tokio::time::sleep(BUSY_RETRY).await;
                }
                result => return result,
            }
        }
    }
    /// Hide this version (and any message); drop a prepared update.
    pub(crate) fn not_now(&self) {
        let mut state = self.lock();
        if state.installing {
            return;
        }
        if matches!(
            state.status.phase,
            "available" | "retry" | "error" | "restart"
        ) {
            state.dismissed = state.status.version;
            state.status.phase = "dismissed";
        }
        state.prepared = None;
    }
}

/// The app's releases, channel and save barrier.
#[cfg(target_os = "macos")]
mod runtime {
    use super::*;
    use crate::note_host::{NoteHost, RestartReady};
    use bh_release::{
        VerifyFor,
        download::{DownloadError, FoundRelease},
        mac_installer::{self, ExtractLimits},
    };
    use tauri::{AppHandle, Manager};

    const PLATFORM: &str = "macos-aarch64";
    const CHANNEL: &str = "stable";
    const LIMITS: ExtractLimits = ExtractLimits {
        entries: 20_000,
        bytes: 1024 * 1024 * 1024,
    };

    pub struct Feed {
        channel: Channel,
        installed: PathBuf,
        running: u64,
    }
    impl Releases for Feed {
        type Found = FoundRelease;
        fn version(found: &FoundRelease) -> u64 {
            found.version()
        }
        fn notes(found: &FoundRelease) -> &str {
            found.whats_new()
        }
        async fn check(&self) -> Result<Option<FoundRelease>, ()> {
            let expected = VerifyFor {
                release_key: &self.channel.key,
                platform: PLATFORM,
                channel: CHANNEL,
                running_version: self.running,
            };
            match self.channel.transport.check(expected).await {
                Ok(found) => Ok(Some(found)),
                Err(DownloadError::Release(bh_release::ReleaseError::NotNewer)) => Ok(None),
                Err(_) => Err(()),
            }
        }
        async fn fetch(&self, found: FoundRelease) -> Result<PreparedInstall, Fetch> {
            // The private stage sits beside the app, on the volume it is exchanged on.
            let beside = self.installed.parent().ok_or(Fetch::Download)?;
            let staged = self
                .channel
                .transport
                .download(found, beside)
                .await
                .map_err(|_| Fetch::Download)?;
            mac_installer::prepare(staged, &self.installed, crate::APP_IDENTIFIER, LIMITS)
                .await
                .map_err(|_| Fetch::Prepare)
        }
    }

    pub struct AppBarrier {
        app: AppHandle,
        installed: PathBuf,
    }
    impl Barrier for AppBarrier {
        type Ready = RestartReady;
        async fn prepare(&self, deadline: Instant) -> Result<RestartReady, Refusal> {
            let host = self.app.state::<NoteHost>();
            host.prepare_restart(&self.app, deadline).await
        }
        fn exit(&self, ready: RestartReady) -> io::Result<()> {
            ready.exit(&self.app, || {
                spawn_relaunch_helper(
                    std::process::id(),
                    &self.installed,
                    Path::new("/usr/bin/open"),
                )
            })
        }
    }

    pub type MacCoordinator = Coordinator<Feed, AppBarrier>;

    /// Manage the coordinator and start automatic checks. Without a complete
    /// compiled channel, or outside a release bundle, updates are disabled.
    pub fn install(app: &tauri::App) {
        let feed = Channel::from_parts(
            option_env!("BH_UPDATE_METADATA_URL"),
            option_env!("BH_UPDATE_ARTIFACT_BASE"),
            option_env!("BH_UPDATE_PUBLIC_KEY"),
        )
        .and_then(|channel| {
            let exe = std::env::current_exe().ok()?;
            let (installed, running) = installed_app(&exe, crate::APP_IDENTIFIER)?;
            Some(Feed {
                channel,
                installed,
                running,
            })
        });
        let enabled = feed.is_some();
        let installed = feed
            .as_ref()
            .map(|feed| feed.installed.clone())
            .unwrap_or_default();
        app.manage(MacCoordinator::new(
            feed,
            AppBarrier {
                app: app.handle().clone(),
                installed,
            },
        ));
        if enabled {
            start(app.handle().clone());
        }
    }

    /// First check shortly after launch, then about every six hours, each
    /// jittered. Requests carry no account, base or device identifier.
    fn start(app: AppHandle) {
        tauri::async_runtime::spawn(async move {
            let jitter =
                |below: u64| u64::from(u16::from_be_bytes(bh_crypto::random::<2>())) % below;
            let mut wait = Duration::from_secs(10 + jitter(60));
            loop {
                tokio::time::sleep(wait).await;
                app.state::<MacCoordinator>().check().await;
                wait = Duration::from_secs(60 * (270 + jitter(181)));
            }
        });
    }
}
#[cfg(target_os = "macos")]
pub use runtime::install;

/// The page's update commands. Same paths on every platform; only the Mac
/// has an updater.
#[cfg(target_os = "macos")]
pub mod commands {
    use super::{Status, runtime::MacCoordinator};
    use tauri::{AppHandle, Manager};

    #[tauri::command]
    pub fn update_status(state: tauri::State<'_, MacCoordinator>) -> Status {
        state.status()
    }
    #[tauri::command]
    pub async fn update_not_now(state: tauri::State<'_, MacCoordinator>) -> Result<(), ()> {
        state.not_now();
        Ok(())
    }
    /// Starts the install and returns; the page follows `update_status`.
    #[tauri::command]
    pub fn update_install(app: AppHandle) {
        tauri::async_runtime::spawn(async move {
            let _ = app.state::<MacCoordinator>().install().await;
        });
    }
}
#[cfg(not(target_os = "macos"))]
pub mod commands {
    use super::Status;

    #[tauri::command]
    pub fn update_status() -> Status {
        Status::new("disabled")
    }
    #[tauri::command]
    pub fn update_not_now() {}
    #[tauri::command]
    pub fn update_install() {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::Refusal;
    use bh_crypto::{Secret, SigningKey, sha256};
    use bh_release::{
        AvailableRelease, Metadata, SignedRelease, VerifyFor, check_available,
        download::StagedArtifact,
        mac_installer::{self, ExtractLimits, PreparedInstall},
    };
    use flate2::{Compression, write::GzEncoder};
    use std::{
        collections::VecDeque,
        fs,
        io::Write,
        path::{Path, PathBuf},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Instant,
    };

    const ID: &str = "app.basehero.client";
    type Log = Arc<Mutex<Vec<String>>>;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn key() -> SigningKey {
        SigningKey::from_seed(&Secret::<32>::from_slice(&[9; 32]).unwrap())
    }
    fn bundle(id: &str, version: u64) -> Vec<u8> {
        let plist = format!(
            "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>{id}</string><key>CFBundleVersion</key><string>{version}</string></dict></plist>"
        );
        let mut tar = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::default()));
        for (path, data) in [
            ("BaseHero.app/Contents/Info.plist", plist.as_bytes()),
            ("BaseHero.app/Contents/MacOS/bh-client", &b"new"[..]),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o755);
            header.set_cksum();
            tar.append_data(&mut header, path, data).unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap()
    }
    fn signed(archive: &[u8], version: u64, platform: &str, signer: &SigningKey) -> SignedRelease {
        let metadata = Metadata {
            version,
            platform: platform.into(),
            channel: "stable".into(),
            source_commit: "a".repeat(40),
            file_name: "BaseHero-macos-aarch64.app.tar.gz".into(),
            sha256: hex(&sha256(archive)),
            whats_new: "Safer notes <b>".into(),
        };
        let signature = hex(&signer.sign(&metadata.signing_bytes().unwrap()));
        SignedRelease {
            metadata,
            signature,
        }
    }

    /// Real signature, hash, extraction and identity checks over fixture bytes;
    /// only the network is replaced.
    struct Fixture {
        release: Mutex<SignedRelease>,
        served: Mutex<Vec<u8>>,
        installed: PathBuf,
        checks: AtomicUsize,
        recheck_result: AtomicUsize,
        recheck_pause: Mutex<
            Option<(
                tokio::sync::oneshot::Sender<()>,
                tokio::sync::oneshot::Receiver<()>,
            )>,
        >,
        fetches: AtomicUsize,
    }
    impl Releases for Arc<Fixture> {
        type Found = AvailableRelease;
        fn version(found: &AvailableRelease) -> u64 {
            found.version()
        }
        fn notes(found: &AvailableRelease) -> &str {
            found.whats_new()
        }
        async fn check(&self) -> Result<Option<AvailableRelease>, ()> {
            self.checks.fetch_add(1, Ordering::SeqCst);
            let pause = self.recheck_pause.lock().unwrap().take();
            if let Some((started, resume)) = pause {
                let _ = started.send(());
                let _ = resume.await;
            }
            match self.recheck_result.load(Ordering::SeqCst) {
                1 => return Err(()),
                2 => return Ok(None),
                _ => {}
            }
            match check_available(
                &self.release.lock().unwrap(),
                VerifyFor {
                    release_key: &key().public(),
                    platform: "macos-aarch64",
                    channel: "stable",
                    running_version: 42,
                },
            ) {
                Ok(found) => Ok(Some(found)),
                Err(bh_release::ReleaseError::NotNewer) => Ok(None),
                Err(_) => Err(()),
            }
        }
        async fn fetch(&self, found: AvailableRelease) -> Result<PreparedInstall, Fetch> {
            self.fetches.fetch_add(1, Ordering::SeqCst);
            let mut file = tempfile::tempfile().unwrap();
            file.write_all(&self.served.lock().unwrap()).unwrap();
            let staged = StagedArtifact::verify(file, &found).map_err(|_| Fetch::Download)?;
            mac_installer::prepare(
                staged,
                &self.installed,
                ID,
                ExtractLimits {
                    entries: 20,
                    bytes: 4096,
                },
            )
            .await
            .map_err(|_| Fetch::Prepare)
        }
    }

    struct Ready {
        log: Log,
        exited: bool,
    }
    impl Drop for Ready {
        fn drop(&mut self) {
            if !self.exited {
                self.log.lock().unwrap().push("resumed".into());
            }
        }
    }
    /// Stands in for the native save barrier and relaunch.
    struct Saver {
        log: Log,
        installed: PathBuf,
        replies: Mutex<VecDeque<Result<(), Refusal>>>,
        relaunch: Result<(), ()>,
        break_exchange: bool,
    }
    impl Barrier for Saver {
        type Ready = Ready;
        async fn prepare(&self, _deadline: Instant) -> Result<Ready, Refusal> {
            let old = self.installed.join("old").exists();
            self.log.lock().unwrap().push(format!("prepare old={old}"));
            self.replies.lock().unwrap().pop_front().unwrap_or(Ok(()))?;
            if self.break_exchange {
                fs::remove_dir_all(&self.installed).unwrap();
            }
            Ok(Ready {
                log: Arc::clone(&self.log),
                exited: false,
            })
        }
        fn exit(&self, mut ready: Ready) -> std::io::Result<()> {
            let new = fs::read(self.installed.join("Contents/MacOS/bh-client")).ok();
            self.log.lock().unwrap().push(format!(
                "relaunch new={}",
                new.as_deref() == Some(&b"new"[..])
            ));
            self.relaunch
                .map_err(|()| std::io::Error::other("injected relaunch failure"))?;
            ready.exited = true;
            self.log.lock().unwrap().push("exit".into());
            Ok(())
        }
    }

    struct Case {
        _dir: tempfile::TempDir,
        installed: PathBuf,
        fixture: Arc<Fixture>,
        log: Log,
        coordinator: Coordinator<Arc<Fixture>, Saver>,
    }
    fn case(release: SignedRelease, served: Vec<u8>, saver: impl FnOnce(&mut Saver)) -> Case {
        // Fixture bundles stay inside this crate's temporary directory, never /Applications or another user's installed app.
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let installed = dir.path().join("BaseHero.app");
        fs::create_dir(&installed).unwrap();
        fs::write(installed.join("old"), b"old").unwrap();
        let fixture = Arc::new(Fixture {
            release: Mutex::new(release),
            served: Mutex::new(served),
            installed: installed.clone(),
            checks: AtomicUsize::new(0),
            recheck_result: AtomicUsize::new(0),
            recheck_pause: Mutex::new(None),
            fetches: AtomicUsize::new(0),
        });
        let log = Log::default();
        let mut barrier = Saver {
            log: Arc::clone(&log),
            installed: installed.clone(),
            replies: Mutex::new(VecDeque::new()),
            relaunch: Ok(()),
            break_exchange: false,
        };
        saver(&mut barrier);
        Case {
            _dir: dir,
            installed,
            coordinator: Coordinator::new(Some(Arc::clone(&fixture)), barrier),
            fixture,
            log,
        }
    }
    fn good() -> Case {
        let archive = bundle(ID, 43);
        case(
            signed(&archive, 43, "macos-aarch64", &key()),
            archive,
            |_| {},
        )
    }
    fn log(case: &Case) -> Vec<String> {
        case.log.lock().unwrap().clone()
    }
    fn is_old(path: &Path) -> bool {
        path.join("old").exists()
    }

    #[tokio::test]
    async fn check_announces_signed_notes_without_downloading() {
        let case = good();
        assert_eq!(case.coordinator.status().phase, "idle");
        case.coordinator.check().await;
        let status = case.coordinator.status();
        assert_eq!(status.phase, "available");
        assert_eq!(status.version, Some(43));
        assert_eq!(status.whats_new.as_deref(), Some("Safer notes <b>"));
        assert_eq!(case.fixture.fetches.load(Ordering::SeqCst), 0);
        assert!(log(&case).is_empty());
    }

    #[tokio::test]
    async fn older_wrong_platform_or_badly_signed_metadata_is_never_offered() {
        let archive = bundle(ID, 43);
        let stranger = SigningKey::from_seed(&Secret::<32>::from_slice(&[7; 32]).unwrap());
        for release in [
            signed(&archive, 42, "macos-aarch64", &key()),
            signed(&archive, 41, "macos-aarch64", &key()),
            signed(&archive, 43, "windows-aarch64", &key()),
            signed(&archive, 43, "macos-aarch64", &stranger),
        ] {
            let case = case(release, archive.clone(), |_| {});
            case.coordinator.check().await;
            assert_eq!(case.coordinator.status().phase, "idle");
            assert!(case.coordinator.install().await.is_err());
            assert_eq!(case.fixture.fetches.load(Ordering::SeqCst), 0);
            assert!(is_old(&case.installed));
        }
    }

    #[tokio::test]
    async fn install_verifies_and_prepares_before_saving_then_exchanges_and_relaunches() {
        let case = good();
        case.coordinator.check().await;
        case.coordinator.install().await.unwrap();
        assert_eq!(case.fixture.fetches.load(Ordering::SeqCst), 1);
        assert_eq!(
            log(&case),
            ["prepare old=true", "relaunch new=true", "exit"],
            "saving waits for the prepared bundle; exchange precedes relaunch"
        );
        assert!(!is_old(&case.installed));
    }

    #[tokio::test]
    async fn corrupt_archive_or_another_apps_bundle_is_refused_before_saving() {
        let archive = bundle(ID, 43);
        let mut corrupt = archive.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        let other = bundle("app.example.other", 43);
        for (release, served, phase) in [
            (
                signed(&archive, 43, "macos-aarch64", &key()),
                corrupt,
                "retry",
            ),
            (signed(&other, 43, "macos-aarch64", &key()), other, "error"),
        ] {
            let case = case(release, served, |_| {});
            case.coordinator.check().await;
            assert!(case.coordinator.install().await.is_err());
            let status = case.coordinator.status();
            assert_eq!(status.phase, phase);
            assert!(status.message.unwrap().contains("BaseHero stays open"));
            assert!(log(&case).is_empty(), "no save barrier was requested");
            assert!(is_old(&case.installed));
        }
    }

    #[tokio::test]
    async fn failed_download_rechecks_metadata_then_retries_without_a_new_user_check() {
        let archive = bundle(ID, 43);
        let case = case(
            signed(&archive, 43, "macos-aarch64", &key()),
            b"corrupt archive".to_vec(),
            |_| {},
        );
        case.coordinator.check().await;
        assert!(case.coordinator.install().await.is_err());
        let status = case.coordinator.status();
        assert_eq!(status.phase, "retry");
        assert!(status.message.unwrap().contains("BaseHero stays open"));
        assert!(is_old(&case.installed));
        assert!(log(&case).is_empty());
        *case.fixture.served.lock().unwrap() = archive;
        case.coordinator.install().await.unwrap();
        assert_eq!(case.fixture.checks.load(Ordering::SeqCst), 2);
        assert_eq!(case.fixture.fetches.load(Ordering::SeqCst), 2);
        assert!(!is_old(&case.installed));
    }

    #[tokio::test]
    async fn a_newer_rechecked_version_waits_for_its_own_install_click() {
        let old_archive = bundle(ID, 43);
        let case = case(
            signed(&old_archive, 43, "macos-aarch64", &key()),
            b"corrupt archive".to_vec(),
            |_| {},
        );
        case.coordinator.check().await;
        assert!(case.coordinator.install().await.is_err());
        assert_eq!(case.coordinator.status().phase, "retry");
        let mut newer = signed(&bundle(ID, 44), 44, "macos-aarch64", &key());
        newer.metadata.whats_new = "Important change".into();
        newer.signature = hex(&key().sign(&newer.metadata.signing_bytes().unwrap()));
        *case.fixture.release.lock().unwrap() = newer;
        assert!(case.coordinator.install().await.is_err());
        let status = case.coordinator.status();
        assert_eq!(status.phase, "available");
        assert_eq!(status.version, Some(44));
        assert_eq!(status.whats_new.as_deref(), Some("Important change"));
        assert_eq!(case.fixture.checks.load(Ordering::SeqCst), 2);
        assert_eq!(case.fixture.fetches.load(Ordering::SeqCst), 1);
        assert!(is_old(&case.installed));
    }

    #[tokio::test]
    async fn a_second_try_again_during_recheck_keeps_the_first_attempts_status() {
        let archive = bundle(ID, 43);
        let case = case(
            signed(&archive, 43, "macos-aarch64", &key()),
            b"corrupt archive".to_vec(),
            |_| {},
        );
        case.coordinator.check().await;
        assert!(case.coordinator.install().await.is_err());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (resume_tx, resume_rx) = tokio::sync::oneshot::channel();
        *case.fixture.recheck_pause.lock().unwrap() = Some((started_tx, resume_rx));
        let first = case.coordinator.install();
        tokio::pin!(first);
        tokio::select! {
            _ = &mut first => panic!("recheck did not pause"),
            _ = started_rx => {}
        }
        assert!(case.coordinator.install().await.is_err());
        assert_eq!(case.coordinator.status().phase, "retry");
        *case.fixture.served.lock().unwrap() = archive;
        resume_tx.send(()).unwrap();
        first.await.unwrap();
        assert_eq!(case.fixture.checks.load(Ordering::SeqCst), 2);
        assert_eq!(case.fixture.fetches.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn failed_download_with_unavailable_metadata_stops_at_error_without_another_fetch() {
        for recheck_result in [1, 2] {
            let archive = bundle(ID, 43);
            let case = case(
                signed(&archive, 43, "macos-aarch64", &key()),
                b"corrupt archive".to_vec(),
                |_| {},
            );
            case.coordinator.check().await;
            assert!(case.coordinator.install().await.is_err());
            assert_eq!(case.coordinator.status().phase, "retry");
            case.fixture
                .recheck_result
                .store(recheck_result, Ordering::SeqCst);
            assert!(case.coordinator.install().await.is_err());
            assert_eq!(case.coordinator.status().phase, "error");
            assert_eq!(case.fixture.checks.load(Ordering::SeqCst), 2);
            assert_eq!(case.fixture.fetches.load(Ordering::SeqCst), 1);
            assert!(is_old(&case.installed));
        }
    }

    #[tokio::test]
    async fn unsaved_writing_refuses_restart_and_retry_needs_no_second_download() {
        for refusal in [Refusal::NotSaved, Refusal::TimedOut] {
            let case = case(
                signed(&bundle(ID, 43), 43, "macos-aarch64", &key()),
                bundle(ID, 43),
                |saver| saver.replies.get_mut().unwrap().push_back(Err(refusal)),
            );
            case.coordinator.check().await;
            assert!(case.coordinator.install().await.is_err());
            let status = case.coordinator.status();
            assert_eq!(status.phase, "retry");
            assert!(status.message.unwrap().contains("still here"));
            assert!(
                is_old(&case.installed),
                "no exchange without committed writing"
            );
            assert_eq!(log(&case), ["prepare old=true"]);

            case.coordinator.install().await.unwrap();
            assert_eq!(case.fixture.fetches.load(Ordering::SeqCst), 1);
            assert_eq!(
                log(&case),
                [
                    "prepare old=true",
                    "prepare old=true",
                    "relaunch new=true",
                    "exit"
                ]
            );
        }
    }

    #[tokio::test]
    async fn busy_saving_is_retried_within_the_deadline() {
        let case = case(
            signed(&bundle(ID, 43), 43, "macos-aarch64", &key()),
            bundle(ID, 43),
            |saver| {
                let replies = saver.replies.get_mut().unwrap();
                replies.push_back(Err(Refusal::Busy));
                replies.push_back(Err(Refusal::Busy));
            },
        );
        case.coordinator.check().await;
        case.coordinator.install().await.unwrap();
        assert_eq!(
            log(&case),
            [
                "prepare old=true",
                "prepare old=true",
                "prepare old=true",
                "relaunch new=true",
                "exit"
            ]
        );
    }

    #[tokio::test]
    async fn failed_exchange_releases_the_hold_and_keeps_the_app_running() {
        let case = case(
            signed(&bundle(ID, 43), 43, "macos-aarch64", &key()),
            bundle(ID, 43),
            |saver| saver.break_exchange = true,
        );
        case.coordinator.check().await;
        assert!(case.coordinator.install().await.is_err());
        assert_eq!(log(&case), ["prepare old=true", "resumed"]);
        let status = case.coordinator.status();
        assert_eq!(status.phase, "error");
        assert!(status.message.unwrap().contains("BaseHero stays open"));
    }

    #[tokio::test]
    async fn failed_relaunch_says_installed_and_stops_checking() {
        let case = case(
            signed(&bundle(ID, 43), 43, "macos-aarch64", &key()),
            bundle(ID, 43),
            |saver| saver.relaunch = Err(()),
        );
        case.coordinator.check().await;
        assert!(case.coordinator.install().await.is_err());
        assert_eq!(
            log(&case),
            ["prepare old=true", "relaunch new=true", "resumed"],
            "editing resumes; nothing is discarded"
        );
        assert!(!is_old(&case.installed));
        let status = case.coordinator.status();
        assert_eq!(status.phase, "restart");
        assert_eq!(
            status.message.as_deref(),
            Some(
                "BaseHero 43 is installed, but couldn't restart. Quit and reopen BaseHero to finish."
            )
        );
        let checks = case.fixture.checks.load(Ordering::SeqCst);
        case.coordinator.check().await;
        assert_eq!(case.fixture.checks.load(Ordering::SeqCst), checks);
        assert!(case.coordinator.install().await.is_err());
    }

    #[tokio::test]
    async fn not_now_hides_this_version_and_drops_a_prepared_update() {
        let case = case(
            signed(&bundle(ID, 43), 43, "macos-aarch64", &key()),
            bundle(ID, 43),
            |saver| {
                saver
                    .replies
                    .get_mut()
                    .unwrap()
                    .push_back(Err(Refusal::NotSaved))
            },
        );
        case.coordinator.check().await;
        let _ = case.coordinator.install().await;
        assert_eq!(fs::read_dir(case._dir.path()).unwrap().count(), 2);
        case.coordinator.not_now();
        assert_eq!(case.coordinator.status().phase, "dismissed");
        assert_eq!(fs::read_dir(case._dir.path()).unwrap().count(), 1);
        case.coordinator.check().await;
        assert_eq!(case.coordinator.status().phase, "dismissed");
    }

    #[test]
    fn unconfigured_or_partial_channel_is_disabled() {
        assert!(Channel::from_parts(None, None, None).is_none());
        assert!(
            Channel::from_parts(
                Some("https://updates.example.test/metadata.json"),
                None,
                Some(&"ab".repeat(32))
            )
            .is_none()
        );
        assert!(
            Channel::from_parts(
                Some("http://updates.example.test/metadata.json"),
                Some("https://updates.example.test/"),
                Some(&"ab".repeat(32))
            )
            .is_none()
        );
        let disabled = Coordinator::<Arc<Fixture>, Saver>::new(
            None,
            Saver {
                log: Log::default(),
                installed: PathBuf::new(),
                replies: Mutex::new(VecDeque::new()),
                relaunch: Ok(()),
                break_exchange: false,
            },
        );
        assert_eq!(disabled.status().phase, "disabled");
    }

    #[test]
    fn complete_channel_uses_only_embedded_trust_and_https() {
        let channel = Channel::from_parts(
            Some("https://updates.example.test/releases/stable.json"),
            Some("https://cdn.example.test/mac/"),
            Some(&"ab".repeat(32)),
        )
        .unwrap();
        assert_eq!(channel.key, [0xab; 32]);
        for (metadata, key) in [
            ("https://updates.example.test/?device=1", "ab".repeat(32)),
            ("https://updates.example.test/", "é".repeat(32)),
        ] {
            assert!(
                Channel::from_parts(
                    Some(metadata),
                    Some("https://cdn.example.test/mac/"),
                    Some(&key)
                )
                .is_none()
            );
        }
    }

    #[test]
    fn running_version_comes_from_this_apps_canonical_bundle_version() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("BaseHero.app");
        fs::create_dir_all(app.join("Contents/MacOS")).unwrap();
        let exe = app.join("Contents/MacOS/bh-client");
        let write = |id: &str, version: &str| {
            fs::write(
                app.join("Contents/Info.plist"),
                format!(
                    "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>{id}</string><key>CFBundleVersion</key><string>{version}</string></dict></plist>"
                ),
            )
            .unwrap();
        };
        write(ID, "42");
        assert_eq!(installed_app(&exe, ID), Some((app.clone(), 42)));
        for (id, version) in [
            (ID, "042"),
            (ID, "0"),
            (ID, "0.1.0"),
            ("app.example.other", "42"),
        ] {
            write(id, version);
            assert_eq!(installed_app(&exe, ID), None, "{id} {version}");
        }
        write(ID, "42");
        assert_eq!(installed_app(&dir.path().join("bh-client"), ID), None);
    }

    /// The same transport and bundle checks as the running app, against a
    /// supplied HTTPS feed and an isolated old bundle. Never opens a WebView,
    /// asks for keys, exchanges the app or restarts it.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    #[ignore = "requires isolated old app and HTTPS signed feed in BH_TEST_UPDATE_* variables"]
    async fn https_feed_prepares_new_bundle_and_refuses_invalid_metadata() {
        let app = PathBuf::from(std::env::var("BH_TEST_UPDATE_APP").unwrap());
        let identifier = std::env::var("BH_TEST_UPDATE_IDENTIFIER").unwrap();
        let base = std::env::var("BH_TEST_UPDATE_BASE").unwrap();
        let key = std::env::var("BH_TEST_UPDATE_PUBLIC_KEY").unwrap();
        let (_, running) =
            installed_app(&app.join("Contents/MacOS/bh-client"), &identifier).unwrap();
        let mut verified = false;
        for name in [
            "stable-macos-aarch64.json",
            "tampered.json",
            "older.json",
            "wrong-platform.json",
        ] {
            let channel =
                Channel::from_parts(Some(&format!("{base}{name}")), Some(&base), Some(&key))
                    .unwrap();
            let found = tokio::time::timeout(
                CHECK_LIMIT,
                channel.transport.check(VerifyFor {
                    release_key: &channel.key,
                    platform: "macos-aarch64",
                    channel: "stable",
                    running_version: running,
                }),
            )
            .await
            .unwrap();
            if name != "stable-macos-aarch64.json" {
                assert!(found.is_err(), "invalid metadata was accepted: {name}");
                continue;
            }
            let found = found.unwrap();
            assert!(found.version() > running);
            let staged = tokio::time::timeout(
                FETCH_LIMIT,
                channel.transport.download(found, app.parent().unwrap()),
            )
            .await
            .unwrap()
            .unwrap();
            let prepared = mac_installer::prepare(
                staged,
                &app,
                &identifier,
                ExtractLimits {
                    entries: 20_000,
                    bytes: 1024 * 1024 * 1024,
                },
            )
            .await
            .unwrap();
            drop(prepared);
            verified = true;
        }
        assert!(verified);
        assert_eq!(
            installed_app(&app.join("Contents/MacOS/bh-client"), &identifier)
                .unwrap()
                .1,
            running
        );
    }

    #[test]
    fn relaunch_helper_waits_for_the_old_process_to_exit() {
        use std::{os::unix::fs::PermissionsExt, process::Command, time::Duration};
        let dir = tempfile::tempdir().unwrap();
        let launcher = dir.path().join("open-fixture");
        let marker = dir.path().join("reopened");
        fs::write(&launcher, "#!/bin/sh\nprintf reopened > \"$1\"\n").unwrap();
        fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();
        let mut old = Command::new("/bin/sh")
            .args(["-c", "sleep 1"])
            .spawn()
            .unwrap();
        spawn_relaunch_helper(old.id(), &marker, &launcher).unwrap();
        std::thread::sleep(Duration::from_millis(250));
        assert!(!marker.exists(), "relaunch overlapped the old process");
        old.wait().unwrap();
        for _ in 0..50 {
            // Shell redirection creates the marker before printf writes it.
            // Wait for the content, not that intermediate empty file.
            if fs::read(&marker).ok().as_deref() == Some(b"reopened") {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_eq!(fs::read(&marker).unwrap(), b"reopened");
    }
}
