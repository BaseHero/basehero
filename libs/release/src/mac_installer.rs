//! Mac bundle installer. No restart or data-directory access: the app owns
//! readiness, exit and relaunch. Only accepts the verified, held inode from
//! `download`, never an artifact path.
use crate::download::StagedArtifact;
use std::io;
use std::{
    cell::Cell,
    collections::HashSet,
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    rc::Rc,
};
use thiserror::Error;

#[derive(Clone, Copy)]
pub struct ExtractLimits {
    pub entries: u64,
    pub bytes: u64,
}

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("invalid archive path")]
    Path,
    #[error("archive entry outside BaseHero.app")]
    OutsideBundle,
    #[error("hard link refused")]
    HardLink,
    #[error("unsupported archive entry")]
    EntryType,
    #[error("archive exceeds extraction limits")]
    Limit,
    #[error("invalid bundle identifier")]
    Identity,
    #[error("bundle version differs from signed version")]
    Version,
    #[error("cannot read or extract update: {0}")]
    Io(#[from] io::Error),
    #[error("cannot replace app bundle: {0}")]
    Swap(io::Error),
}

/// Fully extracted, identity-checked app, still beside the unchanged installed app.
/// Dropping this value discards the prepared update without touching the current app.
pub struct PreparedInstall {
    stage_dir: tempfile::TempDir,
    installed: PathBuf,
}

/// Extract the verified artifact beside `installed` and check that it is the
/// same app (`identifier`, the running app's own bundle identifier) at the
/// signed version: integer v maps to CFBundleVersion's canonical decimal
/// representation, with no leading zeroes. Info.plist only confirms identity;
/// it grants no authority. Nothing is replaced until `PreparedInstall::commit`.
pub async fn prepare(
    staged: StagedArtifact,
    installed: &Path,
    identifier: &str,
    limits: ExtractLimits,
) -> Result<PreparedInstall, InstallError> {
    let installed = installed.to_path_buf();
    let identifier = identifier.to_owned();
    tokio::task::spawn_blocking(move || {
        let stage_dir = prepare_blocking(staged, &installed, &identifier, limits)?;
        Ok(PreparedInstall {
            stage_dir,
            installed,
        })
    })
    .await
    .map_err(|e| InstallError::Io(io::Error::other(e)))?
}

impl PreparedInstall {
    /// Call the app's restart readiness immediately before the exchange. On
    /// exchange failure the ready token is dropped, releasing the hold. The
    /// returned token owns the successful exit and relaunch; the installer never
    /// starts another process.
    pub fn commit<R>(
        self,
        before_exchange: impl FnOnce() -> io::Result<R>,
    ) -> Result<R, InstallError> {
        let ready = before_exchange().map_err(InstallError::Swap)?;
        exchange(&self.stage_dir, &self.installed)?;
        Ok(ready)
    }
}

// Tests use the same prepare + commit path as production.
#[cfg(test)]
async fn install(
    staged: StagedArtifact,
    installed: &Path,
    limits: ExtractLimits,
) -> Result<(), InstallError> {
    install_blocking(staged, installed, "app.basehero.client", limits, || Ok(()))
}

#[cfg(test)]
fn install_blocking<R>(
    staged: StagedArtifact,
    installed: &Path,
    identifier: &str,
    limits: ExtractLimits,
    before_exchange: impl FnOnce() -> io::Result<R>,
) -> Result<R, InstallError> {
    PreparedInstall {
        stage_dir: prepare_blocking(staged, installed, identifier, limits)?,
        installed: installed.to_path_buf(),
    }
    .commit(before_exchange)
}

fn prepare_blocking(
    mut staged: StagedArtifact,
    installed: &Path,
    identifier: &str,
    limits: ExtractLimits,
) -> Result<tempfile::TempDir, InstallError> {
    if installed.file_name().is_none_or(|n| n != "BaseHero.app")
        || !fs::symlink_metadata(installed)?.file_type().is_dir()
    {
        return Err(InstallError::Path);
    }
    let parent = installed.parent().ok_or(InstallError::Path)?;
    // The private directory is created beside the installed bundle so all
    // renames are on the same filesystem. Dropping it cleans failed extracts.
    let stage_dir = tempfile::Builder::new()
        .prefix(".basehero-update-")
        .tempdir_in(parent)?;
    let next = stage_dir.path().join("BaseHero.app");
    extract(staged.reader(), stage_dir.path(), limits)?;
    check_identity(&next, identifier, staged.version())?;
    Ok(stage_dir)
}

fn exchange(stage_dir: &tempfile::TempDir, installed: &Path) -> Result<(), InstallError> {
    let next = stage_dir.path().join("BaseHero.app");
    // One same-volume exchange keeps the installed path present even if the process
    // dies. If the filesystem cannot exchange, leave the old app untouched.
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        &next,
        rustix::fs::CWD,
        installed,
        rustix::fs::RenameFlags::EXCHANGE,
    )
    .map_err(|error| InstallError::Swap(error.into()))?;
    // The old bundle now lives in the private directory, removed on drop.
    // App data and Keychain are untouched.
    Ok(())
}

fn archive_path(raw: &[u8]) -> Result<PathBuf, InstallError> {
    let text = std::str::from_utf8(raw).map_err(|_| InstallError::Path)?;
    let text = text.strip_suffix('/').unwrap_or(text);
    if text.is_empty()
        || text.contains('\\')
        || text
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == "..")
        || Path::new(text)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(InstallError::Path);
    }
    let mut parts = text.split('/');
    if parts.next() != Some("BaseHero.app") {
        return Err(InstallError::OutsideBundle);
    }
    Ok(PathBuf::from(text))
}

// Also cap tar metadata and padding, so long-name/PAX records cannot allocate
// unbounded memory before they become entries. Ordinary tar headers/padding have
// ample room under the per-entry allowance.
struct ReadBudget<R> {
    inner: R,
    left: u64,
    exceeded: Rc<Cell<bool>>,
}
impl<R: Read> Read for ReadBudget<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.left == 0 {
            let mut extra = [0];
            if self.inner.read(&mut extra)? == 0 {
                return Ok(0);
            }
            self.exceeded.set(true);
            return Err(io::Error::other("expanded archive exceeds budget"));
        }
        let bound = self.left.min(buf.len() as u64) as usize;
        let n = self.inner.read(&mut buf[..bound])?;
        self.left -= n as u64;
        Ok(n)
    }
}

fn extract(reader: &mut dyn Read, stage: &Path, limits: ExtractLimits) -> Result<(), InstallError> {
    let max = limits
        .bytes
        .checked_add(
            limits
                .entries
                .checked_mul(4096)
                .ok_or(InstallError::Limit)?,
        )
        .and_then(|n| n.checked_add(4096))
        .ok_or(InstallError::Limit)?;
    let exceeded = Rc::new(Cell::new(false));
    let gz = flate2::read::GzDecoder::new(reader);
    let budget = ReadBudget {
        inner: gz,
        left: max,
        exceeded: exceeded.clone(),
    };
    let mut tar = tar::Archive::new(budget);
    let result = (|| -> Result<(), InstallError> {
        let mut count = 0u64;
        let mut total = 0u64;
        let mut seen = HashSet::new();
        for entry in tar.entries()? {
            let mut entry = entry?;
            count = count.checked_add(1).ok_or(InstallError::Limit)?;
            if count > limits.entries {
                return Err(InstallError::Limit);
            }
            let path = archive_path(&entry.path_bytes())?;
            if !seen.insert(path.clone()) {
                return Err(InstallError::Path);
            }
            let kind = entry.header().entry_type();
            if kind.is_hard_link() {
                return Err(InstallError::HardLink);
            }
            if kind.is_symlink() {
                return Err(InstallError::EntryType);
            }
            let target = stage.join(&path);
            if kind.is_dir() {
                fs::create_dir_all(&target)?;
            } else if kind.is_file() {
                total = total.checked_add(entry.size()).ok_or(InstallError::Limit)?;
                if total > limits.bytes {
                    return Err(InstallError::Limit);
                }
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut out = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)?;
                io::copy(&mut entry, &mut out)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = entry.header().mode()? & 0o755;
                    out.set_permissions(fs::Permissions::from_mode(mode))?;
                }
            } else {
                return Err(InstallError::EntryType);
            }
        }
        Ok(())
    })();
    if exceeded.get() {
        Err(InstallError::Limit)
    } else {
        result
    }
}

fn check_identity(
    bundle: &Path,
    identifier: &str,
    signed_version: u64,
) -> Result<(), InstallError> {
    let info = bundle.join("Contents/Info.plist");
    let meta = fs::symlink_metadata(&info).map_err(|_| InstallError::Identity)?;
    if !meta.file_type().is_file() || meta.len() > 1024 * 1024 {
        return Err(InstallError::Identity);
    }
    let value = plist::Value::from_file(&info).map_err(|_| InstallError::Identity)?;
    let dict = value.as_dictionary().ok_or(InstallError::Identity)?;
    if dict
        .get("CFBundleIdentifier")
        .and_then(plist::Value::as_string)
        != Some(identifier)
    {
        return Err(InstallError::Identity);
    }
    if dict
        .get("CFBundleVersion")
        .and_then(plist::Value::as_string)
        != Some(signed_version.to_string().as_str())
    {
        return Err(InstallError::Version);
    }
    Ok(())
}

#[cfg(test)]
impl PartialEq for InstallError {
    fn eq(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

#[cfg(test)]
fn exchange_with_failure(
    staged: StagedArtifact,
    installed: &Path,
    limits: ExtractLimits,
) -> Result<(), InstallError> {
    install_blocking(staged, installed, "app.basehero.client", limits, || {
        Err::<(), _>(io::Error::other("injected"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::{
        fs,
        io::{Seek, SeekFrom, Write},
    };
    use tar::{Builder, EntryType, Header};

    fn archive(entries: &[(&str, EntryType, &[u8], Option<&str>)]) -> Vec<u8> {
        archive_with_mode(entries, 0o755)
    }
    fn archive_with_mode(entries: &[(&str, EntryType, &[u8], Option<&str>)], mode: u32) -> Vec<u8> {
        let gz = GzEncoder::new(Vec::new(), Compression::default());
        let mut tar = Builder::new(gz);
        for &(path, kind, data, link) in entries {
            let mut header = Header::new_gnu();
            header.set_entry_type(kind);
            header.set_size(if kind.is_file() { data.len() as u64 } else { 0 });
            header.set_mode(mode);
            if let Some(target) = link {
                header.set_link_name(target).unwrap();
            }
            // Craft raw hostile header names: Builder::append_data refuses traversal.
            let raw = header.as_mut_bytes();
            raw[..100].fill(0);
            raw[..path.len()].copy_from_slice(path.as_bytes());
            header.set_cksum();
            tar.append(&header, if kind.is_file() { data } else { &[] })
                .unwrap();
        }
        tar.into_inner().unwrap().finish().unwrap()
    }
    fn plist(id: &str, version: &str) -> Vec<u8> {
        format!("<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>{id}</string><key>CFBundleVersion</key><string>{version}</string></dict></plist>").into_bytes()
    }
    fn valid(id: &str, version: &str) -> Vec<u8> {
        let p = plist(id, version);
        archive(&[
            (
                "BaseHero.app/Contents/Info.plist",
                EntryType::Regular,
                &p,
                None,
            ),
            (
                "BaseHero.app/Contents/MacOS/BaseHero",
                EntryType::Regular,
                b"new",
                None,
            ),
        ])
    }
    fn stage(data: &[u8]) -> StagedArtifact {
        let mut f = tempfile::tempfile_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        f.write_all(data).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        StagedArtifact::test_verified(f, 2)
    }
    const ID: &str = "app.basehero.client";
    fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        // Fixture bundles stay inside this crate's temporary directory, never /Applications or another user's installed app.
        let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        let app = dir.path().join("BaseHero.app");
        fs::create_dir(&app).unwrap();
        fs::write(app.join("old"), b"old").unwrap();
        (dir, app)
    }
    fn assert_old(app: &Path) {
        assert_eq!(fs::read(app.join("old")).unwrap(), b"old");
    }
    fn limits() -> ExtractLimits {
        ExtractLimits {
            entries: 20,
            bytes: 4096,
        }
    }
    fn run_at(bytes: &[u8], app: &Path) -> Result<(), InstallError> {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(install(stage(bytes), app, limits()))
    }
    fn run(bytes: &[u8], limits: ExtractLimits) -> (Result<(), InstallError>, tempfile::TempDir) {
        let (dir, app) = fixture();
        let result =
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(install(stage(bytes), &app, limits));
        if result.is_err() {
            assert_old(&app);
        }
        (result, dir)
    }
    // Run on macOS with BH_TEST_MAC_ARCHIVE and BH_TEST_MAC_VERSION set to
    // a locally packaged archive and its release number.
    // This supplies a test-only verified handle, not a production release signature.
    // The installed fixture stays under this crate's worktree, never /Applications.
    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "requires BH_TEST_MAC_ARCHIVE from a local source-only Mac build"]
    fn packaged_mac_archive_is_accepted_by_installer() {
        let archive = std::env::var("BH_TEST_MAC_ARCHIVE").expect("set BH_TEST_MAC_ARCHIVE");
        let version = std::env::var("BH_TEST_MAC_VERSION")
            .expect("set BH_TEST_MAC_VERSION to the locally packaged release number")
            .parse::<u64>()
            .expect("integer release number");
        let mut f = tempfile::tempfile_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        io::copy(&mut fs::File::open(archive).unwrap(), &mut f).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        let (dir, app) = fixture();
        install_blocking(
            StagedArtifact::test_verified(f, version),
            &app,
            ID,
            ExtractLimits {
                entries: 1000,
                bytes: 200 * 1024 * 1024,
            },
            || Ok(()),
        )
        .unwrap();
        assert!(!app.join("old").exists());
        assert!(app.join("Contents/MacOS/bh-client").is_file());
        let status = std::process::Command::new("codesign")
            .args(["--verify", "--deep", "--strict", "--verbose=2"])
            .arg(dir.path().join("BaseHero.app"))
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn hostile_archives_refuse_without_modifying_install() {
        let p = plist("app.basehero.client", "2");
        let cases = [
            (
                "traversal",
                archive(&[("BaseHero.app/../escape", EntryType::Regular, b"x", None)]),
                InstallError::Path,
            ),
            (
                "absolute",
                archive(&[("/BaseHero.app/escape", EntryType::Regular, b"x", None)]),
                InstallError::Path,
            ),
            (
                "symlink",
                archive(&[(
                    "BaseHero.app/Contents/out",
                    EntryType::Symlink,
                    b"",
                    Some("../../../escape"),
                )]),
                InstallError::EntryType,
            ),
            (
                "duplicate",
                archive(&[
                    (
                        "BaseHero.app/Contents/Info.plist",
                        EntryType::Regular,
                        &p,
                        None,
                    ),
                    (
                        "BaseHero.app/Contents/Info.plist",
                        EntryType::Regular,
                        &p,
                        None,
                    ),
                ]),
                InstallError::Path,
            ),
            (
                "hardlink",
                archive(&[(
                    "BaseHero.app/Contents/out",
                    EntryType::Link,
                    b"",
                    Some("BaseHero.app/old"),
                )]),
                InstallError::HardLink,
            ),
            (
                "device",
                archive(&[("BaseHero.app/Contents/out", EntryType::Char, b"", None)]),
                InstallError::EntryType,
            ),
            (
                "outside",
                archive(&[("Else.app/Contents/Info.plist", EntryType::Regular, &p, None)]),
                InstallError::OutsideBundle,
            ),
        ];
        for (name, bytes, error) in cases {
            assert_eq!(run(&bytes, limits()).0.unwrap_err(), error, "{name}");
        }
        assert_eq!(
            run(
                &valid("app.basehero.client", "2"),
                ExtractLimits {
                    entries: 1,
                    bytes: 4096
                }
            )
            .0
            .unwrap_err(),
            InstallError::Limit
        );
        assert_eq!(
            run(
                &valid("app.basehero.client", "2"),
                ExtractLimits {
                    entries: 20,
                    bytes: 2
                }
            )
            .0
            .unwrap_err(),
            InstallError::Limit
        );
        assert_eq!(
            run(&valid("wrong.id", "2"), limits()).0.unwrap_err(),
            InstallError::Identity
        );
        assert_eq!(
            run(&valid("app.basehero.client", "3"), limits())
                .0
                .unwrap_err(),
            InstallError::Version
        );
        assert_eq!(
            run(&valid("app.basehero.client", "02"), limits())
                .0
                .unwrap_err(),
            InstallError::Version
        );
        let nested = archive(&[
            (
                "BaseHero.app/Contents/link",
                EntryType::Symlink,
                b"",
                Some("../MacOS"),
            ),
            (
                "BaseHero.app/Contents/link/payload",
                EntryType::Regular,
                b"x",
                None,
            ),
        ]);
        assert_eq!(
            run(&nested, limits()).0.unwrap_err(),
            InstallError::EntryType
        );
    }
    #[test]
    fn chained_symlink_archive_is_refused_without_modifying_install() {
        let p = plist("app.basehero.client", "2");
        let chained = archive(&[
            (
                "BaseHero.app/Contents/Info.plist",
                EntryType::Regular,
                &p,
                None,
            ),
            (
                "BaseHero.app/Contents/MacOS/BaseHero",
                EntryType::Regular,
                b"new",
                None,
            ),
            (
                "BaseHero.app/Contents/MacOS/up",
                EntryType::Symlink,
                b"",
                Some("../.."),
            ),
            (
                "BaseHero.app/Contents/MacOS/esc",
                EntryType::Symlink,
                b"",
                Some("up/Contents/MacOS/up/../.."),
            ),
        ]);
        assert_eq!(
            run(&chained, limits()).0.unwrap_err(),
            InstallError::EntryType
        );
    }
    #[test]
    fn valid_archive_replaces_and_removes_old_only_after_success() {
        let (result, dir) = run(&valid("app.basehero.client", "2"), limits());
        result.unwrap();
        let app = dir.path().join("BaseHero.app");
        assert!(!app.join("old").exists());
        assert_eq!(
            fs::read(app.join("Contents/MacOS/BaseHero")).unwrap(),
            b"new"
        );
    }
    #[test]
    fn expanded_archive_metadata_is_bounded() {
        let gz = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = Builder::new(gz);
        let mut header = Header::new_gnu();
        header.set_size(1);
        header.set_mode(0o644);
        header.set_cksum();
        let long = format!("BaseHero.app/{}", "x".repeat(100_000));
        builder.append_data(&mut header, long, &b"x"[..]).unwrap();
        let bytes = builder.into_inner().unwrap().finish().unwrap();
        assert_eq!(
            run(
                &bytes,
                ExtractLimits {
                    entries: 1,
                    bytes: 1
                }
            )
            .0
            .unwrap_err(),
            InstallError::Limit
        );
    }
    #[test]
    fn plain_symlink_is_refused() {
        let p = plist("app.basehero.client", "2");
        let bytes = archive(&[
            (
                "BaseHero.app/Contents/Info.plist",
                EntryType::Regular,
                &p,
                None,
            ),
            (
                "BaseHero.app/Contents/MacOS/BaseHero",
                EntryType::Regular,
                b"new",
                None,
            ),
            (
                "BaseHero.app/Contents/shortcut",
                EntryType::Symlink,
                b"",
                Some("MacOS/BaseHero"),
            ),
        ]);
        assert_eq!(
            run(&bytes, limits()).0.unwrap_err(),
            InstallError::EntryType
        );
    }
    #[test]
    fn unsafe_mode_is_masked() {
        let p = plist("app.basehero.client", "2");
        let bytes = archive_with_mode(
            &[
                (
                    "BaseHero.app/Contents/Info.plist",
                    EntryType::Regular,
                    &p,
                    None,
                ),
                (
                    "BaseHero.app/Contents/MacOS/BaseHero",
                    EntryType::Regular,
                    b"new",
                    None,
                ),
            ],
            0o6777,
        );
        let (result, dir) = run(&bytes, limits());
        result.unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(dir.path().join("BaseHero.app/Contents/MacOS/BaseHero"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
    }
    #[cfg(unix)]
    #[test]
    fn installed_symlink_is_refused_without_touching_old_app() {
        let (dir, real) = fixture();
        let link = dir.path().join("linked.app");
        fs::rename(&real, &link).unwrap();
        std::os::unix::fs::symlink(&link, &real).unwrap();
        assert_eq!(
            run_at(&valid("app.basehero.client", "2"), &real).unwrap_err(),
            InstallError::Path
        );
        assert_old(&link);
        assert_eq!(fs::read_link(&real).unwrap(), link);
    }
    #[test]
    fn preparation_precedes_hold_and_failed_exchange_drops_ready() {
        struct Ready<'a>(&'a Cell<bool>);
        impl Drop for Ready<'_> {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        let (_dir, app) = fixture();
        let held = Cell::new(false);
        let released = Cell::new(false);
        // A bad identity never reaches the readiness closure.
        let result = install_blocking(stage(&valid("wrong.id", "2")), &app, ID, limits(), || {
            held.set(true);
            Ok(Ready(&released))
        });
        assert!(matches!(result, Err(InstallError::Identity)));
        assert!(!held.get());
        assert!(!released.get());
        assert_old(&app);

        let prepared = PreparedInstall {
            stage_dir: prepare_blocking(stage(&valid(ID, "2")), &app, ID, limits()).unwrap(),
            installed: app.clone(),
        };
        assert_old(&app);
        // Make exchange fail after readiness; the production commit must drop
        // the token without requiring a second test-only release callback.
        let result = prepared.commit(|| {
            held.set(true);
            fs::remove_dir_all(&app)?;
            Ok(Ready(&released))
        });
        assert!(matches!(result, Err(InstallError::Swap(_))));
        assert!(held.get());
        assert!(released.get());
    }
    #[test]
    fn bundle_identity_is_the_running_apps_identifier() {
        let demo = "app.basehero.client.updatedemo";
        let (_dir, app) = fixture();
        assert_eq!(
            install_blocking(stage(&valid(demo, "2")), &app, ID, limits(), || Ok(())).unwrap_err(),
            InstallError::Identity
        );
        assert_eq!(
            install_blocking(stage(&valid(ID, "2")), &app, demo, limits(), || Ok(())).unwrap_err(),
            InstallError::Identity
        );
        assert_old(&app);
        install_blocking(stage(&valid(demo, "2")), &app, demo, limits(), || Ok(())).unwrap();
        assert_eq!(
            fs::read(app.join("Contents/MacOS/BaseHero")).unwrap(),
            b"new"
        );
    }
    #[test]
    fn dropping_a_prepared_install_leaves_the_app_and_no_stage() {
        let (dir, app) = fixture();
        let prepared = PreparedInstall {
            stage_dir: prepare_blocking(stage(&valid(ID, "2")), &app, ID, limits()).unwrap(),
            installed: app.clone(),
        };
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
        drop(prepared);
        assert_old(&app);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn failure_before_exchange_keeps_old_bundle() {
        let (_dir, app) = fixture();
        let bytes = valid("app.basehero.client", "2");
        let err = exchange_with_failure(stage(&bytes), &app, limits()).unwrap_err();
        assert!(matches!(err, InstallError::Swap(_)));
        assert_old(&app);
        assert_eq!(fs::read_dir(app.parent().unwrap()).unwrap().count(), 1);
    }
}
