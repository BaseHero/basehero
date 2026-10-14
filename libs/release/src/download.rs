//! Authenticated discovery and held-file staging. No install or restart authority.
//!
//! URLs, release key, limits and stage directory come from native trusted code,
//! never a WebView. TLS authenticates transport; signed metadata and exact bytes
//! are the release authority, including across HTTPS CDN redirects.

use std::{
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::Arc,
};

use futures_util::StreamExt;
use reqwest::{Client, redirect};
#[cfg(test)]
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::{AvailableRelease, ReleaseError, SignedRelease, VerifyFor, check_available};

#[derive(Debug, Error)]
pub enum DownloadError {
    #[error("invalid update configuration")]
    Configuration,
    #[error("update network error")]
    Network(#[from] reqwest::Error),
    #[error("update too large")]
    TooLarge,
    #[error("invalid update metadata")]
    Metadata(#[from] serde_json::Error),
    #[error("release refused: {0}")]
    Release(#[from] ReleaseError),
    #[error("cannot stage update")]
    Storage(#[from] io::Error),
}

/// Constructed only from trusted native configuration. No default endpoint/key.
pub struct Transport {
    client: Client,
    metadata_url: Url,
    artifact_base: Url,
    metadata_limit: usize,
    artifact_limit: u64,
}

pub struct FoundRelease {
    available: AvailableRelease,
    artifact_url: Url,
}

impl FoundRelease {
    pub fn version(&self) -> u64 {
        self.available.version()
    }
    pub fn whats_new(&self) -> &str {
        self.available.whats_new()
    }
}

/// Owns the verified inode, not a pathname which could be replaced after hashing.
/// No extraction, installation, raw writable handle or public stage path.
pub struct StagedArtifact {
    file: std::fs::File,
    version: u64,
}

impl StagedArtifact {
    #[cfg(test)]
    pub(crate) fn test_verified(file: std::fs::File, version: u64) -> Self {
        Self { file, version }
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    /// Synchronous forward-only read access. A future installer must read on a
    /// blocking worker, not the async executor; no path or writable handle escapes.
    pub fn reader(&mut self) -> &mut dyn Read {
        &mut self.file
    }
}

fn valid_url(url: &Url) -> bool {
    url.scheme() == "https"
        && url.has_host()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

fn tls(roots: RootCertStore) -> Result<ClientConfig, DownloadError> {
    Ok(
        ClientConfig::builder_with_provider(
            Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
        )
        .with_safe_default_protocol_versions()
        .map_err(|_| DownloadError::Configuration)?
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

impl Transport {
    pub fn new(
        metadata_url: Url,
        artifact_base: Url,
        metadata_limit: usize,
        artifact_limit: u64,
    ) -> Result<Self, DownloadError> {
        let mut roots = RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().certs {
            roots.add(cert).map_err(|_| DownloadError::Configuration)?;
        }
        Self::with_roots(
            metadata_url,
            artifact_base,
            metadata_limit,
            artifact_limit,
            roots,
        )
    }

    fn with_roots(
        metadata_url: Url,
        artifact_base: Url,
        metadata_limit: usize,
        artifact_limit: u64,
        roots: RootCertStore,
    ) -> Result<Self, DownloadError> {
        if !valid_url(&metadata_url)
            || metadata_url.query().is_some()
            || !valid_url(&artifact_base)
            || !artifact_base.path().ends_with('/')
            || artifact_base.query().is_some()
            || metadata_limit == 0
            || artifact_limit == 0
        {
            return Err(DownloadError::Configuration);
        }
        // Across-host HTTPS CDN redirects are valid. Do not forward credentials:
        // this transport sets no cookies, authorization or sensitive request headers.
        let policy = redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 5 || !valid_url(attempt.url()) {
                attempt.error("unsafe update redirect")
            } else {
                attempt.follow()
            }
        });
        let client = Client::builder()
            .redirect(policy)
            .retry(reqwest::retry::never())
            .https_only(true)
            .use_preconfigured_tls(tls(roots)?)
            .build()?;
        Ok(Self {
            client,
            metadata_url,
            artifact_base,
            metadata_limit,
            artifact_limit,
        })
    }

    /// Never requests the artifact. Authenticate notes/version first; only then
    /// form the artifact URL using one encoded path segment of signed metadata.
    pub async fn check(&self, expected: VerifyFor<'_>) -> Result<FoundRelease, DownloadError> {
        let response = self
            .client
            .get(self.metadata_url.clone())
            .send()
            .await?
            .error_for_status()?;
        let json = bounded(response, self.metadata_limit as u64).await?;
        let release: SignedRelease = serde_json::from_slice(&json)?;
        let available = check_available(&release, expected)?;
        let mut url = self.artifact_base.clone();
        url.path_segments_mut()
            .map_err(|_| DownloadError::Configuration)?
            .pop_if_empty()
            .push(&release.metadata.file_name);
        Ok(FoundRelease {
            available,
            artifact_url: url,
        })
    }

    /// Call only after explicit native user action. The caller owns its deadline.
    /// The anonymous private file is held by the async file or blocking worker;
    /// cancellation never returns a usable stage. A cancelled OS fsync or already
    /// running blocking verification may finish later, then drops its owned file.
    pub async fn download(
        &self,
        found: FoundRelease,
        stage_dir: &Path,
    ) -> Result<StagedArtifact, DownloadError> {
        self.download_inner(found, stage_dir, |_| {}).await
    }

    // The small callback is private: tests park the disk worker after file
    // creation to exercise executor scheduling and cancellation deterministically.
    async fn download_inner<F: FnOnce(&std::fs::File) + Send + 'static>(
        &self,
        found: FoundRelease,
        stage_dir: &Path,
        on_stage_created: F,
    ) -> Result<StagedArtifact, DownloadError> {
        let response = self
            .client
            .get(found.artifact_url)
            .send()
            .await?
            .error_for_status()?;
        if response
            .content_length()
            .is_some_and(|n| n > self.artifact_limit)
        {
            return Err(DownloadError::TooLarge);
        }
        let path: PathBuf = stage_dir.to_path_buf();
        let file = tokio::task::spawn_blocking(move || {
            let file = tempfile::tempfile_in(path)?;
            on_stage_created(&file);
            Ok::<_, io::Error>(file)
        })
        .await
        .map_err(staging_worker_error)??;
        let mut file = tokio::fs::File::from_std(file);
        let mut stream = response.bytes_stream();
        let mut length = 0u64;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            length = length
                .checked_add(chunk.len() as u64)
                .ok_or(DownloadError::TooLarge)?;
            if length > self.artifact_limit {
                return Err(DownloadError::TooLarge);
            }
            file.write_all(&chunk).await?;
        }
        file.flush().await?;
        file.sync_all().await?;
        // into_std waits for Tokio's outstanding file operations. Only the
        // worker sees the raw handle, and it hashes/repositions that same inode.
        let file = file.into_std().await;
        tokio::task::spawn_blocking(move || -> Result<StagedArtifact, DownloadError> {
            let mut file = file;
            file.seek(SeekFrom::Start(0))?;
            let verified = found.available.verify_staged(&mut file)?;
            file.seek(SeekFrom::Start(0))?;
            Ok(StagedArtifact {
                file,
                version: verified.version(),
            })
        })
        .await
        .map_err(staging_worker_error)?
    }

    #[cfg(test)]
    fn with_test_root(
        metadata_url: Url,
        artifact_base: Url,
        metadata_limit: usize,
        artifact_limit: u64,
        cert: CertificateDer<'static>,
    ) -> Result<Self, DownloadError> {
        let mut roots = RootCertStore::empty();
        roots.add(cert).map_err(|_| DownloadError::Configuration)?;
        Self::with_roots(
            metadata_url,
            artifact_base,
            metadata_limit,
            artifact_limit,
            roots,
        )
    }
}

fn staging_worker_error(_: tokio::task::JoinError) -> DownloadError {
    DownloadError::Storage(io::Error::other("update staging worker failed"))
}

async fn bounded(response: reqwest::Response, max: u64) -> Result<Vec<u8>, DownloadError> {
    if response.content_length().is_some_and(|n| n > max) {
        return Err(DownloadError::TooLarge);
    }
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if chunk.len() as u64 > max - body.len() as u64 {
            return Err(DownloadError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_crypto::{Secret, SigningKey, sha256};
    use std::{sync::Arc, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::timeout,
    };

    fn signed(bytes: &[u8]) -> ([u8; 32], SignedRelease) {
        let key = SigningKey::from_seed(&Secret::<32>::from_slice(&[42; 32]).unwrap());
        let metadata = crate::Metadata {
            version: 2,
            platform: "macos-aarch64".into(),
            channel: "stable".into(),
            source_commit: "abcdef0123456789abcdef0123456789abcdef01".into(),
            file_name: "release-file.tar.gz".into(),
            sha256: sha256(bytes).iter().map(|b| format!("{b:02x}")).collect(),
            whats_new: "Fixed notes".into(),
        };
        let signature = key.sign(&metadata.signing_bytes().unwrap());
        (
            key.public(),
            SignedRelease {
                metadata,
                signature: signature.iter().map(|b| format!("{b:02x}")).collect(),
            },
        )
    }

    // Real local TLS and HTTP transport, with a test-only CA rooted in this fixture.
    async fn server(
        release: SignedRelease,
        artifact: Vec<u8>,
        declared: Option<usize>,
        count: usize,
    ) -> (Url, CertificateDer<'static>, tokio::task::JoinHandle<()>) {
        server_with_pause(release, artifact, declared, count, false).await
    }

    async fn server_with_pause(
        release: SignedRelease,
        artifact: Vec<u8>,
        declared: Option<usize>,
        count: usize,
        pause_artifact: bool,
    ) -> (Url, CertificateDer<'static>, tokio::task::JoinHandle<()>) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server_cert = cert.cert.der().clone();
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![server_cert.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "https://localhost:{}/updates/",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        let handle = tokio::spawn(async move {
            for n in 0..count {
                let (socket, _) = timeout(Duration::from_secs(5), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
                let mut socket = acceptor.accept(socket).await.unwrap();
                let mut input = vec![0; 4096];
                let size = timeout(Duration::from_secs(5), socket.read(&mut input))
                    .await
                    .unwrap()
                    .unwrap();
                let request = String::from_utf8_lossy(&input[..size]);
                if n == 0 {
                    assert!(request.starts_with("GET /updates/metadata.json "));
                } else {
                    assert!(request.starts_with("GET /updates/release-file.tar.gz "));
                }
                let body = if n == 0 {
                    serde_json::to_vec(&release).unwrap()
                } else {
                    artifact.clone()
                };
                // None is genuinely chunked, not a Content-Length inferred from body.
                // A declared artifact length may deliberately exceed its bytes to
                // establish that the header guard, not hashing/network EOF, refuses it.
                let length = if n == 0 {
                    declared.map(|_| body.len())
                } else {
                    declared
                };
                let headers = match length {
                    Some(length) => format!("Content-Length: {length}\r\n"),
                    None => "Transfer-Encoding: chunked\r\n".into(),
                };
                socket
                    .write_all(
                        format!("HTTP/1.1 200 OK\r\n{headers}Connection: close\r\n\r\n").as_bytes(),
                    )
                    .await
                    .unwrap();
                for (index, chunk) in body.chunks(3).enumerate() {
                    let wire = if length.is_some() {
                        chunk.to_vec()
                    } else {
                        format!("{:x}\r\n", chunk.len())
                            .into_bytes()
                            .into_iter()
                            .chain(chunk.iter().copied())
                            .chain(b"\r\n".iter().copied())
                            .collect()
                    };
                    if socket.write_all(&wire).await.is_err() {
                        break;
                    }
                    if pause_artifact && n == 1 && index == 0 {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
                if length.is_none() {
                    let _ = socket.write_all(b"0\r\n\r\n").await;
                }
                let _ = socket.shutdown().await;
            }
        });
        (url, server_cert, handle)
    }

    #[tokio::test]
    async fn check_only_reads_metadata_then_explicit_download_verifies_held_file() {
        let bytes = b"one-two-three-four";
        let (key, release) = signed(bytes);
        let (base, cert, server) = server(release, bytes.to_vec(), None, 2).await;
        let dir = tempfile::tempdir().unwrap();
        let transport =
            Transport::with_test_root(base.join("metadata.json").unwrap(), base, 8192, 64, cert)
                .unwrap();
        let found = transport
            .check(VerifyFor {
                release_key: &key,
                platform: "macos-aarch64",
                channel: "stable",
                running_version: 1,
            })
            .await
            .unwrap();
        assert_eq!(found.version(), 2);
        assert_eq!(found.whats_new(), "Fixed notes");
        let mut stage = transport.download(found, dir.path()).await.unwrap();
        let mut result = Vec::new();
        stage.reader().read_to_end(&mut result).unwrap();
        assert_eq!(result, bytes);
        server.await.unwrap();
    }

    #[test]
    fn transport_rejects_insecure_or_credentialed_configuration() {
        let https = Url::parse("https://example.org/updates/").unwrap();
        for url in [
            "http://example.org/metadata.json",
            "https://user:pass@example.org/metadata.json",
        ] {
            assert!(matches!(
                Transport::with_roots(
                    Url::parse(url).unwrap(),
                    https.clone(),
                    1024,
                    1024,
                    RootCertStore::empty()
                ),
                Err(DownloadError::Configuration)
            ));
        }
        assert!(matches!(
            Transport::with_roots(
                https.clone(),
                Url::parse("https://example.org/updates/?token=secret").unwrap(),
                1024,
                1024,
                RootCertStore::empty()
            ),
            Err(DownloadError::Configuration)
        ));
        assert!(matches!(
            Transport::with_roots(
                Url::parse("https://example.org/metadata.json?token=secret").unwrap(),
                https,
                1024,
                1024,
                RootCertStore::empty()
            ),
            Err(DownloadError::Configuration)
        ));
    }

    #[tokio::test]
    async fn metadata_bounds_and_version_refusal_stop_before_artifact_request() {
        let (key, release) = signed(b"valid");
        for (limit, version) in [(10, 1), (8192, 2)] {
            let (base, cert, server) = server(release.clone(), vec![], None, 1).await;
            let transport = Transport::with_test_root(
                base.join("metadata.json").unwrap(),
                base,
                limit,
                64,
                cert,
            )
            .unwrap();
            assert!(
                transport
                    .check(VerifyFor {
                        release_key: &key,
                        platform: "macos-aarch64",
                        channel: "stable",
                        running_version: version
                    })
                    .await
                    .is_err()
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn bad_metadata_is_not_announced_or_downloaded() {
        let (key, mut release) = signed(b"valid");
        release.metadata.whats_new.push('!');
        let (base, cert, server) = server(release, vec![], None, 1).await;
        let transport =
            Transport::with_test_root(base.join("metadata.json").unwrap(), base, 8192, 64, cert)
                .unwrap();
        assert!(
            transport
                .check(VerifyFor {
                    release_key: &key,
                    platform: "macos-aarch64",
                    channel: "stable",
                    running_version: 1
                })
                .await
                .is_err()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cancelling_mid_download_drops_private_stage() {
        let artifact = vec![b'A'; 8192];
        let (key, release) = signed(&artifact);
        let (base, cert, server) = server_with_pause(release, artifact, None, 2, true).await;
        let dir = tempfile::tempdir().unwrap();
        let transport =
            Transport::with_test_root(base.join("metadata.json").unwrap(), base, 8192, 8192, cert)
                .unwrap();
        let found = transport
            .check(VerifyFor {
                release_key: &key,
                platform: "macos-aarch64",
                channel: "stable",
                running_version: 1,
            })
            .await
            .unwrap();
        assert!(
            timeout(
                Duration::from_millis(100),
                transport.download(found, dir.path())
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        server.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn slow_disk_sync_does_not_delay_runtime_timer() {
        let bytes = b"valid";
        let (key, release) = signed(bytes);
        let (base, cert, server) = server(release, bytes.to_vec(), None, 2).await;
        let dir = tempfile::tempdir().unwrap();
        let transport =
            Transport::with_test_root(base.join("metadata.json").unwrap(), base, 8192, 64, cert)
                .unwrap();
        let found = transport
            .check(VerifyFor {
                release_key: &key,
                platform: "macos-aarch64",
                channel: "stable",
                running_version: 1,
            })
            .await
            .unwrap();
        let started = std::time::Instant::now();
        let heartbeat = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            started.elapsed()
        });
        tokio::task::yield_now().await;
        let _stage = transport.download(found, dir.path()).await.unwrap();
        let delay = heartbeat.await.unwrap();
        eprintln!("staging heartbeat after: {delay:?}");
        assert!(
            delay < Duration::from_millis(150),
            "staging blocked the executor: {delay:?}"
        );
        server.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stage_worker_does_not_block_executor_and_cancel_drops_its_file() {
        use std::os::fd::AsRawFd;
        let bytes = b"valid";
        let (key, release) = signed(bytes);
        let (base, cert, server) = server(release, bytes.to_vec(), None, 2).await;
        let dir = tempfile::tempdir().unwrap();
        let transport =
            Transport::with_test_root(base.join("metadata.json").unwrap(), base, 8192, 64, cert)
                .unwrap();
        let found = transport
            .check(VerifyFor {
                release_key: &key,
                platform: "macos-aarch64",
                channel: "stable",
                running_version: 1,
            })
            .await
            .unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let path = dir.path().to_path_buf();
        let task = tokio::spawn(async move {
            transport
                .download_inner(found, &path, move |file| {
                    let _ = started_tx.send(file.as_raw_fd());
                    let _ = release_rx.recv();
                })
                .await
        });
        let fd = timeout(Duration::from_secs(2), started_rx)
            .await
            .unwrap()
            .unwrap();
        #[cfg(not(target_os = "linux"))]
        let _ = fd;
        // The disk worker is parked after the anonymous file exists. This timer
        // must still run on the only executor thread, even before cancellation.
        timeout(
            Duration::from_millis(200),
            tokio::time::sleep(Duration::from_millis(20)),
        )
        .await
        .unwrap();
        task.abort();
        assert!(matches!(task.await, Err(ref e) if e.is_cancelled()));
        release_tx.send(()).unwrap();
        #[cfg(target_os = "linux")]
        {
            let fd_path = format!("/proc/self/fd/{fd}");
            // Once the abandoned worker returns its file, Tokio drops the
            // unobserved result; the staged inode's descriptor must disappear.
            timeout(Duration::from_secs(2), async {
                while std::fs::read_link(&fd_path)
                    .is_ok_and(|p| p.to_string_lossy().contains(dir.path().to_str().unwrap()))
                {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn exact_size_is_allowed_and_matching_oversize_is_rejected_by_both_guards() {
        let bytes = b"signed-match-above-limit";
        for (declared, cap, oversized) in [
            (None, bytes.len() as u64, false),
            (None, bytes.len() as u64 - 1, true),
            (Some(bytes.len()), bytes.len() as u64 - 1, true),
        ] {
            let (key, release) = signed(bytes);
            let (base, cert, server) = server(release, bytes.to_vec(), declared, 2).await;
            let dir = tempfile::tempdir().unwrap();
            let transport = Transport::with_test_root(
                base.join("metadata.json").unwrap(),
                base,
                8192,
                cap,
                cert,
            )
            .unwrap();
            let found = transport
                .check(VerifyFor {
                    release_key: &key,
                    platform: "macos-aarch64",
                    channel: "stable",
                    running_version: 1,
                })
                .await
                .unwrap();
            let result = transport.download(found, dir.path()).await;
            if oversized {
                assert!(
                    matches!(result, Err(DownloadError::TooLarge)),
                    "{declared:?}"
                );
            } else {
                assert_eq!(result.unwrap().version(), 2);
            }
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn metadata_rejects_declared_and_chunked_oversize_at_byte_cap() {
        let (key, release) = signed(b"valid");
        let size = serde_json::to_vec(&release).unwrap().len();
        for (declared, cap, oversized) in [
            (None, size, false),
            (None, size - 1, true),
            (Some(size), size - 1, true),
        ] {
            let (base, cert, server) = server(release.clone(), vec![], declared, 1).await;
            let transport =
                Transport::with_test_root(base.join("metadata.json").unwrap(), base, cap, 64, cert)
                    .unwrap();
            let result = transport
                .check(VerifyFor {
                    release_key: &key,
                    platform: "macos-aarch64",
                    channel: "stable",
                    running_version: 1,
                })
                .await;
            if oversized {
                assert!(
                    matches!(result, Err(DownloadError::TooLarge)),
                    "{declared:?}"
                );
            } else {
                assert_eq!(result.unwrap().version(), 2);
            }
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn https_cdn_redirect_allowed_but_insecure_credentials_and_excess_hops_refused() {
        use std::sync::Mutex;
        for mode in ["cdn", "http", "credentials", "loop"] {
            let (key, release) = signed(b"valid");
            // Two names rooted only in this fixture, including the IP SAN.
            let cert =
                rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
                    .unwrap();
            let root = cert.cert.der().clone();
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![root.clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let base = Url::parse(&format!("https://localhost:{port}/updates/")).unwrap();
            let plain = if mode == "http" {
                Some(TcpListener::bind("127.0.0.1:0").await.unwrap())
            } else {
                None
            };
            let plain_port = plain.as_ref().map(|l| l.local_addr().unwrap().port());
            let plain_task = plain.map(|listener| tokio::spawn(async move {
                match timeout(Duration::from_secs(1), listener.accept()).await {
                    Ok(Ok((mut socket, _))) => {
                        let mut request = [0u8; 4096];
                        let count = socket.read(&mut request).await.unwrap();
                        let path = String::from_utf8_lossy(&request[..count]).into_owned();
                        socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                        Some(path)
                    }
                    _ => None,
                }
            }));
            let location = match mode {
                "cdn" => format!("https://127.0.0.1:{port}/cdn"),
                "http" => format!("http://127.0.0.1:{}/cdn", plain_port.unwrap()),
                "credentials" => format!("https://user:pass@localhost:{port}/cdn"),
                _ => format!("https://localhost:{port}/again"),
            };
            let seen = Arc::new(Mutex::new(Vec::<String>::new()));
            let observations = seen.clone();
            let server = tokio::spawn(async move {
                loop {
                    let (socket, _) = listener.accept().await.unwrap();
                    let mut socket = acceptor.accept(socket).await.unwrap();
                    let mut input = [0u8; 4096];
                    let count = socket.read(&mut input).await.unwrap();
                    let request = String::from_utf8_lossy(&input[..count]).into_owned();
                    let n = {
                        let mut lock = observations.lock().unwrap();
                        lock.push(request);
                        lock.len()
                    };
                    let response = if mode == "cdn" && n == 2 {
                        let body = serde_json::to_string(&release).unwrap();
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                    } else {
                        format!(
                            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        )
                    };
                    socket.write_all(response.as_bytes()).await.unwrap();
                    let _ = socket.shutdown().await;
                }
            });
            let transport = Transport::with_test_root(
                base.join("metadata.json").unwrap(),
                base,
                8192,
                64,
                root,
            )
            .unwrap();
            let result = timeout(
                Duration::from_secs(3),
                transport.check(VerifyFor {
                    release_key: &key,
                    platform: "macos-aarch64",
                    channel: "stable",
                    running_version: 1,
                }),
            )
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "{mode}: redirect did not stop, {} TLS requests",
                    seen.lock().unwrap().len()
                )
            });
            let requests = seen.lock().unwrap().clone();
            if mode == "cdn" {
                assert_eq!(result.unwrap().version(), 2);
                assert_eq!(requests.len(), 2);
                assert!(requests[0].starts_with("GET /updates/metadata.json "));
                assert!(requests[1].starts_with("GET /cdn "));
                assert!(requests[1].contains(&format!("host: 127.0.0.1:{port}")));
            } else {
                assert!(
                    matches!(result, Err(DownloadError::Network(ref e)) if e.is_redirect()),
                    "{mode}"
                );
                assert_eq!(requests.len(), if mode == "loop" { 5 } else { 1 }, "{mode}");
                assert!(
                    requests
                        .iter()
                        .all(|r| r.starts_with("GET /updates/metadata.json ")
                            || r.starts_with("GET /again "))
                );
            }
            if let Some(task) = plain_task {
                assert!(
                    task.await.unwrap().is_none(),
                    "HTTP redirect reached plain server"
                );
            }
            server.abort();
            let _ = server.await;
        }
    }

    #[tokio::test]
    async fn altered_artifact_refuses_verification() {
        let (key, release) = signed(b"valid");
        let (base, cert, server) = server(release, b"altered".to_vec(), None, 2).await;
        let dir = tempfile::tempdir().unwrap();
        let transport =
            Transport::with_test_root(base.join("metadata.json").unwrap(), base, 8192, 64, cert)
                .unwrap();
        let found = transport
            .check(VerifyFor {
                release_key: &key,
                platform: "macos-aarch64",
                channel: "stable",
                running_version: 1,
            })
            .await
            .unwrap();
        assert!(matches!(
            transport.download(found, dir.path()).await,
            Err(DownloadError::Release(ReleaseError::HashMismatch))
        ));
        server.await.unwrap();
    }
}
