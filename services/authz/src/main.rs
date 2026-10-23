//! `bh-authz`: serve devices' attested channels on `/v1/channel`, as the
//! edge's `/v1/authz` proxy reaches it. Keys and policy come from files named
//! on the command line; nothing secret is taken from argv itself or logged.
use bh_authz::{
    Attestation, ChannelConfig, Clock, DstackAttestation, EdgeClient, MonotonicCounter, PermitKeys,
    RecoveryHomeKey, RoughtimeClock, Service,
};
use bh_confidential_host::TimeSampler;
use bh_crypto::{KemKey, Secret, SigningKey};
use bh_qualified_time::{Config, ServerRoot};
use bh_sync::evidence::RecoveryKeyCertificate;
use std::{net::SocketAddr, path::PathBuf, process::ExitCode, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore};
use tokio_tungstenite::tungstenite::{
    handshake::server::{ErrorResponse, Request, Response},
    http::StatusCode,
    protocol::WebSocketConfig,
};

const USAGE: &str = "usage: bh-authz --listen ADDR --db PATH --edge URL --hosting-root HEX
  --permit-key FILE --permit-cert FILE --app-root HEX --policy FILE --policy-signature FILE
  --recovery-key FILE --recovery-cert FILE
  then either the hardware attestation and qualified time:
  --quote-socket PATH --collateral FILE --roughtime ADDR=KEYHEX --roughtime ADDR=KEYHEX
  --time-config HZ,DRIFT_PPM,SMEAR_US,MAX_AGE_TICKS,MAX_WIDTH_MS (HZ is 1000000000)
  or, in a build with the synthetic-attestation feature only, for local use:
  --synthetic-attestation (the recovery flags are then optional)";
/// Concurrent device connections.
const MAX_CONNECTIONS: usize = 1024;
const EDGE_TIMEOUT: Duration = Duration::from_secs(10);
const QUOTE_TIMEOUT: Duration = Duration::from_secs(10);
const TIME_TIMEOUT: Duration = Duration::from_secs(5);
const TIME_REFRESH: Duration = Duration::from_secs(60);
/// A connection must finish its WebSocket upgrade within this.
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(5);
/// Waits after a failed accept (such as no free descriptor), doubling.
const ACCEPT_BACKOFF: (Duration, Duration) = (Duration::from_millis(10), Duration::from_secs(1));

#[derive(Default)]
struct Args {
    listen: Option<SocketAddr>,
    db: Option<PathBuf>,
    edge: Option<String>,
    hosting_root: Option<[u8; 32]>,
    permit_key: Option<PathBuf>,
    permit_cert: Option<PathBuf>,
    app_root: Option<[u8; 32]>,
    policy: Option<PathBuf>,
    policy_signature: Option<PathBuf>,
    recovery_key: Option<PathBuf>,
    recovery_cert: Option<PathBuf>,
    quote_socket: Option<PathBuf>,
    collateral: Option<PathBuf>,
    roughtime: Vec<(SocketAddr, ServerRoot)>,
    time_config: Option<Config>,
    synthetic: bool,
}

fn hex_array<const N: usize>(text: &str, what: &str) -> Result<[u8; N], String> {
    hex::decode(text.trim())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| format!("{what}: expected {N} hex bytes"))
}
fn hex_file<const N: usize>(path: &PathBuf, what: &str) -> Result<[u8; N], String> {
    let text = std::fs::read_to_string(path).map_err(|_| format!("{what}: cannot read file"))?;
    hex_array(&text, what)
}

impl Args {
    fn parse(mut args: impl Iterator<Item = String>) -> Result<Self, String> {
        let mut parsed = Self::default();
        while let Some(flag) = args.next() {
            if flag == "--synthetic-attestation" {
                // Absent from builds without the feature, as every release is.
                if !cfg!(feature = "synthetic-attestation") {
                    return Err(format!("unknown flag {flag}\n{USAGE}"));
                }
                parsed.synthetic = true;
                continue;
            }
            let value = args
                .next()
                .ok_or_else(|| format!("{flag}: missing value"))?;
            let path = || PathBuf::from(&value);
            match flag.as_str() {
                "--listen" => {
                    parsed.listen = Some(value.parse().map_err(|_| "--listen: bad address")?)
                }
                "--db" => parsed.db = Some(path()),
                "--edge" => parsed.edge = Some(value),
                "--hosting-root" => parsed.hosting_root = Some(hex_array(&value, &flag)?),
                "--permit-key" => parsed.permit_key = Some(path()),
                "--permit-cert" => parsed.permit_cert = Some(path()),
                "--app-root" => parsed.app_root = Some(hex_array(&value, &flag)?),
                "--policy" => parsed.policy = Some(path()),
                "--policy-signature" => parsed.policy_signature = Some(path()),
                "--recovery-key" => parsed.recovery_key = Some(path()),
                "--recovery-cert" => parsed.recovery_cert = Some(path()),
                "--quote-socket" => parsed.quote_socket = Some(path()),
                "--collateral" => parsed.collateral = Some(path()),
                "--roughtime" => {
                    let (addr, key) = value.split_once('=').ok_or("--roughtime: ADDR=KEYHEX")?;
                    parsed.roughtime.push((
                        addr.parse().map_err(|_| "--roughtime: bad address")?,
                        ServerRoot {
                            key: hex_array(key, &flag)?,
                        },
                    ));
                }
                "--time-config" => {
                    let n: Vec<u64> = value
                        .split(',')
                        .map(str::parse)
                        .collect::<Result<_, _>>()
                        .map_err(|_| "--time-config: five integers")?;
                    let [hz, drift_ppm, smear_us, max_age_ticks, max_width_ms] = n[..] else {
                        return Err("--time-config: five integers".into());
                    };
                    // The counter's rate is fixed; any other would scale time.
                    if hz != MonotonicCounter::HZ {
                        return Err(format!(
                            "--time-config: HZ must be {}, the counter's nanosecond rate",
                            MonotonicCounter::HZ
                        ));
                    }
                    parsed.time_config = Some(Config {
                        hz,
                        drift_ppm: u32::try_from(drift_ppm).map_err(|_| "--time-config: drift")?,
                        smear_us,
                        max_age_ticks,
                        max_width_ms,
                    });
                }
                _ => return Err(format!("unknown flag {flag}\n{USAGE}")),
            }
        }
        Ok(parsed)
    }
}

fn required<T>(value: Option<T>, flag: &str) -> Result<T, String> {
    value.ok_or_else(|| format!("{flag} is required\n{USAGE}"))
}

/// The home's recovery key, read once from its file, and its certificate.
/// A local synthetic service may run without one: it then refuses claims.
fn recovery(args: &Args, root: &[u8; 32]) -> Result<Option<RecoveryHomeKey>, String> {
    if args.synthetic && args.recovery_key.is_none() && args.recovery_cert.is_none() {
        eprintln!("bh-authz: no --recovery-key: recovery claims are refused");
        return Ok(None);
    }
    let seed = hex_file::<32>(
        &required(args.recovery_key.clone(), "--recovery-key")?,
        "--recovery-key",
    )?;
    let key = KemKey::from_seed(&Secret::from_slice(&seed).map_err(|_| "--recovery-key")?);
    let certificate = hex_file::<{ RecoveryKeyCertificate::LEN }>(
        &required(args.recovery_cert.clone(), "--recovery-cert")?,
        "--recovery-cert",
    )?;
    let certificate = RecoveryKeyCertificate::decode(&certificate)
        .map_err(|_| "--recovery-cert: not a recovery key certificate")?;
    RecoveryHomeKey::new(key, certificate, root)
        .map(Some)
        .map_err(|_| "--recovery-cert does not name --recovery-key under --hosting-root".into())
}

struct Trust {
    attestation: Arc<dyn Attestation>,
    clock: Arc<dyn Clock>,
}

/// Attestation and clock: the dstack quote with qualified Roughtime, or the
/// labelled synthetic pair a local build may choose.
fn trust(args: &Args) -> Result<Trust, String> {
    if args.synthetic {
        #[cfg(feature = "synthetic-attestation")]
        {
            eprintln!(
                "bh-authz: SYNTHETIC ATTESTATION and the local wall clock: local use only, not hardware evidence"
            );
            return Ok(Trust {
                attestation: Arc::new(bh_authz::SyntheticAttestation),
                clock: Arc::new(bh_authz::LocalClock),
            });
        }
        #[cfg(not(feature = "synthetic-attestation"))]
        return Err(format!("unknown flag --synthetic-attestation\n{USAGE}"));
    }
    let attestation = DstackAttestation::new(
        required(args.quote_socket.clone(), "--quote-socket")?,
        required(args.collateral.clone(), "--collateral")?,
        QUOTE_TIMEOUT,
    );
    let [first, second] = args.roughtime[..] else {
        return Err(format!("two --roughtime servers are required\n{USAGE}"));
    };
    let config = required(args.time_config, "--time-config")?;
    let sampler = Arc::new(
        TimeSampler::new([first, second], config, TIME_TIMEOUT)
            .map_err(|_| "--roughtime/--time-config: rejected")?,
    );
    let counter = Arc::new(MonotonicCounter::new());
    // Bounds age out unless refreshed; without them nothing is issued.
    let (refresh, ticks) = (sampler.clone(), counter.clone());
    tokio::spawn(async move {
        loop {
            if refresh.refresh(ticks.as_ref()).await.is_err() {
                eprintln!("bh-authz: qualified time unavailable");
            }
            tokio::time::sleep(TIME_REFRESH).await;
        }
    });
    Ok(Trust {
        attestation: Arc::new(attestation),
        clock: Arc::new(RoughtimeClock::new(sampler, counter)),
    })
}

async fn run() -> Result<(), String> {
    let args = Args::parse(std::env::args().skip(1))?;
    let key = hex_file::<32>(
        &required(args.permit_key.clone(), "--permit-key")?,
        "--permit-key",
    )?;
    let key = SigningKey::from_seed(&Secret::from_slice(&key).map_err(|_| "--permit-key")?);
    let certificate = hex_file(
        &required(args.permit_cert.clone(), "--permit-cert")?,
        "--permit-cert",
    )?;
    let keys = PermitKeys::new(key, certificate)
        .map_err(|_| "--permit-cert does not name --permit-key")?;
    if Some(keys.root()) != args.hosting_root {
        return Err("--permit-cert is not under --hosting-root".into());
    }
    let policy_path = required(args.policy.clone(), "--policy")?;
    let channel = ChannelConfig {
        app_root: required(args.app_root, "--app-root")?,
        policy: std::fs::read(&policy_path).map_err(|_| "--policy: cannot read file")?,
        policy_signature: hex_file(
            &required(args.policy_signature.clone(), "--policy-signature")?,
            "--policy-signature",
        )?,
    };
    let recovery = recovery(&args, &keys.root())?;
    let Trust { attestation, clock } = trust(&args)?;
    let edge = EdgeClient::new(required(args.edge.clone(), "--edge")?, EDGE_TIMEOUT)
        .map_err(|_| "--edge: cannot configure TLS")?;
    let db = required(args.db.clone(), "--db")?;
    let service = match recovery {
        Some(recovery) => Service::open_with_recovery(&db, keys, recovery, clock, Arc::new(edge)),
        None => Service::open(&db, keys, clock, Arc::new(edge)),
    }
    .map_err(|e| e.to_string())?;
    let listen = required(args.listen, "--listen")?;
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|_| "--listen: cannot bind")?;
    let bound = listener.local_addr().map_err(|_| "--listen: cannot bind")?;
    eprintln!("bh-authz: listening on {bound}");
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let channel = Arc::new(channel);
    let mut backoff = ACCEPT_BACKOFF.0;
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => {
                backoff = ACCEPT_BACKOFF.0;
                stream
            }
            Err(_) => {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(ACCEPT_BACKOFF.1);
                continue;
            }
        };
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let (service, channel, attestation) =
            (service.clone(), channel.clone(), attestation.clone());
        tokio::spawn(async move {
            let _slot = slot;
            let config = WebSocketConfig::default()
                .max_message_size(Some(bh_confidential_channel::wire::MAX_FRAME))
                .max_frame_size(Some(bh_confidential_channel::wire::MAX_FRAME));
            // tungstenite's callback type fixes this error's size.
            #[allow(clippy::result_large_err)]
            let route = |request: &Request, response: Response| {
                if request.uri().path() == "/v1/channel" {
                    Ok(response)
                } else {
                    let mut refusal = ErrorResponse::new(None);
                    *refusal.status_mut() = StatusCode::NOT_FOUND;
                    Err(refusal)
                }
            };
            let upgrade =
                tokio_tungstenite::accept_hdr_async_with_config(stream, route, Some(config));
            let Ok(Ok(ws)) = tokio::time::timeout(UPGRADE_TIMEOUT, upgrade).await else {
                return;
            };
            if let Err(error) = service
                .serve_connection(ws, &channel, attestation.as_ref())
                .await
            {
                eprintln!("bh-authz: connection ended: {error}");
            }
        });
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("bh-authz: {message}");
            ExitCode::FAILURE
        }
    }
}
