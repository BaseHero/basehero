//! Verify an attested hardware channel directly or via the forwarding Worker.
//! Trusted time bounds must be supplied from an independent Roughtime sample.
//! Usage:
//!   hardware_probe --execute WSS_URL ENDPOINT_FILE CANDIDATE_HEX COLLATERAL_FILE POLICY_FILE EARLIEST LATEST [--record PATH]
//!   hardware_probe --fixture PROOF_JSON ENDPOINT_FILE CANDIDATE_HEX
//! The fixture mode re-checks a recorded `{hello_hex, proof_hex, admitted_at_system_seconds}`
//! offline: hardware evidence at the recorded time, then the signed policy's build and
//! machine lists. Output is the authenticated measurement and whether it is authorized;
//! refusals are fixed, content-free reasons.
use bh_confidential_attestation::{Evidence, Expected, Time, verify_evidence};
use bh_confidential_channel::{
    appraisal::{PolicyContext, PolicyStore, Sample, StoredState},
    handshake::ClientHello,
    wire,
};
use bh_confidential_policy::{Limits, PolicyGate, Role, Snapshot, TimeBounds};
use futures_util::{SinkExt, StreamExt};
use std::{
    fs,
    io::Write,
    os::unix::fs::OpenOptionsExt,
    sync::{Arc, LazyLock},
    time::Instant,
};
use tokio_tungstenite::{
    Connector as TlsConnector, connect_async_tls_with_config, tungstenite::Message,
};

struct Memory(Option<Snapshot>);
impl PolicyStore for Memory {
    type Error = ();
    fn load(&mut self) -> Result<StoredState, ()> {
        Ok(self
            .0
            .clone()
            .map_or(StoredState::Fresh, StoredState::Committed))
    }
    fn save(&mut self, snapshot: &Snapshot) -> Result<(), ()> {
        self.0 = Some(snapshot.clone());
        Ok(())
    }
}

/// The endpoint values the app itself trusts: app root, policy limits, build floor.
struct Endpoint {
    root: [u8; 32],
    limits: Limits,
    floor: u64,
}
fn endpoint(path: &str) -> Result<Endpoint, String> {
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(path).map_err(|_| "endpoint file".to_string())?)
            .map_err(|_| "endpoint JSON".to_string())?;
    let number = |key: &str| value[key].as_u64().ok_or(format!("endpoint {key}"));
    Ok(Endpoint {
        root: fixed(value["app_root"].as_str().ok_or("endpoint app_root")?)?,
        limits: Limits {
            max_lifetime_secs: number("max_lifetime_secs")?,
            max_uncertainty_secs: number("max_uncertainty_secs")?,
        },
        floor: number("build_floor")?,
    })
}

/// Hardware evidence only (Intel quote, collateral, binding, full RTMR3 replay).
/// Local files, when given, must be the exact delivered bytes.
fn inspect(
    frame: &[u8],
    nonce: [u8; 32],
    candidate: [u8; 32],
    local: Option<(&[u8], &[u8])>,
    time: Time,
) -> Result<
    (
        serde_json::Value,
        bh_confidential_attestation::VerifiedEvidence,
    ),
    String,
> {
    let (kind, body) = wire::parse(frame).map_err(|_| "invalid proof frame".to_string())?;
    if kind != 2 {
        return Err("not a proof".into());
    }
    let proof = wire::proof(body).map_err(|_| "invalid proof".to_string())?;
    if let Some((collateral, policy)) = local {
        if proof.collateral != collateral {
            return Err("collateral bytes differ from local file".into());
        }
        if proof.policy != policy {
            return Err("policy bytes differ from local file".into());
        }
    }
    let evidence = verify_evidence(
        Evidence {
            quote: proof.quote,
            collateral: proof.collateral,
            event_log: proof.log,
        },
        &Expected {
            signing: proof.signing,
            receiving: proof.receiving,
            nonce,
            role: Role::Checker,
        },
        Some(time),
    )
    .map_err(|e| format!("hardware evidence refused: {e:?}"))?;
    let measured = evidence.measured();
    let value = serde_json::json!({"build": measured.build(), "machine": hex::encode(measured.machine()),
        "compose_matches_candidate": measured.build().compose_sha256 == candidate,
        "policy_sha256": hex::encode(bh_crypto::sha256(proof.policy)),
        "collateral_sha256": hex::encode(bh_crypto::sha256(proof.collateral)),
        "evidence_valid_until": evidence.validity().1});
    // A compose mismatch is still authenticated: `report` labels it unauthorized,
    // so it can be diagnosed against the replay rather than discarded.
    Ok((value, evidence))
}
static START: LazyLock<Instant> = LazyLock::new(Instant::now);
fn fixed<const N: usize>(value: &str) -> Result<[u8; N], String> {
    hex::decode(value)
        .map_err(|_| "invalid hex".to_string())?
        .try_into()
        .map_err(|_| "wrong width".to_string())
}

/// Authenticated measurement plus a decision; `Err` only before anything is authenticated.
fn report(mut inspected: serde_json::Value, refusal: Option<String>) -> serde_json::Value {
    let compose_ok = inspected["compose_matches_candidate"] == true;
    let refusal = refusal.or((!compose_ok).then(|| "quote compose differs from candidate".into()));
    inspected["authorized"] = refusal.is_none().into();
    inspected["refusal"] = refusal.map_or(serde_json::Value::Null, Into::into);
    inspected
}

/// Offline: recorded proof at its recorded admission time, then the signed policy.
fn fixture(args: &[String]) -> Result<serde_json::Value, String> {
    let [recorded, endpoint_file, candidate] = args else {
        return Err("expected PROOF_JSON ENDPOINT_FILE CANDIDATE_HEX".into());
    };
    let endpoint = endpoint(endpoint_file)?;
    let candidate = fixed::<32>(candidate)?;
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(recorded).map_err(|_| "proof fixture".to_string())?)
            .map_err(|_| "proof fixture JSON".to_string())?;
    let hello = hex::decode(value["hello_hex"].as_str().ok_or("hello_hex")?)
        .map_err(|_| "hello hex".to_string())?;
    let frame = hex::decode(value["proof_hex"].as_str().ok_or("proof_hex")?)
        .map_err(|_| "proof hex".to_string())?;
    let at = value["admitted_at_system_seconds"]
        .as_u64()
        .ok_or("admitted_at_system_seconds")?;
    let nonce: [u8; 32] = hello
        .get(11..43)
        .ok_or("hello nonce")?
        .try_into()
        .map_err(|_| "hello nonce".to_string())?;
    let time = Time {
        earliest: at,
        latest: at,
        max_uncertainty_secs: 0,
    };
    let (inspected, evidence) = inspect(&frame, nonce, candidate, None, time)?;
    let (_, body) = wire::parse(&frame).map_err(|_| "invalid proof frame".to_string())?;
    let proof = wire::proof(body).map_err(|_| "invalid proof".to_string())?;
    let mut gate = PolicyGate::new(endpoint.root, endpoint.limits)
        .map_err(|e| format!("policy limits: {e:?}"))?;
    let measured = evidence.measured();
    let refusal = gate
        .push(proof.policy, &proof.signature)
        .and_then(|()| {
            gate.check_measurements(
                Role::Checker,
                measured.build(),
                measured.machine(),
                Some(TimeBounds {
                    earliest: at,
                    latest: at,
                }),
            )
        })
        .err()
        .map(|e| format!("{e:?}"));
    Ok(report(inspected, refusal))
}

fn record_proof(path: &str, proof: &[u8]) -> Result<(), String> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut file| file.write_all(proof))
        .map_err(|_| "record proof".to_string())
}

async fn run(args: &[String]) -> Result<serde_json::Value, String> {
    let [
        url,
        endpoint_file,
        candidate,
        collateral,
        policy,
        earliest,
        latest,
        rest @ ..,
    ] = args
    else {
        return Err("expected URL, endpoint, candidate, collateral, policy, time bounds, optional --record PATH".into());
    };
    let record = match rest {
        [] => None,
        [flag, path] if flag == "--record" => Some(path),
        _ => return Err("expected URL, endpoint, candidate, collateral, policy, time bounds, optional --record PATH".into()),
    };
    if !(url.starts_with("wss://") || url.starts_with("ws://127.0.0.1:")) {
        return Err("secure channel URL required".into());
    }
    let endpoint = endpoint(endpoint_file)?;
    let candidate = fixed::<32>(candidate)?;
    let earliest: u64 = earliest.parse().map_err(|_| "time".to_string())?;
    let latest: u64 = latest.parse().map_err(|_| "time".to_string())?;
    if latest < earliest || latest - earliest > 16 {
        return Err("time uncertainty exceeds bound".into());
    }
    let local_collateral = fs::read(collateral).map_err(|_| "collateral file".to_string())?;
    let local_policy = fs::read(policy).map_err(|_| "policy file".to_string())?;
    let context = PolicyContext::new(
        endpoint.root,
        endpoint.limits,
        endpoint.floor,
        Memory(None),
        move || Sample {
            system_seconds: Some(earliest),
            monotonic_ms: START.elapsed().as_millis() as u64,
        },
    )
    .map_err(|_| "policy context".to_string())?;
    let hello = ClientHello::new(context).map_err(|_| "hello".to_string())?;
    let nonce: [u8; 32] = hello.frame()[11..43]
        .try_into()
        .map_err(|_| "hello nonce".to_string())?;
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| "websocket unavailable".to_string())?
    .with_root_certificates(bh_tls_roots::browser_roots())
    .with_no_client_auth();
    let (mut ws, _) =
        connect_async_tls_with_config(url, None, false, Some(TlsConnector::Rustls(Arc::new(tls))))
            .await
            .map_err(|_| "websocket unavailable".to_string())?;
    ws.send(Message::Binary(hello.frame().to_vec().into()))
        .await
        .map_err(|_| "send hello".to_string())?;
    let Message::Binary(proof) = ws
        .next()
        .await
        .ok_or("closed")?
        .map_err(|_| "read proof".to_string())?
    else {
        return Err("binary proof required".into());
    };
    if let Some(path) = record {
        record_proof(path, &proof)?;
    }
    let time = Time {
        earliest,
        latest,
        max_uncertainty_secs: 16,
    };
    let (inspected, _) = inspect(
        &proof,
        nonce,
        candidate,
        Some((&local_collateral, &local_policy)),
        time,
    )?;
    // Production accept_proof rechecks signed policy, time, Intel quote, binding,
    // build/machine authorization and key agreement before yielding a session.
    // Its refusal still reports the authenticated measurement above.
    let checked = match hello.accept_proof(&proof) {
        Ok(checked) => checked,
        Err(e) => {
            return Ok(report(
                inspected,
                Some(format!("channel proof refused: {e:?}")),
            ));
        }
    };
    let handshake = async {
        let (frame, pending) = checked
            .encapsulate()
            .map_err(|e| format!("encapsulation refused: {e:?}"))?;
        ws.send(Message::Binary(frame.into()))
            .await
            .map_err(|_| "send encapsulation".to_string())?;
        let Message::Binary(finish) = ws
            .next()
            .await
            .ok_or("closed")?
            .map_err(|_| "read finish".to_string())?
        else {
            return Err("binary finish required".to_string());
        };
        let (confirm, _session) = pending
            .accept_finish(&finish)
            .map_err(|e| format!("server finish refused: {e:?}"))?;
        ws.send(Message::Binary(confirm.into()))
            .await
            .map_err(|_| "send confirmation".to_string())
    };
    Ok(report(inspected, handshake.await.err()))
}
#[tokio::main]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("--execute") => run(&args[1..]).await,
        Some("--fixture") => fixture(&args[1..]),
        _ => Err("first argument must be --execute or --fixture".into()),
    };
    match result {
        Ok(value) => {
            println!("{value}");
            if value["authorized"] != true {
                std::process::exit(3);
            }
        }
        Err(reason) => {
            // Fixed strings and data-free error variants only.
            eprintln!("hardware channel refused; no measurements accepted: {reason}");
            std::process::exit(2);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    const TIME: Time = Time {
        earliest: 42,
        latest: 42,
        max_uncertainty_secs: 0,
    };
    #[test]
    fn rejects_unframed_or_unexpected_channel_proof() {
        assert!(inspect(b"not BHCH", [0; 32], [0; 32], None, TIME).is_err());
        let frame = wire::make_proof(
            &[0; 32],
            &[0; 1216],
            b"{}",
            &[0; 64],
            b"quote",
            b"collateral",
            b"[]",
        )
        .unwrap();
        let error = |local| inspect(&frame, [0; 32], [0; 32], Some(local), TIME).unwrap_err();
        assert_eq!(
            error((b"collateral", b"different policy")),
            "policy bytes differ from local file"
        );
        assert_eq!(
            error((b"different collateral", b"{}")),
            "collateral bytes differ from local file"
        );
        // A bad quote is a fixed, data-free attestation reason.
        assert_eq!(
            error((b"collateral", b"{}")),
            "hardware evidence refused: Encoding"
        );
    }
    #[test]
    fn refusal_after_authentication_keeps_the_measurement_labelled_unauthorized() {
        let measured = serde_json::json!({"machine": "ab", "compose_matches_candidate": true});
        let refused = report(
            measured.clone(),
            Some("channel proof refused: Policy(MachineDenied)".into()),
        );
        assert_eq!(refused["authorized"], false);
        assert_eq!(refused["machine"], "ab");
        assert_eq!(
            refused["refusal"],
            "channel proof refused: Policy(MachineDenied)"
        );
        assert_eq!(report(measured, None)["authorized"], true);
        let other = report(
            serde_json::json!({"compose_matches_candidate": false}),
            None,
        );
        assert_eq!(other["authorized"], false);
        assert_eq!(other["refusal"], "quote compose differs from candidate");
    }
    #[test]
    fn records_exact_proof_bytes_privately_without_overwriting() {
        use std::os::unix::fs::PermissionsExt;

        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("proof.bin");
        record_proof(path.to_str().unwrap(), b"\0raw\xffproof").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"\0raw\xffproof");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(record_proof(path.to_str().unwrap(), b"replacement").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"\0raw\xffproof");
    }
    #[test]
    fn endpoint_supplies_root_lifetime_uncertainty_and_floor() {
        let t = tempfile::tempdir().unwrap();
        let path = t.path().join("endpoint.json");
        fs::write(
            &path,
            serde_json::json!({"app_root": "11".repeat(32), "max_lifetime_secs": 691200,
                "max_uncertainty_secs": 0, "build_floor": 2})
            .to_string(),
        )
        .unwrap();
        let parsed = endpoint(path.to_str().unwrap()).unwrap();
        assert_eq!(parsed.root, [0x11; 32]);
        assert_eq!(parsed.limits.max_lifetime_secs, 691200);
        assert_eq!(parsed.floor, 2);
        fs::write(&path, b"{\"app_root\":\"11\"}").unwrap();
        assert!(endpoint(path.to_str().unwrap()).is_err());
    }
}
