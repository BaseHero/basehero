//! Synthetic local-only hostile account entries, ordered with the disposable
//! stack's permit key. Pass the hexadecimal account id shown by `list`.
#[path = "support/forged_account_change.rs"]
mod forged;
use bh_account::{AccountEvent, AccountId, ConfirmedTime, VerifiedAccount};
use bh_authz::proto::{account_log_id, account_log_wrap};
use bh_crypto::{Secret, SigningKey};
use bh_sync::{
    Commitment, Digest, Head,
    evidence::OrderingConfirmation,
    permit::{self, LogId, LogKind, Permit, Scope},
    wire::{Request, Response},
};
use forged::{Kind, forge};
use futures_util::{SinkExt, StreamExt};
use rusqlite::Connection;
use std::{
    env, fs,
    net::SocketAddr,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio_tungstenite::{connect_async, tungstenite::Message};

fn seed(path: &Path) -> Result<SigningKey, String> {
    let bytes = hex::decode(fs::read_to_string(path).map_err(|e| e.to_string())?.trim())
        .map_err(|e| e.to_string())?;
    Ok(SigningKey::from_seed(
        &Secret::from_slice(&bytes).map_err(|e| format!("seed: {e:?}"))?,
    ))
}
fn sign(dir: &Path, scope: Scope) -> Result<Vec<u8>, String> {
    let keys = dir.join("keys");
    let cert: [u8; 130] = hex::decode(
        fs::read_to_string(keys.join("permit.cert"))
            .map_err(|e| e.to_string())?
            .trim(),
    )
    .map_err(|e| e.to_string())?
    .try_into()
    .map_err(|_| "bad local permit certificate")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_millis() as u64;
    Ok(permit::sign(
        &seed(&keys.join("permit.seed"))?,
        &cert,
        &Permit {
            scope,
            issued_ms: now,
            deadline_ms: now + 30_000,
            batch: bh_crypto::random(),
        },
    ))
}
async fn data(edge: &str, request: Request) -> Result<Response, String> {
    let url = format!("{}{}", edge.replacen("http://", "ws://", 1), "/v1/data");
    let (mut ws, upgrade) = connect_async(url).await.map_err(|e| e.to_string())?;
    if upgrade.status() != 101 {
        return Err("no local data socket".into());
    }
    ws.send(Message::Binary(
        request
            .encode()
            .map_err(|e| format!("request: {e:?}"))?
            .into(),
    ))
    .await
    .map_err(|e| e.to_string())?;
    let response = ws
        .next()
        .await
        .ok_or("no data response")?
        .map_err(|e| e.to_string())?;
    let Message::Binary(frame) = response else {
        return Err("nonbinary data response".into());
    };
    Response::decode(&frame).map_err(|e| format!("response: {e:?}"))
}

/// The local service's durable *verified* account projection. No UI signing
/// material is read or needed. A missing row means the service has not yet
/// learned of that account; ask the app to sync before trying again.
fn load_view(
    db: &Connection,
    root: &[u8; 32],
    account: AccountId,
) -> Result<(VerifiedAccount, LogId, Head), String> {
    let (recorded_log, position, hash): (Vec<u8>, i64, Vec<u8>) = db
        .query_row(
            "SELECT log, position, log_hash FROM accounts WHERE account=?1",
            [account.0.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|e| format!("account not in local service (sync it first): {e}"))?;
    let genesis: Vec<u8> = db
        .query_row(
            "SELECT bytes FROM account_events WHERE account=?1 AND position=1",
            [account.0.as_slice()],
            |r| r.get(0),
        )
        .map_err(|e| format!("account genesis unavailable: {e}"))?;
    let decoded = AccountEvent::decode(&genesis).map_err(|e| format!("genesis: {e:?}"))?;
    if AccountId::of_genesis(&decoded).map_err(|e| format!("genesis: {e:?}"))? != account {
        return Err("account id does not match its genesis".into());
    }
    let log = LogId {
        kind: LogKind::Account,
        id: account_log_id(&genesis).map_err(|e| format!("log: {e:?}"))?,
    };
    if recorded_log != log.id || position < 1 {
        return Err("wrong account log".into());
    }
    let mut view =
        VerifiedAccount::from_genesis(account, &genesis).map_err(|e| format!("genesis: {e:?}"))?;
    let mut stmt = db.prepare("SELECT e.position, e.bytes, e.body, c.confirmation FROM account_events e LEFT JOIN account_confirmations c ON c.account=e.account AND c.position=e.position WHERE e.account=?1 AND e.position>1 ORDER BY e.position")
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([account.0.as_slice()], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Option<Vec<u8>>>(2)?,
                r.get::<_, Option<Vec<u8>>>(3)?,
            ))
        })
        .map_err(|e| e.to_string())?;
    for row in rows {
        let (pos, original, body, confirmation) = row.map_err(|e| e.to_string())?;
        if pos != (view.head().position + 1) as i64 {
            return Err("nonconsecutive account history".into());
        }
        let time = confirmation
            .map(|raw| {
                let cert = OrderingConfirmation::decode(&raw)
                    .map_err(|e| format!("confirmation: {e:?}"))?;
                let digest = body
                    .as_deref()
                    .map(|b| {
                        b.try_into()
                            .map(Digest)
                            .map_err(|_| "bad body commitment".to_owned())
                    })
                    .transpose()?;
                let claim = cert
                    .verify_for(root, &original, digest)
                    .map_err(|e| format!("confirmation: {e:?}"))?;
                if claim.original_head.position != pos as u64 || claim.log != log {
                    return Err("confirmation for another account position".into());
                }
                Ok::<_, String>(ConfirmedTime {
                    earliest_ms: claim.bounds.earliest_ms,
                    latest_ms: claim.bounds.latest_ms,
                })
            })
            .transpose()?;
        view.apply_timed(&original, time)
            .map_err(|e| format!("history: {e:?}"))?;
    }
    if view.head().position != position as u64 {
        return Err("service history position mismatch".into());
    }
    let head = Head {
        position: position as u64,
        hash: Digest(hash.try_into().map_err(|_| "bad local head")?),
    };
    Ok((view, log, head))
}

/// SQLite rowid is the service's first-seen order. The schema stores no
/// creation timestamp, so do not invent one from an unrelated confirmation.
fn listed(db: &Connection, root: &[u8; 32]) -> Result<Vec<(i64, AccountId, usize)>, String> {
    let mut stmt = db
        .prepare("SELECT rowid, hex(account) FROM accounts ORDER BY rowid")
        .map_err(|e| e.to_string())?;
    let ids = stmt
        .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    ids.into_iter()
        .map(|(order, id)| {
            let account = AccountId(
                hex::decode(&id)
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|_| "bad account id")?,
            );
            let (view, _, _) = load_view(db, root, account)?;
            let count = view
                .active_devices()
                .map_err(|e| format!("devices: {e:?}"))?
                .count();
            Ok((order, account, count))
        })
        .collect()
}

async fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args
        .next()
        .ok_or("usage: forged_account_change list | bad-signature|wrong-signer ACCOUNT_HEX")?;
    let target = if command == "list" {
        if args.next().is_some() {
            return Err("list takes no account".into());
        }
        None
    } else {
        let kind = Kind::parse(&command).ok_or("unknown forgery kind")?;
        let id = args
            .next()
            .ok_or("explicit throwaway account id required")?;
        if args.next().is_some() {
            return Err("expected one account id".into());
        }
        let account = AccountId(
            hex::decode(&id)
                .map_err(|_| "account id must be 64 hex characters")?
                .try_into()
                .map_err(|_| "account id must be 64 hex characters")?,
        );
        Some((kind, account))
    };
    let dir = std::path::PathBuf::from(
        env::var("LOCAL_STACK_DIR").map_err(|_| "LOCAL_STACK_DIR required")?,
    );
    if !dir.is_absolute()
        || !dir.join("env").is_file()
        || !dir.join("keys/permit.seed").is_file()
        || !dir.join("keys/permit.cert").is_file()
    {
        return Err("running local stack environment and permit key required".into());
    }
    let env_text = fs::read_to_string(dir.join("env")).map_err(|e| e.to_string())?;
    let address = env_text
        .lines()
        .find_map(|l| l.strip_prefix("LOCAL_STACK_HOST_EDGE_URL="))
        .and_then(|v| v.strip_prefix("http://"))
        .and_then(|v| v.parse::<SocketAddr>().ok())
        .filter(|address| address.ip().to_string() == "127.0.0.1")
        .ok_or("not a local loopback edge")?;
    let edge = format!("http://{address}");
    let root: [u8; 32] = hex::decode(
        fs::read_to_string(dir.join("keys/hosting-root.pub")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?
    .try_into()
    .map_err(|_| "bad hosting root")?;
    let db = Connection::open_with_flags(
        dir.join("authz.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(|e| e.to_string())?;
    let Some((kind, account)) = target else {
        for (order, account, count) in listed(&db, &root)? {
            println!(
                "{} first-seen={} active-devices={}",
                hex::encode(account.0),
                order,
                count
            );
        }
        return Ok(());
    };
    let (view, log, head) = load_view(&db, &root, account)?;
    let read = data(
        &edge,
        Request::Read {
            id: 1,
            permit: sign(
                &dir,
                Scope::ReadEvents {
                    log,
                    first: head.position,
                    last: head
                        .position
                        .checked_add(1)
                        .ok_or("log position overflow")?,
                },
            )?,
        },
    )
    .await?;
    let Response::Events { items, .. } = read else {
        return Err(format!("cannot read current local log: {read:?}"));
    };
    if items.len() != 1
        || Commitment::decode(&items[0].0)
            .map_err(|e| format!("commitment: {e:?}"))?
            .head()
            != head
    {
        return Err("local log moved; sync the throwaway account first".into());
    }
    let author = view
        .active_devices()
        .map_err(|e| format!("devices: {e:?}"))?
        .next()
        .ok_or("no active author for this account")?
        .id();
    let original = forge(kind, &view, author)?;
    let event = account_log_wrap(&original, None).map_err(|e| format!("wrapper: {e:?}"))?;
    let response = data(
        &edge,
        Request::Append {
            id: 2,
            permit: sign(
                &dir,
                Scope::Append {
                    log,
                    event: event.digest(),
                    body: None,
                    epoch: [0; 32],
                    after: Some(head),
                    attached: None,
                },
            )?,
            event: event.encode(),
        },
    )
    .await?;
    if !matches!(response, Response::Acked { .. }) {
        return Err(format!("forged append refused: {response:?}"));
    }
    println!(
        "ordered one {kind:?} entry into account {}",
        hex::encode(account.0)
    );
    Ok(())
}
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("refused to forge: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_account::{DevicePublicKeys, RecoveryPublicKeys, crypto::KemKey};
    #[test]
    fn lists_stack_accounts_in_first_seen_order_with_active_device_counts() {
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE accounts(account BLOB PRIMARY KEY, log BLOB, position INTEGER, log_hash BLOB);
            CREATE TABLE account_events(account BLOB, position INTEGER, bytes BLOB, body BLOB);
            CREATE TABLE account_confirmations(account BLOB, position INTEGER, confirmation BLOB);").unwrap();
        let mut expected = Vec::new();
        for count in [1, 2] {
            let control = SigningKey::generate();
            let keys = DevicePublicKeys::new(
                SigningKey::generate().public(),
                control.public(),
                KemKey::generate().public(),
            )
            .unwrap();
            let recovery = RecoveryPublicKeys::new(
                SigningKey::generate().public(),
                KemKey::generate().public(),
            );
            let draft = AccountEvent::genesis(keys.clone(), recovery);
            let genesis = draft.finish(control.sign(draft.signing_bytes())).unwrap();
            let account = AccountId::of_genesis(&genesis).unwrap();
            let log = account_log_id(genesis.as_bytes()).unwrap();
            db.execute(
                "INSERT INTO accounts VALUES(?1,?2,?3,?4)",
                rusqlite::params![
                    account.0.as_slice(),
                    log.as_slice(),
                    count as i64,
                    [1u8; 32].as_slice()
                ],
            )
            .unwrap();
            db.execute(
                "INSERT INTO account_events VALUES(?1,1,?2,NULL)",
                rusqlite::params![account.0.as_slice(), genesis.as_bytes()],
            )
            .unwrap();
            if count == 2 {
                let view = VerifiedAccount::from_genesis(account, genesis.as_bytes()).unwrap();
                let second = DevicePublicKeys::new(
                    SigningKey::generate().public(),
                    SigningKey::generate().public(),
                    KemKey::generate().public(),
                )
                .unwrap();
                let request = view.add_device(keys.id(), second).unwrap();
                let add = request
                    .finish(control.sign(request.signing_bytes()))
                    .unwrap();
                db.execute(
                    "INSERT INTO account_events VALUES(?1,2,?2,NULL)",
                    rusqlite::params![account.0.as_slice(), add.as_bytes()],
                )
                .unwrap();
            }
            expected.push((count as i64, account, count));
        }
        assert!(listed(&db, &[0; 32]).unwrap() == expected);
    }
}
