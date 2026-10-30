use crate::{Result, account, invalid, password};
use bh_core::{BackupLocation, BackupProblem, Core, LocalFolder, SignUp, Url, list_backups};
use chrono::{DateTime, Local, NaiveDateTime};
use clap::Subcommand;
use serde_json::{Value, json};
use std::{
    collections::HashSet,
    env,
    path::{Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

#[derive(Subcommand)]
#[allow(
    clippy::large_enum_variant,
    reason = "clap parses restore's flags directly into this variant"
)]
pub(crate) enum BackupCommand {
    /// Write this account's encrypted backup to a folder.
    Write { dir: PathBuf },
    /// List the accounts and devices in a backup folder without opening them.
    List { dir: PathBuf },
    /// Open a backup with a password and recovery kit, without contacting its server.
    Restore {
        dir: PathBuf,
        #[arg(long)]
        account: Option<String>,
        #[arg(long)]
        device: Option<String>,
        #[arg(long)]
        at: Option<String>,
        #[arg(long = "base", conflicts_with = "signup")]
        bases: Vec<String>,
        #[arg(long, conflicts_with_all = ["check", "signup"])]
        out: Option<PathBuf>,
        #[arg(long, conflicts_with = "signup")]
        check: bool,
        #[arg(long, requires_all = ["server", "invite", "email", "name"], conflicts_with_all = ["out", "check"])]
        signup: bool,
        #[arg(long, requires = "signup")]
        server: Option<Url>,
        #[arg(long, requires = "signup")]
        invite: Option<String>,
        #[arg(long, requires = "signup")]
        email: Option<String>,
        #[arg(long, requires = "signup")]
        name: Option<String>,
        #[arg(long)]
        kit: Zeroizing<String>,
    },
}

pub(crate) fn list(dir: &Path) -> Result<Value> {
    let folder = LocalFolder::new(dir.to_path_buf());
    Ok(Value::Array(
        list_backups(&folder)?
            .into_iter()
            .map(|row| {
                json!({
                    "email": row.email, "account": row.account, "device": row.device,
                    "server": row.server, "writtenAt": row.written_at,
                })
            })
            .collect(),
    ))
}

fn requested_time(value: &str) -> Result<i64> {
    if let Ok(time) = NaiveDateTime::parse_from_str(value, "%Y%m%dT%H%M%S%3fZ") {
        return Ok(time.and_utc().timestamp_millis());
    }
    if let Ok(time) = DateTime::parse_from_rfc3339(value) {
        return Ok(time.timestamp_millis());
    }
    // Also accept Unix milliseconds, useful for the point times printed by --check.
    value
        .parse::<i64>()
        .map_err(|_| invalid("--at must be a run name or RFC 3339 time"))
}

pub(crate) async fn execute(
    core: &Core,
    command: &BackupCommand,
    json_output: bool,
) -> Result<Value> {
    match command {
        BackupCommand::Write { dir } => {
            let owner = account(core)?;
            let location = BackupLocation::Path {
                path: dir.clone(),
                label: dir.display().to_string(),
            };
            owner.set_backup(Some(location))?;
            let _ = owner.refresh().await;
            for base in owner.bases() {
                if let Ok(base) = owner.base(base.id) {
                    let _ = base.flush().await;
                }
            }
            let run = owner.backup_now().await?;
            let status = owner.backup_status()?;
            let problem = status.problem;
            let result = json!({ "run": run.run, "objects": run.objects, "parts": run.parts,
                "snapshots": run.snapshots, "status": status });
            if let Some(
                problem @ (BackupProblem::Unreachable
                | BackupProblem::PermissionLost
                | BackupProblem::Full),
            ) = problem
            {
                if json_output {
                    println!("{result}");
                } else {
                    println!("{}", serde_json::to_string_pretty(&result)?);
                }
                return Err(format!("backup paused: {problem:?} in {}", dir.display()).into());
            }
            Ok(result)
        }
        BackupCommand::List { dir } => list(dir),
        BackupCommand::Restore {
            dir,
            account: chosen_account,
            device: chosen_device,
            at,
            bases: requested,
            out,
            check,
            signup,
            server,
            invite,
            email,
            name,
            kit,
        } => {
            let folder = Arc::new(LocalFolder::new(dir.clone()));
            let listings = list_backups(folder.as_ref())?;
            let selected: Vec<_> = listings
                .iter()
                .filter(|item| {
                    chosen_account
                        .as_ref()
                        .is_none_or(|id| id == &item.account.to_string())
                        && chosen_device
                            .as_ref()
                            .is_none_or(|id| id == &item.device.to_string())
                })
                .collect();
            let listing = match selected.as_slice() {
                [listing] => *listing,
                [] => return Err("no matching backup in this folder".into()),
                _ => return Err("more than one backup; specify --account and --device".into()),
            };
            let mut opened = core.open_backup(folder, listing, password()?, kit).await?;
            let extra_passwords = match env::var("BH_HIDDEN_PASSWORD") {
                Ok(passwords) => Some(Zeroizing::new(passwords)),
                Err(env::VarError::NotPresent) => None,
                Err(_) => return Err(invalid("BH_HIDDEN_PASSWORD must be valid UTF-8")),
            };
            if let Some(passwords) = extra_passwords {
                for extra in passwords.lines().filter(|line| !line.is_empty()) {
                    // One extra password may not open anything; another may still open a base.
                    match opened.unlock(Zeroizing::new(extra.to_string())).await {
                        Ok(_) | Err(bh_core::Error::NothingUnlocked) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
            }
            let points = opened.points();
            let latest = *points.first().ok_or("backup has no points")?;
            let point = if let Some(at) = at {
                let target = requested_time(at)?;
                points
                    .iter()
                    .copied()
                    .find(|point| *point <= target)
                    .ok_or_else(|| {
                        format!(
                            "no backup at or before {at}; oldest point: {}",
                            points.last().unwrap()
                        )
                    })?
            } else {
                latest
            };
            if *check {
                let report = opened.check(point).await?;
                let clean = report.ignored_files.is_empty()
                    && report.locked == 0
                    && report.missing == 0
                    && report
                        .bases
                        .iter()
                        .all(|base| base.unreadable == 0 && base.missing_files.is_empty());
                let result = json!({ "points": points, "at": point, "bases": report.bases.iter().map(|base| json!({
                    "id": base.id, "name": base.name, "objects": base.objects,
                    "unreadable": base.unreadable, "missingFiles": base.missing_files,
                })).collect::<Vec<_>>(), "locked": report.locked, "missing": report.missing,
                    "ignoredFiles": report.ignored_files, "opened": clean });
                if !clean {
                    if json_output {
                        println!("{result}");
                    } else {
                        println!("{}", serde_json::to_string_pretty(&result)?);
                    }
                    return Err("backup check failed: some files or bases did not open".into());
                }
                return Ok(result);
            }
            let available = opened.bases(point).await?;
            let selected = if requested.is_empty() {
                available.iter().collect::<Vec<_>>()
            } else {
                let mut chosen = Vec::new();
                for requested in requested {
                    let base = available
                        .iter()
                        .find(|base| base.id.to_string() == *requested || base.name == *requested)
                        .ok_or_else(|| format!("base not found at this point: {requested}"))?;
                    if !chosen
                        .iter()
                        .any(|item: &&bh_core::RestorableBase| item.id == base.id)
                    {
                        chosen.push(base);
                    }
                }
                chosen
            };
            if let Some(out) = out {
                let mut names = HashSet::new();
                for base in &selected {
                    let name = &base.name;
                    if name == "."
                        || name == ".."
                        || name.contains('/')
                        || name.contains('\\')
                        || !names.insert(name)
                    {
                        return Err(format!(
                            "base name cannot be used as a unique output folder: {name}"
                        )
                        .into());
                    }
                }
                let mut exports = Vec::new();
                let mut missing = std::collections::BTreeSet::new();
                for base in selected {
                    let path = out.join(&base.name);
                    let result = opened.export(point, base.id, &path).await?;
                    missing.extend(result.missing_files.iter().map(ToString::to_string));
                    exports.push(json!({ "base": base.id, "name": base.name, "out": path, "summary": result }));
                }
                if !missing.is_empty() {
                    return Err(format!(
                        "exported available content; missing files: {}",
                        missing.into_iter().collect::<Vec<_>>().join(", ")
                    )
                    .into());
                }
                let report = opened.check(point).await?;
                return Ok(json!({ "at": point, "exports": exports,
                    "unreadable": report.bases.iter().map(|base| base.unreadable).sum::<usize>(),
                    "ignoredFiles": report.ignored_files }));
            }
            let (destination, new_kit) = if *signup {
                if !core.accounts().is_empty() {
                    return Err("--signup requires an empty home".into());
                }
                let (account, kit) = core
                    .sign_up(SignUp {
                        server: server.clone().ok_or_else(|| invalid("--server required"))?,
                        invite: invite.clone().ok_or_else(|| invalid("--invite required"))?,
                        email: email.clone().ok_or_else(|| invalid("--email required"))?,
                        password: password()?,
                        device_name: name.clone().ok_or_else(|| invalid("--name required"))?,
                    })
                    .await?;
                let kit = kit.display();
                eprintln!("Recovery kit: {kit}");
                (account, Some(kit))
            } else {
                (account(core)?, None)
            };
            let date = Local::now();
            let label = format!("restored {}", date.format("%-d %b"));
            let ids = selected.iter().map(|base| base.id).collect::<Vec<_>>();
            let summary = opened
                .restore_into(&destination, point, &ids, &label)
                .await?;
            let mut result = json!({ "at": point, "accountId": destination.id(),
                "restored": summary.restored, "locked": summary.locked,
                "missing": summary.missing, "missingFiles": summary.missing_files,
                "unreadable": summary.unreadable, "ignoredFiles": summary.ignored_files });
            if let Some(kit) = new_kit {
                result["kit"] = json!(kit);
            }
            Ok(result)
        }
    }
}
