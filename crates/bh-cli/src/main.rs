#[path = "commands/backup.rs"]
mod backup;
#[path = "commands/export.rs"]
mod export;
#[path = "commands/files.rs"]
mod files;
#[path = "commands/hero.rs"]
mod hero;
#[path = "commands/hidden.rs"]
mod hidden;
#[path = "commands/usage.rs"]
mod usage;
#[path = "commands/versions.rs"]
mod versions;

use bh_core::{
    Account, AppCredentials, AppRequest, Base, BaseGrantRequest, Core, CoreConfig, DeviceId,
    EndReason, Error, FileSecretStore, Filter, Mode, NewObject, ObjectId, Op, Query, SignIn,
    SignUp, TypeDef, TypeRef, Url,
};

#[path = "commands/approve.rs"]
mod approve;
use backup::BackupCommand;
use clap::{Parser, Subcommand};
use files::FileCommand;
use hero::HeroCommand;
use hidden::HiddenCommand;
use serde::Serialize;
use serde_json::{Value, json};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, IsTerminal, Read, Write},
    path::PathBuf,
    sync::Arc,
};
use yrs::updates::decoder::Decode;
use yrs::{Doc, ReadTxn, Transact, Update, WriteTxn, XmlElementPrelim, XmlFragment, XmlTextPrelim};
use zeroize::Zeroizing;

#[derive(Debug)]
struct FinishingError {
    message: String,
    new_kit: Option<String>,
}

impl std::fmt::Display for FinishingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for FinishingError {}

#[derive(Parser)]
#[command(name = "bh", about = "BaseHero command line client", version)]
struct Cli {
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    unlock: bool,
    #[arg(long, global = true)]
    app_credentials: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    Signup {
        #[arg(long)]
        server: Url,
        #[arg(long)]
        invite: String,
        #[arg(long)]
        email: String,
        #[arg(long)]
        name: String,
    },
    Signin {
        #[arg(long)]
        server: Url,
        #[arg(long)]
        email: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        kit: Option<Zeroizing<String>>,
    },
    Approvals,
    Approve {
        id: Option<String>,
        #[arg(long)]
        base: Vec<String>,
        #[arg(long)]
        new_base: Option<String>,
        #[arg(long)]
        folder: Vec<String>,
        #[arg(long)]
        read_only: bool,
        #[arg(long)]
        cap_usd: Option<String>,
        #[arg(long, conflicts_with = "remove_old")]
        keep_old: bool,
        #[arg(long, conflicts_with = "keep_old")]
        remove_old: bool,
    },
    Decline {
        id: String,
    },
    Bases,
    Usage {
        #[arg(long)]
        month: Option<String>,
    },
    Hidden {
        #[command(subcommand)]
        command: HiddenCommand,
    },
    Base {
        #[command(subcommand)]
        command: BaseCommand,
    },
    Ls {
        #[arg(long)]
        base: Option<String>,
        parent: Option<String>,
    },
    Show {
        id: String,
    },
    Search {
        text: String,
    },
    Versions {
        #[arg(long)]
        base: String,
        id: String,
        #[arg(long)]
        before: Option<u64>,
    },
    Restore {
        #[arg(long)]
        base: String,
        id: String,
        seq: u64,
    },
    Hero {
        #[command(subcommand)]
        command: HeroCommand,
    },
    Note {
        #[command(subcommand)]
        command: NoteCommand,
    },
    Folder {
        #[command(subcommand)]
        command: FolderCommand,
    },
    Mv {
        id: String,
        #[arg(long, conflicts_with = "base")]
        into: Option<String>,
        #[arg(long, conflicts_with = "after")]
        base: Option<String>,
        #[arg(long)]
        after: Option<String>,
    },
    Rm {
        id: String,
    },
    Devices,
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },
    App {
        #[command(subcommand)]
        command: AppCommand,
    },
    Type {
        #[command(subcommand)]
        command: TypeCommand,
    },
    Record {
        #[command(subcommand)]
        command: RecordCommand,
    },
    Watch,
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    Sync,
    /// Write a readable plaintext copy of a base. Hidden bases must be unlocked with --unlock; locked bases are not listed.
    Export {
        #[arg(long)]
        base: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Manage attached files.
    File {
        #[command(subcommand)]
        command: FileCommand,
    },
}
#[derive(Subcommand)]
enum BaseCommand {
    Create { name: String },
}
#[derive(Subcommand)]
enum NoteCommand {
    New {
        #[arg(long)]
        base: Option<String>,
        #[arg(long)]
        parent: Option<String>,
        text: String,
    },
    Append {
        id: String,
        text: String,
    },
}
#[derive(Subcommand)]
enum FolderCommand {
    New { name: String },
}
#[derive(Subcommand)]
enum DeviceCommand {
    Remove {
        id: String,
        #[arg(long, conflicts_with = "kept")]
        lost: bool,
        #[arg(long)]
        kept: bool,
    },
    Cap {
        id: String,
        usd: String,
    },
}
#[derive(Subcommand)]
enum AppCommand {
    List,
    Grant {
        device: String,
        #[arg(long, group = "grant", required = true)]
        base: Option<String>,
        #[arg(long, group = "grant")]
        folder: Option<String>,
        #[arg(long)]
        read_only: bool,
    },
    Ungrant {
        device: String,
        #[arg(long)]
        base: String,
    },
    Connect {
        #[arg(long)]
        name: String,
        #[arg(long, group = "grant", required = true)]
        base: Option<String>,
        #[arg(long, group = "grant")]
        new_base: Option<String>,
        #[arg(long, group = "grant")]
        folder: Option<String>,
        #[arg(long)]
        read_only: bool,
        #[arg(long)]
        out: PathBuf,
    },
}
#[derive(Subcommand)]
enum TypeCommand {
    Define { file: PathBuf },
}
#[derive(Subcommand)]
enum RecordCommand {
    Put {
        #[arg(long = "type")]
        ty: String,
        data: String,
    },
    Query {
        #[arg(long = "type")]
        ty: String,
        #[arg(long = "where")]
        where_fields: Vec<String>,
    },
}
#[derive(Subcommand)]
enum AdminCommand {
    Invite {
        #[arg(long)]
        server: Url,
    },
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn invalid(message: &'static str) -> Box<dyn std::error::Error> {
    Box::new(Error::Invalid(message.into()))
}
fn object_id(s: &str) -> Result<ObjectId> {
    s.parse().map_err(|_| invalid("object ID"))
}
fn password() -> Result<Zeroizing<String>> {
    match env::var("BH_PASSWORD") {
        Ok(password) => Ok(Zeroizing::new(password)),
        Err(env::VarError::NotPresent) => {
            Ok(Zeroizing::new(rpassword::prompt_password("Password: ")?))
        }
        Err(_) => Err(invalid("BH_PASSWORD must be valid UTF-8")),
    }
}
fn hidden_password() -> Result<Zeroizing<String>> {
    match env::var("BH_HIDDEN_PASSWORD") {
        Ok(password) => Ok(Zeroizing::new(password)),
        Err(env::VarError::NotPresent) => Ok(Zeroizing::new(rpassword::prompt_password(
            "Extra password: ",
        )?)),
        Err(_) => Err(invalid("BH_HIDDEN_PASSWORD must be valid UTF-8")),
    }
}
fn account(core: &Core) -> Result<Account> {
    let accounts = core.accounts();
    if accounts.len() != 1 {
        return Err(invalid(
            "expected exactly one signed-in account in this home",
        ));
    }
    Ok(core.account(accounts[0].id)?)
}
fn selected_base(account: &Account, requested: Option<&str>) -> Result<Base> {
    let bases = account.bases();
    let id = if let Some(requested) = requested {
        bases
            .iter()
            .find(|b| b.id.to_string() == requested || b.name == requested)
            .ok_or(Error::NotFound)?
            .id
    } else if bases.len() == 1 {
        bases[0].id
    } else {
        return Err(invalid("specify --base when there is not exactly one base"));
    };
    Ok(account.base(id)?)
}
fn containing_base(account: &Account, id: ObjectId) -> Result<Base> {
    for summary in account.bases() {
        if let Ok(live) = account.locate(summary.id, id) {
            return Ok(account.base(live)?);
        }
    }
    Err(Box::new(Error::NotFound))
}

// The CLI constructs an editor update; validation, persistence and sync stay in bh-core.
fn paragraph(state: &[u8], text: &str) -> Result<Vec<u8>> {
    let doc = Doc::new();
    let mut txn = doc.transact_mut();
    if !state.is_empty() {
        txn.apply_update(Update::decode_v1(state)?)?;
    }
    let before = txn.state_vector();
    let body = txn.get_or_insert_xml_fragment("default");
    body.push_back(
        &mut txn,
        XmlElementPrelim::new("paragraph", [XmlTextPrelim::new(text).into()]),
    );
    Ok(txn.encode_state_as_update_v1(&before))
}

/// Calls [`Core::shutdown`] when dropped.
struct StopOnDrop(Core);

impl Drop for StopOnDrop {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}

async fn watch(account: &Account, json_output: bool) -> Result<Value> {
    let (sender, mut changes) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let mut account_events = account.events();
    let account_sender = sender.clone();
    tokio::spawn(async move {
        while let Ok(event) = account_events.recv().await {
            if account_sender.send(json!({ "account": event })).is_err() {
                break;
            }
        }
    });
    let mut subscribed = std::collections::HashSet::new();
    // Account keeps weak base handles: keep these open so their sync tasks run.
    let mut open_bases = Vec::<Base>::new();
    let subscribe = |account: &Account,
                     subscribed: &mut std::collections::HashSet<_>,
                     open_bases: &mut Vec<Base>| {
        for summary in account.bases() {
            if !subscribed.insert(summary.id) {
                continue;
            }
            let base = account.base(summary.id)?;
            let mut events = base.events();
            open_bases.push(base);
            let sender = sender.clone();
            tokio::spawn(async move {
                while let Ok(event) = events.recv().await {
                    if sender
                        .send(json!({ "baseId": summary.id, "event": event }))
                        .is_err()
                    {
                        break;
                    }
                }
            });
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    };
    subscribe(account, &mut subscribed, &mut open_bases)?;
    account.refresh().await?;
    subscribe(account, &mut subscribed, &mut open_bases)?;
    let (eof_tx, mut eof_rx) = tokio::sync::mpsc::channel::<()>(1);
    // A plain thread, not spawn_blocking: the runtime waits for blocking tasks
    // when it shuts down, so a read still pending after Ctrl-C would keep the
    // process alive until the next line of input.
    std::thread::spawn(move || {
        let mut byte = [0u8];
        while let Ok(n) = io::stdin().read(&mut byte) {
            if n == 0 {
                break;
            }
        }
        let _ = eof_tx.blocking_send(());
    });
    // Edits arrive live. Bases made elsewhere appear at the next refresh, at most
    // once a minute, as in the app.
    let mut poll = tokio::time::interval(std::time::Duration::from_secs(60));
    poll.tick().await;
    loop {
        tokio::select! {
            _ = eof_rx.recv() => break,
            _ = poll.tick() => {
                account.refresh().await?;
                subscribe(account, &mut subscribed, &mut open_bases)?;
            },
            event = changes.recv() => {
                let Some(event) = event else { break; };
                if event.get("account").and_then(|v| v.as_str()) == Some("basesChanged") {
                    account.refresh().await?;
                    subscribe(account, &mut subscribed, &mut open_bases)?;
                }
                if json_output { println!("{event}"); }
                else { println!("{}", serde_json::to_string_pretty(&event)?); }
                io::stdout().flush()?;
            }
        }
    }
    Ok(Value::Null)
}

async fn execute(cli: &Cli) -> Result<Value> {
    if let Command::Admin {
        command: AdminCommand::Invite { server },
    } = &cli.command
    {
        // The CLI's one operator-only request deliberately stays out of bh-core,
        // which ships in every app and must not carry an operator-token API.
        let loopback = matches!(
            server.host_str(),
            Some("127.0.0.1" | "[::1]" | "::1" | "localhost")
        );
        if server.scheme() != "https" && !(server.scheme() == "http" && loopback) {
            return Err(invalid("admin invite requires HTTPS or loopback HTTP"));
        }
        let token = Zeroizing::new(
            env::var("BH_OPERATOR_TOKEN").map_err(|_| invalid("BH_OPERATOR_TOKEN is required"))?,
        );
        let response = reqwest::Client::new()
            .post(server.join("v1/admin/invites")?)
            .header("BH-Protocol", "1")
            .bearer_auth(token.as_str())
            .json(&json!({}))
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(invalid("invite request failed"));
        }
        return Ok(response.json().await?);
    }
    let home = match &cli.home {
        Some(home) => home.clone(),
        None => PathBuf::from(env::var_os("HOME").ok_or_else(|| invalid("HOME is required"))?)
            .join(".local/share/basehero-cli"),
    };
    if let Command::Backup {
        command: BackupCommand::List { dir },
    } = &cli.command
    {
        return backup::list(dir);
    }
    // Offline reads never open a signed-in account or contact its server.
    let temporary = if matches!(
        &cli.command,
        Command::Backup {
            command: BackupCommand::Restore { out: Some(_), .. }
                | BackupCommand::Restore { check: true, .. }
        }
    ) {
        if cli.app_credentials.is_some() || cli.unlock {
            return Err(invalid(
                "offline backup restore does not use --app-credentials or --unlock",
            ));
        }
        Some(tempfile::tempdir()?)
    } else {
        None
    };
    let data_dir = temporary
        .as_ref()
        .map_or(home.clone(), |dir| dir.path().to_path_buf());
    let core = Core::open(CoreConfig {
        data_dir: data_dir.clone(),
        secrets: Arc::new(FileSecretStore::new(data_dir.join("secrets"))?),
    })?;
    // Stop the core's threads before the process exits, on every return path:
    // a core thread still in SQLCipher when the process exits crashes it.
    let _stop = StopOnDrop(core.clone());
    if let Some(path) = &cli.app_credentials {
        let creds: AppCredentials = serde_json::from_slice(&fs::read(path)?)?;
        if core.accounts().is_empty() {
            core.install_app(creds).await?;
        } else if core.accounts().len() != 1
            || core.accounts()[0].id != creds.account_id
            || core.account(creds.account_id)?.device_id() != creds.device_id
        {
            return Err(invalid("app credentials do not match this home"));
        }
    }
    let unlocked = if cli.unlock {
        let account = account(&core)?;
        let result = match hidden_password() {
            Ok(password) => account.unlock_hidden(password).await.map(|_| ()),
            Err(error) => {
                account.lock_all_hidden().await;
                return Err(error);
            }
        };
        if let Err(error) = result {
            account.lock_all_hidden().await;
            return Err(Box::new(error));
        }
        Some(account)
    } else {
        None
    };
    // Taken before the command runs: a removal takes the account off the list.
    let current = account(&core).ok();
    // Ctrl-C in watch must return through the same lock path as errors and EOF.
    let result = if cli.unlock && matches!(cli.command, Command::Watch) {
        tokio::select! {
            result = execute_command(core.clone(), cli) => result,
            signal = tokio::signal::ctrl_c() => {
                signal?;
                Ok(Value::Null)
            }
        }
    } else {
        execute_command(core.clone(), cli).await
    };
    // A removal notice starts erasing a removed device's copy in the background.
    // Finish it before the core stops, or the copy outlives every run. Without
    // one, the server alone signed this device out, and the copy stays.
    let result = match (&current, result) {
        (Some(account), Err(error))
            if matches!(error.downcast_ref::<Error>(), Some(Error::Revoked)) =>
        {
            let _ = account.settle_removal().await;
            if account.signed_out_by_server() {
                Err(format!(
                    "the server signed this device out, but none of your devices removed it; \
                     its copy is kept. To erase it: bh device remove {}",
                    account.device_id()
                )
                .into())
            } else {
                Err(error)
            }
        }
        (_, result) => result,
    };
    if let Some(account) = unlocked {
        account.lock_all_hidden().await;
    }
    result
}

async fn execute_command(core: Core, cli: &Cli) -> Result<Value> {
    match &cli.command {
        Command::Backup { command } => backup::execute(&core, command, cli.json).await,
        Command::Signup {
            server,
            invite,
            email,
            name,
        } => {
            let (account, kit) = core
                .sign_up(SignUp {
                    server: server.clone(),
                    invite: invite.clone(),
                    email: email.clone(),
                    password: password()?,
                    device_name: name.clone(),
                })
                .await?;
            Ok(json!({ "accountId": account.id(), "kit": kit.display() }))
        }
        Command::Signin {
            server,
            email,
            name,
            kit,
        } => {
            let pending = core
                .sign_in(SignIn {
                    server: server.clone(),
                    email: email.clone(),
                    password: password()?,
                    device_name: name.clone(),
                })
                .await?;
            let account = if let Some(kit) = kit {
                pending.with_kit(kit).await?
            } else {
                let mut approval = pending.request_approval().await?;
                if cli.json {
                    println!("{}", json!({"approvalId": approval.id()}));
                } else {
                    eprintln!("Approve this device on one of your signed-in devices.");
                }
                let digits = approval.digits().await?;
                if cli.json {
                    #[derive(Serialize)]
                    struct DigitsLine<'a> {
                        digits: &'a str,
                    }
                    let mut out = io::stdout().lock();
                    serde_json::to_writer(
                        &mut out,
                        &DigitsLine {
                            digits: digits.as_str(),
                        },
                    )?;
                    out.write_all(b"\n")?;
                } else {
                    println!("Type {digits} on the approving device.");
                }
                drop(digits);
                approval.wait().await?
            };
            Ok(json!({ "accountId": account.id(), "deviceId": account.device_id() }))
        }
        Command::Approvals => approve::list(&account(&core)?).await,
        Command::Approve {
            id,
            base,
            new_base,
            folder,
            read_only,
            cap_usd,
            keep_old,
            remove_old,
        } => {
            approve::approve(
                &account(&core)?,
                id.as_deref(),
                cli.json,
                &approve::AppFlags {
                    bases: base,
                    new_base: new_base.as_deref(),
                    folders: folder,
                    read_only: *read_only,
                    cap_usd: cap_usd.as_deref(),
                    keep_old: *keep_old,
                    remove_old: *remove_old,
                },
            )
            .await
        }
        Command::Decline { id } => approve::decline(&account(&core)?, id).await,
        Command::Bases => hidden::summaries(account(&core)?.bases()),
        Command::Usage { month } => {
            let account = account(&core)?;
            let report = account.usage(month.as_deref()).await?;
            let selected = month
                .as_deref()
                .or_else(|| report.days.first().map(|r| &r.period[..7]))
                .or_else(|| report.months.last().map(|r| r.period.as_str()))
                .unwrap_or("this month");
            if !cli.json {
                print!("{}", usage::format(&report, selected));
            }
            Ok(usage::json(&report, selected))
        }
        Command::Hidden { command } => hidden::execute(&account(&core)?, command).await,
        Command::Base {
            command: BaseCommand::Create { name },
        } => {
            let base = account(&core)?.create_base(name).await?;
            Ok(json!({ "id": base.id(), "name": approve::terminal_device_name(&base.name()) }))
        }
        Command::Ls { base, parent } => {
            let account = account(&core)?;
            let base = selected_base(&account, base.as_deref())?;
            Ok(serde_json::to_value(account.tree_children(
                base.id(),
                parent.as_deref().map(object_id).transpose()?,
            )?)?)
        }
        Command::Show { id } => {
            let id = object_id(id)?;
            let base = containing_base(&account(&core)?, id)?;
            let summary = base.get(id)?.ok_or(Error::NotFound)?;
            let mut result = serde_json::to_value(&summary)?;
            if matches!(
                summary.ty.name.as_str(),
                "core.note" | "core.folder" | "core.project"
            ) {
                result["text"] = Value::String(base.note(id)?.text());
            }
            Ok(result)
        }
        Command::Versions { base, id, before } => {
            versions::list(&account(&core)?, base, id, *before).await
        }
        Command::Restore { base, id, seq } => {
            versions::restore(&account(&core)?, base, id, *seq).await
        }
        Command::Search { text } => {
            let account = account(&core)?;
            let mut hits = Vec::new();
            for summary in account.bases() {
                let base = account.base(summary.id)?;
                for hit in base.search(text, 100)? {
                    let mut value = serde_json::to_value(hit)?;
                    value["baseId"] = json!(summary.id);
                    hits.push(value);
                }
            }
            Ok(Value::Array(hits))
        }
        Command::Hero { command } => hero::execute(&account(&core)?, command).await,
        Command::Note {
            command: NoteCommand::New { base, parent, text },
        } => {
            let base = selected_base(&account(&core)?, base.as_deref())?;
            let id = base.create(NewObject {
                ty: TypeRef::new("core.note", 1),
                parent: parent.as_deref().map(object_id).transpose()?,
                after: None,
                fields: Default::default(),
            })?;
            base.note(id)?.apply(0, &paragraph(&[], text)?)?;
            Ok(json!({ "id": id, "baseId": base.id() }))
        }
        Command::Note {
            command: NoteCommand::Append { id, text },
        } => {
            let id = object_id(id)?;
            let base = containing_base(&account(&core)?, id)?;
            let note = base.note(id)?;
            note.apply(0, &paragraph(&note.state(), text)?)?;
            Ok(json!({ "id": id }))
        }
        Command::Folder {
            command: FolderCommand::New { name },
        } => {
            let base = selected_base(&account(&core)?, None)?;
            let mut fields = serde_json::Map::new();
            fields.insert("name".into(), Value::String(name.clone()));
            let id = base.create(NewObject {
                ty: TypeRef::new("core.folder", 1),
                parent: None,
                after: None,
                fields,
            })?;
            Ok(json!({ "id": id, "baseId": base.id() }))
        }
        Command::Mv {
            id,
            into,
            base,
            after,
        } => {
            let account = account(&core)?;
            let id = object_id(id)?;
            let source = containing_base(&account, id)?;
            let mut parent = into.as_deref().map(object_id).transpose()?;
            let target = if let Some(base) = base {
                selected_base(&account, Some(base))?.id()
            } else if let Some(id) = parent {
                let owner = containing_base(&account, id)?;
                if let Some(mount) = account
                    .mounts()
                    .iter()
                    .find(|m| m.parent == owner.id() && m.folder == id)
                {
                    parent = None;
                    mount.base
                } else {
                    owner.id()
                }
            } else {
                source.id()
            };
            if target == source.id() {
                source.move_to(id, parent, after.as_deref().map(object_id).transpose()?)?;
            } else {
                if after.is_some() {
                    return Err(invalid("--after is only for moves within a base"));
                }
                account
                    .move_between(source.id(), id, target, parent)
                    .await?;
            }
            Ok(json!({ "id": id }))
        }
        Command::Rm { id } => {
            let id = object_id(id)?;
            containing_base(&account(&core)?, id)?.delete(id)?;
            Ok(json!({ "id": id }))
        }
        Command::Devices => {
            let mut devices = serde_json::to_value(account(&core)?.devices().await?)?;
            if let Value::Array(rows) = &mut devices {
                for row in rows {
                    if let Some(name) = row.get_mut("name")
                        && let Some(raw) = name.as_str()
                    {
                        *name = Value::String(approve::terminal_device_name(raw));
                    }
                }
            }
            Ok(devices)
        }
        Command::Device {
            command: DeviceCommand::Remove { id, lost, kept },
        } => {
            let id: DeviceId = id.parse().map_err(|_| invalid("device ID"))?;
            let account = account(&core)?;
            let this_device = account.device_id() == id;
            let full = if this_device {
                false
            } else {
                account
                    .devices()
                    .await?
                    .iter()
                    .any(|d| d.id == id && d.kind == bh_core::DeviceKind::Full)
            };
            let removal = if full {
                let lost = if *lost {
                    true
                } else if *kept {
                    false
                } else {
                    if !io::stdin().is_terminal() {
                        return Err(invalid("specify --lost or --kept when not on a terminal"));
                    }
                    eprint!(
                        "Do you still have this device? [y = I still have it / n = It's lost or stolen] "
                    );
                    io::stderr().flush()?;
                    let mut answer = String::new();
                    io::stdin().read_line(&mut answer)?;
                    match answer.trim().to_ascii_lowercase().as_str() {
                        "y" => false,
                        "n" => true,
                        _ => return Err(invalid("answer y or n")),
                    }
                };
                bh_core::Removal::Full {
                    password: password()?,
                    lost,
                }
            } else {
                bh_core::Removal::Plain
            };
            let outcome = account.remove_device(id, removal).await?;
            let new_kit = outcome.new_kit.map(|kit| kit.display());
            if full {
                if !cli.json {
                    if let Some(kit) = &new_kit {
                        println!(
                            "Recovery kit: {kit}\nKeep this kit safe; it is required to sign in on another device."
                        );
                    }
                    println!("Finishing…");
                    io::stdout().flush()?;
                }
                account.wait_for_removals().await.map_err(|error| FinishingError {
                    message: format!(
                        "Removal committed; finishing failed: {error}. Finishing continues on the next refresh of any BaseHero device."
                    ),
                    new_kit: new_kit.clone(),
                })?;
            }
            Ok(json!({ "removed": id, "localCopyErased": this_device,
                "newKit": if cli.json { new_kit } else { None },
                "pending": if full { false } else { outcome.pending } }))
        }
        Command::Device {
            command: DeviceCommand::Cap { id, usd },
        } => {
            let id: DeviceId = id.parse().map_err(|_| invalid("device ID"))?;
            let cap = approve::parse_usd(usd)?;
            account(&core)?.set_app_cap(id, cap).await?;
            Ok(json!({"device": id, "capMicroUsd": cap}))
        }
        Command::App {
            command: AppCommand::List,
        } => Ok(serde_json::to_value(account(&core)?.apps())?),
        Command::App {
            command:
                AppCommand::Grant {
                    device,
                    base,
                    folder,
                    read_only,
                },
        } => {
            let account = account(&core)?;
            let device: DeviceId = device.parse().map_err(|_| invalid("device ID"))?;
            let mode = if *read_only {
                Mode::ReadOnly
            } else {
                Mode::ReadWrite
            };
            let grant = if let Some(folder) = folder {
                let folder = object_id(folder)?;
                BaseGrantRequest::Folder {
                    base: containing_base(&account, folder)?.id(),
                    folder,
                    mode,
                }
            } else {
                BaseGrantRequest::Existing {
                    base: selected_base(&account, base.as_deref())?.id(),
                    mode,
                }
            };
            let base = account.add_app_grant(device, grant).await?;
            Ok(json!({ "device": device, "base": base }))
        }
        Command::App {
            command: AppCommand::Ungrant { device, base },
        } => {
            let account = account(&core)?;
            let device: DeviceId = device.parse().map_err(|_| invalid("device ID"))?;
            let base = selected_base(&account, Some(base))?.id();
            account.remove_app_grant(device, base).await?;
            Ok(json!({ "device": device, "base": base }))
        }
        Command::App {
            command:
                AppCommand::Connect {
                    name,
                    base,
                    new_base,
                    folder,
                    read_only,
                    out,
                },
        } => {
            let account = account(&core)?;
            let mode = if *read_only {
                Mode::ReadOnly
            } else {
                Mode::ReadWrite
            };
            let grant = if let Some(folder) = folder {
                let folder = object_id(folder)?;
                BaseGrantRequest::Folder {
                    base: containing_base(&account, folder)?.id(),
                    folder,
                    mode,
                }
            } else if let Some(base) = base {
                BaseGrantRequest::Existing {
                    base: selected_base(&account, Some(base))?.id(),
                    mode,
                }
            } else {
                BaseGrantRequest::New {
                    name: new_base.clone().ok_or_else(|| invalid("new base name"))?,
                    mode,
                }
            };
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            // Reserve the path atomically before registering the app or making a base.
            let mut file = options.open(out)?;
            let result: Result<Value> = async {
                let creds = account
                    .connect_app(AppRequest {
                        app_name: name.clone(),
                        app_id: None,
                        bases: vec![grant],
                        replaces: None,
                    })
                    .await?;
                let bytes = serde_json::to_vec(&creds)?;
                if let Err(error) = file.write_all(&bytes) {
                    let _ = account
                        .remove_device(creds.device_id, bh_core::Removal::Plain)
                        .await;
                    return Err(error.into());
                }
                Ok(json!({ "deviceId": creds.device_id, "bases": creds.bases, "out": out }))
            }
            .await;
            if result.is_err() {
                drop(file);
                let _ = fs::remove_file(out);
            }
            result
        }
        Command::Type {
            command: TypeCommand::Define { file },
        } => {
            let def: TypeDef = serde_json::from_slice(&fs::read(file)?)?;
            selected_base(&account(&core)?, None)?.define_type(def.clone())?;
            Ok(json!({ "name": def.name, "version": def.version }))
        }
        Command::Record {
            command: RecordCommand::Put { ty, data: fields },
        } => {
            let fields: serde_json::Map<String, Value> = serde_json::from_str(fields)?;
            let base = selected_base(&account(&core)?, None)?;
            let version = base
                .types()?
                .into_iter()
                .filter(|d| d.name == *ty)
                .map(|d| d.version)
                .max()
                .ok_or_else(|| invalid("type not defined in this base"))?;
            let id = base.create(NewObject {
                ty: TypeRef::new(ty, version),
                parent: None,
                after: None,
                fields,
            })?;
            Ok(json!({ "id": id, "baseId": base.id() }))
        }
        Command::Record {
            command: RecordCommand::Query { ty, where_fields },
        } => {
            let filters = where_fields
                .iter()
                .map(|entry| {
                    let (field, value) = entry
                        .split_once('=')
                        .ok_or_else(|| invalid("--where requires FIELD=VALUE"))?;
                    if field.is_empty() {
                        return Err(invalid("--where requires FIELD=VALUE"));
                    }
                    Ok(Filter {
                        field: field.into(),
                        op: Op::Eq,
                        value: serde_json::from_str(value)
                            .unwrap_or_else(|_| Value::String(value.into())),
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let account = account(&core)?;
            let mut records = Vec::new();
            for summary in account.bases() {
                records.extend(account.base(summary.id)?.query(&Query {
                    ty: ty.clone(),
                    filters: filters.clone(),
                    order_by: None,
                    limit: None,
                })?);
            }
            Ok(serde_json::to_value(records)?)
        }
        Command::Export { base, out } => export::execute(&core, base, out).await,
        Command::File { command } => files::execute(&core, command),
        Command::Watch => watch(&account(&core)?, cli.json).await,
        Command::Sync => {
            let account = account(&core)?;
            account.refresh().await?;
            let mut states = Vec::new();
            for summary in account.bases() {
                let base = account.base(summary.id)?;
                base.flush().await?;
                states.push(json!({ "baseId": summary.id, "pending": base.sync_state().pending }));
            }
            Ok(json!({ "bases": states }))
        }
        Command::Admin { .. } => unreachable!(),
    }
}

fn approval_end_message(reason: EndReason) -> &'static str {
    match reason {
        EndReason::WrongDigits => "The digits didn't match. Run the sign-in again to start over.",
        EndReason::Declined => "The request was declined.",
        EndReason::Cancelled => "The request was cancelled.",
        EndReason::Expired => {
            "The request expired after two minutes. Run the sign-in again to start over."
        }
        EndReason::AlreadyAnswered => "Another device is already answering this request.",
        EndReason::BadMessage => "The exchange failed. Run the sign-in again to start over.",
    }
}

#[tokio::main]
async fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if !matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) && env::args_os().any(|arg| arg == "--json")
            {
                eprintln!("{}", json!({ "error": error.to_string() }));
                std::process::exit(error.exit_code());
            }
            error.exit();
        }
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    match execute(&cli).await {
        Ok(value) if cli.json => println!("{value}"),
        Ok(value) => match &cli.command {
            Command::Signin {
                email, kit: None, ..
            } => println!("Signed in as {email}."),
            Command::Approve { .. } => {}
            Command::Watch | Command::Usage { .. } => {}
            Command::Device {
                command: DeviceCommand::Remove { .. },
            } if value["localCopyErased"] == true => {
                println!("This device was removed; its home's local copy was erased.")
            }
            Command::Device {
                command: DeviceCommand::Remove { .. },
            } => {
                if let Some(kit) = value["newKit"].as_str() {
                    println!(
                        "Recovery kit: {kit}\nKeep this kit safe; it is required to sign in on another device."
                    );
                }
                if value["pending"] == true {
                    println!("Removal is still finishing.");
                } else {
                    println!("Device removed.");
                }
            }
            Command::Backup {
                command: BackupCommand::Restore { signup: true, .. },
            } => println!(
                "Recovery kit: {}\nKeep this kit safe; it is required to sign in on another device.\n{}",
                value["kit"].as_str().unwrap_or(""),
                serde_json::to_string_pretty(&value).unwrap_or_default()
            ),
            Command::Signup { .. } => println!(
                "Recovery kit: {}\nKeep this kit safe; it is required to sign in on another device.",
                value["kit"].as_str().unwrap_or("")
            ),
            _ => println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_default()
            ),
        },
        Err(error) => {
            let message = match error.downcast_ref::<Error>() {
                Some(Error::ApprovalEnded(reason)) => Some(approval_end_message(*reason)),
                Some(Error::NothingUnlocked) if cli.json => {
                    println!("{}", json!({ "kind": "NothingUnlocked" }));
                    std::process::exit(1);
                }
                _ => None,
            };
            let formatted = message.unwrap_or("");
            if cli.json {
                let detail = if message.is_some() {
                    formatted.to_owned()
                } else {
                    error.to_string()
                };
                if let Some(finishing) = error.downcast_ref::<FinishingError>() {
                    eprintln!(
                        "{}",
                        json!({ "error": detail, "newKit": finishing.new_kit })
                    );
                } else {
                    eprintln!("{}", json!({ "error": detail }));
                }
            } else if message.is_some() {
                eprintln!("{formatted}");
            } else {
                eprintln!("bh: {error}");
            }
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod approval_message_tests {
    use super::*;

    #[test]
    fn end_reason_messages_are_exact() {
        for (reason, expected) in [
            (
                EndReason::WrongDigits,
                "The digits didn't match. Run the sign-in again to start over.",
            ),
            (EndReason::Declined, "The request was declined."),
            (EndReason::Cancelled, "The request was cancelled."),
            (
                EndReason::Expired,
                "The request expired after two minutes. Run the sign-in again to start over.",
            ),
            (
                EndReason::AlreadyAnswered,
                "Another device is already answering this request.",
            ),
            (
                EndReason::BadMessage,
                "The exchange failed. Run the sign-in again to start over.",
            ),
        ] {
            assert_eq!(approval_end_message(reason), expected);
        }
    }
}
