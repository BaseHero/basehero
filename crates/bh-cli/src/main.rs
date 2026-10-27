#[path = "commands/hero.rs"]
mod hero;

use bh_core::{
    Account, AppCredentials, AppRequest, Base, BaseGrantRequest, Core, CoreConfig, DeviceId,
    EndReason, Error, FileSecretStore, Filter, Mode, NewObject, ObjectId, Op, Query, SignIn,
    SignUp, TypeDef, TypeRef, Url,
};

#[path = "commands/approve.rs"]
mod approve;
use clap::{Parser, Subcommand};
use hero::HeroCommand;
use serde::Serialize;
use serde_json::{Value, json};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::{
    env,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::PathBuf,
    sync::Arc,
};
use yrs::updates::decoder::Decode;
use yrs::{Doc, ReadTxn, Transact, Update, WriteTxn, XmlElementPrelim, XmlFragment, XmlTextPrelim};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "bh", about = "BaseHero command line client", version)]
struct Cli {
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    #[arg(long, global = true)]
    json: bool,
    #[arg(long, global = true)]
    app_credentials: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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
    },
    Decline {
        id: String,
    },
    Bases,
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
        #[arg(long)]
        into: Option<String>,
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
    Remove { id: String },
}
#[derive(Subcommand)]
enum AppCommand {
    Connect {
        #[arg(long)]
        name: String,
        #[arg(
            long,
            conflicts_with = "new_base",
            required_unless_present = "new_base"
        )]
        base: Option<String>,
        #[arg(long)]
        new_base: Option<String>,
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
        let base = account.base(summary.id)?;
        if base.get(id)?.is_some() {
            return Ok(base);
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
    tokio::task::spawn_blocking(move || {
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
    let core = Core::open(CoreConfig {
        data_dir: home.clone(),
        secrets: Arc::new(FileSecretStore::new(home.join("secrets"))?),
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
    match &cli.command {
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
        Command::Approve { id } => {
            approve::approve(&account(&core)?, id.as_deref(), cli.json).await
        }
        Command::Decline { id } => approve::decline(&account(&core)?, id).await,
        Command::Bases => Ok(serde_json::to_value(account(&core)?.bases())?),
        Command::Base {
            command: BaseCommand::Create { name },
        } => {
            let base = account(&core)?.create_base(name).await?;
            Ok(json!({ "id": base.id(), "name": base.name() }))
        }
        Command::Ls { base, parent } => {
            let base = selected_base(&account(&core)?, base.as_deref())?;
            Ok(serde_json::to_value(base.children(
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
        Command::Mv { id, into, after } => {
            let id = object_id(id)?;
            let base = containing_base(&account(&core)?, id)?;
            base.move_to(
                id,
                into.as_deref().map(object_id).transpose()?,
                after.as_deref().map(object_id).transpose()?,
            )?;
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
            command: DeviceCommand::Remove { id },
        } => {
            let id: DeviceId = id.parse().map_err(|_| invalid("device ID"))?;
            let this_device = account(&core)?.device_id() == id;
            account(&core)?.remove_device(id).await?;
            Ok(json!({ "removed": id, "localCopyErased": this_device }))
        }
        Command::App {
            command:
                AppCommand::Connect {
                    name,
                    base,
                    new_base,
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
            let grant = if let Some(base) = base {
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
                    let _ = account.remove_device(creds.device_id).await;
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
            Command::Watch => {}
            Command::Device {
                command: DeviceCommand::Remove { .. },
            } if value["localCopyErased"] == true => {
                println!("This device was removed; its home's local copy was erased.")
            }
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
                _ => None,
            };
            let formatted = message.unwrap_or("");
            if cli.json {
                eprintln!(
                    "{}",
                    json!({ "error": if message.is_some() { formatted.to_owned() } else { error.to_string() } })
                );
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
