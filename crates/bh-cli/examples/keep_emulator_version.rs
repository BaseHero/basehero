//! Test-only CLI-home step for the Android history check; no product command or test hook is added.
//! Build with `cargo build -p bh-cli --features test-support --example keep_emulator_version`.
use bh_core::{Clock, Core, CoreConfig, FileSecretStore, ObjectId};
use serde_json::{Map, Value};
use std::{
    env,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let home = PathBuf::from(args.next().ok_or("missing temporary CLI home")?);
    let base_id = args
        .next()
        .ok_or("missing base ID")?
        .into_string()
        .map_err(|_| "base ID")?;
    let note_id: ObjectId = args
        .next()
        .ok_or("missing note ID")?
        .into_string()
        .map_err(|_| "note ID")?
        .parse()?;
    if args.next().is_some() {
        return Err("unexpected arguments".into());
    }
    let (clock, manual) = Clock::manual();
    // CLI and Android edits use wall-time timestamps. Align this manual clock
    // with them, then move it past the five-minute pause without sleeping.
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
    manual.advance(Duration::from_millis(now + 1));
    let core = Core::open_with_clock(
        CoreConfig {
            data_dir: home.clone(),
            secrets: Arc::new(FileSecretStore::new(home.join("secrets"))?),
        },
        clock,
    )?;
    let result = async {
        let account = core.account(core.accounts().first().ok_or("no CLI account")?.id)?;
        let base = account.base(base_id.parse()?)?;
        if base.note(note_id)?.text() != "Ferry at 9" {
            return Err("the Android edit has not arrived".into());
        }
        // A real local field edit marks this note eligible; its body still
        // holds the Android text. The post itself uses the core's test hook.
        base.set_fields(
            note_id,
            Map::from_iter([("title".into(), Value::from("Original draft"))]),
        )?;
        base.flush().await?;
        manual.advance(Duration::from_secs(6 * 60));
        base.tick_versions().await?;
        if base.versions(note_id, None, 1).await?.0.is_empty() {
            return Err("no kept version".into());
        }
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;
    core.shutdown();
    result
}
