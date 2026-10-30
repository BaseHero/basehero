//! Encrypted SQLite stores (SQLCipher) and their migrations: the account
//! database and each base's store.

use crate::objects::ObjectSummary;
use crate::types::TypeRef;
use crate::{DeviceKind, Error, Mode};
use bh_proto::{AccountId, BaseId, ChangeId, DeviceId, ObjectId};
use rusqlite::{Connection, OptionalExtension, Row, params};
use std::collections::HashMap;
use std::mem::ManuallyDrop;
use std::path::Path;
use std::sync::{Condvar, Mutex, MutexGuard, Once};
use std::time::Duration;
use zeroize::Zeroizing;

/// Opens a SQLCipher database with a raw 32-byte key and checks the key works.
pub(crate) fn open_encrypted(path: &Path, key: &[u8]) -> Result<Connection, Error> {
    let _pass = Pass::new();
    if key.len() != 32 {
        return Err(Error::Storage("database key has the wrong length".into()));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // SQLite marks itself initialized before SQLCipher's own initializer has run, so
    // two first opens at once can key a database before SQLCipher is ready, and
    // that key fails. Finish initializing once, before any connection opens.
    static INIT: std::sync::Once = std::sync::Once::new();
    // SAFETY: sqlite3_initialize takes no arguments and is safe to call at any time.
    INIT.call_once(|| unsafe {
        rusqlite::ffi::sqlite3_initialize();
    });
    let connection = Connection::open(path)?;
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{hex}'\";"));
    drop(Zeroizing::new(hex));
    connection.execute_batch(&pragma)?;
    // Reading the schema fails if the key is wrong.
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|_| Error::Crypto)?;
    wait_at_exit();
    connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(connection)
}

/// SQLCipher frees its state when the process exits, so a thread still using a
/// store then crashes it. Each use of a store holds a pass: [`in_use`] for a
/// store behind its lock, [`Pass::new`] while a store is opened, or used before
/// its lock exists. At exit, a handler waits up to five seconds for the passes
/// held; afterwards other threads wait for the process to end instead of
/// starting a use, and a store dropped then is left open rather than closed.
pub(crate) struct Pass(());

struct Passes {
    held: usize,
    /// The thread running exit, once it has begun, as [`this_thread`] names it.
    exiting: Option<usize>,
}

/// This thread, as the operating system names it. Exit can't use
/// `std::thread::current`: on macOS a thread's Rust data is gone by the time its
/// exit handlers run, and the panic would abort the process.
fn this_thread() -> usize {
    // SAFETY: pthread_self has no preconditions and never fails.
    unsafe { libc::pthread_self() as usize }
}

static PASSES: (Mutex<Passes>, Condvar) = (
    Mutex::new(Passes {
        held: 0,
        exiting: None,
    }),
    Condvar::new(),
);

impl Pass {
    pub(crate) fn new() -> Pass {
        let (passes, changed) = &PASSES;
        let mut passes = passes.lock().unwrap_or_else(|e| e.into_inner());
        let this = this_thread();
        while passes.exiting.is_some_and(|exiting| exiting != this) {
            passes = changed.wait(passes).unwrap_or_else(|e| e.into_inner());
        }
        passes.held += 1;
        Pass(())
    }

    /// A pass, unless exit has begun; never waits.
    fn unless_exiting() -> Option<Pass> {
        let mut passes = PASSES.0.lock().unwrap_or_else(|e| e.into_inner());
        if passes.exiting.is_some() {
            return None;
        }
        passes.held += 1;
        Some(Pass(()))
    }
}

impl Drop for Pass {
    fn drop(&mut self) {
        let (passes, changed) = &PASSES;
        passes.lock().unwrap_or_else(|e| e.into_inner()).held -= 1;
        changed.notify_all();
    }
}

extern "C" fn wait_for_passes() {
    let (passes, changed) = &PASSES;
    let mut passes = passes.lock().unwrap_or_else(|e| e.into_inner());
    passes.exiting = Some(this_thread());
    let _ = changed.wait_timeout_while(passes, Duration::from_secs(5), |p| p.held > 0);
}

/// Begins exit as the handler does, without exiting.
#[cfg(test)]
pub(crate) fn test_begin_exit() {
    wait_for_passes();
}

/// Closes a store's connection, or leaves it open once exit has begun.
fn close(connection: &mut ManuallyDrop<Connection>) {
    if let Some(_pass) = Pass::unless_exiting() {
        // SAFETY: each store calls this once, from its `drop`.
        unsafe { ManuallyDrop::drop(connection) }
    }
}

/// Registers the exit handler once. Exit handlers run in reverse order, so it's
/// registered after the first store is keyed, when SQLCipher and OpenSSL have
/// registered theirs.
fn wait_at_exit() {
    unsafe extern "C" {
        fn atexit(handler: extern "C" fn()) -> std::ffi::c_int;
    }
    static REGISTER: Once = Once::new();
    // SAFETY: the handler is a plain function that lives for the whole process.
    REGISTER.call_once(|| unsafe {
        atexit(wait_for_passes);
    });
}

/// A store behind its lock, with a pass for as long as it's held.
pub(crate) struct InUse<'a, T> {
    store: MutexGuard<'a, T>,
    _pass: Pass,
}

/// Locks a store, then takes a pass, so no use starts once exit has begun.
pub(crate) fn in_use<T>(store: &Mutex<T>) -> InUse<'_, T> {
    let store = store.lock().unwrap_or_else(|e| e.into_inner());
    InUse {
        store,
        _pass: Pass::new(),
    }
}

impl<T> std::ops::Deref for InUse<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.store
    }
}

impl<T> std::ops::DerefMut for InUse<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.store
    }
}

/// Runs each migration after the database's `user_version`. A database from a
/// newer version is left untouched.
fn migrate(connection: &mut Connection, migrations: &[&str]) -> Result<(), Error> {
    let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    let version =
        usize::try_from(version).map_err(|_| Error::Storage("bad user_version".into()))?;
    if version > migrations.len() {
        return Err(Error::NeedsUpdate);
    }
    for (index, sql) in migrations.iter().enumerate().skip(version) {
        let tx = connection.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute_batch(&format!("PRAGMA user_version = {}", index + 1))?;
        tx.commit()?;
    }
    Ok(())
}

const ACCOUNT_MIGRATIONS: &[&str] = &[
    "
    CREATE TABLE account (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL,
        server TEXT NOT NULL,
        kind TEXT NOT NULL,
        device_id TEXT NOT NULL
    );
    CREATE TABLE account_data (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        version INTEGER NOT NULL,
        json TEXT NOT NULL
    );
",
    "CREATE TABLE approvals_answered (commitment BLOB PRIMARY KEY, at INTEGER NOT NULL);",
    // Version 2 already stores answered approvals on main; add bases in version 3.
    "
    CREATE TABLE bases (
        base_id TEXT PRIMARY KEY,
        epoch INTEGER NOT NULL,
        wrapper BLOB NOT NULL,
        mode TEXT NOT NULL,
        added_at INTEGER NOT NULL
    );
",
    "CREATE TABLE hidden_bases (
        base_id TEXT PRIMARY KEY,
        epoch INTEGER NOT NULL,
        wrapper BLOB NOT NULL
    );",
    "CREATE TABLE credential_envelope (id INTEGER PRIMARY KEY CHECK (id = 1), hash TEXT NOT NULL);",
    // Whether the cached account data was sealed with its version.
    "ALTER TABLE account_data ADD COLUMN versioned INTEGER NOT NULL DEFAULT 0;",
    "
    CREATE TABLE backup_credentials (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        envelope BLOB NOT NULL,
        salt BLOB NOT NULL,
        checked INTEGER NOT NULL
    );
    CREATE TABLE backup (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        location TEXT,
        enabled INTEGER NOT NULL,
        acknowledged INTEGER NOT NULL,
        generation INTEGER NOT NULL,
        last_run TEXT,
        keys_hash TEXT,
        keys_name TEXT,
        bytes INTEGER NOT NULL,
        merged_day TEXT,
        problem TEXT
    );
    ",
    "CREATE TABLE public_pins (device_id TEXT PRIMARY KEY, public BLOB NOT NULL);",
    "ALTER TABLE bases ADD COLUMN chain TEXT NOT NULL DEFAULT '[]';
     ALTER TABLE bases ADD COLUMN account_epoch INTEGER NOT NULL DEFAULT 1;
     ALTER TABLE bases ADD COLUMN data_floor INTEGER NOT NULL DEFAULT 0;",
    // NULL means the pre-rotation wrapper and epoch are also the store wrapper.
    "ALTER TABLE hidden_bases ADD COLUMN store_wrapper BLOB;
     ALTER TABLE hidden_bases ADD COLUMN store_epoch INTEGER;
     ALTER TABLE hidden_bases ADD COLUMN chain TEXT NOT NULL DEFAULT '[]';
     ALTER TABLE hidden_bases ADD COLUMN account_epoch INTEGER NOT NULL DEFAULT 1;",
];

/// A base this device may open: its key as the server's wrapper, which only
/// this account's (or app's) key opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BaseRow {
    pub id: BaseId,
    pub epoch: u32,
    pub wrapper: Vec<u8>,
    pub mode: Mode,
    pub chain: Vec<(u32, Vec<u8>)>,
    pub account_epoch: u32,
    pub data_floor: u64,
}

#[derive(Clone)]
pub(crate) struct HiddenRow {
    pub id: BaseId,
    pub epoch: u32,
    pub wrapper: Vec<u8>,
    pub store_epoch: u32,
    pub store_wrapper: Vec<u8>,
    pub chain: Vec<(u32, Vec<u8>)>,
}

/// Saved destination and progress for this device.
#[derive(Clone, Default)]
pub(crate) struct BackupRow {
    pub location: Option<crate::BackupLocation>,
    pub enabled: bool,
    pub acknowledged: bool,
    pub generation: i64,
    pub last_run: Option<String>,
    pub keys_hash: Option<String>,
    pub keys_name: Option<String>,
    pub bytes: u64,
    pub merged_day: Option<String>,
    pub problem: Option<String>,
}

pub(crate) type BackupWrappers = (Vec<BaseRow>, Vec<HiddenRow>);

type BackupRowColumns = (
    Option<String>,
    bool,
    bool,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    Option<String>,
    Option<String>,
);

type DirtyObject = (ObjectId, i64, Vec<u8>, Option<Vec<u8>>);

pub(crate) struct AccountRow {
    pub id: AccountId,
    pub email: String,
    pub server: url::Url,
    pub kind: DeviceKind,
    pub device_id: DeviceId,
}

/// The account database. Use it through `Account::db`, or hold a [`Pass`].
pub(crate) struct AccountDb(ManuallyDrop<Connection>);

impl Drop for AccountDb {
    fn drop(&mut self) {
        close(&mut self.0);
    }
}

impl AccountDb {
    pub(crate) fn open(path: &Path, key: &[u8]) -> Result<Self, Error> {
        let _pass = Pass::new();
        let mut connection = open_encrypted(path, key)?;
        migrate(&mut connection, ACCOUNT_MIGRATIONS)?;
        Ok(Self(ManuallyDrop::new(connection)))
    }

    pub(crate) fn set_account(&self, row: &AccountRow) -> Result<(), Error> {
        self.0.execute(
            "INSERT OR REPLACE INTO account (id, email, server, kind, device_id) VALUES (?, ?, ?, ?, ?)",
            params![
                row.id.to_string(),
                row.email,
                row.server.as_str(),
                row.kind.as_str(),
                row.device_id.to_string()
            ],
        )?;
        Ok(())
    }

    pub(crate) fn account(&self) -> Result<AccountRow, Error> {
        let corrupt = |_| Error::Storage("unreadable account row".into());
        let (id, email, server, kind, device_id): (String, String, String, String, String) =
            self.0.query_row(
                "SELECT id, email, server, kind, device_id FROM account",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )?;
        Ok(AccountRow {
            id: id.parse().map_err(corrupt)?,
            email,
            server: server
                .parse()
                .map_err(|_| Error::Storage("unreadable server".into()))?,
            kind: DeviceKind::parse(&kind)?,
            device_id: device_id.parse().map_err(corrupt)?,
        })
    }

    /// The public key first seen for this device, if any.
    pub(crate) fn public_pin(&self, device: DeviceId) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .0
            .query_row(
                "SELECT public FROM public_pins WHERE device_id = ?",
                [device.to_string()],
                |row| row.get(0),
            )
            .optional()?)
    }

    /// Remembers the first public key seen for a device across restarts.
    pub(crate) fn pin_public(&self, device: DeviceId, public: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.execute(
            "INSERT OR IGNORE INTO public_pins (device_id, public) VALUES (?, ?)",
            params![device.to_string(), public],
        )?;
        Ok(self.0.query_row(
            "SELECT public FROM public_pins WHERE device_id = ?",
            [device.to_string()],
            |row| row.get(0),
        )?)
    }

    /// The cached account data and its server version.
    #[allow(
        dead_code,
        reason = "read offline by Account::app_readers, which app devices use"
    )]
    pub(crate) fn account_data(&self) -> Result<Option<(u64, Zeroizing<String>)>, Error> {
        Ok(self
            .0
            .query_row(
                "SELECT version, json FROM account_data WHERE id = 1",
                [],
                |r| Ok((r.get::<_, i64>(0)? as u64, Zeroizing::new(r.get(1)?))),
            )
            .optional()?)
    }

    /// The cached account data with its version, and whether it was sealed with it.
    pub(crate) fn account_data_versioned(
        &self,
    ) -> Result<Option<(u64, Zeroizing<String>, bool)>, Error> {
        Ok(self
            .0
            .query_row(
                "SELECT version, json, versioned FROM account_data WHERE id = 1",
                [],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)? as u64,
                        Zeroizing::new(r.get(1)?),
                        r.get(2)?,
                    ))
                },
            )
            .optional()?)
    }

    /// The cached account data's version, and whether it was sealed with it.
    pub(crate) fn account_data_seen(&self) -> Result<Option<(u64, bool)>, Error> {
        Ok(self
            .0
            .query_row(
                "SELECT version, versioned FROM account_data WHERE id = 1",
                [],
                |r| Ok((r.get::<_, i64>(0)? as u64, r.get(1)?)),
            )
            .optional()?)
    }

    pub(crate) fn backup_credentials(&self) -> Result<Option<crate::account::Credentials>, Error> {
        let row: Option<(Vec<u8>, Vec<u8>, bool)> = self
            .0
            .query_row(
                "SELECT envelope, salt, checked FROM backup_credentials WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        row.map(|(envelope, salt, checked)| {
            let salt = salt
                .try_into()
                .map_err(|_| Error::Storage("unreadable backup salt".into()))?;
            Ok(crate::account::Credentials {
                envelope,
                salt,
                checked,
            })
        })
        .transpose()
    }

    pub(crate) fn set_backup_credentials(
        &self,
        credentials: &crate::account::Credentials,
    ) -> Result<(), Error> {
        self.0.execute(
            "INSERT INTO backup_credentials (id, envelope, salt, checked) VALUES (1, ?, ?, ?)
             ON CONFLICT (id) DO UPDATE SET envelope = excluded.envelope,
                salt = excluded.salt, checked = excluded.checked
             WHERE backup_credentials.checked = 0 OR excluded.checked = 1",
            params![
                &credentials.envelope,
                credentials.salt.as_slice(),
                credentials.checked
            ],
        )?;
        Ok(())
    }

    /// Forgets sign-in details this device never checked.
    pub(crate) fn clear_unchecked_backup_credentials(&self) -> Result<(), Error> {
        self.0.execute(
            "DELETE FROM backup_credentials WHERE id = 1 AND checked = 0",
            [],
        )?;
        Ok(())
    }

    pub(crate) fn backup_row(&self) -> Result<BackupRow, Error> {
        let row: Option<BackupRowColumns> = self.0.query_row(
            "SELECT location, enabled, acknowledged, generation, last_run, keys_hash, keys_name, bytes, merged_day, problem FROM backup WHERE id = 1",
            [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?, r.get(8)?, r.get(9)?)),
        ).optional()?;
        row.map(
            |(
                location,
                enabled,
                acknowledged,
                generation,
                last_run,
                keys_hash,
                keys_name,
                bytes,
                merged_day,
                problem,
            )| {
                Ok(BackupRow {
                    location: location
                        .map(|json| {
                            serde_json::from_str(&json).map_err(|_| corrupt("backup location"))
                        })
                        .transpose()?,
                    enabled,
                    acknowledged,
                    generation,
                    last_run,
                    keys_hash,
                    keys_name,
                    bytes: bytes.try_into().map_err(|_| corrupt("backup bytes"))?,
                    merged_day,
                    problem,
                })
            },
        )
        .transpose()
        .map(|row| row.unwrap_or_default())
    }

    pub(crate) fn set_backup_row(&self, row: &BackupRow) -> Result<(), Error> {
        self.0.execute(
            "INSERT OR REPLACE INTO backup (id, location, enabled, acknowledged, generation, last_run, keys_hash, keys_name, bytes, merged_day, problem) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![row.location.as_ref().map(serde_json::to_string).transpose().map_err(|_| corrupt("backup location"))?, row.enabled, row.acknowledged, row.generation,
                row.last_run, row.keys_hash, row.keys_name, row.bytes.min(i64::MAX as u64) as i64, row.merged_day, row.problem],
        )?;
        Ok(())
    }

    pub(crate) fn update_backup_progress(
        &self,
        row: &BackupRow,
        expected_generation: i64,
        expected_location: &crate::BackupLocation,
    ) -> Result<bool, Error> {
        let transaction = self.0.unchecked_transaction()?;
        let current = self.backup_row()?;
        let same = current.enabled
            && current.generation == expected_generation
            && current
                .location
                .as_ref()
                .is_some_and(|location| location.same_destination(expected_location));
        if !same {
            return Ok(false);
        }
        let updated = transaction.execute(
            "UPDATE backup SET generation = ?, last_run = ?, keys_hash = ?, keys_name = ?, bytes = ?, merged_day = ?, problem = ? WHERE id = 1",
            params![row.generation, row.last_run, row.keys_hash, row.keys_name,
                row.bytes.min(i64::MAX as u64) as i64, row.merged_day, row.problem],
        )? != 0;
        transaction.commit()?;
        Ok(updated)
    }

    /// The last fetched credential envelope's SHA-256, independent of account-data version.
    pub(crate) fn envelope_hash(&self) -> Result<Option<String>, Error> {
        Ok(self
            .0
            .query_row(
                "SELECT hash FROM credential_envelope WHERE id = 1",
                [],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub(crate) fn set_envelope_hash(&self, hash: &str) -> Result<(), Error> {
        self.0.execute(
            "INSERT INTO credential_envelope (id, hash) VALUES (1, ?)
             ON CONFLICT (id) DO UPDATE SET hash = excluded.hash",
            [hash],
        )?;
        Ok(())
    }

    /// Records a commitment before any response is sent; duplicates remain forever.
    pub(crate) fn claim_approval(&self, commitment: &[u8; 32], at: u64) -> Result<bool, Error> {
        Ok(self.0.execute(
            "INSERT OR IGNORE INTO approvals_answered (commitment, at) VALUES (?, ?)",
            params![commitment.as_slice(), at.min(i64::MAX as u64) as i64],
        )? == 1)
    }

    /// Caches account data this device has opened, unless it's older than the
    /// cached version, or in the older format once a versioned one was cached.
    /// Versioned data replaces older-format data of the same version. Returns
    /// whether it was accepted.
    pub(crate) fn accept_account_data(
        &mut self,
        version: u64,
        json: &str,
        versioned: bool,
    ) -> Result<bool, Error> {
        let version = i64::try_from(version).map_err(|_| Error::Crypto)?;
        let tx = self.0.transaction()?;
        let seen: Option<(i64, bool)> = tx
            .query_row(
                "SELECT version, versioned FROM account_data WHERE id = 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let replace = match seen {
            Some((seen, latched)) if version < seen || (latched && !versioned) => {
                return Ok(false);
            }
            Some((seen, latched)) => version > seen || (versioned && !latched),
            None => true,
        };
        if replace {
            tx.execute(
                "INSERT OR REPLACE INTO account_data (id, version, json, versioned)
                 VALUES (1, ?, ?, ?)",
                params![version, json, versioned],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    /// Adds a base or updates its key and mode.
    pub(crate) fn put_base(&self, row: &BaseRow, added_at: i64) -> Result<(), Error> {
        self.0.execute(
            "INSERT INTO bases (base_id, epoch, wrapper, mode, added_at, chain, account_epoch, data_floor)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (base_id) DO UPDATE SET epoch = excluded.epoch,
                 wrapper = excluded.wrapper, mode = excluded.mode, chain = excluded.chain,
                 account_epoch = excluded.account_epoch, data_floor = excluded.data_floor",
            params![
                row.id.to_string(),
                row.epoch,
                row.wrapper,
                mode_text(row.mode),
                added_at,
                serde_json::to_string(&row.chain).map_err(|_| corrupt("base chain"))?,
                row.account_epoch,
                i64::try_from(row.data_floor).map_err(|_| corrupt("base data floor"))?
            ],
        )?;
        Ok(())
    }

    /// Forgets a base this device may no longer open.
    pub(crate) fn forget_base(&self, id: BaseId) -> Result<(), Error> {
        self.0
            .execute("DELETE FROM bases WHERE base_id = ?", [id.to_string()])?;
        Ok(())
    }

    /// Remembers an unopened account wrapper without storing a base name or key.
    pub(crate) fn remember_hidden(
        &self,
        base: BaseId,
        epoch: u32,
        wrapper: &[u8],
        chain: &[(u32, Vec<u8>)],
        account_epoch: u32,
    ) -> Result<(), Error> {
        let chain = serde_json::to_string(chain).map_err(|_| Error::Crypto)?;
        self.0.execute(
            "INSERT INTO hidden_bases (base_id, epoch, wrapper, store_wrapper, store_epoch, chain, account_epoch)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (base_id) DO UPDATE SET
                store_wrapper = COALESCE(hidden_bases.store_wrapper, hidden_bases.wrapper),
                store_epoch = COALESCE(hidden_bases.store_epoch, hidden_bases.epoch),
                epoch = excluded.epoch, wrapper = excluded.wrapper,
                chain = excluded.chain, account_epoch = excluded.account_epoch",
            params![base.to_string(), epoch, wrapper, wrapper, epoch, chain, account_epoch],
        )?;
        Ok(())
    }

    /// The first wrapper stays beside the current one to open this device's store.
    pub(crate) fn hidden_wrappers(&self) -> Result<Vec<HiddenRow>, Error> {
        let mut statement = self.0.prepare(
            "SELECT base_id, epoch, wrapper, COALESCE(store_epoch, epoch),
                    COALESCE(store_wrapper, wrapper), chain
             FROM hidden_bases ORDER BY base_id",
        )?;
        let rows = statement.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, u32>(3)?,
                r.get::<_, Vec<u8>>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        rows.map(|row| {
            let (id, epoch, wrapper, store_epoch, store_wrapper, chain) = row?;
            Ok(HiddenRow {
                id: parse_id(&id)?,
                epoch,
                wrapper,
                store_epoch,
                store_wrapper,
                chain: serde_json::from_str(&chain).map_err(|_| corrupt("hidden chain"))?,
            })
        })
        .collect()
    }

    pub(crate) fn bases(&self) -> Result<Vec<BaseRow>, Error> {
        let mut statement = self.0.prepare(
            "SELECT base_id, epoch, wrapper, mode, chain, account_epoch, data_floor FROM bases ORDER BY added_at, base_id",
        )?;
        let rows = statement.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, Vec<u8>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, u32>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })?;
        rows.map(|row| {
            let (id, epoch, wrapper, mode, chain, account_epoch, data_floor) = row?;
            Ok(BaseRow {
                id: parse_id(&id)?,
                epoch,
                wrapper,
                chain: serde_json::from_str(&chain).map_err(|_| corrupt("base chain"))?,
                account_epoch,
                data_floor: u64::try_from(data_floor).map_err(|_| corrupt("base data floor"))?,
                mode: match mode.as_str() {
                    "rw" => Mode::ReadWrite,
                    "ro" => Mode::ReadOnly,
                    _ => return Err(corrupt("base mode")),
                },
            })
        })
        .collect()
    }
}

fn mode_text(mode: Mode) -> &'static str {
    match mode {
        Mode::ReadWrite => "rw",
        Mode::ReadOnly => "ro",
    }
}

const BASE_MIGRATIONS: &[&str] = &[
    r#"
    CREATE TABLE objects (
        object_id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        type_version INTEGER NOT NULL,
        parent TEXT,
        position TEXT NOT NULL,
        deleted INTEGER NOT NULL,
        title TEXT NOT NULL,
        fields TEXT NOT NULL,
        state BLOB NOT NULL,
        confirmed_seq INTEGER NOT NULL DEFAULT 0,
        updated_at INTEGER NOT NULL,
        updated_by TEXT
    );
    CREATE INDEX objects_by_parent ON objects (parent, position, object_id);
    CREATE TABLE outbox (
        id INTEGER PRIMARY KEY,
        object_id TEXT NOT NULL,
        "update" BLOB NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE INDEX outbox_by_object ON outbox (object_id, id);
    CREATE TABLE sending (
        change_id TEXT PRIMARY KEY,
        object_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        body BLOB NOT NULL,
        covers INTEGER,
        outbox_max_id INTEGER NOT NULL
    );
    CREATE TABLE set_aside (
        id INTEGER PRIMARY KEY,
        object_id TEXT NOT NULL,
        seq INTEGER,
        body BLOB NOT NULL,
        error TEXT NOT NULL,
        at INTEGER NOT NULL
    );
    CREATE TABLE sync (
        key TEXT PRIMARY KEY,
        value
    );
"#,
    // Queries by type. `objects_by_parent` already serves lookups by parent.
    "CREATE INDEX objects_by_type ON objects (type);",
    "DELETE FROM set_aside WHERE seq IS NOT NULL AND id NOT IN
        (SELECT min(id) FROM set_aside WHERE seq IS NOT NULL GROUP BY object_id, seq);
     CREATE UNIQUE INDEX set_aside_unique ON set_aside (object_id, seq) WHERE seq IS NOT NULL;",
    // Main's version 4 holds raw future changes; early search stores used
    // version 4 for FTS. Both layouts migrate to version 5.
    "CREATE TABLE IF NOT EXISTS future_changes (
        object_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        state INTEGER NOT NULL,
        device_id TEXT NOT NULL,
        body BLOB NOT NULL,
        PRIMARY KEY (object_id, seq)
    );",
    "CREATE TABLE IF NOT EXISTS future_changes (
        object_id TEXT NOT NULL,
        seq INTEGER NOT NULL,
        state INTEGER NOT NULL,
        device_id TEXT NOT NULL,
        body BLOB NOT NULL,
        PRIMARY KEY (object_id, seq)
    );
     DELETE FROM set_aside WHERE seq IS NOT NULL AND id NOT IN
         (SELECT min(id) FROM set_aside WHERE seq IS NOT NULL GROUP BY object_id, seq);
     CREATE UNIQUE INDEX IF NOT EXISTS set_aside_unique ON set_aside (object_id, seq) WHERE seq IS NOT NULL;
     CREATE VIRTUAL TABLE IF NOT EXISTS object_search USING fts5(object_id UNINDEXED, title, body);",
    "CREATE TABLE IF NOT EXISTS files (object_id TEXT PRIMARY KEY, parts INTEGER NOT NULL, have INTEGER NOT NULL, sent INTEGER, broken TEXT);
     CREATE TABLE IF NOT EXISTS edits (object_id TEXT PRIMARY KEY, last_edit_at INTEGER NOT NULL, last_version_at INTEGER);",
    "CREATE TABLE IF NOT EXISTS backup_dirty (object_id TEXT PRIMARY KEY, seq INTEGER NOT NULL);
     CREATE TABLE IF NOT EXISTS backup_objects (object_id TEXT PRIMARY KEY, generation INTEGER NOT NULL, sv BLOB NOT NULL);
     CREATE TABLE IF NOT EXISTS backup_parts (object_id TEXT PRIMARY KEY, generation INTEGER NOT NULL, copied INTEGER NOT NULL);
     CREATE TABLE IF NOT EXISTS backup_base (id INTEGER PRIMARY KEY CHECK (id = 1), generation INTEGER NOT NULL,
         snapshot_run TEXT, snapshot_bytes INTEGER NOT NULL, log_bytes INTEGER NOT NULL);
     INSERT OR IGNORE INTO backup_dirty (object_id, seq) SELECT object_id, row_number() OVER (ORDER BY object_id) FROM objects;
     CREATE TRIGGER IF NOT EXISTS backup_object_insert AFTER INSERT ON objects BEGIN
         INSERT INTO backup_dirty VALUES (NEW.object_id, (SELECT coalesce(max(seq), 0) + 1 FROM backup_dirty))
         ON CONFLICT (object_id) DO UPDATE SET seq = excluded.seq;
     END;
     CREATE TRIGGER IF NOT EXISTS backup_object_update AFTER UPDATE OF state ON objects BEGIN
         INSERT INTO backup_dirty VALUES (NEW.object_id, (SELECT coalesce(max(seq), 0) + 1 FROM backup_dirty))
         ON CONFLICT (object_id) DO UPDATE SET seq = excluded.seq;
     END;",
    // The dirty triggers query max(seq) for each inserted or edited object.
    // Without this index, a large bulk insert repeatedly scans the entire table.
    "CREATE INDEX IF NOT EXISTS backup_dirty_by_seq ON backup_dirty (seq);",
    // A pre-rotation snapshot has no recorded epoch; write one fresh snapshot once.
    "ALTER TABLE backup_base ADD COLUMN snapshot_epoch INTEGER;",
];

/// Local progress for one sealed file.
#[derive(Clone, Debug)]
pub(crate) struct FileRow {
    pub id: ObjectId,
    pub parts: u32,
    pub have: u32,
    pub sent: Option<u32>,
    pub broken: Option<String>,
}

/// Types that never show in the folder tree or the trash.
const HIDDEN: &str = "type NOT IN ('core.type', 'core.base')";

pub(crate) const SUMMARY: &str = "object_id, type, type_version, parent, position, deleted, title, fields, updated_at, updated_by";

/// A change recorded before it's sent. It covers its object's outbox rows up
/// to `outbox_max_id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SendingRow {
    pub change_id: ChangeId,
    pub object_id: ObjectId,
    /// A `state` change rather than an `update`.
    pub state: bool,
    pub keep: bool,
    pub body: Vec<u8>,
    pub covers: Option<u64>,
    pub outbox_max_id: i64,
}

/// An object's stored state and the columns derived from it. A deleted copy
/// left behind by a move is stored with `deleted = 2`, so the tree, the trash,
/// search and queries leave it out.
pub(crate) struct ObjectRow {
    pub summary: ObjectSummary,
    pub state: Vec<u8>,
    pub moved: bool,
}

fn corrupt(what: &str) -> Error {
    Error::Storage(format!("unreadable {what}"))
}

fn parse_id<T: std::str::FromStr>(text: &str) -> Result<T, Error> {
    text.parse().map_err(|_| corrupt("object ID"))
}

fn summary(row: &Row) -> rusqlite::Result<Result<ObjectSummary, Error>> {
    let (id, parent, fields, updated_by): (String, Option<String>, String, Option<String>) =
        (row.get(0)?, row.get(3)?, row.get(7)?, row.get(9)?);
    let ty = TypeRef::new(row.get::<_, String>(1)?, row.get(2)?);
    let (position, deleted, title, updated_at) =
        (row.get(4)?, row.get(5)?, row.get(6)?, row.get(8)?);
    Ok((|| {
        Ok(ObjectSummary {
            id: parse_id(&id)?,
            ty,
            parent: parent.as_deref().map(parse_id).transpose()?,
            position,
            deleted,
            title,
            fields: serde_json::from_str(&fields).map_err(|_| corrupt("fields"))?,
            updated_at,
            updated_by: updated_by.as_deref().map(parse_id).transpose()?,
        })
    })())
}

fn hex(id: Option<ObjectId>) -> Option<String> {
    id.map(|id| id.to_string())
}

/// A base's store: object state and summaries, the outbox of local updates,
/// changes being sent, changes set aside, and sync state.
/// Use it through `Base::db`, or hold a [`Pass`].
pub(crate) struct BaseDb(ManuallyDrop<Connection>, bool);

impl Drop for BaseDb {
    fn drop(&mut self) {
        close(&mut self.0);
    }
}

impl BaseDb {
    pub(crate) fn open(path: &Path, key: &[u8]) -> Result<Self, Error> {
        let _pass = Pass::new();
        let mut connection = open_encrypted(path, key)?;
        let version: i64 = connection.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        // FTS must be created and populated before its version is committed.
        // Older stores stop at version 4 until the base can decode their objects.
        if version < 5 {
            migrate(&mut connection, &BASE_MIGRATIONS[..4])?;
        } else {
            migrate(&mut connection, BASE_MIGRATIONS)?;
        }
        Ok(Self(ManuallyDrop::new(connection), version < 5))
    }

    pub(crate) fn connection(&self) -> &Connection {
        &self.0
    }

    pub(crate) fn needs_search_backfill(&self) -> bool {
        self.1
    }

    /// Creates and fills FTS in the same transaction as its version bump.
    pub(crate) fn migrate_search(
        &mut self,
        backfill: impl FnOnce(&mut BaseDb) -> Result<(), Error>,
    ) -> Result<(), Error> {
        self.batch(|db| {
            db.0.execute_batch(BASE_MIGRATIONS[4])?;
            backfill(db)?;
            db.0.execute_batch("PRAGMA user_version = 5")?;
            Ok(())
        })?;
        self.1 = false;
        migrate(&mut self.0, BASE_MIGRATIONS)
    }

    pub(crate) fn backup_state(
        &self,
        generation: i64,
    ) -> Result<(Option<String>, u64, u64, Option<u32>), Error> {
        type Cursor = (i64, Option<String>, i64, i64, Option<u32>);
        let row: Option<Cursor> = self.0.query_row(
            "SELECT generation, snapshot_run, snapshot_bytes, log_bytes, snapshot_epoch FROM backup_base WHERE id = 1", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        ).optional()?;
        match row {
            Some((g, run, size, log, epoch)) if g == generation => {
                Ok((run, size.max(0) as u64, log.max(0) as u64, epoch))
            }
            _ => Ok((None, 0, 0, None)),
        }
    }

    pub(crate) fn dirty_since(
        &self,
        generation: i64,
        all: bool,
    ) -> Result<Vec<DirtyObject>, Error> {
        let mut stmt = self.0.prepare(
            "SELECT o.object_id, coalesce(d.seq, 0), o.state, b.sv FROM objects o
             LEFT JOIN backup_dirty d ON d.object_id = o.object_id
             LEFT JOIN backup_objects b ON b.object_id = o.object_id AND b.generation = ?
             WHERE ? OR d.object_id IS NOT NULL OR b.object_id IS NULL ORDER BY o.object_id",
        )?;
        let rows = stmt.query_map(params![generation, all], |r| {
            Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })?;
        rows.map(|row| {
            let (id, seq, state, sv) = row?;
            Ok((parse_id(&id)?, seq, state, sv))
        })
        .collect()
    }

    pub(crate) fn commit_backup(
        &mut self,
        generation: i64,
        entries: &[(ObjectId, i64, Vec<u8>)],
        log_bytes: u64,
    ) -> Result<(), Error> {
        self.batch(|db| {
            for (id, seq, sv) in entries {
                db.0.execute(
                    "INSERT OR REPLACE INTO backup_objects VALUES (?, ?, ?)",
                    params![id.to_string(), generation, sv],
                )?;
                db.0.execute(
                    "DELETE FROM backup_dirty WHERE object_id = ? AND seq = ?",
                    params![id.to_string(), seq],
                )?;
            }
            db.0.execute(
                "UPDATE backup_base SET log_bytes = log_bytes + ? WHERE id = 1 AND generation = ?",
                params![log_bytes.min(i64::MAX as u64) as i64, generation],
            )?;
            Ok(())
        })
    }

    pub(crate) fn set_snapshot(
        &self,
        generation: i64,
        run: &str,
        size: u64,
        epoch: u32,
    ) -> Result<(), Error> {
        self.0.execute(
            "INSERT OR REPLACE INTO backup_base (id, generation, snapshot_run, snapshot_bytes, log_bytes, snapshot_epoch) VALUES (1, ?, ?, ?, 0, ?)",
            params![generation, run, size.min(i64::MAX as u64) as i64, epoch],
        )?;
        Ok(())
    }

    pub(crate) fn backup_estimate(&self) -> Result<(u64, Vec<(ObjectId, u32)>), Error> {
        let states: i64 = self.0.query_row(
            "SELECT coalesce(sum(length(state)), 0) FROM objects",
            [],
            |row| row.get(0),
        )?;
        let mut stmt = self
            .0
            .prepare("SELECT object_id, have FROM files WHERE broken IS NULL")?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, u32>(1)?))
        })?;
        let parts = rows
            .map(|row| {
                let (id, have) = row?;
                Ok((parse_id(&id)?, have))
            })
            .collect::<Result<_, Error>>()?;
        Ok((states.max(0) as u64, parts))
    }

    pub(crate) fn parts_to_copy(
        &self,
        generation: i64,
    ) -> Result<Vec<(ObjectId, u32, u32)>, Error> {
        let mut stmt = self.0.prepare(
            "SELECT f.object_id, f.parts, coalesce(p.copied, 0) FROM files f
             LEFT JOIN backup_parts p ON p.object_id = f.object_id AND p.generation = ?
             WHERE f.have = f.parts AND f.broken IS NULL AND coalesce(p.copied, 0) < f.parts ORDER BY f.object_id",
        )?;
        let rows = stmt.query_map([generation], |r| {
            Ok((r.get::<_, String>(0)?, r.get(1)?, r.get(2)?))
        })?;
        rows.map(|row| {
            let (id, parts, copied) = row?;
            Ok((parse_id(&id)?, parts, copied))
        })
        .collect()
    }

    pub(crate) fn part_copied(
        &self,
        generation: i64,
        id: ObjectId,
        copied: u32,
    ) -> Result<(), Error> {
        self.0.execute(
            "INSERT OR REPLACE INTO backup_parts VALUES (?, ?, ?)",
            params![id.to_string(), generation, copied],
        )?;
        Ok(())
    }

    pub(crate) fn objects_for_backfill(&self) -> Result<Vec<(ObjectId, Vec<u8>)>, Error> {
        let mut stmt = self.0.prepare("SELECT object_id, state FROM objects")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        rows.map(|r| {
            let (id, state) = r?;
            Ok((parse_id(&id)?, state))
        })
        .collect()
    }

    /// Writes an object's search text in the same transaction as its state.
    pub(crate) fn put_search(&self, id: ObjectId, title: &str, body: &str) -> Result<(), Error> {
        // The objects rowid is stable across upserts. FTS indexes rowid but
        // not its UNINDEXED object_id column, so this avoids a full scan on
        // every edit in a large base.
        self.0.execute(
            "DELETE FROM object_search WHERE rowid = (SELECT rowid FROM objects WHERE object_id = ?)",
            [id.to_string()],
        )?;
        self.0.execute(
            "INSERT INTO object_search (rowid, object_id, title, body)
             VALUES ((SELECT rowid FROM objects WHERE object_id = ?), ?, ?, ?)",
            params![id.to_string(), id.to_string(), title, body],
        )?;
        Ok(())
    }

    /// Updates a record's derived title without changing its source state.
    pub(crate) fn put_title(&self, id: ObjectId, title: &str) -> Result<(), Error> {
        self.0.execute(
            "UPDATE objects SET title = ? WHERE object_id = ?",
            params![title, id.to_string()],
        )?;
        Ok(())
    }

    /// Writes an object's state and summary and, for local edits, their
    /// updates to the outbox, in one transaction. `confirmed_seq` is set when
    /// `confirmed` is given and kept otherwise.
    pub(crate) fn put(
        &mut self,
        row: &ObjectRow,
        outbox: &[&[u8]],
        confirmed: Option<u64>,
    ) -> Result<(), Error> {
        let s = &row.summary;
        let fields = serde_json::to_string(&s.fields).expect("JSON map");
        // A savepoint, so it also works inside `batch`.
        let tx = self.0.savepoint()?;
        tx.execute(
            "INSERT INTO objects (object_id, type, type_version, parent, position, deleted, title,
                 fields, state, updated_at, updated_by, confirmed_seq)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, coalesce(?12, 0))
             ON CONFLICT (object_id) DO UPDATE SET type = excluded.type,
                 type_version = excluded.type_version, parent = excluded.parent,
                 position = excluded.position, deleted = excluded.deleted, title = excluded.title,
                 fields = excluded.fields, state = excluded.state, updated_at = excluded.updated_at,
                 updated_by = excluded.updated_by,
                 confirmed_seq = coalesce(?12, confirmed_seq)",
            params![
                s.id.to_string(),
                s.ty.name,
                s.ty.version,
                hex(s.parent),
                s.position,
                match (s.deleted, row.moved) {
                    (false, _) => 0,
                    (true, false) => 1,
                    (true, true) => 2,
                },
                s.title,
                fields,
                row.state,
                s.updated_at,
                s.updated_by.map(|d| d.to_string()),
                confirmed.map(|c| c as i64),
            ],
        )?;
        for update in outbox {
            tx.execute(
                "INSERT INTO outbox (object_id, \"update\", created_at) VALUES (?, ?, ?)",
                params![s.id.to_string(), update, s.updated_at],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Records a local edit, inside the caller's object/outbox transaction.
    pub(crate) fn record_local_edit(&self, id: ObjectId, at: i64) -> Result<(), Error> {
        self.0.execute(
            "INSERT INTO edits (object_id, last_edit_at) VALUES (?, ?)
             ON CONFLICT(object_id) DO UPDATE SET last_edit_at = excluded.last_edit_at",
            params![id.to_string(), at],
        )?;
        Ok(())
    }

    /// Locally edited objects eligible for a kept state at this time.
    pub(crate) fn version_candidates(
        &self,
        now: i64,
        pause: i64,
        gap: i64,
    ) -> Result<Vec<ObjectId>, Error> {
        let mut stmt = self.0.prepare(
            "SELECT e.object_id FROM edits e JOIN objects o USING (object_id)
             WHERE o.type IN ('core.note', 'core.folder', 'core.project') AND o.type_version = 1
               AND e.last_edit_at <= ?1 AND (e.last_version_at IS NULL OR
                 (e.last_edit_at > e.last_version_at AND e.last_version_at <= ?2))",
        )?;
        let rows = stmt.query_map(
            params![now.saturating_sub(pause), now.saturating_sub(gap)],
            |r| r.get::<_, String>(0),
        )?;
        rows.map(|row| parse_id(&row?)).collect()
    }

    /// Records a successfully kept version; the next edit must be later.
    pub(crate) fn version_stored(&self, id: ObjectId, at: i64) -> Result<(), Error> {
        self.0.execute(
            "UPDATE edits SET last_version_at = ? WHERE object_id = ?",
            params![at, id.to_string()],
        )?;
        Ok(())
    }

    /// Runs `work` in one transaction, which commits only if it succeeds.
    pub(crate) fn batch<T>(
        &mut self,
        work: impl FnOnce(&mut BaseDb) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.0.execute_batch("SAVEPOINT bh_batch")?;
        match work(self) {
            Ok(value) => match self.0.execute_batch("RELEASE bh_batch") {
                Ok(()) => Ok(value),
                Err(e) => {
                    let _ = self
                        .0
                        .execute_batch("ROLLBACK TO bh_batch; RELEASE bh_batch");
                    Err(e.into())
                }
            },
            Err(e) => {
                let _ = self
                    .0
                    .execute_batch("ROLLBACK TO bh_batch; RELEASE bh_batch");
                Err(e)
            }
        }
    }

    /// An object's type and stored state.
    pub(crate) fn state(&self, id: ObjectId) -> Result<Option<(TypeRef, Vec<u8>)>, Error> {
        Ok(self
            .0
            .query_row(
                "SELECT type, type_version, state FROM objects WHERE object_id = ?",
                [id.to_string()],
                |r| Ok((TypeRef::new(r.get::<_, String>(0)?, r.get(1)?), r.get(2)?)),
            )
            .optional()?)
    }

    pub(crate) fn type_of(&self, id: ObjectId) -> Result<Option<TypeRef>, Error> {
        Ok(self
            .0
            .query_row(
                "SELECT type, type_version FROM objects WHERE object_id = ?",
                [id.to_string()],
                |r| Ok(TypeRef::new(r.get::<_, String>(0)?, r.get(1)?)),
            )
            .optional()?)
    }

    /// An object's summary, with its own parent.
    pub(crate) fn summary(&self, id: ObjectId) -> Result<Option<ObjectSummary>, Error> {
        self.0
            .query_row(
                &format!("SELECT {SUMMARY} FROM objects WHERE object_id = ?"),
                [id.to_string()],
                summary,
            )
            .optional()?
            .transpose()
    }

    pub(crate) fn summaries(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<Vec<ObjectSummary>, Error> {
        let mut statement = self.0.prepare(sql)?;
        let rows = statement.query_map(params, summary)?;
        rows.map(|r| r?).collect()
    }

    /// Objects whose own parent is `parent`, not deleted, in order.
    pub(crate) fn children(&self, parent: ObjectId) -> Result<Vec<ObjectSummary>, Error> {
        self.summaries(
            &format!(
                "SELECT {SUMMARY} FROM objects WHERE parent = ? AND deleted = 0 AND {HIDDEN}
                 ORDER BY position, object_id"
            ),
            [parent.to_string()],
        )
    }

    /// Objects without a parent here, or whose parent this store doesn't have.
    pub(crate) fn top_level(&self) -> Result<Vec<ObjectSummary>, Error> {
        self.summaries(
            &format!(
                "SELECT {SUMMARY} FROM objects AS o WHERE deleted = 0 AND {HIDDEN}
                 AND (parent IS NULL
                      OR NOT EXISTS (SELECT 1 FROM objects AS p WHERE p.object_id = o.parent))
                 ORDER BY position, object_id"
            ),
            [],
        )
    }

    /// Deleted objects, the most recently changed first.
    pub(crate) fn trash(&self) -> Result<Vec<ObjectSummary>, Error> {
        self.summaries(
            &format!(
                "SELECT {SUMMARY} FROM objects WHERE deleted = 1 AND {HIDDEN}
                 ORDER BY updated_at DESC, object_id"
            ),
            [],
        )
    }

    /// Objects of one type, deleted or not.
    pub(crate) fn of_type(&self, ty: &str) -> Result<Vec<ObjectSummary>, Error> {
        self.summaries(
            &format!("SELECT {SUMMARY} FROM objects WHERE type = ? ORDER BY object_id"),
            [ty],
        )
    }

    /// `Some(parent)` for an object this store has, `None` for one it doesn't.
    pub(crate) fn parent_of(&self, id: ObjectId) -> Result<Option<Option<ObjectId>>, Error> {
        let parent: Option<Option<String>> = self
            .0
            .query_row(
                "SELECT parent FROM objects WHERE object_id = ?",
                [id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        parent
            .map(|p| p.as_deref().map(parse_id).transpose())
            .transpose()
    }

    /// The own parent of every object that has one.
    pub(crate) fn parents(&self) -> Result<HashMap<ObjectId, Option<ObjectId>>, Error> {
        let mut statement = self
            .0
            .prepare("SELECT object_id, parent FROM objects WHERE parent IS NOT NULL")?;
        let rows =
            statement.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        rows.map(|row| {
            let (id, parent) = row?;
            Ok((parse_id(&id)?, Some(parse_id(&parent)?)))
        })
        .collect()
    }

    /// The IDs and positions of `parent`'s children, deleted ones included, in order.
    pub(crate) fn siblings(
        &self,
        parent: Option<ObjectId>,
    ) -> Result<Vec<(ObjectId, String)>, Error> {
        let mut statement = self.0.prepare(&format!(
            "SELECT object_id, position FROM objects WHERE parent IS ? AND {HIDDEN}
             ORDER BY position, object_id"
        ))?;
        let rows = statement.query_map([hex(parent)], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (id, position) = row?;
            Ok((parse_id(&id)?, position))
        })
        .collect()
    }

    /// The highest seq up to which this device has applied every change to
    /// the object, or `None` for an object it doesn't have.
    pub(crate) fn confirmed(&self, id: ObjectId) -> Result<Option<u64>, Error> {
        Ok(self
            .0
            .query_row(
                "SELECT confirmed_seq FROM objects WHERE object_id = ?",
                [id.to_string()],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .map(|c| c as u64))
    }

    /// Whether this object has raw changes requiring a newer core.
    pub(crate) fn needs_update(&self, id: ObjectId) -> Result<bool, Error> {
        Ok(self.0.query_row(
            "SELECT EXISTS(SELECT 1 FROM future_changes WHERE object_id = ?)",
            [id.to_string()],
            |r| r.get(0),
        )?)
    }

    /// Whether any object in this base needs a newer core.
    pub(crate) fn has_future(&self) -> Result<bool, Error> {
        Ok(self
            .0
            .query_row("SELECT EXISTS(SELECT 1 FROM future_changes)", [], |r| {
                r.get(0)
            })?)
    }

    /// Preserve the exact incoming envelope without decoding, merging or rewriting it.
    pub(crate) fn keep_future(
        &self,
        id: ObjectId,
        seq: u64,
        state: bool,
        device: DeviceId,
        body: &[u8],
    ) -> Result<(), Error> {
        self.0.execute(
            "INSERT OR IGNORE INTO future_changes (object_id, seq, state, device_id, body)
             VALUES (?, ?, ?, ?, ?)",
            params![id.to_string(), seq as i64, state, device.to_string(), body],
        )?;
        Ok(())
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn future_bodies(&self, id: ObjectId) -> Result<Vec<Vec<u8>>, Error> {
        let mut statement = self
            .0
            .prepare("SELECT body FROM future_changes WHERE object_id = ? ORDER BY seq")?;
        statement
            .query_map([id.to_string()], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub(crate) fn set_confirmed(&self, id: ObjectId, seq: u64) -> Result<(), Error> {
        self.0.execute(
            "UPDATE objects SET confirmed_seq = ? WHERE object_id = ?",
            params![seq as i64, id.to_string()],
        )?;
        Ok(())
    }

    /// Test-only: one Yjs update per simulated edit session, in the caller's
    /// transaction. Unlike `put`, does not rewrite the final object state.
    #[cfg(feature = "test-support")]
    pub(crate) fn test_append_outbox(&self, updates: &[(ObjectId, Vec<u8>)]) -> Result<(), Error> {
        let mut statement = self.0.prepare_cached(
            "INSERT INTO outbox (object_id, \"update\", created_at) VALUES (?, ?, ?)",
        )?;
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as i64);
        for (id, update) in updates {
            statement.execute(params![id.to_string(), update, at])?;
        }
        Ok(())
    }

    /// Test-only: unmerged outbox rows, oldest first, bounded like a real
    /// request. The normal sync path deliberately merges an object's edits.
    #[cfg(feature = "test-support")]
    pub(crate) fn test_outbox_batch(
        &self,
        end: i64,
        limit: usize,
        max_bytes: usize,
    ) -> Result<Vec<(i64, ObjectId, Vec<u8>)>, Error> {
        let mut statement = self.0.prepare(
            "SELECT id, object_id, \"update\" FROM outbox WHERE id <= ? ORDER BY id LIMIT ?",
        )?;
        let mut rows = statement.query(params![end, limit as i64])?;
        let (mut out, mut bytes) = (Vec::new(), 0);
        while let Some(row) = rows.next()? {
            let update: Vec<u8> = row.get(2)?;
            if !out.is_empty() && bytes + update.len() + 64 > max_bytes {
                break;
            }
            bytes += update.len() + 64;
            out.push((row.get(0)?, parse_id(&row.get::<_, String>(1)?)?, update));
        }
        Ok(out)
    }

    /// The newest outbox row's ID, or 0.
    pub(crate) fn outbox_end(&self) -> Result<i64, Error> {
        Ok(self
            .0
            .query_row("SELECT coalesce(max(id), 0) FROM outbox", [], |r| r.get(0))?)
    }

    /// The objects with outbox rows up to `end`, the one waiting longest first.
    pub(crate) fn outbox_objects(&self, end: i64) -> Result<Vec<ObjectId>, Error> {
        let mut statement = self.0.prepare(
            "SELECT object_id FROM outbox WHERE id <= ? GROUP BY object_id ORDER BY min(id)",
        )?;
        let rows = statement.query_map([end], |r| r.get::<_, String>(0))?;
        rows.map(|row| parse_id(&row?)).collect()
    }

    /// An object's outbox rows up to `end`, oldest first, as long as their
    /// updates total at most `budget` bytes, and always at least one.
    pub(crate) fn outbox_rows(
        &self,
        id: ObjectId,
        end: i64,
        budget: usize,
    ) -> Result<Vec<(i64, Vec<u8>)>, Error> {
        let mut statement = self.0.prepare(
            "SELECT id, \"update\" FROM outbox WHERE object_id = ? AND id <= ? ORDER BY id",
        )?;
        let mut rows = statement.query(params![id.to_string(), end])?;
        let (mut out, mut total) = (Vec::new(), 0);
        while let Some(row) = rows.next()? {
            let update: Vec<u8> = row.get(1)?;
            total += update.len();
            if total > budget && !out.is_empty() {
                break;
            }
            out.push((row.get(0)?, update));
        }
        Ok(out)
    }

    /// The changes being sent, in the order they were made.
    pub(crate) fn sending(&self) -> Result<Vec<SendingRow>, Error> {
        let mut statement = self.0.prepare(
            "SELECT change_id, object_id, kind, body, covers, outbox_max_id FROM sending ORDER BY rowid",
        )?;
        let rows = statement.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, Vec<u8>>(3)?,
                r.get::<_, Option<i64>>(4)?,
                r.get::<_, i64>(5)?,
            ))
        })?;
        rows.map(|row| {
            let (change_id, object_id, kind, body, covers, outbox_max_id) = row?;
            Ok(SendingRow {
                change_id: parse_id(&change_id)?,
                object_id: parse_id(&object_id)?,
                state: match kind.as_str() {
                    "update" => false,
                    "state" | "kept_state" => true,
                    _ => return Err(corrupt("change kind")),
                },
                keep: kind == "kept_state",
                body,
                covers: covers.map(|c| c as u64),
                outbox_max_id,
            })
        })
        .collect()
    }

    /// Re-seals refused changes without replacing their IDs or outbox positions.
    pub(crate) fn reseal_sending(
        &mut self,
        mut reseal: impl FnMut(ObjectId, bool, &[u8]) -> Result<Option<Vec<u8>>, Error>,
    ) -> Result<bool, Error> {
        let rows = self.sending()?;
        let updates: Vec<_> = rows
            .iter()
            .map(|row| {
                Ok(reseal(row.object_id, row.state, &row.body)?.map(|body| (row.change_id, body)))
            })
            .collect::<Result<Vec<_>, Error>>()?
            .into_iter()
            .flatten()
            .collect();
        if updates.is_empty() {
            return Ok(false);
        }
        let tx = self.0.transaction()?;
        for (id, body) in updates {
            tx.execute(
                "UPDATE sending SET body = ? WHERE change_id = ?",
                params![body, id.to_string()],
            )?;
        }
        tx.commit()?;
        Ok(true)
    }

    /// Records a batch of changes before it's sent, so a retry resends them unchanged.
    pub(crate) fn start_sending(&mut self, batch: &[SendingRow]) -> Result<(), Error> {
        let tx = self.0.transaction()?;
        for c in batch {
            tx.execute(
                "INSERT INTO sending (change_id, object_id, kind, body, covers, outbox_max_id)
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    c.change_id.to_string(),
                    c.object_id.to_string(),
                    if c.keep {
                        "kept_state"
                    } else if c.state {
                        "state"
                    } else {
                        "update"
                    },
                    c.body,
                    c.covers.map(|c| c as i64),
                    c.outbox_max_id
                ],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Forgets changes the server has stored, with the outbox rows they
    /// covered, and advances each object's `confirmed_seq` where given.
    pub(crate) fn sent(&mut self, changes: &[(&SendingRow, Option<u64>)]) -> Result<(), Error> {
        let tx = self.0.transaction()?;
        for (change, confirm) in changes {
            let id = change.object_id.to_string();
            tx.execute(
                "DELETE FROM outbox WHERE object_id = ? AND id <= ?",
                params![id, change.outbox_max_id],
            )?;
            tx.execute(
                "DELETE FROM sending WHERE change_id = ?",
                [change.change_id.to_string()],
            )?;
            if let Some(seq) = confirm {
                tx.execute(
                    "UPDATE objects SET confirmed_seq = ? WHERE object_id = ?",
                    params![*seq as i64, id],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// How many objects have changes waiting to be sent.
    pub(crate) fn pending(&self) -> Result<u64, Error> {
        Ok(self.0.query_row(
            "SELECT count(*) FROM (SELECT object_id FROM outbox UNION SELECT object_id FROM sending)",
            [],
            |r| r.get::<_, i64>(0),
        )? as u64)
    }

    /// Keeps a change that failed to decrypt, decode or apply.
    pub(crate) fn set_aside(
        &self,
        id: ObjectId,
        seq: u64,
        body: &[u8],
        error: &str,
    ) -> Result<(), Error> {
        self.0.execute(
            "INSERT OR IGNORE INTO set_aside (object_id, seq, body, error, at) VALUES (?, ?, ?, ?, ?)",
            params![
                id.to_string(),
                seq as i64,
                body,
                error,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_millis() as i64)
            ],
        )?;
        Ok(())
    }

    /// The set-aside changes' objects, seqs and errors.
    #[cfg(feature = "test-support")]
    pub(crate) fn set_aside_rows(&self) -> Result<Vec<(ObjectId, u64, String)>, Error> {
        let mut statement = self
            .0
            .prepare("SELECT object_id, seq, error FROM set_aside ORDER BY id")?;
        let rows = statement.query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get(2)?))
        })?;
        rows.map(|row| {
            let (id, seq, error) = row?;
            Ok((parse_id(&id)?, seq as u64, error))
        })
        .collect()
    }

    /// A number kept in the `sync` table, such as the base head caught up to.
    pub(crate) fn sync_value(&self, key: &str) -> Result<Option<u64>, Error> {
        Ok(self
            .0
            .query_row("SELECT value FROM sync WHERE key = ?", [key], |r| {
                r.get::<_, i64>(0)
            })
            .optional()?
            .map(|v| v as u64))
    }

    pub(crate) fn set_sync_value(&self, key: &str, value: u64) -> Result<(), Error> {
        self.0.execute(
            "INSERT OR REPLACE INTO sync (key, value) VALUES (?, ?)",
            params![key, value as i64],
        )?;
        Ok(())
    }

    pub(crate) fn file_row(&self, id: ObjectId) -> Result<Option<FileRow>, Error> {
        let row = self
            .0
            .query_row(
                "SELECT parts, have, sent, broken FROM files WHERE object_id = ?",
                [id.to_string()],
                |r| {
                    Ok((
                        r.get::<_, u32>(0)?,
                        r.get::<_, u32>(1)?,
                        r.get::<_, Option<u32>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                    ))
                },
            )
            .optional()?;
        Ok(row.map(|(parts, have, sent, broken)| FileRow {
            id,
            parts,
            have,
            sent,
            broken,
        }))
    }

    /// Records a file whose parts are all here: to be sent, or, when the
    /// server already has them, as if received.
    pub(crate) fn put_file(&self, id: ObjectId, parts: u32, uploaded: bool) -> Result<(), Error> {
        self.0.execute(
            "INSERT INTO files (object_id, parts, have, sent, broken) VALUES (?1, ?2, ?2, ?3, NULL)
             ON CONFLICT(object_id) DO UPDATE SET parts = excluded.parts, have = excluded.have,
                 sent = excluded.sent, broken = NULL",
            params![id.to_string(), parts, (!uploaded).then_some(0)],
        )?;
        Ok(())
    }

    pub(crate) fn file_rows(&self) -> Result<Vec<FileRow>, Error> {
        let mut statement = self
            .0
            .prepare("SELECT object_id, parts, have, sent, broken FROM files")?;
        let rows = statement.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, u32>(2)?,
                r.get::<_, Option<u32>>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?;
        rows.map(|r| {
            let (id, parts, have, sent, broken) = r?;
            Ok(FileRow {
                id: parse_id(&id)?,
                parts,
                have,
                sent,
                broken,
            })
        })
        .collect()
    }

    pub(crate) fn file_candidates(&self) -> Result<Vec<ObjectId>, Error> {
        let mut statement = self
            .0
            .prepare("SELECT object_id FROM objects WHERE type = 'core.file' AND deleted < 2")?;
        let rows = statement.query_map([], |r| r.get::<_, String>(0))?;
        rows.map(|r| parse_id(&r?)).collect()
    }

    pub(crate) fn file_received(&self, id: ObjectId, parts: u32, have: u32) -> Result<(), Error> {
        self.0.execute(
            "INSERT INTO files (object_id, parts, have, sent) VALUES (?, ?, ?, NULL)
             ON CONFLICT(object_id) DO UPDATE SET have = excluded.have WHERE sent IS NULL AND have < excluded.have",
            params![id.to_string(), parts, have],
        )?;
        Ok(())
    }

    pub(crate) fn file_broken(&self, id: ObjectId, parts: u32) -> Result<(), Error> {
        self.0.execute(
            "INSERT INTO files (object_id, parts, have, sent, broken) VALUES (?, ?, 0, NULL, 'authentication failed')
             ON CONFLICT(object_id) DO UPDATE SET broken = 'authentication failed', have = 0",
            params![id.to_string(), parts],
        )?;
        Ok(())
    }

    pub(crate) fn file_sent(&self, id: ObjectId, sent: u32) -> Result<(), Error> {
        self.0.execute(
            "UPDATE files SET sent = ? WHERE object_id = ?",
            params![sent, id.to_string()],
        )?;
        Ok(())
    }

    /// The outbox, oldest first.
    #[cfg(feature = "test-support")]
    pub(crate) fn outbox(&self) -> Result<Vec<(ObjectId, Vec<u8>)>, Error> {
        let mut statement = self
            .0
            .prepare("SELECT object_id, \"update\" FROM outbox ORDER BY id")?;
        let rows = statement.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get(1)?)))?;
        rows.map(|row| {
            let (id, update) = row?;
            Ok((parse_id(&id)?, update))
        })
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Map, Value};

    #[test]
    fn migrating_a_version_5_store_adds_files_and_edits() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("base.sqlite");
        let mut conn = open_encrypted(&path, &[3; 32]).unwrap();
        migrate(&mut conn, &BASE_MIGRATIONS[..5]).unwrap();
        drop(conn);
        let db = BaseDb::open(&path, &[3; 32]).unwrap();
        let version: u32 =
            db.0.query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
        assert_eq!(version, BASE_MIGRATIONS.len() as u32);
        for table in [
            "files",
            "edits",
            "backup_dirty",
            "backup_objects",
            "backup_parts",
            "backup_base",
        ] {
            let count: i64 =
                db.0.query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "{table}");
        }
    }

    #[test]
    fn migrating_a_version_7_store_indexes_dirty_sequence_lookups() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("base.sqlite");
        let mut conn = open_encrypted(&path, &[3; 32]).unwrap();
        migrate(&mut conn, &BASE_MIGRATIONS[..7]).unwrap();
        drop(conn);
        let db = BaseDb::open(&path, &[3; 32]).unwrap();
        let plan: String =
            db.0.query_row(
                "EXPLAIN QUERY PLAN SELECT max(seq) FROM backup_dirty",
                [],
                |row| row.get(3),
            )
            .unwrap();
        assert!(
            plan.contains("USING COVERING INDEX backup_dirty_by_seq"),
            "{plan}"
        );
    }

    #[test]
    fn version_candidates_require_a_local_edit_and_supported_type_version() {
        let tmp = tempfile::tempdir().unwrap();
        let mut db = BaseDb::open(&tmp.path().join("base.sqlite"), &[3; 32]).unwrap();
        db.migrate_search(|_| Ok(())).unwrap();
        let id = ObjectId([5; 16]);
        let mut row = ObjectRow {
            summary: ObjectSummary {
                id,
                ty: TypeRef::new("core.note", 1),
                parent: None,
                position: "V".into(),
                deleted: false,
                title: String::new(),
                fields: Map::new(),
                updated_at: 0,
                updated_by: None,
            },
            state: vec![1],
            moved: false,
        };
        db.put(&row, &[], None).unwrap();
        assert!(
            db.version_candidates(600_000, 300_000, 3_600_000)
                .unwrap()
                .is_empty()
        );
        db.batch(|db| {
            db.put(&row, &[&[1]], None)?;
            db.record_local_edit(id, 0)
        })
        .unwrap();
        assert_eq!(
            db.version_candidates(300_000, 300_000, 3_600_000).unwrap(),
            vec![id]
        );
        db.version_stored(id, 300_000).unwrap();
        db.record_local_edit(id, 600_000).unwrap();
        assert!(
            db.version_candidates(900_000, 300_000, 3_600_000)
                .unwrap()
                .is_empty()
        );
        row.summary.ty.version = 2;
        db.put(&row, &[], None).unwrap();
        assert!(
            db.version_candidates(4_000_000, 300_000, 3_600_000)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn a_base_store_is_encrypted_at_version_4_and_writes_state_with_its_outbox() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("base.sqlite");
        let mut db = BaseDb::open(&path, &[1; 32]).unwrap();
        let id = ObjectId([5; 16]);
        let mut row = ObjectRow {
            summary: ObjectSummary {
                id,
                ty: TypeRef::new("core.folder", 1),
                parent: None,
                position: "V".into(),
                deleted: false,
                title: "plain-marker".into(),
                fields: Map::from_iter([("name".into(), Value::from("plain-marker"))]),
                updated_at: 7,
                updated_by: Some(DeviceId([2; 16])),
            },
            state: vec![1, 2, 3],
            moved: false,
        };
        db.put(&row, &[&[9]], None).unwrap();
        row.summary.deleted = true;
        db.put(&row, &[], Some(4)).unwrap();
        assert_eq!(db.confirmed(id).unwrap(), Some(4));
        db.put(&row, &[], None).unwrap();
        assert_eq!(db.confirmed(id).unwrap(), Some(4));
        assert_eq!(db.summary(id).unwrap().unwrap(), row.summary);
        assert_eq!(db.state(id).unwrap().unwrap().1, vec![1, 2, 3]);
        assert_eq!(db.trash().unwrap().len(), 1);
        // A copy left behind by a move is deleted, but not in the trash.
        row.moved = true;
        db.put(&row, &[], None).unwrap();
        assert!(db.summary(id).unwrap().unwrap().deleted);
        assert!(db.trash().unwrap().is_empty());
        row.moved = false;
        db.put(&row, &[], None).unwrap();
        assert!(db.top_level().unwrap().is_empty());
        let outbox: i64 =
            db.0.query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
                .unwrap();
        assert_eq!(outbox, 1);
        let version: u32 =
            db.0.query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
        assert_eq!(version, 4);
        drop(db);
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(12).any(|w| w == b"plain-marker"));
        assert!(matches!(BaseDb::open(&path, &[2; 32]), Err(Error::Crypto)));
    }

    #[test]
    fn a_version_1_base_store_migrates_to_version_4_and_keeps_its_objects() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("base.sqlite");
        let mut connection = open_encrypted(&path, &[1; 32]).unwrap();
        migrate(&mut connection, &BASE_MIGRATIONS[..1]).unwrap();
        connection
            .execute(
                "INSERT INTO objects (object_id, type, type_version, parent, position, deleted,
                     title, fields, state, updated_at)
                 VALUES (?, 'core.note', 1, ?, 'a0', 0, 'kept', '{}', x'00', 1)",
                [ObjectId([5; 16]).to_string(), ObjectId([6; 16]).to_string()],
            )
            .unwrap();
        drop(connection);
        let db = BaseDb::open(&path, &[1; 32]).unwrap();
        let version: u32 =
            db.0.query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
        assert_eq!(version, 4);
        assert_eq!(
            db.summary(ObjectId([5; 16])).unwrap().unwrap().title,
            "kept"
        );
        assert_eq!(db.of_type("core.note").unwrap().len(), 1);
        assert_eq!(
            db.parents().unwrap(),
            HashMap::from([(ObjectId([5; 16]), Some(ObjectId([6; 16])))])
        );
        let plan = |sql: &str| -> String {
            db.0.query_row(&format!("EXPLAIN QUERY PLAN {sql}"), [], |r| r.get(3))
                .unwrap()
        };
        assert!(plan("SELECT * FROM objects WHERE type = 'x'").contains("objects_by_type"));
        assert!(
            plan("SELECT object_id, parent FROM objects WHERE parent IS NOT NULL")
                .contains("objects_by_parent")
        );
    }

    #[test]
    fn the_account_database_is_encrypted_and_needs_its_key() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a/account.sqlite");
        let mut db = AccountDb::open(&path, &[1; 32]).unwrap();
        db.accept_account_data(3, "{\"marker\":\"plain-marker\"}", true)
            .unwrap();
        drop(db);
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(12).any(|w| w == b"plain-marker"));
        assert!(!raw.starts_with(b"SQLite format 3"));
        assert!(matches!(
            AccountDb::open(&path, &[2; 32]),
            Err(Error::Crypto)
        ));
        let db = AccountDb::open(&path, &[1; 32]).unwrap();
        assert_eq!(db.account_data().unwrap().unwrap().0, 3);
        assert_eq!(db.account_data_seen().unwrap(), Some((3, true)));
        let version: u32 =
            db.0.query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
        assert_eq!(version, 10);
    }

    #[test]
    fn older_account_response_cannot_replace_current_app_readers() {
        let tmp = tempfile::tempdir().unwrap();
        let mut db = AccountDb::open(&tmp.path().join("account.sqlite"), &[1; 32]).unwrap();
        let current = r#"{"apps":{"reader":{"bases":{"health":"ro"}}}}"#;
        let older = r#"{"apps":{}}"#;
        db.accept_account_data(2, current, true).unwrap();
        assert!(!db.accept_account_data(1, older, true).unwrap());
        let (version, json) = db.account_data().unwrap().unwrap();
        assert_eq!(version, 2);
        assert_eq!(json.as_str(), current);
        db.accept_account_data(2, older, true).unwrap();
        assert_eq!(db.account_data().unwrap().unwrap().1.as_str(), current);
    }

    #[test]
    fn account_data_snapshot_keeps_the_version_with_its_app_list() {
        let tmp = tempfile::tempdir().unwrap();
        let mut db = AccountDb::open(&tmp.path().join("account.sqlite"), &[1; 32]).unwrap();
        db.accept_account_data(3, r#"{"apps":{"one":{}}}"#, true)
            .unwrap();
        let first = db.account_data().unwrap().unwrap();
        db.accept_account_data(4, r#"{"apps":{"two":{}}}"#, true)
            .unwrap();
        let second = db.account_data().unwrap().unwrap();
        assert_eq!((first.0, first.1.as_str()), (3, r#"{"apps":{"one":{}}}"#));
        assert_eq!((second.0, second.1.as_str()), (4, r#"{"apps":{"two":{}}}"#));
    }

    #[test]
    fn a_late_unchecked_pair_cannot_replace_a_checked_pair() {
        let tmp = tempfile::tempdir().unwrap();
        let db = AccountDb::open(&tmp.path().join("account.sqlite"), &[1; 32]).unwrap();
        let checked = crate::account::Credentials {
            envelope: vec![1, 2, 3],
            salt: [2; 16],
            checked: true,
        };
        db.set_backup_credentials(&checked).unwrap();
        db.set_backup_credentials(&crate::account::Credentials {
            envelope: vec![9, 8, 7],
            salt: [3; 16],
            checked: false,
        })
        .unwrap();
        assert_eq!(db.backup_credentials().unwrap(), Some(checked));
    }

    #[test]
    fn main_version_2_account_store_migrates_without_losing_approvals() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("account.sqlite");
        let mut connection = open_encrypted(&path, &[1; 32]).unwrap();
        migrate(&mut connection, &ACCOUNT_MIGRATIONS[..2]).unwrap();
        connection
            .execute(
                "INSERT INTO approvals_answered (commitment, at) VALUES (?, 123)",
                [&[4u8; 32][..]],
            )
            .unwrap();
        drop(connection);
        let db = AccountDb::open(&path, &[1; 32]).unwrap();
        assert!(db.bases().unwrap().is_empty());
        let count: u32 =
            db.0.query_row("SELECT count(*) FROM approvals_answered", [], |r| r.get(0))
                .unwrap();
        assert_eq!(count, 1);
        let version: u32 =
            db.0.query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
        assert_eq!(version, 10);
    }

    #[test]
    fn a_main_backup_store_migrates_to_rotation_schema() {
        let tmp = tempfile::tempdir().unwrap();
        let account_path = tmp.path().join("account.sqlite");
        let base_path = tmp.path().join("base.sqlite");
        let mut account = open_encrypted(&account_path, &[1; 32]).unwrap();
        migrate(&mut account, &ACCOUNT_MIGRATIONS[..7]).unwrap();
        account.execute("INSERT INTO bases (base_id, epoch, wrapper, mode, added_at) VALUES (?, 1, ?, 'rw', 1)", params![BaseId([3; 16]).to_string(), vec![5u8; 77]]).unwrap();
        drop(account);
        let mut base = open_encrypted(&base_path, &[1; 32]).unwrap();
        migrate(&mut base, &BASE_MIGRATIONS[..8]).unwrap();
        drop(base);
        let account = AccountDb::open(&account_path, &[1; 32]).unwrap();
        let row = account.bases().unwrap().remove(0);
        assert_eq!((row.account_epoch, row.data_floor), (1, 0));
        assert!(row.chain.is_empty());
        assert_eq!(account.backup_row().unwrap().generation, 0);
        BaseDb::open(&base_path, &[1; 32]).unwrap();
    }

    #[test]
    fn the_hidden_index_survives_reopening() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("account.sqlite");
        let id = BaseId([2; 16]);
        let db = AccountDb::open(&path, &[1; 32]).unwrap();
        db.remember_hidden(id, 1, &[7; 77], &[], 1).unwrap();
        db.remember_hidden(id, 1, &[7; 77], &[], 1).unwrap();
        drop(db);
        let db = AccountDb::open(&path, &[1; 32]).unwrap();
        let hidden = db.hidden_wrappers().unwrap();
        assert_eq!(hidden.len(), 1);
        assert_eq!(hidden[0].id, id);
        assert_eq!(hidden[0].store_wrapper, vec![7; 77]);
        assert_eq!(hidden[0].store_epoch, 1);
        db.remember_hidden(id, 2, &[8; 77], &[(1, vec![9; 77])], 2)
            .unwrap();
        let updated = db.hidden_wrappers().unwrap();
        assert_eq!(updated[0].wrapper, vec![8; 77]);
        assert_eq!(updated[0].store_wrapper, vec![7; 77]);
        assert_eq!(updated[0].store_epoch, 1);
        assert_eq!(updated[0].chain, vec![(1, vec![9; 77])]);
        assert!(db.bases().unwrap().is_empty());
        let version: u32 =
            db.0.query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
        assert_eq!(version, 10);
    }

    #[test]
    fn a_pre_rotation_hidden_index_keeps_its_store_wrapper_after_rekey() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("account.sqlite");
        let id = BaseId([9; 16]);
        let mut connection = open_encrypted(&path, &[1; 32]).unwrap();
        migrate(&mut connection, &ACCOUNT_MIGRATIONS[..10]).unwrap();
        connection
            .execute(
                "INSERT INTO hidden_bases (base_id, epoch, wrapper) VALUES (?, 1, ?)",
                params![id.to_string(), vec![7u8; 77]],
            )
            .unwrap();
        drop(connection);
        let db = AccountDb::open(&path, &[1; 32]).unwrap();
        assert_eq!(db.hidden_wrappers().unwrap()[0].store_wrapper, vec![7; 77]);
        db.remember_hidden(id, 2, &[8; 77], &[], 2).unwrap();
        let row = db.hidden_wrappers().unwrap().remove(0);
        assert_eq!(row.wrapper, vec![8; 77]);
        assert_eq!(row.store_wrapper, vec![7; 77]);
        assert_eq!(row.store_epoch, 1);
    }

    #[test]
    fn the_account_database_keeps_bases_with_their_wrappers() {
        let tmp = tempfile::tempdir().unwrap();
        let db = AccountDb::open(&tmp.path().join("account.sqlite"), &[1; 32]).unwrap();
        let mut row = BaseRow {
            id: BaseId([3; 16]),
            epoch: 1,
            wrapper: vec![1, 2, 3],
            mode: Mode::ReadOnly,
            chain: vec![],
            account_epoch: 1,
            data_floor: 0,
        };
        db.put_base(&row, 5).unwrap();
        row.mode = Mode::ReadWrite;
        db.put_base(&row, 9).unwrap();
        assert_eq!(db.bases().unwrap(), vec![row]);
    }

    #[test]
    fn sent_changes_forget_the_outbox_rows_they_cover() {
        let tmp = tempfile::tempdir().unwrap();
        let mut db = BaseDb::open(&tmp.path().join("base.sqlite"), &[1; 32]).unwrap();
        let id = ObjectId([5; 16]);
        let row = ObjectRow {
            summary: ObjectSummary {
                id,
                ty: TypeRef::new("core.note", 1),
                parent: None,
                position: "V".into(),
                deleted: false,
                title: String::new(),
                fields: Map::new(),
                updated_at: 1,
                updated_by: None,
            },
            state: vec![0, 0],
            moved: false,
        };
        db.put(&row, &[&[1], &[2]], None).unwrap();
        let end = db.outbox_end().unwrap();
        assert_eq!(db.outbox_rows(id, end - 1, usize::MAX).unwrap().len(), 1);
        let covered = db.outbox_rows(id, end, 1).unwrap();
        assert_eq!(covered.len(), 1, "a budget still takes one row");
        let change = SendingRow {
            change_id: ChangeId([7; 16]),
            object_id: id,
            state: false,
            keep: false,
            body: vec![9],
            covers: None,
            outbox_max_id: covered[0].0,
        };
        db.start_sending(std::slice::from_ref(&change)).unwrap();
        db.put(&row, &[&[3]], None).unwrap();
        assert_eq!(db.sending().unwrap(), vec![change.clone()]);
        assert_eq!(db.pending().unwrap(), 1);
        db.sent(&[(&change, Some(12))]).unwrap();
        assert!(db.sending().unwrap().is_empty());
        assert_eq!(db.confirmed(id).unwrap(), Some(12));
        let left: Vec<Vec<u8>> = db.outbox().unwrap().into_iter().map(|(_, u)| u).collect();
        assert_eq!(left, [vec![2], vec![3]]);
    }

    #[test]
    fn accepting_account_data_keeps_the_floor_and_the_versioned_latch() {
        let tmp = tempfile::tempdir().unwrap();
        let mut db = AccountDb::open(&tmp.path().join("account.sqlite"), &[1; 32]).unwrap();
        assert!(db.accept_account_data(2, "{\"n\":2}", false).unwrap());
        // The same version, now sealed with its version, replaces the older format.
        assert!(db.accept_account_data(2, "{\"n\":\"2v\"}", true).unwrap());
        assert_eq!(
            db.account_data().unwrap().unwrap().1.as_str(),
            "{\"n\":\"2v\"}"
        );
        // A late older-format commit can't clear the latch or move the floor.
        assert!(!db.accept_account_data(3, "{\"n\":3}", false).unwrap());
        assert!(!db.accept_account_data(1, "{\"n\":1}", true).unwrap());
        assert_eq!(db.account_data_seen().unwrap(), Some((2, true)));
        assert!(db.accept_account_data(3, "{\"n\":3}", true).unwrap());
        assert_eq!(db.account_data_seen().unwrap(), Some((3, true)));
    }

    #[test]
    fn cached_account_data_from_before_sealed_versions_is_not_marked_versioned() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("account.sqlite");
        let mut connection = open_encrypted(&path, &[1; 32]).unwrap();
        migrate(&mut connection, &ACCOUNT_MIGRATIONS[..5]).unwrap();
        connection
            .execute(
                "INSERT INTO account_data (id, version, json) VALUES (1, 7, '{}')",
                [],
            )
            .unwrap();
        drop(connection);
        let db = AccountDb::open(&path, &[1; 32]).unwrap();
        assert_eq!(db.account_data_seen().unwrap(), Some((7, false)));
    }

    #[test]
    fn old_account_database_migrates_to_answered_commitments() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("account.sqlite");
        let mut connection = open_encrypted(&path, &[1; 32]).unwrap();
        migrate(&mut connection, &ACCOUNT_MIGRATIONS[..1]).unwrap();
        drop(connection);
        let db = AccountDb::open(&path, &[1; 32]).unwrap();
        db.0.execute(
            "INSERT INTO approvals_answered (commitment, at) VALUES (?, ?)",
            params![&[4u8; 32][..], 123],
        )
        .unwrap();
        let version: u32 =
            db.0.query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
        assert_eq!(version, 10);
        let count: u32 =
            db.0.query_row("SELECT count(*) FROM approvals_answered", [], |r| r.get(0))
                .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn a_version_2_base_migrates_duplicate_set_aside_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("base.sqlite");
        let mut connection = open_encrypted(&path, &[1; 32]).unwrap();
        migrate(&mut connection, &BASE_MIGRATIONS[..2]).unwrap();
        connection.execute("INSERT INTO set_aside (object_id, seq, body, error, at) VALUES (?, 1, x'01', 'failed', 1)", [ObjectId([3; 16]).to_string()]).unwrap();
        connection.execute("INSERT INTO set_aside (object_id, seq, body, error, at) VALUES (?, 1, x'02', 'again', 2)", [ObjectId([3; 16]).to_string()]).unwrap();
        drop(connection);
        let db = BaseDb::open(&path, &[1; 32]).unwrap();
        assert_eq!(db.set_aside_rows().unwrap().len(), 1);
        db.set_aside(ObjectId([3; 16]), 1, &[3], "again").unwrap();
        assert_eq!(db.set_aside_rows().unwrap().len(), 1);
    }

    #[test]
    fn a_failed_change_without_a_local_row_is_set_aside_only_once() {
        let tmp = tempfile::tempdir().unwrap();
        let db = BaseDb::open(&tmp.path().join("base.sqlite"), &[1; 32]).unwrap();
        let id = ObjectId([3; 16]);
        db.set_aside(id, 1, &[1], "failed").unwrap();
        db.set_aside(id, 1, &[2], "again").unwrap();
        assert_eq!(db.set_aside_rows().unwrap().len(), 1);
    }

    #[test]
    fn a_newer_database_needs_an_update() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("account.sqlite");
        let db = AccountDb::open(&path, &[1; 32]).unwrap();
        db.0.execute_batch("PRAGMA user_version = 11").unwrap();
        drop(db);
        assert!(matches!(
            AccountDb::open(&path, &[1; 32]),
            Err(Error::NeedsUpdate)
        ));
    }
}
