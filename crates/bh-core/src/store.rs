//! Encrypted SQLite stores (SQLCipher) and their migrations: the account
//! database and each base's store.

use crate::objects::ObjectSummary;
use crate::types::TypeRef;
use crate::{DeviceKind, Error};
use bh_proto::{AccountId, DeviceId, ObjectId};
use rusqlite::{Connection, OptionalExtension, Row, params};
use std::collections::HashMap;
use std::path::Path;
use zeroize::Zeroizing;

/// Opens a SQLCipher database with a raw 32-byte key and checks the key works.
pub(crate) fn open_encrypted(path: &Path, key: &[u8]) -> Result<Connection, Error> {
    if key.len() != 32 {
        return Err(Error::Storage("database key has the wrong length".into()));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let connection = Connection::open(path)?;
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    let pragma = Zeroizing::new(format!("PRAGMA key = \"x'{hex}'\";"));
    drop(Zeroizing::new(hex));
    connection.execute_batch(&pragma)?;
    // Reading the schema fails if the key is wrong.
    connection
        .query_row("SELECT count(*) FROM sqlite_master", [], |_| Ok(()))
        .map_err(|_| Error::Crypto)?;
    connection.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(connection)
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
    "
    CREATE TABLE approvals_answered (commitment BLOB PRIMARY KEY, at INTEGER NOT NULL);
",
];

pub(crate) struct AccountRow {
    pub id: AccountId,
    pub email: String,
    pub server: url::Url,
    pub kind: DeviceKind,
    pub device_id: DeviceId,
}

pub(crate) struct AccountDb(Connection);

impl AccountDb {
    pub(crate) fn open(path: &Path, key: &[u8]) -> Result<Self, Error> {
        let mut connection = open_encrypted(path, key)?;
        migrate(&mut connection, ACCOUNT_MIGRATIONS)?;
        Ok(Self(connection))
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

    pub(crate) fn set_account_data(&self, version: u64, json: &str) -> Result<(), Error> {
        self.0.execute(
            "INSERT OR REPLACE INTO account_data (id, version, json) VALUES (1, ?, ?)",
            params![version as i64, json],
        )?;
        Ok(())
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
];

/// Types that never show in the folder tree or the trash.
const HIDDEN: &str = "type NOT IN ('core.type', 'core.base')";

const SUMMARY: &str = "object_id, type, type_version, parent, position, deleted, title, fields, updated_at, updated_by";

/// An object's stored state and the columns derived from it.
pub(crate) struct ObjectRow {
    pub summary: ObjectSummary,
    pub state: Vec<u8>,
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
pub(crate) struct BaseDb(Connection);

impl BaseDb {
    pub(crate) fn open(path: &Path, key: &[u8]) -> Result<Self, Error> {
        let mut connection = open_encrypted(path, key)?;
        migrate(&mut connection, BASE_MIGRATIONS)?;
        Ok(Self(connection))
    }

    /// Writes an object's state and summary and, for local edits, their
    /// updates to the outbox, in one transaction. `confirmed_seq` is kept.
    pub(crate) fn put(&mut self, row: &ObjectRow, outbox: &[&[u8]]) -> Result<(), Error> {
        let s = &row.summary;
        let fields = serde_json::to_string(&s.fields).expect("JSON map");
        let tx = self.0.transaction()?;
        tx.execute(
            "INSERT INTO objects (object_id, type, type_version, parent, position, deleted, title,
                 fields, state, updated_at, updated_by)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (object_id) DO UPDATE SET type = excluded.type,
                 type_version = excluded.type_version, parent = excluded.parent,
                 position = excluded.position, deleted = excluded.deleted, title = excluded.title,
                 fields = excluded.fields, state = excluded.state, updated_at = excluded.updated_at,
                 updated_by = excluded.updated_by",
            params![
                s.id.to_string(),
                s.ty.name,
                s.ty.version,
                hex(s.parent),
                s.position,
                s.deleted,
                s.title,
                fields,
                row.state,
                s.updated_at,
                s.updated_by.map(|d| d.to_string()),
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

    fn summaries(
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
    fn a_base_store_is_encrypted_at_version_2_and_writes_state_with_its_outbox() {
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
        };
        db.put(&row, &[&[9]]).unwrap();
        row.summary.deleted = true;
        db.put(&row, &[]).unwrap();
        assert_eq!(db.summary(id).unwrap().unwrap(), row.summary);
        assert_eq!(db.state(id).unwrap().unwrap().1, vec![1, 2, 3]);
        assert_eq!(db.trash().unwrap().len(), 1);
        assert!(db.top_level().unwrap().is_empty());
        let outbox: i64 =
            db.0.query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
                .unwrap();
        assert_eq!(outbox, 1);
        let version: u32 =
            db.0.query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
        assert_eq!(version, 2);
        drop(db);
        let raw = std::fs::read(&path).unwrap();
        assert!(!raw.windows(12).any(|w| w == b"plain-marker"));
        assert!(matches!(BaseDb::open(&path, &[2; 32]), Err(Error::Crypto)));
    }

    #[test]
    fn a_version_1_base_store_migrates_to_version_2_and_keeps_its_objects() {
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
        assert_eq!(version, 2);
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
        let db = AccountDb::open(&path, &[1; 32]).unwrap();
        db.set_account_data(3, "{\"marker\":\"plain-marker\"}")
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
        let version: u32 =
            db.0.query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
        assert_eq!(version, 2);
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
        assert_eq!(version, 2);
        let count: u32 =
            db.0.query_row("SELECT count(*) FROM approvals_answered", [], |r| r.get(0))
                .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn a_newer_database_needs_an_update() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("account.sqlite");
        let db = AccountDb::open(&path, &[1; 32]).unwrap();
        db.0.execute_batch("PRAGMA user_version = 9").unwrap();
        drop(db);
        assert!(matches!(
            AccountDb::open(&path, &[1; 32]),
            Err(Error::NeedsUpdate)
        ));
    }
}
