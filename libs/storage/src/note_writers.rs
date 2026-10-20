//! Protocol-neutral durable writer reservations. Native owners verify derivation
//! and capability; SQLite supplies immutability and atomic update linkage.
use crate::{DeviceDatabase, LocalCommit, NoteKey, StoreError};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BaseWriterPhase {
    Unregistered,
    Registered,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterSlot {
    pub key: NoteKey,
    pub account: [u8; 32],
    pub device: [u8; 32],
    pub slot: u32,
    pub nonce: [u8; 32],
    /// Checked index only: the native consumer recomputes it before use.
    pub client_id: u64,
    pub retired: bool,
}

pub(crate) fn migrate(tx: &Transaction<'_>) -> rusqlite::Result<()> {
    tx.execute_batch("CREATE TABLE base_writer_phase (
        base BLOB PRIMARY KEY CHECK(length(base)=32), phase INTEGER NOT NULL CHECK(phase IN (0,1))
    );
    CREATE TRIGGER writer_phase_no_downgrade BEFORE UPDATE OF phase ON base_writer_phase
      WHEN OLD.phase=1 AND NEW.phase!=1 BEGIN SELECT RAISE(ABORT,'registered writer phase'); END;
    CREATE TABLE note_writer_slots (
        base BLOB NOT NULL CHECK(length(base)=32), audience BLOB NOT NULL CHECK(length(audience)=32),
        note BLOB NOT NULL CHECK(length(note)=32), account BLOB NOT NULL CHECK(length(account)=32),
        device BLOB NOT NULL CHECK(length(device)=32), slot INTEGER NOT NULL CHECK(slot BETWEEN 0 AND 4294967295),
        nonce BLOB NOT NULL CHECK(length(nonce)=32), client_id INTEGER NOT NULL CHECK(client_id BETWEEN 0 AND 9007199254740991),
        retired INTEGER NOT NULL DEFAULT 0 CHECK(retired IN (0,1)),
        PRIMARY KEY(base,audience,note,account,device,slot), UNIQUE(base,audience,note,client_id)
    ) WITHOUT ROWID;
    CREATE TRIGGER writer_mapping_immutable BEFORE UPDATE ON note_writer_slots
      WHEN NEW.base!=OLD.base OR NEW.audience!=OLD.audience OR NEW.note!=OLD.note
        OR NEW.account!=OLD.account OR NEW.device!=OLD.device OR NEW.slot!=OLD.slot
        OR NEW.nonce!=OLD.nonce OR NEW.client_id!=OLD.client_id OR NEW.retired<OLD.retired
      BEGIN SELECT RAISE(ABORT,'immutable writer mapping'); END;
    CREATE TABLE note_update_writer (
        update_id INTEGER PRIMARY KEY REFERENCES note_updates(id),
        base BLOB NOT NULL, audience BLOB NOT NULL, note BLOB NOT NULL,
        account BLOB NOT NULL, device BLOB NOT NULL, slot INTEGER NOT NULL,
        FOREIGN KEY(base,audience,note,account,device,slot)
          REFERENCES note_writer_slots(base,audience,note,account,device,slot)
    );
    CREATE TRIGGER update_writer_immutable BEFORE UPDATE ON note_update_writer
      BEGIN SELECT RAISE(ABORT,'immutable update writer'); END;")
}

// Registration calls this inside the verified registration transaction
// (`record_registration`), never to publish a synthetic Ready projection.
pub(crate) fn mark_registered(tx: &Transaction<'_>, base: [u8; 32]) -> Result<(), StoreError> {
    tx.execute("INSERT INTO base_writer_phase(base,phase) VALUES (?1,1) ON CONFLICT(base) DO UPDATE SET phase=1",[base])?;
    Ok(())
}

fn decode(row: &rusqlite::Row<'_>) -> rusqlite::Result<WriterSlot> {
    let array = |i| -> rusqlite::Result<[u8; 32]> {
        let bytes: Vec<u8> = row.get(i)?;
        bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
    };
    Ok(WriterSlot {
        key: NoteKey {
            base: array(0)?,
            audience: array(1)?,
            note: array(2)?,
        },
        account: array(3)?,
        device: array(4)?,
        slot: row.get(5)?,
        nonce: array(6)?,
        client_id: row.get::<_, i64>(7)? as u64,
        retired: row.get(8)?,
    })
}

pub(crate) fn pending_writer(
    db: &Connection,
    update_id: i64,
) -> Result<Option<WriterSlot>, StoreError> {
    Ok(db.query_row("SELECT s.base,s.audience,s.note,s.account,s.device,s.slot,s.nonce,s.client_id,s.retired
        FROM note_update_writer w JOIN note_writer_slots s USING(base,audience,note,account,device,slot)
        WHERE w.update_id=?1",[update_id],decode).optional()?)
}

pub(crate) fn link(
    tx: &Transaction<'_>,
    update_id: i64,
    slot: &WriterSlot,
) -> Result<(), StoreError> {
    let inserted = tx.execute(
        "INSERT INTO note_update_writer(update_id,base,audience,note,account,device,slot)
      SELECT ?1,base,audience,note,account,device,slot FROM note_writer_slots
      WHERE base=?2 AND audience=?3 AND note=?4 AND account=?5 AND device=?6 AND slot=?7
      AND nonce=?8 AND client_id=?9 AND retired=0",
        params![
            update_id,
            slot.key.base,
            slot.key.audience,
            slot.key.note,
            slot.account,
            slot.device,
            slot.slot,
            slot.nonce,
            slot.client_id as i64
        ],
    )?;
    if inserted != 1 {
        return Err(StoreError::InvalidWriter);
    }
    Ok(())
}

impl DeviceDatabase {
    pub fn base_writer_phase(&self, base: [u8; 32]) -> Result<Option<BaseWriterPhase>, StoreError> {
        let phase: Option<u8> = self
            .connection
            .query_row(
                "SELECT phase FROM base_writer_phase WHERE base=?1",
                [base],
                |r| r.get(0),
            )
            .optional()?;
        phase
            .map(|p| match p {
                0 => Ok(BaseWriterPhase::Unregistered),
                1 => Ok(BaseWriterPhase::Registered),
                _ => Err(StoreError::InvalidWriter),
            })
            .transpose()
    }
    pub fn writer_slots(
        &self,
        key: NoteKey,
        account: [u8; 32],
        device: [u8; 32],
    ) -> Result<Vec<WriterSlot>, StoreError> {
        let mut stmt=self.connection.prepare("SELECT base,audience,note,account,device,slot,nonce,client_id,retired
          FROM note_writer_slots WHERE base=?1 AND audience=?2 AND note=?3 AND account=?4 AND device=?5 ORDER BY slot")?;
        Ok(stmt
            .query_map(
                params![key.base, key.audience, key.note, account, device],
                decode,
            )?
            .collect::<Result<_, _>>()?)
    }
    /// Every local reservation for this note, retired ones and any principal.
    pub fn writer_reservations(&self, key: NoteKey) -> Result<Vec<WriterSlot>, StoreError> {
        let mut stmt = self.connection.prepare(
            "SELECT base,audience,note,account,device,slot,nonce,client_id,retired
          FROM note_writer_slots WHERE base=?1 AND audience=?2 AND note=?3",
        )?;
        Ok(stmt
            .query_map(params![key.base, key.audience, key.note], decode)?
            .collect::<Result<_, _>>()?)
    }
    pub fn writer_id_reserved(&self, key: NoteKey, client_id: u64) -> Result<bool, StoreError> {
        Ok(self.connection.query_row("SELECT EXISTS(SELECT 1 FROM note_writer_slots WHERE base=?1 AND audience=?2 AND note=?3 AND client_id=?4)",params![key.base,key.audience,key.note,client_id as i64],|r|r.get(0))?)
    }
    pub fn insert_writer_slot(&mut self, slot: &WriterSlot) -> Result<(), StoreError> {
        self.connection.execute("INSERT INTO note_writer_slots(base,audience,note,account,device,slot,nonce,client_id,retired) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![slot.key.base,slot.key.audience,slot.key.note,slot.account,slot.device,slot.slot,slot.nonce,slot.client_id as i64,slot.retired])?;
        Ok(())
    }
    /// Native caller holds note ownership and final authority/lease fence.
    pub fn commit_writer_update(
        &mut self,
        frontier: i64,
        anchor: [u8; 32],
        request: [u8; 16],
        bytes: &[u8],
        slot: &WriterSlot,
    ) -> Result<LocalCommit, StoreError> {
        self.commit_working_update_inner(
            slot.key,
            frontier,
            anchor,
            request,
            bytes,
            None,
            Some(slot),
        )
    }
    /// As `commit_writer_update`, with the bounded catalogue title derived
    /// from the working note outside every guard, in the same COMMIT. An
    /// exact request retry returns its original commit and never retitles.
    pub fn commit_writer_update_with_title(
        &mut self,
        frontier: i64,
        anchor: [u8; 32],
        request: [u8; 16],
        bytes: &[u8],
        slot: &WriterSlot,
        title: &str,
    ) -> Result<LocalCommit, StoreError> {
        if title.chars().count() > crate::MAX_NOTE_TITLE {
            return Err(StoreError::InvalidNoteTitle);
        }
        self.commit_working_update_inner(
            slot.key,
            frontier,
            anchor,
            request,
            bytes,
            Some(title),
            Some(slot),
        )
    }
    /// Recognized restore/import lineage cannot reuse these reservations.
    /// Pending deltas and their immutable proof links remain untouched.
    pub fn retire_note_writers(&mut self, key: NoteKey) -> Result<(), StoreError> {
        self.connection.execute(
            "UPDATE note_writer_slots SET retired=1 WHERE base=?1 AND audience=?2 AND note=?3",
            params![key.base, key.audience, key.note],
        )?;
        Ok(())
    }
    pub fn retire_writer_slot(&mut self, slot: &WriterSlot) -> Result<(), StoreError> {
        self.connection.execute("UPDATE note_writer_slots SET retired=1 WHERE base=?1 AND audience=?2 AND note=?3 AND account=?4 AND device=?5 AND slot=?6",
            params![slot.key.base,slot.key.audience,slot.key.note,slot.account,slot.device,slot.slot])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_registration_rolls_back_phase_and_evidence_retry_never_downgrades() {
        let mut db = DeviceDatabase::open(":memory:").unwrap();
        db.connection
            .execute_batch("CREATE TABLE receipt (id INTEGER PRIMARY KEY CHECK(id=1));")
            .unwrap();
        {
            let tx = db.connection.transaction().unwrap();
            mark_registered(&tx, [1; 32]).unwrap();
            assert!(tx.execute("INSERT INTO receipt VALUES(2)", []).is_err());
        }
        assert_eq!(db.base_writer_phase([1; 32]).unwrap(), None);
        let tx = db.connection.transaction().unwrap();
        tx.execute("INSERT INTO receipt VALUES(1)", []).unwrap();
        mark_registered(&tx, [1; 32]).unwrap();
        mark_registered(&tx, [1; 32]).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            db.base_writer_phase([1; 32]).unwrap(),
            Some(BaseWriterPhase::Registered)
        );
        assert!(
            db.connection
                .execute("UPDATE base_writer_phase SET phase=0", [])
                .is_err()
        );
    }
}
