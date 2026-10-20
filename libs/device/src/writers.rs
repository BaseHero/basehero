//! Durable writer slots and ephemeral authoring leases. These are unrelated to
//! delivery backpressure tokens. Only a current native capability selects the
//! principal; the page gets a safe integer and an opaque token.
use crate::{
    ContainerId, Owner, OwnerError,
    coordinator::{Ack, Opened},
};
use bh_core::note::{Note, WriterPrefix};
use bh_event::writer::{DeviceWriterDeclaration, WriterScope};
use bh_storage::{
    DeviceDatabase, NoteKey, PendingNoteUpdate,
    note_writers::{BaseWriterPhase, WriterSlot},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterUnavailable;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedWriterBinding {
    pub account: [u8; 32],
    pub device: [u8; 32],
    pub nonce: [u8; 32],
    pub client_id: u64,
    pub accepted_end: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BindingRead {
    /// Revision of this note's accepted bindings, not the common base head.
    pub revision: u64,
    /// None means verified absence, never an unloaded index.
    pub binding: Option<VerifiedWriterBinding>,
}
pub trait AcceptedBindings: Send + Sync {
    /// Called under note ownership and a borrowed DB guard; do not relock it.
    fn binding(
        &self,
        db: &DeviceDatabase,
        key: NoteKey,
        client_id: u64,
    ) -> Result<BindingRead, WriterUnavailable>;
}
/// The production reader: writer bindings committed with each note's
/// accepted state by verified incoming batches. Its revision is the last log
/// position that changed the note's accepted state.
pub struct StoredBindings;
impl AcceptedBindings for StoredBindings {
    fn binding(
        &self,
        db: &DeviceDatabase,
        key: NoteKey,
        client_id: u64,
    ) -> Result<BindingRead, WriterUnavailable> {
        let revision = db.accepted_revision(key).map_err(|_| WriterUnavailable)?;
        let binding = db
            .accepted_binding(key, client_id)
            .map_err(|_| WriterUnavailable)?
            .map(|b| VerifiedWriterBinding {
                account: b.account,
                device: b.device,
                nonce: b.nonce,
                client_id: b.client_id,
                accepted_end: b.accepted_end,
            });
        Ok(BindingRead { revision, binding })
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WriterLease {
    pub client_id: u64,
    pub token: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fence {
    Unregistered,
    Registered(BindingRead),
}
/// Stable identity for one producer. Accepted state is never pinned here:
/// each new save captures its own fence (see `attempt_fence`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActiveWriter {
    pub container: ContainerId,
    pub generation: u64,
    pub lease: WriterLease,
    pub slot: WriterSlot,
}
#[derive(Default)]
pub(crate) struct Writers {
    pub active: Mutex<HashMap<String, ActiveWriter>>,
    readers: Mutex<HashMap<ContainerId, Arc<dyn AcceptedBindings>>>,
    #[cfg(test)]
    test_nonces: Mutex<std::collections::VecDeque<[u8; 32]>>,
}

fn scope(key: NoteKey) -> WriterScope {
    WriterScope {
        base: key.base,
        audience: key.audience,
        note: key.note,
    }
}
fn declaration(slot: &WriterSlot) -> Result<DeviceWriterDeclaration, WriterUnavailable> {
    let d = DeviceWriterDeclaration {
        account: slot.account,
        device: slot.device,
        nonce: slot.nonce,
    };
    if d.client_id(scope(slot.key)) != slot.client_id {
        return Err(WriterUnavailable);
    }
    Ok(d)
}
/// Storage stays protocol-neutral (account already depends on storage). Native
/// packaging uses this checked carrier and the shared 99-byte event codec.
/// Proofless old rows are explicit None, never a retrospective nonce search.
pub fn pending_declaration(
    pending: &PendingNoteUpdate,
) -> Result<Option<DeviceWriterDeclaration>, WriterUnavailable> {
    pending
        .writer
        .map(|s| {
            if s.key != pending.key {
                return Err(WriterUnavailable);
            }
            declaration(&s)
        })
        .transpose()
}
impl Writers {
    fn nonce(&self) -> [u8; 32] {
        #[cfg(test)]
        if let Some(nonce) = self.test_nonces.lock().unwrap().pop_front() {
            return nonce;
        }
        bh_crypto::random()
    }
    pub(crate) fn fence(
        &self,
        id: ContainerId,
        db: &DeviceDatabase,
        key: NoteKey,
        client_id: u64,
    ) -> Result<Fence, OwnerError> {
        match db.base_writer_phase(key.base)? {
            Some(BaseWriterPhase::Unregistered) => Ok(Fence::Unregistered),
            Some(BaseWriterPhase::Registered) => {
                let reader = self
                    .readers
                    .lock()
                    .expect("binding readers")
                    .get(&id)
                    .cloned()
                    .ok_or(OwnerError::WriterUnavailable)?;
                reader
                    .binding(db, key, client_id)
                    .map(Fence::Registered)
                    .map_err(|_| OwnerError::WriterUnavailable)
            }
            None => Err(OwnerError::WriterUnavailable),
        }
    }
    /// Accepted state naming another principal or nonce for any local
    /// reservation (retired too) makes this note's existing structs, and
    /// anything authored after them, ambiguous. Pause all authoring in the
    /// note; every struct, pending byte and proof stays as it is.
    fn conflicted(
        &self,
        id: ContainerId,
        db: &DeviceDatabase,
        key: NoteKey,
    ) -> Result<bool, OwnerError> {
        if db.base_writer_phase(key.base)? != Some(BaseWriterPhase::Registered) {
            return Ok(false);
        }
        for slot in db.writer_reservations(key)? {
            if let Fence::Registered(BindingRead {
                binding: Some(b), ..
            }) = self.fence(id, db, key, slot.client_id)?
                && (b.account, b.device, b.nonce) != (slot.account, slot.device, slot.nonce)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
/// The slot's proven next clock under accepted ownership. Capacity for a
/// further operation is a separate question.
fn owned_end(note: &Note, slot: &WriterSlot, fence: Fence) -> Result<Option<u32>, OwnerError> {
    let Some(end) = note.writer_end(slot.client_id)? else {
        return Ok(None);
    };
    Ok(match fence {
        Fence::Unregistered => Some(end),
        Fence::Registered(read) => read
            .binding
            .is_none_or(|b| {
                b.account == slot.account
                    && b.device == slot.device
                    && b.nonce == slot.nonce
                    && b.client_id == slot.client_id
                    && end >= b.accepted_end
            })
            .then_some(end),
    })
}
fn reusable(note: &Note, slot: &WriterSlot, fence: Fence) -> Result<bool, OwnerError> {
    Ok(!slot.retired && owned_end(note, slot, fence)?.is_some_and(|end| end < u32::MAX))
}
impl Owner {
    pub fn install_binding_reader(&self, id: ContainerId, reader: Arc<dyn AcceptedBindings>) {
        self.writers
            .readers
            .lock()
            .expect("binding readers")
            .insert(id, reader);
    }
    /// Install the production bindings reader for a container whose bases
    /// sync. Native sync calls this when it starts for the container; until
    /// then a registered base stays unavailable for writing.
    pub fn install_stored_bindings(&self, id: ContainerId) {
        self.install_binding_reader(id, Arc::new(StoredBindings));
    }
    /// Record a verified registration of `base` (its genesis receipt, or a
    /// joined base's bootstrap), pinning `hosting_root` from the base's
    /// authenticated hosting association (never an invented one) and
    /// latching its writer phase Registered in the same transaction, and
    /// install the production bindings reader.
    pub fn record_registration(
        &self,
        id: ContainerId,
        base: [u8; 32],
        genesis_receipt: Option<[u8; bh_sync::receipt::RECEIPT_LEN]>,
        hosting_root: [u8; 32],
    ) -> Result<(), OwnerError> {
        let database = self.shared_database(id)?;
        database
            .lock()
            .expect("container writer lock")
            .record_registration(base, genesis_receipt, hosting_root)
            .map_err(|e| match e {
                bh_storage::StoreError::RootConflict => OwnerError::Unavailable,
                other => OwnerError::Store(other),
            })?;
        self.install_stored_bindings(id);
        Ok(())
    }
    /// Native restore/import integration, never a page operation. Fence live
    /// producers and retain every original pending request and declaration.
    pub fn retire_restored_writers(&self, id: ContainerId, key: NoteKey) -> Result<(), OwnerError> {
        let work = self.work_lock(id, key);
        let _work = work.lock.as_ref().unwrap().lock().expect("note work");
        let session = self.account_session(id)?;
        let guard = session.lock().expect("container session");
        let database = guard.shared_database();
        let mut db = database.lock().expect("container writer");
        let (base, _) = guard.authority().current().ok_or(OwnerError::Unbound)?;
        if base != key.base || key.audience != crate::ORDINARY_AUDIENCE || !db.note_exists(key)? {
            return Err(OwnerError::Unbound);
        }
        db.retire_note_writers(key)?;
        self.writers
            .active
            .lock()
            .expect("writer leases")
            .retain(|_, a| a.container != id || a.slot.key != key);
        Ok(())
    }
    pub fn open_leased(&self, window: &str, note: [u8; 32]) -> Result<Opened, OwnerError> {
        self.open_mode(window, note, |_| {}, true, None)
    }
    /// Capacity rollover after the page drained its writing: retire the
    /// caller's own live writer (named by its current token) and grant a fresh
    /// one with full capacity, never another idle near-end slot. Ordinary
    /// opens and a writer whose terminal save already ended its lease use
    /// `open_leased`.
    pub fn open_leased_retiring(
        &self,
        window: &str,
        note: [u8; 32],
        token: [u8; 32],
    ) -> Result<Opened, OwnerError> {
        self.open_mode(window, note, |_| {}, true, Some(token))
    }
    /// The window's latest lease, matched by token, container and note. Its
    /// generation is not compared with the route: any open (including a
    /// failed or Changed retry of this one) advances that, and the old
    /// generation is already fenced from further saves.
    pub(crate) fn retiring_writer(
        &self,
        window: &str,
        id: ContainerId,
        note: [u8; 32],
        token: [u8; 32],
    ) -> Result<ActiveWriter, OwnerError> {
        self.writers
            .active
            .lock()
            .expect("writer leases")
            .get(window)
            .copied()
            .filter(|a| a.container == id && a.slot.key.note == note && a.lease.token == token)
            .ok_or(OwnerError::WriterUnavailable)
    }
    // Under the note work lock and session/DB guards: the same lease is still
    // this window's, for this bound scope and the current capability.
    pub(crate) fn recheck_retiring(
        &self,
        window: &str,
        old: ActiveWriter,
        key: NoteKey,
        principal: ([u8; 32], [u8; 32]),
    ) -> Result<WriterSlot, OwnerError> {
        let current = self
            .writers
            .active
            .lock()
            .expect("writer leases")
            .get(window)
            .copied();
        if current != Some(old)
            || old.slot.key != key
            || (old.slot.account, old.slot.device) != principal
        {
            return Err(OwnerError::WriterUnavailable);
        }
        Ok(old.slot)
    }
    pub fn commit_leased(
        &self,
        window: &str,
        generation: u64,
        token: [u8; 32],
        request: [u8; 16],
        update: &[u8],
    ) -> Result<(Ack, Vec<String>), OwnerError> {
        let (ack, targets, _) = self.commit_queued_with_work_hook(
            window,
            generation,
            request,
            update,
            crate::NO_HOOKS,
            Some(token),
        )?;
        Ok((ack, targets))
    }
    /// Test seam sharing the real final writer fence; callback runs off the DB.
    #[doc(hidden)]
    pub fn commit_leased_with_work_hook(
        &self,
        window: &str,
        generation: u64,
        token: [u8; 32],
        request: [u8; 16],
        update: &[u8],
        prepare: impl FnOnce(),
    ) -> Result<(Ack, Vec<String>), OwnerError> {
        let (ack, targets, _) = self.commit_queued_with_work_hook(
            window,
            generation,
            request,
            update,
            (prepare, crate::noop, crate::noop),
            Some(token),
        )?;
        Ok((ack, targets))
    }
    #[doc(hidden)]
    pub fn commit_leased_with_writer_hooks(
        &self,
        window: &str,
        generation: u64,
        token: [u8; 32],
        request: [u8; 16],
        update: &[u8],
        hooks: (impl FnOnce(), impl FnOnce()),
    ) -> Result<Ack, OwnerError> {
        let (ack, _, _) = self.commit_queued_with_work_hook(
            window,
            generation,
            request,
            update,
            (crate::noop, hooks.0, hooks.1),
            Some(token),
        )?;
        Ok(ack)
    }
    /// A core producer uses its own bound surface/lease, never the read cache's
    /// random replica. Loading a snapshot precedes every authoring operation.
    pub fn core_author(opened: &Opened) -> Result<Note, OwnerError> {
        let lease = opened.writer.ok_or(OwnerError::WriterUnavailable)?;
        let mut note = Note::with_writer(lease.client_id)?;
        note.apply_ordered(&opened.state)?;
        if note.replica_id() != lease.client_id {
            return Err(OwnerError::WriterUnavailable);
        }
        Ok(note)
    }
    // Caller holds the note work lock and container session/writer guards.
    // Never retain a process-global registry guard over the slot's fsync.
    #[allow(clippy::too_many_arguments)] // Authenticated scope plus borrowed candidate/DB.
    pub(crate) fn allocate_writer(
        &self,
        window: &str,
        id: ContainerId,
        generation: u64,
        db: &mut DeviceDatabase,
        key: NoteKey,
        principal: ([u8; 32], [u8; 32]),
        note: &Note,
        retire: Option<WriterSlot>,
    ) -> Result<ActiveWriter, OwnerError> {
        let (account, device) = principal;
        let occupied: Vec<_> = self
            .writers
            .active
            .lock()
            .expect("writer leases")
            .iter()
            .filter(|(w, a)| {
                w.as_str() != window
                    && a.container == id
                    && a.slot.key == key
                    && self.route_current(w, id, a.generation)
            })
            .map(|(_, a)| *a)
            .collect();
        if self.writers.conflicted(id, db, key)? {
            return Err(OwnerError::WriterUnavailable);
        }
        let slots = db.writer_slots(key, account, device)?;
        // Capacity rollover: retire the caller's slot (a retry re-retires it
        // harmlessly) and take only a fresh mapping below.
        if let Some(old) = retire {
            db.retire_writer_slot(&old)?;
        }
        for slot in slots.iter().filter(|_| retire.is_none()) {
            declaration(slot).map_err(|_| OwnerError::WriterUnavailable)?;
            // Pending input keeps its reservation: once the missing dependency
            // integrates, the same writer continues from its real next clock.
            if occupied.iter().any(|a| a.slot.client_id == slot.client_id)
                || slot.retired
                || note.writer_prefix(slot.client_id)? == WriterPrefix::Pending
            {
                continue;
            }
            let fence = self.writers.fence(id, db, key, slot.client_id)?;
            if reusable(note, slot, fence)? {
                return Ok(ActiveWriter {
                    container: id,
                    generation,
                    lease: WriterLease {
                        client_id: slot.client_id,
                        token: bh_crypto::random(),
                    },
                    slot: *slot,
                });
            }
            // Never rewind an incomplete/exhausted reservation. Preserve it for
            // history and pending work; a fresh slot does not rewrite either.
            // Ownership conflicts were refused above, never retired here.
            db.retire_writer_slot(slot)?;
        }
        let slot = slots
            .last()
            .map_or(Some(0), |s| s.slot.checked_add(1))
            .ok_or(OwnerError::WriterUnavailable)?;
        for _ in 0..32 {
            let d = DeviceWriterDeclaration {
                account,
                device,
                nonce: self.writers.nonce(),
            };
            let client_id = d.client_id(scope(key));
            let fence = self.writers.fence(id, db, key, client_id)?;
            if note.has_writer(client_id)?
                || db.writer_id_reserved(key, client_id)?
                || matches!(
                    fence,
                    Fence::Registered(BindingRead {
                        binding: Some(_),
                        ..
                    })
                )
            {
                continue;
            }
            let slot = WriterSlot {
                key,
                account,
                device,
                slot,
                nonce: d.nonce,
                client_id,
                retired: false,
            };
            db.insert_writer_slot(&slot)?;
            return Ok(ActiveWriter {
                container: id,
                generation,
                lease: WriterLease {
                    client_id,
                    token: bh_crypto::random(),
                },
                slot,
            });
        }
        Err(OwnerError::WriterUnavailable)
    }
    pub(crate) fn writer_for(
        &self,
        window: &str,
        id: ContainerId,
        generation: u64,
        token: [u8; 32],
        key: NoteKey,
    ) -> Result<ActiveWriter, OwnerError> {
        self.writers
            .active
            .lock()
            .expect("writer leases")
            .get(window)
            .copied()
            .filter(|a| {
                a.container == id
                    && a.generation == generation
                    && a.lease.token == token
                    && a.slot.key == key
            })
            .ok_or(OwnerError::WriterUnavailable)
    }
    /// Start of one new save, under the note work lock: the current phase and
    /// binding must still own this slot's durable prefix. A benign change since
    /// open (own acknowledgement, another binding, registration) is current
    /// state for this attempt, not a reason to burn the writer.
    pub(crate) fn attempt_fence(
        &self,
        active: ActiveWriter,
        db: &DeviceDatabase,
        note: &Note,
    ) -> Result<Fence, OwnerError> {
        let fence =
            self.writers
                .fence(active.container, db, active.slot.key, active.slot.client_id)?;
        owned_end(note, &active.slot, fence)?.ok_or(OwnerError::WriterUnavailable)?;
        // A newly accepted conflict also stops other live producers. Any later
        // binding change moves the revision this attempt's final fence checks.
        if self
            .writers
            .conflicted(active.container, db, active.slot.key)?
        {
            return Err(OwnerError::WriterUnavailable);
        }
        Ok(fence)
    }
    /// Final writer/capability fence: any change during the attempt refuses
    /// it. An identical retry captures the then-current state afresh.
    pub(crate) fn final_fence(
        &self,
        active: ActiveWriter,
        db: &DeviceDatabase,
        note: &Note,
        attempt: Fence,
    ) -> Result<(), OwnerError> {
        let fence =
            self.writers
                .fence(active.container, db, active.slot.key, active.slot.client_id)?;
        if fence != attempt || owned_end(note, &active.slot, fence)?.is_none() {
            return Err(OwnerError::WriterUnavailable);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn var(mut n: u64, out: &mut Vec<u8>) {
        while n >= 128 {
            out.push((n as u8 & 127) | 128);
            n >>= 7;
        }
        out.push(n as u8);
    }
    #[test]
    fn exhausted_and_gapped_slots_are_retired_instead_of_reused() {
        for exhausted in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("test.db");
            let mut db = DeviceDatabase::open(&path).unwrap();
            let key = NoteKey {
                base: [1; 32],
                audience: [2; 32],
                note: [3; 32],
            };
            rusqlite::Connection::open(&path)
                .unwrap()
                .execute("INSERT INTO base_writer_phase VALUES(?1,0)", [key.base])
                .unwrap();
            let d = DeviceWriterDeclaration {
                account: [4; 32],
                device: [5; 32],
                nonce: [6; 32],
            };
            let client_id = d.client_id(scope(key));
            let slot = WriterSlot {
                key,
                account: d.account,
                device: d.device,
                slot: 0,
                nonce: d.nonce,
                client_id,
                retired: false,
            };
            db.insert_writer_slot(&slot).unwrap();
            let mut bytes = vec![1, if exhausted { 1 } else { 3 }];
            var(client_id, &mut bytes);
            bytes.extend([0, 0]);
            if exhausted {
                var(u32::MAX as u64, &mut bytes);
            } else {
                bytes.extend([2, 10, 2, 0, 2]);
            }
            bytes.push(0);
            let mut note = Note::new().unwrap();
            note.apply_update(&bytes).unwrap();
            assert_eq!(
                note.writer_end(client_id).unwrap(),
                if exhausted { Some(u32::MAX) } else { None }
            );
            let owner = Owner::default();
            let next = owner
                .allocate_writer(
                    "w",
                    ContainerId([1; 16]),
                    1,
                    &mut db,
                    key,
                    ([4; 32], [5; 32]),
                    &note,
                    None,
                )
                .unwrap();
            assert_ne!(next.slot.client_id, client_id);
            assert_eq!(next.slot.slot, 1);
            assert!(db.writer_slots(key, [4; 32], [5; 32]).unwrap()[0].retired);
        }
    }
    #[test]
    fn known_collision_retries_before_exposure_and_failed_mapping_exposes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let mut db = DeviceDatabase::open(&path).unwrap();
        let raw = rusqlite::Connection::open(&path).unwrap();
        let key = NoteKey {
            base: [1; 32],
            audience: [2; 32],
            note: [3; 32],
        };
        raw.execute(
            "INSERT INTO base_writer_phase(base,phase) VALUES (?1,0)",
            [key.base],
        )
        .unwrap();
        let d = DeviceWriterDeclaration {
            account: [4; 32],
            device: [5; 32],
            nonce: [6; 32],
        };
        let mut note = Note::with_writer(d.client_id(scope(key))).unwrap();
        note.append_paragraph("existing").unwrap();
        let owner = Owner::default();
        owner
            .writers
            .test_nonces
            .lock()
            .unwrap()
            .extend([[6; 32], [7; 32]]);
        let allocated = owner
            .allocate_writer(
                "w",
                ContainerId([1; 16]),
                1,
                &mut db,
                key,
                ([4; 32], [5; 32]),
                &note,
                None,
            )
            .unwrap();
        assert_eq!(allocated.slot.nonce, [7; 32]);
        assert_eq!(db.writer_slots(key, [4; 32], [5; 32]).unwrap().len(), 1);
        let other = NoteKey {
            note: [8; 32],
            ..key
        };
        raw.execute_batch("CREATE TRIGGER fail_slot BEFORE INSERT ON note_writer_slots BEGIN SELECT RAISE(ABORT,'disk'); END;").unwrap();
        assert!(
            owner
                .allocate_writer(
                    "other",
                    ContainerId([1; 16]),
                    1,
                    &mut db,
                    other,
                    ([4; 32], [5; 32]),
                    &Note::new().unwrap(),
                    None,
                )
                .is_err()
        );
        assert!(db.writer_slots(other, [4; 32], [5; 32]).unwrap().is_empty());
        assert!(owner.writers.active.lock().unwrap().is_empty());
    }
    struct Accepted(u64);
    impl AcceptedBindings for Accepted {
        fn binding(
            &self,
            _: &DeviceDatabase,
            _: NoteKey,
            client_id: u64,
        ) -> Result<BindingRead, WriterUnavailable> {
            Ok(BindingRead {
                revision: 1,
                binding: (client_id == self.0).then_some(VerifiedWriterBinding {
                    account: [8; 32],
                    device: [8; 32],
                    nonce: [8; 32],
                    client_id,
                    accepted_end: 3,
                }),
            })
        }
    }
    #[test]
    fn accepted_owner_of_an_unexposed_candidate_regenerates_without_pausing_the_note() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let mut db = DeviceDatabase::open(&path).unwrap();
        let key = NoteKey {
            base: [1; 32],
            audience: [2; 32],
            note: [3; 32],
        };
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute("INSERT INTO base_writer_phase VALUES(?1,1)", [key.base])
            .unwrap();
        let taken = DeviceWriterDeclaration {
            account: [4; 32],
            device: [5; 32],
            nonce: [6; 32],
        }
        .client_id(scope(key));
        let owner = Owner::default();
        owner.install_binding_reader(ContainerId([1; 16]), Arc::new(Accepted(taken)));
        owner
            .writers
            .test_nonces
            .lock()
            .unwrap()
            .extend([[6; 32], [7; 32]]);
        let allocated = owner
            .allocate_writer(
                "w",
                ContainerId([1; 16]),
                1,
                &mut db,
                key,
                ([4; 32], [5; 32]),
                &Note::new().unwrap(),
                None,
            )
            .unwrap();
        assert_eq!(allocated.slot.nonce, [7; 32]);
        assert_eq!(db.writer_reservations(key).unwrap(), vec![allocated.slot]);
    }
}
