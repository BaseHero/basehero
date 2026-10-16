//! Single-process note host. DeviceDatabase owns the authoritative yrs notes;
//! the coordinator serializes bindings, durable writes and deliveries. The UI
//! cannot nominate an account, base, audience or another window.
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, MutexGuard},
};

use bh_storage::{DeviceDatabase, LocalCommit, NoteKey, StoreError};

/// Issued by an authenticated account/session source, never reconstructed from
/// page-provided values. No production source is installed before admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    pub account: [u8; 32],
    pub key: NoteKey,
}

pub trait AuthoritySource {
    fn bound_scope(&self, window: &str) -> Option<Scope>;
}
impl AuthoritySource for Box<dyn AuthoritySource + Send> {
    fn bound_scope(&self, window: &str) -> Option<Scope> {
        (**self).bound_scope(window)
    }
}

#[derive(Debug)]
pub enum HostError {
    Unbound,
    Changed,
    Store(StoreError),
}
impl From<StoreError> for HostError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

pub struct Opened {
    pub state: Vec<u8>,
    pub generation: u64,
    pub sequence: u64,
    pub writer: Option<crate::writers::WriterLease>,
}
pub struct Ack {
    pub request_id: [u8; 16],
    pub replayed: bool,
}
#[derive(Clone)]
pub struct Delivery {
    pub window: String,
    pub generation: u64,
    pub sequence: u64,
    /// Exact committed local row the snapshot must cover before this sequence
    /// may be delivered as a resync marker.
    pub through_update_id: i64,
    pub update: Vec<u8>,
    /// Full durable Yjs state to merge into the existing editing copy, never
    /// a request to close and recreate it (which would lose unsaved work).
    pub resync: bool,
}
#[derive(Clone, Copy)]
struct Binding {
    scope: Scope,
    generation: u64,
}

/// Per-container binding and delivery-sequence state. Native owner releases
/// this guard while reconstructing or applying yrs updates. It publishes only
/// after SQLite COMMIT, without executing a WebView callback under this guard.
pub struct Coordinator<A> {
    database: Arc<Mutex<DeviceDatabase>>,
    authority: A,
    bindings: HashMap<String, Binding>,
    invalidated: HashSet<String>,
    note_revisions: HashMap<NoteKey, u64>,
    generation: u64,
    sequence: u64,
}
impl<A: AuthoritySource> Coordinator<A> {
    pub fn new(database: DeviceDatabase, authority: A) -> Self {
        Self {
            database: Arc::new(Mutex::new(database)),
            authority,
            bindings: HashMap::new(),
            invalidated: HashSet::new(),
            note_revisions: HashMap::new(),
            generation: 0,
            sequence: 0,
        }
    }
    pub fn generation_counter(&self) -> u64 {
        self.generation
    }
    pub fn carry_generation(&mut self, last: u64) {
        self.generation = last;
    }
    pub fn database(&self) -> MutexGuard<'_, DeviceDatabase> {
        self.database.lock().expect("container database lock")
    }
    pub fn shared_database(&self) -> Arc<Mutex<DeviceDatabase>> {
        Arc::clone(&self.database)
    }
    pub fn authority_mut(&mut self) -> &mut A {
        &mut self.authority
    }
    pub fn authority(&self) -> &A {
        &self.authority
    }
    pub fn note_revision(&self, key: NoteKey) -> u64 {
        *self.note_revisions.get(&key).unwrap_or(&0)
    }
    pub fn open_with_state(
        &mut self,
        window: &str,
        note: [u8; 32],
        generation: u64,
        expected: u64,
        state: Vec<u8>,
    ) -> Result<Opened, HostError> {
        let scope = self.bound_scope(window).ok_or(HostError::Unbound)?;
        if scope.key.note != note {
            return Err(HostError::Unbound);
        }
        if self.note_revision(scope.key) != expected {
            return Err(HostError::Changed);
        }
        self.generation = self.generation.max(generation);
        self.bindings
            .insert(window.into(), Binding { scope, generation });
        Ok(Opened {
            state,
            generation,
            sequence: self.sequence,
            writer: None,
        })
    }
    pub fn is_current(&self, window: &str, generation: u64) -> bool {
        self.bindings.get(window).is_some_and(|binding| {
            binding.generation == generation && self.bound_scope(window) == Some(binding.scope)
        })
    }
    pub fn bound_scope(&self, window: &str) -> Option<Scope> {
        if self.invalidated.contains(window) {
            return None;
        }
        self.authority.bound_scope(window)
    }

    /// The caller installs its event listener *before* opening, and buffers
    /// deliveries until this snapshot/generation has been installed in the UI.
    pub fn open(&mut self, window: &str, note: [u8; 32]) -> Result<Opened, HostError> {
        let generation = self
            .generation
            .checked_add(1)
            .expect("generation exhausted");
        self.open_with_generation(window, note, generation)
    }
    /// Native owner supplies process-unique generations across account switches.
    pub fn open_with_generation(
        &mut self,
        window: &str,
        note: [u8; 32],
        generation: u64,
    ) -> Result<Opened, HostError> {
        let scope = self.bound_scope(window).ok_or(HostError::Unbound)?;
        if scope.key.note != note {
            return Err(HostError::Unbound);
        }
        // A failed read must not change the previous window binding.
        let state = self.database().note_state(scope.key)?;
        self.generation = self.generation.max(generation);
        self.bindings
            .insert(window.into(), Binding { scope, generation });
        Ok(Opened {
            state,
            generation,
            sequence: self.sequence,
            writer: None,
        })
    }

    /// Publish an already durable update. No Yjs or database work here; the
    /// caller owns the affected Note exclusively and has checked native scope.
    pub fn publish_local(
        &mut self,
        window: &str,
        scope: Scope,
        request_id: [u8; 16],
        update: &[u8],
        commit: LocalCommit,
        mut deliver: impl FnMut(Delivery),
    ) -> Ack {
        if !commit.replayed {
            *self.note_revisions.entry(scope.key).or_default() += 1;
            self.sequence = self.sequence.checked_add(1).expect("sequence exhausted");
            for (other_window, other) in &self.bindings {
                if other_window != window
                    && other.scope == scope
                    && self.bound_scope(other_window) == Some(scope)
                {
                    deliver(Delivery {
                        window: other_window.clone(),
                        generation: other.generation,
                        sequence: self.sequence,
                        through_update_id: commit.update_id,
                        update: update.to_vec(),
                        resync: false,
                    });
                }
            }
        }
        Ack {
            request_id,
            replayed: commit.replayed,
        }
    }
    /// Single-thread storage fixture helper. Native owner does NOT use this
    /// path: it moves the working Note outside container and writer guards.
    pub fn commit(
        &mut self,
        window: &str,
        generation: u64,
        request_id: [u8; 16],
        update: &[u8],
        mut deliver: impl FnMut(Delivery),
    ) -> Result<Ack, HostError> {
        let binding = self.bindings.get(window).ok_or(HostError::Unbound)?;
        if binding.generation != generation || self.bound_scope(window) != Some(binding.scope) {
            return Err(HostError::Unbound);
        }
        let commit = self
            .database()
            .apply_local_update(binding.scope.key, request_id, update)?;
        Ok(
            self.publish_local(window, binding.scope, request_id, update, commit, |d| {
                deliver(d)
            }),
        )
    }
    pub fn close_generation(&mut self, window: &str, generation: u64) {
        if self
            .bindings
            .get(window)
            .is_some_and(|binding| binding.generation == generation)
        {
            self.close(window);
        }
    }
    pub fn close(&mut self, window: &str) {
        self.bindings.remove(window);
    }
    /// Navigation/destruction cannot reuse a stale session scope. Native
    /// authority must explicitly bind the new surface before allowing it.
    pub fn invalidate(&mut self, window: &str) {
        self.close(window);
        self.invalidated.insert(window.into());
    }
    pub fn allow_bound_window(&mut self, window: &str) {
        self.invalidated.remove(window);
    }
}
