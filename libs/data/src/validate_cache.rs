//! A bounded cache of compiled record validators.
//!
//! A revision is the content address of immutable definition bytes, and its
//! pinned dependencies are content addressed too, so one revision compiles to
//! the same validator in every scope and the cache needs no invalidation.
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
};

use crate::{CompiledType, DataError, RevisionId, validate};

pub const DEFAULT_CAPACITY: usize = 64;

pub struct ValidatorCache {
    capacity: usize,
    inner: Mutex<Lru>,
}

#[derive(Default)]
struct Lru {
    tick: u64,
    entries: HashMap<RevisionId, (Arc<validate::Compiled>, u64)>,
}

impl ValidatorCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: Mutex::new(Lru::default()),
        }
    }

    /// The validator for `ct.revision`, compiling it outside the lock on a miss.
    pub fn get(&self, ct: &CompiledType) -> Result<Arc<validate::Compiled>, DataError> {
        if let Some(found) = self.lookup(ct.revision) {
            return Ok(found);
        }
        let compiled = Arc::new(validate::Compiled::new(
            &ct.effective_schema,
            &ct.resources,
        )?);
        let mut lru = self.lock();
        lru.tick += 1;
        let tick = lru.tick;
        if !lru.entries.contains_key(&ct.revision) && lru.entries.len() >= self.capacity {
            let oldest = lru
                .entries
                .iter()
                .min_by_key(|(_, (_, used))| *used)
                .map(|(revision, _)| *revision);
            if let Some(oldest) = oldest {
                lru.entries.remove(&oldest);
            }
        }
        let entry = lru
            .entries
            .entry(ct.revision)
            .or_insert_with(|| (compiled, tick));
        entry.1 = tick;
        Ok(entry.0.clone())
    }

    pub fn len(&self) -> usize {
        self.lock().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lookup(&self, revision: RevisionId) -> Option<Arc<validate::Compiled>> {
        let mut lru = self.lock();
        lru.tick += 1;
        let tick = lru.tick;
        let (compiled, used) = lru.entries.get_mut(&revision)?;
        *used = tick;
        Some(compiled.clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Lru> {
        // The map holds only finished validators; a panic elsewhere cannot leave it torn.
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

static SHARED: LazyLock<ValidatorCache> = LazyLock::new(|| ValidatorCache::new(DEFAULT_CAPACITY));

/// The process-wide cache used by mutation checks.
pub fn shared() -> &'static ValidatorCache {
    &SHARED
}
