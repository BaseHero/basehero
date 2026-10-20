//! Deduplicated background checkpoint and bounded pending-index backfill work.
//! Failures retain original rows; the next open/commit or registration re-arms
//! failed work without a retry timer or perpetual retries of a corrupt note.
use crate::ContainerId;
use bh_storage::{DeviceDatabase, NoteKey, StoreError};
use std::{
    collections::HashSet,
    sync::{
        Arc, Mutex, Weak,
        mpsc::{self, Receiver, Sender},
    },
    thread,
};

type Database = Arc<Mutex<DeviceDatabase>>;
enum Work {
    Compact(ContainerId, NoteKey, Weak<Mutex<DeviceDatabase>>),
    Backfill(ContainerId, Weak<Mutex<DeviceDatabase>>),
    Stop,
}
pub struct Scheduler {
    sender: Sender<Work>,
    active: Arc<Mutex<HashSet<(ContainerId, NoteKey)>>>,
    backfilling: Arc<Mutex<HashSet<ContainerId>>>,
}
impl Default for Scheduler {
    fn default() -> Self {
        let (sender, receiver) = mpsc::channel::<Work>();
        let active = Arc::new(Mutex::new(HashSet::new()));
        let backfilling = Arc::new(Mutex::new(HashSet::new()));
        let receiver = Arc::new(Mutex::new(receiver));
        // Two process workers: a large note or one account's v5 migration
        // cannot monopolise every account's background progress. Each SQL
        // section reads at most one 256-row/256-KiB page or backfill batch.
        for n in 0..2 {
            let rx = Arc::clone(&receiver);
            let active = Arc::clone(&active);
            let backfilling = Arc::clone(&backfilling);
            let sender = sender.clone();
            thread::Builder::new()
                .name(format!("bh-local-compaction-{n}"))
                .spawn(move || run_worker(rx, sender, active, backfilling))
                .expect("background compaction worker");
        }
        Self {
            sender,
            active,
            backfilling,
        }
    }
}
impl Drop for Scheduler {
    fn drop(&mut self) {
        // Worker-held senders keep the channel connected after this sender drops.
        for _ in 0..2 {
            let _ = self.sender.send(Work::Stop);
        }
    }
}
impl Scheduler {
    pub fn schedule_backfill(&self, id: ContainerId, database: &Database) {
        let mut active = self.backfilling.lock().expect("backfill set lock");
        if !active.insert(id) {
            return;
        }
        if self
            .sender
            .send(Work::Backfill(id, Arc::downgrade(database)))
            .is_err()
        {
            active.remove(&id);
        }
    }
    pub fn schedule(&self, id: ContainerId, key: NoteKey, database: &Database) {
        let mut active = self.active.lock().expect("compaction set lock");
        if !active.insert((id, key)) {
            return;
        }
        if self
            .sender
            .send(Work::Compact(id, key, Arc::downgrade(database)))
            .is_err()
        {
            active.remove(&(id, key));
        }
    }
}
fn run_worker(
    receiver: Arc<Mutex<Receiver<Work>>>,
    sender: Sender<Work>,
    active: Arc<Mutex<HashSet<(ContainerId, NoteKey)>>>,
    backfilling: Arc<Mutex<HashSet<ContainerId>>>,
) {
    loop {
        let next = receiver.lock().expect("compaction receiver lock").recv();
        let Ok(work) = next else { break };
        match work {
            Work::Stop => break,
            Work::Compact(id, key, weak) => {
                if let Some(db) = weak.upgrade() {
                    let _ = compact(&db, key);
                }
                active
                    .lock()
                    .expect("compaction set lock")
                    .remove(&(id, key));
            }
            Work::Backfill(id, weak) => {
                let step = weak.upgrade().map(|db| {
                    db.lock()
                        .expect("container writer lock")
                        .backfill_pending_scope(256)
                });
                // A successful incomplete batch yields behind other work.
                // Failure drops the active entry; the next open/registration
                // re-arms it, rather than spinning on a broken database.
                if matches!(step, Some(Ok(false))) && sender.send(Work::Backfill(id, weak)).is_ok()
                {
                    continue;
                }
                backfilling.lock().expect("backfill set lock").remove(&id);
            }
        }
    }
}
fn compact(database: &Database, key: NoteKey) -> Result<(), StoreError> {
    let seed = {
        let db = database.lock().expect("container writer lock");
        if !db.checkpoint_due(key)? {
            return Ok(());
        }
        db.begin_checkpoint(key)?
    };
    let Some(seed) = seed else { return Ok(()) };
    let mut job = seed.start()?; // decode the prior checkpoint outside guards
    loop {
        let page = database
            .lock()
            .expect("container writer lock")
            .checkpoint_page(&job, 256)?;
        if page.is_empty() {
            break;
        }
        job.apply_page(&page)?;
    }
    if let Some(encoded) = job.finish()? {
        database
            .lock()
            .expect("container writer lock")
            .publish_checkpoint(&encoded)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::Scheduler;
    use std::{
        sync::Arc,
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn dropping_scheduler_stops_its_workers() {
        // The workers alone retain this Arc after the scheduler is dropped.
        // A clone of the work sender in each worker otherwise keeps recv alive.
        let scheduler = Scheduler::default();
        let workers = Arc::downgrade(&scheduler.active);
        drop(scheduler);
        let deadline = Instant::now() + Duration::from_secs(2);
        while workers.upgrade().is_some() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            workers.upgrade().is_none(),
            "compaction workers outlived their scheduler"
        );
    }
}
