//! Device-local policy for kept encrypted states.
use crate::base::{Base, BaseWeak};
use crate::objects;
use crate::sync::PostedState;
use crate::{Clock, DeviceId, Error, ObjectId};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::time::Duration;
use ts_rs::TS;
use yrs::types::AsPrelim;
use yrs::types::xml::{Xml as _, XmlIn};
use yrs::{Doc, ReadTxn, Text, Transact, TransactionMut, WriteTxn, XmlFragment, XmlOut};

/// The inactivity, minimum interval and background check interval for versions.
#[derive(Clone, Copy, Debug)]
pub struct VersionPolicy {
    /// Idle time after the latest edit on this device.
    pub pause: Duration,
    /// Minimum time between versions of one object on this device.
    pub min_gap: Duration,
    /// How often the background task checks for eligible objects.
    pub tick: Duration,
}

impl VersionPolicy {
    /// Five minutes idle, one hour between versions, checked every minute.
    pub const DEFAULT: Self = Self {
        pause: Duration::from_secs(5 * 60),
        min_gap: Duration::from_secs(60 * 60),
        tick: Duration::from_secs(60),
    };
}

/// A retained state of one object, named only from decrypted local account data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct ObjectVersion {
    /// Sequence of the kept state.
    #[ts(type = "number")]
    pub seq: u64,
    /// Server time in Unix milliseconds.
    #[ts(type = "number")]
    pub at: i64,
    /// Device that posted the kept state.
    #[ts(type = "string")]
    pub device_id: DeviceId,
    /// Name found in this device's decrypted account data, if it is a known full device.
    pub device_name: Option<String>,
}

/// Copies a historical body and fields into an existing document transaction.
/// The live metadata (including location and deletion) is deliberately untouched.
pub(crate) fn copy_content(txn: &mut TransactionMut, historical: &Doc) -> Result<(), Error> {
    let old = historical.transact();
    let nodes: Vec<XmlIn> = old
        .get_xml_fragment(objects::BODY)
        .map(|body| {
            body.children(&old)
                .map(|node| match node {
                    XmlOut::Element(el) => XmlIn::Element(el.as_prelim(&old)),
                    XmlOut::Text(text) => XmlIn::Text(text.as_prelim(&old)),
                    XmlOut::Fragment(fragment) => XmlIn::Fragment(fragment.as_prelim(&old)),
                })
                .collect()
        })
        .unwrap_or_default();
    let old_fields = objects::read_fields(&old);
    let current_fields = objects::read_fields(txn);
    let body = txn.get_or_insert_xml_fragment(objects::BODY);
    let len = body.len(txn);
    if len > 0 {
        body.remove_range(txn, 0, len);
    }
    for node in nodes {
        body.push_back(txn, node);
    }
    let mut changes = old_fields;
    for key in current_fields.keys() {
        if !changes.contains_key(key) {
            changes.insert(key.clone(), serde_json::Value::Null);
        }
    }
    objects::write_fields(txn, &changes)
}

fn same_children<A: XmlFragment, B: XmlFragment>(
    a: &A,
    ta: &yrs::Transaction,
    b: &B,
    tb: &yrs::Transaction,
) -> bool {
    a.len(ta) == b.len(tb)
        && a.children(ta)
            .zip(b.children(tb))
            .all(|(a, b)| match (a, b) {
                (XmlOut::Element(a), XmlOut::Element(b)) => {
                    a.tag() == b.tag()
                        && a.attributes(ta)
                            .collect::<std::collections::HashMap<_, _>>()
                            == b.attributes(tb).collect()
                        && same_children(&a, ta, &b, tb)
                }
                (XmlOut::Text(a), XmlOut::Text(b)) => {
                    a.diff(ta, yrs::types::text::YChange::identity)
                        == b.diff(tb, yrs::types::text::YChange::identity)
                }
                (XmlOut::Fragment(a), XmlOut::Fragment(b)) => same_children(&a, ta, &b, tb),
                _ => false,
            })
}

pub(crate) fn same_content(current: &Doc, version: &Doc) -> bool {
    let a = current.transact();
    let b = version.transact();
    let body_matches = match (
        a.get_xml_fragment(objects::BODY),
        b.get_xml_fragment(objects::BODY),
    ) {
        (Some(x), Some(y)) => same_children(&x, &a, &y, &b),
        (None, None) => true,
        _ => false,
    };
    body_matches && objects::read_fields(&a) == objects::read_fields(&b)
}

/// A cancellable background worker with no strong ownership of the base.
pub(crate) struct VersionTicker {
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    #[cfg(feature = "test-support")]
    hold: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(feature = "test-support")]
    entered: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl VersionTicker {
    pub(crate) fn start(base: BaseWeak, clock: Clock, runtime: &tokio::runtime::Handle) -> Self {
        #[cfg(feature = "test-support")]
        let hold = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        #[cfg(feature = "test-support")]
        let entered = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        #[cfg(feature = "test-support")]
        let (task_hold, task_entered) = (hold.clone(), entered.clone());
        // The first check is due one interval after the base starts, not after the
        // task first runs, so a busy runtime can't push it past a clock that moved on.
        let interval = VersionPolicy::DEFAULT.tick.as_millis() as u64;
        let mut deadline = clock.now_ms().saturating_add(interval);
        let task = runtime.spawn(async move {
            loop {
                clock.sleep_until(deadline).await;
                let Some(base) = base.upgrade() else { break };
                #[cfg(feature = "test-support")]
                if task_hold.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    task_entered.store(true, std::sync::atomic::Ordering::SeqCst);
                    std::future::pending::<()>().await;
                }
                if base.tick_versions_inner().await.is_err() {
                    // A lost connection leaves eligible rows for the next tick.
                }
                deadline = clock.now_ms().saturating_add(interval);
            }
        });
        Self {
            task: Mutex::new(Some(task)),
            #[cfg(feature = "test-support")]
            hold,
            #[cfg(feature = "test-support")]
            entered,
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn hold_next(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        self.entered
            .store(false, std::sync::atomic::Ordering::SeqCst);
        self.hold.store(true, std::sync::atomic::Ordering::SeqCst);
        self.entered.clone()
    }

    pub(crate) async fn stop(&self) {
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Base {
    /// Lists kept states newest first; `before` excludes that sequence. Needs a connection.
    ///
    /// # Errors
    /// Returns [`Error::Network`] offline, or a server error for an invalid request.
    pub async fn versions(
        &self,
        id: ObjectId,
        before: Option<u64>,
        limit: usize,
    ) -> Result<(Vec<ObjectVersion>, bool), Error> {
        let response = self
            .version_api()?
            .versions(self.id(), id, before, limit)
            .await?;
        Ok((
            response
                .versions
                .into_iter()
                .map(|row| ObjectVersion {
                    seq: row.seq,
                    at: row.at,
                    device_id: row.device_id,
                    device_name: self.version_device_name(row.device_id),
                })
                .collect(),
            response.more,
        ))
    }

    /// Opens a kept encrypted state into a Yjs v1 update for the historical object.
    ///
    /// # Errors
    /// Returns [`Error::Network`] offline, [`Error::NotFound`] for an unknown
    /// sequence, or [`Error::Crypto`] for a body that cannot be opened.
    pub async fn version(&self, id: ObjectId, seq: u64) -> Result<Vec<u8>, Error> {
        let response = self.version_api()?.version(self.id(), id, seq).await?;
        #[cfg(feature = "test-support")]
        self.test_wait_version_fetch().await;
        let doc = self.open_version_body(id, &response.body.0)?;
        let state = doc
            .transact()
            .encode_state_as_update_v1(&Default::default());
        Ok(state)
    }

    /// Restores a historical body and fields as a new local edit, after first
    /// retaining the current content so another restore can undo this one.
    ///
    /// # Errors
    /// Returns [`Error::ReadOnly`] on read-only bases, [`Error::NeedsUpdate`]
    /// on unsupported objects, [`Error::Network`] offline, or an error from
    /// fetching, decrypting or saving the edit.
    pub async fn restore_version(&self, id: ObjectId, seq: u64) -> Result<(), Error> {
        self.version_writable(id)?;
        let body = self.version_api()?.version(self.id(), id, seq).await?;
        #[cfg(feature = "test-support")]
        self.test_wait_version_fetch().await;
        let historical = self.open_version_body(id, &body.body.0)?;
        self.flush().await?;
        let latest = self.version_api()?.versions(self.id(), id, None, 1).await?;
        let already_kept = if let Some(latest) = latest.versions.first() {
            let body = self
                .version_api()?
                .version(self.id(), id, latest.seq)
                .await?;
            let doc = self.open_version_body(id, &body.body.0)?;
            self.current_version_content_matches(id, &doc)?
        } else {
            false
        };
        if !already_kept {
            match self
                .version_sync()
                .ok_or_else(|| Error::Network("base is offline".into()))?
                .post_state_for_restore(id)
                .await?
            {
                PostedState::Stored => {}
                PostedState::Stale | PostedState::Skipped => {
                    return Err(Error::Network("current content could not be kept".into()));
                }
            }
        }
        // An edit concurrent with the restore itself can still lose to its deletion.
        self.restore_content(id, &historical)
    }

    /// Checks all eligible local edits; stale states fetch before another attempt.
    pub(crate) async fn tick_versions_inner(&self) -> Result<(), Error> {
        let _guard = self.version_tick_lock().lock().await;
        let now = self.version_now();
        let policy = VersionPolicy::DEFAULT;
        let ids = self.db()?.version_candidates(
            now,
            policy.pause.as_millis() as i64,
            policy.min_gap.as_millis() as i64,
        )?;
        for id in ids {
            let Some(sync) = self.version_sync() else {
                break;
            };
            match sync.post_state(id).await? {
                PostedState::Stored => self.db()?.version_stored(id, now)?,
                PostedState::Stale | PostedState::Skipped => {}
            }
        }
        Ok(())
    }

    /// Runs one policy check without waiting for an actual clock deadline.
    #[cfg(feature = "test-support")]
    pub async fn tick_versions(&self) -> Result<(), Error> {
        self.tick_versions_inner().await
    }
}
