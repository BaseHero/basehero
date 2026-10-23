//! The own base's control progress, apart from its content. The control feed
//! reads only control-route events, judges each with the metadata-only
//! `ControlSpine` (M, never K) exactly as `History` would, and keeps one fact
//! per judged control. It may run ahead of content, which keeps its single
//! ordered cursor and never passes a control the feed has not judged: a
//! removal or rekey applies to control state even while content waits for a
//! key it cannot open yet.
//!
//! Nothing a scan judges is kept until its coverage is established: every
//! raw control, rejected and repeated ones included, links to the one before
//! it from this device's durable raw checkpoint, and the last reaches the
//! raw control of one endpoint opening whose head a receipt under the base's
//! pinned hosting root names. Every page of a scan must name that same
//! endpoint. A short page, a missing link or an unauthenticated endpoint is
//! missing evidence: the scan waits and commits nothing. Facts, first-use
//! IDs, the cursor and seal waits then commit together.
//!
//! An accepted rekey leaves a durable seal-set wait. Its set is opened with
//! M, this account's seal in it authenticated against the account's verified
//! history and opened with the accepted personal key, and the key installed
//! in the local keyring; content then resumes in order.
pub use bh_storage::control_facts::{ControlCursor, ControlFact, SealWait};

use crate::{
    ContainerId, Owner, OwnerError,
    base_keys::{BaseKeyPurpose, SealHeader, open_seal},
    incoming::{LogId, LogKind, StopReason},
    keyring,
    own_base::OwnBaseError,
};
use bh_account::{
    AccountId, DeviceId, Head as AccountHead, VerifiedAccount,
    journal::{AccountJournal, PendingSetupProtector},
    local_seal::LocalKeyPurpose,
    owner::{AccountCapability, AccountOwner},
    platform::DeviceKeyStore,
};
use bh_crypto::{Secret, hash};
use bh_event::{
    ControlChange, ControlSpine, ControlState, HistoryLookup, LookupError, Outcome, Seen,
    account_run::{apply_copies, base_account, encode_copies},
    key_id,
    rekey::{SealSetRef, rekey_seal_set},
};
use bh_storage::{DeviceDatabase, StoreError, sync_state::LOG_BASE};
use bh_sync::{
    BaseId, BodyObject, Commitment, Digest, EventId, Head, OpaqueEvent, OrderState, Route,
    canonical::RawControlHead,
    receipt::{self, RECEIPT_LEN},
    referenced_body,
};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Controls in one full read page; a shorter page ends the read.
pub const CONTROL_PAGE: usize = 64;

/// One read of a scan: the control-route events after the scan's position,
/// in order, each with its body (None where the server has none), and the
/// endpoint the read was made against with the hosting receipt for its head.
pub struct ControlPage {
    pub items: Vec<(Commitment, OpaqueEvent, Option<Vec<u8>>)>,
    pub endpoint: OrderState,
    pub receipt: Option<[u8; RECEIPT_LEN]>,
}

/// What a page left the scan needing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanStep {
    /// A full page that has not reached the endpoint: read on after
    /// [`ControlScan::after`].
    More,
    /// The endpoint is reached: commit with [`Owner::commit_controls`].
    Complete,
}

/// Why a scan ends without committing anything. The durable state is
/// unchanged; a later scan starts again from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanError {
    /// Evidence is missing or does not prove itself: no receipt for the
    /// endpoint under the pinned root, a page naming another endpoint, a
    /// control missing before the next, or a short page before the
    /// endpoint's raw control. Read again later.
    Unavailable,
    /// A control needs what this device lacks (`UnavailablePause`) or a
    /// newer build (`UnsupportedPause`).
    Paused(Outcome),
}

/// What committing a scan did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlStep {
    /// Every control through `covered` is judged; the last is at `control`.
    Committed { control: u64, covered: u64 },
    /// An authenticated contradiction stopped this base.
    Stopped,
}

/// Why a rekey's key was not installed. The wait stays in every case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallError {
    /// Locked, stale or busy: retry later.
    Unavailable,
    /// No seal in the committed set is for this account's accepted key.
    NotSealedToThisDevice,
    /// Bytes other than the committed set, or a seal that does not verify.
    Invalid,
}

fn fact_head(position: u64, hash: [u8; 32]) -> Head {
    Head {
        position,
        hash: Digest(hash),
    }
}

fn raw_head(cursor: &ControlCursor) -> RawControlHead {
    RawControlHead {
        position: cursor.position,
        node_hash: Digest(cursor.node_hash),
    }
}

/// The spine and the base's copy of the account after the stored facts.
fn resume(
    db: &DeviceDatabase,
    base: [u8; 32],
    anchor: &VerifiedAccount,
    root: [u8; 32],
    cursor: &ControlCursor,
) -> Result<Judging, OwnerError> {
    let last = db
        .control_fact_at(base, cursor.position)?
        .filter(|f| f.position == cursor.position && f.head_hash == cursor.head_hash)
        .ok_or(StoreError::CorruptSyncState)?;
    let records = db.control_account_changes(base, cursor.position)?;
    let view = base_account(anchor, &records, &root).map_err(|_| OwnerError::Unavailable)?;
    if view.head()
        != (AccountHead {
            position: last.account.0,
            hash: last.account.1,
        })
    {
        return Err(StoreError::CorruptSyncState.into());
    }
    let order = OrderState::new(raw_head(cursor), 0, Digest([0; 32]))
        .map_err(|_| StoreError::CorruptSyncState)?;
    if order.head(BaseId(base)) != fact_head(cursor.position, cursor.head_hash) {
        return Err(StoreError::CorruptSyncState.into());
    }
    let spine = ControlSpine::resume(ControlState {
        base: BaseId(base),
        creator: anchor.id(),
        hosting_root: root,
        metadata_id: cursor.metadata_id,
        epoch: last.epoch,
        floor: last.floor,
        control: fact_head(last.control.0, last.control.1),
        control_digest: last.control_digest,
        control_head: fact_head(cursor.position, cursor.head_hash),
        order,
        account: view.head(),
    });
    Ok(Judging { spine, view, last })
}

/// The spine, the base's copy of the account and the last fact, as judged
/// so far in a scan.
struct Judging {
    spine: ControlSpine,
    view: VerifiedAccount,
    last: ControlFact,
}

/// One scan of a base's controls from this device's durable cursor to one
/// authenticated endpoint. Built by [`Owner::control_scan`], fed pages in
/// order, and committed by [`Owner::commit_controls`] once complete.
pub struct ControlScan {
    database: Arc<Mutex<DeviceDatabase>>,
    log: LogId,
    base: BaseId,
    root: [u8; 32],
    anchor: VerifiedAccount,
    /// The durable cursor this scan started from.
    start: Option<ControlCursor>,
    /// The last raw control linked so far, and its position.
    raw: RawControlHead,
    after: u64,
    /// The first page's endpoint, its authenticated head and receipt.
    endpoint: Option<(OrderState, Head, [u8; RECEIPT_LEN])>,
    judging: Option<Judging>,
    facts: Vec<ControlFact>,
    waits: Vec<SealWait>,
    /// IDs this scan used first, with their digests.
    ids: HashMap<[u8; 32], [u8; 32]>,
    /// An authenticated contradiction: an endpoint against what this device
    /// verified proves it at once; a control's, once the endpoint covers
    /// that control. Judging stops at it.
    contradiction: bool,
    complete: bool,
}

impl ControlScan {
    /// The position the next read starts after: never the content cursor.
    pub fn after(&self) -> u64 {
        self.after
    }

    /// The endpoint `page` names, authenticated under the pinned root and
    /// equal to this scan's first.
    fn endpoint(&mut self, page: &ControlPage) -> Result<(OrderState, Head), ScanError> {
        let receipt = page.receipt.ok_or(ScanError::Unavailable)?;
        let head = receipt::verify(&self.root, self.base, &receipt)
            .map(|r| r.head())
            .map_err(|_| ScanError::Unavailable)?;
        if page.endpoint.head(self.base) != head {
            return Err(ScanError::Unavailable);
        }
        match self.endpoint {
            Some((frozen, at, _)) if (frozen, at) == (page.endpoint, head) => {}
            Some(_) => return Err(ScanError::Unavailable),
            None => {
                let raw = page.endpoint.raw_control();
                // An endpoint before this device's raw checkpoint proves
                // nothing new. One that reaches it with an earlier last
                // control, another raw control at its position, or a raw
                // control inside the covered range contradicts what an
                // earlier endpoint proved.
                if raw.position < self.raw.position {
                    if page.endpoint.position() < self.raw.position {
                        return Err(ScanError::Unavailable);
                    }
                    self.contradiction = true;
                }
                if raw.position == self.raw.position && raw != self.raw {
                    self.contradiction = true;
                }
                if self.receipt_covered(raw.position) || self.remembered_conflict(head)? {
                    self.contradiction = true;
                }
                self.endpoint = Some((page.endpoint, head, receipt));
            }
        }
        Ok((page.endpoint, head))
    }

    /// Whether `position` lies after the last raw control of this device's
    /// covered endpoint and within it: a receipt proved no control there.
    fn receipt_covered(&self, position: u64) -> bool {
        self.start.as_ref().is_some_and(|start| {
            start.covered.raw_control().position < position && position <= start.covered.position()
        })
    }

    /// Whether this device verified a different head at `head`'s position,
    /// through content or a judged control.
    fn remembered_conflict(&self, head: Head) -> Result<bool, ScanError> {
        let db = self.database.lock().map_err(|_| ScanError::Unavailable)?;
        let seen = db
            .log_seen(LOG_BASE, self.base.0, head.position)
            .map_err(|_| ScanError::Unavailable)?
            .map(|row| row.head_hash);
        let judged = db
            .control_fact(self.base.0, head.position)
            .map_err(|_| ScanError::Unavailable)?
            .map(|fact| fact.head_hash);
        Ok([seen, judged]
            .into_iter()
            .flatten()
            .any(|known| known != head.hash.0))
    }

    /// Take the next page: link each raw control, judge it with M, and
    /// report whether the endpoint is reached. `metadata` is the base's M.
    pub fn page(
        &mut self,
        metadata: &Secret<32>,
        page: ControlPage,
    ) -> Result<ScanStep, ScanError> {
        if self.complete {
            return Err(ScanError::Unavailable);
        }
        let judged = self.contradiction;
        let (endpoint, _) = self.endpoint(&page)?;
        if self.contradiction && !judged {
            self.complete = true;
            return Ok(ScanStep::Complete);
        }
        let full = page.items.len() == CONTROL_PAGE;
        for (ordered, event, body) in page.items {
            let position = ordered.head().position;
            let body_matches = body.as_ref().is_none_or(|body| {
                BodyObject::new(body.clone())
                    .ok()
                    .zip(referenced_body(&event).ok())
                    .is_some_and(|(object, named)| object.commitment() == named)
            });
            if ordered.base() != self.base
                || ordered.route() != Route::Control
                || position <= self.after
                || position > endpoint.position()
                || ordered.verify_body(&event).is_err()
                || !body_matches
                || ordered.before().raw_control() != self.raw
            {
                return Err(ScanError::Unavailable);
            }
            self.raw = ordered.after().raw_control();
            self.after = position;
            // A control where a receipt proved none, or where this device
            // verified another head: proven once the endpoint covers it.
            if !self.contradiction
                && (self.receipt_covered(position) || self.remembered_conflict(ordered.head())?)
            {
                self.contradiction = true;
            }
            if !self.contradiction {
                self.judge(metadata, &ordered, &event, body.as_deref())?;
            }
        }
        if self.raw == endpoint.raw_control() {
            self.complete = true;
            Ok(ScanStep::Complete)
        } else if full {
            Ok(ScanStep::More)
        } else {
            Err(ScanError::Unavailable)
        }
    }

    fn judge(
        &mut self,
        metadata: &Secret<32>,
        ordered: &Commitment,
        event: &OpaqueEvent,
        body: Option<&[u8]>,
    ) -> Result<(), ScanError> {
        let head = ordered.head();
        let digest = ordered.event_digest().0;
        let event_id = ordered.event_id().0;
        let Some(judging) = self.judging.as_mut() else {
            // The feed starts at the base's genesis, verified with History's
            // own checks against the creator's account.
            let Some(body) = body.filter(|_| head.position == 1) else {
                return Err(ScanError::Unavailable);
            };
            let (spine, genesis) =
                ControlSpine::from_genesis(&self.anchor, event, body, metadata, self.root, ordered)
                    .map_err(|_| ScanError::Unavailable)?;
            if genesis.base != self.base
                || genesis.creator != self.anchor.id()
                || genesis.account_head != self.anchor.head()
            {
                return Err(ScanError::Unavailable);
            }
            let fact = ControlFact {
                position: 1,
                head_hash: head.hash.0,
                digest,
                event_id,
                accepted: true,
                control: (1, head.hash.0),
                control_digest: digest,
                account: (self.anchor.head().position, self.anchor.head().hash),
                epoch: Some(genesis.content_key_id),
                epoch_installed: (1, head.hash.0),
                floor: spine.state().floor,
                account_change: None,
            };
            self.facts.push(fact.clone());
            self.ids.insert(event_id, digest);
            self.judging = Some(Judging {
                spine,
                view: self.anchor.clone(),
                last: fact,
            });
            return Ok(());
        };
        let checked = {
            let ids = &self.ids;
            let database = &self.database;
            let base = self.base.0;
            let used = |id: EventId| -> Result<bool, Outcome> {
                if ids.contains_key(&id.0) {
                    return Ok(true);
                }
                let db = database.lock().map_err(|_| Outcome::UnavailablePause)?;
                db.control_first_use(base, id.0)
                    .map(|first| first.is_some())
                    .map_err(|_| Outcome::UnavailablePause)
            };
            match body {
                Some(body) => {
                    match judging
                        .spine
                        .check(&judging.view, event, body, metadata, ordered, &used)
                    {
                        // Only a receipt under the pinned root contradicting a
                        // head of the linked chain is proof; any other stop is
                        // not, and waits.
                        Err(Outcome::IntegrityStop) => Err(
                            if judging
                                .spine
                                .seen_receipt_conflict(
                                    &judging.view,
                                    event,
                                    body,
                                    metadata,
                                    Some(ordered),
                                    &used,
                                )
                                .is_some()
                            {
                                Outcome::IntegrityStop
                            } else {
                                Outcome::UnavailablePause
                            },
                        ),
                        checked => checked,
                    }
                }
                // Without its body only an invalid submission is decided;
                // nothing proves a contradiction without it.
                None => match judging
                    .spine
                    .inspect(&judging.view, event, metadata, ordered, &used)
                {
                    Ok(()) | Err(Outcome::IntegrityStop) => return Err(ScanError::Unavailable),
                    Err(outcome) => Err(outcome),
                },
            }
        };
        // Every raw control's ID is used from here on, whatever its verdict.
        self.ids.entry(event_id).or_insert(digest);
        match checked {
            Ok(effect) => {
                let mut view = judging.view.clone();
                apply_copies(&mut view, &effect.account_copies, &self.root)
                    .map_err(|_| ScanError::Paused(Outcome::UnavailablePause))?;
                if effect.change == ControlChange::Rekey {
                    let body = body.ok_or(ScanError::Unavailable)?;
                    let set = rekey_seal_set(self.base, event, body, metadata)
                        .ok()
                        .flatten()
                        .ok_or(ScanError::Paused(Outcome::UnavailablePause))?;
                    self.waits.push(SealWait {
                        base: self.base.0,
                        key_id: set.key_id,
                        position: head.position,
                        event_id: set.event_id.0,
                        count: set.count,
                        commitment: set.commitment.0,
                    });
                }
                let fact = ControlFact {
                    position: head.position,
                    head_hash: head.hash.0,
                    digest,
                    event_id,
                    accepted: true,
                    control: (head.position, head.hash.0),
                    control_digest: digest,
                    account: (view.head().position, view.head().hash),
                    epoch: effect.epoch_after,
                    epoch_installed: if effect.change == ControlChange::Rekey {
                        (head.position, head.hash.0)
                    } else {
                        judging.last.epoch_installed
                    },
                    floor: effect.floor_after,
                    account_change: Some(encode_copies(&effect.account_copies)),
                };
                judging
                    .spine
                    .apply(effect, ordered)
                    .map_err(|_| ScanError::Unavailable)?;
                judging.view = view;
                judging.last = fact.clone();
                self.facts.push(fact);
            }
            Err(Outcome::Rejected) => {
                judging
                    .spine
                    .apply_rejected(ordered)
                    .map_err(|_| ScanError::Unavailable)?;
                self.facts.push(ControlFact {
                    position: head.position,
                    head_hash: head.hash.0,
                    digest,
                    event_id,
                    accepted: false,
                    account_change: None,
                    ..judging.last.clone()
                });
            }
            // A receipt under the pinned root contradicting a head of the
            // linked chain (`seen_receipt_conflict` above): proven once the
            // endpoint covers this control.
            Err(Outcome::IntegrityStop) => self.contradiction = true,
            Err(pause) => return Err(ScanError::Paused(pause)),
        }
        Ok(())
    }
}

impl Owner {
    /// The position after which the control feed of `log` reads next: 0
    /// before it judged the genesis.
    pub fn control_after(&self, id: ContainerId, log: LogId) -> Result<u64, OwnerError> {
        let database = self.shared_database(id)?;
        let cursor = database
            .lock()
            .expect("container writer lock")
            .control_cursor(log.id)?;
        Ok(cursor.map_or(0, |c| c.position))
    }

    /// The judged control exactly at `position` of `log`, if the feed has one.
    pub fn control_fact(
        &self,
        id: ContainerId,
        log: LogId,
        position: u64,
    ) -> Result<Option<ControlFact>, OwnerError> {
        let database = self.shared_database(id)?;
        let fact = database
            .lock()
            .expect("container writer lock")
            .control_fact(log.id, position)?;
        Ok(fact)
    }

    /// Rekeys whose seal sets are not opened yet.
    pub fn seal_waits(&self, id: ContainerId) -> Result<Vec<SealWait>, OwnerError> {
        let database = self.shared_database(id)?;
        let waits = database
            .lock()
            .expect("container writer lock")
            .seal_waits()?;
        Ok(waits)
    }

    /// The newest verified state a control by this device builds on, as
    /// `copy_context` claims it: at the control feed's covered endpoint
    /// while that is past content, else at content's head. None before the
    /// genesis is verified.
    pub fn verified_copy(
        &self,
        id: ContainerId,
        log: LogId,
    ) -> Result<Option<VerifiedCopy>, OwnerError> {
        let database = self.shared_database(id)?;
        let db = database.lock().expect("container writer lock");
        let progress = db
            .log_progress(LOG_BASE, log.id)?
            .ok_or(OwnerError::NotRegistered)?;
        if let Some(cursor) = db.control_cursor(log.id)?
            && cursor.covered.position() > progress.position
        {
            let last = db
                .control_fact_at(log.id, cursor.position)?
                .ok_or(StoreError::CorruptSyncState)?;
            return Ok(Some(VerifiedCopy {
                account: last.account,
                through: cursor.covered.position(),
            }));
        }
        Ok(progress.account.map(|account| VerifiedCopy {
            account,
            through: progress.position,
        }))
    }

    /// The digest the base log first ordered under control-route ID
    /// `event_id`, as content or the control feed verified it.
    pub fn ordered_control(
        &self,
        id: ContainerId,
        log: LogId,
        event_id: [u8; 32],
    ) -> Result<Option<[u8; 32]>, OwnerError> {
        let database = self.shared_database(id)?;
        let db = database.lock().expect("container writer lock");
        match db.log_event_digest(LOG_BASE, log.id, event_id)? {
            Some(digest) => Ok(Some(digest)),
            None => Ok(db.control_first_use(log.id, event_id)?),
        }
    }

    /// The position the control feed's verified coverage of `log` reaches;
    /// None before its first scan committed.
    pub fn control_coverage(&self, id: ContainerId, log: LogId) -> Result<Option<u64>, OwnerError> {
        let database = self.shared_database(id)?;
        let db = database.lock().expect("container writer lock");
        Ok(coverage(&db, log.id)?.map(|c| c.through))
    }

    /// Start a scan of the own base's controls from the feed's durable
    /// cursor. `anchor` is the creator's account at the head the base
    /// genesis names.
    pub fn control_scan(
        &self,
        id: ContainerId,
        log: LogId,
        anchor: &VerifiedAccount,
    ) -> Result<ControlScan, OwnerError> {
        if log.kind != LogKind::Base {
            return Err(OwnerError::InvalidBatch);
        }
        if !self.anchored(id) {
            return Err(OwnerError::Unbound);
        }
        let base = log.id;
        let database = self.shared_database(id)?;
        let (root, start, judging) = {
            let db = database.lock().expect("container writer lock");
            if db.own_base()?.is_none_or(|own| own.base != base) {
                return Err(OwnerError::Unbound);
            }
            let progress = db
                .log_progress(LOG_BASE, base)?
                .ok_or(OwnerError::NotRegistered)?;
            if progress.stopped.is_some() {
                return Err(OwnerError::Stopped);
            }
            let start = db.control_cursor(base)?;
            let judging = start
                .as_ref()
                .map(|c| resume(&db, base, anchor, progress.hosting_root, c))
                .transpose()?;
            (progress.hosting_root, start, judging)
        };
        Ok(ControlScan {
            database,
            log,
            base: BaseId(base),
            root,
            anchor: anchor.clone(),
            raw: start.as_ref().map_or(RawControlHead::EMPTY, raw_head),
            after: start.as_ref().map_or(0, |c| c.position),
            start,
            endpoint: None,
            judging,
            facts: Vec::new(),
            waits: Vec::new(),
            ids: HashMap::new(),
            contradiction: false,
            complete: false,
        })
    }

    /// Commit a complete scan: its facts, first-use IDs, seal waits and the
    /// cursor at its covered endpoint in one transaction, only once the
    /// spine finishes its coverage at that endpoint. A proven contradiction
    /// stops the base instead.
    pub fn commit_controls(
        &self,
        id: ContainerId,
        scan: ControlScan,
    ) -> Result<ControlStep, OwnerError> {
        if !scan.complete {
            return Err(OwnerError::InvalidBatch);
        }
        if scan.contradiction {
            self.record_stop(id, scan.log, StopReason::Integrity)?;
            return Ok(ControlStep::Stopped);
        }
        let (endpoint, authenticated, receipt) = scan.endpoint.ok_or(OwnerError::InvalidBatch)?;
        let judging = scan.judging.as_ref().ok_or(OwnerError::Unavailable)?;
        let state = judging.spine.state();
        let coverage = judging
            .spine
            .finish_coverage(endpoint, authenticated)
            .map_err(|_| OwnerError::InvalidBatch)?;
        // An older endpoint than this device's coverage adds nothing.
        let (covered, receipt) = match &scan.start {
            Some(start) if start.covered.position() >= coverage.through().position => {
                (start.covered, start.receipt)
            }
            _ => (endpoint, receipt),
        };
        let cursor = ControlCursor {
            position: state.control_head.position,
            head_hash: state.control_head.hash.0,
            node_hash: state.order.raw_control().node_hash.0,
            covered,
            receipt,
            metadata_id: state.metadata_id,
        };
        if scan.facts.is_empty() && scan.start.as_ref() == Some(&cursor) {
            return Ok(ControlStep::Committed {
                control: cursor.position,
                covered: covered.position(),
            });
        }
        let database = self.shared_database(id)?;
        database
            .lock()
            .expect("container writer lock")
            .commit_controls(
                scan.base.0,
                scan.start.as_ref(),
                &scan.facts,
                &cursor,
                &scan.waits,
            )
            .map_err(|e| match e {
                StoreError::StaleProgress => OwnerError::Changed,
                other => other.into(),
            })?;
        Ok(ControlStep::Committed {
            control: cursor.position,
            covered: covered.position(),
        })
    }

    /// The verified control state of `log`, read from the feed's facts.
    /// `anchor` is the creator's account at the head the base genesis names.
    pub fn control_view(
        &self,
        id: ContainerId,
        log: LogId,
        anchor: &VerifiedAccount,
    ) -> Result<VerifiedControlView, OwnerError> {
        let database = self.shared_database(id)?;
        let root = database
            .lock()
            .expect("container writer lock")
            .log_progress(LOG_BASE, log.id)?
            .ok_or(OwnerError::NotRegistered)?
            .hosting_root;
        Ok(VerifiedControlView {
            database,
            base: log.id,
            anchor: anchor.clone(),
            hosting_root: root,
            active: Mutex::default(),
            replays: AtomicUsize::new(0),
        })
    }
}

/// The base's copy of the account a control by this device builds on, and
/// the position its verified state reaches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedCopy {
    pub account: (u64, [u8; 32]),
    pub through: u64,
}

/// A member device of an account.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Author {
    pub account: AccountId,
    pub device: DeviceId,
}

/// The installed content key and where its control installed it, whether
/// or not this device holds the secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CurrentKey {
    pub key_id: [u8; 32],
    pub installed_at: Head,
}

/// A base's verified control state as of any covered position, from the
/// control feed's facts. Coverage reaches the feed's authenticated endpoint,
/// and content this device verified with the same last raw control. Past it
/// every answer is `LookupError`: a wait, never a verdict. No answer reads a
/// per-content row except `seen`, `event_digest` for content IDs. Each
/// lookup takes the container's writer lock briefly: never call one, or
/// `History::prepare` with this view as its lookup, while holding that lock.
pub struct VerifiedControlView {
    database: Arc<Mutex<DeviceDatabase>>,
    base: [u8; 32],
    anchor: VerifiedAccount,
    hosting_root: [u8; 32],
    /// The active devices of the base's copy of the account at each
    /// accepted account head this view verified: one replay per head.
    active: Mutex<HashMap<(u64, [u8; 32]), ActiveDevices>>,
    /// Replays of the base's copy of the account.
    replays: AtomicUsize,
}

/// The active devices of an account at one head.
type ActiveDevices = BTreeSet<DeviceId>;

/// How far the view's answers reach, and how far content verified.
struct Coverage {
    through: u64,
    content: u64,
}

/// How far the control feed's coverage of `base` reaches, if it started:
/// its authenticated endpoint, and further through content this device
/// verified with the same last raw control.
fn coverage(db: &DeviceDatabase, base: [u8; 32]) -> Result<Option<Coverage>, StoreError> {
    let Some(cursor) = db.control_cursor(base)? else {
        return Ok(None);
    };
    let content = db
        .log_progress(LOG_BASE, base)?
        .ok_or(StoreError::CorruptSyncState)?;
    let mut through = cursor.covered.position();
    if content.order.raw_control() == raw_head(&cursor) {
        through = through.max(content.position);
    }
    Ok(Some(Coverage {
        through,
        content: content.position,
    }))
}

impl VerifiedControlView {
    fn db(&self) -> Result<std::sync::MutexGuard<'_, DeviceDatabase>, LookupError> {
        self.database.lock().map_err(|_| LookupError)
    }
    fn coverage(&self, db: &DeviceDatabase) -> Result<Coverage, LookupError> {
        coverage(db, self.base)
            .map_err(|_| LookupError)?
            .ok_or(LookupError)
    }
    /// The last judged control at or before `position`: None at position 0;
    /// `LookupError` past coverage.
    fn fact_at(&self, position: u64) -> Result<Option<ControlFact>, LookupError> {
        if position == 0 {
            return Ok(None);
        }
        let db = self.db()?;
        if position > self.coverage(&db)?.through {
            return Err(LookupError);
        }
        db.control_fact_at(self.base, position)
            .map_err(|_| LookupError)?
            .ok_or(LookupError)
            .map(Some)
    }

    /// Whether `author` was an active device of the base's copy of the
    /// account once the last accepted control at or before `position`
    /// applied.
    pub fn authorised_at(&self, author: Author, position: u64) -> Result<bool, LookupError> {
        let Some(fact) = self.fact_at(position)? else {
            return Ok(false);
        };
        if author.account != self.anchor.id() {
            return Ok(false);
        }
        if let Some(active) = self
            .active
            .lock()
            .map_err(|_| LookupError)?
            .get(&fact.account)
        {
            return Ok(active.contains(&author.device));
        }
        let records = self
            .db()?
            .control_account_changes(self.base, fact.control.0)
            .map_err(|_| LookupError)?;
        self.replays.fetch_add(1, Ordering::Relaxed);
        let view =
            base_account(&self.anchor, &records, &self.hosting_root).map_err(|_| LookupError)?;
        if view.head().position != fact.account.0 || view.head().hash != fact.account.1 {
            return Err(LookupError);
        }
        // A stopped account has no active device.
        let active: ActiveDevices = view
            .active_devices()
            .map(|devices| devices.map(|keys| keys.id()).collect())
            .unwrap_or_default();
        let answer = active.contains(&author.device);
        self.active
            .lock()
            .map_err(|_| LookupError)?
            .insert(fact.account, active);
        Ok(answer)
    }

    /// How many times this view replayed the base's copy of the account.
    #[doc(hidden)]
    pub fn account_replays(&self) -> usize {
        self.replays.load(Ordering::Relaxed)
    }

    /// The global head of the last accepted control at or before `position`.
    pub fn control_head_at(&self, position: u64) -> Result<Option<Head>, LookupError> {
        Ok(self
            .fact_at(position)?
            .map(|f| fact_head(f.control.0, f.control.1)))
    }

    /// The installed content key as of the view's coverage; None while the
    /// epoch is closed.
    pub fn current_key(&self) -> Result<Option<CurrentKey>, LookupError> {
        let through = self.coverage(&*self.db()?)?.through;
        let fact = self.fact_at(through)?.ok_or(LookupError)?;
        Ok(fact.epoch.map(|key_id| CurrentKey {
            key_id,
            installed_at: fact_head(fact.epoch_installed.0, fact.epoch_installed.1),
        }))
    }

    /// The digest of the last accepted control at or before `position`.
    pub fn control_digest_at(&self, position: u64) -> Result<Option<[u8; 32]>, LookupError> {
        Ok(self.fact_at(position)?.map(|f| f.control_digest))
    }

    /// The base's copy of `account` as of `position`; None for an account
    /// the base does not follow.
    pub fn account_head_at(
        &self,
        account: AccountId,
        position: u64,
    ) -> Result<Option<AccountHead>, LookupError> {
        let fact = self.fact_at(position)?;
        if account != self.anchor.id() {
            return Ok(None);
        }
        Ok(fact.map(|f| AccountHead {
            position: f.account.0,
            hash: f.account.1,
        }))
    }
}

impl HistoryLookup for VerifiedControlView {
    /// What content verified at `position`, or at a control position the
    /// feed judged: its head, the accepted control and account after it.
    /// A content position the feed covers but content has not reached is
    /// unavailable.
    fn seen(&self, position: u64) -> Result<Option<Seen>, LookupError> {
        let db = self.db()?;
        let coverage = self.coverage(&db)?;
        if position > coverage.through {
            return Err(LookupError);
        }
        if let Some(row) = db
            .log_seen(LOG_BASE, self.base, position)
            .map_err(|_| LookupError)?
        {
            return Ok(Some(Seen {
                head: fact_head(row.position, row.head_hash),
                control: row.control_digest,
                account: AccountHead {
                    position: row.account_position,
                    hash: row.account_hash,
                },
            }));
        }
        match db
            .control_fact(self.base, position)
            .map_err(|_| LookupError)?
        {
            Some(f) => Ok(Some(Seen {
                head: fact_head(f.position, f.head_hash),
                control: f.control_digest,
                account: AccountHead {
                    position: f.account.0,
                    hash: f.account.1,
                },
            })),
            None if position <= coverage.content => Ok(None),
            None => Err(LookupError),
        }
    }
    /// The first use of a control-route ID among the judged controls, or of
    /// a content ID among what content verified. An ID found in neither is
    /// unused only when content verified everything the view covers.
    fn event_digest(&self, event_id: [u8; 32]) -> Result<Option<Digest>, LookupError> {
        let db = self.db()?;
        let coverage = self.coverage(&db)?;
        if let Some(digest) = db
            .control_first_use(self.base, event_id)
            .map_err(|_| LookupError)?
        {
            return Ok(Some(Digest(digest)));
        }
        if let Some(digest) = db
            .log_event_digest(LOG_BASE, self.base, event_id)
            .map_err(|_| LookupError)?
        {
            return Ok(Some(Digest(digest)));
        }
        if coverage.content >= coverage.through {
            Ok(None)
        } else {
            Err(LookupError)
        }
    }
}

/// An opened, commitment-checked set. Private construction prevents callers
/// from substituting individual seals after the set was checked.
pub struct OpenedSealSet {
    wait: SealWait,
    seals: Vec<Vec<u8>>,
}

/// The seals in `set`, only if it is exactly the set `wait` names for its
/// base, control and key. Other bytes are `Invalid` and never stand in.
pub fn open_seal_set(
    wait: &SealWait,
    metadata: &Secret<32>,
    set: &[u8],
) -> Result<OpenedSealSet, InstallError> {
    let seals = SealSetRef {
        event_id: EventId(wait.event_id),
        key_id: wait.key_id,
        count: wait.count,
        commitment: Digest(wait.commitment),
    }
    .open(metadata, BaseId(wait.base), set)
    .map_err(|_| InstallError::Invalid)?;
    Ok(OpenedSealSet { wait: *wait, seals })
}

fn install_failed(error: OwnBaseError) -> InstallError {
    match error {
        OwnBaseError::Invalid | OwnBaseError::Seal(_) => InstallError::Invalid,
        _ => InstallError::Unavailable,
    }
}

/// Install the key `wait` names from its opened `seals`: this account's
/// seal, authenticated against the account's verified history at the head
/// it names and opened with the accepted personal key, is kept in the local
/// keyring and the wait ends. Returns the key for the caller's memory. All
/// native key use happens with no database guard held.
pub async fn install_sealed_epoch<J, S, P>(
    account: &mut AccountOwner<J, S, P>,
    capability: Arc<AccountCapability>,
    database: Arc<Mutex<DeviceDatabase>>,
    wait: &SealWait,
    opened: &OpenedSealSet,
) -> Result<Secret<32>, InstallError>
where
    J: AccountJournal,
    S: DeviceKeyStore,
    P: PendingSetupProtector,
{
    if opened.wait != *wait {
        return Err(InstallError::Invalid);
    }
    let delivery = {
        let db = database.lock().map_err(|_| InstallError::Unavailable)?;
        if !db
            .seal_waits()
            .map_err(|_| InstallError::Unavailable)?
            .contains(wait)
        {
            return Err(InstallError::Invalid);
        }
        db.personal_delivery()
            .map_err(|_| InstallError::Unavailable)?
    };
    let personal = account
        .open_current_personal(&capability)
        .await
        .map_err(|_| InstallError::Unavailable)?;
    let recipient = hash(&personal.public());
    let found = opened.seals.iter().find_map(|seal| {
        let header = SealHeader::decode(seal).ok()?;
        (header.purpose == BaseKeyPurpose::Content
            && header.base.0 == wait.base
            && header.audience == [0; 32]
            && header.key_id == wait.key_id
            && header.recipient == recipient)
            .then_some((header, seal))
    });
    let (header, seal) = found.ok_or(InstallError::NotSealedToThisDevice)?;
    if header.sender != capability.account_id() {
        return Err(InstallError::Invalid);
    }
    let history = account
        .verified_at(&capability, header.head.position)
        .map_err(|_| InstallError::Unavailable)?;
    if history.head() != header.head {
        return Err(InstallError::Invalid);
    }
    let content =
        open_seal(&history, &header, seal, &personal).map_err(|_| InstallError::Invalid)?;
    if key_id(&content) != wait.key_id {
        return Err(InstallError::Invalid);
    }
    let row = keyring::sealed(
        capability.account_id(),
        wait.base,
        LocalKeyPurpose::Content,
        &content,
        &personal,
    )
    .map_err(install_failed)?;
    let mut db = database.lock().map_err(|_| InstallError::Unavailable)?;
    let rows = db
        .epoch_keys(wait.base)
        .map_err(|_| InstallError::Unavailable)?;
    // Re-read delivery AFTER the rows. Accepted delivery is monotone, so a
    // cross-process rotation during either read is retryable, not a bad seal.
    // The install's compare-and-commit catches a rotation after this check.
    if db
        .personal_delivery()
        .map_err(|_| InstallError::Unavailable)?
        != delivery
    {
        return Err(InstallError::Unavailable);
    }
    // A pre-existing row must authenticate too: INSERT OR IGNORE must not
    // conceal a tampered row behind a newly opened network seal.
    keyring::held(
        &rows,
        capability.account_id(),
        wait.base,
        LocalKeyPurpose::Content,
        wait.key_id,
        &personal,
    )
    .map_err(install_failed)?;
    db.install_epoch_keys(delivery.as_ref(), &[row], || capability.is_current())
        .map_err(|_| InstallError::Unavailable)?;
    db.finish_seal_wait(wait.base, wait.key_id)
        .map_err(|_| InstallError::Unavailable)?;
    Ok(content)
}
