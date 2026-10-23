//! The first device's setup prefix carries the home's confirmation times, so
//! its maturity matches the home's whichever it reached first.
use std::future::Future;
use std::path::PathBuf;

#[allow(dead_code)]
#[path = "support/protector.rs"]
mod protector;
#[path = "support/store.rs"]
mod store;

use bh_account::journal::{
    AccountJournal, HistoryCursor, HistoryPage, InitialBootstrapRecord, JournalError,
    JournaledAccount, JournaledDevice, PendingSetupRecord, StagedAdmission,
};
use bh_account::owner::{
    AccountCapability, AccountGeneration, AccountLoad, OwnerError, SetupError, SetupStatus,
};
use bh_account::platform::ControlKeyPolicy;
use bh_account::recovery::Password;
use bh_account::storage::DeviceJournal;
use bh_account::{
    AccountId, ConfirmedTime, DeviceId, Error, Head, REMOVAL_WAIT_MS, VerifiedAccount,
};
use protector::PlainProtector;
use rusqlite::{Connection, OptionalExtension};
use store::FakeStore;

type Owner = bh_account::owner::AccountOwner<DeviceJournal, FakeStore, PlainProtector>;
type Evidence = [(ConfirmedTime, Vec<u8>); 2];

fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
    {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => panic!("synthetic adapter unexpectedly pending"),
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    path: PathBuf,
    generation: AccountGeneration,
    store: FakeStore,
}
impl Harness {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let generation = AccountGeneration::new();
        Self {
            path: dir.path().join("account.sqlite"),
            _dir: dir,
            store: FakeStore::new(generation.clone()),
            generation,
        }
    }
    fn owner(&self) -> Owner {
        bh_account::owner::AccountOwner::new(
            self.journal(),
            self.store.clone(),
            PlainProtector,
            self.generation.clone(),
        )
    }
    fn journal(&self) -> DeviceJournal {
        DeviceJournal::open(&self.path).unwrap()
    }
    fn raw(&self) -> Connection {
        Connection::open(&self.path).unwrap()
    }
    fn count(&self, sql: &str) -> i64 {
        self.raw().query_row(sql, [], |r| r.get(0)).unwrap()
    }
    fn projection(&self) -> Option<(i64, i64, Vec<u8>)> {
        self.raw()
            .query_row(
                "SELECT epoch,through_position,summary FROM account_projection",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .unwrap()
    }
    fn times(&self) -> Vec<Option<ConfirmedTime>> {
        self.journal()
            .history_prefix(None, 256)
            .unwrap()
            .unwrap()
            .times
    }
}

fn begin(owner: &mut Owner) -> SetupStatus {
    ready(owner.begin_first_device(
        ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        &Password::new("correct horse battery staple").unwrap(),
    ))
    .unwrap()
}
fn activate(owner: &mut Owner) -> AccountCapability {
    match ready(owner.activate()).unwrap() {
        AccountLoad::Active(capability) => capability,
        other => panic!("expected active account, got {other:?}"),
    }
}
fn time(earliest_ms: u64, latest_ms: u64) -> ConfirmedTime {
    ConfirmedTime {
        earliest_ms,
        latest_ms,
    }
}
fn evidence() -> Evidence {
    [
        (time(1_000, 1_005), b"record confirmation".to_vec()),
        (time(1_010, 1_015), b"key confirmation".to_vec()),
    ]
}
fn first(owner: &Owner, cap: &AccountCapability) -> Option<u64> {
    owner.verified(cap).unwrap().added_at(cap.device_id())
}
/// What the home will judge: the setup prefix with its confirmed times.
fn home_view(setup: &SetupStatus, evidence: &Evidence) -> VerifiedAccount {
    let events = &setup.submission;
    VerifiedAccount::replay_timed(
        setup.anchor,
        &[
            (&events[0], None),
            (&events[1], Some(evidence[0].0)),
            (&events[2], Some(evidence[1].0)),
        ],
        setup.head,
    )
    .unwrap()
}
fn stored_rows(h: &Harness) -> Vec<(i64, i64, i64, Vec<u8>)> {
    let raw = h.raw();
    let mut statement = raw
        .prepare("SELECT position,earliest_ms,latest_ms,confirmation FROM account_confirmations ORDER BY position")
        .unwrap();
    statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}
fn expected_rows() -> Vec<(i64, i64, i64, Vec<u8>)> {
    vec![
        (2, 1_000, 1_005, b"record confirmation".to_vec()),
        (3, 1_010, 1_015, b"key confirmation".to_vec()),
    ]
}
fn signed_addition(owner: &mut Owner, cap: &AccountCapability, seed: u8) -> Vec<u8> {
    let keys =
        bh_account::DevicePublicKeys::new([seed; 32], [seed + 1; 32], [seed + 2; 1216]).unwrap();
    let request = owner.prepare_add_device(cap, keys).unwrap();
    ready(owner.sign_control(cap, &request))
        .unwrap()
        .as_bytes()
        .to_vec()
}

#[test]
fn offline_kit_save_then_home_backfills_setup_times() {
    let h = Harness::new();
    let mut owner = h.owner();
    let setup = begin(&mut owner);
    owner.confirm_kit_saved().unwrap();
    let cap = activate(&mut owner);
    assert_eq!(first(&owner, &cap), None, "offline setup is untimed");
    let before = h.projection().unwrap();

    owner
        .confirm_home_ordered(setup.head, Some(evidence()))
        .unwrap();
    assert!(h.journal().pending_setup().unwrap().is_none());
    assert_eq!(stored_rows(&h), expected_rows());
    assert_eq!(
        h.times(),
        vec![None, Some(evidence()[0].0), Some(evidence()[1].0)],
        "genesis is never timed"
    );
    let after = h.projection().unwrap();
    assert_ne!(after.0, before.0, "rebuilt on a fresh epoch");
    assert_eq!(after.1, 3);
    // The live owner now judges maturity exactly as the home does.
    assert!(cap.is_current());
    let home = home_view(&setup, &evidence());
    assert_eq!(first(&owner, &cap), Some(1_005));
    assert_eq!(home.added_at(cap.device_id()), Some(1_005));
    assert!(
        owner
            .verified(&cap)
            .unwrap()
            .is_mature(cap.device_id(), 1_005 + REMOVAL_WAIT_MS)
    );

    // Reopen from the stored index, then from a full rebuild: both agree.
    drop(owner);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    assert_eq!(first(&owner, &cap), Some(1_005));
    assert_eq!(
        owner
            .verified_at(&cap, 2)
            .unwrap()
            .added_at(cap.device_id()),
        Some(1_005)
    );
    drop(owner);
    h.raw()
        .execute("DELETE FROM account_projection", [])
        .unwrap();
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    assert_eq!(first(&owner, &cap), Some(1_005));
    assert_eq!(
        h.projection().unwrap().2,
        after.2,
        "rebuild agrees with backfill"
    );
}

#[test]
fn reaching_the_home_first_commits_setup_timed() {
    let h = Harness::new();
    let mut owner = h.owner();
    let setup = begin(&mut owner);
    owner
        .confirm_home_ordered(setup.head, Some(evidence()))
        .unwrap();
    assert_eq!(stored_rows(&h), expected_rows());
    assert_eq!(
        h.times(),
        vec![None, Some(evidence()[0].0), Some(evidence()[1].0)]
    );
    // A retried answer is idempotent; the kit save then completes setup.
    owner
        .confirm_home_ordered(setup.head, Some(evidence()))
        .unwrap();
    owner.confirm_kit_saved().unwrap();
    assert!(h.journal().pending_setup().unwrap().is_none());
    assert_eq!(stored_rows(&h), expected_rows());
    let cap = activate(&mut owner);
    assert_eq!(first(&owner, &cap), Some(1_005));
    drop(owner);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    assert_eq!(first(&owner, &cap), Some(1_005));
}

#[test]
fn a_backfill_interrupted_before_clearing_setup_retries_cleanly() {
    let h = Harness::new();
    let mut owner = h.owner();
    let setup = begin(&mut owner);
    owner.confirm_kit_saved().unwrap();
    h.raw()
        .execute_batch("CREATE TRIGGER keep BEFORE DELETE ON account_pending_setup BEGIN SELECT RAISE(FAIL,'interrupted'); END;")
        .unwrap();
    assert!(
        owner
            .confirm_home_ordered(setup.head, Some(evidence()))
            .is_err()
    );
    assert_eq!(stored_rows(&h), expected_rows());
    h.raw().execute_batch("DROP TRIGGER keep").unwrap();
    owner
        .confirm_home_ordered(setup.head, Some(evidence()))
        .unwrap();
    assert!(h.journal().pending_setup().unwrap().is_none());
    assert_eq!(stored_rows(&h), expected_rows());
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    assert_eq!(first(&owner, &cap), Some(1_005));
}

/// Offline kit-saved state, with the inputs a direct attach takes.
fn untimed_setup(h: &Harness) -> SetupStatus {
    let mut owner = h.owner();
    let setup = begin(&mut owner);
    owner.confirm_kit_saved().unwrap();
    setup
}
fn attach(
    h: &Harness,
    anchor: AccountId,
    head: Head,
    originals: [&[u8]; 2],
    evidence: &Evidence,
    view: &VerifiedAccount,
) -> Result<(), JournalError> {
    h.journal()
        .attach_setup_confirmations(anchor, head, originals, evidence, view)
}
fn assert_untouched(h: &Harness, before: &Option<(i64, i64, Vec<u8>)>) {
    assert!(stored_rows(h).is_empty());
    assert_eq!(&h.projection(), before);
    assert_eq!(h.times(), vec![None, None, None]);
}

#[test]
fn attach_refuses_anything_but_the_pending_untimed_setup_prefix() {
    let h = Harness::new();
    let setup = untimed_setup(&h);
    let before = h.projection();
    let view = home_view(&setup, &evidence());
    let originals = [setup.submission[1].as_slice(), &setup.submission[2]];

    // Another account.
    assert!(
        attach(
            &h,
            AccountId([9; 32]),
            setup.head,
            originals,
            &evidence(),
            &view
        )
        .is_err()
    );
    assert_untouched(&h, &before);
    // Another head, at or past the setup position.
    for head in [
        Head {
            position: 3,
            hash: [7; 32],
        },
        Head {
            position: 4,
            hash: setup.head.hash,
        },
    ] {
        assert!(attach(&h, setup.anchor, head, originals, &evidence(), &view).is_err());
        assert_untouched(&h, &before);
    }
    // Other bytes at position 2 or 3.
    let mut changed = setup.submission[1].clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    for originals in [
        [changed.as_slice(), &setup.submission[2]],
        [&setup.submission[1], changed.as_slice()],
        [&setup.submission[2], &setup.submission[1]],
    ] {
        assert!(attach(&h, setup.anchor, setup.head, originals, &evidence(), &view).is_err());
        assert_untouched(&h, &before);
    }
    // A view that is not this prefix with these times.
    let untimed = VerifiedAccount::replay(
        setup.anchor,
        &setup
            .submission
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>(),
        setup.head,
    )
    .unwrap();
    assert!(
        attach(
            &h,
            setup.anchor,
            setup.head,
            originals,
            &evidence(),
            &untimed
        )
        .is_err()
    );
    assert_untouched(&h, &before);
    // Regressing times, even with a matching view.
    let regressed = [
        (time(1_010, 1_015), b"record confirmation".to_vec()),
        (time(1_000, 1_020), b"key confirmation".to_vec()),
    ];
    assert!(attach(&h, setup.anchor, setup.head, originals, &regressed, &view).is_err());
    assert_untouched(&h, &before);
    // Empty proof bytes.
    let mut empty = evidence();
    empty[1].1.clear();
    assert!(attach(&h, setup.anchor, setup.head, originals, &empty, &view).is_err());
    assert_untouched(&h, &before);

    // An existing confirmation row, even an unrelated one.
    h.raw()
        .execute(
            "INSERT INTO account_confirmations(position,earliest_ms,latest_ms,confirmation) VALUES(2,1000,1005,x'01')",
            [],
        )
        .unwrap();
    assert!(attach(&h, setup.anchor, setup.head, originals, &evidence(), &view).is_err());
    assert_eq!(stored_rows(&h).len(), 1);
    assert_eq!(h.projection(), before);
    h.raw()
        .execute("DELETE FROM account_confirmations", [])
        .unwrap();

    // The exact inputs succeed once, and never again.
    attach(&h, setup.anchor, setup.head, originals, &evidence(), &view).unwrap();
    assert_eq!(stored_rows(&h), expected_rows());
    assert!(attach(&h, setup.anchor, setup.head, originals, &evidence(), &view).is_err());
}

#[test]
fn attach_refuses_without_a_pending_setup() {
    let h = Harness::new();
    let mut owner = h.owner();
    let setup = begin(&mut owner);
    owner.confirm_kit_saved().unwrap();
    // A verified legacy home completes setup untimed.
    owner.confirm_home_ordered(setup.head, None).unwrap();
    assert!(h.journal().pending_setup().unwrap().is_none());
    let before = h.projection();
    let view = home_view(&setup, &evidence());
    let originals = [setup.submission[1].as_slice(), &setup.submission[2]];
    assert!(attach(&h, setup.anchor, setup.head, originals, &evidence(), &view).is_err());
    assert_untouched(&h, &before);
    assert_eq!(
        owner.confirm_home_ordered(setup.head, Some(evidence())),
        Err(SetupError::NotStarted)
    );
    assert_untouched(&h, &before);
}

#[test]
fn owner_refuses_bad_setup_evidence_without_changes() {
    let h = Harness::new();
    let mut owner = h.owner();
    let setup = begin(&mut owner);
    owner.confirm_kit_saved().unwrap();
    let before = h.projection();
    let regressed = [
        (time(1_010, 1_015), b"record confirmation".to_vec()),
        (time(1_000, 1_005), b"key confirmation".to_vec()),
    ];
    assert_eq!(
        owner.confirm_home_ordered(setup.head, Some(regressed)),
        Err(SetupError::Protocol(Error::TimeRegressed))
    );
    let mut empty = evidence();
    empty[0].1.clear();
    assert_eq!(
        owner.confirm_home_ordered(setup.head, Some(empty)),
        Err(SetupError::Protocol(Error::MissingTime))
    );
    let wrong = Head {
        position: 3,
        hash: [1; 32],
    };
    assert_eq!(
        owner.confirm_home_ordered(wrong, Some(evidence())),
        Err(SetupError::HomeMismatch)
    );
    assert_untouched(&h, &before);
    assert!(h.journal().pending_setup().unwrap().is_some());
}

/// The home-first prefix is timed; a later different answer cannot retime it.
#[test]
fn setup_times_once_stored_are_never_replaced() {
    let h = Harness::new();
    let mut owner = h.owner();
    let setup = begin(&mut owner);
    owner
        .confirm_home_ordered(setup.head, Some(evidence()))
        .unwrap();
    let other = [
        (time(2_000, 2_005), b"record confirmation".to_vec()),
        (time(2_010, 2_015), b"key confirmation".to_vec()),
    ];
    assert!(owner.confirm_home_ordered(setup.head, Some(other)).is_err());
    assert_eq!(stored_rows(&h), expected_rows());
    // Nor does a legacy answer erase them.
    owner.confirm_home_ordered(setup.head, None).unwrap();
    assert_eq!(stored_rows(&h), expected_rows());
}

#[test]
fn later_history_waits_for_setup_times() {
    let h = Harness::new();
    let mut owner = h.owner();
    let setup = begin(&mut owner);
    owner.confirm_kit_saved().unwrap();
    let cap = activate(&mut owner);
    let addition = signed_addition(&mut owner, &cap, 70);
    let proof = Some((time(2_000, 2_005), b"addition confirmation".to_vec()));
    for timed in [proof.clone(), None] {
        assert_eq!(
            owner.apply_incoming_timed(&[(addition.as_slice(), timed)]),
            Err(OwnerError::Invalid(Error::Unavailable))
        );
        assert_eq!(owner.verified(&cap).unwrap().head(), setup.head);
        assert!(cap.is_current(), "a retryable wait, not a stop");
    }
    assert_eq!(h.count("SELECT count(*) FROM account_events"), 3);

    owner
        .confirm_home_ordered(setup.head, Some(evidence()))
        .unwrap();
    let head = owner
        .apply_incoming_timed(&[(addition.as_slice(), proof.clone())])
        .unwrap();
    assert_eq!(head.position, 4);
    let added: DeviceId = bh_account::DevicePublicKeys::new([70; 32], [71; 32], [72; 1216])
        .unwrap()
        .id();
    let view = owner.verified(&cap).unwrap();
    assert_eq!(view.added_at(cap.device_id()), Some(1_005));
    assert_eq!(view.added_at(added), Some(2_005));
}

/// A scanner's verified reply, received by a fresh showing session.
fn scanner_session(
    anchor: AccountId,
    showing: DeviceId,
    seed: u8,
) -> bh_account::pairing::ShowingSession {
    use bh_account::pairing::{Reply, ShowingSession};
    let scanner =
        bh_account::DevicePublicKeys::new([seed; 32], [seed + 1; 32], [seed + 2; 1216]).unwrap();
    let session = ShowingSession::new(anchor, showing);
    session
        .receive(&Reply::make(&session.qr().unwrap(), scanner, b"Fold").unwrap())
        .unwrap();
    session
}

/// The home's times replay the setup prefix into a fresh index epoch while an
/// approval is already open over the same verified head. Preparing against
/// the loaded view must re-read that projection, not report the approval dead.
#[test]
fn pairing_prepare_re_reads_the_projection_rewritten_by_setup_times() {
    let h = Harness::new();
    let setup = untimed_setup(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let before = h.projection().unwrap();
    assert_eq!((before.0, before.1), (1, 3), "untimed prefix at epoch 1");
    let session = scanner_session(setup.anchor, cap.device_id(), 90);

    let view = home_view(&setup, &evidence());
    let originals = [setup.submission[1].as_slice(), &setup.submission[2]];
    attach(&h, setup.anchor, setup.head, originals, &evidence(), &view).unwrap();
    let after = h.projection().unwrap();
    assert_eq!(
        (after.0, after.1),
        (2, 3),
        "a fresh epoch over the same head"
    );

    let request = session
        .prepare_with_re_read(&mut owner, &cap)
        .expect("a rewritten index over the unchanged head must prepare");
    let signed = ready(owner.sign_control(&cap, &request)).unwrap();
    assert_eq!(
        signed.previous_head(),
        setup.head,
        "still prepared at head 3"
    );
    session
        .stage_journal(&mut owner, &cap, signed.as_bytes(), b"sealed personal key")
        .expect("the approval stages");
    let row = h.journal().staged_admission().unwrap().unwrap();
    assert_eq!(row.event, signed.as_bytes());
    assert_eq!(row.delivery, b"sealed personal key");
    assert_eq!(h.times()[1], Some(evidence()[0].0), "the home's times stay");
}

/// An approval prepared at head 3 cannot apply once the verified head moved:
/// the re-read fence refuses rather than adopt a head the request never named.
#[test]
fn pairing_prepare_refuses_a_moved_head_instead_of_re_reading_past_it() {
    use bh_account::pairing::PairError;
    let h = Harness::new();
    let setup = untimed_setup(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let session = scanner_session(setup.anchor, cap.device_id(), 93);
    let view = home_view(&setup, &evidence());
    let originals = [setup.submission[1].as_slice(), &setup.submission[2]];
    attach(&h, setup.anchor, setup.head, originals, &evidence(), &view).unwrap();
    // Another holder of the same journal completes setup, then orders one
    // verified add: head 3 -> 4.
    let mut other = h.owner();
    other
        .confirm_home_ordered(setup.head, Some(evidence()))
        .unwrap();
    let other_cap = activate(&mut other);
    let addition = signed_addition(&mut other, &other_cap, 70);
    let proof = Some((time(2_000, 2_005), b"addition confirmation".to_vec()));
    other
        .apply_incoming_timed(&[(addition.as_slice(), proof)])
        .unwrap();
    assert_eq!(other.verified(&other_cap).unwrap().head().position, 4);

    assert!(matches!(
        session.prepare_with_re_read(&mut owner, &cap),
        Err(PairError::Owner(OwnerError::Invalid(
            Error::WrongPredecessor
        )))
    ));
    assert_eq!(
        owner.verified(&cap).unwrap().head(),
        setup.head,
        "the loaded view is not re-read past the head it prepared at"
    );
    assert!(h.journal().staged_admission().unwrap().is_none());
}

/// Local evidence that still cannot answer after the one re-read is a
/// retryable wait: the session stays live and prepares once the index answers.
#[test]
fn pairing_prepare_keeps_the_session_live_when_evidence_stays_unavailable() {
    use bh_account::pairing::PairError;
    let h = Harness::new();
    let setup = untimed_setup(&h);
    let mut owner = h.owner();
    let cap = activate(&mut owner);
    let session = scanner_session(setup.anchor, cap.device_id(), 96);
    let view = home_view(&setup, &evidence());
    let originals = [setup.submission[1].as_slice(), &setup.submission[2]];
    attach(&h, setup.anchor, setup.head, originals, &evidence(), &view).unwrap();
    h.raw()
        .execute("ALTER TABLE account_key_use RENAME TO hidden_keys", [])
        .unwrap();
    assert!(
        matches!(
            session.prepare_with_re_read(&mut owner, &cap),
            Err(PairError::Unavailable)
        ),
        "a persistent local read failure is retryable, not a stage failure"
    );
    h.raw()
        .execute("ALTER TABLE hidden_keys RENAME TO account_key_use", [])
        .unwrap();
    session
        .prepare_with_re_read(&mut owner, &cap)
        .expect("the same live session prepares once the index answers");
}

#[test]
fn an_ephemeral_journal_backfills_setup_times_without_an_index() {
    let generation = AccountGeneration::new();
    let store = FakeStore::new(generation.clone());
    let database = std::sync::Arc::new(std::sync::Mutex::new(
        bh_storage::DeviceDatabase::open(":memory:").unwrap(),
    ));
    let owner = || {
        bh_account::owner::AccountOwner::new(
            DeviceJournal::from_shared(database.clone()),
            store.clone(),
            PlainProtector,
            generation.clone(),
        )
    };
    let mut first_owner = owner();
    let setup = begin(&mut first_owner);
    first_owner.confirm_kit_saved().unwrap();
    let cap = activate(&mut first_owner);
    first_owner
        .confirm_home_ordered(setup.head, Some(evidence()))
        .unwrap();
    assert_eq!(first(&first_owner, &cap), Some(1_005));
    drop(first_owner);
    let mut reopened = owner();
    let cap = activate(&mut reopened);
    assert_eq!(first(&reopened, &cap), Some(1_005));
    assert!(
        database
            .lock()
            .unwrap()
            .account_projection()
            .unwrap()
            .is_none()
    );
}

/// A journal that stores no confirmation evidence: the trait defaults apply.
struct LegacyJournal(DeviceJournal);
impl AccountJournal for LegacyJournal {
    fn load(&self) -> Result<Option<JournaledAccount>, JournalError> {
        self.0.load()
    }
    fn history_prefix(
        &self,
        cursor: Option<HistoryCursor>,
        limit: usize,
    ) -> Result<Option<HistoryPage>, JournalError> {
        self.0.history_prefix(cursor, limit)
    }
    fn commit_verified(
        &mut self,
        anchor: AccountId,
        events: &[&[u8]],
        head: Head,
        stopped: bool,
    ) -> Result<(), JournalError> {
        self.0.commit_verified(anchor, events, head, stopped)
    }
    fn device(&self) -> Result<Option<JournaledDevice>, JournalError> {
        self.0.device()
    }
    fn commit_device(&mut self, device: &JournaledDevice) -> Result<(), JournalError> {
        self.0.commit_device(device)
    }
    fn initial_bootstrap(&self) -> Result<Option<InitialBootstrapRecord>, JournalError> {
        self.0.initial_bootstrap()
    }
    fn retain_initial_bootstrap(
        &mut self,
        record: &InitialBootstrapRecord,
        clear_pending: bool,
    ) -> Result<(), JournalError> {
        self.0.retain_initial_bootstrap(record, clear_pending)
    }
    fn pending_setup(&self) -> Result<Option<PendingSetupRecord>, JournalError> {
        self.0.pending_setup()
    }
    fn commit_pending_setup(&mut self, setup: &PendingSetupRecord) -> Result<(), JournalError> {
        self.0.commit_pending_setup(setup)
    }
    fn clear_pending_setup(&mut self) -> Result<(), JournalError> {
        self.0.clear_pending_setup()
    }
    fn staged_admission(&self) -> Result<Option<StagedAdmission>, JournalError> {
        self.0.staged_admission()
    }
    fn insert_staged_admission(&mut self, row: &StagedAdmission) -> Result<(), JournalError> {
        self.0.insert_staged_admission(row)
    }
    fn clear_staged_admission(&mut self, row: &StagedAdmission) -> Result<(), JournalError> {
        self.0.clear_staged_admission(row)
    }
}

#[test]
fn journals_without_setup_times_refuse_them() {
    let h = Harness::new();
    let mut owner = bh_account::owner::AccountOwner::new(
        LegacyJournal(h.journal()),
        h.store.clone(),
        PlainProtector,
        h.generation.clone(),
    );
    let setup = ready(owner.begin_first_device(
        ControlKeyPolicy::AppEnforcedOwnerConfirmation,
        &Password::new("correct horse battery staple").unwrap(),
    ))
    .unwrap();
    // Not committed yet: the default timed commit refuses.
    assert_eq!(
        owner.confirm_home_ordered(setup.head, Some(evidence())),
        Err(SetupError::Journal(JournalError::Storage))
    );
    assert!(h.journal().load().unwrap().is_none());
    // Committed untimed: the default attach refuses.
    owner.confirm_kit_saved().unwrap();
    let before = h.projection();
    assert_eq!(
        owner.confirm_home_ordered(setup.head, Some(evidence())),
        Err(SetupError::Journal(JournalError::Storage))
    );
    assert_untouched(&h, &before);
    assert!(h.journal().pending_setup().unwrap().is_some());
}
