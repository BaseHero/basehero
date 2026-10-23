//! Live typing qualified under realistic costs. The fixture's clock moves
//! with the runtime's paused clock (permits expire and are renewed), and
//! the costs the in-memory fixture would otherwise make free are paid at
//! their seams: the signer, each durable commit, the service's reads
//! through the edge, and the edge's calls to its log objects and body
//! store (`Costs`). Every socket carries the injected round trip.
//!
//! Each test prints one `QUAL` line per measurement. The gates are the
//! shown within 2 s of the pause (p95 of ten runs, and every pause
//! phase) at 100 ms under the default costs; 300 ms is stress only. The
//! acceptance round trip is 100 ms; the costs and gate are unchanged. At
//! every round trip and cost, events bounded by the pacing, not by
//! keystrokes, at most one count shown, at most one package unacknowledged,
//! the derived authorization bound, and converging digests. The slow costs
//! and the 1.5 s round trip are measured, not gated. Cold start is measured
//! on its own.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_event::presence;
use bh_sync_client::{Client, Pacing, Quiet, SyncStatus};
use std::{
    fmt::Write as _,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use support::{
    device::{Device, Typist, until},
    fake::{Costs, Counts, Hook, Hosted, Seen},
};
use tokio::{
    sync::watch,
    time::{Instant, sleep, sleep_until},
};
use yrs::{Assoc, Doc, StickyIndex, Transact, updates::encoder::Encode};

type Started = (Client, watch::Receiver<SyncStatus>);

const fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

/// The rows that assert the latency gate are the shipped default, not a
/// test-only pacing: Q300 goes through the asserted 100 ms path, and S500
/// stays a report-only comparison.
#[test]
fn the_gated_matrix_runs_the_shipped_quiet_policy() {
    let shipped = Setting::new("default", 100);
    assert_eq!(shipped.policy, "Q300");
    assert_eq!(shipped.pacing, Pacing::default());
    assert_eq!(shipped.pacing.quiet, Some(Quiet::default()));
    assert_eq!(shipped.pacing.spacing, ms(500));
    assert!(shipped.gated(), "the 100 ms gate runs the shipped default");
    let s500 = shipped.policy("S500");
    assert_eq!(s500.pacing, spaced(500));
    assert!(!s500.gated(), "S500 stays a reported comparison");
}
const SENTENCE: &str = "Hi, this is a test";
/// About eight keystrokes a second.
const KEYSTROKE: Duration = ms(120);
const GATE: Duration = Duration::from_secs(2);
/// The final keystroke this long after a package's run was captured.
const PHASES: [u64; 4] = [10, 250, 490, 510];
/// A permit's usable life on the client: its 30 s less the 5 s margin.
const PERMIT_LIFE: Duration = Duration::from_secs(25);

/// One cost profile, round trip and pacing policy.
#[derive(Clone, Copy, Debug)]
struct Setting {
    profile: &'static str,
    costs: Costs,
    rtt: Duration,
    policy: &'static str,
    pacing: Pacing,
    /// Part of the pacing sweep, which asserts nothing new.
    sweep: bool,
}
impl Setting {
    fn new(profile: &'static str, rtt_ms: u64) -> Self {
        let costs = match profile {
            "free" => Costs::FREE,
            "default" => Costs::DEFAULT,
            "near" => Costs::NEAR,
            "slow" => Costs::SLOW,
            other => panic!("no profile {other}"),
        };
        Self {
            profile,
            costs,
            rtt: ms(rtt_ms),
            policy: "Q300",
            pacing: Pacing::default(),
            sweep: false,
        }
    }
    /// Another pacing policy, for comparison with the shipped default.
    fn policy(self, policy: &'static str) -> Self {
        let pacing = match policy {
            "S250" => spaced(250),
            "S500" => spaced(500),
            "S750" => spaced(750),
            "S1000" => spaced(1000),
            other => panic!("no policy {other}"),
        };
        Self {
            policy,
            pacing,
            sweep: true,
            ..self
        }
    }
    fn gated(&self) -> bool {
        self.profile == "default" && self.rtt == ms(100) && !self.sweep
    }
    fn label(&self) -> String {
        format!(
            "{}profile={} rtt={}ms policy={}",
            if self.sweep { "sweep " } else { "" },
            self.profile,
            self.rtt.as_millis(),
            self.policy
        )
    }
    fn hosted(&self) -> Arc<Hosted> {
        let hosted = Hosted::new();
        hosted.edge.set_latency(self.rtt);
        hosted.edge.set_costs(self.costs);
        hosted.edge.set_pacing(self.pacing);
        hosted
    }
    /// Events (and appends) an unsplit single-writer burst may cost. Each
    /// new package after the first starts at least `gap` after the one
    /// before (the spacing; or, with a quiet period, its first edit came
    /// after the previous capture and it waited `after` past it), and the
    /// one before the last started before the last keystroke: at most
    /// `1 + ceil(burst / gap)`. Keystroke count does not appear.
    fn event_bound(&self, burst: Duration) -> usize {
        let per = |gap: Duration| 1 + burst.as_millis().div_ceil(gap.as_millis()) as usize;
        let spaced = (!self.pacing.spacing.is_zero()).then(|| per(self.pacing.spacing));
        let quiet = self.pacing.quiet.map(|q| per(q.after));
        spaced
            .into_iter()
            .chain(quiet)
            .min()
            .expect("a paced policy")
    }
}
fn spaced(spacing: u64) -> Pacing {
    Pacing {
        spacing: ms(spacing),
        quiet: None,
    }
}

/// The authorization messages a typing window may cost on both devices,
/// derived from what each package needs and what time alone costs:
///
/// - per package, one write-grant `Permits` message from the typist (its
///   stage and append items together), at most one `ReadBatch` for the
///   typist's own echo and at most one for the reader: `3 × events`;
/// - per package the edge refused (an expired grant, say), one more write
///   grant: `+ refused`;
/// - per device, one renewal of its subscriptions (base and account in one
///   message) for each usable permit life started during the window, plus
///   one because the window need not start where a life does:
///   `2 × (1 + ceil(window / 25 s))`;
/// - per device, one empty read when a notice races its read: `+ 2`.
///
/// The window runs from the first keystroke until both devices settled:
/// renewals follow elapsed time, not keystrokes.
fn authz_bound(events: usize, refused: usize, window: Duration) -> usize {
    let lives = window.as_millis().div_ceil(PERMIT_LIFE.as_millis()) as usize;
    3 * events + refused + 2 * (1 + lives) + 2
}

/// What one typing window cost, and how it showed elsewhere.
#[derive(Clone, Debug, Default)]
struct Measured {
    keystrokes: usize,
    /// First keystroke to last, as typed.
    burst: Duration,
    /// First keystroke until both devices settled.
    window: Duration,
    events: usize,
    appends: usize,
    /// Publications that never reached the log object's append (the edge
    /// refused them first, an expired grant say): each needs new grants.
    refused: usize,
    counts: Counts,
    /// From the last keystroke until the other device showed all of it.
    shown_after_pause: Duration,
    /// The largest gap between a keystroke and its showing on the other
    /// device, while typing as well as after the pause.
    max_lag: Duration,
    max_shown: u64,
    max_unacknowledged: usize,
    commits: Commits,
    /// Content packages the object staged and the edge published.
    stages: usize,
    publishes: usize,
    /// Presence frames each device sent while typing, the typist first.
    presence_frames: (usize, usize),
}

/// Durable commits on the typing device, by what they did, from row
/// triggers: one row per transaction on these paths.
#[derive(Clone, Copy, Debug, Default)]
struct Commits {
    keystrokes: usize,
    seals: usize,
    acks: usize,
    received: usize,
}
impl Commits {
    fn total(&self) -> usize {
        self.keystrokes + self.seals + self.acks + self.received
    }
}

impl Measured {
    /// The gates every setting must meet.
    fn assert_bounded(&self, s: &Setting) {
        let events = s.event_bound(self.burst);
        assert!(
            self.events <= events && self.appends == self.events,
            "{}: events bounded by pacing, not keystrokes ({events}): {self:?}",
            s.label()
        );
        let authz = authz_bound(self.events, self.refused, self.window);
        assert!(
            self.counts.authz_up <= authz,
            "{}: authorization messages ({authz}): {self:?}",
            s.label()
        );
        // Items: one stage and one append grant per publication attempt;
        // two subscriptions per renewal; no ordinary-path event or body
        // permit requests beside ReadBatch.
        let lives = self.window.as_millis().div_ceil(PERMIT_LIFE.as_millis()) as usize;
        assert!(
            self.counts.want_stage <= self.counts.publish
                && self.counts.want_append <= self.counts.publish,
            "{}: write grants: {self:?}",
            s.label()
        );
        assert!(
            self.counts.want_subscribe <= 2 * 2 * (1 + lives),
            "{}: subscriptions: {self:?}",
            s.label()
        );
        assert!(
            self.counts.read_batches <= 2 * self.events + 2,
            "{}: ReadBatch requests: {self:?}",
            s.label()
        );
        assert_eq!(
            self.counts.want_read_events, 0,
            "ordinary ReadEvents wants: {self:?}"
        );
        assert_eq!(
            self.counts.want_read_bodies, 0,
            "ordinary ReadBodies wants: {self:?}"
        );
        assert!(self.max_shown <= 1, "{}: {self:?}", s.label());
        assert!(self.max_unacknowledged <= 1, "{}: {self:?}", s.label());
    }
    fn line(&self) -> String {
        let c = &self.counts;
        let mut line = format!(
            "keys={} burst_ms={} window_ms={} shown_ms={} lag_ms={} events={} appends={} \
             refused={} max_shown={} max_unacked={}",
            self.keystrokes,
            self.burst.as_millis(),
            self.window.as_millis(),
            self.shown_after_pause.as_millis(),
            self.max_lag.as_millis(),
            self.events,
            self.appends,
            self.refused,
            self.max_shown,
            self.max_unacknowledged,
        );
        let _ = write!(
            line,
            " authz_up={}/{}B authz_down={}/{}B data_up={}/{}B data_down={}/{}B body_down={}B \
             items:stage={} append={} read_events={} read_bodies={} subscribe={} \
             permits_msgs={} read_batch={} other={} data:publish={} read_events={} \
             read_bodies={} subscribe={} credits={} edge_reads={}",
            c.authz_up,
            c.authz_up_bytes,
            c.authz_down,
            c.authz_down_bytes,
            c.data_up,
            c.data_up_bytes,
            c.data_down,
            c.data_down_bytes,
            c.body_bytes_down,
            c.want_stage,
            c.want_append,
            c.want_read_events,
            c.want_read_bodies,
            c.want_subscribe,
            c.permits_messages,
            c.read_batches,
            c.other_requests,
            c.publish,
            c.read_events,
            c.read_bodies,
            c.subscribe,
            c.credits,
            c.edge_reads,
        );
        let k = &self.commits;
        let _ = write!(
            line,
            " commits:keys={} seals={} acks={} received={}",
            k.keystrokes, k.seals, k.acks, k.received
        );
        line
    }
}

fn report(s: &Setting, scenario: &str, line: &str) {
    println!("QUAL {} scenario={scenario} {line}", s.label());
}

fn copied(device: &Device) -> u64 {
    device
        .progress()
        .account
        .map_or(0, |(position, _)| position)
}

/// Two devices of one account on the first one's base, both caught up. With
/// `presence`, both start configured and foreground, as the host does.
async fn two(hosted: &Arc<Hosted>, presence: bool) -> (Device, Started, Device, Started) {
    let mac = Device::new();
    if presence {
        mac.label_presence("Mac", 0);
    }
    let mac_client = mac.start_named(hosted, "typist");
    until(120, "registered", || {
        mac.registered() && mac.progress().position >= 1
    })
    .await;
    let fold = Device::join(&mac, hosted).await;
    if presence {
        fold.label_presence("Fold", 1);
    }
    until(120, "addition copied", || copied(&mac) == 4).await;
    let fold_client = fold.start_named(hosted, "reader");
    until(120, "joined device caught up", || {
        fold.progress().position == mac.progress().position && copied(&fold) == 4
    })
    .await;
    // Warm: the joined device's first follow of its account ends, and
    // nothing of pairing is left in flight when typing starts.
    sleep(Duration::from_secs(3)).await;
    (mac, mac_client, fold, fold_client)
}

/// The count the status line shows, if it shows one.
fn shown(status: &mut watch::Receiver<SyncStatus>) -> u64 {
    match *status.borrow_and_update() {
        SyncStatus::Syncing { pending } | SyncStatus::SavedLocal { pending } => pending,
        _ => 0,
    }
}

/// Record, at each seal, how many of this device's packages are sealed and
/// not yet acknowledged (the count only rises at a seal); and count the
/// device's durable commits by kind.
fn instrument(device: &Device) {
    device
        .raw()
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS test_unacknowledged(n INTEGER);
             DELETE FROM test_unacknowledged;
             CREATE TRIGGER IF NOT EXISTS test_unacknowledged AFTER INSERT ON note_outbox BEGIN
               INSERT INTO test_unacknowledged SELECT COUNT(*) FROM note_outbox o
                 LEFT JOIN note_outbox_progress p USING(update_id) WHERE p.outcome IS NULL;
             END;
             CREATE TABLE IF NOT EXISTS test_commits(kind TEXT);
             DELETE FROM test_commits;
             CREATE TRIGGER IF NOT EXISTS test_commit_key AFTER INSERT ON note_updates BEGIN
               INSERT INTO test_commits VALUES('key'); END;
             CREATE TRIGGER IF NOT EXISTS test_commit_seal AFTER INSERT ON note_outbox BEGIN
               INSERT INTO test_commits VALUES('seal'); END;
             CREATE TRIGGER IF NOT EXISTS test_commit_ack_new AFTER INSERT ON note_outbox_progress
               WHEN NEW.acked_position IS NOT NULL BEGIN
               INSERT INTO test_commits VALUES('ack'); END;
             CREATE TRIGGER IF NOT EXISTS test_commit_ack AFTER UPDATE OF acked_position
               ON note_outbox_progress
               WHEN NEW.acked_position IS NOT NULL AND OLD.acked_position IS NULL BEGIN
               INSERT INTO test_commits VALUES('ack'); END;
             CREATE TRIGGER IF NOT EXISTS test_commit_received AFTER UPDATE OF position
               ON log_progress WHEN NEW.position != OLD.position BEGIN
               INSERT INTO test_commits VALUES('received'); END;",
        )
        .unwrap();
}
fn most_unacknowledged(device: &Device) -> usize {
    device
        .raw()
        .query_row(
            "SELECT COALESCE(MAX(n),0) FROM test_unacknowledged",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap() as usize
}
fn commits(device: &Device) -> Commits {
    let raw = device.raw();
    let count = |kind: &str| -> usize {
        raw.query_row(
            "SELECT COUNT(*) FROM test_commits WHERE kind=?1",
            [kind],
            |r| r.get::<_, i64>(0),
        )
        .unwrap() as usize
    };
    Commits {
        keystrokes: count("key"),
        seals: count("seal"),
        acks: count("ack"),
        received: count("received"),
    }
}

fn appends(hosted: &Hosted, log: [u8; 32]) -> usize {
    hosted
        .edge
        .seen()
        .iter()
        .filter(|s| matches!(s, Seen::Append { log: l, .. } if *l == log))
        .count()
}
fn publishes(hosted: &Hosted) -> usize {
    hosted
        .edge
        .seen()
        .iter()
        .filter(|s| matches!(s, Seen::Publish { .. }))
        .count()
}

/// When each of a typist's keystrokes first showed on another device:
/// looked at whenever that device's log moved.
struct Appearing {
    note: [u8; 32],
    position: u64,
    /// Characters already in the note before the measured burst.
    base: usize,
    at: Vec<Instant>,
}
impl Appearing {
    fn new(note: [u8; 32], base: usize) -> Self {
        Self {
            note,
            position: u64::MAX,
            base,
            at: Vec::new(),
        }
    }
    fn look(&mut self, reader: &Device) {
        let position = reader.progress().position;
        if position == self.position {
            return;
        }
        self.position = position;
        let shown = reader
            .paragraphs(self.note)
            .first()
            .map_or(0, |p| p.chars().count());
        let now = Instant::now();
        while self.at.len() + self.base < shown {
            self.at.push(now);
        }
    }
}

/// Uniform keystroke gaps between 80 and 160 ms (about eight a second),
/// the same for the same seed.
fn jittered(n: usize, seed: u64) -> Vec<Duration> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ms(80 + x % 81)
        })
        .collect()
}

/// Fixed assumed word-pause trace: four 90 ms intra-word gaps, then
/// 200/350/700 ms word gaps in rotation. Every 20th word has a 1.8 s
/// thinking pause; every 40th, a 3.5 s idle before one more edit.
/// The sequence and text are identical for both pacing policies.
fn natural_gap(i: usize, seed: usize) -> Duration {
    let word = (i + seed) / 5;
    if (i + seed) % 5 != 4 {
        ms(90)
    } else if word % 40 == 39 {
        ms(3500)
    } else if word % 20 == 19 {
        ms(1800)
    } else {
        ms([200, 350, 700][word % 3])
    }
}
fn natural_gaps(n: usize, seed: usize) -> Vec<Duration> {
    (0..n).map(|i| natural_gap(i, seed)).collect()
}

/// Number of characters in an assumed ten-minute offline trace, without
/// counting a gap after its last character.
fn natural_ten_minutes() -> usize {
    let mut elapsed = Duration::ZERO;
    let mut n = 1;
    loop {
        let gap = natural_gap(n - 1, 0);
        if elapsed + gap > Duration::from_secs(600) {
            return n;
        }
        elapsed += gap;
        n += 1;
    }
}

/// A root position in a note fragment, valid before this device types.
fn root_position() -> Vec<u8> {
    let doc = Doc::new();
    let fragment = doc.get_or_insert_xml_fragment("default");
    StickyIndex::from_type(&doc.transact(), &fragment, Assoc::After).encode_v1()
}

/// Sealed presence frames this device sent, opened with its own key.
fn presence_frames_for(hosted: &Hosted, device: &Device) -> usize {
    let key = device.content_key();
    let base = device.base.0;
    let Some(epoch) = device.progress().epoch_id else {
        return 0;
    };
    hosted
        .edge
        .presence_wire(base)
        .iter()
        .filter(|frame| presence::open(&key, base, base, epoch, frame).is_ok())
        .count()
}

/// What to type and the gap after each keystroke.
struct Burst<'a> {
    text: &'a str,
    gaps: &'a [Duration],
}

/// Type `burst.text` on `mac` with `burst.gaps` after each keystroke, each one
/// saved (its commit time first) and followed by the host's wake; watch `fold`
/// show it; then wait until both settled. With `cursor`, both devices report
/// a selection every 50 ms of virtual time while typing, as the host does.
async fn type_burst(
    s: &Setting,
    hosted: &Arc<Hosted>,
    (mac, mac_client): (&Device, &mut Started),
    fold: &Device,
    cursor: Option<&Client>,
    typist: &mut Typist,
    burst: Burst<'_>,
) -> Measured {
    let Burst { text, gaps } = burst;
    let log = mac.log();
    let events_before = hosted.edge.entries(log).len();
    let appends_before = appends(hosted, log.id);
    let publishes_before = publishes(hosted);
    let stages_before = hosted.edge.stages(log.id).len();
    let counts_before = hosted.edge.counts();
    let presence_before = cursor.map(|_| {
        (
            presence_frames_for(hosted, mac),
            presence_frames_for(hosted, fold),
        )
    });
    let typing = cursor.map(|fold_client| (mac_client.0.presence(), fold_client.presence()));
    if let Some((mac_presence, fold_presence)) = &typing {
        let root = root_position();
        mac_presence.set("typist", typist.note, root.clone(), root.clone());
        fold_presence.set("reader", typist.note, root.clone(), root);
        until(5, "presence live", || hosted.edge.presence_frames() >= 2).await;
    }
    instrument(mac);
    // Every status value the client publishes, as it is delivered.
    let shown_high = Arc::new(AtomicU64::new(0));
    let monitor = {
        let mut status = mac_client.1.clone();
        let high = shown_high.clone();
        tokio::spawn(async move {
            loop {
                high.fetch_max(shown(&mut status), Ordering::SeqCst);
                if status.changed().await.is_err() {
                    return;
                }
            }
        })
    };
    let mut max_shown = 0;
    let chars: Vec<char> = text.chars().collect();
    let base_chars = fold
        .paragraphs(typist.note)
        .first()
        .map_or(0, |p| p.chars().count());
    let mut appearing = Appearing::new(typist.note, base_chars);
    let mut typed = Vec::with_capacity(chars.len());
    let mut last_cursor = Instant::now();
    let start = Instant::now();
    for (i, c) in chars.iter().enumerate() {
        let at = Instant::now();
        typed.push(at);
        // The keystroke's save.
        sleep(s.costs.commit).await;
        mac.type_key(typist, *c);
        mac_client.0.wake();
        if i + 1 == chars.len() {
            break;
        }
        let next = at + gaps[i % gaps.len()];
        while Instant::now() < next {
            appearing.look(fold);
            max_shown = max_shown.max(shown(&mut mac_client.1));
            if let Some((mac_presence, fold_presence)) = &typing
                && last_cursor.elapsed() >= ms(50)
            {
                let position = typist.position();
                mac_presence.set("typist", typist.note, position.clone(), position.clone());
                fold_presence.set("reader", typist.note, position.clone(), position);
                last_cursor = Instant::now();
            }
            sleep((next - Instant::now()).min(ms(5))).await;
        }
    }
    let paused = *typed.last().unwrap();
    while appearing.at.len() < chars.len() {
        assert!(
            paused.elapsed() < Duration::from_secs(600),
            "{}: never shown",
            s.label()
        );
        sleep(ms(2)).await;
        appearing.look(fold);
        max_shown = max_shown.max(shown(&mut mac_client.1));
    }
    let shown_after_pause = appearing.at[chars.len() - 1] - paused;
    let max_lag = typed
        .iter()
        .zip(&appearing.at)
        .map(|(typed, shown)| *shown - *typed)
        .max()
        .unwrap();
    until(600, "both settled", || {
        mac.pending() == 0 && fold.progress().position == mac.progress().position
    })
    .await;
    let window = start.elapsed();
    monitor.abort();
    max_shown = max_shown.max(shown_high.load(Ordering::SeqCst));
    Measured {
        keystrokes: chars.len(),
        burst: paused - start,
        window,
        events: hosted.edge.entries(log).len() - events_before,
        appends: appends(hosted, log.id) - appends_before,
        refused: (publishes(hosted) - publishes_before)
            .saturating_sub(appends(hosted, log.id) - appends_before),
        counts: hosted.edge.counts() - counts_before,
        shown_after_pause,
        max_lag,
        max_shown,
        max_unacknowledged: most_unacknowledged(mac),
        commits: commits(mac),
        stages: hosted.edge.stages(log.id).len() - stages_before,
        publishes: publishes(hosted) - publishes_before,
        presence_frames: presence_before.map_or((0, 0), |(mac_before, fold_before)| {
            (
                presence_frames_for(hosted, mac) - mac_before,
                presence_frames_for(hosted, fold) - fold_before,
            )
        }),
    }
}

fn same_note(a: &Device, b: &Device, note: [u8; 32]) {
    assert_eq!(
        a.reopened(note).digest().unwrap(),
        b.reopened(note).digest().unwrap(),
        "digests converge"
    );
}

/// The reference sentence once, with gaps from `seed`.
async fn sentence_once(
    s: Setting,
    seed: u64,
    natural: bool,
    presence: bool,
    prime: bool,
) -> Measured {
    let hosted = s.hosted();
    let (mac, mut mc, fold, fc) = two(&hosted, presence).await;
    let mut typist = mac.new_typist();
    if prime {
        // Establish an accepted writer so cursor positions on the text typed
        // during the measured burst are not all withheld as a new writer's.
        sleep(s.costs.commit).await;
        mac.type_key(&mut typist, 'P');
        mc.0.wake();
        until(30, "primed writer accepted", || {
            mac.has_binding(typist.note, typist.client())
                && fold.has_binding(typist.note, typist.client())
        })
        .await;
        until(30, "prime shown", || fold.paragraphs(typist.note) == ["P"]).await;
    }
    let gaps = if natural {
        natural_gaps(SENTENCE.len(), seed as usize)
    } else {
        jittered(SENTENCE.len(), seed)
    };
    let cursor = presence.then_some(&fc.0);
    let m = type_burst(
        &s,
        &hosted,
        (&mac, &mut mc),
        &fold,
        cursor,
        &mut typist,
        Burst {
            text: SENTENCE,
            gaps: &gaps,
        },
    )
    .await;
    let expected = if prime {
        format!("P{SENTENCE}")
    } else {
        SENTENCE.to_owned()
    };
    assert_eq!(fold.paragraphs(typist.note), vec![expected]);
    same_note(&mac, &fold, typist.note);
    mc.0.shutdown().await;
    fc.0.shutdown().await;
    m
}

/// Ten independent runs of the reference sentence; returns them by time shown.
async fn sentence(s: Setting) -> Vec<Measured> {
    sentence_trace(s, false, false).await
}
async fn sentence_trace(s: Setting, natural: bool, presence: bool) -> Vec<Measured> {
    let mut runs = futures_util::future::join_all(
        (0..10).map(|i| sentence_once(s, i + 1, natural, presence, false)),
    )
    .await;
    runs.sort_by_key(|m| m.shown_after_pause);
    for r in &runs {
        r.assert_bounded(&s);
    }
    // Nearest-rank p95 of ten is the slowest.
    let p95 = runs.last().unwrap();
    let median = &runs[4];
    report(
        &s,
        if natural {
            "natural_sentence"
        } else {
            "sentence"
        },
        &format!(
            "p95_ms={} median_ms={} p95_run: {}",
            p95.shown_after_pause.as_millis(),
            median.shown_after_pause.as_millis(),
            p95.line()
        ),
    );
    runs
}

/// What one pause phase showed.
#[derive(Debug)]
struct Phase {
    phase: Duration,
    shown: Duration,
    events: usize,
    burst: Duration,
}

/// The final keystroke lands `phase` after the latest package's run was
/// captured (the signer is asked just after); the text must still show
/// within 2 s of the pause.
async fn phase(s: Setting, phase: Duration, presence: bool, prime: bool) -> Phase {
    let hosted = s.hosted();
    let (mac, mc, fold, fc) = two(&hosted, presence).await;
    let mut typist = mac.new_typist();
    if prime {
        sleep(s.costs.commit).await;
        mac.type_key(&mut typist, 'P');
        mc.0.wake();
        until(30, "primed writer accepted", || {
            mac.has_binding(typist.note, typist.client())
                && fold.has_binding(typist.note, typist.client())
        })
        .await;
        until(30, "prime shown", || fold.paragraphs(typist.note) == ["P"]).await;
    }
    let typing = presence.then(|| (mc.0.presence(), fc.0.presence()));
    if let Some((mac_presence, fold_presence)) = &typing {
        let root = root_position();
        mac_presence.set("typist", typist.note, root.clone(), root.clone());
        fold_presence.set("reader", typist.note, root.clone(), root);
        until(5, "presence live", || hosted.edge.presence_frames() >= 2).await;
    }
    let mut last_cursor = Instant::now();
    let log = mac.log();
    let before = hosted.edge.entries(log).len();
    let marks_before = hosted.edge.marks().len();
    let timed_before = hosted.edge.timed().len();
    let asked = mac.signer.sign_asked.lock().unwrap().len();
    let first = Instant::now();
    sleep(s.costs.commit).await;
    mac.type_key(&mut typist, 'a');
    mc.0.wake();
    let captured = loop {
        if let Some(at) = mac.signer.sign_asked.lock().unwrap().get(asked).copied() {
            break at;
        }
        sleep(ms(1)).await;
    };
    let until_at = captured + phase;
    while Instant::now() < until_at {
        if let Some((mac_presence, fold_presence)) = &typing
            && last_cursor.elapsed() >= ms(50)
        {
            let position = typist.position();
            mac_presence.set("typist", typist.note, position.clone(), position.clone());
            fold_presence.set("reader", typist.note, position.clone(), position);
            last_cursor = Instant::now();
        }
        sleep((until_at - Instant::now()).min(ms(5))).await;
    }
    let last = Instant::now();
    sleep(s.costs.commit).await;
    mac.type_key(&mut typist, 'b');
    mc.0.wake();
    let expected = if prime { "Pab" } else { "ab" };
    while fold.paragraphs(typist.note) != [expected] {
        assert!(last.elapsed() < Duration::from_secs(60), "never shown");
        sleep(ms(1)).await;
    }
    let shown = last.elapsed();
    until(60, "settled", || mac.pending() == 0).await;
    same_note(&mac, &fold, typist.note);
    let events = hosted.edge.entries(log).len() - before;
    if s.gated() || std::env::var_os("QUAL_TRACE").is_some() {
        // The way of the final keystroke, relative to it.
        let rel = |at: Instant| {
            at.saturating_duration_since(last).as_millis() as i128
                - last.saturating_duration_since(at).as_millis() as i128
        };
        let mut steps: Vec<(i128, String)> = Vec::new();
        for at in mac.signer.sign_asked.lock().unwrap()[asked..].iter() {
            steps.push((rel(*at), "typist: run captured, signer asked".into()));
        }
        for (at, seen) in &hosted.edge.timed()[timed_before..] {
            let what = match seen {
                Seen::Arrived { .. } => "edge: Publish arrived".to_string(),
                Seen::Append { .. } => "object: ordered".to_string(),
                Seen::Acked { position, .. } => format!("edge: Published {position} leaves"),
                Seen::Publish { .. } => "edge: Publish handled".to_string(),
                _ => continue,
            };
            steps.push((rel(*at), what));
        }
        for (at, what) in &hosted.edge.marks()[marks_before..] {
            steps.push((rel(*at), what.clone()));
        }
        steps.push((shown.as_millis() as i128, "reader: shows \"ab\"".into()));
        steps.sort();
        for (at, what) in steps {
            println!(
                "TRACE {} phase={}ms {at:>6} ms {what}",
                s.label(),
                phase.as_millis()
            );
        }
    }
    mc.0.shutdown().await;
    fc.0.shutdown().await;
    Phase {
        phase,
        shown,
        events,
        burst: last - first,
    }
}

async fn phases(s: Setting, presence: bool, prime: bool) -> Vec<Phase> {
    let phases =
        futures_util::future::join_all(PHASES.map(|p| phase(s, ms(p), presence, prime))).await;
    for p in &phases {
        assert!(p.events <= s.event_bound(p.burst), "{}: {p:?}", s.label());
    }
    let worst = phases.iter().max_by_key(|p| p.shown).unwrap();
    report(
        &s,
        "phases",
        &format!(
            "worst_ms={} worst_phase_ms={} {}",
            worst.shown.as_millis(),
            worst.phase.as_millis(),
            phases
                .iter()
                .map(|p| format!(
                    "phase{}={}ms/{}ev",
                    p.phase.as_millis(),
                    p.shown.as_millis(),
                    p.events
                ))
                .collect::<Vec<_>>()
                .join(" ")
        ),
    );
    phases
}

/// The gated 100 ms sentence and every pause phase, run once content-only
/// and once with both devices reporting a selection every 50 ms while
/// typing. Presence must not change content's packages, grants or commits,
/// and must not slow the text shown past the gate.
#[tokio::test(start_paused = true)]
async fn cursor_traffic_keeps_the_gated_sentence_and_phases() {
    let s = Setting::new("default", 100);
    let mut with = Vec::new();
    for seed in 1..=10u64 {
        let plain = sentence_once(s, seed, false, false, true).await;
        let stormy = sentence_once(s, seed, false, true, true).await;
        let label = format!("seed {seed}");
        assert_eq!(stormy.events, plain.events, "{label}: events");
        assert_eq!(stormy.appends, plain.appends, "{label}: appends");
        assert_eq!(stormy.stages, plain.stages, "{label}: staged packages");
        assert_eq!(stormy.publishes, plain.publishes, "{label}: publishes");
        assert_eq!(
            stormy.counts.read_batches, plain.counts.read_batches,
            "{label}: read batches"
        );
        assert_eq!(
            stormy.counts.want_stage, plain.counts.want_stage,
            "{label}: stage grants"
        );
        assert_eq!(
            stormy.counts.want_append, plain.counts.want_append,
            "{label}: append grants"
        );
        assert_eq!(
            stormy.counts.want_read_events, plain.counts.want_read_events,
            "{label}: ReadEvents wants"
        );
        assert_eq!(
            stormy.counts.want_read_bodies, plain.counts.want_read_bodies,
            "{label}: ReadBodies wants"
        );
        assert_eq!(
            stormy.counts.want_subscribe, plain.counts.want_subscribe,
            "{label}: subscriptions"
        );
        assert_eq!(
            stormy.commits.total(),
            plain.commits.total(),
            "{label}: durable commits"
        );
        assert_eq!(
            stormy.max_unacknowledged, plain.max_unacknowledged,
            "{label}: unacknowledged packages"
        );
        assert!(
            stormy.shown_after_pause <= GATE,
            "{label}: presence run within 2 s: {:?}",
            stormy.shown_after_pause
        );
        assert!(
            stormy.shown_after_pause <= plain.shown_after_pause + ms(100),
            "{label}: presence no slower than content-only (plain {:?}, presence {:?})",
            plain.shown_after_pause,
            stormy.shown_after_pause
        );
        let seconds = stormy.burst.as_secs_f64();
        assert!(
            stormy.presence_frames.0 as f64 >= 8.0 * seconds,
            "{label}: typist presence flowed ({} frames in {seconds:.2} s)",
            stormy.presence_frames.0
        );
        assert!(
            stormy.presence_frames.1 as f64 >= 8.0 * seconds,
            "{label}: reader presence flowed ({} frames in {seconds:.2} s)",
            stormy.presence_frames.1
        );
        with.push(stormy);
    }
    with.sort_by_key(|m| m.shown_after_pause);
    let p95 = with.last().unwrap();
    assert!(
        p95.shown_after_pause <= GATE,
        "presence p95 within 2 s: {:?}",
        p95.shown_after_pause
    );
    report(&s, "sentence", &format!("with_cursor: {}", p95.line()));

    let plain = phases(s, false, true).await;
    let stormy = phases(s, true, true).await;
    let worst = |runs: &[Phase]| runs.iter().map(|p| p.shown).max().unwrap();
    let plain_worst = worst(&plain);
    let stormy_worst = worst(&stormy);
    assert!(
        stormy_worst <= GATE,
        "every pause phase with presence within 2 s: {stormy_worst:?}"
    );
    assert!(
        stormy_worst <= plain_worst + ms(100),
        "presence phases no slower (plain {plain_worst:?}, presence {stormy_worst:?})"
    );
}

/// Three hundred keystrokes at about eight a second, then a pause.
async fn sustained(s: Setting) -> Measured {
    sustained_trace(s, false).await
}
async fn sustained_trace(s: Setting, natural: bool) -> Measured {
    let hosted = s.hosted();
    let (mac, mut mc, fold, fc) = two(&hosted, false).await;
    let mut typist = mac.new_typist();
    let text = "abcdefghij".repeat(30);
    let gaps = if natural {
        natural_gaps(text.len(), 0)
    } else {
        vec![KEYSTROKE]
    };
    let m = type_burst(
        &s,
        &hosted,
        (&mac, &mut mc),
        &fold,
        None,
        &mut typist,
        Burst {
            text: &text,
            gaps: &gaps,
        },
    )
    .await;
    if !natural {
        assert_eq!(m.burst, KEYSTROKE * 299, "first to last keystroke");
    }
    m.assert_bounded(&s);
    same_note(&mac, &fold, typist.note);
    let minutes = m.burst.as_secs_f64() / 60.0;
    report(
        &s,
        if natural {
            "natural_sustained"
        } else {
            "sustained"
        },
        &format!(
            "events_per_min={:.1} commits_per_min={:.1} {}",
            m.events as f64 / minutes,
            m.commits.total() as f64 / minutes,
            m.line()
        ),
    );
    mc.0.shutdown().await;
    fc.0.shutdown().await;
    m
}

/// Both devices type into one note at once, then pause.
async fn both(s: Setting) {
    let hosted = s.hosted();
    let (mac, mc, fold, fc) = two(&hosted, false).await;
    let mut a = mac.new_typist();
    sleep(s.costs.commit).await;
    mac.type_key(&mut a, 'A');
    mc.0.wake();
    until(60, "shared note", || fold.paragraphs(a.note) == ["A"]).await;
    let mut b = fold.typist(a.note);
    let log = mac.log();
    let before = hosted.edge.entries(log).len();
    let start = Instant::now();
    let mut last = start;
    for i in 0..60 {
        last = Instant::now();
        sleep(s.costs.commit).await;
        mac.type_key(&mut a, 'a');
        fold.type_key(&mut b, 'b');
        mc.0.wake();
        fc.0.wake();
        if i < 59 {
            sleep_until(last + KEYSTROKE).await;
        }
    }
    let want = [format!("A{}", "a".repeat(60)), "b".repeat(60)];
    let shows = |device: &Device| {
        let mut text = device.paragraphs(a.note);
        text.sort();
        text == want
    };
    let mut mac_shown = None;
    let mut fold_shown = None;
    while mac_shown.is_none() || fold_shown.is_none() {
        assert!(last.elapsed() < Duration::from_secs(120), "never converged");
        if mac_shown.is_none() && shows(&mac) {
            mac_shown = Some(last.elapsed());
        }
        if fold_shown.is_none() && shows(&fold) {
            fold_shown = Some(last.elapsed());
        }
        sleep(ms(2)).await;
    }
    until(120, "both settled", || {
        mac.pending() == 0
            && fold.pending() == 0
            && mac.progress().position == fold.progress().position
    })
    .await;
    let events = hosted.edge.entries(log).len() - before;
    let burst = last - start;
    // Each device is one unsplit writer of its own runs.
    assert!(
        events <= 2 * s.event_bound(burst),
        "{}: {events} events over {burst:?}",
        s.label()
    );
    same_note(&mac, &fold, a.note);
    report(
        &s,
        "both",
        &format!(
            "burst_ms={} events={events} bound={} mac_shows_all_ms={} fold_shows_all_ms={}",
            burst.as_millis(),
            2 * s.event_bound(burst),
            mac_shown.unwrap().as_millis(),
            fold_shown.unwrap().as_millis()
        ),
    );
    mc.0.shutdown().await;
    fc.0.shutdown().await;
}

/// Two hundred edits while the typing device is offline, then it
/// reconnects.
async fn offline(s: Setting) {
    let hosted = s.hosted();
    let (mac, mc, fold, fc) = two(&hosted, false).await;
    mc.0.shutdown().await;
    drop(mc);
    let log = mac.log();
    let before = hosted.edge.entries(log).len();
    let counts_before = hosted.edge.counts();
    let mut typist = mac.new_typist();
    let text = "offline ".repeat(25);
    for c in text.chars() {
        sleep(s.costs.commit).await;
        mac.type_key(&mut typist, c);
    }
    let reconnected = Instant::now();
    let mc = mac.start_named(&hosted, "typist");
    while fold.paragraphs(typist.note) != [text.clone()] {
        assert!(
            reconnected.elapsed() < Duration::from_secs(120),
            "never shown"
        );
        sleep(ms(2)).await;
    }
    let shown = reconnected.elapsed();
    until(120, "offline burst accepted", || mac.pending() == 0).await;
    let events = hosted.edge.entries(log).len() - before;
    assert!(
        events <= s.event_bound(Duration::ZERO),
        "{}: {events} events for one offline run",
        s.label()
    );
    same_note(&mac, &fold, typist.note);
    let c = hosted.edge.counts() - counts_before;
    report(
        &s,
        "offline",
        &format!(
            "edits=200 reconnect_to_shown_ms={} events={events} authz_up={} permits_msgs={} \
             read_batch={} other={} data_up={}/{}B data_down={}/{}B",
            shown.as_millis(),
            c.authz_up,
            c.permits_messages,
            c.read_batches,
            c.other_requests,
            c.data_up,
            c.data_up_bytes,
            c.data_down,
            c.data_down_bytes
        ),
    );
    mc.0.shutdown().await;
    fc.0.shutdown().await;
}

/// Fresh devices: the first registers, the second pairs and catches up;
/// then the first device's client starts cold and the sentence is typed
/// at once. Measured on its own; not held to the 2 s gate.
async fn cold(s: Setting) {
    let hosted = s.hosted();
    let began = Instant::now();
    let mac = Device::new();
    let mc = mac.start_named(&hosted, "typist");
    until(120, "registered", || {
        mac.registered() && mac.progress().position >= 1
    })
    .await;
    let registered = began.elapsed();
    let joined = Instant::now();
    let fold = Device::join(&mac, &hosted).await;
    until(120, "addition copied", || copied(&mac) == 4).await;
    let fc = fold.start_named(&hosted, "reader");
    until(120, "joined device caught up", || {
        fold.progress().position == mac.progress().position && copied(&fold) == 4
    })
    .await;
    let paired = joined.elapsed();
    mc.0.shutdown().await;
    drop(mc);
    // A cold start: no session, no subscription, nothing open.
    let mut mc = mac.start_named(&hosted, "typist");
    let mut typist = mac.new_typist();
    let m = type_burst(
        &s,
        &hosted,
        (&mac, &mut mc),
        &fold,
        None,
        &mut typist,
        Burst {
            text: SENTENCE,
            gaps: &[KEYSTROKE],
        },
    )
    .await;
    same_note(&mac, &fold, typist.note);
    report(
        &s,
        "cold",
        &format!(
            "register_ms={} pair_and_catch_up_ms={} first_sentence_after_cold_start: {}",
            registered.as_millis(),
            paired.as_millis(),
            m.line()
        ),
    );
    mc.0.shutdown().await;
    fc.0.shutdown().await;
}

/// Sealed packages of this device not yet acknowledged.
fn unacknowledged_packages(device: &Device) -> usize {
    device
        .raw()
        .query_row(
            "SELECT COUNT(*) FROM note_outbox o LEFT JOIN note_outbox_progress p USING(update_id)
             WHERE p.outcome IS NULL",
            [],
            |r| r.get::<_, i64>(0),
        )
        .unwrap() as usize
}

/// Reopen the actual SQLite and owner at `point`: 0 after the local save,
/// 1 after sealing before sending, 2 after the Ack before the echo, 3 after
/// the append committed but its Ack was lost. The exact bytes are kept and
/// published once, at their original position.
async fn reopen(s: Setting, point: u8) {
    let hosted = s.hosted();
    let (mac, mc, fold, fc) = two(&hosted, false).await;
    mc.0.shutdown().await;
    drop(mc);
    let before = hosted.edge.entries(mac.log()).len();
    let mut typist = mac.new_typist();
    let mut last = 0;
    for c in SENTENCE.chars() {
        sleep(s.costs.commit).await;
        last = mac.type_key(&mut typist, c);
    }
    let note = typist.note;
    let mut kept = None;
    if point > 0 {
        hosted.edge.freeze_reads(Some(mac.progress().position));
        if point == 3 {
            hosted.edge.hook(Hook::DropAfterAppend { then_down: true });
        }
        let mc = mac.start_named(&hosted, "typist");
        until(60, "sealed or acked before the crash", || {
            if point == 1 {
                unacknowledged_packages(&mac) == 1
            } else if point == 3 {
                hosted.edge.entries(mac.log()).len() > before
            } else {
                mac.acked(last).is_some()
            }
        })
        .await;
        kept = mac
            .package(last)
            .map(|p| (p.event_id, p.descriptor.encode(), p.body, mac.acked(last)));
        if point == 1 {
            assert_eq!(hosted.edge.entries(mac.log()).len(), before, "not sent");
        }
        mc.0.shutdown().await;
        drop(mc);
    }
    drop(typist);
    let mac = mac.restart();
    hosted.come_up();
    if point != 3 {
        hosted.edge.freeze_reads(None);
    }
    let reopened = Instant::now();
    let mc = mac.start_named(&hosted, "typist");
    if point == 3 {
        until(120, "exact retry's original Ack", || {
            mac.acked(last).is_some()
        })
        .await;
        assert_eq!(mac.acked(last), Some((before + 1) as u64));
        assert_eq!(appends(&hosted, mac.log().id) - before, 2);
        hosted.edge.freeze_reads(None);
        mc.0.wake();
        fc.0.wake();
    }
    until(120, "shown after reopening", || {
        fold.paragraphs(note) == [SENTENCE]
    })
    .await;
    let shown = reopened.elapsed();
    until(120, "accepted after reopening", || mac.pending() == 0).await;
    assert_eq!(hosted.edge.entries(mac.log()).len() - before, 1);
    let package = mac.package(last).unwrap();
    let position = mac.acked(last);
    if let Some((id, descriptor, body, acked)) = kept {
        assert_eq!(package.event_id, id, "same event");
        assert_eq!(package.descriptor.encode(), descriptor, "exact descriptor");
        assert_eq!(package.body, body, "exact body");
        if let Some(acked) = acked {
            assert_eq!(position, Some(acked), "original position");
        }
    }
    let ordered = &hosted.edge.entries(mac.log())[before];
    assert_eq!(ordered.1.encode(), package.descriptor.encode());
    assert_eq!(mac.paragraphs(note), [SENTENCE]);
    same_note(&mac, &fold, note);
    report(
        &s,
        &format!("reopen{point}"),
        &format!(
            "reopen_to_shown_ms={} position={:?} exact_bytes=yes",
            shown.as_millis(),
            position
        ),
    );
    mc.0.shutdown().await;
    fc.0.shutdown().await;
}

macro_rules! matrix {
    ($($name:ident: $profile:literal, $rtt:literal;)*) => {$(
        mod $name {
            use super::*;
            fn setting() -> Setting {
                Setting::new($profile, $rtt)
            }
            #[tokio::test(start_paused = true)]
            async fn sentence() {
                let s = setting();
                let runs = super::sentence(s).await;
                if s.gated() {
                    let p95 = runs.last().unwrap();
                    assert!(p95.shown_after_pause <= GATE, "p95 within 2 s: {p95:?}");
                }
            }
            #[tokio::test(start_paused = true)]
            async fn phases() {
                let s = setting();
                let phases = super::phases(s, false, false).await;
                if s.gated() {
                    for p in &phases {
                        assert!(p.shown <= GATE, "every pause phase within 2 s: {p:?}");
                    }
                }
            }
            #[tokio::test(start_paused = true)]
            async fn sustained() {
                super::sustained(setting()).await;
            }
            #[tokio::test(start_paused = true)]
            async fn both() {
                super::both(setting()).await;
            }
            #[tokio::test(start_paused = true)]
            async fn offline() {
                super::offline(setting()).await;
            }
            #[tokio::test(start_paused = true)]
            async fn cold() {
                super::cold(setting()).await;
            }
            #[tokio::test(start_paused = true)]
            async fn reopen() {
                for point in 0..4 {
                    super::reopen(setting(), point).await;
                }
            }
        }
    )*};
}

matrix! {
    free_10: "free", 10;
    free_1500: "free", 1500;
    default_10: "default", 10;
    default_100: "default", 100;
    default_1500: "default", 1500;
}

// The stress rows: 300 ms round trips (measured, not gated) and the slow
// cost profile. Opt in with `bash scripts/check.sh qualification-stress`.
#[cfg(feature = "qualification-stress")]
matrix! {
    free_300: "free", 300;
    default_300: "default", 300;
    slow_10: "slow", 10;
    slow_300: "slow", 300;
    slow_1500: "slow", 1500;
}

/// The receiving device is offline for ten minutes of typing at human
/// speed (about 4,800 keystrokes, one every 125 ms) while the typist's
/// device publishes as it goes; then it reconnects and catches up.
#[cfg(feature = "qualification-stress")]
async fn catch_up(s: Setting) {
    catch_up_trace(s, false).await
}
async fn catch_up_trace(s: Setting, natural: bool) {
    let hosted = s.hosted();
    let (mac, mc, fold, fc) = two(&hosted, false).await;
    fc.0.shutdown().await;
    drop(fc);
    let log = mac.log();
    let before = hosted.edge.entries(log).len();
    let appends_before = appends(&hosted, log.id);
    let typing_counts_before = hosted.edge.counts();
    instrument(&mac);
    let mut typist = mac.new_typist();
    let keys = if natural { natural_ten_minutes() } else { 4800 };
    let text: String = "abcdefghijklmnopqrstuvwxyz "
        .chars()
        .cycle()
        .take(keys)
        .collect();
    let gaps = if natural {
        natural_gaps(keys, 0)
    } else {
        vec![ms(125)]
    };
    let start = Instant::now();
    let mut last = start;
    for (i, c) in text.chars().enumerate() {
        last = Instant::now();
        sleep(s.costs.commit).await;
        mac.type_key(&mut typist, c);
        mc.0.wake();
        if i + 1 < text.len() {
            sleep_until(last + gaps[i % gaps.len()]).await;
        }
    }
    let burst = last - start;
    until(600, "typist settled", || mac.pending() == 0).await;
    let events = hosted.edge.entries(log).len() - before;
    let typed_appends = appends(&hosted, log.id) - appends_before;
    let typed_commits = commits(&mac);
    let typed_counts = hosted.edge.counts() - typing_counts_before;
    assert!(
        events <= s.event_bound(burst) && typed_appends == events,
        "{}: {events} events, {typed_appends} appends over {burst:?}",
        s.label()
    );
    let counts_before = hosted.edge.counts();
    let reconnected = Instant::now();
    let fc = fold.start_named(&hosted, "reader");
    let target = mac.progress().position;
    while fold.progress().position < target {
        assert!(
            reconnected.elapsed() < Duration::from_secs(1800),
            "{}: never caught up",
            s.label()
        );
        sleep(ms(10)).await;
    }
    let caught_up = reconnected.elapsed();
    assert_eq!(fold.paragraphs(typist.note), vec![text.clone()]);
    same_note(&mac, &fold, typist.note);
    let c = hosted.edge.counts() - counts_before;
    let minutes = burst.as_secs_f64() / 60.0;
    report(
        &s,
        if natural {
            "natural_catch_up"
        } else {
            "catch_up"
        },
        &format!(
            "keys={} burst_ms={} events={events} appends={typed_appends} events_per_min={:.1} \
             commits_per_min={:.1} commits_keys={} seals={} acks={} received={} \
             typing_authz_up={}/{}B typing_authz_down={}/{}B typing_data_up={}/{}B typing_data_down={}/{}B \
             catch_up_ms={} read_batch={} read_bodies={} body_down={}B \
             data_up={}/{}B data_down={}/{}B authz_up={}/{}B authz_down={}/{}B edge_reads={}",
            text.len(),
            burst.as_millis(),
            events as f64 / minutes,
            typed_commits.total() as f64 / minutes,
            typed_commits.keystrokes,
            typed_commits.seals,
            typed_commits.acks,
            typed_commits.received,
            typed_counts.authz_up,
            typed_counts.authz_up_bytes,
            typed_counts.authz_down,
            typed_counts.authz_down_bytes,
            typed_counts.data_up,
            typed_counts.data_up_bytes,
            typed_counts.data_down,
            typed_counts.data_down_bytes,
            caught_up.as_millis(),
            c.read_batches,
            c.read_bodies,
            c.body_bytes_down,
            c.data_up,
            c.data_up_bytes,
            c.data_down,
            c.data_down_bytes,
            c.authz_up,
            c.authz_up_bytes,
            c.authz_down,
            c.authz_down_bytes,
            c.edge_reads,
        ),
    );
    mc.0.shutdown().await;
    fc.0.shutdown().await;
}

#[cfg(feature = "qualification-stress")]
macro_rules! sweep {
    ($($name:ident: $policy:literal, $rtt:literal;)*) => {$(
        mod $name {
            use super::*;
            fn setting() -> Setting {
                Setting::new("default", $rtt).policy($policy)
            }
            #[tokio::test(start_paused = true)]
            async fn sentence() {
                super::sentence(setting()).await;
            }
            #[tokio::test(start_paused = true)]
            async fn phases() {
                super::phases(setting(), false, false).await;
            }
            #[tokio::test(start_paused = true)]
            async fn sustained() {
                super::sustained(setting()).await;
            }
            #[tokio::test(start_paused = true)]
            async fn catch_up() {
                super::catch_up(setting()).await;
            }
        }
    )*};
}

// The pacing sweep compares report-only policies; opt in with `bash
// scripts/check.sh qualification-stress`.
#[cfg(feature = "qualification-stress")]
sweep! {
    sweep_s250_10: "S250", 10;
    sweep_s250_300: "S250", 300;
    sweep_s500_10: "S500", 10;
    sweep_s500_100: "S500", 100;
    sweep_s500_300: "S500", 300;
    sweep_s750_10: "S750", 10;
    sweep_s750_300: "S750", 300;
    sweep_s1000_10: "S1000", 10;
    sweep_s1000_300: "S1000", 300;
}

async fn isolated_edit(s: Setting) {
    let hosted = s.hosted();
    let (mac, mut mc, fold, fc) = two(&hosted, false).await;
    let mut typist = mac.new_typist();
    sleep(ms(3500)).await; // established idle, not a continuation of a word
    let m = type_burst(
        &s,
        &hosted,
        (&mac, &mut mc),
        &fold,
        None,
        &mut typist,
        Burst {
            text: "x",
            gaps: &[],
        },
    )
    .await;
    m.assert_bounded(&s);
    same_note(&mac, &fold, typist.note);
    report(&s, "isolated_edit", &m.line());
    mc.0.shutdown().await;
    fc.0.shutdown().await;
}

/// Paired policies consume the same fixed trace at every RTT; 300 ms is
/// stress, not a latency acceptance gate. Trace seed changes only where
/// the word boundary falls in the short sentence.
#[cfg(feature = "qualification-stress")]
macro_rules! natural_sweep {
    ($($name:ident: $policy:literal, $rtt:literal;)*) => {$(
        mod $name {
            use super::*;
            fn setting() -> Setting { Setting::new("default", $rtt).policy($policy) }
            #[tokio::test(start_paused = true)]
            async fn word_sentence() { super::sentence_trace(setting(), true, false).await; }
            #[tokio::test(start_paused = true)]
            async fn word_sustained() { super::sustained_trace(setting(), true).await; }
            #[tokio::test(start_paused = true)]
            async fn word_catch_up() { super::catch_up_trace(setting(), true).await; }
            #[tokio::test(start_paused = true)]
            async fn single_edit_after_idle() { super::isolated_edit(setting()).await; }
        }
    )*};
}

/// The same traces on the shipped default (Q300), which the table reports.
macro_rules! natural_shipped {
    ($($name:ident: $rtt:literal;)*) => {$(
        mod $name {
            use super::*;
            fn setting() -> Setting { Setting::new("default", $rtt) }
            #[tokio::test(start_paused = true)]
            async fn word_sentence() { super::sentence_trace(setting(), true, false).await; }
            #[tokio::test(start_paused = true)]
            async fn word_sustained() { super::sustained_trace(setting(), true).await; }
            #[tokio::test(start_paused = true)]
            async fn word_catch_up() { super::catch_up_trace(setting(), true).await; }
            #[tokio::test(start_paused = true)]
            async fn single_edit_after_idle() { super::isolated_edit(setting()).await; }
        }
    )*};
}
// The paired natural traces on the compared policies, and the 300 ms
// shipped-default row; opt in with `bash scripts/check.sh qualification-stress`.
#[cfg(feature = "qualification-stress")]
natural_sweep! {
    natural_s500_10: "S500", 10;
    natural_s500_100: "S500", 100;
    natural_s500_300: "S500", 300;
}
natural_shipped! {
    natural_shipped_10: 10;
    natural_shipped_100: 100;
}
#[cfg(feature = "qualification-stress")]
natural_shipped! {
    natural_shipped_300: 300;
}

/// A publication held at the edge past its grants' deadline is refused
/// `Expired` (the clock moves with the runtime), then published again with
/// fresh grants and the same bytes, once, while typing goes on: no work is
/// lost and the bounds hold.
#[tokio::test(start_paused = true)]
async fn a_grant_expiring_in_flight_is_renewed_with_the_same_bytes() {
    let s = Setting::new("default", 300);
    let hosted = s.hosted();
    let (mac, mut mc, fold, fc) = two(&hosted, false).await;
    let mut typist = mac.new_typist();
    let hold = hosted.edge.hold_next_stage();
    let text = "abcdefghij".repeat(30);
    let release = async {
        hold.arrived.await.unwrap();
        // Past the grants' 30 s, and past a subscription's renewal.
        sleep(Duration::from_secs(31)).await;
        let _ = hold.release.send(());
    };
    let (m, ()) = tokio::join!(
        type_burst(
            &s,
            &hosted,
            (&mac, &mut mc),
            &fold,
            None,
            &mut typist,
            Burst {
                text: &text,
                gaps: &[KEYSTROKE],
            },
        ),
        release
    );
    report(&s, "grant_expiry", &m.line());
    let expired = hosted
        .edge
        .seen()
        .iter()
        .filter(|s| {
            matches!(
                s,
                Seen::Refused {
                    reason: bh_sync::wire::Refusal::Expired
                }
            )
        })
        .count();
    assert!(expired >= 1, "the held grant expired: {m:?}");
    assert!(m.refused >= 1, "and it was published again: {m:?}");
    m.assert_bounded(&s);
    // Each sealed event is in the log once, with the bytes it was sealed with.
    let entries = hosted.edge.entries(mac.log());
    let ids: std::collections::HashSet<_> = entries
        .iter()
        .map(|(c, e)| e.publication_id(c.route()).0)
        .collect();
    assert_eq!(ids.len(), entries.len(), "no event ordered twice");
    assert_eq!(fold.paragraphs(typist.note), vec![text]);
    same_note(&mac, &fold, typist.note);
    mc.0.shutdown().await;
    fc.0.shutdown().await;
}

/// A large run uploading in one note on a constrained uplink while the
/// sentence is typed in another: how long the sentence takes to show.
/// Measured, not gated: the publisher's round still waits for all of its
/// Publish replies.
#[cfg(feature = "qualification-stress")]
async fn large_run_ahead(s: Setting, uplink: u64, size: usize) {
    let hosted = s.hosted();
    hosted.edge.set_uplink(Some(uplink));
    let (mac, mut mc, fold, fc) = two(&hosted, false).await;
    let mut large = mac.new_typist();
    let mut typist = mac.new_typist();
    // About 200 KiB in one paste: one package in the 256 KiB body class.
    // Without it, the same sentence alone on the same uplink.
    let paste = "x".repeat(size);
    let pasted = Instant::now();
    if size > 0 {
        sleep(s.costs.commit).await;
        mac.type_text(&mut large, &paste);
        mc.0.wake();
    }
    sleep(ms(50)).await;
    let m = type_burst(
        &s,
        &hosted,
        (&mac, &mut mc),
        &fold,
        None,
        &mut typist,
        Burst {
            text: SENTENCE,
            gaps: &[KEYSTROKE],
        },
    )
    .await;
    if size > 0 {
        assert_eq!(fold.paragraphs(large.note), vec![paste]);
        same_note(&mac, &fold, large.note);
    }
    assert_eq!(fold.paragraphs(typist.note), vec![SENTENCE.to_string()]);
    same_note(&mac, &fold, typist.note);
    report(
        &s,
        &format!("large_run_ahead_uplink_{uplink}Bps_paste_{size}B"),
        &format!(
            "sentence_shown_after_pause_ms={} paste_to_settled_ms={} {}",
            m.shown_after_pause.as_millis(),
            pasted.elapsed().as_millis(),
            m.line()
        ),
    );
    mc.0.shutdown().await;
    fc.0.shutdown().await;
}

#[cfg(feature = "qualification-stress")]
#[tokio::test(start_paused = true)]
async fn a_large_run_in_one_note_ahead_of_the_sentence_in_another() {
    // 1 Mbit/s and 4 Mbit/s uplinks, with and without the large run.
    for uplink in [125_000, 500_000] {
        for size in [200 * 1024, 0] {
            large_run_ahead(Setting::new("default", 300), uplink, size).await;
        }
    }
}

/// Sensitivity to the hop assumption: the default signer and commit with
/// 5 ms hops. Measured, not gated; opt in with `bash scripts/check.sh
/// qualification-stress`.
#[cfg(feature = "qualification-stress")]
mod near_300 {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn sentence() {
        super::sentence(Setting::new("near", 300)).await;
    }
    #[tokio::test(start_paused = true)]
    async fn phases() {
        super::phases(Setting::new("near", 300), false, false).await;
    }
}
