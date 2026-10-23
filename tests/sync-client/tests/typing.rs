//! Typing on one device reaches the other within seconds, over the shared
//! production client and the fake hosted environment with an injected round
//! trip on every socket. Time is the runtime's paused clock: nothing here
//! waits on the wall clock, so each measured duration is what the injected
//! latency and the client's own timers make it.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_sync_client::{Client, SyncStatus};
use std::{sync::Arc, time::Duration};
use support::{
    device::{Device, Typist, until},
    fake::{Hosted, Seen},
};
use tokio::{
    sync::watch,
    time::{Instant, sleep},
};

type Started = (Client, watch::Receiver<SyncStatus>);

const SENTENCE: &str = "Hi, this is a test";
/// About eight keystrokes a second.
const KEYSTROKE: Duration = Duration::from_millis(120);
/// The client's minimum spacing between one note's new package starts.
const SPACING: Duration = Duration::from_millis(500);

/// Events (and appends) an unsplit single-writer burst may cost: one at
/// its first keystroke, then at most one per started spacing interval,
/// including the final flush. Keystroke count does not appear.
fn event_bound(burst: Duration) -> usize {
    1 + burst.as_millis().div_ceil(SPACING.as_millis()) as usize
}

/// Authorization messages a burst may cost on both devices: per package one
/// write-grant request from the typist, one ReadBatch for its own echo and
/// one for the reader. Per device, one renewal of its subscriptions (taken
/// together, renewed in one message) for each started 25 s usable permit
/// life, plus one because the burst need not start where a life does; and
/// one empty read when a notice races its read.
fn authz_bound(events: usize, burst: Duration) -> usize {
    let lives = burst.as_millis().div_ceil(25_000) as usize;
    let renewals = 2 * (1 + lives);
    3 * events + renewals + 2
}

fn copied(device: &Device) -> u64 {
    device
        .progress()
        .account
        .map_or(0, |(position, _)| position)
}

/// Two devices of one account on the first one's base, both caught up.
async fn two(hosted: &Arc<Hosted>) -> (Device, Started, Device, Started) {
    let mac = Device::new();
    let mac_client = mac.start(hosted);
    until(60, "registered", || {
        mac.registered() && mac.progress().position >= 1
    })
    .await;
    let fold = Device::join(&mac, hosted).await;
    until(60, "addition copied", || copied(&mac) == 4).await;
    let fold_client = fold.start(hosted);
    until(60, "joined device caught up", || {
        fold.progress().position == mac.progress().position && copied(&fold) == 4
    })
    .await;
    (mac, mac_client, fold, fold_client)
}

/// The count the status line shows, if it shows one.
fn shown(status: &mut watch::Receiver<SyncStatus>) -> u64 {
    match *status.borrow_and_update() {
        SyncStatus::Syncing { pending } | SyncStatus::SavedLocal { pending } => pending,
        _ => 0,
    }
}

/// Record, as each package is sealed, how many of this device's packages
/// are sealed and not yet acknowledged. That count only rises at a seal, so
/// its high water is observed at every transition, not sampled.
fn count_unacknowledged_at_each_seal(device: &Device) {
    device
        .raw()
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS test_unacknowledged(n INTEGER);
             DELETE FROM test_unacknowledged;
             CREATE TRIGGER IF NOT EXISTS test_unacknowledged AFTER INSERT ON note_outbox BEGIN
               INSERT INTO test_unacknowledged SELECT COUNT(*) FROM note_outbox o
                 LEFT JOIN note_outbox_progress p USING(update_id) WHERE p.outcome IS NULL;
             END;",
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

/// What typing one burst cost and how long it took to show elsewhere.
#[derive(Debug)]
struct Measured {
    keystrokes: usize,
    /// Content events ordered in the log for the burst.
    events: usize,
    /// Appends the edge received for the burst, retries included.
    appends: usize,
    /// Messages both devices sent on their authorization sockets.
    authz_messages: usize,
    /// The largest count the typing device's status line showed.
    max_shown: u64,
    /// The most packages sealed and not yet acknowledged at once.
    max_unacknowledged: usize,
    /// From the last keystroke until the other device showed the text.
    shown_after_pause: Duration,
    /// From the first keystroke to the last, traced as they were typed.
    burst: Duration,
    /// Body bytes the edge staged for the burst.
    staged_bytes: usize,
}

impl Measured {
    /// The derived cost bounds for an unsplit single-writer burst, and the
    /// status/in-flight bounds, whatever the round trip.
    fn assert_bounded(&self) {
        let events = event_bound(self.burst);
        assert!(
            self.events <= events && self.appends == self.events,
            "events bounded by spacing, not keystrokes ({events}): {self:?}"
        );
        assert!(
            self.authz_messages <= authz_bound(self.events, self.burst),
            "authorization cost ({}): {self:?}",
            authz_bound(self.events, self.burst)
        );
        assert!(
            self.staged_bytes <= self.events * bh_sync::BODY_SIZES[0],
            "each small run stages one smallest padded body: {self:?}"
        );
        assert!(
            self.max_shown <= 1,
            "the status never counts keystrokes: {self:?}"
        );
        assert!(self.max_unacknowledged <= 1, "{self:?}");
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

/// Type `text` on `mac`, one keystroke every `gap`, waking its client as the
/// host does after each save; then wait until `fold` shows it.
async fn type_and_wait(
    hosted: &Arc<Hosted>,
    (mac, mac_client): (&Device, &mut Started),
    fold: &Device,
    typist: &mut Typist,
    text: &str,
    gap: Duration,
) -> Measured {
    let log = mac.log();
    let events_before = hosted.edge.entries(log).len();
    let staged_before: usize = hosted.edge.stages(log.id).iter().map(Vec::len).sum();
    let appends_before = appends(hosted, log.id);
    let authz_before = hosted
        .edge
        .authz_messages
        .load(std::sync::atomic::Ordering::SeqCst);
    count_unacknowledged_at_each_seal(mac);
    // Every status value the client publishes, as it is delivered.
    let shown_high = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let monitor = {
        let mut status = mac_client.1.clone();
        let high = shown_high.clone();
        tokio::spawn(async move {
            loop {
                high.fetch_max(shown(&mut status), std::sync::atomic::Ordering::SeqCst);
                if status.changed().await.is_err() {
                    return;
                }
            }
        })
    };
    let mut max_shown = 0;
    let mut max_unacknowledged = 0;
    let note = typist.note;
    let typed = |device: &Device| device.paragraphs(note).iter().any(|p| p == text);
    // Traced explicitly: the first keystroke is typed now.
    let start = Instant::now();
    let mut paused = start;
    for c in text.chars() {
        paused = Instant::now();
        mac.type_key(typist, c);
        mac_client.0.wake();
        sleep(gap).await;
        max_shown = max_shown.max(shown(&mut mac_client.1));
        max_unacknowledged = max_unacknowledged.max(unacknowledged_packages(mac));
    }
    while !typed(fold) {
        assert!(paused.elapsed() < Duration::from_secs(360), "never shown");
        sleep(Duration::from_millis(10)).await;
        max_shown = max_shown.max(shown(&mut mac_client.1));
        max_unacknowledged = max_unacknowledged.max(unacknowledged_packages(mac));
    }
    let shown_after_pause = paused.elapsed();
    if std::env::var_os("TYPING_TIMELINE").is_some() {
        for (at, seen) in hosted.edge.timed() {
            if at < start {
                continue;
            }
            let what = match seen {
                Seen::Stage { .. } => "stage".to_string(),
                Seen::Append { .. } => "append".to_string(),
                Seen::Acked { position, .. } => format!("acked {position}"),
                Seen::Read { first, last, .. } => format!("read {first}..={last}"),
                Seen::Arrived { .. } => continue,
                other => format!("{other:?}"),
            };
            println!("{:>8} ms {what}", (at - start).as_millis());
        }
    }
    until(120, "typing device settled", || mac.pending() == 0).await;
    monitor.abort();
    max_shown = max_shown.max(shown_high.load(std::sync::atomic::Ordering::SeqCst));
    max_unacknowledged = max_unacknowledged.max(most_unacknowledged(mac));
    Measured {
        keystrokes: text.chars().count(),
        events: hosted.edge.entries(log).len() - events_before,
        appends: appends(hosted, log.id) - appends_before,
        authz_messages: hosted
            .edge
            .authz_messages
            .load(std::sync::atomic::Ordering::SeqCst)
            - authz_before,
        max_shown,
        max_unacknowledged,
        shown_after_pause,
        burst: paused - start,
        staged_bytes: hosted
            .edge
            .stages(log.id)
            .iter()
            .map(Vec::len)
            .sum::<usize>()
            - staged_before,
    }
}

async fn typical_case(round_trip: Duration) -> Measured {
    let hosted = Hosted::new();
    hosted.edge.set_latency(round_trip);
    let (mac, mut mac_client, fold, fold_client) = two(&hosted).await;
    let mut typist = mac.new_typist();
    let measured = type_and_wait(
        &hosted,
        (&mac, &mut mac_client),
        &fold,
        &mut typist,
        SENTENCE,
        KEYSTROKE,
    )
    .await;
    println!("round trip {round_trip:?}: {measured:?}");
    assert_eq!(fold.paragraphs(typist.note), vec![SENTENCE.to_string()]);
    mac_client.0.shutdown().await;
    fold_client.0.shutdown().await;
    measured
}

/// The reference case: "Hi, this is a test" typed at about eight keystrokes a
/// second, with a 300 ms round trip on every request.
#[tokio::test(start_paused = true)]
async fn a_typed_sentence_shows_on_the_other_device_within_seconds() {
    let mut runs =
        futures_util::future::join_all((0..10).map(|_| typical_case(Duration::from_millis(300))))
            .await;
    runs.sort_by_key(|m| m.shown_after_pause);
    let m = runs.last().unwrap(); // nearest-rank p95 of ten independent runs
    println!("ten-run p95: {:?}", m.shown_after_pause);
    assert_eq!(m.keystrokes, 18);
    assert_eq!(m.burst, KEYSTROKE * 17, "first to last keystroke");
    for r in &runs {
        r.assert_bounded();
    }
    assert!(
        m.shown_after_pause <= Duration::from_secs(2),
        "shown within 2 s of the pause: {m:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn sustained_typing_bounds_events_bytes_and_the_status_count() {
    sustained(Duration::from_millis(300)).await;
}

/// Three hundred keystrokes at about eight a second, then a pause.
async fn sustained(round_trip: Duration) -> Measured {
    let hosted = Hosted::new();
    hosted.edge.set_latency(round_trip);
    let (mac, mut mc, fold, fc) = two(&hosted).await;
    let mut typist = mac.new_typist();
    let text = "abcdefghij".repeat(30);
    let m = type_and_wait(
        &hosted,
        (&mac, &mut mc),
        &fold,
        &mut typist,
        &text,
        KEYSTROKE,
    )
    .await;
    println!("sustained, round trip {round_trip:?}: {m:?}");
    assert_eq!(m.keystrokes, 300);
    assert_eq!(m.burst, KEYSTROKE * 299, "first to last keystroke");
    m.assert_bounded();
    assert_eq!(
        mac.reopened(typist.note).digest().unwrap(),
        fold.reopened(typist.note).digest().unwrap()
    );
    mc.0.shutdown().await;
    fc.0.shutdown().await;
    m
}

/// On a fast link rounds are quick: only the spacing keeps publication from
/// following every keystroke.
#[tokio::test(start_paused = true)]
async fn a_fast_link_publishes_by_spacing_not_by_keystroke() {
    let runs =
        futures_util::future::join_all((0..10).map(|_| typical_case(Duration::from_millis(10))))
            .await;
    for r in &runs {
        r.assert_bounded();
        assert!(r.shown_after_pause <= Duration::from_secs(2), "{r:?}");
    }
    let mut times: Vec<_> = runs.iter().map(|r| r.shown_after_pause).collect();
    times.sort();
    println!("fast-link ten-run p95: {:?}", times.last().unwrap());
}

#[tokio::test(start_paused = true)]
async fn sustained_typing_on_a_fast_link_is_bounded_by_spacing() {
    let m = sustained(Duration::from_millis(10)).await;
    assert!(m.shown_after_pause <= Duration::from_secs(2), "{m:?}");
}

#[tokio::test(start_paused = true)]
async fn fifty_keys_while_the_first_package_is_in_flight_make_only_two_packages() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(300));
    let (mac, mc, fold, fc) = two(&hosted).await;
    let before = hosted.edge.entries(mac.log()).len();
    let mut typist = mac.new_typist();
    mac.type_key(&mut typist, 'a');
    mc.0.wake();
    until(20, "first sealed", || unacknowledged_packages(&mac) == 1).await;
    for _ in 0..50 {
        mac.type_key(&mut typist, 'b');
    }
    mc.0.wake();
    until(40, "fifty received", || {
        fold.paragraphs(typist.note) == [format!("a{}", "b".repeat(50))]
    })
    .await;
    until(40, "own echo", || mac.pending() == 0).await;
    assert_eq!(hosted.edge.entries(mac.log()).len() - before, 2);
    assert_eq!(
        mac.reopened(typist.note).digest().unwrap(),
        fold.reopened(typist.note).digest().unwrap()
    );
    mc.0.shutdown().await;
    fc.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn an_offline_burst_is_one_package_on_reconnect() {
    let hosted = Hosted::new();
    let (mac, mc, fold, fc) = two(&hosted).await;
    mc.0.shutdown().await;
    let before = hosted.edge.entries(mac.log()).len();
    let mut typist = mac.new_typist();
    let text = "offline ".repeat(25);
    for c in text.chars() {
        mac.type_key(&mut typist, c);
    }
    let mc = mac.start(&hosted);
    until(40, "offline burst received", || {
        fold.paragraphs(typist.note) == [text.clone()]
    })
    .await;
    until(40, "offline burst accepted", || mac.pending() == 0).await;
    assert_eq!(hosted.edge.entries(mac.log()).len() - before, 1);
    mc.0.shutdown().await;
    fc.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn both_devices_keep_typing_while_publishing_and_converge() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(300));
    let (mac, mc, fold, fc) = two(&hosted).await;
    let mut a = mac.new_typist();
    mac.type_key(&mut a, 'A');
    mc.0.wake();
    until(30, "shared note", || fold.paragraphs(a.note) == ["A"]).await;
    let mut b = fold.typist(a.note);
    for _ in 0..60 {
        mac.type_key(&mut a, 'a');
        fold.type_key(&mut b, 'b');
        mc.0.wake();
        fc.0.wake();
        sleep(KEYSTROKE).await;
    }
    until(60, "both settled", || {
        mac.pending() == 0
            && fold.pending() == 0
            && mac.progress().position == fold.progress().position
    })
    .await;
    let mut text = fold.paragraphs(a.note);
    text.sort();
    assert_eq!(text, [format!("A{}", "a".repeat(60)), "b".repeat(60)]);
    assert_eq!(
        mac.reopened(a.note).digest().unwrap(),
        fold.reopened(a.note).digest().unwrap()
    );
    mc.0.shutdown().await;
    fc.0.shutdown().await;
}

/// Actual SQLite and owner reopen, not just restarting the loop on a retained
/// connection. Each point has its own keys, directory and paused runtime.
async fn restart_at(point: u8) {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(300));
    let (mac, mc, fold, fc) = two(&hosted).await;
    mc.0.shutdown().await;
    drop(mc);
    let before = hosted.edge.entries(mac.log()).len();
    let mut typist = mac.new_typist();
    let mut last = 0;
    for c in SENTENCE.chars() {
        last = mac.type_key(&mut typist, c);
    }
    let note = typist.note;
    let mut kept = None;
    if point > 0 {
        hosted.edge.freeze_reads(Some(mac.progress().position));
        if point == 3 {
            hosted
                .edge
                .hook(support::fake::Hook::DropAfterAppend { then_down: true });
        }
        let mc = mac.start(&hosted);
        until(30, "sealed or acked before crash", || {
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
            assert_eq!(
                hosted.edge.entries(mac.log()).len(),
                before,
                "sealed, not sent"
            );
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
    let mc = mac.start(&hosted);
    if point == 3 {
        until(60, "exact retry ack", || mac.acked(last).is_some()).await;
        assert_eq!(mac.acked(last), Some((before + 1) as u64));
        assert_eq!(appends(&hosted, mac.log().id) - before, 2);
        hosted.edge.freeze_reads(None);
        mc.0.wake();
        fc.0.wake();
    }
    until(60, "restart received", || {
        fold.paragraphs(note) == [SENTENCE]
    })
    .await;
    until(60, "restart accepted", || mac.pending() == 0).await;
    assert_eq!(hosted.edge.entries(mac.log()).len() - before, 1);
    let package = mac.package(last).unwrap();
    if let Some((id, descriptor, body, position)) = kept {
        assert_eq!(package.event_id, id);
        assert_eq!(package.descriptor.encode(), descriptor);
        assert_eq!(package.body, body);
        if let Some(position) = position {
            assert_eq!(mac.acked(last), Some(position));
        }
    }
    assert_eq!(mac.paragraphs(note), [SENTENCE]);
    mc.0.shutdown().await;
    fc.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn reopen_between_local_save_and_publish() {
    restart_at(0).await;
}
#[tokio::test(start_paused = true)]
async fn reopen_after_sealing_before_sending() {
    restart_at(1).await;
}
#[tokio::test(start_paused = true)]
async fn reopen_after_ack_before_echo() {
    restart_at(2).await;
}

#[tokio::test(start_paused = true)]
async fn lost_ack_reopens_and_retries_the_exact_run_at_the_original_position() {
    restart_at(3).await;
}

/// The same sentence over a slow, 1.5 s round trip.
#[tokio::test(start_paused = true)]
async fn a_typed_sentence_over_a_slow_link_is_still_a_few_packages() {
    let m = typical_case(Duration::from_millis(1500)).await;
    m.assert_bounded();
    assert!(
        m.events <= 3,
        "events bounded by rounds, not keystrokes: {m:?}"
    );
}
