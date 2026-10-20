//! Publishing and receiving progress independently, over the production
//! client and the fake hosted environment with an injected round trip on
//! every socket. The runtime's clock is paused: every duration below is the
//! injected latency, the client's own timers and the held steps.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_sync_client::{Client, SyncStatus};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::Duration,
};
use support::{
    device::{Device, until},
    fake::{Hosted, Seen},
};
use tokio::{
    sync::watch,
    time::{Instant, sleep, timeout},
};

type Started = (Client, watch::Receiver<SyncStatus>);

/// One registered device whose genesis is applied.
async fn one(hosted: &Arc<Hosted>) -> (Device, Started) {
    let mac = Device::new();
    let started = mac.start(hosted);
    until(60, "registered", || {
        mac.registered() && mac.progress().position >= 1
    })
    .await;
    (mac, started)
}

fn copied(device: &Device) -> u64 {
    device
        .progress()
        .account
        .map_or(0, |(position, _)| position)
}

/// Two devices of one account on the first one's base, both caught up.
async fn two(hosted: &Arc<Hosted>) -> (Device, Started, Device, Started) {
    let (mac, mac_client) = one(hosted).await;
    let fold = Device::join(&mac, hosted);
    until(60, "addition copied", || copied(&mac) == 4).await;
    let fold_client = fold.start(hosted);
    until(60, "joined device caught up", || {
        fold.progress().position == mac.progress().position && copied(&fold) == 4
    })
    .await;
    (mac, mac_client, fold, fold_client)
}

fn publishes(hosted: &Hosted) -> usize {
    hosted
        .edge
        .seen()
        .iter()
        .filter(|s| matches!(s, Seen::Publish { .. }))
        .count()
}

/// The client's minimum spacing between one note's new package starts.
const SPACING: Duration = Duration::from_millis(500);
const KEYSTROKE: Duration = Duration::from_millis(120);

/// When each package of this device is sealed from now on, observed every
/// millisecond of the paused clock. Nothing waits between capturing a run
/// and persisting its seal here (the test signer answers at once), so each
/// instant is its package's start, at most a millisecond late.
fn record_seals(device: &Device) -> (tokio::task::JoinHandle<()>, Arc<Mutex<Vec<Instant>>>) {
    let raw = device.raw();
    let ids = |raw: &rusqlite::Connection| -> Vec<i64> {
        let mut statement = raw.prepare("SELECT update_id FROM note_outbox").unwrap();
        statement
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    let mut known: HashSet<i64> = ids(&raw).into_iter().collect();
    let seals = Arc::new(Mutex::new(Vec::new()));
    let seen = seals.clone();
    let task = tokio::spawn(async move {
        loop {
            for id in ids(&raw) {
                if known.insert(id) {
                    seen.lock().unwrap().push(Instant::now());
                }
            }
            sleep(Duration::from_millis(1)).await;
        }
    });
    (task, seals)
}

/// The package covering this update.
fn covering(device: &Device, update_id: i64) -> i64 {
    device
        .raw()
        .query_row(
            "SELECT COALESCE(
                (SELECT package_update_id FROM note_outbox_members WHERE update_id=?1),
                (SELECT update_id FROM note_outbox WHERE update_id=?1))",
            [update_id],
            |r| r.get(0),
        )
        .unwrap()
}

/// Every new package start at least the spacing after the one before,
/// allowing the millisecond each observation may lag.
fn assert_paced(seals: &[Instant]) {
    for pair in seals.windows(2) {
        let gap = pair[1] - pair[0];
        assert!(
            gap >= SPACING - Duration::from_millis(1),
            "package started {gap:?} after the one before"
        );
    }
}

/// Sealed packages of this device not yet acknowledged.
fn unacknowledged(device: &Device) -> usize {
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

#[tokio::test(start_paused = true)]
async fn a_stalled_body_read_does_not_delay_the_next_publish() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(300));
    let (mac, started) = one(&hosted).await;
    // Another producer's event whose body stream this device then stalls on.
    let hold = hosted.edge.hold_next_body_read();
    mac.remote_note(&hosted, [99; 32], b"a body that stalls");
    started.0.wake();
    timeout(Duration::from_secs(20), hold.arrived)
        .await
        .expect("body read reached the edge")
        .unwrap();
    let (_writer, update) = mac.new_note("published while receiving stalls");
    started.0.wake();
    let typed = Instant::now();
    until(10, "acknowledged while a body read is held", || {
        mac.acked(update).is_some()
    })
    .await;
    let published = typed.elapsed();
    println!("published {published:?} after the save, body read still held");
    // The shipped quiet period, then permit and Publish: two round trips,
    // no wait for the stalled read.
    assert!(published <= Duration::from_millis(950), "{published:?}");
    let _ = hold.release.send(());
    until(30, "own echo after the stall ends", || mac.pending() == 0).await;
    started.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_slow_batch_reply_delays_publication_only_by_its_fifo_wait() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(300));
    let (mac, started) = one(&hosted).await;
    // The receiver's next ReadBatch reply is held on the authorization
    // socket; a permit request behind it on that socket waits in FIFO order.
    let hold = hosted.edge.hold_next_batch_reply();
    mac.remote_note(&hosted, [98; 32], b"read through a slow reply");
    started.0.wake();
    timeout(Duration::from_secs(20), hold.arrived)
        .await
        .unwrap()
        .unwrap();
    let held_at = Instant::now();
    let (_writer, update) = mac.new_note("queued behind the slow reply");
    started.0.wake();
    let slow = Duration::from_secs(2);
    sleep(slow).await;
    assert!(mac.acked(update).is_none(), "the FIFO wait is unavoidable");
    let _ = hold.release.send(());
    until(10, "acknowledged once the reply arrived", || {
        mac.acked(update).is_some()
    })
    .await;
    let after_release = held_at.elapsed() - slow;
    println!(
        "slow ReadBatch reply held {slow:?}: publication waited it out, then {after_release:?}"
    );
    // After the reply the queued permit is already on its way: at most the
    // rest of its round trip and one for Publish, with no other barrier.
    assert!(
        after_release <= Duration::from_millis(700),
        "{after_release:?}"
    );
    started.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn rapid_local_commits_wake_publication_without_a_poll() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(10));
    let (mac, mut started, fold, fold_started) = two(&hosted).await;
    let mut typist = mac.new_typist();
    // Idle well past the spacing, then a burst of commits with no yield
    // between them, each followed by the host's wake.
    sleep(Duration::from_secs(3)).await;
    let before = publishes(&hosted);
    let typed = Instant::now();
    for c in "rapid burst".chars() {
        mac.type_key(&mut typist, c);
        started.0.wake();
    }
    until(5, "published", || publishes(&hosted) > before).await;
    let first = typed.elapsed();
    until(5, "shown on the other device", || {
        fold.paragraphs(typist.note) == ["rapid burst"]
    })
    .await;
    let shown = typed.elapsed();
    println!("first publication after {first:?}, shown after {shown:?}");
    // Woken by the commits: the shipped 300 ms quiet period is well inside
    // the one-second poll, so a burst still publishes before it.
    assert!(first <= Duration::from_millis(500), "{first:?}");
    assert!(shown <= Duration::from_millis(700), "{shown:?}");
    until(5, "settled", || mac.pending() == 0).await;
    assert!(matches!(
        *started.1.borrow_and_update(),
        SyncStatus::Synced | SyncStatus::Syncing { .. }
    ));
    started.0.shutdown().await;
    fold_started.0.shutdown().await;
}

/// The final keystroke lands `phase` after the note's latest package
/// started; the text must still show within 2 s of the pause, at the
/// derived event cost.
async fn pause_after_start(round_trip: Duration, phase: Duration) {
    let hosted = Hosted::new();
    hosted.edge.set_latency(round_trip);
    let (mac, started, fold, fold_started) = two(&hosted).await;
    let mut typist = mac.new_typist();
    let log = mac.log();
    let before = hosted.edge.entries(log).len();
    let first = Instant::now();
    mac.type_key(&mut typist, 'a');
    started.0.wake();
    // The package starts when its run is captured and sealed.
    while unacknowledged(&mac) == 0 {
        sleep(Duration::from_millis(1)).await;
    }
    let package_start = Instant::now();
    sleep(phase).await;
    let last = Instant::now();
    mac.type_key(&mut typist, 'b');
    started.0.wake();
    while fold.paragraphs(typist.note) != ["ab"] {
        assert!(last.elapsed() < Duration::from_secs(30), "never shown");
        sleep(Duration::from_millis(1)).await;
    }
    let shown = last.elapsed();
    until(30, "settled", || mac.pending() == 0).await;
    let events = hosted.edge.entries(log).len() - before;
    let burst = last - first;
    println!(
        "round trip {round_trip:?}, final key {:?} after a package start: \
         shown {shown:?}, {events} events over {burst:?}",
        last - package_start
    );
    assert!(
        events <= 1 + burst.as_millis().div_ceil(500) as usize,
        "{events} events over {burst:?}"
    );
    assert!(shown <= Duration::from_secs(2), "{shown:?}");
    started.0.shutdown().await;
    fold_started.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn every_pause_phase_shows_within_two_seconds_on_a_fast_link() {
    for phase in [10, 250, 490, 510] {
        pause_after_start(Duration::from_millis(10), Duration::from_millis(phase)).await;
    }
}

#[tokio::test(start_paused = true)]
async fn every_pause_phase_shows_within_two_seconds_at_300_ms() {
    for phase in [10, 250, 490, 510] {
        pause_after_start(Duration::from_millis(300), Duration::from_millis(phase)).await;
    }
}

#[tokio::test(start_paused = true)]
async fn an_edit_after_idle_waits_out_the_quiet_period() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(10));
    let (mac, started) = one(&hosted).await;
    let mut typist = mac.new_typist();
    for word in ["one", "two"] {
        // Idle past the tracker's memory each time.
        sleep(Duration::from_secs(2)).await;
        let before = publishes(&hosted);
        let typed = Instant::now();
        for c in word.chars() {
            mac.type_key(&mut typist, c);
        }
        started.0.wake();
        until(5, "published", || publishes(&hosted) > before).await;
        // The shipped quiet period, then seal, permit round trip and half
        // a round trip to the edge: woken by the host, not the poll.
        let published = typed.elapsed();
        assert!(
            published <= Duration::from_millis(400),
            "{word}: {published:?}"
        );
        assert!(
            published >= Duration::from_millis(300),
            "{word}: {published:?}"
        );
    }
    started.0.shutdown().await;
}

/// Rows pending before this client started carry no edit time in memory:
/// they are a backlog, not typing, so the first publish does not sit out a
/// quiet period. The run's own edits still do (see the test above).
#[tokio::test(start_paused = true)]
async fn a_backlog_from_before_start_is_published_without_a_quiet_wait() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(10));
    // Control: what starting a client costs with nothing pending.
    let control_device = Device::new();
    let control_at = Instant::now();
    let (control, _control_status) = control_device.start(&hosted);
    until(20, "control registered", || {
        control_device.registered() && control_device.progress().position >= 1
    })
    .await;
    let registered = control_at.elapsed();
    control.shutdown().await;
    let mac = Device::new();
    // Typed before any client for this device exists: no wake ever timed it.
    let (_writer, update) = mac.new_note("typed while stopped");
    let started_at = Instant::now();
    let (client, _status) = mac.start(&hosted);
    until(10, "backlog acknowledged", || mac.acked(update).is_some()).await;
    let published = started_at.elapsed();
    println!("backlog published {published:?} after start, registration alone {registered:?}");
    // Registration, a seal and one publish, but no 300 ms quiet wait: that
    // wait alone would take the same start far past this bound.
    assert!(
        published <= registered + Duration::from_millis(100),
        "{published:?}"
    );
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn notes_typed_together_each_get_their_own_spacing() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(10));
    let (mac, started, fold, fold_started) = two(&hosted).await;
    let mut typists: Vec<_> = (0..3).map(|_| mac.new_typist()).collect();
    let log = mac.log();
    let before = hosted.edge.entries(log).len();
    let first = Instant::now();
    let mut last = first;
    for round in 0..20 {
        for typist in &mut typists {
            mac.type_key(typist, char::from(b'a' + round));
        }
        last = Instant::now();
        started.0.wake();
        sleep(Duration::from_millis(120)).await;
    }
    let text: String = (0..20).map(|n| char::from(b'a' + n)).collect();
    let paused = last;
    for typist in &typists {
        until(10, "each note shown", || {
            fold.paragraphs(typist.note) == [text.clone()]
        })
        .await;
    }
    let shown = paused.elapsed();
    until(20, "settled", || mac.pending() == 0).await;
    let burst = last - first;
    let bound = typists.len() * (1 + burst.as_millis().div_ceil(500) as usize);
    let events = hosted.edge.entries(log).len() - before;
    println!("three notes: {events} events over {burst:?} (bound {bound}), shown {shown:?}");
    assert!(events <= bound, "{events} > {bound}");
    assert!(shown <= Duration::from_secs(2), "{shown:?}");
    started.0.shutdown().await;
    fold_started.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn revocation_while_signing_sends_and_seals_nothing() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(300));
    let (mac, started) = one(&hosted).await;
    let hold = mac.signer.hold_next_sign();
    let (_writer, update) = mac.new_note("signed as authority ends");
    started.0.wake();
    timeout(Duration::from_secs(10), hold.arrived)
        .await
        .unwrap()
        .unwrap();
    let before = publishes(&hosted);
    // Lock: every authority minted before is superseded.
    mac.signer.relock();
    let _ = hold.release.send(());
    sleep(Duration::from_secs(5)).await;
    assert_eq!(
        publishes(&hosted),
        before,
        "no publication after revocation"
    );
    assert!(mac.package(update).is_none(), "nothing sealed under it");
    assert_eq!(mac.pending(), 1, "the local work is kept");
    mac.authorize().unwrap();
    started.0.wake();
    until(30, "published under the new authority", || {
        mac.pending() == 0
    })
    .await;
    started.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn revocation_during_a_body_read_commits_nothing() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(300));
    let (mac, started) = one(&hosted).await;
    let hold = hosted.edge.hold_next_body_read();
    mac.remote_note(&hosted, [97; 32], b"read as authority ends");
    started.0.wake();
    timeout(Duration::from_secs(20), hold.arrived)
        .await
        .unwrap()
        .unwrap();
    let position = mac.progress().position;
    mac.signer.relock();
    let _ = hold.release.send(());
    sleep(Duration::from_secs(5)).await;
    assert_eq!(
        mac.progress().position,
        position,
        "nothing committed under superseded authority"
    );
    mac.authorize().unwrap();
    started.0.wake();
    until(30, "committed under the new authority", || {
        mac.progress().position == hosted.edge.head(mac.log()).position
    })
    .await;
    started.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn revocation_while_connecting_sends_nothing_and_keeps_the_exact_package() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(300));
    let (mac, started) = one(&hosted).await;
    // The publisher opens its own data link at its first publication.
    let hold = hosted.edge.hold_next_data_connect();
    let (_writer, update) = mac.new_note("sealed, then authority ends");
    started.0.wake();
    timeout(Duration::from_secs(10), hold.arrived)
        .await
        .unwrap()
        .unwrap();
    let sealed = mac.package(update).expect("sealed before connecting");
    let before = publishes(&hosted);
    mac.signer.relock();
    let _ = hold.release.send(());
    sleep(Duration::from_secs(5)).await;
    assert_eq!(
        publishes(&hosted),
        before,
        "nothing enqueued after revocation"
    );
    mac.authorize().unwrap();
    started.0.wake();
    until(30, "acknowledged under the new authority", || {
        mac.acked(update).is_some()
    })
    .await;
    let kept = mac.package(update).unwrap();
    assert_eq!(kept.descriptor.encode(), sealed.descriptor.encode());
    assert_eq!(kept.body, sealed.body);
    assert!(hosted.edge.seen().iter().all(|s| match s {
        Seen::Publish { event, body } if *event == sealed.descriptor.encode() => {
            *body == sealed.body
        }
        _ => true,
    }));
    started.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_stop_while_signing_seals_and_sends_nothing() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(300));
    let (mac, mut started) = one(&hosted).await;
    let hold = mac.signer.hold_next_sign();
    let (_writer, update) = mac.new_note("signed as the log stops");
    started.0.wake();
    timeout(Duration::from_secs(10), hold.arrived)
        .await
        .unwrap()
        .unwrap();
    let before = publishes(&hosted);
    mac.owner
        .record_stop(
            mac.id,
            mac.log(),
            bh_device::incoming::StopReason::Integrity,
        )
        .unwrap();
    let _ = hold.release.send(());
    sleep(Duration::from_secs(5)).await;
    assert_eq!(publishes(&hosted), before);
    assert!(mac.package(update).is_none());
    assert_eq!(mac.pending(), 1, "the local work is kept");
    assert_eq!(*started.1.borrow_and_update(), SyncStatus::Stopped);
    started.0.shutdown().await;
}

/// Whether this update is in a sealed package yet.
fn sealed_yet(device: &Device, update_id: i64) -> bool {
    device
        .raw()
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM note_outbox_members WHERE update_id=?1)
                 OR EXISTS(SELECT 1 FROM note_outbox WHERE update_id=?1)",
            [update_id],
            |r| r.get(0),
        )
        .unwrap()
}

/// A writer change splits a note's run. The second writer's work is a new
/// package, started no sooner than the spacing allows, and costs at most
/// one event more than an unsplit burst's bound.
#[tokio::test(start_paused = true)]
async fn a_writer_change_mid_burst_splits_into_paced_packages() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(10));
    let (mac, started, fold, fold_started) = two(&hosted).await;
    let log = mac.log();
    let before = hosted.edge.entries(log).len();
    let appends_before = hosted.edge.appends(log.id).len();
    let (monitor, seals) = record_seals(&mac);
    let mut first = mac.new_typist();
    let note = first.note;
    let start = Instant::now();
    let mut last = start;
    let mut handed_over = 0;
    for (n, c) in "first wri".chars().enumerate() {
        last = Instant::now();
        handed_over = mac.type_key(&mut first, c);
        started.0.wake();
        if n < 8 {
            sleep(KEYSTROKE).await;
        }
    }
    // Another window on the same note: another writer, mid-burst. Its first
    // key is committed at the same instant, with no await, so both await the
    // same next start in one unsealed run: only the writer change can split
    // them.
    let mut second = mac.typist(note);
    let mut taken_over = 0;
    for (n, c) in "second wr".chars().enumerate() {
        last = Instant::now();
        let id = mac.type_key(&mut second, c);
        if n == 0 {
            taken_over = id;
            assert!(
                !sealed_yet(&mac, handed_over) && !sealed_yet(&mac, taken_over),
                "the handover is unsealed"
            );
        }
        started.0.wake();
        if n < 8 {
            sleep(KEYSTROKE).await;
        }
    }
    let both = || {
        let mut shown = fold.paragraphs(note);
        shown.sort();
        shown == ["first wri", "second wr"]
    };
    while !both() {
        assert!(last.elapsed() < Duration::from_secs(30), "never shown");
        sleep(Duration::from_millis(1)).await;
    }
    let shown = last.elapsed();
    until(30, "settled", || mac.pending() == 0).await;
    monitor.abort();
    let seals = seals.lock().unwrap().clone();
    let burst = last - start;
    let events = hosted.edge.entries(log).len() - before;
    let appends = hosted.edge.appends(log.id).len() - appends_before;
    // One writer change: one package more than the unsplit bound, at most.
    let bound = 1 + burst.as_millis().div_ceil(SPACING.as_millis()) as usize + 1;
    println!(
        "writer change: {events} events over {burst:?} (bound {bound}), shown {shown:?}, \
         starts {:?}",
        seals.windows(2).map(|p| p[1] - p[0]).collect::<Vec<_>>()
    );
    assert_eq!(burst, KEYSTROKE * 16, "first to last keystroke");
    assert_ne!(
        covering(&mac, handed_over),
        covering(&mac, taken_over),
        "split at the writer change"
    );
    assert!(events <= bound && appends == events, "{events}/{appends}");
    assert_eq!(seals.len(), events, "every package counted");
    assert_paced(&seals);
    assert!(shown <= Duration::from_secs(2), "{shown:?}");
    started.0.shutdown().await;
    fold_started.0.shutdown().await;
}

/// The 256 KiB run bound splits pastes made at once the same way: the
/// second package is a new start, paced like any other, and the count is
/// what the bound makes it.
#[tokio::test(start_paused = true)]
async fn the_run_bound_splits_large_pastes_into_paced_packages() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(10));
    let (mac, started) = one(&hosted).await;
    let log = mac.log();
    sleep(Duration::from_secs(2)).await;
    let before = hosted.edge.entries(log).len();
    let (monitor, seals) = record_seals(&mac);
    let mut typist = mac.new_typist();
    // Two fit in one run; a third would pass the bound.
    let paste = "x".repeat(100 * 1024);
    let ids: Vec<i64> = (0..4).map(|_| mac.type_text(&mut typist, &paste)).collect();
    started.0.wake();
    let pending = || {
        mac.raw()
            .query_row("SELECT COUNT(*) FROM pending_note_work", [], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
    };
    until(30, "accepted", || pending() == 0).await;
    monitor.abort();
    let seals = seals.lock().unwrap().clone();
    let events = hosted.edge.entries(log).len() - before;
    println!(
        "four 100 KiB pastes: {events} events, starts {:?}",
        seals.windows(2).map(|p| p[1] - p[0]).collect::<Vec<_>>()
    );
    assert_eq!(covering(&mac, ids[0]), covering(&mac, ids[1]));
    assert_ne!(covering(&mac, ids[1]), covering(&mac, ids[2]));
    assert_eq!(covering(&mac, ids[2]), covering(&mac, ids[3]));
    assert_eq!(events, 2);
    assert_eq!(seals.len(), events, "every package counted");
    assert_paced(&seals);
    assert_eq!(
        mac.paragraphs(typist.note),
        [paste.repeat(4)],
        "all of it, once"
    );
    started.0.shutdown().await;
}

/// A control copied while a sealed package waits to be sent ends the
/// round's fence: nothing is sent under it. The exact bytes go once, under
/// the next fence, and are acknowledged at the position the log gave them;
/// a note typed meanwhile is not held back.
#[tokio::test(start_paused = true)]
async fn a_control_between_seal_and_enqueue_sends_nothing_under_the_old_fence() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(300));
    let (mac, mut started) = one(&hosted).await;
    let log = mac.log();
    // The publisher opens its own data link at its first publication.
    let hold = hosted.edge.hold_next_data_connect();
    let (_a, a) = mac.new_note("sealed before the control");
    started.0.wake();
    timeout(Duration::from_secs(10), hold.arrived)
        .await
        .unwrap()
        .unwrap();
    let sealed = mac.package(a).expect("sealed before connecting");
    let control = mac.progress().control_digest;
    // Another device joins: this one copies the addition into its base.
    let _fold = Device::join(&mac, &hosted);
    until(30, "addition copied", || copied(&mac) == 4).await;
    assert_ne!(mac.progress().control_digest, control, "a control applied");
    let control_at = mac.progress().position;
    let _ = hold.release.send(());
    let (_b, b) = mac.new_note("typed after the control");
    started.0.wake();
    until(30, "both acknowledged", || {
        mac.acked(a).is_some() && mac.acked(b).is_some()
    })
    .await;
    let publishes_of = |event: &[u8]| {
        hosted
            .edge
            .seen()
            .iter()
            .filter(|s| matches!(s, Seen::Publish { event: e, .. } if e == event))
            .count()
    };
    let kept = mac.package(a).unwrap();
    assert_eq!(kept.descriptor.encode(), sealed.descriptor.encode());
    assert_eq!(kept.body, sealed.body);
    // Sent under the old fence, its Ack could not be recorded and the bytes
    // would go again: once means only under the new one.
    assert_eq!(publishes_of(&sealed.descriptor.encode()), 1);
    let position = mac.acked(a).unwrap();
    assert!(position > control_at, "{position} after {control_at}");
    let ordered = hosted.edge.entries(log);
    let (_, event) = ordered
        .iter()
        .find(|(c, _)| c.head().position == position)
        .unwrap();
    assert_eq!(event.encode(), sealed.descriptor.encode());
    assert_eq!(
        publishes_of(&mac.package(b).unwrap().descriptor.encode()),
        1
    );
    until(30, "synced", || {
        *started.1.borrow_and_update() == SyncStatus::Synced
    })
    .await;
    started.0.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn revocation_during_the_permit_wait_sends_nothing_and_keeps_the_exact_package() {
    let hosted = Hosted::new();
    hosted.edge.set_latency(Duration::from_millis(300));
    let (mac, started) = one(&hosted).await;
    let sign = mac.signer.hold_next_sign();
    let (_writer, update) = mac.new_note("permits asked for as authority ends");
    started.0.wake();
    timeout(Duration::from_secs(10), sign.arrived)
        .await
        .unwrap()
        .unwrap();
    // The permit request leaves as the seal persists; its answer, and any
    // reply ahead of it on that socket, waits.
    let permits = hosted.edge.hold_next_authz_reply();
    let _ = sign.release.send(());
    timeout(Duration::from_secs(10), permits.arrived)
        .await
        .unwrap()
        .unwrap();
    let sealed = mac.package(update).expect("sealed before the permits");
    let before = publishes(&hosted);
    mac.signer.relock();
    let _ = permits.release.send(());
    sleep(Duration::from_secs(5)).await;
    assert_eq!(
        publishes(&hosted),
        before,
        "nothing enqueued after revocation"
    );
    assert_eq!(mac.pending(), 1, "the local work is kept");
    mac.authorize().unwrap();
    started.0.wake();
    until(30, "acknowledged under the new authority", || {
        mac.acked(update).is_some()
    })
    .await;
    let kept = mac.package(update).unwrap();
    assert_eq!(kept.descriptor.encode(), sealed.descriptor.encode());
    assert_eq!(kept.body, sealed.body);
    assert!(hosted.edge.seen().iter().all(|s| match s {
        Seen::Publish { event, body } if *event == sealed.descriptor.encode() => {
            *body == sealed.body
        }
        _ => true,
    }));
    started.0.shutdown().await;
}
