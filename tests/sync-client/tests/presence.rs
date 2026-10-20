//! Own-device presence through two real clients, the reviewed authz, record
//! and crypto code, and a fake edge that relays as the Worker and log object
//! do. Two production `Client`s with isolated stores and keys; fake clock and
//! paused Tokio time only.
#![cfg(feature = "synthetic-attestation")]
mod support;

use bh_crypto::Secret;
use bh_event::presence::{self, PresenceRecord};
use std::{sync::Arc, time::Duration};
use support::{
    device::{Device, until},
    fake::{Edge, Hosted},
};
use tokio::sync::watch;
use yrs::{Assoc, Doc, StickyIndex, Transact, updates::encoder::Encode};

type Started = (
    bh_sync_client::Client,
    watch::Receiver<bh_sync_client::SyncStatus>,
);

/// A root relative position in a note fragment, naming no writer.
fn root(assoc: Assoc) -> Vec<u8> {
    let doc = Doc::new();
    let fragment = doc.get_or_insert_xml_fragment("default");
    StickyIndex::from_type(&doc.transact(), &fragment, assoc).encode_v1()
}

fn before() -> Vec<u8> {
    root(Assoc::Before)
}

fn after() -> Vec<u8> {
    root(Assoc::After)
}

fn configured(device: &Device, label: &str, colour: u8) {
    device.label_presence(label, colour);
}

/// Fixed virtual window in small steps, so timer chains queued after an
/// earlier timer get a chance to run instead of being skipped by one jump.
async fn steps(count: usize, each: Duration) {
    for _ in 0..count {
        tokio::time::advance(each).await;
        tokio::task::yield_now().await;
    }
}

/// Both devices registered in one base with one accepted note, and the note
/// known to both. The clients that registered them are dropped; each test
/// starts its own.
async fn pair(hosted: &Arc<Hosted>) -> (Device, Device, [u8; 32]) {
    let first = Device::new();
    let (a, _) = first.start(hosted);
    until(20, "first registered", || {
        first.registered() && first.progress().position == 1
    })
    .await;
    let second = Device::join(&first, hosted);
    a.wake();
    let (b, _) = second.start(hosted);
    until(20, "second joined", || second.progress().position >= 2).await;
    let (writer, _) = first.new_note("note");
    let note = writer.note;
    a.wake();
    until(20, "note accepted", || {
        first.progress().position >= 3 && second.progress().position >= 3
    })
    .await;
    drop(a);
    drop(b);
    (first, second, note)
}

/// Start a configured, foreground client, as the host does.
fn open(device: &Device, hosted: &Arc<Hosted>) -> Started {
    device.start(hosted)
}

/// Every presence frame this device's base put on the wire, opened with its
/// own content key, in order.
fn records(hosted: &Hosted, device: &Device) -> Vec<PresenceRecord> {
    let key = device.content_key();
    let base = device.base.0;
    let Some(epoch) = device.progress().epoch_id else {
        return Vec::new();
    };
    hosted
        .edge
        .presence_wire(base)
        .iter()
        .filter_map(|frame| presence::open(&key, base, base, epoch, frame).ok())
        .collect()
}

/// The last frame this device sent that is worth showing: a selection or a
/// clear.
fn last_selection(hosted: &Hosted, device: &Device) -> Option<PresenceRecord> {
    let records = records(hosted, device);
    records
        .iter()
        .rev()
        .find(|record| record.kind == 1 || record.kind == 2)
        .cloned()
}

fn caret<'a>(
    state: &'a bh_sync_client::RemoteState,
    label: &str,
) -> Option<&'a bh_sync_client::RemotePresence> {
    state.entries().iter().find(|peer| peer.label == label)
}

/// When each of `device`'s own sealed frames reached the fake edge.
fn frame_times(hosted: &Hosted, device: &Device) -> Vec<tokio::time::Instant> {
    let key = device.content_key();
    let base = device.base.0;
    let Some(epoch) = device.progress().epoch_id else {
        return Vec::new();
    };
    let handle = presence::handle(&key, device.signer.device_id());
    hosted
        .edge
        .presence_wire_at(base)
        .into_iter()
        .filter(|(_, frame)| {
            presence::open(&key, base, base, epoch, frame)
                .is_ok_and(|record| record.handle == handle)
        })
        .map(|(at, _)| at)
        .collect()
}

/// The edge slot of `device`'s most recent presence frame.
fn sender_slot(hosted: &Hosted, device: &Device) -> u32 {
    let key = device.content_key();
    let base = device.base.0;
    let epoch = device.progress().epoch_id.expect("an epoch");
    let handle = presence::handle(&key, device.signer.device_id());
    hosted
        .edge
        .presence_wire_from(base)
        .iter()
        .rev()
        .find(|(_, frame)| {
            presence::open(&key, base, base, epoch, frame)
                .is_ok_and(|record| record.handle == handle)
        })
        .map(|(slot, _)| *slot)
        .expect("the device's slot")
}

#[tokio::test(start_paused = true)]
async fn both_directions_show_distinct_label_colour_and_cursor_within_a_second() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    // The decided qualified normal delay: 100 ms round trip.
    hosted.edge.set_latency(Duration::from_millis(100));
    configured(&first, "Mac", 0);
    configured(&second, "Pixel 10 Pro Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_a = a.presence().subscribe();
    let at_b = b.presence().subscribe();
    let appends = hosted.edge.entries(first.log()).len();
    let pos = before();
    let started = tokio::time::Instant::now();
    assert!(a.presence().set("mac", note, pos.clone(), pos.clone()));
    assert!(b.presence().set("fold", note, pos.clone(), pos.clone()));

    until(1, "both directions within a second", || {
        caret(&at_a.borrow(), "Pixel 10 Pro Fold").is_some_and(|p| p.note == note)
            && caret(&at_b.borrow(), "Mac").is_some_and(|p| p.note == note)
    })
    .await;
    assert!(
        tokio::time::Instant::now() - started <= Duration::from_secs(1),
        "presence took longer than a second"
    );
    let seen_a = at_a.borrow();
    let fold = caret(&seen_a, "Pixel 10 Pro Fold").expect("the Fold's caret at the Mac");
    assert_eq!(fold.colour, 1);
    assert_eq!(fold.anchor, pos);
    assert_eq!(fold.head, pos);
    let seen_b = at_b.borrow();
    let mac = caret(&seen_b, "Mac").expect("the Mac's caret at the Fold");
    assert_eq!(mac.colour, 0);
    assert_eq!(mac.anchor, pos);
    assert_ne!(
        mac.handle, fold.handle,
        "distinct devices are distinct handles"
    );
    drop(seen_a);
    drop(seen_b);

    // Five moves each way: the last value is the one delivered.
    for n in 0..5 {
        let pos = if n % 2 == 0 { after() } else { before() };
        a.presence().set("mac", note, pos.clone(), pos.clone());
        b.presence().set("fold", note, pos.clone(), pos.clone());
        tokio::time::advance(Duration::from_millis(150)).await;
    }
    a.presence().set("mac", note, after(), after());
    b.presence().set("fold", note, after(), after());
    until(1, "both last moves", || {
        caret(&at_a.borrow(), "Pixel 10 Pro Fold")
            .is_some_and(|p| p.anchor == after() && p.head == after())
            && caret(&at_b.borrow(), "Mac")
                .is_some_and(|p| p.anchor == after() && p.head == after())
    })
    .await;
    assert_eq!(
        hosted.edge.entries(first.log()).len(),
        appends,
        "presence is never an ordered append"
    );
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn same_device_windows_last_active_wins_falls_back_then_clears() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_b = b.presence().subscribe();
    b.presence().set("fold", note, before(), before());

    // Three Mac windows on the note: the last one to set is the one shown.
    a.presence().set("zero", note, before(), before());
    a.presence().set("one", note, after(), after());
    a.presence().set("two", note, before(), before());
    until(2, "window two", || {
        caret(&at_b.borrow(), "Mac").is_some_and(|p| p.anchor == before())
    })
    .await;

    // Closing an inactive window changes nothing and sends nothing.
    let sent = hosted.edge.presence_frames();
    a.presence().clear("zero");
    tokio::time::advance(Duration::from_millis(400)).await;
    assert_eq!(hosted.edge.presence_frames(), sent);
    assert_eq!(caret(&at_b.borrow(), "Mac").unwrap().anchor, before());

    // Closing the active window falls back to the most recently active other.
    a.presence().clear("two");
    until(2, "falls back to one", || {
        caret(&at_b.borrow(), "Mac").is_some_and(|p| p.anchor == after())
    })
    .await;

    // The last window closing clears the caret.
    a.presence().clear("one");
    until(2, "cleared", || caret(&at_b.borrow(), "Mac").is_none()).await;
    assert!(last_selection(&hosted, &first).is_some_and(|record| record.kind == 2));
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_ninth_local_note_evicts_the_least_recently_active_as_cleared() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_b = b.presence().subscribe();
    b.presence().set("fold", note, before(), before());

    a.presence().set("mac", note, before(), before());
    until(2, "ready", || caret(&at_b.borrow(), "Mac").is_some()).await;
    for n in 1..=8u8 {
        a.presence().set("mac", [n; 32], before(), before());
        tokio::time::advance(Duration::from_millis(150)).await;
    }
    until(2, "evicted note cleared", || {
        records(&hosted, &first)
            .iter()
            .any(|record| record.kind == 2 && record.note == note)
    })
    .await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn leave_and_silent_loss_remove_the_remote_caret() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_a = a.presence().subscribe();
    b.presence().set("fold", note, before(), before());
    a.presence().set("mac", note, before(), before());
    until(5, "shown", || caret(&at_a.borrow(), "Fold").is_some()).await;

    // Leaving announces nothing to show, then closes the join.
    b.presence().leave();
    until(5, "left", || caret(&at_a.borrow(), "Fold").is_none()).await;

    // Back, then a silent loss: only the sender's join ends, as its permit
    // deadline does, and its `left` removes the caret while this device's own
    // join keeps running.
    b.presence().foreground(true);
    b.presence().set("fold", note, before(), before());
    until(5, "shown again", || caret(&at_a.borrow(), "Fold").is_some()).await;
    // A third live presence socket keeps the roster nonempty, so only the
    // named `left` can remove the sender's caret.
    let _observer = hosted.edge.attach_presence_peer(second.base.0);
    let slot = sender_slot(&hosted, &second);
    hosted.edge.presence_expire_slot(second.base.0, slot);
    until(5, "left removed it", || {
        caret(&at_a.borrow(), "Fold").is_none()
    })
    .await;
    let epoch = first.progress().epoch_id.unwrap();
    let key = first.content_key();
    let base = first.base.0;
    let record = PresenceRecord {
        kind: 1,
        handle: [7; 16],
        seq: 1,
        colour: 0,
        note,
        anchor: after(),
        head: after(),
        label: "still here".to_owned(),
    };
    hosted.edge.inject_presence(
        base,
        presence::seal(&key, base, base, epoch, &record).unwrap(),
    );
    until(5, "this device's join still delivers", || {
        at_a.borrow().entries().iter().any(|p| p.handle == [7; 16])
    })
    .await;
    a.shutdown().await;
    b.shutdown().await;
}

/// An Android pause and resume, as a fold that locks the screen: the editor
/// keeps its DOM focus and reports nothing new, so neither device moves.
#[tokio::test(start_paused = true)]
async fn a_pause_and_resume_shows_both_carets_again_without_moving() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    hosted.edge.set_latency(Duration::from_millis(100));
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_a = a.presence().subscribe();
    let at_b = b.presence().subscribe();
    b.presence().set("fold", note, before(), before());
    a.presence().set("mac", note, before(), before());
    until(5, "shown", || {
        caret(&at_a.borrow(), "Fold").is_some() && caret(&at_b.borrow(), "Mac").is_some()
    })
    .await;

    // Paused: nothing is on the Fold's screen, so both carets go.
    b.presence().leave();
    until(5, "paused", || {
        caret(&at_a.borrow(), "Fold").is_none() && caret(&at_b.borrow(), "Mac").is_none()
    })
    .await;

    // Resumed, with no new selection from either side.
    b.presence().foreground(true);
    until(5, "shown again after resume", || {
        caret(&at_a.borrow(), "Fold").is_some_and(|p| p.anchor == before())
            && caret(&at_b.borrow(), "Mac").is_some_and(|p| p.anchor == before())
    })
    .await;
    steps(50, Duration::from_millis(100)).await;
    assert!(
        caret(&at_b.borrow(), "Mac").is_some(),
        "the resumed join stays and keeps the Mac caret"
    );
    assert!(caret(&at_a.borrow(), "Fold").is_some());
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_senders_left_removes_the_caret_when_its_best_effort_clears_are_lost() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_a = a.presence().subscribe();
    a.presence().set("mac", note, before(), before());
    b.presence().set("fold", note, before(), before());
    until(5, "shown", || caret(&at_a.borrow(), "Fold").is_some()).await;

    // The sender leaves; its best-effort clears never cross the lost path, so
    // only the join's close (`left`) can remove the caret. A third live socket
    // keeps the roster nonempty, so a roster-wide clear cannot hide it.
    let _observer = hosted.edge.attach_presence_peer(second.base.0);
    let slot = sender_slot(&hosted, &second);
    hosted.edge.silence_presence_frames_from(slot);
    b.shutdown().await;
    until(5, "left removed it", || {
        caret(&at_a.borrow(), "Fold").is_none()
    })
    .await;
    a.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn restart_and_relaunch_resend_current_selections_without_a_ghost() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_a = a.presence().subscribe();
    let at_b = b.presence().subscribe();
    b.presence().set("fold", note, before(), before());
    a.presence().set("mac", note, before(), before());
    until(5, "shown", || {
        caret(&at_a.borrow(), "Fold").is_some() && caret(&at_b.borrow(), "Mac").is_some()
    })
    .await;

    // A DO restart ends every join; both sides clear, rejoin and resend what
    // they already show, without a new set.
    hosted.go_down();
    until(5, "cleared", || {
        caret(&at_a.borrow(), "Fold").is_none() && caret(&at_b.borrow(), "Mac").is_none()
    })
    .await;
    hosted.come_up();
    until(20, "rejoined with the same caret", || {
        caret(&at_a.borrow(), "Fold").is_some_and(|p| p.anchor == before())
            && caret(&at_b.borrow(), "Mac").is_some_and(|p| p.anchor == before())
    })
    .await;
    assert_eq!(at_a.borrow().entries().len(), 1);
    assert_eq!(at_b.borrow().entries().len(), 1);

    // A relaunch reappears on a new slot. Its frame replaces the old slot's
    // entry, and the old slot's later `left` must not delete the new caret.
    let old = at_a.borrow().entries()[0].clone();
    let base = second.base.0;
    let key = second.content_key();
    let epoch = second.progress().epoch_id.unwrap();
    let old_slot = hosted
        .edge
        .presence_wire_from(base)
        .iter()
        .rev()
        .find(|(_, frame)| {
            presence::open(&key, base, base, epoch, frame)
                .is_ok_and(|record| record.handle == old.handle)
        })
        .map(|(slot, _)| *slot)
        .expect("the relaunched device's slot");
    let record = PresenceRecord {
        kind: 1,
        handle: old.handle,
        seq: 1,
        colour: 1,
        note,
        anchor: after(),
        head: after(),
        label: "Fold".to_owned(),
    };
    hosted.edge.inject_presence_from(
        base,
        9_999,
        presence::seal(&key, base, base, epoch, &record).unwrap(),
    );
    until(5, "new slot replaced the entry", || {
        let seen = at_a.borrow();
        seen.entries().len() == 1
            && seen.entries()[0].handle == old.handle
            && seen.entries()[0].anchor == after()
    })
    .await;
    hosted.edge.presence_left_slot(base, old_slot);
    tokio::time::advance(Duration::from_millis(300)).await;
    let seen = at_a.borrow();
    assert_eq!(
        seen.entries().len(),
        1,
        "old slot's left spared the new caret"
    );
    assert_eq!(seen.entries()[0].anchor, after());
    drop(seen);

    // Nor does a late clear from the old slot.
    let mut cleared = record.clone();
    cleared.kind = 2;
    cleared.anchor = Vec::new();
    cleared.head = Vec::new();
    cleared.seq = 2;
    hosted.edge.inject_presence_from(
        base,
        old_slot,
        presence::seal(&key, base, base, epoch, &cleared).unwrap(),
    );
    tokio::time::advance(Duration::from_millis(300)).await;
    let seen = at_a.borrow();
    assert_eq!(
        seen.entries().len(),
        1,
        "old slot's clear spared the new caret"
    );
    assert_eq!(seen.entries()[0].anchor, after());
    drop(seen);

    // A freshly started client shows nothing until a frame arrives.
    let (fresh, _) = second.start(&hosted);
    assert!(fresh.presence().subscribe().borrow().entries().is_empty());
    drop(fresh);
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn nothing_is_sent_while_the_roster_is_empty_and_a_join_resends_it() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    a.presence().set("mac", note, before(), before());
    tokio::time::advance(Duration::from_secs(1)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        hosted.edge.presence_frames(),
        0,
        "no other device: nothing is sent"
    );

    let (b, _) = open(&second, &hosted);
    let at_b = b.presence().subscribe();
    b.presence().set("fold", note, before(), before());
    until(5, "resent on join", || {
        caret(&at_b.borrow(), "Mac").is_some()
    })
    .await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_frame_may_arrive_before_the_roster_snapshot() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    a.presence().set("mac", note, before(), before());
    hosted.edge.frames_before_peers();
    let (b, _) = open(&second, &hosted);
    let at_b = b.presence().subscribe();
    b.presence().set("fold", note, before(), before());
    until(5, "frame before the snapshot", || {
        hosted.edge.presence_before_peers() > 0
    })
    .await;
    until(5, "caret shown", || caret(&at_b.borrow(), "Mac").is_some()).await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_writer_position_is_withheld_until_its_update_is_accepted() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_b = b.presence().subscribe();
    b.presence().set("fold", note, before(), before());
    a.presence().set("mac", note, before(), before());
    until(5, "ready", || caret(&at_b.borrow(), "Mac").is_some()).await;
    let sent = hosted.edge.presence_frames();

    // This writer's update is accepted by the edge but its echo is frozen, so
    // no binding exists here yet.
    let frozen = first.progress().position;
    hosted.edge.freeze_reads(Some(frozen));
    let appends = hosted.edge.appends(first.log().id).len();
    let (client, position) = first.type_with_position(note, "future");
    a.wake();
    until(20, "append accepted by the edge", || {
        hosted.edge.appends(first.log().id).len() > appends
    })
    .await;
    assert!(!first.has_binding(note, client));
    a.presence()
        .set("mac", note, position.clone(), position.clone());
    tokio::time::advance(Duration::from_millis(500)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    assert_eq!(
        hosted.edge.presence_frames(),
        sent,
        "nothing naming a writer without an accepted binding is sent"
    );
    assert!(
        records(&hosted, &first)
            .iter()
            .all(|record| record.anchor != position && record.head != position),
        "no frame naming the unaccepted writer ever reached the wire"
    );

    // Its accepted echo arrives: the exact latest position is sent once.
    hosted.edge.freeze_reads(None);
    a.wake();
    until(20, "accepted binding", || first.has_binding(note, client)).await;
    until(20, "withheld frame sent", || {
        hosted.edge.presence_frames() > sent
    })
    .await;
    until(5, "exact position", || {
        caret(&at_b.borrow(), "Mac").is_some_and(|p| p.anchor == position && p.head == position)
    })
    .await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn an_accepted_writer_position_is_sent_without_waiting() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_b = b.presence().subscribe();
    b.presence().set("fold", note, before(), before());
    a.presence().set("mac", note, before(), before());
    until(5, "ready", || caret(&at_b.borrow(), "Mac").is_some()).await;
    let (client, position) = first.type_with_position(note, "present");
    a.wake();
    until(20, "binding", || first.has_binding(note, client)).await;
    let sent = hosted.edge.presence_frames();
    a.presence()
        .set("mac", note, position.clone(), position.clone());
    until(1, "sent at once", || hosted.edge.presence_frames() > sent).await;
    until(2, "delivered", || {
        caret(&at_b.borrow(), "Mac").is_some_and(|p| p.anchor == position)
    })
    .await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_thousand_sets_coalesce_to_at_most_one_hundred_and_one_frames() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_b = b.presence().subscribe();
    b.presence().set("fold", note, before(), before());
    a.presence().set("mac", note, before(), before());
    until(5, "ready", || caret(&at_b.borrow(), "Mac").is_some()).await;
    let sent = hosted.edge.presence_frames();
    let permits = hosted
        .edge
        .authz_messages
        .load(std::sync::atomic::Ordering::SeqCst);
    // The host reports a selection every 50 ms at most: 1,000 sets over 10 s
    // of virtual time, each given the runtime a chance to send.
    for n in 0..1_000u32 {
        let pos = if n + 1 == 1_000 { after() } else { before() };
        a.presence().set("mac", note, pos.clone(), pos);
        tokio::time::advance(Duration::from_millis(10)).await;
        tokio::task::yield_now().await;
    }
    tokio::time::advance(Duration::from_millis(200)).await;
    until(1, "trailing latest", || {
        caret(&at_b.borrow(), "Mac").is_some_and(|p| p.anchor == after())
    })
    .await;
    let frames = hosted.edge.presence_frames() - sent;
    assert!(frames <= 101, "sent {frames} frames for 1,000 sets in 10 s");
    let times = frame_times(&hosted, &first);
    assert!(times.len() >= 2, "the storm sent frames");
    for gap in times.windows(2).map(|pair| pair[1] - pair[0]) {
        assert!(
            gap >= bh_sync_client::SEND_INTERVAL,
            "two frames {gap:?} apart, under the {SEND_INTERVAL:?} limit",
            SEND_INTERVAL = bh_sync_client::SEND_INTERVAL
        );
    }
    assert_eq!(
        at_b.borrow().entries().len(),
        1,
        "one caret per other device per note"
    );
    let after = hosted
        .edge
        .authz_messages
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        after - permits <= 1,
        "no permit per cursor, only a renewal: {}",
        after - permits
    );
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn immediate_unavailable_joins_back_off_instead_of_four_a_second() {
    let hosted = Hosted::new();
    let (first, _second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    hosted.edge.refuse_presence_unavailable();
    let (a, _) = open(&first, &hosted);
    a.presence().set("mac", note, before(), before());
    let attempts = hosted.edge.presence_attempts();
    for _ in 0..60 {
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }
    let tried = hosted.edge.presence_attempts() - attempts;
    // 250 ms doubling with jitter and a 30 s cap: about eight attempts in a
    // minute, each one authz permit. A reset on socket open would be ~240.
    assert!(
        tried <= 12,
        "tried {tried} joins in 60 s of immediate Unavailable"
    );
    a.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn repeated_epoch_refusals_also_back_off() {
    let hosted = Hosted::new();
    let (first, _second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    hosted.edge.refuse_presence_epochs();
    let (a, _) = open(&first, &hosted);
    a.presence().set("mac", note, before(), before());
    let attempts = hosted.edge.presence_attempts();
    for _ in 0..60 {
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }
    let tried = hosted.edge.presence_attempts() - attempts;
    // 0-2 s jitter alone would rejoin about once a second; the refusal count
    // must grow the delay as well.
    assert!(
        tried <= 15,
        "tried {tried} joins in 60 s of immediate Epoch refusals"
    );
    a.shutdown().await;
}

/// A device whose person is typing reports a selection every 50 ms, and (when
/// `wake` is set) the host also calls `Client::wake()` every 100 ms, as a local
/// note commit does. Neither may cut the rejoin wait: every join refused for a
/// minute still costs only the backoff's few permits.
async fn active_selections_do_not_cut_a_rejoin_backoff(
    refuse: fn(&Edge),
    bound: usize,
    what: &str,
    wake: bool,
) {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    refuse(&hosted.edge);
    a.presence().set("mac", note, before(), before());
    let attempts = hosted.edge.presence_attempts();
    for step in 0..1_200u32 {
        let pos = if step + 1 == 1_200 { after() } else { before() };
        a.presence().set("mac", note, pos.clone(), pos);
        if wake && step % 2 == 1 {
            a.wake();
        }
        tokio::time::advance(Duration::from_millis(50)).await;
        tokio::task::yield_now().await;
    }
    let tried = hosted.edge.presence_attempts() - attempts;
    assert!(
        tried <= bound,
        "tried {tried} joins in 60 s of {what} refusals with a selection every 50 ms"
    );

    // Once a join is admitted, the coalesced latest value goes once; the
    // minute's selection reports are not replayed.
    hosted.edge.admit_presence();
    let (b, _) = open(&second, &hosted);
    let at_b = b.presence().subscribe();
    b.presence().set("fold", note, before(), before());
    until(40, "latest after admission", || {
        caret(&at_b.borrow(), "Mac").is_some_and(|p| p.anchor == after())
    })
    .await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn active_selections_do_not_cut_an_unavailable_backoff() {
    active_selections_do_not_cut_a_rejoin_backoff(
        Edge::refuse_presence_unavailable,
        12,
        "Unavailable",
        false,
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn active_selections_do_not_cut_an_epoch_backoff() {
    active_selections_do_not_cut_a_rejoin_backoff(Edge::refuse_presence_epochs, 15, "Epoch", false)
        .await;
}

#[tokio::test(start_paused = true)]
async fn a_note_commit_wake_does_not_cut_an_unavailable_backoff() {
    active_selections_do_not_cut_a_rejoin_backoff(
        Edge::refuse_presence_unavailable,
        12,
        "Unavailable",
        true,
    )
    .await;
}

#[tokio::test(start_paused = true)]
async fn a_note_commit_wake_does_not_cut_an_epoch_backoff() {
    active_selections_do_not_cut_a_rejoin_backoff(Edge::refuse_presence_epochs, 15, "Epoch", true)
        .await;
}

#[tokio::test(start_paused = true)]
async fn a_content_key_that_is_not_the_stored_epoch_seals_and_opens_nothing() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_b = b.presence().subscribe();
    a.presence().set("mac", note, before(), before());
    b.presence().set("fold", note, before(), before());
    until(5, "ready", || caret(&at_b.borrow(), "Mac").is_some()).await;
    let epoch = first.progress().epoch_id.unwrap();
    let key = first.content_key();
    let base = first.base.0;

    // Seal: the signer hands out a root that is not the stored epoch's key.
    let slot = sender_slot(&hosted, &first);
    let sent = hosted
        .edge
        .presence_wire_from(first.base.0)
        .iter()
        .filter(|(from, _)| *from == slot)
        .count();
    first
        .signer
        .use_content_key(Some(Secret::from_slice(&[0x11; 32]).unwrap()));
    a.presence().set("mac", note, after(), after());
    steps(50, Duration::from_millis(10)).await;
    let after_frames = hosted
        .edge
        .presence_wire_from(first.base.0)
        .iter()
        .filter(|(from, _)| *from == slot)
        .count();
    assert_eq!(
        after_frames, sent,
        "nothing is sealed under a root that is not the epoch's key"
    );
    first.signer.use_content_key(None);

    // Open: the receiver is handed a wrong root, and a frame exists under it
    // with the stored epoch label. Only the key-to-epoch check refuses it.
    let wrong_open = Secret::from_slice(&[0x22; 32]).unwrap();
    second
        .signer
        .use_content_key(Some(Secret::from_slice(&[0x22; 32]).unwrap()));
    let record = PresenceRecord {
        kind: 1,
        handle: [9; 16],
        seq: 1,
        colour: 0,
        note,
        anchor: after(),
        head: after(),
        label: "wrong key".to_owned(),
    };
    hosted.edge.inject_presence(
        base,
        presence::seal(&wrong_open, base, base, epoch, &record).unwrap(),
    );
    steps(50, Duration::from_millis(10)).await;
    assert!(
        at_b.borrow().entries().iter().all(|p| p.handle != [9; 16]),
        "a frame under a root that is not the epoch's key opens nothing"
    );
    second.signer.use_content_key(None);

    // The true key still opens the same record.
    hosted.edge.inject_presence(
        base,
        presence::seal(&key, base, base, epoch, &record).unwrap(),
    );
    until(5, "true key delivered", || {
        at_b.borrow().entries().iter().any(|p| p.handle == [9; 16])
    })
    .await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_leaving_clear_under_a_key_that_is_not_the_epoch_is_not_sent() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_b = b.presence().subscribe();
    a.presence().set("mac", note, before(), before());
    b.presence().set("fold", note, before(), before());
    until(20, "both shown", || caret(&at_b.borrow(), "Mac").is_some()).await;

    // Leaving sends a best-effort clear for every held note. Under a root that
    // is not the stored epoch's key it must seal and send nothing.
    let slot = sender_slot(&hosted, &first);
    let sent = hosted
        .edge
        .presence_wire_from(first.base.0)
        .iter()
        .filter(|(from, _)| *from == slot)
        .count();
    first
        .signer
        .use_content_key(Some(Secret::from_slice(&[0x11; 32]).unwrap()));
    a.presence().leave();
    steps(50, Duration::from_millis(10)).await;
    let after_frames = hosted
        .edge
        .presence_wire_from(first.base.0)
        .iter()
        .filter(|(from, _)| *from == slot)
        .count();
    assert_eq!(
        after_frames, sent,
        "no clear is sealed under a root that is not the epoch's key"
    );
    first.signer.use_content_key(None);
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_cursor_storm_does_not_change_content_appends_or_packages() {
    async fn content(hosted: &Arc<Hosted>, storm: bool) -> (usize, usize) {
        let (first, second, note) = pair(hosted).await;
        configured(&first, "Mac", 0);
        configured(&second, "Fold", 1);
        let (a, _) = open(&first, hosted);
        let (b, _) = open(&second, hosted);
        let at_b = b.presence().subscribe();
        if storm {
            b.presence().set("fold", note, before(), before());
            a.presence().set("mac", note, before(), before());
            until(5, "ready", || caret(&at_b.borrow(), "Mac").is_some()).await;
        }
        let before_len = hosted.edge.entries(first.log()).len();
        let before_stages = hosted.edge.stages(first.base.0).len();
        let _ = first.new_note("later");
        for _ in 0..200 {
            if storm {
                a.presence().set("mac", note, before(), before());
            }
        }
        a.wake();
        until(20, "acked", || {
            first.progress().position as usize > before_len
        })
        .await;
        let appends = hosted.edge.appends(first.log().id).len();
        let stages = hosted.edge.stages(first.base.0).len() - before_stages;
        a.shutdown().await;
        b.shutdown().await;
        (appends, stages)
    }
    let plain = Hosted::new();
    let (plain_appends, plain_stages) = content(&plain, false).await;
    let stormy = Hosted::new();
    let (storm_appends, storm_stages) = content(&stormy, true).await;
    assert_eq!(storm_appends, plain_appends, "same appended packages");
    assert_eq!(storm_stages, plain_stages, "same staged packages");
}

#[tokio::test(start_paused = true)]
async fn a_roster_join_does_not_bypass_the_send_interval() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    b.presence().set("fold", note, before(), before());
    a.presence().set("mac", note, before(), before());
    until(5, "first frame", || frame_times(&hosted, &first).len() == 1).await;

    // Another device joins inside the send interval while a new value is
    // pending. The roster `joined` proves the join was admitted, but it must
    // not move `next_send_at` back to now.
    a.presence().set("mac", note, after(), after());
    tokio::time::advance(Duration::from_millis(50)).await;
    tokio::task::yield_now().await;
    let _peer = hosted.edge.attach_presence_peer(first.base.0);
    until(5, "second frame", || {
        frame_times(&hosted, &first).len() >= 2
    })
    .await;
    for gap in frame_times(&hosted, &first)
        .windows(2)
        .map(|pair| pair[1] - pair[0])
    {
        assert!(
            gap >= bh_sync_client::SEND_INTERVAL,
            "a roster join cut the {SEND_INTERVAL:?} send interval: {gap:?}",
            SEND_INTERVAL = bh_sync_client::SEND_INTERVAL
        );
    }
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn invalid_frames_epochs_and_positions_never_deliver_a_caret() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_b = b.presence().subscribe();
    b.presence().set("fold", note, before(), before());
    a.presence().set("mac", note, before(), before());
    until(2, "ready", || caret(&at_b.borrow(), "Mac").is_some()).await;
    let epoch = first.progress().epoch_id.unwrap();
    let key = first.content_key();
    let base = first.base.0;
    let record = PresenceRecord {
        kind: 1,
        handle: presence::handle(&key, first.signer.device_id()),
        seq: 1,
        colour: 0,
        note,
        anchor: before(),
        head: before(),
        label: "Canary".to_owned(),
    };
    let good = presence::seal(&key, base, base, epoch, &record).unwrap();
    let mut corrupt = good.clone();
    corrupt[57] ^= 1;
    let mut bad_version = good.clone();
    bad_version[0] = 9;
    let mut bad_epoch = good.clone();
    bad_epoch[1] = 0xab;
    let mut bad_positions = record.clone();
    bad_positions.anchor = vec![0xff; 3];
    let bad_positions = presence::seal(&key, base, base, epoch, &bad_positions).unwrap();
    let mut wrong_base = record.clone();
    wrong_base.handle = [9; 16];
    let wrong_base = presence::seal(&key, [0x5a; 32], base, epoch, &wrong_base).unwrap();
    let mut wrong_audience = record.clone();
    wrong_audience.handle = [8; 16];
    let wrong_audience = presence::seal(&key, base, [0x5b; 32], epoch, &wrong_audience).unwrap();
    for frame in [
        corrupt,
        bad_version,
        bad_epoch,
        bad_positions,
        wrong_base,
        wrong_audience,
    ] {
        hosted.edge.inject_presence(base, frame);
    }
    tokio::time::advance(Duration::from_millis(500)).await;
    let seen = at_b.borrow();
    assert_eq!(seen.entries().len(), 1, "only the Mac's own accepted caret");
    for rejected in [[9u8; 16], [8u8; 16]] {
        assert!(
            seen.entries().iter().all(|p| p.handle != rejected),
            "no invalid frame delivered a caret"
        );
    }
    drop(seen);

    // The good frame does deliver, proving the fixture's delivery path.
    let mut accepted = record.clone();
    accepted.handle = [7; 16];
    accepted.anchor = after();
    accepted.head = after();
    hosted.edge.inject_presence(
        base,
        presence::seal(&key, base, base, epoch, &accepted).unwrap(),
    );
    until(5, "well-formed delivered", || {
        at_b.borrow().entries().iter().any(|p| p.handle == [7; 16])
    })
    .await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn same_epoch_renewal_keeps_the_caret_and_an_epoch_refusal_rejoins() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_a = a.presence().subscribe();
    let at_b = b.presence().subscribe();
    a.presence().set("mac", note, before(), before());
    b.presence().set("fold", note, before(), before());
    until(5, "both", || {
        caret(&at_a.borrow(), "Fold").is_some() && caret(&at_b.borrow(), "Mac").is_some()
    })
    .await;
    let joins = hosted.edge.presence_joins();

    // Across a same-epoch renewal the upstream is kept and no caret clears.
    hosted.edge.clock.advance(26_000);
    tokio::time::advance(Duration::from_secs(26)).await;
    until(5, "renewed", || hosted.edge.presence_joins() > joins).await;
    assert!(caret(&at_a.borrow(), "Fold").is_some());
    assert!(caret(&at_b.borrow(), "Mac").is_some());

    // A same-epoch Refused{Epoch} (a control was ordered) rejoins with fresh
    // authority instead of waiting for an epoch change.
    let refused = hosted.edge.presence_joins();
    hosted.edge.refuse_next_presence_epoch();
    hosted.edge.clock.advance(26_000);
    tokio::time::advance(Duration::from_secs(26)).await;
    until(5, "rejoined", || hosted.edge.presence_joins() > refused).await;
    until(5, "carets back", || {
        caret(&at_a.borrow(), "Fold").is_some() && caret(&at_b.borrow(), "Mac").is_some()
    })
    .await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn canaries_never_reach_the_wire_or_a_debug_string_and_nothing_appends() {
    let hosted = Hosted::new();
    let (first, second, _note) = pair(&hosted).await;
    configured(&first, "Mac-canary-label", 0);
    configured(&second, "Fold", 1);
    let (a, status_a) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    // A real note whose text is a canary: the content path stores it, so the
    // check below is scoped to what presence itself put on the wire and in
    // its state, not to the note log.
    let (canary_note, _) = first.new_note("canary-note-content");
    a.wake();
    until(20, "canary note accepted", || {
        first.progress().position >= 4 && second.progress().position >= 4
    })
    .await;
    let canary_text = b"canary-note-content";
    b.presence()
        .set("fold", canary_note.note, before(), before());
    a.presence()
        .set("mac-canary-window", canary_note.note, before(), before());
    let at_b = b.presence().subscribe();
    until(5, "ready", || {
        caret(&at_b.borrow(), "Mac-canary-label").is_some()
    })
    .await;
    let appends = hosted.edge.entries(first.log()).len();
    for _ in 0..100 {
        a.presence()
            .set("mac-canary-window", canary_note.note, before(), before());
        tokio::time::advance(Duration::from_millis(100)).await;
    }
    let wire = hosted.edge.presence_wire(first.base.0);
    let canaries: [&[u8]; 3] = [b"Mac-canary-label", canary_text, b"mac-canary-window"];
    for frame in &wire {
        for needle in canaries {
            assert!(
                !frame.windows(needle.len()).any(|window| window == needle),
                "canary on the wire"
            );
        }
    }
    let state = format!("{:?}", at_b.borrow());
    let local = format!("{:?}", a.presence());
    let record = format!("{:?}", last_selection(&hosted, &first));
    for debug in [state, local, record] {
        assert!(!debug.contains("canary"), "{debug}");
        assert!(!debug.contains("canary-note-content"), "{debug}");
    }
    assert_eq!(*status_a.borrow(), bh_sync_client::SyncStatus::Synced);
    assert!(
        !hosted
            .edge
            .storage_contains(&[b"Mac-canary-label", b"mac-canary-window"]),
        "no canary label or window name in stored bytes"
    );
    assert_eq!(
        hosted.edge.entries(first.log()).len(),
        appends,
        "100 presence frames append nothing"
    );
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn dormant_presence_opens_no_socket_and_leaves_note_status_alone() {
    let hosted = Hosted::new();
    let (first, second, _note) = pair(&hosted).await;
    let joins = hosted.edge.presence_joins();
    let (a, status_a) = first.start(&hosted);
    let (b, status_b) = second.start(&hosted);
    tokio::time::advance(Duration::from_secs(60)).await;
    assert_eq!(hosted.edge.presence_joins(), joins);
    assert_eq!(*status_a.borrow(), *status_b.borrow());
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_stopped_client_cannot_deliver_a_new_caret() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_b = b.presence().subscribe();
    a.presence().set("mac", note, before(), before());
    b.presence().set("fold", note, before(), before());
    until(5, "shown", || caret(&at_b.borrow(), "Mac").is_some()).await;

    // The client stops: its join ends and the other device drops the caret.
    a.shutdown().await;
    until(5, "gone", || caret(&at_b.borrow(), "Mac").is_none()).await;
    let sent = hosted.edge.presence_frames();
    a.presence().set("mac", note, after(), after());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(hosted.edge.presence_frames(), sent);
    assert!(caret(&at_b.borrow(), "Mac").is_none());
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn remote_state_is_bounded_and_dropped_when_the_note_closes() {
    let hosted = Hosted::new();
    let (first, second, note) = pair(&hosted).await;
    configured(&first, "Mac", 0);
    configured(&second, "Fold", 1);
    let (a, _) = open(&first, &hosted);
    let (b, _) = open(&second, &hosted);
    let at_b = b.presence().subscribe();
    a.presence().set("mac", note, before(), before());
    b.presence().set("fold", note, before(), before());
    until(5, "shown", || caret(&at_b.borrow(), "Mac").is_some()).await;

    // More untrusted senders than the cache holds: the count stays bounded.
    let epoch = first.progress().epoch_id.unwrap();
    let key = first.content_key();
    let base = first.base.0;
    for n in 0..70u8 {
        let record = PresenceRecord {
            kind: 1,
            handle: [n; 16],
            seq: u64::from(n),
            colour: 0,
            note,
            anchor: before(),
            head: before(),
            label: "peer".to_owned(),
        };
        hosted.edge.inject_presence(
            base,
            presence::seal(&key, base, base, epoch, &record).unwrap(),
        );
    }
    tokio::time::advance(Duration::from_millis(500)).await;
    assert!(at_b.borrow().entries().len() <= bh_sync_client::MAX_REMOTE);

    // Closing the note's last window drops all of its remote carets.
    b.presence().clear("fold");
    until(5, "dropped with the window", || {
        at_b.borrow().entries().is_empty()
    })
    .await;
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_closed_epoch_drops_presence_and_refuses_a_new_caret() {
    let hosted = Hosted::new();
    let (mac, fold, note) = pair(&hosted).await;
    configured(&mac, "Mac", 0);
    configured(&fold, "Fold", 1);
    let (a, _) = open(&mac, &hosted);
    let (b, _) = open(&fold, &hosted);
    let at_a = a.presence().subscribe();
    let at_b = b.presence().subscribe();
    a.presence().set("mac", note, before(), before());
    b.presence().set("fold", note, before(), before());
    until(20, "both shown", || {
        caret(&at_a.borrow(), "Fold").is_some() && caret(&at_b.borrow(), "Mac").is_some()
    })
    .await;
    let epoch = mac.progress().epoch_id.unwrap();
    let key = mac.content_key();
    let base = mac.base.0;
    let record = PresenceRecord {
        kind: 1,
        handle: [4; 16],
        seq: 99,
        colour: 2,
        note,
        anchor: after(),
        head: after(),
        label: "stale".to_owned(),
    };
    let stale = presence::seal(&key, base, base, epoch, &record).unwrap();

    // The Fold removes itself; the Mac copies the removal, which closes the
    // base's content epoch.
    let removal = fold.signer.remove_self();
    hosted.edge.order_account(mac.account_log, &removal);
    a.wake();
    until(20, "epoch closed", || mac.progress().epoch_id.is_none()).await;
    until(20, "presence closed", || {
        at_a.borrow().entries().is_empty() && at_b.borrow().entries().is_empty()
    })
    .await;

    // A frame from the closed epoch cannot deliver a caret, and a new local
    // selection cannot be sent.
    hosted.edge.inject_presence(base, stale);
    let sent = hosted.edge.presence_frames();
    steps(50, Duration::from_millis(10)).await;
    assert!(
        at_a.borrow().entries().is_empty(),
        "no caret from a closed epoch"
    );
    a.presence().set("mac", note, before(), before());
    steps(50, Duration::from_millis(10)).await;
    assert_eq!(
        hosted.edge.presence_frames(),
        sent,
        "no presence frame after the epoch closed"
    );
    a.shutdown().await;
    b.shutdown().await;
}
