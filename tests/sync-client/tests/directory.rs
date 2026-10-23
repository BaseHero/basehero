//! The account directory at the home: a device writes its own base's entry
//! once, carrying only the current epoch's key package, reads the directory
//! only when it knows of no entry of its own or the entry names another
//! epoch, and never takes back a version it has seen. Real signed-up devices,
//! the real authorization service, and a data edge that stores and serves
//! entries as the Worker does, on a paused runtime.
#![cfg(feature = "synthetic-attestation")]

mod support;

use bh_account::{
    DevicePublicKeys, VerifiedAccount,
    directory::{self, DirectoryEntry},
    owner::staging::directory_entry_id,
};
use bh_crypto::{KemKey, Secret, SigningKey};
use bh_sync_client::{Client, Signer};
use std::sync::{Arc, atomic::Ordering};
use support::{
    device::{Device, ready, until},
    fake::Hosted,
};

const SERVER: &str = "http://edge.invalid";

fn reads(hosted: &Hosted) -> usize {
    hosted.edge.directory_reads.load(Ordering::SeqCst)
}
fn writes(hosted: &Hosted) -> usize {
    hosted.edge.directory_writes.load(Ordering::SeqCst)
}

/// The version this device remembers for directory entry `entry`.
fn remembered(device: &Device, entry: [u8; 32]) -> Option<i64> {
    device
        .raw()
        .query_row(
            "SELECT version FROM account_directory_versions WHERE entry=?1",
            [entry.as_slice()],
            |r| r.get(0),
        )
        .ok()
}

/// A first device whose own-base entry is written.
async fn written(hosted: &Arc<Hosted>) -> (Device, Client) {
    let mac = Device::new();
    let (client, _) = mac.start(hosted);
    until(30, "own-base entry written", || {
        mac.signer.directory_state().unwrap() == Some((1, true))
    })
    .await;
    (mac, client)
}

/// Start again with no record of an entry of its own, as a device upgraded
/// from a build that kept none.
async fn forgetting(mac: &Device, client: Client, hosted: &Arc<Hosted>) -> Client {
    client.shutdown().await;
    drop(client);
    mac.raw()
        .execute("DELETE FROM account_directory_state", [])
        .unwrap();
    mac.start(hosted).0
}

/// The own base's entry for `epoch` at `version`, signed by `mac`.
async fn base_entry(mac: &Device, epoch: [u8; 32], version: u64) -> Vec<u8> {
    mac.signer
        .prepare_base_entry(mac.base, epoch, SERVER.into(), version)
        .await
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn upgrade_writes_directory_and_index_once() {
    let hosted = Hosted::new();
    let (mac, client) = written(&hosted).await;
    // The home indexed the signup's recovery record.
    until(20, "home stored", || !mac.home_pending()).await;
    assert!(!hosted.edge.home_stores().is_empty());
    let entries = hosted.edge.directory(mac.account_log);
    assert_eq!(entries.len(), 1);
    let (id, version, bytes) = entries[0].clone();
    assert_eq!((directory_entry_id(&bytes), version), (Some(id), 1));
    let opened = mac
        .signer
        .open_directory_entries(vec![bytes])
        .await
        .unwrap();
    let opened = opened[0].as_ref().ok().unwrap();
    let DirectoryEntry::Base {
        base,
        server,
        epoch_id,
        current_key_seal,
        ..
    } = &opened.entry
    else {
        panic!("not a base entry");
    };
    assert_eq!(*base, mac.base.0);
    assert_eq!(server, SERVER);
    assert_eq!(Some(*epoch_id), mac.progress().epoch_id);
    assert!(!current_key_seal.is_empty());
    assert!(opened.signer == mac.signer.device_id());
    // One read (no entry of its own known yet) and one write.
    assert_eq!((reads(&hosted), writes(&hosted)), (1, 1));

    client.shutdown().await;
    drop(client);
    let mac = mac.restart();
    let (client, _) = mac.start(&hosted);
    until(20, "registered again", || mac.registered()).await;
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    assert_eq!((reads(&hosted), writes(&hosted)), (1, 1));
    assert_eq!(hosted.edge.directory(mac.account_log).len(), 1);
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn directory_entry_rolled_back_to_a_lower_version_is_refused() {
    let hosted = Hosted::new();
    let (mac, client) = written(&hosted).await;
    let epoch = mac.progress().epoch_id.unwrap();
    let (v5, v3) = (
        base_entry(&mac, epoch, 5).await,
        base_entry(&mac, epoch, 3).await,
    );
    let id = directory_entry_id(&v5).unwrap();
    assert_eq!(hosted.edge.directory(mac.account_log)[0].0, id);
    // Another device raised the entry; this one reads it on an upgrade.
    hosted.edge.put_directory_entry(mac.account_log, id, 5, v5);
    let client = forgetting(&mac, client, &hosted).await;
    until(20, "entry read", || {
        mac.signer.directory_state().unwrap() == Some((1, true))
    })
    .await;
    assert_eq!(remembered(&mac, id), Some(5));
    let written = writes(&hosted);

    // The home rolls the entry back to a lower version.
    hosted.edge.put_directory_entry(mac.account_log, id, 3, v3);
    let read = reads(&hosted);
    let client = forgetting(&mac, client, &hosted).await;
    until(60, "read again after following", || {
        reads(&hosted) >= read + 2
    })
    .await;
    // Refused: not taken as the entry, the floor kept, nothing rewritten.
    assert_eq!(mac.signer.directory_state().unwrap(), None);
    assert_eq!(remembered(&mac, id), Some(5));
    assert_eq!(writes(&hosted), written);
    // The floor holds across a restart.
    client.shutdown().await;
    drop(client);
    let mac = mac.restart();
    assert_eq!(remembered(&mac, id), Some(5));
}

#[tokio::test(start_paused = true)]
async fn an_entry_under_an_old_epoch_is_retried_after_follow() {
    let hosted = Hosted::new();
    let (mac, client) = written(&hosted).await;
    let current = mac.progress().epoch_id.unwrap();
    // The home's entry names another epoch.
    let other = Secret::<32>::random();
    mac.signer
        .hold_epoch(Secret::from_slice(other.expose()).unwrap());
    let stale = base_entry(&mac, bh_crypto::committed_key_id(&other), 2).await;
    let id = directory_entry_id(&stale).unwrap();
    hosted
        .edge
        .put_directory_entry(mac.account_log, id, 2, stale);
    let read = reads(&hosted);
    let followed = hosted.edge.reads(mac.account_log).len();
    let written = writes(&hosted);
    let client = forgetting(&mac, client, &hosted).await;
    until(60, "read again after following", || {
        reads(&hosted) >= read + 3
    })
    .await;
    // Each read again came after a follow of the account; nothing is
    // written over another device's newer epoch, nothing marked written.
    assert!(hosted.edge.reads(mac.account_log).len() > followed);
    assert_eq!(mac.signer.directory_state().unwrap(), None);
    assert_eq!(writes(&hosted), written);
    // Paced, never a loop.
    let paced = reads(&hosted);
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    assert!(reads(&hosted) <= paced + 2);

    // Once the entry names the base's current epoch, it is taken.
    let fresh = base_entry(&mac, current, 4).await;
    hosted
        .edge
        .put_directory_entry(mac.account_log, id, 4, fresh);
    until(120, "entry read", || {
        mac.signer.directory_state().unwrap() == Some((1, true))
    })
    .await;
    let settled = reads(&hosted);
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    assert_eq!(reads(&hosted), settled);
    assert_eq!(writes(&hosted), written);
    client.shutdown().await;
}

/// The names one read of `entries` opens for `device`, as its own signer
/// opens them now.
async fn names_held(device: &Device, hosted: &Hosted) -> Vec<([u8; 32], String)> {
    let entries = hosted
        .edge
        .directory(device.account_log)
        .into_iter()
        .map(|(_, _, bytes)| bytes)
        .collect();
    device
        .signer
        .open_directory_entries(entries)
        .await
        .unwrap()
        .into_iter()
        .flatten()
        .filter_map(|opened| match opened.entry {
            DirectoryEntry::DeviceName { device, name } => Some((device.0, name)),
            _ => None,
        })
        .collect()
}

/// Ask `device`'s client for a directory read and wait for its answer.
async fn read_names(device: &Device, client: &Client) -> Vec<([u8; 32], String)> {
    let before = device.signer.own.reads.lock().unwrap().len();
    device.signer.own.wanted.store(true, Ordering::SeqCst);
    client.wake();
    until(30, "directory read", || {
        device.signer.own.reads.lock().unwrap().len() > before
    })
    .await;
    let reads = device.signer.own.reads.lock().unwrap();
    let last = reads.last().unwrap();
    last.iter().map(|(id, name)| (id.0, name.clone())).collect()
}

/// A member device with its own keys, outside any container: enough to
/// sign its own directory entry and its removal of itself.
struct Member {
    ordinary: SigningKey,
    control: SigningKey,
    keys: DevicePublicKeys,
}
impl Member {
    fn new() -> Self {
        let (ordinary, control) = (SigningKey::generate(), SigningKey::generate());
        let keys = DevicePublicKeys::new(
            ordinary.public(),
            control.public(),
            KemKey::generate().public(),
        )
        .unwrap();
        Self {
            ordinary,
            control,
            keys,
        }
    }
    /// Its own name entry at `version`, under the account's personal key.
    fn name_entry(&self, mac: &Device, name: &str, version: u64) -> ([u8; 32], Vec<u8>) {
        let (mut account, cap, _) = mac.signer.account_owner();
        let personal = ready(account.open_current_personal(&cap)).unwrap();
        let request = directory::prepare_entry(
            account.verified(&cap).unwrap(),
            &personal,
            self.keys.id(),
            &DirectoryEntry::DeviceName {
                device: self.keys.id(),
                name: name.into(),
            },
            version,
        )
        .unwrap();
        let bytes = request
            .finish(self.ordinary.sign(request.signing_bytes()))
            .unwrap();
        (directory_entry_id(&bytes).unwrap(), bytes)
    }
    fn leave(&self, account: &VerifiedAccount) -> Vec<u8> {
        let request = account.remove_self(self.keys.id()).unwrap();
        request
            .finish(self.control.sign(request.signing_bytes()))
            .unwrap()
            .as_bytes()
            .to_vec()
    }
}

/// Order `original` on the account log and wait until `mac` followed it.
async fn ordered(hosted: &Hosted, mac: &Device, client: &Client, original: &[u8]) -> u64 {
    let at = hosted.edge.order_account(mac.account_log, original);
    until(30, "followed", || {
        client.wake();
        mac.signer.current_account().unwrap().head().position >= at
    })
    .await;
    at
}

#[tokio::test(start_paused = true)]
async fn a_device_writes_its_name_once_across_restart() {
    let hosted = Hosted::new();
    let mac = Device::new();
    *mac.signer.own.label.lock().unwrap() = Some("MacBook Pro".into());
    let (client, _) = mac.start(&hosted);
    let id = mac.signer.device_id();
    until(30, "name written", || {
        hosted.edge.directory(mac.account_log).len() == 2
    })
    .await;
    assert_eq!(
        names_held(&mac, &hosted).await,
        vec![(id.0, "MacBook Pro".to_string())]
    );
    let written = writes(&hosted);
    assert_eq!(written, 2, "the own base's entry and the name, once each");
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    assert_eq!(writes(&hosted), written);

    client.shutdown().await;
    drop(client);
    let mac = mac.restart();
    *mac.signer.own.label.lock().unwrap() = Some("MacBook Pro".into());
    let (client, _) = mac.start(&hosted);
    until(20, "registered again", || mac.registered()).await;
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    assert_eq!(writes(&hosted), written, "not written again");
    client.shutdown().await;
}

/// Wait for `done` while the directory is read at most `most` times. Each
/// tick first lets other tasks run a while and checks the count, so a
/// client reading on every pass, which keeps the paused clock from moving,
/// fails here rather than hangs.
async fn until_reading_at_most(
    hosted: &Hosted,
    most: usize,
    seconds: u64,
    what: &str,
    mut done: impl FnMut() -> bool,
) {
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(seconds);
    loop {
        for _ in 0..200 {
            tokio::task::yield_now().await;
            assert!(reads(hosted) <= most, "a read on every pass: {what}");
        }
        if done() {
            return;
        }
        assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// A minute of passes with no read.
async fn idle_without_reads(hosted: &Hosted, expected: usize) {
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    until_reading_at_most(hosted, expected, 61, "idle", || {
        tokio::time::Instant::now() >= end
    })
    .await;
    assert_eq!(reads(hosted), expected, "a read on an idle pass");
}

#[tokio::test(start_paused = true)]
async fn names_are_read_when_asked_or_after_an_addition_never_each_pass() {
    let hosted = Hosted::new();
    let mac = Device::new();
    let (client, _) = mac.start(&hosted);
    // One read: no entry of its own is known yet.
    until_reading_at_most(&hosted, 1, 30, "own-base entry written", || {
        mac.signer.directory_state().unwrap() == Some((1, true))
    })
    .await;
    let start = reads(&hosted);
    idle_without_reads(&hosted, start).await;
    assert!(mac.signer.own.reads.lock().unwrap().is_empty());

    // The devices view opens: one read.
    read_names(&mac, &client).await;
    assert_eq!(reads(&hosted), start + 1);
    idle_without_reads(&hosted, start + 1).await;

    // An addition followed: read once more for the new device's name.
    let member = Member::new();
    ordered(
        &hosted,
        &mac,
        &client,
        &mac.signer.add_device(member.keys.clone()),
    )
    .await;
    until(30, "read after the addition", || {
        mac.signer.own.reads.lock().unwrap().len() == 2
    })
    .await;
    idle_without_reads(&hosted, start + 2).await;
    assert_eq!(mac.signer.own.reads.lock().unwrap().len(), 2);
    client.shutdown().await;
}

/// Own entries that cannot be prepared hold back neither the own base's
/// entry nor a read the host asked for: each waits its own backoff.
#[tokio::test(start_paused = true)]
async fn a_failing_own_entry_holds_back_no_other_directory_work() {
    let hosted = Hosted::new();
    let mac = Device::new();
    mac.signer.own.fail_own.store(true, Ordering::SeqCst);
    let (client, _) = mac.start(&hosted);
    until(30, "own-base entry written", || {
        mac.signer.directory_state().unwrap() == Some((1, true))
    })
    .await;
    read_names(&mac, &client).await;
    client.shutdown().await;
}

/// A read that fails is reported to the host, which then need not wait for
/// names it cannot have yet.
#[tokio::test(start_paused = true)]
async fn a_failed_read_is_reported() {
    let hosted = Hosted::new();
    let (mac, client) = written(&hosted).await;
    mac.signer.own.fail_reads.store(true, Ordering::SeqCst);
    mac.signer.own.wanted.store(true, Ordering::SeqCst);
    client.wake();
    until(30, "failure reported", || {
        mac.signer.own.unread.load(Ordering::SeqCst) > 0
    })
    .await;
    assert!(mac.signer.own.reads.lock().unwrap().is_empty());
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_name_signed_by_an_inactive_or_other_device_is_ignored() {
    let hosted = Hosted::new();
    let mac = Device::new();
    *mac.signer.own.label.lock().unwrap() = Some("MacBook Pro".into());
    let (client, _) = mac.start(&hosted);
    until(30, "name written", || {
        hosted.edge.directory(mac.account_log).len() == 2
    })
    .await;
    let member = Member::new();
    ordered(
        &hosted,
        &mac,
        &client,
        &mac.signer.add_device(member.keys.clone()),
    )
    .await;
    let (entry, bytes) = member.name_entry(&mac, "Old phone", 1);
    hosted
        .edge
        .put_directory_entry(mac.account_log, entry, 1, bytes);
    let mac_id = mac.signer.device_id();
    let names = read_names(&mac, &client).await;
    assert!(names.contains(&(member.keys.id().0, "Old phone".into())));
    assert!(names.contains(&(mac_id.0, "MacBook Pro".into())));

    // The mac names the member: a device names only itself.
    let (mut account, cap, _) = mac.signer.account_owner();
    let forged = ready(account.prepare_own_entry(
        &cap,
        &DirectoryEntry::DeviceName {
            device: member.keys.id(),
            name: "Renamed by another".into(),
        },
        2,
    ));
    assert!(forged.is_err(), "this device's owner names only itself");
    let personal = ready(account.open_current_personal(&cap)).unwrap();
    let request = directory::prepare_entry(
        account.verified(&cap).unwrap(),
        &personal,
        mac_id,
        &DirectoryEntry::DeviceName {
            device: member.keys.id(),
            name: "Renamed by another".into(),
        },
        2,
    )
    .unwrap();
    let signature = ready(account.sign_content(&cap, request.signing_bytes())).unwrap();
    let forged = request.finish(signature).unwrap();
    drop(account);
    hosted
        .edge
        .put_directory_entry(mac.account_log, entry, 2, forged);
    let names = read_names(&mac, &client).await;
    assert!(
        names
            .iter()
            .all(|(device, _)| *device != member.keys.id().0),
        "{names:?}"
    );

    // The member leaves: its own entry, signed while it was active, is
    // ignored once it is not. (No rotation, so the key is the same.)
    let (_, bytes) = member.name_entry(&mac, "Old phone", 3);
    hosted
        .edge
        .put_directory_entry(mac.account_log, entry, 3, bytes);
    mac.signer.refuse_rotation.store(true, Ordering::SeqCst);
    ordered(
        &hosted,
        &mac,
        &client,
        &member.leave(&mac.signer.current_account().unwrap()),
    )
    .await;
    let names = read_names(&mac, &client).await;
    assert_eq!(names, vec![(mac_id.0, "MacBook Pro".to_string())]);
    client.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn a_name_rolled_back_to_a_lower_version_is_refused() {
    let hosted = Hosted::new();
    let (mac, client) = written(&hosted).await;
    let member = Member::new();
    ordered(
        &hosted,
        &mac,
        &client,
        &mac.signer.add_device(member.keys.clone()),
    )
    .await;
    let (entry, v5) = member.name_entry(&mac, "Pixel 10 Pro Fold", 5);
    let (_, v3) = member.name_entry(&mac, "Older name", 3);
    hosted
        .edge
        .put_directory_entry(mac.account_log, entry, 5, v5);
    let names = read_names(&mac, &client).await;
    assert_eq!(
        names,
        vec![(member.keys.id().0, "Pixel 10 Pro Fold".to_string())]
    );
    assert_eq!(remembered(&mac, entry), Some(5));
    hosted
        .edge
        .put_directory_entry(mac.account_log, entry, 3, v3);
    let names = read_names(&mac, &client).await;
    assert!(names.is_empty(), "{names:?}");
    assert_eq!(remembered(&mac, entry), Some(5));
    client.shutdown().await;
}
