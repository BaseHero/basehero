//! Helpers for tests of bases and sync through the core.

use crate::{device, new_signup, signin_for};
use bh_core::test_support::Fault;
use bh_core::{Account, Base, NewObject, ObjectId, TypeRef};
use serde_json::Map;
use std::path::Path;
use std::time::Duration;
use yrs::updates::decoder::Decode;
use yrs::{Doc, ReadTxn, Transact, Update, WriteTxn, XmlElementPrelim, XmlFragment, XmlTextPrelim};

/// Two full devices of one new account.
pub async fn two_devices() -> (Account, Account) {
    let (a, kit) = device("a").sign_up(new_signup()).await.expect("sign up");
    let b = device("b")
        .sign_in(signin_for(&a))
        .await
        .expect("sign in")
        .with_kit(&kit.display())
        .await
        .expect("kit");
    (a, b)
}

/// A device and its open handle to a base.
#[derive(Clone, Debug)]
pub struct DeviceBase {
    pub account: Account,
    pub base: Base,
}

/// Two devices of one account, each with the same base open and synced.
pub async fn two_devices_sharing_a_base() -> (DeviceBase, DeviceBase) {
    let (a, b) = two_devices().await;
    let base = a.create_base("Shared").await.expect("create base");
    base.flush().await.expect("flush");
    b.refresh().await.expect("refresh");
    let other = b.base(base.id()).expect("open base");
    wait_for_base(&other, || other.name() == "Shared").await;
    (
        DeviceBase { account: a, base },
        DeviceBase {
            account: b,
            base: other,
        },
    )
}

/// Polls `condition` every 20 ms, and panics if it doesn't hold within a generous
/// 30 s, so a loaded machine slows a test down instead of failing it.
pub async fn wait_for(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(30), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("condition not met within 30 s");
}

/// Waits for an open base's sync events, with a safety deadline for a stuck sync.
/// Subscribes before checking so quick changes cannot be lost.
pub async fn wait_for_base(base: &Base, mut condition: impl FnMut() -> bool) {
    let mut events = base.events();
    tokio::time::timeout(Duration::from_secs(30), async {
        while !condition() {
            // A notification normally wakes us immediately. The periodic check also
            // covers conditions that change without producing a base event.
            tokio::select! {
                _ = events.recv() => {},
                _ = tokio::time::sleep(Duration::from_secs(1)) => {},
            }
        }
    })
    .await
    .expect("base condition not met after sync events");
}

/// A new, empty note at the top level.
pub fn note() -> NewObject {
    NewObject {
        ty: TypeRef::new("core.note", 1),
        parent: None,
        after: None,
        fields: Map::new(),
    }
}

/// Creates a note in `base` whose body is one paragraph of `text`.
pub fn note_with_text(base: &Base, text: &str) -> ObjectId {
    let id = base.create(note()).expect("create note");
    base.note(id)
        .expect("open note")
        .apply(5, &insert_text(text))
        .expect("write text");
    id
}

/// An update that adds one paragraph of `text` to a note's body.
pub fn insert_text(text: &str) -> Vec<u8> {
    append_text(
        &Doc::new()
            .transact()
            .encode_state_as_update_v1(&Default::default()),
        text,
    )
}

/// An update that adds a paragraph of `text` after the document in `state`,
/// as an editor holding that document would.
pub fn append_text(state: &[u8], text: &str) -> Vec<u8> {
    let doc = Doc::new();
    let mut txn = doc.transact_mut();
    txn.apply_update(Update::decode_v1(state).expect("state"))
        .expect("apply state");
    let before = txn.state_vector();
    let body = txn.get_or_insert_xml_fragment("default");
    body.push_back(
        &mut txn,
        XmlElementPrelim::new("paragraph", [XmlTextPrelim::new(text).into()]),
    );
    txn.encode_state_as_update_v1(&before)
}

/// Stops `base`'s sync task from sending or fetching until [`resume_sync`].
pub fn pause_sync(base: &Base) {
    base.test_pause_sync();
}

pub fn resume_sync(base: &Base) {
    base.test_resume_sync();
}

/// The server handles `account`'s next post of changes to `base`, but the
/// reply is lost.
pub fn drop_next_reply(account: &Account, base: &Base) {
    let path: &'static str = Box::leak(format!("v1/bases/{}/changes", base.id()).into_boxed_str());
    account.test_inject_fault(Fault {
        method: "POST",
        path,
        lost_reply: true,
        times: 1,
    });
}

/// Whether any file under `dir` contains `needle`.
pub fn found_under(dir: &Path, needle: &[u8]) -> bool {
    std::fs::read_dir(dir)
        .expect("readable directory")
        .any(|entry| {
            let path = entry.expect("directory entry").path();
            if path.is_dir() {
                found_under(&path, needle)
            } else {
                std::fs::read(&path)
                    .is_ok_and(|bytes| bytes.windows(needle.len()).any(|w| w == needle))
            }
        })
}
