mod common;

use basehero_app_lib::commands::note::{BaseRef, apply, close, encode_opened, open};
use basehero_app_lib::notes::NoteSessions;
use bh_core::{AccountId, Base, Clock, ObjectId, SignUp};
use bh_testkit::{LocalServer, TEST_PASSWORD, append_text, insert_text, invite, note};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};
use yrs::updates::decoder::Decode;
use yrs::{Any, Doc, GetString, Map, ReadTxn, Transact, Update, WriteTxn};

fn fixture() -> &'static (Base, AccountId) {
    static BASE: OnceLock<(Base, AccountId)> = OnceLock::new();
    BASE.get_or_init(|| {
        let server = LocalServer::shared();
        let core = bh_testkit::device_on_server("editor", &Clock::system(), server);
        let req = signup(server);
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (account, _) = runtime.block_on(core.sign_up(req)).unwrap();
        let base = runtime.block_on(account.create_base("Notes")).unwrap();
        (base, account.id())
    })
}

fn signup(server: &LocalServer) -> SignUp {
    SignUp {
        server: server.url(),
        invite: invite(server),
        email: format!("{}@example.test", AccountId::random()),
        password: TEST_PASSWORD.to_string().into(),
        device_name: "editor".into(),
    }
}

#[derive(Clone, Default)]
struct Recorder(Arc<(Mutex<Vec<Vec<u8>>>, Condvar)>);
impl Recorder {
    fn sink(&self) -> Box<dyn Fn(Vec<u8>) + Send + Sync> {
        let me = self.clone();
        Box::new(move |bytes| {
            let (seen, arrived) = &*me.0;
            seen.lock().unwrap().push(bytes);
            arrived.notify_all();
        })
    }
    fn updates(&self, count: usize) -> Vec<Vec<u8>> {
        let (seen, arrived) = &*self.0;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut seen = seen.lock().unwrap();
        while seen.len() < count {
            let left = deadline
                .checked_duration_since(Instant::now())
                .expect("missing update");
            seen = arrived.wait_timeout(seen, left).unwrap().0;
        }
        seen.clone()
    }
    fn len(&self) -> usize {
        self.0.0.lock().unwrap().len()
    }
}

fn apply_all(state: &[u8], updates: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let doc = Doc::new();
    let mut txn = doc.transact_mut();
    txn.apply_update(Update::decode_v1(state).unwrap()).unwrap();
    for update in updates {
        txn.apply_update(Update::decode_v1(&update).unwrap())
            .unwrap();
    }
    txn.encode_state_as_update_v1(&Default::default())
}
fn document_text(state: &[u8]) -> String {
    let doc = Doc::new();
    let mut txn = doc.transact_mut();
    txn.apply_update(Update::decode_v1(state).unwrap()).unwrap();
    txn.get_or_insert_xml_fragment("default").get_string(&txn)
}

fn equal_docs(a: &[u8], b: &[u8]) {
    assert_eq!(document_text(a), document_text(b), "document text differs");
    // Encoding can differ in ordering, so compare both directions via state vectors.
    let doc = Doc::new();
    let mut txn = doc.transact_mut();
    txn.apply_update(Update::decode_v1(a).unwrap()).unwrap();
    let before = txn.state_vector();
    txn.apply_update(Update::decode_v1(b).unwrap()).unwrap();
    assert_eq!(txn.state_vector(), before);
    let reverse = Doc::new();
    let mut txn = reverse.transact_mut();
    txn.apply_update(Update::decode_v1(b).unwrap()).unwrap();
    let before = txn.state_vector();
    txn.apply_update(Update::decode_v1(a).unwrap()).unwrap();
    assert_eq!(txn.state_vector(), before);
}

#[test]
fn two_sessions_see_each_others_edits_but_not_their_own() {
    let (base, account) = fixture();
    let id = base.create(note()).unwrap();
    let n = NoteSessions::default();
    let (r1, r2) = (Recorder::default(), Recorder::default());
    let s1 = n.open("w-1", *account, base, id, r1.sink()).unwrap();
    let _s2 = n.open("w-2", *account, base, id, r2.sink()).unwrap();
    n.apply(s1.session, &insert_text("hi")).unwrap();
    r2.updates(1);
    assert_eq!(r1.len(), 0);
    assert_eq!(base.note(id).unwrap().text(), "hi");
}

#[test]
fn opening_while_another_session_types_loses_nothing() {
    let (base, account) = fixture();
    let id = base.create(note()).unwrap();
    let n = Arc::new(NoteSessions::default());
    let s1 = n
        .open("w-1", *account, base, id, Recorder::default().sink())
        .unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let writer = {
        let n = n.clone();
        let base = base.clone();
        std::thread::spawn(move || {
            for i in 0..200 {
                let update = append_text(&base.note(id).unwrap().state(), &format!("{i}"));
                n.apply(s1.session, &update).unwrap();
                if i == 0 {
                    started_tx.send(()).unwrap();
                }
            }
        })
    };
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let r2 = Recorder::default();
    let s2 = n.open("w-2", *account, base, id, r2.sink()).unwrap();
    writer.join().unwrap();
    let expected = base.note(id).unwrap().state();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let seen = r2.0.0.lock().unwrap().clone();
        let actual = apply_all(&s2.state, seen);
        let doc = Doc::new();
        let mut txn = doc.transact_mut();
        txn.apply_update(Update::decode_v1(&actual).unwrap())
            .unwrap();
        let want = Doc::new();
        let mut w = want.transact_mut();
        w.apply_update(Update::decode_v1(&expected).unwrap())
            .unwrap();
        if txn.state_vector() == w.state_vector() {
            break;
        }
        assert!(Instant::now() < deadline, "opening lost edits");
        std::thread::sleep(Duration::from_millis(10));
    }
    equal_docs(
        &apply_all(&s2.state, r2.0.0.lock().unwrap().clone()),
        &expected,
    );
}

#[test]
fn a_lagging_session_receives_the_whole_state() {
    let (base, account) = fixture();
    let id = base.create(note()).unwrap();
    let n = NoteSessions::default();
    let blocked = Arc::new((Mutex::new(false), Condvar::new()));
    let entered = Arc::new((Mutex::new(false), Condvar::new()));
    let rec = Recorder::default();
    let (gate, signal, capture) = (blocked.clone(), entered.clone(), rec.clone());
    let sink = Box::new(move |update| {
        let (lock, cv) = &*signal;
        *lock.lock().unwrap() = true;
        cv.notify_all();
        let (lock, cv) = &*gate;
        let mut released = lock.lock().unwrap();
        while !*released {
            released = cv.wait(released).unwrap();
        }
        (capture.sink())(update);
    });
    let _s = n.open("lag", *account, base, id, sink).unwrap();
    let doc = base.note(id).unwrap();
    doc.apply(1, &insert_text("start")).unwrap();
    {
        let (lock, cv) = &*entered;
        let mut entered = lock.lock().unwrap();
        while !*entered {
            entered = cv.wait_timeout(entered, Duration::from_secs(5)).unwrap().0;
        }
    }
    for i in 0..300 {
        doc.apply(1, &append_text(&doc.state(), &format!("{i}")))
            .unwrap();
    }
    let (lock, cv) = &*blocked;
    *lock.lock().unwrap() = true;
    cv.notify_all();
    let last = rec.updates(2).last().unwrap().clone();
    let current = doc.state();
    equal_docs(&last, &current);
}

#[test]
fn closing_a_window_closes_only_its_sessions() {
    let (base, account) = fixture();
    let id = base.create(note()).unwrap();
    let n = NoteSessions::default();
    let s1 = n
        .open("w-1", *account, base, id, Recorder::default().sink())
        .unwrap();
    let rec = Recorder::default();
    let s2 = n.open("w-2", *account, base, id, rec.sink()).unwrap();
    n.close_window("w-1");
    assert_eq!(
        n.apply(s1.session, &insert_text("bad")).unwrap_err().kind,
        "NotFound"
    );
    n.apply(s2.session, &insert_text("good")).unwrap();
    assert_eq!(rec.len(), 0);
    base.note(id)
        .unwrap()
        .apply(1, &append_text(&base.note(id).unwrap().state(), "else"))
        .unwrap();
    rec.updates(1);
}

#[test]
fn closing_an_account_invalidates_only_its_sessions() {
    let (base, account) = fixture();
    let id = base.create(note()).unwrap();
    let sessions = NoteSessions::default();
    let closed = sessions
        .open("w", *account, base, id, Recorder::default().sink())
        .unwrap();
    let other = sessions
        .open(
            "w",
            AccountId::random(),
            base,
            id,
            Recorder::default().sink(),
        )
        .unwrap();
    sessions.close_account(*account);
    assert_eq!(
        sessions
            .apply(closed.session, &insert_text("no"))
            .unwrap_err()
            .kind,
        "NotFound"
    );
    sessions.apply(other.session, &insert_text("yes")).unwrap();
    assert_eq!(base.note(id).unwrap().text(), "yes");
}

#[test]
fn a_real_newer_note_needs_update_instead_of_opening_read_only() {
    let (base, account) = fixture();
    let id = ObjectId::random();
    let doc = Doc::new();
    let update = {
        let mut txn = doc.transact_mut();
        let meta = txn.get_or_insert_map("meta");
        meta.insert(&mut txn, "type", "core.note");
        meta.insert(&mut txn, "v", Any::from(2));
        meta.insert(&mut txn, "pos", "V");
        meta.insert(&mut txn, "deleted", false);
        txn.encode_update_v1()
    };
    base.test_apply_remote(id, &update).unwrap();
    assert_eq!(
        NoteSessions::default()
            .open("w", *account, base, id, Recorder::default().sink())
            .err()
            .unwrap()
            .kind,
        "NeedsUpdate"
    );
}

#[test]
fn malformed_webview_update_is_rejected_without_changing_the_note() {
    let (base, account) = fixture();
    let id = base.create(note()).unwrap();
    let sessions = NoteSessions::default();
    let opened = sessions
        .open("w", *account, base, id, Recorder::default().sink())
        .unwrap();
    let before = base.note(id).unwrap().state();
    assert_eq!(
        sessions
            .apply(opened.session, &[255, 0, 255])
            .unwrap_err()
            .kind,
        "Invalid"
    );
    equal_docs(&base.note(id).unwrap().state(), &before);
}

#[test]
fn command_bridge_resolves_the_base_and_invalidates_closed_sessions() {
    let (state, _events) = common::state_at("http://127.0.0.1:9".parse().unwrap());
    let (base, account) = fixture();
    // A different core cannot resolve this account; the bridge must not accept a forged base.
    let result = open(
        &state,
        "w",
        BaseRef {
            account: *account,
            base: base.id(),
        },
        base.create(note()).unwrap(),
        Recorder::default().sink(),
    );
    assert_eq!(result.err().unwrap().kind, "NotFound");
    let missing = apply(&state, 2, &insert_text("bad")).unwrap_err();
    assert_eq!(missing.kind, "NotFound");
    close(&state, 2);
}

#[test]
fn opened_response_has_big_endian_session_read_only_flag_and_raw_state() {
    let opened = basehero_app_lib::notes::NoteOpened {
        session: 0x0102030405060708,
        read_only: true,
        state: vec![0, 255, 7],
    };
    assert_eq!(
        encode_opened(opened),
        [1, 2, 3, 4, 5, 6, 7, 8, 1, 0, 255, 7]
    );
}

#[tokio::test]
async fn an_applied_edit_survives_reopening_the_app() {
    let server = LocalServer::shared();
    let (state, events) = common::state_at(server.url());
    bh_core::test_support::set_test_bypass(server.operator_token());
    let (account, _) = state.core.sign_up(signup(server)).await.unwrap();
    let base = account.create_base("Saved").await.unwrap();
    let id = base.create(note()).unwrap();
    let opened = state
        .notes
        .open("w", account.id(), &base, id, Recorder::default().sink())
        .unwrap();
    state
        .notes
        .apply(opened.session, &insert_text("survives"))
        .unwrap();
    let aid = account.id();
    let bid = base.id();
    drop(opened);
    drop(base);
    drop(account);
    drop(state);
    let reopened = common::open_at(events.data_dir(), server.url(), &events);
    assert_eq!(
        reopened
            .core
            .account(aid)
            .unwrap()
            .base(bid)
            .unwrap()
            .note(id)
            .unwrap()
            .text(),
        "survives"
    );
}
