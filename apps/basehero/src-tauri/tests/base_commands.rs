mod common;

use basehero_app_lib::commands::base::{self, ItemKind, NewItem};
use basehero_app_lib::views::{AppEvent, BaseRef};
use bh_core::{BaseEvent, SignIn, SignUp};
use bh_testkit::{LocalServer, TEST_PASSWORD, invite};

async fn setup() -> (
    LocalServer,
    basehero_app_lib::state::AppState,
    common::Events,
    bh_core::AccountId,
    String,
) {
    let server = LocalServer::start();
    let (state, events) = common::state_at(server.url());
    let (account, kit) = state
        .core
        .sign_up(SignUp {
            server: server.url(),
            invite: invite(&server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: TEST_PASSWORD.to_owned().into(),
            device_name: "mac".into(),
        })
        .await
        .unwrap();
    let id = account.id();
    (server, state, events, id, kit.display())
}

fn item(
    kind: ItemKind,
    parent: Option<bh_core::ObjectId>,
    after: Option<bh_core::ObjectId>,
    name: Option<&str>,
) -> NewItem {
    NewItem {
        kind,
        parent,
        after,
        name: name.map(str::to_owned),
    }
}

#[tokio::test]
async fn items_are_created_in_place_and_listed_in_order() {
    let (_server, state, _events, account, _kit) = setup().await;
    let base = base::create_base(&state, account, "Travel").await.unwrap();
    let r = BaseRef {
        account,
        base: base.id,
    };
    let trips = base::create_object(
        &state,
        &r,
        item(ItemKind::Folder, None, None, Some("Trips")),
    )
    .unwrap();
    let note =
        base::create_object(&state, &r, item(ItemKind::Note, Some(trips), None, None)).unwrap();
    let japan = base::create_object(
        &state,
        &r,
        item(ItemKind::Project, Some(trips), Some(note), Some("Japan")),
    )
    .unwrap();
    let children = base::children(&state, &r, Some(trips)).unwrap();
    assert_eq!(
        children
            .iter()
            .map(|s| s.ty.name.as_str())
            .collect::<Vec<_>>(),
        ["core.note", "core.project"]
    );
    assert_eq!(
        children.iter().map(|s| s.id).collect::<Vec<_>>(),
        [note, japan]
    );
    assert_eq!(
        base::get_object(&state, &r, japan).unwrap().unwrap().title,
        "Japan"
    );
    assert_eq!(base::children(&state, &r, None).unwrap()[0].id, trips);
}

#[tokio::test]
async fn a_note_cannot_be_renamed() {
    let (_server, state, _events, account, _kit) = setup().await;
    let base = base::create_base(&state, account, "Travel").await.unwrap();
    let r = BaseRef {
        account,
        base: base.id,
    };
    let id = base::create_object(&state, &r, item(ItemKind::Note, None, None, None)).unwrap();
    assert_eq!(
        base::rename_object(&state, &r, id, "Wrong title")
            .unwrap_err()
            .kind,
        "Invalid"
    );
}

#[tokio::test]
async fn deleting_moves_to_trash_and_restore_brings_it_back() {
    let (_server, state, _events, account, _kit) = setup().await;
    let base = base::create_base(&state, account, "Travel").await.unwrap();
    let r = BaseRef {
        account,
        base: base.id,
    };
    let id = base::create_object(
        &state,
        &r,
        item(ItemKind::Folder, None, None, Some("Trips")),
    )
    .unwrap();
    base::delete_object(&state, &r, id).unwrap();
    assert!(base::children(&state, &r, None).unwrap().is_empty());
    assert_eq!(base::trash(&state, &r).unwrap()[0].summary.id, id);
    base::restore_object(&state, &r, id).unwrap();
    assert!(base::trash(&state, &r).unwrap().is_empty());
    assert_eq!(base::children(&state, &r, None).unwrap()[0].id, id);
}

#[tokio::test]
async fn search_lists_the_current_base_first() {
    let (_server, state, _events, account, _kit) = setup().await;
    let personal = base::create_base(&state, account, "Personal")
        .await
        .unwrap();
    let travel = base::create_base(&state, account, "Travel").await.unwrap();
    for id in [personal.id, travel.id] {
        base::create_object(
            &state,
            &BaseRef { account, base: id },
            item(ItemKind::Project, None, None, Some("ferry")),
        )
        .unwrap();
    }
    let results = base::search(&state, account, Some(travel.id), "ferry", 2).unwrap();
    assert_eq!(
        results.iter().map(|s| s.base).collect::<Vec<_>>(),
        [travel.id, personal.id]
    );
    assert_eq!(results[0].base_name, "Travel");
    assert_eq!(
        base::search(&state, account, Some(travel.id), "ferry", 1)
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn a_signed_out_account_cannot_use_a_cached_base() {
    let (_server, state, _events, account, _kit) = setup().await;
    let base = base::create_base(&state, account, "Travel").await.unwrap();
    let r = BaseRef {
        account,
        base: base.id,
    };
    state
        .core
        .account(account)
        .unwrap()
        .sign_out()
        .await
        .unwrap();
    assert_eq!(
        base::children(&state, &r, None).unwrap_err().kind,
        "NotFound"
    );
}

#[tokio::test]
async fn a_change_on_another_device_is_announced() {
    let (server, state, _events, account_id, kit) = setup().await;
    let a = state.core.account(account_id).unwrap();
    let (other, events) = common::state_at(server.url());
    let pending = other
        .core
        .sign_in(SignIn {
            server: server.url(),
            email: a.email(),
            password: TEST_PASSWORD.to_owned().into(),
            device_name: "fold".into(),
        })
        .await
        .unwrap();
    let b = pending.with_kit(&kit).await.unwrap();
    let base = base::create_base(&state, account_id, "Travel")
        .await
        .unwrap();
    a.base(base.id).unwrap().flush().await.unwrap();
    b.refresh().await.unwrap();
    let r = BaseRef {
        account: b.id(),
        base: base.id,
    };
    // Opening the shell base installs its event forwarder before the remote change.
    other.base(&r).unwrap();
    let id = base::create_object(
        &state,
        &BaseRef {
            account: account_id,
            base: base.id,
        },
        item(ItemKind::Note, None, None, None),
    )
    .unwrap();
    a.base(base.id).unwrap().flush().await.unwrap();
    events.wait_for(|event| {
        matches!(event, AppEvent::Base { account, base, event: BaseEvent::ObjectsChanged(ids) }
        if *account == b.id() && *base == r.base && ids.contains(&id))
    });
}
