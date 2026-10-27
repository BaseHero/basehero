mod common;

use basehero_app_lib::commands::{base, files};
use basehero_app_lib::views::BaseRef;
use bh_core::{AccountId, NewFile, SignUp};
use bh_testkit::{
    LocalServer, TEST_PASSWORD, invite, note, note_with_text, signin_for, wait_for_base,
};
use std::time::Duration;

const PNG: &[u8] = b"\x89PNG\r\n\x1a\nfile contents";

async fn setup() -> (
    LocalServer,
    basehero_app_lib::state::AppState,
    common::Events,
    BaseRef,
) {
    let server = LocalServer::start();
    let (state, events) = common::state_at(server.url());
    let (account, _) = state
        .core
        .sign_up(SignUp {
            server: server.url(),
            invite: invite(&server),
            email: format!("{}@example.test", AccountId::random()),
            password: TEST_PASSWORD.to_owned().into(),
            device_name: "mac".into(),
        })
        .await
        .unwrap();
    state.listen(account.id()).unwrap();
    let created = base::create_base(&state, account.id(), "Personal")
        .await
        .unwrap();
    let r = BaseRef {
        account: account.id(),
        base: created.id,
    };
    (server, state, events, r)
}

#[tokio::test]
async fn added_files_list_in_parent_order_and_only_real_raster_bytes_render() {
    let (_server, state, _events, r) = setup().await;
    let parent = state.base(&r).unwrap().create(note()).unwrap();
    let first = files::file_add(&state, &r, Some(parent), "a.svg", "image/svg+xml", PNG).unwrap();
    let second =
        files::file_add(&state, &r, Some(parent), "b.png", "image/png", b"<svg/>").unwrap();
    assert_eq!(
        files::files(&state, &r, Some(parent))
            .unwrap()
            .iter()
            .map(|f| f.id)
            .collect::<Vec<_>>(),
        [first.id, second.id]
    );
    assert!(files::files(&state, &r, None).unwrap().is_empty());
    assert_eq!(
        files::file_info(&state, &r, first.id)
            .unwrap()
            .unwrap()
            .name,
        "a.svg"
    );
    let image = files::file_image(&state, &r, first.id).await.unwrap();
    assert_eq!(image.mime, "image/png");
    assert_eq!(image.bytes, PNG);
    assert_eq!(
        files::file_image(&state, &r, second.id)
            .await
            .unwrap_err()
            .kind,
        "Invalid"
    );
    base::delete_object(&state, &r, first.id).unwrap();
    assert_eq!(files::files(&state, &r, Some(parent)).unwrap().len(), 1);
}

#[tokio::test]
async fn opening_writes_plain_bytes_under_the_cache_and_the_next_start_clears_them() {
    let (_server, state, events, r) = setup().await;
    let id = state
        .base(&r)
        .unwrap()
        .add_file(
            NewFile {
                parent: None,
                name: "photo.png".into(),
                mime: "image/png".into(),
            },
            PNG,
        )
        .unwrap();
    let path = files::open_copy(&state, &r, id).await.unwrap();
    assert!(
        path.starts_with(
            events
                .data_dir()
                .join("cache/open")
                .join(r.base.to_string())
                .join(id.to_string())
        )
    );
    assert_eq!(std::fs::read(&path).unwrap(), PNG);
    drop(state);
    let _reopened = common::open_at(events.data_dir(), _server.url(), &events);
    assert!(!path.exists());
}

#[tokio::test]
async fn hostile_names_stay_inside_the_file_directory() {
    let (_server, state, _events, r) = setup().await;
    let id = state
        .base(&r)
        .unwrap()
        .add_file(
            NewFile {
                parent: None,
                name: "../../escape.svg".into(),
                mime: "text/html".into(),
            },
            b"not executable here",
        )
        .unwrap();
    let path = files::open_copy(&state, &r, id).await.unwrap();
    assert!(
        path.starts_with(
            state
                .cache_dir
                .join("open")
                .join(r.base.to_string())
                .join(id.to_string())
        )
    );
    assert_eq!(std::fs::read(path).unwrap(), b"not executable here");
}

#[tokio::test]
async fn versions_and_restore_pass_through() {
    let server = LocalServer::start();
    let (state, _events) = common::state_at(server.url());
    let (owner, kit) = state
        .core
        .sign_up(SignUp {
            server: server.url(),
            invite: invite(&server),
            email: format!("{}@example.test", AccountId::random()),
            password: TEST_PASSWORD.to_owned().into(),
            device_name: "mac".into(),
        })
        .await
        .unwrap();
    state.listen(owner.id()).unwrap();
    let created = base::create_base(&state, owner.id(), "Personal")
        .await
        .unwrap();
    let r = BaseRef {
        account: owner.id(),
        base: created.id,
    };
    let (clock, manual) = bh_core::Clock::manual();
    let mut sign_in = signin_for(&owner);
    sign_in.server = server.url();
    sign_in.device_name = "fold".into();
    let other = bh_testkit::device_on_server("fold", &clock, &server)
        .sign_in(sign_in)
        .await
        .unwrap()
        .with_kit(&kit.display())
        .await
        .unwrap();
    other.refresh().await.unwrap();
    let remote = other.base(r.base).unwrap();
    let id = note_with_text(&remote, "Old text");
    remote.flush().await.unwrap();
    manual.advance(Duration::from_secs(6 * 60));
    remote.tick_versions().await.unwrap();
    let (rows, more) = files::versions(&state, &r, id, None).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert!(!more);
    let historical = files::version_state(&state, &r, id, rows[0].seq)
        .await
        .unwrap();
    assert!(!historical.is_empty());
    wait_for_base(&state.base(&r).unwrap(), || {
        state.base(&r).unwrap().note(id).is_ok()
    })
    .await;
    let note = state.base(&r).unwrap().note(id).unwrap();
    note.apply(10, &bh_testkit::append_text(&note.state(), " New text"))
        .unwrap();
    state.base(&r).unwrap().flush().await.unwrap();
    files::version_restore(&state, &r, id, rows[0].seq)
        .await
        .unwrap();
    assert_eq!(note.text(), "Old text");
}

#[cfg(unix)]
#[tokio::test]
async fn an_open_cache_symlink_does_not_write_outside_the_cache() {
    let (_server, state, events, r) = setup().await;
    let id = state
        .base(&r)
        .unwrap()
        .add_file(
            NewFile {
                parent: None,
                name: "photo.png".into(),
                mime: "image/png".into(),
            },
            PNG,
        )
        .unwrap();
    let outside = events.data_dir().join("elsewhere");
    std::fs::create_dir(&outside).unwrap();
    std::fs::create_dir_all(&state.cache_dir).unwrap();
    std::os::unix::fs::symlink(&outside, state.cache_dir.join("open")).unwrap();
    assert_eq!(
        files::open_copy(&state, &r, id).await.unwrap_err().kind,
        "Invalid"
    );
    assert!(
        !outside
            .join(r.base.to_string())
            .join(id.to_string())
            .join("photo.png")
            .exists()
    );
}
