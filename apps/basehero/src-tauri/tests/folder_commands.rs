mod common;

use basehero_app_lib::commands::base::{ItemKind, NewItem};
use basehero_app_lib::commands::{account, approval, base};
use basehero_app_lib::views::{BaseRef, SignUpForm};
use bh_core::{AppIdentity, BaseGrantRequest, Mode};
use bh_testkit::{LocalServer, TEST_PASSWORD, invite};
use std::time::Duration;

#[tokio::test]
async fn a_folder_choice_approves_a_folder() {
    let choice = approval::BaseChoiceInput {
        base: Some(bh_core::BaseId::random()),
        folder: Some(bh_core::ObjectId::random()),
        new_name: None,
        mode: Mode::ReadOnly,
    };
    assert!(matches!(
        choice.into_grant().unwrap(),
        BaseGrantRequest::Folder {
            mode: Mode::ReadOnly,
            ..
        }
    ));
}

#[tokio::test]
async fn folder_commands_show_contents_moves_and_grants() {
    let server = LocalServer::shared();
    let (full, _events) = common::state_at(server.url());
    let signed = account::sign_up(
        &full,
        SignUpForm {
            invite: invite(server),
            email: format!("{}@example.test", bh_core::AccountId::random()),
            password: TEST_PASSWORD.into(),
            device_name: "Mac".into(),
        },
    )
    .await
    .unwrap();
    let account_id = signed.account.id;
    let personal = base::bases(&full, account_id).unwrap()[0].id;
    let r = BaseRef {
        account: account_id,
        base: personal,
    };
    let folder = base::create_object(
        &full,
        &r,
        NewItem {
            kind: ItemKind::Folder,
            parent: None,
            after: None,
            name: Some("Health".into()),
        },
    )
    .unwrap();
    let inside = base::create_object(
        &full,
        &r,
        NewItem {
            kind: ItemKind::Project,
            parent: Some(folder),
            after: None,
            name: Some("Inside".into()),
        },
    )
    .unwrap();
    let outside = base::create_object(
        &full,
        &r,
        NewItem {
            kind: ItemKind::Project,
            parent: None,
            after: None,
            name: Some("Outside".into()),
        },
    )
    .unwrap();
    let (app, _events) = common::state_at(server.url());
    let mut pending = app
        .core
        .start_connection(
            server.url(),
            &signed.account.email,
            AppIdentity {
                name: "Sample".into(),
                app_id: "app.basehero.sample".into(),
            },
        )
        .await
        .unwrap();
    let (opened, digits) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(
            approval::connect_open(&full, account_id, pending.id()),
            pending.digits()
        )
    })
    .await
    .unwrap();
    opened.unwrap();
    approval::connect_check(
        &full,
        account_id,
        pending.id(),
        &digits.unwrap().to_string(),
    )
    .await
    .unwrap();
    let (device, _) = approval::connect_approve(
        &full,
        account_id,
        pending.id(),
        approval::AppChoiceInput {
            bases: vec![approval::BaseChoiceInput {
                base: Some(personal),
                folder: None,
                new_name: None,
                mode: Mode::ReadOnly,
            }],
            cap_micro_usd: 1_000_000,
            replaces: None,
        },
    )
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(30), pending.wait())
        .await
        .unwrap()
        .unwrap();
    let health = account::app_grant_add(
        &full,
        account_id,
        device,
        approval::BaseChoiceInput {
            base: Some(personal),
            folder: Some(folder),
            new_name: None,
            mode: Mode::ReadOnly,
        },
    )
    .await
    .unwrap();
    assert_eq!(
        base::tree_children(&full, &r, Some(folder)).unwrap()[0]
            .summary
            .id,
        inside
    );
    assert_eq!(
        base::tree_children(&full, &r, Some(folder)).unwrap()[0].base,
        health
    );
    assert_eq!(
        base::tree_children(&full, &r, None)
            .unwrap()
            .iter()
            .find(|item| item.summary.id == folder)
            .unwrap()
            .mounted,
        Some(health)
    );
    assert_eq!(base::locate(&full, &r, inside).unwrap(), health);
    assert_eq!(
        base::moved_from(
            &full,
            &BaseRef {
                account: account_id,
                base: health
            },
            inside
        )
        .unwrap(),
        Some(personal)
    );
    assert!(
        account::apps(&full, account_id)
            .unwrap()
            .iter()
            .find(|app| app.device_id == device)
            .unwrap()
            .bases
            .iter()
            .any(|grant| grant.base == health)
    );
    base::move_object(&full, &r, outside, Some(health), None, None)
        .await
        .unwrap();
    assert_eq!(base::locate(&full, &r, outside).unwrap(), health);
    assert_eq!(
        base::tree_children(&full, &r, Some(folder)).unwrap().len(),
        2
    );
    base::delete_object(
        &full,
        &BaseRef {
            account: account_id,
            base: health,
        },
        outside,
    )
    .unwrap();
    assert!(
        base::trash(&full, &r)
            .unwrap()
            .iter()
            .any(|item| item.summary.id == outside && item.base == health)
    );
    account::app_grant_remove(&full, account_id, device, health)
        .await
        .unwrap();
    assert!(
        !account::apps(&full, account_id)
            .unwrap()
            .iter()
            .find(|app| app.device_id == device)
            .unwrap()
            .bases
            .iter()
            .any(|grant| grant.base == health)
    );
}
