use super::{
    access::Access,
    tools::Tools,
    turn::{self, ResultKind, TurnLimits},
};
use crate::{Base, NewObject, TypeRef};
use bh_models::{
    Completion, Finish, Message, Role, ToolCall,
    testing::{Scripted, ScriptedModel},
};
use serde_json::json;

fn local() -> (Base, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let base = Base::open_local(dir.path(), bh_crypto::random::<32>()).unwrap();
    (base, dir)
}
fn read(base: crate::BaseId, id: crate::ObjectId) -> Scripted {
    Scripted::Reply(Completion {
        text: None,
        tool_calls: vec![ToolCall {
            id: "read1".into(),
            name: "read".into(),
            arguments: json!({"base":base,"id":id}).to_string(),
        }],
        finish: Finish::ToolCalls,
        usage: None,
    })
}
fn user() -> Vec<Message> {
    vec![Message {
        role: Role::User,
        content: Some("Read this".into()),
        tool_calls: vec![],
        tool_call_id: None,
    }]
}
#[tokio::test]
async fn asking_and_answering_rechecks_access_without_leaking_content() {
    let (chat, _chat_dir) = local();
    let (private, _private_dir) = local();
    let id = private
        .create(NewObject {
            ty: TypeRef::new("core.folder", 1),
            parent: None,
            after: None,
            fields: json!({"name":"Private title"}).as_object().unwrap().clone(),
        })
        .unwrap();
    let model = ScriptedModel::new(vec![read(private.id(), id)]);
    let mut tools = Tools::new(chat.clone(), vec![(private.clone(), Access::Ask)], None);
    let (_sender, cancel) = tokio::sync::watch::channel(false);
    let result = turn::run(
        model.as_ref(),
        &mut tools,
        user(),
        TurnLimits::default(),
        cancel,
        |_, _| {},
        |tools, call| Some(tools.call(call)),
    )
    .await;
    assert!(matches!(result.kind,ResultKind::Ask(base) if base==private.id()));
    assert!(!format!("{:?}", model.requests()).contains("Private title"));
    let denied = ScriptedModel::new(vec![
        read(private.id(), id),
        Scripted::Reply(Completion {
            text: Some("No access".into()),
            tool_calls: vec![],
            finish: Finish::Stop,
            usage: None,
        }),
    ]);
    let mut tools = Tools::new(chat.clone(), vec![(private.clone(), Access::Never)], None);
    let (_sender, cancel) = tokio::sync::watch::channel(false);
    let outcome = turn::run(
        denied.as_ref(),
        &mut tools,
        user(),
        TurnLimits::default(),
        cancel,
        |_, _| {},
        |tools, call| Some(tools.call(call)),
    )
    .await;
    assert!(matches!(outcome.kind, ResultKind::Answer(_)));
    assert!(format!("{:?}", denied.requests()).contains("not_allowed"));
    let allowed = ScriptedModel::new(vec![
        read(private.id(), id),
        Scripted::Reply(Completion {
            text: Some("Found".into()),
            tool_calls: vec![],
            finish: Finish::Stop,
            usage: None,
        }),
    ]);
    let mut tools = Tools::new(chat, vec![(private, Access::Free)], None);
    let (_sender, cancel) = tokio::sync::watch::channel(false);
    let outcome = turn::run(
        allowed.as_ref(),
        &mut tools,
        user(),
        TurnLimits::default(),
        cancel,
        |_, _| {},
        |tools, call| Some(tools.call(call)),
    )
    .await;
    assert!(matches!(outcome.kind, ResultKind::Answer(_)));
    assert!(format!("{:?}", allowed.requests()).contains("Private title"));
}
