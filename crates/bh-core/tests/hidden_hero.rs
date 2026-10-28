//! Hidden-base Hero isolation against a local account and a scripted model.
use bh_core::{
    Error,
    hero::{HeroEvent, MessageState},
};
use bh_models::{
    Completion, Finish, ToolCall,
    testing::{Scripted, ScriptedModel, StreamScript},
};
use bh_testkit::{device, new_signup, note_with_text, wait_for};
use serde_json::json;
use std::time::Duration;
use zeroize::Zeroizing;

fn call(name: &str, args: serde_json::Value) -> Scripted {
    Scripted::Reply(Completion {
        text: None,
        tool_calls: vec![ToolCall {
            id: "call1".into(),
            name: name.into(),
            arguments: args.to_string(),
        }],
        finish: Finish::ToolCalls,
        usage: None,
    })
}
fn reply(text: &str) -> Scripted {
    Scripted::Reply(Completion {
        text: Some(text.into()),
        tool_calls: vec![],
        finish: Finish::Stop,
        usage: None,
    })
}

#[tokio::test]
async fn locking_a_hidden_base_stops_heros_turn_and_leaves_no_hero_context() {
    let (account, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let personal = account.create_base("Personal").await.unwrap();
    let personal = personal.id();
    note_with_text(&account.base(personal).unwrap(), "Ferry at 9");
    let password = || Zeroizing::new("ferry lantern quartz".to_string());
    let hidden = account
        .create_hidden_base("Zebra Diary", password())
        .await
        .unwrap();
    let hidden_id = hidden.id();
    note_with_text(&hidden, "Gelato with Marguerite");
    let model = ScriptedModel::new(vec![
        call("search", json!({"text":"gelato"})),
        Scripted::Hang,
        call("list_bases", json!({})),
        call("search", json!({"text":"gelato"})),
        reply("Nothing found."),
    ]);
    let hero = account.hero_with_model(model.clone());
    let chat = hero.new_chat(hidden_id).unwrap();
    hero.send(hidden_id, chat, "What did I write about gelato?", None)
        .unwrap();
    wait_for(|| model.requests().len() == 2).await;
    assert!(format!("{:?}", model.requests()).contains("Marguerite"));

    tokio::time::timeout(Duration::from_secs(1), account.lock_hidden(hidden_id))
        .await
        .expect("lock must not wait for the hung model")
        .unwrap();
    tokio::time::timeout(Duration::from_millis(100), hero.wait_idle(chat))
        .await
        .expect("the cancelled turn must have ended");
    assert!(matches!(hero.chats(hidden_id), Err(Error::NotFound)));
    assert!(matches!(
        hero.messages(hidden_id, chat),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        hero.send(hidden_id, chat, "Again", None),
        Err(Error::NotFound)
    ));
    assert_eq!(
        model.requests().len(),
        2,
        "a cancelled turn cannot call the model again"
    );

    let personal_chat = hero.new_chat(personal).unwrap();
    hero.send(
        personal,
        personal_chat,
        "What do I know about gelato?",
        None,
    )
    .unwrap();
    hero.wait_idle(personal_chat).await;
    let requests = model.requests();
    assert_eq!(requests.len(), 5);
    let later = format!("{:?}", &requests[2..]);
    for forbidden in [
        "Gelato",
        "Marguerite",
        "Zebra Diary",
        &hidden_id.to_string(),
    ] {
        assert!(
            !later.contains(forbidden),
            "hidden context reached a later request: {forbidden}"
        );
    }
    let list_result = requests[3]
        .messages
        .iter()
        .find(|m| m.tool_call_id.is_some())
        .and_then(|m| m.content.as_deref())
        .expect("the list_bases tool result was sent to the model");
    assert!(!list_result.contains(&hidden_id.to_string()));
    assert_eq!(
        hero.messages(personal, personal_chat).unwrap()[1].state,
        MessageState::Done
    );

    account.unlock_hidden(password()).await.unwrap();
    let messages = hero.messages(hidden_id, chat).unwrap();
    let result = &messages[1];
    assert!(
        result.state == MessageState::Stopped
            || (result.state == MessageState::Failed
                && result.error.as_deref() == Some("interrupted")),
        "cancelled turn cannot finish as Done: {:?}",
        result.state
    );
    assert_eq!(model.requests().len(), 5);
}

#[tokio::test]
async fn locking_cancels_every_hidden_chat_without_stopping_ordinary_chats() {
    let (account, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let personal = account.create_base("Personal").await.unwrap();
    let password = || Zeroizing::new("ferry lantern quartz".to_string());
    let hidden = account
        .create_hidden_base("Zebra Diary", password())
        .await
        .unwrap();
    let model = ScriptedModel::new(vec![Scripted::Hang, Scripted::Hang, Scripted::Hang]);
    let hero = account.hero_with_model(model.clone());
    let first = hero.new_chat(hidden.id()).unwrap();
    let second = hero.new_chat(hidden.id()).unwrap();
    hero.send(hidden.id(), first, "First", None).unwrap();
    wait_for(|| model.requests().len() == 1).await;
    hero.send(hidden.id(), second, "Second", None).unwrap();
    wait_for(|| model.requests().len() == 2).await;
    let ordinary = hero.new_chat(personal.id()).unwrap();
    hero.send(personal.id(), ordinary, "Keep working", None)
        .unwrap();
    wait_for(|| model.requests().len() == 3).await;
    tokio::time::timeout(Duration::from_secs(1), account.lock_hidden(hidden.id()))
        .await
        .expect("locking must cancel both hung turns")
        .unwrap();
    for chat in [first, second] {
        tokio::time::timeout(Duration::from_millis(100), hero.wait_idle(chat))
            .await
            .expect("both hidden chats are idle");
    }
    assert_eq!(
        hero.messages(personal.id(), ordinary).unwrap()[1].state,
        MessageState::Working
    );
    assert_eq!(model.requests().len(), 3);
    hero.stop(personal.id(), ordinary).unwrap();
    account.unlock_hidden(password()).await.unwrap();
    for chat in [first, second] {
        let message = &hero.messages(hidden.id(), chat).unwrap()[1];
        assert!(
            message.state == MessageState::Stopped
                || (message.state == MessageState::Failed
                    && message.error.as_deref() == Some("interrupted"))
        );
    }
}

#[tokio::test]
async fn locking_does_not_wait_for_a_held_reader_refresh() {
    let (account, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let hidden = account
        .create_hidden_base("Zebra Diary", Zeroizing::new("ferry lantern quartz".into()))
        .await
        .unwrap();
    let held = account.test_hold_next_account_get();
    let before = account.test_request_count("v1/account");
    let model = ScriptedModel::new(vec![Scripted::Hang]);
    let hero = account.hero_with_model(model.clone());
    let chat = hero.new_chat(hidden.id()).unwrap();
    hero.send(hidden.id(), chat, "Hi", None).unwrap();
    wait_for(|| account.test_request_count("v1/account") > before).await;
    tokio::time::timeout(Duration::from_secs(2), hidden.flush())
        .await
        .expect("the outbox must be clear to isolate the cancellation bound")
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), account.lock_hidden(hidden.id()))
        .await
        .expect("lock must cancel the reader refresh, not wait ten seconds")
        .unwrap();
    hero.wait_idle(chat).await;
    assert!(
        model.requests().is_empty(),
        "a cancelled pre-model turn never calls the model"
    );
    drop(held);
}

#[tokio::test]
async fn a_chat_inside_an_unlocked_hidden_base_reads_it() {
    let (account, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let hidden = account
        .create_hidden_base("Zebra Diary", Zeroizing::new("ferry lantern quartz".into()))
        .await
        .unwrap();
    note_with_text(&hidden, "Gelato with Marguerite");
    let model = ScriptedModel::new(vec![
        call("search", json!({"text":"gelato"})),
        reply("You wrote about gelato."),
    ]);
    let hero = account.hero_with_model(model.clone());
    let chat = hero.new_chat(hidden.id()).unwrap();
    hero.send(hidden.id(), chat, "What did I write about gelato?", None)
        .unwrap();
    hero.wait_idle(chat).await;
    let message = &hero.messages(hidden.id(), chat).unwrap()[1];
    assert_eq!(message.state, MessageState::Done);
    assert!(message.steps.iter().any(|step| step.tool == "search"));
    let tool_result = model.requests()[1]
        .messages
        .iter()
        .find(|m| m.tool_call_id.is_some())
        .and_then(|m| m.content.clone())
        .unwrap();
    assert!(tool_result.contains("Gelato"));
    assert!(tool_result.contains(&hidden.id().to_string()));
}

#[tokio::test]
async fn locking_mid_stream_writes_nothing_more() {
    let (account, _) = device("mac").sign_up(new_signup()).await.unwrap();
    let password = || Zeroizing::new("ferry lantern quartz".to_string());
    let hidden = account
        .create_hidden_base("Zebra Diary", password())
        .await
        .unwrap();
    let (script, control) = StreamScript::new();
    let model = ScriptedModel::new(vec![Scripted::Stream(script)]);
    let hero = account.hero_with_model(model.clone());
    let chat = hero.new_chat(hidden.id()).unwrap();
    let mut events = hero.events();
    hero.send(hidden.id(), chat, "Write", None).unwrap();
    control.text("Secret");
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let HeroEvent::Text { text, .. } = events.recv().await.unwrap() {
                assert_eq!(text, "Secret");
                break;
            }
        }
    })
    .await
    .expect("the text is shown before the lock");

    tokio::time::timeout(Duration::from_secs(1), account.lock_hidden(hidden.id()))
        .await
        .expect("lock must not wait for the stream")
        .unwrap();
    control.text(" more");
    control.finish(Completion {
        text: Some("Secret more".into()),
        tool_calls: vec![],
        finish: Finish::Stop,
        usage: None,
    });
    hero.wait_idle(chat).await;
    while let Ok(event) = events.try_recv() {
        assert!(
            !matches!(event, HeroEvent::Text { .. }),
            "no text is shown after the lock"
        );
    }

    account.unlock_hidden(password()).await.unwrap();
    let message = &hero.messages(hidden.id(), chat).unwrap()[1];
    assert_eq!(
        (message.state, message.text.as_str()),
        (MessageState::Stopped, "Secret")
    );
    assert_eq!(model.requests().len(), 1);
}
