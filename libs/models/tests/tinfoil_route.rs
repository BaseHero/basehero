#![cfg(feature = "tinfoil-route")]

use basehero_models::accounting::WorkKind;
use basehero_models::response::Limits;
use basehero_models::tinfoil_route::{ChatRequest, Gateway, Message, Role, RouteError};

#[test]
fn public_configuration_refuses_unsafe_gateway_before_network() {
    for url in [
        "http://example.com",
        "https://user@example.com",
        "https://example.com/#x",
        "https://example.com/?next=evil",
        "file:///tmp/key",
        "https://example.com:0",
    ] {
        assert!(matches!(Gateway::new(url), Err(RouteError::InvalidGateway)));
    }
    assert!(Gateway::new("https://gateway.example.com/model/").is_ok());
}

#[tokio::test]
async fn invalid_request_and_proxy_credential_fail_before_network() {
    let gateway = Gateway::new("https://gateway.example.com").unwrap();
    let request = |max_tokens| ChatRequest {
        messages: vec![Message {
            role: Role::User,
            content: Some(serde_json::json!("no-network-canary")),
            tool_calls: None,
            tool_call_id: None,
        }],
        tools: None,
        tool_choice: None,
        response_format: None,
        max_tokens,
    };
    assert!(matches!(
        gateway.start(
            request(0),
            "credential".into(),
            WorkKind::AskedTurn,
            Limits::default()
        ),
        Err(RouteError::InvalidRequest)
    ));
    assert!(matches!(
        gateway.start(
            request(10),
            "bad\ncredential".into(),
            WorkKind::AskedTurn,
            Limits::default()
        ),
        Err(RouteError::InvalidRequest)
    ));
}
