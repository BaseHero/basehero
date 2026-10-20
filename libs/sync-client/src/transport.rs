//! WebSocket connections to the edge's two device routes.
use bh_sync::wire::MAX_FRAME_LEN;
use futures_util::{Sink, Stream, future::BoxFuture};
use std::{pin::Pin, sync::Arc};
use tokio_tungstenite::{
    Connector as TlsConnector, connect_async_tls_with_config,
    tungstenite::{Error as WsError, Message, protocol::WebSocketConfig},
};

/// The edge route a socket is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// `/v1/authz`: the attested channel to the authorization service.
    Authz,
    /// `/v1/data`: permit-checked data frames.
    Data,
}

/// Any WebSocket message stream and sink.
pub trait SocketIo:
    Stream<Item = Result<Message, WsError>> + Sink<Message, Error = WsError> + Send
{
}
impl<T> SocketIo for T where
    T: Stream<Item = Result<Message, WsError>> + Sink<Message, Error = WsError> + Send
{
}
pub type Socket = Pin<Box<dyn SocketIo>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportError;

pub trait Connector: Send + Sync {
    fn connect(&self, route: Route) -> BoxFuture<'_, Result<Socket, TransportError>>;
}

/// The largest message either route carries.
pub fn socket_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_FRAME_LEN))
        .max_frame_size(Some(MAX_FRAME_LEN))
}

/// Production transport: `wss://` with bundled public roots (`ws://` for a
/// local `http://` edge).
pub struct WsConnector {
    base: Option<String>,
    tls: Option<Arc<rustls::ClientConfig>>,
}
impl WsConnector {
    pub fn new(edge_url: &str) -> Arc<Self> {
        let base = edge_url.trim_end_matches('/');
        let base = if let Some(rest) = base.strip_prefix("https://") {
            Some(format!("wss://{rest}"))
        } else {
            base.strip_prefix("http://")
                .map(|rest| format!("ws://{rest}"))
        };
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .ok()
        .map(|builder| {
            Arc::new(
                builder
                    .with_root_certificates(bh_tls_roots::browser_roots())
                    .with_no_client_auth(),
            )
        });
        Arc::new(Self { base, tls })
    }
}
impl Connector for WsConnector {
    fn connect(&self, route: Route) -> BoxFuture<'_, Result<Socket, TransportError>> {
        Box::pin(async move {
            let (Some(base), Some(tls)) = (&self.base, &self.tls) else {
                return Err(TransportError);
            };
            let path = match route {
                Route::Authz => "/v1/authz",
                Route::Data => "/v1/data",
            };
            let (socket, _) = connect_async_tls_with_config(
                format!("{base}{path}"),
                Some(socket_config()),
                true,
                Some(TlsConnector::Rustls(tls.clone())),
            )
            .await
            .map_err(|_| TransportError)?;
            Ok(Box::pin(socket) as Socket)
        })
    }
}
