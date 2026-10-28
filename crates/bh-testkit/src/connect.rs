//! Approving an app's connection from a full device, as a person would.

use bh_core::{
    Account, AccountEvent, AppChoice, AppIdentity, AppOffer, DeviceId, Digits, Error, RequestKind,
};
use tokio::sync::{broadcast::error::RecvError, oneshot};

/// The sample app's claimed identity.
pub fn app_identity() -> AppIdentity {
    AppIdentity {
        name: "Sample".into(),
        app_id: "app.basehero.sample".into(),
    }
}

/// Waits for an app's request on `full`, opens it, types the digits the app
/// shows once they arrive on `digits`, and approves with `choose`'s answer.
pub async fn approve_next_app(
    full: &Account,
    digits: oneshot::Receiver<Digits>,
    choose: impl FnOnce(&AppOffer) -> AppChoice,
) -> Result<DeviceId, Error> {
    let mut events = full.events();
    let listed = full
        .approval_requests()
        .await?
        .into_iter()
        .find(|r| r.kind == RequestKind::App);
    let id = match listed {
        Some(request) => request.id,
        None => loop {
            match events.recv().await {
                Ok(AccountEvent::ApprovalRequested(request))
                    if request.kind == RequestKind::App =>
                {
                    break request.id;
                }
                Ok(_) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return Err(Error::Network("account closed".into())),
            }
        },
    };
    let mut open = full.open_app_request(id).await?;
    let typed = digits
        .await
        .map_err(|_| Error::Invalid("no digits".into()))?;
    let offer = open.check_digits(&typed).await?;
    full.approve_app(open, choose(&offer))
        .await
        .map(|(device, _)| device)
}
