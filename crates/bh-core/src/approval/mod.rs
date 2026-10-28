//! Device approval: a signed-in device gives a new device the account key.

/// Connecting an app by approval: the app's side and the approving side.
pub mod connect;
/// Binary exchange messages, bounded state machines and displayed digits.
pub mod protocol;

use crate::client::{Api, ApprovalLive, ApprovalState};
use crate::core::PendingSignIn;
use crate::{Account, Clock, EndReason, Error};
use bh_proto::{ApprovalId, ApprovalKind, Bytes, DeviceId};
use futures_util::StreamExt;
use protocol::{ApproverSide, Digits, Ids, NewSide, TTL_MS};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use ts_rs::TS;

/// Whether a request comes from a new device or from an app.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub enum RequestKind {
    /// A new device of this account, signed in with the password.
    Device,
    /// An app that wants to connect.
    App,
}

impl From<ApprovalKind> for RequestKind {
    fn from(kind: ApprovalKind) -> Self {
        match kind {
            ApprovalKind::Device => Self::Device,
            ApprovalKind::App => Self::App,
        }
    }
}

/// A request's public metadata. Reading it does not answer the request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct ApprovalRequest {
    /// The exchange identifier.
    #[ts(type = "string")]
    pub id: ApprovalId,
    /// The pending device.
    #[ts(type = "string")]
    pub device_id: DeviceId,
    /// Server time for display only.
    #[ts(type = "number")]
    pub created_at: i64,
    /// Server time for display only; device deadlines use their own clock.
    #[ts(type = "number")]
    pub expires_at: i64,
    /// A new device or an app; an app's request shows nothing it sent.
    pub kind: RequestKind,
}

/// An opened request, carrying the approver's one-time secret until approved.
/// Dropping it before approval cancels the exchange best-effort.
pub struct OpenRequest {
    pub(crate) id: ApprovalId,
    pub(crate) device_id: DeviceId,
    pub(crate) side: Option<ApproverSide>,
    pub(crate) api: Api,
    pub(crate) clock: Clock,
    pub(crate) deadline: u64,
    pub(crate) handle: tokio::runtime::Handle,
}

impl OpenRequest {
    /// The opened exchange's identifier.
    pub fn id(&self) -> ApprovalId {
        self.id
    }
    /// The pending device's identifier.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }
    /// How long the approving device has left to type the digits.
    pub fn expires_in(&self) -> Duration {
        Duration::from_millis(self.deadline.saturating_sub(self.clock.now_ms()))
    }
}

impl Drop for OpenRequest {
    fn drop(&mut self) {
        if self.side.take().is_some() {
            let api = self.api.clone();
            let id = self.id;
            self.handle.spawn(async move {
                let _ = api.approval_end(id, EndReason::Cancelled).await;
            });
        }
    }
}

/// A pending device's approval exchange. Its secret state is never formatted or logged.
pub struct Approval {
    pending: PendingSignIn,
    id: ApprovalId,
    side: Option<NewSide>,
    deadline: u64,
    digits: Option<Digits>,
}

impl Approval {
    /// This attempt's random identifier; retry creates another.
    pub fn id(&self) -> ApprovalId {
        self.id
    }

    /// Waits for the response, posts the reveal and returns digits for the approving device.
    /// Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] if already signed in,
    /// [`Error::ApprovalEnded`] if the exchange expired or ended,
    /// [`Error::NeedsUpdate`] for a newer message format, or [`Error::Network`]
    /// if the exchange cannot be reached.
    pub async fn digits(&mut self) -> Result<Digits, Error> {
        if self.pending.is_complete().await {
            return Err(Error::invalid("signed in"));
        }
        if self.pending.clock().now_ms() >= self.deadline {
            if self.side.is_some() {
                self.end_on_error(&Error::ApprovalEnded(EndReason::Expired))
                    .await;
            }
            return Err(Error::ApprovalEnded(EndReason::Expired));
        }
        if self.side.is_none() {
            return Err(Error::ApprovalEnded(EndReason::Cancelled));
        }
        if let Some(digits) = &self.digits {
            return Ok(digits.clone());
        }
        let state = follow(
            &self.pending.api,
            self.id,
            &self.pending.clock(),
            self.deadline,
            |s| s.response.is_some(),
        )
        .await;
        let result = async {
            let state = state?;
            let response = state
                .response
                .ok_or(Error::ApprovalEnded(EndReason::BadMessage))?;
            let (reveal, digits) = self
                .side
                .as_mut()
                .ok_or(Error::ApprovalEnded(EndReason::Cancelled))?
                .on_response(&response.0, self.pending.clock().now_ms())?;
            self.pending
                .api
                .approval_reveal(self.id, Bytes(reveal))
                .await?;
            Ok(digits)
        }
        .await;
        match result {
            Ok(digits) if self.pending.clock().now_ms() >= self.deadline => {
                drop(digits);
                self.end_on_error(&Error::ApprovalEnded(EndReason::Expired))
                    .await;
                Err(Error::ApprovalEnded(EndReason::Expired))
            }
            Ok(digits) => {
                self.digits = Some(digits.clone());
                Ok(digits)
            }
            Err(error) => {
                self.end_on_error(&error).await;
                Err(error)
            }
        }
    }

    /// Waits for the sealed account key, opens it and activates the pending device.
    /// Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] for a completed sign-in,
    /// [`Error::ApprovalEnded`] for an ended exchange, [`Error::Network`]
    /// for a connection failure, or [`Error::Storage`] for a local install failure.
    pub async fn wait(&mut self) -> Result<Account, Error> {
        if self.side.is_none() {
            return Err(Error::invalid("signed in"));
        }
        if self.digits.is_none() {
            self.digits().await?;
        }
        let state = follow(
            &self.pending.api,
            self.id,
            &self.pending.clock(),
            self.deadline,
            |s| s.transfer.is_some(),
        )
        .await;
        let result = async {
            let state = state?;
            let transfer = state
                .transfer
                .ok_or(Error::ApprovalEnded(EndReason::BadMessage))?;
            let key = self
                .side
                .take()
                .ok_or(Error::ApprovalEnded(EndReason::Cancelled))?
                .on_transfer(&transfer.0, self.pending.clock().now_ms())?;
            self.pending.snapshot().finish(key).await
        }
        .await;
        match result {
            Ok(account) => {
                self.digits = None;
                Ok(account)
            }
            Err(error) => {
                self.end_on_error(&error).await;
                Err(error)
            }
        }
    }

    /// Starts a fresh exchange after the previous exchange has ended.
    /// Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] if already signed in, [`Error::Network`]
    /// on connection failure, or an error from [`Self::cancel`].
    pub async fn retry(&mut self) -> Result<(), Error> {
        if self.pending.is_complete().await {
            return Err(Error::invalid("signed in"));
        }
        if self.side.is_some() {
            self.cancel().await?;
        }
        let id = ApprovalId::random();
        let started = self.pending.clock().now_ms();
        let (side, request) = NewSide::start(
            Ids {
                account: self.pending.account_id,
                approval: id,
                new: self.pending.device_id,
            },
            started,
        );
        self.pending.api.approval_create(id, Bytes(request)).await?;
        self.id = id;
        self.deadline = started.saturating_add(TTL_MS);
        self.side = Some(side);
        self.digits = None;
        Ok(())
    }

    /// Erases this device's exchange state even if ending it on the relay fails.
    /// Returns that relay error so the app can report it. Needs the network
    /// to notify the relay.
    ///
    /// # Errors
    /// Returns [`Error::Network`] if the relay cannot be reached or a
    /// server error such as [`Error::Revoked`].
    pub async fn cancel(&mut self) -> Result<(), Error> {
        self.side = None;
        self.digits = None;
        match self
            .pending
            .api
            .approval_end(self.id, EndReason::Cancelled)
            .await
        {
            Ok(()) | Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Switches to the recovery kit. A bad kit can be retried on this handle.
    /// Needs the network to activate the device.
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] if already signed in, [`Error::BadKit`]
    /// for an incorrect kit, [`Error::Network`] on connection failure, or
    /// errors from [`Self::cancel`].
    pub async fn use_kit(&mut self, kit: &str) -> Result<Account, Error> {
        if self.side.is_none() && self.pending.is_complete().await {
            return Err(Error::invalid("signed in"));
        }
        self.cancel().await?;
        self.pending.with_kit(kit).await
    }

    async fn end_on_error(&mut self, error: &Error) {
        self.side = None;
        self.digits = None;
        let reason = match error {
            Error::ApprovalEnded(EndReason::Expired) => Some(EndReason::Expired),
            Error::ApprovalEnded(EndReason::BadMessage) | Error::NeedsUpdate => {
                Some(EndReason::BadMessage)
            }
            _ => None,
        };
        if let Some(reason) = reason {
            let _ = self.pending.api.approval_end(self.id, reason).await;
        }
    }
}

impl PendingSignIn {
    /// Creates an approval request after password sign-in; no kit is needed.
    /// Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Network`] on connection failure or server errors
    /// including [`Error::Revoked`] and [`Error::Conflict`].
    pub async fn request_approval(&self) -> Result<Approval, Error> {
        let id = ApprovalId::random();
        let clock = self.clock();
        let start = clock.now_ms();
        let (side, request) = NewSide::start(
            Ids {
                account: self.account_id,
                approval: id,
                new: self.device_id,
            },
            start,
        );
        self.api.approval_create(id, Bytes(request)).await?;
        Ok(Approval {
            pending: self.snapshot(),
            id,
            side: Some(side),
            deadline: start.saturating_add(TTL_MS),
            digits: None,
        })
    }
}

/// Watches one exchange; on every reconnect and notification re-reads server state.
/// The device's monotonic deadline governs even stalled network operations.
pub(crate) async fn follow(
    api: &Api,
    id: ApprovalId,
    clock: &Clock,
    deadline: u64,
    ready: impl Fn(&ApprovalState) -> bool,
) -> Result<ApprovalState, Error> {
    tokio::select! {
        biased;
        _ = clock.sleep_until(deadline) => Err(Error::ApprovalEnded(EndReason::Expired)),
        result = async {
            loop {
                if let Ok(mut socket) = api.approvals_live().await {
                    loop {
                        match api.approval(id).await {
                            Ok(None) => return Err(Error::ApprovalEnded(EndReason::Expired)),
                            Ok(Some(state)) if state.state == "ended" => return Err(Error::ApprovalEnded(state.end_reason.unwrap_or(EndReason::BadMessage))),
                            Ok(Some(state)) if ready(&state) => return Ok(state),
                            Ok(Some(_)) => {},
                            Err(Error::Network(_)) => break, // The socket or reply was lost: reconnect and read again.
                            Err(e) => return Err(e),
                        }
                        match socket.next().await {
                            Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                                if let Ok(live) = serde_json::from_str::<ApprovalLive>(&text)
                                    && live.t == "approval" && live.approval_id == id { continue; }
                            }
                            Some(Ok(_)) => {},
                            _ => break,
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        } => result,
    }
}
