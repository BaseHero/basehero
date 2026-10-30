//! Connecting an app by approval. The app sends a request routed by the
//! account's email and shows six digits; a full device types them, chooses the
//! grant and sends the app its credentials under the exchange's key.

use super::protocol::{AppHello, Digits, Exchange, Ids, NewSide, TTL_MS, email_scope};
use crate::client::{Api, ApprovalState};
use crate::{Account, AppCredentials, AppGrant, BaseGrantRequest, Clock, Core, EndReason, Error};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bh_crypto::{KemKey, Secret};
use bh_proto::{ApprovalId, Bytes, ConnectCreateRequest, DeviceId};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use ts_rs::TS;
use url::Url;
use zeroize::Zeroizing;

/// An app device's monthly model spending cap unless the person chooses another.
pub const DEFAULT_APP_CAP_MICRO_USD: u64 = 1_000_000;

/// A connection last seen more than this many milliseconds ago starts selected for removal.
pub const WEEK_MS: i64 = 604_800_000;

/// What an app claims to be; shown as not verified once the digits match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppIdentity {
    /// Display name, 1–40 characters.
    pub name: String,
    /// Identifier used to recognize the app again, such as `app.example.notes`.
    pub app_id: String,
}

/// The app's side of a connection: its request, then its digits, then its
/// credentials. Its secret state is never formatted or logged.
pub struct PendingConnection {
    core: Core,
    api: Api,
    id: ApprovalId,
    device_id: DeviceId,
    hello: AppHello,
    kem_seed: Option<Secret<32>>,
    side: Option<NewSide>,
    clock: Clock,
    deadline: u64,
    digits: Option<Digits>,
}

impl Core {
    /// Asks the account with `email` to connect this app. Any of the account's
    /// full devices can answer within two minutes. Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::Invalid`] for a malformed app name or ID,
    /// [`Error::RateLimited`] after too many requests for this email, or
    /// [`Error::Network`] on connection failure.
    pub async fn start_connection(
        &self,
        server: Url,
        email: &str,
        app: AppIdentity,
    ) -> Result<PendingConnection, Error> {
        let kem_seed = Secret::<32>::random();
        let hello = AppHello {
            name: app.name,
            app_id: app.app_id,
            public: Some(URL_SAFE_NO_PAD.encode(KemKey::from_seed(&kem_seed).public())),
        };
        hello
            .validate()
            .map_err(|_| Error::invalid("app identity"))?;
        let secret = Zeroizing::new(bh_crypto::random::<32>());
        let id = ApprovalId::random();
        let device_id = DeviceId::random();
        let clock = self.shared.clock.clone();
        let started = clock.now_ms();
        let (side, request) = NewSide::start_as(
            Exchange::App,
            Ids {
                account: email_scope(email),
                approval: id,
                new: device_id,
            },
            started,
        );
        let api = self
            .shared
            .api(server, None)
            .with_connect(Zeroizing::new(URL_SAFE_NO_PAD.encode(*secret)), email);
        api.connect_create(&ConnectCreateRequest {
            email: email.to_string(),
            approval_id: id,
            device_id,
            secret_hash: Bytes(bh_crypto::sha256(&*secret).to_vec()),
            request: Bytes(request),
        })
        .await?;
        Ok(PendingConnection {
            core: self.clone(),
            api,
            id,
            device_id,
            hello,
            kem_seed: Some(kem_seed),
            side: Some(side),
            clock,
            deadline: started.saturating_add(TTL_MS),
            digits: None,
        })
    }
}

impl PendingConnection {
    /// This request's random identifier.
    pub fn id(&self) -> ApprovalId {
        self.id
    }

    /// Waits for a device to open the request, sends the app's sealed name and
    /// ID, and returns the digits to show. Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::ApprovalEnded`] if the request expired, was declined
    /// or cancelled, or a message was malformed, or [`Error::Network`] if the
    /// request cannot be reached.
    pub async fn digits(&mut self) -> Result<Digits, Error> {
        if self.clock.now_ms() >= self.deadline {
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
        let state = poll(&self.api, self.id, &self.clock, self.deadline, |s| {
            s.response.is_some()
        })
        .await;
        let result = async {
            let response = state?
                .response
                .ok_or(Error::ApprovalEnded(EndReason::BadMessage))?;
            let (reveal, digits) = self
                .side
                .as_mut()
                .ok_or(Error::ApprovalEnded(EndReason::Cancelled))?
                .on_app_response(&response.0, &self.hello, self.clock.now_ms())?;
            self.api.connect_reveal(self.id, Bytes(reveal)).await?;
            Ok(digits)
        }
        .await;
        match result {
            Ok(digits) if self.clock.now_ms() >= self.deadline => {
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

    /// Waits for the approving device's choice, opens the credentials and
    /// installs the app's account. Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::ApprovalEnded`] for an ended exchange or credentials
    /// for another device, [`Error::Network`] on connection failure, or
    /// errors from [`Core::install_app`].
    pub async fn wait(&mut self) -> Result<Account, Error> {
        if self.side.is_none() {
            return Err(Error::ApprovalEnded(EndReason::Cancelled));
        }
        if self.digits.is_none() {
            self.digits().await?;
        }
        let state = poll(&self.api, self.id, &self.clock, self.deadline, |s| {
            s.transfer.is_some()
        })
        .await;
        let result = async {
            let transfer = state?
                .transfer
                .ok_or(Error::ApprovalEnded(EndReason::BadMessage))?;
            let payload = self
                .side
                .take()
                .ok_or(Error::ApprovalEnded(EndReason::Cancelled))?
                .on_app_transfer(&transfer.0, self.clock.now_ms())?;
            let credentials: AppCredentials = serde_json::from_slice(&payload)
                .map_err(|_| Error::ApprovalEnded(EndReason::BadMessage))?;
            if credentials.device_id != self.device_id {
                return Err(Error::ApprovalEnded(EndReason::BadMessage));
            }
            self.core
                .install_app_with_seed(credentials, self.kem_seed.take())
                .await
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

    /// Erases this app's exchange state and ends the request. Needs the
    /// network to tell the approving device.
    ///
    /// # Errors
    /// Returns [`Error::Network`] if the relay cannot be reached.
    pub async fn cancel(&mut self) -> Result<(), Error> {
        self.side = None;
        self.kem_seed = None;
        self.digits = None;
        match self.api.connect_end(self.id, EndReason::Cancelled).await {
            Ok(()) | Err(Error::NotFound) => Ok(()),
            Err(e) => Err(e),
        }
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
            let _ = self.api.connect_end(self.id, reason).await;
        }
    }
}

/// Reads the app's request once a second until `ready` or the device's own deadline.
async fn poll(
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
                match api.connect_state(id).await {
                    Ok(None) => return Err(Error::ApprovalEnded(EndReason::Expired)),
                    Ok(Some(state)) if state.state == "ended" => return Err(Error::ApprovalEnded(state.end_reason.unwrap_or(EndReason::BadMessage))),
                    Ok(Some(state)) if ready(&state) => return Ok(state),
                    Ok(Some(_)) | Err(Error::Network(_)) => {}
                    Err(e) => return Err(e),
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        } => result,
    }
}

/// An opened app request on a full device. Until [`Self::check_digits`]
/// matches, nothing the app sent is shown. Dropping it before approval
/// cancels the exchange, best effort.
pub struct OpenAppRequest {
    pub(crate) id: ApprovalId,
    pub(crate) device_id: DeviceId,
    pub(crate) side: Option<super::protocol::ApproverSide>,
    pub(crate) account: Account,
    pub(crate) deadline: u64,
    pub(crate) checked: Option<AppOffer>,
    pub(crate) checked_public: Option<String>,
}

impl OpenAppRequest {
    /// The opened exchange's identifier.
    pub fn id(&self) -> ApprovalId {
        self.id
    }

    /// How long this device has left to type the digits and approve.
    pub fn expires_in(&self) -> Duration {
        Duration::from_millis(self.deadline.saturating_sub(self.account.clock().now_ms()))
    }

    /// Compares the typed digits and, if they match, returns what the app
    /// would get. Wrong digits end the exchange on both sides. Needs the network.
    ///
    /// # Errors
    /// Returns [`Error::ApprovalEnded`] for wrong digits or an ended exchange,
    /// or [`Error::Network`] if the account cannot be read.
    pub async fn check_digits(&mut self, typed: &Digits) -> Result<AppOffer, Error> {
        let mut side = self
            .side
            .take()
            .ok_or(Error::ApprovalEnded(EndReason::Cancelled))?;
        let account = self.account.clone();
        let id = self.id;
        let typed = typed.clone();
        let result = self
            .account
            .run(async move {
                let api = account.api();
                let ended = match api.approval(id).await {
                    Ok(Some(state)) if state.state == "ended" => {
                        Some(state.end_reason.unwrap_or(EndReason::BadMessage))
                    }
                    Ok(_) => None,
                    Err(e) => {
                        let _ = api.approval_end(id, EndReason::BadMessage).await;
                        return Err(e);
                    }
                };
                if let Some(reason) = ended {
                    return Err(Error::ApprovalEnded(reason));
                }
                let hello = match side.check(&typed, account.clock().now_ms()) {
                    Ok(hello) => hello,
                    Err(e) => {
                        let reason = match e {
                            Error::ApprovalEnded(reason) => reason,
                            _ => EndReason::BadMessage,
                        };
                        let _ = api.approval_end(id, reason).await;
                        return Err(e);
                    }
                };
                let public = hello.public.clone();
                match account.app_offer(hello).await {
                    Ok(offer) => Ok((side, offer, public)),
                    Err(e) => {
                        let _ = api.approval_end(id, EndReason::BadMessage).await;
                        Err(e)
                    }
                }
            })
            .await;
        let (side, offer, public) = result?;
        self.side = Some(side);
        self.checked_public = public;
        self.checked = Some(offer.clone());
        Ok(offer)
    }
}

impl Drop for OpenAppRequest {
    fn drop(&mut self) {
        if self.side.take().is_some() {
            let api = self.account.api();
            let id = self.id;
            self.account.runtime().spawn(async move {
                let _ = api.approval_end(id, EndReason::Cancelled).await;
            });
        }
    }
}

/// What an app would get, shown after the digits match. The name and ID are
/// the app's own claim, not verified.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct AppOffer {
    /// The app's claimed name.
    pub name: String,
    /// The app's claimed identifier.
    pub app_id: String,
    /// The name its device will have, `"<You> - <App>"`.
    pub device_name: String,
    /// The bases selected to start with: the account's own base, read-write.
    pub bases: Vec<AppGrant>,
    /// The monthly cap to start with, in micro-dollars.
    #[ts(type = "number")]
    pub cap_micro_usd: u64,
    /// An earlier connection of the same app, if any.
    pub old: Option<OldConnection>,
    /// Whether removing the old connection starts selected.
    pub remove_old: bool,
}

/// An earlier connection of the same app.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct OldConnection {
    /// Its device.
    #[ts(type = "string")]
    pub device_id: DeviceId,
    /// Its device name.
    pub name: String,
    /// When it was last seen, in Unix milliseconds.
    #[ts(type = "number")]
    pub last_seen_at: i64,
}

/// The person's choice for an app: whole bases, a monthly cap and,
/// optionally, the old connection to remove.
#[derive(Clone, Debug)]
pub struct AppChoice {
    /// Bases to grant, existing or new.
    pub bases: Vec<BaseGrantRequest>,
    /// Monthly model spending cap, in micro-dollars.
    pub cap_micro_usd: u64,
    /// The old connection to remove after this one succeeds.
    pub replaces: Option<DeviceId>,
}

/// `"<You> - <App>"`, where `<You>` is the email's part before `@` with its
/// first letter capitalized, cut to 60 characters.
pub(crate) fn device_name(email: &str, app: &str) -> String {
    let local = email.split('@').next().unwrap_or_default();
    let mut chars = local.chars();
    let you: String = chars
        .next()
        .map(|first| first.to_uppercase().chain(chars).collect())
        .unwrap_or_default();
    format!("{you} - {}", app.trim()).chars().take(60).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_device_name_is_you_and_the_app_cut_to_sixty_characters() {
        assert_eq!(device_name("dan@hld.ca", "Raring"), "Dan - Raring");
        assert_eq!(device_name("ölaf@x", " Sample "), "Ölaf - Sample");
        let long = device_name(&format!("{}@x", "a".repeat(55)), "Sample");
        assert_eq!(long, format!("A{} - Sa", "a".repeat(54)));
    }
}
