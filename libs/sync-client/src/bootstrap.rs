//! A joined device's one-time bootstrap: read its own base's log through the
//! receiver (the same verification and apply as every later read, in
//! bounded batches committed with their receipts), resuming from stored
//! progress after an interruption, then make the container usable in one
//! commit (`Owner::activate_joined`).
//!
//! It starts where the admission's registration left progress: the base's
//! first position today. A snapshot start would be recorded there instead.
//! The joined device never registers the base; it reads its genesis.
use crate::{
    Endpoint, Shared, Signer, SyncStatus,
    backoff::Backoff,
    outbox::{Fail, Link},
    puller::{self, Receiver},
    register,
    transport::Connector,
};
use bh_device::{ContainerId, Owner};
use bh_sync::permit::LogKind;
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

/// How far the base is read: verified positions, of those known to exist.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Progress {
    pub done: u64,
    pub total: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapError {
    /// The container did not join by pairing, or its admission is not
    /// committed.
    NotJoined,
    /// The container is already active: bootstrap commits without note
    /// authority, so it runs only before activation.
    Active,
    /// The base log is stopped by a proven contradiction.
    Stopped,
    /// The log needs semantics this build does not support.
    Unsupported,
    /// Local state could not be read or written.
    Local,
}

/// How long to wait for news when nothing moved.
const POLL: Duration = Duration::from_secs(1);

/// Read the joined container's own base to the tail it knows of, then
/// activate the container. Cancel by dropping it; what committed is kept.
pub async fn run(
    endpoint: Endpoint,
    connector: Arc<dyn Connector>,
    owner: Arc<Owner>,
    container: ContainerId,
    signer: Arc<dyn Signer>,
    progress: watch::Sender<Progress>,
) -> Result<(), BootstrapError> {
    let joined = owner
        .joined(container)
        .map_err(|_| BootstrapError::Local)?
        .ok_or(BootstrapError::NotJoined)?;
    if joined.delivery.is_none() {
        return Err(BootstrapError::NotJoined);
    }
    if joined.activated {
        return Err(BootstrapError::Active);
    }
    let account = signer
        .current_account()
        .map_err(|_| BootstrapError::Local)?;
    owner
        .anchor(container, &account)
        .map_err(|_| BootstrapError::Local)?;
    let (status, _) = watch::channel(SyncStatus::SavedLocal { pending: 0 });
    let shared = Shared::new(
        endpoint,
        connector,
        owner,
        container,
        signer,
        status,
        crate::Tuning::default(),
    );
    let result = read_to_tail(&shared, progress).await;
    shared.authz.close().await;
    result?;
    shared
        .owner
        .activate_joined(container)
        .map_err(|_| BootstrapError::Local)
}

async fn read_to_tail(
    shared: &Shared,
    progress: watch::Sender<Progress>,
) -> Result<(), BootstrapError> {
    let mut link = Link::default();
    let mut registration = register::Progress::default();
    let mut receiver = Receiver::default();
    receiver.progress = Some(progress);
    // Its container has no authority before activation.
    receiver.bootstrap = true;
    receiver.watch(shared, None);
    let mut backoff = Backoff::default();
    loop {
        receiver.take_news();
        let (moved, waiting) = match register::ensure(shared, &mut link, &mut registration).await {
            Ok(Some(base)) => {
                match puller::pull(shared, &mut link, &mut receiver, base.log).await {
                    Ok(moved) => (moved, None),
                    Err(fail) => (false, Some(fail)),
                }
            }
            Ok(None) => return Err(BootstrapError::NotJoined),
            Err(fail) => (false, Some(fail)),
        };
        let stored = {
            let database = shared
                .owner
                .shared_database(shared.container)
                .map_err(|_| BootstrapError::Local)?;
            let base = database
                .lock()
                .expect("container writer lock")
                .own_base()
                .map_err(|_| BootstrapError::Local)?
                .ok_or(BootstrapError::NotJoined)?
                .base;
            database
                .lock()
                .expect("container writer lock")
                .log_progress(LogKind::Base as u8, base)
                .map_err(|_| BootstrapError::Local)?
                .ok_or(BootstrapError::NotJoined)?
        };
        if stored.stopped.is_some() {
            return Err(BootstrapError::Stopped);
        }
        receiver.report(stored.position);
        match waiting {
            None if receiver.caught_up(stored.position) && stored.position > 0 => return Ok(()),
            // A pass that committed reads on at once: the next read either
            // continues or proves the tail, so there is no news to wait for.
            None if moved => backoff.reset(),
            None => {
                backoff.reset();
                receiver.wait(shared, POLL, false).await;
            }
            Some(Fail::Unsupported) => return Err(BootstrapError::Unsupported),
            Some(Fail::Stopped) => return Err(BootstrapError::Stopped),
            Some(Fail::Local) => return Err(BootstrapError::Local),
            Some(Fail::Network) => {
                link.drop_data();
                receiver.drop_subscriptions();
                tokio::time::sleep(backoff.next()).await;
            }
            Some(_) => tokio::time::sleep(backoff.next()).await,
        }
    }
}
