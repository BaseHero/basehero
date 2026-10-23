//! Rekeys' seal sets. An accepted `ACCOUNT_REKEY` leaves a durable wait
//! (`Owner::seal_waits`) for the seal set its control commits to; content
//! keeps its one ordered cursor at the first event of that epoch until this
//! device holds the key. While a wait stays, the receiver reads that set by
//! its commitment (`ReadBodies`) and has the signer install this account's
//! key from it (`Signer::install_epoch`), which keeps it in the keyring and
//! in the host's memory and ends the wait; content then resumes in order.
//!
//! A set the log does not hold, a read that fails, bytes other than the
//! committed set, or a set with no seal for this account's accepted key
//! install nothing and leave the wait, and the pass goes on to content.
//! Each wait is tried once at once, then after 1 s doubling to 60 s, and
//! again after a restart.
use crate::{
    Shared,
    outbox::{Fail, Link},
    puller,
};
use bh_authz_proto::{ToService, Want};
use bh_device::control::SealWait;
use bh_sync::{
    BodyObject, Digest, Head,
    permit::LogId,
    wire::{Refusal, Request, Response},
};
use std::{collections::HashMap, time::Duration};
use tokio::time::Instant;

/// A base's new content epoch, installed on this device: the key's id and
/// the ordered head of the rekey that installed it. For the snapshot writer;
/// it names no key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EpochInstalled {
    pub base: [u8; 32],
    pub epoch: [u8; 32],
    pub installed_at: Head,
}

/// When each wait may be tried again, by its key id. Not durable: the waits
/// are, and a restart tries each at once.
#[derive(Default)]
pub(crate) struct SealRetries {
    next: HashMap<[u8; 32], (Instant, Duration)>,
}

/// Read and install the seal set of every wait of `log` that is due.
/// Returns whether a key was installed.
pub(crate) async fn install_waiting(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    retries: &mut SealRetries,
) -> Result<bool, Fail> {
    let waits: Vec<SealWait> = shared
        .owner
        .seal_waits(shared.container)
        .map_err(|_| Fail::Local)?
        .into_iter()
        .filter(|wait| wait.base == log.id)
        .collect();
    retries
        .next
        .retain(|key, _| waits.iter().any(|wait| wait.key_id == *key));
    let mut installed = false;
    for wait in waits {
        if !crate::backoff::permit(&mut retries.next, wait.key_id, Instant::now()) {
            continue;
        }
        // A set the log lacks, or one that fails to read or is not the
        // committed bytes, is this wait not installed this time: its next
        // read is already put off, and content below its rekey goes on.
        let Ok(Some(set)) = read_set(shared, link, log, Digest(wait.commitment)).await else {
            continue;
        };
        // Bytes that are not the committed set, or a set with no seal for
        // this account's accepted key, install nothing: the wait stays.
        if shared.signer.install_epoch(wait, set).await.is_err() {
            continue;
        }
        retries.next.remove(&wait.key_id);
        installed = true;
        if let Some(fact) = shared
            .owner
            .control_fact(shared.container, log, wait.position)
            .map_err(|_| Fail::Local)?
        {
            shared.installed.send_replace(Some(EpochInstalled {
                base: wait.base,
                epoch: wait.key_id,
                installed_at: Head {
                    position: fact.position,
                    hash: Digest(fact.head_hash),
                },
            }));
        }
    }
    Ok(installed)
}

/// The body `commitment` names in `log`, or None where the log has none.
async fn read_set(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    commitment: Digest,
) -> Result<Option<Vec<u8>>, Fail> {
    let answer = shared
        .authz
        .request(
            shared,
            ToService::Permits {
                items: vec![Want::ReadBodies {
                    log,
                    bodies: vec![commitment],
                }],
            },
        )
        .await?;
    let permit = puller::only(answer)?;
    let data = link.data(shared).await?;
    let mut answers = data
        .send(|id| Request::Read { id, permit })
        .map_err(|_| Fail::Network)?;
    match answers.next().await {
        Some(Response::Body {
            index: 0,
            last: true,
            bytes,
            ..
        }) => {
            // Transport is checked before anything is judged: other bytes
            // are never handed on.
            if BodyObject::new(bytes.clone()).is_ok_and(|body| body.commitment() == commitment) {
                Ok(Some(bytes))
            } else {
                Err(Fail::Network)
            }
        }
        Some(Response::Refused {
            reason: Refusal::Missing,
            ..
        }) => Ok(None),
        Some(other) => Err(Fail::from_response(&other)),
        None => Err(Fail::Network),
    }
}
