//! The client's lanes. The own base is registered first; then a publisher
//! (`outbox::run_publisher`) and a receiver (`puller::run_receiver`) run as
//! their own tasks, each with its own data link, and neither waits for the
//! other's round. They tell each other, and the status writer here, only
//! their latest facts. The status writer alone sets the status, from both
//! lanes' facts and the store's durable counts.
use crate::{
    Shared,
    backoff::Backoff,
    outbox::{self, Fail, Link},
    puller::{self, Held},
    register,
    status::{self, Condition},
};
use bh_sync::permit::LogId;
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

/// How long to wait for an own base to exist, without a wake.
const POLL: Duration = Duration::from_secs(1);

/// The publisher's latest facts.
#[derive(Clone, Debug, Default)]
pub(crate) struct PublishFacts {
    /// A pass has run.
    pub started: bool,
    /// Why its work is waiting, if it is.
    pub waiting: Option<Fail>,
    /// Notes held by an alarm.
    pub alarms: u64,
    /// The highest base head a verified Ack proved: a hint, never history.
    pub latest: u64,
    /// Raised each time the service said the base lacks an account change.
    pub follow: u64,
    /// Raised each time the service no longer knew the own base.
    pub unregistered: u64,
}

/// The receiver's latest facts.
#[derive(Clone, Debug, Default)]
pub(crate) struct ReceiveFacts {
    pub started: bool,
    pub waiting: Option<Fail>,
    pub held: Held,
    pub tail_known: bool,
    pub latest: u64,
    /// An account change the base lacks, or a kept copy not yet settled.
    pub unsettled: bool,
    pub control_not_accepted: bool,
    /// The account owner stopped on contradicting history.
    pub stopped: bool,
    /// Publication may proceed under this generation: registration holds,
    /// authority is current, the base is not stopped and no control is
    /// being ordered. Withdrawn before control work and on a stop or an
    /// authority change; a new generation follows each withdrawal.
    pub ready: Option<u64>,
    /// Raised after every pass, so durable counts are read again.
    pub revision: u64,
}

/// The receiver's grant of publication, in generations: each grant after a
/// withdrawal is a new one, so a package decided under an earlier grant is
/// not sent under a later one.
pub(crate) struct Readiness<'a> {
    facts: &'a watch::Sender<ReceiveFacts>,
    generation: u64,
}
impl<'a> Readiness<'a> {
    pub(crate) fn new(facts: &'a watch::Sender<ReceiveFacts>) -> Self {
        Self {
            facts,
            generation: 0,
        }
    }
    pub(crate) fn withdraw(&mut self) {
        self.facts.send_if_modified(|f| f.ready.take().is_some());
    }
    pub(crate) fn grant(&mut self) {
        let generation = &mut self.generation;
        self.facts.send_if_modified(|f| {
            if f.ready.is_some() {
                return false;
            }
            *generation += 1;
            f.ready = Some(*generation);
            true
        });
    }
}

pub(crate) async fn run(shared: Arc<Shared>) {
    let (publish, publish_facts) = watch::channel(PublishFacts::default());
    let (receive, receive_facts) = watch::channel(ReceiveFacts::default());
    let status = Owned(tokio::spawn(write_status(
        shared.clone(),
        publish_facts.clone(),
        receive_facts.clone(),
    )));
    let mut link = Link::default();
    let base = tokio::select! {
        _ = shared.halted() => None,
        base = registered(&shared, &mut link, &receive) => Some(base),
    };
    if let Some(log) = base {
        let lanes = [
            Owned(tokio::spawn(puller::run_receiver(
                shared.clone(),
                link,
                log,
                publish_facts,
                receive,
            ))),
            Owned(tokio::spawn(outbox::run_publisher(
                shared.clone(),
                log,
                receive_facts,
                publish,
            ))),
        ];
        for mut lane in lanes {
            let _ = (&mut lane.0).await;
        }
    } else {
        link.shutdown().await;
    }
    drop(status);
}

/// A lane or writer task, cancelled if the scheduler itself is.
struct Owned(tokio::task::JoinHandle<()>);
impl Drop for Owned {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Register the own base and apply its genesis, retrying until it exists
/// and is registered. Failures show as the receiver's.
async fn registered(
    shared: &Shared,
    link: &mut Link,
    facts: &watch::Sender<ReceiveFacts>,
) -> LogId {
    let mut progress = register::Progress::default();
    let mut backoff = Backoff::default();
    let mut wake = shared.wake.subscribe();
    loop {
        wake.borrow_and_update();
        let fail = match register::ensure(shared, link, &mut progress).await {
            Ok(Some(base)) => return base.log,
            Ok(None) => None,
            Err(Fail::Unregistered) => register::reregister(shared, link).await.err(),
            Err(fail) => Some(fail),
        };
        if fail == Some(Fail::Network) {
            link.drop_data();
        }
        facts.send_modify(|f| f.waiting = fail);
        let wait = if fail.is_some() { backoff.next() } else { POLL };
        let _ = tokio::time::timeout(wait, wake.changed()).await;
    }
}

/// The one status, written here alone: from both lanes' latest facts and
/// the store's durable counts, after any of them may have changed.
async fn write_status(
    shared: Arc<Shared>,
    mut publish: watch::Receiver<PublishFacts>,
    mut receive: watch::Receiver<ReceiveFacts>,
) {
    let mut wake = shared.wake.subscribe();
    loop {
        wake.borrow_and_update();
        let inputs = merge(&publish.borrow_and_update(), &receive.borrow_and_update());
        if let Some(status) = status::derive(&shared.owner, shared.container, inputs) {
            shared.status.send_if_modified(|current| {
                let changed = *current != status;
                *current = status;
                changed
            });
        }
        tokio::select! {
            changed = publish.changed() => if changed.is_err() { return },
            changed = receive.changed() => if changed.is_err() { return },
            _ = wake.changed() => {}
        }
    }
}

/// The status inputs from both lanes' facts. Each lane's reason to wait is
/// its own latest; the worse of the two shows, so one lane's success never
/// hides the other's stop or error. An idle publisher alone never means
/// Synced: that also needs the receiver's verified tail.
pub(crate) fn merge(publish: &PublishFacts, receive: &ReceiveFacts) -> status::Inputs {
    let waiting = match (publish.waiting, receive.waiting) {
        (Some(p), r) => outbox::worse(r, p),
        (None, r) => r,
    };
    let condition = if receive.stopped {
        Condition::Stopped
    } else {
        match waiting {
            Some(fail) => outbox::condition_of(fail),
            None if !(publish.started && receive.started) => Condition::Starting,
            None => Condition::Working,
        }
    };
    status::Inputs {
        condition,
        alarms: publish.alarms,
        held: receive.held,
        tail_known: receive.tail_known,
        latest: receive.latest.max(publish.latest),
        unsettled: receive.unsettled,
        control_not_accepted: receive.control_not_accepted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ran<T: Default>(f: impl FnOnce(&mut T)) -> T {
        let mut facts = T::default();
        f(&mut facts);
        facts
    }

    #[test]
    fn one_lanes_success_never_hides_the_others_stop_or_error() {
        let idle = ran(|p: &mut PublishFacts| p.started = true);
        let receiving = |waiting| {
            ran(|r: &mut ReceiveFacts| {
                r.started = true;
                r.waiting = waiting;
            })
        };
        for (fail, condition) in [
            (Fail::Network, Condition::Network),
            (Fail::Authorization, Condition::Authorization),
            (Fail::Unsupported, Condition::Unsupported),
            (Fail::Stopped, Condition::Stopped),
        ] {
            assert_eq!(merge(&idle, &receiving(Some(fail))).condition, condition);
            let publishing = ran(|p: &mut PublishFacts| {
                p.started = true;
                p.waiting = Some(fail);
            });
            assert_eq!(merge(&publishing, &receiving(None)).condition, condition);
        }
        // The worse of two errors shows, whichever lane reported it.
        let network = ran(|p: &mut PublishFacts| {
            p.started = true;
            p.waiting = Some(Fail::Network);
        });
        assert_eq!(
            merge(&network, &receiving(Some(Fail::Stopped))).condition,
            Condition::Stopped
        );
        let stopped = ran(|r: &mut ReceiveFacts| {
            r.started = true;
            r.stopped = true;
        });
        assert_eq!(merge(&idle, &stopped).condition, Condition::Stopped);
    }

    #[test]
    fn an_idle_publisher_alone_is_not_synced() {
        let idle = ran(|p: &mut PublishFacts| {
            p.started = true;
            p.latest = 9;
        });
        // The receiver has not run: still starting, its tail unknown.
        let inputs = merge(&idle, &ReceiveFacts::default());
        assert_eq!(inputs.condition, Condition::Starting);
        assert!(!inputs.tail_known);
        // An Ack hint raises the head known to exist above a verified tail.
        let receiving = ran(|r: &mut ReceiveFacts| {
            r.started = true;
            r.tail_known = true;
            r.latest = 4;
        });
        assert_eq!(merge(&idle, &receiving).latest, 9);
    }

    #[test]
    fn a_transient_account_follow_shows_as_syncing_not_missing_history() {
        let idle = ran(|p: &mut PublishFacts| p.started = true);
        let following = ran(|r: &mut ReceiveFacts| {
            r.started = true;
            r.waiting = Some(Fail::Missing);
        });
        let inputs = merge(&idle, &following);
        assert_eq!(inputs.condition, Condition::Working);
        assert_eq!(inputs.held, Held::No);
        assert!(!inputs.tail_known);
    }
}
