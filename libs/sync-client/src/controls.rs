//! The own base's metadata-only control feed. Each scan reads control-route
//! events after the feed's own control cursor (never the content cursor)
//! under `ReadControls` permits, with their bodies, page by page against the
//! endpoint the first page named, and hands them to the device's scan,
//! which judges them with M alone and commits only once its coverage is
//! established. Content never passes a control the feed has not judged.
use crate::{
    Shared,
    outbox::{Fail, Link},
    puller::{self, Held, Receiver},
};
use bh_authz_proto::{ToService, Want};
use bh_device::{
    OwnerError,
    control::{ControlPage, ControlStep, ScanError, ScanStep},
};
use bh_event::Outcome;
use bh_sync::{
    BaseId, Commitment, OpaqueEvent,
    permit::LogId,
    wire::{Request, Response},
};

/// Whether the feed should scan before content reads: it has never
/// committed a scan, or content waits (and controls may move on without
/// it). Otherwise content calls it when it reaches a control the feed has
/// not judged, and content-only progress needs no control read at all.
pub(crate) fn due(shared: &Shared, log: LogId, receiver: &Receiver) -> Result<bool, Fail> {
    let covered = shared
        .owner
        .control_coverage(shared.container, log)
        .map_err(|_| Fail::Local)?;
    Ok(covered.is_none() || receiver.held != Held::No)
}

/// One scan from the feed's cursor to the endpoint its first read names.
/// Returns whether it committed anything new.
pub(crate) async fn follow(shared: &Shared, link: &mut Link, log: LogId) -> Result<bool, Fail> {
    let identity = shared.signer.identity().map_err(|_| Fail::Authorization)?;
    let before = shared
        .owner
        .control_coverage(shared.container, log)
        .map_err(|_| Fail::Local)?;
    let mut scan = shared
        .owner
        .control_scan(shared.container, log, &identity.anchor)
        .map_err(owner_fail)?;
    loop {
        let page = read_page(shared, link, log, scan.after()).await?;
        let mut page = Some(page);
        let mut step = None;
        shared
            .signer
            .with_metadata_key(BaseId(log.id), &mut |m| {
                if let Some(page) = page.take() {
                    step = Some(scan.page(m, page));
                }
            })
            .map_err(|_| Fail::Authorization)?;
        match step.ok_or(Fail::Authorization)? {
            Ok(ScanStep::More) => {}
            Ok(ScanStep::Complete) => break,
            Err(ScanError::Unavailable) => return Err(Fail::Missing),
            Err(ScanError::Paused(Outcome::UnsupportedPause)) => return Err(Fail::Unsupported),
            Err(ScanError::Paused(_)) => return Err(Fail::Missing),
        }
    }
    match shared
        .owner
        .commit_controls(shared.container, scan)
        .map_err(owner_fail)?
    {
        ControlStep::Committed { covered, .. } => Ok(before.is_none_or(|b| covered > b)),
        ControlStep::Stopped => Err(Fail::Stopped),
    }
}

fn owner_fail(error: OwnerError) -> Fail {
    match error {
        OwnerError::Unbound | OwnerError::AnchorMismatch => Fail::Authorization,
        OwnerError::Stopped => Fail::Stopped,
        // Another scan committed first: scan again.
        OwnerError::Changed => Fail::Retry,
        OwnerError::Unavailable => Fail::Missing,
        _ => Fail::Local,
    }
}

/// One control read after `after`, its items checked as transport and each
/// given its body, or None where the log has none.
async fn read_page(
    shared: &Shared,
    link: &mut Link,
    log: LogId,
    after: u64,
) -> Result<ControlPage, Fail> {
    let answer = shared
        .authz
        .request(
            shared,
            ToService::Permits {
                items: vec![Want::ReadControls { log, after }],
            },
        )
        .await?;
    let permit = puller::only(answer)?;
    let data = link.data(shared).await?;
    let response = data
        .ask(|id| Request::Read { id, permit })
        .await
        .map_err(|_| Fail::Network)?;
    let (items, coverage) = match response {
        Response::Events {
            items,
            receipt: None,
            coverage: Some(coverage),
            ..
        } => (items, coverage),
        other => return Err(Fail::from_response(&other)),
    };
    let mut events: Vec<(Commitment, OpaqueEvent)> = Vec::with_capacity(items.len());
    for (commitment, event) in &items {
        let commitment = Commitment::decode(commitment).map_err(|_| Fail::Network)?;
        let event = OpaqueEvent::decode(event).map_err(|_| Fail::Network)?;
        events.push((commitment, event));
    }
    drop(items);
    // Bodies in order. One the log reports missing is None: only an
    // invalid original is judged without it.
    let mut bodies: Vec<Option<Vec<u8>>> = Vec::with_capacity(events.len());
    while bodies.len() < events.len() {
        let (read, missing) =
            puller::read_bodies(shared, link, log, &events[bodies.len()..], None).await?;
        let progressed = !read.is_empty();
        bodies.extend(read);
        if missing && bodies.len() < events.len() {
            bodies.push(None);
        } else if !progressed {
            return Err(Fail::Network);
        }
    }
    Ok(ControlPage {
        items: events
            .into_iter()
            .zip(bodies)
            .map(|((commitment, event), body)| (commitment, event, body))
            .collect(),
        endpoint: coverage.order,
        receipt: coverage.receipt,
    })
}
