//! The home's notices that the account's kit was used: read once when the
//! receiver starts and again after it follows an account entry, never on a
//! timer. Each is kept as an alert once per time; the newest kept is where
//! the next read starts, and with none kept, this device's confirmed
//! addition: a device never alerts a use from before it joined. A read that
//! fails waits for the next of those; only a broken link is the lane's.
use crate::{Shared, outbox::Fail};
use bh_account::Head as AccountHead;
use bh_authz_proto::{FromService, ToService};

/// The most notices one read returns: a full page is read on at once.
const PAGE: usize = 64;

/// The account head the notices were last read at.
#[derive(Default)]
pub(crate) struct Notices {
    read_at: Option<AccountHead>,
}

/// Read the notices if none were read at the account's current head.
/// Whether a new alert was kept.
pub(crate) async fn step(shared: &Shared, notices: &mut Notices) -> Result<bool, Fail> {
    let account = shared
        .signer
        .current_account()
        .map_err(|_| Fail::Authorization)?;
    let head = account.head();
    if notices.read_at == Some(head) {
        return Ok(false);
    }
    let device = shared
        .signer
        .identity()
        .map_err(|_| Fail::Authorization)?
        .device;
    // An addition not confirmed in this device's history yet: read after
    // the next followed entry.
    let Some(added_ms) = account.added_at(device) else {
        return Ok(false);
    };
    let database = shared
        .owner
        .shared_database(shared.container)
        .map_err(|_| Fail::Local)?;
    let mut kept = false;
    loop {
        let after_ms = database
            .lock()
            .expect("container writer lock")
            .newest_kit_used()
            .map_err(|_| Fail::Local)?
            .unwrap_or(added_ms);
        let answer = match shared
            .authz
            .request(shared, ToService::ReadNotices { after_ms })
            .await
        {
            Ok(answer) => answer,
            // Only a broken link is the lane's.
            Err(error) if Fail::from(error) == Fail::Network => return Err(Fail::Network),
            Err(_) => break,
        };
        // A home that cannot answer now is asked again after the next
        // followed entry.
        let FromService::Notices { kit_used_ms } = answer else {
            break;
        };
        let (wrote, failed) = {
            let mut database = database.lock().expect("container writer lock");
            let mut wrote = false;
            let mut failed = false;
            for time_ms in &kit_used_ms {
                match database.record_kit_used(*time_ms) {
                    Ok(new) => wrote |= new,
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
            (wrote, failed)
        };
        // Each row is committed on its own. Flush the page even when a later
        // row fails, and before a next page can fail at the network.
        if wrote {
            kept = true;
            shared.signer.alerts_written();
        }
        if failed {
            return Err(Fail::Local);
        }
        // A full page reads on from its newest; one that moved nothing ends.
        if kit_used_ms.len() < PAGE || kit_used_ms.iter().all(|time| *time <= after_ms) {
            break;
        }
    }
    notices.read_at = Some(head);
    Ok(kept)
}
