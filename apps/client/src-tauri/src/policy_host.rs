//! Native-only bootstrap seam; deliberately not called until an authenticated
//! release supplies the trust ceiling and signed initial bytes.
use basehero_models::provider_policy::Trust;
use bh_confidential_attestation::Time;
use bh_provider_policy_store::{Error, Owner};
use tauri::Manager;

pub(crate) fn bootstrap(
    app: &tauri::AppHandle,
    trust: &Trust<'_>,
    signed_release_bytes: &[u8],
    device_time: Option<Time>,
) -> Result<Owner, Error> {
    let app_data = app
        .path()
        .app_data_dir()
        .map_err(|_| Error::Configuration)?;
    Owner::open(
        &app_data.join("provider-policies"),
        trust,
        signed_release_bytes,
        device_time,
    )
}
