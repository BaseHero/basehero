//! The build's fixed sync endpoint for the app's sync host
//! (`bh_host::sync`): the file `build.rs` checked and copied in, never a
//! page or runtime value.
use bh_host::sync::Configured;

const BUILT_ENDPOINT: &str = include_str!(concat!(env!("OUT_DIR"), "/sync-endpoint.json"));

pub(crate) fn configured() -> Configured {
    Configured::from_text(BUILT_ENDPOINT)
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_build_without_an_endpoint_is_local_only() {
        if option_env!("BH_SYNC_ENDPOINT").is_none() {
            assert!(matches!(super::configured(), super::Configured::Missing));
        }
    }
}
