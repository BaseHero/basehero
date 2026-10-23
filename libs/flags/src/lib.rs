//! Compile-time settings shared by clients and the checker. No runtime toggles.

#[cfg(bh_flag_removal_wait_5m)]
pub const REMOVAL_WAIT_MS: u64 = 300_000;
#[cfg(not(bh_flag_removal_wait_5m))]
pub const REMOVAL_WAIT_MS: u64 = 259_200_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flag {
    pub name: &'static str,
    pub value: &'static str,
}

pub fn off_default() -> &'static [Flag] {
    #[cfg(bh_flag_removal_wait_5m)]
    {
        &[Flag {
            name: "removal wait",
            value: "5 minutes",
        }]
    }
    #[cfg(not(bh_flag_removal_wait_5m))]
    {
        &[]
    }
}

/// Default builds preserve the existing app-root bytes, so released peers
/// retain their existing handshake and policy identity.
pub fn bind_root(app_root: [u8; 32]) -> [u8; 32] {
    let flags = off_default();
    if flags.is_empty() {
        return app_root;
    }
    let mut settings = Vec::new();
    for flag in flags {
        settings.extend_from_slice(flag.name.as_bytes());
        settings.push(0);
        settings.extend_from_slice(flag.value.as_bytes());
        settings.push(0);
    }
    let digest = bh_crypto::hash(&settings);
    bh_crypto::hash(&[b"bh flags root v1\0".as_slice(), &app_root, &digest].concat())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BuildInfo {
    pub build: &'static str,
    pub commit: &'static str,
}

pub fn build_info() -> BuildInfo {
    BuildInfo {
        build: env!("BH_FLAGS_BUILD_NUMBER"),
        commit: env!("BH_FLAGS_SOURCE_COMMIT"),
    }
}
