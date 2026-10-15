//! Bundled public HTTPS trust anchors. No platform certificate-folder access.

/// Standard browser CA roots for public HTTPS; callers choose their own TLS provider.
/// Private-CA self-hosted endpoints are not trusted by this store.
pub fn browser_roots() -> rustls::RootCertStore {
    rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
}

#[cfg(test)]
mod tests {
    #[test]
    fn browser_roots_include_isrg_root_x1() {
        let roots = super::browser_roots();
        assert!(!roots.is_empty());
        assert!(roots.roots.iter().any(|anchor| {
            anchor
                .subject
                .as_ref()
                .windows(b"ISRG Root X1".len())
                .any(|part| part == b"ISRG Root X1")
        }));
    }
}
