//! URL and address admission, before any socket is opened.

use crate::FetchError;
use ipnet::IpNet;
use std::{net::IpAddr, sync::LazyLock};
use url::Url;

pub(crate) fn check_url(raw: &str) -> Result<Url, FetchError> {
    let mut url = Url::parse(raw).map_err(|_| FetchError::InvalidUrl)?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(FetchError::InvalidUrl);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(FetchError::Credentials);
    }
    match url.host().ok_or(FetchError::InvalidUrl)? {
        url::Host::Ipv4(ip) if !is_public(ip.into()) => return Err(FetchError::NonPublic),
        url::Host::Ipv6(ip) if !is_public(ip.into()) => return Err(FetchError::NonPublic),
        url::Host::Domain(host) => {
            let host = host.trim_end_matches('.');
            if !host.contains('.')
                || ["localhost", "local", "internal", "home.arpa", "onion"]
                    .iter()
                    .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
            {
                return Err(FetchError::NonPublic);
            }
        }
        _ => {}
    }
    url.set_fragment(None);
    Ok(url)
}

// Deny non-global IPv4 and special-use IPv6. Transition mechanisms are denied
// rather than trying to infer the eventual translated IPv4 destination.
static BLOCKED: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
    ]
    .iter()
    .map(|range| range.parse().expect("constant network"))
    .collect()
});

pub(crate) fn is_public(ip: IpAddr) -> bool {
    if let IpAddr::V6(v6) = ip {
        // Only global unicast, excluding reserved/transition ranges below.
        if v6.segments()[0] & 0xe000 != 0x2000 {
            return false;
        }
    }
    !BLOCKED.iter().any(|range| range.contains(&ip))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_urls_normalise_only_after_provenance_check() {
        assert_eq!(
            check_url("HTTPS://EXAMPLE.com:443/a/../b#part")
                .unwrap()
                .as_str(),
            "https://example.com/b"
        );
        assert!(check_url("https://bücher.example/a").is_ok());
    }

    #[test]
    fn refuses_credentials_schemes_and_local_hosts() {
        for url in [
            "file:///etc/passwd",
            "ftp://example.com",
            "https://user:secret@example.com",
            "https://user@example.com",
            "http://localhost",
            "http://localhost.",
            "http://x.localhost",
            "http://printer.local",
            "http://intranet",
            "http://127.0.0.1",
            "http://0x7f.1",
            "http://2130706433",
            "http://[::1]",
            "http://[::ffff:127.0.0.1]",
            "http://169.254.169.254",
        ] {
            assert!(check_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn public_address_matrix() {
        for address in ["11.0.0.10", "93.184.215.14", "2606:4700::6810:84e5"] {
            assert!(is_public(address.parse().unwrap()), "{address}");
        }
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.1.2.3",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.0.1",
            "192.0.0.9",
            "192.0.2.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:10.0.0.1",
            "::11.0.0.10",
            "64:ff9b::a00:1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "2002:7f00:1::",
            "3fff::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        ] {
            assert!(!is_public(address.parse().unwrap()), "{address}");
        }
    }
}
