//! Resolves again for every hop; only checked answers reach the connector.
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
};

pub(crate) struct GuardedResolver(pub Arc<dyn Lookup>);
impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let lookup = self.0.lookup(name.as_str().to_owned());
        Box::pin(async move {
            // Discard name-bearing OS/resolver errors at this boundary.
            let answers = lookup.await.map_err(|_| io::Error::other("DNS failed"))?;
            let allowed: Vec<_> = answers
                .into_iter()
                .filter(|ip| crate::policy::is_public(*ip))
                .collect();
            if allowed.is_empty() {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "no public address",
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            let addresses: Addrs = Box::new(allowed.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addresses)
        })
    }
}

pub(crate) type LookupFuture = Pin<Box<dyn Future<Output = io::Result<Vec<IpAddr>>> + Send>>;
pub(crate) trait Lookup: Send + Sync + 'static {
    fn lookup(&self, host: String) -> LookupFuture;
}
pub(crate) struct SystemLookup;
impl Lookup for SystemLookup {
    fn lookup(&self, host: String) -> LookupFuture {
        Box::pin(async move {
            Ok(tokio::net::lookup_host((host.as_str(), 0))
                .await?
                .map(|a| a.ip())
                .collect())
        })
    }
}
