//! Standalone public HTTPS handshake probe: cargo run -p bh-tls-roots --example https_probe.
//! Also cross-buildable for the Android x86_64 emulator; no account/provider traffic.
use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
    time::Duration,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host = "example.com";
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(bh_tls_roots::browser_roots())
    .with_no_client_auth();
    let conn = rustls::ClientConnection::new(Arc::new(config), host.try_into()?)?;
    let socket = TcpStream::connect((host, 443))?;
    socket.set_read_timeout(Some(Duration::from_secs(15)))?;
    socket.set_write_timeout(Some(Duration::from_secs(15)))?;
    let mut tls = rustls::StreamOwned::new(conn, socket);
    tls.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")?;
    let mut reply = [0; 256];
    let count = tls.read(&mut reply)?;
    if !reply[..count].starts_with(b"HTTP/1.1 200 ") {
        return Err(format!("unexpected HTTPS response: {:?}", &reply[..count]).into());
    }
    println!("verified HTTPS GET example.com: HTTP 200");
    Ok(())
}
