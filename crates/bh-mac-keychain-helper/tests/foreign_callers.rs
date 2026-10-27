//! The test process is not BaseHero, so the real helper must refuse it
//! before reading a request.
#![cfg(target_os = "macos")]
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
};

#[test]
fn a_foreign_parent_is_refused_before_any_request_is_read() {
    let mut helper = Command::new(env!("CARGO_BIN_EXE_bh-keychain-helper"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let request = bh_mac_keychain_helper::encode_request(&bh_mac_keychain_helper::Request::Read(
        bh_mac_keychain_helper::Item::Ordinary([7; 32]),
    ));
    let _ = helper.stdin.take().unwrap().write_all(&request);
    let mut reply = Vec::new();
    helper
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut reply)
        .unwrap();
    assert_eq!(helper.wait().unwrap().code(), Some(3));
    assert!(reply.is_empty(), "{reply:?}");
}
