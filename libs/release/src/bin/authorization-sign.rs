//! Public local issuer. Only `sign` reads one hidden, bounded seed from stdin.
use bh_crypto::Secret;
use bh_release::{
    authorization::{self, Expected, Kind, SignedAuthorization},
    decode_hex,
};
use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    path::PathBuf,
};

mod common;
use common::HiddenEcho;

fn seed() -> Result<Secret<32>, ()> {
    let _echo = HiddenEcho::for_stdin()?;
    let mut input = Vec::new();
    let mut stdin = io::stdin().lock();
    for _ in 0..67 {
        let mut byte = [0];
        if stdin.read(&mut byte).map_err(|_| ())? == 0 {
            break;
        }
        input.push(byte[0]);
        byte.fill(0);
        if input.last() == Some(&b'\n') {
            break;
        }
    }
    if input.last() == Some(&b'\n') {
        input.pop();
        if input.last() == Some(&b'\r') {
            input.pop();
        }
    }
    let value = std::str::from_utf8(&input).ok().and_then(decode_hex::<32>);
    input.fill(0);
    let mut bytes = value.ok_or(())?;
    let secret = Secret::from_slice(&bytes).map_err(|_| ())?;
    bytes.fill(0);
    Ok(secret)
}
fn bounded_file(path: &PathBuf, max: u64) -> Result<Vec<u8>, ()> {
    let file = File::open(path).map_err(|_| ())?;
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes).map_err(|_| ())?;
    if bytes.len() as u64 > max {
        return Err(());
    }
    Ok(bytes)
}
fn run() -> Result<(), ()> {
    let mut args = env::args_os().skip(1);
    let command = args.next().ok_or(())?;
    if !["inspect", "sign", "verify"].iter().any(|v| command == *v) {
        return Err(());
    }
    let request = PathBuf::from(args.next().ok_or(())?);
    let mut sha = None;
    let mut root = None;
    let mut commit = None;
    let mut tree = None;
    let mut kind = None;
    let mut artifacts = None;
    let mut signed = None;
    while let Some(flag) = args.next() {
        let value = args.next().ok_or(())?;
        let name = flag.to_str().ok_or(())?;
        let field = match name {
            "--request-sha256" => &mut sha,
            "--expected-root" => &mut root,
            "--public-commit" => &mut commit,
            "--product-tree" => &mut tree,
            "--kind" => &mut kind,
            "--artifacts" => &mut artifacts,
            "--signed" => &mut signed,
            _ => return Err(()),
        };
        if field.replace(value).is_some() {
            return Err(());
        }
    }
    if (command == "verify") != signed.is_some() {
        return Err(());
    }
    let expected = Expected {
        request_sha256: decode_hex::<32>(sha.as_ref().ok_or(())?.to_str().ok_or(())?).ok_or(())?,
        root: decode_hex::<32>(root.as_ref().ok_or(())?.to_str().ok_or(())?).ok_or(())?,
        public_commit: commit.ok_or(())?.into_string().map_err(|_| ())?,
        product_tree: tree.ok_or(())?.into_string().map_err(|_| ())?,
        kind: Kind::parse(kind.as_ref().ok_or(())?.to_str().ok_or(())?).ok_or(())?,
    };
    let raw = bounded_file(&request, 1024 * 1024)?;
    let checked = authorization::inspect(&raw, &expected, &PathBuf::from(artifacts.ok_or(())?))
        .map_err(|_| ())?;
    match command.to_str().ok_or(())? {
        "inspect" => println!("{}", checked.summary()),
        "sign" => {
            let signed = authorization::sign(&checked, &seed()?).map_err(|_| ())?;
            let output = serde_json::to_string(&signed).map_err(|_| ())?;
            println!("{output}");
        }
        "verify" => {
            let result = bounded_file(&PathBuf::from(signed.ok_or(())?), 1024 * 1024)?;
            let value: SignedAuthorization = serde_json::from_slice(&result).map_err(|_| ())?;
            authorization::verify(&checked, &value).map_err(|_| ())?;
            println!("authorization verified");
        }
        _ => return Err(()),
    }
    io::stdout().flush().map_err(|_| ())?;
    Ok(())
}
fn main() {
    if run().is_err() {
        eprintln!("authorization failed");
        std::process::exit(1);
    }
}
