//! Release-key generation and signing. The seed is read from stdin only,
//! never from a command line, the environment or a default file.
use std::{
    env,
    fs::File,
    io::{self, BufRead, IsTerminal, Read, Write},
    path::Path,
    process::{Command, Stdio},
};

use bh_crypto::{Secret, Sha256, SigningKey};
use bh_release::{Metadata, SignedRelease, decode_hex};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn seed_from_stdin(input: &mut impl BufRead) -> Result<Secret<32>, String> {
    let mut line = String::new();
    input.read_line(&mut line).map_err(|e| e.to_string())?;
    let value = line.trim_end_matches(['\r', '\n']);
    let mut bytes = decode_hex::<32>(value)
        .ok_or("expected exactly 64 lowercase hexadecimal seed characters on stdin")?;
    // The stack copy is erased after transferring into the protected owner.
    let secret = Secret::from_slice(&bytes).map_err(|_| "invalid seed")?;
    bytes.fill(0);
    // Clear the input buffer before returning (terminal and OS buffers remain outside us).
    line.into_bytes().fill(0);
    Ok(secret)
}

// An interactive paste must not be echoed into terminal scrollback. Pipes used
// by test fixtures have no terminal to modify. Restore echo on every normal exit.
struct HiddenEcho(bool);
impl HiddenEcho {
    fn for_stdin() -> Result<Self, String> {
        if !io::stdin().is_terminal() {
            return Ok(Self(false));
        }
        let status = Command::new("stty")
            .arg("-echo")
            .stdin(Stdio::inherit())
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err("cannot hide seed input on terminal".into());
        }
        Ok(Self(true))
    }
}
impl Drop for HiddenEcho {
    fn drop(&mut self) {
        if self.0 {
            let _ = Command::new("stty")
                .arg("echo")
                .stdin(Stdio::inherit())
                .status();
            eprintln!();
        }
    }
}

fn sign(seed: &Secret<32>, metadata: Metadata) -> Result<SignedRelease, String> {
    let key = SigningKey::from_seed(seed);
    let signature = key.sign(&metadata.signing_bytes().map_err(|e| e.to_string())?);
    Ok(SignedRelease {
        metadata,
        signature: hex(&signature),
    })
}

fn file_hash(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hex(&hash.finalize()))
}

fn run() -> Result<(), String> {
    let args: Vec<_> = env::args().collect();
    match args.as_slice() {
        [_, command] if command == "generate" => {
            let seed = Secret::<32>::random();
            let key = SigningKey::from_seed(&seed);
            // Shown once. Run in a private terminal and enter the seed straight
            // into the signing secret store; never a repository, log or chat.
            println!("Public release key: {}", hex(&key.public()));
            println!("Seed (store only in the signing secret): {}", hex(seed.expose()));
            eprintln!("Clear terminal scrollback after storing the seed.");
            Ok(())
        }
        [_, command, version, platform, channel, commit, archive, notes]
            if command == "sign" => {
            let archive = Path::new(archive);
            let file_name = archive.file_name().and_then(|n| n.to_str())
                .ok_or("archive must have a UTF-8 basename")?;
            let metadata = Metadata {
                version: version.parse().map_err(|_| "invalid version")?,
                platform: platform.to_string(), channel: channel.to_string(),
                source_commit: commit.to_string(), file_name: file_name.to_string(),
                sha256: file_hash(archive).map_err(|e| e.to_string())?,
                whats_new: std::fs::read_to_string(notes).map_err(|e| e.to_string())?,
            };
            metadata.signing_bytes().map_err(|e| e.to_string())?;
            eprint!("Paste release seed (64 hex characters), then press Enter: ");
            io::stderr().flush().map_err(|e| e.to_string())?;
            let echo = HiddenEcho::for_stdin()?;
            let seed = seed_from_stdin(&mut io::stdin().lock())?;
            drop(echo);
            eprintln!("Release public key: {}", hex(&SigningKey::from_seed(&seed).public()));
            let release = sign(&seed, metadata)?;
            println!("{}", serde_json::to_string_pretty(&release).map_err(|e| e.to_string())?);
            Ok(())
        }
        _ => Err("usage: release-sign generate | sign VERSION PLATFORM CHANNEL SOURCE_COMMIT ARCHIVE NOTES_FILE (seed via stdin; signed JSON to stdout)".into()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bh_release::{VerifyFor, check_available};

    #[test]
    fn fixture_signer_matches_release_verifier_and_rejects_bad_input() {
        let mut input = io::Cursor::new(format!("{}\n", "2a".repeat(32)));
        let seed = seed_from_stdin(&mut input).unwrap();
        let key = SigningKey::from_seed(&seed);
        let metadata = Metadata {
            version: 43,
            platform: "macos-aarch64".into(),
            channel: "stable".into(),
            source_commit: "a".repeat(40),
            file_name: "BaseHero.app.tar.gz".into(),
            sha256: hex(&bh_crypto::sha256(b"fixture")),
            whats_new: "Notes <script>".into(),
        };
        let release = sign(&seed, metadata).unwrap();
        let available = check_available(
            &release,
            VerifyFor {
                release_key: &key.public(),
                platform: "macos-aarch64",
                channel: "stable",
                running_version: 42,
            },
        )
        .unwrap();
        assert_eq!(available.whats_new(), "Notes <script>");
        assert_eq!(available.version(), 43);
        assert!(available.verify_staged(&b"corrupt"[..]).is_err());
        assert!(seed_from_stdin(&mut io::Cursor::new(b"abcd\n")).is_err());
    }
}
