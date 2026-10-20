//! Disposable operator keys and signed measured checker policy. No synthetic evidence.
//! Usage:
//!   hardware_keys init DIR MEASUREMENTS_JSON ISSUED_AT EXPIRES_AT --max-lifetime SECS
//!       --build COMPOSE_SHA256 [--build ...] --machine PPID_SHA256 [--machine ...]
//!   hardware_keys renew DIR MEASUREMENTS_JSON ISSUED_AT EXPIRES_AT --endpoint ENDPOINT_FILE
//!       --build COMPOSE_SHA256 [--build ...] --machine PPID_SHA256 [--machine ...]
//! Every listed build shares the measured boot registers of MEASUREMENTS_JSON (one image
//! and instance type). A renewal is the next generation under the same app root, issued
//! after the previous one; it may follow a lapse, add builds or withdraw them.
use bh_confidential_policy::{Build, Limits, Policy, Role};
use bh_crypto::{Secret, SigningKey};
use std::{fs, io::Write, path::Path};

fn fixed_hex<const N: usize>(text: &str) -> Result<[u8; N], String> {
    hex::decode(text)
        .map_err(|_| "invalid hex".to_string())?
        .try_into()
        .map_err(|_| "wrong measurement width".to_string())
}
fn put(dir: &Path, name: &str, value: &[u8]) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(dir.join(name))
        .map_err(|_| "refusing existing output".to_string())?;
    file.write_all(value)
        .map_err(|_| "write failed".to_string())?;
    file.sync_all().map_err(|_| "sync failed".to_string())
}
fn signing_key(dir: &Path, name: &str) -> Result<SigningKey, String> {
    let seed: [u8; 32] = bh_crypto::random();
    put(dir, name, hex::encode(seed).as_bytes())?;
    Ok(SigningKey::from_seed(
        &Secret::from_slice(&seed).map_err(|_| "seed".to_string())?,
    ))
}

/// What a generation lists; boot registers come only from the reproduced replay.
struct Allow<'a> {
    measurements: &'a Path,
    builds: &'a [String],
    machines: &'a [String],
}
fn policy(
    allow: &Allow,
    issued: u64,
    expires: u64,
    lifetime: u64,
    generation: u64,
) -> Result<Policy, String> {
    if allow.builds.is_empty() || allow.machines.is_empty() {
        return Err("at least one build and machine".into());
    }
    let raw: serde_json::Value = serde_json::from_slice(
        &fs::read(allow.measurements).map_err(|_| "measurements".to_string())?,
    )
    .map_err(|_| "measurements JSON".to_string())?;
    let measurements = &raw["tdx.small"];
    let mut boot = [vec![], vec![], vec![], vec![]];
    for (item, name) in boot.iter_mut().zip(["mrtd", "rtmr0", "rtmr1", "rtmr2"]) {
        *item =
            fixed_hex::<48>(measurements[name].as_str().ok_or("missing boot register")?)?.to_vec();
    }
    let mut builds = vec![];
    for compose in allow.builds {
        let build = Build {
            role: Role::Checker,
            compose_sha256: fixed_hex::<32>(compose)?,
            boot: boot.clone(),
        };
        if builds.contains(&build) {
            return Err("duplicate build".into());
        }
        builds.push(build);
    }
    let mut machines = vec![];
    for machine in allow.machines {
        let machine = fixed_hex::<32>(machine)?;
        if machines.contains(&machine) {
            return Err("duplicate machine".into());
        }
        machines.push(machine);
    }
    let policy = Policy {
        version: 1,
        generation,
        issued_at: issued,
        expires_at: expires,
        builds,
        machines,
    };
    // The same structural rule the app applies with the endpoint's lifetime cap.
    policy
        .validate_structure(Limits {
            max_lifetime_secs: lifetime,
            max_uncertainty_secs: 0,
        })
        .map_err(|_| "policy lifetime or measurements".to_string())?;
    Ok(policy)
}
fn sign(app: &SigningKey, payload: &[u8]) -> Result<String, String> {
    Ok(hex::encode(
        app.sign(
            &bh_confidential_policy::signing_message(payload)
                .map_err(|_| "policy too large".to_string())?,
        ),
    ))
}
fn generate(
    dir: &Path,
    allow: &Allow,
    issued: u64,
    expires: u64,
    lifetime: u64,
) -> Result<(), String> {
    let payload = serde_json::to_vec(&policy(allow, issued, expires, lifetime, 1)?)
        .map_err(|_| "policy JSON".to_string())?;
    // Create a new private directory, never overwrite a prior root, seed, or policy.
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|_| "output directory must not exist".to_string())?;
    let hosting = signing_key(dir, "hosting-root.seed")?;
    put(
        dir,
        "hosting-root.pub",
        hex::encode(hosting.public()).as_bytes(),
    )?;
    let receipt = signing_key(dir, "receipt.seed")?;
    put(
        dir,
        "receipt.cert",
        hex::encode(bh_sync::receipt::certify(&hosting, receipt.public())).as_bytes(),
    )?;
    let permit = signing_key(dir, "permit.seed")?;
    put(
        dir,
        "permit.cert",
        hex::encode(bh_sync::permit::certify(&hosting, permit.public())).as_bytes(),
    )?;
    let app = signing_key(dir, "app-root.seed")?;
    put(dir, "app-root.pub", hex::encode(app.public()).as_bytes())?;
    put(dir, "policy.json", &payload)?;
    put(dir, "policy.sig", sign(&app, &payload)?.as_bytes())
}
/// The endpoint's own app root and lifetime cap, so a renewal is one the app accepts.
fn endpoint_lifetime(dir: &Path, endpoint: &Path) -> Result<u64, String> {
    let value: serde_json::Value =
        serde_json::from_slice(&fs::read(endpoint).map_err(|_| "endpoint".to_string())?)
            .map_err(|_| "endpoint JSON".to_string())?;
    let root = fs::read_to_string(dir.join("app-root.pub")).map_err(|_| "app root".to_string())?;
    if value["app_root"].as_str() != Some(root.as_str()) {
        return Err("endpoint app root differs".into());
    }
    value["max_lifetime_secs"]
        .as_u64()
        .ok_or("endpoint lifetime".into())
}
fn renew(
    dir: &Path,
    allow: &Allow,
    issued: u64,
    expires: u64,
    endpoint: &Path,
) -> Result<u64, String> {
    let lifetime = endpoint_lifetime(dir, endpoint)?;
    let prior = fs::read_dir(dir)
        .map_err(|_| "keys directory".to_string())?
        .filter_map(|entry| {
            entry.ok().and_then(|item| {
                item.file_name().to_str().and_then(|s| {
                    s.strip_prefix("policy-gen-")?
                        .strip_suffix(".json")?
                        .parse::<u64>()
                        .ok()
                })
            })
        })
        .max()
        .unwrap_or(1);
    let previous = if prior == 1 {
        dir.join("policy.json")
    } else {
        dir.join(format!("policy-gen-{prior}.json"))
    };
    let last: Policy =
        serde_json::from_slice(&fs::read(previous).map_err(|_| "previous policy".to_string())?)
            .map_err(|_| "previous policy".to_string())?;
    // Only ordering is required: a lapsed policy may be renewed under the same root.
    if last.generation != prior || issued <= last.issued_at {
        return Err("not a sequential policy renewal".into());
    }
    let generation = prior.checked_add(1).ok_or("generation exhausted")?;
    let payload = serde_json::to_vec(&policy(allow, issued, expires, lifetime, generation)?)
        .map_err(|_| "policy JSON".to_string())?;
    let seed = fixed_hex::<32>(
        &fs::read_to_string(dir.join("app-root.seed")).map_err(|_| "app seed".to_string())?,
    )?;
    let app = SigningKey::from_seed(&Secret::from_slice(&seed).map_err(|_| "seed".to_string())?);
    if fs::read_to_string(dir.join("app-root.pub")).map_err(|_| "app root".to_string())?
        != hex::encode(app.public())
    {
        return Err("app root mismatch".into());
    }
    let signature = sign(&app, &payload)?;
    let name = format!("policy-gen-{generation}");
    // The payload first: an interrupted write leaves an unsigned generation that the
    // next renewal steps past, never a signature without its bytes.
    put(dir, &format!("{name}.json"), &payload)?;
    put(dir, &format!("{name}.sig"), signature.as_bytes())?;
    Ok(generation)
}
struct Args {
    renew: bool,
    dir: String,
    measurements: String,
    issued: u64,
    expires: u64,
    lifetime: Option<u64>,
    endpoint: Option<String>,
    builds: Vec<String>,
    machines: Vec<String>,
}
fn parse(args: &[String]) -> Result<Args, String> {
    let (renew, rest) = match args.first().map(String::as_str) {
        Some("init") => (false, &args[1..]),
        Some("renew") => (true, &args[1..]),
        _ => return Err("init or renew".into()),
    };
    let [dir, measurements, issued, expires, options @ ..] = rest else {
        return Err("missing arguments".into());
    };
    let mut parsed = Args {
        renew,
        dir: dir.clone(),
        measurements: measurements.clone(),
        issued: issued.parse().map_err(|_| "invalid issued_at")?,
        expires: expires.parse().map_err(|_| "invalid expires_at")?,
        lifetime: None,
        endpoint: None,
        builds: vec![],
        machines: vec![],
    };
    let mut options = options.iter();
    while let Some(flag) = options.next() {
        let value = options.next().ok_or("option value")?.clone();
        match flag.as_str() {
            "--build" => parsed.builds.push(value),
            "--machine" => parsed.machines.push(value),
            "--max-lifetime" if !renew && parsed.lifetime.is_none() => {
                parsed.lifetime = Some(value.parse().map_err(|_| "invalid lifetime")?)
            }
            "--endpoint" if renew && parsed.endpoint.is_none() => parsed.endpoint = Some(value),
            _ => return Err("unknown option".into()),
        }
    }
    if renew != parsed.endpoint.is_some() || renew == parsed.lifetime.is_some() {
        return Err("init needs --max-lifetime; renew needs --endpoint".into());
    }
    Ok(parsed)
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = parse(&args).and_then(|a| {
        let allow = Allow {
            measurements: Path::new(&a.measurements),
            builds: &a.builds,
            machines: &a.machines,
        };
        let dir = Path::new(&a.dir);
        match (a.renew, a.lifetime, a.endpoint.as_deref()) {
            (false, Some(lifetime), _) => generate(dir, &allow, a.issued, a.expires, lifetime),
            (true, _, Some(endpoint)) => {
                renew(dir, &allow, a.issued, a.expires, Path::new(endpoint)).map(|_| ())
            }
            _ => Err("init needs --max-lifetime; renew needs --endpoint".into()),
        }
    });
    if let Err(reason) = result {
        // Fixed strings only: never seeds, paths or file contents.
        eprintln!("hardware keys refused: {reason}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }
    fn measurements(t: &Path) -> std::path::PathBuf {
        let path = t.join("measurements.json");
        fs::write(
            &path,
            serde_json::json!({"tdx.small": {
            "mrtd": "ab".repeat(48), "rtmr0": "bc".repeat(48), "rtmr1": "cd".repeat(48),
            "rtmr2": "de".repeat(48)}})
            .to_string(),
        )
        .unwrap();
        path
    }
    fn endpoint(dir: &Path, lifetime: u64) -> std::path::PathBuf {
        let path = dir
            .parent()
            .unwrap()
            .join(format!("endpoint-{lifetime}.json"));
        let root = fs::read_to_string(dir.join("app-root.pub")).unwrap();
        fs::write(
            &path,
            serde_json::json!({"app_root": root, "max_lifetime_secs": lifetime}).to_string(),
        )
        .unwrap();
        path
    }
    fn signed(dir: &Path, name: &str) -> Policy {
        let payload = fs::read(dir.join(format!("{name}.json"))).unwrap();
        let sig: [u8; 64] =
            hex::decode(fs::read_to_string(dir.join(format!("{name}.sig"))).unwrap())
                .unwrap()
                .try_into()
                .unwrap();
        let root: [u8; 32] = hex::decode(fs::read_to_string(dir.join("app-root.pub")).unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        bh_crypto::verify(
            &root,
            &bh_confidential_policy::signing_message(&payload).unwrap(),
            &sig,
        )
        .unwrap();
        serde_json::from_slice(&payload).unwrap()
    }
    #[test]
    fn writes_private_keys_and_signed_real_measurements_without_overwrite() {
        let t = tempfile::tempdir().unwrap();
        let m = measurements(t.path());
        let dir = t.path().join("keys");
        let (builds, machines) = (strings(&[&"ef".repeat(32)]), strings(&[&"23".repeat(32)]));
        let allow = Allow {
            measurements: &m,
            builds: &builds,
            machines: &machines,
        };
        generate(&dir, &allow, 1000, 2000, 86_400).unwrap();
        let parsed = signed(&dir, "policy");
        assert_eq!(parsed.builds[0].boot[0], vec![0xab; 48]);
        assert_eq!(parsed.builds[0].compose_sha256, [0xef; 32]);
        assert_eq!(parsed.machines, vec![[0x23; 32]]);
        assert_eq!(parsed.generation, 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&dir.join("app-root.seed")), 0o600);
            assert_eq!(mode(&dir), 0o700);
        }
        assert!(generate(&dir, &allow, 1000, 2000, 86_400).is_err());
        // Lifetime beyond the endpoint cap is refused before anything is written.
        assert!(generate(&t.path().join("long"), &allow, 1000, 90_000, 86_400).is_err());
        assert!(!t.path().join("long").exists());
    }
    #[test]
    fn renewals_list_several_builds_withdraw_one_and_may_follow_a_lapse() {
        let t = tempfile::tempdir().unwrap();
        let m = measurements(t.path());
        let dir = t.path().join("keys");
        let (old, new, machine) = ("e1".repeat(32), "e2".repeat(32), "23".repeat(32));
        let one = |builds: &[&str]| (strings(builds), strings(&[&machine]));
        let (b1, ms) = one(&[&old]);
        generate(
            &dir,
            &Allow {
                measurements: &m,
                builds: &b1,
                machines: &ms,
            },
            1000,
            1000 + 8 * 86_400,
            8 * 86_400,
        )
        .unwrap();
        let app_seed = fs::read(dir.join("app-root.seed")).unwrap();
        let ep = endpoint(&dir, 8 * 86_400);
        let (both, ms) = one(&[&old, &new]);
        let allow = Allow {
            measurements: &m,
            builds: &both,
            machines: &ms,
        };
        // gen-2 lists both builds, issued long after gen-1 lapsed.
        let lapsed = 1000 + 9 * 86_400;
        assert_eq!(
            renew(&dir, &allow, lapsed, lapsed + 86_400, &ep).unwrap(),
            2
        );
        let second = signed(&dir, "policy-gen-2");
        assert_eq!(second.builds.len(), 2);
        assert_eq!(fs::read(dir.join("app-root.seed")).unwrap(), app_seed);
        // gen-3 withdraws the old build.
        let (only_new, ms) = one(&[&new]);
        let allow = Allow {
            measurements: &m,
            builds: &only_new,
            machines: &ms,
        };
        assert_eq!(
            renew(&dir, &allow, lapsed + 10, lapsed + 20, &ep).unwrap(),
            3
        );
        let third = signed(&dir, "policy-gen-3");
        assert_eq!(third.builds.len(), 1);
        assert_eq!(third.builds[0].compose_sha256, [0xe2; 32]);
        // Not issued after the previous generation; beyond the endpoint cap; another root.
        assert!(renew(&dir, &allow, lapsed + 10, lapsed + 30, &ep).is_err());
        assert!(renew(&dir, &allow, lapsed + 40, lapsed + 40 + 9 * 86_400, &ep).is_err());
        let other = t.path().join("other.json");
        fs::write(
            &other,
            serde_json::json!({"app_root": "00".repeat(32), "max_lifetime_secs": 86_400})
                .to_string(),
        )
        .unwrap();
        assert!(renew(&dir, &allow, lapsed + 50, lapsed + 60, &other).is_err());
        assert!(!dir.join("policy-gen-4.json").exists());
    }
    #[test]
    fn an_unsigned_leftover_generation_is_stepped_past() {
        let t = tempfile::tempdir().unwrap();
        let m = measurements(t.path());
        let dir = t.path().join("keys");
        let (b, ms) = (strings(&[&"e1".repeat(32)]), strings(&[&"23".repeat(32)]));
        let allow = Allow {
            measurements: &m,
            builds: &b,
            machines: &ms,
        };
        generate(&dir, &allow, 1000, 2000, 86_400).unwrap();
        let ep = endpoint(&dir, 86_400);
        // As if the signature write had failed after the payload write.
        let mut orphan = signed(&dir, "policy");
        orphan.generation = 2;
        orphan.issued_at = 1100;
        fs::write(
            dir.join("policy-gen-2.json"),
            serde_json::to_vec(&orphan).unwrap(),
        )
        .unwrap();
        assert_eq!(renew(&dir, &allow, 1200, 2200, &ep).unwrap(), 3);
        signed(&dir, "policy-gen-3");
    }
    #[test]
    fn arguments_need_builds_machines_and_the_right_lifetime_source() {
        let ok = |s: &str| parse(&strings(&s.split(' ').collect::<Vec<_>>()));
        assert!(ok("init d m 1 2 --max-lifetime 9 --build a --build b --machine c").is_ok());
        assert!(ok("renew d m 1 2 --endpoint e --build a --machine c").is_ok());
        assert!(ok("init d m 1 2 --endpoint e --build a --machine c").is_err());
        assert!(ok("renew d m 1 2 --max-lifetime 9 --build a --machine c").is_err());
        assert!(ok("d m c p 1 2").is_err());
        let t = tempfile::tempdir().unwrap();
        let m = measurements(t.path());
        let none: Vec<String> = vec![];
        let machines = strings(&[&"23".repeat(32)]);
        let allow = Allow {
            measurements: &m,
            builds: &none,
            machines: &machines,
        };
        assert!(policy(&allow, 1, 2, 10, 1).is_err());
    }
}
