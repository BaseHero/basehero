//! One qualified Roughtime sample from two pinned servers: trusted time bounds for an
//! operator check such as hardware_probe. Same sampler and arithmetic as the service.
//! Usage: roughtime_sample --execute IP:PORT KEY_HEX IP:PORT KEY_HEX HZ DRIFT_PPM SMEAR_US MAX_AGE_TICKS MAX_WIDTH_MS
//! The five numbers are the service's time configuration. Prints POSIX-second bounds
//! rounded outward, as the attestation verifier takes them.
use bh_confidential_host::TimeSampler;
use bh_qualified_time::{Config, Counter, ServerRoot};
use std::{net::SocketAddr, time::Duration, time::Instant};

struct Monotonic(Instant);
impl Counter for Monotonic {
    fn ticks(&self) -> u64 {
        u64::try_from(self.0.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}

fn parse(args: &[String]) -> Result<([(SocketAddr, ServerRoot); 2], Config), String> {
    let [mode, a, ka, b, kb, numbers @ ..] = args else {
        return Err("expected --execute, two IP:PORT KEY_HEX pins and five numbers".into());
    };
    if mode != "--execute" {
        return Err("first argument must be --execute".into());
    }
    let pin = |address: &str, key: &str| -> Result<(SocketAddr, ServerRoot), String> {
        let address: SocketAddr = address.parse().map_err(|_| "literal IP:PORT required")?;
        let key: [u8; 32] = hex::decode(key)
            .map_err(|_| "key hex")?
            .try_into()
            .map_err(|_| "key width")?;
        Ok((address, ServerRoot { key }))
    };
    let numbers: Vec<u64> = numbers
        .iter()
        .map(|n| n.parse().map_err(|_| "time configuration".to_string()))
        .collect::<Result<_, _>>()?;
    let [hz, drift, smear, age, width] = numbers[..] else {
        return Err("five time configuration numbers required".into());
    };
    if hz != 1_000_000_000 {
        return Err("this sampler counts nanoseconds: HZ must be 1000000000".into());
    }
    let config = Config {
        hz,
        drift_ppm: u32::try_from(drift).map_err(|_| "drift")?,
        smear_us: smear,
        max_age_ticks: age,
        max_width_ms: width,
    };
    Ok(([pin(a, ka)?, pin(b, kb)?], config))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = async {
        let (servers, config) = parse(&args)?;
        let counter = Monotonic(Instant::now());
        let sampler = TimeSampler::new(servers, config, Duration::from_secs(10))
            .map_err(|_| "sampler configuration".to_string())?;
        let bounds = sampler
            .refresh(&counter)
            .await
            .map_err(|_| "qualified time unavailable".to_string())?;
        let time = bounds.to_policy_time();
        Ok::<_, String>(
            serde_json::json!({"earliest": time.earliest, "latest": time.latest,
            "width_ms": bounds.latest_ms - bounds.earliest_ms}),
        )
    }
    .await;
    match result {
        Ok(value) => println!("{value}"),
        Err(reason) => {
            eprintln!("roughtime sample refused: {reason}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(s: &str) -> Vec<String> {
        s.split(' ').map(str::to_owned).collect()
    }
    #[test]
    fn needs_execute_two_literal_pins_and_the_nanosecond_service_config() {
        let key = "ab".repeat(32);
        let good = format!(
            "--execute 192.0.2.1:2002 {key} 192.0.2.2:2003 {key} 1000000000 500 1000000 600000000000 15000"
        );
        let (servers, config) = parse(&args(&good)).unwrap();
        assert_eq!(servers[1].0, "192.0.2.2:2003".parse().unwrap());
        assert_eq!((config.drift_ppm, config.max_width_ms), (500, 15000));
        for bad in [
            good.replacen("--execute", "--dry-run", 1),
            good.replacen("192.0.2.1:2002", "time.example:2002", 1),
            good.replacen(&key, "abcd", 1),
            good.replacen("1000000000", "1000", 1),
            good.replacen(" 15000", "", 1),
        ] {
            assert!(parse(&args(&bad)).is_err(), "{bad}");
        }
    }
}
