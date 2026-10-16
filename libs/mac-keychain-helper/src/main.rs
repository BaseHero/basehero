//! BaseHero's Keychain helper. It runs only as the app's child, checks that
//! its parent is BaseHero, then answers protocol requests on stdin/stdout.
//! Its bytes are meant to stay identical across app releases, so the
//! Keychain's per-code partition keeps naming it after an update.
#[cfg(target_os = "macos")]
mod caller;
#[cfg(target_os = "macos")]
mod keychain;

use std::process::ExitCode;

/// The bundle identifier the parent must carry; also the service prefix.
const APP_IDENTIFIER: &str = match option_env!("BH_APP_IDENTIFIER") {
    Some(identifier) => identifier,
    None => "app.basehero.client",
};
/// SHA-1 of the app-signing certificate. Without it every caller is refused.
const CALLER_ROOT: Option<&str> = option_env!("BH_KEYCHAIN_CALLER_ROOT");

const USAGE: u8 = 2;
const REFUSED: u8 = 3;
const PROTOCOL: u8 = 4;
const KEYCHAIN: u8 = 5;

// The same reverse-DNS shape the packager accepts, so it can't break out of
// the requirement's quotes.
fn is_bundle_identifier(text: &str) -> bool {
    let mut labels = 0;
    for label in text.split('.') {
        let mut chars = label.chars();
        if !chars.next().is_some_and(|c| c.is_ascii_lowercase())
            || !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return false;
        }
        labels += 1;
    }
    labels >= 2
}

/// The designated requirement a trusted parent satisfies, or `None` when the
/// build configuration is unusable.
fn caller_requirement(identifier: &str, root: Option<&str>) -> Option<String> {
    let root = root
        .filter(|r| r.len() == 40 && r.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))?;
    is_bundle_identifier(identifier)
        .then(|| format!(r#"identifier "{identifier}" and certificate root = H"{root}""#))
}

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    let _ = (
        APP_IDENTIFIER,
        CALLER_ROOT,
        caller_requirement,
        USAGE,
        PROTOCOL,
        KEYCHAIN,
    );
    ExitCode::from(REFUSED)
}

/// Exits 0 when the app closes the pipe. Every refusal happens before stdin is read.
#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    let Some(requirement) = caller_requirement(APP_IDENTIFIER, CALLER_ROOT) else {
        return ExitCode::from(REFUSED);
    };
    if !caller::parent_satisfies(&requirement) {
        return ExitCode::from(REFUSED);
    }
    // `--keychain-file <path>` pins one keychain file and turns prompts into
    // errors, for headless checks. The app passes no arguments.
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let file = match args.as_slice() {
        [] => None,
        [flag, path] if flag == "--keychain-file" => Some(std::path::Path::new(path)),
        _ => return ExitCode::from(USAGE),
    };
    let Ok(mut store) = keychain::Keychain::open(APP_IDENTIFIER, file) else {
        return ExitCode::from(KEYCHAIN);
    };
    match bh_mac_keychain_helper::serve(
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        &mut store,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(PROTOCOL),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: &str = "0ce10d31b5a12378c8bb85527be3a8e0a5a52ea7";

    #[test]
    fn the_parent_must_be_this_bundle_signed_by_our_certificate() {
        assert_eq!(
            caller_requirement("app.basehero.client", Some(ROOT)).as_deref(),
            Some(
                r#"identifier "app.basehero.client" and certificate root = H"0ce10d31b5a12378c8bb85527be3a8e0a5a52ea7""#
            )
        );
        assert_eq!(
            caller_requirement("app.basehero.client.updatedemo", Some(ROOT)).as_deref(),
            Some(
                r#"identifier "app.basehero.client.updatedemo" and certificate root = H"0ce10d31b5a12378c8bb85527be3a8e0a5a52ea7""#
            )
        );
    }

    #[test]
    fn an_unusable_configuration_refuses_every_caller() {
        assert_eq!(caller_requirement("app.basehero.client", None), None);
        for root in [
            "",
            "0ce1",
            &ROOT.to_uppercase(),
            &format!("{ROOT}0"),
            "0ce10d31b5a12378c8bb85527be3a8e0a5a52eaz",
        ] {
            assert_eq!(
                caller_requirement("app.basehero.client", Some(root)),
                None,
                "{root}"
            );
        }
        for identifier in [
            "",
            "basehero",
            "app.basehero.\"x",
            "App.BaseHero",
            "app..basehero",
            "app.basehero client",
        ] {
            assert_eq!(
                caller_requirement(identifier, Some(ROOT)),
                None,
                "{identifier}"
            );
        }
    }
}
