//! Coaching for extra passwords, without imposing a minimum.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// Estimated strength and practical feedback; no minimum is enforced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "apps/basehero/src/lib/generated/")]
pub struct PasswordStrength {
    /// zxcvbn's score from 0 to 4.
    pub score: u8,
    /// Whether the guess estimate reaches 10^10.
    pub strong: bool,
    /// A reason the password may be easy to guess.
    pub warning: Option<String>,
    /// Ways to strengthen the password.
    pub suggestions: Vec<String>,
}

/// Estimates strength with BaseHero and caller context, without rejecting passwords.
pub fn password_strength(password: &str, context: &[&str]) -> PasswordStrength {
    let mut inputs = Vec::with_capacity(context.len() + 1);
    inputs.push("basehero");
    inputs.extend_from_slice(context);
    let estimate = zxcvbn::zxcvbn(password, &inputs);
    let feedback = estimate.feedback();
    PasswordStrength {
        score: estimate.score() as u8,
        strong: estimate.guesses() >= 10_000_000_000,
        warning: feedback.and_then(|f| f.warning()).map(|w| w.to_string()),
        suggestions: feedback.map_or_else(Vec::new, |f| {
            f.suggestions().iter().map(ToString::to_string).collect()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strength_coaches_without_refusing() {
        let weak = password_strength("password123", &[]);
        assert!(weak.score <= 1 && !weak.strong && weak.warning.is_some());
        assert!(password_strength("ripple amber horizon nectar willow", &[]).strong);
        assert!(!password_strength("zebra diary", &["Zebra Diary"]).strong);
    }

    #[test]
    fn context_and_empty_password_get_coaching() {
        let context = password_strength("Zebra Diary", &["Zebra Diary"]);
        assert!(!context.strong);
        assert!(!password_strength("", &[]).strong);
    }
}
