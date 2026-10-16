//! Mac first-account password suggestion and approximate custom-guess check.
//! Five words sampled independently and uniformly from EFF's 7776-word long
//! list yield about 64.6 bits of entropy, above the ~10^10 guess floor. No arbitrary
//! capitalization, symbol or character-class rule applies to a custom password.
use bh_account::crypto;

static WORDS: std::sync::LazyLock<Vec<&'static str>> = std::sync::LazyLock::new(|| {
    let words: Vec<_> = include_str!("eff_large_wordlist.txt")
        .lines()
        .map(|line| line.split_once('\t').expect("EFF diceword and word").1)
        .collect();
    assert_eq!(words.len(), 7776);
    words
});

pub fn suggest() -> String {
    (0..5)
        .map(|_| {
            // Reject the incomplete last bucket; modulo is uniform over 7776
            // when the accepted range is exactly eight complete buckets.
            loop {
                let random: [u8; 2] = crypto::random();
                let sample = u16::from_le_bytes(random);
                if sample < 8 * 7776 {
                    break WORDS[usize::from(sample % 7776)];
                }
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn acceptable(password: &str) -> bool {
    !password.is_empty()
        && password.len() <= 1024
        && zxcvbn::zxcvbn(
            password,
            &["basehero", "base", "hero", "correct horse battery staple"],
        )
        .guesses()
            >= 10_000_000_000
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn passphrase_has_five_independent_uniform_words_above_guess_floor() {
        use std::collections::HashSet;
        assert_eq!(WORDS.len(), 7776);
        assert_eq!(WORDS.iter().collect::<HashSet<_>>().len(), 7776);
        assert!(7776u128.pow(5) > 10_000_000_000);
        for _ in 0..100 {
            let phrase = suggest();
            let words: Vec<_> = phrase.split(' ').collect();
            assert_eq!(words.len(), 5);
            assert!(words.iter().all(|word| WORDS.contains(word)));
            assert!(
                acceptable(&phrase),
                "the app must accept its own suggestion"
            );
        }
    }
    #[test]
    fn custom_password_uses_guess_estimate_not_punctuation_rules() {
        assert!(!acceptable("BaseHero2026!"));
        assert!(!acceptable("password12345"));
        assert!(!acceptable("correct horse battery staple"));
        assert!(acceptable("ripple amber horizon nectar willow"));
        assert!(acceptable("D4$fj@cH2rM!Xk9p"));
        assert!(!acceptable(""));
    }
}
