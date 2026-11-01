//! Keystore password generation and strength feedback.
//!
//! This exists because neither `keytool` nor the OpenSSL CLI nor (until
//! recently) KeyStore Explorer ever stopped a user from protecting a
//! private key with `"changeit"` or `"password123"`. A PKCS#12/JKS export
//! is only as strong as the password on it, so the wizard surfaces
//! strength feedback instead of accepting anything silently.

use zxcvbn::Score;

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";

/// Generate a random password suitable for protecting a PKCS#12/JKS file.
/// Pure Rust, uses the OS CSPRNG (see `keys.rs` for the same pattern).
pub fn generate(length: usize) -> String {
    let length = length.max(12);
    (0..length)
        .map(|_| CHARSET[rand::random_range(0..CHARSET.len())] as char)
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    VeryWeak,
    Weak,
    Fair,
    Strong,
    VeryStrong,
}

impl Strength {
    pub fn label(&self) -> &'static str {
        match self {
            Strength::VeryWeak => "Very weak",
            Strength::Weak => "Weak",
            Strength::Fair => "Fair",
            Strength::Strong => "Strong",
            Strength::VeryStrong => "Very strong",
        }
    }

    /// Below this, the wizard should warn (not block — it's the user's
    /// file) before letting the export proceed.
    pub fn is_acceptable(&self) -> bool {
        *self >= Strength::Fair
    }
}

pub struct Assessment {
    pub strength: Strength,
    /// Plain-language suggestions zxcvbn produced, if any.
    pub suggestions: Vec<String>,
}

/// Score a candidate password. `context` is extra strings (the alias,
/// subject CN, etc.) that would make an otherwise-OK-looking password
/// trivially guessable in this specific keystore.
pub fn assess(password: &str, context: &[&str]) -> Assessment {
    let entropy = zxcvbn::zxcvbn(password, context);
    let strength = match entropy.score() {
        Score::Zero => Strength::VeryWeak,
        Score::One => Strength::Weak,
        Score::Two => Strength::Fair,
        Score::Three => Strength::Strong,
        Score::Four => Strength::VeryStrong,
        _ => Strength::VeryWeak,
    };
    let suggestions = entropy
        .feedback()
        .map(|f| f.suggestions().iter().map(|s| s.to_string()).collect())
        .unwrap_or_default();
    Assessment { strength, suggestions }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_passwords_are_long_and_varied() {
        let a = generate(20);
        let b = generate(20);
        assert_eq!(a.len(), 20);
        assert_ne!(a, b, "two generated passwords collided, RNG is broken");
        assert!(a.chars().all(|c| CHARSET.contains(&(c as u8))));
    }

    #[test]
    fn obviously_weak_passwords_score_low() {
        assert!(!assess("password", &[]).strength.is_acceptable());
        assert!(!assess("changeit", &[]).strength.is_acceptable());
    }

    #[test]
    fn a_long_random_password_scores_well() {
        let pw = generate(24);
        assert!(assess(&pw, &[]).strength.is_acceptable());
    }

    #[test]
    fn context_words_make_a_password_weaker() {
        let weak_in_context = assess("MyCompanyName2024", &["MyCompanyName"]);
        assert!(!weak_in_context.strength.is_acceptable());
    }
}
