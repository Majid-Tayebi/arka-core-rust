//! Vault-wide security posture metrics derived from decrypted entries.
//!
//! Runs entirely in memory on cleartext already held by an unlocked session —
//! no additional disk I/O and no persistence of audited secrets.

use std::collections::HashMap;

use crate::api::generator::entropy_bits;
use crate::api::vault::DecryptedPasswordEntry;

/// Entropy threshold (bits) below which a password is flagged as weak.
const WEAK_ENTROPY_BITS: f64 = 60.0;

/// Common substrings that indicate human-chosen, low-quality passwords.
const WEAK_SUBSTRINGS: &[&str] = &["123", "password", "admin"];

/// Aggregate security findings for a decrypted vault snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSecurityReport {
    /// Passwords whose estimated entropy is below [`WEAK_ENTROPY_BITS`].
    pub weak_passwords_count: u32,
    /// Entries whose password value is shared by more than one account.
    pub reused_passwords_count: u32,
    /// Composite score from 0 (critical) to 100 (excellent).
    pub total_score: u32,
}

/// Scans `entries` once, counting weak and reused passwords via [`HashMap`].
pub fn analyze_vault_security(entries: Vec<DecryptedPasswordEntry>) -> VaultSecurityReport {
    let total = entries.len();
    if total == 0 {
        return VaultSecurityReport {
            weak_passwords_count: 0,
            reused_passwords_count: 0,
            total_score: 100,
        };
    }

    let mut weak_passwords_count = 0u32;
    let mut password_counts: HashMap<&str, u32> = HashMap::with_capacity(total);

    for entry in &entries {
        if is_weak_password(&entry.password) {
            weak_passwords_count += 1;
        }
        *password_counts
            .entry(entry.password.as_str())
            .or_insert(0) += 1;
    }

    let reused_passwords_count = password_counts
        .values()
        .filter(|&&count| count > 1)
        .copied()
        .sum();

    let total_score = compute_total_score(total as u32, weak_passwords_count, reused_passwords_count);

    VaultSecurityReport {
        weak_passwords_count,
        reused_passwords_count,
        total_score,
    }
}

/// Flags low-entropy passwords and those with obvious human patterns.
fn is_weak_password(password: &str) -> bool {
    if entropy_bits(password) < WEAK_ENTROPY_BITS {
        return true;
    }

    if contains_weak_substring(password) || has_consecutive_run(password) {
        return true;
    }

    false
}

fn contains_weak_substring(password: &str) -> bool {
    let lower = password.to_lowercase();
    WEAK_SUBSTRINGS.iter().any(|pattern| lower.contains(pattern))
}

/// Detects three or more identical consecutive characters (`aaa`, `111`, …).
fn has_consecutive_run(password: &str) -> bool {
    let mut prev: Option<char> = None;
    let mut run = 0usize;

    for ch in password.chars() {
        if Some(ch) == prev {
            run += 1;
            if run >= 3 {
                return true;
            }
        } else {
            prev = Some(ch);
            run = 1;
        }
    }

    false
}

/// Penalizes weak and reused fractions equally — both dominate real-world breach risk.
fn compute_total_score(total: u32, weak: u32, reused: u32) -> u32 {
    let n = total as f64;
    let weak_fraction = weak as f64 / n;
    let reused_fraction = reused as f64 / n;
    let raw = 100.0 * (1.0 - weak_fraction * 0.55 - reused_fraction * 0.55);
    raw.clamp(0.0, 100.0).round() as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::vault::DecryptedPasswordEntry;
    use zeroize::Zeroizing;

    fn entry(id: i64, password: &str) -> DecryptedPasswordEntry {
        DecryptedPasswordEntry {
            id,
            title: format!("Site-{id}"),
            username: "user".into(),
            category: String::new(),
            password: Zeroizing::new(password.into()),
            website_url: String::new(),
            note: String::new(),
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn empty_vault_scores_perfect() {
        let report = analyze_vault_security(vec![]);
        assert_eq!(report.total_score, 100);
        assert_eq!(report.weak_passwords_count, 0);
        assert_eq!(report.reused_passwords_count, 0);
    }

    #[test]
    fn detects_weak_and_reused_passwords() {
        let strong = "Zx9!mK2$pL7@nQ4#wR8%tY6&uI3*oP1";
        let entries = vec![
            entry(1, "abc"),
            entry(2, "abc"),
            entry(3, strong),
        ];

        let report = analyze_vault_security(entries);
        assert_eq!(report.weak_passwords_count, 2);
        assert_eq!(report.reused_passwords_count, 2);
        assert!(report.total_score < 100);
    }

    #[test]
    fn strong_unique_vault_scores_high() {
        let entries = vec![
            entry(1, "Zx9!mK2$pL7@nQ4#wR8%tY6&uI3*oP1"),
            entry(2, "Aa1!Bb2@Cc3#Dd4$Ee5%Ff6^Gg7&Hh8"),
        ];

        let report = analyze_vault_security(entries);
        assert_eq!(report.weak_passwords_count, 0);
        assert_eq!(report.reused_passwords_count, 0);
        assert_eq!(report.total_score, 100);
    }

    #[test]
    fn flags_dictionary_like_password_despite_charset_mix() {
        let entries = vec![entry(1, "Admin123!@#")];

        let report = analyze_vault_security(entries);
        assert_eq!(report.weak_passwords_count, 1);
        assert!(report.total_score < 100);
    }

    #[test]
    fn flags_consecutive_runs_despite_charset_mix() {
        let entries = vec![entry(1, "Aa1!bbb@Xy9")];

        let report = analyze_vault_security(entries);
        assert_eq!(report.weak_passwords_count, 1);
    }
}
