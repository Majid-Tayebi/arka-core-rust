//! Autofill candidate selection — metadata-only matching before decryption.
//!
//! `website_url` is the primary signal for browser autofill; title/username remain
//! fallbacks for legacy entries and Android package names.

use crate::api::vault::DecryptedPasswordEntry;

/// Returns vault entries whose metadata plausibly matches `origin`.
///
/// `origin` is an Android package name (`com.twitter.android`) or web host
/// (`account.proton.me`).
pub fn filter_for_origin(
    entries: Vec<DecryptedPasswordEntry>,
    origin: &str,
) -> Vec<DecryptedPasswordEntry> {
    let needles = origin_needles(origin);
    if needles.is_empty() {
        return entries;
    }

    let filtered: Vec<_> = entries
        .iter()
        .filter(|entry| entry_matches(&needles, entry))
        .cloned()
        .collect();

    if !filtered.is_empty() {
        return filtered;
    }

    // Chrome sometimes omits webDomain — surface saved web credentials instead of nothing.
    if is_browser_package(origin) {
        let web_entries: Vec<_> = entries
            .into_iter()
            .filter(|entry| !entry.website_url.trim().is_empty())
            .collect();
        if !web_entries.is_empty() {
            return web_entries;
        }
    }

    Vec::new()
}

fn is_browser_package(origin: &str) -> bool {
    matches!(
        origin.trim().to_lowercase().as_str(),
        "com.android.chrome"
            | "com.chrome.beta"
            | "com.chrome.dev"
            | "com.chrome.canary"
            | "com.google.android.apps.chrome"
            | "org.chromium.chrome"
            | "com.brave.browser"
            | "org.mozilla.firefox"
            | "com.microsoft.emmx"
            | "com.opera.browser"
            | "com.sec.android.app.sbrowser"
    )
}

fn origin_needles(origin: &str) -> Vec<String> {
    let trimmed = origin.trim().to_lowercase();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut needles = vec![trimmed.clone()];

    if trimmed.contains('.') && !trimmed.contains('/') {
        // Package name — add meaningful segments (skip `com`, `org`, …).
        let skip = ["com", "org", "net", "io", "app", "android", "mobile"];
        for segment in trimmed.split('.') {
            if segment.len() >= 3 && !skip.contains(&segment) {
                needles.push(segment.to_string());
            }
        }
    } else {
        // Web host — strip www.
        needles.push(trimmed.trim_start_matches("www.").to_string());
    }

    needles.sort();
    needles.dedup();
    needles
}

fn normalize_host(raw: &str) -> String {
    let mut host = raw.trim().to_lowercase();
    host = host
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .to_string();
    host = host.split('/').next().unwrap_or(&host).to_string();
    host = host.split(':').next().unwrap_or(&host).to_string();
    host.trim_start_matches("www.").to_string()
}

fn host_matches(needle: &str, website: &str) -> bool {
    let n = normalize_host(needle);
    let w = normalize_host(website);
    if n.is_empty() || w.is_empty() {
        return false;
    }

    if n.contains('.') {
        // Domain-style needles: exact match, subdomain of credential host, or parent credential.
        return w == n
            || w.ends_with(&format!(".{n}"))
            || n.ends_with(&format!(".{w}"));
    }

    // Single label: compare only against dot-separated host parts (blocks evil-amazon ⊃ amazon).
    w.split('.').any(|part| part == n)
}

fn entry_matches(needles: &[String], entry: &DecryptedPasswordEntry) -> bool {
    let title = entry.title.to_lowercase();
    let username = entry.username.to_lowercase();
    let website = entry.website_url.to_lowercase();

    needles.iter().any(|needle| {
        if !website.is_empty() && host_matches(needle, &website) {
            return true;
        }
        if !title.is_empty()
            && (title.contains(needle)
                || needle.contains(&title)
                || fuzzy_host_match(needle, &title))
        {
            return true;
        }
        !username.is_empty() && username.contains(needle)
    })
}

fn fuzzy_host_match(needle: &str, title: &str) -> bool {
    let host = needle.split('/').next().unwrap_or(needle);
    title.contains(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::vault::DecryptedPasswordEntry;
    use zeroize::Zeroizing;

    fn entry(title: &str, username: &str, website_url: &str) -> DecryptedPasswordEntry {
        DecryptedPasswordEntry {
            id: 1,
            title: title.into(),
            username: username.into(),
            category: String::new(),
            password: Zeroizing::new("secret".into()),
            website_url: website_url.into(),
            note: String::new(),
            created_at: 1,
            updated_at: 1,
        }
    }

    #[test]
    fn matches_package_segment() {
        let entries = vec![entry("Twitter", "user@x.com", "")];
        let matched = filter_for_origin(entries, "com.twitter.android");
        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn matches_web_host_via_website_url() {
        let entries = vec![entry("Proton", "dev", "account.proton.me")];
        let matched = filter_for_origin(entries, "account.proton.me");
        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn matches_web_host_subdomain() {
        let entries = vec![entry("Proton", "dev", "proton.me")];
        let matched = filter_for_origin(entries, "account.proton.me");
        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn matches_legacy_title_host() {
        let entries = vec![entry("github.com", "dev", "")];
        let matched = filter_for_origin(entries, "github.com");
        assert_eq!(matched.len(), 1);
    }

    #[test]
    fn browser_fallback_returns_web_credentials() {
        let entries = vec![
            entry("Bank", "user", ""),
            entry("Proton", "dev", "account.proton.me"),
        ];
        let matched = filter_for_origin(entries, "com.android.chrome");
        assert_eq!(matched.len(), 1);
        assert_eq!(matched[0].website_url, "account.proton.me");
    }

    #[test]
    fn empty_title_does_not_match_package_needle() {
        let entries = vec![entry("", "user@x.com", "")];
        let matched = filter_for_origin(entries, "com.twitter.android");
        assert!(matched.is_empty());
    }

    #[test]
    fn phishing_domain_does_not_match_legitimate_host() {
        assert!(!host_matches("amazon.com", "evil-amazon.com"));
        assert!(!host_matches("amazon", "evil-amazon.com"));
    }

    #[test]
    fn legitimate_subdomain_and_parent_matches() {
        assert!(host_matches("account.proton.me", "proton.me"));
        assert!(host_matches("amazon.com", "login.amazon.com"));
    }
}
