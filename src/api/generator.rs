//! Cryptographically secure password generation and entropy estimation.

use rand::rngs::StdRng;
use rand::{CryptoRng, Rng, RngExt, SeedableRng};

use crate::ArkaError;

const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGITS: &[u8] = b"0123456789";
const SPECIAL: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

/// Options for [`generate_password`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratorOptions {
    pub length: u32,
    pub use_uppercase: bool,
    pub use_lowercase: bool,
    pub use_numbers: bool,
    pub use_special: bool,
}

/// Generates a random password using a CSPRNG seeded from the OS.
///
/// At least one character from each enabled character class is guaranteed.
pub fn generate_password(options: GeneratorOptions) -> Result<String, ArkaError> {
    let pools = active_pools(&options)?;
    let pool_count = pools.len();
    let length = options.length as usize;

    if length == 0 {
        return Err(ArkaError::empty_field("length"));
    }
    if length < pool_count {
        return Err(ArkaError::empty_field("length"));
    }

    let mut rng = crypto_rng()?;
    let combined = combined_charset(&pools);
    let mut password = Vec::with_capacity(length);

    for pool in &pools {
        password.push(random_char_from_pool(&mut rng, pool));
    }

    for _ in pool_count..length {
        password.push(random_char_from_pool(&mut rng, &combined));
    }

    shuffle_bytes(&mut rng, &mut password);

    String::from_utf8(password).map_err(|_| ArkaError::InvalidUtf8)
}

/// Estimates password strength as Shannon entropy in bits (`length × log₂(pool)`).
///
/// The character pool is inferred from classes present in `password`.
pub fn calculate_entropy(password: String) -> f64 {
    entropy_bits(&password)
}

/// Same as [`calculate_entropy`] without allocating for FFI callers inside Rust.
pub fn entropy_bits(password: &str) -> f64 {
    let length = password.chars().count();
    if length == 0 {
        return 0.0;
    }

    let pool_size = inferred_pool_size(password);
    length as f64 * (pool_size as f64).log2()
}

fn active_pools(options: &GeneratorOptions) -> Result<Vec<&'static [u8]>, ArkaError> {
    let mut pools = Vec::new();

    if options.use_uppercase {
        pools.push(UPPERCASE);
    }
    if options.use_lowercase {
        pools.push(LOWERCASE);
    }
    if options.use_numbers {
        pools.push(DIGITS);
    }
    if options.use_special {
        pools.push(SPECIAL);
    }

    if pools.is_empty() {
        return Err(ArkaError::empty_field("charset"));
    }

    Ok(pools)
}

fn combined_charset(pools: &[&[u8]]) -> Vec<u8> {
    let mut charset = Vec::new();
    for pool in pools {
        charset.extend_from_slice(pool);
    }
    charset
}

fn crypto_rng() -> Result<StdRng, ArkaError> {
    let mut seed = [0u8; 32];
    crate::crypto::fill_os_random(&mut seed)?;
    Ok(StdRng::from_seed(seed))
}

fn random_char_from_pool<R>(rng: &mut R, pool: &[u8]) -> u8
where
    R: Rng + RngExt + CryptoRng + ?Sized,
{
    let index = rng.random_range(0..pool.len());
    pool[index]
}

fn shuffle_bytes<R>(rng: &mut R, bytes: &mut [u8])
where
    R: Rng + RngExt + CryptoRng + ?Sized,
{
    for i in (1..bytes.len()).rev() {
        let j = rng.random_range(0..=i);
        bytes.swap(i, j);
    }
}

fn inferred_pool_size(password: &str) -> u32 {
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_special = false;
    let mut non_ascii_distinct = std::collections::HashSet::new();

    for c in password.chars() {
        if c.is_ascii() {
            let byte = c as u8;
            if LOWERCASE.contains(&byte) {
                has_lower = true;
            }
            if UPPERCASE.contains(&byte) {
                has_upper = true;
            }
            if DIGITS.contains(&byte) {
                has_digit = true;
            }
            if SPECIAL.contains(&byte) {
                has_special = true;
            }
        } else {
            non_ascii_distinct.insert(c);
        }
    }

    let mut pool = 0u32;
    if has_lower {
        pool += LOWERCASE.len() as u32;
    }
    if has_upper {
        pool += UPPERCASE.len() as u32;
    }
    if has_digit {
        pool += DIGITS.len() as u32;
    }
    if has_special {
        pool += SPECIAL.len() as u32;
    }
    if !non_ascii_distinct.is_empty() {
        pool += non_ascii_distinct.len() as u32;
    }

    pool.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_options(length: u32) -> GeneratorOptions {
        GeneratorOptions {
            length,
            use_uppercase: true,
            use_lowercase: true,
            use_numbers: true,
            use_special: true,
        }
    }

    fn contains_from_pool(password: &str, pool: &[u8]) -> bool {
        password.bytes().any(|byte| pool.contains(&byte))
    }

    #[test]
    fn rejects_empty_charset() {
        let err = generate_password(GeneratorOptions {
            length: 16,
            use_uppercase: false,
            use_lowercase: false,
            use_numbers: false,
            use_special: false,
        })
        .unwrap_err();

        assert!(matches!(
            err,
            ArkaError::EmptyField { field } if field == "charset"
        ));
    }

    #[test]
    fn rejects_zero_length() {
        let err = generate_password(full_options(0)).unwrap_err();
        assert!(matches!(
            err,
            ArkaError::EmptyField { field } if field == "length"
        ));
    }

    #[test]
    fn rejects_length_shorter_than_active_pools() {
        let err = generate_password(full_options(3)).unwrap_err();
        assert!(matches!(
            err,
            ArkaError::EmptyField { field } if field == "length"
        ));
    }

    #[test]
    fn includes_each_enabled_class() {
        let password = match generate_password(full_options(24)) {
            Ok(value) => value,
            Err(err) => panic!("generate_password failed: {err:?}"),
        };

        assert_eq!(password.len(), 24);
        assert!(contains_from_pool(&password, UPPERCASE));
        assert!(contains_from_pool(&password, LOWERCASE));
        assert!(contains_from_pool(&password, DIGITS));
        assert!(contains_from_pool(&password, SPECIAL));
    }

    #[test]
    fn single_class_password() {
        let password = match generate_password(GeneratorOptions {
            length: 12,
            use_uppercase: false,
            use_lowercase: true,
            use_numbers: false,
            use_special: false,
        }) {
            Ok(value) => value,
            Err(err) => panic!("generate_password failed: {err:?}"),
        };

        assert_eq!(password.len(), 12);
        assert!(password.bytes().all(|b| LOWERCASE.contains(&b)));
    }

    #[test]
    fn calculate_entropy_empty_is_zero() {
        assert_eq!(calculate_entropy(String::new()), 0.0);
    }

    #[test]
    fn calculate_entropy_lowercase_only() {
        let entropy = calculate_entropy("abcdef".into());
        let expected = 6.0 * (LOWERCASE.len() as f64).log2();
        assert!((entropy - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn calculate_entropy_counts_non_ascii_distinct_chars() {
        let persian = "گاوصندوق۱۲۳";
        let entropy = calculate_entropy(persian.into());
        let distinct = persian.chars().collect::<std::collections::HashSet<_>>().len();
        let expected = persian.chars().count() as f64 * (distinct as f64).log2();
        assert!(entropy >= expected - f64::EPSILON);
        assert!(entropy > 0.0);
    }
}
