//! Cryptographic primitives for the Arka offline vault.
//!
//! # Key hierarchy
//!
//! User-facing secrets never touch disk in plaintext. A **master password** is stretched
//! with Argon2id into a 256-bit [`EncryptionKey`]. Entry passwords are encrypted with
//! AES-256-GCM under that key before persistence.
//!
//! # On-disk layout for encrypted secrets
//!
//! Each blob is `nonce (12 B) || ciphertext || tag (16 B)`. The nonce is prepended because
//! GCM requires a unique nonce per key; storing it beside the ciphertext avoids a separate
//! column while keeping decryption self-contained.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(target_os = "android")]
use std::io::Read;

#[cfg(not(target_os = "android"))]
use rand::rngs::SysRng;
#[cfg(not(target_os = "android"))]
use rand::TryRng;

use crate::ArkaError;

/// Length of keys derived for AES-256 (256 bits).
pub const KEY_SIZE: usize = 32;

/// Salt length for Argon2id (128 bits — above RFC 9106 minimum).
pub const SALT_SIZE: usize = 16;

/// GCM nonce size (96 bits, NIST SP 800-38D).
pub const NONCE_SIZE: usize = 12;

/// Pinned OWASP-aligned Argon2id memory cost: 64 MiB in 1 KiB blocks (legacy / desktop).
pub const ARGON2_M_COST_KIB: u32 = 65_536;

/// Pinned OWASP-aligned Argon2id time cost (iterations).
pub const ARGON2_T_COST: u32 = 3;

/// Pinned Argon2id parallelism — fixed so future `argon2` crate defaults cannot break vaults.
pub const ARGON2_P_COST: u32 = 4;

/// Argon2id parameters persisted per vault — legacy vaults without metadata use [`KdfParams::LEGACY`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// Original OWASP desktop parameters — used for vaults created before per-vault KDF metadata.
    pub const LEGACY: Self = Self {
        m_cost_kib: ARGON2_M_COST_KIB,
        t_cost: ARGON2_T_COST,
        p_cost: ARGON2_P_COST,
    };

    /// Lower memory footprint for constrained mobile devices (OWASP minimum recommendation).
    pub const MOBILE: Self = Self {
        m_cost_kib: 19_456,
        t_cost: 3,
        p_cost: 1,
    };

    /// Parameters written into new vault metadata on this platform.
    #[cfg(target_os = "android")]
    pub fn new_vault() -> Self {
        Self::MOBILE
    }

    #[cfg(not(target_os = "android"))]
    pub fn new_vault() -> Self {
        Self::LEGACY
    }
}

/// GCM authentication tag size (128 bits, NIST SP 800-38D).
const GCM_TAG_SIZE: usize = 16;

/// Minimum byte length of an [`EncryptedSecret`]: `nonce (12 B) + ciphertext (≥1 B) + tag (16 B)`.
const MIN_ENCRYPTED_LEN: usize = NONCE_SIZE + 1 + GCM_TAG_SIZE;

/// A 256-bit key derived from the master password — not the password itself.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptionKey([u8; KEY_SIZE]);

/// Per-vault salt persisted in `vault_meta`; must remain stable for the life of the vault.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KdfSalt([u8; SALT_SIZE]);

/// Ciphertext sealed with AES-256-GCM, including prepended nonce and authentication tag.
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedSecret(Vec<u8>);

impl std::fmt::Debug for EncryptedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedSecret")
            .field("len", &self.0.len())
            .finish()
    }
}

impl EncryptionKey {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }

    #[must_use]
    pub(crate) fn from_key_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }
}

impl KdfSalt {
    #[must_use]
    pub fn from_bytes(bytes: [u8; SALT_SIZE]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SALT_SIZE] {
        &self.0
    }
}

impl EncryptedSecret {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for EncryptedSecret {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

/// Returns a pinned Argon2id instance — parameters are explicit and stable across crate updates.
fn argon2_kdf(params: &KdfParams) -> Result<Argon2<'static>, ArkaError> {
    let argon2_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(Params::DEFAULT_OUTPUT_LEN),
    )
    .map_err(|_| ArkaError::KeyDerivationFailed)?;

    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params))
}

/// Draws a cryptographically secure salt for first-time vault provisioning.
///
/// Salts must be unique per vault so rainbow tables against one export do not
/// weaken others.
pub fn generate_salt() -> Result<KdfSalt, ArkaError> {
    Ok(KdfSalt(random_bytes()?))
}

/// Stretches a master password into an [`EncryptionKey`] using vault-specific Argon2id parameters.
pub fn derive_key(
    master_password: &str,
    salt: &KdfSalt,
    params: &KdfParams,
) -> Result<EncryptionKey, ArkaError> {
    let argon2 = argon2_kdf(params)?;
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);

    argon2
        .hash_password_into(
            master_password.as_bytes(),
            salt.as_bytes(),
            key.as_mut(),
        )
        .map_err(|_| ArkaError::KeyDerivationFailed)?;

    Ok(EncryptionKey(*key))
}

/// Seals UTF-8 `plaintext` and returns nonce-prefixed ciphertext.
///
/// Each call draws a fresh 96-bit nonce from `SysRng`; nonce reuse under the same
/// key would break GCM confidentiality and must never occur.
pub fn encrypt(key: &EncryptionKey, plaintext: &str) -> Result<EncryptedSecret, ArkaError> {
    let cipher = build_cipher(key)?;
    let nonce_bytes = random_bytes::<NONCE_SIZE>()?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut payload = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|_| ArkaError::EncryptionFailed)?;

    let mut output = Vec::with_capacity(NONCE_SIZE + payload.len());
    output.extend_from_slice(&nonce_bytes);
    output.append(&mut payload);
    Ok(EncryptedSecret(output))
}

/// Opens an [`EncryptedSecret`] produced by [`encrypt`].
///
/// Cleartext is wrapped in [`Zeroizing`] so it is wiped when the caller's scope ends.
pub fn decrypt(
    key: &EncryptionKey,
    secret: &EncryptedSecret,
) -> Result<Zeroizing<String>, ArkaError> {
    let (nonce_bytes, ciphertext) = split_encrypted(secret.as_bytes())?;
    let cipher = build_cipher(key)?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| ArkaError::AuthenticationFailed)?;

    String::from_utf8(plaintext)
        .map(Zeroizing::new)
        .map_err(|_| ArkaError::InvalidUtf8)
}

fn build_cipher(key: &EncryptionKey) -> Result<Aes256Gcm, ArkaError> {
    Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| ArkaError::EncryptionFailed)
}

fn split_encrypted(data: &[u8]) -> Result<(&[u8], &[u8]), ArkaError> {
    if data.len() < MIN_ENCRYPTED_LEN {
        return Err(ArkaError::InvalidCiphertext);
    }
    Ok(data.split_at(NONCE_SIZE))
}

/// Fills `buf` from the OS CSPRNG without panicking across the JNI boundary.
///
/// On Android, [`getrandom::fill`] is tried first; if the syscall backend is
/// unavailable on a specific device/API combo, `/dev/urandom` is used as a
/// documented fallback so vault provisioning never aborts the host process.
pub(crate) fn fill_os_random(buf: &mut [u8]) -> Result<(), ArkaError> {
    if getrandom::fill(buf).is_ok() {
        return Ok(());
    }

    #[cfg(target_os = "android")]
    {
        let mut urandom = std::fs::File::open("/dev/urandom")
            .map_err(|_| ArkaError::RandomnessUnavailable)?;
        urandom
            .read_exact(buf)
            .map_err(|_| ArkaError::RandomnessUnavailable)?;
        return Ok(());
    }

    #[cfg(not(target_os = "android"))]
    {
        SysRng
            .try_fill_bytes(buf)
            .map_err(|_| ArkaError::RandomnessUnavailable)?;
    }

    Ok(())
}

fn random_bytes<const N: usize>() -> Result<[u8; N], ArkaError> {
    let mut buf = [0u8; N];
    fill_os_random(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn argon2_params_are_pinned_to_owasp_values() {
        assert_eq!(ARGON2_M_COST_KIB, 65_536);
        assert_eq!(ARGON2_T_COST, 3);
        assert_eq!(ARGON2_P_COST, 4);
        assert!(ARGON2_M_COST_KIB >= ARGON2_P_COST * 8);
    }

    #[test]
    fn derive_key_is_stable_for_fixed_inputs() -> Result<(), ArkaError> {
        let salt = generate_salt()?;
        let params = KdfParams::LEGACY;
        let a = derive_key("master-password", &salt, &params)?;
        let b = derive_key("master-password", &salt, &params)?;
        assert_eq!(a.as_bytes(), b.as_bytes());
        Ok(())
    }

    #[test]
    fn encrypt_decrypt_roundtrip() -> Result<(), ArkaError> {
        let salt = generate_salt()?;
        let key = derive_key("Arka!Master#2026", &salt, &KdfParams::LEGACY)?;
        let secret = "vault-entry: github / user@example.com";

        let encrypted = encrypt(&key, secret)?;
        assert!(encrypted.as_bytes().len() > NONCE_SIZE);
        assert_ne!(encrypted.as_bytes(), secret.as_bytes());

        let opened = decrypt(&key, &encrypted)?;
        assert_eq!(opened.as_str(), secret);
        Ok(())
    }

    #[test]
    fn encrypt_uses_unique_nonces() -> Result<(), ArkaError> {
        let salt = generate_salt()?;
        let key = derive_key("nonce-uniqueness", &salt, &KdfParams::LEGACY)?;
        let a = encrypt(&key, "same plaintext")?;
        let b = encrypt(&key, "same plaintext")?;
        assert_ne!(
            &a.as_bytes()[..NONCE_SIZE],
            &b.as_bytes()[..NONCE_SIZE],
            "each encryption must draw a fresh nonce under the same key"
        );
        Ok(())
    }

    #[test]
    fn decrypt_rejects_wrong_key() -> Result<(), ArkaError> {
        let salt = generate_salt()?;
        let key = derive_key("correct-password", &salt, &KdfParams::LEGACY)?;
        let wrong = derive_key("wrong-password", &salt, &KdfParams::LEGACY)?;
        let encrypted = encrypt(&key, "secret payload")?;

        assert!(matches!(
            decrypt(&wrong, &encrypted),
            Err(ArkaError::AuthenticationFailed)
        ));
        Ok(())
    }
}
