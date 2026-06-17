//! Unified error surface for the Arka vault core.
//!
//! Internal modules map low-level failures here so callers (including the FFI
//! layer) never depend on `rusqlite` or `argon2` error types directly.

/// Operational and security-relevant failures across crypto, storage, and API layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArkaError {
    /// Argon2id could not produce a key (misconfiguration or library failure).
    KeyDerivationFailed,
    /// AES-GCM authentication failed — wrong master password, tampering, or corrupt blob.
    ///
    /// We deliberately collapse decryption failures into one variant so callers cannot
    /// distinguish "bad password" from "truncated ciphertext" via error messages alone.
    AuthenticationFailed,
    /// Plaintext could not be sealed with the derived key.
    EncryptionFailed,
    /// Stored blob is too short to contain a nonce or is otherwise malformed.
    InvalidCiphertext,
    /// Decrypted bytes are not valid UTF-8 (vault entries are text passwords).
    InvalidUtf8,
    /// A required string field was empty or whitespace-only.
    EmptyField {
        /// Stable identifier for UI mapping (e.g. `"master_password"`).
        field: String,
    },
    /// `add_password` was invoked before a vault session was opened via [`super::vault::init_database`].
    VaultNotInitialized,
    /// SQLite or schema operation failed.
    Database { message: String },
    /// Vault metadata is missing or inconsistent (e.g. KDF salt length drift).
    CorruptVault { message: String },
    /// Process-global vault mutex was poisoned after a panicking thread.
    LockPoisoned,
    /// OS CSPRNG refused entropy (sandbox, early boot, or platform failure).
    RandomnessUnavailable,
}

impl std::fmt::Display for ArkaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyDerivationFailed => write!(f, "key derivation failed"),
            Self::AuthenticationFailed => {
                write!(
                    f,
                    "authentication failed: wrong master password or corrupt entry"
                )
            }
            Self::EncryptionFailed => write!(f, "encryption failed"),
            Self::InvalidCiphertext => write!(f, "invalid ciphertext layout"),
            Self::InvalidUtf8 => write!(f, "decrypted secret is not valid UTF-8"),
            Self::EmptyField { field } => write!(f, "{field} must not be empty"),
            Self::VaultNotInitialized => {
                write!(f, "vault not initialized; call init_database first")
            }
            Self::Database { message } => write!(f, "database error: {message}"),
            Self::CorruptVault { message } => write!(f, "corrupt vault: {message}"),
            Self::LockPoisoned => write!(f, "vault lock poisoned"),
            Self::RandomnessUnavailable => write!(f, "OS randomness unavailable"),
        }
    }
}

impl std::error::Error for ArkaError {}

impl From<rusqlite::Error> for ArkaError {
    fn from(_err: rusqlite::Error) -> Self {
        Self::Database {
            message: "database operation failed".into(),
        }
    }
}

fn field_err(field: &'static str) -> ArkaError {
    ArkaError::EmptyField {
        field: field.to_string(),
    }
}

impl ArkaError {
    pub(crate) fn empty_field(field: &'static str) -> Self {
        field_err(field)
    }
}
