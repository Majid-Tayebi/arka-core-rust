//! Vault operations for JNI and in-process callers.
//!
//! Functions in this module orchestrate [`crate::crypto`] and [`crate::db`].
//! Cryptographic work always happens here — never in the FFI glue — so the
//! open-source Rust core remains reviewable as a single security boundary.

use crate::crypto::{self, EncryptedSecret, EncryptionKey};
use crate::db::{StagedPasswordRow, VaultDatabase};
use crate::ArkaError;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

mod session {
    use std::sync::{Mutex, OnceLock};

    use crate::db::VaultDatabase;
    use crate::ArkaError;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    pub(super) struct SessionState {
        db: VaultDatabase,
        db_path: String,
        /// Avoids repeating Argon2id on every JNI call within the same unlocked process.
        unlock: Option<CachedUnlock>,
    }

    #[derive(Zeroize, ZeroizeOnDrop)]
    struct CachedUnlock {
        master_tag: [u8; 32],
        key: crate::crypto::EncryptionKey,
    }

    fn master_tag(master_password: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(master_password.as_bytes());
        hasher.finalize().into()
    }

    pub(super) fn resolve_key_owned(
        state: &mut SessionState,
        master_password: &str,
    ) -> Result<crate::crypto::EncryptionKey, ArkaError> {
        let tag = master_tag(master_password);
        if state
            .unlock
            .as_ref()
            .is_some_and(|cached| cached.master_tag == tag)
        {
            let bytes = *state
                .unlock
                .as_ref()
                .expect("unlock tag matched")
                .key
                .as_bytes();
            return Ok(crate::crypto::EncryptionKey::from_key_bytes(bytes));
        }
        let key = super::unlock_vault(master_password, state.db())?;
        let stored = crate::crypto::EncryptionKey::from_key_bytes(*key.as_bytes());
        state.unlock = Some(CachedUnlock {
            master_tag: tag,
            key: stored,
        });
        let bytes = *state
            .unlock
            .as_ref()
            .expect("unlock just stored")
            .key
            .as_bytes();
        Ok(crate::crypto::EncryptionKey::from_key_bytes(bytes))
    }

    impl SessionState {
        pub(super) fn new(db: VaultDatabase, db_path: String) -> Self {
            Self {
                db,
                db_path,
                unlock: None,
            }
        }

        pub(super) fn db(&self) -> &VaultDatabase {
            &self.db
        }

        pub(super) fn db_path(&self) -> &str {
            &self.db_path
        }
    }

    pub(super) fn install_fast_key(state: &mut SessionState, key: crate::crypto::EncryptionKey) {
        state.unlock = Some(CachedUnlock {
            master_tag: FAST_UNLOCK_TAG,
            key,
        });
    }

    pub(super) fn active_key(state: &SessionState) -> Result<crate::crypto::EncryptionKey, ArkaError> {
        state
            .unlock
            .as_ref()
            .map(|cached| {
                crate::crypto::EncryptionKey::from_key_bytes(*cached.key.as_bytes())
            })
            .ok_or(ArkaError::VaultNotInitialized)
    }

    /// Sentinel tag — session was primed via Keystore fast path, not master-password KDF.
    const FAST_UNLOCK_TAG: [u8; 32] = [0xFA; 32];

    static ACTIVE: OnceLock<Mutex<Option<SessionState>>> = OnceLock::new();

    pub(super) fn vault_store() -> &'static Mutex<Option<SessionState>> {
        ACTIVE.get_or_init(|| Mutex::new(None))
    }
}

const BACKUP_FORMAT_VERSION: u32 = 2;

/// Active unlocked vault — derived encryption key bound to the open database handle.
struct VaultSession<'a> {
    db: &'a VaultDatabase,
    db_path: &'a str,
    key: EncryptionKey,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultBackupPayload {
    version: u32,
    entries: Vec<VaultBackupEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultBackupEntry {
    title: String,
    username: String,
    category: String,
    password: String,
    #[serde(default)]
    website_url: String,
    #[serde(default)]
    note: String,
}

/// Cleartext credential returned after successful decryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedPasswordEntry {
    pub id: i64,
    pub title: String,
    pub username: String,
    pub category: String,
    pub password: Zeroizing<String>,
    pub website_url: String,
    pub note: String,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Opens (or creates) the vault at `db_path` and registers it as the active session.
///
/// Idempotent: if a session for the **same** `db_path` is already open, the existing
/// session — including its cached Argon2id unlock key — is preserved. This keeps bulk
/// operations (e.g. importing 100+ credentials) from re-deriving the key on every call,
/// which previously made imports hang for minutes.
pub fn init_database(db_path: String) -> Result<(), ArkaError> {
    require_non_empty(&db_path, "db_path")?;

    let mut guard = session::vault_store()
        .lock()
        .map_err(|_| ArkaError::LockPoisoned)?;

    if guard
        .as_ref()
        .is_some_and(|state| state.db_path() == db_path)
    {
        // Same vault already open — keep the cached unlock key alive.
        return Ok(());
    }

    let db = VaultDatabase::open(&db_path)?;
    db.ensure_kdf_salt()?;
    guard.replace(session::SessionState::new(db, db_path));

    Ok(())
}

/// Creates a new vault file and primes the in-memory session key in one Argon2 pass.
pub fn bootstrap_vault(db_path: String, master_password: String) -> Result<(), ArkaError> {
    let master_password = Zeroizing::new(master_password);
    require_non_empty(master_password.as_str(), "master_password")?;
    init_database(db_path)?;
    with_vault_session(master_password.as_str(), |_| Ok(()))
}

/// Drops the in-memory vault session so derived keys and DB handles are released.
///
/// Called when the user locks the app or auto-lock fires — ciphertext on disk stays
/// encrypted; callers must unlock again with the master password.
pub fn lock_vault() -> Result<(), ArkaError> {
    session::vault_store()
        .lock()
        .map_err(|_| ArkaError::LockPoisoned)?
        .take();
    Ok(())
}

/// Returns the active session encryption key after a successful master-password unlock.
///
/// Used to seal the derived key in Android Keystore so autofill can skip Argon2id.
pub fn export_session_key(
    db_path: String,
    master_password: String,
) -> Result<[u8; crypto::KEY_SIZE], ArkaError> {
    let master_password = Zeroizing::new(master_password);
    require_non_empty(master_password.as_str(), "master_password")?;
    with_vault_session(master_password.as_str(), |session| {
        if session.db_path != db_path {
            return Err(ArkaError::CorruptVault {
                message: "db_path does not match the active vault session".into(),
            });
        }
        Ok(*session.key.as_bytes())
    })
}

/// Installs a previously sealed session key — no Argon2id on the autofill hot path.
pub fn install_session_key(
    db_path: String,
    key_bytes: [u8; crypto::KEY_SIZE],
) -> Result<(), ArkaError> {
    require_non_empty(&db_path, "db_path")?;
    init_database(db_path.clone())?;
    let key = crypto::EncryptionKey::from_key_bytes(key_bytes);
    let mut guard = session::vault_store()
        .lock()
        .map_err(|_| ArkaError::LockPoisoned)?;
    let state = guard.as_mut().ok_or(ArkaError::VaultNotInitialized)?;
    if state.db_path() != db_path {
        return Err(ArkaError::CorruptVault {
            message: "db_path does not match the active vault session".into(),
        });
    }
    session::install_fast_key(state, key);
    Ok(())
}

/// Decrypts one vault row using the in-memory session key (Keystore fast path).
pub fn get_entry_by_id_fast(
    db_path: String,
    entry_id: i64,
) -> Result<Option<DecryptedPasswordEntry>, ArkaError> {
    require_non_empty(&db_path, "db_path")?;
    let mut guard = session::vault_store()
        .lock()
        .map_err(|_| ArkaError::LockPoisoned)?;
    let state = guard.as_mut().ok_or(ArkaError::VaultNotInitialized)?;
    if state.db_path() != db_path {
        return Err(ArkaError::CorruptVault {
            message: "db_path does not match the active vault session".into(),
        });
    }
    let key = session::active_key(state)?;
    let Some(record) = state.db().get_password_by_id(entry_id)? else {
        return Ok(None);
    };
    Ok(Some(decrypt_record(&key, record)?))
}

/// Derives a key, encrypts `password`, and stores the entry in the active vault.
pub fn add_password(
    title: String,
    username: String,
    category: String,
    password: String,
    master_password: String,
    website_url: String,
    note: String,
) -> Result<i64, ArkaError> {
    let master_password = Zeroizing::new(master_password);
    require_non_empty(master_password.as_str(), "master_password")?;
    require_non_empty(&title, "title")?;
    require_non_empty(&password, "password")?;

    with_vault_session(master_password.as_str(), |session| {
        let encrypted = crypto::encrypt(&session.key, &password)?;
        session.db.insert_password(
            &title,
            &username,
            &category,
            crate::db::optional_metadata(&website_url),
            crate::db::optional_metadata(&note),
            &encrypted,
        )
    })
}

/// Re-encrypts and updates an existing credential in the active vault.
#[allow(clippy::too_many_arguments)]
pub fn update_password(
    id: i64,
    title: String,
    username: String,
    category: String,
    password: String,
    master_password: String,
    website_url: String,
    note: String,
) -> Result<(), ArkaError> {
    let master_password = Zeroizing::new(master_password);
    require_non_empty(master_password.as_str(), "master_password")?;
    require_non_empty(&title, "title")?;
    require_non_empty(&password, "password")?;

    with_vault_session(master_password.as_str(), |session| {
        let encrypted = crypto::encrypt(&session.key, &password)?;
        session.db.update_password(
            id,
            &title,
            &username,
            &category,
            crate::db::optional_metadata(&website_url),
            crate::db::optional_metadata(&note),
            &encrypted,
        )
    })
}

/// Deletes a credential from the active vault after verifying `master_password`.
pub fn delete_password(id: i64, master_password: String) -> Result<(), ArkaError> {
    let master_password = Zeroizing::new(master_password);
    require_non_empty(master_password.as_str(), "master_password")?;

    with_vault_session(master_password.as_str(), |session| session.db.delete_password_by_id(id))
}

/// Reads every entry from the active vault session and decrypts secrets with `master_password`.
pub fn get_all_entries(
    db_path: String,
    master_password: String,
) -> Result<Vec<DecryptedPasswordEntry>, ArkaError> {
    require_non_empty(&db_path, "db_path")?;
    let master_password = Zeroizing::new(master_password);
    require_non_empty(master_password.as_str(), "master_password")?;

    with_vault_session(master_password.as_str(), |session| {
        if session.db_path != db_path {
            return Err(ArkaError::CorruptVault {
                message: "db_path does not match the active vault session".into(),
            });
        }

        session
            .db
            .list_passwords()?
            .into_iter()
            .map(|record| decrypt_record(&session.key, record))
            .collect()
    })
}

/// Decrypts a single vault row by id — used by autofill to avoid scanning the full vault.
pub fn get_entry_by_id(
    db_path: String,
    master_password: String,
    entry_id: i64,
) -> Result<Option<DecryptedPasswordEntry>, ArkaError> {
    require_non_empty(&db_path, "db_path")?;
    let master_password = Zeroizing::new(master_password);
    require_non_empty(master_password.as_str(), "master_password")?;

    with_vault_session(master_password.as_str(), |session| {
        if session.db_path != db_path {
            return Err(ArkaError::CorruptVault {
                message: "db_path does not match the active vault session".into(),
            });
        }

        let Some(record) = session.db.get_password_by_id(entry_id)? else {
            return Ok(None);
        };
        Ok(Some(decrypt_record(&session.key, record)?))
    })
}

/// Serializes all vault rows to JSON, then seals the payload with the session key.
fn export_encrypted_vault(session: &VaultSession<'_>) -> Result<Vec<u8>, ArkaError> {
    let entries = session
        .db
        .list_passwords()?
        .into_iter()
        .map(|record| {
            let password = crypto::decrypt(&session.key, &record.encrypted_password)?;
            Ok(VaultBackupEntry {
                title: record.title,
                username: record.username,
                category: record.category,
                password: password.to_string(),
                website_url: record.website_url.unwrap_or_default(),
                note: record.note.unwrap_or_default(),
            })
        })
        .collect::<Result<Vec<_>, ArkaError>>()?;

    let payload = VaultBackupPayload {
        version: BACKUP_FORMAT_VERSION,
        entries,
    };

    let json = Zeroizing::new(
        serde_json::to_string(&payload).map_err(|err| ArkaError::CorruptVault {
            message: format!("backup serialization failed: {err}"),
        })?,
    );

    Ok(crypto::encrypt(&session.key, json.as_str())?.into_bytes())
}

/// Opens an encrypted backup and **replaces** all local credentials with its contents.
type StagedImportRow = (
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    EncryptedSecret,
);

fn import_encrypted_vault(bytes: Vec<u8>, session: &VaultSession<'_>) -> Result<(), ArkaError> {
    if bytes.is_empty() {
        return Err(ArkaError::InvalidCiphertext);
    }

    let json = crypto::decrypt(&session.key, &EncryptedSecret::from(bytes))?;
    let payload: VaultBackupPayload = serde_json::from_str(json.as_str()).map_err(|err| {
        ArkaError::CorruptVault {
            message: format!("backup JSON invalid: {err}"),
        }
    })?;

    if payload.version != BACKUP_FORMAT_VERSION && payload.version != 1 {
        return Err(ArkaError::CorruptVault {
            message: format!(
                "unsupported backup version {} (expected 1 or {BACKUP_FORMAT_VERSION})",
                payload.version
            ),
        });
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut staged_rows: Vec<StagedImportRow> = Vec::with_capacity(payload.entries.len());

    for entry in payload.entries {
        require_non_empty(&entry.title, "title")?;
        require_non_empty(&entry.username, "username")?;
        require_non_empty(&entry.password, "password")?;

        let encrypted = crypto::encrypt(&session.key, &entry.password)?;
        staged_rows.push((
            entry.title,
            entry.username,
            entry.category,
            crate::db::optional_metadata(&entry.website_url).map(str::to_string),
            crate::db::optional_metadata(&entry.note).map(str::to_string),
            encrypted,
        ));
    }

    let rows: Vec<StagedPasswordRow<'_>> = staged_rows
        .iter()
        .map(
            |(title, username, category, website_url, note, encrypted)| StagedPasswordRow {
                title,
                username,
                category,
                website_url: website_url.as_deref(),
                note: note.as_deref(),
                encrypted_password: encrypted,
                created_at: now,
                updated_at: now,
            },
        )
        .collect();

    session.db.replace_all_passwords(&rows)
}

/// FFI entry — exports the active vault as an AES-256-GCM sealed binary blob.
pub fn export_vault_backup(master_password: String) -> Result<Vec<u8>, ArkaError> {
    let master_password = Zeroizing::new(master_password);
    require_non_empty(master_password.as_str(), "master_password")?;
    with_vault_session(master_password.as_str(), export_encrypted_vault)
}

/// FFI entry — restores entries from a blob created by [`export_vault_backup`].
pub fn import_vault_backup(bytes: Vec<u8>, master_password: String) -> Result<(), ArkaError> {
    let master_password = Zeroizing::new(master_password);
    require_non_empty(master_password.as_str(), "master_password")?;
    with_vault_session(master_password.as_str(), |session| {
        import_encrypted_vault(bytes, session)
    })
}

fn with_vault_session<T>(
    master_password: &str,
    operation: impl FnOnce(&VaultSession<'_>) -> Result<T, ArkaError>,
) -> Result<T, ArkaError> {
    let mut guard = session::vault_store()
        .lock()
        .map_err(|_| ArkaError::LockPoisoned)?;

    let state = guard.as_mut().ok_or(ArkaError::VaultNotInitialized)?;
    let key = session::resolve_key_owned(state, master_password)?;
    let session = VaultSession {
        db: state.db(),
        db_path: state.db_path(),
        key,
    };

    operation(&session)
}

fn unlock_vault(master_password: &str, db: &VaultDatabase) -> Result<EncryptionKey, ArkaError> {
    let salt = db.require_kdf_salt()?;
    let params = db.kdf_params_or_legacy()?;
    crypto::derive_key(master_password, &salt, &params)
}

fn decrypt_record(
    key: &EncryptionKey,
    record: crate::db::PasswordRecord,
) -> Result<DecryptedPasswordEntry, ArkaError> {
    let password = crypto::decrypt(key, &record.encrypted_password)?;
    Ok(DecryptedPasswordEntry {
        id: record.id,
        title: record.title,
        username: record.username,
        category: record.category,
        password,
        website_url: record.website_url.unwrap_or_default(),
        note: record.note.unwrap_or_default(),
        created_at: record.created_at,
        updated_at: record.updated_at,
    })
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), ArkaError> {
    if value.trim().is_empty() {
        return Err(ArkaError::empty_field(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    /// Serializes vault tests — they share a process-wide session static.
    static VAULT_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn temp_db_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("arka-{label}-{nanos}.db"))
    }

    fn reset_session() -> Result<(), ArkaError> {
        session::vault_store()
            .lock()
            .map_err(|_| ArkaError::LockPoisoned)?
            .take();
        Ok(())
    }

    fn remove_db(path: &Path) {
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn full_vault_roundtrip() -> Result<(), ArkaError> {
        let _guard = VAULT_TEST_LOCK.lock().map_err(|_| ArkaError::LockPoisoned)?;
        reset_session()?;
        let path = temp_db_path("roundtrip");
        let path_str = path.to_string_lossy().into_owned();
        let master = "master-password-123";

        init_database(path_str.clone())?;
        let id = add_password(
            "GitHub".into(),
            "user@example.com".into(),
            "کار".into(),
            "plain-secret".into(),
            master.into(),
            String::new(),
            String::new(),
        )?;

        let entries = get_all_entries(path_str, master.into())?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, id);
        assert_eq!(entries[0].category, "کار");
        assert_eq!(entries[0].password.as_str(), "plain-secret");

        remove_db(&path);
        Ok(())
    }

    #[test]
    fn wrong_master_password_is_authentication_failure() -> Result<(), ArkaError> {
        let _guard = VAULT_TEST_LOCK.lock().map_err(|_| ArkaError::LockPoisoned)?;
        reset_session()?;
        let path = temp_db_path("wrong-master");
        let path_str = path.to_string_lossy().into_owned();

        init_database(path_str.clone())?;
        add_password(
            "Site".into(),
            "user".into(),
            String::new(),
            "secret".into(),
            "correct-master".into(),
            String::new(),
            String::new(),
        )?;

        let err = match get_all_entries(path_str, "wrong-master".into()) {
            Err(err) => err,
            Ok(_) => panic!("wrong master password must fail"),
        };
        assert!(matches!(err, ArkaError::AuthenticationFailed));

        remove_db(&path);
        Ok(())
    }

    #[test]
    fn lock_vault_clears_active_session() -> Result<(), ArkaError> {
        let _guard = VAULT_TEST_LOCK.lock().map_err(|_| ArkaError::LockPoisoned)?;
        reset_session()?;
        let path = temp_db_path("lock-session");
        let path_str = path.to_string_lossy().into_owned();

        init_database(path_str)?;
        lock_vault()?;

        let err = add_password(
            "Site".into(),
            "user".into(),
            String::new(),
            "secret".into(),
            "master".into(),
            String::new(),
            String::new(),
        )
        .expect_err("add after lock must fail");
        assert!(matches!(err, ArkaError::VaultNotInitialized));

        remove_db(&path);
        Ok(())
    }

    #[test]
    fn add_password_requires_session() -> Result<(), ArkaError> {
        let _guard = VAULT_TEST_LOCK.lock().map_err(|_| ArkaError::LockPoisoned)?;
        reset_session()?;
        let err = match add_password(
            "Site".into(),
            "user".into(),
            String::new(),
            "secret".into(),
            "master".into(),
            String::new(),
            String::new(),
        ) {
            Err(err) => err,
            Ok(_) => panic!("add without init must fail"),
        };
        assert!(matches!(err, ArkaError::VaultNotInitialized));
        Ok(())
    }

    #[test]
    fn add_password_rejects_blank_title() -> Result<(), ArkaError> {
        let _guard = VAULT_TEST_LOCK.lock().map_err(|_| ArkaError::LockPoisoned)?;
        reset_session()?;
        let path = temp_db_path("blank-title");
        let path_str = path.to_string_lossy().into_owned();

        init_database(path_str)?;
        let err = add_password(
            "   ".into(),
            "user".into(),
            String::new(),
            "secret".into(),
            "master".into(),
            String::new(),
            String::new(),
        )
        .expect_err("blank title must fail");

        assert!(matches!(
            err,
            ArkaError::EmptyField { field } if field == "title"
        ));

        remove_db(&path);
        Ok(())
    }

    #[test]
    fn get_all_entries_rejects_mismatched_db_path() -> Result<(), ArkaError> {
        let _guard = VAULT_TEST_LOCK.lock().map_err(|_| ArkaError::LockPoisoned)?;
        reset_session()?;
        let path = temp_db_path("path-mismatch");
        let path_str = path.to_string_lossy().into_owned();

        init_database(path_str.clone())?;
        add_password(
            "Site".into(),
            "user".into(),
            String::new(),
            "secret".into(),
            "master".into(),
            String::new(),
            String::new(),
        )?;

        let err = match get_all_entries("/wrong/path.db".into(), "master".into()) {
            Err(err) => err,
            Ok(_) => panic!("mismatched db_path must fail"),
        };
        assert!(matches!(err, ArkaError::CorruptVault { .. }));

        remove_db(&path);
        Ok(())
    }

    #[test]
    fn backup_import_replaces_existing_rows() -> Result<(), ArkaError> {
        let _guard = VAULT_TEST_LOCK.lock().map_err(|_| ArkaError::LockPoisoned)?;
        reset_session()?;
        let path = temp_db_path("backup");
        let path_str = path.to_string_lossy().into_owned();
        let master = "backup-master-key";

        init_database(path_str.clone())?;
        add_password(
            "Bank".into(),
            "alice".into(),
            "مالی".into(),
            "hunter2".into(),
            master.into(),
            String::new(),
            String::new(),
        )?;

        let blob = export_vault_backup(master.into())?;
        assert!(blob.len() > crypto::NONCE_SIZE);

        add_password(
            "Temp".into(),
            "bob".into(),
            String::new(),
            "remove-me".into(),
            master.into(),
            String::new(),
            String::new(),
        )?;
        assert_eq!(get_all_entries(path_str.clone(), master.into())?.len(), 2);

        import_vault_backup(blob, master.into())?;
        let entries = get_all_entries(path_str, master.into())?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "Bank");
        assert_eq!(entries[0].category, "مالی");
        assert!(!entries.iter().any(|entry| entry.title == "Temp"));

        remove_db(&path);
        Ok(())
    }

    #[test]
    fn update_password_roundtrip() -> Result<(), ArkaError> {
        let _guard = VAULT_TEST_LOCK.lock().map_err(|_| ArkaError::LockPoisoned)?;
        reset_session()?;
        let path = temp_db_path("update");
        let path_str = path.to_string_lossy().into_owned();
        let master = "master-password-123";

        init_database(path_str.clone())?;
        let id = add_password(
            "GitHub".into(),
            "old@example.com".into(),
            "عمومی".into(),
            "old-secret".into(),
            master.into(),
            String::new(),
            String::new(),
        )?;

        update_password(
            id,
            "GitLab".into(),
            "new@example.com".into(),
            "کار".into(),
            "new-secret".into(),
            master.into(),
            "gitlab.com".into(),
            "updated".into(),
        )?;

        let entries = get_all_entries(path_str, master.into())?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "GitLab");
        assert_eq!(entries[0].username, "new@example.com");
        assert_eq!(entries[0].category, "کار");
        assert_eq!(entries[0].password.as_str(), "new-secret");
        assert_eq!(entries[0].website_url, "gitlab.com");
        assert_eq!(entries[0].note, "updated");

        remove_db(&path);
        Ok(())
    }

    #[test]
    fn delete_password_removes_row() -> Result<(), ArkaError> {
        let _guard = VAULT_TEST_LOCK.lock().map_err(|_| ArkaError::LockPoisoned)?;
        reset_session()?;
        let path = temp_db_path("delete");
        let path_str = path.to_string_lossy().into_owned();
        let master = "delete-master-key";

        init_database(path_str.clone())?;
        let id = add_password(
            "Temp".into(),
            "bob".into(),
            String::new(),
            "secret".into(),
            master.into(),
            String::new(),
            String::new(),
        )?;
        assert_eq!(get_all_entries(path_str.clone(), master.into())?.len(), 1);

        delete_password(id, master.into())?;
        assert_eq!(get_all_entries(path_str, master.into())?.len(), 0);

        remove_db(&path);
        Ok(())
    }
}
