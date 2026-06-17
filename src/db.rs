//! Local SQLite persistence for encrypted vault entries.
//!
//! This layer is intentionally **crypto-agnostic**: it stores opaque blobs produced
//! by [`crate::crypto`] and never sees plaintext passwords. Splitting concerns makes
//! storage audits straightforward and keeps SQL injection surface limited to metadata
//! columns (`title`, `username`, `category`, `website_url`, `note`).

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, Row};

use crate::crypto::{self, EncryptedSecret, KdfParams, KdfSalt, SALT_SIZE};
use crate::ArkaError;

mod schema {
    pub const PASSWORDS: &str = "
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            username TEXT NOT NULL,
            category TEXT NOT NULL DEFAULT '',
            website_url TEXT,
            note TEXT,
            encrypted_password BLOB NOT NULL,
            created_at INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT 0
        );
    ";

    pub const VAULT_META: &str = "
        CREATE TABLE IF NOT EXISTS vault_meta (
            key TEXT PRIMARY KEY NOT NULL,
            value BLOB NOT NULL
        );
    ";

    pub const KDF_SALT_KEY: &str = "kdf_salt";
    pub const KDF_PARAMS_KEY: &str = "kdf_params";
}

/// Row returned from disk — password field remains encrypted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasswordRecord {
    pub id: i64,
    pub title: String,
    pub username: String,
    pub category: String,
    pub website_url: Option<String>,
    pub note: Option<String>,
    pub encrypted_password: EncryptedSecret,
    pub created_at: i64,
    pub updated_at: i64,
}

/// One credential row staged for atomic vault restore.
pub struct StagedPasswordRow<'a> {
    pub title: &'a str,
    pub username: &'a str,
    pub category: &'a str,
    pub website_url: Option<&'a str>,
    pub note: Option<&'a str>,
    pub encrypted_password: &'a EncryptedSecret,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Handle to an open vault database file.
pub struct VaultDatabase {
    conn: Connection,
}

impl VaultDatabase {
    /// Opens `path`, creating the file when absent, and migrates schema idempotently.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ArkaError> {
        let conn = Connection::open(path)?;
        conn.execute_batch(schema::PASSWORDS)?;
        conn.execute_batch(schema::VAULT_META)?;
        migrate_passwords_table(&conn)?;
        migrate_passwords_extended(&conn)?;
        Ok(Self { conn })
    }

    /// Returns the persisted KDF salt, generating one atomically on first vault use.
    pub fn ensure_kdf_salt(&self) -> Result<KdfSalt, ArkaError> {
        if let Some(salt) = self.read_kdf_salt()? {
            return Ok(salt);
        }

        let salt = crypto::generate_salt()?;
        let params = KdfParams::new_vault();
        let params_json = serde_json::to_vec(&params).map_err(|err| ArkaError::CorruptVault {
            message: format!("kdf params encode failed: {err}"),
        })?;

        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO vault_meta (key, value) VALUES (?1, ?2)",
            params![schema::KDF_SALT_KEY, salt.as_bytes().as_slice()],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO vault_meta (key, value) VALUES (?1, ?2)",
            params![schema::KDF_PARAMS_KEY, params_json],
        )?;
        tx.commit()?;

        self.read_kdf_salt()?.ok_or_else(|| ArkaError::CorruptVault {
            message: "KDF salt missing after provisioning".into(),
        })
    }

    /// Loads persisted KDF parameters or falls back to legacy desktop defaults.
    pub fn kdf_params_or_legacy(&self) -> Result<KdfParams, ArkaError> {
        if let Some(params) = self.read_kdf_params()? {
            return Ok(params);
        }

        // Empty vaults provisioned before per-vault KDF metadata shipped (e.g. failed Android
        // create) — pin mobile parameters so Argon2 does not allocate 64 MiB on first unlock.
        #[cfg(target_os = "android")]
        if self.list_passwords()?.is_empty() {
            let params = KdfParams::MOBILE;
            self.persist_kdf_params(&params)?;
            return Ok(params);
        }

        Ok(KdfParams::LEGACY)
    }

    /// Loads the KDF salt or fails when the vault file predates metadata support.
    pub fn require_kdf_salt(&self) -> Result<KdfSalt, ArkaError> {
        self.read_kdf_salt()?
            .ok_or_else(|| ArkaError::CorruptVault {
                message: "KDF salt missing from vault metadata".into(),
            })
    }

    /// Persists one entry; `encrypted_password` must already be sealed upstream.
    pub fn insert_password(
        &self,
        title: &str,
        username: &str,
        category: &str,
        website_url: Option<&str>,
        note: Option<&str>,
        encrypted_password: &EncryptedSecret,
    ) -> Result<i64, ArkaError> {
        validate_insert(title, username, encrypted_password)?;

        let now = current_unix_ts();
        self.conn.execute(
            "INSERT INTO passwords
             (title, username, category, website_url, note, encrypted_password, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                title,
                username,
                category,
                website_url,
                note,
                encrypted_password.as_bytes(),
                now,
                now
            ],
        )?;

        Ok(self.conn.last_insert_rowid())
    }

    /// Updates an existing credential row; returns an error when `id` is unknown.
    #[allow(clippy::too_many_arguments)]
    pub fn update_password(
        &self,
        id: i64,
        title: &str,
        username: &str,
        category: &str,
        website_url: Option<&str>,
        note: Option<&str>,
        encrypted_password: &EncryptedSecret,
    ) -> Result<(), ArkaError> {
        validate_insert(title, username, encrypted_password)?;

        let now = current_unix_ts();
        let updated = self.conn.execute(
            "UPDATE passwords
             SET title = ?1, username = ?2, category = ?3, website_url = ?4, note = ?5,
                 encrypted_password = ?6, updated_at = ?7
             WHERE id = ?8",
            params![
                title,
                username,
                category,
                website_url,
                note,
                encrypted_password.as_bytes(),
                now,
                id
            ],
        )?;

        if updated == 0 {
            return Err(ArkaError::CorruptVault {
                message: format!("password entry {id} not found"),
            });
        }

        Ok(())
    }

    /// Removes one credential row by primary key.
    pub fn delete_password_by_id(&self, id: i64) -> Result<(), ArkaError> {
        let deleted = self
            .conn
            .execute("DELETE FROM passwords WHERE id = ?1", params![id])?;
        if deleted == 0 {
            return Err(ArkaError::CorruptVault {
                message: format!("password entry {id} not found"),
            });
        }
        Ok(())
    }

    /// Lists all entries in insertion order; blobs remain encrypted.
    pub fn list_passwords(&self) -> Result<Vec<PasswordRecord>, ArkaError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, title, username, category, website_url, note,
                    encrypted_password, created_at, updated_at
             FROM passwords
             ORDER BY id ASC",
        )?;

        let rows = stmt.query_map([], decode_password_row)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(ArkaError::from)
    }

    /// Fetches one row by primary key — avoids listing/decrypting the entire vault for autofill.
    pub fn get_password_by_id(&self, id: i64) -> Result<Option<PasswordRecord>, ArkaError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, title, username, category, website_url, note,
                    encrypted_password, created_at, updated_at
             FROM passwords
             WHERE id = ?1",
        )?;
        let mut rows = stmt.query(params![id])?;
        let Some(row) = rows.next()? else {
            return Ok(None);
        };
        decode_password_row(row).map(Some).map_err(ArkaError::from)
    }

    /// Deletes every stored credential while preserving vault metadata (KDF salt).
    pub fn clear_all_passwords(&self) -> Result<(), ArkaError> {
        self.conn.execute("DELETE FROM passwords", [])?;
        Ok(())
    }

    /// Atomically replaces all password rows inside a single SQLite transaction.
    pub fn replace_all_passwords(&self, rows: &[StagedPasswordRow<'_>]) -> Result<(), ArkaError> {
        for row in rows {
            validate_insert(row.title, row.username, row.encrypted_password)?;
        }

        let tx = self.conn.unchecked_transaction()?;
        tx.execute("DELETE FROM passwords", [])?;

        for row in rows {
            tx.execute(
                "INSERT INTO passwords
                 (title, username, category, website_url, note, encrypted_password, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    row.title,
                    row.username,
                    row.category,
                    row.website_url,
                    row.note,
                    row.encrypted_password.as_bytes(),
                    row.created_at,
                    row.updated_at
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    fn read_kdf_salt(&self) -> Result<Option<KdfSalt>, ArkaError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM vault_meta WHERE key = ?1")?;
        let mut rows = stmt.query(params![schema::KDF_SALT_KEY])?;

        let Some(row) = rows.next()? else {
            return Ok(None);
        };

        decode_kdf_salt(row.get::<_, Vec<u8>>(0)?)
    }

    fn read_kdf_params(&self) -> Result<Option<KdfParams>, ArkaError> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM vault_meta WHERE key = ?1")?;
        let mut rows = stmt.query(params![schema::KDF_PARAMS_KEY])?;

        let Some(row) = rows.next()? else {
            return Ok(None);
        };

        let bytes: Vec<u8> = row.get(0)?;
        serde_json::from_slice(&bytes).map_err(|err| ArkaError::CorruptVault {
            message: format!("kdf params decode failed: {err}"),
        })
    }

    #[cfg_attr(not(target_os = "android"), allow(dead_code))]
    fn persist_kdf_params(&self, params: &KdfParams) -> Result<(), ArkaError> {
        let params_json = serde_json::to_vec(params).map_err(|err| ArkaError::CorruptVault {
            message: format!("kdf params encode failed: {err}"),
        })?;
        self.conn.execute(
            "INSERT OR REPLACE INTO vault_meta (key, value) VALUES (?1, ?2)",
            params![schema::KDF_PARAMS_KEY, params_json],
        )?;
        Ok(())
    }
}

fn current_unix_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn optional_text(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Exposed for vault API — normalizes optional metadata before persistence.
pub(crate) fn optional_metadata(value: &str) -> Option<&str> {
    optional_text(value)
}

/// Adds `category` to legacy vaults created before categorization shipped.
fn migrate_passwords_table(conn: &Connection) -> Result<(), ArkaError> {
    if passwords_has_column(conn, "category")? {
        return Ok(());
    }

    conn.execute(
        "ALTER TABLE passwords ADD COLUMN category TEXT NOT NULL DEFAULT ''",
        [],
    )?;
    Ok(())
}

/// Adds website URL, note, and audit timestamps to legacy vaults.
fn migrate_passwords_extended(conn: &Connection) -> Result<(), ArkaError> {
    let now = current_unix_ts();

    if !passwords_has_column(conn, "website_url")? {
        conn.execute("ALTER TABLE passwords ADD COLUMN website_url TEXT", [])?;
    }
    if !passwords_has_column(conn, "note")? {
        conn.execute("ALTER TABLE passwords ADD COLUMN note TEXT", [])?;
    }
    if !passwords_has_column(conn, "created_at")? {
        conn.execute(
            "ALTER TABLE passwords ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
        conn.execute(
            "UPDATE passwords SET created_at = ?1 WHERE created_at = 0",
            [now],
        )?;
    }
    if !passwords_has_column(conn, "updated_at")? {
        conn.execute(
            "ALTER TABLE passwords ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
        conn.execute(
            "UPDATE passwords SET updated_at = ?1 WHERE updated_at = 0",
            [now],
        )?;
    }

    Ok(())
}

fn passwords_has_column(conn: &Connection, column: &str) -> Result<bool, ArkaError> {
    let mut stmt = conn.prepare("PRAGMA table_info(passwords)")?;
    let mut rows = stmt.query([])?;

    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }

    Ok(false)
}

fn validate_insert(
    title: &str,
    username: &str,
    encrypted_password: &EncryptedSecret,
) -> Result<(), ArkaError> {
    require_non_empty(title, "title")?;
    require_non_empty(username, "username")?;
    if encrypted_password.as_bytes().is_empty() {
        return Err(ArkaError::empty_field("encrypted_password"));
    }
    Ok(())
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), ArkaError> {
    if value.trim().is_empty() {
        return Err(ArkaError::empty_field(field));
    }
    Ok(())
}

fn decode_kdf_salt(bytes: Vec<u8>) -> Result<Option<KdfSalt>, ArkaError> {
    if bytes.len() != SALT_SIZE {
        return Err(ArkaError::CorruptVault {
            message: format!("expected {SALT_SIZE}-byte KDF salt, found {}", bytes.len()),
        });
    }
    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&bytes);
    Ok(Some(KdfSalt::from_bytes(salt)))
}

fn decode_password_row(row: &Row<'_>) -> Result<PasswordRecord, rusqlite::Error> {
    Ok(PasswordRecord {
        id: row.get(0)?,
        title: row.get(1)?,
        username: row.get(2)?,
        category: row.get(3)?,
        website_url: row.get(4)?,
        note: row.get(5)?,
        encrypted_password: EncryptedSecret::from(row.get::<_, Vec<u8>>(6)?),
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_db() -> Result<VaultDatabase, ArkaError> {
        VaultDatabase::open(":memory:")
    }

    #[test]
    fn update_password_replaces_fields() -> Result<(), ArkaError> {
        let db = memory_db()?;
        let blob = EncryptedSecret::from(vec![0x01, 0x02]);
        let id = db.insert_password("Old", "old@x.com", "عمومی", None, None, &blob)?;

        let new_blob = EncryptedSecret::from(vec![0xAA, 0xBB]);
        db.update_password(
            id,
            "New",
            "new@x.com",
            "بانکی",
            Some("proton.me"),
            Some("work account"),
            &new_blob,
        )?;

        let records = db.list_passwords()?;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].title, "New");
        assert_eq!(records[0].username, "new@x.com");
        assert_eq!(records[0].category, "بانکی");
        assert_eq!(records[0].website_url.as_deref(), Some("proton.me"));
        assert_eq!(records[0].note.as_deref(), Some("work account"));
        assert_eq!(records[0].encrypted_password, new_blob);
        assert!(records[0].created_at > 0);
        assert!(records[0].updated_at >= records[0].created_at);
        Ok(())
    }

    #[test]
    fn open_yields_empty_vault() -> Result<(), ArkaError> {
        let db = memory_db()?;
        assert!(db.list_passwords()?.is_empty());
        Ok(())
    }

    #[test]
    fn insert_and_list_roundtrip() -> Result<(), ArkaError> {
        let db = memory_db()?;
        let blob = EncryptedSecret::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);

        let id = db.insert_password(
            "GitHub",
            "user@example.com",
            "کار",
            Some("github.com"),
            None,
            &blob,
        )?;
        let records = db.list_passwords()?;

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, id);
        assert_eq!(records[0].title, "GitHub");
        assert_eq!(records[0].website_url.as_deref(), Some("github.com"));
        assert_eq!(records[0].encrypted_password, blob);
        Ok(())
    }

    #[test]
    fn insert_rejects_empty_blob() -> Result<(), ArkaError> {
        let db = memory_db()?;
        match db.insert_password("Site", "user", "", None, None, &EncryptedSecret::from(vec![])) {
            Err(ArkaError::EmptyField { field }) if field == "encrypted_password" => Ok(()),
            Err(other) => panic!("unexpected error: {other}"),
            Ok(_) => panic!("empty blob must be rejected"),
        }
    }

    #[test]
    fn list_preserves_insertion_order() -> Result<(), ArkaError> {
        let db = memory_db()?;
        db.insert_password("First", "a", "", None, None, &EncryptedSecret::from(vec![1]))?;
        db.insert_password(
            "Second",
            "b",
            "شخصی",
            None,
            None,
            &EncryptedSecret::from(vec![2]),
        )?;

        let titles: Vec<_> = db.list_passwords()?.into_iter().map(|r| r.title).collect();
        assert_eq!(titles, vec!["First", "Second"]);
        Ok(())
    }

    #[test]
    fn legacy_schema_gains_extended_columns() -> Result<(), ArkaError> {
        let conn = Connection::open(":memory:")?;
        conn.execute_batch(
            "CREATE TABLE passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password BLOB NOT NULL
            );",
        )?;

        migrate_passwords_table(&conn)?;
        migrate_passwords_extended(&conn)?;
        assert!(passwords_has_column(&conn, "category")?);
        assert!(passwords_has_column(&conn, "website_url")?);
        assert!(passwords_has_column(&conn, "note")?);
        assert!(passwords_has_column(&conn, "created_at")?);
        assert!(passwords_has_column(&conn, "updated_at")?);

        Ok(())
    }

    #[test]
    fn replace_all_passwords_rolls_back_on_failure() -> Result<(), ArkaError> {
        let db = memory_db()?;
        db.insert_password("Keep", "user", "", None, None, &EncryptedSecret::from(vec![1]))?;

        let bad_rows = [StagedPasswordRow {
            title: "",
            username: "user",
            category: "",
            website_url: None,
            note: None,
            encrypted_password: &EncryptedSecret::from(vec![2]),
            created_at: 1,
            updated_at: 1,
        }];

        assert!(matches!(
            db.replace_all_passwords(&bad_rows),
            Err(ArkaError::EmptyField { .. })
        ));
        assert_eq!(db.list_passwords()?.len(), 1);
        assert_eq!(db.list_passwords()?[0].title, "Keep");

        Ok(())
    }

    #[test]
    fn ensure_kdf_salt_is_idempotent() -> Result<(), ArkaError> {
        let db = memory_db()?;
        let first = db.ensure_kdf_salt()?;
        let second = db.ensure_kdf_salt()?;
        assert_eq!(first.as_bytes(), second.as_bytes());
        Ok(())
    }
}
