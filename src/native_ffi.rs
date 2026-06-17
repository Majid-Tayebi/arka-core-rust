//! C/JNI-facing vault operations for the Android autofill service.
//!
//! Cryptography remains in [`crate::api::vault`] — this module only marshals
//! strings and JSON across the FFI boundary.

#![cfg_attr(not(target_os = "android"), allow(dead_code))]

use std::ffi::{c_char, CStr, CString};
use std::os::raw::c_int;
use std::sync::atomic::{AtomicI32, Ordering};

use serde::Serialize;

use crate::api::autofill;
use crate::api::generator::{generate_password, GeneratorOptions};
use crate::api::vault::{self, DecryptedPasswordEntry};
use crate::ArkaError;

/// FFI status codes — stable across Kotlin and Rust releases.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArkaFfiStatus {
    Ok = 0,
    InvalidInput = 1,
    VaultNotInitialized = 2,
    AuthenticationFailed = 3,
    Database = 4,
    CorruptVault = 5,
    EmptyField = 6,
    /// OS CSPRNG refused entropy — vault salt/nonce generation cannot proceed safely.
    RandomnessUnavailable = 7,
    Other = 99,
}

static LAST_FFI_STATUS: AtomicI32 = AtomicI32::new(ArkaFfiStatus::Ok as i32);

/// Records the outcome of the most recent JNI/C FFI call (for string-returning APIs).
pub fn set_last_ffi_status(status: ArkaFfiStatus) {
    LAST_FFI_STATUS.store(status as i32, Ordering::Release);
}

/// Returns the status recorded by the most recent JNI/C FFI call.
pub fn last_ffi_status() -> ArkaFfiStatus {
    match LAST_FFI_STATUS.load(Ordering::Acquire) {
        0 => ArkaFfiStatus::Ok,
        1 => ArkaFfiStatus::InvalidInput,
        2 => ArkaFfiStatus::VaultNotInitialized,
        3 => ArkaFfiStatus::AuthenticationFailed,
        4 => ArkaFfiStatus::Database,
        5 => ArkaFfiStatus::CorruptVault,
        6 => ArkaFfiStatus::EmptyField,
        7 => ArkaFfiStatus::RandomnessUnavailable,
        99 => ArkaFfiStatus::Other,
        _ => ArkaFfiStatus::Other,
    }
}

impl From<ArkaError> for ArkaFfiStatus {
    fn from(err: ArkaError) -> Self {
        match err {
            ArkaError::VaultNotInitialized => Self::VaultNotInitialized,
            ArkaError::AuthenticationFailed => Self::AuthenticationFailed,
            ArkaError::Database { .. } => Self::Database,
            ArkaError::CorruptVault { .. } => Self::CorruptVault,
            ArkaError::EmptyField { .. } => Self::EmptyField,
            ArkaError::RandomnessUnavailable => Self::RandomnessUnavailable,
            _ => Self::Other,
        }
    }
}

#[derive(Serialize)]
struct AutofillCredentialJson {
    id: i64,
    title: String,
    username: String,
    password: String,
}

#[derive(Serialize)]
struct VaultEntryJson {
    id: i64,
    title: String,
    username: String,
    category: String,
    password: String,
    website_url: String,
    note: String,
    created_at: i64,
    updated_at: i64,
}

impl From<DecryptedPasswordEntry> for AutofillCredentialJson {
    fn from(entry: DecryptedPasswordEntry) -> Self {
        Self {
            id: entry.id,
            title: entry.title,
            username: entry.username,
            password: entry.password.as_str().to_string(),
        }
    }
}

/// # Safety
///
/// `ptr` must be null or a valid NUL-terminated UTF-8 C string for the duration of the call.
unsafe fn read_str<'a>(ptr: *const c_char) -> Result<&'a str, ArkaFfiStatus> {
    if ptr.is_null() {
        return Err(ArkaFfiStatus::InvalidInput);
    }
    CStr::from_ptr(ptr)
        .to_str()
        .map_err(|_| ArkaFfiStatus::InvalidInput)
        .and_then(|s| {
            if s.trim().is_empty() {
                Err(ArkaFfiStatus::EmptyField)
            } else {
                Ok(s)
            }
        })
}

fn to_c_string(value: String) -> *mut c_char {
    CString::new(value)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

pub(crate) fn init_vault(db_path: &str) -> Result<(), ArkaError> {
    vault::init_database(db_path.to_string())
}

/// Releases the in-memory Rust vault session (keys + DB handle).
pub(crate) fn lock_vault_session() -> Result<(), ArkaError> {
    vault::lock_vault()
}

/// 32-byte session key for Android Keystore sealing — only after master unlock.
pub(crate) fn export_session_key(
    db_path: &str,
    master_password: &str,
) -> Result<[u8; crate::crypto::KEY_SIZE], ArkaError> {
    vault::export_session_key(db_path.to_string(), master_password.to_string())
}

pub(crate) fn install_session_key(
    db_path: &str,
    key_bytes: &[u8; crate::crypto::KEY_SIZE],
) -> Result<(), ArkaError> {
    vault::install_session_key(db_path.to_string(), *key_bytes)
}

pub(crate) fn get_entry_json_fast(db_path: &str, entry_id: i64) -> Result<String, ArkaError> {
    vault::init_database(db_path.to_string())?;
    let entry = vault::get_entry_by_id_fast(db_path.to_string(), entry_id)?;
    let Some(entry) = entry else {
        return Ok(String::from("null"));
    };
    serde_json::to_string(&AutofillCredentialJson::from(entry)).map_err(|err| {
        ArkaError::CorruptVault {
            message: format!("autofill entry json encode failed: {err}"),
        }
    })
}

impl From<DecryptedPasswordEntry> for VaultEntryJson {
    fn from(entry: DecryptedPasswordEntry) -> Self {
        Self {
            id: entry.id,
            title: entry.title,
            username: entry.username,
            category: entry.category,
            password: entry.password.as_str().to_string(),
            website_url: entry.website_url,
            note: entry.note,
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        }
    }
}

pub(crate) fn get_all_entries_json(
    db_path: &str,
    master_password: &str,
) -> Result<String, ArkaError> {
    vault::init_database(db_path.to_string())?;
    let entries = vault::get_all_entries(db_path.to_string(), master_password.to_string())?;
    let payload: Vec<VaultEntryJson> = entries.into_iter().map(Into::into).collect();
    serde_json::to_string(&payload).map_err(|err| ArkaError::CorruptVault {
        message: format!("entries json encode failed: {err}"),
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn update_credential(
    db_path: &str,
    master_password: &str,
    id: i64,
    title: &str,
    username: &str,
    category: &str,
    password: &str,
    website_url: &str,
    note: &str,
) -> Result<(), ArkaError> {
    vault::init_database(db_path.to_string())?;
    vault::update_password(
        id,
        title.to_string(),
        username.to_string(),
        category.to_string(),
        password.to_string(),
        master_password.to_string(),
        website_url.to_string(),
        note.to_string(),
    )
}

pub(crate) fn get_candidates_json(
    db_path: &str,
    master_password: &str,
    origin: &str,
) -> Result<String, ArkaError> {
    vault::init_database(db_path.to_string())?;
    let entries = vault::get_all_entries(db_path.to_string(), master_password.to_string())?;
    let filtered = autofill::filter_for_origin(entries, origin);
    let payload: Vec<AutofillCredentialJson> = filtered.into_iter().map(Into::into).collect();
    serde_json::to_string(&payload).map_err(|err| ArkaError::CorruptVault {
        message: format!("autofill json encode failed: {err}"),
    })
}

/// Single-entry autofill JSON — skips full-vault decrypt when [entry_id] is known from the UI.
pub(crate) fn get_entry_json(
    db_path: &str,
    master_password: &str,
    entry_id: i64,
) -> Result<String, ArkaError> {
    vault::init_database(db_path.to_string())?;
    let entry = vault::get_entry_by_id(
        db_path.to_string(),
        master_password.to_string(),
        entry_id,
    )?;
    let Some(entry) = entry else {
        return Ok(String::from("null"));
    };
    serde_json::to_string(&AutofillCredentialJson::from(entry)).map_err(|err| {
        ArkaError::CorruptVault {
            message: format!("autofill entry json encode failed: {err}"),
        }
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_credential(
    db_path: &str,
    master_password: &str,
    title: &str,
    username: &str,
    category: &str,
    password: &str,
    website_url: &str,
    note: &str,
) -> Result<i64, ArkaError> {
    vault::init_database(db_path.to_string())?;
    vault::add_password(
        title.to_string(),
        username.to_string(),
        category.to_string(),
        password.to_string(),
        master_password.to_string(),
        website_url.to_string(),
        note.to_string(),
    )
}

pub(crate) fn vault_file_exists(db_path: &str) -> bool {
    std::path::Path::new(db_path).is_file()
}

pub(crate) fn generate_password_string(
    length: u32,
    use_uppercase: bool,
    use_lowercase: bool,
    use_numbers: bool,
    use_special: bool,
) -> Result<String, ArkaError> {
    generate_password(GeneratorOptions {
        length,
        use_uppercase,
        use_lowercase,
        use_numbers,
        use_special,
    })
}

pub(crate) fn export_backup(db_path: &str, master_password: &str) -> Result<Vec<u8>, ArkaError> {
    vault::init_database(db_path.to_string())?;
    vault::export_vault_backup(master_password.to_string())
}

pub(crate) fn import_backup(
    db_path: &str,
    bytes: &[u8],
    master_password: &str,
) -> Result<(), ArkaError> {
    vault::init_database(db_path.to_string())?;
    vault::import_vault_backup(bytes.to_vec(), master_password.to_string())
}

/// Frees a heap string returned by [`arka_autofill_get_candidates`].
///
/// # Safety
///
/// `ptr` must be null or a pointer previously produced by this crate's FFI
/// allocators and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn arka_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    drop(CString::from_raw(ptr));
}

/// # Safety
///
/// `db_path` must be null or a valid NUL-terminated UTF-8 path string.
#[no_mangle]
pub unsafe extern "C" fn arka_vault_exists(db_path: *const c_char) -> c_int {
    match read_str(db_path) {
        Ok(path) => i32::from(vault_file_exists(path)),
        Err(_) => 0,
    }
}

/// # Safety
///
/// `db_path` must be null or a valid NUL-terminated UTF-8 path string.
#[no_mangle]
pub unsafe extern "C" fn arka_init_vault(db_path: *const c_char) -> c_int {
    match read_str(db_path).and_then(|path| {
        init_vault(path).map_err(ArkaFfiStatus::from)
    }) {
        Ok(()) => {
            set_last_ffi_status(ArkaFfiStatus::Ok);
            ArkaFfiStatus::Ok as c_int
        }
        Err(code) => {
            set_last_ffi_status(code);
            code as c_int
        }
    }
}

/// Returns a JSON array of `{id,title,username,password}` or null on failure.
/// Caller must free with [`arka_string_free`].
///
/// # Safety
///
/// All pointer arguments must be null or valid NUL-terminated UTF-8 C strings.
#[no_mangle]
pub unsafe extern "C" fn arka_autofill_get_candidates(
    db_path: *const c_char,
    master_password: *const c_char,
    origin: *const c_char,
) -> *mut c_char {
    let result = (|| {
        let path = read_str(db_path)?;
        let master = read_str(master_password)?;
        let origin = read_str(origin).unwrap_or("");
        get_candidates_json(path, master, origin).map_err(ArkaFfiStatus::from)
    })();

    match result {
        Ok(json) => {
            set_last_ffi_status(ArkaFfiStatus::Ok);
            to_c_string(json)
        }
        Err(code) => {
            set_last_ffi_status(code);
            std::ptr::null_mut()
        }
    }
}

/// # Safety
///
/// All pointer arguments must be null or valid NUL-terminated UTF-8 C strings.
/// `website_url` may be null (treated as empty).
#[no_mangle]
pub unsafe extern "C" fn arka_autofill_add_password(
    db_path: *const c_char,
    master_password: *const c_char,
    title: *const c_char,
    username: *const c_char,
    password: *const c_char,
    website_url: *const c_char,
) -> i64 {
    let result = (|| {
        let path = read_str(db_path)?;
        let master = read_str(master_password)?;
        let title = read_str(title)?;
        let username = read_str(username)?;
        let password = read_str(password)?;
        let website = if website_url.is_null() {
            ""
        } else {
            read_str(website_url).unwrap_or("")
        };
        add_credential(path, master, title, username, "", password, website, "")
            .map_err(ArkaFfiStatus::from)
    })();

    match result {
        Ok(id) => {
            set_last_ffi_status(ArkaFfiStatus::Ok);
            id
        }
        Err(code) => {
            set_last_ffi_status(code);
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ArkaError;

    #[test]
    fn vault_exists_false_for_missing_path() {
        assert_eq!(vault_file_exists("/no/such/arka_vault.db"), false);
    }

    #[test]
    fn randomness_unavailable_maps_to_dedicated_status() {
        assert_eq!(
            ArkaFfiStatus::from(ArkaError::RandomnessUnavailable),
            ArkaFfiStatus::RandomnessUnavailable
        );
    }
}
