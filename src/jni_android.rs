//! JNI exports for the Android autofill service — no Flutter runtime required.

use std::panic::{catch_unwind, AssertUnwindSafe, UnwindSafe};

use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jint, jlong, jstring, jbyteArray};
use jni::JNIEnv;

use crate::native_ffi::{self, ArkaFfiStatus};
use crate::ArkaError;

fn jstring_to_string(env: &mut JNIEnv, value: &JString) -> Option<String> {
    env.get_string(value).ok().map(|s| s.into())
}

fn status_ok() -> jint {
    native_ffi::set_last_ffi_status(ArkaFfiStatus::Ok);
    ArkaFfiStatus::Ok as jint
}

fn status_from_error(err: ArkaError) -> jint {
    let status = ArkaFfiStatus::from(err);
    native_ffi::set_last_ffi_status(status);
    status as jint
}

fn status_invalid_input() -> jint {
    native_ffi::set_last_ffi_status(ArkaFfiStatus::InvalidInput);
    ArkaFfiStatus::InvalidInput as jint
}

fn status_panic() -> jint {
    native_ffi::set_last_ffi_status(ArkaFfiStatus::Other);
    ArkaFfiStatus::Other as jint
}

/// Catches Rust panics at the JNI boundary so `panic = "abort"` cannot kill the JVM.
fn guard_jint(f: impl FnOnce() -> jint + UnwindSafe) -> jint {
    match catch_unwind(f) {
        Ok(code) => code,
        Err(_) => status_panic(),
    }
}

fn guard_jlong(f: impl FnOnce() -> jlong + UnwindSafe) -> jlong {
    match catch_unwind(f) {
        Ok(id) => id,
        Err(_) => {
            status_panic();
            -1
        }
    }
}

fn guard_jstring(f: impl FnOnce() -> jstring + UnwindSafe) -> jstring {
    match catch_unwind(f) {
        Ok(ptr) => ptr,
        Err(_) => {
            status_panic();
            std::ptr::null_mut()
        }
    }
}

fn guard_jbytearray(f: impl FnOnce() -> jbyteArray + UnwindSafe) -> jbyteArray {
    match catch_unwind(f) {
        Ok(ptr) => ptr,
        Err(_) => {
            status_panic();
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_arkavault_secure_ArkaVaultNative_vaultExists(
    mut env: JNIEnv,
    _class: JClass,
    db_path: JString,
) -> jint {
    let Some(path) = jstring_to_string(&mut env, &db_path) else {
        return 0;
    };
    i32::from(native_ffi::vault_file_exists(&path))
}

#[no_mangle]
pub extern "system" fn Java_com_arkavault_secure_ArkaVaultNative_initVault(
    mut env: JNIEnv,
    _class: JClass,
    db_path: JString,
) -> jint {
    let Some(path) = jstring_to_string(&mut env, &db_path) else {
        return status_invalid_input();
    };
    guard_jint(|| match native_ffi::init_vault(&path) {
        Ok(()) => status_ok(),
        Err(err) => status_from_error(err),
    })
}

#[no_mangle]
pub extern "system" fn Java_com_arkavault_secure_ArkaVaultNative_lockVault(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    guard_jint(|| match native_ffi::lock_vault_session() {
        Ok(()) => status_ok(),
        Err(err) => status_from_error(err),
    })
}

#[no_mangle]
pub extern "system" fn Java_com_arkavault_secure_ArkaVaultNative_getLastFfiStatus(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    native_ffi::last_ffi_status() as jint
}

#[no_mangle]
pub extern "system" fn Java_com_arkavault_secure_ArkaVaultNative_getAutofillCandidatesJson(
    mut env: JNIEnv,
    _class: JClass,
    db_path: JString,
    master_password: JString,
    origin: JString,
) -> jstring {
    let Some(path) = jstring_to_string(&mut env, &db_path) else {
        status_invalid_input();
        return std::ptr::null_mut();
    };
    let Some(master) = jstring_to_string(&mut env, &master_password) else {
        status_invalid_input();
        return std::ptr::null_mut();
    };
    let origin = jstring_to_string(&mut env, &origin).unwrap_or_default();

    guard_jstring(|| match native_ffi::get_candidates_json(&path, &master, &origin) {
        Ok(json) => {
            native_ffi::set_last_ffi_status(ArkaFfiStatus::Ok);
            env.new_string(json)
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut())
        }
        Err(err) => {
            status_from_error(err);
            std::ptr::null_mut()
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_arkavault_secure_ArkaVaultNative_getAutofillEntryJson(
    mut env: JNIEnv,
    _class: JClass,
    db_path: JString,
    master_password: JString,
    entry_id: jlong,
) -> jstring {
    let Some(path) = jstring_to_string(&mut env, &db_path) else {
        status_invalid_input();
        return std::ptr::null_mut();
    };
    let Some(master) = jstring_to_string(&mut env, &master_password) else {
        status_invalid_input();
        return std::ptr::null_mut();
    };

    guard_jstring(|| match native_ffi::get_entry_json(&path, &master, entry_id) {
        Ok(json) => {
            native_ffi::set_last_ffi_status(ArkaFfiStatus::Ok);
            env.new_string(json)
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut())
        }
        Err(err) => {
            status_from_error(err);
            std::ptr::null_mut()
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_arkavault_secure_ArkaVaultNative_exportSessionKey(
    mut env: JNIEnv,
    _class: JClass,
    db_path: JString,
    master_password: JString,
) -> jbyteArray {
    let Some(path) = jstring_to_string(&mut env, &db_path) else {
        status_invalid_input();
        return std::ptr::null_mut();
    };
    let Some(master) = jstring_to_string(&mut env, &master_password) else {
        status_invalid_input();
        return std::ptr::null_mut();
    };

    guard_jbytearray(|| {
        match native_ffi::export_session_key(&path, &master) {
            Ok(key) => {
                native_ffi::set_last_ffi_status(ArkaFfiStatus::Ok);
                env.byte_array_from_slice(&key)
                    .map(|arr| arr.into_raw())
                    .unwrap_or(std::ptr::null_mut())
            }
            Err(err) => {
                status_from_error(err);
                std::ptr::null_mut()
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_arkavault_secure_ArkaVaultNative_installSessionKey(
    mut env: JNIEnv,
    _class: JClass,
    db_path: JString,
    session_key: JByteArray,
) -> jint {
    let Some(path) = jstring_to_string(&mut env, &db_path) else {
        return status_invalid_input();
    };
    let Ok(bytes) = env.convert_byte_array(&session_key) else {
        return status_invalid_input();
    };
    if bytes.len() != crate::crypto::KEY_SIZE {
        return status_invalid_input();
    }
    let mut key = [0u8; crate::crypto::KEY_SIZE];
    key.copy_from_slice(&bytes);

    guard_jint(|| match native_ffi::install_session_key(&path, &key) {
        Ok(()) => status_ok(),
        Err(err) => status_from_error(err),
    })
}

#[no_mangle]
pub extern "system" fn Java_com_arkavault_secure_ArkaVaultNative_getAutofillEntryJsonFast(
    mut env: JNIEnv,
    _class: JClass,
    db_path: JString,
    entry_id: jlong,
) -> jstring {
    let Some(path) = jstring_to_string(&mut env, &db_path) else {
        status_invalid_input();
        return std::ptr::null_mut();
    };

    guard_jstring(|| match native_ffi::get_entry_json_fast(&path, entry_id) {
        Ok(json) => {
            native_ffi::set_last_ffi_status(ArkaFfiStatus::Ok);
            env.new_string(json)
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut())
        }
        Err(err) => {
            status_from_error(err);
            std::ptr::null_mut()
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_arkavault_secure_ArkaVaultNative_addPassword(
    mut env: JNIEnv,
    _class: JClass,
    db_path: JString,
    master_password: JString,
    title: JString,
    username: JString,
    password: JString,
    website_url: JString,
    note: JString,
    category: JString,
) -> jlong {
    let Some(path) = jstring_to_string(&mut env, &db_path) else {
        status_invalid_input();
        return -1;
    };
    let Some(master) = jstring_to_string(&mut env, &master_password) else {
        status_invalid_input();
        return -1;
    };
    let Some(title) = jstring_to_string(&mut env, &title) else {
        status_invalid_input();
        return -1;
    };
    let Some(username) = jstring_to_string(&mut env, &username) else {
        status_invalid_input();
        return -1;
    };
    let Some(password) = jstring_to_string(&mut env, &password) else {
        status_invalid_input();
        return -1;
    };
    let website = jstring_to_string(&mut env, &website_url).unwrap_or_default();
    let note = jstring_to_string(&mut env, &note).unwrap_or_default();
    let category = jstring_to_string(&mut env, &category).unwrap_or_default();

    guard_jlong(|| {
        match native_ffi::add_credential(
            &path, &master, &title, &username, &category, &password, &website, &note,
        ) {
            Ok(id) => {
                native_ffi::set_last_ffi_status(ArkaFfiStatus::Ok);
                id
            }
            Err(err) => {
                status_from_error(err);
                -1
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_arkavault_secure_ArkaVaultNative_getAllEntriesJson(
    mut env: JNIEnv,
    _class: JClass,
    db_path: JString,
    master_password: JString,
) -> jstring {
    let Some(path) = jstring_to_string(&mut env, &db_path) else {
        status_invalid_input();
        return std::ptr::null_mut();
    };
    let Some(master) = jstring_to_string(&mut env, &master_password) else {
        status_invalid_input();
        return std::ptr::null_mut();
    };

    guard_jstring(|| match native_ffi::get_all_entries_json(&path, &master) {
        Ok(json) => {
            native_ffi::set_last_ffi_status(ArkaFfiStatus::Ok);
            env.new_string(json)
                .map(|s| s.into_raw())
                .unwrap_or(std::ptr::null_mut())
        }
        Err(err) => {
            status_from_error(err);
            std::ptr::null_mut()
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_arkavault_secure_ArkaVaultNative_updatePassword(
    mut env: JNIEnv,
    _class: JClass,
    db_path: JString,
    master_password: JString,
    id: jlong,
    title: JString,
    username: JString,
    category: JString,
    password: JString,
    website_url: JString,
    note: JString,
) -> jint {
    let Some(path) = jstring_to_string(&mut env, &db_path) else {
        return status_invalid_input();
    };
    let Some(master) = jstring_to_string(&mut env, &master_password) else {
        return status_invalid_input();
    };
    let Some(title) = jstring_to_string(&mut env, &title) else {
        return status_invalid_input();
    };
    let Some(username) = jstring_to_string(&mut env, &username) else {
        return status_invalid_input();
    };
    let Some(category) = jstring_to_string(&mut env, &category) else {
        return status_invalid_input();
    };
    let Some(password) = jstring_to_string(&mut env, &password) else {
        return status_invalid_input();
    };
    let website = jstring_to_string(&mut env, &website_url).unwrap_or_default();
    let note = jstring_to_string(&mut env, &note).unwrap_or_default();

    guard_jint(|| {
        match native_ffi::update_credential(
            &path, &master, id, &title, &username, &category, &password, &website, &note,
        ) {
            Ok(()) => status_ok(),
            Err(err) => status_from_error(err),
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_arkavault_secure_ArkaVaultNative_generatePassword(
    mut env: JNIEnv,
    _class: JClass,
    length: jint,
    use_uppercase: jboolean,
    use_lowercase: jboolean,
    use_numbers: jboolean,
    use_special: jboolean,
) -> jstring {
    guard_jstring(|| {
        match native_ffi::generate_password_string(
            length as u32,
            use_uppercase != 0,
            use_lowercase != 0,
            use_numbers != 0,
            use_special != 0,
        ) {
            Ok(password) => {
                native_ffi::set_last_ffi_status(ArkaFfiStatus::Ok);
                env.new_string(password)
                    .map(|s| s.into_raw())
                    .unwrap_or(std::ptr::null_mut())
            }
            Err(err) => {
                status_from_error(err);
                std::ptr::null_mut()
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_arkavault_secure_ArkaVaultNative_exportVaultBackup(
    mut env: JNIEnv,
    _class: JClass,
    db_path: JString,
    master_password: JString,
) -> jbyteArray {
    let Some(path) = jstring_to_string(&mut env, &db_path) else {
        status_invalid_input();
        return std::ptr::null_mut();
    };
    let Some(master) = jstring_to_string(&mut env, &master_password) else {
        status_invalid_input();
        return std::ptr::null_mut();
    };

    match native_ffi::export_backup(&path, &master) {
        Ok(bytes) => env.byte_array_from_slice(&bytes).map_or_else(
            |_| {
                status_from_error(ArkaError::Database {
                    message: "jni byte array alloc failed".into(),
                });
                std::ptr::null_mut()
            },
            |array| {
                native_ffi::set_last_ffi_status(ArkaFfiStatus::Ok);
                array.into_raw()
            },
        ),
        Err(err) => {
            status_from_error(err);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_arkavault_secure_ArkaVaultNative_importVaultBackup(
    mut env: JNIEnv,
    _class: JClass,
    db_path: JString,
    master_password: JString,
    backup: JByteArray,
) -> jint {
    let Some(path) = jstring_to_string(&mut env, &db_path) else {
        return status_invalid_input();
    };
    let Some(master) = jstring_to_string(&mut env, &master_password) else {
        return status_invalid_input();
    };

    let Ok(len) = env.get_array_length(&backup) else {
        return status_invalid_input();
    };
    if len <= 0 {
        return status_invalid_input();
    }
    let mut buf = vec![0i8; len as usize];
    if env.get_byte_array_region(&backup, 0, &mut buf).is_err() {
        return status_invalid_input();
    }
    let bytes: Vec<u8> = buf.into_iter().map(|b| b as u8).collect();

    guard_jint(|| match native_ffi::import_backup(&path, &bytes, &master) {
        Ok(()) => status_ok(),
        Err(err) => status_from_error(err),
    })
}
