# Arka Rust Core

Cryptography and encrypted storage for the Arka password manager.

Consumed by the native Android app via JNI (`rust/src/jni_android.rs` → `rust_lib_arka.so`). UI and platform integration live in `../android/`.

## Layout

| Module | Role |
|--------|------|
| `crypto` | Argon2id KDF, AES-256-GCM |
| `db` | SQLite vault schema and migrations |
| `api/vault` | Session, CRUD, backup import/export |
| `api/autofill` | Domain matching for Android Autofill |
| `native_ffi` | JSON/C FFI helpers for JNI |
| `jni_android` | `#[no_mangle]` exports for Kotlin |

## Development

```bash
cargo test
cargo clippy -- -D warnings
```

## Threat model (summary)

- Master password never persisted in Rust; only derived keys in RAM during an unlocked session.
- Decryption failures map to `AuthenticationFailed` — no password oracle via error text.
- Secrets use `zeroize` on drop.

See the root [README](../README.md) for Android build instructions.
