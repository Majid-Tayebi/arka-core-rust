# 🚀 Arka Core (Rust)

> ⚡ High-performance, memory-safe security core for the **Arka** offline password manager.

---

## 🌍 Overview

**Arka Core** is the Rust foundation of [Arka](../README.md) — a production-oriented vault engine that powers the Android app with:

* ⚡ High performance on device
* 🔒 Strong cryptography and memory safety
* 🧩 Clean, testable module boundaries
* 🏦 Financial-grade reliability mindset (offline-first, no oracle leaks)

The Kotlin/Compose UI and platform integration live in [`../android/`](../android/). This crate compiles to `rust_lib_arka` and is consumed via JNI on Android (`jni_android.rs` → `.so`).

---

## 💡 Problem

Password managers and local-first apps often suffer from:

* 🌀 Crypto logic scattered across UI layers
* 🐛 Memory bugs and subtle concurrency issues in native code
* 🕳️ Weak error handling that leaks authentication hints
* 🐘 Backends or runtimes that are heavier than the problem requires

---

## ✅ Solution

Arka Core centralizes security-sensitive work in Rust:

* 🛡️ **Memory safety** without a GC — secrets are zeroized on drop
* 🧱 **Explicit modules** — crypto, storage, vault API, autofill matching
* 🧪 **Test-friendly** — unit tests for KDF, encryption, CRUD, backup round-trips
* 🔌 **JNI boundary** — Kotlin never handles raw keys or KDF parameters

---

## 🎯 Vision

A reliable **local-first security core** suitable for:

* 📴 Offline password vaults
* 📱 Mobile-native apps with Rust backends
* 🔍 Products that need audit-friendly crypto boundaries
* 🔄 Future sync / subscription verification layers (without trusting the UI)

---

## 🧠 Why Rust?

* 🛡 Memory safety without garbage collection
* ⚡ Performance comparable to C/C++ for crypto hot paths
* 🔁 Concurrency without data races (when used)
* 🧱 Compile-time guarantees and strong tooling (`clippy`, `cargo test`)

---

## 🏗 Architecture

Arka Core is modular rather than a monolith. Current layout:

```
rust/src/
├── crypto.rs          # Argon2id KDF, AES-256-GCM, key material newtypes
├── db.rs              # SQLite schema, migrations, encrypted rows
├── api/
│   ├── vault.rs       # Unlock session, CRUD, backup import/export
│   ├── autofill.rs    # Domain matching for Android Autofill
│   ├── generator.rs   # Cryptographic password generation
│   ├── audit.rs       # Security audit helpers
│   └── error.rs       # ArkaError — no password oracle
├── native_ffi.rs      # JSON/C helpers for JNI
└── jni_android.rs     # #[no_mangle] exports for Kotlin (Android only)
```

| Module | Role |
|--------|------|
| `crypto` | 🔐 Argon2id KDF, AES-256-GCM |
| `db` | 🗄 SQLite vault schema and migrations |
| `api/vault` | 🔑 Session, CRUD, backup import/export |
| `api/autofill` | 🌐 Domain matching for Android Autofill |
| `native_ffi` | 🔗 JSON/C FFI helpers for JNI |
| `jni_android` | 📲 JNI exports for `ArkaVaultNative.kt` |

Design principles: decoupled layers, replaceable storage, explicit errors, tests at the domain boundary.

---

## 🔐 Security & Reliability

* 🔑 Master password is **never** persisted; only derived keys live in RAM during an unlocked session.
* 🤐 Decryption failures collapse to `AuthenticationFailed` — no password oracle via error text.
* 🧹 Sensitive buffers use `zeroize` on drop.
* 🦀 Crypto stays in Rust; the Android app never runs KDF or holds long-lived master keys in Kotlin.

---

## ⚙️ Core Features

* 🔐 Argon2id + AES-256-GCM vault encryption
* 🗄 SQLite-backed encrypted credential store
* 💾 Encrypted backup export/import
* 🎲 Secure password generator
* 🌐 Autofill domain matching API
* ✅ Full test suite + Clippy `-D warnings`

---

## 🛠 Tech Stack

| | |
|---|---|
| **Language** | 🦀 Rust (2021 edition) |
| **Storage** | 🗄 SQLite (`rusqlite`, bundled) |
| **KDF** | 🔐 Argon2id |
| **AEAD** | 🛡 AES-256-GCM |
| **Android bridge** | 📲 JNI (`jni` crate) |
| **Build on Android** | 🔧 [Cargokit](https://github.com/irondash/cargokit) via Gradle |

---

## 📦 Getting Started

```bash
cd rust
cargo test
cargo clippy -- -D warnings
```

Android builds compile this crate automatically when you sync Gradle in `../android/`.

```bash
cd ../android
./gradlew :app:assembleDebug
```

> ℹ️ There is no standalone `cargo run` entry point — this library is embedded in the mobile app.

---

## 🧪 Development Philosophy

* ✨ Simplicity over complexity
* 📖 Explicit over implicit
* ⚡ Performance as a feature where crypto matters
* 🔒 Security by default — fail closed, no oracle errors

---

## 🗺 Roadmap

* [ ] 📦 Hardened backup format versioning
* [ ] 🔄 Optional sync engine (local-first, conflict-safe)
* [ ] 💳 Server-side purchase verification adapter (Bazaar / payment gateways)
* [ ] 🔍 Expanded audit and breach-check hooks
* [ ] 🖥 Desktop / iOS FFI surfaces (non-JNI)

---

## 🤝 Contribution

We welcome contributions! 🙌

* 💬 Open issues
* 💡 Suggest improvements
* 🔀 Submit pull requests

Follow the repo-wide standards in [`.cursor/rules/`](../.cursor/rules/) — no `unwrap()` in production Rust, propagate `Result<T, ArkaError>`.

---

## 📄 License

[MIT](LICENSE) — Copyright (c) 2026 Majid Tayebi

---

# 🇮🇷 نسخه فارسی

## 🚀 معرفی

**Arka Core** هسته امنیتی Rust برای **آرکا** — گاوصندوق رمز آفلاین — است. تمام عملیات حساس (KDF، رمزنگاری، SQLite، پشتیبان) در این لایه انجام می‌شود و اپ اندروید از طریق JNI با آن صحبت می‌کند.

---

## 💡 مسئله

در بسیاری از اپ‌های مشابه:

* 🌀 منطق رمزنگاری داخل UI پخش می‌شود
* 🐛 باگ حافظه و خطاهای concurrency در کد native رخ می‌دهد
* 🕳️ پیام خطا به کاربر سرنخ درباره رمز اشتباه می‌دهد (oracle)

---

## ✅ راه‌حل

Arka Core با Rust:

* 🛡️ ایمنی حافظه و **zeroize** برای داده حساس
* 🧱 معماری ماژولار و قابل تست
* 🔌 مرز JNI — Kotlin کلید خام یا KDF را اجرا نمی‌کند
* 🤐 خطای یکسان برای شکست احراز هویت

---

## 🎯 هدف

ساخت یک **هسته پایدار و production-ready** برای:

* 📴 گاوصندوق رمز آفلاین
* 📱 اپ موبایل با لایه امنیتی Rust
* 🔄 محصولات local-first

---

## 🏗 معماری

| ماژول | نقش |
|--------|------|
| `crypto` | 🔐 Argon2id، AES-256-GCM |
| `db` | 🗄 SQLite و migration |
| `api/vault` | 🔑 session، CRUD، پشتیبان |
| `api/autofill` | 🌐 تطبیق دامنه برای Autofill |
| `jni_android` | 📲 پل JNI برای Kotlin |

---

## 🔐 امنیت

* 🔑 رمز اصلی ذخیره نمی‌شود؛ فقط کلید مشتق‌شده در RAM (در session باز)
* 🤐 شکست رمزگشایی → `AuthenticationFailed` بدون افشای جزئیات
* 🧹 `zeroize` برای بافرهای حساس

---

## 📦 شروع توسعه

```bash
cd rust
cargo test
cargo clippy -- -D warnings
```

بیلد اندروید به‌صورت خودکار این crate را کامپایل می‌کند:

```bash
cd ../android
./gradlew :app:assembleDebug
```

---

## 🗺 نقشه راه

* 📦 نسخه‌بندی فرمت پشتیبان
* 🔄 موتور sync (local-first)
* 💳 تأیید خرید (کافه‌بازار و درگاه‌ها)
* 🖥 سطح FFI برای پلتفرم‌های دیگر

---

## 🤝 مشارکت و لایسنس

مشارکت شما پروژه را بهتر می‌کند 🙌 — لایسنس: [MIT](LICENSE).

---

## 🌟 حمایت

If this project helps you, give the repo a ⭐!
