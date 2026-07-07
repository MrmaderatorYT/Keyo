# Keyo — Zero-Knowledge Password Manager

A completely free Android app (API 26+, pure Java) for storing passwords with synchronization via Firebase Firestore, which **cannot** decrypt your data.

## Zero-Knowledge Architecture

```
 User Device                                   │  Firebase (Server)
                                               │
 Master Password (char[], RAM only)            │  ✗ never transmitted
        │ Argon2id (salt, 32 MiB, t=3)         │
        ▼                                      │
 Master Key AES-256 (RAM only, until           │  ✗ never transmitted
 auto-lock)                                    │
        │ AES-256-GCM, unique IV               │
        ▼                                      │
 Field ciphertexts  ────── sync ─────────────▶ │  ✓ stored (unreadable)
 KDF salt, parameters, verifier ─────────────▶ │  ✓ stored (not secret)
```

- **Firebase account password ≠ master password.** The first one only unlocks access to synchronization; the second encrypts the data and never leaves the device.
- **Verifier** — ciphertext of a known constant. Allows checking the master password locally (GCM tag matches → password is correct), without storing the password or its hash.
- Forgot the master password → data recovery is **impossible**. This is the price of Zero-Knowledge.

## Code Structure

| Layer | Files |
|---|---|
| Crypto Core | `crypto/KeyoCryptographer.java` — Argon2id (Bouncy Castle, pure Java) + AES-256-GCM |
| Session | `session/SessionManager.java` — key in RAM, 2 min auto-lock |
| Models | `model/PasswordEntry.java`, `model/VaultProfile.java` |
| Firebase | `firebase/FirebaseManager.java` — Auth + Firestore (ciphertexts only) |
| UI | `ui/LoginActivity`, `ui/SetupActivity`, `ui/MainActivity`, `ui/DetailActivity`, `ui/PasswordEntryAdapter`, `ui/BaseSecureActivity` (FLAG_SECURE + auto-lock) |
| Utils | `util/PasswordStrengthChecker.java`, `util/LocalVaultStore.java` |

## Firebase Setup (required before launch)

1. Create a project at [console.firebase.google.com](https://console.firebase.google.com).
2. Add an Android app with the package name **`com.ccs.keyo`**.
3. Download `google-services.json` and place it in **`app/`**.
   (The project compiles without this file, but Firebase won't work — the google-services plugin is applied conditionally, see `app/build.gradle`.)
4. In the **Authentication → Sign-in method** section, enable **Email/Password**.
5. Create a **Firestore** database and publish the rules from the [`firestore.rules`](firestore.rules) file (Firestore → Rules).

## Build

```bash
./gradlew assembleDebug
# APK: app/build/outputs/apk/debug/app-debug.apk
```

## Implemented Security Mechanisms

- **Argon2id** (Bouncy Castle, without NDK): 32 MiB memory, 3 iterations — parameters are stored in the profile, so they can be strengthened without migration.
- **AES-256-GCM** with a random 12-byte IV for each operation (authenticated encryption: ciphertext substitution → exception).
- **FLAG_SECURE** on all screens: no screenshots, screen recording, and previews in "recent apps".
- **Auto-lock** after 2 minutes of inactivity (`SessionManager.AUTO_LOCK_TIMEOUT_MS`), the key in memory is wiped.
- Password in the clipboard is marked as sensitive (API 33+) and cleared after 30 s.
- `allowBackup=false` — local cache is not included in Android backups.
- Wiping `char[]`/`byte[]` after use (best-effort within JVM limits).

## Known Limits (honestly)

- Java does not guarantee a complete wipe of secrets in memory (GC can leave copies). For a paranoid level — moving KDF/keys to NDK; the current architecture does not require this.
- The service name is stored openly (for list sorting). If desired, it can be encrypted just like the login — a change of a few lines in `DetailActivity`.
- No master password recovery — by design.
- **Clipboard on Samsung (One UI) and Xiaomi (MIUI/HyperOS) devices**: built-in keyboards of these manufacturers have their own clipboard history, which may ignore the system privacy flag (`EXTRA_IS_SENSITIVE`) and store passwords. In this case, it is recommended to use keyboards that respect privacy (e.g., Gboard from Google), or manually clear the keyboard history.
