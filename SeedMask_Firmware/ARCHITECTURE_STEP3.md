# SeedMask firmware — PasswordService + Vault API (Step 3)

This document explains **how to use** the refactored APIs and **how to update** old patterns safely.  
Steps 1–2 are already applied in this tree; use this as the reference for new code.

---

## 1. Layering (mental model)

| Layer | Responsibility |
|--------|----------------|
| **UI** (`SeedMask Firmware.ino` drawing/input) | Screens, gestures, editors. Calls **services** only — no direct vault crypto, no parsing persisted blobs for passwords. |
| **PasswordService** (`PasswordService.h`) | Single owner of **in-RAM** password entries (title/value), count, grid selection flags. CRUD + display helpers. |
| **Vault** (`Vault.h`) | **Boundary** between decrypted **password plaintext** (wire format) and `PasswordService`. Anything that loads/saves the password *section* after decrypt or before encrypt goes through Vault. |
| **Core crypto / storage** (still mostly in `.ino` today) | AES-GCM, PBKDF2, NVS, SD files. Builds the big plaintext string; only the **password substring** is imported/exported via Vault. |

**Rule:** Do not reintroduce global password arrays. Do not call `PasswordServicePriv.h` from new code — only `Vault.cpp` may include it.

---

## 2. Which API to call?

### UI / editor / list (user is editing or viewing)

Use **`PasswordService`** only:

- `pwSvc_getCount()`, `pwSvc_isFull()`
- `pwSvc_getTitleCStr(i)`, `pwSvc_getValueCStr(i)` (short-lived pointers; single-threaded UI)
- `pwSvc_setTitle`, `pwSvc_setValue`, `pwSvc_append`
- `pwSvc_removeSelectedEntries`, selection: `pwSvc_isSelected`, `pwSvc_toggleSelected`, `pwSvc_clearSelection`
- `pwSvc_clearAll()` when wiping session passwords (e.g. lock/wipe flows)

**Do not** call `vault_import_passwords_plaintext` / `vault_export_passwords_plaintext` from UI unless you are writing a dedicated import/export screen that intentionally manipulates persisted format (prefer keeping that in one place).

### After decrypt OR before encrypt (NVS / SD / QR payload)

Use **`Vault`** for the password **section** string:

- **Import** decrypted bytes into RAM passwords:  
  `vault_import_passwords_plaintext(ptr, len)`  
  Returns `true` if at least one entry was parsed (same semantics as before).

- **Export** current passwords for concatenation into vault plaintext:  
  `vault_export_passwords_plaintext()`  
  Returns `String` (same `title\tvalue\n` lines as before).

Notes / TOTP sections are still handled separately in the sketch until those get their own services.

---

## 3. BEFORE / AFTER quick reference

### 3.1 Globals (removed — do not bring back)

```cpp
// BEFORE (removed)
// static PwItem g_pwItems[MAX_PW_ITEMS];
// static uint8_t g_pwCount;
// static bool g_pwSelected[MAX_PW_ITEMS];

// AFTER
// Use PasswordService + Vault as below.
```

### 3.2 Count / full check

```cpp
// BEFORE
// if (g_pwCount >= MAX_PW_ITEMS)

// AFTER
if (pwSvc_isFull()) { ... }
// or
if (pwSvc_getCount() >= PW_MAX_ITEMS) { ... }
```

### 3.3 Read title/value for display

```cpp
// BEFORE
// gfx->print(g_pwItems[i].title);
// printTruncatedFixedWidth(g_pwItems[i].value);

// AFTER
gfx->print(pwSvc_getTitleCStr(i));
printTruncatedFixedWidth(pwSvc_getValueCStr(i));
```

### 3.4 Save new / update password from editor

```cpp
// BEFORE
// strncpy(g_pwItems[g_viewPwIndex].value, g_editBuf, ...);

// AFTER
pwSvc_setValue(g_viewPwIndex, g_editBuf);
// new entry:
if (!pwSvc_append(g_tmpTitle, g_editBuf)) { /* full */ }
```

### 3.5 Build vault plaintext for NVS/SD (password block)

```cpp
// BEFORE
// s += pwSvc_serializePlain();   // if it were still public on PasswordService

// AFTER
#include "Vault.h"
s += vault_export_passwords_plaintext();
```

### 3.6 Load decrypted password section into RAM

```cpp
// BEFORE
// pwSvc_deserializePlain(p, pwLen);

// AFTER
#include "Vault.h"
vault_import_passwords_plaintext(p, pwLen);
```

### 3.7 Multi-delete (edit mode)

```cpp
// BEFORE
// compact loop with memcpy between g_pwItems[...]

// AFTER
pwSvc_removeSelectedEntries();
```

### 3.8 Selection checkbox state

```cpp
// BEFORE
// g_pwSelected[i] = !g_pwSelected[i];
// memset(g_pwSelected, 0, sizeof(g_pwSelected));

// AFTER
pwSvc_toggleSelected(i);
pwSvc_clearSelection();
```

---

## 4. Files to know

| File | Purpose |
|------|---------|
| `PasswordService.h` | Public CRUD + UI helpers for passwords. |
| `PasswordService.cpp` | Implementation + internal serialize/deserialize (wire format). |
| `PasswordServicePriv.h` | **Do not include from new code** — only `Vault.cpp` and `PasswordService.cpp`. |
| `Vault.h` / `Vault.cpp` | `vault_import_passwords_plaintext` / `vault_export_passwords_plaintext`. |
| `SeedMask Firmware.ino` | UI + crypto orchestration; uses Vault where the password blob is assembled or parsed. |

---

## 5. Future work (not required for Step 3)

- Move **notes** / **TOTP** into their own service modules mirroring passwords.
- Move **AES-GCM / key derivation** into a `Crypto` or expanded `Vault` module with explicit buffer zeroing.
- Replace `String` export with fixed buffers + length where you need tighter memory/security guarantees.

---

## 6. Checklist when touching password persistence

1. Decrypted password bytes → **`vault_import_passwords_plaintext`** only.
2. Building encrypted payload → **`vault_export_passwords_plaintext`** for the password part.
3. Screen code → **`pwSvc_*`** only; no parsing of `\t`/` \n` vault lines in UI.
4. Never include **`PasswordServicePriv.h`** outside **`Vault.cpp`** / **`PasswordService.cpp`**.

---

## 7. Steps 4–6 (lock, lazy access policy, wiping)

### Lock / unlock (Step 4)

- **`bool vault_is_unlocked(void)`** — true after **`vault_set_unlocked(true)`** at end of **`session_login_from_seed`**.
- **`vault_set_unlocked(false)`** — called after **`pwSvc_clearAll()`** in **`session_lock_to_home`** (RAM cleared first, then logical lock).
- **`PasswordService`** — all secret APIs check **`vault_is_unlocked()`** via **`Vault.h`**; **`pwSvc_clearAll()`** is **not** gated (used for wipe while transitioning).
- **`vault_import_passwords_plaintext` / `vault_export_passwords_plaintext`** — return empty / false when locked.

### Plaintext lifetime (Step 5)

- **Design goal:** decrypted blobs are **not** kept longer than needed on **heap** paths used for NVS + SD vault load.
- **Password entries** still live in **`PasswordService`** static RAM while the session is unlocked (full per-entry decrypt-on-demand would be a larger change).

### Secure wiping (Step 6)

- **`SecureMem.h` / `SecureMem.cpp`** — **`secure_memzero(ptr, len)`** (volatile clear).
- **`load_passwords_notes_from_nvs`** — wipes decrypted **`plain`** buffer before **`free`**.
- **`pw_vault_load_from_sd`** — wipes **`pt`**, **`plainStr`**, and **`seed_specific_pw`** on success/error paths added in this pass.

---

## 8. Security documentation (production)

| Document | Purpose |
|----------|---------|
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Assets, adversaries, mitigations. |
| [`docs/ESP32_PRODUCTION.md`](docs/ESP32_PRODUCTION.md) | Secure Boot, Flash Encryption, `SEEDMASK_CRYPTO_DEBUG`, manufacturing notes. |
| [`docs/RAM_AND_STRING_POLICY.md`](docs/RAM_AND_STRING_POLICY.md) | `String` vs fixed buffers, lock/wipe behavior, auto-lock gap. |
| [`docs/WALLET_SEPARATION.md`](docs/WALLET_SEPARATION.md) | Future wallet vs PM vault key separation (HKDF labels). |
| [`docs/VERIFY_AND_RELEASE.md`](docs/VERIFY_AND_RELEASE.md) | Signing, CI guards, pen-test, incident response. |

- **Crypto Serial:** verbose UART logging for AES-GCM and vault/backup paths is gated with **`SEEDMASK_CRYPTO_DEBUG`** (default **0**) in `SeedMask Firmware.ino`. Never enable in production.
- **CI:** [`scripts/verify_crypto_serial_guards.sh`](scripts/verify_crypto_serial_guards.sh) blocks reintroduction of known-dangerous debug strings.

---

*End of Step 3 deliverable — documentation + migration patterns.*
