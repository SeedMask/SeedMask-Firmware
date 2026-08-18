# RAM, `String`, and lock behavior

## `Arduino::String` and secrets

Several paths build the vault plaintext with **`String`** (e.g. `save_passwords_notes_to_nvs`, `pw_vault_save_to_sd`, QR rebuild):

- **Pros:** Simple serialization.
- **Cons:** Heap copies are harder to wipe; fragmentation on embedded targets.

**Policy:** Prefer **fixed buffers + explicit length** for new code that handles long-lived secrets. Migrating existing `String` paths is incremental work; track as technical debt.

## Lock and wipe (current behavior)

On **`session_lock_to_home()`** ([`SeedMask Firmware.ino`](../SeedMask Firmware.ino)) the firmware:

- Clears **`g_seed`**, **`g_masterPw`**, password entry fields, backup code buffers.
- Zeroes **vault key caches**: `s_vault_blob_key`, `s_vault_seed_key`, `s_vault_nvs_key` and marks them invalid.
- Calls **`pwSvc_clearAll()`** then **`vault_set_unlocked(false)`**.
- Clears **notes** and **TOTP** arrays (`g_noteItems`, `g_totpItems`).
- Resets vault QR payload dirty flag / empty QR buffer.

**Device wipe (`nvs_wipe()`):** Erase NVS and SPIFFS (and FAT / coredump if present) with erase → random fill → erase. Does **not** touch the firmware partition or microSD. Then the same RAM clear as lock (`session_lock_to_home` / silent-wipe stay-locked).

**Auto-lock:** There is **no idle timer** in the current code paths found by review—lock is user-initiated (menu) or flow-driven. If product requirements demand **inactivity timeout**, add a `millis()`-based watchdog that calls `session_lock_to_home()` after N minutes of no touch, and document the default N in user-facing materials.

## `secure_memzero`

Heap allocations that held ciphertext or plaintext should call **`secure_memzero()`** from [`SecureMem.cpp`](../SecureMem.cpp) before **`free()`** where feasible.

## Related

- [`ARCHITECTURE_STEP3.md`](../ARCHITECTURE_STEP3.md) — Vault / PasswordService layering.
