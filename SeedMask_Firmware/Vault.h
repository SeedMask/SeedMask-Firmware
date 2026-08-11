/**
 * Vault — boundary for moving password plaintext between encrypted storage and PasswordService.
 *
 * - Only Vault (and PasswordService internals) should construct or parse persisted password blobs.
 * - UI code uses PasswordService for CRUD; crypto/NVS/SD code calls Vault to import/export the password section.
 *
 * Lock state (Step 4): session code calls vault_set_unlocked(true) after successful login,
 * vault_set_unlocked(false) on lock. PasswordService refuses secret access when locked.
 *
 * Format: lines of title\\tvalue\\n (same as before).
 */
#pragma once

#include <Arduino.h>
#include <cstddef>

/** True after successful session login until lock/wipe. */
bool vault_is_unlocked(void);

/** Called from session layer only — not from UI. */
void vault_set_unlocked(bool unlocked);

/** Load decrypted password section into PasswordService. Returns true if at least one entry parsed. */
bool vault_import_passwords_plaintext(const char* data, size_t len);

/** Serialize current passwords for embedding in NVS/SD vault plaintext. */
String vault_export_passwords_plaintext();
