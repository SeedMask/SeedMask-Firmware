#include "Vault.h"
#include "PasswordServicePriv.h"

static bool s_vault_unlocked = false;

bool vault_is_unlocked(void) { return s_vault_unlocked; }

void vault_set_unlocked(bool unlocked) { s_vault_unlocked = unlocked; }

bool vault_import_passwords_plaintext(const char* data, size_t len) {
  if (!s_vault_unlocked) return false;
  return pwSvc_deserializePlain(data, len);
}

String vault_export_passwords_plaintext() {
  if (!s_vault_unlocked) return String();
  return pwSvc_serializePlain();
}
