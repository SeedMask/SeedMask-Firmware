/**
 * PasswordService — single owner of in-RAM password entries (Step 1 refactor).
 * All password list state lives here; UI and vault code use this API only.
 */
#pragma once

#include <Arduino.h>
#include <cstddef>
#include <cstdint>

struct PwItem {
  // Packed metadata: "name | user | website | notes" — needs room for all four fields (was 32; truncation caused data loss).
  char title[128];  // up to 127 chars + NUL
  char value[96];   // Diceware / long passwords
};

static constexpr uint8_t PW_MAX_ITEMS = 64;

// ---- Lifecycle / counts ----
/** Allocate password entry table in PSRAM (call once from setup after PSRAM init). */
void pwSvc_alloc_storage();

/** False only if alloc_storage ran out of both SPIRAM and internal heap (should never happen). */
bool pwSvc_storage_ok();

void pwSvc_clearAll();

uint8_t pwSvc_getCount();
bool pwSvc_isFull();

// ---- CRUD ----
bool pwSvc_getAt(uint8_t index, PwItem* out);

/** Read-only pointer to a transient decrypted scratch buffer (single-threaded UI). Do not retain. */
const char* pwSvc_getTitleCStr(uint8_t index);
const char* pwSvc_getValueCStr(uint8_t index);

void pwSvc_setTitle(uint8_t index, const char* title);
void pwSvc_setValue(uint8_t index, const char* value);

/** Append one entry; returns false if list is full. */
bool pwSvc_append(const char* title, const char* value);

/** List edit mode: drop entries whose checkbox is selected (keep unselected). */
void pwSvc_removeSelectedEntries();

// Plaintext import/export for persistence is only through Vault (see Vault.h) — not exposed here.

// ---- Multi-select UI state (password grid) ----
bool pwSvc_isSelected(uint8_t index);
void pwSvc_toggleSelected(uint8_t index);
void pwSvc_clearSelection();
