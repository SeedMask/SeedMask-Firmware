#include "PasswordService.h"
#include "PasswordServicePriv.h"
#include "Vault.h"
#include "SecureMem.h"

#include <cstring>
#include <esp_system.h>
#if defined(ARDUINO_ARCH_ESP32)
#include <esp_heap_caps.h>
#endif

static PwItem* s_items = nullptr;
static uint8_t s_count = 0;
static bool s_selected[PW_MAX_ITEMS];
static uint8_t s_valueLen[PW_MAX_ITEMS];
static uint8_t s_valueMask[32];
static bool s_maskReady = false;
static char s_valueScratch[sizeof(PwItem::value)];

void pwSvc_alloc_storage() {
  if (s_items) return;
#if defined(ARDUINO_ARCH_ESP32)
  s_items = (PwItem*)heap_caps_calloc(PW_MAX_ITEMS, sizeof(PwItem), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
#endif
  if (!s_items)
    s_items = (PwItem*)calloc(PW_MAX_ITEMS, sizeof(PwItem));
}

bool pwSvc_storage_ok() { return s_items != nullptr; }

static size_t pwSvc_items_bytes() { return (size_t)PW_MAX_ITEMS * sizeof(PwItem); }

/** Secrets must not be observable or mutable while vault is locked (except explicit wipe). */
static bool allow_secrets(void) { return vault_is_unlocked(); }

static void ensure_mask(void) {
  if (s_maskReady) return;
  esp_fill_random(s_valueMask, sizeof(s_valueMask));
  s_maskReady = true;
}

static void encode_value(uint8_t index, const char* value) {
  if (!s_items || index >= PW_MAX_ITEMS) return;
  ensure_mask();
  const size_t cap = sizeof(s_items[index].value) - 1;
  const size_t inLen = value ? strlen(value) : 0;
  size_t n = inLen;
  if (n > cap) n = cap;
  s_valueLen[index] = (uint8_t)n;
  for (size_t i = 0; i < n; i++) {
    s_items[index].value[i] = (char)(((uint8_t)value[i]) ^ s_valueMask[i % sizeof(s_valueMask)]);
  }
  s_items[index].value[n] = 0;
}

static const char* decode_value_ptr(uint8_t index) {
  if (!s_items || index >= PW_MAX_ITEMS) return "";
  if (!s_maskReady) return "";
  const size_t n = s_valueLen[index];
  if (n >= sizeof(s_valueScratch)) return "";
  for (size_t i = 0; i < n; i++) {
    s_valueScratch[i] = (char)(((uint8_t)s_items[index].value[i]) ^ s_valueMask[i % sizeof(s_valueMask)]);
  }
  s_valueScratch[n] = 0;
  return s_valueScratch;
}

void pwSvc_clearAll() {
  secure_memzero(s_valueScratch, sizeof(s_valueScratch));
  if (s_items) memset(s_items, 0, pwSvc_items_bytes());
  memset(s_selected, 0, sizeof(s_selected));
  memset(s_valueLen, 0, sizeof(s_valueLen));
  secure_memzero(s_valueMask, sizeof(s_valueMask));
  s_maskReady = false;
  s_count = 0;
}

uint8_t pwSvc_getCount() {
  if (!allow_secrets() || !s_items) return 0;
  return s_count;
}

bool pwSvc_isFull() {
  if (!allow_secrets() || !s_items) return false;
  return s_count >= PW_MAX_ITEMS;
}

bool pwSvc_getAt(uint8_t index, PwItem* out) {
  if (!allow_secrets() || !s_items) return false;
  if (!out || index >= s_count) return false;
  *out = s_items[index];
  const char* dec = decode_value_ptr(index);
  strncpy(out->value, dec, sizeof(out->value) - 1);
  out->value[sizeof(out->value) - 1] = 0;
  secure_memzero(s_valueScratch, sizeof(s_valueScratch));
  return true;
}

const char* pwSvc_getTitleCStr(uint8_t index) {
  if (!allow_secrets() || !s_items) return "";
  if (index >= s_count) return "";
  return s_items[index].title;
}

const char* pwSvc_getValueCStr(uint8_t index) {
  if (!allow_secrets() || !s_items) return "";
  if (index >= s_count) return "";
  return decode_value_ptr(index);
}

void pwSvc_setTitle(uint8_t index, const char* title) {
  if (!allow_secrets() || !s_items) return;
  if (index >= s_count) return;
  strncpy(s_items[index].title, title ? title : "", sizeof(s_items[index].title) - 1);
  s_items[index].title[sizeof(s_items[index].title) - 1] = 0;
}

void pwSvc_setValue(uint8_t index, const char* value) {
  if (!allow_secrets() || !s_items) return;
  if (index >= s_count) return;
  encode_value(index, value ? value : "");
  secure_memzero(s_valueScratch, sizeof(s_valueScratch));
}

bool pwSvc_append(const char* title, const char* value) {
  if (!allow_secrets() || !s_items) return false;
  if (s_count >= PW_MAX_ITEMS) return false;
  strncpy(s_items[s_count].title, title ? title : "", sizeof(s_items[s_count].title) - 1);
  s_items[s_count].title[sizeof(s_items[s_count].title) - 1] = 0;
  encode_value(s_count, value ? value : "");
  s_count++;
  secure_memzero(s_valueScratch, sizeof(s_valueScratch));
  return true;
}

void pwSvc_removeLast() {
  if (!allow_secrets() || !s_items || s_count == 0) return;
  uint8_t i = (uint8_t)(s_count - 1);
  secure_memzero(s_items[i].title, sizeof(s_items[i].title));
  secure_memzero(s_items[i].value, sizeof(s_items[i].value));
  s_valueLen[i] = 0;
  s_selected[i] = false;
  s_count = i;
}

void pwSvc_removeSelectedEntries() {
  if (!allow_secrets() || !s_items) return;
  uint8_t n = 0;
  for (uint8_t i = 0; i < s_count; i++) {
    if (!s_selected[i]) {
      if (n != i) {
        s_items[n] = s_items[i];
        s_valueLen[n] = s_valueLen[i];
      }
      n++;
    }
  }
  for (uint8_t i = n; i < s_count; i++) {
    secure_memzero(s_items[i].value, sizeof(s_items[i].value));
    s_valueLen[i] = 0;
  }
  s_count = n;
  memset(s_selected, 0, sizeof(s_selected));
}

bool pwSvc_deserializePlain(const char* str, size_t len) {
  if (!s_items) return false;
  memset(s_items, 0, pwSvc_items_bytes());
  memset(s_selected, 0, sizeof(s_selected));
  memset(s_valueLen, 0, sizeof(s_valueLen));
  ensure_mask();
  s_count = 0;
  if (!str || len == 0) return false;
  const char* p = str;
  const char* end = str + len;
  while (p < end && s_count < PW_MAX_ITEMS) {
    const char* lineStart = p;
    while (p < end && *p != '\n' && *p != '\r') p++;
    if (p > lineStart) {
      const char* tab = (const char*)memchr(lineStart, '\t', (size_t)(p - lineStart));
      if (tab && tab > lineStart) {
        size_t titleLen = (size_t)(tab - lineStart);
        if (titleLen >= sizeof(s_items[0].title)) titleLen = sizeof(s_items[0].title) - 1;
        memcpy(s_items[s_count].title, lineStart, titleLen);
        s_items[s_count].title[titleLen] = 0;
        size_t valueLen = (size_t)(p - (tab + 1));
        if (valueLen >= sizeof(s_items[0].value)) valueLen = sizeof(s_items[0].value) - 1;
        s_valueLen[s_count] = (uint8_t)valueLen;
        for (size_t i = 0; i < valueLen; i++) {
          s_items[s_count].value[i] = (char)(((uint8_t)tab[1 + i]) ^ s_valueMask[i % sizeof(s_valueMask)]);
        }
        s_items[s_count].value[valueLen] = 0;
        s_count++;
      }
    }
    while (p < end && (*p == '\n' || *p == '\r')) p++;
  }
  return s_count > 0;
}

String pwSvc_serializePlain() {
  String s;
  if (!s_items) return s;
  for (uint8_t i = 0; i < s_count; i++) {
    s += s_items[i].title;
    s += "\t";
    s += decode_value_ptr(i);
    secure_memzero(s_valueScratch, sizeof(s_valueScratch));
    s += "\n";
  }
  return s;
}

bool pwSvc_isSelected(uint8_t index) {
  if (!allow_secrets() || !s_items) return false;
  if (index >= PW_MAX_ITEMS) return false;
  return s_selected[index];
}

void pwSvc_toggleSelected(uint8_t index) {
  if (!allow_secrets() || !s_items) return;
  if (index >= PW_MAX_ITEMS) return;
  s_selected[index] = !s_selected[index];
}

void pwSvc_clearSelection() {
  if (!allow_secrets() || !s_items) return;
  memset(s_selected, 0, sizeof(s_selected));
}
