#include "seedmask_qr_payload.h"

#include <mbedtls/base64.h>

// Prefix to identify SeedMask QR payloads
static const char *QR_PREFIX = "SPQR1:";

// VERY small JSON helper (controlled input only)
static bool json_get_string(const String &json, const char *key, String &out) {
  String k = String("\"") + key + "\":";
  int i = json.indexOf(k);
  if (i < 0) return false;
  i += k.length();

  while (i < (int)json.length() && isspace(json[i])) i++;
  if (i >= (int)json.length() || json[i] != '"') return false;
  i++;

  int j = i;
  while (j < (int)json.length()) {
    if (json[j] == '"' && json[j - 1] != '\\') break;
    j++;
  }
  if (j >= (int)json.length()) return false;

  out = json.substring(i, j);
  out.replace("\\\"", "\"");
  out.replace("\\n", "\n");
  out.replace("\\\\", "\\");
  return true;
}

bool seedmask_parse_qr_payload(const String &qrText, String &outId, String &outBlob) {
  String t = qrText;
  t.trim();

  if (!t.startsWith(QR_PREFIX)) return false;

  // Base64 payload
  String b64 = t.substring(strlen(QR_PREFIX));

  // base64url → base64
  b64.replace('-', '+');
  b64.replace('_', '/');
  while (b64.length() % 4 != 0) b64 += "=";

  // Decode base64
  size_t olen = 0;
  int rc = mbedtls_base64_decode(
      nullptr, 0, &olen,
      (const unsigned char *)b64.c_str(), b64.length());

  if (rc != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) return false;

  uint8_t *buf = (uint8_t *)malloc(olen + 1);
  if (!buf) return false;

  rc = mbedtls_base64_decode(
      buf, olen, &olen,
      (const unsigned char *)b64.c_str(), b64.length());

  if (rc != 0) {
    free(buf);
    return false;
  }

  buf[olen] = 0;
  String json = String((char *)buf);
  free(buf);

  // Minimal validation
  if (json.indexOf("\"v\":1") < 0) return false;

  String id, blob;
  if (!json_get_string(json, "id", id)) return false;
  if (!json_get_string(json, "blob", blob)) return false;

  outId = id;
  outBlob = blob;
  return true;
}