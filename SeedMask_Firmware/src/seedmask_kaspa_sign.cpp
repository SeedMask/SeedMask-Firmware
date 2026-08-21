// SPDX-License-Identifier: MIT
// Kaspa native tx (v0) Schnorr signing from coordinator JSON v2.

#include "seedmask_kaspa_sign.h"

#include "seedmask_kaspa_bip340.h"
#include "seedmask_kaspa_hash.h"
#include "seedmask_kaspa_sighash.h"
#include "kaspa_address.h"
#include "mbedtls/sha512.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "esp_random.h"

#include <cctype>
#include <cstdio>
#include <cstring>

namespace {

static constexpr uint32_t KASPA_BIP44_COIN = 111111u;

struct Bip32Node {
  uint8_t k[32];
  uint8_t c[32];
};

static void sp_zero(void* p, size_t n) {
  if (!p || n == 0) return;
  volatile uint8_t* vp = (volatile uint8_t*)p;
  while (n--) *vp++ = 0;
}

static int sp_rng(void*, unsigned char* out, size_t len) {
  esp_fill_random(out, len);
  return 0;
}

// Same HMAC-SHA512 as seedmask_psbt_sign.cpp (ESP32 mbedtls often omits MBEDTLS_MD_C).
static bool hmac_sha512(const uint8_t* key, size_t keyLen, const uint8_t* msg, size_t msgLen, uint8_t out[64]) {
  uint8_t kopad[128], kipad[128], khash[64], inner[64];
  memset(kopad, 0, sizeof(kopad));
  memset(kipad, 0, sizeof(kipad));
  memset(khash, 0, sizeof(khash));
  if (keyLen > 128) {
    mbedtls_sha512_context c;
    mbedtls_sha512_init(&c);
    mbedtls_sha512_starts(&c, 0);
    mbedtls_sha512_update(&c, key, keyLen);
    mbedtls_sha512_finish(&c, khash);
    mbedtls_sha512_free(&c);
    memcpy(kipad, khash, 64);
  } else {
    memcpy(kipad, key, keyLen);
  }
  memcpy(kopad, kipad, 128);
  for (size_t i = 0; i < 128; i++) {
    kipad[i] ^= 0x36;
    kopad[i] ^= 0x5c;
  }
  mbedtls_sha512_context c;
  mbedtls_sha512_init(&c);
  mbedtls_sha512_starts(&c, 0);
  mbedtls_sha512_update(&c, kipad, sizeof(kipad));
  mbedtls_sha512_update(&c, msg, msgLen);
  mbedtls_sha512_finish(&c, inner);
  mbedtls_sha512_starts(&c, 0);
  mbedtls_sha512_update(&c, kopad, sizeof(kopad));
  mbedtls_sha512_update(&c, inner, sizeof(inner));
  mbedtls_sha512_finish(&c, out);
  mbedtls_sha512_free(&c);
  sp_zero(inner, sizeof(inner));
  sp_zero(khash, sizeof(khash));
  sp_zero(kipad, sizeof(kipad));
  sp_zero(kopad, sizeof(kopad));
  return true;
}

static bool pbkdf2_sha512(const uint8_t* pw, size_t pwLen, const uint8_t* salt, size_t saltLen, uint32_t iters,
                          uint8_t* outKey, size_t outKeyLen) {
  if (!pw || !salt || !outKey || iters == 0 || outKeyLen == 0) return false;
  uint32_t blocks = (uint32_t)((outKeyLen + 63) / 64);
  uint8_t asalt[128], u[64], t[64];
  for (uint32_t i = 1; i <= blocks; i++) {
    if (saltLen + 4 > sizeof(asalt)) return false;
    memcpy(asalt, salt, saltLen);
    asalt[saltLen + 0] = (uint8_t)(i >> 24);
    asalt[saltLen + 1] = (uint8_t)(i >> 16);
    asalt[saltLen + 2] = (uint8_t)(i >> 8);
    asalt[saltLen + 3] = (uint8_t)(i);
    if (!hmac_sha512(pw, pwLen, asalt, saltLen + 4, u)) return false;
    memcpy(t, u, sizeof(t));
    for (uint32_t j = 1; j < iters; j++) {
      if (!hmac_sha512(pw, pwLen, u, sizeof(u), u)) return false;
      for (size_t k = 0; k < sizeof(t); k++) t[k] ^= u[k];
    }
    size_t off = (size_t)(i - 1) * 64;
    size_t take = (outKeyLen - off > 64) ? 64 : (outKeyLen - off);
    memcpy(outKey + off, t, take);
  }
  sp_zero(asalt, sizeof(asalt));
  sp_zero(u, sizeof(u));
  sp_zero(t, sizeof(t));
  return true;
}

static void ser32be(uint32_t v, uint8_t out[4]) {
  out[0] = (uint8_t)(v >> 24);
  out[1] = (uint8_t)(v >> 16);
  out[2] = (uint8_t)(v >> 8);
  out[3] = (uint8_t)v;
}

static bool secp_pubkey_compressed(const uint8_t priv[32], uint8_t out33[33]) {
  mbedtls_ecp_group grp;
  mbedtls_ecp_point Q;
  mbedtls_mpi d;
  size_t olen = 0;
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_point_init(&Q);
  mbedtls_mpi_init(&d);
  bool ok = false;
  if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0) goto done;
  if (mbedtls_mpi_read_binary(&d, priv, 32) != 0) goto done;
  if (mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, sp_rng, nullptr) != 0) goto done;
  if (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_COMPRESSED, &olen, out33, 33) != 0) goto done;
  ok = (olen == 33);
done:
  mbedtls_ecp_point_free(&Q);
  mbedtls_ecp_group_free(&grp);
  mbedtls_mpi_free(&d);
  return ok;
}

static bool bip32_master_from_seed(const uint8_t seed[64], Bip32Node* out) {
  static const uint8_t key[] = "Bitcoin seed";
  uint8_t I[64];
  if (!hmac_sha512(key, sizeof(key) - 1, seed, 64, I)) return false;
  memcpy(out->k, I, 32);
  memcpy(out->c, I + 32, 32);
  sp_zero(I, sizeof(I));
  return true;
}

static bool bip32_ckd_priv(Bip32Node* n, uint32_t idx, bool hardened) {
  uint8_t data[1 + 33 + 4];
  size_t dlen = 0;
  if (hardened) {
    data[0] = 0;
    memcpy(data + 1, n->k, 32);
    dlen = 33;
    idx |= 0x80000000UL;
  } else {
    uint8_t pub[33];
    if (!secp_pubkey_compressed(n->k, pub)) return false;
    memcpy(data, pub, 33);
    dlen = 33;
    sp_zero(pub, sizeof(pub));
  }
  ser32be(idx, data + dlen);
  dlen += 4;
  uint8_t I[64];
  if (!hmac_sha512(n->c, 32, data, dlen, I)) return false;

  mbedtls_ecp_group grp;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi il, k, sum;
  mbedtls_mpi_init(&il);
  mbedtls_mpi_init(&k);
  mbedtls_mpi_init(&sum);
  bool ok = false;
  if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0) goto done;
  if (mbedtls_mpi_read_binary(&il, I, 32) != 0) goto done;
  if (mbedtls_mpi_cmp_mpi(&il, &grp.N) >= 0) goto done;
  if (mbedtls_mpi_read_binary(&k, n->k, 32) != 0) goto done;
  if (mbedtls_mpi_add_mpi(&sum, &il, &k) != 0) goto done;
  if (mbedtls_mpi_mod_mpi(&sum, &sum, &grp.N) != 0) goto done;
  if (mbedtls_mpi_cmp_int(&sum, 0) == 0) goto done;
  if (mbedtls_mpi_write_binary(&sum, n->k, 32) != 0) goto done;
  memcpy(n->c, I + 32, 32);
  ok = true;
done:
  sp_zero(data, sizeof(data));
  sp_zero(I, sizeof(I));
  mbedtls_mpi_free(&sum);
  mbedtls_mpi_free(&k);
  mbedtls_mpi_free(&il);
  mbedtls_ecp_group_free(&grp);
  return ok;
}

static bool derive_kaspa_priv(Bip32Node master, uint32_t account, uint32_t chain, uint32_t index, uint8_t priv[32]) {
  if (!bip32_ckd_priv(&master, 44, true)) return false;
  if (!bip32_ckd_priv(&master, KASPA_BIP44_COIN, true)) return false;
  if (!bip32_ckd_priv(&master, account, true)) return false;
  if (!bip32_ckd_priv(&master, chain, false)) return false;
  if (!bip32_ckd_priv(&master, index, false)) return false;
  memcpy(priv, master.k, 32);
  sp_zero(&master, sizeof(master));
  return true;
}

static bool validate_mnemonic_word_count(const char* mnemonic, int word_count) {
  if (!mnemonic || !mnemonic[0]) return false;
  if (word_count != 12 && word_count != 15 && word_count != 18 && word_count != 21 && word_count != 24) return false;
  int n = 0;
  const char* p = mnemonic;
  while (*p && std::isspace((unsigned char)*p)) p++;
  while (*p) {
    n++;
    while (*p && !std::isspace((unsigned char)*p)) p++;
    while (*p && std::isspace((unsigned char)*p)) p++;
  }
  return n == word_count;
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static bool hex_decode(const char* hex, uint8_t* out, size_t out_cap, size_t* out_len) {
  if (!hex || !out || !out_len) return false;
  size_t n = 0;
  int hi = -1;
  for (const char* p = hex; *p; p++) {
    if (std::isspace((unsigned char)*p)) continue;
    int v = hex_nibble(*p);
    if (v < 0) return false;
    if (hi < 0) {
      hi = v;
    } else {
      if (n >= out_cap) return false;
      out[n++] = (uint8_t)((hi << 4) | v);
      hi = -1;
    }
  }
  if (hi >= 0) return false;
  *out_len = n;
  return true;
}

static bool json_find_key(const char* src, const char* key, const char** val_out) {
  if (!src || !key || !val_out) return false;
  char pat[48];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char* p = strstr(src, pat);
  if (!p) return false;
  p = strchr(p + strlen(pat), ':');
  if (!p) return false;
  p++;
  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
  *val_out = p;
  return true;
}

static bool json_parse_u64(const char* src, const char* key, uint64_t* out) {
  const char* p = nullptr;
  if (!json_find_key(src, key, &p) || !out) return false;
  unsigned long long v = 0;
  if (sscanf(p, "%llu", &v) != 1) return false;
  *out = (uint64_t)v;
  return true;
}

static bool json_parse_u32(const char* src, const char* key, uint32_t* out) {
  const char* p = nullptr;
  if (!json_find_key(src, key, &p) || !out) return false;
  unsigned v = 0;
  if (sscanf(p, "%u", &v) != 1) return false;
  *out = (uint32_t)v;
  return true;
}

static bool json_parse_u16(const char* src, const char* key, uint16_t* out) {
  const char* p = nullptr;
  if (!json_find_key(src, key, &p) || !out) return false;
  unsigned v = 0;
  if (sscanf(p, "%u", &v) != 1) return false;
  *out = (uint16_t)v;
  return true;
}

static bool json_parse_u8(const char* src, const char* key, uint8_t* out) {
  const char* p = nullptr;
  if (!json_find_key(src, key, &p) || !out) return false;
  unsigned v = 0;
  if (sscanf(p, "%u", &v) != 1) return false;
  *out = (uint8_t)v;
  return true;
}

static bool json_parse_hex_field(const char* src, const char* key, uint8_t* out, size_t out_cap, size_t* out_len) {
  const char* p = nullptr;
  if (!json_find_key(src, key, &p)) return false;
  while (*p == ' ' || *p == '\t') p++;
  if (*p != '"') return false;
  p++;
  char tmp[(KASPA_SIGN_MAX_REDEEM * 2) + 8];
  size_t i = 0;
  while (*p && *p != '"' && i + 1 < sizeof(tmp)) tmp[i++] = *p++;
  tmp[i] = 0;
  return hex_decode(tmp, out, out_cap, out_len);
}

static bool json_parse_string_field(const char* src, const char* key, char* out, size_t cap) {
  const char* p = nullptr;
  if (!json_find_key(src, key, &p) || !out || cap == 0) return false;
  while (*p == ' ' || *p == '\t') p++;
  if (*p != '"') return false;
  p++;
  size_t n = 0;
  while (*p && *p != '"' && n + 1 < cap) out[n++] = *p++;
  out[n] = 0;
  return n > 0;
}

static bool json_has_key(const char* obj, const char* key) {
  const char* p = nullptr;
  return json_find_key(obj, key, &p);
}

static bool json_has_kaspa_multisig_redeem(const char* json);  // after json_array_nth_object

static const char* json_skip_ws(const char* p) {
  while (p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
  return p;
}

static const char* json_array_nth_object(const char* json, const char* array_key, size_t index) {
  const char* p = nullptr;
  if (!json_find_key(json, array_key, &p)) return nullptr;
  p = json_skip_ws(p);
  if (*p != '[') return nullptr;
  p++;

  /* Walk only inside this array. Do not spill into later objects (e.g. outputs after inputs). */
  size_t seen = 0;
  int arr_depth = 1;
  int obj_depth = 0;
  bool in_string = false;
  bool escape = false;
  for (; *p; p++) {
    const char c = *p;
    if (in_string) {
      if (escape) {
        escape = false;
        continue;
      }
      if (c == '\\') {
        escape = true;
        continue;
      }
      if (c == '"') in_string = false;
      continue;
    }
    if (c == '"') {
      in_string = true;
      continue;
    }
    if (c == '[') {
      if (obj_depth == 0) arr_depth++;
      continue;
    }
    if (c == ']') {
      if (obj_depth == 0) {
        arr_depth--;
        if (arr_depth <= 0) return nullptr;
      }
      continue;
    }
    if (c == '{') {
      if (obj_depth == 0 && arr_depth == 1) {
        if (seen == index) return p;
        obj_depth = 1;
      } else if (obj_depth > 0) {
        obj_depth++;
      }
      continue;
    }
    if (c == '}') {
      if (obj_depth > 0) {
        obj_depth--;
        if (obj_depth == 0) seen++;
      }
    }
  }
  return nullptr;
}

static bool json_has_kaspa_multisig_redeem(const char* json) {
  /* Must be a non-empty hex redeem — PSKT serde often emits "redeemScript": null on singlesig. */
  if (!json) return false;
  for (size_t i = 0;; i++) {
    const char* inp = json_array_nth_object(json, "inputs", i);
    if (!inp) break;
    uint8_t redeem[KASPA_SIGN_MAX_REDEEM];
    size_t redeem_len = 0;
    if (json_parse_hex_field(inp, "redeem_script_hex", redeem, sizeof(redeem), &redeem_len) && redeem_len > 0) {
      return true;
    }
    if (json_parse_hex_field(inp, "redeemScript", redeem, sizeof(redeem), &redeem_len) && redeem_len > 0) {
      return true;
    }
  }
  return false;
}

static void kaspa_addr_ascii_lower(const char* in, char* out, size_t cap) {
  if (!in || !out || cap == 0) return;
  size_t n = 0;
  for (; in[n] && n + 1 < cap; n++) {
    char c = in[n];
    if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    out[n] = c;
  }
  out[n] = 0;
}

static bool kaspa_addrs_equal_ci(const char* a, const char* b) {
  if (!a || !b) return false;
  char la[80], lb[80];
  kaspa_addr_ascii_lower(a, la, sizeof(la));
  kaspa_addr_ascii_lower(b, lb, sizeof(lb));
  return strcmp(la, lb) == 0;
}

static void hex_encode(const uint8_t* in, size_t in_len, char* out, size_t out_cap) {
  static const char* hx = "0123456789abcdef";
  size_t o = 0;
  for (size_t i = 0; i < in_len && o + 2 < out_cap; i++) {
    out[o++] = hx[(in[i] >> 4) & 0xf];
    out[o++] = hx[in[i] & 0xf];
  }
  out[o] = 0;
}

static bool kaspa_script_contains_xonly_pubkey(const uint8_t* script, size_t script_len, const uint8_t xonly[32]) {
  if (!script || !xonly || script_len < 36) return false;
  for (size_t i = 0; i + 33 <= script_len; i++) {
    if (script[i] == 0x20 && memcmp(script + i + 1, xonly, 32) == 0) return true;
  }
  return false;
}

/** True when this device account's multisig pubkey appears in input redeem_script_hex. */
static bool kaspa_device_pubkey_in_unsigned_redeem(const char* json, uint32_t account) {
  const char* inp0 = json_array_nth_object(json, "inputs", 0);
  if (!inp0) return false;
  const char* redeem_key = json_has_key(inp0, "redeem_script_hex") ? "redeem_script_hex"
                         : (json_has_key(inp0, "redeemScript") ? "redeemScript" : nullptr);
  if (!redeem_key) return false;

  uint8_t redeem_script[KASPA_SIGN_MAX_REDEEM];
  size_t redeem_len = 0;
  if (!json_parse_hex_field(inp0, redeem_key, redeem_script, sizeof(redeem_script), &redeem_len)) return false;

  uint32_t chain = 0, addr_index = 0;
  if (!json_parse_u32(inp0, "sign_chain", &chain) || chain > 1) {
    sp_zero(redeem_script, sizeof(redeem_script));
    return false;
  }
  if (!json_parse_u32(inp0, "sign_address_index", &addr_index)) {
    sp_zero(redeem_script, sizeof(redeem_script));
    return false;
  }

  uint8_t priv[32];
  uint8_t signer_pub[33];
  memset(priv, 0, sizeof(priv));
  memset(signer_pub, 0, sizeof(signer_pub));
  bool ok = seedmask_wallet_derive_kaspa_multisig_priv(account, chain, addr_index, priv)
            && secp_pubkey_compressed(priv, signer_pub)
            && kaspa_script_contains_xonly_pubkey(redeem_script, redeem_len, signer_pub + 1);
  sp_zero(priv, sizeof(priv));
  sp_zero(signer_pub, sizeof(signer_pub));
  sp_zero(redeem_script, sizeof(redeem_script));
  return ok;
}

static bool kaspa_validate_multisig_redeem_script(const uint8_t* script, size_t script_len, uint8_t* required_out,
                                                  uint8_t* total_out) {
  if (!script || script_len < 36) return false;
  const uint8_t op_m = script[0];
  if (op_m < 0x51 || op_m > 0x60) return false;
  const uint8_t required = (uint8_t)(op_m - 0x50);
  size_t pos = 1;
  uint8_t total = 0;
  while (pos + 33 <= script_len && script[pos] == 0x20) {
    total++;
    pos += 33;
  }
  if (total == 0 || required == 0 || required > total) return false;
  if (pos + 2 != script_len) return false;
  if (script[pos] != (uint8_t)(0x50 + total)) return false;
  if (script[pos + 1] != 0xae) return false; /* OP_CHECKMULTISIG */
  if (required_out) *required_out = required;
  if (total_out) *total_out = total;
  return true;
}

static bool kaspa_p2sh_matches_redeem_script(const uint8_t* p2sh_script, size_t p2sh_len, const uint8_t* redeem_script,
                                             size_t redeem_len) {
  if (!p2sh_script || !redeem_script || p2sh_len != 35 || redeem_len == 0) return false;
  if (p2sh_script[0] != 0xaa || p2sh_script[1] != 0x20 || p2sh_script[34] != 0x87) return false;
  uint8_t h[32];
  kaspa_blake2b_256(redeem_script, redeem_len, h);
  bool ok = (memcmp(p2sh_script + 2, h, 32) == 0);
  sp_zero(h, sizeof(h));
  return ok;
}

static bool build_tx_from_json(const char* json, KaspaSignTx* tx, char* err, size_t err_len) {
  auto seterr = [&](const char* m) {
    if (err && err_len) snprintf(err, err_len, "%s", m);
  };
  memset(tx, 0, sizeof(*tx));
  tx->sighash_type = 1;

  if (!json_parse_u16(json, "tx_version", &tx->version)) {
    seterr("tx_version");
    return false;
  }

  char net[16];
  if (!json_parse_string_field(json, "network", net, sizeof(net)) || strcasecmp(net, "mainnet") != 0) {
    seterr("mainnet only");
    return false;
  }

  if (!json_parse_u64(json, "lock_time", &tx->lock_time)) {
    tx->lock_time = 0;
  }
  if (!json_parse_u64(json, "gas", &tx->gas)) {
    tx->gas = 0;
  }

  size_t sub_len = 0;
  if (!json_parse_hex_field(json, "subnetwork_id_hex", tx->subnetwork_id, sizeof(tx->subnetwork_id), &sub_len) ||
      sub_len != 20) {
    memset(tx->subnetwork_id, 0, 20);
  }

  size_t pay_len = 0;
  if (json_find_key(json, "payload_hex", nullptr)) {
    if (!json_parse_hex_field(json, "payload_hex", tx->payload, sizeof(tx->payload), &pay_len)) {
      seterr("payload_hex");
      return false;
    }
    tx->payload_len = (uint8_t)pay_len;
  }

  const char* out_arr = nullptr;
  if (!json_find_key(json, "outputs", &out_arr)) {
    seterr("outputs");
    return false;
  }
  uint8_t num_out = 0;
  for (size_t i = 0; i < KASPA_SIGN_MAX_OUTPUTS; i++) {
    const char* obj = json_array_nth_object(json, "outputs", i);
    if (!obj) break;
    KaspaSignOutputDesc* o = &tx->outputs[num_out];
    if (!json_parse_u64(obj, "value", &o->value)) break;
    if (!json_parse_u16(obj, "script_version", &o->script_version)) o->script_version = 0;
    size_t sl = 0;
    if (!json_parse_hex_field(obj, "script_hex", o->script, sizeof(o->script), &sl)) break;
    o->script_len = (uint16_t)sl;
    const char* cov = nullptr;
    if (json_find_key(obj, "covenant", &cov) && cov) {
      uint32_t auth = 0;
      if (json_parse_u32(cov, "authorizing_input", &auth) ||
          json_parse_u32(cov, "authorizingInput", &auth)) {
        size_t cid_len = 0;
        if (json_parse_hex_field(cov, "covenant_id", o->covenant_id, sizeof(o->covenant_id), &cid_len) ||
            json_parse_hex_field(cov, "covenantId", o->covenant_id, sizeof(o->covenant_id), &cid_len)) {
          if (cid_len == 32) {
            o->has_covenant = true;
            o->covenant_authorizing_input = auth;
          }
        }
      }
    }
    num_out++;
  }
  if (num_out == 0) {
    seterr("no outputs");
    return false;
  }
  if (json_array_nth_object(json, "outputs", num_out)) {
    if (num_out >= KASPA_SIGN_MAX_OUTPUTS) seterr("too many outputs");
    else seterr("bad output");
    return false;
  }
  tx->num_outputs = num_out;

  uint8_t num_in = 0;
  for (size_t i = 0; i < KASPA_SIGN_MAX_INPUTS; i++) {
    const char* obj = json_array_nth_object(json, "inputs", i);
    if (!obj) break;
    KaspaSignInputDesc* inp = &tx->inputs[num_in];
    size_t tl = 0;
    if (!json_parse_hex_field(obj, "prev_tx_id", inp->prev_tx_id, sizeof(inp->prev_tx_id), &tl) || tl != 32) break;
    if (!json_parse_u32(obj, "prev_index", &inp->prev_index)) break;
    if (!json_parse_u64(obj, "sequence", &inp->sequence)) inp->sequence = 0;
    if (!json_parse_u8(obj, "sig_op_count", &inp->sig_op_count)) inp->sig_op_count = 0;
    if (!json_parse_u16(obj, "compute_budget", &inp->compute_budget)) inp->compute_budget = 0;
    if (!json_parse_u64(obj, "utxo_amount", &inp->utxo_amount)) break;
    if (!json_parse_u16(obj, "utxo_script_version", &inp->utxo_script_version)) inp->utxo_script_version = 0;
    size_t sl = 0;
    if (!json_parse_hex_field(obj, "utxo_script_hex", inp->utxo_script, sizeof(inp->utxo_script), &sl)) break;
    inp->utxo_script_len = (uint16_t)sl;
    if (json_has_key(obj, "sign_address_index")) {
      tx->sign_input_indices[tx->num_sign_inputs] = num_in;
      tx->num_sign_inputs++;
    }
    num_in++;
  }
  if (num_in == 0) {
    seterr("no inputs");
    return false;
  }
  if (json_array_nth_object(json, "inputs", num_in)) {
    if (num_in >= KASPA_SIGN_MAX_INPUTS) seterr("too many inputs");
    else seterr("bad input");
    return false;
  }
  tx->num_inputs = num_in;
  // Singlesig multi-UTXO: one approval must sign every input (each coin has its own sighash).
  // Do not rely only on which objects happened to include sign_address_index.
  if (!json_has_kaspa_multisig_redeem(json) && num_in > 0) {
    tx->num_sign_inputs = num_in;
    for (uint8_t i = 0; i < num_in; i++) {
      tx->sign_input_indices[i] = i;
    }
  }
  if (tx->num_sign_inputs == 0) {
    seterr("nothing to sign");
    return false;
  }
  return true;
}

}  // namespace

extern "C" bool seedmask_kaspa_sighash_selftest(char* err, size_t err_len) {
  auto seterr = [&](const char* m) {
    if (err && err_len) snprintf(err, err_len, "%s", m);
  };
  // Never put KaspaSignTx on the stack — multi-input capacity is several KB.
  static KaspaSignTx tx;
  memset(&tx, 0, sizeof(tx));
  tx.version = 0;
  tx.lock_time = 1615462089000ULL;
  tx.sighash_type = 1;
  tx.num_inputs = 3;
  tx.num_outputs = 2;

  size_t dummy = 0;
  hex_decode("880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3", tx.inputs[0].prev_tx_id, 32, &dummy);
  for (int i = 0; i < 3; i++) {
    memcpy(tx.inputs[i].prev_tx_id, tx.inputs[0].prev_tx_id, 32);
    tx.inputs[i].prev_index = (uint32_t)i;
    tx.inputs[i].sequence = (uint64_t)i;
    tx.inputs[i].sig_op_count = 0;
    tx.inputs[i].utxo_script_version = 0;
    size_t sl = 0;
    if (i == 0) {
      hex_decode("208325613d2eeaf7176ac6c670b13c0043156c427438ed72d74b7800862ad884e8ac", tx.inputs[i].utxo_script,
                 sizeof(tx.inputs[i].utxo_script), &sl);
      tx.inputs[i].utxo_amount = 100;
    } else if (i == 1) {
      hex_decode("20fcef4c106cf11135bbd70f02a726a92162d2fb8b22f0469126f800862ad884e8ac", tx.inputs[i].utxo_script,
                 sizeof(tx.inputs[i].utxo_script), &sl);
      tx.inputs[i].utxo_amount = 200;
    } else {
      hex_decode("20fcef4c106cf11135bbd70f02a726a92162d2fb8b22f0469126f800862ad884e8ac", tx.inputs[i].utxo_script,
                 sizeof(tx.inputs[i].utxo_script), &sl);
      tx.inputs[i].utxo_amount = 300;
    }
    tx.inputs[i].utxo_script_len = (uint16_t)sl;
  }

  size_t sl = 0;
  hex_decode("20fcef4c106cf11135bbd70f02a726a92162d2fb8b22f0469126f800862ad884e8ac", tx.outputs[0].script,
             sizeof(tx.outputs[0].script), &sl);
  tx.outputs[0].script_len = (uint16_t)sl;
  tx.outputs[0].value = 300;
  hex_decode("208325613d2eeaf7176ac6c670b13c0043156c427438ed72d74b7800862ad884e8ac", tx.outputs[1].script,
             sizeof(tx.outputs[1].script), &sl);
  tx.outputs[1].script_len = (uint16_t)sl;
  tx.outputs[1].value = 300;

  uint8_t hash[32];
  if (!kaspa_calc_schnorr_sighash(&tx, 0, hash)) {
    seterr("sighash calc");
    return false;
  }
  char got[65];
  hex_encode(hash, 32, got, sizeof(got));
  if (strcmp(got, "03b7ac6927b2b67100734c3cc313ff8c2e8b3ce3e746d46dd660b706a916b1f5") != 0) {
    seterr("sighash mismatch");
    return false;
  }

  uint8_t redeem[102];
  uint8_t p2sh[35];
  size_t redeem_len = 0, p2sh_len = 0;
  if (!hex_decode(
          "5220111111111111111111111111111111111111111111111111111111111111111120222222222222222222222222222222222222222222222222222222222222222220333333333333333333333333333333333333333333333333333333333333333353ae",
          redeem, sizeof(redeem), &redeem_len) ||
      !hex_decode("aa2042311bb06e80da61d37ff354ea78d9e5a50561273202d955cdb904732c8ccc9f87", p2sh,
                  sizeof(p2sh), &p2sh_len)) {
    seterr("multisig vector");
    return false;
  }
  uint8_t req = 0, total = 0;
  if (redeem_len != sizeof(redeem) || p2sh_len != sizeof(p2sh) ||
      !kaspa_validate_multisig_redeem_script(redeem, redeem_len, &req, &total) || req != 2 || total != 3 ||
      !kaspa_p2sh_matches_redeem_script(p2sh, p2sh_len, redeem, redeem_len) ||
      !kaspa_script_contains_xonly_pubkey(redeem, redeem_len, redeem + 2)) {
    seterr("multisig p2sh");
    return false;
  }
  return true;
}

extern "C" bool seedmask_kaspa_unsigned_is_v2(const char* json, size_t json_len) {
  if (!json || json_len < 10) return false;
  uint32_t ver = 0;
  return json_parse_u32(json, "version", &ver) && ver == 2;
}

extern "C" bool seedmask_kaspa_unsigned_has_multisig_redeem(const char* json, size_t json_len) {
  (void)json_len;
  return json_has_kaspa_multisig_redeem(json);
}

extern "C" int seedmask_kaspa_unsigned_kpub_status(const char* json, size_t json_len, uint32_t account) {
  if (!json || json_len < 10) return 0;
  const bool is_multisig = json_has_kaspa_multisig_redeem(json);
  char tx_kpub[120] = {0};
  bool has_tx_kpub = false;
  if (json_parse_string_field(json, "kpub", tx_kpub, sizeof(tx_kpub)) && tx_kpub[0]) {
    has_tx_kpub = true;
  } else if (json_parse_string_field(json, "xpub", tx_kpub, sizeof(tx_kpub)) && tx_kpub[0]) {
    has_tx_kpub = true;
  }
  if (is_multisig) {
    // Cosigner check is authoritative for multisig (tx may omit kpub or carry a coordinator watch kpub).
    if (kaspa_device_pubkey_in_unsigned_redeem(json, account)) return 1;
    if (has_tx_kpub && seedmask_wallet_kaspa_imported_kpub_matches(account, tx_kpub)) return 1;
    return 2;  // this device is not a signer for this policy/tx
  }
  if (!has_tx_kpub) return 0;
  if (seedmask_wallet_kaspa_imported_kpub_matches(account, tx_kpub)) return 1;
  return 2;
}

static bool kaspa_script_to_mainnet_address(const uint8_t* script, size_t script_len, char* out, size_t out_len) {
  if (!script || !out || out_len < 16) return false;
  // P2PK Schnorr: OP_DATA_32 || xonly || OP_CHECKSIG
  if (script_len == 34 && script[0] == 0x20 && script[33] == 0xac)
    return kaspa_encode_address_mainnet(script + 1, out, out_len);
  // P2SH: OP_BLAKE2B || OP_DATA_32 || hash || OP_EQUAL
  if (script_len == 35 && script[0] == 0xaa && script[1] == 0x20 && script[34] == 0x87)
    return kaspa_encode_p2sh_address_mainnet(script + 2, out, out_len);
  return false;
}

static bool kaspa_scripts_equal(const uint8_t* a, size_t alen, const uint8_t* b, size_t blen) {
  return a && b && alen == blen && alen > 0 && memcmp(a, b, alen) == 0;
}

extern "C" bool seedmask_kaspa_review_summarize(const char* json, size_t json_len, seedmask_kaspa_review_t* out) {
  if (!out) return false;
  memset(out, 0, sizeof(*out));
  if (!json || json_len < 20) {
    snprintf(out->err, sizeof(out->err), "no tx");
    return false;
  }
  if (!seedmask_kaspa_unsigned_is_v2(json, json_len)) {
    snprintf(out->err, sizeof(out->err), "need v2");
    return false;
  }

  static KaspaSignTx tx;
  memset(&tx, 0, sizeof(tx));
  char parse_err[64] = {0};
  if (!build_tx_from_json(json, &tx, parse_err, sizeof(parse_err))) {
    snprintf(out->err, sizeof(out->err), "%s", parse_err[0] ? parse_err : "parse");
    return false;
  }

  uint64_t in_sum = 0;
  for (uint8_t i = 0; i < tx.num_inputs; i++) in_sum += tx.inputs[i].utxo_amount;
  uint64_t out_sum = 0;
  for (uint8_t i = 0; i < tx.num_outputs; i++) out_sum += tx.outputs[i].value;
  if (out_sum > in_sum) {
    snprintf(out->err, sizeof(out->err), "outputs>inputs");
    return false;
  }

  uint64_t change_sum = 0;
  uint64_t send_sum = 0;
  int first_send = -1;
  int first_change = -1;
  bool any_change_marked = false;

  for (uint8_t oi = 0; oi < tx.num_outputs; oi++) {
    bool is_change = false;
    for (uint8_t ii = 0; ii < tx.num_inputs; ii++) {
      if (kaspa_scripts_equal(tx.outputs[oi].script, tx.outputs[oi].script_len, tx.inputs[ii].utxo_script,
                              tx.inputs[ii].utxo_script_len)) {
        is_change = true;
        break;
      }
    }
    if (is_change) {
      any_change_marked = true;
      change_sum += tx.outputs[oi].value;
      if (first_change < 0) first_change = (int)oi;
    } else {
      send_sum += tx.outputs[oi].value;
      if (first_send < 0) first_send = (int)oi;
    }
  }

  // No script overlap (e.g. all external): treat first output as send, rest as change.
  if (!any_change_marked && tx.num_outputs >= 2) {
    send_sum = tx.outputs[0].value;
    change_sum = 0;
    for (uint8_t oi = 1; oi < tx.num_outputs; oi++) change_sum += tx.outputs[oi].value;
    first_send = 0;
    first_change = 1;
  } else if (!any_change_marked && tx.num_outputs == 1) {
    send_sum = tx.outputs[0].value;
    change_sum = 0;
    first_send = 0;
  }

  out->in_sompi = in_sum;
  out->send_sompi = send_sum;
  out->change_sompi = change_sum;
  out->fee_sompi = in_sum - out_sum;
  out->num_inputs = tx.num_inputs;
  out->num_outputs = tx.num_outputs;

  if (first_send >= 0) {
    if (!kaspa_script_to_mainnet_address(tx.outputs[first_send].script, tx.outputs[first_send].script_len,
                                         out->dest_addr, sizeof(out->dest_addr))) {
      // Prefer optional address fields still present on some payloads
      const char* obj = json_array_nth_object(json, "outputs", (size_t)first_send);
      if (!obj || (!json_parse_string_field(obj, "kaspa_address", out->dest_addr, sizeof(out->dest_addr))
                   && !json_parse_string_field(obj, "to_address", out->dest_addr, sizeof(out->dest_addr)))) {
        snprintf(out->dest_addr, sizeof(out->dest_addr), "(see outputs)");
      }
    }
  } else {
    snprintf(out->dest_addr, sizeof(out->dest_addr), "-");
  }

  if (first_change >= 0 && change_sum > 0) {
    if (!kaspa_script_to_mainnet_address(tx.outputs[first_change].script, tx.outputs[first_change].script_len,
                                         out->change_addr, sizeof(out->change_addr))) {
      const char* obj = json_array_nth_object(json, "outputs", (size_t)first_change);
      if (!obj || (!json_parse_string_field(obj, "kaspa_address", out->change_addr, sizeof(out->change_addr))
                   && !json_parse_string_field(obj, "to_address", out->change_addr, sizeof(out->change_addr)))) {
        snprintf(out->change_addr, sizeof(out->change_addr), "(see outputs)");
      }
    }
  }

  if (out->send_sompi > 0) {
    // tenths of a percent: fee * 1000 / send
    out->fee_pct_of_send_tenths =
        (uint32_t)((out->fee_sompi * 1000ull) / out->send_sompi);
    out->big_fee_warn = (out->fee_pct_of_send_tenths >= 50u);  // >= 5.0%
  }

  // Visualize inputs: exact utxo_amount + Receive/Change from sign_chain / sign_address_index
  out->num_viz_inputs = 0;
  for (uint8_t i = 0; i < tx.num_inputs && out->num_viz_inputs < SEEDMASK_KASPA_REVIEW_MAX_INPUTS; i++) {
    const char* obj = json_array_nth_object(json, "inputs", i);
    uint32_t chain = 0;
    uint32_t addr_index = 0;
    if (obj) {
      if (!json_parse_u32(obj, "sign_chain", &chain)) {
        (void)json_parse_u32(obj, "chain", &chain);
      }
      if (!json_parse_u32(obj, "sign_address_index", &addr_index)) {
        if (!json_parse_u32(obj, "address_index", &addr_index))
          (void)json_parse_u32(obj, "index", &addr_index);
      }
    }
    if (chain > 1) chain = 0;
    const uint8_t slot = out->num_viz_inputs;
    out->viz_input_is_change[slot] = (chain == 1u) ? 1 : 0;
    out->viz_input_index[slot] = addr_index;
    out->viz_input_sompi[slot] = tx.inputs[i].utxo_amount;
    out->num_viz_inputs = (uint8_t)(slot + 1);
  }

  out->is_multisig = false;
  out->ms_required = 0;
  out->ms_total = 0;
  if (json_has_kaspa_multisig_redeem(json)) {
    const char* inp0 = json_array_nth_object(json, "inputs", 0);
    if (inp0) {
      uint8_t redeem[KASPA_SIGN_MAX_REDEEM];
      size_t redeem_len = 0;
      const char* redeem_key = json_has_key(inp0, "redeem_script_hex") ? "redeem_script_hex"
                             : (json_has_key(inp0, "redeemScript") ? "redeemScript" : nullptr);
      if (redeem_key
          && json_parse_hex_field(inp0, redeem_key, redeem, sizeof(redeem), &redeem_len)
          && redeem_len > 0) {
        uint8_t req = 0, tot = 0;
        if (kaspa_validate_multisig_redeem_script(redeem, redeem_len, &req, &tot)) {
          out->is_multisig = true;
          out->ms_required = req;
          out->ms_total = tot;
        }
        sp_zero(redeem, sizeof(redeem));
      }
    }
    if (!out->is_multisig) {
      out->is_multisig = true;  // redeem present even if m/n parse failed
    }
  }

  out->ok = true;
  return true;
}

extern "C" bool seedmask_kaspa_sign_with_mnemonic(const char* json, size_t json_len, const char* mnemonic, int word_count,
                                                const char* bip39_passphrase, uint32_t expected_account,
                                                char* out_json, size_t out_cap, size_t* out_len, char* err,
                                                size_t err_len) {
  auto seterr = [&](const char* m) {
    if (err && err_len) snprintf(err, err_len, "%s", m);
  };
  if (!json || json_len < 20 || !mnemonic || !out_json || !out_len || out_cap < 128) {
    seterr("bad args");
    return false;
  }
  *out_len = 0;

  uint32_t ver = 0;
  if (!json_parse_u32(json, "version", &ver) || ver != 2) {
    seterr("need version 2");
    return false;
  }
  char draft_hash[65] = {0};
  bool has_draft_hash = json_parse_string_field(json, "draft_hash", draft_hash, sizeof(draft_hash)) && draft_hash[0];
  if (!validate_mnemonic_word_count(mnemonic, word_count)) {
    seterr("mnemonic");
    return false;
  }

  static KaspaSignTx tx;
  memset(&tx, 0, sizeof(tx));
  if (!build_tx_from_json(json, &tx, err, err_len)) return false;

  uint32_t account = 0;
  if (!json_parse_u32(json, "account", &account)) {
    seterr("account");
    return false;
  }
  const bool unsigned_is_multisig = json_has_kaspa_multisig_redeem(json);
  if (account != expected_account && !unsigned_is_multisig) {
    seterr("account mismatch");
    return false;
  }
  if (unsigned_is_multisig) account = expected_account;
  (void)bip39_passphrase; /* derivation uses device seed cache (passphrase already applied there) */

  char tx_kpub[120] = {0};
  bool has_tx_kpub = false;
  if (json_parse_string_field(json, "kpub", tx_kpub, sizeof(tx_kpub)) && tx_kpub[0]) {
    has_tx_kpub = true;
  } else if (json_parse_string_field(json, "xpub", tx_kpub, sizeof(tx_kpub)) && tx_kpub[0]) {
    has_tx_kpub = true;
  }
  const bool tx_kpub_matches =
      has_tx_kpub && seedmask_wallet_kaspa_imported_kpub_matches(account, tx_kpub);

  // Keep large per-input scratch off the call stack (ESP32).
  static char sig_hex[KASPA_SIGN_MAX_INPUTS][131];
  static char sig_pubkey_hex[KASPA_SIGN_MAX_INPUTS][67];
  static bool sig_has_pubkey[KASPA_SIGN_MAX_INPUTS];
  static uint8_t sig_idx_map[KASPA_SIGN_MAX_INPUTS];
  uint8_t ns = 0;
  memset(sig_hex, 0, sizeof(sig_hex));
  memset(sig_pubkey_hex, 0, sizeof(sig_pubkey_hex));
  memset(sig_has_pubkey, 0, sizeof(sig_has_pubkey));
  memset(sig_idx_map, 0, sizeof(sig_idx_map));

  for (uint8_t si = 0; si < tx.num_sign_inputs; si++) {
    uint8_t in_idx = tx.sign_input_indices[si];
    const char* obj = json_array_nth_object(json, "inputs", in_idx);
    if (!obj) {
      seterr("input obj");
      return false;
    }
    uint32_t chain = 0, addr_index = 0;
    if (!json_parse_u32(obj, "sign_chain", &chain) || chain > 1) {
      seterr("sign_chain");
      return false;
    }
    if (!json_parse_u32(obj, "sign_address_index", &addr_index)) {
      seterr("sign_address_index");
      return false;
    }

    KaspaSignInputDesc* inp = &tx.inputs[in_idx];
    uint8_t priv[32];
    uint8_t signer_pub[33];
    bool is_multisig = false;
    memset(priv, 0, sizeof(priv));
    memset(signer_pub, 0, sizeof(signer_pub));

    uint8_t redeem_script[KASPA_SIGN_MAX_REDEEM];
    size_t redeem_len = 0;
    const char* redeem_key = json_has_key(obj, "redeem_script_hex") ? "redeem_script_hex"
                           : (json_has_key(obj, "redeemScript") ? "redeemScript" : nullptr);
    if (redeem_key) {
      if (!json_parse_hex_field(obj, redeem_key, redeem_script, sizeof(redeem_script), &redeem_len)) {
        seterr("redeem_script_hex");
        return false;
      }
      is_multisig = true;
      uint8_t required = 0, total = 0;
      if (!kaspa_validate_multisig_redeem_script(redeem_script, redeem_len, &required, &total)) {
        sp_zero(redeem_script, sizeof(redeem_script));
        seterr("bad redeem script");
        return false;
      }
      if (inp->sig_op_count != 0 && inp->sig_op_count != total) {
        sp_zero(redeem_script, sizeof(redeem_script));
        seterr("bad sig_op_count");
        return false;
      }
      inp->sig_op_count = total;
      if (!kaspa_p2sh_matches_redeem_script(inp->utxo_script, inp->utxo_script_len, redeem_script, redeem_len)) {
        sp_zero(redeem_script, sizeof(redeem_script));
        seterr("p2sh hash mismatch");
        return false;
      }
      if (!seedmask_wallet_derive_kaspa_multisig_priv(account, chain, addr_index, priv)) {
        sp_zero(redeem_script, sizeof(redeem_script));
        seterr("derive multisig");
        return false;
      }
      if (!secp_pubkey_compressed(priv, signer_pub)) {
        sp_zero(priv, sizeof(priv));
        sp_zero(redeem_script, sizeof(redeem_script));
        seterr("derive pubkey");
        return false;
      }
      if (!kaspa_script_contains_xonly_pubkey(redeem_script, redeem_len, signer_pub + 1)) {
        sp_zero(priv, sizeof(priv));
        sp_zero(signer_pub, sizeof(signer_pub));
        sp_zero(redeem_script, sizeof(redeem_script));
        seterr("signer not in redeem — wrong acct?");
        return false;
      }
      /* rusty-kaspa sighash hashes the P2SH script_public_key (utxo_script_hex), not the redeem
       * script. inp->utxo_script already holds the validated P2SH wrapper from JSON. */
      hex_encode(signer_pub, sizeof(signer_pub), sig_pubkey_hex[ns], sizeof(sig_pubkey_hex[ns]));
      sig_has_pubkey[ns] = true;
    } else {
      if (!seedmask_wallet_derive_kaspa_priv(account, chain, addr_index, priv)) {
        seterr("derive (unlock seed?)");
        return false;
      }

      /* On-chain script for this path — always from device (QR script_hex is often wrong from explorers). */
      uint8_t onchain_script[34];
      if (!seedmask_wallet_kaspa_build_utxo_script(account, chain, addr_index, onchain_script)) {
        sp_zero(priv, sizeof(priv));
        seterr("derive script");
        return false;
      }
      memcpy(inp->utxo_script, onchain_script, 34);
      inp->utxo_script_len = 34;
    }

    char qr_recv[80] = {0};
    if (!is_multisig && json_parse_string_field(obj, "receive_address", qr_recv, sizeof(qr_recv)) && qr_recv[0]) {
      char dev_recv[80] = {0};
      bool addr_ok = seedmask_wallet_kaspa_address_for_index(account, chain, addr_index, dev_recv, sizeof(dev_recv))
                     && kaspa_addrs_equal_ci(qr_recv, dev_recv);
      if (!addr_ok) {
        if (tx_kpub_matches) {
          /* Coordinator file/QR may carry a stale receive_address; kpub proves same wallet. */
        } else if (has_tx_kpub) {
          sp_zero(priv, sizeof(priv));
          snprintf(err, err_len, "kpub mismatch (acct %u)", (unsigned)account);
          return false;
        } else {
          sp_zero(priv, sizeof(priv));
          snprintf(err, err_len, "QR address != Receive #%u", (unsigned)addr_index);
          return false;
        }
      }
    } else if (!is_multisig && has_tx_kpub && !tx_kpub_matches) {
      sp_zero(priv, sizeof(priv));
      snprintf(err, err_len, "kpub mismatch (acct %u)", (unsigned)account);
      return false;
    }

    uint8_t sighash[32];
    if (!kaspa_calc_schnorr_sighash(&tx, in_idx, sighash)) {
      sp_zero(priv, sizeof(priv));
      sp_zero(signer_pub, sizeof(signer_pub));
      sp_zero(redeem_script, sizeof(redeem_script));
      seterr("sighash");
      return false;
    }
    uint8_t sig64[64];
    if (!seedmask_kaspa_bip340_sign(priv, sighash, nullptr, sig64)) {
      sp_zero(priv, sizeof(priv));
      sp_zero(sighash, sizeof(sighash));
      sp_zero(signer_pub, sizeof(signer_pub));
      sp_zero(redeem_script, sizeof(redeem_script));
      seterr("Schnorr failed");
      return false;
    }
    sp_zero(priv, sizeof(priv));
    sp_zero(sighash, sizeof(sighash));
    hex_encode(sig64, 64, sig_hex[ns], sizeof(sig_hex[ns]));
    sp_zero(sig64, sizeof(sig64));
    sp_zero(signer_pub, sizeof(signer_pub));
    sp_zero(redeem_script, sizeof(redeem_script));
    sig_idx_map[ns] = in_idx;
    ns++;
  }

  int n = has_draft_hash
              ? snprintf(out_json, out_cap,
                         "{\"version\":2,\"network\":\"mainnet\",\"account\":%u,\"draft_hash\":\"%s\",\"signatures\":[",
                         account, draft_hash)
              : snprintf(out_json, out_cap,
                         "{\"version\":2,\"network\":\"mainnet\",\"account\":%u,\"signatures\":[", account);
  if (n < 0 || (size_t)n >= out_cap) {
    seterr("out full");
    return false;
  }
  size_t off = (size_t)n;
  for (uint8_t i = 0; i < ns; i++) {
    int m = sig_has_pubkey[i]
                ? snprintf(out_json + off, out_cap - off,
                           "%s{\"input_index\":%u,\"sig_hex\":\"%s\",\"pubkey_hex\":\"%s\"}", i ? "," : "",
                           (unsigned)sig_idx_map[i], sig_hex[i], sig_pubkey_hex[i])
                : snprintf(out_json + off, out_cap - off,
                           "%s{\"input_index\":%u,\"sig_hex\":\"%s\"}", i ? "," : "", (unsigned)sig_idx_map[i],
                           sig_hex[i]);
    if (m < 0 || (size_t)m >= out_cap - off) {
      seterr("out full");
      return false;
    }
    off += (size_t)m;
  }
  if (off + 2 >= out_cap) {
    seterr("out full");
    return false;
  }
  out_json[off++] = ']';
  out_json[off++] = '}';
  out_json[off] = 0;
  *out_len = off;
  return true;
}
