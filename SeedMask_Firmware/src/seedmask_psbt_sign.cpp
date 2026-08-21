// SPDX-License-Identifier: MIT
// BIP174 PSBT parse/update, BIP143 segwit-v0 sighash (P2WPKH/P2WSH), ECDSA (mbedtls), BC-UR single-part decode.

#include "seedmask_psbt_sign.h"

#include "bc-ur/bytewords.hpp"
#include "bc-ur/cbor-lite.hpp"
#include "bc-ur/fountain-decoder.hpp"
#include "bc-ur/fountain-encoder.hpp"

#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/bignum.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/platform_util.h"
#if defined(MBEDTLS_ECDSA_DETERMINISTIC)
#include "mbedtls/md.h"
#endif

#include "esp_random.h"

#include <algorithm>
#include <cstring>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#if defined(ARDUINO_ARCH_ESP32)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
static inline void seedmask_boot_selftest_yield(void) {
  vTaskDelay(pdMS_TO_TICKS(2));
}
#else
static inline void seedmask_boot_selftest_yield(void) {}
#endif

namespace {

using PsbtMap = std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>;
static constexpr size_t PSBT_MAX_MAP_ENTRIES = 512;
static constexpr size_t PSBT_MAX_KEY_LEN = 1024;
static constexpr size_t PSBT_MAX_VALUE_LEN = 1024 * 1024;  // 1MB upper guard

static void sp_zero(void* p, size_t n) {
  if (!p || n == 0) return;
#if defined(MBEDTLS_PLATFORM_ZEROIZE_ALT) || defined(MBEDTLS_PLATFORM_C)
  // Preferred hardened wipe primitive from mbedTLS.
  mbedtls_platform_zeroize(p, n);
#else
  // Fallback that resists optimization when platform zeroize is unavailable.
  volatile uint8_t* vp = (volatile uint8_t*)p;
  while (n--) *vp++ = 0;
#endif
}

static int sp_rng(void*, unsigned char* out, size_t len) {
  esp_fill_random(out, len);
  return 0;
}

static void sha256_once(const uint8_t* in, size_t inLen, uint8_t out[32]) {
  mbedtls_sha256_context c;
  mbedtls_sha256_init(&c);
  mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, in, inLen);
  mbedtls_sha256_finish(&c, out);
  mbedtls_sha256_free(&c);
}

static void sha256d(const uint8_t* in, size_t inLen, uint8_t out[32]) {
  uint8_t t[32];
  sha256_once(in, inLen, t);
  sha256_once(t, sizeof(t), out);
  sp_zero(t, sizeof(t));
}

static inline uint32_t rol32(uint32_t x, uint8_t n) { return (x << n) | (x >> (32 - n)); }
static inline uint32_t ripemd_f(uint8_t j, uint32_t x, uint32_t y, uint32_t z) {
  if (j < 16) return x ^ y ^ z;
  if (j < 32) return (x & y) | (~x & z);
  if (j < 48) return (x | ~y) ^ z;
  if (j < 64) return (x & z) | (y & ~z);
  return x ^ (y | ~z);
}
static inline uint32_t ripemd_k(uint8_t j) {
  if (j < 16) return 0x00000000UL;
  if (j < 32) return 0x5A827999UL;
  if (j < 48) return 0x6ED9EBA1UL;
  if (j < 64) return 0x8F1BBCDCUL;
  return 0xA953FD4EUL;
}
static inline uint32_t ripemd_kk(uint8_t j) {
  if (j < 16) return 0x50A28BE6UL;
  if (j < 32) return 0x5C4DD124UL;
  if (j < 48) return 0x6D703EF3UL;
  if (j < 64) return 0x7A6D76E9UL;
  return 0x00000000UL;
}
static bool ripemd160_once(const uint8_t* msg, size_t len, uint8_t out20[20]) {
  static const uint8_t RL[80] = {
      0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
      7, 4,13, 1,10, 6,15, 3,12, 0, 9, 5, 2,14,11, 8,
      3,10,14, 4, 9,15, 8, 1, 2, 7, 0, 6,13,11, 5,12,
      1, 9,11,10, 0, 8,12, 4,13, 3, 7,15,14, 5, 6, 2,
      4, 0, 5, 9, 7,12, 2,10,14, 1, 3, 8,11, 6,15,13
  };
  static const uint8_t RR[80] = {
      5,14, 7, 0, 9, 2,11, 4,13, 6,15, 8, 1,10, 3,12,
      6,11, 3, 7, 0,13, 5,10,14,15, 8,12, 4, 9, 1, 2,
     15, 5, 1, 3, 7,14, 6, 9,11, 8,12, 2,10, 0, 4,13,
      8, 6, 4, 1, 3,11,15, 0, 5,12, 2,13, 9, 7,10,14,
     12,15,10, 4, 1, 5, 8, 7, 6, 2,13,14, 0, 3, 9,11
  };
  static const uint8_t SL[80] = {
     11,14,15,12, 5, 8, 7, 9,11,13,14,15, 6, 7, 9, 8,
      7, 6, 8,13,11, 9, 7,15, 7,12,15, 9,11, 7,13,12,
     11,13, 6, 7,14, 9,13,15,14, 8,13, 6, 5,12, 7, 5,
     11,12,14,15,14,15, 9, 8, 9,14, 5, 6, 8, 6, 5,12,
      9,15, 5,11, 6, 8,13,12, 5,12,13,14,11, 8, 5, 6
  };
  static const uint8_t SR[80] = {
      8, 9, 9,11,13,15,15, 5, 7, 7, 8,11,14,14,12, 6,
      9,13,15, 7,12, 8, 9,11, 7, 7,12, 7, 6,15,13,11,
      9, 7,15,11, 8, 6, 6,14,12,13, 5,14,13,13, 7, 5,
     15, 5, 8,11,14,14, 6,14, 6, 9,12, 9,12, 5,15, 8,
      8, 5,12, 9,12, 5,14, 6, 8,13, 6, 5,15,13,11,11
  };
  uint32_t h0 = 0x67452301UL, h1 = 0xEFCDAB89UL, h2 = 0x98BADCFEUL, h3 = 0x10325476UL, h4 = 0xC3D2E1F0UL;
  size_t total = len + 1 + 8;
  size_t pad = (64 - (total % 64)) % 64;
  size_t msgLen = len + 1 + pad + 8;
  uint8_t* m = (uint8_t*)malloc(msgLen);
  if (!m) return false;
  memcpy(m, msg, len);
  m[len] = 0x80;
  if (pad) memset(m + len + 1, 0, pad);
  memset(m + len + 1 + pad, 0, 8);
  uint64_t bitLen = (uint64_t)len * 8ULL;
  for (uint8_t i = 0; i < 8; i++) m[msgLen - 8 + i] = (uint8_t)(bitLen >> (8 * i));

  for (size_t off = 0; off < msgLen; off += 64) {
    uint32_t X[16];
    for (uint8_t i = 0; i < 16; i++) {
      const uint8_t* p = m + off + i * 4;
      X[i] = ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    }
    uint32_t al=h0, bl=h1, cl=h2, dl=h3, el=h4;
    uint32_t ar=h0, br=h1, cr=h2, dr=h3, er=h4;
    for (uint8_t j = 0; j < 80; j++) {
      uint32_t tl = rol32(al + ripemd_f(j, bl, cl, dl) + X[RL[j]] + ripemd_k(j), SL[j]) + el;
      al = el; el = dl; dl = rol32(cl, 10); cl = bl; bl = tl;
      uint8_t jj = (uint8_t)(79 - j);
      uint32_t tr = rol32(ar + ripemd_f(jj, br, cr, dr) + X[RR[j]] + ripemd_kk(j), SR[j]) + er;
      ar = er; er = dr; dr = rol32(cr, 10); cr = br; br = tr;
    }
    uint32_t t = h1 + cl + dr;
    h1 = h2 + dl + er;
    h2 = h3 + el + ar;
    h3 = h4 + al + br;
    h4 = h0 + bl + cr;
    h0 = t;
    sp_zero(X, sizeof(X));
  }
  free(m);
  uint32_t H[5] = { h0, h1, h2, h3, h4 };
  for (uint8_t i = 0; i < 5; i++) {
    out20[i*4 + 0] = (uint8_t)(H[i] & 0xFF);
    out20[i*4 + 1] = (uint8_t)((H[i] >> 8) & 0xFF);
    out20[i*4 + 2] = (uint8_t)((H[i] >> 16) & 0xFF);
    out20[i*4 + 3] = (uint8_t)((H[i] >> 24) & 0xFF);
  }
  sp_zero(H, sizeof(H));
  return true;
}

static bool hash160_mbedtls(const uint8_t* in, size_t inLen, uint8_t out20[20]) {
  uint8_t s[32];
  sha256_once(in, inLen, s);
  bool ok = ripemd160_once(s, sizeof(s), out20);
  sp_zero(s, sizeof(s));
  return ok;
}

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

static bool pbkdf2_sha512(const uint8_t* pw, size_t pwLen, const uint8_t* salt, size_t saltLen,
                          uint32_t iters, uint8_t* outKey, size_t outKeyLen) {
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
      if ((j & 127u) == 0u) seedmask_boot_selftest_yield();
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

struct Bip32Node {
  uint8_t k[32];
  uint8_t c[32];
};

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

/// Derive child private key from an already-loaded master node (single PBKDF2 path for PSBT signing).
static bool derive_priv_from_master_node(Bip32Node n, const uint32_t* path, size_t pathLen, uint8_t priv[32]) {
  for (size_t i = 0; i < pathLen; i++) {
    uint32_t raw = path[i];
    bool h = (raw & 0x80000000u) != 0;
    uint32_t idx = raw & 0x7fffffffu;
    if (!bip32_ckd_priv(&n, idx, h)) {
      sp_zero(&n, sizeof(n));
      return false;
    }
  }
  memcpy(priv, n.k, 32);
  sp_zero(&n, sizeof(n));
  return true;
}

/// BIP39: valid counts and whitespace-separated words must match `word_count`.
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

struct ClearBip32Node {
  Bip32Node* n;
  explicit ClearBip32Node(Bip32Node* p) : n(p) {}
  ~ClearBip32Node() {
    if (n) sp_zero(n, sizeof(Bip32Node));
  }
};

static bool read_compact_size(const uint8_t* p, size_t len, size_t& pos, uint64_t& out) {
  if (pos >= len) return false;
  uint8_t c = p[pos++];
  if (c < 0xfd) {
    out = c;
    return true;
  }
  if (c == 0xfd) {
    if (pos + 2 > len) return false;
    out = (uint64_t)p[pos] | ((uint64_t)p[pos + 1] << 8);
    pos += 2;
    return true;
  }
  if (c == 0xfe) {
    if (pos + 4 > len) return false;
    out = (uint64_t)p[pos] | ((uint64_t)p[pos + 1] << 8) | ((uint64_t)p[pos + 2] << 16) | ((uint64_t)p[pos + 3] << 24);
    pos += 4;
    return true;
  }
  if (pos + 8 > len) return false;
  out = 0;
  for (int i = 0; i < 8; i++) out |= (uint64_t)p[pos + i] << (8 * i);
  pos += 8;
  return true;
}

static void write_compact_size(std::vector<uint8_t>& out, uint64_t v) {
  if (v < 0xfd) {
    out.push_back((uint8_t)v);
  } else if (v <= 0xffff) {
    out.push_back(0xfd);
    out.push_back((uint8_t)(v & 0xff));
    out.push_back((uint8_t)((v >> 8) & 0xff));
  } else if (v <= 0xffffffffu) {
    out.push_back(0xfe);
    for (int i = 0; i < 4; i++) out.push_back((uint8_t)((v >> (8 * i)) & 0xff));
  } else {
    out.push_back(0xff);
    for (int i = 0; i < 8; i++) out.push_back((uint8_t)((v >> (8 * i)) & 0xff));
  }
}

struct TxInParsed {
  uint8_t prev[32];
  uint32_t prev_index;
  std::vector<uint8_t> script_sig;
  uint32_t sequence;
};

struct TxOutParsed {
  uint64_t value;
  std::vector<uint8_t> script_pubkey;
};

static bool parse_unsigned_tx(const uint8_t* tx, size_t txLen, std::vector<TxInParsed>& ins, std::vector<TxOutParsed>& outs,
                              uint32_t& version, uint32_t& locktime) {
  size_t pos = 0;
  if (txLen < 4) return false;
  version = (uint32_t)tx[pos] | ((uint32_t)tx[pos + 1] << 8) | ((uint32_t)tx[pos + 2] << 16) | ((uint32_t)tx[pos + 3] << 24);
  pos += 4;
  if (pos + 2 <= txLen && tx[pos] == 0x00 && tx[pos + 1] == 0x01) pos += 2;
  uint64_t nIn = 0;
  if (!read_compact_size(tx, txLen, pos, nIn) || nIn > 100000) return false;
  ins.clear();
  for (uint64_t i = 0; i < nIn; i++) {
    if (pos + 36 > txLen) return false;
    TxInParsed tin;
    memcpy(tin.prev, tx + pos, 32);
    pos += 32;
    tin.prev_index = (uint32_t)tx[pos] | ((uint32_t)tx[pos + 1] << 8) | ((uint32_t)tx[pos + 2] << 16) | ((uint32_t)tx[pos + 3] << 24);
    pos += 4;
    uint64_t slen = 0;
    if (!read_compact_size(tx, txLen, pos, slen) || slen > 10000000) return false;
    if (pos + slen > txLen) return false;
    tin.script_sig.assign(tx + pos, tx + pos + (size_t)slen);
    pos += (size_t)slen;
    if (pos + 4 > txLen) return false;
    tin.sequence = (uint32_t)tx[pos] | ((uint32_t)tx[pos + 1] << 8) | ((uint32_t)tx[pos + 2] << 16) | ((uint32_t)tx[pos + 3] << 24);
    pos += 4;
    ins.push_back(std::move(tin));
  }
  uint64_t nOut = 0;
  if (!read_compact_size(tx, txLen, pos, nOut) || nOut > 100000) return false;
  outs.clear();
  for (uint64_t i = 0; i < nOut; i++) {
    if (pos + 8 > txLen) return false;
    TxOutParsed tout;
    tout.value = 0;
    for (int b = 0; b < 8; b++) tout.value |= (uint64_t)tx[pos + b] << (8 * b);
    pos += 8;
    uint64_t pklen = 0;
    if (!read_compact_size(tx, txLen, pos, pklen) || pklen > 10000000) return false;
    if (pos + pklen > txLen) return false;
    tout.script_pubkey.assign(tx + pos, tx + pos + (size_t)pklen);
    pos += (size_t)pklen;
    outs.push_back(std::move(tout));
  }
  if (pos + 4 > txLen) return false;
  locktime = (uint32_t)tx[pos] | ((uint32_t)tx[pos + 1] << 8) | ((uint32_t)tx[pos + 2] << 16) | ((uint32_t)tx[pos + 3] << 24);
  return true;
}

static void serialize_outs_for_hash(const std::vector<TxOutParsed>& outs, std::vector<uint8_t>& buf) {
  buf.clear();
  // BIP143 hashOutputs is the double-SHA256 of the concatenation of ALL txouts,
  // without the txout-count CompactSize prefix.
  for (const auto& o : outs) {
    for (int b = 0; b < 8; b++) buf.push_back((uint8_t)((o.value >> (8 * b)) & 0xff));
    write_compact_size(buf, o.script_pubkey.size());
    buf.insert(buf.end(), o.script_pubkey.begin(), o.script_pubkey.end());
  }
}

static void hash_prevouts_seq(const std::vector<TxInParsed>& ins, uint8_t hprev[32], uint8_t hseq[32]) {
  std::vector<uint8_t> pbuf, sbuf;
  for (const auto& in : ins) {
    pbuf.insert(pbuf.end(), in.prev, in.prev + 32);
    for (int b = 0; b < 4; b++) pbuf.push_back((uint8_t)((in.prev_index >> (8 * b)) & 0xff));
    for (int b = 0; b < 4; b++) sbuf.push_back((uint8_t)((in.sequence >> (8 * b)) & 0xff));
  }
  sha256d(pbuf.data(), pbuf.size(), hprev);
  sha256d(sbuf.data(), sbuf.size(), hseq);
}

static bool ecdsa_der_sign(const uint8_t priv[32], const uint8_t msg32[32], uint8_t* der, size_t* derLen, size_t derCap) {
  mbedtls_ecp_group grp;
  mbedtls_mpi r, s, d;
  mbedtls_ecp_point Q;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&d);
  mbedtls_ecp_point_init(&Q);
  bool ok = false;
  if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0) goto done;
  if (mbedtls_mpi_read_binary(&d, priv, 32) != 0) goto done;
  if (mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, sp_rng, nullptr) != 0) goto done;
  {
    int sr = -1;
#if defined(MBEDTLS_ECDSA_DETERMINISTIC) && defined(MBEDTLS_VERSION_NUMBER) && (MBEDTLS_VERSION_NUMBER >= 0x03000000)
    sr = mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d, msg32, 32, MBEDTLS_MD_SHA256, sp_rng, nullptr);
#elif defined(MBEDTLS_ECDSA_DETERMINISTIC)
    sr = mbedtls_ecdsa_sign_det(&grp, &r, &s, &d, msg32, 32, MBEDTLS_MD_SHA256);
#endif
    if (sr != 0) {
      if (mbedtls_ecdsa_sign(&grp, &r, &s, &d, msg32, 32, sp_rng, nullptr) != 0) goto done;
    }
  }
  {
    mbedtls_mpi half;
    mbedtls_mpi_init(&half);
    mbedtls_mpi_copy(&half, &grp.N);
    mbedtls_mpi_shift_r(&half, 1);
    if (mbedtls_mpi_cmp_mpi(&s, &half) > 0) mbedtls_mpi_sub_mpi(&s, &grp.N, &s);
    mbedtls_mpi_free(&half);
  }
  if (mbedtls_ecdsa_verify(&grp, msg32, 32, &Q, &r, &s) != 0) goto done;
  {
    unsigned char buf[80];
    unsigned char* p = buf + sizeof(buf);
    size_t len = 0;
    int ret;
    if ((ret = mbedtls_asn1_write_mpi(&p, buf, &s)) < 0) goto done;
    len += (size_t)ret;
    if ((ret = mbedtls_asn1_write_mpi(&p, buf, &r)) < 0) goto done;
    len += (size_t)ret;
    size_t body = len;
    if ((ret = mbedtls_asn1_write_len(&p, buf, body)) < 0) goto done;
    len += (size_t)ret;
    if ((ret = mbedtls_asn1_write_tag(&p, buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) < 0) goto done;
    len += (size_t)ret;
    if (len > derCap) goto done;
    memcpy(der, p, len);
    *derLen = len;
    ok = true;
  }
done:
  mbedtls_ecp_point_free(&Q);
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_ecp_group_free(&grp);
  return ok;
}

static bool read_psbt_map(const uint8_t* in, size_t inLen, size_t& pos, PsbtMap& map) {
  map.clear();
  size_t entries = 0;
  while (true) {
    uint64_t keylen = 0;
    if (!read_compact_size(in, inLen, pos, keylen)) return false;
    if (keylen == 0) break;
    if (keylen > PSBT_MAX_KEY_LEN) return false;
    if (pos + keylen > inLen) return false;
    std::vector<uint8_t> key(in + pos, in + pos + (size_t)keylen);
    pos += (size_t)keylen;
    uint64_t vlen = 0;
    if (!read_compact_size(in, inLen, pos, vlen)) return false;
    if (vlen > PSBT_MAX_VALUE_LEN) return false;
    if (pos + vlen > inLen) return false;
    for (const auto& kv : map) {
      if (kv.first == key) return false;  // duplicate key in same map is invalid
    }
    std::vector<uint8_t> val(in + pos, in + pos + (size_t)vlen);
    pos += (size_t)vlen;
    map.push_back({std::move(key), std::move(val)});
    entries++;
    if (entries > PSBT_MAX_MAP_ENTRIES) return false;
  }
  return true;
}

static void write_psbt_map(std::vector<uint8_t>& out, const PsbtMap& map) {
  PsbtMap sorted = map;
  std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
  for (const auto& kv : sorted) {
    write_compact_size(out, kv.first.size());
    out.insert(out.end(), kv.first.begin(), kv.first.end());
    write_compact_size(out, kv.second.size());
    out.insert(out.end(), kv.second.begin(), kv.second.end());
  }
  write_compact_size(out, 0);
}

static const uint8_t PSBT_MAGIC[5] = {'p', 's', 'b', 't', 0xff};

enum class WitnessInputKind : uint8_t {
  UNKNOWN = 0,
  P2WPKH,
  P2WSH,
  P2SH
};

static bool parse_witness_utxo_script(const std::vector<uint8_t>& val, uint64_t& satoshis,
                                      std::vector<uint8_t>& script_pubkey, WitnessInputKind& kind) {
  if (val.size() < 8) return false;
  satoshis = 0;
  for (int b = 0; b < 8; b++) satoshis |= (uint64_t)val[b] << (8 * b);
  size_t pos = 8;
  uint64_t spklen = 0;
  if (!read_compact_size(val.data(), val.size(), pos, spklen)) return false;
  if (pos + spklen > val.size()) return false;
  const uint8_t* spk = val.data() + pos;
  script_pubkey.assign(spk, spk + (size_t)spklen);
  kind = WitnessInputKind::UNKNOWN;
  if (spklen == 22 && spk[0] == 0x00 && spk[1] == 0x14) kind = WitnessInputKind::P2WPKH;
  else if (spklen == 34 && spk[0] == 0x00 && spk[1] == 0x20) kind = WitnessInputKind::P2WSH;
  else if (spklen == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87) kind = WitnessInputKind::P2SH;
  return (kind != WitnessInputKind::UNKNOWN);
}

static bool script_contains_pubkey_push(const std::vector<uint8_t>& script, const uint8_t pub33[33]) {
  if (!pub33 || script.size() < 34) return false;
  for (size_t i = 0; i + 34 <= script.size(); i++) {
    if (script[i] == 0x21 && memcmp(script.data() + i + 1, pub33, 33) == 0) return true;
  }
  return false;
}

// BIP174 magic + parsable global map + unsigned tx key (0x00) present.
static bool validate_decoded_psbt_payload(const uint8_t* in, size_t inLen, char* err, size_t errLen) {
  auto seterr = [&](const char* m) {
    if (err && errLen) snprintf(err, errLen, "%s", m);
  };
  if (!in || inLen < 10) {
    seterr("PSBT too short");
    return false;
  }
  if (memcmp(in, PSBT_MAGIC, 5) != 0) {
    seterr("not PSBT");
    return false;
  }
  size_t pos = 5;
  PsbtMap global;
  if (!read_psbt_map(in, inLen, pos, global)) {
    seterr("bad PSBT global map");
    return false;
  }
  bool has_unsigned = false;
  size_t unsigned_count = 0;
  for (const auto& kv : global) {
    if (kv.first.size() == 1 && kv.first[0] == 0x00) {
      has_unsigned = true;
      unsigned_count++;
      if (kv.second.empty()) {
        seterr("empty unsigned tx");
        return false;
      }
    }
  }
  if (!has_unsigned) {
    seterr("no unsigned tx");
    return false;
  }
  if (unsigned_count != 1) {
    seterr("multiple unsigned tx");
    return false;
  }

  // Parse unsigned tx to enforce full PSBT structure size/count sanity.
  const std::vector<uint8_t>* unsigned_raw = nullptr;
  for (const auto& kv : global) {
    if (kv.first.size() == 1 && kv.first[0] == 0x00) {
      unsigned_raw = &kv.second;
      break;
    }
  }
  if (!unsigned_raw) {
    seterr("no unsigned tx");
    return false;
  }
  std::vector<TxInParsed> tins;
  std::vector<TxOutParsed> touts;
  uint32_t version = 0, locktime = 0;
  if (!parse_unsigned_tx(unsigned_raw->data(), unsigned_raw->size(), tins, touts, version, locktime)) {
    seterr("bad unsigned tx");
    return false;
  }

  // Ensure exactly one map per input/output (BIP174 canonical layout).
  PsbtMap tmp;
  for (size_t i = 0; i < tins.size(); i++) {
    if (!read_psbt_map(in, inLen, pos, tmp)) {
      seterr("bad input map");
      return false;
    }
  }
  for (size_t i = 0; i < touts.size(); i++) {
    if (!read_psbt_map(in, inLen, pos, tmp)) {
      seterr("bad output map");
      return false;
    }
  }
  if (pos != inLen) {
    seterr("trailing PSBT data");
    return false;
  }

  return true;
}

static bool witness_utxo_value_sat(const std::vector<uint8_t>& val, uint64_t& sat) {
  if (val.size() < 8) return false;
  sat = 0;
  for (int b = 0; b < 8; b++) sat |= (uint64_t)val[b] << (8 * b);
  return true;
}

// Match common BTC change script types for a derived compressed pubkey.
static bool script_matches_pubkey_change(const std::vector<uint8_t>& script_pubkey, const uint8_t pub33[33]) {
  if (!pub33) return false;
  // P2TR key-path: OP_1 0x20 <32-byte x-only> (BIP341)
  if (script_pubkey.size() == 34 && script_pubkey[0] == 0x51 && script_pubkey[1] == 0x20) {
    return memcmp(script_pubkey.data() + 2, pub33 + 1, 32) == 0;
  }
  uint8_t h160[20];
  if (!hash160_mbedtls(pub33, 33, h160)) return false;
  bool ok = false;
  // P2WPKH: 0x00 0x14 <20>
  if (script_pubkey.size() == 22 && script_pubkey[0] == 0x00 && script_pubkey[1] == 0x14) {
    ok = (memcmp(script_pubkey.data() + 2, h160, 20) == 0);
  }
  // P2PKH: OP_DUP OP_HASH160 0x14 <20> OP_EQUALVERIFY OP_CHECKSIG
  else if (script_pubkey.size() == 25 && script_pubkey[0] == 0x76 && script_pubkey[1] == 0xa9 &&
           script_pubkey[2] == 0x14 && script_pubkey[23] == 0x88 && script_pubkey[24] == 0xac) {
    ok = (memcmp(script_pubkey.data() + 3, h160, 20) == 0);
  }
  // P2SH-P2WPKH: OP_HASH160 0x14 <20> OP_EQUAL ; redeem = 0x00 0x14 <h160(pub)>
  else if (script_pubkey.size() == 23 && script_pubkey[0] == 0xa9 && script_pubkey[1] == 0x14 &&
           script_pubkey[22] == 0x87) {
    uint8_t redeem[22];
    redeem[0] = 0x00;
    redeem[1] = 0x14;
    memcpy(redeem + 2, h160, 20);
    uint8_t rh160[20];
    if (hash160_mbedtls(redeem, sizeof(redeem), rh160)) {
      ok = (memcmp(script_pubkey.data() + 2, rh160, 20) == 0);
    }
    sp_zero(redeem, sizeof(redeem));
    sp_zero(rh160, sizeof(rh160));
  }
  sp_zero(h160, sizeof(h160));
  return ok;
}

// BIP371 PSBT_OUT_TAP_BIP32_DERIVATION value: compact hashes + fingerprint + path.
static bool parse_tap_bip32_deriv_value(const std::vector<uint8_t>& val, uint8_t fp_out[4],
                                        std::vector<uint32_t>& path_out) {
  if (!fp_out || val.empty()) return false;
  size_t off = 0;
  uint64_t n_hashes = 0;
  if (val[0] < 253) {
    n_hashes = val[0];
    off = 1;
  } else if (val[0] == 253 && val.size() >= 3) {
    n_hashes = (uint64_t)val[1] | ((uint64_t)val[2] << 8);
    off = 3;
  } else {
    return false;
  }
  if (off + n_hashes * 32ull + 4ull > val.size()) return false;
  off += (size_t)n_hashes * 32u;
  memcpy(fp_out, val.data() + off, 4);
  off += 4;
  if (((val.size() - off) % 4) != 0) return false;
  const size_t n_path = (val.size() - off) / 4;
  path_out.resize(n_path);
  for (size_t p = 0; p < n_path; p++) {
    const uint8_t* q = val.data() + off + p * 4;
    path_out[p] = (uint32_t)q[0] | ((uint32_t)q[1] << 8) | ((uint32_t)q[2] << 16) | ((uint32_t)q[3] << 24);
  }
  return true;
}

static bool script_matches_xonly_change(const std::vector<uint8_t>& script_pubkey, const uint8_t xonly32[32]) {
  if (!xonly32) return false;
  if (script_pubkey.size() == 34 && script_pubkey[0] == 0x51 && script_pubkey[1] == 0x20)
    return memcmp(script_pubkey.data() + 2, xonly32, 32) == 0;
  return false;
}

static bool map_get_bytes_for_type(const PsbtMap& m, uint8_t keyType, std::vector<uint8_t>& out) {
  for (const auto& kv : m) {
    if (kv.first.size() == 1 && kv.first[0] == keyType) {
      out = kv.second;
      return true;
    }
  }
  out.clear();
  return false;
}

static bool multisig_change_claim_matches(const PsbtMap& m, const std::vector<uint8_t>& script_pubkey,
                                          const uint8_t claim_pub[33]) {
  std::vector<uint8_t> redeem_script;
  std::vector<uint8_t> witness_script;
  (void)map_get_bytes_for_type(m, 0x00, redeem_script);   // PSBT_OUT_REDEEM_SCRIPT
  (void)map_get_bytes_for_type(m, 0x01, witness_script);  // PSBT_OUT_WITNESS_SCRIPT

  // Native P2WSH output.
  if (script_pubkey.size() == 34 && script_pubkey[0] == 0x00 && script_pubkey[1] == 0x20) {
    if (witness_script.empty() || !script_contains_pubkey_push(witness_script, claim_pub)) return false;
    uint8_t sh[32];
    sha256_once(witness_script.data(), witness_script.size(), sh);
    bool ok = (memcmp(script_pubkey.data() + 2, sh, 32) == 0);
    sp_zero(sh, sizeof(sh));
    return ok;
  }

  // Nested P2WSH output in P2SH.
  if (script_pubkey.size() == 23 && script_pubkey[0] == 0xa9 && script_pubkey[1] == 0x14 && script_pubkey[22] == 0x87) {
    if (redeem_script.size() == 34 && redeem_script[0] == 0x00 && redeem_script[1] == 0x20 && !witness_script.empty()
        && script_contains_pubkey_push(witness_script, claim_pub)) {
      uint8_t rh160[20];
      uint8_t sh[32];
      bool ok = false;
      sha256_once(witness_script.data(), witness_script.size(), sh);
      if (memcmp(redeem_script.data() + 2, sh, 32) == 0 && hash160_mbedtls(redeem_script.data(), redeem_script.size(), rh160)) {
        ok = (memcmp(script_pubkey.data() + 2, rh160, 20) == 0);
      }
      sp_zero(sh, sizeof(sh));
      sp_zero(rh160, sizeof(rh160));
      return ok;
    }
    // Legacy P2SH multisig (change detection only): redeem script directly under hash160.
    if (!redeem_script.empty() && script_contains_pubkey_push(redeem_script, claim_pub)) {
      uint8_t rh160[20];
      bool ok = hash160_mbedtls(redeem_script.data(), redeem_script.size(), rh160)
                && (memcmp(script_pubkey.data() + 2, rh160, 20) == 0);
      sp_zero(rh160, sizeof(rh160));
      return ok;
    }
  }
  return false;
}

// Verify that a PSBT output marked with BIP32 derivation and our master fingerprint
// is truly ours: derive pubkey from seed path and confirm it matches output script.
static bool psbt_output_is_change_verified(const PsbtMap& m, const std::vector<uint8_t>& script_pubkey,
                                           const Bip32Node& master_node, const uint8_t master_fp[4]) {
  for (const auto& kv : m) {
    if (kv.first.size() == 34 && kv.first[0] == 0x02) {
      if (kv.second.size() < 8 || ((kv.second.size() - 4) % 4) != 0) continue;
      if (memcmp(kv.second.data(), master_fp, 4) != 0) continue;

      const uint8_t* claim_pub = kv.first.data() + 1;
      const size_t n_path = (kv.second.size() - 4) / 4;
      std::vector<uint32_t> path(n_path);
      for (size_t p = 0; p < n_path; p++) {
        const uint8_t* q = kv.second.data() + 4 + p * 4;
        path[p] = (uint32_t)q[0] | ((uint32_t)q[1] << 8) | ((uint32_t)q[2] << 16) | ((uint32_t)q[3] << 24);
      }

      uint8_t priv[32];
      uint8_t pub[33];
      bool ok = derive_priv_from_master_node(master_node, path.data(), path.size(), priv) &&
                secp_pubkey_compressed(priv, pub) &&
                memcmp(pub, claim_pub, 33) == 0 &&
                (script_matches_pubkey_change(script_pubkey, pub)
                 || multisig_change_claim_matches(m, script_pubkey, pub));
      sp_zero(priv, sizeof(priv));
      sp_zero(pub, sizeof(pub));
      if (ok) return true;
      continue;
    }
    // BIP371 taproot key-path change (script = tweaked Q; claim = internal P)
    if (kv.first.size() == 33 && kv.first[0] == 0x07) {
      uint8_t fp[4];
      std::vector<uint32_t> path;
      if (!parse_tap_bip32_deriv_value(kv.second, fp, path)) continue;
      if (memcmp(fp, master_fp, 4) != 0) continue;
      if (script_pubkey.size() != 34 || script_pubkey[0] != 0x51 || script_pubkey[1] != 0x20) continue;
      uint8_t priv[32];
      uint8_t pub[33];
      bool ok = derive_priv_from_master_node(master_node, path.data(), path.size(), priv) &&
                secp_pubkey_compressed(priv, pub) &&
                memcmp(pub + 1, kv.first.data() + 1, 32) == 0;
      sp_zero(priv, sizeof(priv));
      sp_zero(pub, sizeof(pub));
      if (ok) return true;
    }
  }
  return false;
}

// BIP44/49/84/86 and typical multisig: path ends with …/change/index. Change chain == 1.
static bool bip32_path_is_change_chain(const uint32_t* path, size_t n_path) {
  if (!path || n_path < 2) return false;
  return (path[n_path - 2] & 0x7fffffffu) == 1u;
}

// Review-only helper (no seed available): require master-fingerprint claim AND that claimed pubkey
// is at least script-consistent AND the path is the change chain (…/1/i). Receive-path outputs
// (self-pay / Sparrow-tagged payment) must count as send, not change.
// Full ownership proof is enforced in signer via psbt_output_is_change_verified(..., master_node, ...).
static bool psbt_output_is_change_claim_consistent(const PsbtMap& m, const std::vector<uint8_t>& script_pubkey,
                                                   const uint8_t master_fp[4]) {
  for (const auto& kv : m) {
    // PSBT_OUT_BIP32_DERIVATION (segwit / legacy / multisig)
    if (kv.first.size() == 34 && kv.first[0] == 0x02) {
      if (kv.second.size() < 8 || ((kv.second.size() - 4) % 4) != 0) continue;
      if (memcmp(kv.second.data(), master_fp, 4) != 0) continue;
      const size_t n_path = (kv.second.size() - 4) / 4;
      std::vector<uint32_t> path(n_path);
      for (size_t p = 0; p < n_path; p++) {
        const uint8_t* q = kv.second.data() + 4 + p * 4;
        path[p] = (uint32_t)q[0] | ((uint32_t)q[1] << 8) | ((uint32_t)q[2] << 16) | ((uint32_t)q[3] << 24);
      }
      if (!bip32_path_is_change_chain(path.data(), n_path)) continue;
      const uint8_t* claim_pub = kv.first.data() + 1;
      if (script_matches_pubkey_change(script_pubkey, claim_pub)
          || multisig_change_claim_matches(m, script_pubkey, claim_pub)) return true;
      continue;
    }
    // PSBT_OUT_TAP_BIP32_DERIVATION (BIP371) — Coordinator taproot change uses this, not 0x02.
    // scriptPubKey holds the tweaked output key; BIP32 claim is the internal x-only.
    if (kv.first.size() == 33 && kv.first[0] == 0x07) {
      uint8_t fp[4];
      std::vector<uint32_t> path;
      if (!parse_tap_bip32_deriv_value(kv.second, fp, path)) continue;
      if (memcmp(fp, master_fp, 4) != 0) continue;
      if (!bip32_path_is_change_chain(path.data(), path.size())) continue;
      if (script_pubkey.size() != 34 || script_pubkey[0] != 0x51 || script_pubkey[1] != 0x20) continue;
      const uint8_t* xonly = kv.first.data() + 1;
      bool internal_ok = true;
      for (const auto& ik : m) {
        if (ik.first.size() == 1 && ik.first[0] == 0x05 && ik.second.size() == 32) {
          internal_ok = (memcmp(ik.second.data(), xonly, 32) == 0);
          break;
        }
      }
      if (internal_ok) return true;
    }
  }
  return false;
}

}  // namespace

static ur::FountainDecoder g_psbt_fountain;
static ur::FountainDecoder g_policy_fountain;
static ur::FountainDecoder g_kaspa_pskt_fountain;

static bool ur_cbor_to_psbt_bytes(const ur::ByteVector& cbor, uint8_t* out, size_t maxOut, size_t* outLen) {
  try {
    auto it = cbor.begin();
    auto end = cbor.end();
    ur::ByteVector raw;
    CborLite::decodeBytes(it, end, raw);
    if (it != end) return false;  // reject trailing CBOR (invalid UR payload)
    if (raw.empty() || raw.size() > maxOut) return false;
    memcpy(out, raw.data(), raw.size());
    *outLen = raw.size();
    return true;
  } catch (...) {
    return false;
  }
}

extern "C" void seedmask_ur_psbt_scan_reset(void) { g_psbt_fountain = ur::FountainDecoder(); }

extern "C" void seedmask_ur_psbt_get_scan_progress(float* pctOut, uint32_t* partsReceived, uint32_t* partsTotal,
                                                  int* multipartActive) {
  if (pctOut) *pctOut = 0.f;
  if (partsReceived) *partsReceived = 0;
  if (partsTotal) *partsTotal = 0;
  if (multipartActive) *multipartActive = 0;
  if (!g_psbt_fountain.has_session()) return;
  if (multipartActive) *multipartActive = 1;
  if (partsReceived) *partsReceived = (uint32_t)g_psbt_fountain.received_part_indexes().size();
  if (partsTotal) *partsTotal = (uint32_t)g_psbt_fountain.expected_part_count();
  if (pctOut) *pctOut = (float)g_psbt_fountain.estimated_percent_complete();
}

extern "C" bool seedmask_psbt_validate_decoded(const uint8_t* psbt, size_t len, char* err, size_t errLen) {
  return validate_decoded_psbt_payload(psbt, len, err, errLen);
}

extern "C" bool seedmask_psbt_parser_selftest(char* err, size_t errLen) {
  auto seterr = [&](const char* m) {
    if (err && errLen) snprintf(err, errLen, "%s", m);
  };
  char e[96] = {0};
  // Minimal valid PSBT: magic + global map with key=0x00 + 1-byte tx placeholder + map terminator.
  const uint8_t kValidMin[] = {
      'p','s','b','t',0xff,
      0x01, 0x00,  // keylen=1, key=0x00
      // unsigned tx: 01000000 00 00 00000000  (version=1, 0 in, 0 out, locktime=0)
      0x0a, 0x01,0x00,0x00,0x00, 0x00, 0x00, 0x00,0x00,0x00,0x00,
      0x00         // end of global map
  };
  if (!validate_decoded_psbt_payload(kValidMin, sizeof(kValidMin), e, sizeof(e))) {
    seterr("selftest: valid rejected");
    return false;
  }

  // Duplicate global unsigned-tx key must fail.
  const uint8_t kDupUnsigned[] = {
      'p','s','b','t',0xff,
      0x01,0x00, 0x01,0x00,
      0x01,0x00, 0x01,0x00,
      0x00
  };
  if (validate_decoded_psbt_payload(kDupUnsigned, sizeof(kDupUnsigned), e, sizeof(e))) {
    seterr("selftest: dup key accepted");
    return false;
  }

  // Trailing bytes must fail.
  const uint8_t kTrailing[] = {
      'p','s','b','t',0xff,
      0x01,0x00, 0x01,0x00,
      0x00,
      0xaa,0xbb
  };
  if (validate_decoded_psbt_payload(kTrailing, sizeof(kTrailing), e, sizeof(e))) {
    seterr("selftest: trailing accepted");
    return false;
  }

  // Wrong magic must fail.
  const uint8_t kBadMagic[] = {'x','s','b','t',0xff,0x00};
  if (validate_decoded_psbt_payload(kBadMagic, sizeof(kBadMagic), e, sizeof(e))) {
    seterr("selftest: bad magic accepted");
    return false;
  }

  // Missing input/output maps for declared tx inputs/outputs must fail.
  const uint8_t kMissingMaps[] = {
      'p','s','b','t',0xff,
      0x01,0x00,
      // unsigned tx: v1, 1 input (dummy), 0 outputs, locktime 0
      0x2a,
      0x01,0x00,0x00,0x00,  // version
      0x01,                  // vin=1
      // prevout (32 bytes hash + 4 index)
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0xff,0xff,0xff,0xff,   // prev index
      0x00,                  // scriptSig len
      0xff,0xff,0xff,0xff,   // sequence
      0x00,                  // vout=0
      0x00,0x00,0x00,0x00,   // locktime
      0x00                   // end global
      // required 1 input map is missing
  };
  if (validate_decoded_psbt_payload(kMissingMaps, sizeof(kMissingMaps), e, sizeof(e))) {
    seterr("selftest: missing maps accepted");
    return false;
  }

  // Input map with duplicate key must fail.
  const uint8_t kDupInputKey[] = {
      'p','s','b','t',0xff,
      0x01,0x00,
      // unsigned tx: v1, 1 input, 0 outputs, locktime 0
      0x2a,
      0x01,0x00,0x00,0x00, 0x01,
      0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
      0xff,0xff,0xff,0xff, 0x00, 0xff,0xff,0xff,0xff, 0x00, 0x00,0x00,0x00,
      0x00,  // end global
      // input map (duplicate key 0x01)
      0x01,0x01, 0x01,0x00,
      0x01,0x01, 0x01,0x00,
      0x00
  };
  if (validate_decoded_psbt_payload(kDupInputKey, sizeof(kDupInputKey), e, sizeof(e))) {
    seterr("selftest: dup input key accepted");
    return false;
  }
  return true;
}

extern "C" bool seedmask_psbt_signing_selftest(char* err, size_t errLen) {
  auto seterr = [&](const char* m) {
    if (err && errLen) snprintf(err, errLen, "%s", m);
  };

  seedmask_boot_selftest_yield();

  // Deterministic BIP39 test vector seed.
  static const char* kMnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  uint8_t salt[8] = {'m','n','e','m','o','n','i','c'};
  uint8_t seed[64];
  if (!pbkdf2_sha512((const uint8_t*)kMnemonic, strlen(kMnemonic), salt, sizeof(salt), 2048, seed, sizeof(seed))) {
    seterr("selftest: pbkdf2");
    return false;
  }
  Bip32Node master;
  memset(&master, 0, sizeof(master));
  if (!bip32_master_from_seed(seed, &master)) {
    sp_zero(seed, sizeof(seed));
    seterr("selftest: master");
    return false;
  }
  sp_zero(seed, sizeof(seed));
  seedmask_boot_selftest_yield();

  uint8_t master_pub[33];
  uint8_t master_h160[20];
  uint8_t master_fp[4];
  if (!secp_pubkey_compressed(master.k, master_pub) || !hash160_mbedtls(master_pub, sizeof(master_pub), master_h160)) {
    sp_zero(master_pub, sizeof(master_pub));
    sp_zero(master_h160, sizeof(master_h160));
    sp_zero(&master, sizeof(master));
    seterr("selftest: fp");
    return false;
  }
  memcpy(master_fp, master_h160, 4);
  sp_zero(master_pub, sizeof(master_pub));
  sp_zero(master_h160, sizeof(master_h160));

  auto run_case = [&](bool nested_p2sh_p2wsh, const uint32_t path_a[6], const uint32_t path_b[6], const char* case_name) -> bool {
    uint8_t priv_a[32], priv_b[32], pub_a[33], pub_b[33];
    if (!derive_priv_from_master_node(master, path_a, 6, priv_a) ||
        !derive_priv_from_master_node(master, path_b, 6, priv_b) ||
        !secp_pubkey_compressed(priv_a, pub_a) ||
        !secp_pubkey_compressed(priv_b, pub_b)) {
      sp_zero(priv_a, sizeof(priv_a));
      sp_zero(priv_b, sizeof(priv_b));
      seterr("selftest: derive multisig");
      return false;
    }
    sp_zero(priv_a, sizeof(priv_a));
    sp_zero(priv_b, sizeof(priv_b));

    // Deterministic 2-of-2 multisig witness script.
    std::vector<uint8_t> witness_script;
    witness_script.reserve(71);
    witness_script.push_back(0x52);  // OP_2
    witness_script.push_back(0x21); witness_script.insert(witness_script.end(), pub_a, pub_a + 33);
    witness_script.push_back(0x21); witness_script.insert(witness_script.end(), pub_b, pub_b + 33);
    witness_script.push_back(0x52);  // OP_2
    witness_script.push_back(0xae);  // OP_CHECKMULTISIG

    uint8_t wsh[32];
    sha256_once(witness_script.data(), witness_script.size(), wsh);
    std::vector<uint8_t> script_pubkey;
    std::vector<uint8_t> redeem_script;
    if (nested_p2sh_p2wsh) {
      redeem_script.push_back(0x00);
      redeem_script.push_back(0x20);
      redeem_script.insert(redeem_script.end(), wsh, wsh + 32);
      uint8_t rh160[20];
      if (!hash160_mbedtls(redeem_script.data(), redeem_script.size(), rh160)) {
        sp_zero(pub_a, sizeof(pub_a));
        sp_zero(pub_b, sizeof(pub_b));
        sp_zero(wsh, sizeof(wsh));
        seterr("selftest: redeem hash");
        return false;
      }
      script_pubkey.push_back(0xa9);  // OP_HASH160
      script_pubkey.push_back(0x14);
      script_pubkey.insert(script_pubkey.end(), rh160, rh160 + 20);
      script_pubkey.push_back(0x87);  // OP_EQUAL
      sp_zero(rh160, sizeof(rh160));
    } else {
      script_pubkey.push_back(0x00);
      script_pubkey.push_back(0x20);
      script_pubkey.insert(script_pubkey.end(), wsh, wsh + 32);
    }
    sp_zero(wsh, sizeof(wsh));

    // witness_utxo value: 1000 sats.
    std::vector<uint8_t> witness_utxo;
    const uint64_t prev_value = 1000ULL;
    for (int b = 0; b < 8; b++) witness_utxo.push_back((uint8_t)((prev_value >> (8 * b)) & 0xff));
    write_compact_size(witness_utxo, script_pubkey.size());
    witness_utxo.insert(witness_utxo.end(), script_pubkey.begin(), script_pubkey.end());

    // unsigned tx: 1 input, 1 output.
    std::vector<uint8_t> unsigned_tx;
    unsigned_tx.reserve(96);
    unsigned_tx.push_back(0x01); unsigned_tx.push_back(0x00); unsigned_tx.push_back(0x00); unsigned_tx.push_back(0x00);
    unsigned_tx.push_back(0x01);
    for (int i = 0; i < 32; i++) unsigned_tx.push_back(0x00);
    unsigned_tx.push_back(0x00); unsigned_tx.push_back(0x00); unsigned_tx.push_back(0x00); unsigned_tx.push_back(0x00);
    unsigned_tx.push_back(0x00);
    unsigned_tx.push_back(0xff); unsigned_tx.push_back(0xff); unsigned_tx.push_back(0xff); unsigned_tx.push_back(0xff);
    unsigned_tx.push_back(0x01);
    const uint64_t send_value = 900ULL;
    for (int b = 0; b < 8; b++) unsigned_tx.push_back((uint8_t)((send_value >> (8 * b)) & 0xff));
    unsigned_tx.push_back(22);
    unsigned_tx.push_back(0x00); unsigned_tx.push_back(0x14);
    for (int i = 0; i < 20; i++) unsigned_tx.push_back((uint8_t)(0x11 + i));
    unsigned_tx.push_back(0x00); unsigned_tx.push_back(0x00); unsigned_tx.push_back(0x00); unsigned_tx.push_back(0x00);

    std::vector<uint8_t> psbt;
    psbt.insert(psbt.end(), PSBT_MAGIC, PSBT_MAGIC + 5);
    PsbtMap global;
    global.push_back({std::vector<uint8_t>{0x00}, unsigned_tx});
    write_psbt_map(psbt, global);

    PsbtMap in0;
    in0.push_back({std::vector<uint8_t>{0x01}, witness_utxo});
    in0.push_back({std::vector<uint8_t>{0x05}, witness_script});
    in0.push_back({std::vector<uint8_t>{0x03}, std::vector<uint8_t>{0x01, 0x00, 0x00, 0x00}});
    if (nested_p2sh_p2wsh) {
      in0.push_back({std::vector<uint8_t>{0x04}, redeem_script});
    }
    std::vector<uint8_t> der_key;
    der_key.push_back(0x06);
    der_key.insert(der_key.end(), pub_a, pub_a + 33);
    std::vector<uint8_t> der_val;
    der_val.insert(der_val.end(), master_fp, master_fp + 4);
    for (int i = 0; i < 6; i++) {
      uint32_t v = path_a[i];
      der_val.push_back((uint8_t)(v & 0xff));
      der_val.push_back((uint8_t)((v >> 8) & 0xff));
      der_val.push_back((uint8_t)((v >> 16) & 0xff));
      der_val.push_back((uint8_t)((v >> 24) & 0xff));
    }
    in0.push_back({der_key, der_val});
    write_psbt_map(psbt, in0);
    PsbtMap out0;
    write_psbt_map(psbt, out0);

    uint8_t signed_psbt[4096];
    size_t signed_len = 0;
    char sign_err[96] = {0};
    seedmask_boot_selftest_yield();
    if (!seedmask_psbt_sign_with_mnemonic(psbt.data(), psbt.size(), kMnemonic, 12, "", signed_psbt, &signed_len,
                                          sizeof(signed_psbt), sign_err, sizeof(sign_err))) {
      seterr(sign_err[0] ? sign_err : case_name);
      sp_zero(pub_a, sizeof(pub_a));
      sp_zero(pub_b, sizeof(pub_b));
      return false;
    }
    seedmask_boot_selftest_yield();

    size_t pos = 5;
    PsbtMap g2;
    if (signed_len < 10 || memcmp(signed_psbt, PSBT_MAGIC, 5) != 0 || !read_psbt_map(signed_psbt, signed_len, pos, g2)) {
      seterr("selftest: signed parse");
      sp_zero(pub_a, sizeof(pub_a));
      sp_zero(pub_b, sizeof(pub_b));
      return false;
    }
    PsbtMap in2;
    if (!read_psbt_map(signed_psbt, signed_len, pos, in2)) {
      seterr("selftest: signed in map");
      sp_zero(pub_a, sizeof(pub_a));
      sp_zero(pub_b, sizeof(pub_b));
      return false;
    }
    bool has_psig = false;
    for (const auto& kv : in2) {
      if (kv.first.size() == 34 && kv.first[0] == 0x02 && memcmp(kv.first.data() + 1, pub_a, 33) == 0
          && !kv.second.empty() && kv.second.back() == 0x01) {
        has_psig = true;
        break;
      }
    }
    sp_zero(pub_a, sizeof(pub_a));
    sp_zero(pub_b, sizeof(pub_b));
    if (!has_psig) {
      seterr(case_name);
      return false;
    }
    return true;
  };

  const uint32_t kPathWshA[6] = {0x80000030u, 0x80000000u, 0x80000000u, 0x80000002u, 0u, 0u};  // m/48'/0'/0'/2'/0/0
  const uint32_t kPathWshB[6] = {0x80000030u, 0x80000000u, 0x80000000u, 0x80000002u, 0u, 1u};  // m/48'/0'/0'/2'/0/1
  const uint32_t kPathShWshA[6] = {0x80000030u, 0x80000000u, 0x80000000u, 0x80000001u, 0u, 0u};  // m/48'/0'/0'/1'/0/0
  const uint32_t kPathShWshB[6] = {0x80000030u, 0x80000000u, 0x80000000u, 0x80000001u, 0u, 1u};  // m/48'/0'/0'/1'/0/1

  seedmask_boot_selftest_yield();
  bool ok_native = run_case(false, kPathWshA, kPathWshB, "selftest: no multisig psig p2wsh");
  seedmask_boot_selftest_yield();
  bool ok_nested = ok_native && run_case(true, kPathShWshA, kPathShWshB, "selftest: no multisig psig p2sh-p2wsh");
  seedmask_boot_selftest_yield();

  sp_zero(&master, sizeof(master));
  return ok_native && ok_nested;
}

extern "C" int seedmask_ur_feed_psbt_qr(const char* ur, uint8_t* out, size_t maxOut, size_t* outLen, float* pctOut,
                                        char* err, size_t errLen) {
  auto seterr = [&](const char* m) {
    if (err && errLen) {
      snprintf(err, errLen, "%s", m);
    }
  };
  if (!ur || !ur[0] || !out || !outLen) {
    seterr("bad args");
    return SEEDMASK_UR_PSBT_ERROR;
  }
  *outLen = 0;
  if (pctOut) *pctOut = 0.0f;
  try {
    std::string s(ur);
    for (char& c : s) c = (char)tolower((unsigned char)c);
    if (s.size() < 4 || s.compare(0, 3, "ur:") != 0) {
      seterr("not a UR");
      return SEEDMASK_UR_PSBT_ERROR;
    }
    std::string path = s.substr(3);
    std::vector<std::string> comps;
    size_t start = 0;
    while (start < path.size()) {
      size_t p = path.find('/', start);
      if (p == std::string::npos) {
        comps.push_back(path.substr(start));
        break;
      }
      comps.push_back(path.substr(start, p - start));
      start = p + 1;
    }
    if (comps.size() < 2) {
      seterr("UR path too short");
      return SEEDMASK_UR_PSBT_ERROR;
    }
    const std::string& typ = comps[0];
    if (typ != "crypto-psbt" && typ != "bytes" && typ != "psbt") {
      seterr("need psbt, crypto-psbt, or bytes");
      return SEEDMASK_UR_PSBT_ERROR;
    }

    if (comps.size() == 2) {
      // Single-frame UR: start fresh (abandons any in-progress multipart).
      g_psbt_fountain = ur::FountainDecoder();
      ur::ByteVector cbor = ur::Bytewords::decode(ur::Bytewords::style::minimal, comps[1]);
      if (!ur_cbor_to_psbt_bytes(cbor, out, maxOut, outLen)) {
        seterr("PSBT too large or bad CBOR");
        return SEEDMASK_UR_PSBT_ERROR;
      }
      if (!validate_decoded_psbt_payload(out, *outLen, err, errLen)) {
        return SEEDMASK_UR_PSBT_ERROR;
      }
      if (pctOut) *pctOut = 1.0f;
      return SEEDMASK_UR_PSBT_COMPLETE;
    }

    if (comps.size() == 3) {
      // BC-UR multipart path: type / seqNum-seqLen / bytewords
      {
        const std::string& mid = comps[1];
        const char* ms = mid.c_str();
        char* endp = nullptr;
        unsigned long seqn = strtoul(ms, &endp, 10);
        if (endp == ms || !endp || *endp != '-') {
          seterr("bad UR-seq field");
          return SEEDMASK_UR_PSBT_ERROR;
        }
        const char* rest = endp + 1;
        char* endp2 = nullptr;
        unsigned long seql = strtoul(rest, &endp2, 10);
        if (endp2 == rest || !endp2 || *endp2 != '\0') {
          seterr("bad UR-seq field");
          return SEEDMASK_UR_PSBT_ERROR;
        }
        if (seql == 0 || seql > 4096u) {
          seterr("bad UR sequence length");
          return SEEDMASK_UR_PSBT_ERROR;
        }
        (void)seqn;
      }
      ur::ByteVector partCbor = ur::Bytewords::decode(ur::Bytewords::style::minimal, comps[2]);
      ur::FountainEncoder::Part encPart(partCbor);
      if (!g_psbt_fountain.receive_part(encPart)) {
        if (g_psbt_fountain.is_complete()) {
          seterr("already decoded");
          return SEEDMASK_UR_PSBT_ERROR;
        }
        g_psbt_fountain = ur::FountainDecoder();
        seterr("bad or mismatched UR part");
        return SEEDMASK_UR_PSBT_ERROR;
      }
      if (pctOut) *pctOut = (float)g_psbt_fountain.estimated_percent_complete();
      if (g_psbt_fountain.is_complete()) {
        if (g_psbt_fountain.is_failure()) {
          try {
            const std::exception& ex = g_psbt_fountain.result_error();
            seterr(ex.what());
          } catch (...) {
            seterr("fountain checksum failed");
          }
          g_psbt_fountain = ur::FountainDecoder();
          return SEEDMASK_UR_PSBT_ERROR;
        }
        if (g_psbt_fountain.is_success()) {
          const ur::ByteVector& msg = g_psbt_fountain.result_message();
          if (!ur_cbor_to_psbt_bytes(msg, out, maxOut, outLen)) {
            seterr("PSBT too large or bad CBOR");
            g_psbt_fountain = ur::FountainDecoder();
            return SEEDMASK_UR_PSBT_ERROR;
          }
          if (!validate_decoded_psbt_payload(out, *outLen, err, errLen)) {
            g_psbt_fountain = ur::FountainDecoder();
            return SEEDMASK_UR_PSBT_ERROR;
          }
          g_psbt_fountain = ur::FountainDecoder();
          if (pctOut) *pctOut = 1.0f;
          return SEEDMASK_UR_PSBT_COMPLETE;
        }
      }
      return SEEDMASK_UR_PSBT_NEED_MORE;
    }

    seterr("bad UR path");
    return SEEDMASK_UR_PSBT_ERROR;
  } catch (...) {
    seterr("UR decode failed");
    g_psbt_fountain = ur::FountainDecoder();
    return SEEDMASK_UR_PSBT_ERROR;
  }
}

extern "C" bool seedmask_ur_decode_psbt_payload(const char* ur, uint8_t* out, size_t maxOut, size_t* outLen,
                                                char* err, size_t errLen) {
  seedmask_ur_psbt_scan_reset();
  float pct = 0;
  int r = seedmask_ur_feed_psbt_qr(ur, out, maxOut, outLen, &pct, err, errLen);
  return r == SEEDMASK_UR_PSBT_COMPLETE;
}

extern "C" void seedmask_ur_policy_scan_reset(void) { g_policy_fountain = ur::FountainDecoder(); }

extern "C" void seedmask_ur_kaspa_pskt_scan_reset(void) { g_kaspa_pskt_fountain = ur::FountainDecoder(); }

extern "C" void seedmask_ur_kaspa_pskt_get_scan_progress(float* pctOut, uint32_t* partsReceived, uint32_t* partsTotal,
                                                        int* multipartActive) {
  if (pctOut) *pctOut = 0.f;
  if (partsReceived) *partsReceived = 0;
  if (partsTotal) *partsTotal = 0;
  if (multipartActive) *multipartActive = 0;
  if (!g_kaspa_pskt_fountain.has_session()) return;
  if (multipartActive) *multipartActive = 1;
  if (partsReceived) *partsReceived = (uint32_t)g_kaspa_pskt_fountain.received_part_indexes().size();
  if (partsTotal) *partsTotal = (uint32_t)g_kaspa_pskt_fountain.expected_part_count();
  if (pctOut) *pctOut = (float)g_kaspa_pskt_fountain.estimated_percent_complete();
}

extern "C" void seedmask_ur_policy_get_scan_progress(float* pctOut, uint32_t* partsReceived, uint32_t* partsTotal,
                                                    int* multipartActive) {
  if (pctOut) *pctOut = 0.f;
  if (partsReceived) *partsReceived = 0;
  if (partsTotal) *partsTotal = 0;
  if (multipartActive) *multipartActive = 0;
  if (!g_policy_fountain.has_session()) return;
  if (multipartActive) *multipartActive = 1;
  if (partsReceived) *partsReceived = (uint32_t)g_policy_fountain.received_part_indexes().size();
  if (partsTotal) *partsTotal = (uint32_t)g_policy_fountain.expected_part_count();
  if (pctOut) *pctOut = (float)g_policy_fountain.estimated_percent_complete();
}

extern "C" int seedmask_ur_feed_policy_qr(const char* ur, char* out, size_t outCap, float* pctOut, char* err,
                                         size_t errLen) {
  auto seterr = [&](const char* m) {
    if (err && errLen) snprintf(err, errLen, "%s", m);
  };
  if (!ur || !ur[0] || !out || outCap < 2) {
    seterr("bad args");
    return SEEDMASK_UR_PSBT_ERROR;
  }
  out[0] = 0;
  if (pctOut) *pctOut = 0.0f;
  try {
    std::string s(ur);
    for (char& c : s) c = (char)tolower((unsigned char)c);
    if (s.size() < 4 || s.compare(0, 3, "ur:") != 0) {
      seterr("not a UR");
      return SEEDMASK_UR_PSBT_ERROR;
    }
    std::string path = s.substr(3);
    std::vector<std::string> comps;
    size_t start = 0;
    while (start < path.size()) {
      size_t p = path.find('/', start);
      if (p == std::string::npos) {
        comps.push_back(path.substr(start));
        break;
      }
      comps.push_back(path.substr(start, p - start));
      start = p + 1;
    }
    if (comps.size() < 2) {
      seterr("UR path too short");
      return SEEDMASK_UR_PSBT_ERROR;
    }
    const std::string& typ = comps[0];
    if (typ != "bytes" && typ != "crypto-account" && typ != "account") {
      seterr("need bytes, crypto-account, or account UR");
      return SEEDMASK_UR_PSBT_ERROR;
    }

    if (comps.size() == 2) {
      g_policy_fountain = ur::FountainDecoder();
      ur::ByteVector cbor = ur::Bytewords::decode(ur::Bytewords::style::minimal, comps[1]);
      size_t rawLen = 0;
      if (!ur_cbor_to_psbt_bytes(cbor, (uint8_t*)out, outCap - 1, &rawLen)) {
        seterr("policy too large or bad CBOR");
        return SEEDMASK_UR_PSBT_ERROR;
      }
      out[rawLen] = 0;
      if (pctOut) *pctOut = 1.0f;
      return SEEDMASK_UR_PSBT_COMPLETE;
    }

    if (comps.size() == 3) {
      {
        const std::string& mid = comps[1];
        const char* ms = mid.c_str();
        char* endp = nullptr;
        unsigned long seqn = strtoul(ms, &endp, 10);
        if (endp == ms || !endp || *endp != '-') {
          seterr("bad UR-seq field");
          return SEEDMASK_UR_PSBT_ERROR;
        }
        const char* rest = endp + 1;
        char* endp2 = nullptr;
        unsigned long seql = strtoul(rest, &endp2, 10);
        if (endp2 == rest || !endp2 || *endp2 != '\0') {
          seterr("bad UR-seq field");
          return SEEDMASK_UR_PSBT_ERROR;
        }
        if (seql == 0 || seql > 4096u) {
          seterr("bad UR sequence length");
          return SEEDMASK_UR_PSBT_ERROR;
        }
        (void)seqn;
      }
      ur::ByteVector partCbor = ur::Bytewords::decode(ur::Bytewords::style::minimal, comps[2]);
      ur::FountainEncoder::Part encPart(partCbor);
      if (!g_policy_fountain.receive_part(encPart)) {
        if (g_policy_fountain.is_complete()) {
          seterr("already decoded");
          return SEEDMASK_UR_PSBT_ERROR;
        }
        g_policy_fountain = ur::FountainDecoder();
        seterr("bad or mismatched UR part");
        return SEEDMASK_UR_PSBT_ERROR;
      }
      if (pctOut) *pctOut = (float)g_policy_fountain.estimated_percent_complete();
      if (g_policy_fountain.is_complete()) {
        if (g_policy_fountain.is_failure()) {
          try {
            const std::exception& ex = g_policy_fountain.result_error();
            seterr(ex.what());
          } catch (...) {
            seterr("fountain checksum failed");
          }
          g_policy_fountain = ur::FountainDecoder();
          return SEEDMASK_UR_PSBT_ERROR;
        }
        if (g_policy_fountain.is_success()) {
          const ur::ByteVector& msg = g_policy_fountain.result_message();
          size_t rawLen = 0;
          if (!ur_cbor_to_psbt_bytes(msg, (uint8_t*)out, outCap - 1, &rawLen)) {
            seterr("policy too large or bad CBOR");
            g_policy_fountain = ur::FountainDecoder();
            return SEEDMASK_UR_PSBT_ERROR;
          }
          out[rawLen] = 0;
          g_policy_fountain = ur::FountainDecoder();
          if (pctOut) *pctOut = 1.0f;
          return SEEDMASK_UR_PSBT_COMPLETE;
        }
      }
      return SEEDMASK_UR_PSBT_NEED_MORE;
    }

    seterr("bad UR path");
    return SEEDMASK_UR_PSBT_ERROR;
  } catch (...) {
    seterr("UR decode failed");
    g_policy_fountain = ur::FountainDecoder();
    return SEEDMASK_UR_PSBT_ERROR;
  }
}

extern "C" int seedmask_ur_feed_kaspa_pskt_qr(const char* ur, char* out, size_t outCap, float* pctOut, char* err,
                                             size_t errLen) {
  auto seterr = [&](const char* m) {
    if (err && errLen) snprintf(err, errLen, "%s", m);
  };
  if (!ur || !ur[0] || !out || outCap < 2) {
    seterr("bad args");
    return SEEDMASK_UR_PSBT_ERROR;
  }
  out[0] = 0;
  if (pctOut) *pctOut = 0.0f;
  try {
    std::string s(ur);
    for (char& c : s) c = (char)tolower((unsigned char)c);
    if (s.size() < 4 || s.compare(0, 3, "ur:") != 0) {
      seterr("not a UR");
      return SEEDMASK_UR_PSBT_ERROR;
    }
    std::string path = s.substr(3);
    std::vector<std::string> comps;
    size_t start = 0;
    while (start < path.size()) {
      size_t p = path.find('/', start);
      if (p == std::string::npos) {
        comps.push_back(path.substr(start));
        break;
      }
      comps.push_back(path.substr(start, p - start));
      start = p + 1;
    }
    if (comps.size() < 2) {
      seterr("UR path too short");
      return SEEDMASK_UR_PSBT_ERROR;
    }
    if (comps[0] != "bytes") {
      if (g_kaspa_pskt_fountain.has_session()) {
        if (pctOut) *pctOut = (float)g_kaspa_pskt_fountain.estimated_percent_complete();
        return SEEDMASK_UR_PSBT_NEED_MORE;
      }
      seterr("Kaspa PSKT needs ur:bytes/");
      return SEEDMASK_UR_PSBT_ERROR;
    }

    if (comps.size() == 2) {
      /* Mis-read / single-frame while multipart is active — do not wipe assembly progress. */
      if (g_kaspa_pskt_fountain.has_session()) {
        if (pctOut) *pctOut = (float)g_kaspa_pskt_fountain.estimated_percent_complete();
        return SEEDMASK_UR_PSBT_NEED_MORE;
      }
      g_kaspa_pskt_fountain = ur::FountainDecoder();
      ur::ByteVector cbor = ur::Bytewords::decode(ur::Bytewords::style::minimal, comps[1]);
      size_t rawLen = 0;
      if (!ur_cbor_to_psbt_bytes(cbor, (uint8_t*)out, outCap - 1, &rawLen)) {
        seterr("PSKT JSON too large or bad CBOR");
        return SEEDMASK_UR_PSBT_ERROR;
      }
      out[rawLen] = 0;
      if (pctOut) *pctOut = 1.0f;
      return SEEDMASK_UR_PSBT_COMPLETE;
    }

    if (comps.size() == 3) {
      const std::string& mid = comps[1];
      const char* ms = mid.c_str();
      char* endp = nullptr;
      unsigned long seqn = strtoul(ms, &endp, 10);
      if (endp == ms || !endp || *endp != '-') {
        seterr("bad UR-seq field");
        return SEEDMASK_UR_PSBT_ERROR;
      }
      const char* rest = endp + 1;
      char* endp2 = nullptr;
      unsigned long seql = strtoul(rest, &endp2, 10);
      if (endp2 == rest || !endp2 || *endp2 != '\0') {
        seterr("bad UR-seq field");
        return SEEDMASK_UR_PSBT_ERROR;
      }
      if (seql == 0 || seql > 4096u) {
        seterr("bad UR sequence length");
        return SEEDMASK_UR_PSBT_ERROR;
      }
      (void)seqn;
      ur::ByteVector partCbor = ur::Bytewords::decode(ur::Bytewords::style::minimal, comps[2]);
      ur::FountainEncoder::Part encPart(partCbor);
      if (!g_kaspa_pskt_fountain.receive_part(encPart)) {
        if (g_kaspa_pskt_fountain.is_complete()) {
          seterr("already decoded");
          return SEEDMASK_UR_PSBT_ERROR;
        }
        /* Glitch frame / wrong fountain slice — keep session so the progress bar does not jump to 0. */
        if (pctOut) *pctOut = (float)g_kaspa_pskt_fountain.estimated_percent_complete();
        return SEEDMASK_UR_PSBT_NEED_MORE;
      }
      if (pctOut) *pctOut = (float)g_kaspa_pskt_fountain.estimated_percent_complete();
      if (g_kaspa_pskt_fountain.is_complete()) {
        if (g_kaspa_pskt_fountain.is_failure()) {
          try {
            const std::exception& ex = g_kaspa_pskt_fountain.result_error();
            seterr(ex.what());
          } catch (...) {
            seterr("fountain checksum failed");
          }
          g_kaspa_pskt_fountain = ur::FountainDecoder();
          return SEEDMASK_UR_PSBT_ERROR;
        }
        if (g_kaspa_pskt_fountain.is_success()) {
          const ur::ByteVector& msg = g_kaspa_pskt_fountain.result_message();
          size_t rawLen = 0;
          if (!ur_cbor_to_psbt_bytes(msg, (uint8_t*)out, outCap - 1, &rawLen)) {
            seterr("PSKT JSON too large or bad CBOR");
            g_kaspa_pskt_fountain = ur::FountainDecoder();
            return SEEDMASK_UR_PSBT_ERROR;
          }
          out[rawLen] = 0;
          g_kaspa_pskt_fountain = ur::FountainDecoder();
          if (pctOut) *pctOut = 1.0f;
          return SEEDMASK_UR_PSBT_COMPLETE;
        }
      }
      return SEEDMASK_UR_PSBT_NEED_MORE;
    }

    seterr("bad UR path");
    return SEEDMASK_UR_PSBT_ERROR;
  } catch (...) {
    if (g_kaspa_pskt_fountain.has_session()) {
      if (pctOut) *pctOut = (float)g_kaspa_pskt_fountain.estimated_percent_complete();
      return SEEDMASK_UR_PSBT_NEED_MORE;
    }
    seterr("UR decode failed");
    g_kaspa_pskt_fountain = ur::FountainDecoder();
    return SEEDMASK_UR_PSBT_ERROR;
  }
}

extern "C" bool seedmask_kaspa_ur_fountain_selftest(char* err, size_t errLen) {
  auto seterr = [&](const char* m) {
    if (err && errLen) snprintf(err, errLen, "%s", m);
  };
  static const char* kParts[] = {
      "ur:bytes/1-3/lpadaxcsfecyecgtlbjphghdfxkgcpkocpfteydwcphsiaiajlkpjtjycpftdydwcpjkoeiekefy",
      "ur:bytes/2-3/lpaoaxcsfecyecgtlbjphginiojthehsieiejpihjkjkheinjtieihkscpftdydwcpintirpdmpr",
      "ur:bytes/3-3/lpaxaxcsfecyecgtlbjphgjtjokpjyjkcpfthphldwcpjlkpjyjokpjyjkcpfthphlkiaasgjnhn",
  };
  seedmask_ur_kaspa_pskt_scan_reset();
  char out[512];
  char e[96];
  int last = SEEDMASK_UR_PSBT_ERROR;
  for (unsigned i = 0; i < sizeof(kParts) / sizeof(kParts[0]); i++) {
    float pct = 0;
    last = seedmask_ur_feed_kaspa_pskt_qr(kParts[i], out, sizeof(out) - 1, &pct, e, sizeof(e));
    if (last == SEEDMASK_UR_PSBT_ERROR) {
      seterr(e[0] ? e : "UR part rejected");
      return false;
    }
    if (i + 1 < sizeof(kParts) / sizeof(kParts[0]) && last != SEEDMASK_UR_PSBT_NEED_MORE) {
      seterr("expected NEED_MORE");
      return false;
    }
  }
  if (last != SEEDMASK_UR_PSBT_COMPLETE) {
    seterr("fountain incomplete");
    return false;
  }
  if (out[0] != '{') {
    seterr("decoded JSON missing");
    return false;
  }
  return true;
}

extern "C" bool seedmask_ur_decode_text_payload(const char* ur, char* out, size_t outCap, char* err, size_t errLen) {
  auto seterr = [&](const char* m) {
    if (err && errLen) snprintf(err, errLen, "%s", m);
  };
  if (!ur || !out || outCap < 2) {
    seterr("bad args");
    return false;
  }
  out[0] = 0;
  try {
    std::string s(ur);
    for (char& c : s) c = (char)tolower((unsigned char)c);
    if (s.size() < 4 || s.compare(0, 3, "ur:") != 0) {
      seterr("not a UR");
      return false;
    }
    std::string path = s.substr(3);
    std::vector<std::string> comps;
    size_t start = 0;
    while (start < path.size()) {
      size_t p = path.find('/', start);
      if (p == std::string::npos) { comps.push_back(path.substr(start)); break; }
      comps.push_back(path.substr(start, p - start));
      start = p + 1;
    }
    if (comps.size() != 2) {
      seterr("need single-part UR");
      return false;
    }
    const std::string& typ = comps[0];
    if (typ != "bytes" && typ != "crypto-account" && typ != "account") {
      seterr("unsupported UR type");
      return false;
    }
    ur::ByteVector cbor = ur::Bytewords::decode(ur::Bytewords::style::minimal, comps[1]);
    auto it = cbor.begin();
    auto end = cbor.end();
    ur::ByteVector raw;
    CborLite::decodeBytes(it, end, raw);
    if (it != end || raw.empty()) {
      seterr("bad CBOR bytes");
      return false;
    }
    size_t n = raw.size();
    if (n >= outCap) n = outCap - 1;
    memcpy(out, raw.data(), n);
    out[n] = 0;
    return true;
  } catch (...) {
    seterr("UR decode failed");
    return false;
  }
}

extern "C" bool seedmask_psbt_sign_with_mnemonic(const uint8_t* psbt_in, size_t psbt_in_len, const char* mnemonic,
                                                 int word_count, const char* bip39_passphrase,
                                                 uint8_t* psbt_out, size_t* psbt_out_len,
                                                 size_t psbt_out_cap, char* err, size_t errLen) {
  auto seterr = [&](const char* m) {
    if (err && errLen) snprintf(err, errLen, "%s", m);
  };
  if (!psbt_in || psbt_in_len < 10 || !mnemonic || !psbt_out || !psbt_out_len || psbt_out_cap < psbt_in_len + 200) {
    seterr("bad args");
    return false;
  }
  *psbt_out_len = 0;
  if (!validate_mnemonic_word_count(mnemonic, word_count)) {
    seterr("mnemonic words");
    return false;
  }
  if (memcmp(psbt_in, PSBT_MAGIC, 5) != 0) {
    seterr("not PSBT");
    return false;
  }

  // BIP39 passphrase is appended to "mnemonic" salt (salt = "mnemonic" || passphrase).
  // We cap passphrase length to keep stack usage bounded.
  const size_t PASSPHRASE_MAX_BYTES = 128;
  uint8_t salt[8 + 128];
  memcpy(salt, "mnemonic", 8);
  size_t passLen = (bip39_passphrase && bip39_passphrase[0])
                      ? strnlen(bip39_passphrase, PASSPHRASE_MAX_BYTES)
                      : 0;
  if (passLen) memcpy(salt + 8, bip39_passphrase, passLen);
  uint8_t bip39_seed[64];
  if (!pbkdf2_sha512((const uint8_t*)mnemonic, strlen(mnemonic), salt, 8 + passLen,
                      2048, bip39_seed, sizeof(bip39_seed))) {
    seterr("pbkdf2");
    sp_zero(salt, sizeof(salt));
    return false;
  }
  sp_zero(salt, sizeof(salt));
  Bip32Node master_node;
  memset(&master_node, 0, sizeof(master_node));
  if (!bip32_master_from_seed(bip39_seed, &master_node)) {
    sp_zero(bip39_seed, sizeof(bip39_seed));
    seterr("bip32 master");
    return false;
  }
  sp_zero(bip39_seed, sizeof(bip39_seed));
  // Wipe master secret key on every return path after this point.
  ClearBip32Node wipe_master(&master_node);

  uint8_t master_fp[4];
  uint8_t mpub[33];
  if (!secp_pubkey_compressed(master_node.k, mpub)) {
    seterr("master pub");
    return false;
  }
  uint8_t mh160[20];
  if (!hash160_mbedtls(mpub, sizeof(mpub), mh160)) {
    sp_zero(mpub, sizeof(mpub));
    sp_zero(mh160, sizeof(mh160));
    seterr("master fp");
    return false;
  }
  memcpy(master_fp, mh160, 4);
  sp_zero(mpub, sizeof(mpub));
  sp_zero(mh160, sizeof(mh160));

  size_t pos = 5;
  PsbtMap global;
  if (!read_psbt_map(psbt_in, psbt_in_len, pos, global)) {
    seterr("parse global");
    return false;
  }
  const std::vector<uint8_t>* unsigned_raw = nullptr;
  for (const auto& kv : global) {
    if (kv.first.size() == 1 && kv.first[0] == 0x00) {
      unsigned_raw = &kv.second;
      break;
    }
  }
  if (!unsigned_raw) {
    seterr("no unsigned tx");
    return false;
  }

  std::vector<TxInParsed> tins;
  std::vector<TxOutParsed> touts;
  uint32_t version = 0, locktime = 0;
  if (!parse_unsigned_tx(unsigned_raw->data(), unsigned_raw->size(), tins, touts, version, locktime)) {
    seterr("parse tx");
    return false;
  }
  size_t n_in = tins.size();
  size_t n_out = touts.size();

  std::vector<PsbtMap> in_maps(n_in);
  for (size_t i = 0; i < n_in; i++) {
    if (!read_psbt_map(psbt_in, psbt_in_len, pos, in_maps[i])) {
      seterr("parse in map");
      return false;
    }
  }
  std::vector<PsbtMap> out_maps(n_out);
  for (size_t i = 0; i < n_out; i++) {
    if (!read_psbt_map(psbt_in, psbt_in_len, pos, out_maps[i])) {
      seterr("parse out map");
      return false;
    }
  }
  if (pos > psbt_in_len) {
    seterr("overflow");
    return false;
  }

  // Strict anti-theft guard: any output claiming our master fingerprint must be
  // cryptographically verified against our derived pubkey and output script.
  // If not, abort signing (host may be redirecting change).
  for (size_t oi = 0; oi < n_out; oi++) {
    bool has_our_change_claim = false;
    for (const auto& kv : out_maps[oi]) {
      if (kv.first.size() == 34 && kv.first[0] == 0x02 && kv.second.size() >= 4 &&
          memcmp(kv.second.data(), master_fp, 4) == 0) {
        has_our_change_claim = true;
        break;
      }
    }
    if (!has_our_change_claim) continue;
    if (!psbt_output_is_change_verified(out_maps[oi], touts[oi].script_pubkey, master_node, master_fp)) {
      seterr("unverified change output");
      return false;
    }
  }

  std::vector<uint8_t> outs_buf;
  serialize_outs_for_hash(touts, outs_buf);
  uint8_t hash_prevouts[32], hash_sequence[32], hash_outputs[32];
  hash_prevouts_seq(tins, hash_prevouts, hash_sequence);
  sha256d(outs_buf.data(), outs_buf.size(), hash_outputs);

  for (size_t idx = 0; idx < n_in; idx++) {
    const auto& inm = in_maps[idx];
    std::vector<uint8_t> witness_val;
    std::vector<uint8_t> redeem_script;
    std::vector<uint8_t> witness_script;
    uint32_t sighash_type = 1;
    for (const auto& kv : inm) {
      if (kv.first.size() == 1 && kv.first[0] == 0x01) witness_val = kv.second;
      if (kv.first.size() == 1 && kv.first[0] == 0x04) redeem_script = kv.second;  // PSBT_IN_REDEEM_SCRIPT
      if (kv.first.size() == 1 && kv.first[0] == 0x05) witness_script = kv.second; // PSBT_IN_WITNESS_SCRIPT
      if (kv.first.size() == 1 && kv.first[0] == 0x03 && kv.second.size() == 4) {
        sighash_type = (uint32_t)kv.second[0] | ((uint32_t)kv.second[1] << 8) | ((uint32_t)kv.second[2] << 16) |
                       ((uint32_t)kv.second[3] << 24);
      }
    }
    if (witness_val.empty()) {
      seterr("missing witness utxo");
      return false;
    }
    uint64_t val_sat = 0;
    std::vector<uint8_t> script_pubkey;
    WitnessInputKind in_kind = WitnessInputKind::UNKNOWN;
    if (!parse_witness_utxo_script(witness_val, val_sat, script_pubkey, in_kind)) {
      seterr("need segwit witness utxo");
      return false;
    }

    // Decide script-code and script ownership mode.
    bool segwit_keypath = false;  // P2WPKH key-hash ownership
    uint8_t spk_h20[20];
    memset(spk_h20, 0, sizeof(spk_h20));
    std::vector<uint8_t> script_code;
    if (in_kind == WitnessInputKind::P2WPKH) {
      segwit_keypath = true;
      memcpy(spk_h20, script_pubkey.data() + 2, 20);
      script_code.push_back(0x76);
      script_code.push_back(0xa9);
      script_code.push_back(0x14);
      script_code.insert(script_code.end(), spk_h20, spk_h20 + 20);
      script_code.push_back(0x88);
      script_code.push_back(0xac);
    } else if (in_kind == WitnessInputKind::P2WSH) {
      if (witness_script.empty()) {
        seterr("missing witness script");
        return false;
      }
      uint8_t sh[32];
      sha256_once(witness_script.data(), witness_script.size(), sh);
      bool ok = (memcmp(script_pubkey.data() + 2, sh, 32) == 0);
      sp_zero(sh, sizeof(sh));
      if (!ok) {
        seterr("witness script hash mismatch");
        return false;
      }
      script_code = witness_script;  // BIP143 scriptCode = witness script for P2WSH.
    } else if (in_kind == WitnessInputKind::P2SH) {
      if (redeem_script.size() == 34 && redeem_script[0] == 0x00 && redeem_script[1] == 0x20 && !witness_script.empty()) {
        uint8_t rh160[20];
        uint8_t sh[32];
        bool ok = false;
        sha256_once(witness_script.data(), witness_script.size(), sh);
        if (memcmp(redeem_script.data() + 2, sh, 32) == 0 && hash160_mbedtls(redeem_script.data(), redeem_script.size(), rh160)) {
          ok = (memcmp(script_pubkey.data() + 2, rh160, 20) == 0);
        }
        sp_zero(rh160, sizeof(rh160));
        sp_zero(sh, sizeof(sh));
        if (!ok) {
          seterr("redeem/witness mismatch");
          return false;
        }
        script_code = witness_script;  // Nested P2WSH uses witness script in preimage.
      } else if (redeem_script.size() == 22 && redeem_script[0] == 0x00 && redeem_script[1] == 0x14) {
        uint8_t rh160[20];
        bool ok = hash160_mbedtls(redeem_script.data(), redeem_script.size(), rh160)
                  && (memcmp(script_pubkey.data() + 2, rh160, 20) == 0);
        sp_zero(rh160, sizeof(rh160));
        if (!ok) {
          seterr("redeem script mismatch");
          return false;
        }
        segwit_keypath = true;
        memcpy(spk_h20, redeem_script.data() + 2, 20);
        script_code.push_back(0x76);
        script_code.push_back(0xa9);
        script_code.push_back(0x14);
        script_code.insert(script_code.end(), spk_h20, spk_h20 + 20);
        script_code.push_back(0x88);
        script_code.push_back(0xac);
      } else {
        seterr("unsupported P2SH witness input");
        return false;
      }
    } else {
      seterr("unsupported witness input");
      return false;
    }

    uint8_t priv[32];
    uint8_t pub[33];
    bool have_key = false;
    for (const auto& kv : inm) {
      if (kv.first.size() != 34 || kv.first[0] != 0x06) continue;
      const uint8_t* claim_pub = kv.first.data() + 1;
      const std::vector<uint8_t>& der_path_val = kv.second;
      if (der_path_val.size() < 4 || (der_path_val.size() - 4) % 4 != 0) continue;
      if (memcmp(der_path_val.data(), master_fp, 4) != 0) continue;
      size_t n_path = (der_path_val.size() - 4) / 4;
      std::vector<uint32_t> path(n_path);
      for (size_t p = 0; p < n_path; p++) {
        const uint8_t* q = der_path_val.data() + 4 + p * 4;
        path[p] = (uint32_t)q[0] | ((uint32_t)q[1] << 8) | ((uint32_t)q[2] << 16) | ((uint32_t)q[3] << 24);
      }
      if (!derive_priv_from_master_node(master_node, path.data(), path.size(), priv)) continue;
      if (!secp_pubkey_compressed(priv, pub)) {
        sp_zero(priv, sizeof(priv));
        continue;
      }
      if (memcmp(pub, claim_pub, 33) != 0) {
        sp_zero(priv, sizeof(priv));
        sp_zero(pub, sizeof(pub));
        continue;
      }
      if (segwit_keypath) {
        uint8_t h160c[20];
        if (!hash160_mbedtls(pub, 33, h160c) || memcmp(h160c, spk_h20, 20) != 0) {
          sp_zero(priv, sizeof(priv));
          sp_zero(pub, sizeof(pub));
          continue;
        }
      } else {
        if (!script_contains_pubkey_push(script_code, pub)) {
          sp_zero(priv, sizeof(priv));
          sp_zero(pub, sizeof(pub));
          continue;
        }
      }
      have_key = true;
      break;
    }
    if (!have_key) {
      seterr("no matching key (fp/path/script)");
      return false;
    }

    // BIP143 preimage below is for SIGHASH_ALL only; reject ANYONECANPAY / NONE / SINGLE (see BIP143).
    if (sighash_type != 1u) {
      sp_zero(priv, sizeof(priv));
      seterr("need SIGHASH_ALL (1)");
      return false;
    }

    std::vector<uint8_t> preimage;
    for (int b = 0; b < 4; b++) preimage.push_back((uint8_t)((version >> (8 * b)) & 0xff));
    preimage.insert(preimage.end(), hash_prevouts, hash_prevouts + 32);
    preimage.insert(preimage.end(), hash_sequence, hash_sequence + 32);
    preimage.insert(preimage.end(), tins[idx].prev, tins[idx].prev + 32);
    for (int b = 0; b < 4; b++) preimage.push_back((uint8_t)((tins[idx].prev_index >> (8 * b)) & 0xff));
    write_compact_size(preimage, script_code.size());
    preimage.insert(preimage.end(), script_code.begin(), script_code.end());
    for (int b = 0; b < 8; b++) preimage.push_back((uint8_t)((val_sat >> (8 * b)) & 0xff));
    for (int b = 0; b < 4; b++) preimage.push_back((uint8_t)((tins[idx].sequence >> (8 * b)) & 0xff));
    preimage.insert(preimage.end(), hash_outputs, hash_outputs + 32);
    for (int b = 0; b < 4; b++) preimage.push_back((uint8_t)((locktime >> (8 * b)) & 0xff));
    for (int b = 0; b < 4; b++) preimage.push_back((uint8_t)((sighash_type >> (8 * b)) & 0xff));

    uint8_t sighash[32];
    sha256d(preimage.data(), preimage.size(), sighash);

    uint8_t der[80];
    size_t derlen = 0;
    if (!ecdsa_der_sign(priv, sighash, der, &derlen, sizeof(der))) {
      sp_zero(priv, sizeof(priv));
      sp_zero(sighash, sizeof(sighash));
      seterr("sign failed");
      return false;
    }
    sp_zero(priv, sizeof(priv));
    sp_zero(sighash, sizeof(sighash));

    std::vector<uint8_t> psig;
    psig.insert(psig.end(), der, der + derlen);
    psig.push_back(0x01);  // SIGHASH_ALL (must match sighash_type == 1)

    std::vector<uint8_t> psig_key;
    psig_key.push_back(0x02);
    psig_key.insert(psig_key.end(), pub, pub + 33);

    bool replaced = false;
    for (auto& kv : in_maps[idx]) {
      if (kv.first == psig_key) {
        kv.second = std::move(psig);
        replaced = true;
        break;
      }
    }
    if (!replaced) in_maps[idx].push_back({std::move(psig_key), std::move(psig)});
  }

  std::vector<uint8_t> out;
  out.insert(out.end(), PSBT_MAGIC, PSBT_MAGIC + 5);
  write_psbt_map(out, global);
  for (size_t i = 0; i < n_in; i++) write_psbt_map(out, in_maps[i]);
  for (size_t i = 0; i < n_out; i++) write_psbt_map(out, out_maps[i]);

  if (out.size() > psbt_out_cap) {
    seterr("output too big");
    return false;
  }
  memcpy(psbt_out, out.data(), out.size());
  *psbt_out_len = out.size();
  return true;
}

extern "C" bool seedmask_psbt_review_summarize(const uint8_t* psbt, size_t len, const uint8_t master_fp[4],
                                               seedmask_psbt_review_t* out) {
  if (!out || !psbt || !master_fp) return false;
  std::memset(out, 0, sizeof(*out));
  auto fail = [&](const char* m) {
    snprintf(out->err, sizeof(out->err), "%s", m);
    return false;
  };
  if (len < 10 || memcmp(psbt, PSBT_MAGIC, 5) != 0) return fail("not PSBT");

  size_t pos = 5;
  PsbtMap global;
  if (!read_psbt_map(psbt, len, pos, global)) return fail("parse global");
  const std::vector<uint8_t>* unsigned_raw = nullptr;
  for (const auto& kv : global) {
    if (kv.first.size() == 1 && kv.first[0] == 0x00) {
      unsigned_raw = &kv.second;
      break;
    }
  }
  if (!unsigned_raw) return fail("no unsigned tx");

  std::vector<TxInParsed> tins;
  std::vector<TxOutParsed> touts;
  uint32_t version = 0, locktime = 0;
  if (!parse_unsigned_tx(unsigned_raw->data(), unsigned_raw->size(), tins, touts, version, locktime)) return fail("parse tx");

  size_t n_in = tins.size();
  size_t n_out = touts.size();
  std::vector<PsbtMap> in_maps(n_in);
  for (size_t i = 0; i < n_in; i++) {
    if (!read_psbt_map(psbt, len, pos, in_maps[i])) return fail("parse in map");
  }
  std::vector<PsbtMap> out_maps(n_out);
  for (size_t i = 0; i < n_out; i++) {
    if (!read_psbt_map(psbt, len, pos, out_maps[i])) return fail("parse out map");
  }
  if (pos > len) return fail("overflow");

  uint64_t total_in = 0;
  out->num_inputs = (uint8_t)((n_in > 255) ? 255 : n_in);
  out->num_viz_inputs = 0;
  for (size_t i = 0; i < n_in; i++) {
    std::vector<uint8_t> witness_val;
    for (const auto& kv : in_maps[i]) {
      if (kv.first.size() == 1 && kv.first[0] == 0x01) witness_val = kv.second;
    }
    if (witness_val.empty()) return fail("missing witness utxo");
    uint64_t vin = 0;
    if (!witness_utxo_value_sat(witness_val, vin)) return fail("bad witness value");
    total_in += vin;

    // Visualizer labels: PSBT_IN_BIP32_DERIVATION (0x06) matching master fingerprint → Receive/Change #index
    if (out->num_viz_inputs < SEEDMASK_PSBT_REVIEW_MAX_INPUTS) {
      bool labeled = false;
      for (const auto& kv : in_maps[i]) {
        if (kv.first.size() != 34 || kv.first[0] != 0x06) continue;
        if (kv.second.size() < 8 || ((kv.second.size() - 4) % 4) != 0) continue;
        if (memcmp(kv.second.data(), master_fp, 4) != 0) continue;
        const size_t n_path = (kv.second.size() - 4) / 4;
        if (n_path < 2) continue;
        std::vector<uint32_t> path(n_path);
        for (size_t p = 0; p < n_path; p++) {
          const uint8_t* q = kv.second.data() + 4 + p * 4;
          path[p] = (uint32_t)q[0] | ((uint32_t)q[1] << 8) | ((uint32_t)q[2] << 16) | ((uint32_t)q[3] << 24);
        }
        const uint8_t slot = out->num_viz_inputs;
        out->viz_input_is_change[slot] = bip32_path_is_change_chain(path.data(), n_path) ? 1 : 0;
        out->viz_input_index[slot] = path[n_path - 1] & 0x7fffffffu;
        out->viz_input_sat[slot] = vin;
        out->num_viz_inputs = (uint8_t)(slot + 1);
        labeled = true;
        break;
      }
      if (!labeled) {
        // Taproot input BIP32 (BIP371): key type 0x07 in some wallets; try tap deriv value on 0x07 keys
        for (const auto& kv : in_maps[i]) {
          if (kv.first.size() != 33 || kv.first[0] != 0x07) continue;
          uint8_t fp[4];
          std::vector<uint32_t> path;
          if (!parse_tap_bip32_deriv_value(kv.second, fp, path)) continue;
          if (memcmp(fp, master_fp, 4) != 0) continue;
          if (path.size() < 2) continue;
          const uint8_t slot = out->num_viz_inputs;
          out->viz_input_is_change[slot] = bip32_path_is_change_chain(path.data(), path.size()) ? 1 : 0;
          out->viz_input_index[slot] = path[path.size() - 1] & 0x7fffffffu;
          out->viz_input_sat[slot] = vin;
          out->num_viz_inputs = (uint8_t)(slot + 1);
          break;
        }
      }
    }
  }

  uint64_t total_out = 0;
  for (const auto& o : touts) total_out += o.value;

  if (total_in < total_out) return fail("inputs < outputs");
  uint64_t fee = total_in - total_out;

  uint64_t send_sat = 0;
  uint64_t change_sat = 0;
  uint32_t num_send = 0;
  uint32_t num_change = 0;
  uint8_t first_spk_len = 0;
  uint8_t first_spk[40];
  memset(first_spk, 0, sizeof(first_spk));
  uint8_t first_chg_spk_len = 0;
  uint8_t first_chg_spk[40];
  memset(first_chg_spk, 0, sizeof(first_chg_spk));

  for (size_t i = 0; i < n_out; i++) {
    bool isch = psbt_output_is_change_claim_consistent(out_maps[i], touts[i].script_pubkey, master_fp);
    if (isch) {
      change_sat += touts[i].value;
      num_change++;
      if (first_chg_spk_len == 0 && !touts[i].script_pubkey.empty() &&
          touts[i].script_pubkey.size() <= sizeof(first_chg_spk)) {
        first_chg_spk_len = (uint8_t)touts[i].script_pubkey.size();
        memcpy(first_chg_spk, touts[i].script_pubkey.data(), first_chg_spk_len);
      }
    } else {
      send_sat += touts[i].value;
      num_send++;
      if (first_spk_len == 0 && !touts[i].script_pubkey.empty() && touts[i].script_pubkey.size() <= sizeof(first_spk)) {
        first_spk_len = (uint8_t)touts[i].script_pubkey.size();
        memcpy(first_spk, touts[i].script_pubkey.data(), first_spk_len);
      }
    }
  }

  out->send_sat = send_sat;
  out->change_sat = change_sat;
  out->fee_sat = fee;
  out->num_send_outputs = num_send;
  out->first_send_spk_len = first_spk_len;
  if (first_spk_len) memcpy(out->first_send_spk, first_spk, first_spk_len);
  out->num_change_outputs = num_change;
  out->first_change_spk_len = first_chg_spk_len;
  if (first_chg_spk_len) memcpy(out->first_change_spk, first_chg_spk, first_chg_spk_len);

  // Fee % vs total moving to on-chain outputs (send + change), not send alone — otherwise change makes fee look
  // much higher than it is (e.g. fee 69, send 700, change 478 → 9.8% of send but 5.86% of 700+478).
  const uint64_t fee_denom = send_sat + change_sat;
  if (fee_denom > 0) {
    out->fee_pct_of_send_tenths = (uint32_t)((fee * 1000ULL) / fee_denom);
    if (fee * 100ULL > fee_denom * 5ULL) out->big_fee_warn = 1;
  }

  out->is_multisig = false;
  out->ms_required = 0;
  out->ms_total = 0;
  out->device_is_cosigner = 0;
  {
    auto script_is_multisig_mn = [](const std::vector<uint8_t>& sc, uint8_t* m, uint8_t* n) -> bool {
      if (sc.size() < 37 || sc.back() != 0xae) return false;  // OP_CHECKMULTISIG
      const uint8_t op_m = sc.front();
      const uint8_t op_n = sc[sc.size() - 2];
      if (op_m < 0x51 || op_m > 0x60 || op_n < 0x51 || op_n > 0x60) return false;
      *m = (uint8_t)(op_m - 0x50);
      *n = (uint8_t)(op_n - 0x50);
      return *m >= 1 && *n >= *m && *n <= 16;
    };
    bool fp_seen = false;
    for (size_t i = 0; i < n_in; i++) {
      std::vector<uint8_t> witness_script;
      std::vector<uint8_t> redeem_script;
      for (const auto& kv : in_maps[i]) {
        if (kv.first.size() == 1 && kv.first[0] == 0x05) witness_script = kv.second;  // PSBT_IN_WITNESS_SCRIPT
        if (kv.first.size() == 1 && kv.first[0] == 0x04) redeem_script = kv.second;    // PSBT_IN_REDEEM_SCRIPT
        if (kv.first.size() == 34 && kv.first[0] == 0x06 && kv.second.size() >= 4) {
          if (memcmp(kv.second.data(), master_fp, 4) == 0) fp_seen = true;
        }
      }
      uint8_t m = 0, n = 0;
      if ((!witness_script.empty() && script_is_multisig_mn(witness_script, &m, &n))
          || (!redeem_script.empty() && script_is_multisig_mn(redeem_script, &m, &n))) {
        out->is_multisig = true;
        if (out->ms_required == 0) {
          out->ms_required = m;
          out->ms_total = n;
        }
      }
    }
    if (out->is_multisig) out->device_is_cosigner = fp_seen ? (int8_t)1 : (int8_t)2;
  }

  out->ok = 1;
  return true;
}

// Added for firmware that declares seedmask_psbt_distinct_signing_account_indices in seedmask_psbt_sign.h (multisig UI).
// Full path extraction can be extended later; returning true with *out_count=0 matches prior "no distinct accounts" UI path.
extern "C" bool seedmask_psbt_distinct_signing_account_indices(const uint8_t* psbt, size_t len,
                                                               const uint8_t master_fp[4], uint32_t* accounts_out,
                                                               uint8_t* out_count, uint8_t max_out) {
  (void)psbt;
  (void)len;
  (void)master_fp;
  (void)accounts_out;
  (void)max_out;
  if (out_count) *out_count = 0;
  return true;
}
