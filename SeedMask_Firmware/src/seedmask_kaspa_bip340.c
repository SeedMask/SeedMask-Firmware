#include "seedmask_kaspa_bip340.h"

#include <stdio.h>
#include <string.h>

#if defined(ARDUINO_ARCH_ESP32)
#include "esp_random.h"
#endif

#include "mbedtls/bignum.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"

static int kaspa_bip340_rng(void* ctx, unsigned char* out, size_t len) {
  (void)ctx;
#if defined(ARDUINO_ARCH_ESP32)
  esp_fill_random(out, len);
#else
  for (size_t i = 0; i < len; i++) out[i] = (uint8_t)(i + 1);
#endif
  return 0;
}

static void sha256_once(const uint8_t* in, size_t in_len, uint8_t out[32]) {
  mbedtls_sha256_context c;
  mbedtls_sha256_init(&c);
  mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, in, in_len);
  mbedtls_sha256_finish(&c, out);
  mbedtls_sha256_free(&c);
}

static void tagged_hash(const char* tag, const uint8_t* msg, size_t msg_len, uint8_t out[32]) {
  uint8_t th[32];
  size_t tag_len = strlen(tag);
  sha256_once((const uint8_t*)tag, tag_len, th);
  mbedtls_sha256_context c;
  mbedtls_sha256_init(&c);
  mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, th, 32);
  mbedtls_sha256_update(&c, th, 32);
  if (msg && msg_len) mbedtls_sha256_update(&c, msg, msg_len);
  mbedtls_sha256_finish(&c, out);
  mbedtls_sha256_free(&c);
  memset(th, 0, sizeof(th));
}

static void bip340_masked_key_bytes(const uint8_t seckey32[32], const uint8_t aux_rand32[32], uint8_t masked[32]) {
  static const uint8_t kZeroAuxMask[32] = {
      84, 241, 105, 207, 201, 226, 229, 114, 116, 128, 68, 31, 144, 186, 37, 196,
      136, 244, 97, 199, 11, 94, 165, 220, 170, 247, 175, 105, 39, 10, 165, 20};
  uint8_t aux_hash[32];
  if (aux_rand32) {
    tagged_hash("BIP0340/aux", aux_rand32, 32, aux_hash);
    for (int i = 0; i < 32; i++) masked[i] = (uint8_t)(seckey32[i] ^ aux_hash[i]);
    memset(aux_hash, 0, sizeof(aux_hash));
  } else {
    for (int i = 0; i < 32; i++) masked[i] = (uint8_t)(seckey32[i] ^ kZeroAuxMask[i]);
  }
}

static void bip340_nonce32(const uint8_t masked_key[32], const uint8_t xonly32[32], const uint8_t msg32[32],
                           uint8_t nonce32[32]) {
  uint8_t buf[96];
  memcpy(buf, masked_key, 32);
  memcpy(buf + 32, xonly32, 32);
  memcpy(buf + 64, msg32, 32);
  tagged_hash("BIP0340/nonce", buf, 96, nonce32);
  memset(buf, 0, sizeof(buf));
}

/* mbedTLS 3: ECP point X/Y are not public — use compressed (0x02/0x03) and uncompressed export. */
static bool bip340_point_y_is_odd(const mbedtls_ecp_group* grp, const mbedtls_ecp_point* pt) {
  uint8_t comp[33];
  size_t olen = 0;
  if (mbedtls_ecp_point_write_binary(grp, pt, MBEDTLS_ECP_PF_COMPRESSED, &olen, comp, sizeof(comp)) != 0)
    return false;
  if (olen != 33) return false;
  return comp[0] == 0x03;
}

static bool bip340_point_xonly32(const mbedtls_ecp_group* grp, const mbedtls_ecp_point* pt, uint8_t xonly32[32]) {
  uint8_t comp[33];
  size_t olen = 0;
  if (mbedtls_ecp_point_write_binary(grp, pt, MBEDTLS_ECP_PF_COMPRESSED, &olen, comp, sizeof(comp)) != 0)
    return false;
  if (olen != 33 || (comp[0] != 0x02 && comp[0] != 0x03)) return false;
  memcpy(xonly32, comp + 1, 32);
  return true;
}

/* BIP-340: even-Y scalar; write 32-byte secret and x-only pubkey. */
static bool bip340_load_even_key(const uint8_t priv32[32], mbedtls_ecp_group* grp, mbedtls_mpi* d_out,
                                 uint8_t seckey32[32], uint8_t xonly32[32]) {
  mbedtls_mpi d_raw, d_adj;
  mbedtls_ecp_point P;
  mbedtls_mpi_init(&d_raw);
  mbedtls_mpi_init(&d_adj);
  mbedtls_ecp_point_init(&P);
  bool ok = false;

  if (mbedtls_mpi_read_binary(&d_raw, priv32, 32) != 0) goto cleanup;
  if (mbedtls_mpi_mod_mpi(&d_raw, &d_raw, &grp->N) != 0) goto cleanup;
  if (mbedtls_mpi_cmp_int(&d_raw, 0) == 0) goto cleanup;
  if (mbedtls_ecp_mul(grp, &P, &d_raw, &grp->G, kaspa_bip340_rng, NULL) != 0) goto cleanup;
  if (mbedtls_mpi_copy(&d_adj, &d_raw) != 0) goto cleanup;
  if (bip340_point_y_is_odd(grp, &P)) {
    if (mbedtls_mpi_sub_mpi(&d_adj, &grp->N, &d_raw) != 0) goto cleanup;
    if (mbedtls_ecp_mul(grp, &P, &d_adj, &grp->G, kaspa_bip340_rng, NULL) != 0) goto cleanup;
  }
  if (bip340_point_y_is_odd(grp, &P)) goto cleanup;
  if (mbedtls_mpi_write_binary(&d_adj, seckey32, 32) != 0) goto cleanup;
  if (!bip340_point_xonly32(grp, &P, xonly32)) goto cleanup;
  if (mbedtls_mpi_copy(d_out, &d_adj) != 0) goto cleanup;
  ok = true;

cleanup:
  mbedtls_mpi_free(&d_adj);
  mbedtls_mpi_free(&d_raw);
  mbedtls_ecp_point_free(&P);
  return ok;
}

static bool mpi_from_hash_nonzero(const uint8_t hash32[32], const mbedtls_mpi* order, mbedtls_mpi* out) {
  if (mbedtls_mpi_read_binary(out, hash32, 32) != 0) return false;
  if (mbedtls_mpi_mod_mpi(out, out, order) != 0) return false;
  return mbedtls_mpi_cmp_int(out, 0) != 0;
}

bool seedmask_kaspa_bip340_pubkey_xonly(const uint8_t priv32[32], uint8_t xonly32[32]) {
  if (!priv32 || !xonly32) return false;
  mbedtls_ecp_group grp;
  mbedtls_mpi d;
  uint8_t seckey[32];
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  bool ok = false;
  if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0) goto done;
  ok = bip340_load_even_key(priv32, &grp, &d, seckey, xonly32);
done:
  mbedtls_mpi_free(&d);
  mbedtls_ecp_group_free(&grp);
  memset(seckey, 0, sizeof(seckey));
  return ok;
}

bool seedmask_kaspa_bip340_sign(const uint8_t priv32[32], const uint8_t msg32[32], const uint8_t aux_rand32[32],
                                uint8_t sig64[64]) {
  if (!priv32 || !msg32 || !sig64) return false;

  mbedtls_ecp_group grp;
  mbedtls_mpi d, k, e, ed;
  mbedtls_ecp_point R;
  uint8_t seckey[32];
  uint8_t ax[32];
  uint8_t masked[32];
  uint8_t hash[32];
  uint8_t buf[96];
  uint8_t aux_local[32];

  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&d);
  mbedtls_mpi_init(&k);
  mbedtls_mpi_init(&e);
  mbedtls_mpi_init(&ed);
  mbedtls_ecp_point_init(&R);

  bool ok = false;
  if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0) goto cleanup;
  if (!bip340_load_even_key(priv32, &grp, &d, seckey, ax)) goto cleanup;

  for (int attempt = 0; attempt < 64; attempt++) {
    const uint8_t* aux_ptr = aux_rand32;
    if (!aux_ptr) {
#if defined(ARDUINO_ARCH_ESP32)
      if (attempt > 0) {
        esp_fill_random(aux_local, sizeof(aux_local));
        aux_ptr = aux_local;
      }
#else
      if (attempt > 0) {
        memset(aux_local, 0, sizeof(aux_local));
        aux_local[31] = (uint8_t)attempt;
        aux_ptr = aux_local;
      }
#endif
    }
    bip340_masked_key_bytes(seckey, aux_ptr, masked);
    bip340_nonce32(masked, ax, msg32, hash);
    if (!mpi_from_hash_nonzero(hash, &grp.N, &k)) continue;
    if (mbedtls_ecp_mul(&grp, &R, &k, &grp.G, kaspa_bip340_rng, NULL) != 0) continue;
    if (bip340_point_y_is_odd(&grp, &R)) {
      if (mbedtls_mpi_sub_mpi(&k, &grp.N, &k) != 0) continue;
      if (mbedtls_ecp_mul(&grp, &R, &k, &grp.G, kaspa_bip340_rng, NULL) != 0) continue;
    }
    if (bip340_point_y_is_odd(&grp, &R)) continue;
    ok = true;
    break;
  }
  if (!ok) goto cleanup;

  if (!bip340_point_xonly32(&grp, &R, sig64)) goto cleanup;

  memcpy(buf, sig64, 32);
  memcpy(buf + 32, ax, 32);
  memcpy(buf + 64, msg32, 32);
  tagged_hash("BIP0340/challenge", buf, 96, hash);
  if (!mpi_from_hash_nonzero(hash, &grp.N, &e)) goto cleanup;

  if (mbedtls_mpi_mul_mpi(&ed, &e, &d) != 0) goto cleanup;
  if (mbedtls_mpi_mod_mpi(&ed, &ed, &grp.N) != 0) goto cleanup;
  if (mbedtls_mpi_add_mpi(&k, &k, &ed) != 0) goto cleanup;
  if (mbedtls_mpi_mod_mpi(&k, &k, &grp.N) != 0) goto cleanup;
  if (mbedtls_mpi_write_binary(&k, sig64 + 32, 32) != 0) goto cleanup;

  ok = true;

cleanup:
  memset(seckey, 0, sizeof(seckey));
  memset(ax, 0, sizeof(ax));
  memset(masked, 0, sizeof(masked));
  memset(hash, 0, sizeof(hash));
  memset(buf, 0, sizeof(buf));
  memset(aux_local, 0, sizeof(aux_local));
  if (!ok) memset(sig64, 0, 64);
  mbedtls_mpi_free(&ed);
  mbedtls_mpi_free(&e);
  mbedtls_mpi_free(&k);
  mbedtls_mpi_free(&d);
  mbedtls_ecp_point_free(&R);
  mbedtls_ecp_group_free(&grp);
  return ok;
}

bool seedmask_kaspa_bip340_selftest(char* err, size_t err_len) {
  /* BIP-340 test vector 0 (test-vectors.csv index 0). */
  static const uint8_t priv[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3};
  static const uint8_t msg[32] = {0};
  static const uint8_t aux[32] = {0};
  static const uint8_t expect_pk[32] = {
      0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52, 0x29,
      0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0, 0x36, 0xf9};
  static const uint8_t expect_sig[64] = {
      0xe9, 0x07, 0x83, 0x1f, 0x80, 0x84, 0x8d, 0x10, 0x69, 0xa5, 0x37, 0x1b, 0x40, 0x24, 0x10, 0x36,
      0x4b, 0xdf, 0x1c, 0x5f, 0x83, 0x07, 0xb0, 0x08, 0x4c, 0x55, 0xf1, 0xce, 0x2d, 0xca, 0x82, 0x15,
      0x25, 0xf6, 0x6a, 0x4a, 0x85, 0xea, 0x8b, 0x71, 0xe4, 0x82, 0xa7, 0x4f, 0x38, 0x2d, 0x2c, 0xe5,
      0xeb, 0xee, 0xe8, 0xfd, 0xb2, 0x17, 0x2f, 0x47, 0x7d, 0xf4, 0x90, 0x0d, 0x31, 0x05, 0x36, 0xc0};
  uint8_t pk[32];
  uint8_t sig[64];
  if (!seedmask_kaspa_bip340_pubkey_xonly(priv, pk)) {
    if (err && err_len) snprintf(err, err_len, "%s", "bip340 pubkey");
    return false;
  }
  if (memcmp(pk, expect_pk, 32) != 0) {
    if (err && err_len) snprintf(err, err_len, "%s", "bip340 pubkey");
    return false;
  }
  if (!seedmask_kaspa_bip340_sign(priv, msg, aux, sig)) {
    if (err && err_len) snprintf(err, err_len, "%s", "bip340 sign");
    return false;
  }
  if (memcmp(sig, expect_sig, 64) != 0) {
    if (err && err_len) snprintf(err, err_len, "%s", "bip340 vector");
    return false;
  }
  return true;
}
