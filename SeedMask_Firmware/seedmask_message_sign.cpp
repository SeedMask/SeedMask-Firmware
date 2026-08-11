// SPDX-License-Identifier: MIT
// Bitcoin signed message: Sparrow Drongo preimage + Hash256 + P2WPKH compact header (matches ECKey.signMessage).

#include "seedmask_message_sign.h"

#include "mbedtls/asn1write.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/bignum.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

#include "esp_random.h"

extern "C" {
#include "src/trezor_firmware/crypto/ecdsa.h"
}
extern const ecdsa_curve secp256k1;

#include <string.h>

#if !defined(MBEDTLS_ECDSA_DETERMINISTIC)
#error "MBEDTLS_ECDSA_DETERMINISTIC is required for deterministic message signing (RFC6979)."
#endif

static int sp_rng(void *, unsigned char *out, size_t len) {
  esp_fill_random(out, len);
  return 0;
}

static void sha256_once(const uint8_t *in, size_t inLen, uint8_t out[32]) {
  mbedtls_sha256_context c;
  mbedtls_sha256_init(&c);
  mbedtls_sha256_starts(&c, 0);
  mbedtls_sha256_update(&c, in, inLen);
  mbedtls_sha256_finish(&c, out);
  mbedtls_sha256_free(&c);
}

// Hash256 — same as Sparrow Drongo ECKey.signMessage / signedMessageToKey (Sha256Hash.twiceOf).
static void sha256d(const uint8_t *in, size_t inLen, uint8_t out[32]) {
  uint8_t t[32];
  sha256_once(in, inLen, t);
  sha256_once(t, sizeof(t), out);
  mbedtls_platform_zeroize(t, sizeof(t));
}

// Preimage: compact length + string (same idea as Drongo formatMessageForSigning).
static bool append_string_bitcoin(const char *s, size_t slen, uint8_t *buf, size_t bufCap, size_t *off) {
  size_t o = *off;
  if (slen < 253) {
    if (o + 1 + slen > bufCap) return false;
    buf[o++] = (uint8_t)slen;
  } else if (slen <= 0xffff) {
    if (o + 3 + slen > bufCap) return false;
    buf[o++] = 253;
    buf[o++] = (uint8_t)(slen & 0xff);
    buf[o++] = (uint8_t)((slen >> 8) & 0xff);
  } else {
    return false;
  }
  memcpy(buf + o, s, slen);
  o += slen;
  *off = o;
  return true;
}

bool seedmask_bitcoin_signed_message_hash(const char *message, size_t messageLen, uint8_t hash32[32]) {
  // Core: strMessageMagic = "Bitcoin Signed Message:\n" (24 chars) → compact varint 0x18 + 24 bytes.
  // Do NOT embed 0x18 in the string; append_string_bitcoin adds the length prefix.
  static const char kMagic[] = "Bitcoin Signed Message:\n";
  const size_t magicLen = sizeof(kMagic) - 1u;
  uint8_t buf[1100];
  size_t o = 0;
  if (!append_string_bitcoin(kMagic, magicLen, buf, sizeof(buf), &o)) return false;
  if (!message) messageLen = 0;
  if (!append_string_bitcoin(message, messageLen, buf, sizeof(buf), &o)) return false;
  // Sparrow (com.sparrowwallet.drongo.crypto.ECKey): Sha256Hash.twiceOf(formatted bytes) — must match exactly.
  sha256d(buf, o, hash32);
  mbedtls_platform_zeroize(buf, sizeof(buf));
  return true;
}

bool seedmask_ecdsa_sign_hash_det(const uint8_t priv32[32], const uint8_t hash32[32], uint8_t *derOut,
                                  size_t *derLen, size_t derCap) {
  mbedtls_ecp_group grp;
  mbedtls_mpi r, s, d;
  mbedtls_ecp_group_init(&grp);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&d);
  bool ok = false;
  if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1) != 0) goto done;
  if (mbedtls_mpi_read_binary(&d, priv32, 32) != 0) goto done;
#if defined(MBEDTLS_VERSION_NUMBER) && (MBEDTLS_VERSION_NUMBER >= 0x03000000)
  if (mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d, hash32, 32, MBEDTLS_MD_SHA256, sp_rng, nullptr) != 0)
    goto done;
#else
  if (mbedtls_ecdsa_sign_det(&grp, &r, &s, &d, hash32, 32, MBEDTLS_MD_SHA256) != 0) goto done;
#endif
  {
    mbedtls_mpi half;
    mbedtls_mpi_init(&half);
    mbedtls_mpi_copy(&half, &grp.N);
    mbedtls_mpi_shift_r(&half, 1);
    if (mbedtls_mpi_cmp_mpi(&s, &half) > 0) mbedtls_mpi_sub_mpi(&s, &grp.N, &s);
    mbedtls_mpi_free(&half);
  }
  {
    unsigned char asn[80];
    unsigned char *p = asn + sizeof(asn);
    size_t len = 0;
    int ret;
    if ((ret = mbedtls_asn1_write_mpi(&p, asn, &s)) < 0) goto done;
    len += (size_t)ret;
    if ((ret = mbedtls_asn1_write_mpi(&p, asn, &r)) < 0) goto done;
    len += (size_t)ret;
    size_t body = len;
    if ((ret = mbedtls_asn1_write_len(&p, asn, body)) < 0) goto done;
    len += (size_t)ret;
    if ((ret = mbedtls_asn1_write_tag(&p, asn, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) < 0) goto done;
    len += (size_t)ret;
    if (len > derCap) goto done;
    memcpy(derOut, p, len);
    *derLen = len;
    ok = true;
  }
done:
  mbedtls_mpi_free(&d);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_ecp_group_free(&grp);
  return ok;
}

// Compact 65-byte message sig: Trezor ecdsa_sign_digest (RFC6979, low-S). libsecp256k1 context_create
// for sign_recoverable allocates ~100KB+ heap and deep stack — caused ESP32 reboot on "Sign".

bool seedmask_bitcoin_message_sign_compact(const uint8_t priv32[32], const uint8_t hash32[32], uint8_t compact65[65],
                                           uint8_t headerBase) {
  uint8_t sig64[64];
  uint8_t pby = 0;
  if (ecdsa_sign_digest(&secp256k1, priv32, hash32, sig64, &pby, nullptr) != 0) return false;
  compact65[0] = (unsigned char)(headerBase + pby);
  memcpy(compact65 + 1, sig64, 64);
  return true;
}
