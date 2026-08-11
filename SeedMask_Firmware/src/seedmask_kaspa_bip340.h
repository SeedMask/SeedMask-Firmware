#ifndef SEEDMASK_KASPA_BIP340_H
#define SEEDMASK_KASPA_BIP340_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** BIP-340 Schnorr sign (SIGHASH_ALL implicit — 64-byte sig). aux_rand32 may be NULL (uses zeros). */
bool seedmask_kaspa_bip340_sign(const uint8_t priv32[32], const uint8_t msg32[32],
                                const uint8_t aux_rand32[32], uint8_t sig64[64]);

/** X-only pubkey (32 bytes) from private key, BIP-340 even-y normalization. */
bool seedmask_kaspa_bip340_pubkey_xonly(const uint8_t priv32[32], uint8_t xonly32[32]);

/** BIP-340 test vector 0 (aux all-zero). Returns false on failure. */
bool seedmask_kaspa_bip340_selftest(char* err, size_t err_len);

#ifdef __cplusplus
}
#endif

#endif
