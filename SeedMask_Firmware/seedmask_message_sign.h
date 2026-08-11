// SPDX-License-Identifier: MIT
// Bitcoin Core / Passport–style signed message (BIP-137 hash + compact 65-byte sig).

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Preimage serialized like Sparrow/Drongo; digest = SHA256(SHA256(preimage)) (32 bytes). */
bool seedmask_bitcoin_signed_message_hash(const char *message, size_t messageLen, uint8_t hash32[32]);

/** RFC6979 deterministic ECDSA on secp256k1, SHA-256, low-S; DER written to derOut. */
bool seedmask_ecdsa_sign_hash_det(const uint8_t priv32[32], const uint8_t hash32[32],
                                  uint8_t *derOut, size_t *derLen, size_t derCap);

/** Compact message signature (65 B): Trezor ecdsa_sign_digest, then r||s.
 *  headerBase matches Electrum/bitcoinjs-message: 31=P2PKH compressed & P2WPKH (device legacy), 35=P2SH-P2WPKH. */
bool seedmask_bitcoin_message_sign_compact(const uint8_t priv32[32], const uint8_t hash32[32],
                                           uint8_t compact65[65], uint8_t headerBase);

#ifdef __cplusplus
}
#endif
