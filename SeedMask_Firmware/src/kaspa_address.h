#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Encode Kaspa mainnet Schnorr PubKey address (version 0) from 32-byte x-only secp256k1 key. */
bool kaspa_encode_address_mainnet(const uint8_t xonly32[32], char* out, size_t outLen);

/** Encode Kaspa mainnet P2SH address (version 8) from 32-byte script hash. */
bool kaspa_encode_p2sh_address_mainnet(const uint8_t script_hash32[32], char* out, size_t outLen);

/** Encode from 33-byte compressed secp256k1 pubkey (uses x-only = bytes 1..32). */
bool kaspa_encode_address_from_compressed_pubkey(const uint8_t compressed33[33], char* out, size_t outLen);

#ifdef __cplusplus
}
#endif
