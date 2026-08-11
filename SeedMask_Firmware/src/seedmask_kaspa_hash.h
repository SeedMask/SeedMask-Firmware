#ifndef SEEDMASK_KASPA_HASH_H
#define SEEDMASK_KASPA_HASH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Kaspa domain-separated Blake2b-256 (key = "TransactionSigningHash", 64-byte BLAKE2 key slot). */
typedef struct {
  void* state; /* blake2b_state* — opaque to keep header minimal */
} KaspaTxSigningHasher;

void kaspa_tx_signing_hasher_init(KaspaTxSigningHasher* h);
void kaspa_tx_signing_hasher_update(KaspaTxSigningHasher* h, const void* data, size_t len);
void kaspa_tx_signing_hasher_finalize(KaspaTxSigningHasher* h, uint8_t out32[32]);
void kaspa_tx_signing_hasher_free(KaspaTxSigningHasher* h);

void kaspa_hash_write_u8(KaspaTxSigningHasher* h, uint8_t v);
void kaspa_hash_write_u16(KaspaTxSigningHasher* h, uint16_t v);
void kaspa_hash_write_u32(KaspaTxSigningHasher* h, uint32_t v);
void kaspa_hash_write_u64(KaspaTxSigningHasher* h, uint64_t v);
void kaspa_hash_write_bytes(KaspaTxSigningHasher* h, const uint8_t* data, size_t len);
void kaspa_hash_write_var_bytes(KaspaTxSigningHasher* h, const uint8_t* data, size_t len);

/** Unkeyed Blake2b-256, used by Kaspa P2SH script hashes. */
void kaspa_blake2b_256(const uint8_t* data, size_t len, uint8_t out32[32]);

#ifdef __cplusplus
}
#endif

#endif
