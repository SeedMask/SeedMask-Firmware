#include "seedmask_kaspa_hash.h"

#include <stdlib.h>
#include <string.h>

#include "../src/trezor_firmware/crypto/blake2b.h"

/* Match rusty-kaspa blake2b_simd Params::key(b"TransactionSigningHash") — 21 bytes, not zero-padded. */
static const char KASPA_TX_SIGNING_HASH_KEY[] = "TransactionSigningHash";

void kaspa_tx_signing_hasher_init(KaspaTxSigningHasher* h) {
  if (!h) return;
  blake2b_state* st = (blake2b_state*)calloc(1, sizeof(blake2b_state));
  h->state = st;
  if (!st) return;
  blake2b_InitKey(st, 32, KASPA_TX_SIGNING_HASH_KEY, sizeof(KASPA_TX_SIGNING_HASH_KEY) - 1u);
}

void kaspa_tx_signing_hasher_update(KaspaTxSigningHasher* h, const void* data, size_t len) {
  if (!h || !h->state || !data || len == 0) return;
  blake2b_Update((blake2b_state*)h->state, data, len);
}

void kaspa_tx_signing_hasher_finalize(KaspaTxSigningHasher* h, uint8_t out32[32]) {
  if (!h || !h->state || !out32) return;
  blake2b_Final((blake2b_state*)h->state, out32, 32);
}

void kaspa_tx_signing_hasher_free(KaspaTxSigningHasher* h) {
  if (!h) return;
  if (h->state) {
    free(h->state);
    h->state = NULL;
  }
}

void kaspa_hash_write_u8(KaspaTxSigningHasher* h, uint8_t v) {
  kaspa_tx_signing_hasher_update(h, &v, 1);
}

void kaspa_hash_write_u16(KaspaTxSigningHasher* h, uint16_t v) {
  uint8_t b[2] = { (uint8_t)(v & 0xff), (uint8_t)((v >> 8) & 0xff) };
  kaspa_tx_signing_hasher_update(h, b, 2);
}

void kaspa_hash_write_u32(KaspaTxSigningHasher* h, uint32_t v) {
  uint8_t b[4];
  b[0] = (uint8_t)(v & 0xff);
  b[1] = (uint8_t)((v >> 8) & 0xff);
  b[2] = (uint8_t)((v >> 16) & 0xff);
  b[3] = (uint8_t)((v >> 24) & 0xff);
  kaspa_tx_signing_hasher_update(h, b, 4);
}

void kaspa_hash_write_u64(KaspaTxSigningHasher* h, uint64_t v) {
  uint8_t b[8];
  for (int i = 0; i < 8; i++) b[i] = (uint8_t)((v >> (8 * i)) & 0xff);
  kaspa_tx_signing_hasher_update(h, b, 8);
}

void kaspa_hash_write_bytes(KaspaTxSigningHasher* h, const uint8_t* data, size_t len) {
  kaspa_tx_signing_hasher_update(h, data, len);
}

void kaspa_hash_write_var_bytes(KaspaTxSigningHasher* h, const uint8_t* data, size_t len) {
  kaspa_hash_write_u64(h, (uint64_t)len);
  if (data && len) kaspa_hash_write_bytes(h, data, len);
}

void kaspa_blake2b_256(const uint8_t* data, size_t len, uint8_t out32[32]) {
  if (!out32) return;
  blake2b_state st;
  memset(&st, 0, sizeof(st));
  blake2b_Init(&st, 32);
  if (data && len) blake2b_Update(&st, data, len);
  blake2b_Final(&st, out32, 32);
  memset(&st, 0, sizeof(st));
}
