#include "seedmask_kaspa_sighash.h"

#include <string.h>

#include "seedmask_kaspa_hash.h"

static void previous_outputs_hash(const KaspaSignTx* tx, uint8_t out32[32]) {
  KaspaTxSigningHasher h;
  kaspa_tx_signing_hasher_init(&h);
  for (uint8_t i = 0; i < tx->num_inputs; i++) {
    kaspa_hash_write_bytes(&h, tx->inputs[i].prev_tx_id, 32);
    kaspa_hash_write_u32(&h, tx->inputs[i].prev_index);
  }
  kaspa_tx_signing_hasher_finalize(&h, out32);
  kaspa_tx_signing_hasher_free(&h);
}

static void sequences_hash(const KaspaSignTx* tx, uint8_t out32[32]) {
  KaspaTxSigningHasher h;
  kaspa_tx_signing_hasher_init(&h);
  for (uint8_t i = 0; i < tx->num_inputs; i++) kaspa_hash_write_u64(&h, tx->inputs[i].sequence);
  kaspa_tx_signing_hasher_finalize(&h, out32);
  kaspa_tx_signing_hasher_free(&h);
}

static void sig_op_counts_hash(const KaspaSignTx* tx, uint8_t out32[32]) {
  KaspaTxSigningHasher h;
  kaspa_tx_signing_hasher_init(&h);
  for (uint8_t i = 0; i < tx->num_inputs; i++) kaspa_hash_write_u8(&h, tx->inputs[i].sig_op_count);
  kaspa_tx_signing_hasher_finalize(&h, out32);
  kaspa_tx_signing_hasher_free(&h);
}

static void outputs_hash_all_v0(const KaspaSignTx* tx, uint8_t out32[32]) {
  KaspaTxSigningHasher h;
  kaspa_tx_signing_hasher_init(&h);
  for (uint8_t i = 0; i < tx->num_outputs; i++) {
    kaspa_hash_write_u64(&h, tx->outputs[i].value);
    kaspa_hash_write_u16(&h, tx->outputs[i].script_version);
    kaspa_hash_write_var_bytes(&h, tx->outputs[i].script, tx->outputs[i].script_len);
  }
  kaspa_tx_signing_hasher_finalize(&h, out32);
  kaspa_tx_signing_hasher_free(&h);
}

static void outputs_hash_all_v1(const KaspaSignTx* tx, uint8_t out32[32]) {
  KaspaTxSigningHasher h;
  kaspa_tx_signing_hasher_init(&h);
  for (uint8_t i = 0; i < tx->num_outputs; i++) {
    const KaspaSignOutputDesc* o = &tx->outputs[i];
    kaspa_hash_write_u64(&h, o->value);
    kaspa_hash_write_u16(&h, o->script_version);
    kaspa_hash_write_var_bytes(&h, o->script, o->script_len);
    if (o->has_covenant) {
      kaspa_hash_write_u32(&h, o->covenant_authorizing_input);
      kaspa_hash_write_bytes(&h, o->covenant_id, 32);
    }
  }
  kaspa_tx_signing_hasher_finalize(&h, out32);
  kaspa_tx_signing_hasher_free(&h);
}

static void payload_hash(const KaspaSignTx* tx, uint8_t out32[32]) {
  bool native = true;
  for (int i = 0; i < 20; i++) {
    if (tx->subnetwork_id[i] != 0) {
      native = false;
      break;
    }
  }
  if (native && tx->payload_len == 0) {
    memset(out32, 0, 32);
    return;
  }
  KaspaTxSigningHasher h;
  kaspa_tx_signing_hasher_init(&h);
  kaspa_hash_write_var_bytes(&h, tx->payload, tx->payload_len);
  kaspa_tx_signing_hasher_finalize(&h, out32);
  kaspa_tx_signing_hasher_free(&h);
}

static bool kaspa_calc_schnorr_sighash_v0(const KaspaSignTx* tx, size_t input_index, uint8_t out32[32]) {
  uint8_t prev_h[32], seq_h[32], sigops_h[32], out_h[32], pay_h[32];
  previous_outputs_hash(tx, prev_h);
  sequences_hash(tx, seq_h);
  sig_op_counts_hash(tx, sigops_h);
  outputs_hash_all_v0(tx, out_h);
  payload_hash(tx, pay_h);

  const KaspaSignInputDesc* inp = &tx->inputs[input_index];

  KaspaTxSigningHasher h;
  kaspa_tx_signing_hasher_init(&h);
  kaspa_hash_write_u16(&h, tx->version);
  kaspa_hash_write_bytes(&h, prev_h, 32);
  kaspa_hash_write_bytes(&h, seq_h, 32);
  kaspa_hash_write_bytes(&h, sigops_h, 32);
  kaspa_hash_write_bytes(&h, inp->prev_tx_id, 32);
  kaspa_hash_write_u32(&h, inp->prev_index);
  kaspa_hash_write_u16(&h, inp->utxo_script_version);
  kaspa_hash_write_var_bytes(&h, inp->utxo_script, inp->utxo_script_len);
  kaspa_hash_write_u64(&h, inp->utxo_amount);
  kaspa_hash_write_u64(&h, inp->sequence);
  kaspa_hash_write_u8(&h, inp->sig_op_count);
  kaspa_hash_write_bytes(&h, out_h, 32);
  kaspa_hash_write_u64(&h, tx->lock_time);
  kaspa_hash_write_bytes(&h, tx->subnetwork_id, 20);
  kaspa_hash_write_u64(&h, tx->gas);
  kaspa_hash_write_bytes(&h, pay_h, 32);
  kaspa_hash_write_u8(&h, tx->sighash_type);
  kaspa_tx_signing_hasher_finalize(&h, out32);
  kaspa_tx_signing_hasher_free(&h);
  return true;
}

static bool kaspa_calc_schnorr_sighash_v1(const KaspaSignTx* tx, size_t input_index, uint8_t out32[32]) {
  uint8_t prev_h[32], seq_h[32], out_h[32], pay_h[32];
  previous_outputs_hash(tx, prev_h);
  sequences_hash(tx, seq_h);
  outputs_hash_all_v1(tx, out_h);
  payload_hash(tx, pay_h);

  const KaspaSignInputDesc* inp = &tx->inputs[input_index];

  KaspaTxSigningHasher h;
  kaspa_tx_signing_hasher_init(&h);
  kaspa_hash_write_u16(&h, tx->version);
  kaspa_hash_write_bytes(&h, prev_h, 32);
  kaspa_hash_write_bytes(&h, seq_h, 32);
  kaspa_hash_write_bytes(&h, inp->prev_tx_id, 32);
  kaspa_hash_write_u32(&h, inp->prev_index);
  kaspa_hash_write_u16(&h, inp->utxo_script_version);
  kaspa_hash_write_var_bytes(&h, inp->utxo_script, inp->utxo_script_len);
  kaspa_hash_write_u64(&h, inp->utxo_amount);
  kaspa_hash_write_u64(&h, inp->sequence);
  kaspa_hash_write_bytes(&h, out_h, 32);
  kaspa_hash_write_u64(&h, tx->lock_time);
  kaspa_hash_write_bytes(&h, tx->subnetwork_id, 20);
  kaspa_hash_write_u64(&h, tx->gas);
  kaspa_hash_write_bytes(&h, pay_h, 32);
  kaspa_hash_write_u8(&h, tx->sighash_type);
  kaspa_tx_signing_hasher_finalize(&h, out32);
  kaspa_tx_signing_hasher_free(&h);
  return true;
}

bool kaspa_calc_schnorr_sighash(const KaspaSignTx* tx, size_t input_index, uint8_t out32[32]) {
  if (!tx || !out32 || input_index >= tx->num_inputs) return false;
  if (tx->version >= 1) return kaspa_calc_schnorr_sighash_v1(tx, input_index, out32);
  return kaspa_calc_schnorr_sighash_v0(tx, input_index, out32);
}
