#ifndef SEEDMASK_KASPA_SIGHASH_H
#define SEEDMASK_KASPA_SIGHASH_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Multi-UTXO singlesig needs many inputs; keep on-chain scripts small (P2PK/P2SH ≈ 34–35 B)
 * so KaspaSignTx stays DRAM-safe (static/PSRAM, never stack). Large multisig redeem scripts
 * use KASPA_SIGN_MAX_REDEEM. Cap is a published device limit (commercial HW style), not protocol. */
#define KASPA_SIGN_MAX_INPUTS 50
#define KASPA_SIGN_MAX_OUTPUTS 6
#define KASPA_SIGN_MAX_SCRIPT 128
#define KASPA_SIGN_MAX_REDEEM 600
#define KASPA_SIGN_MAX_PAYLOAD 256

typedef struct {
  uint8_t prev_tx_id[32];
  uint32_t prev_index;
  uint64_t sequence;
  uint8_t sig_op_count;
  uint16_t compute_budget;
  uint64_t utxo_amount;
  uint16_t utxo_script_version;
  uint16_t utxo_script_len;
  uint8_t utxo_script[KASPA_SIGN_MAX_SCRIPT];
} KaspaSignInputDesc;

typedef struct {
  uint64_t value;
  uint16_t script_version;
  uint16_t script_len;
  uint8_t script[KASPA_SIGN_MAX_SCRIPT];
  bool has_covenant;
  uint32_t covenant_authorizing_input;
  uint8_t covenant_id[32];
} KaspaSignOutputDesc;

typedef struct {
  uint16_t version;
  uint64_t lock_time;
  uint8_t subnetwork_id[20];
  uint64_t gas;
  uint8_t payload_len;
  uint8_t payload[KASPA_SIGN_MAX_PAYLOAD];
  uint8_t num_inputs;
  uint8_t num_outputs;
  KaspaSignInputDesc inputs[KASPA_SIGN_MAX_INPUTS];
  KaspaSignOutputDesc outputs[KASPA_SIGN_MAX_OUTPUTS];
  uint8_t sighash_type; /* 1 = SIGHASH_ALL */
  uint8_t sign_input_indices[KASPA_SIGN_MAX_INPUTS];
  uint8_t num_sign_inputs;
} KaspaSignTx;

/** Compute Schnorr sighash for one input (tx version 0 or Toccata v1). */
bool kaspa_calc_schnorr_sighash(const KaspaSignTx* tx, size_t input_index, uint8_t out32[32]);

#ifdef __cplusplus
}
#endif

#endif
