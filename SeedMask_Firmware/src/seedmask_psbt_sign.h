// SPDX-License-Identifier: MIT
// On-device PSBT signing (BIP174 + BIP143 segwit-v0 P2WPKH/P2WSH) + BC-UR single-part decode.

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// BC-UR PSBT: single-frame `ur:crypto-psbt/...` and multipart fountain `ur:crypto-psbt/seq-seqlen/...`.
#define SEEDMASK_UR_PSBT_NEED_MORE 0
#define SEEDMASK_UR_PSBT_COMPLETE 1
#define SEEDMASK_UR_PSBT_ERROR 2

// Reset fountain decoder when opening PSBT scan (discard partial multipart progress).
void seedmask_ur_psbt_scan_reset(void);

// Feed one scanned UR string. Returns SEEDMASK_UR_PSBT_*; on COMPLETE, `out` holds raw PSBT bytes.
int seedmask_ur_feed_psbt_qr(const char* ur, uint8_t* out, size_t maxOut, size_t* outLen, float* pctOut,
                             char* err, size_t errLen);

// Live multipart progress (fountain decoder). `multipartActive` 0 until first multipart frame.
void seedmask_ur_psbt_get_scan_progress(float* pctOut, uint32_t* partsReceived, uint32_t* partsTotal,
                                        int* multipartActive);

// BIP174 magic + global map + unsigned tx key (0x00). Used after UR decode; exposed for tests.
bool seedmask_psbt_validate_decoded(const uint8_t* psbt, size_t len, char* err, size_t errLen);

// Built-in parser hardening self-tests (valid + malicious PSBT vectors).
// Useful for CI or on-device diagnostics.
bool seedmask_psbt_parser_selftest(char* err, size_t errLen);
// Built-in signer self-test (includes a deterministic P2WSH vector).
bool seedmask_psbt_signing_selftest(char* err, size_t errLen);

// Convenience: reset + single-frame decode only (same as one feed of a 2-component UR).
bool seedmask_ur_decode_psbt_payload(const char* ur, uint8_t* out, size_t maxOut, size_t* outLen,
                                     char* err, size_t errLen);
// Decode single-part UR bytes/account payload to UTF-8 text.
bool seedmask_ur_decode_text_payload(const char* ur, char* out, size_t outCap, char* err, size_t errLen);

// Multisig policy: BC-UR `bytes` / `crypto-account` / `account` — single-frame + fountain multipart (animated QR).
// Same return codes as PSBT feed (SEEDMASK_UR_PSBT_*); on COMPLETE `out` is null-terminated UTF-8 policy text.
void seedmask_ur_policy_scan_reset(void);
int seedmask_ur_feed_policy_qr(const char* ur, char* out, size_t outCap, float* pctOut, char* err, size_t errLen);
void seedmask_ur_policy_get_scan_progress(float* pctOut, uint32_t* partsReceived, uint32_t* partsTotal,
                                          int* multipartActive);

// Kaspa unsigned PSKT (coordinator JSON in `ur:bytes/` fountain) — separate decoder from multisig policy.
void seedmask_ur_kaspa_pskt_scan_reset(void);
int seedmask_ur_feed_kaspa_pskt_qr(const char* ur, char* out, size_t outCap, float* pctOut, char* err, size_t errLen);
void seedmask_ur_kaspa_pskt_get_scan_progress(float* pctOut, uint32_t* partsReceived, uint32_t* partsTotal,
                                              int* multipartActive);
bool seedmask_kaspa_ur_fountain_selftest(char* err, size_t errLen);

// Sign PSBT: segwit-v0 inputs (P2WPKH, P2WSH, P2SH-P2WSH, P2SH-P2WPKH);
// requires witness UTXO + BIP32 derivation matching master fingerprint.
// `word_count` must be 12/15/18/21/24 and match whitespace-separated words in `mnemonic` (BIP39 length check).
bool seedmask_psbt_sign_with_mnemonic(const uint8_t* psbt_in, size_t psbt_in_len,
                                        const char* mnemonic, int word_count,
                                        const char* bip39_passphrase,
                                        uint8_t* psbt_out, size_t* psbt_out_len, size_t psbt_out_cap,
                                        char* err, size_t errLen);

/// PSBT review: fee, send/change split via PSBT_OUT_BIP32_DERIVATION + master fingerprint.
#ifndef SEEDMASK_PSBT_REVIEW_MAX_INPUTS
#define SEEDMASK_PSBT_REVIEW_MAX_INPUTS 16
#endif
typedef struct seedmask_psbt_review {
  int ok;
  char err[96];
  uint64_t send_sat;
  uint64_t change_sat;
  uint64_t fee_sat;
  uint32_t num_send_outputs;
  uint8_t first_send_spk_len;
  uint8_t first_send_spk[40];
  uint32_t num_change_outputs;
  uint8_t first_change_spk_len;
  uint8_t first_change_spk[40];
  int big_fee_warn;
  uint32_t fee_pct_of_send_tenths; /* fee*1000/(send+change); e.g. 125 = 12.5% (misnamed "send" — denom is all outputs) */
  /** Visualizer: up to N inputs with BIP32 receive/change index (matching master_fp). */
  uint8_t num_inputs;
  uint8_t num_viz_inputs;
  uint8_t viz_input_is_change[SEEDMASK_PSBT_REVIEW_MAX_INPUTS];
  uint32_t viz_input_index[SEEDMASK_PSBT_REVIEW_MAX_INPUTS];
  uint64_t viz_input_sat[SEEDMASK_PSBT_REVIEW_MAX_INPUTS];
} seedmask_psbt_review_t;

bool seedmask_psbt_review_summarize(const uint8_t* psbt, size_t len, const uint8_t master_fp[4],
                                    seedmask_psbt_review_t* out);

// Distinct BIP32 account indices (path component after purpose/coin, e.g. m/84'/0'/acct'/…) from PSBT input
// PSBT_IN_BIP32_DERIVATION entries whose fingerprint matches `master_fp`. Singlesig + multisig (BIP44/48/49/84/86).
bool seedmask_psbt_distinct_signing_account_indices(const uint8_t* psbt, size_t len, const uint8_t master_fp[4],
                                                    uint32_t* accounts_out, uint8_t* out_count, uint8_t max_out);

#ifdef __cplusplus
}
#endif
