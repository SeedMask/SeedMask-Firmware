#ifndef SEEDMASK_KASPA_SIGN_H
#define SEEDMASK_KASPA_SIGN_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KASPA_SIGNED_JSON_MAX 8192

/** rusty-kaspa `native-all-0` sighash self-test. */
bool seedmask_kaspa_sighash_selftest(char* err, size_t err_len);

/** Derive Kaspa receive/change privkey (m/44'/111111'/account'/chain/index) using device seed cache. */
bool seedmask_wallet_derive_kaspa_priv(uint32_t account, uint32_t chain, uint32_t index, uint8_t priv32[32]);

/** Derive Kaspa multisig privkey (m/45'/111111'/account'/chain/index) using device seed cache. */
bool seedmask_wallet_derive_kaspa_multisig_priv(uint32_t account, uint32_t chain, uint32_t index, uint8_t priv32[32]);

/** Build P2PK Schnorr script (0x20 || x || 0xac) for m/44'/111111'/account'/chain/index. */
bool seedmask_wallet_kaspa_build_utxo_script(uint32_t account, uint32_t chain, uint32_t index, uint8_t script34[34]);

/** Mainnet kaspa:... address for the same path (matches Receive screen). */
bool seedmask_wallet_kaspa_address_for_index(uint32_t account, uint32_t chain, uint32_t index, char* out,
                                            size_t out_len);

/**
 * Sign coordinator JSON v2 (mainnet tx version 0 or Toccata v1).
 * Input: {"version":2,"network":"mainnet","account":N,"tx":{...}}
 * Output: {"version":2,"network":"mainnet","signatures":[{"input_index":0,"sig_hex":"..."},...]}
 */
bool seedmask_kaspa_sign_with_mnemonic(const char* json, size_t json_len, const char* mnemonic, int word_count,
                                       const char* bip39_passphrase, uint32_t expected_account, char* out_json,
                                       size_t out_cap, size_t* out_len, char* err, size_t err_len);

/** True when json contains top-level "version": 2 (Coordinator / pretty-print tolerant). */
bool seedmask_kaspa_unsigned_is_v2(const char* json, size_t json_len);

/** Compare imported kpub/xpub Base58 to device account kpub (chain code + pubkey bytes). */
bool seedmask_wallet_kaspa_imported_kpub_matches(uint32_t account, const char* imported58);

/** 0 = no kpub / multisig cosigner kpub not proven, 1 = kpub matches device, 2 = singlesig kpub mismatch. */
int seedmask_kaspa_unsigned_kpub_status(const char* json, size_t json_len, uint32_t account);

/** Review summary for Kaspa unsigned JSON v2 (amounts in sompi; 1 KAS = 1e8 sompi). */
#ifndef SEEDMASK_KASPA_REVIEW_MAX_INPUTS
#define SEEDMASK_KASPA_REVIEW_MAX_INPUTS 16
#endif
typedef struct {
  bool ok;
  uint64_t in_sompi;
  uint64_t send_sompi;
  uint64_t change_sompi;
  uint64_t fee_sompi;
  uint8_t num_inputs;
  uint8_t num_outputs;
  /** Fee as tenths of a percent of send (same idea as PSBT review). */
  uint32_t fee_pct_of_send_tenths;
  bool big_fee_warn;
  char dest_addr[96];
  char change_addr[96];
  char err[48];
  /** Per-input labels for Visualize (Receive/Change #N + exact utxo_amount). */
  uint8_t num_viz_inputs;
  uint8_t viz_input_is_change[SEEDMASK_KASPA_REVIEW_MAX_INPUTS];
  uint32_t viz_input_index[SEEDMASK_KASPA_REVIEW_MAX_INPUTS];
  uint64_t viz_input_sompi[SEEDMASK_KASPA_REVIEW_MAX_INPUTS];
} seedmask_kaspa_review_t;

bool seedmask_kaspa_review_summarize(const char* json, size_t json_len, seedmask_kaspa_review_t* out);

#ifdef __cplusplus
}
#endif

#endif
