// C wrapper for Blockchain Commons bc-ur (same stack as Foundation Passport / Sparrow).
// See src/bc-ur/ — BSD-2-Clause Plus Patent License.

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void seedmask_bc_ur_reset(void);

/// Build UR encoder for signed PSBT. `ur_type` is the registry name only: "psbt" or "crypto-psbt"
/// (Blockchain Commons uses both; Sparrow accepts either — match what you scanned when possible).
/// max_fragment_len is passed to FountainEncoder (bc-ur); typical 100–250 for QR-friendly parts.
bool seedmask_bc_ur_begin_psbt_ex(const uint8_t* psbt, size_t len, size_t max_fragment_len, const char* ur_type);

/// Default output type "crypto-psbt" (Passport / Sparrow); prefer begin_psbt_ex to match scanned wallet.
bool seedmask_bc_ur_begin_psbt(const uint8_t* psbt, size_t len, size_t max_fragment_len);

/// Next UR string: single-part `ur:crypto-psbt/...` or multipart `ur:crypto-psbt/seq-seqlen/...` (fountain).
bool seedmask_bc_ur_next_part(char* out, size_t outCap);

bool seedmask_bc_ur_is_single_part(void);
uint32_t seedmask_bc_ur_seq_num(void);
size_t seedmask_bc_ur_seq_len(void);

#ifdef __cplusplus
}
#endif
