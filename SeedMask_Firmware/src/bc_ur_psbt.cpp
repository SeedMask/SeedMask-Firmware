// SPDX-License-Identifier: BSD-2-Clause-Patent
// Wrapper © SeedMask — links Blockchain Commons bc-ur for Passport-identical UR output.

#include "bc_ur_psbt.h"

#include "bc-ur/ur.hpp"
#include "bc-ur/ur-encoder.hpp"
#include "bc-ur/utils.hpp"
#include "bc-ur/cbor-lite.hpp"

#include <memory>
#include <string>
#include <cstring>

static std::unique_ptr<ur::UR> g_bcUr;
static std::unique_ptr<ur::UREncoder> g_bcUrEnc;

static ur::ByteVector cbor_wrap_psbt(const uint8_t* psbt, size_t len) {
  ur::ByteVector buf;
  ur::ByteVector bytes(psbt, psbt + len);
  CborLite::encodeBytes(buf, bytes);
  return buf;
}

extern "C" void seedmask_bc_ur_reset(void) {
  g_bcUrEnc.reset();
  g_bcUr.reset();
}

extern "C" bool seedmask_bc_ur_begin_psbt_ex(const uint8_t* psbt, size_t len, size_t max_fragment_len,
                                             const char* ur_type) {
  try {
    seedmask_bc_ur_reset();
    if (!psbt || len == 0 || max_fragment_len < 10) return false;
    const char* t = ur_type && ur_type[0] ? ur_type : "crypto-psbt";
    ur::ByteVector cbor = cbor_wrap_psbt(psbt, len);
    g_bcUr = std::make_unique<ur::UR>(std::string(t), cbor);
    // Passport / bc-ur reference: first_seq_num=0, min_fragment_len=10 (Blockchain Commons UREncoder defaults).
    g_bcUrEnc = std::make_unique<ur::UREncoder>(*g_bcUr, max_fragment_len, 0, 10);
    return true;
  } catch (...) {
    seedmask_bc_ur_reset();
    return false;
  }
}

extern "C" bool seedmask_bc_ur_begin_psbt(const uint8_t* psbt, size_t len, size_t max_fragment_len) {
  return seedmask_bc_ur_begin_psbt_ex(psbt, len, max_fragment_len, "crypto-psbt");
}

extern "C" bool seedmask_bc_ur_next_part(char* out, size_t outCap) {
  if (!g_bcUrEnc || !out || outCap < 2) return false;
  try {
    std::string s = g_bcUrEnc->next_part();
    if (s.size() >= outCap) return false;
    std::memcpy(out, s.c_str(), s.size());
    out[s.size()] = 0;
    return true;
  } catch (...) {
    return false;
  }
}

extern "C" bool seedmask_bc_ur_is_single_part(void) {
  return g_bcUrEnc && g_bcUrEnc->is_single_part();
}

extern "C" uint32_t seedmask_bc_ur_seq_num(void) {
  return g_bcUrEnc ? g_bcUrEnc->seq_num() : 0;
}

extern "C" size_t seedmask_bc_ur_seq_len(void) {
  return g_bcUrEnc ? g_bcUrEnc->seq_len() : 0;
}
