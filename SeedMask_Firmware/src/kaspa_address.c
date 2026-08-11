#include "kaspa_address.h"

#include <string.h>

static const char KASPA_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint64_t kaspa_polymod_step(uint64_t c, uint8_t v) {
  uint64_t c0 = c >> 35;
  c = ((c & 0x07ffffffffULL) << 5) ^ (uint64_t)v;
  if (c0 & 0x01ULL) c ^= 0x98f2bc8e61ULL;
  if (c0 & 0x02ULL) c ^= 0x79b76d99e2ULL;
  if (c0 & 0x04ULL) c ^= 0xf33e5fb3c4ULL;
  if (c0 & 0x08ULL) c ^= 0xae2eabe2a8ULL;
  if (c0 & 0x10ULL) c ^= 0x1e4f43e470ULL;
  return c;
}

static uint64_t kaspa_checksum(const uint8_t* payload5, size_t payloadLen, const char* hrp) {
  uint64_t c = 1;
  for (const char* p = hrp; *p; p++) {
    c = kaspa_polymod_step(c, (uint8_t)(*p & 0x1fu));
  }
  c = kaspa_polymod_step(c, 0);
  for (size_t i = 0; i < payloadLen; i++) {
    c = kaspa_polymod_step(c, payload5[i]);
  }
  for (int i = 0; i < 8; i++) {
    c = kaspa_polymod_step(c, 0);
  }
  return c ^ 1;
}

static size_t conv8to5(const uint8_t* in, size_t inLen, uint8_t* out, size_t outCap) {
  size_t outLen = (inLen * 8 + 4) / 5;
  if (outLen > outCap) return 0;
  size_t outIdx = 0;
  uint16_t buff = 0;
  uint8_t bits = 0;
  for (size_t i = 0; i < inLen; i++) {
    buff = (uint16_t)((buff << 8) | in[i]);
    bits = (uint8_t)(bits + 8);
    while (bits >= 5) {
      bits = (uint8_t)(bits - 5);
      out[outIdx++] = (uint8_t)(buff >> bits);
      buff = (uint16_t)(buff & ((1u << bits) - 1u));
    }
  }
  if (bits > 0) {
    out[outIdx++] = (uint8_t)(buff << (5 - bits));
  }
  return outIdx;
}

static bool kaspa_encode_bech32(const char* hrp, const uint8_t* payload8, size_t payload8Len, char* out,
                                size_t outLen) {
  if (!hrp || !payload8 || !out || outLen < 16) return false;
  uint8_t data5[80];
  size_t data5Len = conv8to5(payload8, payload8Len, data5, sizeof(data5));
  if (data5Len == 0 || data5Len > sizeof(data5) - 8) return false;

  uint64_t chk = kaspa_checksum(data5, data5Len, hrp);
  /* Match rusty-kaspa: conv8to5(checksum.to_be_bytes()[3..]) — lower 5 bytes of u64 BE. */
  uint8_t chk8[5];
  chk8[0] = (uint8_t)((chk >> 32) & 0xff);
  chk8[1] = (uint8_t)((chk >> 24) & 0xff);
  chk8[2] = (uint8_t)((chk >> 16) & 0xff);
  chk8[3] = (uint8_t)((chk >> 8) & 0xff);
  chk8[4] = (uint8_t)(chk & 0xff);
  size_t chk5Len = conv8to5(chk8, 5, data5 + data5Len, sizeof(data5) - data5Len);
  if (chk5Len != 8) return false;
  data5Len += chk5Len;

  size_t hrpLen = strlen(hrp);
  size_t need = hrpLen + 1 + data5Len + 1;
  if (need >= outLen) return false;
  memcpy(out, hrp, hrpLen);
  out[hrpLen] = ':';
  for (size_t i = 0; i < data5Len; i++) {
    if (data5[i] >= 32) return false;
    out[hrpLen + 1 + i] = KASPA_CHARSET[data5[i]];
  }
  out[hrpLen + 1 + data5Len] = 0;
  return true;
}

bool kaspa_encode_address_mainnet(const uint8_t xonly32[32], char* out, size_t outLen) {
  if (!xonly32 || !out) return false;
  uint8_t payload[33];
  payload[0] = 0; /* PubKey Schnorr */
  memcpy(payload + 1, xonly32, 32);
  return kaspa_encode_bech32("kaspa", payload, sizeof(payload), out, outLen);
}

bool kaspa_encode_p2sh_address_mainnet(const uint8_t script_hash32[32], char* out, size_t outLen) {
  if (!script_hash32 || !out) return false;
  uint8_t payload[33];
  payload[0] = 8; /* ScriptHash */
  memcpy(payload + 1, script_hash32, 32);
  return kaspa_encode_bech32("kaspa", payload, sizeof(payload), out, outLen);
}

bool kaspa_encode_address_from_compressed_pubkey(const uint8_t compressed33[33], char* out, size_t outLen) {
  if (!compressed33 || !out) return false;
  if (compressed33[0] != 0x02 && compressed33[0] != 0x03) return false;
  return kaspa_encode_address_mainnet(compressed33 + 1, out, outLen);
}
