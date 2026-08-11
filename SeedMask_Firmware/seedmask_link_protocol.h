/**
 * Shared framing for SeedMask (host) <-> accessory (dongle).
 * Keep this file byte-identical on both sides once the host sender exists.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>

#define SEEDMASK_LINK_MAGIC0 0xA5u
#define SEEDMASK_LINK_MAGIC1 0x5Au

enum SeedMaskLinkMsgType : uint8_t {
  SP_LINK_HEARTBEAT = 0,
  SP_LINK_PASSWORD = 1,
  SP_LINK_NOTE = 2,
  SP_LINK_TOTP = 3,
};

/** Max payload bytes (single frame). Host must chunk larger notes. */
#define SP_LINK_MAX_PAYLOAD 2048

struct SeedMaskLinkHeader {
  uint8_t magic0;
  uint8_t magic1;
  uint8_t type;
  uint8_t reserved;
  uint16_t len_le; /* payload length, little-endian */
  uint16_t crc16_le; /* CRC16-CCITT-FALSE over type, reserved, len, payload */
} __attribute__((packed));

static inline uint16_t sp_link_crc16_ccitt(const uint8_t* data, size_t len) {
  uint16_t crc = 0xFFFFu;
  for (size_t i = 0; i < len; i++) {
    crc ^= (uint16_t)data[i] << 8;
    for (int b = 0; b < 8; b++) {
      if (crc & 0x8000u)
        crc = (uint16_t)((crc << 1) ^ 0x1021u);
      else
        crc <<= 1;
    }
  }
  return crc;
}
