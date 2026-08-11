/**
 * Types needed before Arduino IDE auto-generated sketch prototypes.
 * Include as the last #include in the opening block of SeedMask Firmware.ino.
 */
#pragma once

#include <Arduino.h>
#include <stdint.h>
#include "esp_camera.h"

struct Rect {
  int16_t x, y, w, h;
};

enum class UIScreen : uint8_t;

struct Bip32Node;

enum class AddrType : uint8_t;

enum class NavSwitcherTouchMode : uint8_t;

#define PIN_WRAP_BLOB_MAX (12 + 128 + 16)

enum class DuressCredKind : uint8_t { NONE = 0, PIN = 1, PASSWORD = 2 };
enum class DuressBehavior : uint8_t { EMPTY_VAULT = 0, GAMES = 1, NONE = 2, DECOY_VAULT = 3 };
struct DuressTypeSlot {
  bool active = false;
  uint8_t salt[16] = {0};
  uint8_t wrap[PIN_WRAP_BLOB_MAX] = {0};
  size_t wrapLen = 0;
};
