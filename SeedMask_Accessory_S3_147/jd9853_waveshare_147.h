/**
 * JD9853 register init for Waveshare ESP32-S3-Touch-LCD-1.47 (172×320).
 * Generic Arduino_ST7789 tftInit() is not sufficient — panel stays black until this runs.
 * Source: https://github.com/lovyan03/LovyanGFX/issues/746 (Waveshare wiki pattern).
 *
 * Use with Arduino_GFX batchOperation format (Arduino_DataBus.h).
 */
#pragma once

#include <Arduino_DataBus.h>
#include "display/Arduino_ST7789.h"

/** JD9853 register block (see Waveshare wiki / LovyanGFX #746). */
static const uint8_t jd9853_waveshare_147_init_operations[] = {
    BEGIN_WRITE,
    WRITE_COMMAND_8,
    0x11,
    END_WRITE,
    DELAY,
    120,

    BEGIN_WRITE,
    WRITE_C8_D16,
    0xDF,
    0x98,
    0x53,
    WRITE_C8_D8,
    0xB2,
    0x23,

    WRITE_COMMAND_8,
    0xB7,
    WRITE_BYTES,
    4,
    0x00,
    0x47,
    0x00,
    0x6F,

    WRITE_COMMAND_8,
    0xBB,
    WRITE_BYTES,
    6,
    0x1C,
    0x1A,
    0x55,
    0x73,
    0x63,
    0xF0,

    WRITE_C8_D16,
    0xC0,
    0x44,
    0xA4,
    WRITE_C8_D8,
    0xC1,
    0x16,

    WRITE_COMMAND_8,
    0xC3,
    WRITE_BYTES,
    8,
    0x7D,
    0x07,
    0x14,
    0x06,
    0xCF,
    0x71,
    0x72,
    0x77,

    WRITE_COMMAND_8,
    0xC4,
    WRITE_BYTES,
    12,
    0x00,
    0x00,
    0xA0,
    0x79,
    0x0B,
    0x0A,
    0x16,
    0x79,
    0x0B,
    0x0A,
    0x16,
    0x82,

    WRITE_COMMAND_8,
    0xC8,
    WRITE_BYTES,
    32,
    0x3F,
    0x32,
    0x29,
    0x29,
    0x27,
    0x2B,
    0x27,
    0x28,
    0x28,
    0x26,
    0x25,
    0x17,
    0x12,
    0x0D,
    0x04,
    0x00,
    0x3F,
    0x32,
    0x29,
    0x29,
    0x27,
    0x2B,
    0x27,
    0x28,
    0x28,
    0x26,
    0x25,
    0x17,
    0x12,
    0x0D,
    0x04,
    0x00,

    WRITE_COMMAND_8,
    0xD0,
    WRITE_BYTES,
    5,
    0x04,
    0x06,
    0x6B,
    0x0F,
    0x00,

    WRITE_C8_D16,
    0xD7,
    0x00,
    0x30,
    WRITE_C8_D8,
    0xE6,
    0x14,
    WRITE_C8_D8,
    0xDE,
    0x01,

    WRITE_COMMAND_8,
    0xB7,
    WRITE_BYTES,
    5,
    0x03,
    0x13,
    0xEF,
    0x35,
    0x35,

    WRITE_COMMAND_8,
    0xC1,
    WRITE_BYTES,
    3,
    0x14,
    0x15,
    0xC0,

    WRITE_C8_D16,
    0xC2,
    0x06,
    0x3A,
    WRITE_C8_D16,
    0xC4,
    0x72,
    0x12,
    WRITE_C8_D8,
    0xBE,
    0x00,
    WRITE_C8_D8,
    0xDE,
    0x02,

    WRITE_COMMAND_8,
    0xE5,
    WRITE_BYTES,
    3,
    0x00,
    0x02,
    0x00,

    WRITE_COMMAND_8,
    0xE5,
    WRITE_BYTES,
    3,
    0x01,
    0x02,
    0x00,

    WRITE_C8_D8,
    0xDE,
    0x00,
    WRITE_C8_D8,
    0x35,
    0x00,
    WRITE_C8_D8,
    0x3A,
    0x05,

    WRITE_COMMAND_8,
    0x2A,
    WRITE_BYTES,
    4,
    0x00,
    0x22,
    0x00,
    0xCD,

    WRITE_COMMAND_8,
    0x2B,
    WRITE_BYTES,
    4,
    0x00,
    0x00,
    0x01,
    0x3F,

    WRITE_C8_D8,
    0xDE,
    0x02,

    WRITE_COMMAND_8,
    0xE5,
    WRITE_BYTES,
    3,
    0x00,
    0x02,
    0x00,

    WRITE_C8_D8,
    0xDE,
    0x00,
    WRITE_C8_D8,
    0x36,
    0x00,
    WRITE_COMMAND_8,
    0x21,
    END_WRITE,

    DELAY,
    10,

    BEGIN_WRITE,
    WRITE_COMMAND_8,
    0x29,
    END_WRITE,
};

/**
 * Waveshare wiki order: create Arduino_ST7789(..., ips=false), gfx->begin(), **then** call this on the same SPI bus.
 * Running only this blob (without stock ST7789 tftInit first) often leaves a JD9853 panel black.
 */
static inline void jd9853_waveshare_147_lcd_reg_init(Arduino_DataBus* bus) {
  bus->batchOperation(jd9853_waveshare_147_init_operations, sizeof(jd9853_waveshare_147_init_operations));
}

/**
 * Experimental: tftInit = HW reset + SWRESET + JD9853 batch only (no stock ST7789 register blob).
 * Often gives **black panel** — stock tftInit appears required before JD9853 on this hardware.
 */
class Arduino_ST7789_JD9853_Only : public Arduino_ST7789 {
public:
  using Arduino_ST7789::Arduino_ST7789;

protected:
  void tftInit() override {
    if (_rst != GFX_NOT_DEFINED) {
      pinMode(_rst, OUTPUT);
      digitalWrite(_rst, HIGH);
      delay(100);
      digitalWrite(_rst, LOW);
      delay(ST7789_RST_DELAY);
      digitalWrite(_rst, HIGH);
      delay(ST7789_RST_DELAY);
    }
    _bus->sendCommand(ST7789_SWRESET);
    delay(ST7789_RST_DELAY);
    jd9853_waveshare_147_lcd_reg_init(_bus);
    invertDisplay(false);
  }
};
