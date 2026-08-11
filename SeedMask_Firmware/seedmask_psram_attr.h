// SPDX-License-Identifier: MIT
// Large scratch buffers tagged for external PSRAM .bss when the Arduino/IDF build allows it
// (Tools: PSRAM enabled; CONFIG_SPIRAM_ALLOW_BSS_SEG_EXTERNAL_MEMORY). If not, EXT_RAM_BSS_ATTR is empty.
#pragma once

#if defined(ARDUINO_ARCH_ESP32)
#include <esp_attr.h>
#else
#ifndef EXT_RAM_BSS_ATTR
#define EXT_RAM_BSS_ATTR
#endif
#endif

#define SEEDMASK_PSRAM_BSS EXT_RAM_BSS_ATTR
