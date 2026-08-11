/**
 * SeedMask accessory — ESP32-S3 + 1.47" Waveshare-class LCD (JD9853 via ST7789-like driver in demos).
 *
 * Install library: "GFX Library for Arduino" (moononournation) from Library Manager.
 *
 * Host firmware: SeedMask Firmware.ino (separate upload).
 *
 * **Malina314 SKU ESP32-S3-LCD-1.47** is Waveshare **ESP32-S3-LCD-1.47** (non–Type-B): wiki lists controller
 * **ST7789**, SPI DC41/CS42/SCK40/MOSI45/RST39, **BL GPIO48** — use **`SP147_LCD_LAYOUT 1`** and keep
 * **`SP_USE_JD9853_INIT 0`** (JD9853 blob is for different glass; wrong IC ⇒ flash then black).
 * Type-B / BL46: **`SP147_LCD_LAYOUT 3`**.
 */

#include "seedmask_link_protocol.h"

#include <Arduino.h>
#include <cstring>
#include <Preferences.h>
#include <Wire.h>
#if defined(ARDUINO_ARCH_ESP32)
#include "esp32-hal-ledc.h"
#endif

/** 1 = turn WiFi off at boot (less RF noise on SPI — some 1.47″ boards glitch to black). */
#ifndef SP_LCD_WIFI_OFF_AT_BOOT
#define SP_LCD_WIFI_OFF_AT_BOOT 1
#endif

#if defined(ARDUINO_ARCH_ESP32) && SP_LCD_WIFI_OFF_AT_BOOT
#include <WiFi.h>
#endif

// ---------------------------------------------------------------------------
// Set to 0 only if you do not have GFX installed yet (Serial-only debug).
// ---------------------------------------------------------------------------
#ifndef USE_LCD_GRAPHICS
#define USE_LCD_GRAPHICS 1
#endif

/**
 * 1 = init Waveshare 1.47″ LCD paths (`SP147_LCD_LAYOUT` selects **LCD 1.47** vs **Touch LCD 1.47** vs bare module).
 * 0 = skip LCD/touch init (custom wiring — set SPI + touch I2C yourself).
 */
#ifndef BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_147
#define BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_147 1
#endif

// ---------------------------------------------------------------------------
// UART link (SeedMask TX → ACCESSORY_RX; SeedMask RX ← ACCESSORY_TX).
//
// **Do not use GPIO17/GPIO18 on many ESP32-S3 1.47″ boards** (Spotpear / Malina-class):
// those lines are wired to the **microSD data bus**. Starting UART2 there fights the SD
// routing and commonly produces **one good LCD frame then black / dead SPI**.
// Defaults: RX **44**, TX **43** (free on typical LCD SPI pinouts). Rewire + set the same
// pins on SeedMask Firmware (`SEEDMASK_ACCESSORY_UART_*`).
// ---------------------------------------------------------------------------
#ifndef ACCESSORY_UART_RX
#define ACCESSORY_UART_RX 44
#endif
#ifndef ACCESSORY_UART_TX
#define ACCESSORY_UART_TX 43
#endif
#ifndef ACCESSORY_UART_BAUD
#define ACCESSORY_UART_BAUD 115200
#endif

/**
 * Ignore link UART until this many ms after boot. Floating RX / noise can fake `0xA5 0x5A` and corrupt the
 * parser — symptoms look like UI flashes once then goes black.
 */
#ifndef SP_LINK_UART_ARM_MS
#define SP_LINK_UART_ARM_MS 600
#endif

/**
 * Redraw full UI + reassert backlight this often (**0 = disabled**, recommended once display is stable).
 * Non‑zero causes visible **flicker** on full-screen redraw — only enable if you still see SPI dropout.
 */
#ifndef SP_LCD_PERIODIC_REFRESH_MS
#define SP_LCD_PERIODIC_REFRESH_MS 0
#endif

/** 1 = never read link UART — diagnostic: if UI stays up, noise/commands were involved. */
#ifndef SP_LINK_DISABLE_UART_RX
#define SP_LINK_DISABLE_UART_RX 0
#endif

// ---------------------------------------------------------------------------
// USB HID keyboard — type stored PW / Note / TOTP into host PC (plug dongle USB into PC).
// Press BOOT (default GPIO 0, active LOW on ESP32-S3 devkits) to send **current tab** payload.
// Set SP_ACCESSORY_BOOT_SEND_GPIO to **-1** to disable. Requires ESP32-S3/S2 native USB.
// ---------------------------------------------------------------------------
#ifndef SP_ACCESSORY_USB_HID_SEND
#define SP_ACCESSORY_USB_HID_SEND 1
#endif
/** BOOT button GPIO (-1 = disable HID typing trigger). Many S3 boards use GPIO 0. */
#ifndef SP_ACCESSORY_BOOT_SEND_GPIO
#define SP_ACCESSORY_BOOT_SEND_GPIO 0
#endif

#if SP_ACCESSORY_USB_HID_SEND && (defined(ARDUINO_ESP32S3_DEV) || defined(ARDUINO_ESP32S2_DEV) || defined(CONFIG_IDF_TARGET_ESP32S3) || defined(CONFIG_IDF_TARGET_ESP32S2))
#include <USB.h>
#include <USBHIDKeyboard.h>
static USBHIDKeyboard SpAccessoryKeyboard;
#define SP_ACCESSORY_HID_KEYBOARD 1
#else
#define SP_ACCESSORY_HID_KEYBOARD 0
#endif

// ---------------------------------------------------------------------------
// Touch (AXS5106L on Waveshare — I2C; protocol matches AXS15231-style read used on SeedMask).
// CircuitPython board def: SDA=42, SCL=41. Override for custom wiring.
// ---------------------------------------------------------------------------
#ifndef TOUCH_I2C_SDA
#define TOUCH_I2C_SDA 42
#endif
#ifndef TOUCH_I2C_SCL
#define TOUCH_I2C_SCL 41
#endif
/** 7-bit I2C address (AXS5106L typical). */
#ifndef TOUCH_ADDR
#define TOUCH_ADDR 0x63
#endif

/** Panel size for coordinate mapping (matches GFX rotation 0). */
#define LCD_PANEL_W 172
#define LCD_PANEL_H 320

// Tune if taps misalign (log raw values over Serial when SP_TOUCH_DEBUG is 1).
#ifndef SP_TOUCH_DEBUG
#define SP_TOUCH_DEBUG 0
#endif
#ifndef TOUCH_RAW_X_MIN
#define TOUCH_RAW_X_MIN 0
#endif
#ifndef TOUCH_RAW_X_MAX
#define TOUCH_RAW_X_MAX 171
#endif
#ifndef TOUCH_RAW_Y_MIN
#define TOUCH_RAW_Y_MIN 0
#endif
#ifndef TOUCH_RAW_Y_MAX
#define TOUCH_RAW_Y_MAX 319
#endif

static HardwareSerial LinkSerial(2);

#if USE_LCD_GRAPHICS && BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_147
#include <Arduino_GFX_Library.h>
#include "jd9853_waveshare_147.h"

/**
 * SPI GPIO routing — **wrong pins = solid black panel** (no pixels).
 *
 * - **1 (default)** — **Waveshare `ESP32-S3-LCD-1.47`** & Malina **non-B** listings: SPI DC41 CS42 SCK40 MOSI45
 *   RST39, backlight **GPIO48**. Same as GFX `WAVESHARE_ESP32_S3_LCD_1_47`.
 * - **3** — **ESP32-S3-LCD-1.47B** / “Type B” / some Malina **-B** SKUs: **same SPI**, backlight **GPIO46**
 *   (see Melopero / Spotpear tables). Use **3** only if **1** stays dark but glass looks ok with a torch.
 * - **0** — **Waveshare Touch-LCD-1.47** all-in-one: DC45 CS21 SCK38 MOSI39 RST47, BL48, touch SDA42/SCL41.
 * - **2** — bare 1.47″ module + wires: https://www.waveshare.com/wiki/1.47inch_Touch_LCD
 *
 * If still black: try **`#define SP147_LCD_LAYOUT 3`** (BL46) or **`#define PIN_LCD_BL 46`** / **48** explicitly.
 */
#ifndef SP147_LCD_LAYOUT
#define SP147_LCD_LAYOUT 1
#endif

#if SP147_LCD_LAYOUT == 2
/** https://www.waveshare.com/wiki/1.47inch_Touch_LCD — “Working with ESP32” / 13-pin cable */
#define GFX_DC 41
#define GFX_CS 39
#define GFX_SCK 1
#define GFX_MOSI 2
#define GFX_RST 40
#elif SP147_LCD_LAYOUT == 1 || SP147_LCD_LAYOUT == 3
#define GFX_DC 41
#define GFX_CS 42
#define GFX_SCK 40
#define GFX_MOSI 45
#define GFX_RST 39
#elif SP147_LCD_LAYOUT == 0
#define GFX_DC 45
#define GFX_CS 21
#define GFX_SCK 38
#define GFX_MOSI 39
#define GFX_RST 47
#else
#error "SP147_LCD_LAYOUT must be 0, 1, 2, or 3"
#endif

#if SP147_LCD_LAYOUT == 2
#undef TOUCH_I2C_SDA
#undef TOUCH_I2C_SCL
#define TOUCH_I2C_SDA 15
#define TOUCH_I2C_SCL 7
#endif

#if SP147_LCD_LAYOUT == 1 || SP147_LCD_LAYOUT == 3
#define SP_TOUCH_I2C_AVAILABLE 0
#else
#define SP_TOUCH_I2C_AVAILABLE 1
#endif

#ifndef PIN_LCD_BL
#if SP147_LCD_LAYOUT == 2
#define PIN_LCD_BL 6
#elif SP147_LCD_LAYOUT == 3
#define PIN_LCD_BL 46
#else
#define PIN_LCD_BL 48
#endif
#endif

/**
 * 1 = after gfx->begin(), run JD9853 `lcd_reg_init` (some **Touch-LCD-1.47** / JD9853 modules only).
 * 0 = **stock Arduino_GFX ST7789 tftInit** — **Waveshare ESP32-S3-LCD-1.47** & Malina non-B list **ST7789**
 * ([wiki](https://www.waveshare.com/wiki/ESP32-S3-LCD-1.47)); JD9853 sequence on ST7789 silicon often yields
 * **one good frame then black**.
 *
 * Defaults: layout **1** (LCD-1.47 non-B) and **3** (1.47B / BL46) ⇒ **0**. Layout **0** (Touch all-in-one)
 * ⇒ **1** (often JD9853). Override if your vendor confirms the controller.
 */
#ifndef SP_USE_JD9853_INIT
#if SP147_LCD_LAYOUT == 1 || SP147_LCD_LAYOUT == 3
#define SP_USE_JD9853_INIT 0
#else
#define SP_USE_JD9853_INIT 1
#endif
#endif

/**
 * With `SP_USE_JD9853_INIT`: IPS passed into Arduino_ST7789 **before** lcd_reg_init.
 * **Default 0** matches LovyanGFX #746 / Waveshare snippet (`false`). IPS=1 here breaks JD9853 + RGB565
 * (flash then black / wrong pixels). Set **1** only if you know your revision needs it.
 */
#ifndef SP147_JD9853_IPS
#define SP147_JD9853_IPS 0
#endif

/**
 * After lcd_reg_init the blob sets pixel format **0x05**; Arduino_GFX ST7789 pipeline expects **COLMOD 0x55**
 * (16-bit RGB565 like stock tftInit). Re-send COLMOD after JD9853 batch — fixes sustained black after a flash.
 */
#ifndef SP147_JD9853_FORCE_COLMOD_RGB565
#define SP147_JD9853_FORCE_COLMOD_RGB565 1
#endif

/**
 * 1 = tftInit runs **only** JD9853 (subclass). On many JD9853 panels this yields **black only** — stock ST7789
 * wakeup seems required first. **0** (default): stock tftInit + lcd_reg_init after begin (Waveshare order).
 * If you see random colour flashes with 0, keep 0 — do **not** switch to 1 unless debugging.
 */
#ifndef SP147_JD9853_REPLACE_TFTINIT
#define SP147_JD9853_REPLACE_TFTINIT 0
#endif

/** SPI clock (Hz). With JD9853 overlay (replace=0): **4 MHz** default; try 2M if glitchy. JD9853-only: try 2M. */
#ifndef SP147_SPI_HZ
#if SP_USE_JD9853_INIT && SP147_JD9853_REPLACE_TFTINIT
#define SP147_SPI_HZ 2000000
#elif SP_USE_JD9853_INIT
/** 500 kHz — JD9853 + long traces tolerate slow SPI better than 1–8 MHz “flash then black”. */
#define SP147_SPI_HZ 500000
#else
#define SP147_SPI_HZ 8000000
#endif
#endif

/**
 * **0 (default):** steady GPIO HIGH on `PIN_LCD_BL` — most reliable on ESP32-S3 (LEDC/PWM can glitch after
 * UART/peripheral init and the screen *looks* black). Set **1** only if you need PWM dimming.
 */
#ifndef SP_LCD_BL_USE_PWM
#define SP_LCD_BL_USE_PWM 0
#endif

/** 1 = turn backlight fully on before gfx->begin() (some boards need BL early). */
#ifndef SP_LCD_BL_BEFORE_PANEL_INIT
#define SP_LCD_BL_BEFORE_PANEL_INIT 1
#endif

/** ST7789 column offsets for 172×320 (JD9853). Try **0** if image is shifted or blank. */
#ifndef SP147_ST7789_COL_OFS
#define SP147_ST7789_COL_OFS 34
#endif

/**
 * Arduino_GFX display rotation **0–3**. **2** = 180° — natural upright when USB is at the **bottom** on
 * Waveshare ESP32-S3-LCD-1.47 / Malina non-B. Use **0** if your image is upside down after this default.
 */
#ifndef SP147_LCD_ROTATION
#define SP147_LCD_ROTATION 2
#endif

/**
 * If 1: full-screen **RED → GREEN → BLUE → WHITE**, ~0.6s each — look **straight at the LCD glass**.
 * Plastic bezel / edge glow is **not** a picture; only solid colour **across the whole glass** counts.
 * Set to 0 after display works (saves boot time).
 */
#ifndef SP_LCD_RGBW_TEST
#define SP_LCD_RGBW_TEST 0
#endif

#ifndef SP_LCD_RGBW_HOLD_MS
#define SP_LCD_RGBW_HOLD_MS 600
#endif

/** If 1 (and SP_LCD_RGBW_TEST is 0): brief red+white only — weaker diagnostic. */
#ifndef SP_LCD_BOOT_FLASH
#define SP_LCD_BOOT_FLASH 0
#endif

/** Some revisions use active-low backlight (try 1 if panel stays dark even when SPI works). */
#ifndef SP_LCD_BL_ACTIVE_LOW
#define SP_LCD_BL_ACTIVE_LOW 0
#endif

/** Set to 1 to force gfx->invertDisplay(true) after init (fixes washed/inverted image on some units). */
#ifndef SP_LCD_TRY_INVERT
#define SP_LCD_TRY_INVERT 0
#endif

/**
 * 0 = always call gfx->displayOn() after init (SLPOUT wake — keeps panel from looking dead after JD9853).
 * 1 = skip (legacy experiments only).
 */
#ifndef SP_LCD_SKIP_DISPLAYON_AFTER_JD9853
#define SP_LCD_SKIP_DISPLAYON_AFTER_JD9853 0
#endif

/** ms to wait after JD9853 + setRotation before drawing (panel settle). */
#ifndef SP_LCD_JD9853_SETTLE_MS
#define SP_LCD_JD9853_SETTLE_MS 80
#endif

/**
 * After RGBW test, draw boot label as **black text on white band** on black background.
 * If inversion/MADCTL is wrong, white-on-black text can look invisible; this stays readable.
 */
#ifndef SP_LCD_BOOT_UI_HIGH_CONTRAST
#define SP_LCD_BOOT_UI_HIGH_CONTRAST 1
#endif

/**
 * 1 = call gfx->flush() after each full UI paint. Some SPI stacks mis-handle flush after JD9853;
 * default **0** (drawing paths already push pixels).
 */
#ifndef SP_LCD_GFX_FLUSH
#define SP_LCD_GFX_FLUSH 0
#endif

/** Backlight GPIO: defaults with `SP147_LCD_LAYOUT` — BL48 (all-in-one), BL6 (wiki 1.47inch module); override with `#define PIN_LCD_BL` before layout block if needed. */

/** Call after UART/other peripheral init — PWM BL can drop; digital HIGH keeps the lamp on. */
static void backlight_reassert_digital(void) {
  pinMode(PIN_LCD_BL, OUTPUT);
#if SP_LCD_BL_ACTIVE_LOW
  digitalWrite(PIN_LCD_BL, LOW);
#else
  digitalWrite(PIN_LCD_BL, HIGH);
#endif
}

/**
 * IPS flag for Arduino_ST7789 when **not** using `SP_USE_JD9853_INIT`. With JD9853 init, use `SP147_JD9853_IPS`.
 */
#ifndef ST7789_IPS_PANEL
#define ST7789_IPS_PANEL 1
#endif

static Arduino_DataBus* sp_bus = nullptr;
Arduino_GFX* gfx = nullptr;
#endif

#if USE_LCD_GRAPHICS && !BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_147
Arduino_GFX* gfx = nullptr;
#endif

static uint8_t sp_rx_buf[SP_LINK_MAX_PAYLOAD + sizeof(SeedMaskLinkHeader)];
static size_t sp_rx_fill;

// ---- Stored payloads (UART + NVS) -------------------------------------------
static Preferences sp_prefs;
static const char PREF_NS[] = "sp_acc";

static char sp_store_pw[SP_LINK_MAX_PAYLOAD + 1];
static char sp_store_note[SP_LINK_MAX_PAYLOAD + 1];
static char sp_store_totp[SP_LINK_MAX_PAYLOAD + 1];
static size_t sp_len_pw = 0, sp_len_note = 0, sp_len_totp = 0;

enum SpUiTab : uint8_t { TAB_PW = 0, TAB_NOTE = 1, TAB_TOTP = 2 };
static SpUiTab sp_active_tab = TAB_PW;

static void sp_prefs_load(void) {
  sp_prefs.begin(PREF_NS, true);
  size_t n;

  n = sp_prefs.getBytesLength("pw");
  if (n > 0 && n <= SP_LINK_MAX_PAYLOAD) {
    sp_prefs.getBytes("pw", sp_store_pw, n);
    sp_len_pw = n;
    sp_store_pw[n] = 0;
  }

  n = sp_prefs.getBytesLength("note");
  if (n > 0 && n <= SP_LINK_MAX_PAYLOAD) {
    sp_prefs.getBytes("note", sp_store_note, n);
    sp_len_note = n;
    sp_store_note[n] = 0;
  }

  n = sp_prefs.getBytesLength("totp");
  if (n > 0 && n <= SP_LINK_MAX_PAYLOAD) {
    sp_prefs.getBytes("totp", sp_store_totp, n);
    sp_len_totp = n;
    sp_store_totp[n] = 0;
  }
  sp_prefs.end();
}

static void sp_prefs_save_slot(const char* key, const uint8_t* data, size_t len) {
  if (len > SP_LINK_MAX_PAYLOAD) len = SP_LINK_MAX_PAYLOAD;
  sp_prefs.begin(PREF_NS, false);
  sp_prefs.putBytes(key, data, len);
  sp_prefs.end();
}

static void sp_store_update(SeedMaskLinkMsgType t, const uint8_t* payload, size_t len) {
  if (len > SP_LINK_MAX_PAYLOAD) len = SP_LINK_MAX_PAYLOAD;

  switch (t) {
    case SP_LINK_PASSWORD:
      memcpy(sp_store_pw, payload, len);
      sp_store_pw[len] = 0;
      sp_len_pw = len;
      sp_prefs_save_slot("pw", payload, len);
      sp_active_tab = TAB_PW;
      break;
    case SP_LINK_NOTE:
      memcpy(sp_store_note, payload, len);
      sp_store_note[len] = 0;
      sp_len_note = len;
      sp_prefs_save_slot("note", payload, len);
      sp_active_tab = TAB_NOTE;
      break;
    case SP_LINK_TOTP:
      memcpy(sp_store_totp, payload, len);
      sp_store_totp[len] = 0;
      sp_len_totp = len;
      sp_prefs_save_slot("totp", payload, len);
      sp_active_tab = TAB_TOTP;
      break;
    default:
      break;
  }
}

#if USE_LCD_GRAPHICS && BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_147
/** Digital-only backlight during reset (some PMICs expect BL before/around panel wake). */
static void backlight_digital_prepare(void) {
  pinMode(PIN_LCD_BL, OUTPUT);
#if SP_LCD_BL_ACTIVE_LOW
  digitalWrite(PIN_LCD_BL, LOW);
#else
  digitalWrite(PIN_LCD_BL, HIGH);
#endif
}

/** Full brightness — prefer PWM on ESP32 (matches SeedMask behaviour on similar boards). */
static void backlight_full_on(void) {
#if defined(ARDUINO_ARCH_ESP32) && SP_LCD_BL_USE_PWM
  bool pwm = ledcAttach(PIN_LCD_BL, 5000, 8);
  if (pwm) {
    ledcWrite(PIN_LCD_BL, 255);
    Serial.println("[LCD] Backlight: PWM on GPIO (duty=max)");
    return;
  }
  Serial.println("[LCD] Backlight: PWM attach failed, falling back to GPIO");
#endif
  pinMode(PIN_LCD_BL, OUTPUT);
#if SP_LCD_BL_ACTIVE_LOW
  digitalWrite(PIN_LCD_BL, LOW);
#else
  digitalWrite(PIN_LCD_BL, HIGH);
#endif
  Serial.println("[LCD] Backlight: GPIO digital");
}

static void setup_display_waveshare() {
  backlight_digital_prepare();
  delay(20);
#if SP_LCD_BL_BEFORE_PANEL_INIT
  backlight_full_on();
  delay(50);
#endif

  sp_bus = new Arduino_ESP32SPI(GFX_DC, GFX_CS, GFX_SCK, GFX_MOSI /* MISO NC */);
#if SP_USE_JD9853_INIT && SP147_JD9853_REPLACE_TFTINIT
  gfx = new Arduino_ST7789_JD9853_Only(sp_bus, GFX_RST, SP147_LCD_ROTATION, (SP147_JD9853_IPS != 0),
                                       172 /* w */, 320 /* h */,
                                       SP147_ST7789_COL_OFS /* col offset 1 */, 0,
                                       SP147_ST7789_COL_OFS /* col offset 2 */, 0);
#elif SP_USE_JD9853_INIT
  gfx = new Arduino_ST7789(sp_bus, GFX_RST, SP147_LCD_ROTATION, (SP147_JD9853_IPS != 0),
                           172 /* w */, 320 /* h */,
                           SP147_ST7789_COL_OFS /* col offset 1 */, 0,
                           SP147_ST7789_COL_OFS /* col offset 2 */, 0);
#else
  gfx = new Arduino_ST7789(sp_bus, GFX_RST, SP147_LCD_ROTATION, ST7789_IPS_PANEL /* IPS */,
                           172 /* w */, 320 /* h */,
                           SP147_ST7789_COL_OFS /* col offset 1 */, 0,
                           SP147_ST7789_COL_OFS /* col offset 2 */, 0);
#endif

  bool ok = gfx->begin(SP147_SPI_HZ);
  Serial.printf(
      "[LCD] begin(%lu Hz) %s  layout=%d  rot=%d  DC=%d CS=%d SCK=%d MOSI=%d RST=%d  jd9853=%d  "
      "jd9853_replace_tft=%d  IPS_used=%d  BL GPIO=%d  col_ofs=%d\n",
      (unsigned long)SP147_SPI_HZ, ok ? "OK" : "FAIL", SP147_LCD_LAYOUT, SP147_LCD_ROTATION, GFX_DC, GFX_CS,
      GFX_SCK, GFX_MOSI, GFX_RST, SP_USE_JD9853_INIT ? 1 : 0,
      (SP_USE_JD9853_INIT && SP147_JD9853_REPLACE_TFTINIT) ? 1 : 0,
      (SP_USE_JD9853_INIT ? (SP147_JD9853_IPS != 0) : (ST7789_IPS_PANEL != 0)) ? 1 : 0, PIN_LCD_BL,
      SP147_ST7789_COL_OFS);
  if (!ok) {
    Serial.println("[LCD] begin failed — check SPI pins / supply.");
    return;
  }

#if SP_USE_JD9853_INIT && !SP147_JD9853_REPLACE_TFTINIT
  jd9853_waveshare_147_lcd_reg_init(sp_bus);
#if SP147_JD9853_FORCE_COLMOD_RGB565
  /** Same 16-bit RGB565 as Arduino ST7789 tftInit (`WRITE_C8_D8, COLMOD, 0x55`). */
  sp_bus->beginWrite();
  sp_bus->writeC8D8(0x3A, 0x55);
  sp_bus->endWrite();
#endif
  gfx->invertDisplay(false);
  delay(SP_LCD_JD9853_SETTLE_MS);
  Serial.println("[LCD] JD9853 lcd_reg_init after begin (legacy: stock tftInit + overlay)");
#elif SP_USE_JD9853_INIT && SP147_JD9853_REPLACE_TFTINIT
  delay(SP_LCD_JD9853_SETTLE_MS);
  Serial.println("[LCD] JD9853-only tftInit (no mixed ST7789 blob — fixes random colour flashes)");
#endif

#if !SP_LCD_BL_BEFORE_PANEL_INIT
  backlight_full_on();
  delay(60);
#else
  delay(30);
#endif

#if !(SP_USE_JD9853_INIT && SP_LCD_SKIP_DISPLAYON_AFTER_JD9853)
  gfx->displayOn();
  delay(20);
#endif

#if !SP_USE_JD9853_INIT
  /** Waveshare ST7789 path: deterministic inversion (JD9853 blob sets INVON elsewhere). */
  gfx->invertDisplay(false);
#endif

  delay(80);
#if SP_LCD_TRY_INVERT
  gfx->invertDisplay(true);
#endif

  gfx->setRotation(SP147_LCD_ROTATION);

#if SP_LCD_RGBW_TEST
  Serial.println("");
  Serial.println("[LCD] RGBW test — backlight edges can glow; that is NOT the image.");
  Serial.println("[LCD] Hold the board so you look perpendicular at the **LCD glass**.");
  {
    const uint16_t colours[] = { RGB565_RED, RGB565_GREEN, RGB565_BLUE, RGB565_WHITE };
    const char* names[] = { "RED", "GREEN", "BLUE", "WHITE" };
    for (unsigned i = 0; i < 4; i++) {
      Serial.printf("[LCD] Full screen %s — do you see this colour on the glass?\n", names[i]);
      gfx->fillScreen(colours[i]);
      gfx->flush();
      delay(SP_LCD_RGBW_HOLD_MS);
    }
  }
  Serial.println("[LCD] If the glass stayed black for all four, SPI/init does not match this panel.");
#elif SP_LCD_BOOT_FLASH
  gfx->fillScreen(RGB565_RED);
  gfx->flush();
  delay(180);
  gfx->fillScreen(RGB565_WHITE);
  gfx->flush();
  delay(250);
#endif

  /** Single UI paint happens in setup() via draw_main_ui() — no duplicate boot splash here. */
  backlight_reassert_digital();
}
#endif

#if USE_LCD_GRAPHICS && BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_147
static void touch_setup(void) {
#if SP_TOUCH_I2C_AVAILABLE
  Wire.begin(TOUCH_I2C_SDA, TOUCH_I2C_SCL);
  Wire.setClock(400000);
#else
  (void)0;
#endif
}

/** Same read sequence as SeedMask AXS stack (register-compatible AXS5106 / AXS15231 family). */
static bool read_touch_raw(uint16_t& x, uint16_t& y) {
#if !SP_TOUCH_I2C_AVAILABLE
  (void)x;
  (void)y;
  return false;
#else
  uint8_t cmd[8] = {0xB5, 0xAB, 0xA5, 0x5A, 0, 0, 0, 0x08};
  uint8_t data[8];

  Wire.beginTransmission(TOUCH_ADDR);
  Wire.write(cmd, 8);
  if (Wire.endTransmission(false) != 0) return false;

  if (Wire.requestFrom((uint8_t)TOUCH_ADDR, (uint8_t)8) != 8) return false;
  for (int i = 0; i < 8; i++) data[i] = Wire.read();

  if ((data[1] & 0x01) == 0) return false;

  x = (uint16_t)(((uint16_t)(data[2] & 0x0F) << 8) | data[3]);
  y = (uint16_t)(((uint16_t)(data[4] & 0x0F) << 8) | data[5]);

  if (x > 1200 || y > 1200) return false;
  return true;
#endif
}

static void map_touch(uint16_t rx, uint16_t ry, uint16_t& sx, uint16_t& sy) {
  uint16_t rcx = rx;
  uint16_t rcy = ry;
  if (rcx < TOUCH_RAW_X_MIN) rcx = TOUCH_RAW_X_MIN;
  if (rcx > TOUCH_RAW_X_MAX) rcx = TOUCH_RAW_X_MAX;
  if (rcy < TOUCH_RAW_Y_MIN) rcy = TOUCH_RAW_Y_MIN;
  if (rcy > TOUCH_RAW_Y_MAX) rcy = TOUCH_RAW_Y_MAX;
  sx = (uint16_t)map(rcx, TOUCH_RAW_X_MIN, TOUCH_RAW_X_MAX, 0, LCD_PANEL_W - 1);
  sy = (uint16_t)map(rcy, TOUCH_RAW_Y_MIN, TOUCH_RAW_Y_MAX, 0, LCD_PANEL_H - 1);
}

static bool read_touch_screen(uint16_t& sx, uint16_t& sy) {
  uint16_t rx, ry;
  if (!read_touch_raw(rx, ry)) return false;
#if SP_TOUCH_DEBUG
  static uint32_t last_dbg;
  if (millis() - last_dbg > 500) {
    last_dbg = millis();
    Serial.printf("[touch raw] x=%u y=%u\n", (unsigned)rx, (unsigned)ry);
  }
#endif
  map_touch(rx, ry, sx, sy);
  return true;
}

static const int TAB_BAR_Y = 278;
static const int TAB_BAR_H = 42;
static const int TAB_COUNT = 4;
static const int TAB_W = LCD_PANEL_W / TAB_COUNT;

static bool hit_tab_bar(uint16_t x, uint16_t y, uint8_t& out_index) {
  if (y < (uint16_t)TAB_BAR_Y || y >= (uint16_t)(TAB_BAR_Y + TAB_BAR_H)) return false;
  out_index = (uint8_t)(x / TAB_W);
  if (out_index >= TAB_COUNT) out_index = TAB_COUNT - 1;
  return true;
}

static void draw_tab_bar(void) {
  if (!gfx) return;
  const uint16_t labels_fg = RGB565_WHITE;
  const uint16_t bg_dim = RGB565_DARKGREY;
  const uint16_t bg_hi = 0x39C7;
  const char* lbl[TAB_COUNT] = {"PW", "Note", "2FA", "Clr"};

  for (int i = 0; i < TAB_COUNT; i++) {
    int x0 = i * TAB_W;
    bool hi = ((int)sp_active_tab == i && i < 3);
    gfx->fillRect(x0, TAB_BAR_Y, TAB_W, TAB_BAR_H, i == 3 ? RGB565_RED : (hi ? bg_hi : bg_dim));
    gfx->drawRect(x0, TAB_BAR_Y, TAB_W, TAB_BAR_H, RGB565_WHITE);
    gfx->setTextSize(2);
    gfx->setTextColor(labels_fg);
    int tw = (int)strlen(lbl[i]) * 12;
    gfx->setCursor((int16_t)(x0 + (TAB_W - tw) / 2), (int16_t)(TAB_BAR_Y + 12));
    gfx->print(lbl[i]);
  }
}

/** Draw wrapped text (size 1) in box; updates gfx cursor — leave room for tab bar. */
static void draw_text_block(const char* s, int16_t x0, int16_t y0, int16_t max_w_px, int16_t y_max) {
  if (!gfx || !s) return;
  const int char_w = 6;
  const int line_h = 10;
  int max_chars = max_w_px / char_w;
  if (max_chars < 8) max_chars = 8;

  int16_t cx = x0, cy = y0;
  gfx->setTextSize(1);
  const char* p = s;
  int col = 0;

  while (*p && cy < y_max) {
    char c = *p++;
    if (c == '\r') continue;
    if (c == '\n') {
      cy += line_h;
      cx = x0;
      col = 0;
      continue;
    }
    if (col >= max_chars) {
      cy += line_h;
      cx = x0;
      col = 0;
      if (cy >= y_max) break;
    }
    gfx->setCursor(cx, cy);
    gfx->write(c);
    cx += char_w;
    col++;
  }
}

static void draw_main_ui(void) {
  if (!gfx) return;

  /** Avoid gfx->displayOn() every paint — on stock ST7789 it can glitch the pipeline; wake from loop timer if needed. */

  gfx->fillScreen(RGB565_BLACK);
  constexpr int hdr_h = 50;
  gfx->fillRect(0, 0, LCD_PANEL_W, hdr_h, RGB565_WHITE);

  const char* body = "";
  const char* title = "";
  switch (sp_active_tab) {
    case TAB_PW:
      title = "Password";
      body = sp_len_pw ? sp_store_pw : "(empty)";
      break;
    case TAB_NOTE:
      title = "Note";
      body = sp_len_note ? sp_store_note : "(empty)";
      break;
    case TAB_TOTP:
      title = "2FA / TOTP";
      body = sp_len_totp ? sp_store_totp : "(empty)";
      break;
  }

  gfx->setTextColor(RGB565_BLACK);
  gfx->setTextSize(1);
  gfx->setCursor(4, 4);
  gfx->print("SeedMask accessory");

  gfx->setTextSize(2);
  gfx->setCursor(4, 18);
  gfx->print(title);

  gfx->setTextColor(RGB565_WHITE);
  draw_text_block(body, 4, hdr_h + 6, LCD_PANEL_W - 8, TAB_BAR_Y - 6);

  draw_tab_bar();
#if SP_LCD_GFX_FLUSH
  gfx->flush();
#endif
}

static void clear_active_slot(void) {
  switch (sp_active_tab) {
    case TAB_PW:
      sp_len_pw = 0;
      sp_store_pw[0] = 0;
      sp_prefs.begin(PREF_NS, false);
      sp_prefs.remove("pw");
      sp_prefs.end();
      break;
    case TAB_NOTE:
      sp_len_note = 0;
      sp_store_note[0] = 0;
      sp_prefs.begin(PREF_NS, false);
      sp_prefs.remove("note");
      sp_prefs.end();
      break;
    case TAB_TOTP:
      sp_len_totp = 0;
      sp_store_totp[0] = 0;
      sp_prefs.begin(PREF_NS, false);
      sp_prefs.remove("totp");
      sp_prefs.end();
      break;
  }
}

static bool sp_was_touching = false;

static void poll_touch_ui(void) {
  uint16_t sx, sy;
  bool now = read_touch_screen(sx, sy);
  if (now && !sp_was_touching) {
    uint8_t ti = 0;
    if (hit_tab_bar(sx, sy, ti)) {
      if (ti < 3) {
        sp_active_tab = (SpUiTab)ti;
        draw_main_ui();
      } else {
        clear_active_slot();
        draw_main_ui();
      }
    }
  }
  sp_was_touching = now;
}
#endif  // USE_LCD_GRAPHICS && BOARD_WAVESHARE

#if SP_ACCESSORY_HID_KEYBOARD
/** Short tap BOOT (active LOW): USB-HID type printable ASCII for **active tab** (PW / Note / 2FA). */
static void poll_boot_hid_type_active_slot(void) {
#if SP_ACCESSORY_BOOT_SEND_GPIO < 0
  return;
#else
  static bool boot_armed = true;
  const bool down = (digitalRead(SP_ACCESSORY_BOOT_SEND_GPIO) == LOW);
  if (down) {
    if (!boot_armed) return;
    boot_armed = false;

    const char* payload = nullptr;
    switch (sp_active_tab) {
      case TAB_PW:
        if (sp_len_pw > 0) payload = sp_store_pw;
        break;
      case TAB_NOTE:
        if (sp_len_note > 0) payload = sp_store_note;
        break;
      case TAB_TOTP:
        if (sp_len_totp > 0) payload = sp_store_totp;
        break;
      default:
        break;
    }

    if (!payload || !payload[0]) {
      Serial.println("[HID] Active slot empty — nothing to type");
      return;
    }

    Serial.println("[HID] Typing to USB host (focus a text field on PC/phone)...");
    for (const char* p = payload; *p; ++p) {
      const unsigned char uc = (unsigned char)*p;
      if (uc >= 32 && uc <= 126) {
        SpAccessoryKeyboard.write((uint8_t)uc);
        delay(25);
      } else if (uc == '\n' || uc == '\r') {
        SpAccessoryKeyboard.write(KEY_RETURN);
        delay(25);
      }
    }
    Serial.println("[HID] Done.");
  } else {
    boot_armed = true;
  }
#endif
}
#endif

static void sp_show_payload_text(SeedMaskLinkMsgType t, const char* payload, size_t len) {
  sp_store_update(t, reinterpret_cast<const uint8_t*>(payload), len);

#if USE_LCD_GRAPHICS
  if (gfx) {
#if BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_147
    draw_main_ui();
#else
    gfx->fillScreen(RGB565_BLACK);
    gfx->setTextColor(RGB565_WHITE);
    gfx->setTextSize(2);
    gfx->setCursor(4, 8);
    switch (t) {
      case SP_LINK_PASSWORD:
        gfx->println("Password");
        break;
      case SP_LINK_NOTE:
        gfx->println("Note");
        break;
      case SP_LINK_TOTP:
        gfx->println("2FA / TOTP");
        break;
      default:
        gfx->println("Data");
        break;
    }
    gfx->setTextSize(1);
    gfx->setCursor(4, 40);
    {
      size_t n = len;
      if (n > 512) n = 512;
      char tmp[516];
      memcpy(tmp, payload, n);
      tmp[n] = 0;
      gfx->println(tmp);
    }
    gfx->flush();
#endif
    return;
  }
#endif
  Serial.printf("[Accessory] stored type=%u len=%u\n", (unsigned)t, (unsigned)len);
  Serial.write(reinterpret_cast<const uint8_t*>(payload), len);
  Serial.println();
}

static bool sp_consume_one_frame(void) {
  if (sp_rx_fill < sizeof(SeedMaskLinkHeader)) return false;
  auto* h = reinterpret_cast<SeedMaskLinkHeader*>(sp_rx_buf);
  if (h->magic0 != SEEDMASK_LINK_MAGIC0 || h->magic1 != SEEDMASK_LINK_MAGIC1) {
    memmove(sp_rx_buf, sp_rx_buf + 1, sp_rx_fill - 1);
    sp_rx_fill--;
    return true;
  }
  uint16_t plen = (uint16_t)(h->len_le & 0xFFFFu);
  size_t need = sizeof(SeedMaskLinkHeader) + (size_t)plen;
  if (plen > SP_LINK_MAX_PAYLOAD || need > sizeof(sp_rx_buf)) {
    sp_rx_fill = 0;
    return false;
  }
  if (sp_rx_fill < need) return false;

  uint8_t crc_src[4 + SP_LINK_MAX_PAYLOAD];
  crc_src[0] = h->type;
  crc_src[1] = h->reserved;
  crc_src[2] = (uint8_t)(h->len_le & 0xFFu);
  crc_src[3] = (uint8_t)((h->len_le >> 8) & 0xFFu);
  memcpy(crc_src + 4, sp_rx_buf + sizeof(SeedMaskLinkHeader), plen);
  uint16_t crc_calc = sp_link_crc16_ccitt(crc_src, 4u + plen);
  uint16_t crc_rx = (uint16_t)((uint16_t)h->crc16_le & 0xFFFFu);

  const uint8_t* payload = sp_rx_buf + sizeof(SeedMaskLinkHeader);
  if (crc_calc != crc_rx) {
    Serial.println("[Accessory] CRC mismatch — drop sync");
    sp_rx_fill = 0;
    return false;
  }

  if (h->type != SP_LINK_HEARTBEAT)
    sp_show_payload_text((SeedMaskLinkMsgType)h->type, reinterpret_cast<const char*>(payload), plen);

  size_t rest = sp_rx_fill - need;
  memmove(sp_rx_buf, sp_rx_buf + need, rest);
  sp_rx_fill = rest;
  return true;
}

void setup() {
  Serial.begin(115200);
#if SP_ACCESSORY_HID_KEYBOARD
  // Same ordering as SeedMask Firmware: Keyboard.begin() before USB.begin() for a valid composite descriptor.
  SpAccessoryKeyboard.begin();
  USB.begin();
#if SP_ACCESSORY_BOOT_SEND_GPIO >= 0
  pinMode(SP_ACCESSORY_BOOT_SEND_GPIO, INPUT_PULLUP);
#endif
#endif
  delay(300);
#if defined(ARDUINO_ARCH_ESP32) && SP_LCD_WIFI_OFF_AT_BOOT
  WiFi.mode(WIFI_OFF);
#endif
  Serial.println();
  Serial.println("SeedMask accessory S3 / 1.47 — link receiver");
  Serial.println("[LCD] Layout **1** = Malina/Waveshare **ESP32-S3-LCD-1.47**, ST7789, BL GPIO48 (see wiki). "
                 "Layout **3** = 1.47**B**, BL46. Layout **0** = Touch-LCD-1.47. Default jd9853 overlay is **off** "
                 "on layout 1/3 (ST7789); set SP_USE_JD9853_INIT 1 only if your panel needs it.");
#if USE_LCD_GRAPHICS && SP_LCD_PERIODIC_REFRESH_MS > 0
  Serial.printf("[LCD] periodic UI + BL reassert every %d ms (set SP_LCD_PERIODIC_REFRESH_MS 0 to disable)\n",
                SP_LCD_PERIODIC_REFRESH_MS);
#endif
#if SP_LINK_DISABLE_UART_RX
  Serial.println("[Link] SP_LINK_DISABLE_UART_RX=1 — UART RX disabled (diagnostic).");
#endif
#if SP_ACCESSORY_HID_KEYBOARD
  Serial.println("[HID] USB keyboard ready — focus a text field on the PC, tap BOOT to type the active tab");
#if SP_ACCESSORY_BOOT_SEND_GPIO >= 0
  Serial.printf("[HID] BOOT GPIO=%d (active LOW)\n", SP_ACCESSORY_BOOT_SEND_GPIO);
#else
  Serial.println("[HID] BOOT typing disabled (SP_ACCESSORY_BOOT_SEND_GPIO=-1)");
#endif
#endif

  sp_prefs_load();

#if USE_LCD_GRAPHICS && BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_147
  setup_display_waveshare();
  touch_setup();
#if SP_TOUCH_I2C_AVAILABLE
  Serial.printf("Touch I2C SDA=%d SCL=%d addr=0x%02X\n", TOUCH_I2C_SDA, TOUCH_I2C_SCL, TOUCH_ADDR);
#else
  Serial.println("Touch I2C disabled (SP147_LCD_LAYOUT=1 uses GPIO41/42 for SPI — use layout 0 for Touch board).");
#endif
#elif USE_LCD_GRAPHICS && !BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_147
  Serial.println("USE_LCD_GRAPHICS=1 but BOARD_WAVESHARE...=0 — add SPI init + optional Wire/touch");
#else
  Serial.println("USE_LCD_GRAPHICS=0 — install GFX Library for Arduino, set USE_LCD_GRAPHICS 1");
#endif

  LinkSerial.begin(ACCESSORY_UART_BAUD, SERIAL_8N1, ACCESSORY_UART_RX, ACCESSORY_UART_TX);
  delay(30);
  while (LinkSerial.available()) {
    (void)LinkSerial.read();
  }
  sp_rx_fill = 0;

#if USE_LCD_GRAPHICS && BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_147
  /** PWM backlight + UART init can leave BL dim/off; force lamp on before first interaction. */
  backlight_reassert_digital();
  if (gfx) {
    gfx->displayOn();
    draw_main_ui();
  }
#endif
}

void loop() {
#if USE_LCD_GRAPHICS && BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_147
  static uint32_t sp_uart_live_at_ms = 0;
  if (sp_uart_live_at_ms == 0) {
    sp_uart_live_at_ms = millis() + SP_LINK_UART_ARM_MS;
  }
  const bool sp_link_ready = ((int32_t)(millis() - sp_uart_live_at_ms) >= 0);
#else
  const bool sp_link_ready = true;
#endif

#if !SP_LINK_DISABLE_UART_RX
  if (sp_link_ready) {
    while (LinkSerial.available() && sp_rx_fill < sizeof(sp_rx_buf)) {
      sp_rx_buf[sp_rx_fill++] = (uint8_t)LinkSerial.read();
      while (sp_consume_one_frame()) {}
    }
  }
#endif

#if USE_LCD_GRAPHICS && BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_147
  poll_touch_ui();
#if SP_LCD_PERIODIC_REFRESH_MS > 0
  static uint32_t sp_lcd_next_refresh_ms = 0;
  if (gfx && SP_LCD_PERIODIC_REFRESH_MS > 0) {
    uint32_t t = millis();
    if (sp_lcd_next_refresh_ms == 0) {
      sp_lcd_next_refresh_ms = t + (uint32_t)SP_LCD_PERIODIC_REFRESH_MS;
    }
    if ((int32_t)(t - sp_lcd_next_refresh_ms) >= 0) {
      sp_lcd_next_refresh_ms = t + (uint32_t)SP_LCD_PERIODIC_REFRESH_MS;
      backlight_reassert_digital();
      gfx->displayOn();
      draw_main_ui();
    }
  }
#endif
#endif

#if SP_ACCESSORY_HID_KEYBOARD
  poll_boot_hid_type_active_slot();
#endif
}
