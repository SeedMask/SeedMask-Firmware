# SeedMask accessory — ESP32-S3 + 1.47″ (172×320)

This folder is **firmware for the small dongle only**. It does **not** replace or merge into `SeedMask Firmware/SeedMask Firmware.ino`.

## Hardware (your module)

- **Panel**: Waveshare-class 1.47″ micro LCD, **172×320**, **JD9853** (4-wire SPI), **AXS5106L** touch (I2C).  
  Product reference: [malina314 listing](https://malina314.com/proizvod/1-47inch-lcd-touch-micro-lcd/).

## How the two projects relate

| Repo / folder | Role |
|---------------|------|
| `SeedMask Firmware/` | SeedMask “host”: passwords, notes, 2FA UI + NVS — **sender** (you add UART TX + optional dock-detect GPIO later). |
| `SeedMask_Accessory_S3_147/` | Dongle: **receiver**, stores + shows what SeedMask sends over UART. |

Integration path:

1. Flash **this** sketch on the S3 stick; verify framed packets via **USB Serial** (or UART echo).
2. Wire **GND + SeedMask TX → dongle RX** (and optionally dongle TX → host RX for acks).  
   **Important:** On **ESP32-S3 1.47″ dev boards** (Malina / Spotpear / many “LCD+SD” layouts), **GPIO17 and GPIO18 are usually SD card data lines**. Using UART on those pins can glitch power/SPI and produce **one good frame then a black LCD**. Defaults in `SeedMask_Accessory_S3_147.ino` use **UART RX = GPIO44**, **TX = GPIO43** — set the matching **`SEEDMASK_ACCESSORY_UART_TX` / `RX`** on `SeedMask Firmware.ino` (TX **43**, RX **44**), or override both sketches consistently if you use different free pins.
3. On SeedMask, enable **`SEEDMASK_ACCESSORY_UART_TX` / `RX`** so `SeedMask Firmware.ino` sends using **`seedmask_link_protocol.h`** (same file as this folder).

### Touch + saved items (Waveshare board)

- **I2C** (AXS5106L): default **SDA = GPIO 42**, **SCL = GPIO 41** (`TOUCH_I2C_SDA` / `TOUCH_I2C_SCL`). **Address** default **`0x63`** (`TOUCH_ADDR`). If touches do not register, set **`#define SP_TOUCH_DEBUG 1`** and watch Serial for raw coordinates, then adjust **`TOUCH_RAW_*`** mapping defines.
- **Storage**: last received **password**, **note**, and **2FA** payloads are saved to **NVS** (`Preferences`, namespace `sp_acc`) and persist across reboots.
- **UI**: bottom row **PW | Note | 2FA** switches the view; **Clr** clears the **currently selected** slot only.

## Build (Arduino IDE)

1. Install library **GFX Library for Arduino** (Library Manager).
2. Board: **ESP32S3 Dev Module** — Flash **16 MB**, PSRAM **OPI** (8 MB), **USB CDC On Boot: Enabled** (see Waveshare wiki for ESP32-S3-Touch-LCD-1.47).
3. Open `SeedMask_Accessory_S3_147.ino`. By default **`USE_LCD_GRAPHICS`** is **1** and **`BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_147`** is **1** (integrated Waveshare board). You should see **backlight + splash text** after flash.

### Screen stays black

1. **Serial Monitor @ 115200** — Look for **`[LCD] begin(...)`** with **`OK`**/`FAIL` and **`layout=`**. **`FAIL`** means SPI init failed.
2. **Wrong SPI GPIO** — Using pins from the wrong PCB revision yields a **black** panel. Two layouts are built in:
   - **`#define SP147_LCD_LAYOUT 0`** (default): **Touch-LCD-1.47** wiki pins — DC45 CS21 SCK38 MOSI39 RST47.
   - **`#define SP147_LCD_LAYOUT 1`**: GFX **`WAVESHARE_ESP32_S3_LCD_1.47`** (LCD-only) — DC41 CS42 SCK40 MOSI45 RST39. Do **not** use **1** on the integrated **Touch** board (GPIO 41/42 are SPI there).
3. **JD9853 vs plain ST7789** — [Waveshare ESP32-S3-LCD-1.47 wiki](https://www.waveshare.com/wiki/ESP32-S3-LCD-1.47) lists the controller as **ST7789** (Malina SKU **ESP32-S3-LCD-1.47** matches this board). For **`SP147_LCD_LAYOUT 1`** (and **3**), default **`SP_USE_JD9853_INIT`** is **0**: stock **`Arduino_ST7789`** init only. The JD9853 register block ([LovyanGFX #746](https://github.com/lovyan03/LovyanGFX/issues/746)) is for **different glass** — using it on ST7789 often looks like **one frame then black**. Set **`SP_USE_JD9853_INIT 1`** only if your vendor confirms JD9853 or you use **`SP147_LCD_LAYOUT 0`** (Touch-LCD-1.47).
4. **Boot colours** — **`SP_LCD_RGBW_TEST 1`** cycles **full-screen red/green/blue/white**. **No colour on the glass** ⇒ SPI routing or init still wrong.
5. **IPS / invert** — With **`SP_USE_JD9853_INIT 1`**, IPS is forced **false** per wiki. If you use **`SP_USE_JD9853_INIT 0`**, try **`ST7789_IPS_PANEL 0`** or **`SP_LCD_TRY_INVERT 1`** if you see image but wrong colours.
6. **Backlight** — Default **`PIN_LCD_BL`** = **48**, active-high. If the glass stays pitch-black, try **`SP_LCD_BL_ACTIVE_LOW 1`**.
7. **SPI speed** — With **`SP_USE_JD9853_INIT 1`**, default is **500 kHz** for stability; raise gradually (**1000000**, **4000000**) only after the image stays stable.
8. **UART vs SD pins** — If the UI appears once then dies, confirm link UART is **not** on GPIO17/18 (see Integration path above).
9. **Backlight PWM** — Sketch default is **`SP_LCD_BL_USE_PWM 0`** (digital HIGH). If you enable PWM and the log shows **PWM attach failed** or the panel stays dark, try **`SP_LCD_BL_ACTIVE_LOW 1`**.
10. **Column offset** — If you see a coloured flash but UI is off-screen or blank, try **`#define SP147_ST7789_COL_OFS 0`**.
11. **Flicker** — **`SP_LCD_PERIODIC_REFRESH_MS`** defaults to **0**. A non‑zero value redraws the whole UI on a timer and **will flicker**; only enable if you need a keepalive for a flaky panel.
12. **Upside down** — Set **`#define SP147_LCD_ROTATION N`** with **N** in **0…3** (Arduino_GFX). Default is **2** (180°) for typical Waveshare/Malina USB-at-bottom orientation; try **0** or **3** if text is still wrong.

**Bare Malina module** (no Waveshare MCU): set **`BOARD_WAVESHARE_ESP32_S3_TOUCH_LCD_147`** to **`0`** and wire SPI + **`PIN_LCD_BL`** from your schematic.

**Sanity check**: flash Waveshare **`01_gfx_helloworld`**; match whichever pinout works there to **`SP147_LCD_LAYOUT`** / custom `#define`s.

### “The plastic case flashes but the glass is black”

The **backlight** leaks around the edges of a clear enclosure — that coloured glow is **not** the LCD image. Only changes **across the whole glass area** (full red/green/blue/white) mean the matrix is updating.

With **`SP_LCD_RGBW_TEST 1`** (default), Serial walks through **RED → GREEN → BLUE → WHITE** (~0.6s each). Watch the **glass** straight on:

- **You see solid colours** → SPI/init OK; tune IPS/invert/text if UI looks wrong.
- **Glass stays black for every colour** → confirm **`SP_USE_JD9853_INIT 1`**, **`SP147_LCD_LAYOUT 0`** on the Touch board, then **`SP147_ST7789_COL_OFS 0`** if still wrong. **`SP147_LCD_LAYOUT 1`** only if your PCB matches the LCD-only SKU. Flash Waveshare’s factory Arduino demo to confirm hardware if needed.

## Display library

Official resources: [Waveshare ESP32-S3-Touch-LCD-1.47 wiki](https://www.waveshare.com/wiki/ESP32-S3-Touch-LCD-1.47) — pin numbers there match **their** dev board; if you use a **bare JD9853 module** + your own S3, copy pinout from your schematic into the `#define LCD_*` section.

## Security note

Default sketch assumes **UART payload handling** for bring-up. For production, add pairing, encryption, or at least an HMAC once the electrical link is fixed.
