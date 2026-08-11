# Arduino IDE Tools profile (ESP32-S3 3.5B-C)

Must match `build/fqbn.txt` / Docker release builds.

| Tools menu | Value |
|------------|--------|
| Board | ESP32S3 Dev Module |
| JTAG Adapter | Disabled |
| PSRAM | OPI PSRAM |
| Flash Mode | QIO 80MHz |
| Flash Size | 16MB (128Mb) |
| Arduino Runs On | Core 1 |
| Events Run On | Core 1 |
| USB Mode | USB-OTG (TinyUSB) |
| USB CDC On Boot | Enabled |
| USB Firmware MSC On Boot | Disabled |
| USB DFU On Boot | Disabled |
| Upload Mode | USB-OTG CDC (TinyUSB) |
| Partition Scheme | Huge APP (3MB No OTA/1MB SPIFFS) |
| CPU Frequency | 240MHz (WiFi) |
| Upload Speed | 921600 |
| Core Debug Level | None |
| Zigbee Mode | Disabled |
| Erase All Flash Before Sketch Upload | Disabled (upload-only; not in FQBN) |

Board package: **esp32** by Espressif — version pinned in `build/versions.env`.
