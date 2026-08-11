# SeedMask Firmware

Open-source firmware for SeedMask hardware (ESP32-S3).

## Source code (GPLv3)

This tree is the **corresponding source** for SeedMask device firmware builds.

- **License:** [GNU GPLv3](LICENSES/GPL-3.0.txt) — see [LICENSE](LICENSE)
- **Third-party code:** [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) (Trezor, secp256k1, Blockchain Commons, quirc, GFX, Passport-related GPL, …)

When this repository is published on GitHub, use that URL as the public source link for the product (example):

`https://github.com/SeedMask/SeedMask-Firmware`

Until then, this Desktop folder **is** the source tree to publish.

## Contents

- `SeedMask_Firmware/` — main device sketch (open `SeedMask_Firmware.ino` in Arduino IDE)
- `libraries/` — libraries used by the sketch (`SeedMask_QR_scan`, `SeedMask_UI_C`, `quirc`, GFX, …)
- `SeedMask_Accessory_S3_147/` — optional accessory firmware
- `plugins/` — optional Arduino IDE helpers (e.g. LittleFS upload)
- `build/` — pinned FQBN + toolchain versions for reproducible release builds
- `docker/` + `scripts/docker-build.sh` — **official** byte-for-byte build path

Status: early public hardware / firmware preview — not a finished retail product release.

## Development (Arduino IDE)

1. Install **esp32** by Espressif (Arduino Boards Manager). Use the version in [`build/versions.env`](build/versions.env) when you care about matching release behavior.
2. Install **GFX Library for Arduino** by moononournation, **or** use the copy under `libraries/`.
3. Point Arduino’s sketchbook at this repo root (so `libraries/` resolves), **or** copy `libraries/*` into your Arduino `libraries` folder.
4. Open `SeedMask_Firmware/SeedMask_Firmware.ino` via **File → Open**.
5. Set **Tools** to match [`build/tools-profile.md`](build/tools-profile.md) (Waveshare ESP32-S3 3.5B-C / ESP32S3 Dev Module).

IDE builds are for iterating and flashing. They are **not** the byte-for-byte release path.

## Reproducible release build (Docker)

Anyone on Mac, Windows, or Linux can rebuild the **same** official `.bin` bytes:

```bash
./scripts/docker-build.sh
shasum -a 256 -c dist/SHA256SUMS
```

See [`docs/REPRODUCIBLE_BUILD.md`](docs/REPRODUCIBLE_BUILD.md).
