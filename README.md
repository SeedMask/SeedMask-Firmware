# SeedMask Firmware

Open-source firmware for SeedMask hardware (ESP32-S3).

## Source code (GPLv3)

This tree is the **corresponding source** for SeedMask device firmware builds.

- **License:** [GNU GPLv3](LICENSE) — see also [LICENSE.note](LICENSE.note) and [LICENSES/GPL-3.0.txt](LICENSES/GPL-3.0.txt)
- **Third-party code:** [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) (Trezor, secp256k1, Blockchain Commons, quirc, GFX, Passport-related GPL, …)

Public source: [github.com/SeedMask/SeedMask-Firmware](https://github.com/SeedMask/SeedMask-Firmware).

## Contents

- `SeedMask_Firmware/` — main device sketch (open `SeedMask_Firmware.ino` in Arduino IDE)
- `libraries/` — libraries used by the sketch (`SeedMask_QR_scan`, `SeedMask_UI_C`, `quirc`, GFX, …)
- `SeedMask_Accessory_S3_147/` — optional accessory firmware
- `plugins/` — optional Arduino IDE helpers (e.g. LittleFS upload)
- `build/` — pinned FQBN + toolchain versions for reproducible release builds
- `docker/` + `scripts/docker-build.sh` — **official** byte-for-byte build path

Status: early public hardware / firmware preview — not a finished retail product release.

## Backup codes (breaking)

Portable seed backups are **SPB1 v2** (password-wrapped). See [`SeedMask_Firmware/docs/THREAT_MODEL.md`](SeedMask_Firmware/docs/THREAT_MODEL.md).

- **Old (v1) backup codes will not restore** after you flash this firmware. Create a new backup code on the device.
- **Create** password must be 12+ characters with uppercase, digit, and symbol; obvious weak passwords are rejected. Lock PIN and vault unlock are not on this floor.
- After creating a **seed** backup, **QR** is that backup code (not the password-vault QR).

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
