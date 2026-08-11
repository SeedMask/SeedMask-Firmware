# Blockchain Commons `bc-ur` (Passport-identical UR output)

Signed PSBT QR output uses the **reference** [Blockchain Commons `bc-ur`](https://github.com/BlockchainCommons/bc-ur) C++ library (BSD-2-Clause Plus Patent License), the same encoder stack used by **Foundation Passport** and **Sparrow** for `ur:crypto-psbt` and **fountain** multipart sequences.

## Layout

- `src/bc_ur_psbt.cpp` / `src/bc_ur_psbt.h` — thin C wrapper for the sketch
- `src/bc-ur/` — vendored upstream sources (encoder + **fountain-decoder** for multipart PSBT receive)

## Build requirements

- **Arduino IDE 2.x** (or **arduino-cli**) with **ESP32** core — the sketch must compile everything under `src/` (including `src/bc-ur/*.cpp`). Arduino IDE 1.8.x may not recurse into `src/`; use IDE 2 or flatten/move sources if needed.
- **C++17** or newer (`std::optional` / `std::variant` in `fountain-decoder.hpp`); exceptions enabled (default on ESP32 Arduino). If the core defaults to C++11, set the board to **C++17** in **Tools** or add `-std=gnu++17` to build flags.

## Tunable

`SP_BC_UR_MAX_FRAGMENT_LEN` (default `200`) controls fountain fragment sizing passed to `UREncoder` / `FountainEncoder`. The sketch **retries with smaller fragments** until each `ur:…/…` string fits the on-device QR encoder (**max version 16**, `SP_BC_UR_QR_MAX_URI_CHARS` default **560** at **ECC-L**, matching Passport-class webcam scanning). Signed output uses registry **`crypto-psbt`** by default; if you scan **`ur:psbt/`** from a wallet, the device **echoes `psbt`** on the animated QR so Sparrow sees the same type. If parts are still too long, UR encoding fails and a base64 fallback is used (Sparrow expects BC-UR — use smaller txs or lower `SP_BC_UR_MAX_FRAGMENT_LEN`).
