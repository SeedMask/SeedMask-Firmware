# Third-party notices

SeedMask firmware is not written from scratch. It includes open-source code and
ideas from several projects. This file is a **living inventory** — if you add
or remove a dependency, update this list.

Exact license texts usually live next to the vendored sources (or in
`LICENSES/`).

| Component | Upstream | Typical license | Where in this tree |
|-----------|----------|-----------------|--------------------|
| Trezor crypto (subset) | [trezor/trezor-firmware](https://github.com/trezor/trezor-firmware) | MIT | `SeedMask_Firmware/src/trezor_firmware/crypto/` |
| libsecp256k1 / secp256k1-zkp | Bitcoin Core / Blockstream et al. | MIT | `SeedMask_Firmware/third_party/libsecp256k1/`, `…/trezor_firmware/vendor/secp256k1-zkp/` |
| Blockchain Commons `bc-ur` | [BlockchainCommons/bc-ur](https://github.com/BlockchainCommons/bc-ur) | BSD-2-Clause Plus Patent | `SeedMask_Firmware/src/bc-ur/` |
| quirc (QR decode) | [dlbeer/quirc](https://github.com/dlbeer/quirc) | ISC | `libraries/quirc/`, `SeedMask_Firmware/quirc/` |
| GFX Library for Arduino | [moononournation/Arduino_GFX](https://github.com/moononournation/Arduino_GFX) (Adafruit heritage) | BSD-2-Clause | `libraries/GFX_Library_for_Arduino/` |
| mbedTLS (via ESP32 Arduino core) | Arm mbedTLS / Espressif | Apache-2.0 | Not vendored here — comes with the ESP32 board package |
| ESP32 Arduino core / IDF pieces | Espressif | Apache-2.0 (and others) | Board package / toolchain, not this repo |
| Foundation Passport | [Foundation-Devices/passport2](https://github.com/Foundation-Devices/passport2) | **GPL-3.0** (and others) | Patterns / ported logic in the sketch and related modules — treat combined firmware as GPLv3 |

## Notes

- **Trezor:** We use a crypto subset under MIT (see `src/trezor_firmware/crypto/LICENSE`). Keep that notice when redistributing.
- **Foundation Passport:** Passport advocates open source and licenses firmware under GPLv3. If SeedMask includes Passport-derived code or a combined work with GPLv3 components, the **distributed firmware must comply with GPLv3** (source offer, notices, same license for the combined work).
- **Coldcard / Coinkite:** Do **not** ship Coldcard firmware under MIT+Commons Clause in a commercial product without a separate legal review. BIP-85 in SeedMask is implemented from [BIP-0085](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki), not Coldcard source.
- **Standards (BIPs, etc.):** Specs are not “code theft”; implementations must still respect any code you copy.

## Incomplete list

You may have more ported snippets (UI patterns, UR/PSBT flows, etc.) that still need a line in this table. When you find one, add:

1. Upstream name + URL  
2. License  
3. Path in this repo  

A future pass can automate scanning for `SPDX-License-Identifier` and `Copyright` headers.
