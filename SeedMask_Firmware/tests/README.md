# Crypto / vault tests (future)

The main firmware is an Arduino sketch (`SeedMask Firmware.ino`). Recommended approach for **automated crypto tests**:

1. **Extract** `pbkdf2_sha256`, `aes_gcm_encrypt` / `aes_gcm_decrypt`, and blob pack/parse into one or more `.cpp` / `.h` files under `SeedMask Firmware/` (no UI).
2. Add an **ESP-IDF `unity`** test app or **host build** with mbedtls linked, feeding **NIST / mbedtls test vectors** for GCM and PBKDF2.
3. Keep **`SEEDMASK_CRYPTO_DEBUG=0`** in CI firmware builds.

Until extraction is done, rely on:

- [`scripts/verify_crypto_serial_guards.sh`](../scripts/verify_crypto_serial_guards.sh)
- Manual QA on device
- External pen-test for releases ([`docs/VERIFY_AND_RELEASE.md`](../docs/VERIFY_AND_RELEASE.md))
