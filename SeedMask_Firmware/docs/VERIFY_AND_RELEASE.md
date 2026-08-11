# Verification, signing, and release process

## Pre-release checks (automatable)

1. **Crypto debug off:** Production builds must use **`SEEDMASK_CRYPTO_DEBUG=0`** (default in source).
2. Run **`scripts/verify_crypto_serial_guards.sh`** from repo root (or CI) to catch accidental plaintext logging patterns.

```bash
bash SeedMask Firmware/scripts/verify_crypto_serial_guards.sh
```

## Firmware signing (release)

1. **Offline** generate and store signing keys (PKI for Secure Boot / app signing per Espressif workflow).
2. CI should **build** only; **sign** on an offline machine or HSM-connected station if policy requires.
3. Publish **SHA-256** hashes of shipped binaries on a trusted channel so users can verify downloads.

## Tests (crypto boundaries)

- **Unit tests** for PBKDF2/AES-GCM wrappers are best done in a **host** or **ESP-IDF unity** harness with known test vectors (NIST ACVP / mbedtls test vectors). The Arduino monolith is not required to host the full suite; extract crypto into a `.cpp` module when ready.
- **Minimum:** regression tests after any change to `aes_gcm_*`, blob parsers, or KDF iteration counts.

## External penetration test

**Schedule** before a major retail launch or enterprise pilot:

- Build must match **production**: Secure Boot + Flash Encryption + `SEEDMASK_CRYPTO_DEBUG=0`.
- Scope: UART leakage, SD/NVS tampering, lock bypass, memory scraping on locked device (within agreed rules).

## Incident response (users)

Document for users:

- How to **change vault password** and re-encrypt blobs.
- How to **rotate seed** (new wallet / re-backup) if firmware vulnerability is found.

## CI

See [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) for the guard script job.
