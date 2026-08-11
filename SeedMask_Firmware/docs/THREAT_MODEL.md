# SeedMask threat model (short)

This document defines **what we protect**, **against whom**, and **how** firmware and hardware controls map to mitigations. Refine per product SKU and jurisdiction.

## Assets (what must stay confidential or intact)

| Asset | Description |
|-------|-------------|
| **BIP39 seed** | Full recovery of wallet/password vault if exposed. |
| **Vault password (master)** | Decrypts NVS/SD vault blobs; offline guessing applies. |
| **Password entries** | Title + secret values in PasswordService. |
| **Notes / TOTP secrets** | Stored in same encrypted blob as passwords (stateful flow). |
| **Derived keys** | `s_vault_*_key`, seed-specific KDF outputs in RAM—must be zeroed on lock. |
| **Firmware integrity** | Prevents malicious code from stealing secrets at runtime. |

## Adversaries (examples)

| Actor | Capability | Typical goals |
|-------|------------|----------------|
| **Remote** | No physical device | Not applicable to offline-only device unless you add network/USB attack surface later. |
| **Malicious host** | USB HID "type password" | Sniff keystrokes, malware—**out of scope** for device firmware except clear UX warnings. |
| **Physical, casual** | Steals device powered off | Flash readout, SD card read—mitigated by **encryption at rest** + **Flash Encryption**. |
| **Physical, capable** | UART/JTAG, decapsulation | **Partial** mitigation only; raises cost via Secure Boot, FE, enclosure. |

## Out of scope (explicit)

- Nation-state invasive lab attacks on the silicon.
- User choosing weak vault passwords (mitigate with UX, KDF cost, rate limits—not yet all implemented).
- Host OS compromise during USB typing.

## Mitigations mapping

| Risk | Mitigation (current or planned) |
|------|----------------------------------|
| Secrets on UART | `SEEDMASK_CRYPTO_DEBUG=0` (default); no plaintext dumps in `aes_gcm_decrypt` in release. |
| RAM after lock | `session_lock_to_home()` clears seed, master password, key caches, PasswordService, notes, TOTP. |
| Encrypted storage | AES-GCM + PBKDF2 for vault blobs; SD/NVS formats versioned. |
| Malicious firmware | **Secure Boot** + signed releases (see [`ESP32_PRODUCTION.md`](ESP32_PRODUCTION.md)). |
| Raw flash readout | **Flash Encryption** + production eFuse policy. |
| Wallet vs PM confusion (future) | Separate KDF domains—see [`WALLET_SEPARATION.md`](WALLET_SEPARATION.md). |

## Review cadence

- Update this file when adding **network**, **OTA**, **wallet signing**, or **new persistence formats**.
- Before major release: external **penetration test** on a **production-like** binary (see [`VERIFY_AND_RELEASE.md`](VERIFY_AND_RELEASE.md)).
