# SeedMask threat model (short)

This document defines **what we protect**, **against whom**, and **how** firmware and hardware controls map to mitigations. Refine per product SKU and jurisdiction.

## Preview vs retail

**v0.1.0 on ESP32-S3 preview boards is not the retail device.**

| Control | Preview (now) | Retail (planned) |
|---------|----------------|------------------|
| **Secure Boot** | **Not enabled.** Unsigned / ad-hoc firmware. | Secure Boot + signed releases — [`ESP32_PRODUCTION.md`](ESP32_PRODUCTION.md) |
| **Flash Encryption** | **Not enabled.** External flash can be read. | Flash Encryption + eFuse policy |
| **Wipe** | Erase NVS + SPIFFS (and FAT / coredump if present): erase → random overwrite → erase. Then RAM clear. Firmware partition and microSD are not touched. Digital flash dump of those data partitions has no leftover vault. | Same sequence. Encrypted flash (retail) so leftovers without keys are ciphertext. |
| **Entropy** | Hardware RNG (radio off; ADC analog feed). Unmeasured. Not a certified TRNG. Dice is the honest Create path. | To be tightened (health tests / extra mixing / SE RNG as the hardware allows) |
| **Backup code (SPB1)** | **v2 only.** Packed seed: PBKDF2-HMAC-SHA256 (100k) + XOR keystream + 4-byte HMAC (binds `SPB1` + ver + word count + salt + ciphertext). Create password: 12+ chars, 1 uppercase, 1 digit, 1 symbol; obvious/common strings rejected. Lock PIN (20k) and vault AES-GCM (10k) unchanged. Not AES-GCM. Not a substitute for the words. **v1 CRC+10k codes do not restore.** After create, on-device QR is this SPB1 line (not the password-vault SPE1 QR). | AES-GCM wrap if length budget allows; still not a substitute for BIP39 words |
| **Radio** | Board **has** Wi-Fi and Bluetooth. Firmware leaves them off. That is policy, not a warranty the radios cannot be enabled. | Production profile / eFuses / hardware without leftover debug radios as the SKU allows |

Treat preview firmware as test / burner-seed only.

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
| **Remote** | Network if radios were on | Preview board includes Wi-Fi/BT silicon. Firmware is meant to keep RF off; we do not warrant that. Device is designed for air-gapped use (QR / MicroSD), not as a networked vault. |
| **Malicious host** | USB HID "type password" | Sniff keystrokes, malware—**out of scope** for device firmware except clear UX warnings. |
| **Physical, casual** | Steals device powered off | Flash / SD readout. Password vault: AES-GCM at rest. SPB1 backup code: weaker wrap. **No Flash Encryption**, so a dump of a **live** vault may still be useful. **Wipe** blanks NVS/SPIFFS (and FAT / coredump if present) with erase → random → erase; it does not touch microSD. Retail: Flash Encryption. |
| **Physical, capable** | UART/JTAG, decapsulation | **Partial** mitigation only. Preview has no Secure Boot. Retail: Secure Boot, Flash Encryption, enclosure. |

## Out of scope (explicit)

- Nation-state invasive lab attacks on the silicon.
- User choosing a weak **vault / lock** password (backup-code **create** has a class floor; vault unlock and PIN do not).
- Host OS compromise during USB typing.

## Mitigations mapping

| Risk | Preview (now) | Planned (retail / later firmware) |
|------|----------------|-----------------------------------|
| Secrets on UART | `SEEDMASK_CRYPTO_DEBUG=0` (default); no plaintext dumps in `aes_gcm_decrypt` in release. | Same, plus production debug eFuses. |
| RAM after lock | `session_lock_to_home()` clears seed, master password, key caches, PasswordService, notes, TOTP. | Same. |
| Device wipe | `nvs_wipe()`: NVS + SPIFFS (and FAT / coredump if present) erase → random → erase. Firmware and microSD untouched. Then session RAM clear. Used by Wipe Device and lockout wipe. | Same. Encrypted flash so unread leftovers stay ciphertext. |
| Password / notes vault | AES-GCM + PBKDF2 on NVS/SD `vault_pw` blobs. KDF still needs a higher iteration count. | Higher KDF cost. |
| Portable backup code (SPB1 v2) | PBKDF2 100k + XOR + 4-byte HMAC. Create password floor (12+, upper, digit, symbol, not obvious). v1 CRC+10k will not restore. QR after seed-backup create is SPB1, not vault SPE1. NVS after create/restore is still AES-GCM (10k). Not a substitute for BIP39 words. | AES-GCM wrap if length budget allows. |
| Radio / RF | Firmware leaves Wi-Fi/BT off. Chip still has the radios. | Production eFuse / SKU policy. |
| Malicious firmware | **No Secure Boot on preview.** | **Secure Boot** + signed releases — [`ESP32_PRODUCTION.md`](ESP32_PRODUCTION.md) |
| Raw flash readout | **No Flash Encryption** on a live vault. After **wipe**, NVS/SPIFFS (and FAT / coredump if present) are overwritten then erased. | **Flash Encryption** + production eFuse policy. |
| Wallet vs PM confusion | Same-seed domain split still evolving — [`WALLET_SEPARATION.md`](WALLET_SEPARATION.md) | Separate KDF domains. |

## Review cadence

- Update this file when adding **network**, **OTA**, **wallet signing**, or **new persistence formats**.
- Before major release: external **penetration test** on a **production-like** binary (see [`VERIFY_AND_RELEASE.md`](VERIFY_AND_RELEASE.md)).
