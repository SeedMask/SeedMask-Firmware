# Wallet vs password vault — key separation (design)

When you add a **crypto wallet** alongside the password manager, **do not** reuse the same symmetric key material or a single PBKDF2 output for both domains.

## Principles

1. **Separate root secrets (if product allows)**  
   - Option A: Same BIP39 seed, **different derivation** for “wallet” vs “PM vault” using domain separation.  
   - Option B: Separate seeds (stronger isolation, worse UX).  

2. **Domain separation for KDF / HKDF**  
   Use distinct, versioned labels for any HKDF or KDF context, e.g. UTF-8 or ASCII constants:  
   - `SeedMask/vault/nvs/v1` — NVS blob keys  
   - `SeedMask/vault/sd/v1` — SD blob keys  
   - `SeedMask/wallet/signing/v1` — wallet-specific keys (future)  

   Never use the **same** 32-byte key for **AES-GCM vault** and **wallet signing** without an explicit HKDF step.

3. **Separate storage namespaces**  
   - NVS namespace / keys: e.g. `vault_*` vs `wallet_*`.  
   - SD filenames: distinct prefixes so backup/restore cannot cross-contaminate by accident.

4. **Separate RAM buffers**  
   Wallet signing should not reuse `s_vault_blob_key` or PM serialization buffers.

5. **Threat model**  
   If the PM vault password is weaker than wallet expectations, **wallet keys must not** be derivable from PM-only material.

## Implementation sketch (future)

```text
master_secret (from seed / PIN policy)
    ├── HKDF(label = "SeedMask/vault/...")
    │       └── AES keys for NVS/SD
    └── HKDF(label = "SeedMask/wallet/...")
            └── secp256k1 / Ed25519 key material (wallet stack)
```

## References

- [`THREAT_MODEL.md`](THREAT_MODEL.md)  
- NIST SP 800-108 (KDF), HKDF (RFC 5869) for domain-separated subkeys.
