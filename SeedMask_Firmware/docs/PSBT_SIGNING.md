# PSBT signing (SeedMask)

## Implemented

- **UR decode (single-frame + multipart fountain)**  
  - **Single:** `ur:crypto-psbt/…` or `ur:bytes/…` (two path components) → CBOR byte string → raw PSBT.  
  - **Multipart (Blockchain Commons / Sparrow):** `ur:crypto-psbt/seq-seqlen/…` — each frame is fed into the **Luby transform** fountain decoder (`src/bc-ur/fountain-decoder.cpp`, same algorithm as `bc-ur`). Scan **rotating** QR frames until the message completes; progress is shown on the scan screen.  
  - Stay on the **PSBT scan** screen until all parts are received; leaving the screen resets the fountain state.

- **Validation (after UR decode)**  
  - CBOR byte string must fully consume the payload (no trailing bytes).  
  - PSBT must have magic `psbt\xff`, parsable **global** map, and key **0x00** (unsigned tx).  
  - Multipart UR middle segment must be `seqNum-seqLen` (decimal digits only).

- **Signing** (`src/seedmask_psbt_sign.cpp`)  
  - BIP-174 parse / merge **partial signatures**  
  - Segwit-v0 inputs:  
    - **P2WPKH** (`witness UTXO` script `0x00 0x14 <20>`)  
    - **P2WSH** (`witness UTXO` script `0x00 0x20 <32>`, requires `PSBT_IN_WITNESS_SCRIPT`)  
    - **P2SH-P2WSH** (`witness UTXO` P2SH + `PSBT_IN_REDEEM_SCRIPT` as `0x00 0x20 <32>` + matching `PSBT_IN_WITNESS_SCRIPT`)  
    - **P2SH-P2WPKH** (`witness UTXO` P2SH + `PSBT_IN_REDEEM_SCRIPT` as `0x00 0x14 <20>`)  
  - **BIP143** sighash with **`SIGHASH_ALL` exactly** — `PSBT_IN_SIGHASH_TYPE` must be **`0x00000001`** (rejects `ANYONECANPAY` / `NONE` / `SINGLE` flags; those need different BIP143 preimages).  
  - **BIP32** paths from PSBT `PSBT_IN_BIP32_DERIVATION` (key `0x06` + pubkey), matched to **master fingerprint** + derived key that pays the witness program  
  - **One PBKDF2** (BIP39) per sign operation; per-input derivation CKD-only from the loaded master node  
  - **Mnemonic length check:** `word_count` must be a valid BIP39 length and match the number of whitespace-separated words  
  - **ECDSA** DER + low-S (mbedtls)  
  - **Signed PSBT** re-encoded as **BC-UR** for QR (same encoder as before)

- **Review screen (after UR scan)**  
  - **Amount (to pay):** sum of outputs that are **not** classified as change (see below).  
  - **Destination:** first payment output’s address (Bech32 / legacy / P2SH); if multiple, shows `address (+N)`.  
  - **Change:** sum of outputs with **PSBT_OUT_BIP32_DERIVATION** (`0x02` + pubkey) whose fingerprint matches the wallet master — or **“No change”** if none.  
  - **Network fee:** `sum(input witness UTXO values) − sum(outputs)`.  
  - **Big fee warning (Passport-style):** if `fee / payment_amount > 5%` (payment = non-change total), shows **“Big fee: network fee is X.X% of payment (>5%)”**.

## Not implemented (yet)

- Taproot / Schnorr, legacy non-segwit multisig signing, legacy P2PKH sighash  
- `SIGHASH` modes other than **ALL** for v0 witness  

## References

- BIP-174, BIP-143  
