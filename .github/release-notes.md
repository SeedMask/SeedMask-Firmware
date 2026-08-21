## SeedMask Firmware v0.1.2 (preview)

**Highly experimental early public build. Not a finished product.**

This release is for development, testing, and source verification only. Expect bugs, incomplete flows, and breaking changes. Do not treat it as production-ready or as a safe store of significant funds.

### What’s new
- Kaspa Review addresses format like Coordinator: `kaspa:` intact, body grouped in 4s.
- Multisig Review badge (m-of-n, cosigner status, policy name when known) on Kaspa and Bitcoin.
- Change address shown when the tx has change; otherwise `(see outputs)`.
- Wrong-wallet / cosigner mismatch fails clearly on Review (no silent fail).
- Tall Review content can scroll under **Continue**; short txs stay fixed.
- Finger-drag scroll is 1:1; asset logos stay visible; path hardened against mid-drag reboot/tear.
- Confirm top bar shows **Confirm signing** (not Fee) on Kaspa and Bitcoin.
- Slide-to-sign commits and reaches the signed QR (no snap-back / stuck start).
- Slide failures reset and show the real yellow error on the confirm overlay.
- Snappier slide → signed QR; fixed brief signed-QR flash then exit after the slide.
- Coordinator Save envelopes unwrap correctly; null `redeemScript` no longer false-triggers multisig.
- Signing wait: clean ASCII text, comet spinner that keeps moving, no flash before the QR.
- Signed QR: short **Saved as:** card after Save; animated UR seq loops 1…N; steadier scan caption.
- SD **OPEN** / **LOAD** aligned on the same row as **BACK**.

### Known limitations (examples)
- Vault / master-password KDF currently uses PBKDF2 at only **10,000** iterations (far below a hardened final target; we plan to raise this)
- PIN / lock KDF is **20,000** iterations
- Backup-code wrap is **100,000** iterations (stronger than v0.1.0, still not a substitute for the words)
- Many rough edges, errors, and unfinished behavior remain
- UX and security posture will change as the firmware matures

### Verify the build
Reproducible Docker builds: see `docs/REPRODUCIBLE_BUILD.md` in this repo. Compare `SHA256SUMS` from this release with a local `./scripts/docker-build.sh` on tag `v0.1.2`.

### Flash
Browser flasher: https://seedmask.io/features/firmware  
Primary app image: `SeedMask_Firmware.bin`  
(Optional full image: `SeedMask_Firmware.merged.bin`)

Source: GPLv3 — https://github.com/SeedMask/SeedMask-Firmware
