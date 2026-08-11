# Reproducible firmware builds

Official **preview** SeedMask device binaries are produced only with the pinned
**Docker** build. Same git revision + same image pins → **byte-for-byte identical**
`.bin` files (verified by SHA-256).

Arduino IDE is for day-to-day development and flashing. An IDE “Verify” on your
laptop is **not** expected to match Release hashes.

Secure Boot / flash-encryption signing is out of scope for this preview path.

## Pins

| Item | Source |
|------|--------|
| Board options (FQBN) | [`build/fqbn.txt`](../build/fqbn.txt) — see [`build/tools-profile.md`](../build/tools-profile.md) |
| `arduino-cli` / `esp32` core / `SOURCE_DATE_EPOCH` | [`build/versions.env`](../build/versions.env) |
| GFX + SeedMask libraries | vendored under [`libraries/`](../libraries/) |

## Build (any OS with Docker)

```bash
git clone https://github.com/SeedMask/SeedMask-Firmware.git
cd SeedMask-Firmware
git checkout <tag>   # use the Release tag you are verifying

./scripts/docker-build.sh
```

Artifacts land in `dist/`:

- `SeedMask_Firmware.bin` — application image (flash this for preview)
- `SeedMask_Firmware.bootloader.bin`
- `SeedMask_Firmware.partitions.bin`
- `SeedMask_Firmware.merged.bin` — full 16MB image (optional)
- `SHA256SUMS`

First run downloads the pinned ESP32 toolchain into the image (can take several minutes). Later runs reuse the local image tag `seedmask-firmware-build:<core>-cli<cli>`.

## Verify against a GitHub Release

```bash
# After ./scripts/docker-build.sh
shasum -a 256 -c dist/SHA256SUMS

# Compare to the Release asset SHA256SUMS (must match SeedMask_Firmware.bin line)
```

Or:

```bash
shasum -a 256 dist/SeedMask_Firmware.bin
# must equal the hash published on the Release for that tag
```

## Release flow (maintainers)

1. Tag the commit that should ship (`vX.Y.Z`).
2. GitHub Actions (`.github/workflows/release-build.yml`) builds with the same Docker path and uploads `dist/*.bin` + `SHA256SUMS`.
3. Optionally run `./scripts/docker-build.sh` locally and confirm hashes match CI before announcing.

## Limits

- Host OS (Mac / Windows / Linux) only runs Docker; compilation always happens in the same Linux image.
- Changing `build/versions.env`, FQBN, libraries, or source changes the hash — bump the Release tag.
- Do not publish production devices from this unsigned preview image without the separate Secure Boot process.
