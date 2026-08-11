#!/usr/bin/env bash
# Compile SeedMask_Firmware with pinned FQBN; write artifacts to dist/.
set -euo pipefail

ROOT="${SEEDMASK_SRC:-/src}"
cd "$ROOT"

# shellcheck disable=SC1091
source "$ROOT/build/versions.env"

FQBN="$(tr -d '\n' < "$ROOT/build/fqbn.txt")"
SKETCH="$ROOT/SeedMask_Firmware"
BUILD_PATH=/tmp/seedmask-arduino-build
OUT="$ROOT/dist"
mkdir -p "$OUT"
rm -rf "$BUILD_PATH"
mkdir -p "$BUILD_PATH"

# Drop previous artifacts so hashes only cover this build
rm -f "$OUT"/*.bin "$OUT"/*.elf "$OUT"/*.map "$OUT"/SHA256SUMS 2>/dev/null || true

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}"
export ARDUINO_DIRECTORIES_USER="$ROOT"
export TZ=UTC
export LC_ALL=C

echo "==> arduino-cli $(arduino-cli version)"
echo "==> FQBN=$FQBN"
echo "==> SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
echo "==> esp32 core expect ${ESP32_CORE_VERSION}"

arduino-cli core list
arduino-cli lib list || true

arduino-cli compile \
  --fqbn "$FQBN" \
  --build-path "$BUILD_PATH" \
  --output-dir "$OUT" \
  --build-property "compiler.cpp.extra_flags=-DSEEDMASK_CRYPTO_DEBUG=0" \
  --build-property "compiler.c.extra_flags=-DSEEDMASK_CRYPTO_DEBUG=0" \
  --warnings none \
  --jobs 1 \
  "$SKETCH"

# Prefer Arduino CLI's *.ino.bin name; normalize to stable release names
if [[ -f "$OUT/SeedMask_Firmware.ino.bin" ]]; then
  cp -f "$OUT/SeedMask_Firmware.ino.bin" "$OUT/SeedMask_Firmware.bin"
elif [[ -f "$OUT/SeedMask_Firmware.bin" ]]; then
  :
else
  echo "error: no app .bin produced in $OUT" >&2
  ls -la "$OUT" >&2 || true
  exit 1
fi

[[ -f "$OUT/SeedMask_Firmware.ino.bootloader.bin" ]] && \
  cp -f "$OUT/SeedMask_Firmware.ino.bootloader.bin" "$OUT/SeedMask_Firmware.bootloader.bin"
[[ -f "$OUT/SeedMask_Firmware.ino.partitions.bin" ]] && \
  cp -f "$OUT/SeedMask_Firmware.ino.partitions.bin" "$OUT/SeedMask_Firmware.partitions.bin"
[[ -f "$OUT/SeedMask_Firmware.ino.merged.bin" ]] && \
  cp -f "$OUT/SeedMask_Firmware.ino.merged.bin" "$OUT/SeedMask_Firmware.merged.bin"

bash "$ROOT/scripts/export-hashes.sh" "$OUT"
echo "==> done. Artifacts in dist/"
ls -la "$OUT"
