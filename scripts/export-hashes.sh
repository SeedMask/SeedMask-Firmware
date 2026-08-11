#!/usr/bin/env bash
# Write SHA256SUMS for canonical release artifacts.
set -euo pipefail
DIR="${1:-dist}"
cd "$DIR"
: > SHA256SUMS
for f in \
  SeedMask_Firmware.bin \
  SeedMask_Firmware.bootloader.bin \
  SeedMask_Firmware.partitions.bin \
  SeedMask_Firmware.merged.bin
do
  [[ -f "$f" ]] || continue
  sha256sum "$f" >> SHA256SUMS
done
echo "==> SHA256SUMS"
cat SHA256SUMS
