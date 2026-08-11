#!/usr/bin/env bash
# Fail CI if known-dangerous plaintext logging strings reappear in the main sketch.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
INO="$ROOT/SeedMask Firmware.ino"
if [[ ! -f "$INO" ]]; then
  echo "ERROR: $INO not found"
  exit 1
fi

banned=(
  "Decrypted plaintext"
  "aes_gcm_decrypt: As text"
)

for s in "${banned[@]}"; do
  if grep -qF "$s" "$INO"; then
    echo "ERROR: banned debug substring found in $INO: $s"
    exit 1
  fi
done

echo "OK: crypto serial guard checks passed for SeedMask Firmware.ino"
