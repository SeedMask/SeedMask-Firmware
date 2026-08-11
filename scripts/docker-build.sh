#!/usr/bin/env bash
# Rebuild SeedMask Firmware inside the pinned Docker image (byte-for-byte path).
# Usage: ./scripts/docker-build.sh [--no-cache]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# shellcheck disable=SC1091
source "$ROOT/build/versions.env"

IMAGE="${SEEDMASK_BUILD_IMAGE:-seedmask-firmware-build:${ESP32_CORE_VERSION}-cli${ARDUINO_CLI_VERSION}}"

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker is required. Install Docker Desktop (Mac/Windows) or Docker Engine (Linux)." >&2
  exit 1
fi

echo "==> Building image $IMAGE"
# Classic `docker build` loads the image into the local engine (required for `docker run`).
if [[ "${1:-}" == "--no-cache" ]]; then
  docker build --no-cache \
    --build-arg "ARDUINO_CLI_VERSION=${ARDUINO_CLI_VERSION}" \
    --build-arg "ESP32_CORE_VERSION=${ESP32_CORE_VERSION}" \
    -t "$IMAGE" \
    -f docker/Dockerfile \
    .
else
  docker build \
    --build-arg "ARDUINO_CLI_VERSION=${ARDUINO_CLI_VERSION}" \
    --build-arg "ESP32_CORE_VERSION=${ESP32_CORE_VERSION}" \
    -t "$IMAGE" \
    -f docker/Dockerfile \
    .
fi

mkdir -p "$ROOT/dist"
# Fixed mount path /src — required for path-stable builds
echo "==> Compiling inside container"
docker run --rm \
  --entrypoint /src/scripts/docker-entrypoint.sh \
  --env SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
  -v "$ROOT:/src:rw" \
  -w /src \
  "$IMAGE"

echo ""
echo "Verify against a GitHub Release:"
echo "  shasum -a 256 -c dist/SHA256SUMS"
echo "  # or compare SeedMask_Firmware.bin hash to the Release SHA256SUMS file"
