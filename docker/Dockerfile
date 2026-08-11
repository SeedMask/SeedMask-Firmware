# SeedMask Firmware — reproducible preview builds (arduino-cli + pinned esp32 core).
# Build context: repository root (SeedMask-Firmware/).
FROM debian:bookworm-20250113-slim

ARG ARDUINO_CLI_VERSION=1.2.0
ARG ESP32_CORE_VERSION=3.3.6
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive \
    ARDUINO_DIRECTORIES_DATA=/opt/arduino15 \
    ARDUINO_DIRECTORIES_USER=/src \
    ARDUINO_DIRECTORIES_DOWNLOADS=/opt/arduino15/staging \
    PATH=/opt/arduino-cli:${PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      python3 \
      python3-serial \
      xz-utils \
      unzip \
      make \
    && rm -rf /var/lib/apt/lists/*

# Install arduino-cli (pinned)
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64) cli_arch=Linux_64bit ;; \
      aarch64|arm64) cli_arch=Linux_ARM64 ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/arduino/arduino-cli/releases/download/v${ARDUINO_CLI_VERSION}/arduino-cli_${ARDUINO_CLI_VERSION}_${cli_arch}.tar.gz" \
      | tar -xz -C /tmp; \
    mkdir -p /opt/arduino-cli; \
    mv /tmp/arduino-cli /opt/arduino-cli/; \
    arduino-cli version

# Pin Espressif boards URL + install exact esp32 core (downloads host toolchain once at image build)
RUN mkdir -p /opt/arduino15 && \
    arduino-cli config init --overwrite && \
    arduino-cli config set board_manager.additional_urls \
      https://espressif.github.io/arduino-esp32/package_esp32_index.json && \
    arduino-cli core update-index && \
    arduino-cli core install "esp32:esp32@${ESP32_CORE_VERSION}"

WORKDIR /src
COPY scripts/docker-entrypoint.sh /usr/local/bin/seedmask-build
RUN chmod +x /usr/local/bin/seedmask-build
ENTRYPOINT ["/usr/local/bin/seedmask-build"]
