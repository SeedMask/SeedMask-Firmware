# ESP32 production firmware profile (SeedMask)

Development builds often leave **UART debug**, **unencrypted flash**, and **unsigned firmware** enabled. Production devices should use a **separate build profile** and manufacturing steps.

## Goals

| Control | Why |
|--------|-----|
| **Secure Boot** | Only bootloader-trusted signed app images run; reduces flash-swap attacks. |
| **Flash Encryption** | External flash contents are encrypted with a device key; raises bar for offline readout. |
| **Disable production debug** | JTAG / USB-JTAG / ROM print where policy requires (see ESP-IDF eFuse docs for your chip). |
| **Anti-rollback (optional)** | Prevents downgrading to a known-vulnerable firmware version. |

## Firmware compile flags (this repo)

- **`SEEDMASK_CRYPTO_DEBUG`**: Default **0** in [`SeedMask Firmware.ino`](../SeedMask Firmware.ino). Set to **1** only on a trusted dev device when debugging crypto/vault paths.
  - Arduino IDE: add to *Tools* → *Compiler options* or `build_flags` if using `arduino-cli`/PlatformIO.
  - Never ship production builds with `SEEDMASK_CRYPTO_DEBUG=1`.

## Arduino CLI example (release-oriented)

```bash
arduino-cli compile --fqbn esp32:esp32:esp32s3:PartitionScheme=default \
  --build-property "build.extra_flags=-DSEEDMASK_CRYPTO_DEBUG=0" \
  SeedMask Firmware
```

Adjust FQBN for your exact board (`esp32s3`, `PartitionScheme`, USB mode, etc.).

## ESP-IDF / sdkconfig (when using ESP-IDF or hybrid flows)

Use `idf.py menuconfig` (or merge a defaults file) to enable at minimum for production:

- `CONFIG_SECURE_BOOT=y` (variant depends on chip: e.g. Secure Boot V2 on ESP32-S3)
- `CONFIG_SECURE_FLASH_ENC_ENABLED=y`
- Review `CONFIG_ESP_CONSOLE_*` for whether UART0 stays enabled in release

**Reference fragment:** see [`sdkconfig.production.defaults`](../sdkconfig.production.defaults) in this folder (comments only—merge into your real `sdkconfig` after reading Espressif docs for your chip revision).

## Manufacturing checklist

1. Generate signing keys offline; **never** commit private signing keys to git.
2. Flash bootloader + app with Secure Boot + Flash Encryption per Espressif **first-time flash** procedure.
3. Blow eFuses only after validating a **golden** image on engineering units.
4. Document recovery procedure for bricked units (RMA / factory-only reflash).

## Dev vs prod summary

| | Development | Production |
|---|-------------|------------|
| `SEEDMASK_CRYPTO_DEBUG` | 1 (optional, local only) | **0** |
| Secure Boot | Often off | **On** |
| Flash encryption | Often off | **On** |
| UART pads | Exposed | Epoxy / no header per threat model |

See also [`THREAT_MODEL.md`](THREAT_MODEL.md) and [`VERIFY_AND_RELEASE.md`](VERIFY_AND_RELEASE.md).
