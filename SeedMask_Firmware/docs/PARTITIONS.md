# Flash partitions (ESP32) — black screen / won’t boot after flash

## What went wrong

The previous default in this repo was **dual OTA** on **4 MB** flash: each of `app0` / `app1` was **0x140000** bytes (~**1.25 MB**). If the compiled firmware is **larger than that**, esptool may refuse to flash, or the image can be **truncated / invalid**, and the device can **boot to a blank screen** or reset in a loop.

Growing the sketch (UI, crypto, assets) commonly pushes the `.bin` past ~1.2 MB.

## Fix (recommended for development)

1. Use the **large single-app** table: `partitions.csv` in this folder (already set to a **~3 MB** `factory` app + SPIFFS on 4 MB flash).
2. In **Arduino IDE**: **Tools → Partition Scheme →** pick **Custom** (or **Huge APP** if your board package offers it — both give a big app region).
3. Set **Tools → Flash Size** to match your module (**4 MB** for this table).
4. **Clean** and **rebuild**, then **upload** again.

## If you need dual OTA again

- Copy `partitions_ota_dual_4mb.csv` over `partitions.csv` (or swap filenames).
- You must keep each OTA image **≤ ~1.2 MB**, or reduce features / optimize, or move to a **larger flash** chip with a bigger partition table.

## 8 MB modules

If your board has **8 MB** flash, select **8 MB** under Tools and use a partition CSV sized for 8 MB (you can duplicate `partitions.csv` and increase `factory` + `spiffs` so the sum matches 8 MB). The stock **Huge APP** scheme in the board menu is often enough.

## Check binary size

After compile, confirm the reported **Program storage** / `.bin` size is **below** your `factory` (or `app0`) partition size. If it isn’t, fix partitions or shrink the firmware before relying on the device to boot.
