#!/usr/bin/env python3
"""New account: two stacked UXWing papers → RGB565.

Same quality path as Export xPub/kPub:
  - full UXWing strokes
  - LANCZOS scale (keeps soft edges)
  - only snap near-black → black, chroma → transparent
  - NO flat fill quantization (that made it look broken/pixelated)

back=blue, front=white
Source: https://uxwing.com/paper-icon/
"""
from __future__ import annotations

from collections import deque
from pathlib import Path

import numpy as np
from PIL import Image

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "assets" / "uxwing_paper_icon_source.png"
OUT = ROOT / "crypto_new_account_icon_rgb565.h"

OUT_W, OUT_H = 63, 76
CHROMA = 0xF81F
CHROMA_RGB = (255, 0, 255)
BLACK_RGB = (0, 0, 0)
BACK_FILL = (65, 179, 231)
FRONT_FILL = (255, 255, 255)


def rgb888_to_rgb565(r: int, g: int, b: int) -> int:
    return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)


def flood_exterior(ink):
    h, w = len(ink), len(ink[0])
    ext = [[False] * w for _ in range(h)]
    q = deque()
    for x in range(w):
        for y in (0, h - 1):
            if not ink[y][x] and not ext[y][x]:
                ext[y][x] = True
                q.append((x, y))
    for y in range(h):
        for x in (0, w - 1):
            if not ink[y][x] and not ext[y][x]:
                ext[y][x] = True
                q.append((x, y))
    while q:
        x, y = q.popleft()
        for dx, dy in ((0, 1), (0, -1), (1, 0), (-1, 0)):
            nx, ny = x + dx, y + dy
            if 0 <= nx < w and 0 <= ny < h and not ink[ny][nx] and not ext[ny][nx]:
                ext[ny][nx] = True
                q.append((nx, ny))
    return ext


def build_document_rgb(src_rgba: Image.Image, fill_rgb: tuple[int, int, int]) -> Image.Image:
    """Same as Export xPub: ink→black, interior→fill, else chroma."""
    im = src_rgba.convert("RGBA")
    w, h = im.size
    px = im.load()
    ink = [[False] * w for _ in range(h)]
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            if a > 40 and (r + g + b) < 500:
                ink[y][x] = True
    ext = flood_exterior(ink)
    out = Image.new("RGB", (w, h), CHROMA_RGB)
    for y in range(h):
        for x in range(w):
            if ink[y][x]:
                out.putpixel((x, y), BLACK_RGB)
            elif not ext[y][x]:
                out.putpixel((x, y), fill_rgb)
    return out


def crop_doc(doc_rgb: Image.Image, pad: int = 4) -> Image.Image:
    px = doc_rgb.load()
    w, h = doc_rgb.size
    xs, ys = [], []
    for y in range(h):
        for x in range(w):
            if px[x, y] != CHROMA_RGB:
                xs.append(x)
                ys.append(y)
    if not xs:
        raise SystemExit("empty document")
    x0, x1 = max(0, min(xs) - pad), min(w - 1, max(xs) + pad)
    y0, y1 = max(0, min(ys) - pad), min(h - 1, max(ys) + pad)
    return doc_rgb.crop((x0, y0, x1 + 1, y1 + 1))


def is_chroma(r: int, g: int, b: int) -> bool:
    return (r, g, b) == CHROMA_RGB or (r > 200 and b > 200 and g < 130)


def scale_doc_soft(doc_rgb: Image.Image, max_w: int, max_h: int) -> Image.Image:
    """LANCZOS like Export — keep soft edge colors (do not flatten to pure fill)."""
    dw, dh = doc_rgb.size
    scale = min(max_w / dw, max_h / dh)
    nw, nh = max(1, int(round(dw * scale))), max(1, int(round(dh * scale)))
    return doc_rgb.resize((nw, nh), Image.Resampling.LANCZOS)


def rgb_to_rgba(doc_rgb: Image.Image) -> Image.Image:
    """Chroma → transparent; near-black → pure black; keep other LANCZOS colors."""
    w, h = doc_rgb.size
    px = doc_rgb.load()
    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    op = out.load()
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            if is_chroma(r, g, b):
                continue
            if r < 45 and g < 45 and b < 45:
                op[x, y] = (0, 0, 0, 255)
            else:
                op[x, y] = (r, g, b, 255)
    return out


def resize_rgba_premultiplied(im: Image.Image, size: tuple[int, int]) -> Image.Image:
    """Smooth downscale for the final stacked icon."""
    arr = np.array(im).astype(np.float32)
    a = arr[:, :, 3:4] / 255.0
    arr[:, :, :3] *= a
    premul = Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8), "RGBA")
    resized = premul.resize(size, Image.Resampling.LANCZOS)
    out = np.array(resized).astype(np.float32)
    a = out[:, :, 3:4]
    with np.errstate(divide="ignore", invalid="ignore"):
        rgb = np.where(a > 1.0, out[:, :, :3] * 255.0 / np.maximum(a, 1.0), 0.0)
    out[:, :, :3] = rgb
    out[:, :, 3] = a[:, :, 0]
    return Image.fromarray(np.clip(out, 0, 255).astype(np.uint8), "RGBA")


def build_icon() -> Image.Image:
    src = Image.open(SRC).convert("RGBA")

    # Build papers at ~2× device paper size (same idea as Export's ~38×50 paper),
    # stack on a 2× canvas, then one soft downscale → smooth like Export.
    hi_w, hi_h = OUT_W * 2, OUT_H * 2  # 126×152
    back = rgb_to_rgba(scale_doc_soft(crop_doc(build_document_rgb(src, BACK_FILL)), 88, 116))
    front = rgb_to_rgba(scale_doc_soft(crop_doc(build_document_rgb(src, FRONT_FILL)), 88, 116))

    canvas = Image.new("RGBA", (hi_w, hi_h), (0, 0, 0, 0))
    bw, bh = back.size
    fw, fh = front.size
    # Stack offset proportional to Export-style card layout.
    canvas.alpha_composite(back, (hi_w - bw - 4, 4))
    canvas.alpha_composite(front, (4, hi_h - fh - 4))

    # One high-quality downscale to device size.
    small = resize_rgba_premultiplied(canvas, (OUT_W, OUT_H))

    # Final light stroke snap only (Export-style), keep soft fill edges.
    w, h = small.size
    px = small.load()
    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    op = out.load()
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            if a < 40:
                continue
            if r < 50 and g < 50 and b < 50:
                op[x, y] = (0, 0, 0, 255)
            else:
                # keep soft color; boost alpha if mostly opaque
                op[x, y] = (r, g, b, 255 if a > 160 else a)
    return out


def main() -> None:
    if not SRC.exists():
        raise SystemExit(f"Missing {SRC}")

    icon = build_icon()
    px = icon.load()
    pixels: list[int] = []
    for y in range(OUT_H):
        for x in range(OUT_W):
            r, g, b, a = px[x, y]
            if a < 96:
                pixels.append(CHROMA)
            elif r < 40 and g < 40 and b < 40:
                pixels.append(0x0000)
            else:
                c = rgb888_to_rgb565(r, g, b)
                if c == CHROMA:
                    c ^= 0x20
                pixels.append(c)

    lines = [
        "#pragma once",
        "#include <Arduino.h>",
        "",
        "// New account: stacked UXWing papers — Export-quality LANCZOS path.",
        "// back=blue, front=white. Source: https://uxwing.com/paper-icon/",
        f"#define CRYPTO_NEW_ACCOUNT_ICON_W {OUT_W}",
        f"#define CRYPTO_NEW_ACCOUNT_ICON_H {OUT_H}",
        f"#define CRYPTO_NEW_ACCOUNT_ICON_CHROMA_KEY 0x{CHROMA:04X}u",
        "",
        "static const uint16_t CRYPTO_NEW_ACCOUNT_ICON_RGB565[] PROGMEM = {",
    ]
    row: list[str] = []
    for i, p in enumerate(pixels):
        row.append(f"0x{p:04X}u")
        if len(row) == 8 or i == len(pixels) - 1:
            lines.append("    " + ", ".join(row) + ("," if i < len(pixels) - 1 else ""))
            row = []
    lines.append("};")
    lines.append("")
    OUT.write_text("\n".join(lines), encoding="utf-8")

    preview = ROOT / "assets" / "_crypto_new_account_preview.png"
    bg = Image.new("RGBA", (OUT_W * 4, OUT_H * 4), (24, 32, 48, 255))
    bg.alpha_composite(icon.resize((OUT_W * 4, OUT_H * 4), Image.Resampling.NEAREST))
    bg.convert("RGB").save(preview)

    # refresh export preview + side-by-side
    import re

    htxt = (ROOT / "export_xpub_icon_rgb565.h").read_text()
    vals = [int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]+)u", re.search(r"PROGMEM = \{(.*?)\};", htxt, re.S).group(1))]
    ew = eh = 58
    eim = Image.new("RGBA", (ew, eh), (0, 0, 0, 0))
    for i, c in enumerate(vals):
        if c == CHROMA:
            continue
        r = ((c >> 11) & 0x1F) * 255 // 31
        g = ((c >> 5) & 0x3F) * 255 // 63
        b = (c & 0x1F) * 255 // 31
        eim.putpixel((i % ew, i // ew), (r, g, b, 255))
    ebg = Image.new("RGBA", (ew * 4, eh * 4), (24, 32, 48, 255))
    ebg.alpha_composite(eim.resize((ew * 4, eh * 4), Image.Resampling.NEAREST))
    ebg.convert("RGB").save(ROOT / "assets" / "_export_xpub_preview.png")

    a = Image.open(ROOT / "assets" / "_export_xpub_preview.png")
    b = Image.open(preview)
    hh = max(a.size[1], b.size[1])

    def pad(im: Image.Image) -> Image.Image:
        o = Image.new("RGB", (im.size[0], hh), (24, 32, 48))
        o.paste(im, (0, (hh - im.size[1]) // 2))
        return o

    aa, bb = pad(a), pad(b)
    side = Image.new("RGB", (aa.size[0] + bb.size[0] + 16, hh), (24, 32, 48))
    side.paste(aa, (0, 0))
    side.paste(bb, (aa.size[0] + 16, 0))
    side.save(ROOT / "assets" / "_compare_export_vs_new_account.png")

    print("Wrote", OUT)
    print("Preview", preview)


if __name__ == "__main__":
    main()
