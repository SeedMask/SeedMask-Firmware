#!/usr/bin/env python3
"""Rasterize the Heroicons microSD SVG (single path, even-odd) to one RGB565 bitmap."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / ".pydeps"))

from svg.path import Arc, Close, CubicBezier, Line, Move, QuadraticBezier, parse_path

HEROICON_PATH = (
    "M6 9l5-5h5.5A1.5 1.5 0 0118 5.5v13a1.5 1.5 0 01-1.5 1.5h-9A1.5 1.5 0 016 18.5V9z"
    "m9.75-3a.75.75 0 00-.75.75v2.5a.75.75 0 001.5 0v-2.5a.75.75 0 00-.75-.75z"
    "M13 6.75a.75.75 0 011.5 0v2.5a.75.75 0 01-1.5 0v-2.5z"
    "M11.75 6a.75.75 0 00-.75.75v2.5a.75.75 0 001.5 0v-2.5a.75.75 0 00-.75-.75z"
)

VIEWBOX = 24.0
OUT_SIZE = 35
SUB = 4  # subpixel grid per axis for anti-aliasing
TRAN = 0x0841
INK = 0xFFDF


def segment_edges(path):
    for seg in path:
        if isinstance(seg, Line):
            yield (seg.start.real, seg.start.imag, seg.end.real, seg.end.imag)
        elif isinstance(seg, Arc):
            steps = 12  # svg.path Arc.delta is degrees, not radians
            prev = seg.start
            for i in range(1, steps + 1):
                p = seg.point(i / steps)
                yield (prev.real, prev.imag, p.real, p.imag)
                prev = p
        elif isinstance(seg, CubicBezier):
            prev = seg.start
            for i in range(1, 13):
                p = seg.point(i / 12)
                yield (prev.real, prev.imag, p.real, p.imag)
                prev = p
        elif isinstance(seg, QuadraticBezier):
            prev = seg.start
            for i in range(1, 11):
                p = seg.point(i / 10)
                yield (prev.real, prev.imag, p.real, p.imag)
                prev = p
        elif isinstance(seg, Close):
            yield (seg.start.real, seg.start.imag, seg.end.real, seg.end.imag)


def scanline_crossings(py: float, edges) -> list[float]:
    xs: list[float] = []
    for x0, y0, x1, y1 in edges:
        if (y0 <= py < y1) or (y1 <= py < y0):
            if abs(y1 - y0) < 1e-12:
                continue
            xs.append(x0 + (py - y0) * (x1 - x0) / (y1 - y0))
    xs.sort()
    return xs


def rasterize(path_d: str, size: int) -> list[list[float]]:
    edges = list(segment_edges(parse_path(path_d)))
    scale = size / VIEWBOX
    out = [[0.0] * size for _ in range(size)]
    inv = 1.0 / (scale * SUB)

    def inside(px: float, py: float) -> bool:
        crossings = 0
        for x0, y0, x1, y1 in edges:
            if (y0 <= py < y1) or (y1 <= py < y0):
                if abs(y1 - y0) < 1e-12:
                    continue
                if px < x0 + (py - y0) * (x1 - x0) / (y1 - y0):
                    crossings += 1
        return (crossings & 1) == 1

    for y in range(size):
        for x in range(size):
            hits = 0
            for sy in range(SUB):
                for sx in range(SUB):
                    px = (x * SUB + sx + 0.5) * inv
                    py = (y * SUB + sy + 0.5) * inv
                    if inside(px, py):
                        hits += 1
            out[y][x] = hits / (SUB * SUB)
    return out


def emit_ino_header() -> None:
    cov = rasterize(HEROICON_PATH, OUT_SIZE)
    filled = sum(1 for row in cov for v in row if v >= 0.5)
    print(f"// coverage pixels: {filled}", file=sys.stderr)
    for y in range(OUT_SIZE):
        print("".join("#" if cov[y][x] >= 0.5 else "." for x in range(OUT_SIZE)), file=sys.stderr)

    print(
        f"// Heroicons microSD — single SVG path (viewBox 0 0 24 24), even-odd, "
        f"{OUT_SIZE}x{OUT_SIZE} 1:1. Regenerate: python3 gen_sd_icon.py --patch"
    )
    print(f"static const int SD_ICON_W = {OUT_SIZE};")
    print(f"static const int SD_ICON_H = {OUT_SIZE};")
    print("static const uint16_t SD_ICON_BITMAP[] = {")
    for y in range(OUT_SIZE):
        row = [f"0x{INK:04X}" if cov[y][x] >= 0.5 else f"0x{TRAN:04X}" for x in range(OUT_SIZE)]
        print("  " + ", ".join(row) + ",")
    print("};")
    print("static void drawMicroSDIcon(int x, int y, int w, int h) {")
    print("  const int ox = x + (w - SD_ICON_W) / 2;")
    print("  const int oy = y + (h - SD_ICON_H) / 2;")
    print("  gfx->draw16bitRGBBitmapWithTranColor(ox, oy, const_cast<uint16_t*>(SD_ICON_BITMAP),")
    print("                                       UI_TOP, SD_ICON_W, SD_ICON_H);")
    print("}")


def patch_ino() -> None:
    ino = Path(__file__).parent / "SeedMask Firmware.ino"
    text = ino.read_text()
    anchor = "static Rect BTN_SCROLL_UP = { 280, 80, 35, 30 }; // Scroll up button\n"
    start = text.find(anchor)
    if start < 0:
        raise SystemExit("BTN_SCROLL_UP anchor not found in .ino")
    start += len(anchor)
    end = text.find("static Rect BTN_SCROLL_DOWN", start)
    if end < 0:
        raise SystemExit("BTN_SCROLL_DOWN not found in .ino")
    block = subprocess.check_output(
        [sys.executable, str(Path(__file__).resolve()), "--emit-only"],
        text=True,
    )
    ino.write_text(text[:start] + "\n" + block + text[end:])
    print(f"Patched {ino}", file=sys.stderr)


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "--emit-only":
        emit_ino_header()
    elif len(sys.argv) > 1 and sys.argv[1] == "--patch":
        patch_ino()
    else:
        emit_ino_header()


if __name__ == "__main__":
    main()
