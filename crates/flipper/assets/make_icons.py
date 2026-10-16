#!/usr/bin/env python3
"""Regenerate the `.icon` files from the PNGs in this directory.

An `.icon` is one header byte (0x00 = uncompressed) followed by the 1-bit
bitmap, rows padded to whole bytes, least significant bit leftmost, 1 = black.
Usage: python3 make_icons.py   (needs Pillow)
"""
from pathlib import Path

from PIL import Image

HERE = Path(__file__).parent


def to_icon(png: Path) -> bytes:
    image = Image.open(png).convert("RGBA")
    # Flatten transparency onto white so transparent pixels are not black.
    flat = Image.new("RGBA", image.size, (255, 255, 255, 255))
    flat.alpha_composite(image)
    gray = flat.convert("L")
    width, height = gray.size
    row_bytes = (width + 7) // 8
    out = bytearray([0x00])
    for y in range(height):
        row = bytearray(row_bytes)
        for x in range(width):
            if gray.getpixel((x, y)) < 128:
                row[x // 8] |= 1 << (x % 8)
        out += row
    return bytes(out)


for png in sorted(HERE.glob("*.png")):
    png.with_suffix(".icon").write_bytes(to_icon(png))
    print(f"{png.name} -> {png.stem}.icon")
