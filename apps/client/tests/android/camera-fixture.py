#!/usr/bin/env python3
"""Render a live showing host's QR SVG for the API 36 Fold imagefile camera.

    python3 camera-fixture.py <host-qr.svg> <camera.png>

The emulator 37.1.11 imagefile camera rotates/crops a 1920x1080 source before
CameraX analysis. A labelled grid measured raw 1280x960 analysis coordinates:
    frame_x = 1.185 * source_y + 0.267
    frame_y = -1.1853125 * source_x + 1243.475
Source (644,540), NOT the source image centre, maps to frame centre (640,480).
A 61-module host QR at 7 px/module then has complete four-module quiet zone
and about 8.3 px/module in the analysis frame. Preview coordinates are not
used. Recalibrate raw analysis pixels if the emulator/camera setup changes.

This creates a test image only; it neither decodes a code nor injects a scan.
The input must come from a fresh live showing session (expires after 300 s).
"""
import json
import re
import struct
import sys
import zlib
from pathlib import Path

WIDTH, HEIGHT = 1920, 1080
MODULE_PX = 7


def render(svg):
    match = re.fullmatch(
        r'<svg xmlns="http://www\.w3\.org/2000/svg" viewBox="0 0 (\d+) (\d+)"><path d="((?:M\d+ \d+h1v1h-1z)+)"/></svg>', svg)
    if not match or match.group(1) != match.group(2):
        raise ValueError('unexpected QR SVG')
    side = int(match.group(1))
    modules = [(int(x), int(y)) for x, y in re.findall(r'M(\d+) (\d+)h1v1h-1z', match.group(3))]
    # This fixture is calibrated for the host's current 167-character BH1 QR.
    if side != 61 or any(not (4 <= x < side - 4 and 4 <= y < side - 4) for x, y in modules):
        raise ValueError('unexpected QR SVG size or quiet zone')
    image = bytearray([255]) * (WIDTH * HEIGHT)

    def rect(x, y, width, height, value=0):
        for row in range(y, y + height):
            image[row * WIDTH + x:row * WIDTH + x + width] = bytes([value]) * width

    size = side * MODULE_PX
    left, top = 644 - size // 2, 540 - size // 2
    for x, y in modules:
        rect(left + x * MODULE_PX, top + y * MODULE_PX, MODULE_PX, MODULE_PX)
    # The diagnostic border sits another 40px beyond the existing quiet zone.
    pad = 40
    for x, y, w, h in (
        (left - pad, top - pad, size + 2 * pad, 3),
        (left - pad, top + size + pad - 3, size + 2 * pad, 3),
        (left - pad, top - pad, 3, size + 2 * pad),
        (left + size + pad - 3, top - pad, 3, size + 2 * pad),
    ):
        rect(x, y, w, h, 96)
    edge, arm, thick = 24, 120, 12
    for cx, cy, dx, dy in (
        (edge, edge, 1, 1), (WIDTH - edge, edge, -1, 1),
        (edge, HEIGHT - edge, 1, -1), (WIDTH - edge, HEIGHT - edge, -1, -1),
    ):
        rect(cx if dx > 0 else cx - arm, cy if dy > 0 else cy - thick, arm, thick)
        rect(cx if dx > 0 else cx - thick, cy if dy > 0 else cy - arm, thick, arm)
    rect(edge + 30, edge + 30, 60, 60)
    for x, y, w, h in (
        (WIDTH // 2 - 4, 0, 8, 60), (WIDTH // 2 - 4, HEIGHT - 60, 8, 60),
        (0, HEIGHT // 2 - 4, 60, 8), (WIDTH - 60, HEIGHT // 2 - 4, 60, 8),
    ):
        rect(x, y, w, h)

    def chunk(kind, data):
        return (struct.pack('>I', len(data)) + kind + data
                + struct.pack('>I', zlib.crc32(kind + data) & 0xffffffff))

    raw = b''.join(b'\0' + image[y * WIDTH:(y + 1) * WIDTH] for y in range(HEIGHT))
    png = (b'\x89PNG\r\n\x1a\n'
           + chunk(b'IHDR', struct.pack('>IIBBBBB', WIDTH, HEIGHT, 8, 0, 0, 0, 0))
           + chunk(b'IDAT', zlib.compress(raw, 9)) + chunk(b'IEND', b''))
    geometry = {'image': [WIDTH, HEIGHT], 'centre_source': [644, 540],
                'qr_modules_with_quiet_zone': side, 'module_px': MODULE_PX,
                'qr_box_including_quiet_zone': [left, top, size, size],
                'outer_box_margin_px': pad, 'corner_brackets_from_edge_px': edge}
    return png, geometry


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    svg, output = map(Path, sys.argv[1:])
    png, geometry = render(svg.read_text())
    output.write_bytes(png)
    Path(str(output) + '.json').write_text(json.dumps(geometry, indent=2))
    print(json.dumps(geometry))


if __name__ == '__main__':
    main()
