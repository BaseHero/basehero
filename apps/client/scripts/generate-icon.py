#!/usr/bin/env python3
"""Render the Dispatch B app icon: ui/icon.png and the Mac ui/icon.icns.

The mark sits on the standard Mac rounded tile (body 824 of 1024, transparent
outside) so the system shows it as drawn rather than in its grey fallback
tile. Every icns size is rendered directly from the outlines with
anti-aliasing, never scaled from another bitmap.
"""
import math
import struct
import zlib
from pathlib import Path

BACKGROUND = (15, 17, 20)
YELLOW = (255, 194, 14)

# The tile: Apple's icon grid body with its corner radius, in 1024 units.
TILE = (100, 100, 924, 924)
RADIUS = 185


def rounded_rect(left, top, right, bottom, radius, steps=48):
    points = []
    for cx, cy, start in ((right - radius, top + radius, -90), (right - radius, bottom - radius, 0),
                          (left + radius, bottom - radius, 90), (left + radius, top + radius, 180)):
        for i in range(steps + 1):
            angle = math.radians(start + 90 * i / steps)
            points.append((cx + radius * math.cos(angle), cy + radius * math.sin(angle)))
    return points


def dispatch_b():
    """The square B: a straight stem, a narrower upper bowl and a wider lower
    bowl with cut right corners, so its waist steps in like a B, not an 8."""
    height, stroke, cut = 470, 84, 40
    upper, lower = 300, 336
    x0, y0 = 512 - lower / 2, 505 - height / 2
    y1, waist = y0 + height, y0 + 0.46 * height
    outer = [(x0, y0), (x0 + upper - cut, y0), (x0 + upper, y0 + cut), (x0 + upper, waist - cut),
             (x0 + upper - cut, waist), (x0 + lower - cut, waist), (x0 + lower, waist + cut),
             (x0 + lower, y1 - cut), (x0 + lower - cut, y1), (x0, y1)]

    def counter(right, top, bottom, inner=16):
        left = x0 + stroke
        return [(left, top), (right - inner, top), (right, top + inner), (right, bottom - inner),
                (right - inner, bottom), (left, bottom)]

    return [outer,
            counter(x0 + upper - stroke, y0 + stroke, waist - stroke / 2),
            counter(x0 + lower - stroke, waist + stroke / 2, y1 - stroke)]


def coverage(contours, size, samples=16):
    """Even-odd area coverage per pixel at `size`, from 1024-unit outlines."""
    scale = size / 1024
    edges = []
    for contour in contours:
        points = [(x * scale, y * scale) for x, y in contour]
        for (ax, ay), (bx, by) in zip(points, points[1:] + points[:1]):
            if ay != by:
                edges.append((ax, ay, bx, by))
    grid = [[0.0] * size for _ in range(size)]
    for row in range(size):
        line = grid[row]
        for s in range(samples):
            y = row + (s + 0.5) / samples
            xs = sorted(ax + (y - ay) * (bx - ax) / (by - ay)
                        for ax, ay, bx, by in edges if (ay <= y < by) or (by <= y < ay))
            for a, b in zip(xs[0::2], xs[1::2]):
                a, b = max(a, 0.0), min(b, float(size))
                first, last = int(a), min(int(b), size - 1)
                if first == last:
                    line[first] += (b - a) / samples
                    continue
                line[first] += (first + 1 - a) / samples
                for x in range(first + 1, last):
                    line[x] += 1 / samples
                line[last] += (b - last) / samples
    return grid


def render(size):
    """Rows of (r, g, b, a) pixels."""
    tile = coverage([rounded_rect(*TILE, RADIUS)], size)
    mark = coverage(dispatch_b(), size)
    rows = []
    for y in range(size):
        row = []
        for x in range(size):
            alpha, ink = min(tile[y][x], 1.0), min(mark[y][x], 1.0)
            # The mark lies inside the tile; blend it over the black body.
            colour = [round(b + (k - b) * ink) for b, k in zip(BACKGROUND, YELLOW)]
            row.append((*colour, round(255 * alpha)))
        rows.append(row)
    return rows


def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))


def png(rows):
    size = len(rows)
    data = b''.join(b'\x00' + bytes(v for pixel in row for v in pixel) for row in rows)  # no-filter rows
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('>IIBBBBB', size, size, 8, 6, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(data, 9))
            + chunk(b'IEND', b''))


def argb(rows):
    """The 16 and 32 px entries as iconutil writes them: 'ARGB', then the
    alpha, red, green and blue planes, each in icns run-length encoding."""
    out = bytearray(b'ARGB')
    for channel in (3, 0, 1, 2):
        plane = [pixel[channel] for row in rows for pixel in row]
        at = 0
        while at < len(plane):
            run = 1
            while at + run < len(plane) and run < 130 and plane[at + run] == plane[at]:
                run += 1
            if run >= 3:
                out += bytes((0x80 + run - 3, plane[at]))
                at += run
                continue
            start = at
            while at < len(plane) and at - start < 128:
                if at + 2 < len(plane) and plane[at] == plane[at + 1] == plane[at + 2]:
                    break
                at += 1
            out += bytes((at - start - 1,)) + bytes(plane[start:at])
    return bytes(out)


# icns entries by pixel size, in iconutil's types: 1x and 2x of each point size.
ICNS = ((b'ic04', 16, argb), (b'ic05', 32, argb), (b'ic11', 32, png), (b'ic12', 64, png), (b'ic07', 128, png),
        (b'ic13', 256, png), (b'ic08', 256, png), (b'ic14', 512, png), (b'ic09', 512, png), (b'ic10', 1024, png))


def icns(images):
    body = b''
    for kind, size, encode in ICNS:
        data = encode(images[size])
        body += kind + struct.pack('>I', len(data) + 8) + data
    return b'icns' + struct.pack('>I', len(body) + 8) + body


if __name__ == '__main__':
    ui = Path(__file__).resolve().parents[1] / 'ui'
    images = {size: render(size) for size in sorted({size for _, size, _ in ICNS})}
    (ui / 'icon.png').write_bytes(png(images[1024]))
    (ui / 'icon.icns').write_bytes(icns(images))
