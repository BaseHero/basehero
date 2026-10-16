// The Mac icon file holds the entry types macOS's own iconutil writes: 16 and
// 32 px as RLE-compressed ARGB, every larger size as PNG. Small PNG entries
// (icp4/icp5) decode as noise on current macOS.
import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const icns = await readFile(new URL("../ui/icon.icns", import.meta.url));

function entries(data) {
  assert.equal(data.subarray(0, 4).toString("latin1"), "icns");
  assert.equal(data.readUInt32BE(4), data.length);
  const out = new Map();
  for (let at = 8; at < data.length;) {
    const length = data.readUInt32BE(at + 4);
    out.set(data.subarray(at, at + 4).toString("latin1"), data.subarray(at + 8, at + length));
    at += length;
  }
  return out;
}
// icns RLE: a header byte below 0x80 copies that many plus one bytes; from
// 0x80 it repeats the next byte (header - 0x80 + 3) times.
function channels(payload, pixels) {
  assert.equal(payload.subarray(0, 4).toString("latin1"), "ARGB");
  const out = [];
  for (let at = 4; out.length < 4 * pixels;) {
    const header = payload[at++];
    if (header < 0x80) { for (let i = 0; i <= header; i++) out.push(payload[at++]); }
    else { const value = payload[at++]; for (let i = 0; i < header - 0x80 + 3; i++) out.push(value); }
  }
  assert.equal(out.length, 4 * pixels, "exactly four planes");
  return [0, 1, 2, 3].map((plane) => out.slice(plane * pixels, (plane + 1) * pixels));
}

test("icon.icns has iconutil's entry types with PNGs of the right size", () => {
  const found = entries(icns);
  assert.deepEqual([...found.keys()].sort(), ["ic04", "ic05", "ic07", "ic08", "ic09", "ic10", "ic11", "ic12", "ic13", "ic14"]);
  const png = { ic11: 32, ic12: 64, ic07: 128, ic13: 256, ic08: 256, ic14: 512, ic09: 512, ic10: 1024 };
  for (const [kind, size] of Object.entries(png)) {
    const data = found.get(kind);
    assert.equal(data.subarray(1, 4).toString("latin1"), "PNG", kind);
    assert.deepEqual([data.readUInt32BE(16), data.readUInt32BE(20)], [size, size], kind);
  }
});

test("the 16 and 32 px icons are the tile and B, not noise", () => {
  const found = entries(icns);
  for (const [kind, size] of [["ic04", 16], ["ic05", 32]]) {
    const [alpha, red, green, blue] = channels(found.get(kind), size * size);
    const at = (x, y) => [alpha, red, green, blue].map((plane) => plane[y * size + x]);
    assert.equal(at(0, 0)[0], 0, `${kind} corner is transparent`);
    assert.deepEqual(at(Math.round(size * 0.15), Math.round(size * 0.5)).slice(0, 1), [255], `${kind} tile body is opaque`);
    // Across the middle: dark tile, the yellow stem, the dark counter.
    const row = Array.from({ length: size }, (_, x) => at(x, Math.round(size * 0.55)));
    const yellow = row.map(([a, r, g, b]) => a === 255 && r > 150 && g > 100 && b < 100);
    const first = yellow.indexOf(true);
    assert.ok(first > size * 0.25 && first < size * 0.45, `${kind} stem starts at ${first}`);
    assert.ok(yellow.slice(0, first).every((y) => !y) && row[Math.round(size * 0.15)][1] < 40, `${kind} tile left of the stem is dark`);
    assert.ok(!yellow[Math.round(size * 0.5)], `${kind} counter is dark`);
  }
});
