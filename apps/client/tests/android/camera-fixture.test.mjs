// Catches source-centred placement (which clips the QR), lost quiet zone,
// resampling of modules, and accepting input other than the host's SVG format.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inflateSync } from 'node:zlib';
import test from 'node:test';

const script = fileURLToPath(new URL('./camera-fixture.py', import.meta.url));
function fixture(t, svg) {
  const dir = mkdtempSync(path.join(tmpdir(), 'camera-fixture-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const input = path.join(dir, 'host.svg'), output = path.join(dir, 'camera.png');
  writeFileSync(input, svg);
  return { output, result: spawnSync('python3', [script, input, output], { encoding: 'utf8' }) };
}
function pixels(file) {
  const png = readFileSync(file), chunks = [];
  assert.equal(png.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
  assert.equal(png.readUInt32BE(16), 1920);
  assert.equal(png.readUInt32BE(20), 1080);
  for (let offset = 8; offset < png.length;) {
    const length = png.readUInt32BE(offset);
    if (png.subarray(offset + 4, offset + 8).toString() === 'IDAT') chunks.push(png.subarray(offset + 8, offset + 8 + length));
    offset += 12 + length;
  }
  const raw = inflateSync(Buffer.concat(chunks));
  assert.equal(raw.length, 1921 * 1080);
  for (let y = 0; y < 1080; y++) assert.equal(raw[y * 1921], 0);
  return (x, y) => raw[y * 1921 + x + 1];
}

test('host modules remain exact with complete quiet zone at calibrated frame centre', t => {
  // Two real SVG unit modules at opposite corners of the data area, leaving
  // the host's four-module quiet zone. No live session is committed.
  const { result, output } = fixture(t, '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 61 61"><path d="M4 4h1v1h-1zM56 56h1v1h-1z"/></svg>');
  assert.equal(result.status, 0, result.stderr);
  const at = pixels(output);
  assert.equal(at(459, 355), 0);
  assert.equal(at(465, 361), 0);
  assert.equal(at(466, 361), 255);
  assert.equal(at(823, 719), 0);
  assert.equal(at(829, 725), 0);
  for (let y = 327; y < 754; y++) for (let x = 431; x < 858; x++) {
    if (x < 459 || x >= 830 || y < 355 || y >= 726) assert.equal(at(x, y), 255);
  }
  // Independent measured camera map: the complete source box lands within
  // X≈388..894, Y≈227..733 of the 1280×960 raw frame, rather than above row 0.
  const meta = JSON.parse(readFileSync(output + '.json', 'utf8'));
  assert.deepEqual(meta.qr_box_including_quiet_zone, [431, 327, 427, 427]);
});

test('refuses arbitrary SVG rather than silently rendering a different fixture', t => {
  const { result } = fixture(t, '<svg><image href="https://example.invalid/qr.png"/></svg>');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /unexpected QR SVG/);
});
