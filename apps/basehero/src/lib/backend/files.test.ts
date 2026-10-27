import { describe, expect, it } from 'vitest';
import { FakeBackend } from './fake';

const r = { account: 'account', base: 'base' };
const png = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 1]);

describe('fake file boundary', () => {
  it('sniffs all four supported raster formats regardless of supplied type', async () => {
    const backend = new FakeBackend();
    const note = await backend.createObject(r, { kind: 'note', parent: null, after: null, name: null });
    for (const [mime, signature] of [
      ['image/jpeg', [255,216,255,0]],
      ['image/gif', [...new TextEncoder().encode('GIF89a'),0]],
      ['image/webp', [...new TextEncoder().encode('RIFF'),0,0,0,0,...new TextEncoder().encode('WEBP')]],
    ] as const) {
      const bytes = new Uint8Array(signature);
      const file = await backend.fileAdd(r,note,'wrong.svg','image/svg+xml',bytes);
      expect(await backend.fileImage(r,file.id)).toEqual({mime,bytes});
    }
  });
  it('keeps the uploaded bytes and never trusts declared MIME for image display', async () => {
    const backend = new FakeBackend();
    const note = await backend.createObject(r, { kind: 'note', parent: null, after: null, name: null });
    const file = await backend.fileAdd(r, note, 'photo.svg', 'image/svg+xml', png);
    expect((await backend.files(r, note)).map(f => f.id)).toEqual([file.id]);
    expect(await backend.fileImage(r, file.id)).toEqual({ mime: 'image/png', bytes: png });
    const falseImage = await backend.fileAdd(r, note, 'photo.png', 'image/png', new TextEncoder().encode('<svg/>'));
    await expect(backend.fileImage(r, falseImage.id)).rejects.toMatchObject({ kind: 'Invalid' });
    backend.setFileStatus(file.id, { kind: 'fetching', done: 0, parts: 1 });
    expect((await backend.fileInfo(r, file.id))?.status).toEqual({ kind: 'fetching', done: 0, parts: 1 });
    await expect(backend.fileOpen(r, file.id)).rejects.toMatchObject({ kind: 'NotFound' });
    backend.setFileStatus(file.id, { kind: 'here' });
    await backend.fileOpen(r, file.id);
    expect(backend.calls).toContain(`fileOpen ${r.account}`);
    await backend.deleteObject(r, file.id);
    expect((await backend.files(r, note)).map(f => f.id)).toEqual([falseImage.id]);
  });
});
