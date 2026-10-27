import { describe, expect, it, vi } from 'vitest';

const invoke = vi.hoisted(() => vi.fn());
vi.mock('@tauri-apps/api/core', () => ({
  invoke,
  Channel: class {
    onmessage?: (value: ArrayBuffer | Uint8Array) => void;
  },
}));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn() }));
vi.mock('@tauri-apps/plugin-opener', () => ({ openUrl: vi.fn() }));

import { tauriBackend } from './tauri';

describe('note IPC', () => {
  it('decodes the raw open response and raw channel updates on Android', async () => {
    const seen: Uint8Array[] = [];
    invoke.mockImplementation(async (command, args) => {
      expect(command).toBe('note_open');
      args.channel.onmessage(new Uint8Array([0, 255]).buffer);
      return new Uint8Array([0, 0, 0, 0, 0, 0, 0, 2, 0, 255, 127]).buffer;
    });
    const opened = await tauriBackend.noteOpen({ account: 'a', base: 'b' }, 'n', update => seen.push(update));
    expect(opened).toEqual({ session: 2, readOnly: false, state: new Uint8Array([255, 127]) });
    expect(seen).toEqual([new Uint8Array([0, 255])]);
  });

  it('sends a Uint8Array without changing the desktop or Android input path', async () => {
    invoke.mockResolvedValue(undefined);
    const update = new Uint8Array([0, 255]);
    await tauriBackend.noteApply(2, update);
    expect(invoke).toHaveBeenCalledWith('note_apply', update, { headers: { 'bh-session': '2' } });
  });
});
