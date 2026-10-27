import { describe, expect, it } from 'vitest';
import { drainAll, noteHost, trackEditor } from './host';
import { FakeBackend } from '../backend/fake';
import * as Y from 'yjs';

const r = { account: 'account', base: 'base' };

describe('note host', () => {
  it('acknowledges only after the backend has committed the exact update', async () => {
    const backend = new FakeBackend();
    const id = await backend.createObject(r, { kind: 'note', name: 'Note', parent: null, after: null });
    const host = noteHost(backend, r, id);
    const opened = await host.open(() => {});
    expect(opened.clientId).toBeGreaterThanOrEqual(2);
    const doc = new Y.Doc();
    const paragraph = new Y.XmlElement('paragraph');
    paragraph.insert(0, [new Y.XmlText('Safe')]);
    doc.getXmlFragment('default').insert(0, [paragraph]);
    expect(await host.commit(Y.encodeStateAsUpdate(doc), 'request-1')).toEqual({ requestId: 'request-1' });
    expect(backend.noteText(id)).toBe('Safe');
    opened.unsubscribe();
    await expect(host.commit(Y.encodeStateAsUpdate(doc), 'request-2')).rejects.toThrow('closed');
    doc.destroy();
  });

  it('waits for every open editor and refuses an unsuccessful drain', async () => {
    let finish!: (ok: boolean) => void;
    const stopping = trackEditor({ drain: () => new Promise<boolean>(resolve => { finish = resolve; }) });
    try {
      const pending = drainAll();
      let finished = false;
      void pending.then(() => { finished = true; });
      await Promise.resolve();
      expect(finished).toBe(false);
      finish(true);
      await pending;
      stopping();
      const rejecting = trackEditor({ drain: async () => false });
      try { await expect(drainAll()).rejects.toThrow('Could not save'); }
      finally { rejecting(); }
    } finally { stopping(); }
  });
});
