import { describe, expect, it, vi } from 'vitest';
import { FakeBackend } from './fake';
import * as Y from 'yjs';

const r = { account: 'account', base: 'base' };

describe('fake backend', () => {
  it('logs each method and the first string argument', async () => {
    const fake = new FakeBackend();
    await fake.appInfo();
    await fake.bases('account');
    await fake.children(r, null);
    expect(fake.calls).toEqual(['appInfo', 'bases account', 'children']);
  });

  it('delivers remote objects and sync events', async () => {
    const fake = new FakeBackend();
    const handler = vi.fn();
    const unsubscribe = await fake.onEvent(handler);
    const id = fake.remoteCreate(r, { kind: 'note', name: 'First', parent: null, after: null });
    fake.setSync(r, { online: false, pending: 1, lastSyncedAt: null });
    expect((await fake.children(r, null)).map(item => item.id)).toEqual([id]);
    expect(handler).toHaveBeenCalledTimes(2);
    expect((await fake.syncState(r)).online).toBe(false);
    unsubscribe();
    fake.remoteCreate(r, { kind: 'folder', name: 'Second', parent: null, after: null });
    expect(handler).toHaveBeenCalledTimes(2);
  });

  it('counts note sessions and echoes updates to other sessions only', async () => {
    const fake = new FakeBackend();
    const first = vi.fn();
    const second = vi.fn();
    const a = await fake.noteOpen(r, 'note', first);
    const b = await fake.noteOpen(r, 'note', second);
    expect(fake.openSessions()).toBe(2);
    const doc = new Y.Doc();
    const paragraph = new Y.XmlElement('paragraph');
    paragraph.insert(0, [new Y.XmlText('Hello')]);
    doc.getXmlFragment('default').insert(0, [paragraph]);
    await fake.noteApply(a.session, Y.encodeStateAsUpdate(doc));
    expect(fake.noteText('note')).toBe('Hello');
    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledOnce();
    await fake.noteClose(a.session);
    await fake.noteClose(b.session);
    expect(fake.openSessions()).toBe(0);
  });
});
