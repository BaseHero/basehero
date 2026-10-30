import { describe, expect, it, vi } from 'vitest';
import { FakeBackend } from './fake';
import * as Y from 'yjs';

const r = { account: 'account', base: 'base' };

describe('fake backend', () => {
  it('starts Mac backup to its unacknowledged default and leaves phone backup off', async () => {
    const mac = new FakeBackend();
    mac.setPlatform('macos');
    const signed = await mac.signUp({ invite: 'invite', email: 'mac@example.test', password: 'correct horse battery staple', deviceName: 'Mac' });
    expect(await mac.backupStatus(signed.account.id)).toMatchObject({ enabled: true, acknowledged: false, location: { label: 'iCloud Drive › BaseHero' } });
    await mac.setBackup(signed.account.id, null);
    expect((await mac.backupStatus(signed.account.id)).enabled).toBe(false);
    const phone = new FakeBackend();
    phone.setPlatform('android');
    const phoneAccount = await phone.signUp({ invite: 'invite', email: 'phone@example.test', password: 'correct horse battery staple', deviceName: 'Fold' });
    expect((await phone.backupStatus(phoneAccount.account.id)).enabled).toBe(false);
  });

  it('reports backup problems and restores a hidden base from two points', async () => {
    const fake = new FakeBackend();
    const signed = await fake.signUp({ invite: 'invite', email: 'person@example.test', password: 'correct horse battery staple', deviceName: 'Mac' });
    const account = signed.account.id;
    const location = { kind: 'path' as const, path: '/tmp/BaseHero', label: 'Documents › BaseHero' };
    await fake.setBackup(account, location);
    await fake.backupNow(account);
    fake.setBackupFolderProblem(location, 'unreachable');
    await fake.backupNow(account);
    expect((await fake.backupStatus(account)).problem).toEqual({ kind: 'unreachable' });
    for (const problem of ['full', 'permissionLost'] as const) {
      fake.setBackupFolderProblem(location, problem);
      await fake.backupNow(account);
      expect((await fake.backupStatus(account)).problem).toEqual({ kind: problem });
    }
    fake.setBackupFolderProblem(location, null);
    await fake.backupNow(account);
    const [listing] = await fake.restoreList(location);
    const handle = await fake.restoreOpen(location, listing, 'correct horse battery staple', signed.kit);
    expect(await fake.restorePoints(handle)).toHaveLength(2);
    const at = (await fake.restorePoints(handle))[0];
    expect((await fake.restoreCheck(handle, at)).locked).toBe(1);
    await fake.restoreUnlock(handle, 'hidden password');
    const bases = await fake.restoreBases(handle, at);
    expect(bases.some(base => base.hidden)).toBe(true);
    expect((await fake.restoreCheck(handle, at)).ignoredFiles).toHaveLength(1);
    const summary = await fake.restoreInto(handle, account, at, bases.map(base => base.id), 'restored today');
    expect(summary.restored).toHaveLength(bases.length);
    await fake.restoreClose(handle);
    await expect(fake.restorePoints(handle)).rejects.toMatchObject({ kind: 'NotFound' });
  });
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

  it('mounts a folder, lists its contents in place, and moves items into it', async () => {
    const fake = new FakeBackend();
    const personal = await fake.createBase('account', 'Personal');
    const root = { account: 'account', base: personal.id };
    const folder = await fake.createObject(root, { kind: 'folder', name: 'Health', parent: null, after: null });
    const inside = await fake.createObject(root, { kind: 'note', name: 'Inside', parent: folder, after: null });
    const outside = await fake.createObject(root, { kind: 'note', name: 'Outside', parent: null, after: null });
    const mounted = await fake.grantFolder('account', personal.id, folder, 'Sample');
    expect((await fake.bases('account')).find(b => b.id === mounted)?.mount).toEqual({ base: mounted, parent: personal.id, folder });
    expect((await fake.treeChildren(root, null)).find(item => item.id === folder)).toMatchObject({ mounted, readers: ['Sample'] });
    expect(await fake.treeChildren(root, folder)).toMatchObject([{ id: inside, base: mounted }]);
    await fake.moveObject(root, outside, mounted, null, null);
    expect((await fake.treeChildren(root, folder)).map(item => item.id)).toEqual([inside, outside]);
    expect(await fake.locate(root, outside)).toBe(mounted);
    expect(await fake.movedFrom({ account: 'account', base: mounted }, outside)).toBe(personal.id);
    await fake.deleteObject({ account: 'account', base: mounted }, outside);
    expect(await fake.trash(root)).toMatchObject([{ id: outside, base: mounted }]);
  });

  it('rejects an unknown tree parent in the requested base', async () => {
    const fake = new FakeBackend();
    const personal = await fake.createBase('account', 'Personal');
    const health = await fake.createBase('account', 'Health');
    const folder = await fake.createObject({ account: 'account', base: health.id }, { kind: 'folder', name: 'Visits', parent: null, after: null });
    await expect(fake.treeChildren({ account: 'account', base: personal.id }, folder)).rejects.toMatchObject({ kind: 'NotFound' });
  });

  it('counts note sessions and echoes updates to other sessions only', async () => {
    const fake = new FakeBackend();
    const first = vi.fn();
    const second = vi.fn();
    const id = await fake.createObject(r, { kind: 'note', name: 'Note', parent: null, after: null });
    const a = await fake.noteOpen(r, id, first);
    const b = await fake.noteOpen(r, id, second);
    expect(fake.openSessions()).toBe(2);
    const doc = new Y.Doc();
    const paragraph = new Y.XmlElement('paragraph');
    paragraph.insert(0, [new Y.XmlText('Hello')]);
    doc.getXmlFragment('default').insert(0, [paragraph]);
    await fake.noteApply(a.session, Y.encodeStateAsUpdate(doc));
    expect(fake.noteText(id)).toBe('Hello');
    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledOnce();
    await fake.noteClose(a.session);
    await fake.noteClose(b.session);
    expect(fake.openSessions()).toBe(0);
  });

  it('opens folders and projects but rejects missing and non-note objects', async () => {
    const fake = new FakeBackend();
    for (const kind of ['folder', 'project'] as const) {
      const id = await fake.createObject(r, { kind, name: kind, parent: null, after: null });
      await fake.noteClose((await fake.noteOpen(r, id, () => {})).session);
    }
    await expect(fake.noteOpen(r, 'unknown', () => {})).rejects.toMatchObject({ kind: 'NotFound' });
    const chat = fake.remoteCreate(r, { kind: 'chat' as 'note', name: 'Chat', parent: null, after: null });
    await expect(fake.noteOpen(r, chat, () => {})).rejects.toMatchObject({ kind: 'Invalid' });
    expect(fake.openSessions()).toBe(0);
  });
});
