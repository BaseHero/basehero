import * as Y from 'yjs';
import { BackendError, type Backend, type AppEvent, type AppInfo, type AccountSummary, type SignUpForm, type SignInForm, type SignedUp, type DeviceSummary, type BaseSummary, type BaseRef, type NewItem, type ObjectSummary, type SearchResult, type SyncState, type NoteOpened, type UpdateInfo } from './types';

export class FakeBackend implements Backend {
  calls: string[] = [];
  private platform: AppInfo['platform'] | undefined; // else from ?platform=, or ?update for the Mac
  setPlatform(platform: AppInfo['platform']) { this.platform = platform; }
  private handlers = new Set<(event: AppEvent) => void>();
  private accountList: AccountSummary[] = [];
  private passwords = new Map<string, string>();
  private unsavedKits = new Set<string>();
  private kits = new Map<string, string>();
  private baseList = new Map<string, BaseSummary[]>();
  private deviceList = new Map<string, DeviceSummary[]>();
  private items = new Map<string, ObjectSummary[]>();
  private sync = new Map<string, SyncState>();
  private sessions = new Map<number, { id: string; onUpdate: (update: Uint8Array) => void }>();
  private notes = new Map<string, Y.Doc>();
  private newerNotes = new Set<string>();
  private channel = typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel('basehero-fake-notes');
  constructor() {
    this.channel?.addEventListener('message', ({ data }: MessageEvent<{ id: string; update: number[] }>) => {
      if (!data || typeof data.id !== 'string' || !Array.isArray(data.update)) return;
      const update = Uint8Array.from(data.update);
      Y.applyUpdate(this.doc(data.id), update);
      for (const session of this.sessions.values()) if (session.id === data.id) session.onUpdate(update);
    });
  }
  private doc(id: string): Y.Doc {
    let doc = this.notes.get(id);
    if (!doc) {
      doc = new Y.Doc();
      if (typeof localStorage !== 'undefined') {
        const saved = localStorage.getItem(`basehero:fake-note:${id}`);
        if (saved) Y.applyUpdate(doc, Uint8Array.from(JSON.parse(saved) as number[]));
      }
      this.notes.set(id, doc);
    }
    return doc;
  }
  seedNewerNote(id: string) { this.newerNotes.add(id); }
  private nextSession = 1;
  private nextId = 1;
  private log(method: string, first?: unknown) { this.calls.push(method + (typeof first === 'string' ? ` ${first}` : '')); }
  private key(r: BaseRef) { return `${r.account}:${r.base}`; }
  private id() { return (this.nextId++).toString(16).padStart(32, '0'); }
  emit(e: AppEvent) {
    if (e.kind.toLowerCase() === 'account' && e.event === 'Removed') {
      this.accountList = this.accountList.filter(account => account.id !== e.account);
      this.kits.delete(e.account);
      this.passwords.delete(e.account);
      this.baseList.delete(e.account);
      this.deviceList.delete(e.account);
      for (const [key, items] of this.items) if (key.startsWith(`${e.account}:`)) {
        for (const item of items) this.notes.delete(item.id);
        this.items.delete(key);
      }
      for (const key of this.sync.keys()) if (key.startsWith(`${e.account}:`)) this.sync.delete(key);
    }
    for (const handler of this.handlers) handler(e);
  }
  setDevices(account: string, devices: DeviceSummary[]) { this.deviceList.set(account, [...devices]); }
  setSync(r: BaseRef, s: SyncState) { this.sync.set(this.key(r), s); this.emit({ kind: 'base', account: r.account, base: r.base, event: { sync: s } }); }
  remoteCreate(r: BaseRef, item: NewItem) { const id = this.addItem(r, item); this.emit({ kind: 'base', account: r.account, base: r.base, event: { objectsChanged: [id] } }); return id; }
  noteText(id: string): string {
    const text = (nodes: (Y.XmlElement | Y.XmlText | Y.XmlHook)[]): string => nodes.map(node =>
      node instanceof Y.XmlElement ? text(node.toArray()) : node.toString()
    ).join('');
    return text(this.doc(id).getXmlFragment('default').toArray());
  }
  openSessions(): number { return this.sessions.size; }
  private addItem(r: BaseRef, item: NewItem) { const id = this.id(); const list = this.items.get(this.key(r)) ?? []; list.push({ id, title: item.name ?? '', parent: item.parent, deleted: false, kind: item.kind }); this.items.set(this.key(r), list); return id; }
  async appInfo(): Promise<AppInfo> {
    this.log('appInfo');
    const params = new URLSearchParams(location.search);
    const platform = this.platform ?? (params.get('platform') ?? (params.has('update') ? 'macos' : 'linux')) as AppInfo['platform'];
    return { version: '0.1.0', server: 'https://dev-api.basehero.com', platform };
  }
  async accounts() { this.log('accounts'); if (new URLSearchParams(location.search).has('keyError')) throw new BackendError('KeyUnavailable', 'Keychain status -25308'); return [...this.accountList]; }
  async signUp(form: SignUpForm): Promise<SignedUp> { this.log('signUp'); const account: AccountSummary = { id: this.id(), email: form.email, kind: 'full' }; this.accountList.push(account); this.deviceList.set(account.id, [{ id: this.id(), name: form.deviceName, kind: 'Mac', status: 'active', thisDevice: true, createdAt: Date.now(), lastSeenAt: Date.now() }]); this.passwords.set(account.id, form.password); this.unsavedKits.add(account.id); const kit = '7KQ2-M9XD-4F8P-2L6R-V3TN-H5YA-ZC'; this.kits.set(account.id, kit); return { account, kit }; }
  async signInStart(form: SignInForm) { this.log('signInStart'); return form.email; }
  async signInWithKit(pending: string, kit: string) { this.log('signInWithKit'); const existing = this.accountList.find(a => a.email === pending); if (kit !== (existing ? this.kits.get(existing.id) : '7KQ2-M9XD-4F8P-2L6R-V3TN-H5YA-ZC')) throw new BackendError('BadKit', 'Bad kit'); if (existing) return existing; const account: AccountSummary = { id: this.id(), email: pending, kind: 'full' }; this.accountList.push(account); this.passwords.set(account.id, 'correct horse battery staple'); this.kits.set(account.id, kit); return account; }
  async signInCancel(pending: string) { this.log('signInCancel', pending); }
  async signOut(account: string) { this.log('signOut', account); this.accountList = this.accountList.filter(a => a.id !== account); }
  async newKit(account: string, password: string): Promise<string> {
    this.log('newKit', account);
    if (this.passwords.get(account) !== password) throw new BackendError('BadCredentials', 'Wrong password');
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const bytes = crypto.getRandomValues(new Uint8Array(26));
    const characters = Array.from(bytes, byte => alphabet[byte % alphabet.length]).join('');
    const kit = characters.match(/.{1,4}/g)!.join('-');
    this.kits.set(account, kit);
    this.unsavedKits.add(account);
    return kit;
  }
  async kitSaved(account: string) { this.log('kitSaved', account); return !this.unsavedKits.has(account); }
  async setKitSaved(account: string) { this.log('setKitSaved', account); this.unsavedKits.delete(account); }
  async devices(account: string): Promise<DeviceSummary[]> { this.log('devices', account); return [...(this.deviceList.get(account) ?? [])]; }
  async removeDevice(account: string, device: string) {
    this.log('removeDevice', device);
    const mine = this.deviceList.get(account)?.find(item => item.id === device)?.thisDevice;
    this.deviceList.set(account, (this.deviceList.get(account) ?? []).filter(item => item.id !== device));
    this.emit({ kind: 'account', account, event: mine ? 'Removed' : 'DevicesChanged' });
  }
  async bases(account: string) { this.log('bases', account); return [...(this.baseList.get(account) ?? [])]; }
  async createBase(account: string, name: string) { this.log('createBase', account); const base: BaseSummary = { id: this.id(), name, mode: 'readWrite' }; this.baseList.set(account, [...(this.baseList.get(account) ?? []), base]); return base; }
  async children(r: BaseRef, parent: string | null) { this.log('children', r); return (this.items.get(this.key(r)) ?? []).filter(x => x.parent === parent && !x.deleted); }
  async getObject(r: BaseRef, id: string) { this.log('getObject', r); return this.items.get(this.key(r))?.find(x => x.id === id) ?? null; }
  async createObject(r: BaseRef, item: NewItem) { this.log('createObject', r); const id = this.addItem(r, item); this.emit({ kind: 'base', account: r.account, base: r.base, event: { objectsChanged: [id] } }); return id; }
  async renameObject(r: BaseRef, id: string, name: string) { this.log('renameObject', r); const object = await this.getObject(r, id); if (!object) throw new BackendError('NotFound', 'Object not found'); object.title = name; }
  async moveObject(r: BaseRef, id: string, parent: string | null, _after: string | null) { this.log('moveObject', r); const object = await this.getObject(r, id); if (!object) throw new BackendError('NotFound', 'Object not found'); object.parent = parent; }
  async deleteObject(r: BaseRef, id: string) { this.log('deleteObject', r); const object = await this.getObject(r, id); if (object) object.deleted = true; }
  async restoreObject(r: BaseRef, id: string) { this.log('restoreObject', r); const object = await this.getObject(r, id); if (object) object.deleted = false; }
  async trash(r: BaseRef) { this.log('trash', r); return (this.items.get(this.key(r)) ?? []).filter(x => x.deleted); }
  async search(account: string, base: string, text: string, limit: number): Promise<SearchResult[]> { this.log('search', account); return (this.items.get(this.key({ account, base })) ?? []).filter(x => !x.deleted && x.title.toLowerCase().includes(text.toLowerCase())).slice(0, limit).map(x => ({ base, baseName: this.baseList.get(account)?.find(b => b.id === base)?.name ?? '', hit: { id: x.id, ty: x.kind as 'note' | 'folder' | 'project', title: x.title, snippet: '' } })); }
  async syncState(r: BaseRef) { this.log('syncState', r); return this.sync.get(this.key(r)) ?? { pending: 0, online: true, lastSyncedAt: null }; }
  async noteOpen(r: BaseRef, note: string, onUpdate: (update: Uint8Array) => void): Promise<NoteOpened> {
    this.log('noteOpen', r);
    const object = await this.getObject(r, note);
    if (!object) throw new BackendError('NotFound', 'Object not found');
    const kind = (object.ty as { name?: string } | undefined)?.name ?? `core.${object.kind}`;
    if (!['core.note', 'core.folder', 'core.project'].includes(kind)) throw new BackendError('Invalid', 'Not a note, folder or project');
    const session = this.nextSession++;
    this.sessions.set(session, { id: note, onUpdate });
    return { session, state: Y.encodeStateAsUpdate(this.doc(note)), readOnly: this.newerNotes.has(note) };
  }
  async noteApply(session: number, update: Uint8Array) { this.log('noteApply', session); const entry = this.sessions.get(session); if (!entry) throw new BackendError('NotFound', 'Session not found'); const doc = this.doc(entry.id); Y.applyUpdate(doc, update);
    if (typeof localStorage !== 'undefined') localStorage.setItem(`basehero:fake-note:${entry.id}`, JSON.stringify(Array.from(Y.encodeStateAsUpdate(doc))));
    this.channel?.postMessage({ id: entry.id, update: Array.from(update) });
    for (const [id, other] of this.sessions) if (id !== session && other.id === entry.id) other.onUpdate(update); }
  async noteClose(session: number) { this.log('noteClose', session); this.sessions.delete(session); }
  async openWindow(route: string) { this.log('openWindow', route); }
  async updateCheck(): Promise<UpdateInfo | null> { this.log('updateCheck'); const version = new URLSearchParams(location.search).get('update'); return version ? { version, notes: `BaseHero ${version}` } : null; }
  async updateInstall() { this.log('updateInstall'); }
  async openExternal(url: string) { this.log('openExternal', url); if (!/^https?:\/\//.test(url)) throw new BackendError('Invalid', 'Only HTTP(S) links are allowed'); }
  async onEvent(handler: (event: AppEvent) => void) { this.log('onEvent'); this.handlers.add(handler); return () => { this.handlers.delete(handler); }; }
}
