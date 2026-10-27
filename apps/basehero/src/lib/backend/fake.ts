import * as Y from 'yjs';
import { BackendError, type Backend, type KitStatus, type AppEvent, type AppInfo, type AccountSummary, type SignUpForm, type SignInForm, type SignedUp, type ApprovalRequest, type OpenedRequest, type DeviceSummary, type BaseSummary, type BaseRef, type NewItem, type ObjectSummary, type SearchResult, type SyncState, type NoteOpened, type UpdateInfo, type ChatMessage, type ChatSummary, type PasswordStrength, type AccountUsage, type UsageRow, type FileInfo, type FileStatus, type FileImage } from './types';

export class FakeBackend implements Backend {
  calls: string[] = [];
  private platform: AppInfo['platform'] | undefined; // else from ?platform=, or ?update for the Mac
  setPlatform(platform: AppInfo['platform']) { this.platform = platform; }
  private handlers = new Set<(event: AppEvent) => void>();
  private accountList: AccountSummary[] = [];
  private keyUnavailable = typeof location !== 'undefined' && new URLSearchParams(location.search).has('keyError');
  private passwords = new Map<string, string>();
  private kitStates = new Map<string, KitStatus>();
  private kits = new Map<string, string>();
  // Model the shell's asynchronous platform save separately from account acknowledgement.
  private storedOnAndroid = typeof location !== 'undefined' && new URLSearchParams(location.search).get('kitStored') === '1';
  private delayedKitSave = typeof location !== 'undefined' && new URLSearchParams(location.search).get('kitSaveDelayed') === '1';
  private storedKits = new Map<string, string>();
  private pendingKitSaves = new Map<string, string>();
  private scheduleKitSave(account: string) {
    if (this.platform !== 'android' || (!this.storedOnAndroid && !this.delayedKitSave)) return;
    const kit = this.kits.get(account);
    if (!kit) return;
    this.pendingKitSaves.set(account, kit);
    if (!this.delayedKitSave) queueMicrotask(() => this.completeKitSave(account));
  }
  completeKitSave(account: string) {
    const kit = this.pendingKitSaves.get(account);
    if (!kit) return;
    this.pendingKitSaves.delete(account);
    this.storedKits.set(account, kit);
    this.emit({ kind: 'kitChanged', account, event: null });
  }
  seedOlderAccount(account: string) {
    this.kits.delete(account);
    this.kitStates.delete(account);
  }
  private baseList = new Map<string, BaseSummary[]>();
  private hiddenList = new Map<string, { base: BaseSummary; password: string; open: boolean }[]>();
  private hiddenChannel = typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel('basehero-fake-hidden');
  private deviceList = new Map<string, DeviceSummary[]>();
  private usageList = new Map<string, AccountUsage>();
  private usageDays = new Map<string, UsageRow[]>();
  private approvalList = new Map<string, ApprovalRequest[]>();
  private approvalDigitsValues = new Map<string, string>();
  private digitWaiters = new Map<string, (digits: string) => void>();
  private approvalWaiters = new Map<string, { resolve: (account: AccountSummary) => void; reject: (error: BackendError) => void }>();
  private approvalsDone = new Map<string, AccountSummary>();
  private items = new Map<string, ObjectSummary[]>();
  private fileData = new Map<string, { r: BaseRef; info: FileInfo; bytes: Uint8Array }>();
  private sync = new Map<string, SyncState>();
  private sessions = new Map<number, { id: string; onUpdate: (update: Uint8Array) => void }>();
  private notes = new Map<string, Y.Doc>();
  private heroChatsByBase = new Map<string, ChatSummary[]>();
  private heroByProject = new Map<string, string>();
  private heroMessagesByChat = new Map<string, ChatMessage[]>();
  heroSends: { account: string; base: string; chat: string; text: string; focus: string | null }[] = [];
  heroAnswers: { account: string; base: string; chat: string; allow: boolean }[] = [];
  private newerNotes = new Set<string>();
  private channel = typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel('basehero-fake-notes');
  constructor() {
    this.hiddenChannel?.addEventListener('message', ({ data }: MessageEvent<{ action: 'lock' | 'lockAll'; account?: string; base?: string }>) => {
      if (data.action === 'lockAll') void this.lockAllHidden(false);
      else if (data.account && data.base) void this.lockHidden(data.account, data.base, false);
    });
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
    if (e.kind.toLowerCase() === 'account' && typeof e.event === 'object' && e.event !== null && 'ApprovalClosed' in e.event) {
      const closed = e.event.ApprovalClosed;
      this.approvalList.set(e.account, (this.approvalList.get(e.account) ?? []).filter(r => r.id !== closed));
    }
    if (e.kind.toLowerCase() === 'account' && e.event === 'Removed') {
      this.accountList = this.accountList.filter(account => account.id !== e.account);
      this.kits.delete(e.account);
      this.kitStates.delete(e.account);
      this.storedKits.delete(e.account);
      this.passwords.delete(e.account);
      this.baseList.delete(e.account);
      this.hiddenList.delete(e.account);
      for (const key of this.heroByProject.keys()) if (key.startsWith(`${e.account}:`)) this.heroByProject.delete(key);
      for (const key of this.heroChatsByBase.keys()) if (key.startsWith(`${e.account}:`)) this.heroChatsByBase.delete(key);
      for (const key of this.heroMessagesByChat.keys()) if (key.startsWith(`${e.account}:`)) this.heroMessagesByChat.delete(key);
      this.deviceList.delete(e.account);
      this.usageList.delete(e.account);
      for (const key of this.usageDays.keys()) if (key.startsWith(`${e.account}:`)) this.usageDays.delete(key);
      for (const [key, items] of this.items) if (key.startsWith(`${e.account}:`)) {
        for (const item of items) this.notes.delete(item.id);
        this.items.delete(key);
      }
      for (const key of this.sync.keys()) if (key.startsWith(`${e.account}:`)) this.sync.delete(key);
      for (const [id, entry] of this.fileData) if (entry.r.account === e.account) this.fileData.delete(id);
    }
    for (const handler of this.handlers) handler(e);
  }
  addApprovalRequest(account: string, request: ApprovalRequest) { this.approvalList.set(account, [...(this.approvalList.get(account) ?? []), request]); }
  setApprovalDigits(pending: string, digits: string) { this.approvalDigitsValues.set(pending, digits); this.digitWaiters.get(pending)?.(digits); this.digitWaiters.delete(pending); }
  completeApproval(pending: string) { const account = this.installPending(pending); this.approvalsDone.set(pending, account); this.approvalWaiters.get(pending)?.resolve(account); this.approvalWaiters.delete(pending); }
  endApproval(pending: string, reason: string) { this.approvalWaiters.get(pending)?.reject(new BackendError('ApprovalEnded', reason)); this.approvalWaiters.delete(pending); }
  private installPending(pending: string): AccountSummary {
    let account = this.accountList.find(a => a.email === pending);
    if (!account) { account = { id: this.id(), email: pending, kind: 'full' }; this.accountList.push(account); }
    return account;
  }
  seedHeroChat(account: string, base: string, project: string | null, chat: string) {
    this.heroByProject.set(`${account}:${base}:${project ?? ''}`, chat);
    this.heroChatsByBase.set(`${account}:${base}`, [{ id: chat, title: 'Hero', project, updatedAt: Date.now() }]);
  }
  seedHeroMessages(account: string, base: string, chat: string, messages: ChatMessage[]) {
    this.heroMessagesByChat.set(`${account}:${base}:${chat}`, [...messages]);
  }
  private heroKey(account: string, base: string, chat: string) { return `${account}:${base}:${chat}`; }
  private heroChanged(account: string, base: string, chat: string) {
    this.emit({ kind: 'hero', account, base, chat, event: { changed: { base, chat } } });
  }
  async heroChats(account: string, base: string) { this.log('heroChats', account); return [...(this.heroChatsByBase.get(`${account}:${base}`) ?? [])]; }
  async heroChatFor(account: string, base: string, project: string | null) {
    this.log('heroChatFor', account);
    const key = `${account}:${base}:${project ?? ''}`;
    return this.heroByProject.get(key) ?? this.heroNewChat(account, base, project);
  }
  async heroNewChat(account: string, base: string, project: string | null = null) {
    this.log('heroNewChat', account);
    const chat = this.id(); this.seedHeroChat(account, base, project, chat); return chat;
  }
  async heroMessages(account: string, base: string, chat: string) {
    this.log('heroMessages', account); return [...(this.heroMessagesByChat.get(this.heroKey(account, base, chat)) ?? [])];
  }
  async heroSend(account: string, base: string, chat: string, text: string, focus: string | null) {
    this.log('heroSend', account); this.heroSends.push({ account, base, chat, text, focus });
    const key = this.heroKey(account, base, chat), messages = this.heroMessagesByChat.get(key) ?? [];
    const at = new Date().toISOString();
    const id = this.id();
    messages.push({ id, role: 'user', text, at, state: 'done', error: null, steps: [], created: [], ask: null },
      { id: this.id(), role: 'hero', text: '', at, state: 'working', error: null, steps: [], created: [], ask: null });
    this.heroMessagesByChat.set(key, messages); this.heroChanged(account, base, chat); return id;
  }
  async heroStop(account: string, base: string, chat: string) {
    this.log('heroStop', account);
    const messages = this.heroMessagesByChat.get(this.heroKey(account, base, chat)) ?? [];
    const last = messages.at(-1); if (last?.state === 'working') last.state = 'stopped';
    this.heroChanged(account, base, chat);
  }
  async heroAnswer(account: string, base: string, chat: string, allow: boolean) {
    this.log('heroAnswer', account); this.heroAnswers.push({ account, base, chat, allow });
    const last = this.heroMessagesByChat.get(this.heroKey(account, base, chat))?.at(-1);
    if (last?.state === 'asking') { last.state = allow ? 'working' : 'stopped'; last.ask = null; }
    this.heroChanged(account, base, chat);
  }
  async heroRetry(account: string, base: string, chat: string) {
    this.log('heroRetry', account);
    const last = this.heroMessagesByChat.get(this.heroKey(account, base, chat))?.at(-1);
    if (last?.state === 'failed') { last.state = 'working'; last.error = null; }
    this.heroChanged(account, base, chat);
  }
  setDevices(account: string, devices: DeviceSummary[]) { this.deviceList.set(account, [...devices]); }
  seedUsage(account: string, usage: AccountUsage) { this.usageList.set(account, usage); }
  seedUsageDays(account: string, month: string, days: UsageRow[]) { this.usageDays.set(`${account}:${month}`, days); }
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
    this.platform = platform;
    return { version: '0.1.0', server: 'https://dev-api.basehero.com', platform };
  }
  async accounts() { this.log('accounts'); if (this.keyUnavailable) throw new BackendError('KeyUnavailable', 'Keychain status -25308'); return [...this.accountList]; }
  async resetDevice() { this.log('resetDevice'); if (!this.keyUnavailable) throw new BackendError('Invalid', 'No key error'); this.keyUnavailable = false; this.accountList = []; }
  async signUp(form: SignUpForm): Promise<SignedUp> { this.log('signUp'); const account: AccountSummary = { id: this.id(), email: form.email, kind: 'full' }; this.accountList.push(account); this.deviceList.set(account.id, [{ id: this.id(), name: form.deviceName, kind: 'Mac', status: 'active', thisDevice: true, createdAt: Date.now(), lastSeenAt: Date.now() }]); this.passwords.set(account.id, form.password); this.kitStates.set(account.id, { known: true, saved: false, madeAt: Date.now() }); const kit = '7KQ2-M9XD-4F8P-2L6R-V3TN-H5YA-ZC'; this.kits.set(account.id, kit); this.scheduleKitSave(account.id); return { account, kit };  }
  async signInStart(form: SignInForm) { this.log('signInStart'); return form.email; }
  async signInSavedKit(_pending: string): Promise<AccountSummary | null> { this.log('signInSavedKit'); return null; }
  async signInWithKit(pending: string, kit: string) { this.log('signInWithKit'); const existing = this.accountList.find(a => a.email === pending); if (kit !== (existing ? this.kits.get(existing.id) : '7KQ2-M9XD-4F8P-2L6R-V3TN-H5YA-ZC')) throw new BackendError('BadKit', 'Bad kit'); if (existing) return existing; const account: AccountSummary = { id: this.id(), email: pending, kind: 'full' }; this.accountList.push(account); this.passwords.set(account.id, 'correct horse battery staple'); this.kits.set(account.id, kit); this.kitStates.set(account.id, { known: true, saved: true, madeAt: Date.now() }); return account; }
  async signInCancel(pending: string) { this.log('signInCancel', pending); }
  async approvalStart(pending: string) { this.log('approvalStart', pending); return this.id(); }
  async approvalDigits(pending: string) { this.log('approvalDigits', pending); return this.approvalDigitsValues.get(pending) ?? new Promise<string>(resolve => this.digitWaiters.set(pending, resolve)); }
  async approvalWait(pending: string) { this.log('approvalWait', pending); return this.approvalsDone.get(pending) ?? new Promise<AccountSummary>((resolve, reject) => this.approvalWaiters.set(pending, { resolve, reject })); }
  async approvalCancel(pending: string) { this.log('approvalCancel', pending); this.digitWaiters.delete(pending); this.approvalWaiters.delete(pending); }
  async approvalUseKit(pending: string, kit: string) { this.log('approvalUseKit', pending); return this.signInWithKit(pending, kit); }
  async approvalRequests(account: string) { this.log('approvalRequests', account); return [...(this.approvalList.get(account) ?? [])]; }
  async approvalOpen(account: string, id: string): Promise<OpenedRequest> { this.log('approvalOpen', account); if (!this.approvalList.get(account)?.some(r => r.id === id)) throw new BackendError('NotFound', 'Not found'); return { id }; }
  async approvalApprove(account: string, id: string, digits: string) { this.log('approvalApprove', account); if (!/^\d{6}$/.test(digits.replace(/[ -]/g, ''))) throw new BackendError('Invalid', 'Invalid digits'); this.approvalList.set(account, (this.approvalList.get(account) ?? []).filter(r => r.id !== id)); return this.id(); }
  async approvalDecline(account: string, id: string) { this.log('approvalDecline', account); this.approvalList.set(account, (this.approvalList.get(account) ?? []).filter(r => r.id !== id)); this.emit({ kind: 'account', account, event: { ApprovalClosed: id } }); }
  async signOut(account: string) { this.log('signOut', account); this.accountList = this.accountList.filter(a => a.id !== account); }
  async newKit(account: string, password: string): Promise<string> {
    this.log('newKit', account);
    if (this.passwords.get(account) !== password) throw new BackendError('BadCredentials', 'Wrong password');
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const bytes = crypto.getRandomValues(new Uint8Array(26));
    const characters = Array.from(bytes, byte => alphabet[byte % alphabet.length]).join('');
    const kit = characters.match(/.{1,4}/g)!.join('-');
    this.kits.set(account, kit);
    this.kitStates.set(account, { known: true, saved: false, madeAt: Date.now() });
    this.scheduleKitSave(account);
    return kit;
  }
  async kitStatus(account: string) { this.log('kitStatus', account); return this.kitStates.get(account) ?? { known: false, saved: false, madeAt: null }; }
  async kitKeptHere(account: string) { this.log('kitKeptHere', account); return !!this.kits.get(account) && this.storedKits.get(account) === this.kits.get(account); }
  async showKit(account: string) { this.log('showKit', account); const kit = this.kits.get(account); if (!kit) throw new BackendError('NotFound', 'Kit not found'); return kit; }
  async setKitSaved(account: string, kit: string) { this.log('setKitSaved', account); const status = this.kitStates.get(account); if (!status?.known) throw new BackendError('NotFound', 'Kit not found'); if (this.kits.get(account) !== kit) throw new BackendError('Conflict', 'kit_changed'); this.kitStates.set(account, { ...status, saved: true }); }
  async devices(account: string): Promise<DeviceSummary[]> { this.log('devices', account); return [...(this.deviceList.get(account) ?? [])]; }
  async usage(account: string, month: string | null): Promise<AccountUsage> {
    this.log('usage', month ?? 'current');
    const selected = month ?? new Date().toISOString().slice(0, 7);
    const report = this.usageList.get(account) ?? { months: [], days: [], baseNames: {}, deviceNames: {} };
    return { ...report, days: this.usageDays.get(`${account}:${selected}`) ?? report.days.filter(row => row.period.startsWith(`${selected}-`)) };
  }
  async removeDevice(account: string, device: string) {
    this.log('removeDevice', device);
    const mine = this.deviceList.get(account)?.find(item => item.id === device)?.thisDevice;
    this.deviceList.set(account, (this.deviceList.get(account) ?? []).filter(item => item.id !== device));
    this.emit({ kind: 'account', account, event: mine ? 'Removed' : 'DevicesChanged' });
  }
  async bases(account: string) { this.log('bases', account); return [...(this.baseList.get(account) ?? []), ...(this.hiddenList.get(account) ?? []).filter(entry => entry.open).map(entry => entry.base)]; }
  async createBase(account: string, name: string) { this.log('createBase', account); const base: BaseSummary = { id: this.id(), name, mode: 'readWrite', hidden: false }; this.baseList.set(account, [...(this.baseList.get(account) ?? []), base]); this.emit({ kind: 'account', account, event: 'BasesChanged' }); return base; }
  async createHiddenBase(account: string, name: string, password: string) {
    this.log('createHiddenBase', account);
    if (!name.trim() || !password) throw new BackendError('Invalid', 'Invalid hidden base');
    const base: BaseSummary = { id: this.id(), name, mode: 'readWrite', hidden: true };
    this.hiddenList.set(account, [...(this.hiddenList.get(account) ?? []), { base, password: password.normalize('NFKC'), open: true }]);
    this.emit({ kind: 'account', account, event: 'BasesChanged' });
    return base;
  }
  async unlockHidden(account: string, password: string) {
    this.log('unlockHidden', account);
    const matching = (this.hiddenList.get(account) ?? []).filter(entry => entry.password === password.normalize('NFKC'));
    if (!matching.length) throw new BackendError('NothingUnlocked', 'Nothing unlocked');
    const changed = matching.some(entry => !entry.open);
    matching.forEach(entry => entry.open = true);
    if (changed) this.emit({ kind: 'account', account, event: 'BasesChanged' });
    return matching.map(entry => entry.base);
  }
  async lockHidden(account: string, base: string, broadcast = true) {
    this.log('lockHidden', account);
    const entry = this.hiddenList.get(account)?.find(entry => entry.base.id === base && entry.open);
    if (!entry) { if (broadcast) throw new BackendError('NotFound', 'Not found'); return; }
    entry.open = false;
    this.emit({ kind: 'account', account, event: 'BasesChanged' });
    if (broadcast) this.hiddenChannel?.postMessage({ action: 'lock', account, base });
  }
  async lockAllHidden(broadcast = true) {
    this.log('lockAllHidden');
    for (const [account, entries] of this.hiddenList) {
      if (!entries.some(entry => entry.open)) continue;
      entries.forEach(entry => entry.open = false);
      this.emit({ kind: 'account', account, event: 'BasesChanged' });
    }
    if (broadcast) this.hiddenChannel?.postMessage({ action: 'lockAll' });
  }
  async passwordStrength(password: string, context: string[]): Promise<PasswordStrength> {
    this.log('passwordStrength');
    const weak = /password|123|basehero/i.test(password) || context.some(word => word && password.toLowerCase().includes(word.toLowerCase()));
    const score = weak || password.length < 10 ? 1 : password.length < 16 ? 2 : password.length < 22 ? 3 : 4;
    return { score, strong: score === 4, warning: weak ? 'This is an easy password to guess.' : null, suggestions: weak ? ['Try a few unrelated words.'] : [] };
  }
  async refreshAccount(account: string) { this.log('refreshAccount', account); this.emit({ kind: 'kitChanged', account, event: null }); this.scheduleKitSave(account); }
  async fileAdd(r: BaseRef, parent: string | null, name: string, mime: string, bytes: Uint8Array): Promise<FileInfo> {
    this.log('fileAdd', r.account);
    if (bytes.length > 104_857_600) throw new BackendError('TooLarge', 'File is too large');
    const id = this.id();
    const info: FileInfo = { id, parent, name, mime, size: bytes.length, status: { kind: 'here' } };
    this.fileData.set(id, { r: { ...r }, info, bytes: bytes.slice() });
    const list = this.items.get(this.key(r)) ?? [];
    list.push({ id, title: name, parent, deleted: false, ty: { name: 'core.file', version: 1 } });
    this.items.set(this.key(r), list);
    this.emit({ kind: 'base', account: r.account, base: r.base, event: { filesChanged: [id] } });
    return { ...info };
  }
  setFileStatus(id: string, status: FileStatus) {
    const file = this.fileData.get(id);
    if (!file) throw new BackendError('NotFound', 'File not found');
    file.info.status = status;
    this.emit({ kind: 'base', account: file.r.account, base: file.r.base, event: { filesChanged: [id] } });
  }
  async files(r: BaseRef, parent: string | null): Promise<FileInfo[]> {
    this.log('files', r.account);
    return (this.items.get(this.key(r)) ?? []).filter(item => item.parent === parent && !item.deleted)
      .flatMap(item => { const file = this.fileData.get(item.id); return file ? [{ ...file.info }] : []; });
  }
  async fileInfo(r: BaseRef, id: string): Promise<FileInfo | null> {
    this.log('fileInfo', r.account);
    const file = this.fileData.get(id);
    return file && this.key(file.r) === this.key(r) && !this.items.get(this.key(r))?.find(item => item.id === id)?.deleted ? { ...file.info } : null;
  }
  async fileImage(r: BaseRef, id: string): Promise<FileImage> {
    this.log('fileImage', r.account);
    const file = this.fileData.get(id);
    if (!file || !await this.fileInfo(r, id)) throw new BackendError('NotFound', 'File not found');
    if (file.info.status.kind !== 'here') throw new BackendError('NotFound', 'File not on this device');
    const signature = [137, 80, 78, 71, 13, 10, 26, 10];
    if (!signature.every((byte, index) => file.bytes[index] === byte)) throw new BackendError('Invalid', 'Not an image');
    return { mime: 'image/png', bytes: file.bytes.slice() };
  }
  async fileOpen(r: BaseRef, id: string): Promise<void> {
    this.log('fileOpen', r.account);
    const file = this.fileData.get(id);
    if (!file || !await this.fileInfo(r, id) || file.info.status.kind !== 'here') throw new BackendError('NotFound', 'File not on this device');
  }
  async children(r: BaseRef, parent: string | null) { this.log('children', r); return (this.items.get(this.key(r)) ?? []).filter(x => x.parent === parent && !x.deleted); }
  async getObject(r: BaseRef, id: string) { this.log('getObject', r); return this.items.get(this.key(r))?.find(x => x.id === id) ?? null; }
  async createObject(r: BaseRef, item: NewItem) { this.log('createObject', r); const id = this.addItem(r, item); this.emit({ kind: 'base', account: r.account, base: r.base, event: { objectsChanged: [id] } }); return id; }
  async renameObject(r: BaseRef, id: string, name: string) { this.log('renameObject', r); const object = await this.getObject(r, id); if (!object) throw new BackendError('NotFound', 'Object not found'); object.title = name; }
  async moveObject(r: BaseRef, id: string, parent: string | null, _after: string | null) { this.log('moveObject', r); const object = await this.getObject(r, id); if (!object) throw new BackendError('NotFound', 'Object not found'); object.parent = parent; }
  async deleteObject(r: BaseRef, id: string) { this.log('deleteObject', r); const object = await this.getObject(r, id); if (object) object.deleted = true; }
  async restoreObject(r: BaseRef, id: string) { this.log('restoreObject', r); const object = await this.getObject(r, id); if (object) object.deleted = false; }
  async trash(r: BaseRef) { this.log('trash', r); return (this.items.get(this.key(r)) ?? []).filter(x => x.deleted); }
  async search(account: string, base: string | null, text: string, limit: number): Promise<SearchResult[]> {
    this.log('search', account);
    if (limit <= 0) return [];
    const bases = [...(this.baseList.get(account) ?? []), ...(this.hiddenList.get(account) ?? []).filter(entry => entry.open).map(entry => entry.base)];
    const ordered = base ? [...bases].sort((a, b) => Number(b.id === base) - Number(a.id === base)) : bases;
    const results: SearchResult[] = [];
    for (const entry of ordered) {
      for (const item of this.items.get(this.key({ account, base: entry.id })) ?? []) {
        if (item.deleted || !item.title.toLowerCase().includes(text.toLowerCase())) continue;
        results.push({ base: entry.id, baseName: entry.name, hit: {
          id: item.id, ty: { name: `core.${item.kind}`, version: 1 }, title: item.title, snippet: '',
        } });
        if (results.length >= limit) return results;
      }
    }
    return results;
  }
  async syncState(r: BaseRef) { this.log('syncState', r); return this.sync.get(this.key(r)) ?? { pending: 0, online: true, lastSyncedAt: null }; }
  async noteOpen(r: BaseRef, note: string, onUpdate: (update: Uint8Array) => void): Promise<NoteOpened> {
    this.log('noteOpen', r);
    const object = await this.getObject(r, note);
    if (!object) throw new BackendError('NotFound', 'Object not found');
    const kind = (object.ty as { name?: string } | undefined)?.name ?? `core.${object.kind}`;
    if (!['core.note', 'core.folder', 'core.project'].includes(kind)) throw new BackendError('Invalid', 'Not a note, folder or project');
    if (this.newerNotes.has(note)) throw new BackendError('NeedsUpdate', 'Note requires a newer version');
    const session = this.nextSession++;
    this.sessions.set(session, { id: note, onUpdate });
    return { session, state: Y.encodeStateAsUpdate(this.doc(note)), readOnly: false };
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
