// Core summaries are structural until foundation generates the shared bindings.
import type { AppInfo } from '../generated/AppInfo';
import type { CommandError } from '../generated/CommandError';
import type { UpdateInfo } from '../generated/UpdateInfo';
export type { AppInfo, CommandError, UpdateInfo };
export type AccountId = string;
export type BaseId = string;
export type ObjectId = string;
export type DeviceId = string;
export type BaseRef = { account: AccountId; base: BaseId };
export class BackendError extends Error {
  constructor(public kind: string, message: string) { super(message); this.name = 'BackendError'; }
}
export type AccountSummary = { id: AccountId; email: string; kind: 'full' | 'app' };
export type DeviceSummary = { id: DeviceId; name: string; kind: string; status: string; thisDevice: boolean; createdAt: number; lastSeenAt: number | null };
export type BaseSummary = { id: BaseId; name: string; mode: 'readWrite' | 'readOnly' };
export type ObjectSummary = { id: ObjectId; title: string; parent: ObjectId | null; deleted: boolean; [key: string]: unknown };
export type ItemKind = 'note' | 'folder' | 'project';
export type NewItem = { kind: ItemKind; parent: ObjectId | null; after: ObjectId | null; name: string | null };
export type SyncState = { pending: number; online: boolean; lastSyncedAt: number | null };
export type SearchResult = { base: BaseId; baseName: string; hit: { id: ObjectId; ty: ItemKind; title: string; snippet: string } };
export type AppEvent = { kind: 'account' | 'base' | 'hero' | 'Account' | 'Base' | 'Hero'; account: AccountId; base?: BaseId; chat?: ObjectId; event: unknown };
export type NoteOpened = { session: number; state: Uint8Array; readOnly: boolean };
export type SignUpForm = { invite: string; email: string; password: string; deviceName: string };
export type SignInForm = { email: string; password: string; deviceName: string };
export type SignedUp = { account: AccountSummary; kit: string };

export interface Backend {
  appInfo(): Promise<AppInfo>;
  accounts(): Promise<AccountSummary[]>;
  signUp(form: SignUpForm): Promise<SignedUp>;
  signInStart(form: SignInForm): Promise<string>;
  signInWithKit(pending: string, kit: string): Promise<AccountSummary>;
  signInCancel(pending: string): Promise<void>;
  signOut(account: AccountId): Promise<void>;
  newKit(account: AccountId, password: string): Promise<string>;
  kitSaved(account: AccountId): Promise<boolean>;
  setKitSaved(account: AccountId): Promise<void>;
  devices(account: AccountId): Promise<DeviceSummary[]>;
  removeDevice(account: AccountId, device: DeviceId): Promise<void>;
  bases(account: AccountId): Promise<BaseSummary[]>;
  createBase(account: AccountId, name: string): Promise<BaseSummary>;
  children(r: BaseRef, parent: ObjectId | null): Promise<ObjectSummary[]>;
  getObject(r: BaseRef, id: ObjectId): Promise<ObjectSummary | null>;
  createObject(r: BaseRef, item: NewItem): Promise<ObjectId>;
  renameObject(r: BaseRef, id: ObjectId, name: string): Promise<void>;
  moveObject(r: BaseRef, id: ObjectId, parent: ObjectId | null, after: ObjectId | null): Promise<void>;
  deleteObject(r: BaseRef, id: ObjectId): Promise<void>;
  restoreObject(r: BaseRef, id: ObjectId): Promise<void>;
  trash(r: BaseRef): Promise<ObjectSummary[]>;
  search(account: AccountId, base: BaseId, text: string, limit: number): Promise<SearchResult[]>;
  syncState(r: BaseRef): Promise<SyncState>;
  noteOpen(r: BaseRef, note: ObjectId, onUpdate: (update: Uint8Array) => void): Promise<NoteOpened>;
  noteApply(session: number, update: Uint8Array): Promise<void>;
  noteClose(session: number): Promise<void>;
  openWindow(route: string): Promise<void>;
  updateCheck(): Promise<UpdateInfo | null>;
  updateInstall(): Promise<void>;
  openExternal(url: string): Promise<void>;
  onEvent(handler: (event: AppEvent) => void): Promise<() => void>;
}
