import { invoke, Channel } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { openUrl } from '@tauri-apps/plugin-opener';
import { BackendError, type Backend, type AppEvent, type BaseRef, type NoteOpened } from './types';

// The core-backed commands are introduced by later shell tasks. Keep their mapping here.
const commands: Record<string, [string, string[]]> = {
  appInfo: ['app_info', []], accounts: ['accounts', []], resetDevice: ['reset_device', []], signUp: ['sign_up', ['form']],
  signInStart: ['sign_in_start', ['form']], signInWithKit: ['sign_in_with_kit', ['pending', 'kit']],
  signInCancel: ['sign_in_cancel', ['pending']], signOut: ['sign_out', ['account']],
  approvalStart: ['approval_start', ['pending']], approvalDigits: ['approval_digits', ['pending']],
  approvalWait: ['approval_wait', ['pending']], approvalCancel: ['approval_cancel', ['pending']],
  approvalUseKit: ['approval_use_kit', ['pending', 'kit']], approvalRequests: ['approval_requests', ['account']],
  approvalOpen: ['approval_open', ['account', 'id']], approvalApprove: ['approval_approve', ['account', 'id', 'digits']],
  approvalDecline: ['approval_decline', ['account', 'id']],
  newKit: ['new_kit', ['account', 'password']], kitSaved: ['kit_saved', ['account']], setKitSaved: ['set_kit_saved', ['account']],
  devices: ['devices', ['account']], removeDevice: ['remove_device', ['account', 'device']],
  bases: ['bases', ['account']], createBase: ['create_base', ['account', 'name']],
  children: ['children', ['r', 'parent']], getObject: ['get_object', ['r', 'id']],
  createObject: ['create_object', ['r', 'item']], renameObject: ['rename_object', ['r', 'id', 'name']],
  moveObject: ['move_object', ['r', 'id', 'parent', 'after']],
  deleteObject: ['delete_object', ['r', 'id']], restoreObject: ['restore_object', ['r', 'id']],
  trash: ['trash', ['r']], search: ['search', ['account', 'base', 'text', 'limit']],
  syncState: ['sync_state', ['r']], noteClose: ['note_close', ['session']],
  heroChats: ['hero_chats', ['account', 'base']], heroChatFor: ['hero_chat_for', ['account', 'base', 'project']],
  heroNewChat: ['hero_new_chat', ['account', 'base']], heroMessages: ['hero_messages', ['account', 'base', 'chat']],
  heroSend: ['hero_send', ['account', 'base', 'chat', 'text', 'focus']],
  heroStop: ['hero_stop', ['account', 'base', 'chat']], heroAnswer: ['hero_answer', ['account', 'base', 'chat', 'allow']],
  heroRetry: ['hero_retry', ['account', 'base', 'chat']],
  openWindow: ['open_window', ['route']], updateCheck: ['update_check', []], updateInstall: ['update_install', []],
};
function rethrow(e: unknown): never {
  if (typeof e === 'object' && e !== null && 'kind' in e && 'message' in e) {
    throw new BackendError(String(e.kind), String(e.message));
  }
  throw e;
}
function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  return invoke<T>(command, args).catch(rethrow);
}

export const tauriBackend: Backend = new Proxy({
  async noteOpen(r: BaseRef, note: string, onUpdate: (update: Uint8Array) => void): Promise<NoteOpened> {
    // Tauri delivers raw channel bytes as ArrayBuffer (including on Android).
    const channel = new Channel<ArrayBuffer | Uint8Array>();
    channel.onmessage = update => onUpdate(new Uint8Array(update));
    const raw = await call<Uint8Array>('note_open', { r, note, channel });
    const bytes = new Uint8Array(raw);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return { session: Number(view.getBigUint64(0)), readOnly: bytes[8] !== 0, state: bytes.slice(9) };
  },
  noteApply(session: number, update: Uint8Array) {
    return invoke<void>('note_apply', update, { headers: { 'bh-session': String(session) } }).catch(rethrow);
  },
  async onEvent(handler: (event: AppEvent) => void) {
    const unlisten = await listen<AppEvent>('bh:event', e => handler(e.payload));
    return unlisten;
  },
  async openExternal(url: string) {
    if (!/^https?:\/\//.test(url)) throw new BackendError('Invalid', 'Only HTTP(S) links are allowed');
    await openUrl(url);
  },
} as Backend, {
  get(target, property: keyof Backend) {
    if (property in target) return target[property];
    const entry = commands[property];
    if (!entry) return undefined;
    return (...args: unknown[]) => call(entry[0], Object.fromEntries(entry[1].map((name, index) => [name, args[index]])));
  },
});
