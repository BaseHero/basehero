import type { Backend, BaseRef, ObjectId } from '../backend/types';

export interface NoteHost {
  readOnly: boolean;
  open(onUpdate: (update: Uint8Array) => void): Promise<{
    state: [Uint8Array]; clientId: number; unsubscribe: () => void;
  }>;
  commit(update: Uint8Array, requestId: string): Promise<{ requestId: string }>;
  openExternal(url: string): Promise<void>;
  search(text: string): Promise<{ id: ObjectId; title: string }[]>;
}

// The backend owns the atomic snapshot/subscription and commits before acknowledging.
export function noteHost(backend: Backend, r: BaseRef, id: ObjectId): NoteHost {
  let session: number | undefined;
  let readOnly = false;
  return {
    get readOnly() { return readOnly; },
    async open(onUpdate) {
      const opened = await backend.noteOpen(r, id, onUpdate);
      session = opened.session;
      readOnly = opened.readOnly;
      return {
        state: [opened.state], clientId: Math.max(2, crypto.getRandomValues(new Uint32Array(1))[0]),
        unsubscribe: () => { if (session !== undefined) { const closing = session; session = undefined; void backend.noteClose(closing); } },
      };
    },
    async commit(update, requestId) {
      if (session === undefined) throw new Error('Note session is closed');
      await backend.noteApply(session, update);
      return { requestId };
    },
    openExternal: url => backend.openExternal(url),
    async search(text) {
      const found = await backend.search(r.account, r.base, text, 20);
      const notes = await Promise.all(found.map(async result => {
        const item = await backend.getObject(r, result.hit.id);
        return item?.kind === 'note' ? { id: result.hit.id, title: result.hit.title } : null;
      }));
      return notes.filter((item): item is { id: ObjectId; title: string } => item !== null);
    },
  };
}

export function staticHost(state: Uint8Array): NoteHost {
  return {
    readOnly: true,
    async open() {
      return { state: [state], clientId: Math.max(2, crypto.getRandomValues(new Uint32Array(1))[0]), unsubscribe: () => {} };
    },
    async commit() { throw new Error('Historical versions are read-only'); },
    async openExternal() { throw new Error('Historical versions are read-only'); },
    async search() { return []; },
  };
}

export interface DrainingEditor { drain(deadline: number, reason?: string): Promise<boolean>; resume(reason?: string): void }
const editors = new Set<DrainingEditor>();
export function trackEditor(editor: DrainingEditor): () => void {
  editors.add(editor);
  return () => { editors.delete(editor); };
}
// A drain holds each editor until it closes or resumeAll is called with the same reason.
export async function drainAll(reason = 'update'): Promise<void> {
  const drained = await Promise.all([...editors].map(editor => editor.drain(Date.now() + 30_000, reason)));
  if (drained.some(ok => !ok)) throw new Error('Could not save every open note');
}
export function resumeAll(reason: string): void {
  for (const editor of editors) editor.resume(reason);
}
