import { getBackend } from './backend';
import type { BaseRef } from './backend/types';

// One blob per open file. Node views explicitly release their reference on
// destruction; pending readers share the same request and URL.
const urls = new Map<string, { users: number; pending: Promise<string>; url?: string }>();
const key = (r: BaseRef, id: string) => `${r.account}:${r.base}:${id}`;
export async function objectUrl(r: BaseRef, id: string): Promise<string> {
  const k = key(r, id);
  let entry = urls.get(k);
  if (!entry) {
    entry = { users: 0, pending: Promise.resolve('') };
    const current = entry;
    current.pending = getBackend().fileImage(r, id).then(({ mime, bytes }) => {
      // Only the core's sniffed raster MIME may become an image URL.
      if (!['image/png','image/jpeg','image/gif','image/webp'].includes(mime)) throw new Error('Invalid image type');
      const url = URL.createObjectURL(new Blob([new Uint8Array(bytes)], { type: mime }));
      current.url = url;
      if (current.users === 0) { URL.revokeObjectURL(url); urls.delete(k); }
      return url;
    }).catch(error => { if (urls.get(k) === current) urls.delete(k); throw error; });
    urls.set(k, current);
    entry = current;
  }
  entry.users++;
  try { return await entry.pending; }
  catch(error) { releaseObjectUrl(r,id); throw error; }
}
export function releaseObjectUrl(r: BaseRef, id: string): void {
  const k=key(r,id), entry=urls.get(k);
  if (!entry) return;
  entry.users=Math.max(0,entry.users-1);
  if (entry.users === 0 && entry.url) { URL.revokeObjectURL(entry.url); urls.delete(k); }
}
