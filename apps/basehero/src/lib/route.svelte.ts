import type { BaseId, ObjectId } from './backend/types';
import { session } from './session.svelte';

export const route = $state({ path: '/' });
export function openObject(base: BaseId, id: ObjectId): void {
  if (session.account) location.hash = `#/a/${session.account.id}/b/${base}/n/${id}`;
}
