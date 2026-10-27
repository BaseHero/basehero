import { BackendError, type Backend, type BaseRef, type SyncState } from './backend/types';

// View state only: the backend owns the queue, connectivity, and update requirement.
export class SyncStatus {
  state = $state<SyncState | null>(null);
  needsUpdate = $state(false);
  private generation = 0;

  clear() { this.generation++; this.state = null; this.needsUpdate = false; }
  async refresh(backend: Backend, ref: BaseRef) {
    const generation = ++this.generation;
    try {
      const state = await backend.syncState(ref);
      if (generation === this.generation) this.state = state;
    } catch (error) {
      if (generation === this.generation && error instanceof BackendError && error.kind === 'NeedsUpdate') this.needsUpdate = true;
    }
  }
}
