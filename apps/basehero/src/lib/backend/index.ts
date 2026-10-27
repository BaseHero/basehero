import type { Backend } from './types';
import { FakeBackend } from './fake';
import { tauriBackend } from './tauri';
export type * from './types';

const backend: Backend = import.meta.env.MODE === 'fake' ? new FakeBackend() : tauriBackend;
if (import.meta.env.MODE === 'fake') {
  Object.assign(window, { __fake: backend });
}
export function getBackend(): Backend { return backend; }

declare global { interface Window { __fake: FakeBackend; __bhBack?: () => void; __bhRestart?: () => Promise<void> } }
