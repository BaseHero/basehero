import type { AccountSummary } from './backend/types';

// UI-only state. Secrets are never persisted in browser storage or a route.
export const session = $state<{ account: AccountSummary | null }>({ account: null });
