<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import { getBackend } from './lib/backend';
  import type { AccountSummary, BaseRef, KitStatus, SearchResult, SignedUp } from './lib/backend/types';
  import { SyncStatus } from './lib/sync.svelte';
  import Search from './screens/Search.svelte';
  import Devices from './screens/Devices.svelte';
  import Usage from './screens/Usage.svelte';
  import Removed from './screens/Removed.svelte';
  import StatusBar from './components/StatusBar.svelte';
  import KeyError from './screens/KeyError.svelte';
  import { errorMessage } from './lib/errors';
  import { session } from './lib/session.svelte';
  import { drainAll, resumeAll } from './lib/editor/host';
  import Base from './screens/Base.svelte';
  import Bases from './screens/Bases.svelte';
  import Welcome from './screens/Welcome.svelte';
  import UpdateBanner from './components/UpdateBanner.svelte';
  import SignUp from './screens/SignUp.svelte';
  import Kit from './screens/Kit.svelte';
  import SignIn from './screens/SignIn.svelte';
  import PendingSignIn from './screens/PendingSignIn.svelte';
  import ApprovalRequests from './components/ApprovalRequests.svelte';

  type Screen = 'welcome' | 'signup' | 'kit' | 'signin' | 'pending' | 'account' | 'search' | 'devices' | 'usage' | 'removed';
  let screen = $state<Screen>('welcome');
  let keyError = $state<{ kind: string; message: string } | null>(null);
  // Accounts the server refused without a notice from the person's devices: from
  // events for any account, and the account list for those refused before this window.
  let serverSignedOut = $state<string[]>([]);
  function markSignedOut(account: AccountSummary) {
    if (account.signedOutByServer && !serverSignedOut.includes(account.id)) serverSignedOut = [...serverSignedOut, account.id];
  }
  let erasing = $state(false);
  let deviceName = $state('Mac');
  let signedUp = $state<SignedUp | null>(null);
  let kitStatus = $state<KitStatus>({ known: false, saved: false, madeAt: null });
  let kitStatusAccount = $state<string | null>(null);
  let kitRevision = $state(0);
  let reminderDue = $state(false);
  let olderKitOffer = $state(false);
  let kitReturn = $state<'account' | 'devices'>('account');
  let reminderTimer: ReturnType<typeof setTimeout> | undefined;
  let pending = $state<string | null>(null);
  let currentBase = $state<string | null>(null);
  let searchText = $state('');
  let query = $state('');
  let platform = $state('linux');
  let quitSaveError = $state('');
  const LOCK_AFTER_MS = 60_000;
  function lockAfterMs(): number {
    // The emulator APK is a debug native build but Vite still runs `vite build`.
    if (import.meta.env.DEV || import.meta.env.VITE_BH_DEBUG === '1') {
      const value = Number(localStorage.getItem('bh.lockAfterMs'));
      if (Number.isFinite(value) && value > 0) return value;
    }
    return LOCK_AFTER_MS;
  }
  let away = $state(false);
  let lockTimer: ReturnType<typeof setTimeout> | undefined;
  let timerFired = false;
  let lockingAway: Promise<void> | undefined;
  const lastRefresh = new Map<string, number>();
  function refreshAccount(account: string) {
    const now = Date.now();
    if (now - (lastRefresh.get(account) ?? 0) < 60_000) return;
    lastRefresh.set(account, now);
    void getBackend().refreshAccount(account).then(() => {
      if (session.account?.id === account) void refreshKit(session.account);
    }).catch(() => {});
  }
  let checkingBases: Promise<void> | undefined;
  let basesDirty = false;
  function checkBases(account: string): Promise<void> {
    basesDirty = true;
    if (checkingBases) return checkingBases;
    checkingBases = (async () => {
      do {
        basesDirty = false;
        const bases = await getBackend().bases(account);
        if (basesDirty) continue; // A lock may have invalidated the in-flight snapshot.
        const base = route?.[1] === account ? route[2] : null;
        if (base && !bases.some(item => item.id === base)) {
          // The core has already removed this base. Do not rerender its note on the way out.
          const next = `#/a/${account}`;
          currentBase = null;
          hash = next;
          history.replaceState(null, '', location.pathname + location.search + next);
          screen = 'account';
        }
      } while (basesDirty);
    })().finally(() => { checkingBases = undefined; });
    return checkingBases;
  }
  function lockAway(): Promise<void> {
    if (lockingAway) return lockingAway;
    timerFired = true;
    lockingAway = (async () => {
      try {
        // Automatic locking cannot wait for a failed or stalled editor save.
        let timeout: ReturnType<typeof setTimeout> | undefined;
        try {
          await Promise.race([
            drainAll('away').catch(() => {}),
            new Promise<void>(resolve => { timeout = setTimeout(resolve, 3_000); }),
          ]);
        } finally { clearTimeout(timeout); }
        await getBackend().lockAllHidden();
        if (session.account) await checkBases(session.account.id);
        timerFired = false;
        quitSaveError = '';
      } finally { lockingAway = undefined; }
    })();
    return lockingAway;
  }
  let searchField = $state<HTMLInputElement>();
  const sync = new SyncStatus();
  const removedAccounts = new Set<string>();
  let knownAccounts = $state<string[]>([]);
  let accountsLoaded = $state(false);
  function ref(): BaseRef | null {
    return session.account && currentBase ? { account: session.account.id, base: currentBase } : null;
  }
  function submitSearch(event: SubmitEvent) {
    event.preventDefault();
    if (!session.account || !searchText.trim()) return;
    void requestRoute(`#/a/${session.account.id}/search?q=${encodeURIComponent(searchText.trim())}`);
  }
  async function showBase(event: MouseEvent) {
    event.preventDefault();
    if (!session.account) return;
    const bases = await getBackend().bases(session.account.id);
    const base = bases.find(base => base.name === 'Personal')?.id ?? bases[0]?.id;
    void requestRoute(base ? `#/a/${session.account.id}/b/${base}` : `#/a/${session.account.id}`);
  }
  async function openHit(result: SearchResult) {
    if (!session.account) return;
    if (result.hit.ty.name === 'core.file') {
      const file = await getBackend().getObject({ account: session.account.id, base: result.base }, result.hit.id);
      if (file?.parent) await requestRoute(`#/a/${session.account.id}/b/${result.base}/n/${file.parent}?files=1`);
      return;
    }
    await requestRoute(`#/a/${session.account.id}/b/${result.base}/n/${result.hit.id}`);
  }

  let hash = $state(location.hash);
  let leave: (() => Promise<boolean>) | undefined;
  let requestedHash = '';
  let transitioning = false;
  let route = $derived(/^#\/a\/([^/]+)(?:\/b\/([^/]+)(?:\/n\/([^/?]+)(?:\?files=1)?)?)?$/.exec(hash));
  let specialRoute = $derived(/^#\/a\/([^/]+)\/(search(?:\?q=[^#]*)?|devices|usage)$/.exec(hash));
  let routeAccount = $derived(route?.[1] ?? specialRoute?.[1]);
  let knownRoute = $derived(accountsLoaded && !!routeAccount && knownAccounts.includes(routeAccount) && !removedAccounts.has(routeAccount));
  $effect(() => {
    const account = session.account;
    if (screen !== 'account' || route?.[2] || !account || kitStatusAccount !== account.id || kitStatus.known) return;
    const key = `basehero:kit-offer:${account.id}`;
    if (!localStorage.getItem(key)) {
      olderKitOffer = true;
      localStorage.setItem(key, 'shown'); // Non-secret, once per device; the kit stays native.
    }
  });
  $effect(() => {
    const base = route?.[2];
    if (base && knownRoute && base !== currentBase) {
      currentBase = base;
      void sync.refresh(getBackend(), { account: route![1], base });
      void checkBases(route![1]);
    }
  });

  $effect(() => {
    screen;
    hash;
    void tick().then(() => {
      const heading = document.querySelector<HTMLElement>('main h1');
      if (heading) { heading.tabIndex = -1; heading.focus(); }
    });
  });
  async function navigate(next: Screen) {
    if (!await guardLeave()) return;
    history.pushState(null, '', '/'); // Never put credentials, pending ids, or kits in URLs or history.
    hash = '';
    screen = next;
  }
  function onleave(hook: () => Promise<boolean>) {
    leave = hook;
    return () => { if (leave === hook) leave = undefined; };
  }
  async function guardLeave(): Promise<boolean> {
    if (route?.[3] && leave && !await leave()) return false;
    if (screen === 'kit') signedUp = null;
    return true;
  }
  function setReminder(status: KitStatus) {
    kitStatus = status;
    if (reminderTimer) clearTimeout(reminderTimer);
    reminderTimer = undefined;
    const remaining = status.madeAt === null ? Infinity : status.madeAt + 24 * 60 * 60 * 1000 - Date.now();
    reminderDue = status.known && !status.saved && remaining <= 0;
    if (status.known && !status.saved && remaining > 0 && Number.isFinite(remaining)) {
      reminderTimer = setTimeout(() => { reminderDue = true; reminderTimer = undefined; }, remaining);
    }
  }
  async function refreshKit(account: AccountSummary) {
    const status = await getBackend().kitStatus(account.id);
    if (session.account?.id !== account.id) return;
    olderKitOffer = false;
    kitStatusAccount = account.id;
    setReminder(status);
  }
  async function showKit() {
    const account = session.account;
    if (!account) return;
    kitActionError = '';
    try {
      const kit = await getBackend().showKit(account.id);
      await refreshKit(account);
      kitReturn = screen === 'devices' ? 'devices' : 'account';
      signedUp = { account, kit };
      await navigate('kit');
    } catch (cause) {
      kitActionError = errorMessage(cause);
      await refreshKit(account);
      if (!kitStatus.known) await requestRoute(`#/a/${account.id}/devices`);
    }
  }
  let kitActionError = $state('');
  async function leaveKit() {
    const destination = kitReturn;
    signedUp = null;
    if (destination === 'devices' && session.account) await requestRoute(`#/a/${session.account.id}/devices`);
    else await navigate('account');
  }
  function allowed(next: string): boolean {
    const account = /^#\/a\/([^/]+)/.exec(next)?.[1];
    return !account || (screen !== 'removed' && !removedAccounts.has(account) && (!accountsLoaded || knownAccounts.includes(account)));
  }
  async function requestRoute(next: string) {
    if (screen === 'removed') { history.replaceState(null, '', '/'); return; }
    const targetAccount = /^#\/a\/([^/]+)/.exec(next)?.[1];
    let found: AccountSummary | undefined;
    if (targetAccount && !knownAccounts.includes(targetAccount) && !removedAccounts.has(targetAccount)) {
      try { found = (await getBackend().accounts()).find(account => account.id === targetAccount); }
      catch { /* An unavailable account list cannot authorize a route. */ }
    }
    if (found && !knownAccounts.includes(found.id)) knownAccounts = [...knownAccounts, found.id];
    const fallback = session.account && knownAccounts.includes(session.account.id) ? `#/a/${session.account.id}` : '';
    const destination = allowed(next) ? next : fallback;
    if (destination === hash && screen !== 'kit') return;
    requestedHash = destination;
    if (transitioning) return;
    transitioning = true;
    try {
      if (!await guardLeave()) return;
      // A newer route requested during the editor drain wins; removal cancels both.
      const target = requestedHash;
      if (!allowed(target)) return;
      hash = target;
      if (location.hash !== target) history.pushState(null, '', location.pathname + location.search + target);
      if (/^#\/a\/[^/]+\/search(?:\?|$)/.test(target)) {
        query = new URLSearchParams(target.split('?')[1] ?? '').get('q') ?? '';
        searchText = query;
        screen = 'search';
      } else if (/^#\/a\/[^/]+\/devices$/.test(target)) screen = 'devices';
      else if (/^#\/a\/[^/]+\/usage$/.test(target)) screen = 'usage';
      else screen = target ? 'account' : (session.account ? 'account' : 'welcome');
      if (found && target === next) await openAccount(found);
      requestedHash = '';
    } finally { transitioning = false; }
  }
  async function openAccount(account: AccountSummary) {
    markSignedOut(account);
    session.account = account;
    if (!knownAccounts.includes(account.id)) knownAccounts = [...knownAccounts, account.id];
    refreshAccount(account.id);
    await refreshKit(account);
    if (session.account?.id === account.id) {
      currentBase = null;
      sync.clear();
      if (specialRoute?.[2].startsWith('search')) {
        query = new URLSearchParams(hash.split('?')[1] ?? '').get('q') ?? '';
        searchText = query;
        screen = 'search';
      } else if (specialRoute?.[2] === 'devices') screen = 'devices';
      else if (specialRoute?.[2] === 'usage') screen = 'usage';
      else if (route) screen = 'account'; // Keep a directly opened note route mounted.
      else navigate('account');
    }
  }
  function entered(account: AccountSummary) {
    signedUp = null;
    pending = null;
    void openAccount(account);
  }
  async function acknowledgeKit() {
    if (!signedUp) return;
    const { account, kit } = signedUp;
    try {
      await getBackend().setKitSaved(account.id, kit);
      setReminder(await getBackend().kitStatus(account.id));
      await leaveKit();
    } catch (cause) {
      // Conflict: a newer kit replaced it. NotFound: no kit is kept for this account any more.
      if (typeof cause !== 'object' || cause === null || !('kind' in cause) || (cause.kind !== 'Conflict' && cause.kind !== 'NotFound')) throw cause;
      // Only the kit on this screen can be acknowledged. Replace a stale one
      // with the current kit, never retry the old acknowledgement implicitly.
      await refreshKit(account);
      if (!kitStatus.known) {
        signedUp = null;
        await requestRoute(`#/a/${account.id}/devices`);
        return;
      }
      signedUp = { account, kit: await getBackend().showKit(account.id) };
      kitActionError = 'Your kit changed. This is the current kit. Save it before confirming.';
    }
  }
  async function madeKit(kit: string) {
    if (!session.account) return;
    const account = session.account;
    await refreshKit(account);
    kitActionError = '';
    kitReturn = 'devices';
    signedUp = { account, kit };
    await navigate('kit');
  }
  async function cancelPending(destination: 'welcome' | 'signin' = 'welcome') {
    const id = pending;
    pending = null;
    void navigate(destination);
    if (id !== null) {
      try { await getBackend().approvalCancel(id); } catch { /* A cancelled request cannot be retried here. */ }
      try { await getBackend().signInCancel(id); } catch { /* A cancelled sign-in cannot be retried here. */ }
    }
  }
  async function eraseDevice(account: string) {
    if (erasing || !window.confirm("Erase BaseHero's notes and keys on this device? Changes that haven't synced are lost.")) return;
    erasing = true;
    // Erasing emits Removed, which shows the Removed screen.
    try { await getBackend().signOut(account); } finally { erasing = false; }
  }
  async function resetDevice() {
    await getBackend().resetDevice();
    session.account = null;
    signedUp = null;
    pending = null;
    if (reminderTimer) clearTimeout(reminderTimer);
    setReminder({ known: false, saved: false, madeAt: null });
    kitStatusAccount = null;
    knownAccounts = [];
    accountsLoaded = true;
    currentBase = null;
    sync.clear();
    history.replaceState(null, '', '/');
    hash = '';
    screen = 'welcome';
    keyError = null;
  }
  function startupError(cause: unknown): { kind: string; message: string } {
    // The native startup path returns CommandError; don't stringify arbitrary
    // thrown values, which can contain data unrelated to the startup failure.
    if (typeof cause === 'object' && cause !== null && 'kind' in cause && 'message' in cause &&
        typeof cause.kind === 'string' && typeof cause.message === 'string') {
      return { kind: cause.kind, message: cause.message };
    }
    return { kind: 'Unknown', message: 'The startup check failed.' };
  }
  onMount(() => {
    let active = true;
    getBackend().appInfo().then(info => {
      if (active) { platform = info.platform; deviceName = info.platform === 'android' ? 'Android' : 'Mac'; }
    }).catch(() => {});
    getBackend().accounts().then(accounts => {
      if (!active) return;
      knownAccounts = accounts.map(account => account.id);
      for (const account of accounts) { markSignedOut(account); refreshAccount(account.id); }
      accountsLoaded = true;
      if (screen !== 'welcome') return;
      const requested = /^#\/a\/([^/]+)/.exec(hash)?.[1];
      if (requested && !knownAccounts.includes(requested)) {
        const fallback = accounts[0];
        void requestRoute(fallback ? `#/a/${fallback.id}` : '').then(() => {
          if (active && fallback) void openAccount(fallback);
        });
      } else if (accounts.length) void openAccount(accounts.find(account => account.id === requested) ?? accounts[0]);
    }).catch(cause => {
      if (!active) return;
      accountsLoaded = true;
      keyError = startupError(cause);
    });
    let unsubscribe: (() => void) | undefined;
    let unlistenClose: (() => void) | undefined;
    let unlistenDrain: (() => void) | undefined;
    let closing = false;
    const stopAway = () => {
      // onPause and visibilitychange can fire for the same trip. Preserve a
      // failed lock's retry on the next stop; only pending work is a duplicate.
      if (lockTimer !== undefined || lockingAway) return;
      away = true; // Hide first; Android can suspend timers and network work immediately.
      void drainAll('away').catch(() => { quitSaveError = 'Could not save your notes. Copy your text and try again.'; });
      clearTimeout(lockTimer);
      if (timerFired) {
        void lockAway().catch(() => { quitSaveError = 'Could not lock hidden bases. Try again.'; });
      } else {
        lockTimer = setTimeout(() => {
          lockTimer = undefined;
          void lockAway().catch(() => { quitSaveError = 'Could not lock hidden bases. Try again.'; });
        }, lockAfterMs());
      }
    };
    const resumeAway = (event: Event) => {
      const { awayMs } = (event as CustomEvent<{ awayMs?: number }>).detail ?? {};
      clearTimeout(lockTimer);
      lockTimer = undefined;
      if (timerFired || (awayMs ?? 0) >= lockAfterMs()) {
        // Keep content blank until both the lock and route eviction have finished.
        void lockAway().then(() => { away = false; resumeAll('away'); }, () => { quitSaveError = 'Could not lock hidden bases. Try again.'; });
      } else {
        away = false;
        resumeAll('away');
      }
      if (session.account) refreshAccount(session.account.id);
    };
    window.addEventListener('bh:stop', stopAway);
    // The WebView can freeze before evaluateJavascript from onPause runs.
    // Its own visibility event blanks content before the page is suspended.
    const hideWhenBackgrounded = () => { if (document.visibilityState === 'hidden') stopAway(); };
    document.addEventListener('visibilitychange', hideWhenBackgrounded);
    window.addEventListener('bh:resume', resumeAway);
    const focused = () => { if (session.account) refreshAccount(session.account.id); };
    window.addEventListener('focus', focused);
    async function drainForQuit(requestId: number) {
      let ok = false;
      try {
        await drainAll('quit');
        ok = true;
      } catch {
        quitSaveError = 'Could not save your notes. Copy your text and try again.';
        resumeAll('quit');
      }
      if (import.meta.env.MODE === 'fake') {
        const testWindow = window as typeof window & { __bhDrainAcks?: { requestId: number; ok: boolean }[] };
        (testWindow.__bhDrainAcks ??= []).push({ requestId, ok });
      } else {
        await invoke('window_drained', { requestId, ok });
      }
    }
    const fakeDrain = (event: Event) => { void drainForQuit((event as CustomEvent<{ requestId: number }>).detail.requestId); };
    if (import.meta.env.MODE === 'fake') window.addEventListener('bh:drain-requested', fakeDrain);
    else void listen<{ requestId: number }>('bh:drain-requested', event => {
      void drainForQuit(event.payload.requestId);
    }).then(stop => { if (active) unlistenDrain = stop; else stop(); });
    // Native CloseRequested is prevented until this window's route guard saves its editor.
    if (import.meta.env.MODE !== 'fake') {
      void listen('bh:close-requested', async () => {
        if (closing) return;
        closing = true;
        try {
          if (await guardLeave()) await invoke('close_window');
        } catch (cause) {
          console.error('Could not close window after saving', cause);
        } finally { closing = false; }
      }).then(stop => { if (active) unlistenClose = stop; else stop(); });
    }
    void getBackend().onEvent(event => {
      if (!active) return;
      if (event.kind.toLowerCase() === 'account' && event.event === 'SignedOutByServer' && !serverSignedOut.includes(event.account)) {
        serverSignedOut = [...serverSignedOut, event.account];
      } else if (event.kind.toLowerCase() === 'account' && event.event === 'Removed') {
        serverSignedOut = serverSignedOut.filter(account => account !== event.account);
      }
      if (event.account !== session.account?.id) return;
      if (event.kind.toLowerCase() === 'account' && event.event === 'Removed') {
        removedAccounts.add(event.account);
        requestedHash = '';
        hash = '';
        signedUp = null;
        setReminder({ known: false, saved: false, madeAt: null });
        kitStatusAccount = null;
        pending = null;
        session.account = null;
        currentBase = null;
        sync.clear();
        history.replaceState(null, '', '/');
        screen = 'removed';
      } else if (event.kind.toLowerCase() === 'kitchanged') {
        kitRevision++;
        if (session.account) void refreshKit(session.account);
      } else if (event.kind.toLowerCase() === 'account' &&
          (event.event === 'BasesChanged' || (typeof event.event === 'object' && event.event !== null && 'BasesChanged' in event.event))) {
        void checkBases(event.account);
      } else if (event.kind.toLowerCase() === 'base' && event.base === currentBase) {
        if (event.event === 'needsUpdate' || event.event === 'NeedsUpdate' || (typeof event.event === 'object' && event.event !== null && 'NeedsUpdate' in event.event)) sync.needsUpdate = true;
        else { const r = ref(); if (r) void sync.refresh(getBackend(), r); }
      }
    }).then(stop => {
      if (!active) { stop(); return; }
      unsubscribe = stop;
      // A refusal between the first account list and this subscription sent its
      // event to no one: read the list again now that later events arrive. Marks only add.
      void getBackend().accounts().then(accounts => { if (active) accounts.forEach(markSignedOut); }).catch(() => {});
    });
    const shortcut = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k' && session.account) {
        event.preventDefault(); searchField?.focus();
      }
    };
    window.addEventListener('keydown', shortcut);
    const restoreRoute = (next: string) => {
      // hashchange and Back update the URL before the leave guard can drain.
      // Keep the mounted route visible and restore its URL until leaving succeeds.
      history.replaceState(null, '', location.pathname + location.search + hash);
      void requestRoute(next);
    };
    const back = (popped = false) => {
      // Some WebViews send popstate as well as hashchange for fragment navigation.
      // Route both through the same guards, rather than treating it as kit Back.
      if (screen === 'removed') { history.replaceState(null, '', '/'); return; }
      if (popped && location.hash !== hash) { restoreRoute(location.hash); return; }
      if ((route || specialRoute) && (screen === 'account' || screen === 'welcome' || screen === 'search' || screen === 'devices' || screen === 'usage')) {
        if (!popped) void requestRoute('');
      } else if (screen === 'kit') {
        void leaveKit();
      } else if (pending !== null) void cancelPending();
      else void navigate(session.account ? 'account' : 'welcome');
    };
    const pop = () => back(true);
    const update = () => {
      const next = location.hash;
      if (next !== hash) restoreRoute(next);
    };
    window.__bhBack = () => back();
    window.addEventListener('popstate', pop);
    window.addEventListener('hashchange', update);
    return () => {
      active = false;
      unsubscribe?.();
      unlistenClose?.();
      unlistenDrain?.();
      clearTimeout(lockTimer);
      window.removeEventListener('bh:stop', stopAway);
      document.removeEventListener('visibilitychange', hideWhenBackgrounded);
      window.removeEventListener('bh:resume', resumeAway);
      window.removeEventListener('focus', focused);
      window.removeEventListener('bh:drain-requested', fakeDrain);
      window.removeEventListener('keydown', shortcut);
      delete window.__bhBack;
      window.removeEventListener('popstate', pop);
      window.removeEventListener('hashchange', update);
      if (reminderTimer) clearTimeout(reminderTimer);
    };
  });
</script>
<div class:away-hidden={away && !!session.account}>
{#if !keyError && session.account && ((screen === 'account' && (!routeAccount || knownRoute)) || (knownRoute && (screen === 'search' || screen === 'devices' || screen === 'usage')))}
  <header class="location-bar">
    <a href="/" onclick={(event) => { event.preventDefault(); void requestRoute(''); }}>BaseHero</a>
    <form role="search" onsubmit={submitSearch}><input type="search" aria-label="Search" placeholder="Search" bind:value={searchText} bind:this={searchField} /></form>
    <StatusBar {sync} mac={platform === 'macos'} />
  </header>
  <nav class="workspace-nav"><a href={`#/a/${session.account.id}/b/${currentBase ?? ''}`} onclick={showBase}>Personal</a>
    <a href={`#/a/${session.account.id}/devices`} onclick={(event) => { event.preventDefault(); void requestRoute(`#/a/${session.account?.id}/devices`); }}>Devices</a>
    <a href={`#/a/${session.account.id}/usage`} onclick={(event) => { event.preventDefault(); void requestRoute(`#/a/${session.account?.id}/usage`); }}>Usage</a></nav>
{/if}
{#if !keyError && session.account && serverSignedOut.includes(session.account.id)}
  {@const account = session.account.id}
  <div class="server-signed-out" role="alert">
    <p>The server signed this device out, but none of your devices removed it. Its notes stay here and won't sync.</p>
    <button disabled={erasing} onclick={() => void eraseDevice(account)}>Erase this device</button>
  </div>
{/if}
{#if keyError}
  <KeyError kind={keyError.kind} message={keyError.message} onreset={resetDevice} />
{:else if route?.[2] && knownRoute && (screen === 'account' || screen === 'welcome')}
  {#key `${route[1]}:${route[2]}`}<Base r={{ account: route[1], base: route[2] }} id={route[3] ?? null} filesOpen={hash.endsWith('?files=1')}
    {onleave} retryleave={() => { if (requestedHash) void requestRoute(requestedHash); }} />{/key}
{:else if route && knownRoute && (screen === 'account' || screen === 'welcome')}
  <Bases account={route[1]} email={session.account?.email ?? ''} onopen={base => void requestRoute(`#/a/${route[1]}/b/${base}`)} />
{:else if screen === 'welcome'}
  <Welcome onsignup={() => navigate('signup')} onsignin={() => navigate('signin')} />
{:else if screen === 'signup'}
  <SignUp {deviceName} oncreated={(result) => { session.account = result.account; knownAccounts = [...knownAccounts, result.account.id]; kitReturn = 'account'; signedUp = result; void refreshKit(result.account); void navigate('kit'); }} onback={() => void navigate('welcome')} />
{:else if screen === 'kit' && signedUp}
  <Kit kit={signedUp.kit} mac={platform === 'macos'} notice={kitActionError} onsaved={acknowledgeKit} onlater={() => void leaveKit()} />
{:else if screen === 'signin'}
  <SignIn {deviceName} onpending={(id) => { pending = id; void navigate('pending'); }} onback={() => void navigate('welcome')} />
{:else if screen === 'pending' && pending !== null}
  <PendingSignIn {pending} onapproved={entered} oncancel={() => void cancelPending()} onrestart={() => void cancelPending('signin')} />
{:else if screen === 'removed'}
  <Removed oncontinue={() => void navigate('welcome')} />
{:else if session.account && (screen === 'account' || (knownRoute && (screen === 'search' || screen === 'devices' || screen === 'usage')))}
  {#if screen === 'search'}
    <Search account={session.account.id} base={currentBase} {query} open={openHit} />
  {:else if screen === 'devices'}
    <Devices account={session.account.id} {kitRevision} onshow={showKit} onnewkit={madeKit} />
  {:else if screen === 'usage'}
    <Usage account={session.account.id} />
  {:else}
  <main class="entry-grid"><section class="entry-panel"><span class="eyebrow">YOUR SPACE</span><h1>BaseHero</h1>
    {#if reminderDue}
      <div class="kit-reminder" role="status">
        <p>Save your recovery kit. You'll need it to open your account if you lose your devices.</p>
        {#if kitActionError}<p class="error" role="alert">{kitActionError}</p>{/if}
        <div class="actions"><button onclick={showKit}>Show kit</button><button onclick={showKit}>I've saved it</button></div>
      </div>
    {/if}
    {#if olderKitOffer}<div class="kit-reminder" role="status"><p>BaseHero can now keep your recovery kit for you.</p><button onclick={() => { if (session.account) void requestRoute(`#/a/${session.account.id}/devices`); }}>Make a new kit</button></div>{/if}
    <ApprovalRequests account={session.account.id} />
    <Bases account={session.account.id} email={session.account.email} onopen={base => void requestRoute(`#/a/${session.account!.id}/b/${base}`)} />
  </section></main>
  {/if}
{/if}
</div>
{#if quitSaveError}<p role="alert" class="quit-save-error">{quitSaveError}</p>{/if}
<UpdateBanner />
<style>
  .away-hidden { visibility: hidden; }
  .quit-save-error { position: fixed; z-index: 1000; bottom: 1rem; left: 1rem; padding: 1rem; background: var(--bar); color: var(--on-bar); }
  .location-bar { display: flex; align-items: center; gap: 1rem; min-height: 3.5rem; padding: .5rem 1rem; background: var(--bar); color: var(--on-bar); position: relative; }
  .location-bar a { color: var(--on-bar); font-weight: 600; }
  .location-bar form { flex: 1; display: block; }
  .location-bar input { width: 100%; padding: .5rem; background: var(--bar-2); color: var(--on-bar); border: 1px solid var(--bar-line); font: .85rem var(--sans); }
  .server-signed-out { display: flex; align-items: center; gap: 1rem; padding: .75rem 1.5rem; border-bottom: 1px solid var(--line); }
  .server-signed-out p { flex: 1; margin: 0; }
  .workspace-nav { display: flex; gap: 1.5rem; padding: 1rem 1.5rem; border-bottom: 1px solid var(--line); }
  :global(.workspace) { padding: clamp(1rem, 4vw, 3rem); max-width: 60rem; margin: auto; }
</style>
