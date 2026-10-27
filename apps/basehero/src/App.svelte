<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import { getBackend } from './lib/backend';
  import type { AccountSummary, BaseRef, SearchResult, SignedUp } from './lib/backend/types';
  import { SyncStatus } from './lib/sync.svelte';
  import Search from './screens/Search.svelte';
  import Devices from './screens/Devices.svelte';
  import Removed from './screens/Removed.svelte';
  import StatusBar from './components/StatusBar.svelte';
  import KeyError from './screens/KeyError.svelte';
  import { errorMessage } from './lib/errors';
  import { session } from './lib/session.svelte';
  import { drainAll } from './lib/editor/host';
  import Base from './screens/Base.svelte';
  import Bases from './screens/Bases.svelte';
  import Welcome from './screens/Welcome.svelte';
  import UpdateBanner from './components/UpdateBanner.svelte';
  import SignUp from './screens/SignUp.svelte';
  import Kit from './screens/Kit.svelte';
  import SignIn from './screens/SignIn.svelte';
  import PendingSignIn from './screens/PendingSignIn.svelte';
  import ApprovalRequests from './components/ApprovalRequests.svelte';

  type Screen = 'welcome' | 'signup' | 'kit' | 'signin' | 'pending' | 'account' | 'search' | 'devices' | 'removed';
  let screen = $state<Screen>('welcome');
  let keyError = $state<{ kind: string; message: string } | null>(null);
  let deviceName = $state('Mac');
  let signedUp = $state<SignedUp | null>(null);
  let kitNotSaved = $state(false);
  let pending = $state<string | null>(null);
  let newPassword = $state('');
  let newKitError = $state('');
  let newKitOpen = $state(false);
  let newKitBusy = $state(false);
  let currentBase = $state<string | null>(null);
  let searchText = $state('');
  let query = $state('');
  let platform = $state('linux');
  let quitSaveError = $state('');
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
  function openHit(result: SearchResult) {
    if (!session.account) return;
    void requestRoute(`#/a/${session.account.id}/b/${result.base}/n/${result.hit.id}`);
  }

  let hash = $state(location.hash);
  let leave: (() => Promise<boolean>) | undefined;
  let requestedHash = '';
  let transitioning = false;
  let route = $derived(/^#\/a\/([^/]+)(?:\/b\/([^/]+)(?:\/n\/([^/]+))?)?$/.exec(hash));
  let specialRoute = $derived(/^#\/a\/([^/]+)\/(search(?:\?q=[^#]*)?|devices)$/.exec(hash));
  let routeAccount = $derived(route?.[1] ?? specialRoute?.[1]);
  let knownRoute = $derived(accountsLoaded && !!routeAccount && knownAccounts.includes(routeAccount) && !removedAccounts.has(routeAccount));
  $effect(() => {
    const base = route?.[2];
    if (base && knownRoute && base !== currentBase) {
      currentBase = base;
      void sync.refresh(getBackend(), { account: route![1], base });
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
    if (screen === 'kit' && signedUp && !window.confirm("You haven't saved your recovery kit. You won't be able to see it again. Leave anyway?")) return false;
    if (route?.[3] && leave && !await leave()) return false;
    if (screen === 'kit') signedUp = null;
    return true;
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
      else screen = target ? 'account' : (session.account ? 'account' : 'welcome');
      if (found && target === next) await openAccount(found);
      requestedHash = '';
    } finally { transitioning = false; }
  }
  async function openAccount(account: AccountSummary) {
    session.account = account;
    if (!knownAccounts.includes(account.id)) knownAccounts = [...knownAccounts, account.id];
    kitNotSaved = !(await getBackend().kitSaved(account.id));
    if (session.account?.id === account.id) {
      currentBase = null;
      sync.clear();
      if (specialRoute?.[2].startsWith('search')) {
        query = new URLSearchParams(hash.split('?')[1] ?? '').get('q') ?? '';
        searchText = query;
        screen = 'search';
      } else if (specialRoute?.[2] === 'devices') screen = 'devices';
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
    await getBackend().setKitSaved(signedUp.account.id);
    kitNotSaved = false;
    entered(signedUp.account);
  }
  async function makeKit(event: SubmitEvent) {
    event.preventDefault();
    if (newKitBusy || !session.account) return;
    newKitBusy = true; newKitError = '';
    const account = session.account;
    try {
      const kit = await getBackend().newKit(account.id, newPassword);
      kitNotSaved = true;
      signedUp = { account, kit };
      newKitOpen = false;
      navigate('kit');
    } catch (cause) { newKitError = errorMessage(cause); }
    finally { newPassword = ''; newKitBusy = false; }
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
  async function resetDevice() {
    await getBackend().resetDevice();
    session.account = null;
    signedUp = null;
    pending = null;
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
    async function drainForQuit(requestId: number) {
      let ok = false;
      try {
        await drainAll();
        ok = true;
      } catch {
        quitSaveError = 'Could not save your notes. Copy your text and try again.';
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
      if (!active || event.account !== session.account?.id) return;
      if (event.kind.toLowerCase() === 'account' && event.event === 'Removed') {
        removedAccounts.add(event.account);
        requestedHash = '';
        hash = '';
        signedUp = null;
        kitNotSaved = false;
        pending = null;
        newPassword = '';
        session.account = null;
        currentBase = null;
        sync.clear();
        history.replaceState(null, '', '/');
        screen = 'removed';
      } else if (event.kind.toLowerCase() === 'base' && event.base === currentBase) {
        if (event.event === 'needsUpdate' || event.event === 'NeedsUpdate' || (typeof event.event === 'object' && event.event !== null && 'NeedsUpdate' in event.event)) sync.needsUpdate = true;
        else { const r = ref(); if (r) void sync.refresh(getBackend(), r); }
      }
    }).then(stop => { if (active) unsubscribe = stop; else stop(); });
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
      if ((route || specialRoute) && (screen === 'account' || screen === 'welcome' || screen === 'search' || screen === 'devices')) {
        if (!popped) void requestRoute('');
      } else if (screen === 'kit' && signedUp) {
        // A refused browser Back must restore the history entry so a later Back is still guarded.
        void navigate('account').then(() => { if (popped) history.pushState(null, '', '/'); });
      } else if (pending !== null) void cancelPending();
      else void navigate(session.account ? 'account' : 'welcome');
    };
    const pop = () => back(true);
    const update = () => {
      const next = location.hash;
      if (next !== hash) restoreRoute(next);
    };
    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (!kitNotSaved) return;
      event.preventDefault();
      event.returnValue = '';
    };
    window.__bhBack = () => back();
    window.addEventListener('popstate', pop);
    window.addEventListener('hashchange', update);
    window.addEventListener('beforeunload', beforeUnload);
    return () => {
      active = false;
      unsubscribe?.();
      unlistenClose?.();
      unlistenDrain?.();
      window.removeEventListener('bh:drain-requested', fakeDrain);
      window.removeEventListener('keydown', shortcut);
      delete window.__bhBack;
      window.removeEventListener('popstate', pop);
      window.removeEventListener('hashchange', update);
      window.removeEventListener('beforeunload', beforeUnload);
    };
  });
</script>
{#if !keyError && session.account && ((screen === 'account' && (!routeAccount || knownRoute)) || (knownRoute && (screen === 'search' || screen === 'devices')))}
  <header class="location-bar">
    <a href="/" onclick={(event) => { event.preventDefault(); void requestRoute(''); }}>BaseHero</a>
    <form role="search" onsubmit={submitSearch}><input type="search" aria-label="Search" placeholder="Search" bind:value={searchText} bind:this={searchField} /></form>
    <StatusBar {sync} mac={platform === 'macos'} />
  </header>
  <nav class="workspace-nav"><a href={`#/a/${session.account.id}/b/${currentBase ?? ''}`} onclick={showBase}>Personal</a>
    <a href={`#/a/${session.account.id}/devices`} onclick={(event) => { event.preventDefault(); void requestRoute(`#/a/${session.account?.id}/devices`); }}>Devices</a></nav>
{/if}
{#if keyError}
  <KeyError kind={keyError.kind} message={keyError.message} onreset={resetDevice} />
{:else if route?.[2] && knownRoute && (screen === 'account' || screen === 'welcome')}
  {#key `${route[1]}:${route[2]}`}<Base r={{ account: route[1], base: route[2] }} id={route[3] ?? null}
    {onleave} retryleave={() => { if (requestedHash) void requestRoute(requestedHash); }} />{/key}
{:else if route && knownRoute && (screen === 'account' || screen === 'welcome')}
  <Bases account={route[1]} onopen={base => void requestRoute(`#/a/${route[1]}/b/${base}`)} />
{:else if screen === 'welcome'}
  <Welcome onsignup={() => navigate('signup')} onsignin={() => navigate('signin')} />
{:else if screen === 'signup'}
  <SignUp {deviceName} oncreated={(result) => { session.account = result.account; knownAccounts = [...knownAccounts, result.account.id]; kitNotSaved = true; signedUp = result; void navigate('kit'); }} onback={() => void navigate('welcome')} />
{:else if screen === 'kit' && signedUp}
  <Kit kit={signedUp.kit} oncontinue={acknowledgeKit} onback={() => void navigate('account')} />
{:else if screen === 'signin'}
  <SignIn {deviceName} onpending={(id) => { pending = id; void navigate('pending'); }} onback={() => void navigate('welcome')} />
{:else if screen === 'pending' && pending !== null}
  <PendingSignIn {pending} onapproved={entered} oncancel={() => void cancelPending()} onrestart={() => void cancelPending('signin')} />
{:else if screen === 'removed'}
  <Removed oncontinue={() => void navigate('welcome')} />
{:else if session.account && (screen === 'account' || (knownRoute && (screen === 'search' || screen === 'devices')))}
  {#if screen === 'search'}
    <Search account={session.account.id} base={currentBase} {query} open={openHit} />
  {:else if screen === 'devices'}
    <Devices account={session.account.id} />
  {:else}
  <main class="entry-grid"><section class="entry-panel"><span class="eyebrow">YOUR SPACE</span><h1>BaseHero</h1>
    {#if kitNotSaved}
      <div class="kit-reminder" role="status">
        <p>You haven't saved your recovery kit. Make a new one so you can open your account on another device.</p>
        {#if !newKitOpen}<button onclick={() => { newKitOpen = true; newKitError = ''; }}>Make a new recovery kit</button>{/if}
      </div>
      {#if newKitOpen}
        <form onsubmit={makeKit}>
          <label>Password<input type="password" required autocomplete="current-password" bind:value={newPassword} /></label>
          {#if newKitError}<p class="error" role="alert">{newKitError}</p>{/if}
          <div class="actions"><button class="primary" type="submit" disabled={newKitBusy}>Make kit</button><button type="button" onclick={() => { newPassword = ''; newKitOpen = false; }}>Cancel</button></div>
        </form>
      {/if}
    {/if}
    <ApprovalRequests account={session.account.id} />
    <Bases account={session.account.id} onopen={base => void requestRoute(`#/a/${session.account!.id}/b/${base}`)} />
  </section></main>
  {/if}
{/if}
{#if quitSaveError}<p role="alert" class="quit-save-error">{quitSaveError}</p>{/if}
<UpdateBanner />
<style>
  .quit-save-error { position: fixed; z-index: 1000; bottom: 1rem; left: 1rem; padding: 1rem; background: var(--bar); color: var(--on-bar); }
  .location-bar { display: flex; align-items: center; gap: 1rem; min-height: 3.5rem; padding: .5rem 1rem; background: var(--bar); color: var(--on-bar); position: relative; }
  .location-bar a { color: var(--on-bar); font-weight: 600; }
  .location-bar form { flex: 1; display: block; }
  .location-bar input { width: 100%; padding: .5rem; background: var(--bar-2); color: var(--on-bar); border: 1px solid var(--bar-line); font: .85rem var(--sans); }
  .workspace-nav { display: flex; gap: 1.5rem; padding: 1rem 1.5rem; border-bottom: 1px solid var(--line); }
  :global(.workspace) { padding: clamp(1rem, 4vw, 3rem); max-width: 60rem; margin: auto; }
</style>
