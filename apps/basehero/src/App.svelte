<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { getBackend } from './lib/backend';
  import type { AccountSummary, BaseRef, ObjectId, SearchResult, SignedUp } from './lib/backend/types';
  import { SyncStatus } from './lib/sync.svelte';
  import Search from './screens/Search.svelte';
  import Devices from './screens/Devices.svelte';
  import Removed from './screens/Removed.svelte';
  import StatusBar from './components/StatusBar.svelte';
  import KeyError from './screens/KeyError.svelte';
  import { errorMessage } from './lib/errors';
  import { session } from './lib/session.svelte';
  import NoteEditor from './components/NoteEditor.svelte';
  import Welcome from './screens/Welcome.svelte';
  import UpdateBanner from './components/UpdateBanner.svelte';
  import SignUp from './screens/SignUp.svelte';
  import Kit from './screens/Kit.svelte';
  import SignIn from './screens/SignIn.svelte';
  import PendingSignIn from './screens/PendingSignIn.svelte';

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
  let searchField = $state<HTMLInputElement>();
  const sync = new SyncStatus();
  const removedAccounts = new Set<string>();
  function ref(): BaseRef | null {
    return session.account && currentBase ? { account: session.account.id, base: currentBase } : null;
  }
  function submitSearch(event: SubmitEvent) {
    event.preventDefault();
    if (!session.account || !searchText.trim()) return;
    query = searchText.trim();
    location.hash = `/a/${session.account.id}/search?q=${encodeURIComponent(query)}`;
    screen = 'search';
  }
  async function showBase(event: MouseEvent) {
    event.preventDefault();
    if (!session.account) return;
    const bases = await getBackend().bases(session.account.id);
    currentBase = bases.find(base => base.name === 'Personal')?.id ?? bases[0]?.id ?? null;
    if (currentBase) {
      location.hash = `/a/${session.account.id}/b/${currentBase}`;
      void sync.refresh(getBackend(), { account: session.account.id, base: currentBase });
    }
    screen = 'account';
  }
  function openHit(result: SearchResult) {
    if (!session.account) return;
    currentBase = result.base;
    void sync.refresh(getBackend(), { account: session.account.id, base: result.base });
    screen = 'account';
    void requestRoute(`#/a/${session.account.id}/b/${result.base}/n/${result.hit.id}`);
  }

  let hash = $state(location.hash);
  let leave: (() => Promise<boolean>) | undefined;
  let requestedHash = '';
  let transitioning = false;
  let route = $derived(/^#\/a\/([^/]+)\/b\/([^/]+)\/n\/([^/]+)$/.exec(hash));

  $effect(() => {
    screen;
    hash;
    void tick().then(() => {
      const heading = document.querySelector<HTMLElement>('main h1');
      if (heading) { heading.tabIndex = -1; heading.focus(); }
    });
  });
  function navigate(next: Screen) {
    history.pushState(null, '', '/'); // Never put credentials, pending ids, or kits in URLs or history.
    hash = '';
    screen = next;
  }
  function onleave(hook: () => Promise<boolean>) {
    leave = hook;
    return () => { if (leave === hook) leave = undefined; };
  }
  function leaveKit() {
    if (!window.confirm("You haven't saved your recovery kit. You won't be able to see it again. Leave anyway?")) return false;
    signedUp = null;
    screen = 'account';
    return true;
  }
  function allowed(next: string): boolean {
    const account = /^#\/a\/([^/]+)/.exec(next)?.[1];
    return !account || (screen !== 'removed' && !removedAccounts.has(account));
  }
  async function requestRoute(next: string) {
    if (!allowed(next)) {
      history.replaceState(null, '', location.pathname + location.search + hash);
      return;
    }
    if (next === hash) return;
    requestedHash = next;
    if (transitioning) return;
    transitioning = true;
    try {
      if (screen === 'kit' && signedUp && !leaveKit()) return;
      if (route && leave && !await leave()) return;
      // A newer route requested during the editor drain wins; removal cancels both.
      const destination = requestedHash;
      if (!allowed(destination)) {
        history.replaceState(null, '', location.pathname + location.search + hash);
        return;
      }
      hash = destination;
      if (location.hash !== destination) location.hash = destination;
      if (/^#\/a\/[^/]+\/search(?:\?|$)/.test(destination)) {
        query = new URLSearchParams(destination.split('?')[1] ?? '').get('q') ?? '';
        searchText = query;
        screen = 'search';
      } else if (destination.includes('/devices')) screen = 'devices';
      else if (destination.startsWith('#/a/')) screen = 'account';
      requestedHash = '';
    } finally { transitioning = false; }
  }
  function navigateNote(r: BaseRef, id: ObjectId) {
    void requestRoute(`#/a/${r.account}/b/${r.base}/n/${id}`);
  }
  async function openAccount(account: AccountSummary) {
    session.account = account;
    kitNotSaved = !(await getBackend().kitSaved(account.id));
    if (session.account?.id === account.id) {
      currentBase = null;
      sync.clear();
      if (route) screen = 'account'; // Keep a directly opened note route mounted.
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
  async function cancelPending() {
    const id = pending;
    pending = null;
    screen = 'welcome';
    if (id !== null) {
      try { await getBackend().signInCancel(id); } catch { /* A cancelled request cannot be retried here. */ }
    }
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
      if (active && accounts.length && screen === 'welcome') void openAccount(accounts[0]);
    }).catch(cause => {
      if (active) keyError = startupError(cause);
    });
    let unsubscribe: (() => void) | undefined;
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
        if (event.event === 'NeedsUpdate' || (typeof event.event === 'object' && event.event !== null && 'NeedsUpdate' in event.event)) sync.needsUpdate = true;
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
      if (route && (screen === 'account' || screen === 'welcome')) {
        if (!popped) void requestRoute('');
      } else if (screen === 'kit' && signedUp) {
        const left = leaveKit();
        // A refused browser Back must restore the history entry so a later Back is still guarded.
        if (popped || left) history.pushState(null, '', '/');
      } else if (pending !== null) void cancelPending();
      else screen = session.account ? 'account' : 'welcome';
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
      window.removeEventListener('keydown', shortcut);
      delete window.__bhBack;
      window.removeEventListener('popstate', pop);
      window.removeEventListener('hashchange', update);
      window.removeEventListener('beforeunload', beforeUnload);
    };
  });
</script>
{#if keyError}
  <KeyError kind={keyError.kind} message={keyError.message} />
{:else if route && (screen === 'account' || screen === 'welcome') && !removedAccounts.has(route[1])}
  {#key hash}<NoteEditor r={{ account: route[1], base: route[2] }} id={route[3]} readOnly={false}
    onnavigate={navigateNote} {onleave} retryleave={() => { if (requestedHash) void requestRoute(requestedHash); }} />{/key}
{:else if screen === 'welcome'}
  <Welcome onsignup={() => navigate('signup')} onsignin={() => navigate('signin')} />
{:else if screen === 'signup'}
  <SignUp {deviceName} oncreated={(result) => { session.account = result.account; kitNotSaved = true; signedUp = result; navigate('kit'); }} onback={() => screen = 'welcome'} />
{:else if screen === 'kit' && signedUp}
  <Kit kit={signedUp.kit} oncontinue={acknowledgeKit} onback={() => { if (leaveKit()) history.pushState(null, '', '/'); }} />
{:else if screen === 'signin'}
  <SignIn {deviceName} onpending={(id) => { pending = id; navigate('pending'); }} onback={() => screen = 'welcome'} />
{:else if screen === 'pending' && pending !== null}
  <PendingSignIn {pending} onapproved={entered} oncancel={cancelPending} />
{:else if screen === 'removed'}
  <Removed oncontinue={() => { history.replaceState(null, '', '/'); screen = 'welcome'; }} />
{:else if session.account && (screen === 'account' || screen === 'search' || screen === 'devices')}
  <header class="location-bar">
    <a href="/" onclick={(event) => { event.preventDefault(); void requestRoute(''); screen = 'account'; }}>BaseHero</a>
    <form role="search" onsubmit={submitSearch}><input type="search" aria-label="Search" placeholder="Search" bind:value={searchText} bind:this={searchField} /></form>
    <StatusBar {sync} mac={platform === 'macos'} />
  </header>
  <nav class="workspace-nav"><a href={`#/a/${session.account.id}/b/${currentBase ?? ''}`} onclick={showBase}>Personal</a>
    <a href={`#/a/${session.account.id}/devices`} onclick={(event) => { event.preventDefault(); void requestRoute(`#/a/${session.account?.id}/devices`); }}>Devices</a></nav>
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
  </section></main>
  {/if}
{/if}
<UpdateBanner />
<style>
  .location-bar { display: flex; align-items: center; gap: 1rem; min-height: 3.5rem; padding: .5rem 1rem; background: var(--bar); color: var(--on-bar); position: relative; }
  .location-bar a { color: var(--on-bar); font-weight: 600; }
  .location-bar form { flex: 1; display: block; }
  .location-bar input { width: 100%; padding: .5rem; background: var(--bar-2); color: var(--on-bar); border: 1px solid var(--bar-line); font: .85rem var(--sans); }
  .workspace-nav { display: flex; gap: 1.5rem; padding: 1rem 1.5rem; border-bottom: 1px solid var(--line); }
  :global(.workspace) { padding: clamp(1rem, 4vw, 3rem); max-width: 60rem; margin: auto; }
</style>
