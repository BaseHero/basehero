<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../lib/backend';
  import type { SearchResult } from '../lib/backend/types';
  let { account, base, query, open }: { account: string; base: string | null; query: string; open: (result: SearchResult) => void } = $props();
  let groups = $state<{ base: string; name: string; results: SearchResult[] }[]>([]);
  const label = (name: string) => ({ 'core.note': 'Note', 'core.folder': 'Folder', 'core.project': 'Project' })[name as 'core.note' | 'core.folder' | 'core.project'] ?? name;
  let error = $state('');
  let revision = $state(0);
  onMount(() => {
    let active = true;
    let stop: (() => void) | undefined;
    void getBackend().onEvent(event => {
      if (active && event.kind.toLowerCase() === 'account' && event.account === account &&
          (event.event === 'BasesChanged' || (typeof event.event === 'object' && event.event !== null && 'BasesChanged' in event.event))) {
        revision++;
        groups = []; // Clear visible plaintext before any replacement request completes.
      }
    }).then(unsubscribe => { if (active) stop = unsubscribe; else unsubscribe(); });
    return () => { active = false; stop?.(); };
  });
  $effect(() => {
    const text = query.trim();
    const requestedRevision = revision;
    let active = true;
    groups = [];
    error = '';
    if (text) {
      void (async () => {
        try {
          const results = await getBackend().search(account, base, text, 50);
          const grouped = new Map<string, { base: string; name: string; results: SearchResult[] }>();
          for (const result of results) {
            if (!grouped.has(result.base)) grouped.set(result.base, { base: result.base, name: result.baseName, results: [] });
            grouped.get(result.base)!.results.push(result);
          }
          if (active && requestedRevision === revision) groups = [...grouped.values()];
        } catch { if (active && requestedRevision === revision) error = 'Search is unavailable. Try again.'; }
      })();
    }
    return () => { active = false; };
  });
</script>
<main class="workspace"><h1>Search</h1>
  {#if error}<p role="alert">{error}</p>{/if}
  {#each groups as group (group.base)}
    <section data-search-base={group.base}>
      <h2>{group.name}</h2>
      <ul>{#each group.results as result (result.hit.id)}
        <li><a href={`#/a/${account}/b/${result.base}/n/${result.hit.id}`} onclick={(event) => { event.preventDefault(); open(result); }}>{result.hit.title}</a>
          <small>{label(result.hit.ty.name)}</small>{#if result.hit.snippet}<p>{result.hit.snippet}</p>{/if}</li>
      {/each}</ul>
    </section>
  {/each}
</main>
<style>
  section { border-top: 1px solid var(--line); margin-top: 1.5rem; }
  ul { list-style: none; padding: 0; }
  li { padding: .85rem 0; border-bottom: 1px solid var(--line); display: flex; gap: 1rem; align-items: baseline; }
  small { color: var(--text-3); }
</style>
