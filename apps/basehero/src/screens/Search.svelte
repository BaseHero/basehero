<script lang="ts">
  import { getBackend } from '../lib/backend';
  import type { BaseSummary, SearchResult } from '../lib/backend/types';
  let { account, base, query, open }: { account: string; base: string | null; query: string; open: (result: SearchResult) => void } = $props();
  let groups = $state<{ base: BaseSummary; results: SearchResult[] }[]>([]);
  let error = $state('');
  $effect(() => {
    const text = query.trim();
    let active = true;
    groups = [];
    error = '';
    if (text) {
      void (async () => {
        try {
          const bases = await getBackend().bases(account);
          const sorted = [...bases].sort((a, b) => Number(b.id === base) - Number(a.id === base));
          const results = await Promise.all(sorted.map(async item => ({ base: item, results: await getBackend().search(account, item.id, text, 50) })));
          if (active) groups = results.filter(group => group.results.length > 0);
        } catch { if (active) error = 'Search is unavailable. Try again.'; }
      })();
    }
    return () => { active = false; };
  });
</script>
<main class="workspace"><h1>Search</h1>
  {#if error}<p role="alert">{error}</p>{/if}
  {#each groups as group (group.base.id)}
    <section data-search-base={group.base.id}>
      <h2>{group.base.name}</h2>
      <ul>{#each group.results as result (result.hit.id)}
        <li><a href={`#/a/${account}/b/${result.base}/n/${result.hit.id}`} onclick={(event) => { event.preventDefault(); open(result); }}>{result.hit.title}</a>
          <small>{result.hit.ty}</small>{#if result.hit.snippet}<p>{result.hit.snippet}</p>{/if}</li>
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
