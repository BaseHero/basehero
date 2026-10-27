<script lang="ts">
  import { getBackend } from '../lib/backend';
  import type { BaseRef, ObjectId, ObjectSummary } from '../lib/backend/types';
  let { r, baseName, id, revision, onopen }: { r: BaseRef; baseName: string; id: ObjectId | null; revision: number; onopen: (id: ObjectId | null) => void } = $props();
  let path = $state<ObjectSummary[]>([]);
  let address = $state('');
  $effect(() => { address = `/a/${r.account}/b/${r.base}${id ? `/n/${id}` : ''}`; });
  function go(event: SubmitEvent) {
    event.preventDefault();
    const target = address.trim().replace(/^#/, '');
    if (new RegExp(`^/a/${r.account}/(?:search\\?q=[^#]*|devices|b/[^/]+(?:/n/[^/]+)?)$`).test(target)) location.hash = target;
  }
  $effect(() => {
    let active = true;
    const current = id;
    revision; // Reload breadcrumbs when the selected item is renamed.
    const load = async () => {
      const items: ObjectSummary[] = [];
      const seen = new Set<string>();
      let next = current;
      while (next && !seen.has(next)) {
        seen.add(next);
        const item = await getBackend().getObject(r, next);
        if (!item) break;
        items.unshift(item);
        next = item.parent;
      }
      if (active) path = items;
    };
    void load();
    return () => { active = false; };
  });
</script>
<nav aria-label="Location" class="location-bar">
  {#if id}<button onclick={() => onopen(null)}>{baseName}</button>{:else}<span class="plate">{baseName}</span>{/if}
  {#each path as item, i (item.id)}
    <span aria-hidden="true">/</span>
    {#if i === path.length - 1}<span class="plate">{item.title || 'Untitled note'}</span>
    {:else}<button onclick={() => onopen(item.id)}>{item.title}</button>{/if}
  {/each}
  <form onsubmit={go}><label>Go to location <input aria-label="Go to location" bind:value={address} /></label><button type="submit">Go</button></form>
</nav>
