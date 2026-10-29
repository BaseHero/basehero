<script lang="ts">
  import { getBackend } from '../lib/backend';
  import { drainAll, resumeAll } from '../lib/editor/host';
  import { errorMessage } from '../lib/errors';
  import type { BaseRef, ObjectId, ObjectSummary, Mount } from '../lib/backend/types';
  let { r, root, mounts, baseName, hidden = false, id, revision, onopen }: { r: BaseRef; root: BaseRef; mounts: Mount[]; baseName: string; hidden?: boolean; id: ObjectId | null; revision: number; onopen: (id: ObjectId | null, base?: string) => void } = $props();
  let locking = $state(false);
  let error = $state('');
  async function lock() {
    if (locking) return;
    locking = true;
    try { await drainAll('lock'); await getBackend().lockHidden(r.account, r.base); }
    catch (cause) { error = errorMessage(cause); }
    finally { locking = false; resumeAll('lock'); }
  }
  let path = $state<(ObjectSummary & { base: string })[]>([]);
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
    const outer = root.base;
    const knownMounts = mounts;
    revision; // Reload breadcrumbs when the selected item is renamed.
    const load = async () => {
      const items: (ObjectSummary & { base: string })[] = [];
      const seen = new Set<string>();
      let next = current;
      let base = r.base;
      while (next && !seen.has(`${base}:${next}`)) {
        seen.add(`${base}:${next}`);
        const item = await getBackend().getObject({ account: r.account, base }, next);
        if (!item) break;
        items.unshift({ ...item, base });
        next = item.parent;
        if (!next && base !== outer) {
          const mount = knownMounts.find(row => row.base === base);
          if (mount) { base = mount.parent; next = mount.folder; }
        }
      }
      if (active) path = items;
    };
    void load();
    return () => { active = false; };
  });
</script>
<nav aria-label="Location" class="location-bar">
  {#if id}<button onclick={() => onopen(null, root.base)}>{baseName}</button>{:else}<span class="plate">{baseName}</span>{/if}
  {#if hidden}<span class="hidden-tag">HIDDEN</span><button disabled={locking} onclick={lock}>Lock</button>{/if}
  {#if error}<span role="alert">{error}</span>{/if}
  {#each path as item, i (item.id)}
    <span aria-hidden="true">/</span>
    {#if i === path.length - 1}<span class="plate">{item.title || 'Untitled note'}</span>
    {:else}<button onclick={() => onopen(item.id, item.base)}>{item.title}</button>{/if}
  {/each}
  <form onsubmit={go}><label>Go to location <input aria-label="Go to location" bind:value={address} /></label><button type="submit">Go</button></form>
</nav>
<style>
  .hidden-tag { font: 500 .75rem var(--mono); letter-spacing: .05em; border: 1px solid var(--yellow); color: var(--yellow); padding: .25rem; }
</style>
