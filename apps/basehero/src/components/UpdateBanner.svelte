<script lang="ts">
  import { onMount } from 'svelte';
  import { getBackend } from '../lib/backend';
  import type { UpdateInfo } from '../lib/backend/types';

  let update = $state<UpdateInfo | null>(null);
  let installing = $state(false);
  let error = $state('');
  const backend = getBackend();

  onMount(() => {
    let active = true;
    async function check() {
      try {
        const found = await backend.updateCheck();
        if (active) update = found;
      } catch {
        // An offline update check should not interrupt the app.
      }
    }
    void backend.appInfo().then(info => {
      if (active && info.platform === 'macos') {
        void check();
        timer = setInterval(check, 6 * 60 * 60 * 1000);
      }
    });
    let timer: ReturnType<typeof setInterval> | undefined;
    return () => { active = false; if (timer) clearInterval(timer); };
  });

  async function install() {
    if (installing) return;
    installing = true;
    error = '';
    try {
      await backend.updateInstall();
    } catch {
      error = 'Could not install the update. Try again.';
    } finally {
      installing = false;
    }
  }
</script>

{#if update}
  <aside aria-label="App update">
    <p>BaseHero {update.version} is ready</p>
    {#if update.notes}<p>{update.notes}</p>{/if}
    <button type="button" onclick={install} disabled={installing}>Restart to update</button>
    {#if error}<p role="alert">{error}</p>{/if}
  </aside>
{/if}
