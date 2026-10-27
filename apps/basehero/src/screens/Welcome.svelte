<script lang="ts">
  import { getBackend } from '../lib/backend';
  let { onsignup, onsignin }: { onsignup: () => void; onsignin: () => void } = $props();
  let version = $state('');
  getBackend().appInfo().then(info => { version = info.version; });
</script>
<main class="entry-grid">
  <section class="entry-panel">
    <span class="eyebrow">PRIVATE BY DESIGN / 001</span>
    <h1>BaseHero</h1>
    <p>Your space for notes and ideas.</p>
    <div class="actions"><button class="primary" onclick={onsignup}>Create account</button><button onclick={onsignin}>Sign in</button></div>
    {#if version}<small>Version {version}</small>{/if}
  </section>
</main>
