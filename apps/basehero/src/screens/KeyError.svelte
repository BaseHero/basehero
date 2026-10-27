<script lang="ts">
  let { kind, message }: { kind: string; message: string } = $props();
</script>

<main role="alert">
  <h1>BaseHero can't reach its key on this device.</h1>
  <p>Close BaseHero and open it again. If this keeps happening, restart the device.</p>
  <details>
    <summary>Technical details</summary>
    <p>{kind}: {message}</p>
  </details>
</main>

<style>
  h1 { font-size: 1.75rem; max-width: 22ch; margin-inline: auto; }
</style>
