<script lang="ts">
  let { oncontinue }: { oncontinue: () => void } = $props();
</script>
<main class="entry-grid"><section class="entry-panel">
  <span class="eyebrow">ACCOUNT / DEVICE</span>
  <h1>Device removed</h1>
  <p>This device was removed from your account. Its notes and keys have been erased from it.</p>
  <button class="primary" onclick={oncontinue}>Continue</button>
</section></main>
