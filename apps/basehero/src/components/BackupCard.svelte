<script lang="ts">
  let { label, saved, onchange, onok, onkit, busy }: { label: string; saved: boolean; onchange: () => void; onok: () => void; onkit: () => void; busy: boolean } = $props();
</script>
<section class="backup-card" aria-label="Your backup">
  <span class="eyebrow">YOUR BACKUP</span>
  <p>BaseHero keeps an encrypted backup in {label}. It opens with your password and recovery kit, even without BaseHero's servers.</p>
  <div class="actions"><button type="button" disabled={busy} onclick={onchange}>Change folder…</button><button type="button" class="primary" disabled={busy} onclick={onok}>OK</button>{#if !saved}<button type="button" onclick={onkit}>Save your kit</button>{/if}</div>
</section>
<style>
  .backup-card { background: var(--panel); border: 1px solid var(--line-strong); padding: 1.2rem; margin: 1rem 0; }
  p { margin: .75rem 0; }
  .actions { display: flex; gap: .6rem; flex-wrap: wrap; }
</style>
