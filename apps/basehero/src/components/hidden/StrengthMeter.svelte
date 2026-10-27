<script lang="ts">
  import { getBackend } from '../../lib/backend';
  import type { PasswordStrength } from '../../lib/backend/types';
  let { password, email, name }: { password: string; email: string; name: string } = $props();
  let strength = $state<PasswordStrength | null>(null);
  $effect(() => {
    const typed = password, context = [email, name];
    strength = null;
    if (!typed) return;
    let active = true;
    const timer = setTimeout(() => { void getBackend().passwordStrength(typed, context).then(result => { if (active) strength = result; }); }, 150);
    return () => { active = false; clearTimeout(timer); };
  });
  let label = $derived(strength ? ['Weak', 'Weak', 'Fair', 'Good', 'Strong'][strength.score] : '');
</script>
{#if strength}
  <div class="strength" aria-live="polite"><span class="eyebrow">PASSWORD STRENGTH</span><strong>{label}</strong>
    {#if !strength.strong}
      <p>Add another word or two. Length helps more than symbols.</p>
      {#if strength.warning}<p>{strength.warning}</p>{/if}
      {#each strength.suggestions as suggestion}<p>{suggestion}</p>{/each}
    {/if}
  </div>
{/if}
<style>
  .strength { padding: .75rem; border-left: 4px solid var(--yellow); background: var(--panel-2); }
  strong { display: block; margin: .4rem 0; }
  p { margin: .4rem 0; color: var(--text-2); }
</style>
