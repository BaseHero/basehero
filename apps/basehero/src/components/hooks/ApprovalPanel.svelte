<script lang="ts">
  import type { AccountSummary } from '../../lib/backend/types';
  // Device approval fills this hook in a later task.
  let { pending: _pending, onapproved: _onapproved }: { pending: string; onapproved: (a: AccountSummary) => void } = $props();
</script>
<section class="approval-panel"><h2>Approval in the app</h2></section>
