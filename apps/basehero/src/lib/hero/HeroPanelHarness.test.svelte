<script lang="ts">
  import HeroPanel from './HeroPanel.svelte';
  let project = $state<string | null>(null);
</script>
<button onclick={() => project = 'project-2'}>Switch project</button>
<HeroPanel account="a" base="b" focus="note" {project} />
