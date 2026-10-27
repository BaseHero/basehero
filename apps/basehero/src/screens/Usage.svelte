<script lang="ts">
  import { getBackend } from '../lib/backend';
  import { errorMessage } from '../lib/errors';
  import type { AccountUsage, UsageRow } from '../lib/backend/types';

  let { account }: { account: string } = $props();
  const thisMonth = new Date().toISOString().slice(0, 7);
  let selected = $state(thisMonth);
  let report = $state<AccountUsage | null>(null);
  let error = $state('');
  let loading = $state(true);
  let generation = 0;

  async function refresh(account: string, month: string) {
    const request = ++generation;
    loading = true;
    error = '';
    try {
      const result = await getBackend().usage(account, month);
      if (request === generation) report = result;
    } catch (cause) { if (request === generation) error = errorMessage(cause); }
    finally { if (request === generation) loading = false; }
  }
  $effect(() => { void refresh(account, selected); });

  type Total = { name: string; calls: number; unreported: number; cost: number; price: number; storedBytes: number };
  function totals(rows: UsageRow[], key: (row: UsageRow) => [string, string]): Total[] {
    const values = new Map<string, Total>();
    for (const row of rows) {
      const [id, name] = key(row);
      const total = values.get(id) ?? { name, calls: 0, unreported: 0, cost: 0, price: 0, storedBytes: 0 };
      total.calls += row.requests;
      total.unreported += row.unreported;
      total.cost += row.costMicroUsd;
      total.price += row.priceMicroUsd;
      total.storedBytes += row.storedBytes;
      values.set(id, total);
    }
    return [...values.values()].sort((a, b) => b.price - a.price || a.name.localeCompare(b.name));
  }
  function money(micro: number): string {
    const dollars = micro / 1_000_000;
    return `$${dollars.toFixed(dollars < .1 && micro !== 0 ? 4 : 2)}`;
  }
  function byteSize(bytes: number): string {
    return bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(bytes % (1024 * 1024) === 0 ? 0 : 1)} MiB stored` : `${bytes} bytes stored`;
  }
  let months = $derived(totals(report?.months ?? [], row => [row.period, row.period]).sort((a, b) => b.name.localeCompare(a.name)));
  let current = $derived((report?.months ?? []).filter(row => row.period === selected));
  let monthTotal = $derived(totals(current, () => ['total', 'total'])[0]);
  let services = $derived(totals(current, row => [row.service, row.service]));
  let bases = $derived(totals(current, row => {
    // Known hidden-bases limit: someone holding an unlocked device can see how
    // many hidden bases exist. Fold unnamed storage into Other so totals add up.
    const name = row.base ? report?.baseNames[row.base] : undefined;
    return name ? [row.base!, name] : row.base === null && row.device === null ? ['legacy', 'not broken down'] : ['other', 'Other'];
  }));
  let apps = $derived(totals(current.filter(row => row.service !== 'storage'), row => row.device
    ? [row.device, report?.deviceNames[row.device] || 'a removed device']
    : ['legacy', 'not broken down']));
  let days = $derived(totals(report?.days ?? [], row => [row.period, row.period]).sort((a, b) => b.name.localeCompare(a.name)));
</script>

<main class="workspace usage-screen">
  <span class="eyebrow">ACCOUNT / USAGE</span>
  <h1>Usage</h1>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if report}
    <div class="hero-total"><span class="eyebrow">YOUR PRICE</span><p>{selected === thisMonth ? 'This month' : selected}: <strong>{money(monthTotal?.price ?? 0)}</strong></p></div>
    {#if current.some(row => row.service === 'storage')}<p class="storage-period">Storage is a month at today's size.</p>{/if}
    {#if !report.months.length}
      <p>No use yet.</p>
    {:else}
      {#if monthTotal?.unreported}<p class="unreported">Calls with no reported cost: {monthTotal.unreported}</p>{/if}
      <div class="breakdowns">
        {#each [{ title: 'By service', key: 'service', entries: services }, { title: 'By base', key: 'base', entries: bases }, { title: 'By app', key: 'app', entries: apps }] as group}
          <section class="breakdown" data-usage-group={group.key}>
            <h2>{group.title}</h2>
            <ul>{#each group.entries as entry}
              <li><span class="name">{entry.name}</span><span class="amount">{money(entry.price)}</span><small>{#if entry.storedBytes}{byteSize(entry.storedBytes)}{#if entry.calls} · {/if}{/if}{#if entry.calls || !entry.storedBytes}{entry.calls} {entry.calls === 1 ? 'call' : 'calls'}{/if}</small></li>
            {/each}</ul>
          </section>
        {/each}
      </div>
      <section class="history"><h2>Months</h2>
        <table><thead><tr><th scope="col">Month</th><th scope="col">Calls</th><th scope="col">Our cost</th><th scope="col">Price</th></tr></thead>
          <tbody>{#each months as item}<tr class:chosen={item.name === selected}><th scope="row"><button class="month-button" aria-current={item.name === selected ? 'true' : undefined} onclick={() => selected = item.name}>{item.name}</button></th><td>{item.calls}</td><td>{money(item.cost)}</td><td>{money(item.price)}</td></tr>{/each}</tbody></table>
      </section>
      <section class="history"><h2>Days · {selected}</h2>
        {#if days.length}<table><thead><tr><th scope="col">Day</th><th scope="col">Calls</th><th scope="col">Our cost</th><th scope="col">Price</th></tr></thead>
          <tbody>{#each days as item}<tr><th scope="row">{item.name}</th><td>{item.calls}</td><td>{money(item.cost)}</td><td>{money(item.price)}</td></tr>{/each}</tbody></table>
        {:else if !loading}<p>No use this month.</p>{/if}
      </section>
    {/if}
    <p class="utc">Days and months are UTC.</p>
  {/if}
</main>
<style>
  .usage-screen { min-width: 0; }
  .usage-screen h1 { margin: .35rem 0 1.5rem; }
  .hero-total { padding: 1.4rem; border: 1px solid var(--line-strong); background: var(--panel); margin-bottom: 1.5rem; }
  .hero-total p { color: var(--text); margin: .4rem 0 0; font-size: clamp(1.3rem, 5vw, 2rem); letter-spacing: -.03em; }
  .hero-total strong { font-family: var(--mono); font-weight: 600; }
  .storage-period { margin: -1rem 0 1.5rem; font: .75rem var(--mono); color: var(--text-3); }
  .unreported { margin-bottom: 1rem; }
  .breakdowns { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; }
  .breakdown { min-width: 0; border: 1px solid var(--line); background: var(--panel); padding: 1rem; }
  h2 { margin: 0 0 .85rem; font: 600 .8rem var(--mono); text-transform: uppercase; }
  ul { list-style: none; margin: 0; padding: 0; }
  li { display: grid; grid-template-columns: minmax(0, 1fr) auto; gap: .15rem .4rem; padding: .6rem 0; border-top: 1px solid var(--line); }
  .name { min-width: 0; overflow-wrap: anywhere; }
  .amount { font: 600 .9rem var(--mono); white-space: nowrap; }
  li small { grid-column: 1 / -1; }
  .history { margin-top: 2rem; }
  table { border-collapse: collapse; width: 100%; table-layout: fixed; font: .8rem var(--mono); }
  th, td { padding: .7rem .35rem; border-bottom: 1px solid var(--line); text-align: right; overflow-wrap: anywhere; }
  th:first-child { text-align: left; width: 30%; }
  th:nth-child(2) { width: 14%; }
  thead th { color: var(--text-3); font-weight: 500; }
  .chosen { background: var(--panel); }
  .month-button { border: 0; padding: .1rem; font: inherit; text-align: left; text-transform: none; text-decoration: underline; }
  .utc { margin: 1.5rem 0; font: .75rem var(--mono); color: var(--text-3); }
  @media (max-width: 700px) {
    .breakdowns { grid-template-columns: 1fr; }
    table { font-size: .68rem; }
    th, td { padding: .65rem .15rem; }
    th:first-child { width: 31%; }
    th:nth-child(2) { width: 13%; }
  }
</style>
