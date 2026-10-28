<script lang="ts">
  import { onMount, tick } from 'svelte';
  import type { HeroEvent } from '../generated/HeroEvent';
  import type { AccountId, BaseId, ObjectId, ChatMessage, AppEvent } from '../backend/types';
  import { openObject } from '../route.svelte';
  import { errorMessage } from '../errors';
  import { hero } from './hero';

  let { account, base, focus, project }: { account: AccountId; base: BaseId; focus: ObjectId | null; project: ObjectId | null } = $props();
  let chat = $state<ObjectId | null>(null);
  let messages = $state<ChatMessage[]>([]);
  let conversation: HTMLDivElement;
  function showMessages(next: ChatMessage[]) {
    const follow = conversation && conversation.scrollHeight - conversation.scrollTop - conversation.clientHeight <= 2;
    messages = next;
    if (follow) void tick().then(() => { if (conversation) conversation.scrollTop = conversation.scrollHeight; });
  }
  let text = $state('');
  let error = $state('');
  let createdNames = $state<Record<string, string>>({});
  let active = true;
  let loadNumber = 0;
  let api = $derived(hero(account, base));
  let last = $derived(messages.at(-1));
  let working = $derived(last?.role === 'hero' && last.state === 'working');

  async function reload(id: ObjectId) {
    const load = ++loadNumber;
    try {
      const next = await api.messages(id);
      if (!active || chat !== id || load !== loadNumber) return;
      showMessages(next);
      const names: Record<string, string> = {};
      await Promise.all(next.flatMap(message => message.created).map(async object => {
        // One note that can't be read (gone, or from a newer version) shouldn't hide the rest.
        const summary = await api.getObject({ account, base }, object).catch(() => null);
        if (summary && !summary.deleted) names[object] = summary.title;
      }));
      if (active && chat === id && load === loadNumber) createdNames = names;
    } catch (cause) { if (active && chat === id && load === loadNumber) error = errorMessage(cause); }
  }
  $effect(() => {
    const selected = project;
    const controller = api;
    let current = true;
    chat = null; messages = []; createdNames = {}; error = '';
    void controller.chatFor(selected).then(id => {
      if (current && active) { chat = id; void reload(id); }
    }).catch(cause => { if (current && active) error = errorMessage(cause); });
    return () => { current = false; };
  });
  onMount(() => {
    active = true;
    let stop = () => {};
    void api.onEvent((event: AppEvent) => {
      if (event.kind.toLowerCase() !== 'hero' || event.account !== account || event.base !== base || event.chat !== chat || !chat) return;
      const update = event.event as HeroEvent;
      if (update && 'text' in update) {
        const { message, text: reply, base: eventBase, chat: eventChat } = update.text;
        const current = messages.at(-1);
        if (eventBase === base && eventChat === chat && current?.id === message && current.role === 'hero' && current.state === 'working') {
          showMessages([...messages.slice(0, -1), { ...current, text: reply }]);
        }
      } else void reload(chat);
    }).then(unsubscribe => { if (active) stop = unsubscribe; else unsubscribe(); });
    return () => { active = false; stop(); };
  });
  async function send(event: SubmitEvent) {
    event.preventDefault();
    if (!chat || !text.trim() || working) return;
    const value = text.trim(); text = ''; error = '';
    try { await api.send(chat, value, focus); await reload(chat); }
    catch (cause) { text = value; error = errorMessage(cause); }
  }
  async function act(action: () => Promise<void>) {
    error = '';
    try { await action(); if (chat) await reload(chat); }
    catch (cause) { error = errorMessage(cause); }
  }
  function failure(code: string | null): string {
    switch (code) {
      case 'interrupted': return 'Hero stopped when this device closed.';
      case 'rate_limited': return 'Hero has reached its limit for now. Try again later.';
      case 'verification': return "Hero couldn't verify the model's secure hardware, so it sent nothing.";
      case 'needs_update': return 'Update BaseHero to keep using Hero.';
      default: return "Hero couldn't reply.";
    }
  }
</script>
<section class="hero-panel" aria-label="Hero">
  <header><span class="eyebrow">ASSISTANT</span><h2>Hero</h2></header>
  <div class="conversation" aria-live="polite" bind:this={conversation}>
    {#each messages as message (message.id)}
      <article class:user={message.role === 'user'}>
        <span class="speaker">{message.role === 'user' ? 'You' : 'Hero'}</span>
        {#if message.text}<p>{message.text}</p>{/if}
        {#if message.role === 'hero'}
          {#if message.state === 'working' && !message.text}<p class="status">Hero is working…</p>{/if}
          {#if message.state === 'working' && message.steps.length}<p class="step">{message.steps.at(-1)?.title ?? message.steps.at(-1)?.tool}</p>{/if}
          {#if message.state === 'stopped'}<p class="status">Stopped.</p>{/if}
          {#if message.state === 'failed'}<p class="status">{message.text && message.error !== 'interrupted' ? "Hero's reply stopped partway." : failure(message.error)}</p>{#if (message.text && message.error !== 'interrupted') || (message.error !== 'rate_limited' && message.error !== 'needs_update')}<button onclick={() => chat && act(() => api.retry(chat!))}>Retry</button>{/if}{/if}
          {#if message.ask && message.state === 'asking' && message.id === messages.findLast(m => m.role === 'hero')?.id}
            <p>Hero wants to use {message.ask.baseName} in this chat. {message.ask.readersWithout.join(' and ')} can read this chat's base but not {message.ask.baseName}.</p>
            <div class="actions"><button onclick={() => chat && message.ask && act(() => api.answer(chat!, message.ask!.base, true))}>Allow in this chat</button><button onclick={() => chat && message.ask && act(() => api.answer(chat!, message.ask!.base, false))}>Not now</button></div>
          {/if}
          {#each message.created as object (object)}
            {#if Object.hasOwn(createdNames, object)}
              <button class="created" onclick={() => openObject(base, object)}>{createdNames[object]}</button>
            {/if}
          {/each}
        {/if}
      </article>
    {/each}
  </div>
  {#if error}<p role="alert">{error}</p>{/if}
  <form onsubmit={send}>
    <label for="hero-prompt">Ask Hero</label>
    <textarea id="hero-prompt" rows="3" placeholder="Ask about your notes…" bind:value={text} disabled={!chat || working}></textarea>
    {#if working}<button type="button" onclick={() => chat && act(() => api.stop(chat!))}>Stop</button>{/if}
    <button type="submit" disabled={!chat || working || !text.trim()}>Send</button>
  </form>
</section>
<style>
  .hero-panel { display: flex; flex-direction: column; height: 100%; min-height: 24rem; background: var(--paper, #faf9f6); border-left: 1px solid var(--line); font: .9rem var(--sans); }
  header { padding: 1rem 1.25rem; border-bottom: 1px solid var(--line); }
  h2 { font-size: 1.25rem; margin: .25rem 0 0; }
  .conversation { flex: 1; overflow-y: auto; padding: 1.25rem; }
  article { margin-bottom: 1.5rem; }
  .speaker { font-size: .7rem; font-weight: 600; text-transform: uppercase; letter-spacing: .08em; opacity: .65; }
  article p { white-space: pre-wrap; overflow-wrap: anywhere; line-height: 1.5; margin: .5rem 0; }
  article.user { border-left: 2px solid var(--line); padding-left: .75rem; }
  .status, .step { opacity: .7; }
  .created { display: block; margin-top: .75rem; }
  .actions { display: flex; flex-wrap: wrap; gap: .5rem; }
  form { border-top: 1px solid var(--line); padding: 1rem; display: grid; gap: .5rem; }
  textarea { width: 100%; resize: vertical; font: inherit; padding: .6rem; border: 1px solid var(--line); color: inherit; background: transparent; }
  form button { justify-self: end; }
</style>
