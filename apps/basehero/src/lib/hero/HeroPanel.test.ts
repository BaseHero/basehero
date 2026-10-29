// @vitest-environment jsdom
import { afterEach, beforeEach, expect, test, vi } from 'vitest';
import { mount, unmount, tick } from 'svelte';
import { FakeBackend } from '../backend/fake';
import { session } from '../session.svelte';
import type { ChatMessage } from '../generated/ChatMessage';
import HeroPanelHarness from './HeroPanelHarness.test.svelte';

const fake = vi.hoisted(() => ({ backend: null as FakeBackend | null }));
vi.mock('../backend', () => ({ getBackend: () => fake.backend }));
const account = 'a', base = 'b', focus = 'note', chat = 'chat';
const message = (state: ChatMessage['state'], overrides: Partial<ChatMessage> = {}): ChatMessage => ({
  id: 'hero', role: 'hero', text: '', at: '2026-10-30T00:00:00Z', state, error: null, steps: [], created: [], ask: null, ...overrides,
});
let target: HTMLDivElement;
let component: ReturnType<typeof mount>;
const flush = async () => { await new Promise(resolve => setTimeout(resolve, 0)); await tick(); };
const button = (label: string) => [...target.querySelectorAll('button')].find(el => el.textContent?.trim() === label)!;
const send = async (text: string) => {
  const input = target.querySelector('textarea')!;
  input.value = text;
  input.dispatchEvent(new Event('input', { bubbles: true }));
  await tick(); button('Send').click(); await flush();
};
beforeEach(async () => {
  fake.backend = new FakeBackend();
  fake.backend.seedHeroChat(account, base, null, chat);
  session.account = { id: account, email: 'test@example.test', kind: 'full', signedOutByServer: false };
  target = document.createElement('div'); document.body.append(target);
  component = mount(HeroPanelHarness, { target });
  await flush();
});
afterEach(async () => { await unmount(component); target.remove(); session.account = null; fake.backend = null; location.hash = ''; vi.restoreAllMocks(); });

test('sending shows the user message and disables Send while Hero works', async () => {
  await send('What happened in Kyoto?');
  expect(target.textContent).toContain('What happened in Kyoto?');
  expect(fake.backend!.calls).toContain('heroSend a');
  expect(fake.backend!.heroSends.at(-1)).toEqual({ account, base, chat, text: 'What happened in Kyoto?', focus });
  expect(target.textContent).toContain('Hero is working…');
  expect(button('Send').disabled).toBe(true);
  expect(button('Stop')).toBeTruthy();
});

test('streamed text replaces Hero is working without reloading', async () => {
  await send('Ferry?');
  const working = (await fake.backend!.heroMessages(account, base, chat)).at(-1)!;
  const calls = fake.backend!.calls.filter(c => c.startsWith('heroMessages')).length;
  fake.backend!.heroText(account, base, chat, working.id, 'It leaves');
  fake.backend!.heroText(account, base, chat, working.id, 'It leaves at');
  await flush();
  expect(target.textContent).toContain('It leaves at');
  expect(target.textContent).not.toContain('Hero is working…');
  expect(button('Stop')).toBeTruthy();
  expect(fake.backend!.calls.filter(c => c.startsWith('heroMessages')).length).toBe(calls);
});

test('text for another chat or an older message is ignored', async () => {
  await send('Ferry?');
  const working = (await fake.backend!.heroMessages(account, base, chat)).at(-1)!;
  const calls = fake.backend!.calls.filter(c => c.startsWith('heroMessages')).length;
  for (const [id, conversation] of [[working.id, 'other-chat'], ['older-message', chat]] as const) {
    fake.backend!.emit({ kind: 'hero', account, base, chat: conversation, event: { text: { base, chat: conversation, message: id, text: 'Wrong reply' } } });
  }
  await flush();
  expect(target.textContent).not.toContain('Wrong reply');
  expect(target.textContent).toContain('Hero is working…');
  expect(fake.backend!.calls.filter(c => c.startsWith('heroMessages')).length).toBe(calls);
});

test('Stop during a stream keeps the text and shows Stopped.', async () => {
  await send('Ferry?');
  const working = (await fake.backend!.heroMessages(account, base, chat)).at(-1)!;
  fake.backend!.heroText(account, base, chat, working.id, 'It leaves');
  await flush(); button('Stop').click(); await flush();
  expect(target.textContent).toContain('It leaves');
  expect(target.textContent).toContain('Stopped.');
  expect(button('Stop')).toBeUndefined();
});

test('a failed reply with partial text offers Retry', async () => {
  fake.backend!.seedHeroMessages(account, base, chat, [message('failed', { text: 'It lea', error: 'unavailable' })]);
  fake.backend!.emit({ kind: 'hero', account, base, chat, event: { changed: { base, chat } } }); await flush();
  expect(target.textContent).toContain("Hero's reply stopped partway.");
  expect(button('Retry')).toBeTruthy();
});

test('a rate-limited partial reply can be retried', async () => {
  fake.backend!.seedHeroMessages(account, base, chat, [message('failed', { text: 'First part', error: 'rate_limited' })]);
  fake.backend!.emit({ kind: 'hero', account, base, chat, event: { changed: { base, chat } } }); await flush();
  expect(target.textContent).toContain("Hero's reply stopped partway.");
  expect(button('Retry')).toBeTruthy();
});

test('streamed <script> renders as text, not markup', async () => {
  await send('Ferry?');
  const working = (await fake.backend!.heroMessages(account, base, chat)).at(-1)!;
  fake.backend!.emit({ kind: 'hero', account, base, chat, event: { text: { base, chat, message: working.id, text: '<script>alert(1)</script>' } } }); await flush();
  expect(target.textContent).toContain('<script>alert(1)</script>');
  expect(target.querySelector('script')).toBeNull();
});

test('Stop calls hero_stop and the stopped message reads Stopped.', async () => {
  await send('Hello'); button('Stop').click(); await flush();
  expect(fake.backend!.calls).toContain('heroStop a');
  expect(target.textContent).toContain('Stopped.');
});

test('an ask shows both buttons and Allow calls hero_answer(true)', async () => {
  fake.backend!.seedHeroMessages(account, base, chat, [message('asking', { ask: { base: 'other', baseName: 'Health', readersWithout: ['Demo Raring'] } })]);
  fake.backend!.emit({ kind: 'hero', account, base, chat, event: { changed: { base, chat } } }); await flush();
  expect(target.textContent).toContain("Hero wants to use Health in this chat. Demo Raring can read this chat's base but not Health.");
  expect(button('Not now')).toBeTruthy();
  button('Allow in this chat').click(); await flush();
  expect(fake.backend!.heroAnswers.at(-1)).toEqual({ account, base, chat, requested: 'other', allow: true });
});

test('reply text with <script> renders as text, not markup', async () => {
  fake.backend!.seedHeroMessages(account, base, chat, [message('done', { text: 'Hi <script>alert(1)</script>' })]);
  fake.backend!.emit({ kind: 'hero', account, base, chat, event: { changed: { base, chat } } }); await flush();
  expect(target.textContent).toContain('Hi <script>alert(1)</script>');
  expect(target.querySelector('script')).toBeNull();
});

test('created notes open with openObject', async () => {
  fake.backend!.remoteCreate({ account, base }, { kind: 'note', name: 'Kyoto notes', parent: null, after: null });
  const note = await fake.backend!.createObject({ account, base }, { kind: 'note', name: 'Itinerary', parent: null, after: null });
  fake.backend!.seedHeroMessages(account, base, chat, [message('done', { text: 'Made a note.', created: [note] })]);
  fake.backend!.emit({ kind: 'hero', account, base, chat, event: { changed: { base, chat } } }); await flush();
  button('Itinerary').click();
  expect(location.hash).toBe(`#/a/${account}/b/${base}/n/${note}`);
});

test.each(['missing', 'deleted'] as const)('a %s created object has no button', async state => {
  const note = state === 'deleted'
    ? await fake.backend!.createObject({ account, base }, { kind: 'note', name: 'Gone note', parent: null, after: null })
    : 'missing-note';
  if (state === 'deleted') await fake.backend!.deleteObject({ account, base }, note);
  fake.backend!.seedHeroMessages(account, base, chat, [message('done', { created: [note] })]);
  fake.backend!.emit({ kind: 'hero', account, base, chat, event: { changed: { base, chat } } }); await flush();
  expect(target.querySelector('.created')).toBeNull();
});

test('a failed reload from the previous chat does not show an error in the new chat', async () => {
  fake.backend!.seedHeroChat(account, base, 'project-2', 'chat-2');
  let rejectReload!: (reason?: unknown) => void;
  vi.spyOn(fake.backend!, 'heroMessages').mockImplementationOnce(() => new Promise((_, reject) => { rejectReload = reject; }));
  fake.backend!.emit({ kind: 'hero', account, base, chat, event: { changed: { base, chat } } }); await flush();
  expect(rejectReload).toBeDefined();
  button('Switch project').click(); await flush();
  expect(fake.backend!.calls.filter(call => call.startsWith('heroChatFor')).length).toBe(2);
  expect(fake.backend!.calls.filter(call => call.startsWith('heroMessages')).length).toBe(2);
  rejectReload(new Error('old chat reload failed')); await flush();
  expect(target.querySelector('[role="alert"]')).toBeNull();
});

test('a bh:event AppEvent::Hero for another chat does not reload', async () => {
  const before = fake.backend!.calls.filter(c => c.startsWith('heroMessages')).length;
  fake.backend!.emit({ kind: 'hero', account, base, chat: 'other-chat', event: { changed: { base, chat: 'other-chat' } } }); await flush();
  expect(fake.backend!.calls.filter(c => c.startsWith('heroMessages')).length).toBe(before);
});
