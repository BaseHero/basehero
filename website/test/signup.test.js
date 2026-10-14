import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import worker from '../src/worker.js';
import { sendBroadcast } from '../src/broadcast.js';

function fixture() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(readFileSync(new URL('../schema.sql', import.meta.url), 'utf8'));
  const DB = {
    prepare(sql) { return { bind(...args) { return {
      run() { return { meta: { changes: sqlite.prepare(sql).run(...args).changes } }; },
      first() { return sqlite.prepare(sql).get(...args); },
      all() { return { results: sqlite.prepare(sql).all(...args) }; }
    }; } }; }
  };
  const sent = [];
  const env = { DB, ASSETS: { fetch: () => new Response('asset') }, PUBLIC_ORIGIN: 'https://basehero.com', SIGNUP_ENABLED: 'true', MAIL_MODE: 'stub', STUB_MAIL: (email, url) => { sent.push({ email, url }); } };
  const post = (email) => worker.fetch(new Request('https://basehero.com/api/signup', { method: 'POST', body: new URLSearchParams({ email }) }), env);
  const row = email => sqlite.prepare('SELECT * FROM subscribers WHERE email=?').get(email);
  return { sqlite, env, sent, post, row };
}

test('both purposes remain pending until confirmation, and links are one-use', async () => {
  const f = fixture();
  assert.equal((await f.post(' Me@Example.com ')).status, 200);
  assert.equal(f.row('me@example.com').status, 'pending');
  assert.equal(f.row('me@example.com').confirmed_at, null);
  assert.equal(f.sent.length, 1);
  assert.match(f.row('me@example.com').consent_source, /newsletter/);
  const link = f.sent[0].url;
  const confirmationPage = await worker.fetch(new Request(link), f.env);
  assert.equal(confirmationPage.status, 200);
  const confirmationBody = await confirmationPage.text();
  assert.match(confirmationBody, /Confirm your beta request and newsletter subscription/);
  assert.match(confirmationBody, /method="post" action="\/api\/confirm"/);
  const token = new URL(link).searchParams.get('token');
  const formToken = /name="token" value="([0-9a-f]{64})"/.exec(confirmationBody)?.[1];
  assert.equal(formToken, token);
  assert.equal(f.row('me@example.com').status, 'pending');
  const confirm = () => worker.fetch(new Request('https://basehero.com/api/confirm', { method: 'POST', body: new URLSearchParams({ token: formToken }) }), f.env);
  assert.match(await (await confirm()).text(), /You’re confirmed/);
  assert.equal(f.row('me@example.com').status, 'confirmed');
  assert.equal((await confirm()).status, 400);
  await f.post('me@example.com');
  assert.equal(f.sent.length, 1);
});

test('rate limit pending requests, reject bad addresses, retry failed sends without activation', async () => {
  const f = fixture();
  assert.equal((await f.post('invalid')).status, 400);
  assert.equal((await f.post('person@example.com')).status, 200);
  await f.post('person@example.com');
  assert.equal(f.sent.length, 1);
  f.env.STUB_MAIL = () => { throw Error('failed'); };
  assert.equal((await f.post('other@example.com')).status, 503);
  assert.equal(f.row('other@example.com').status, 'pending');
  assert.equal(f.row('other@example.com').confirmation_hash, null);
  f.env.STUB_MAIL = (email, url) => f.sent.push({ email, url });
  assert.equal((await f.post('other@example.com')).status, 200);
  assert.equal(f.sent.length, 2);
  const token = new URL(f.sent[1].url).searchParams.get('token');
  const confirmation = await worker.fetch(new Request('https://basehero.com/api/confirm', { method: 'POST', body: new URLSearchParams({ token }) }), f.env);
  assert.equal(confirmation.status, 200);
  assert.equal(f.row('other@example.com').status, 'confirmed');
});

test('expired confirmation never activates either purpose', async () => {
  const f = fixture();
  await f.post('expired@example.com');
  const token = new URL(f.sent[0].url).searchParams.get('token');
  f.sqlite.prepare('UPDATE subscribers SET confirmation_expires_at=? WHERE email=?').run('2000-01-01T00:00:00.000Z', 'expired@example.com');
  const response = await worker.fetch(new Request('https://basehero.com/api/confirm', { method: 'POST', body: new URLSearchParams({ token }) }), f.env);
  assert.equal(response.status, 400);
  assert.equal(f.row('expired@example.com').status, 'pending');
});

test('live send is transactional and consent-specific, disables tracking, and fails closed on rejection', async () => {
  const f = fixture();
  f.env.MAIL_MODE = 'live';
  f.env.LETTERMINT_PROJECT_TOKEN = 'local-fake-token';
  f.env.LETTERMINT_TRANSACTIONAL_ROUTE = 'outgoing';
  f.env.MAIL_FROM = 'BaseHero <news@example.com>';
  const original = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options) => { calls.push({ url, options }); return { ok: calls.length === 1, status: 503 }; };
  try {
    assert.equal((await f.post('live@example.com')).status, 200);
    assert.equal(calls[0].url, 'https://api.lettermint.co/v1/send');
    assert.equal(calls[0].options.headers['x-lettermint-token'], 'local-fake-token');
    const mail = JSON.parse(calls[0].options.body);
    assert.equal(mail.route, 'outgoing');
    assert.deepEqual(mail.to, ['live@example.com']);
    assert.match(mail.text, /beta request and newsletter subscription/);
    assert.match(mail.text, /isn't guaranteed/);
    assert.match(mail.text, /MotiveSite Inc\.\n133 Knudson Dr\., Ottawa, ON K2K 2L8, Canada\./);
    assert.match(mail.text, /\/api\/confirm\?token=[0-9a-f]{64}/);
    assert.deepEqual(mail.settings, { track_opens: false, track_clicks: false });
    assert.equal((await f.post('rejected@example.com')).status, 503);
    assert.equal(f.row('rejected@example.com').confirmation_hash, null);
    assert.equal(f.row('rejected@example.com').status, 'pending');
  } finally { globalThis.fetch = original; }
});

test('unsubscribe webhook stops both purposes; forged events and new signups cannot revive them', async () => {
  const f = fixture();
  await f.post('person@example.com');
  let event = { id: 'event-1', event: 'message.unsubscribed', data: { recipient: 'person@example.com' } };
  const body = JSON.stringify(event);
  f.env.LETTERMINT_WEBHOOK_SECRET = 'whsec_local';
  const timestamp = String(Math.floor(Date.now() / 1000));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(f.env.LETTERMINT_WEBHOOK_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const mac = [...new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${timestamp}.${body}`)))].map(x => x.toString(16).padStart(2, '0')).join('');
  const request = (sig = mac) => new Request('https://basehero.com/api/lettermint-webhook', { method: 'POST', headers: { 'x-lettermint-delivery': timestamp, 'x-lettermint-signature': `t=${timestamp},v1=${sig}` }, body });
  assert.equal((await worker.fetch(request('0'.repeat(64)), f.env)).status, 401);
  assert.equal((await worker.fetch(request(), f.env)).status, 200);
  assert.equal(f.row('person@example.com').status, 'unsubscribed');
  assert.equal((await worker.fetch(request(), f.env)).status, 200);
  assert.equal(f.row('person@example.com').status, 'unsubscribed');
  assert.equal(f.row('person@example.com').confirmation_hash, null);
  await f.post('person@example.com');
  assert.equal(f.sent.length, 1);
});

test('broadcast uses only confirmed addresses, provider-hosted unsubscribe and no tracking', async () => {
  const f = fixture();
  await f.post('one@example.com');
  await f.post('two@example.com');
  f.sqlite.prepare("UPDATE subscribers SET status='confirmed' WHERE email=?").run('one@example.com');
  f.env.LETTERMINT_PROJECT_TOKEN = 'local-only';
  f.env.LETTERMINT_BROADCAST_ROUTE = 'broadcast';
  f.env.MAIL_FROM = 'BaseHero <news@example.com>';
  const payloads = [];
  const count = await sendBroadcast(f.env, { subject: 'News', text: 'Hello' }, async (url, options) => {
    assert.equal(url, 'https://api.lettermint.co/v1/send');
    payloads.push(JSON.parse(options.body));
    return { ok: true };
  });
  assert.equal(count, 1);
  assert.deepEqual(payloads[0].to, ['one@example.com']);
  assert.equal(payloads[0].route, 'broadcast');
  assert.match(payloads[0].text, /MotiveSite Inc\.\n133 Knudson Dr\., Ottawa, ON K2K 2L8, Canada\./);
  assert.deepEqual(payloads[0].settings, { track_opens: false, track_clicks: false });
  assert.equal(payloads[0].headers, undefined); // Lettermint adds hosted unsubscribe and one-click headers.
});

test('malformed confirmation and rejected dependency return responses', async () => {
  const f = fixture();
  const malformed = await worker.fetch(new Request('https://basehero.com/api/confirm', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{' }), f.env);
  assert.equal(malformed.status, 400);
  f.env.ASSETS.fetch = async () => { throw Error('outage'); };
  assert.equal((await worker.fetch(new Request('https://basehero.com/'), f.env)).status, 503);
});

test('www permanently redirects to apex, preserving path and query before handlers', async () => {
  const f = fixture();
  let assetCalls = 0;
  f.env.ASSETS.fetch = () => { assetCalls++; return new Response('asset'); };
  for (const path of ['/', '/privacy?mode=dark&ref=a%2Fb', '/api/signup?source=www', '//example.org/path?token=fictional', '//basehero.com.evil.invalid/']) {
    const response = await worker.fetch(new Request(`https://www.basehero.com${path}`), f.env);
    assert.equal(response.status, 308);
    assert.equal(response.headers.get('location'), `https://basehero.com${path}`);
  }
  const withPort = await worker.fetch(new Request('https://www.basehero.com:8443/privacy?mode=dark'), f.env);
  assert.equal(withPort.status, 308);
  assert.equal(withPort.headers.get('location'), 'https://basehero.com/privacy?mode=dark');
  const signup = await worker.fetch(new Request('https://www.basehero.com/api/signup', { method: 'POST', body: new URLSearchParams({ email: 'fictional@example.invalid' }) }), f.env);
  assert.equal(signup.status, 308);
  assert.equal(signup.headers.get('location'), 'https://basehero.com/api/signup');
  assert.equal(assetCalls, 0);
  assert.equal(f.sqlite.prepare('SELECT COUNT(*) AS count FROM subscribers').get().count, 0);
  assert.equal((await worker.fetch(new Request('https://basehero.com/privacy'), f.env)).status, 200);
});

test('signup is disabled until explicitly enabled, assets stay separate', async () => {
  const f = fixture();
  f.env.SIGNUP_ENABLED = 'false';
  let dbReads = 0;
  let mailReads = 0;
  Object.defineProperty(f.env, 'DB', { get() { dbReads++; throw Error('Disabled signup touched D1'); } });
  Object.defineProperty(f.env, 'STUB_MAIL', { get() { mailReads++; throw Error('Disabled signup touched mail'); } });
  const refused = await f.post('me@example.com');
  assert.equal(refused.status, 503);
  assert.match(await refused.text(), /Signups are not open yet/);
  for (const request of [
    new Request('https://basehero.com/api/confirm?token=' + 'a'.repeat(64)),
    new Request('https://basehero.com/api/confirm', { method: 'POST', body: new URLSearchParams({ token: 'a'.repeat(64) }) })
  ]) {
    const response = await worker.fetch(request, f.env);
    assert.equal(response.status, 503);
    assert.match(await response.text(), /Signups are not open yet/);
  }
  assert.equal(dbReads, 0, 'disabled requests must not access D1');
  assert.equal(mailReads, 0, 'disabled requests must not access mail');
  assert.equal(f.sent.length, 0);
  assert.equal((await worker.fetch(new Request('https://basehero.com/'), f.env)).status, 200);
  assert.equal(f.sqlite.prepare('SELECT COUNT(*) AS count FROM subscribers').get().count, 0);
});
