import { mailingFooter } from './mail-footer.js';

const htmlHeaders = { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer' };
const html = (body, status = 200) => new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>BaseHero beta list</title><main style="max-width:36rem;margin:4rem auto;font:1.2rem/1.5 system-ui;padding:1rem"><a href="/">BaseHero</a>${body}</main></html>`, { status, headers: htmlHeaders });
const statusPage = (title, detail, status = 200) => html(`<h1>${title}</h1><p>${detail}</p><a href="/#beta">Back to signup</a>`, status);
const hex = (bytes) => [...bytes].map(b => b.toString(16).padStart(2, '0')).join('');
const digest = async (token) => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))));
const validEmail = (email) => typeof email === 'string' && email.length <= 254 && /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email);
const normalEmail = (email) => email.trim().toLowerCase();
const now = () => new Date().toISOString();
const mailText = (url) => `Confirm your BaseHero beta request and newsletter subscription:\n\n${url}\n\nA beta invitation isn't guaranteed. This does not create an account. If you didn't request this, ignore this email; neither signup becomes active. When confirmed, you can unsubscribe from either kind of email using the link in every invitation and newsletter.${mailingFooter}`;

async function sendConfirmation(env, email, url) {
  if (env.MAIL_MODE === 'stub') {
    // Stub is deliberately unavailable in deployed builds; tests inject a sink.
    if (!env.STUB_MAIL) throw new Error('Local mail sink missing');
    return env.STUB_MAIL(email, url);
  }
  if (env.MAIL_MODE !== 'live' || !env.LETTERMINT_PROJECT_TOKEN || !env.MAIL_FROM || !env.LETTERMINT_TRANSACTIONAL_ROUTE) throw new Error('Mail is not configured');
  const result = await fetch('https://api.lettermint.co/v1/send', {
    method: 'POST', headers: { 'content-type': 'application/json', 'x-lettermint-token': env.LETTERMINT_PROJECT_TOKEN },
    body: JSON.stringify({ route: env.LETTERMINT_TRANSACTIONAL_ROUTE, from: env.MAIL_FROM, to: [email], subject: 'Confirm your BaseHero beta request and newsletter', text: mailText(url), settings: { track_opens: false, track_clicks: false } })
  });
  if (!result.ok) throw new Error(`Mail delivery rejected (${result.status})`);
}

async function signup(request, env) {
  if (env.SIGNUP_ENABLED !== 'true') return statusPage('Signups are not open yet.', 'Please check back later.', 503);
  if (!env.DB || !env.PUBLIC_ORIGIN || new URL(request.url).origin !== env.PUBLIC_ORIGIN) return statusPage('Unavailable', 'Please try again later.', 503);
  if (request.headers.get('origin') && request.headers.get('origin') !== env.PUBLIC_ORIGIN) return statusPage('Invalid request', 'Use the signup form on this site.', 403);
  if (Number(request.headers.get('content-length') || 0) > 2048) return statusPage('Invalid email', 'Please enter a valid address.', 400);
  let email;
  try { email = normalEmail((await request.formData()).get('email')); } catch { return statusPage('Invalid email', 'Please enter a valid address.', 400); }
  if (!validEmail(email)) return statusPage('Invalid email', 'Please enter a valid address.', 400);
  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  const hash = await digest(token);
  const time = now();
  const cutoff = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  const result = await env.DB.prepare(`INSERT INTO subscribers (email,status,requested_at,consent_source,confirmation_hash,confirmation_expires_at,last_sent_at)
    VALUES (?,'pending',?,'website beta request + newsletter form',?,?,?)
    ON CONFLICT(email) DO UPDATE SET requested_at=excluded.requested_at,confirmation_hash=excluded.confirmation_hash,
    confirmation_expires_at=excluded.confirmation_expires_at,last_sent_at=excluded.last_sent_at
    WHERE subscribers.status='pending' AND (subscribers.last_sent_at IS NULL OR subscribers.last_sent_at < ?)`)
    .bind(email, time, hash, expiry, time, cutoff).run();
  if (result.meta.changes) {
    try { await sendConfirmation(env, email, `${env.PUBLIC_ORIGIN}/api/confirm?token=${token}`); }
    catch {
      await env.DB.prepare("UPDATE subscribers SET last_sent_at=NULL,confirmation_hash=NULL,confirmation_expires_at=NULL WHERE email=? AND status='pending' AND confirmation_hash=?").bind(email, hash).run();
      return statusPage('Could not send the email.', 'Please try again shortly.', 503);
    }
  }
  return statusPage('Check your inbox.', 'Follow the link in our email to confirm your beta request and newsletter subscription. If you have recently requested a link, wait a little before trying again.');
}

async function confirm(request, env) {
  if (env.SIGNUP_ENABLED !== 'true') return statusPage('Signups are not open yet.', 'Please check back later.', 503);
  let token;
  try { token = request.method === 'GET' ? new URL(request.url).searchParams.get('token') : (await request.formData()).get('token'); }
  catch { return statusPage('Link invalid or expired.', 'Request another confirmation from the signup form.', 400); }
  if (!token || !/^[0-9a-f]{64}$/.test(token)) return statusPage('Link invalid or expired.', 'Request another confirmation from the signup form.', 400);
  if (request.method === 'GET') return html(`<h1>Confirm your signup</h1><p>Confirm your beta request and newsletter subscription. A beta invitation is not guaranteed and no account is created.</p><form method="post" action="/api/confirm"><input type="hidden" name="token" value="${token}"><button type="submit">Confirm both</button></form>`);
  const result = await env.DB.prepare("UPDATE subscribers SET status='confirmed',confirmed_at=?,confirmation_hash=NULL,confirmation_expires_at=NULL WHERE confirmation_hash=? AND status='pending' AND confirmation_expires_at>?").bind(now(), await digest(token), now()).run();
  return result.meta.changes ? statusPage('You’re confirmed.', 'Your beta request and newsletter subscription are active. Any invitation is not guaranteed; there is no BaseHero account.') : statusPage('Link invalid or expired.', 'Request another confirmation from the signup form.', 400);
}

async function verifyWebhook(request, secret) {
  if (!secret) return null;
  const signature = request.headers.get('x-lettermint-signature') || '';
  const delivery = request.headers.get('x-lettermint-delivery');
  const match = /^t=(\d+),v1=([a-f0-9]{64})$/.exec(signature);
  if (!match || delivery !== match[1] || Math.abs(Date.now() / 1000 - Number(delivery)) > 300) return null;
  const body = await request.text();
  if (body.length > 16384) return null;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const expected = new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${delivery}.${body}`)));
  const actual = Uint8Array.from(match[2].match(/../g), x => parseInt(x, 16));
  let diff = 0;
  for (let i = 0; i < 32; i++) diff |= expected[i] ^ actual[i];
  if (diff) return null;
  try { return JSON.parse(body); } catch { return null; }
}

async function webhook(request, env) {
  const event = await verifyWebhook(request, env.LETTERMINT_WEBHOOK_SECRET);
  if (!event) return new Response('Invalid signature', { status: 401 });
  if (!['message.unsubscribed', 'message.hard_bounced', 'message.spam_complaint', 'suppression.added'].includes(event.event)) return new Response('OK');
  const recipient = event.event === 'suppression.added' && event.data?.type === 'email' ? event.data.value : event.data?.recipient;
  if (!event.id || !validEmail(recipient)) return new Response('Invalid event', { status: 400 });
  const status = event.event === 'message.hard_bounced' || event.data?.reason === 'hard_bounce' ? 'bounced' : 'unsubscribed';
  const email = normalEmail(recipient);
  // A repeated stop is harmless; never reactivate a stopped subscriber.
  await env.DB.prepare("UPDATE subscribers SET status=?,stopped_at=?,confirmation_hash=NULL,confirmation_expires_at=NULL WHERE email=? AND status IN ('pending','confirmed')").bind(status, now(), email).run();
  return new Response('OK');
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.hostname === 'www.basehero.com') {
        const canonical = new URL('https://basehero.com');
        canonical.pathname = url.pathname;
        canonical.search = url.search;
        return Response.redirect(canonical.toString(), 308);
      }
      if (url.pathname === '/api/signup' && request.method === 'POST') return await signup(request, env);
      if (url.pathname === '/api/confirm' && ['GET','POST'].includes(request.method)) return await confirm(request, env);
      if (url.pathname === '/api/lettermint-webhook' && request.method === 'POST') return await webhook(request, env);
      if (url.pathname.startsWith('/api/')) return new Response('Not found', { status: 404 });
      return await env.ASSETS.fetch(request);
    } catch {
      return statusPage('Something went wrong.', 'Please try again later.', 503);
    }
  }
};
