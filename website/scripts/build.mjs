import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
const root = resolve(import.meta.dirname, '..');
const dist = resolve(root, 'dist');
rmSync(dist, { recursive: true, force: true });
mkdirSync(dist);
cpSync(resolve(root, 'public'), resolve(dist, 'assets'), { recursive: true });
if (process.env.SIGNUP_ENABLED !== 'true') rmSync(resolve(dist, 'assets/beta-list.html'), { force: true });
if (process.env.SIGNUP_ENABLED === 'true') {
  if (!existsSync(resolve(root, 'public/beta-list.html')) || process.env.WEBSITE_LAUNCHED !== 'true' || !process.env.D1_DATABASE_ID) {
    throw Error('Signup held: verified notice, launched website and provisioned D1 are required.');
  }
  const path = resolve(dist, 'assets/index.html');
  const page = readFileSync(path, 'utf8');
  writeFileSync(path, page
    .replace('Beta signup opening soon. When it opens, you can request an invitation and subscribe to BaseHero news. Beta access isn’t guaranteed.', 'Request a beta invitation and subscribe to the BaseHero newsletter. Beta access isn’t guaranteed.')
    .replace('Beta signups will open later.', 'Request beta access and get our news.')
    .replace('About the beta list', 'Join the beta list')
    .replace('required aria-describedby="signup-note" disabled', 'required aria-describedby="signup-note"')
    .replace('<button class="button" type="submit" disabled>', '<button class="button" type="submit">')
    .replace('Beta signup opening soon. No addresses are collected yet. When signup opens, confirmation will activate both the beta request and newsletter subscription. No account is created. Unsubscribe anytime.', 'Confirm your email to activate both. No account is created. Unsubscribe anytime. <a href="beta-list.html">About your signup</a>')
    .replace('<a href="privacy.html">Privacy</a></p></footer>', '<a href="privacy.html">Privacy</a> <a href="beta-list.html">About your signup</a></p></footer>'));
}
// Wrangler bundles the Worker code and uploads only assets/ and the bundle.
writeFileSync(resolve(dist, 'wrangler.jsonc'), JSON.stringify({
  name: 'basehero-website', main: '../src/worker.js', compatibility_date: '2026-10-01',
  assets: { directory: './assets', binding: 'ASSETS', run_worker_first: true },
  ...(process.env.D1_DATABASE_ID ? { d1_databases: [{ binding: 'DB', database_name: 'basehero-website', database_id: process.env.D1_DATABASE_ID }] } : {}),
  vars: { PUBLIC_ORIGIN: 'https://basehero.com', SIGNUP_ENABLED: process.env.SIGNUP_ENABLED === 'true' ? 'true' : 'false', MAIL_MODE: process.env.SIGNUP_ENABLED === 'true' ? 'live' : 'disabled', LETTERMINT_TRANSACTIONAL_ROUTE: 'outgoing', LETTERMINT_BROADCAST_ROUTE: 'broadcast' }
}, null, 2));
