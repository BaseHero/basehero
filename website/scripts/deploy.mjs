import { spawnSync } from 'node:child_process';
if (process.env.WEBSITE_LAUNCHED !== 'true') {
  console.error('Deployment held: initial public cutover has not been approved.');
  process.exit(1);
}
if (!process.env.CLOUDFLARE_ACCOUNT_ID || !process.env.CLOUDFLARE_API_TOKEN || (process.env.SIGNUP_ENABLED === 'true' && !process.env.D1_DATABASE_ID)) {
  console.error('Deployment held: Cloudflare account/token missing, or D1 missing for enabled signup.');
  process.exit(1);
}
const result = spawnSync('npm', ['exec', '--', 'wrangler', 'deploy', '--config', 'dist/wrangler.jsonc'], {
  stdio: 'inherit', env: { ...process.env, WRANGLER_SEND_METRICS: 'false' }
});
process.exit(result.status ?? 1);
