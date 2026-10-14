import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { resolve, dirname, extname } from 'node:path';
import assert from 'node:assert/strict';
const root = resolve(import.meta.dirname, '..');
const assets = resolve(root, 'dist/assets');
const config = JSON.parse(readFileSync(resolve(root, 'dist/wrangler.jsonc'), 'utf8'));
assert.equal(config.assets.run_worker_first, true, 'All hostnames, including static www paths, must reach the canonical redirect first');
const files = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap(entry => entry.isDirectory() ? files(resolve(dir, entry.name)) : [resolve(dir, entry.name)]);
const published = files(assets);
assert(published.some(x => x.endsWith('/index.html')) && published.some(x => x.endsWith('/privacy.html')));
assert(!published.some(x => /beta-flow|\.map$/.test(x)));
for (const file of published) {
  if (!['.html', '.css', '.js'].includes(extname(file))) continue;
  const content = readFileSync(file, 'utf8');
  assert(!/(?:design\/|docs\/decisions|plan\/|\.paseo\/|\/home\/dan\/|\.\.\/dispatch\/)/i.test(content), `Private reference: ${file}`);
  assert(!/<(?:script|link)[^>]+(?:src|href)=["']https?:/i.test(content), `Remote asset: ${file}`);
  if (extname(file) === '.html') {
    assert(!/(?:class=["'][^"']*\b(?:review-note|support-preview)\b|Design study|Design preview|for review, not a live product)/i.test(content), `Review-only markup: ${file}`);
    for (const [, link] of content.matchAll(/(?:href|src)="([^"#?]+)(?:\?[^"#]*)?(?:#[^"]*)?"/g)) {
      if (/^(?:https?:|mailto:|data:|\/api\/)/.test(link)) continue;
      const path = link === './' ? 'index.html' : link;
      assert(existsSync(resolve(dirname(file), path)), `Broken local asset ${link} in ${file}`);
    }
  }
}
console.log(`Checked ${published.length} website assets; no private paths or remote assets.`);
