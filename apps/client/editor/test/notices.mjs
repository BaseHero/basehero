// Generates the third-party notice shipped beside the bundled note editor.
// Run with --write after installing dependencies; otherwise it checks that the
// committed notice still covers exactly the packages esbuild bundles.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const root = fileURLToPath(new URL('..', import.meta.url));
const output = new URL('../../ui/note-editor.THIRD_PARTY.txt', import.meta.url);

// Keep in step with the "build" script in package.json; only inputs matter here.
const result = await build({
  entryPoints: [fileURLToPath(new URL('../src/editor.mjs', import.meta.url))],
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: 'es2022',
  minify: true,
  define: { localStorage: 'undefined', sessionStorage: 'undefined' },
  metafile: true,
  write: false,
});

const packages = new Set();
for (const input of Object.keys(result.metafile.inputs)) {
  const match = input.match(/node_modules\/((?:@[^/]+\/)?[^/]+)\//);
  if (match) packages.add(match[1]);
}

function licenceText(dir) {
  for (const name of ['LICENSE', 'LICENSE.md', 'LICENSE.txt', 'LICENCE']) {
    const path = `${root}/node_modules/${dir}/${name}`;
    if (existsSync(path)) return readFileSync(path, 'utf8').replace(/\s+$/, '');
  }
  throw new Error(`No licence file for ${dir}`);
}

const sections = [...packages].sort().map(dir => {
  const manifest = JSON.parse(readFileSync(`${root}/node_modules/${dir}/package.json`, 'utf8'));
  return `${manifest.name} ${manifest.version} — ${manifest.license}\n\n${licenceText(dir)}`;
});

const text = `Third-party notices for the bundled note editor (note-editor.js)

The bundle above includes the packages below. Each is used under the licence
reproduced here. Regenerate with:

  node test/notices.mjs --write

${sections.join('\n\n' + '-'.repeat(78) + '\n\n')}\n`;

if (process.argv.includes('--write')) {
  writeFileSync(output, text);
  console.log(`note-editor notices: ${packages.size} packages`);
} else {
  assert.equal(readFileSync(output, 'utf8'), text, 'note-editor third-party notice is stale');
  assert.ok(packages.size > 0, 'no bundled packages found');
  console.log(`note-editor notices: ${packages.size} packages`);
}
