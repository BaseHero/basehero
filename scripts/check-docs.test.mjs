import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const checker = fileURLToPath(new URL('./check-docs.mjs', import.meta.url));
const certificate = 'dd6b40572532b149be66e2e7e9a15c89828d25301e481bfa14eb237d24e2459c';

function check(files) {
  const root = mkdtempSync(join(tmpdir(), 'bh-docs-'));
  try {
    for (const [path, body] of Object.entries(files)) {
      const destination = join(root, path);
      mkdirSync(join(destination, '..'), { recursive: true });
      writeFileSync(destination, body);
    }
    return spawnSync(process.execPath, [checker, root], { encoding: 'utf8', timeout: 10_000 });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test('a broken relative link fails', () => {
  const result = check({
    'docs/a.md': '# A\n\n[missing](b.md#missing)\n',
    'docs/b.md': '# Present\n',
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /docs\/a\.md:3: no anchor #missing in b\.md/);
});

test('a snippet that drifted from its source fails', () => {
  const result = check({
    'docs/a.md': '# A\n\n<!-- snippet: src/example.kt#hello -->\n```kotlin\nval answer = 43\n```\n',
    'src/example.kt': '// snippet:hello\nval answer = 42\n// end-snippet\n',
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /docs\/a\.md:3: .*snippet.*hello/i);
});

test('the published release certificate must match release-identity.json', () => {
  const result = check({
    'README.md': `The release certificate SHA-256 is ${'a'.repeat(64)}.\n`,
    'apps/basehero/release-identity.json': JSON.stringify({ androidCertSha256: certificate }),
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /README\.md:1: .*release certificate/i);
});

test('a clean tree passes', () => {
  const result = check({
    'README.md': '[Guide](docs/a.md#my-heading)\n',
    'docs/a.md': `# My Heading\n\n[Go to section](#my-heading)\n\nThe release certificate SHA-256 is ${certificate}.\n\n<!-- snippet: src/example.kt#hello -->\n\x60\x60\x60kotlin\nval answer = 42\n\x60\x60\x60\n`,
    'src/example.kt': '// snippet:hello\nval answer = 42\n// end-snippet\n',
    'apps/basehero/release-identity.json': JSON.stringify({ androidCertSha256: certificate }),
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
});

test('an HTML source marker and a missing local file are checked', () => {
  const result = check({
    'docs/a.md': '# A\n\n<!-- snippet: src/example.xml#queries -->\n```xml\n<queries/>\n```\n\n[missing](gone.md)\n',
    'src/example.xml': '<!-- snippet:queries -->\n<queries/>\n<!-- end-snippet -->\n',
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /docs\/a\.md:8: missing link gone\.md/);
  assert.doesNotMatch(result.stderr, /snippet/i);
});

test('missing snippet source and duplicate heading anchors are checked', () => {
  const result = check({
    'docs/a.md': '# Heading\n# Heading\n[second](#heading-1)\n\n<!-- snippet: src/missing.kt#hello -->\n```kotlin\nval x = 1\n```\n',
  });
  assert.equal(result.status, 1);
  assert.doesNotMatch(result.stderr, /no anchor #heading-1/);
  assert.match(result.stderr, /snippet.*hello/i);
});

test('anchors follow GitHub: marks are kept, suffixes stay unique, punctuation goes', () => {
  const result = check({
    'docs/a.md': '# Cafe\u0301 notes\n# Foo\n# Foo-1\n# Foo\n## Test against `dev`?\n\n'
      + '[mark](#cafe\u0301-notes) [third](#foo-2) [code](#test-against-dev)\n',
  });
  assert.equal(result.status, 0, result.stderr);
});
