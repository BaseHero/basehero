#!/usr/bin/env node
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(process.argv[2] ?? fileURLToPath(new URL('..', import.meta.url)));
const problems = [];
const report = (file, line, reason) => problems.push(`${relative(root, file)}:${line}: ${reason}`);
const inside = (path) => path === root || (!relative(root, path).startsWith('..') && !isAbsolute(relative(root, path)));
const linesOf = (file) => readFileSync(file, 'utf8').replace(/\r\n/g, '\n').split('\n');

function markdownFiles(folder) {
  if (!existsSync(folder)) return [];
  return readdirSync(folder, { withFileTypes: true }).flatMap((entry) => {
    const file = join(folder, entry.name);
    return entry.isDirectory() ? markdownFiles(file) : entry.isFile() && entry.name.endsWith('.md') ? [file] : [];
  });
}

const files = [...(existsSync(join(root, 'README.md')) ? [join(root, 'README.md')] : []), ...markdownFiles(join(root, 'docs'))];
const documents = new Map(files.map((file) => [file, linesOf(file)]));

// As GitHub's slugger does: drop controls, punctuation and symbols except `-` and
// `_`, keep letters, marks and numbers, and turn each space into `-`.
function headingSlug(heading) {
  return heading.toLowerCase().replace(/<[^>]*>/g, '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/[\p{C}\p{P}\p{S}]/gu, (c) => (c === '-' || c === '_' ? c : '')).replace(/ /g, '-');
}

function anchors(file) {
  const found = new Set();
  const counts = new Map();
  let fence = null;
  for (const line of documents.get(file) ?? linesOf(file)) {
    const boundary = line.match(/^\s*(`{3,}|~{3,})/);
    if (boundary) {
      if (!fence) fence = boundary[1];
      else if (boundary[1][0] === fence[0] && boundary[1].length >= fence.length) fence = null;
      continue;
    }
    if (fence) continue;
    const heading = line.match(/^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$/);
    if (!heading) continue;
    // A repeated heading takes the next `-N` that no earlier heading already has.
    const base = headingSlug(heading[1]);
    let slug = base;
    while (found.has(slug)) {
      counts.set(base, (counts.get(base) ?? 0) + 1);
      slug = `${base}-${counts.get(base)}`;
    }
    found.add(slug);
  }
  return found;
}

function checkLink(file, line, target) {
  if (/^(?:[a-z][a-z\d+.-]*:|\/\/|\/)/i.test(target)) return;
  const [path, hash] = target.split('#', 2);
  let decodedPath;
  let decodedHash;
  try {
    decodedPath = decodeURIComponent(path);
    decodedHash = hash === undefined ? undefined : decodeURIComponent(hash);
  } catch {
    report(file, line, `invalid link ${target}`);
    return;
  }
  const dest = decodedPath ? resolve(dirname(file), decodedPath) : file;
  if (!inside(dest) || !existsSync(dest) || !statSync(dest).isFile()) {
    report(file, line, `missing link ${target}`);
  } else if (decodedHash && dest.endsWith('.md') && !anchors(dest).has(decodedHash)) {
    report(file, line, `no anchor #${decodedHash} in ${path || relative(dirname(file), dest)}`);
  }
}

function checkSnippet(file, line, marker, block) {
  const match = marker.match(/^\s*<!--\s*snippet:\s*([^\s#]+)#([^\s]+)\s*-->\s*$/);
  if (!match) return;
  const [, path, name] = match;
  const source = resolve(root, path);
  if (!inside(source) || !existsSync(source) || !statSync(source).isFile()) {
    report(file, line, `snippet ${path}#${name}: source missing`);
    return;
  }
  const sourceLines = linesOf(source);
  const start = sourceLines.findIndex((text) => markerName(text, 'snippet') === name);
  const end = sourceLines.findIndex((text, index) => index > start && markerName(text, 'end-snippet') !== null);
  if (start < 0 || end < 0 || sourceLines.slice(start + 1, end).join('\n') !== block.join('\n')) {
    report(file, line, `snippet ${path}#${name} differs from source`);
  }
}

function markerName(text, kind) {
  const escaped = kind === 'snippet' ? 'snippet' : 'end-snippet';
  const match = text.match(/^\s*(?:\/\/\s*|<!--\s*)(snippet:([^\s]+)|end-snippet)(?:\s*-->)?\s*$/);
  if (!match || !match[1].startsWith(escaped)) return null;
  return kind === 'snippet' ? match[2] : '';
}

let certificate;
try {
  certificate = JSON.parse(readFileSync(join(root, 'apps/basehero/release-identity.json'), 'utf8')).androidCertSha256;
} catch {
  // Only needed if a page prints a release certificate; temporary trees may omit it.
}

for (const [file, lines] of documents) {
  let fence = null;
  let marker = null;
  let block = [];
  let blockLine = 0;
  for (let index = 0; index < lines.length; index++) {
    const text = lines[index];
    const boundary = text.match(/^\s*(`{3,}|~{3,})/);
    if (boundary) {
      if (!fence) {
        fence = boundary[1];
        block = [];
        blockLine = index;
      } else if (boundary[1][0] === fence[0] && boundary[1].length >= fence.length) {
        if (marker) checkSnippet(file, blockLine, marker, block);
        fence = null;
        marker = null;
      } else block.push(text);
      continue;
    }
    if (fence) {
      block.push(text);
      continue;
    }
    const snippet = text.match(/^\s*<!--\s*snippet:\s*[^\s#]+#[^\s]+\s*-->\s*$/);
    if (snippet) {
      marker = text;
      continue;
    }
    if (marker && text.trim()) marker = null;
    for (const match of text.matchAll(/!?\[[^\]]*\]\(<?([^\s)>]+)>?(?:\s+[^)]*)?\)/g)) {
      checkLink(file, index + 1, match[1]);
    }
    const reference = text.match(/^\s*\[[^\]]+\]:\s*<?([^\s>]+)>?/);
    if (reference) checkLink(file, index + 1, reference[1]);
    const cert = text.match(/release certificate\b[^\n]*?\b([a-f\d]{64})\b/i);
    if (cert && (!certificate || cert[1].toLowerCase() !== certificate.toLowerCase())) {
      report(file, index + 1, 'release certificate differs from release-identity.json');
    }
  }
}

if (problems.length) {
  for (const problem of problems) console.error(problem);
  process.exitCode = 1;
}
