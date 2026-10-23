// Exercise the actual native-injected emulator script, not a duplicate of its flow.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const rust = readFileSync(new URL('../../src-tauri/src/android_account.rs', import.meta.url), 'utf8');
const script = rust.match(/const SCRIPT: &str = r#"([\s\S]*?)"#;/)?.[1];
assert.ok(script, 'fixture script exists');

function fixture() {
  const elements = new Map();
  function element(tag) {
    return {
      tag, style: {}, children: [], listeners: {}, hidden: false, disabled: false,
      append(...nodes) { this.children.push(...nodes); },
      setAttribute() {},
      addEventListener(name, handler) { this.listeners[name] = handler; },
    };
  }
  const body = element('body');
  body.append = (...nodes) => { for (const node of nodes) { body.children.push(node); if (node.id) elements.set(node.id, node); } };
  const calls = [];
  let reloads = 0;
  const invoke = async (name, args) => {
    calls.push({ name, args });
    if (name === 'account_suggest_password') return { screen: 'password', suggested: 'test password words' };
    if (name === 'account_create') return { screen: 'kit', code: 'TEST-CODE-123' };
    if (name === 'account_confirm_kit') return { screen: 'ready' };
    throw Error(name);
  };
  const document = {
    readyState: 'complete', body, createElement: element,
    getElementById: (id) => elements.get(id),
    querySelector: (selector) => selector === 'main .label' ? { textContent: 'WELCOME' } : null,
  };
  const window = { __TAURI_INTERNALS__: { invoke } };
  window.top = window;
  vm.runInNewContext(script, { window, document, MutationObserver: class { observe() {} }, location: { reload() { reloads++; } } });
  const bar = elements.get('bh-emulator-fixture');
  return { calls, bar, buttons: bar.children.filter(child => child.tag === 'button'), reloads: () => reloads };
}

test('existing fixture button continues to confirm automatically', async () => {
  const ui = fixture();
  const button = ui.buttons.find(b => b.textContent === 'Create emulator test account');
  assert.ok(button);
  await button.listeners.click();
  assert.deepEqual(ui.calls.map(c => c.name), ['account_suggest_password', 'account_create', 'account_confirm_kit']);
  assert.equal(ui.reloads(), 1);
});

test('opt-in fixture shows the password and code before confirmation', async () => {
  const ui = fixture();
  const button = ui.buttons.find(b => b.textContent === 'Create test account and show kit');
  assert.ok(button, 'explicit show-kit action available on the labelled fixture');
  await button.listeners.click();
  assert.deepEqual(ui.calls.map(c => c.name), ['account_suggest_password', 'account_create']);
  assert.equal(ui.calls[1].args.password, 'test password words');
  assert.equal(ui.reloads(), 0);
  const shown = ui.bar.children.map(c => c.textContent).join(' ');
  assert.match(shown, /test password words/);
  assert.match(shown, /TEST-CODE-123/);
  const continueButton = ui.buttons.find(b => b.textContent === 'Continue');
  assert.ok(continueButton);
  await continueButton.listeners.click();
  assert.deepEqual(ui.calls.map(c => c.name), ['account_suggest_password', 'account_create', 'account_confirm_kit']);
  assert.equal(ui.reloads(), 1);
});
