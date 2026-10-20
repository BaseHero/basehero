// Pairing and sync status, presentation only. Native pairing owns every
// session, code, key and account: the page passes back only the opaque
// session or ticket it was given, and the code text the person scanned or
// pasted. Device names from another device are untrusted plain text.
//
// The Android camera adapter emits bh-pair-code on #pair-scan; it never
// submits a join itself. The same native parser handles scanned and pasted text.
import { mountPairScan } from './pair-scan.js';

const element = (tag, text, className) => {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  if (className) node.className = className;
  return node;
};
const button = (text, action, primary = false) => {
  const node = element('button', text, primary ? 'primary' : 'secondary');
  node.type = 'button';
  node.addEventListener('click', () => void action(node));
  return node;
};
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const mac = () => /Mac|iP(hone|[oa]d)/.test(navigator.platform);
export const android = () => /Android/i.test(navigator.userAgent ?? '');
const thisDevice = () => (mac() ? 'this Mac' : 'this device');

// Native draws the code as one SVG path. Rebuild it from the path data only,
// so nothing else in the string (script, links, styles) can reach the page.
function drawCode(svgText) {
  const parsed = new DOMParser().parseFromString(svgText, 'image/svg+xml');
  const root = parsed.documentElement;
  const path = root?.firstElementChild;
  const box = root?.getAttribute('viewBox') ?? '';
  const d = path?.getAttribute('d') ?? '';
  if (root?.localName !== 'svg' || root.childElementCount !== 1 || path.localName !== 'path'
      || !/^0 0 \d{1,3} \d{1,3}$/.test(box) || !/^[Mhvz0-9 -]*$/.test(d)) return null;
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', box);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'Pairing code');
  const drawn = document.createElementNS(ns, 'path');
  drawn.setAttribute('d', d);
  svg.append(drawn);
  return svg;
}

// ---- Showing a code from an account's note window ----

const showingText = {
  waiting: () => 'Open BaseHero on your other device, choose “I already have an account”, then scan this code. Keep this screen open.',
  approving: () => `Confirm on ${thisDevice()} to add it.`,
  ordered: name => `${name} was added. It is downloading your notes now.`,
  cancelled: () => 'Pairing cancelled. Nothing was added.',
};
const failureText = {
  expired: 'This code expired. Nothing was added.',
  competing: 'Another device also scanned this code, so it was ended. Nothing was added.',
  'not-confirmed': 'Not confirmed. Nothing was added.',
  refused: 'That device could not be added.',
  invalid: 'That device could not be added.',
  network: 'Couldn’t reach BaseHero. Check the connection and show a new code.',
  unavailable: 'Adding a device is unavailable right now.',
};

/** A bar button opening the pairing screen of this window's account. */
export function pairingButton(invoke, glyph) {
  const opener = element('button', null, 'ib');
  opener.type = 'button';
  opener.setAttribute('aria-label', 'Add a device');
  opener.title = 'Add a device';
  opener.append(glyph);
  opener.addEventListener('click', () => void openPairing(invoke, opener));
  return opener;
}

async function openPairing(invoke, opener) {
  const dialog = element('dialog', null, 'pairing');
  dialog.setAttribute('aria-labelledby', 'pairing-title');
  const title = element('h2', 'Add a device');
  title.id = 'pairing-title';
  const body = element('div', null, 'pairing-body');
  const message = element('p', null, 'pairing-message');
  message.setAttribute('aria-live', 'polite');
  const actions = element('div', null, 'pairing-actions');
  dialog.append(element('p', 'YOUR DEVICES', 'label'), title, body, message, actions);
  document.body.append(dialog);
  let session = null, closed = false, approved = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    // Ends this screen's volatile flow; an approved addition still completes.
    if (session) await invoke('pairing_cancel', { session }).catch(() => {});
    dialog.close();
    dialog.remove();
    opener.focus();
  };
  dialog.addEventListener('cancel', event => { event.preventDefault(); void close(); });
  dialog.showModal();
  const show = async () => {
    approved = false;
    body.replaceChildren();
    actions.replaceChildren(button('Cancel', close));
    message.textContent = 'Preparing a code…';
    try {
      const shown = await invoke('pairing_show');
      session = shown.session;
      const code = drawCode(shown.qrSvg);
      if (code) {
        const frame = element('div', null, 'pairing-code');
        frame.append(code);
        body.append(frame);
      }
      const text = element('details', null, 'pairing-text');
      const summary = element('summary', 'Can’t scan? Show the code as text');
      const field = element('textarea');
      field.readOnly = true;
      field.value = shown.qrText;
      field.setAttribute('aria-label', 'Pairing code text');
      text.append(summary, field);
      body.append(text);
      message.textContent = showingText.waiting();
    } catch {
      message.textContent = failureText.unavailable;
      return;
    }
    let drawn = '';
    while (!closed) {
      let status;
      try { status = await invoke('pairing_status', { session }); } catch { status = { state: 'failed', reason: 'unavailable' }; }
      const key = JSON.stringify(status);
      if (key !== drawn) { drawn = key; draw(status); }
      if (['ordered', 'cancelled', 'failed'].includes(status.state)) return;
      await wait(500);
    }
  };
  const draw = status => {
    const name = status.label ?? 'this device';
    actions.replaceChildren();
    switch (status.state) {
      case 'candidate': {
        body.replaceChildren(element('h3', `Add ${name}?`),
          element('p', 'It will be able to open your BaseHero account and notes. Approve only the device you just scanned with.'));
        message.textContent = '';
        const approve = button(`Approve on ${thisDevice()}`, async node => {
          if (approved) return;
          approved = true;
          node.disabled = true;
          try { draw(await invoke('pairing_approve', { session })); } catch { node.disabled = false; approved = false; }
        }, true);
        actions.append(approve, button('Cancel', close));
        approve.focus();
        break;
      }
      case 'approving':
        message.textContent = showingText.approving();
        actions.append(button('Cancel', close));
        break;
      case 'ordered':
        body.replaceChildren();
        message.textContent = showingText.ordered(name);
        actions.append(button('Done', close, true));
        actions.firstChild.focus();
        break;
      case 'cancelled':
        body.replaceChildren();
        message.textContent = status.reason === 'approved'
          ? `${name} was approved and is still being added.` : showingText.cancelled();
        actions.append(button('Show a new code', show, true), button('Close', close));
        break;
      case 'failed':
        body.replaceChildren();
        message.textContent = failureText[status.reason] ?? failureText.unavailable;
        actions.append(button('Show a new code', show, true), button('Close', close));
        actions.firstChild.focus();
        break;
      default:
        actions.append(button('Cancel', close));
    }
  };
  await show();
}

// ---- The network's view of this account, in the window's status line ----

export const cloudText = {
  // A build without an endpoint: its notes stay on this device.
  'saved-local': v => v.network === 'off' ? 'Cloud sync not connected'
    : v.pending ? `Saved on this device · ${v.pending} not yet synced` : 'Saved on this device',
  syncing: v => v.pending ? `Syncing ${v.pending} ${v.pending === 1 ? 'note' : 'notes'}` : 'Syncing',
  synced: () => 'Synced',
  'update-needed': () => 'Some content needs an app update',
  'waiting-network': () => 'Saved on this device · Waiting for network',
  'waiting-authorization': v => v.confirm ? 'Waiting for your confirmation' : 'Waiting for authorization',
  'history-missing': () => 'Waiting for missing history',
  unsupported: v => v.network === 'unsupported' ? 'Cloud sync unavailable in this build' : 'Update BaseHero to keep syncing',
  stopped: () => 'Sync stopped · History could not be verified',
  'publishing-stopped': () => 'Publishing stopped on this device',
  'not-accepted': v => {
    const notes = v.notes ?? 1;
    return `${notes} ${notes === 1 ? 'note' : 'notes'} not accepted · Kept on this device`;
  },
  'control-not-accepted': () => 'An account change was not accepted · Kept on this device',
};
// The first device's account setup, apart from note sync; a retry says why.
const homeText = {
  pending: () => 'Storing account setup',
  retrying: v => `Account setup not yet stored · ${retryText[v.homeReason] ?? 'Retrying'}`,
};
const retryText = {
  unavailable: 'Couldn’t reach BaseHero, retrying',
  refused: 'Not accepted yet, retrying',
  'setup-not-ready': 'Waiting for this device, retrying',
};

/**
 * Keep `cloud` showing this window's account status from native, and tell
 * `changed` each status it shows. Native posts `sync://status` to the page
 * it is on and answers the page's own request (`render`); each view carries
 * the host's revision, and the newest shown wins, whichever arrives last.
 * `follow()` starts a new page, which shows only its own statuses.
 */
export function syncLine(cloud, invoke, changed = () => {}) {
  // Nothing is claimed before native's first status for this window.
  const text = element('span', 'Checking sync…', 'sync-text');
  const home = element('span', null, 'home');
  home.hidden = true;
  const confirm = button('Confirm on this device', async node => {
    node.disabled = true;
    try { await invoke('pairing_reconfirm'); } catch { node.disabled = false; }
  });
  confirm.className = 'sync-confirm';
  confirm.hidden = true;
  cloud.setAttribute('aria-live', 'polite');
  let shown = 0;
  const render = view => {
    if (!view || typeof view.state !== 'string' || !cloudText[view.state]
        || !Number.isSafeInteger(view.revision) || view.revision < shown) return;
    shown = view.revision;
    cloud.dataset.sync = view.state;
    text.textContent = cloudText[view.state](view);
    const homeNow = homeText[view.home]?.(view);
    home.hidden = !homeNow;
    home.textContent = homeNow ?? '';
    if (view.homeReason) home.dataset.reason = view.homeReason; else delete home.dataset.reason;
    confirm.hidden = !view.confirm;
    if (!view.confirm) confirm.disabled = false;
    changed(view);
  };
  window.addEventListener('sync://status', event => render(event.detail));
  const follow = () => { shown = 0; };
  return { nodes: [text, home, confirm], render, follow };
}

// ---- Joining from a device with no account ----

const joinText = {
  'waiting-approval': () => 'Code accepted. Approve this device on your other device.',
  admitted: () => 'Added to your account. Checking its history…',
  bootstrapping: s => s.total ? `Downloading your notes: ${s.done ?? 0} of ${s.total}` : 'Downloading your notes…',
  ready: () => 'Ready on this device.',
};
const joinFailure = {
  refused: 'This device was not added. Show a new code on your other device and scan it again.',
  invalid: 'This device was not added. Show a new code on your other device and scan it again.',
  expired: 'The code expired before this device was added. Show a new code and scan it again.',
  competing: 'Another device scanned the same code. Show a new code and scan it again.',
  network: 'Couldn’t reach BaseHero. What this device already has is kept; try again.',
  stopped: 'This account’s history could not be verified. Nothing was opened.',
  unsupported: 'Update BaseHero to finish joining this account.',
  unavailable: 'Joining isn’t available right now. Try again.',
};
const joinRefusal = {
  'pairing code invalid': 'That isn’t a BaseHero pairing code.',
  'account exists': 'This device already has an account.',
  'pairing unavailable': 'Joining isn’t available in this build.',
};

/**
 * The join screen: scan slot, a pasted code, then progress to ready.
 * `heading(step, title, intro, status)` draws the screen's heading and
 * footer status, left empty while joining; `ready()` runs
 * once the account is ready here; `back` (desktop) returns to the welcome.
 */
export function joinScreen(root, invoke, { heading, ready, retry, back, ticket }) {
  let polling = 0, scanner;
  const showError = text => {
    let error = root.querySelector('.signup-error');
    if (!error) { error = element('p', null, 'signup-error'); error.setAttribute('role', 'alert'); root.append(error); }
    error.textContent = text;
  };
  const form = () => {
    polling++;
    scanner?.stop();
    heading(android() ? 'WELCOME' : 'ACCOUNT / JOIN', 'Join your account',
      'On a device that already has your BaseHero account, choose Add a device to show a code. Scan it here, or paste the code.', '');
    const scan = element('div', null, 'pair-scan');
    scan.id = 'pair-scan';
    const paste = element('section', null, 'signup-own');
    const label = element('label', 'Pairing code');
    const input = element('input');
    input.id = 'pair-code';
    input.autocomplete = 'off';
    input.spellcheck = false;
    input.setAttribute('autocapitalize', 'off');
    label.htmlFor = input.id;
    paste.append(label, input);
    let submitting = false;
    const submit = async code => {
      if (submitting) return;
      submitting = true;
      scanner?.cancel();
      try { follow((await invoke('pairing_join', { qrText: code.trim() })).ticket); }
      catch (error) { showError(joinRefusal[String(error)] ?? joinFailure.unavailable); }
      finally { submitting = false; }
    };
    scan.addEventListener('bh-pair-code', event => {
      if (typeof event.detail?.code === 'string') void submit(event.detail.code);
    });
    input.addEventListener('keydown', event => {
      if (event.key === 'Enter') { event.preventDefault(); void submit(input.value); }
    });
    const join = button('Join', async node => { node.disabled = true; try { await submit(input.value); } finally { node.disabled = false; } }, true);
    const row = element('div', null, 'signup-actions');
    row.append(join);
    if (back) row.append(button('Back', back));
    root.append(scan, paste, row);
    scanner = mountPairScan(scan, invoke);
  };
  const follow = async ticket => {
    const run = ++polling;
    scanner?.stop();
    heading(android() ? 'WELCOME' : 'ACCOUNT / JOIN', 'Joining your account', 'Keep BaseHero open on both devices until this finishes.', '');
    const progress = element('p', null, 'join-progress');
    progress.setAttribute('aria-live', 'polite');
    const row = element('div', null, 'signup-actions');
    root.append(progress, row);
    let drawn = '';
    while (run === polling) {
      let status;
      try { status = await invoke('pairing_join_status', { ticket }); }
      catch { status = { state: 'failed', reason: 'unavailable' }; }
      const key = JSON.stringify(status);
      if (key !== drawn) {
        drawn = key;
        row.replaceChildren();
        if (joinText[status.state]) progress.textContent = joinText[status.state](status);
        else {
          progress.textContent = joinFailure[status.reason] ?? joinFailure.unavailable;
          // After admission, a retry resumes what this device kept.
          if (status.reason === 'network' || status.reason === 'unavailable') row.append(button('Try again', retry, true));
          else row.append(button('Scan again', form, true));
          row.firstChild.focus();
          return;
        }
      }
      if (status.state === 'ready') { await ready(); return; }
      await wait(500);
    }
  };
  if (ticket) void follow(ticket); else form();
}
