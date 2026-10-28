const invoke = window.__TAURI__.core.invoke;
const status = document.querySelector('#status');
const digits = document.querySelector('#digits');
const digitsHelp = document.querySelector('#digits-help');
let connecting = false;
let generation = 0;
async function run(command, args = {}) {
  status.textContent = 'Working…';
  try { status.textContent = await invoke(command, args); }
  catch (error) { status.textContent = `Error: ${error}`; }
}
document.querySelector('#connect').addEventListener('click', async () => {
  if (connecting) return;
  connecting = true;
  const attempt = ++generation;
  digits.textContent = '';
  digitsHelp.hidden = true;
  status.textContent = 'Open BaseHero on one of your devices.';
  try {
    const code = await invoke('connect_start', { email: document.querySelector('#email').value });
    if (attempt !== generation) return;
    digits.textContent = code;
    digitsHelp.hidden = false;
    status.textContent = 'Open BaseHero on one of your devices.';
    const result = await invoke('connect_finish');
    if (attempt === generation) status.textContent = result;
  } catch (error) {
    if (attempt === generation) status.textContent = `Error: ${error}`;
  } finally {
    if (attempt === generation) {
      connecting = false;
      digits.textContent = '';
      digitsHelp.hidden = true;
    }
  }
});
document.querySelector('#cancel').addEventListener('click', async () => {
  ++generation;
  connecting = false;
  digits.textContent = '';
  digitsHelp.hidden = true;
  try { await invoke('connect_cancel'); status.textContent = await invoke('status'); }
  catch (error) { status.textContent = `Error: ${error}`; }
});
document.querySelector('#write').addEventListener('click', () => run('write_reading', {
  value: Number(document.querySelector('#value').value),
}));
document.querySelector('#read').addEventListener('click', () => run('read_back'));
document.querySelector('#ask').addEventListener('click', () => run('ask_model', {
  question: document.querySelector('#question').value,
}));
document.addEventListener('visibilitychange', async () => {
  if (document.hidden) return;
  try {
    const current = await invoke('status');
    if (!connecting || current !== 'not connected') status.textContent = current;
  } catch (error) {
    status.textContent = `Error: ${error}`;
  }
});
run('status');
