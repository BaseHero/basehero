const invoke = window.__TAURI__.core.invoke;
const status = document.querySelector('#status');
async function run(command, args = {}) {
  status.textContent = 'Working…';
  try { status.textContent = await invoke(command, args); }
  catch (error) { status.textContent = `Error: ${error}`; }
}
document.querySelector('#connect').addEventListener('click', () => run('connect'));
document.querySelector('#write').addEventListener('click', () => run('write_reading', {
  value: Number(document.querySelector('#value').value),
}));
document.querySelector('#read').addEventListener('click', () => run('read_back'));
document.querySelector('#ask').addEventListener('click', () => run('ask_model', {
  question: document.querySelector('#question').value,
}));
run('status');
