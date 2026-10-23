// App-owned display of compile-time metadata. Nothing in this screen is HTML
// from the native host: every value is inserted as text.
export function renderAbout(container, about) {
  const row = (name, value) => {
    const line = document.createElement('p');
    line.textContent = `${name}: ${value}`;
    return line;
  };
  const title = document.createElement('h2');
  title.textContent = 'About BaseHero';
  container.replaceChildren(title,
    row('Version', about.version),
    row('Build', about.build),
    row('Source commit', about.commit));
  if (about.test_settings.length) {
    const heading = document.createElement('h3');
    heading.textContent = 'Test settings';
    container.append(heading, ...about.test_settings.map(setting => row(setting.name, setting.value)));
  }
}

const invoke = window.__TAURI_INTERNALS__?.invoke;
if (invoke) {
  window.__bhAbout = async () => {
    let about;
    try { about = await invoke('app_about'); } catch { return; }
    document.querySelector('#bh-about')?.remove();
    const dialog = document.createElement('dialog');
    dialog.id = 'bh-about';
    dialog.setAttribute('aria-label', 'About BaseHero');
    const close = document.createElement('button');
    close.type = 'button';
    close.textContent = 'Close';
    close.addEventListener('click', () => dialog.close());
    dialog.addEventListener('close', () => dialog.remove());
    renderAbout(dialog, about);
    dialog.append(close);
    document.body.append(dialog);
    dialog.showModal();
    close.focus();
  };
}
