// Only the Android main-window join screen may request the camera. Scanner
// output is untrusted text: the existing join listener passes it to native's
// canonical pairing-code parser, never to markup or a page-selected account.
const command = name => `plugin:qr-scan|${name}`;
const supported = () => /Android/i.test(navigator.userAgent ?? '')
  && window.__TAURI_INTERNALS__?.metadata?.currentWindow?.label === 'main';

export function mountPairScan(slot, invoke) {
  if (!supported()) return { cancel() {}, stop() {} };
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'secondary';
  button.textContent = 'Scan code';
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.className = 'secondary';
  cancel.textContent = 'Cancel scan';
  cancel.hidden = true;
  const message = document.createElement('p');
  message.className = 'pair-scan-message';
  message.setAttribute('role', 'alert');
  slot.append(button, cancel, message);
  let generation = 0, busy = false, camera = false, disposed = false;
  const live = token => !disposed && generation === token && slot.isConnected && !document.hidden;
  const appearance = () => {
    document.documentElement.classList.toggle('pair-camera-active', camera);
    cancel.hidden = !camera;
    button.disabled = busy;
  };
  const stop = () => {
    generation++;
    const wasCamera = camera;
    camera = false;
    busy = false;
    appearance();
    if (wasCamera) void invoke(command('cancel')).catch(() => {});
  };
  const dispose = () => {
    if (disposed) return;
    disposed = true;
    stop();
    observer.disconnect();
    window.removeEventListener('pagehide', dispose);
    document.removeEventListener('visibilitychange', hidden);
  };
  // Android's own permission dialog briefly hides the WebView. Do not
  // invalidate the pending deliberate request; after it answers, `live`
  // still refuses to start a camera on a page that remains hidden.
  const hidden = () => { if (document.hidden && camera) stop(); };
  const observer = new MutationObserver(() => { if (!slot.isConnected) dispose(); });
  observer.observe(document.documentElement, { childList: true, subtree: true });
  window.addEventListener('pagehide', dispose);
  document.addEventListener('visibilitychange', hidden);
  cancel.addEventListener('click', () => { stop(); message.textContent = 'Scan cancelled. You can paste the code or scan again.'; });
  button.addEventListener('click', async () => {
    if (busy || disposed || !slot.isConnected) return;
    busy = true;
    const token = ++generation;
    message.textContent = '';
    appearance();
    try {
      // No permission check or prompt happens on mount or on a paste.
      const permission = await invoke(command('request_permissions'));
      if (!live(token)) return;
      if (permission?.camera !== 'granted') {
        message.textContent = 'Camera permission denied. Allow it in Android settings, or paste the pairing code below.';
        return;
      }
      camera = true;
      message.textContent = 'Point the camera at the pairing code on your other device.';
      appearance();
      // The native adapter is back-camera and QR only; the page chooses neither.
      const result = await invoke(command('scan'));
      if (!live(token)) return;
      stop();
      if (typeof result?.content === 'string') {
        slot.dispatchEvent(new CustomEvent('bh-pair-code', { detail: { code: result.content } }));
      } else message.textContent = 'That isn’t a BaseHero pairing code. Scan again or paste the code below.';
    } catch {
      if (live(token)) message.textContent = 'Camera unavailable or scan cancelled. Scan again or paste the code below.';
    } finally {
      if (generation === token) stop();
    }
  });
  return { cancel: stop, stop: dispose };
}
