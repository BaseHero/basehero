// Pre-app IPC stub for browser UI checks.
//
// The Tauri shell exposes `window.__TAURI_INTERNALS__` before any app code runs;
// `@tauri-apps/api` reaches it through `invoke` and `transformCallback`. These
// checks install this stub with `page.addInitScript`, which runs in the page
// before the first `<script>` is evaluated, so app code sees the same object a
// packaged build would.
//
// Deliberately not `@tauri-apps/api/mocks` `mockIPC`: that requires the API
// package (a second dependency tree and its own build) and installs a module
// monkey-patch rather than the shell's real pre-app global. Command names are
// owned by the real UI, so this stub is generic: a test registers a handler for
// the command it expects and unhandled commands reject loudly.
//
// The function below is serialised into the browser by Playwright and must not
// close over anything outside its own body.
export function tauriIpcStub() {
  const calls = [];
  const handlers = new Map();
  const callbacks = new Map();
  let nextCallbackId = 1;

  const ipc = {
    // Every command the page invoked, in order, for a test to assert on.
    calls,
    handle(command, handler) {
      handlers.set(command, handler);
    },
    async invoke(command, args, options) {
      const call = { command, args: args ?? {}, options: options ?? null };
      calls.push(call);
      const handler = handlers.get(command);
      if (handler) return await handler(call.args, call);
      throw new Error(`no stub IPC handler for ${command}`);
    },
    transformCallback(callback, once = false) {
      const id = nextCallbackId++;
      callbacks.set(id, { callback, once });
      return id;
    },
    unregisterCallback(id) {
      callbacks.delete(id);
    },
  };

  window.__bhIpc = ipc;
  window.__TAURI_INTERNALS__ = {
    invoke: (command, args, options) => ipc.invoke(command, args, options),
    transformCallback: (callback, once) => ipc.transformCallback(callback, once),
    unregisterCallback: (id) => ipc.unregisterCallback(id),
    convertFileSrc: (path) => path,
    metadata: {
      currentWindow: { label: "main" },
      currentWebview: { windowLabel: "main", label: "main" },
    },
  };

  // Product code must never read web storage. Record failures to install the
  // guard instead of aborting the whole stub, and let a test assert the count.
  window.__bhStorageReads = 0;
  window.__bhStorageGuarded = true;
  for (const key of ["localStorage", "sessionStorage"]) {
    try {
      Object.defineProperty(window, key, {
        configurable: true,
        get() {
          window.__bhStorageReads += 1;
          throw new Error(`web storage ${key} must not be read`);
        },
      });
    } catch {
      window.__bhStorageGuarded = false;
    }
  }
}
