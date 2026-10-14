// A page-side caller for the pre-app stub, so tests exercise the same
// `window.__TAURI_INTERNALS__.invoke` path the real UI will.
window.__bhIpcFixture = {
  async call(command, args) {
    try {
      return { ok: true, value: await window.__TAURI_INTERNALS__.invoke(command, args) };
    } catch (error) {
      return { ok: false, error: String(error?.message ?? error) };
    }
  },
};
