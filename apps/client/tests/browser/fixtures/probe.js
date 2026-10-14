// Records, at module evaluation time, whether the pre-app shell globals were
// already installed. The ordering check relies on this being the first page
// script after the (blocked) inline one.
window.__bhProbe = {
  internalsAtModuleEval: typeof window.__TAURI_INTERNALS__,
  invokeAtModuleEval: typeof window.__TAURI_INTERNALS__?.invoke,
  storageGuarded: window.__bhStorageGuarded,
  inlineRan: window.__inlineRan,
};
