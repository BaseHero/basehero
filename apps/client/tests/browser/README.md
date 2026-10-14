# Client UI browser checks

Playwright checks that serve the real `apps/client/ui` over loopback and drive it
in Chromium and WebKit. Run them with:

```sh
bash scripts/check.sh ui
```

`scripts/check-client-ui.sh` resolves the browser binaries from the product
flake's pinned nixpkgs (`playwright` 1.63.0) unless `PLAYWRIGHT_BROWSERS_PATH`
is already set, installs the pinned `playwright` npm package from the committed
lock, and runs `node --test`.

Chromium approximates an Android WebView and WebKit the macOS WKWebView. Neither
is a real-device check, and neither is WKWebView on macOS or a system WebView on
a phone.

## What the harness does

- `harness.mjs` serves `apps/client/ui` at `/` with the shell's own CSP (read
  from `src-tauri/tauri.conf.json`) and the fixtures under `/__harness/`, on an
  ephemeral loopback port. Nothing leaves the machine.
- `tauri-ipc-stub.mjs` installs `window.__TAURI_INTERNALS__` with
  `page.addInitScript`, so it exists before the first page script, exactly where
  the Tauri shell puts it. Tests register handlers with `window.__bhIpc.handle`
  and read `window.__bhIpc.calls`. This is deliberately not
  `@tauri-apps/api/mocks` `mockIPC`, and the package does not depend on the
  Tauri API package at all.
- The stub also counts web-storage reads and refuses unhandled commands, so a
  missing handler fails loudly instead of returning `undefined`.

## Status

The bundled shell is currently a static setup screen, so these checks cover the
setup screen, theme, responsive layout, CSP and IPC-stub behaviour. Editing is
covered separately by the real EditorView cases in `apps/client/editor/test/`,
which `bash scripts/check.sh ui` also runs in Chromium and WebKit; navigation and
drafts have no shell wiring yet, so neither suite is evidence they work. Chromium
and WebKit are engine approximations, not device acceptance.
