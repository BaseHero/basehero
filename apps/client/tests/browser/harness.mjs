// Shared browser-check harness: a local-only server for the real bundled UI and
// the pre-app IPC stub. No product code lives here and nothing is fetched from
// outside this machine.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { join, normalize, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium, webkit } from "playwright";
import { tauriIpcStub } from "./tauri-ipc-stub.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));

export const uiRoot = join(here, "..", "..", "ui");
const fixturesRoot = join(here, "fixtures");
const configPath = join(here, "..", "..", "src-tauri", "tauri.conf.json");

// The two engines this suite runs. Chromium approximates an Android WebView and
// WebKit approximates the macOS WKWebView; neither is a real device.
export const browserMatrix = ["chromium", "webkit"];

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".woff2": "font/woff2",
  ".png": "image/png",
};

// The shell's CSP is the one Tauri applies to the bundled page; serve it so the
// browser behaves like the packaged app rather than an unguarded static server.
export async function shellCsp() {
  const config = JSON.parse(await readFile(configPath, "utf8"));
  return config.app.security.csp;
}

function resolveWithin(root, relativePath) {
  const resolved = normalize(join(root, relativePath));
  if (resolved !== root && !resolved.startsWith(root + sep)) return null;
  return resolved;
}

async function readWithin(root, relativePath, res) {
  const resolved = resolveWithin(root, relativePath);
  if (!resolved) return false;
  try {
    const body = await readFile(resolved);
    res.setHeader("Content-Type", contentTypes[resolved.slice(resolved.lastIndexOf("."))] ?? "application/octet-stream");
    res.end(body);
    return true;
  } catch {
    return false;
  }
}

// Serve the real `ui/` at `/` and harness fixtures under `/__harness/`. Binds an
// ephemeral loopback port so parallel check runs never collide.
export async function startUiServer() {
  const csp = await shellCsp();
  const server = createServer(async (req, res) => {
    res.setHeader("Content-Security-Policy", csp);
    const pathname = decodeURIComponent(new URL(req.url, "http://localhost").pathname);
    if (pathname.startsWith("/__harness/")) {
      if (await readWithin(fixturesRoot, pathname.slice("/__harness/".length), res)) return;
      res.writeHead(404).end();
      return;
    }
    if (pathname === "/") {
      if (await readWithin(uiRoot, "index.html", res)) return;
      res.writeHead(404).end();
      return;
    }
    if (await readWithin(uiRoot, pathname.slice(1), res)) return;
    res.writeHead(404).end();
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const { port } = server.address();
  return {
    origin: `http://127.0.0.1:${port}`,
    fixture: (name) => `http://127.0.0.1:${port}/__harness/${name}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

export function launchBrowser(name) {
  const type = name === "webkit" ? webkit : name === "chromium" ? chromium : null;
  if (!type) throw new Error(`unknown browser ${name}`);
  if (!process.env.PLAYWRIGHT_BROWSERS_PATH) {
    throw new Error("PLAYWRIGHT_BROWSERS_PATH is unset; run via scripts/check-client-ui.sh");
  }
  return type.launch({ headless: true });
}

// Install the pre-app IPC stub, then load a page. `path` is relative to the
// server ("" is the real shell, "__harness/x.html" a fixture). Init scripts run
// in the page before its first script, so ordering here is the guarantee under
// test. `extraInit` adds probe scripts after the stub.
export async function openPage(
  browser,
  origin,
  { path = "", stub = true, colorScheme, viewport, extraInit = [] } = {},
) {
  const page = await browser.newPage({ viewport });
  if (colorScheme) await page.emulateMedia({ colorScheme });
  if (stub) await page.addInitScript(tauriIpcStub);
  for (const init of extraInit) await page.addInitScript(init);
  await page.goto(`${origin}/${path}`, { waitUntil: "load" });
  return page;
}
