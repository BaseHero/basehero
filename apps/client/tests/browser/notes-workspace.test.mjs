// The shipped notes workspace against a page-side model of the native core.
// The model is a test host, not an account, a native Mac window or real
// fanout; Yjs merging for its snapshots runs in Node with the editor's Yjs.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { mkdir } from "node:fs/promises";
import { join } from "node:path";
import * as Y from "../../editor/node_modules/yjs/dist/yjs.mjs";
import { browserMatrix, launchBrowser, startUiServer } from "./harness.mjs";
import { tauriIpcStub } from "./tauri-ipc-stub.mjs";

// One core note store per page. `window.__bhCore` lets a test hold acks,
// fail saves and relay committed updates to another page.
function coreHost() {
  const ipc = window.__bhIpc;
  const hex = (note) => note.map((b) => b.toString(16).padStart(2, "0")).join("");
  const notes = new Map();
  let counter = 0, surface = 0, generation = 0, current = null, screen = { screen: "welcome" };
  const make = () => {
    const id = Array.from(crypto.getRandomValues(new Uint8Array(32)));
    notes.set(hex(id), { id, updates: [], touched: ++counter });
    return id;
  };
  const core = (window.__bhCore = {
    notes, hex, make, holdAcks: false, failNext: false, held: [], committed: [],
    current: () => current, setCurrent: (note) => { current = note; },
    generation: () => generation, screen: (next) => { screen = next; },
  });
  ipc.handle("note_binding", () => (current ? { note: current, surface: String(++surface) } : null));
  ipc.handle("account_screen", () => screen);
  ipc.handle("account_suggest_password", () => ({ screen: "password", suggested: "acorn breeze copper dawn elm" }));
  ipc.handle("account_create", () => (screen = { screen: "kit", code: "DEMO-CODE-NEVER-A-REAL-ACCOUNT" }));
  ipc.handle("account_save_kit_file", () => { screen = { screen: "ready" }; return { result: "saved", route: "file" }; });
  ipc.handle("account_open_note", () => { current = current ?? make(); return null; });
  ipc.handle("note_list", () => [...notes.values()].sort((a, b) => b.touched - a.touched)
    .map((note) => ({ note: note.id, title: "", touched: note.touched })));
  ipc.handle("note_create", () => make());
  // A local-only build: its notes stay on this device.
  ipc.handle("sync_status", () => ({ revision: 1, state: "saved-local", pending: 0, network: "off", home: null, account: "active", confirm: false }));
  ipc.handle("note_show", ({ note }) => {
    if (!notes.has(hex(note))) throw "note unavailable";
    current = note;
    return null;
  });
  ipc.handle("note_open", async ({ note }) => {
    const stored = notes.get(hex(note));
    // Like native: the stored updates in order, not one merged state.
    const updates = stored.updates.length ? stored.updates : [[0, 0]];
    return {clientId:window.__bhTestWriterId??2002468231004600,writerToken:Array(32).fill(9),updates, generation: ++generation, sequence: 0 };
  });
  ipc.handle("note_commit", ({ update, requestId, generation: from }) => {
    const commit = () => {
      if (core.failNext) { core.failNext = false; throw "note commit failed"; }
      const stored = notes.get(hex(current));
      stored.updates.push(update);
      stored.touched = ++counter;
      core.committed.push({ update, generation: from });
      return { requestId };
    };
    if (!core.holdAcks) return commit();
    return new Promise((resolve, reject) => core.held.push(() => {
      try { resolve(commit()); } catch (error) { reject(error); }
    }));
  });
  ipc.handle("note_close", () => null);
  ipc.handle("note_selection", () => []);
  ipc.handle("note_new_window", () => null);
}

// Test-host stand-in for the native catalogue title: first block's literal
// text. The bounded native extraction itself is tested in Rust.
function hostTitle(updates) {
  const doc = new Y.Doc();
  for (const update of updates) Y.applyUpdate(doc, new Uint8Array(update));
  for (const block of doc.getXmlFragment("default").toArray()) {
    const text = block.toArray().map((node) => node instanceof Y.XmlText
      ? node.toDelta().map((d) => (typeof d.insert === "string" ? d.insert : "")).join("") : "").join("").trim();
    if (text) return text.slice(0, 80);
  }
  return "";
}
// Lists the page model's notes with titles from their committed updates.
function titledList() {
  const core = window.__bhCore;
  window.__bhIpc.handle("note_list", async () => {
    const rows = [];
    for (const note of [...core.notes.values()].sort((a, b) => b.touched - a.touched))
      rows.push({ note: note.id, title: await window.bhTitle(note.updates), touched: note.touched });
    return rows;
  });
}

async function corePage(browser, origin, init = []) {
  const page = await browser.newPage();
  await page.exposeFunction("bhTitle", hostTitle);
  await page.addInitScript(tauriIpcStub);
  await page.addInitScript(coreHost);
  for (const script of init) {
    if (Array.isArray(script)) await page.addInitScript(...script);
    else await page.addInitScript(script);
  }
  await page.goto(`${origin}/`, { waitUntil: "load" });
  return page;
}
const calls = (page, command) => page.evaluate((name) =>
  window.__bhIpc.calls.filter((call) => call.command === name).map((call) => call.args), command);
const statusText = (page) => page.locator("[data-status]").textContent();
const editorText = (page) => page.locator(".ProseMirror").textContent();
async function saved(page) {
  await page.waitForFunction(() => document.querySelector("[data-status]")?.textContent === "Saved on this Mac");
}
// Bind an already-ready account straight to a shared note.
function readyShared() {
  window.__bhCore.screen({ screen: "ready" });
}

for (const browserName of browserMatrix) {
  describe(`notes workspace in ${browserName}`, () => {
    test('quick saves keep the saved indicator steady', async () => {
      const server=await startUiServer();const browser=await launchBrowser(browserName);
      try {
        const page=await corePage(browser,server.origin,[readyShared]);
        await page.locator('.ProseMirror').waitFor();
        await page.locator('.ProseMirror').click();await page.keyboard.insertText('fast');
        await page.waitForFunction(()=>window.__bhCore.committed.length>0);
        await page.waitForTimeout(200);
        assert.equal(await statusText(page),'Saved on this Mac');
        // Mutation caught: an immediate pending label shows during an ordinary save.
        await page.evaluate(()=>{window.__bhCore.holdAcks=true;});
        await page.keyboard.insertText('slow');
        await page.waitForFunction(()=>window.__bhCore.held.length>0);
        assert.equal(await statusText(page),'Saved on this Mac');
        await page.evaluate(()=>window.__bhCore.held.shift()());
        await saved(page);
        await page.close();
      } finally {await browser.close();await server.close();}
    });
    test('slow save waits about a second while a failed save reports immediately',async()=>{
      const server=await startUiServer();const browser=await launchBrowser(browserName);
      try {
        const page=await corePage(browser,server.origin,[readyShared]);
        await page.locator('.ProseMirror').waitFor();
        await page.evaluate(()=>{window.__bhCore.holdAcks=true;});
        await page.locator('.ProseMirror').click();await page.keyboard.insertText('slow');
        await page.waitForFunction(()=>window.__bhCore.held.length>0);
        assert.equal(await statusText(page),'Saved on this Mac');
        await page.waitForFunction(()=>document.querySelector('[data-status]')?.textContent==='Saving…',{timeout:3000});
        await page.evaluate(()=>{window.__bhCore.failNext=true;window.__bhCore.held.shift()();});
        await page.getByRole('button',{name:'Retry save'}).waitFor({state:'visible'});
        assert.equal(await statusText(page),'Not saved');
        await page.close();
      } finally {await browser.close();await server.close();}
    });
    test("signup leads to a note list, New note, switching notes and New window", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(browserName);
      try {
        const page = await corePage(browser, server.origin);
        await page.getByRole("button", { name: "Create my account" }).click();
        await page.getByRole("button", { name: "Use this password" }).click();
        await page.getByRole("button", { name: "Save a file" }).click();
        await page.locator(".ProseMirror").waitFor();
        assert.equal(await page.locator("header .crumb").textContent(), "My base");
        const list = page.getByRole("navigation", { name: "Notes" });
        await list.getByRole("button", { name: "Untitled" }).waitFor();
        assert.equal(await page.getByText("Cloud sync not connected").count(), 1);

        await page.locator(".ProseMirror").click();
        await page.keyboard.insertText("first note");
        await saved(page);
        const first = await page.evaluate(() => window.__bhCore.current());
        if(process.env.BH_WORKSPACE_SCREENSHOTS) {
          await mkdir(process.env.BH_WORKSPACE_SCREENSHOTS,{recursive:true});
          for(const colorScheme of ['light','dark']) {
            await page.emulateMedia({colorScheme});
            await page.screenshot({path:join(process.env.BH_WORKSPACE_SCREENSHOTS,`${browserName}-${colorScheme}.png`),fullPage:true});
          }
        }

        await page.getByRole("button", { name: "New note" }).click();
        await page.waitForFunction((old) => JSON.stringify(window.__bhCore.current()) !== JSON.stringify(old), first);
        await page.locator(".ProseMirror").waitFor();
        await page.waitForFunction(() => document.querySelector(".ProseMirror")?.textContent === "");
        assert.equal(await list.getByRole("button").count(), 2);
        assert.equal(await list.locator('[aria-current="true"]').count(), 1);
        await page.locator(".ProseMirror").click();
        await page.keyboard.insertText("second note");
        await saved(page);
        const second = await page.evaluate(() => window.__bhCore.current());

        // Opening a note normally uses this window.
        await list.getByRole("button", { name: "Untitled" }).nth(1).click();
        await page.waitForFunction(() => document.querySelector(".ProseMirror")?.textContent === "first note");
        assert.deepEqual(await page.evaluate(() => window.__bhCore.current()), first);
        assert.equal(await page.evaluate(() => document.querySelectorAll(".ProseMirror").length), 1);

        await page.getByRole("button", { name: "New window" }).click();
        await page.waitForFunction(() => window.__bhIpc.calls.some((call) => call.command === "note_new_window"));
        assert.deepEqual(await calls(page, "note_new_window"), [{ note: first }]);
        // The page names notes only; never an account, container, base or key.
        assert.deepEqual(await calls(page, "note_show"), [{ note: second }, { note: first }]);
        assert.deepEqual((await calls(page, "note_create")).map(Object.keys), [[]]);
        for (const args of await calls(page, "note_list")) assert.deepEqual(Object.keys(args), ["after"]);
        // Every switch closed the previous load before routing the window.
        const commands = await page.evaluate(() => window.__bhIpc.calls.map((call) => call.command));
        const shows = commands.flatMap((command, index) => (command === "note_show" ? [index] : []));
        for (const index of shows) assert.equal(commands.slice(0, index).findLast((c) => c === "note_close" || c === "note_open"), "note_close");
        const body = await page.locator("body").textContent();
        assert.doesNotMatch(body, /\b(?:Synced|Hero|chat|project)\b/i);
        await page.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("catalogue pages render titles literally and fit both colour modes", async () => {
      const server=await startUiServer();const browser=await launchBrowser(browserName);
      try {
        const page=await corePage(browser,server.origin,[readyShared,()=>{
          const malicious='<img src="https://example.invalid/leak" onerror="alert(1)">';
          window.__bhIpc.handle('note_list',({after})=>{
            if(after) {
              if(after.touched!==51 || after.note[0]!==49) throw Error('wrong cursor');
              return [{note:Array(32).fill(50),title:'Last note',touched:50}];
            }
            return Array.from({length:50},(_,i)=>({note:Array(32).fill(i),title:i===0?malicious:'',touched:100-i}));
          });
        }]);
        const nav=page.getByRole('navigation',{name:'Notes'});
        await nav.getByRole('button',{name:'More notes'}).click();
        await nav.getByRole('button',{name:'Last note'}).waitFor();
        assert.equal(await nav.locator('button').count(),51);
        assert.equal(await nav.locator('img,script').count(),0);
        assert.equal(await nav.getByRole('button',{name:'<img src="https://example.invalid/leak" onerror="alert(1)">',exact:true}).count(),1);
        for(const colorScheme of ['light','dark']) {
          await page.emulateMedia({colorScheme});
          for(const width of [360,1000]) {
            await page.setViewportSize({width,height:760});
            assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true,`${colorScheme}/${width}`);
          }
        }
        await page.close();
      } finally {await browser.close();await server.close();}
    });

    test("a saved note's literal title replaces Untitled once typing settles", async () => {
      const server=await startUiServer();const browser=await launchBrowser(browserName);
      try {
        const page=await corePage(browser,server.origin,[readyShared,titledList]);
        const nav=page.getByRole('navigation',{name:'Notes'});
        await nav.getByRole('button',{name:'Untitled'}).waitFor();
        const lists=async()=>(await calls(page,'note_list')).length;
        const before=await lists();
        await page.locator('.ProseMirror').click();
        await page.keyboard.type('First',{delay:30});
        await page.keyboard.press('ControlOrMeta+b');
        await page.keyboard.type(' bold',{delay:30});
        await saved(page);
        await nav.getByRole('button',{name:'First bold',exact:true}).waitFor();
        assert.equal(await nav.locator('strong,b,em,code').count(),0,'formatting stays plain');
        assert.ok((await calls(page,'note_commit')).length>=3,'several saves while typing');
        assert.equal(await lists()-before,1,'one coalesced catalogue page for the burst');
        // A failed save neither refreshes nor advertises its text; idle never polls.
        await page.evaluate(()=>{window.__bhCore.failNext=true;});
        await page.keyboard.type('!');
        await page.getByRole('button',{name:'Retry save'}).waitFor();
        await page.waitForTimeout(1200);
        assert.equal(await lists()-before,1);
        await nav.getByRole('button',{name:'First bold',exact:true}).waitFor();
        await page.close();
      } finally {await browser.close();await server.close();}
    });

    test("a delivered same-note commit refreshes the other window's title once", async () => {
      const server=await startUiServer();const browser=await launchBrowser(browserName);
      try {
        const shared=[readyShared,titledList,()=>{
          const core=window.__bhCore;const id=Array(32).fill(6);
          core.notes.set(core.hex(id),{id,updates:[],touched:1});core.setCurrent(id);
        }];
        const left=await corePage(browser,server.origin,shared);
        const right=await corePage(browser,server.origin,[...shared,()=>{window.__bhTestWriterId=2002468231004601;}]);
        for (const page of [left,right]) await page.locator('.ProseMirror').waitFor();
        await right.getByRole('navigation',{name:'Notes'}).getByRole('button',{name:'Untitled'}).waitFor();
        const lists=async()=>(await calls(right,'note_list')).length;
        const before=await lists();
        // A packet for another generation is stale: no refresh.
        assert.equal(await right.evaluate(()=>window.__bhNoteDelivery({generation:window.__bhCore.generation()+1,sequence:1,update:[0,0],resync:false})),'stale');
        await left.locator('.ProseMirror').click();
        await left.keyboard.type('Shared words',{delay:30});
        await saved(left);
        const updates=await left.evaluate(()=>window.__bhCore.committed.splice(0).map(c=>c.update));
        assert.ok(updates.length>=2);
        for (const [i,update] of updates.entries()) {
          const outcome=await right.evaluate(({update,sequence})=>{
            window.__bhCore.notes.get(window.__bhCore.hex(Array(32).fill(6))).updates.push(update);
            return window.__bhNoteDelivery({generation:window.__bhCore.generation(),sequence,update,resync:false});
          },{update,sequence:i+1});
          assert.equal(outcome,'accepted');
        }
        await right.getByRole('navigation',{name:'Notes'}).getByRole('button',{name:'Shared words',exact:true}).waitFor();
        await right.waitForTimeout(1200);
        assert.equal(await lists()-before,1);
        await left.close();await right.close();
      } finally {await browser.close();await server.close();}
    });

    test("composition keeps the current editor until the input finishes", async () => {
      const server=await startUiServer();const browser=await launchBrowser(browserName);
      try {
        const page=await corePage(browser,server.origin,[readyShared]);
        await page.locator('.ProseMirror').waitFor();
        const note=await page.evaluate(()=>window.__bhCore.current());
        await page.locator('.ProseMirror').dispatchEvent('compositionstart');
        await page.getByRole('button',{name:'New note'}).click();
        assert.deepEqual(await page.evaluate(()=>window.__bhCore.current()),note);
        assert.equal((await calls(page,'note_close')).length,0);
        await page.locator('.ProseMirror').dispatchEvent('compositionend');
        await page.getByRole('button',{name:'New note'}).click();
        await page.waitForFunction(()=>window.__bhIpc.calls.filter(c=>c.command==='note_open').length===2);
        await page.close();
      } finally {await browser.close();await server.close();}
    });

    test("an unsaved note is not left behind when another note is chosen", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(browserName);
      try {
        const page = await corePage(browser, server.origin, [readyShared]);
        await page.locator(".ProseMirror").waitFor();
        await page.getByRole("button", { name: "New note" }).click();
        await page.waitForFunction(() => window.__bhCore.notes.size === 2 && !!document.querySelector(".ProseMirror"));
        await page.waitForFunction(() => window.__bhIpc.calls.filter((c) => c.command === "note_open").length === 2);
        const before = await page.evaluate(() => window.__bhCore.current());
        await page.evaluate(() => { window.__bhCore.holdAcks = true; window.__bhCore.failNext = true; });
        await page.locator(".ProseMirror").click();
        await page.keyboard.insertText("not yet saved");
        await page.waitForFunction(() => window.__bhCore.held.length === 1);
        assert.equal(await statusText(page), "Saved on this Mac");
        await page.getByRole("navigation", { name: "Notes" }).getByRole("button", { name: "Untitled" }).nth(1).click();
        // Switching drains first: the failed save is retried once, unchanged.
        await page.evaluate(() => window.__bhCore.held.shift()());
        await page.waitForFunction(() => window.__bhCore.held.length === 1);
        await page.evaluate(() => { window.__bhCore.failNext = true; window.__bhCore.held.shift()(); });
        await page.getByRole("button", { name: "Retry save" }).waitFor();
        assert.equal(await statusText(page), "Not saved");
        assert.match(await page.getByRole("alert").textContent(), /isn’t saved yet/);
        assert.equal(await editorText(page), "not yet saved");
        assert.equal(await page.locator(".ProseMirror").getAttribute("contenteditable"), "true");
        assert.deepEqual(await page.evaluate(() => window.__bhCore.current()), before);
        assert.equal((await calls(page, "note_show")).length, 1, "only the New note switch");
        assert.equal((await calls(page, "note_close")).length, 1);
        await page.evaluate(() => { window.__bhCore.holdAcks = false; });
        await page.getByRole("button", { name: "Retry save" }).click();
        await saved(page);
        await page.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("a failed New note request leaves the existing editor and late typing open", async () => {
      const server=await startUiServer();const browser=await launchBrowser(browserName);
      try {
        const page=await corePage(browser,server.origin,[readyShared,()=>{
          window.__bhIpc.handle('note_create',()=>new Promise((_,reject)=>{window.failCreate=()=>reject(Error('storage unavailable'));}));
        }]);
        await page.locator('.ProseMirror').waitFor();
        await page.getByRole('button',{name:'New note'}).click();
        await page.waitForFunction(()=>!!window.failCreate);
        await page.evaluate(()=>{window.__bhCore.holdAcks=true;});
        await page.locator('.ProseMirror').click();await page.keyboard.insertText('keep writing');
        await page.waitForFunction(()=>window.__bhCore.held.length===1);
        await page.evaluate(()=>window.failCreate());
        assert.equal(await editorText(page),'keep writing');
        assert.equal(await statusText(page),'Saved on this Mac');
        assert.equal((await calls(page,'note_close')).length,0);
        await page.close();
      } finally {await browser.close();await server.close();}
    });

    test("switching notes in place rotates the page token for native delivery", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(browserName);
      try {
        const page = await corePage(browser, server.origin, [readyShared]);
        await page.locator(".ProseMirror").waitFor();
        const old = await page.evaluate(() => window.__bhNotePage);
        await page.getByRole("button", { name: "New note" }).click();
        await page.waitForFunction((token) => window.__bhNotePage !== token, old);
        await page.waitForFunction(() => window.__bhIpc.calls.filter((c) => c.command === "note_open").length === 2);
        await page.locator(".ProseMirror").waitFor();
        const result = await page.evaluate((token) => {
          let dispatched = 0;
          const receive = window.__bhNoteDelivery;
          window.__bhNoteDelivery = (packet) => { dispatched++; return receive(packet); };
          // Same expression as native: compare before constructing the payload.
          const outcome = (() => { if (window.__bhNotePage !== token) return "stale"; return window.__bhNoteDelivery?.({ generation: 1, sequence: 9, update: [], updates: [[0, 0]], resync: true }) ?? "stale"; })();
          return { outcome, dispatched };
        }, old);
        assert.deepEqual(result, { outcome: "stale", dispatched: 0 });
        await page.close();
      } finally { await browser.close(); await server.close(); }
    });

    test("two windows keep their own Undo and a delivered commit keeps unsaved typing", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(browserName);
      try {
        // Both pages show the same core note; this test relays each committed
        // update to the other page as native fanout does.
        const shared = [readyShared, () => {
          const core = window.__bhCore;
          const id = Array(32).fill(5);
          core.notes.set(core.hex(id), { id, updates: [], touched: 1 });
          core.setCurrent(id);
        }];
        const left = await corePage(browser, server.origin, shared);
        const right = await corePage(browser, server.origin, [...shared,()=>{window.__bhTestWriterId=2002468231004601;}]);
        for (const page of [left, right]) await page.locator(".ProseMirror").waitFor();
        const sequences = new Map([[left, 0], [right, 0]]);
        const relay = async (from, to) => {
          const updates = await from.evaluate(() => window.__bhCore.committed.splice(0).map((c) => c.update));
          for (const update of updates) {
            const sequence = sequences.get(to) + 1;
            sequences.set(to, sequence);
            const outcome = await to.evaluate(({ update, sequence }) =>
              window.__bhNoteDelivery({ generation: window.__bhCore.generation(), sequence, update, resync: false }),
            { update, sequence });
            assert.equal(outcome, "accepted");
          }
        };
        await left.locator(".ProseMirror").click();
        await left.keyboard.insertText("left words");
        await saved(left);
        await relay(left, right);
        await right.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "left words");
        await right.locator(".ProseMirror").click();
        await right.keyboard.press("End");
        await right.keyboard.insertText(" right words");
        await saved(right);
        await relay(right, left);
        await left.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "left words right words");

        // End the first local typing group explicitly, without relying on the
        // UndoManager's wall-clock capture timeout on different engines.
        for (const page of [left,right]) await page.locator('.ProseMirror').evaluate(element=>{
          const state=element.editor.state;
          for (const plugin of state.plugins) plugin.getState(state)?.undoManager?.stopCapturing();
        });
        // Right's next typing stays unsaved while left's commit arrives.
        await right.evaluate(() => { window.__bhCore.holdAcks = true; });
        await right.keyboard.insertText(" pending");
        await right.waitForFunction(() => window.__bhCore.held.length === 1);
        await left.locator(".ProseMirror").click();
        await left.keyboard.press("Home");
        await left.keyboard.insertText("New ");
        await saved(left);
        await relay(left, right);
        await right.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "New left words right words pending");
        assert.equal(await statusText(right), "Saved on this Mac");
        await right.evaluate(() => { window.__bhCore.holdAcks = false; window.__bhCore.held.shift()(); });
        await saved(right);
        await relay(right, left);
        await left.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "New left words right words pending");

        // Left's Undo reverses only left's own typing, never right's.
        await left.locator(".ProseMirror").press("ControlOrMeta+z");
        await left.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "left words right words pending");
        await saved(left);
        await relay(left, right);
        await right.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "left words right words pending");
        await right.locator(".ProseMirror").press("ControlOrMeta+z");
        await right.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "left words right words");
        await saved(right);
        await relay(right, left);
        await left.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "left words right words");
        // A fresh open of every committed update shows what both live windows show.
        const note = (page) => page.evaluate(() => window.__bhCore.notes.get(window.__bhCore.hex(Array(32).fill(5))).updates);
        const all = [...await note(left), ...await note(right)];
        const reopened = await corePage(browser, server.origin, [readyShared, [(updates) => {
          const core = window.__bhCore;
          const id = Array(32).fill(5);
          core.notes.set(core.hex(id), { id, updates, touched: 1 });
          core.setCurrent(id);
        }, all]]);
        await reopened.waitForFunction(() => document.querySelector(".ProseMirror")?.textContent === "left words right words");
        await left.close(); await right.close(); await reopened.close();
      } finally { await browser.close(); await server.close(); }
    });
  });
}
