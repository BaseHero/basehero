// Bound bridge checks use the actual bundled EditorView under the shell CSP.
// IPC is a test-only host, not an account session or native-device evidence.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { browserMatrix, launchBrowser, openPage, startUiServer } from "./harness.mjs";
import { tauriIpcStub } from "./tauri-ipc-stub.mjs";

function senderHost() {
  window.__bhIpc.handle("note_binding", () => ({note:Array(32).fill(3),surface:crypto.randomUUID()}));
  window.__bhIpc.handle("note_open", () => ({clientId:window.__bhTestWriterId??2002468231004600,writerToken:Array(32).fill(9),updates: [[0, 0]], generation: 7, sequence: 5 }));
  window.__bhIpc.handle("note_commit", (args) => new Promise((resolve) => {
    (window.__bhPendingAcks ??= []).push({ args, resolve });
  }));
  window.__bhIpc.handle("note_close", () => null);
}

function receiverHost() {
  window.__bhIpc.handle("note_binding", () => ({note:Array(32).fill(3),surface:'42'}));
  window.__bhIpc.handle("note_open", () => new Promise((resolve) => {
    window.__bhFinishOpen = () => resolve({clientId:2002468231004601,writerToken:Array(32).fill(9),updates: [[0, 0]], generation: 7, sequence: 5 });
  }));
  window.__bhIpc.handle("note_commit", (args) => ({ requestId: args.requestId }));
  window.__bhIpc.handle("note_close", () => null);
}

async function dispatch(page, generation, sequence, update) {
  await page.evaluate(({ generation, sequence, update }) => {
    window.dispatchEvent(new CustomEvent("bh-note-update", { detail: { generation, sequence, update } }));
  }, { generation, sequence, update });
}

for (const browserName of browserMatrix) {
  describe(`bound note bridge in ${browserName}`, () => {
    test("synchronous native result reports failure and retries the same sequence", async () => {
      const server = await startUiServer(); const browser = await launchBrowser(browserName);
      try {
        const page = await browser.newPage();
        await page.addInitScript(tauriIpcStub);
        await page.addInitScript(() => {
          window.__bhIpc.handle('note_binding', () => ({note:Array(32).fill(3),surface:'42'}));
          window.__bhIpc.handle('note_open', () => ({clientId:2002468231004600,writerToken:Array(32).fill(9),updates:[[0,0]],generation:7,sequence:5}));
          window.__bhIpc.handle('note_close', () => null);
        });
        // Only the editor is fault-injected; the actual bundled bridge handles
        // a synchronous throwing onUpdate and a successful same-sequence retry.
        await page.route('**/note-editor.js', route => route.fulfill({contentType:'text/javascript',body:`
          export async function createNoteEditor(root,host) {
            let calls=0;
            await host.open(() => { if (++calls === 1) throw Error('injected render failure'); });
            window.__bhHandlerCalls=()=>calls;
          }
        `}));
        await page.goto(`${server.origin}/`, {waitUntil:'load'});
        await page.waitForFunction(() => typeof window.__bhNoteDelivery === 'function');
        const result = await page.evaluate(() => {
          const packet = {generation:7, sequence:6, update:[], updates:[[0,0]], resync:true};
          const failed = window.__bhNoteDelivery(packet);
          const staleGeneration = window.__bhNoteDelivery({...packet, generation:8});
          const valid = window.__bhNoteDelivery(packet);
          const duplicate = window.__bhNoteDelivery(packet);
          const handlerCalls = window.__bhHandlerCalls();
          window.dispatchEvent(new Event('pagehide'));
          const noListener = window.__bhNoteDelivery?.(packet) ?? 'stale';
          return {failed, staleGeneration, valid, duplicate, handlerCalls, noListener};
        });
        assert.deepEqual(result, {failed:'failed', staleGeneration:'stale', valid:'accepted', duplicate:'stale', handlerCalls:2, noListener:'stale'});
        await page.close();
      } finally { await browser.close(); await server.close(); }
    });
    test("a buffered handler failure closes the view instead of leaving a stale editor", async () => {
      const server=await startUiServer();const browser=await launchBrowser(browserName);
      try {
        const page=await browser.newPage();
        await page.addInitScript(tauriIpcStub);
        await page.addInitScript(() => {
          window.__bhIpc.handle('note_binding',()=>({note:Array(32).fill(3),surface:'42'}));
          window.__bhIpc.handle('note_open',()=>new Promise(resolve=>{window.__bhResolve=()=>resolve({clientId:2002468231004600,writerToken:Array(32).fill(9),updates:[[0,0]],generation:7,sequence:5});}));
          window.__bhIpc.handle('note_close',()=>null);
        });
        await page.route('**/note-editor.js',route=>route.fulfill({contentType:'text/javascript',body:`
          export async function createNoteEditor(root,host) {
            await host.open(() => {throw Error('injected buffered render failure');});
            root.textContent='editable';
          }
        `}));
        await page.goto(`${server.origin}/`,{waitUntil:'load'});
        await page.waitForFunction(()=>typeof window.__bhResolve==='function');
        assert.equal(await page.evaluate(()=>window.__bhNoteDelivery({generation:7,sequence:6,update:[],updates:[[0,0]],resync:true})),'buffered');
        await page.evaluate(()=>window.__bhResolve());
        await page.getByText('Note unavailable').waitFor();
        assert.equal(await page.locator('main').getByText('editable').count(),0);
        assert.equal(await page.evaluate(()=>window.__bhIpc.calls.filter(call=>call.command==='note_close').length),1);
        await page.close();
      } finally {await browser.close();await server.close();}
    });
    test("an old queued eval cannot deliver into a reloaded page", async () => {
      const server=await startUiServer(); const browser=await launchBrowser(browserName);
      try {
        const page=await openPage(browser,server.origin,{extraInit:[senderHost]});
        await page.locator('.ProseMirror').waitFor();
        const old=await page.evaluate(() => window.__bhNotePage);
        await page.reload();
        await page.locator('.ProseMirror').waitFor();
        const result=await page.evaluate(old => {
          let dispatched=0;
          const receive=window.__bhNoteDelivery;
          window.__bhNoteDelivery=packet=>{dispatched++;return receive(packet);};
          // Same expression as native: compare before constructing the payload.
          const result=(()=>{if(window.__bhNotePage!==old)return 'stale';return window.__bhNoteDelivery?.({generation:7,sequence:6,update:[],updates:[[0,0]],resync:true})??'stale'})();
          return {result,dispatched,current:window.__bhNotePage};
        },old);
        assert.notEqual(result.current,old);
        assert.deepEqual({result:result.result,dispatched:result.dispatched},{result:'stale',dispatched:0});
        await page.close();
      } finally {await browser.close();await server.close();}
    });
    test("only a capacity rollover passes the current writer token to native open", async () => {
      const server=await startUiServer();const browser=await launchBrowser(browserName);
      try {
        const page=await browser.newPage();
        await page.addInitScript(tauriIpcStub);
        await page.addInitScript(() => {
          let opens=0;
          window.__bhIpc.handle('note_binding',()=>({note:Array(32).fill(3),surface:'42'}));
          window.__bhIpc.handle('note_open',()=>{
            opens++;
            if (opens===3) throw 'note changed; retry open';
            // Three successful native opens whose arrivals overflow the buffer.
            if (opens>=5 && opens<=7) for (let i=1;i<=257;i++)
              window.dispatchEvent(new CustomEvent('bh-note-update',{detail:{generation:opens,sequence:i,update:[0,0]}}));
            return {clientId:opens,writerToken:Array(32).fill(opens),updates:[[0,0]],generation:opens,sequence:0};
          });
          window.__bhIpc.handle('note_close',()=>null);
        });
        await page.route('**/note-editor.js',route=>route.fulfill({contentType:'text/javascript',body:`
          export async function createNoteEditor(root,host) {
            await host.open(()=>{});
            await host.open(()=>{});
            await host.open(()=>{},{retire:true});
            await host.open(()=>{},{retire:true}).catch(()=>{});
            await host.open(()=>{},{retire:true});
            window.__bhOpened=true;
            return {state:()=>({pending:0}),close(){}};
          }
        `}));
        await page.goto(`${server.origin}/`,{waitUntil:'load'});
        await page.waitForFunction(()=>window.__bhOpened===true);
        const opens=await page.evaluate(()=>window.__bhIpc.calls.filter(c=>c.command==='note_open').map(c=>c.args));
        // Ordinary opens never name a writer; the rollover names the current
        // one, its bridge-level Changed retry keeps naming that same token, and
        // a native open that succeeded before the page gave up is the current one.
        assert.deepEqual(opens.map(args=>args.retireWriter?.[0]??null),[null,null,2,2,4,5,6,7]);
        await page.close();
      } finally {await browser.close();await server.close();}
    });
    test("retryable native open never falls back to empty editing or setup", async () => {
      const server=await startUiServer();const browser=await launchBrowser(browserName);
      try {
        const page=await openPage(browser,server.origin,{extraInit:[() => {
          window.__bhIpc.handle('note_binding',()=>({note:Array(32).fill(3),surface:'42'}));
          let calls=0;
          window.__bhIpc.handle('note_open',()=>{
            if (++calls<3) throw 'note changed; retry open';
            return {clientId:2002468231004600,writerToken:Array(32).fill(9),updates:[[0,0]],generation:9,sequence:0};
          });
          window.__bhIpc.handle('note_commit',args=>({requestId:args.requestId}));
          window.__bhIpc.handle('note_close',()=>null);
        }]});
        await page.locator('.ProseMirror').waitFor();
        assert.equal(await page.locator('header .crumb').textContent(),'My base');
        assert.equal(await page.evaluate(()=>window.__bhIpc.calls.filter(call=>call.command==='note_open').length),3);
        assert.equal(await page.locator('[role="status"]').textContent(),'Saved on this Mac');
        await page.close();
      } finally {await browser.close();await server.close();}
    });
    test("failed native open offers an explicit retry without an empty editor", async () => {
      const server=await startUiServer();const browser=await launchBrowser(browserName);
      try {
        const page=await openPage(browser,server.origin,{extraInit:[() => {
          window.__bhIpc.handle('note_binding',()=>({note:Array(32).fill(3),surface:'42'}));
          let calls=0;
          window.__bhIpc.handle('note_open',()=>{
            if (++calls===1) throw 'note unavailable';
            return {clientId:2002468231004600,writerToken:Array(32).fill(9),updates:[[0,0]],generation:9,sequence:0};
          });
          window.__bhIpc.handle('note_commit',args=>({requestId:args.requestId}));
          window.__bhIpc.handle('note_close',()=>null);
        }]});
        await page.getByRole('button',{name:'Retry opening note'}).waitFor();
        assert.equal(await page.locator('.ProseMirror').count(),0);
        assert.equal(await page.locator('header strong').textContent(),'Notes');
        await page.getByRole('button',{name:'Retry opening note'}).click();
        await page.locator('.ProseMirror').waitFor();
        assert.equal(await page.evaluate(()=>window.__bhIpc.calls.filter(c=>c.command==='note_open').length),2);
        await page.close();
      } finally {await browser.close();await server.close();}
    });
    test("bounded pre-open events force fresh committed snapshot rather than partial replay", async () => {
      const server=await startUiServer();const browser=await launchBrowser(browserName);
      try {
        const source=await openPage(browser,server.origin,{extraInit:[senderHost]});
        await source.locator('.ProseMirror').waitFor();
        await source.locator('.ProseMirror').click();await source.keyboard.insertText('committed elsewhere');
        await source.waitForFunction(()=>window.__bhPendingAcks?.length===1);
        const remote=await source.evaluate(()=>window.__bhPendingAcks[0].args.update);
        const receiver=await openPage(browser,server.origin,{extraInit:[() => {
          window.__bhIpc.handle('note_binding',()=>({note:Array(32).fill(3),surface:'42'}));
          let opens=0;
          window.__bhIpc.handle('note_open',()=>{
            if (++opens===1) return new Promise(resolve=>{window.__bhFirstOpen=()=>resolve({clientId:2002468231004600,writerToken:Array(32).fill(9),updates:[[0,0]],generation:7,sequence:5});});
            return {clientId:2002468231004600,writerToken:Array(32).fill(9),updates:[window.__bhCommittedState],generation:8,sequence:258};
          });
          window.__bhIpc.handle('note_commit',args=>({requestId:args.requestId}));
          window.__bhIpc.handle('note_close',()=>null);
        }]});
        await receiver.waitForFunction(()=>typeof window.__bhFirstOpen==='function');
        await receiver.evaluate(update=>{
          window.__bhCommittedState=update;
          for(let sequence=6;sequence<=262;sequence++) window.dispatchEvent(new CustomEvent('bh-note-update',{detail:{generation:7,sequence,update}}));
          window.__bhFirstOpen();
        },remote);
        await receiver.locator('.ProseMirror').waitFor();
        assert.match(await receiver.locator('.ProseMirror').textContent(),/committed elsewhere/);
        assert.equal(await receiver.evaluate(()=>window.__bhIpc.calls.filter(c=>c.command==='note_open').length),2);
        await receiver.close();await source.close();
      } finally {await browser.close();await server.close();}
    });
    test("resync merges into an editing view without losing an unacked edit or retry identity", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(browserName);
      try {
        const source = await openPage(browser, server.origin, {extraInit:[senderHost]});
        await source.locator('.ProseMirror').waitFor();
        await source.locator('.ProseMirror').click();
        await source.keyboard.insertText('remote');
        await source.waitForFunction(() => window.__bhPendingAcks?.length === 1);
        const remote = await source.evaluate(() => window.__bhPendingAcks[0].args.update);
        const view = await openPage(browser, server.origin, {extraInit:[senderHost,()=>{window.__bhTestWriterId=2002468231004601;}]});
        await view.locator('.ProseMirror').waitFor();
        await view.locator('.ProseMirror').click();
        await view.keyboard.insertText('local');
        await view.waitForFunction(() => window.__bhPendingAcks?.length === 1);
        const before = await view.evaluate(() => window.__bhPendingAcks[0].args);
        await view.evaluate((update) => window.dispatchEvent(new CustomEvent('bh-note-update',{
          detail:{generation:7,sequence:6,resync:true,update:[],updates:[update]}
        })),remote);
        await view.waitForFunction(() => document.querySelector('.ProseMirror')?.textContent.includes('remote'));
        assert.match(await view.locator('.ProseMirror').textContent(),/local/);
        assert.equal(await view.locator('[role="status"]').textContent(),'Saved on this Mac');
        // A failed save keeps exactly the same request bytes. Another overflow
        // merge does not take the destructive editor close/recreate path.
        await view.evaluate(() => window.__bhPendingAcks[0].resolve({requestId:'wrong-id'}));
        await view.getByRole('button',{name:'Retry save'}).waitFor({state:'visible'});
        await view.evaluate((update) => window.dispatchEvent(new CustomEvent('bh-note-update',{
          detail:{generation:7,sequence:7,resync:true,update:[],updates:[update]}
        })),remote);
        await view.getByRole('button',{name:'Retry save'}).click();
        await view.waitForFunction(() => window.__bhPendingAcks.length === 2);
        const retry = await view.evaluate(() => window.__bhPendingAcks[1].args);
        assert.deepEqual(retry,before);
        await view.evaluate(() => window.__bhPendingAcks[1].resolve({requestId:window.__bhPendingAcks[1].args.requestId}));
        await view.waitForFunction(() => document.querySelector('[role="status"]').textContent === 'Saved on this Mac');
        const text = await view.locator('.ProseMirror').textContent();
        assert.match(text,/remote/);assert.match(text,/local/);
        assert.equal(await view.evaluate(() => window.__bhIpc.calls.filter(c => c.command === 'note_commit').length),2);
        await source.close();await view.close();
      } finally {await browser.close();await server.close();}
    });
    test("a resync applies native's ordered updates in turn and a reload reopens from them", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(browserName);
      try {
        const source = await openPage(browser, server.origin, {extraInit:[senderHost]});
        await source.locator('.ProseMirror').waitFor();
        await source.locator('.ProseMirror').click();
        await source.keyboard.insertText('first');
        await source.waitForFunction(() => window.__bhPendingAcks?.length === 1);
        await source.evaluate(() => window.__bhPendingAcks[0].resolve({requestId:window.__bhPendingAcks[0].args.requestId}));
        await source.keyboard.insertText(' second');
        await source.waitForFunction(() => window.__bhPendingAcks.length === 2);
        const updates = await source.evaluate(() => window.__bhPendingAcks.map(ack => ack.args.update));
        const view = await openPage(browser, server.origin, {extraInit:[() => {
          window.__bhIpc.handle('note_binding', () => ({note:Array(32).fill(3),surface:crypto.randomUUID()}));
          window.__bhIpc.handle('note_open', () => ({clientId:2002468231004601,writerToken:Array(32).fill(9),
            updates:window.__bhReopened ?? [[0,0]],generation:window.__bhReopened ? 8 : 7,sequence:5}));
          window.__bhIpc.handle('note_commit', args => ({requestId:args.requestId}));
          window.__bhIpc.handle('note_close', () => null);
        }]});
        await view.locator('.ProseMirror').waitFor();
        // The later update depends on the earlier: they apply in their order.
        assert.equal(await view.evaluate(updates => window.__bhNoteDelivery(
          {generation:7,sequence:6,resync:true,update:[],updates}),updates),'accepted');
        await view.waitForFunction(() => document.querySelector('.ProseMirror')?.textContent === 'first second');
        // A reload replaces the merged copy with a fresh open of native's order.
        await view.evaluate(updates => {window.__bhReopened = updates;}, updates);
        assert.equal(await view.evaluate(updates => window.__bhNoteDelivery(
          {generation:7,sequence:7,resync:true,reload:true,update:[],updates}),updates),'accepted');
        await view.waitForFunction(() => window.__bhIpc.calls.filter(c => c.command === 'note_open').length === 2);
        await view.waitForFunction(() => document.querySelector('.ProseMirror')?.textContent === 'first second');
        assert.equal(await view.evaluate(() => window.__bhIpc.calls.filter(c => c.command === 'note_close').length), 1);
        assert.equal(await view.evaluate(() => window.__bhIpc.calls.filter(c => c.command === 'note_commit').length), 0,
          'a reload never echoes as local commits');
        await source.close();await view.close();
      } finally {await browser.close();await server.close();}
    });
    test("a reload with unsaved typing saves it first, and a failed drain keeps the merged copy", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(browserName);
      try {
        const host = () => {
          window.__bhIpc.handle('note_binding', () => ({note:Array(32).fill(3),surface:crypto.randomUUID()}));
          window.__bhIpc.handle('note_open', () => ({clientId:2002468231004601,writerToken:Array(32).fill(9),
            updates:[[0,0]],generation:7 + window.__bhIpc.calls.filter(c => c.command === 'note_open').length,sequence:5}));
          window.__bhIpc.handle('note_commit', args => new Promise(resolve => {
            (window.__bhPendingAcks ??= []).push({args, resolve});
          }));
          window.__bhIpc.handle('note_close', () => null);
        };
        const opens = page => page.evaluate(() => window.__bhIpc.calls.filter(c => c.command === 'note_open').length);
        const reload = page => page.evaluate(() => window.__bhNoteDelivery(
          {generation:8,sequence:6,resync:true,reload:true,update:[],updates:[[0,0]]}));
        // Unsaved typing is saved by the drain before the note reopens.
        const view = await openPage(browser, server.origin, {extraInit:[host]});
        await view.locator('.ProseMirror').waitFor();
        await view.locator('.ProseMirror').click();
        await view.keyboard.insertText('unsaved');
        await view.waitForFunction(() => window.__bhPendingAcks?.length === 1);
        assert.equal(await reload(view), 'accepted');
        await view.waitForTimeout(100);
        assert.equal(await opens(view), 1, 'no reopen before the typing is saved');
        await view.evaluate(() => window.__bhPendingAcks[0].resolve({requestId:window.__bhPendingAcks[0].args.requestId}));
        await view.waitForFunction(() => window.__bhIpc.calls.filter(c => c.command === 'note_open').length === 2);
        assert.equal(await view.evaluate(() => window.__bhIpc.calls.filter(c => c.command === 'note_commit').length), 1);
        await view.close();

        // Typing that cannot be saved keeps the merged copy open and editable.
        const failing = await openPage(browser, server.origin, {extraInit:[host]});
        await failing.locator('.ProseMirror').waitFor();
        await failing.locator('.ProseMirror').click();
        await failing.keyboard.insertText('kept');
        await failing.waitForFunction(() => window.__bhPendingAcks?.length === 1);
        assert.equal(await reload(failing), 'accepted');
        await failing.evaluate(() => window.__bhPendingAcks[0].resolve({requestId:'wrong-id'}));
        // The drain retries the same save once; it fails again.
        await failing.waitForFunction(() => window.__bhPendingAcks.length === 2);
        await failing.evaluate(() => window.__bhPendingAcks[1].resolve({requestId:'wrong-id'}));
        await failing.waitForFunction(() => document.querySelector('.ProseMirror')?.getAttribute('contenteditable') === 'true');
        assert.equal(await opens(failing), 1);
        assert.match(await failing.locator('.ProseMirror').textContent(), /kept/);
        await failing.close();
      } finally {await browser.close();await server.close();}
    });
    test("a reload marker that arrives while navigating or under a drain fence is re-armed", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(browserName);
      try {
        const page = await openPage(browser, server.origin, {extraInit:[() => {
          window.__bhIpc.handle('note_binding', () => ({note:Array(32).fill(3),surface:'42'}));
          window.__bhIpc.handle('note_open', () => ({clientId:2002468231004601,writerToken:Array(32).fill(9),
            updates:[[0,0]],generation:7 + window.__bhIpc.calls.filter(c => c.command === 'note_open').length,sequence:5}));
          window.__bhIpc.handle('note_commit', args => ({requestId:args.requestId}));
          window.__bhIpc.handle('note_close', () => null);
          window.__bhIpc.handle('note_drained', () => true);
          // Navigation to the same note waits here, so it is in progress.
          window.__bhIpc.handle('note_create', () => new Promise(resolve => {window.__bhCreated = () => resolve(Array(32).fill(3));}));
        }]});
        await page.locator('.ProseMirror').waitFor();
        const opens = () => page.evaluate(() => window.__bhIpc.calls.filter(c => c.command === 'note_open').length);
        const reload = generation => page.evaluate(generation => window.__bhNoteDelivery(
          {generation,sequence:6,resync:true,reload:true,update:[],updates:[[0,0]]}), generation);
        // While navigating: the marker waits until navigation ends here.
        await page.evaluate(() => window.__bhMenu('new-note'));
        await page.waitForFunction(() => typeof window.__bhCreated === 'function');
        assert.equal(await reload(8), 'accepted');
        await page.waitForTimeout(50);
        assert.equal(await opens(), 1);
        await page.evaluate(() => window.__bhCreated());
        await page.waitForFunction(() => window.__bhIpc.calls.filter(c => c.command === 'note_open').length === 2);
        // Under a drain fence: the marker waits until native resumes editing.
        await page.locator('.ProseMirror').waitFor();
        const surface = await page.evaluate(() => window.__bhNotePage);
        assert.equal(await page.evaluate(surface => window.__bhDrain({page:surface,fence:'f1',timeoutMs:5000,reason:'close'}), surface), 'accepted');
        await page.waitForFunction(() => window.__bhIpc.calls.some(c => c.command === 'note_drained'));
        assert.equal(await reload(9), 'accepted');
        await page.waitForTimeout(50);
        assert.equal(await opens(), 2);
        await page.evaluate(() => window.__bhResumeEditing('f1'));
        await page.waitForFunction(() => window.__bhIpc.calls.filter(c => c.command === 'note_open').length === 3);
        await page.close();
      } finally {await browser.close();await server.close();}
    });
    test("mounts only with a binding, buffers and fences updates, and saves only matching commits", async () => {
      const server = await startUiServer();
      const browser = await launchBrowser(browserName);
      try {
        const unbound = await openPage(browser, server.origin, {
          extraInit: [() => window.__bhIpc.handle("note_binding", () => null)],
        });
        assert.equal(await unbound.locator("header strong").textContent(), "SETUP");
        assert.equal(await unbound.locator(".ProseMirror").count(), 0);
        assert.deepEqual(await unbound.evaluate(() => window.__bhIpc.calls.map(c => c.command).filter(c => !c.startsWith("update_"))), ["note_binding", "account_screen"]);
        assert.equal(await unbound.evaluate(() => window.__bhStorageReads), 0);
        await unbound.close();

        const sender = await openPage(browser, server.origin, { extraInit: [senderHost] });
        await sender.locator(".ProseMirror").waitFor();
        assert.equal(await sender.locator("header .crumb").textContent(), "My base");
        assert.equal(await sender.locator(".note-content").count(), 1);
        assert.equal(await sender.evaluate(() => window.__bhStorageReads), 0);
        await sender.locator(".ProseMirror").click();
        await sender.keyboard.insertText("hello");
        await sender.waitForFunction(() => window.__bhPendingAcks?.length === 1);
        const first = await sender.evaluate(() => window.__bhPendingAcks[0].args);
        assert.equal(first.generation, 7);
        assert.equal(typeof first.requestId, "string");
        assert.ok(first.update.length > 0);
        assert.equal(await sender.locator('[role="status"]').textContent(), "Saved on this Mac");
        await sender.evaluate(() => window.__bhPendingAcks[0].resolve({ requestId: "wrong-id" }));
        await sender.getByRole("button", { name: "Retry save" }).waitFor({ state: "visible" });
        assert.notEqual(await sender.locator('[role="status"]').textContent(), "Saved on this Mac");
        await sender.getByRole("button", { name: "Retry save" }).click();
        await sender.waitForFunction(() => window.__bhPendingAcks.length === 2);
        const retry = await sender.evaluate(() => window.__bhPendingAcks[1].args);
        assert.deepEqual(retry, first, "retry preserves the same request and update");
        await sender.evaluate(() => window.__bhPendingAcks[1].resolve({ requestId: window.__bhPendingAcks[1].args.requestId }));
        await sender.waitForFunction(() => document.querySelector('[role="status"]').textContent === "Saved on this Mac");
        await sender.keyboard.insertText("!");
        await sender.waitForFunction(() => window.__bhPendingAcks.length === 3);
        const later = await sender.evaluate(() => window.__bhPendingAcks[2].args);
        assert.equal(later.generation, 7);
        await sender.evaluate(() => window.__bhPendingAcks[2].resolve({ requestId: window.__bhPendingAcks[2].args.requestId }));
        await sender.waitForFunction(() => document.querySelector('[role="status"]').textContent === "Saved on this Mac");

        const receiver = await openPage(browser, server.origin, { extraInit: [receiverHost] });
        await receiver.waitForFunction(() => typeof window.__bhFinishOpen === "function");
        // These arrive during note_open, before the snapshot and generation are known.
        assert.equal(await receiver.evaluate(update => window.__bhNoteDelivery({generation:8,sequence:100,update}),later.update),'buffered');
        await dispatch(receiver, 8, 100, later.update);
        await dispatch(receiver, 7, 6, first.update);
        assert.equal(await receiver.locator(".ProseMirror").count(), 0);
        await receiver.evaluate(() => window.__bhFinishOpen());
        await receiver.locator(".ProseMirror").waitFor();
        await receiver.waitForFunction(() => document.querySelector(".ProseMirror").textContent.trim() === "hello");
        assert.equal(await receiver.locator(".ProseMirror").textContent(), "hello");
        await dispatch(receiver, 7, 6, later.update); // equal sequence, distinct content
        await dispatch(receiver, 7, 5, later.update); // older than snapshot
        await dispatch(receiver, 8, 101, later.update); // wrong generation
        assert.equal(await receiver.locator(".ProseMirror").textContent(), "hello");
        await dispatch(receiver, 7, 7, later.update);
        await receiver.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "hello!");
        assert.equal(await receiver.evaluate(() => window.__bhIpc.calls.filter(c => c.command === "note_commit").length), 0,
          "incoming updates never echo as local commits");
        await receiver.locator(".ProseMirror").click();
        await receiver.keyboard.press("End");
        await receiver.keyboard.insertText(" world");
        await receiver.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "hello! world");
        await receiver.locator(".ProseMirror").press("ControlOrMeta+z");
        await receiver.waitForFunction(() => document.querySelector(".ProseMirror").textContent === "hello!");
        assert.equal(await receiver.locator(".ProseMirror").textContent(), "hello!",
          "local Undo leaves incoming content intact");
        assert.equal(await receiver.evaluate(() => window.__bhStorageReads), 0);
        await receiver.evaluate(() => window.dispatchEvent(new Event("pagehide")));
        assert.deepEqual(await receiver.evaluate(() => window.__bhIpc.calls.filter(c => c.command === "note_close").map(c => c.args)),
          [{ generation: 7 }]);
        await sender.evaluate(() => window.dispatchEvent(new Event("pagehide")));
        assert.deepEqual(await sender.evaluate(() => window.__bhIpc.calls.filter(c => c.command === "note_close").map(c => c.args)),
          [{ generation: 7 }]);
        assert.equal(await sender.evaluate(() => window.__bhStorageReads), 0);
        await receiver.close();
        await sender.close();
      } finally {
        await browser.close();
        await server.close();
      }
    });
  });
}
