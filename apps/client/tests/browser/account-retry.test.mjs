import test from 'node:test';
import assert from 'node:assert/strict';
import { browserMatrix, launchBrowser, openPage, startUiServer } from './harness.mjs';

for (const engine of browserMatrix) {
  test(`${engine}: a failed unlock never re-requests without Try again`,async()=>{
    const server=await startUiServer();const browser=await launchBrowser(engine);
    try {
      const page=await openPage(browser,server.origin,{extraInit:[function(){
        const ipc=window.__bhIpc;
        ipc.handle('note_binding',()=>null);
        ipc.handle('account_screen',()=>({screen:'retry'}));
        ipc.handle('account_retry',()=>({screen:'ready'}));
        ipc.handle('account_open_note',()=>{throw Error('not bound');});
      }]});
      await page.getByText('Your account is still on this Mac.').waitFor();
      await page.waitForTimeout(1200);
      assert.equal((await page.evaluate(()=>window.__bhIpc.calls)).filter(c=>c.command==='account_screen').length,1);
      assert.equal((await page.evaluate(()=>window.__bhIpc.calls)).filter(c=>c.command==='account_retry').length,0);
      await page.getByRole('button',{name:'Try again'}).click();
      assert.equal((await page.evaluate(()=>window.__bhIpc.calls)).filter(c=>c.command==='account_retry').length,1);
      await page.close();
    }finally{await browser.close();await server.close();}
  });
}
