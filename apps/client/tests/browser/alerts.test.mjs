import assert from 'node:assert/strict';
import { test } from 'node:test';
import { browserMatrix, launchBrowser, openPage, startUiServer } from './harness.mjs';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
async function shot(page,name) { if(process.env.BH_SCREENSHOT_DIR){await mkdir(process.env.BH_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:join(process.env.BH_SCREENSHOT_DIR,name+'.png')});} }
const alerts = [
  ['device_added_by_kit','Your account was opened on a new device with your password and recovery kit'],
  ['device_added_by_qr','Pixel was added'],
  ['kit_used','Your recovery kit was used'],
  ['removal_requested','Removal of Pixel requested from MacBook'],
  ['removal_cancelled','Removal of Pixel was cancelled'],
  ['removal_effective','Pixel was removed'],
  ['kit_changed','Password and recovery kit changed from MacBook'],
  ['refused_change','BaseHero refused an invalid change to your account'],
  ['kit_not_changed','Your recovery kit wasn’t changed. Your old kit still works.'],
].map(([kind,copy],i)=>({id:i+1,kind,copy,subject_name:'Pixel',actor_name:'MacBook',time_ms:100+i,deadline_ms:null}));
for (const engine of browserMatrix) {
  test(`${engine}: each alert kind renders its copy, newest first`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await openPage(browser,server.origin,{extraInit:[()=>{
      const ipc=window.__bhIpc;
      ipc.handle('note_binding',()=>null);
      ipc.handle('account_screen',()=>({screen:'ready'}));
      ipc.handle('account_open_note',()=>null);
      ipc.handle('devices_kit_screen',()=>null);
      ipc.handle('devices_view',()=>({wait_ms:300000,devices:[],alerts:[],password_change_needs_kit:false}));
      ipc.handle('alerts_list',()=>window.__alertFixture);
    }]});
      await page.evaluate(rows=>{window.__alertFixture=rows;},alerts);
      await page.evaluate(()=>window.__bhDevices?.());
      await page.getByRole('button',{name:'Security alerts'}).click();
      const rendered=await page.locator('.alert-list li').allTextContents();
      assert.equal(rendered.length,alerts.length);
      await shot(page,`${engine}-security-alerts`);
      for (let i=0;i<alerts.length;i++) assert.ok(rendered[i].includes(alerts[alerts.length-1-i].copy),alerts[alerts.length-1-i].kind);
    }finally{await browser.close();await server.close();}
  });
}
