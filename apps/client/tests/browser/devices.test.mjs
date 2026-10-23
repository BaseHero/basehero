import assert from 'node:assert/strict';
import { test } from 'node:test';
import { browserMatrix, launchBrowser, openPage, startUiServer } from './harness.mjs';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
async function shot(page,name) { if(process.env.BH_SCREENSHOT_DIR){await mkdir(process.env.BH_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:join(process.env.BH_SCREENSHOT_DIR,name+'.png')});} }

const deadline = new Date(2026, 9, 15, 9, 14).getTime();
const item = (name, thisDevice, extra={}) => ({id_hex:thisDevice?'aa'.repeat(32):'bb'.repeat(32),name,this_device:thisDevice,added_ms:deadline-1e7,pending:null,submitting:false,can_remove:true,can_remove_now:false,can_cancel:false,...extra});
const data = (wait_ms=259200000, other={}) => ({wait_ms,password_change_needs_kit:false,alerts:[],devices:[item('MacBook Pro',true),item('Pixel 10 Pro Fold',false,other)]});
async function open(browser, origin, value) {
  const page = await openPage(browser,origin,{extraInit:[() => {
    const ipc=window.__bhIpc;
    ipc.handle('note_binding',()=>null);
    ipc.handle('account_screen',()=>({screen:'ready'}));
    ipc.handle('account_open_note',()=>null);
    ipc.handle('devices_view',()=>window.__devicesValue);
    ipc.handle('devices_kit_screen',()=>window.__bhKit??null);
    ipc.handle('devices_request_removal',()=>({screen:'ready'}));
    ipc.handle('devices_cancel_removal',()=>({screen:'cancel_took_effect'}));
  }]});
  await page.evaluate(value => {window.__devicesValue=value;},value);
  await page.evaluate(() => window.__bhDevices?.());
  return page;
}
for(const engine of browserMatrix) {
  test(`${engine}: 412px note status shows the full protection message`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await openPage(browser,server.origin,{viewport:{width:412,height:915},extraInit:[()=>{
      const ipc=window.__bhIpc;
      ipc.handle('note_binding',()=>({note:Array(32).fill(3),surface:'1'}));
      ipc.handle('note_open',()=>({clientId:2002468231004600,writerToken:Array(32).fill(9),updates:[[0,0]],generation:1,sequence:0}));
      ipc.handle('note_close',()=>null);
      ipc.handle('note_list',()=>[]);
      ipc.handle('note_selection',()=>[]);
      ipc.handle('sync_status',()=>({revision:1,state:'protecting',pending:0,network:'on',home:'done',account:'active',confirm:false}));
    }]});
      await page.locator('.ProseMirror').waitFor();
      await page.evaluate(()=>window.dispatchEvent(new CustomEvent('sync://status',{detail:{revision:2,state:'synced',pending:0,network:'on',home:'done',account:'active',confirm:false}})));
      const label=page.locator('footer.status .sync-text');
      await label.getByText('New changes are protected').waitFor();
      if(process.env.BH_SCREENSHOT_DIR) await shot(page,`${engine}-412-status-${process.env.BH_STATUS_SHOT_PHASE??'after'}`);
      const layout=await label.evaluate(node=>({visible:node.clientWidth,full:node.scrollWidth,
        footer:node.closest('footer').getBoundingClientRect().width,
        viewport:document.documentElement.clientWidth}));
      assert.equal(layout.viewport,412);
      assert.equal(layout.footer,412);
      assert.ok(layout.visible>=layout.full,`status is clipped: ${JSON.stringify(layout)}`);
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: protecting state changes to protected after verified sync`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await openPage(browser,server.origin,{extraInit:[()=>{
      window.__bhIpc.handle('note_binding',()=>null);
      window.__bhIpc.handle('account_screen',()=>({screen:'unavailable'}));
    }]});
      const texts=await page.evaluate(async()=>{
        const {syncLine}=await import('./pairing.js');const target=document.createElement('section');document.body.append(target);
        const line=syncLine(target,()=>null);target.append(...line.nodes);
        const view=(revision,state)=>({revision,state,pending:0,network:'on',home:'done',account:'active',confirm:false});
        line.render(view(1,'protecting'));const during=target.querySelector('.sync-text').textContent;
        line.render(view(2,'waiting-network'));const offline=target.querySelector('.sync-text').textContent;
        line.render(view(3,'syncing'));const syncing=target.querySelector('.sync-text').textContent;
        line.render(view(4,'synced'));const finished=target.querySelector('.sync-text').textContent;
        line.render(view(5,'protecting'));
        line.render(view(6,'stopped'));
        line.render(view(7,'synced'));
        return [during,offline,syncing,finished,target.querySelector('.sync-text').textContent];
      });
      assert.deepEqual(texts,['Updating protection…','Saved on this device · Waiting for network','Syncing','New changes are protected','Synced']);
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: this device has Remove this device; others Remove`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await open(browser,server.origin,data());
      await page.getByRole('heading',{name:'Your devices'}).waitFor();
      await page.getByRole('button',{name:'Remove this device'}).waitFor();
      await page.getByRole('button',{name:'Remove',exact:true}).waitFor();
      await shot(page,`${engine}-your-devices`);
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: remove now offered only when eligible; wait text follows the build`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await open(browser,server.origin,data());
      await page.getByRole('button',{name:'Remove',exact:true}).click();
      await page.getByRole('button',{name:'Remove after three days'}).waitFor();
      await shot(page,`${engine}-remove-confirm`);
      assert.equal(await page.getByRole('button',{name:'Remove now with your recovery kit'}).count(),0);
      await page.evaluate(()=>{window.__devicesValue={...window.__devicesValue,wait_ms:300000,devices:window.__devicesValue.devices.map((d,i)=>i?{...d,can_remove_now:true}:d)};});
      await page.evaluate(()=>window.__bhDevices());
      await page.getByRole('button',{name:'Remove',exact:true}).click();
      await page.getByRole('button',{name:'Remove after 5 minutes'}).waitFor();
      await page.getByRole('button',{name:'Remove now with your recovery kit'}).waitFor();
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: immediate removal asks for password and kit`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await open(browser,server.origin,data(300000,{can_remove_now:true}));
      await page.getByRole('button',{name:'Remove',exact:true}).click();
      await page.getByRole('button',{name:'Remove now with your recovery kit'}).click();
      await page.getByLabel('Recovery code').waitFor();
      await shot(page,`${engine}-remove-now`);
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: kit wait refusal uses the recovery wait screen`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await open(browser,server.origin,data(300000,{can_remove_now:true}));
      await page.evaluate(()=>window.__bhIpc.handle('devices_remove_now',()=>({screen:'recover_refused',reason:'wait',next_try_ms:1792060440000,tries_left:null})));
      await page.getByRole('button',{name:'Remove',exact:true}).click();
      await page.getByRole('button',{name:'Remove now with your recovery kit'}).click();
      await page.getByRole('button',{name:'Remove now with password and kit'}).click();
      await page.getByRole('heading',{name:'Wait before trying again'}).waitFor();
      await page.getByText('You can try again at',{exact:false}).waitFor();
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: pending shows deadline and cancel only when eligible; target banner has no cancel`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const pending={request:4,deadline_ms:deadline,requested_by:'MacBook Pro'};
      const page=await open(browser,server.origin,data(259200000,{pending,can_remove:false,can_cancel:true}));
      await page.getByText('Removal takes effect Thursday, 15 October at 9:14 am',{exact:false}).waitFor();
      await page.getByRole('button',{name:'Cancel removal'}).waitFor();
      await shot(page,`${engine}-removal-pending`);
      await page.getByRole('button',{name:'Close'}).click();
      await page.evaluate(pending=>{window.__devicesValue={...window.__devicesValue,devices:[{...window.__devicesValue.devices[0],pending,can_cancel:false},{...window.__devicesValue.devices[1],pending:null,can_cancel:false}]};},pending);
      await page.evaluate(()=>window.__bhDevices());
      await page.getByText('This device will be removed from your account on Thursday, 15 October at 9:14 am.',{exact:false}).waitFor();
      await shot(page,`${engine}-target-banner`);
      assert.equal(await page.getByRole('button',{name:'Cancel removal'}).count(),0);
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: change password shows new kit and saves it`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await open(browser,server.origin,data());
      await page.evaluate(()=>{
        window.__bhIpc.handle('account_change_password',()=>({screen:'new_kit',code:'DEMO-NEW-KIT'}));
        window.__bhIpc.handle('account_confirm_new_kit',()=>({screen:'ready'}));
      });
      await page.getByRole('button',{name:'Change password & recovery kit'}).click();
      await page.getByRole('heading',{name:'Change password & recovery kit'}).waitFor();
      await shot(page,`${engine}-change-password`);
      await page.getByLabel('Current password',{exact:true}).fill('the current password');
      await page.getByLabel('New password',{exact:true}).fill('the new password');
      await page.getByRole('button',{name:'Continue'}).click();
      await page.locator('.devices-dialog .signup-kit-code').getByText('DEMO-NEW-KIT',{exact:true}).waitFor();
      await shot(page,`${engine}-new-kit`);
      await page.emulateMedia({media:'print'});
      assert.equal(await page.evaluate(()=>getComputedStyle(document.querySelector('main')).display),'none');
      assert.equal(await page.locator('.devices-dialog .signup-print-kit').isVisible(),true);
      assert.equal(await page.locator('.devices-dialog .signup-print-kit').textContent(),
        'BaseHero recovery kit\n\nRecovery code: DEMO-NEW-KIT\n\nKeep this code and your password. You need both if you lose access to your devices. BaseHero cannot reset a forgotten password. Keep the kit somewhere you can reach if this Mac is lost. The password is not in this file.\n');
      assert.equal(await page.locator('.devices-dialog .signup-kit-code').isVisible(),false);
      assert.equal(await page.evaluate(()=>getComputedStyle(document.querySelector('.devices-dialog'),'::backdrop').backgroundColor),'rgba(0, 0, 0, 0)');
      await shot(page,`${engine}-changed-kit-print`);
      if(engine==='chromium' && process.env.BH_SCREENSHOT_DIR) await page.pdf({path:join(process.env.BH_SCREENSHOT_DIR,'changed-kit-print.pdf')});
      await page.emulateMedia({media:'screen'});
      await page.getByRole('button',{name:'I saved my kit'}).click();
      await page.getByRole('heading',{name:'Your devices'}).waitFor();
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: a secondary note window saves its changed kit through its native file route`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await openPage(browser,server.origin,{extraInit:[()=>{
      const ipc=window.__bhIpc;
      window.__TAURI_INTERNALS__.metadata.currentWindow.label='note-2';
      window.__TAURI_INTERNALS__.metadata.currentWebview.windowLabel='note-2';
      const note=Array(32).fill(7);
      ipc.handle('note_binding',()=>({note,surface:'1'}));
      ipc.handle('note_open',()=>({clientId:2002468231004600,writerToken:Array(32).fill(9),updates:[[0,0]],generation:1,sequence:0}));
      ipc.handle('note_close',()=>null);
      ipc.handle('note_list',()=>[]);
      ipc.handle('note_selection',()=>[]);
      ipc.handle('sync_status',()=>({revision:1,state:'synced',pending:0,network:'on',home:'done',account:'active',confirm:false}));
      ipc.handle('window_sidebar',()=>true);
      ipc.handle('devices_kit_screen',()=>window.__bhKit??null);
      ipc.handle('devices_view',()=>window.__devicesValue);
      ipc.handle('account_change_password',()=>window.__bhKit={screen:'new_kit',code:'DEMO-SECOND-KIT'});
      ipc.handle('account_save_kit_file',()=>{window.__bhKit=null;return {result:'saved',route:'file'};});
    }]});
      await page.evaluate(view=>window.__devicesValue=view,data());
      await page.locator('.ProseMirror').waitFor();
      await page.getByRole('button',{name:'Devices'}).click();
      await page.getByRole('button',{name:'Change password & recovery kit'}).click();
      await page.getByRole('button',{name:'Continue'}).click();
      await page.locator('.devices-dialog .signup-kit-code').getByText('DEMO-SECOND-KIT',{exact:true}).waitFor();
      await page.getByRole('button',{name:'Save a file'}).click();
      await page.getByRole('heading',{name:'Your devices'}).waitFor();
      const calls=await page.evaluate(()=>({label:window.__TAURI_INTERNALS__.metadata.currentWindow.label,
        commands:window.__bhIpc.calls.map(c=>c.command)}));
      assert.equal(calls.label,'note-2');
      assert.equal(calls.commands.filter(c=>c==='account_save_kit_file').length,1);
      assert.equal(calls.commands.filter(c=>c==='account_confirm_new_kit').length,0);
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: unsaved changed kit survives closing Devices and a page reload`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await open(browser,server.origin,data());
      await page.evaluate(()=>{window.__bhKit={screen:'new_kit',code:'DEMO-KEPT-KIT'};});
      await page.getByRole('button',{name:'Close'}).click();
      await page.evaluate(()=>window.__bhDevices());
      await page.locator('.devices-dialog .signup-kit-code').getByText('DEMO-KEPT-KIT',{exact:true}).waitFor();
      await page.getByRole('button',{name:'Close'}).click();
      await page.reload();
      await page.evaluate(()=>window.__bhIpc.handle('devices_kit_screen',()=>({screen:'new_kit',code:'DEMO-KEPT-KIT'})));
      await page.evaluate(()=>window.__bhDevices());
      await page.locator('.devices-dialog .signup-kit-code').getByText('DEMO-KEPT-KIT',{exact:true}).waitFor();
      assert.equal((await page.evaluate(()=>window.__bhIpc.calls)).filter(c=>c.command==='devices_kit_screen').length,1);
      await shot(page,`${engine}-changed-kit-reopened`);
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: saving the changed kit as a file confirms natively once`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await open(browser,server.origin,data());
      await page.evaluate(()=>{
        window.__bhIpc.handle('account_change_password',()=>({screen:'new_kit',code:'DEMO-NEW-KIT'}));
        window.__bhIpc.handle('account_save_kit_file',()=>({result:'saved',route:'file'}));
        window.__bhIpc.handle('account_confirm_new_kit',()=>{throw Error('duplicate confirmation');});
      });
      await page.getByRole('button',{name:'Change password & recovery kit'}).click();
      await page.getByRole('button',{name:'Continue'}).click();
      await page.getByRole('button',{name:'Save a file'}).click();
      await page.getByRole('heading',{name:'Your devices'}).waitFor();
      assert.equal((await page.evaluate(()=>window.__bhIpc.calls)).filter(c=>c.command==='account_confirm_new_kit').length,0);
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: self removal shows erasure and unsent count`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await open(browser,server.origin,data());
      await page.evaluate(()=>window.__bhIpc.handle('devices_remove_self',()=>({screen:'erased',unsent:3})));
      await page.getByRole('button',{name:'Remove this device'}).click();
      await page.getByRole('button',{name:'Remove this device'}).click();
      await page.getByText('3 unsynced changes were not sent.').waitFor();
      await shot(page,`${engine}-erased`);
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: incomplete erasure offers retry, not a false erased claim`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await open(browser,server.origin,data());
      await page.evaluate(()=>window.__bhIpc.handle('devices_remove_self',()=>({screen:'erase_incomplete',failed:2})));
      await page.getByRole('button',{name:'Remove this device'}).click();
      await page.getByRole('button',{name:'Remove this device'}).click();
      await page.getByText('BaseHero couldn’t finish erasing this account’s data.').waitFor();
      assert.equal(await page.getByText('BaseHero erased this account’s data here.').count(),0);
      await shot(page,`${engine}-erase-incomplete`);
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: lapsed cancel says it already took effect`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await open(browser,server.origin,data(259200000,{pending:{request:4,deadline_ms:deadline,requested_by:'MacBook Pro'},can_cancel:true}));
      await page.getByRole('button',{name:'Cancel removal'}).click();
      await page.getByText('This removal already took effect.').waitFor();
      await shot(page,`${engine}-lapsed-cancel`);
    }finally{await browser.close();await server.close();}
  });
}
