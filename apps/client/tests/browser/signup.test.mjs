import test from 'node:test';
import assert from 'node:assert/strict';
import { browserMatrix, launchBrowser, openPage, startUiServer } from './harness.mjs';

for (const engine of browserMatrix) {
  test(`${engine}: print route shows only the recovery kit on the print page`,async()=>{
    const server=await startUiServer();const browser=await launchBrowser(engine);
    try {
      const page=await openPage(browser,server.origin,{extraInit:[function(){
        const ipc=window.__bhIpc;let state={screen:'welcome'};
        ipc.handle('note_binding',()=>null);
        ipc.handle('account_screen',()=>state);
        ipc.handle('account_suggest_password',()=>({screen:'password',suggested:'acorn breeze copper dawn elm'}));
        ipc.handle('account_create',()=>state={screen:'kit',code:'DEMO-CODE-NEVER-REAL'});
        ipc.handle('account_print_kit',()=>({result:'opened',route:'print'}));
        ipc.handle('account_confirm_kit',()=>({screen:'ready'}));
        ipc.handle('account_open_note',()=>{throw new Error('own base not yet installed');});
      }]});
      await page.getByRole('button',{name:'Create my account'}).click();
      await page.getByRole('button',{name:'Use this password'}).click();
      await page.getByRole('button',{name:'Print',exact:true}).click();
      await page.getByRole('heading',{name:'Did you keep your kit?'}).waitFor();
      await page.emulateMedia({media:'print'});
      const printed=await page.evaluate(()=>{
        const visible=selector=>{
          let el=document.querySelector(selector);
          if(!el)return false;
          for(;el;el=el.parentElement){
            const style=getComputedStyle(el);
            if(style.display==='none'||style.visibility==='hidden')return false;
          }
          return true;
        };
        const kit=document.querySelector('.signup-print-kit');
        return {text:kit?.textContent,kit:visible('.signup-print-kit'),
          header:visible('header'),footer:visible('footer'),banner:visible('#update-banner'),
          actions:visible('.signup-actions'),heading:visible('main.signup > h1'),intro:visible('.signup-intro')};
      });
      assert.equal(printed.kit,true);
      assert.equal(printed.text,'BaseHero recovery kit\n\nRecovery code: DEMO-CODE-NEVER-REAL\n\nKeep this code and your password. You need both if you lose access to your devices. BaseHero cannot reset a forgotten password. Keep the kit somewhere you can reach if this Mac is lost. The password is not in this file.\n');
      for(const key of ['header','footer','banner','actions','heading','intro'])assert.equal(printed[key],false,key);
      await page.emulateMedia({media:'screen'});
      assert.equal(await page.locator('.signup-print-kit').isVisible(),false);
      await page.getByRole('button',{name:'I saved my kit'}).click();
      await page.getByRole('heading',{name:'Opening your note'}).waitFor();
      assert.equal(await page.locator('.signup-print-kit').count(),0);
      assert.equal((await page.evaluate(()=>window.__bhIpc.calls)).filter(c=>c.command==='account_print_kit').length,1);
      await page.close();
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: first-run screens fit a narrow view in light and dark`, async () => {
    const server=await startUiServer();const browser=await launchBrowser(engine);
    try {
      for (const colorScheme of ['light','dark']) {
        const page=await openPage(browser,server.origin,{viewport:{width:360,height:640},colorScheme,extraInit:[function(){
          const ipc=window.__bhIpc;let state={screen:'welcome'};
          ipc.handle('note_binding',()=>null);
          ipc.handle('account_screen',()=>state);
          ipc.handle('account_suggest_password',()=>({screen:'password',suggested:'acorn breeze copper dawn elm'}));
          ipc.handle('account_create',()=>state={screen:'kit',code:'DEMO-CODE-NOT-REAL'});
        }]});
        for (const step of ['welcome','password','kit']) {
          assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true,`${step} overflows ${colorScheme}`);
          if (step==='welcome') await page.getByRole('button',{name:'Create my account'}).click();
          if (step==='password') await page.getByRole('button',{name:'Use this password'}).click();
        }
        await page.close();
      }
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: an enrolled Mac opens its bound note without repeating setup`, async () => {
    const server=await startUiServer();
    const browser=await launchBrowser(engine);
    try {
      const page=await openPage(browser,server.origin,{extraInit:[function(){
        const ipc=window.__bhIpc;
        let bound=false;
        ipc.handle('note_binding',()=>bound?{note:Array(32).fill(4),surface:'1'}:null);
        ipc.handle('account_screen',()=>({screen:'ready'}));
        ipc.handle('account_open_note',()=>{bound=true;return null;});
        ipc.handle('note_open',()=>({clientId:2002468231004600,writerToken:Array(32).fill(9),state:[0,0],generation:6,sequence:0}));
        ipc.handle('note_commit',args=>({requestId:args.requestId}));
        ipc.handle('note_close',()=>null);
      }]});
      await page.locator('.ProseMirror').waitFor();
      const commands=await page.evaluate(()=>window.__bhIpc.calls.map(c=>c.command).filter(c=>!c.startsWith('update_')));
      assert.deepEqual(commands.slice(0,5),['note_binding','account_screen','account_open_note','note_binding','note_open']);
      assert.equal(await page.getByRole('heading',{name:'Choose your password'}).count(),0);
      await page.close();
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: saved file advances natively without a second page confirmation`, async () => {
    const server=await startUiServer();const browser=await launchBrowser(engine);
    try {
      const page=await openPage(browser,server.origin,{extraInit:[function(){
        const ipc=window.__bhIpc;let state={screen:'welcome'};
        ipc.handle('note_binding',()=>null);
        ipc.handle('account_screen',()=>state);
        ipc.handle('account_suggest_password',()=>({screen:'password',suggested:'acorn breeze copper dawn elm'}));
        ipc.handle('account_create',()=>state={screen:'kit',code:'DEMO-CODE'});
        ipc.handle('account_save_kit_file',()=>{state={screen:'ready'};return {result:'saved',route:'file'};});
        ipc.handle('account_open_note',()=>{throw new Error('own base not yet installed');});
        ipc.handle('account_confirm_kit',()=>{throw new Error('duplicate confirmation');});
      }]});
      await page.getByRole('button',{name:'Create my account'}).click();
      await page.getByRole('button',{name:'Use this password'}).click();
      await page.getByRole('button',{name:'Save a file'}).click();
      await page.getByText('Notes will open after your own base is ready.').waitFor();
      const commands=await page.evaluate(()=>window.__bhIpc.calls.map(c=>c.command));
      assert.equal(commands.filter(command=>command==='account_confirm_kit').length,0);
      assert.equal(commands.filter(command=>command==='account_save_kit_file').length,1);
      await page.close();
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: unavailable and retry screens offer another attempt`, async () => {
    const server=await startUiServer();const browser=await launchBrowser(engine);
    try {
      const page=await openPage(browser,server.origin,{extraInit:[function(){
        let calls=0;const ipc=window.__bhIpc;
        ipc.handle('note_binding',()=>null);
        ipc.handle('account_screen',()=>++calls===1?{screen:'unavailable'}:{screen:'retry'});
      }]});
      await page.getByRole('button',{name:'Try again'}).click();
      await page.getByRole('heading',{name:'Try again'}).waitFor();
      await page.getByRole('button',{name:'Try again'}).waitFor();
      await page.close();
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: first-run kit routes never report opened destinations as saved`, async () => {
    const server=await startUiServer();
    const browser=await launchBrowser(engine);
    try {
      const page=await openPage(browser,server.origin,{viewport:{width:1024,height:768}, extraInit:[function(){
        const ipc=window.__bhIpc;
        let screen={screen:'welcome'};
        ipc.handle('note_binding',()=>screen.screen==='note'?{note:Array(32).fill(3),surface:'1'}:null);
        ipc.handle('note_open',()=>({clientId:2002468231004600,writerToken:Array(32).fill(9),state:[0,0],generation:3,sequence:0}));
        ipc.handle('note_commit',args=>({requestId:args.requestId}));
        ipc.handle('note_close',()=>null);
        ipc.handle('account_screen',()=>screen);
        ipc.handle('account_suggest_password',()=>({screen:'password',suggested:'acorn breeze copper dawn elm'}));
        ipc.handle('account_create',({password})=>{
          if (password==='weak') return {screen:'password',suggested:'acorn breeze copper dawn elm',error:'That password is too easy to guess. Try a longer phrase, or use the suggested one.'};
          screen={screen:'kit',code:'DEMO-CODE-NEVER-A-REAL-ACCOUNT'};
          return screen;
        });
        ipc.handle('account_print_kit',()=>({result:'cancelled'}));
        ipc.handle('account_email_kit',()=>({result:'opened'}));
        let fileAttempt=0;
        ipc.handle('account_save_kit_file',()=>({result:++fileAttempt===1?'failed':'cancelled'}));
        ipc.handle('account_confirm_kit',()=>{screen={screen:'ready'};return screen;});
        ipc.handle('account_open_note',()=>{screen={screen:'note'};return screen;});
      }]});
      await page.getByRole('button',{name:'Create my account'}).click();
      await page.getByRole('heading',{name:'Choose your password'}).waitFor();
      await page.getByRole('button',{name:'Use my own password'}).click();
      await page.getByLabel('Your password').fill('weak');
      await page.getByRole('button',{name:'Continue with this password'}).click();
      await page.getByText('too easy to guess').waitFor();
      await page.getByRole('button',{name:'Use suggested password'}).click();
      await page.getByRole('button',{name:'Use this password'}).click();
      await page.getByRole('heading',{name:'Keep your way back in'}).waitFor();
      await page.getByText('Saving it only on this device won’t help if you lose the device.').waitFor();
      const labels=await page.locator('.kit-routes > button').allTextContents();
      assert.deepEqual(labels.map(s=>s.trim().replace(/\s+/g,' ')),[
        'Save to Passwords — unavailable in this build','Print','Email to myself','Save a file'
      ]);
      assert(await page.getByRole('button',{name:/Save to Passwords/}).isDisabled());
      await page.getByRole('button',{name:'Print',exact:true}).click();
      await page.getByRole('heading',{name:'Keep your way back in'}).waitFor();
      assert.equal(await page.getByText('DEMO-CODE-NEVER-A-REAL-ACCOUNT',{exact:true}).count(),1);
      await page.getByRole('button',{name:'Email to myself'}).click();
      await page.getByRole('heading',{name:'Did you keep your kit?'}).waitFor();
      assert.equal((await page.evaluate(()=>window.__bhIpc.calls)).filter(c=>c.command==='account_confirm_kit').length,0);
      await page.getByRole('button',{name:'Try another way'}).click();
      await page.getByRole('button',{name:'Save a file'}).click();
      await page.getByRole('heading',{name:'Keep your way back in'}).waitFor();
      await page.getByText('That save didn’t work').waitFor();
      await page.getByRole('button',{name:'Save a file'}).click();
      await page.getByRole('heading',{name:'Keep your way back in'}).waitFor();
      await page.getByRole('button',{name:'Email to myself'}).click();
      await page.getByRole('button',{name:'I saved my kit'}).click();
      await page.locator('.ProseMirror').waitFor();
      if (process.env.BH_READY_SCREENSHOT && engine==='chromium') await page.screenshot({path:process.env.BH_READY_SCREENSHOT});
      assert.equal((await page.evaluate(()=>window.__bhIpc.calls)).filter(c=>c.command==='account_confirm_kit').length,1);
      assert.equal(await page.getByText('DEMO-CODE-NEVER-A-REAL-ACCOUNT').count(),0);
      assert.equal(await page.getByRole('button',{name:'Write a note'}).count(),0);
      assert.equal(await page.locator('header .crumb').textContent(), 'My base');
      assert.equal((await page.evaluate(()=>window.__bhIpc.calls)).filter(c=>c.command==='account_open_note').length,1);
      await page.close();
    } finally {await browser.close();await server.close();}
  });
}
