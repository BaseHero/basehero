import assert from 'node:assert/strict';
import { test } from 'node:test';
import { browserMatrix, launchBrowser, openPage, startUiServer } from './harness.mjs';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
async function shot(page,name) { if(process.env.BH_SCREENSHOT_DIR){await mkdir(process.env.BH_SCREENSHOT_DIR,{recursive:true});await page.screenshot({path:join(process.env.BH_SCREENSHOT_DIR,name+'.png')});} }

async function fresh(browser, origin, answers = []) {
  const page = await openPage(browser, origin, {extraInit: [() => {
    const ipc = window.__bhIpc;
    ipc.handle('note_binding', () => null);
    ipc.handle('account_screen', () => ({screen: 'welcome'}));
    ipc.handle('account_check_code', ({code}) => code === 'bad' ? false : true);
    ipc.handle('account_recover', () => window.__recoveryAnswers?.shift() ?? {screen: 'recovered'});
    ipc.handle('account_recovery_status', () => ({state:'ready',done:3,total:3}));
    ipc.handle('account_open_note', () => null);
  }]});
  await page.evaluate(answers => { window.__recoveryAnswers = answers; }, answers);
  return page;
}

for (const engine of browserMatrix) {
  test(`${engine}: welcome offers both ways back`, async () => {
    const server = await startUiServer(), browser = await launchBrowser(engine);
    try {
      const page = await fresh(browser, server.origin);
      await page.getByRole('button',{name:'I already have an account'}).click();
      await page.getByRole('heading',{name:'Welcome back'}).waitFor();
      await page.getByText('Do you still have BaseHero on another device?').waitFor();
      await page.getByRole('button',{name:'Use my other device'}).waitFor();
      await page.getByRole('button',{name:'Use password and recovery kit'}).waitFor();
      await shot(page,`${engine}-welcome-back`);
    } finally { await browser.close(); await server.close(); }
  });
  test(`${engine}: typo shows not recognised without a recovery request`, async () => {
    const server = await startUiServer(), browser = await launchBrowser(engine);
    try {
      const page = await fresh(browser, server.origin);
      await page.getByRole('button',{name:'I already have an account'}).click();
      await page.getByRole('button',{name:'Use password and recovery kit'}).click();
      await page.getByLabel('Recovery code').fill('bad');
      await page.getByLabel('Password').fill('correct');
      await page.getByRole('button',{name:'Recover account'}).click();
      await page.getByRole('heading',{name:'Code not recognised'}).waitFor();
      await page.getByText('This did not use a password attempt.').waitFor();
      await shot(page,`${engine}-code-not-recognised`);
      const calls = await page.evaluate(() => window.__bhIpc.calls.map(c => c.command));
      assert.equal(calls.filter(c => c === 'account_check_code').length, 1);
      assert.equal(calls.filter(c => c === 'account_recover').length, 0);
    } finally { await browser.close(); await server.close(); }
  });
  test(`${engine}: a rejected checksum invoke reports unreachable, not a mistyped code`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await fresh(browser,server.origin);
      await page.evaluate(()=>window.__bhIpc.handle('account_check_code',()=>{throw Error('native service unavailable');}));
      await page.getByRole('button',{name:'I already have an account'}).click();
      await page.getByRole('button',{name:'Use password and recovery kit'}).click();
      await page.getByLabel('Recovery code').fill('valid');
      await page.getByLabel('Password').fill('correct');
      await page.getByRole('button',{name:'Recover account'}).click();
      await page.getByRole('heading',{name:'Can’t reach recovery right now'}).waitFor();
      assert.equal(await page.getByText('This did not use a password attempt.').count(),0);
      const calls=await page.evaluate(()=>window.__bhIpc.calls.map(c=>c.command));
      assert.equal(calls.filter(c=>c==='account_check_code').length,1);
      assert.equal(calls.filter(c=>c==='account_recover').length,0);
      await shot(page,`${engine}-checksum-unavailable`);
    }finally{await browser.close();await server.close();}
  });
  test(`${engine}: recovery shows the join download stage before the recovered screen`,async()=>{
    const server=await startUiServer(),browser=await launchBrowser(engine);
    try {const page=await fresh(browser,server.origin);
      await page.evaluate(()=>{
        window.__bhIpc.handle('account_recover',()=>new Promise(resolve=>{window.__finishRecovery=()=>resolve({screen:'recovered'});}));
        window.__bhIpc.handle('account_recovery_status',()=>({state:'bootstrapping',done:1,total:3}));
      });
      await page.getByRole('button',{name:'I already have an account'}).click();
      await page.getByRole('button',{name:'Use password and recovery kit'}).click();
      await page.getByLabel('Recovery code').fill('valid');
      await page.getByLabel('Password').fill('correct');
      await shot(page,`${engine}-recovery-form`);
      await page.getByRole('button',{name:'Recover account'}).click();
      await page.getByText('Downloading your notes: 1 of 3').waitFor();
      await shot(page,`${engine}-recovery-download`);
      await page.evaluate(()=>window.__finishRecovery());
      await page.getByRole('heading',{name:'Back in your space'}).waitFor();
      await page.getByRole('button',{name:'Review devices'}).waitFor();
      await shot(page,`${engine}-recovered`);
    }finally{await browser.close();await server.close();}
  });
  for (const [name, answer, expected] of [
    ['password mismatch shows tries left from the service', {screen:'recover_refused',reason:'password',tries_left:4,next_try_ms:null}, '4 tries left'],
    ['wait shows the service time', {screen:'recover_refused',reason:'wait',tries_left:null,next_try_ms:1792060440000}, '2026'],
  ]) test(`${engine}: ${name}`, async () => {
    const server = await startUiServer(), browser = await launchBrowser(engine);
    try {
      const page = await fresh(browser, server.origin, [answer]);
      await page.getByRole('button',{name:'I already have an account'}).click();
      await page.getByRole('button',{name:'Use password and recovery kit'}).click();
      await page.getByLabel('Recovery code').fill('valid');
      await page.getByLabel('Password').fill('wrong');
      await page.getByRole('button',{name:'Recover account'}).click();
      await page.getByText(expected,{exact:false}).waitFor();
      await shot(page,`${engine}-${answer.reason}`);
    } finally { await browser.close(); await server.close(); }
  });
}
