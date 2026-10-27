import { test, expect, type Page } from '@playwright/test';

const r = { account: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', base: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' };
const note = 'cccccccccccccccccccccccccccccccc';
const png = [137,80,78,71,13,10,26,10,0,0,0,0];
test.beforeEach(async ({ context }) => {
  await context.addInitScript(() => {
    Object.defineProperty(window, '__fake', { configurable: true, set(fake: typeof window.__fake) {
      Object.defineProperty(window, '__fake', { configurable: true, value: fake });
      const state = fake as unknown as {accountList: {id:string;email:string;kind:'full'}[];baseList:Map<string,{id:string;name:string;mode:'readWrite'}[]>;items:Map<string,{id:string;title:string;parent:null;deleted:false;kind:'note'}[]>};
      const account='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',base='bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
      state.accountList.push({id:account,email:'fixture@example.com',kind:'full'});
      state.baseList.set(account,[{id:base,name:'Personal',mode:'readWrite'}]);
      state.items.set(`${account}:${base}`,[{id:'cccccccccccccccccccccccccccccccc',title:'Note',parent:null,deleted:false,kind:'note'}]);
    } });
  });
});
async function open(page: Page) { await page.goto(`/#/a/${r.account}/b/${r.base}/n/${note}`); await expect(page.locator('.ProseMirror')).toBeVisible(); }
async function paste(page: Page, name:string, type:string, bytes:number[]) {
  await page.locator('.ProseMirror').evaluate((el,{name,type,bytes})=>{
    const transfer=new DataTransfer();transfer.items.add(new File([new Uint8Array(bytes)],name,{type}));
    el.dispatchEvent(new ClipboardEvent('paste',{bubbles:true,cancelable:true,clipboardData:transfer}));
  },{name,type,bytes});
}
test('pasting a PNG adds a file and shows the image', async ({page})=>{
  await open(page);await paste(page,'photo.png','image/png',png);
  const image=page.locator('.ProseMirror img');await expect(image).toHaveAttribute('src',/^blob:/);
  expect(await image.evaluate(el=>el.getAttributeNames().sort())).toEqual(['alt','class','src']);
  await expect(page.locator('.ProseMirror p')).toHaveCount(1);
  await expect.poll(()=>page.evaluate(()=>window.__fake.calls)).toContain(`fileAdd ${r.account}`);
  await expect.poll(()=>page.evaluate(()=>window.__fake.calls.some(call=>call.startsWith('noteApply')))).toBe(true);
  // Reopening the note reads its saved image ID and makes a fresh object URL.
  await page.evaluate(ref=>{location.hash=`#/a/${ref.account}/b/${ref.base}`;},r);
  await expect(page.locator('.ProseMirror')).toHaveCount(0);
  await page.evaluate(({r,note})=>{location.hash=`#/a/${r.account}/b/${r.base}/n/${note}`;},{r,note});
  await expect(page.locator('.ProseMirror img')).toHaveAttribute('src',/^blob:/);
});
test('an SVG pasted as image/png shows as a file, not an image',async({page})=>{
  await open(page);await paste(page,'bad.svg','image/png',Array.from(new TextEncoder().encode('<svg><script/></svg>')));
  await expect.poll(()=>page.evaluate(()=>window.__fake.calls)).toContain(`fileAdd ${r.account}`);
  await expect(page.locator('.ProseMirror img')).toHaveCount(0);
});
test('an image not yet here shows a placeholder, then appears',async({page})=>{
  await open(page);
  await paste(page,'later.png','image/png',png);
  await expect(page.locator('.ProseMirror img')).toHaveAttribute('src',/^blob:/);
  const id=await page.evaluate(async ref=>(await window.__fake.files(ref,'cccccccccccccccccccccccccccccccc'))[0].id,r);
  await page.evaluate(id=>window.__fake.setFileStatus(id,{kind:'fetching',done:0,parts:1}),id);
  await expect(page.getByText('Image not on this device yet')).toBeVisible();
  await page.evaluate(id=>window.__fake.setFileStatus(id,{kind:'here'}),id);
  await expect(page.locator('.ProseMirror img')).toHaveAttribute('src',/^blob:/);
});
test('a file over 100 MB is refused with a message',async({page})=>{
  await open(page);
  await page.locator('.ProseMirror').evaluate(el=>{
    const transfer=new DataTransfer();transfer.items.add(new File([new Uint8Array(104_857_601)],'big.png',{type:'image/png'}));
    el.dispatchEvent(new ClipboardEvent('paste',{bubbles:true,cancelable:true,clipboardData:transfer}));
  });
  await expect(page.getByRole('alert')).toContainText('Files can be at most 100 MB.');
  await expect(page.locator('.ProseMirror img')).toHaveCount(0);
});
test('pasting formatted HTML with images keeps the formatting',async({page})=>{
  await open(page);
  let requests=0;
  page.on('request',req=>{if(req.url().includes('x.example')) requests++;});
  await page.locator('.ProseMirror').evaluate(el=>{
    const transfer=new DataTransfer();
    transfer.setData('text/html','<h2>Kyoto</h2><img src="https://x.example/a.png"><ul><li>Ferry at 9</li></ul>');
    transfer.setData('text/plain','Kyoto\nFerry at 9');
    el.dispatchEvent(new ClipboardEvent('paste',{bubbles:true,cancelable:true,clipboardData:transfer}));
  });
  await expect(page.locator('.ProseMirror h2')).toHaveText('Kyoto');
  await expect(page.locator('.ProseMirror li')).toHaveText('Ferry at 9');
  await expect(page.locator('.ProseMirror img')).toHaveCount(0);
  expect(requests).toBe(0);
});
test('pasted HTML images without a file id add nothing',async({page})=>{
  await open(page);let requests=0;
  page.on('request',req=>{if(req.url().includes('x.example')) requests++;});
  await page.locator('.ProseMirror').evaluate(el=>{
    const transfer=new DataTransfer();transfer.setData('text/html','<img src="https://x.example/y.png"><img data-bh-file="nothex" src="https://x.example/z.png">');
    el.dispatchEvent(new ClipboardEvent('paste',{bubbles:true,cancelable:true,clipboardData:transfer}));
  });
  const id=await page.evaluate(async({r,note,png})=>(await window.__fake.fileAdd(r,note,'real.png','image/png',new Uint8Array(png))).id,{r,note,png});
  await page.locator('.ProseMirror').evaluate((el,id)=>{
    const transfer=new DataTransfer();transfer.setData('text/html',`<img data-bh-file="${id}" src="https://x.example/other.png">`);
    el.dispatchEvent(new ClipboardEvent('paste',{bubbles:true,cancelable:true,clipboardData:transfer}));
  },id);
  await expect(page.locator('.ProseMirror img')).toHaveCount(0);
  expect(requests).toBe(0);
});
