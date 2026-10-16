import test from 'node:test';
import assert from 'node:assert/strict';
import { browserMatrix, launchBrowser, openPage, startUiServer } from './harness.mjs';

// The Mac app icon: a rounded tile on the standard icon grid (body about
// 824 of 1024, transparent outside) with the Dispatch B optically centred.
for (const engine of browserMatrix) {
  test(`${engine}: bundled app icon is a rounded tile with a centred Dispatch B`,async()=>{
    const server=await startUiServer();const browser=await launchBrowser(engine);
    try {
      const page=await openPage(browser,server.origin,{stub:false});
      const icon=await page.evaluate(async()=>{
        const image=new Image();image.src='/icon.png';await image.decode();
        const canvas=document.createElement('canvas');canvas.width=canvas.height=1024;
        const context=canvas.getContext('2d');context.drawImage(image,0,0);
        const data=context.getImageData(0,0,1024,1024).data;
        const at=(x,y)=>Array.from(data.slice((y*1024+x)*4,(y*1024+x)*4+4));
        const yellow=(x,y)=>{const [r,g,b,a]=at(x,y);return a===255&&r>240&&g>180&&b<60;};
        let left=1024,right=-1,top=1024,bottom=-1,mass=0,cx=0;
        for(let y=0;y<1024;y++)for(let x=0;x<1024;x++)if(yellow(x,y)){
          left=Math.min(left,x);right=Math.max(right,x);top=Math.min(top,y);bottom=Math.max(bottom,y);mass++;cx+=x;
        }
        // Outline edges of the mark on a row: first and last yellow pixel.
        const edges=y=>{let a=-1,b=-1;for(let x=0;x<1024;x++)if(yellow(x,y)){if(a<0)a=x;b=x;}return [a,b];};
        return {width:image.naturalWidth,height:image.naturalHeight,corner:at(4,4),outside:at(60,512),tileCorner:at(112,112),
          body:at(512,880),edgeIn:at(106,512),left,right,top,bottom,centroid:cx/mass,
          rows:[0.2,0.5,0.8].map(f=>edges(Math.round(top+f*(bottom-top)))),
          waist:Array.from({length:bottom-top},(_,i)=>edges(top+i)[1])};
      });
      assert.equal(icon.width,1024);assert.equal(icon.height,1024);
      for(const key of ['corner','outside','tileCorner'])assert.equal(icon[key][3],0,`${key} is transparent`);
      assert.deepEqual(icon.body,[15,17,20,255],'the tile is Dispatch black');
      assert.deepEqual(icon.edgeIn,[15,17,20,255],'the tile body starts about 100 px in');
      // Optically centred: the mark's box centre sits on the tile's centre.
      assert.ok(Math.abs((icon.left+icon.right)/2-512)<=10,`horizontal centre ${(icon.left+icon.right)/2}`);
      assert.ok(Math.abs((icon.top+icon.bottom)/2-505)<=12,`vertical centre ${(icon.top+icon.bottom)/2}`);
      assert.ok(icon.bottom-icon.top>=400 && icon.bottom-icon.top<=520,`mark height ${icon.bottom-icon.top}`);
      // A B, not an 8: one straight stem on the left, a narrower upper bowl
      // and a waist where the right side steps in between the bowls.
      assert.equal(new Set(icon.rows.map(([a])=>a)).size,1,'straight left stem');
      const [upper,,lower]=icon.rows.map(([,b])=>b);
      assert.ok(upper<lower-12,`upper bowl ${upper} is narrower than lower ${lower}`);
      const waistIn=Math.min(...icon.waist.slice(Math.round(icon.waist.length*0.3),Math.round(icon.waist.length*0.6)));
      assert.ok(waistIn<upper-20,`waist ${waistIn} steps in from the upper bowl ${upper}`);
      await page.close();
    }finally{await browser.close();await server.close();}
  });
}
