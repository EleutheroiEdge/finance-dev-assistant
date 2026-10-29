// Synthetic public media only. Render code-native artwork and the existing demo cast locally.
// Requires the locked Playwright browser and ffmpeg; never calls an image/model service.
import { chromium } from '@playwright/test';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';

const target = new URL('../../docs/images/', import.meta.url);
const rows = (await readFile(new URL('demo.cast.txt', target), 'utf8')).trim().split('\n').map(JSON.parse);
const escape = s => s.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
const css = `<style>*{box-sizing:border-box}body{margin:0;background:#102625;color:#f4f8f5;font-family:'DejaVu Sans',sans-serif}main{padding:64px}small{color:#9edbc7;letter-spacing:3px;font-size:17px}h1{font-size:62px;letter-spacing:-2px;margin:28px 0}p{color:#cee0da;font-size:25px;line-height:1.5}footer{color:#a7c4b8;font-size:18px;margin-top:36px}.flow{display:flex;gap:18px;margin:48px 0 32px}.step{flex:1;background:#f4f8f5;color:#102625;border-radius:12px;padding:24px 20px;position:relative}.step b{font-size:24px;display:block;margin:20px 0 12px}.step p{font-size:17px;color:#254a40;margin:0}.step span{color:#316956;font-size:16px}.step:not(:last-child):after{content:'→';position:absolute;right:-17px;top:88px;color:#9edbc7;font-size:22px}pre{font:16px/1.35 'DejaVu Sans Mono',monospace;margin:24px 0;white-space:pre-wrap}.terminal{padding:32px 40px}header{display:flex;justify-content:space-between;border-bottom:1px solid #36534a;padding-bottom:18px;font-size:19px}header span{color:#9edbc7}</style>`;
const env = {};
for (const name of ['PATH', 'HOME', 'SystemRoot', 'TEMP', 'TMP']) if (process.env[name]) env[name] = process.env[name];
const browser = await chromium.launch({env});
const temp = await mkdtemp(path.join(tmpdir(), 'finledgerpoli-media-'));
try {
  const page = await browser.newPage({viewport: {width:1280,height:640},deviceScaleFactor:1,colorScheme:'light'});
  await page.route('**/*', route => route.abort());
  await page.setContent(`${css}<main><small>LOCAL CODE. YOUR DECISIONS.</small><h1>finledgerpoli</h1><p>AI code review for financial software that keeps your code local<br>and backs every finding with evidence.</p><footer>Offline by default · Your model · Reproducible checks</footer></main>`);
  await page.screenshot({path: new URL('social-preview.png',target).pathname});
  const steps = [['Plan','Choose the exact code version.'],['Review','Inspect findings with your chosen model.'],['Reproduce','Run your own checks.'],['Propose','Inspect and approve each patch.'],['Audit','Save evidence for your change records.']];
  await page.setContent(`${css}<main><small>FINLEDGERPOLI / HOW IT WORKS</small><h1>From change to evidence</h1><div class="flow">${steps.map(([name,text],i)=>`<div class="step"><span>0${i+1}</span><b>${name}</b><p>${text}</p></div>`).join('')}</div><footer>Offline by default. Nothing merges, deploys or trades by itself.</footer></main>`);
  await page.screenshot({path:new URL('how-it-works.png',target).pathname});
  // Sample the cast at a fixed 5 fps; hold the actual final JSON for two seconds.
  // Scroll the terminal rather than abbreviating or inventing demo results.
  await page.setViewportSize({width:1000,height:660});
  const duration = rows.at(-1)[0] + 2;
  if (duration >= 15) throw new Error('Demo recording exceeds hero duration');
  for(let i=0;i<Math.ceil(duration*5);i++) {
    const text = rows.slice(1).filter(row=>row[0]<=i/5).map(row=>row[2]).join('').replaceAll('\r','');
    const lines = text.trimEnd().split('\n').slice(-22).join('\n');
    await page.setContent(`${css}<div class="terminal"><header><b>finledgerpoli</b><span>Synthetic demo · offline · no model calls</span></header><pre>${escape(lines)}</pre></div>`);
    await page.screenshot({path:path.join(temp,`frame-${String(i).padStart(3,'0')}.png`)});
  }
  const result=spawnSync('ffmpeg',['-v','error','-y','-framerate','5','-i',path.join(temp,'frame-%03d.png'),'-filter_complex','[0:v]split[a][b];[a]palettegen=stats_mode=diff[p];[b][p]paletteuse=dither=none','-loop','0',new URL('hero.gif',target).pathname],{env,shell:false,encoding:'utf8'});
  if(result.status!==0) throw new Error(`GIF rendering failed: ${result.stderr}`);
} finally {await browser.close();await rm(temp,{recursive:true,force:true});}
