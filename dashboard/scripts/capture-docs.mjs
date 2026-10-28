// Maintainer-only screenshot generation. Temporary synthetic state; no provider calls.
import { chromium } from '@playwright/test';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

const root = await mkdtemp(path.join(tmpdir(), 'finassist-docs-'));
const python = process.env.FINASSIST_TEST_PYTHON || (process.platform === 'win32' ? '../.venv/Scripts/python.exe' : '../.venv/bin/python');
const env = {};
for (const name of ['PATH', 'SystemRoot', 'SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP', 'HOME', 'USERPROFILE']) {
  if (process.env[name]) env[name] = process.env[name];
}
const project = path.join(root, 'synthetic');
const result = spawnSync(python, ['../scripts/seed_docs_demo.py', project], { env, shell: false, encoding: 'utf8' });
if (result.status !== 0) throw new Error('Synthetic fixture failed');
const child = spawn(python, ['-m', 'finassist', '--config', path.join(project, 'configuration.json'), 'dashboard', '--state-dir', path.join(project, 'state')], { env, shell: false });
let browser;
try {
  const origin = await new Promise((resolve, reject) => {
    let text = '';
    const timer = setTimeout(() => reject(new Error('Startup timed out')), 15000);
    child.stdout.on('data', block => {text += block.toString('utf8'); const m = text.match(/Dashboard: (http:\/\/127\.0\.0\.1:\d+)/); if (m) {clearTimeout(timer); resolve(m[1]);}});
    child.once('exit', () => { clearTimeout(timer); reject(new Error('Dashboard exited')); });
  });
  browser = await chromium.launch();
  const page = await browser.newPage({ viewport: {width: 1280, height: 900}, deviceScaleFactor: 1 });
  const external = [];
  await page.route('**/*', route => {
    if (new URL(route.request().url()).origin !== origin) {external.push(route.request().url()); return route.abort();}
    return route.continue();
  });
  await page.goto(origin);
  await page.getByRole('heading', {name: 'Configuration', exact: true}).waitFor();
  await page.getByLabel('Provider', {exact: true}).waitFor();
  await mkdir('../docs/images', {recursive: true});
  await page.screenshot({path: '../docs/images/dashboard-configuration.png'});
  await page.getByRole('button', {name: /^Statistics/}).click();
  await page.getByRole('heading', {name: 'Recent runs'}).waitFor();
  await page.getByRole('img', {name: 'Recorded spend (USD)', exact: true}).waitFor();
  await page.screenshot({path: '../docs/images/dashboard-statistics.png'});
  await page.getByRole('button', {name: /^Health/}).click();
  await page.getByText('Configuration is valid').waitFor();
  await page.screenshot({path: '../docs/images/dashboard-health.png'});
  if (external.length) throw new Error('External requests refused');
} finally {
  if (browser) await browser.close();
  if (child.exitCode === null) {child.kill(); await new Promise(resolve => child.once('exit', resolve));}
  await rm(root, {recursive: true, force: true});
}
