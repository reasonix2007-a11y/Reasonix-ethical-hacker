import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { chromium } from 'playwright-core';

const ROOT = process.cwd();
const server = http.createServer(async (req, res) => {
  try {
    const data = await readFile(path.join(ROOT, 'index.html'));
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(data);
  } catch { res.writeHead(404); res.end(); }
});
await new Promise(r => server.listen(4174, '127.0.0.1', r));

const browser = await chromium.launch({ channel: 'chrome', headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
page.on('console', m => console.log(`[console.${m.type()}]`, m.text().slice(0, 200)));
page.on('pageerror', e => console.log('[pageerror]', String(e).slice(0, 300)));
page.on('requestfailed', r => console.log('[reqfail]', r.url().slice(0, 120), r.failure()?.errorText));

await page.goto('http://127.0.0.1:4174/index.html', { waitUntil: 'load' });
await page.waitForTimeout(4000);
const state = await page.evaluate(() => ({
  boot: !!document.querySelector('#boot'),
  bootText: document.querySelector('#boot')?.textContent.slice(0, 80),
  visibleView: document.querySelector('.view:not(.hidden)')?.id,
  goType: typeof globalThis.go,
  targetVisible: !!document.querySelector('#target') && getComputedStyle(document.querySelector('#target')).display !== 'none',
  scripts: [...document.scripts].map(s => s.src.split('/').pop() || 'inline').slice(0, 10)
}));
console.log(JSON.stringify(state, null, 2));
await browser.close(); server.close();
