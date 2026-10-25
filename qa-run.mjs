// مشغّل الفحص: يشغّل الاختبارات على Chrome ضد الخادم الفعلي
// الاستخدام:  node qa-run.mjs [test1.mjs test2.mjs ...]
import { chromium } from 'playwright-core';
import path from 'node:path';

const URL = process.env.QA_URL || 'http://127.0.0.1:5500/index.html';

const browser = await chromium.launch({ channel: 'chrome', headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });

const results = {};
const mods = process.argv[2] ? process.argv.slice(2).map(p => './' + p.replace(/^\.\//, '')) : ['./qa.mjs', './qa-visual.mjs'];
for (const mod of mods) {
  const name = path.basename(mod, '.mjs');
  console.log(`\n=== ${name} ===`);
  try {
    await page.goto(URL, { waitUntil: 'load', timeout: 30000 });
    results[name] = await (await import(mod)).default(page, console);
    console.log(JSON.stringify(results[name], null, 2));
  } catch (e) {
    results[name] = { error: String(e).split('\n')[0] };
      console.log('FAILED:', results[name].error);
    }
}

await browser.close();
console.log('\ndone');
