export default async function run(page, ui) {
  await page.waitForSelector('#boot', { state: 'detached', timeout: 8000 }).catch(() => {});
  await page.evaluate(() => { const b = document.querySelector('#boot'); if (b) b.remove(); });
  await page.waitForFunction(() => typeof go === 'function', null, { timeout: 10000 }).catch(() => {});
  await page.evaluate(() => { const b = document.querySelector('#boot'); if (b) b.remove(); });
  const state0 = await page.evaluate(() => ({
    bootGone: !document.querySelector('#boot'),
    firstView: document.querySelector('.view:not(.hidden)')?.id,
    statCards: document.querySelectorAll('#view-overview .glass.rounded-2xl').length
  }));

  // الفاحص
  await page.evaluate(() => { if (typeof go === 'function') go('scanner'); else document.querySelector('a[data-view="scanner"]').click(); });
  await page.waitForTimeout(300);
  await page.evaluate(() => { document.querySelector('#target').value = 'https://demo.testfire.net'; });
  await page.click('#btn-scan');
  await page.waitForSelector('#scan-result', { state: 'visible', timeout: 40000 });
  const scan = await page.evaluate(() => ({
    pct: document.querySelector('#scan-pct').textContent,
    termLines: document.querySelectorAll('#term-log .ln').length,
    countsBadges: document.querySelector('#scan-done-counts')?.textContent,
    doneSub: document.querySelector('#scan-done-sub')?.textContent.slice(0, 60)
  }));

  // النتائج
  await page.click('#scan-result button:first-of-type');
  await page.waitForTimeout(400);
  const fnd = await page.evaluate(() => ({
    visible: !document.querySelector('#view-findings').classList.contains('hidden'),
    cards: document.querySelectorAll('#fnd-list > div').length,
    chips: document.querySelectorAll('#fnd-counts .chip').length,
    firstCard: document.querySelector('#fnd-list .sev')?.textContent
  }));

  // نافذة التفاصيل
  await page.click('#fnd-list > div:first-child button:first-child');
  await page.waitForTimeout(300);
  const modal = await page.evaluate(() => ({
    open: !document.querySelector('#fmodal').classList.contains('hidden'),
    title: document.querySelector('#fm-title')?.textContent.slice(0, 45),
    sections: document.querySelectorAll('#fm-body h4').length,
    codeBlocks: document.querySelectorAll('#fm-body pre').length
  }));
  await page.click('#fmodal .fm-panel button'); // زر الإغلاق في الرأس
  await page.waitForTimeout(250);

  // وضع مُصلحة من البطاقة
  await page.click('#fnd-list > div:first-child button:nth-of-type(2)');
  await page.waitForTimeout(300);
  const fixedCheck = await page.evaluate(() => ({
    fixedBadge: !!document.querySelector('#fnd-list .sev-fixed'),
    toast: document.querySelector('#toasts')?.textContent.slice(0, 40)
  }));

  // التقرير
  await page.click('a[data-view="report"]');
  await page.waitForTimeout(400);
  const rep = await page.evaluate(() => ({
    visible: !document.querySelector('#view-report').classList.contains('hidden'),
    rows: document.querySelectorAll('#rep-tbody tr').length,
    grade: document.querySelector('#rep-grade')?.textContent,
    gaugeVal: document.querySelector('#rep-gauge-val')?.textContent,
    bars: document.querySelectorAll('#rep-bars > div').length,
    details: document.querySelectorAll('#rep-details details').length
  }));

  // المساعد الذكي
  await page.click('a[data-view="assistant"]');
  await page.fill('#chat-in', 'كيف أمنع XSS؟');
  await page.click('#view-assistant .btn-primary');
  await page.waitForTimeout(1800);
  const chat = await page.evaluate(() => ({
    msgs: document.querySelectorAll('#chat > div').length,
    answer: document.querySelector('#chat > div:last-child div')?.textContent.slice(0, 60)
  }));

  // اللغة الإنجليزية ثم العودة
  await page.click('#btn-lang');
  await page.waitForTimeout(300);
  const lang = await page.evaluate(() => ({
    dir: document.documentElement.dir,
    navText: document.querySelector('.navlink.active')?.textContent
  }));
  await page.click('#btn-lang');

  const dl = await page.evaluate(() => ({
    buttons: [...document.querySelectorAll('#view-report button')].map(b => b.textContent.trim()).slice(0, 3)
  }));

  return { state0, scan, fnd, modal, fixedCheck, rep, chat, lang, dl };
}
