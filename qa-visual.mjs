// فحص بصري: يجري نفس مسار qa.mjs لكن يلتقط لقطات شاشة لكل مرحلة
// ويعيد ملخصاً + قائمة اللقطات + أخطاء الكونسول إن وجدت
export default async function run(page, ui) {
  const shots = [];
  const errors = [];
  try {
    page.on('pageerror', e => errors.push('pageerror: ' + e));
    page.on('console', m => { if (m.type() === 'error') errors.push('console: ' + m.text()); });
  } catch { }

  const shot = async (name, fullPage = true) => {
    const file = `shot-${name}.png`;
    await page.screenshot({ path: file, fullPage });
    shots.push(file);
  };

  // الإقلاع: بعض الإطارات لا تزيل #boot بنفسها فنزيلها يدوياً كما في qa.mjs
  await page.waitForSelector('#boot', { state: 'detached', timeout: 9000 }).catch(() => { });
  await page.evaluate(() => { const b = document.querySelector('#boot'); if (b) b.remove(); });
  await page.waitForFunction(() => typeof go === 'function', null, { timeout: 10000 }).catch(() => { });

  // 1) لوحة القيادة
  await page.waitForTimeout(400);
  await shot('overview');

  // 2) الفاحص: بدء الفحص وانتظار نتيجته
  await page.click('a[data-view="scanner"]');
  await page.fill('#target', 'https://demo.testfire.net');
  await page.click('#btn-scan');
  await page.waitForSelector('#scan-result', { state: 'visible', timeout: 40000 });
  await page.waitForTimeout(400);
  await shot('scanner');
  const scan = await page.evaluate(() => ({
    pct: document.querySelector('#scan-pct')?.textContent,
    counts: document.querySelector('#scan-done-counts')?.textContent
  }));

  // 3) الثغرات
  await page.click('#scan-result button:first-of-type');
  await page.waitForTimeout(500);
  await shot('findings');
  const fnd = await page.evaluate(() => ({
    cards: document.querySelectorAll('#fnd-list > div').length
  }));

  // 4) نافذة التفاصيل ثم إغلاقها
  await page.click('#fnd-list > div:first-child button:first-child');
  await page.waitForTimeout(300);
  await shot('modal', false);
  await page.click('#fmodal .fm-panel button');
  await page.waitForTimeout(250);

  // 5) التقرير الكامل
  await page.click('a[data-view="report"]');
  await page.waitForTimeout(1400);
  await shot('report');
  const rep = await page.evaluate(() => ({
    visible: !document.querySelector('#view-report').classList.contains('hidden'),
    rows: document.querySelectorAll('#rep-tbody tr').length,
    grade: document.querySelector('#rep-grade')?.textContent
  }));

  // 6) المساعد الذكي
  await page.click('a[data-view="assistant"]');
  await page.fill('#chat-in', 'كيف أمنع XSS؟');
  await page.click('#view-assistant .btn-primary');
  await page.waitForTimeout(1800);
  await shot('assistant');
  const chat = await page.evaluate(() => ({
    msgs: document.querySelectorAll('#chat > div').length
  }));

  // 7) الوضع المحمول: إعادة تحميل (الحالة محفوظة في localStorage) + القائمة
  const vp = page.viewportSize?.();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.reload();
  await page.waitForSelector('#boot', { state: 'detached', timeout: 9000 }).catch(() => { });
  await page.evaluate(() => { const b = document.querySelector('#boot'); if (b) b.remove(); });
  await page.waitForTimeout(500);
  await shot('mobile-overview');
  await page.click('#btn-menu');
  await page.waitForTimeout(300);
  await shot('mobile-menu', false);
  await page.click('#btn-menu');
  if (vp) await page.setViewportSize(vp);

  const ok = rep.visible && rep.rows > 0 && fnd.cards > 0 && chat.msgs > 1 && errors.length === 0;
  return { ok, scan, fnd, rep, chat, shots, errors };
}
