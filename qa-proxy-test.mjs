// اختبار عبر البروكسي الحقيقي (serve.mjs على 5500) بدون تسجيل دخول
const r = await fetch('http://127.0.0.1:5500/api/scanner/quick-scan', {
  method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'http://127.0.0.1:5500', Referer: 'http://127.0.0.1:5500/' },
  body: JSON.stringify({ target: '127.0.0.1:2' }),
  signal: AbortSignal.timeout(600000),
}).then(async x => ({ status: x.status, data: await x.json() }));
console.log('status:', r.status);
console.log(JSON.stringify(r.data, null, 2).slice(0, 900));
