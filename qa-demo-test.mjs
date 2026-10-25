// اختبار الفحص التجريبي بدون تسجيل دخول — أي هدف
const post = body => fetch('http://127.0.0.1:17890/quick-scan', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body), signal: AbortSignal.timeout(400000),
}).then(async r => ({ status: r.status, data: await r.json() })).catch(e => ({ status: 'ERR', data: e.message }));

// 1) هدف محلي (أسرع، يحرر القفل بسرعة)
const local = await post({ target: '127.0.0.1:2' });
console.log('1 (محلي):', local.status, JSON.stringify(local.data).slice(0, 600));
// 2) نطاق عام — يعمل بدون تسجيل دخول (قد ياخذ 2-3 دقائق لـ nmap)
console.log('2 (example.com) — قد ياخذ دقائق، لا تنتظره هنا:', '');
