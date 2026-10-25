// استعلام سريع: هل القفل محرر؟ (يعني الفحص انتهى)
const r = await fetch('http://127.0.0.1:17890/quick-scan', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ target: '127.0.0.1:2' }),
  signal: AbortSignal.timeout(8000),
}).then(x => x.status).catch(e => 'ERR ' + e.message);
console.log(r === 409 ? 'الفحص السابق ما زال جارياً' : 'القفل محرر — الفحص السابق انتهى (status ' + r + ')');
