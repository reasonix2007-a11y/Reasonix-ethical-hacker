// موقع تجريبي محلي مصاب عمداً — للأخلاقي: للتدريب فقط على جهازك
// تشغيل: REASONIX_ENABLE_VULNERABLE_DEMO=true node vulnerable-site.mjs → http://localhost:8899
import http from 'node:http';

const demoEnabled = process.env.REASONIX_ENABLE_VULNERABLE_DEMO === 'true';
const configuredPort = process.env.REASONIX_VULNERABLE_DEMO_PORT;
const port = configuredPort === undefined ? 8899 : Number(configuredPort);
const html = `<!doctype html><html><head><title>Demo Shop — Local Training Target</title></head>
<body><h1>Demo Shop</h1><form><input name=q><button>search</button></form>
<p>Welcome to the intentionally vulnerable demo app.</p></body></html>`;

const routes = {
  '/': { s: 200, b: html },
  '/admin/': { s: 200, b: '<title>Admin Panel — Training Fixture</title><h1>Dashboard</h1><p>DEMO ONLY — no real credentials or data</p>' },
  '/.env': { s: 200, b: 'DB_PASSWORD=DEMO_ONLY_NOT_A_SECRET\nAPI_KEY=DEMO_ONLY_NOT_A_KEY\nJWT_SECRET=DEMO_ONLY_NOT_A_SECRET' },
  '/backup/': { s: 200, b: '<html><head><title>Index of /backup/</title></head><body><a href="backup.sql">backup.sql</a><a href="users.csv">users.csv</a></body></html>' },
  '/backup.sql': { s: 200, b: '-- DEMO ONLY: no real users or credentials\nINSERT INTO demo_users VALUES (1, "training-user", "not-a-real-secret");' },
  '/api/': { s: 200, h: { 'Content-Type': 'application/json' }, b: JSON.stringify({ users: [{ id: 1, user: 'admin', email: 'admin@demo.local', role: 'superadmin' }] }) },
};

const server = http.createServer((q, r) => {
  let p = decodeURIComponent(q.url.split('?')[0]);
  if (p.length > 1 && p.endsWith('/')) {
    const alt = p.slice(0, -1);
    if (routes[alt]) p = alt;
  }
  const hit = routes[p];
  if (!hit || (p !== '/' && !demoEnabled)) {
    r.writeHead(404, { 'Content-Type': 'text/plain' });
    r.end('Not found');
    return;
  }
  r.writeHead(hit.s, {
    'Content-Type': 'text/html; charset=utf-8',
    'Server': 'Express/4.17.1', // كشف إصدار الخادم عمداً
    ...(hit.h || {})
  });
  r.end(hit.b);
});

server.listen(port, '127.0.0.1', () => {
  const address = server.address();
  console.log(`vulnerable demo target ready on http://127.0.0.1:${address.port}${demoEnabled ? ' (unsafe training routes enabled)' : ' (training routes disabled)'}`);
});
