// هدف تجريبي متعمّد الثغرات — لاختبار قدرة الفاحص على الاكتشاف فقط.
// لا تستخدمه على شبكة عامة؛ اربطه على 127.0.0.1 حصراً.
import http from 'node:http';
import crypto from 'node:crypto';

const PORT = 9999;
const SESSION_COOKIE = 'rsx_session=abc123demo';

const VULN_USERS = [
  { id: 1, email: 'admin@demo.local', role: 'admin' },
  { id: 2, email: 'user@demo.local', role: 'user' },
];

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://127.0.0.1:${PORT}`);
  const path = url.pathname;
  const q = url.searchParams;

  // ثغرة 1: TRACE مفتوح
  if (req.method === 'TRACE') {
    const echo = `${req.method} ${req.url} ${JSON.stringify(req.headers)}`;
    res.writeHead(200, { 'Content-Type': 'message/http' });
    return res.end(echo);
  }

  // ثغرة 2: كوكيز جلسة بلا Secure/HttpOnly/SameSite
  res.setHeader('Set-Cookie', 'rsx_session=demo123; Path=/'); // بلا أي حماية

  // ثغرة 3: كشف إصدار الخادم والتقنية
  res.setHeader('Server', 'DemoVulnServer/1.0.3 (Win64)');
  res.setHeader('X-Powered-By', 'Express 4.18.2');

  // ثغرة 4: ترويسات أمان ناقصة تماماً (لا CSP ولا HSTS ولا XFO ...)
  // ثغرة 5: CORS عاكس لأي Origin مع allow-credentials
  const origin = req.headers['origin'];
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  res.setHeader('Content-Type', 'text/html; charset=utf-8');

  // ثغرة 6: SQLi وهمي — يشبه سلوك حقن Boolean/Error فعلياً ليتعرف عليه sqlmap
  if (path === '/product' || path === '/') {
    const id = q.get('id');
    if (id) {
      // محاكاة SQLi: القيم الرقمية تعمل، حمولات الحقن تسبب خطأ SQL أو تغيّر السلوك
      if (/^\d+$/.test(id)) {
        const user = VULN_USERS[Number(id) % VULN_USERS.length];
        res.end(`<html><head><title>Product ${id}</title></head><body><h1>Product #${id}</h1><p>Owner: ${user.email}</p></body></html>`);
      } else if (/(?:'|%27|--|union|select|sleep|or\s+1=1)/i.test(id)) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        return res.end(`SQLSTATE[42000]: Syntax error or access violation: 1064 You have an error in your SQL syntax near '${id}'`);
      } else {
        res.writeHead(404);
        return res.end('Not found');
      }
    }
  }

  // ثغرة 7: انعكاس مدخل بلا ترميز (XSS بيئة)
  if (q.get('q')) {
    const raw = q.get('q');
    if (/<[a-z][^>]*>/i.test(raw)) {
      return res.end(`<html><body><div id="search">نتائج البحث عن: ${raw}</div></body></html>`);
    }
  }

  // ثغرة 8: لوحة إدارة مكشوفة بلا مصادقة
  if (path === '/admin/' || path === '/admin') {
    return res.end('<html><head><title>Admin Panel — Control</title></head><body><h1>Admin Dashboard</h1><form action="/admin" method="post"><input type="password" name="pw"><button>Log in</button></form><p>User management, system logs, config editor.</p></body></html>');
  }

  // ثغرة 9: ملف .env مكشوف بأسرار
  if (path === '/.env') {
    res.setHeader('Content-Type', 'text/plain');
    return res.end('DB_PASSWORD=SuperSecretDemo123\nAPI_KEY=sk-demo-1234567890abcdef\nJWT_SECRET=demo-jwt-secret-value\nDATABASE_URL=mysql://root:pass@localhost/demo\n');
  }

  // ثغرة 10: مسارات .git مكشوفة
  if (path === '/.git/config') {
    res.setHeader('Content-Type', 'text/plain');
    return res.end('[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote "origin"]\n\turl = https://github.com/demo/vuln-app.git\n');
  }
  if (path === '/.git/HEAD') {
    res.setHeader('Content-Type', 'text/plain');
    return res.end('ref: refs/heads/main\n');
  }

  // ثغرة 11: نسخة احتياطية مكشوفة
  if (path === '/backup.sql') {
    res.setHeader('Content-Type', 'application/sql');
    return res.end('-- MySQL dump\nCREATE TABLE users (id INT, email VARCHAR(255), password_hash VARCHAR(255));\nINSERT INTO users VALUES (1, \'admin@demo.local\', \'$2y$10$demo...\');\n');
  }

  // ثغرة 12: عرض محتويات دليل
  if (path === '/uploads/' || path === '/backup/') {
    return res.end('<html><head><title>Index of ' + path + '</title></head><body><h1>Directory listing for ' + path + '</h1><ul><li><a href="secret.txt">secret.txt</a></li><li><a href="db.sqlite">db.sqlite</a></li></ul></body></html>');
  }

  // ثغرة 13: phpinfo/info مكشوفة
  if (path === '/phpinfo.php' || path === '/info.php') {
    return res.end('<html><head><title>phpinfo()</title></head><body><h1>PHP Version 7.4.33</h1><table><tr><td>_SERVER["DOCUMENT_ROOT"]</td><td>C:/www/demo</td></tr></table></body></html>');
  }

  // ثغرة 14: robots.txt يكشف مسارات إدارية
  if (path === '/robots.txt') {
    res.setHeader('Content-Type', 'text/plain');
    return res.end('User-agent: *\nDisallow: /admin/\nDisallow: /backup/\nDisallow: /panel/\nSitemap: http://127.0.0.1:9999/sitemap.xml\n');
  }

  // ثغرة 15: API مكشوف (actuator وهمي)
  if (path === '/actuator/env') {
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({ propertySources: [{ name: 'systemProperties' }], activeProfiles: ['prod'] }));
  }
  if (path === '/swagger.json') {
    res.setHeader('Content-Type', 'application/json');
    return res.end(JSON.stringify({ openapi: '3.0.1', info: { title: 'Demo API' }, paths: {} }));
  }

  // ثغرة 16: أسرار في JS الواجهة
  if (path === '/app.js') {
    res.setHeader('Content-Type', 'application/javascript');
    return res.end('const config = { apiKey: "AIzaSyDemo1234567890abcdefghijk", stripeKey: "sk_test_demo" };\n');
  }

  // ثغرة 17: رسائل خطأ تكشف مسارات وتقنيات
  if (path === '/boom' || q.get('reasonix-error-probe')) {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    return res.end('Traceback (most recent call last):\n  File "C:\\www\\demo\\app.py", line 42, in handler\n    raise ValueError("bad input")\nValueError: bad input\n');
  }

  // ثغرة 18: نقطة API بمعاملات لـ SQLi
  if (path === '/api/user') {
    const id = q.get('id') || q.get('uid');
    if (id && /^\d+$/.test(id)) {
      res.setHeader('Content-Type', 'application/json');
      const u = VULN_USERS[Number(id) % VULN_USERS.length];
      return res.end(JSON.stringify({ id: Number(id), email: u.email, role: u.role, ts: crypto.randomBytes(4).toString('hex') }));
    }
    if (id) {
      res.writeHead(500, { 'Content-Type': 'text/plain' });
      return res.end(`mysql_fetch_assoc(): supplied argument is not a valid MySQL result near '${id}'`);
    }
  }

  // صفحة رئيسية عادية
  res.end('<html><head><title>Demo Vulnerable App</title></head><body><h1>Demo Vulnerable App</h1><p>Use /product?id=1 و /api/user?id=1 و /admin/ و /?q=test</p></body></html>');
});

server.listen(PORT, '127.0.0.1', () => console.log(`vulnerable demo target → http://127.0.0.1:${PORT}`));
