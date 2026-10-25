export default async function run(page, ui) {
  await page.waitForTimeout(4000);
  await page.evaluate(async () => {
    const r = await fetch('/api/auth/login', {
      method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'qa1791626976539@example.com', password: 'Passw0rd!1234' })
    });
    const j = await r.json();
    await enterApp(j.user, 'Passw0rd!1234');
  });
  await page.waitForTimeout(400);
  return await page.evaluate(() => {
    const mk = (id, cwe, mod, title, ep, param) => ({ id, cwe, mod, title, ep, param, file: 'a.py', line: 1, sev: 'high', ev: [], isFixed: false });
    return {
      sqli: exploitFor(mk('sqli1', 'CWE-89', 'sqli', 'SQL injection', '/item', 'id')),
      jwt: exploitFor(mk('jwt1', 'CWE-347', 'auth', 'JWT alg confusion', '/api', 'token')),
      ssrf: exploitFor(mk('ssrf1', 'CWE-918', 'ssrf', 'SSRF in fetch', '/fetch', 'url')),
      cookie: exploitFor(mk('ck1', 'CWE-1026', 'cookies', 'Cookie flags missing', '/', '')),
      generic: exploitFor(mk('hdr1', 'CWE-693', 'headers', 'Missing headers', '/', '')),
    };
  });
}
