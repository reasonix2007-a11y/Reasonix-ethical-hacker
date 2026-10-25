export default async function run(page, ui) {
  await page.evaluate(async () => {
    const r = await fetch('/api/auth/login', {
      method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'qa1791626976539@example.com', password: 'Passw0rd!1234' })
    });
    const j = await r.json();
    await enterApp(j.user, 'Passw0rd!1234');
  });
  await page.waitForTimeout(400);
  // Seed a fake scan via the app's own code path: state is script-scoped but functions are global,
  // so use renderExploitPlanModal after setting state through the same global-scope evaluation
  // (function declarations live in the same script scope as `let state`, so they CAN see it):
  const seeded = await page.evaluate(() => {
    try {
      // exploitFor etc. are declared in the same script scope; state too. We can't assign directly,
      // but we can verify by calling a function that reads it. Use a trick: Function-scoped eval
      // won't see it either. So instead we check the empty-state behavior only.
      return 'indirect';
    } catch (e) { return 'ERR:' + e.message; }
  });
  // Direct test of exploit command generation with representative findings:
  const cmds = await page.evaluate(() => {
    const mk = (id, cwe, mod, title, ep, param) => ({ id, cwe, mod, title, ep, param, file: 'a.py', line: 1, sev: 'high', ev: [], isFixed: false });
    return {
      sqli: exploitFor(mk('sqli1', 'CWE-89', 'sqli', 'SQL injection', '/item', 'id')),
      jwt: exploitFor(mk('jwt1', 'CWE-347', 'auth', 'JWT alg confusion', '/api', 'token')),
      ssrf: exploitFor(mk('ssrf1', 'CWE-918', 'ssrf', 'SSRF in fetch', '/fetch', 'url')),
      generic: exploitFor(mk('hdr1', 'CWE-693', 'headers', 'Missing headers', '/', '')),
    };
  });
  return { seeded, cmds };
}
