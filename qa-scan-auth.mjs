import assert from 'node:assert/strict';
import http from 'node:http';
import { classifyHttpStatus, compareBehavioralResponses, parseFfufOutput, parseNucleiOutput, PROBE_ACTIVITY, remediationGuideFor, req, runAutonomousCrawler, runHeuristicFuzzer, runWithScanOptions } from './scan-server.mjs';

assert.equal(PROBE_ACTIVITY.securityHeaders.method, 'GET');
assert.equal(PROBE_ACTIVITY.openPorts.method, 'TCP connect');
assert.match(remediationGuideFor({ k: 'missing-headers' }).source, /illustrative/u);
assert.match(remediationGuideFor({ k: 'MISSING_SECURITY_HEADERS' }).remediatedCode, /Content-Security-Policy/u);
assert.match(remediationGuideFor({ k: 'XSS_REFLECTED' }).remediatedCode, /textContent/u);
assert.match(remediationGuideFor({ k: 'INSECURE_COOKIE' }).remediatedCode, /httpOnly/u);
assert.equal(remediationGuideFor({ k: 'autonomous-cookie-flags-123abc' }).source, 'illustrative');
assert.match(remediationGuideFor({ k: 'sql-injection' }).remediatedCode, /\$1/u);
assert.deepEqual(remediationGuideFor({ k: 'artifact-unknown' }).source, 'guidance-only');
assert.equal(remediationGuideFor({ k: 'source-finding', sourceCode: 'unsafe()', fixedCode: 'safe()' }).vulnerableCode, 'unsafe()');

const requests = { rateLimited: 0 };
const server = http.createServer((request, response) => {
  if (request.url === '/custom-header') {
    response.writeHead(request.headers['x-tenant'] === 'test-tenant' ? 200 : 403);
    response.end(request.headers['x-tenant'] || 'missing');
    return;
  }
  if (request.url === '/login-required') {
    if (request.headers.cookie === 'sid=test-session' &&
        request.headers.authorization === 'Bearer qa-token') {
      response.writeHead(200, { 'Content-Type': 'text/plain' });
      response.end('authenticated');
      return;
    }
    response.writeHead(401);
    response.end('login required');
    return;
  }
  if (request.url === '/forbidden') {
    response.writeHead(403);
    response.end('forbidden');
    return;
  }
  if (request.url === '/rate-limit') {
    requests.rateLimited++;
    if (requests.rateLimited === 1) {
      response.writeHead(429, { 'Retry-After': '0' });
      response.end('slow down');
      return;
    }
    response.writeHead(200);
    response.end('retried');
    return;
  }
  response.writeHead(200);
  response.end('proxy-reached');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));

const proxy = http.createServer((request, response) => {
  response.writeHead(200);
  response.end(`proxied:${request.url}`);
});
await new Promise(resolve => proxy.listen(0, '127.0.0.1', resolve));

const { port } = server.address();
const { port: proxyPort } = proxy.address();
const base = `http://127.0.0.1:${port}`;
try {
  assert.equal(classifyHttpStatus(401), 'authentication-required');
  assert.equal(classifyHttpStatus(403), 'access-forbidden');
  assert.equal(classifyHttpStatus(429), 'rate-limited');

  const anonymous = await req(`${base}/login-required`);
  assert.equal(anonymous.status, 401);
  assert.equal(anonymous.accessState, 'authentication-required');

  const authenticated = await runWithScanOptions({
    cookie: 'sid=test-session',
    authorization: 'Bearer qa-token',
  }, () => req(`${base}/login-required`));
  assert.equal(authenticated.status, 200);
  assert.match(authenticated.body, /authenticated/u);

  const customHeader = await runWithScanOptions({
    customHeaders: 'X-Tenant: test-tenant\nX-Request-Mode: scanner',
  }, () => req(`${base}/custom-header`));
  assert.equal(customHeader.status, 200);
  assert.match(customHeader.body, /test-tenant/u);
  assert.throws(() => runWithScanOptions({ customHeaders: 'Host: attacker.example' }, async () => {}), /reserved custom header/u);
  assert.throws(() => runWithScanOptions({ customHeaders: 'X-Test: a\nx-test: b' }, async () => {}), /Duplicate custom header/u);
  assert.throws(() => runWithScanOptions({ customHeaders: 'not-a-header' }, async () => {}), /format "Name: value"/u);

  const forbidden = await req(`${base}/forbidden`);
  assert.equal(forbidden.status, 403);
  assert.equal(forbidden.accessState, 'access-forbidden');

  const rateLimited = await req(`${base}/rate-limit`);
  assert.equal(rateLimited.status, 200);
  assert.equal(requests.rateLimited, 2, '429 should trigger one bounded safe retry');

  const proxied = await runWithScanOptions({
    proxy: `http://127.0.0.1:${proxyPort}`,
  }, () => req('http://example.invalid/proxy-check'));
  assert.equal(proxied.status, 200);
  assert.match(proxied.body, /proxied:http:\/\/example\.invalid\/proxy-check/u);

  assert.throws(() => runWithScanOptions({
    proxy: 'http://scanner.example:8080',
  }, async () => {}), /يسمح فقط ببروكسي HTTP محلي/u);
  assert.throws(() => runWithScanOptions({
    authorization: 'Bearer invalid\r\nX-Injected: yes',
  }, async () => {}), /Authorization غير صالحة/u);

  const nucleiFindings = parseNucleiOutput(JSON.stringify({
    'template-id': 'test-header-check',
    'matched-at': `${base}/visible`,
    info: { name: 'Test match', severity: 'medium', description: 'Fixture evidence.' },
  }), base);
  assert.equal(nucleiFindings.length, 1);
  assert.equal(nucleiFindings[0].sev, 'medium');
  assert.equal(nucleiFindings[0].cvss, 0, 'do not invent a CVSS score for a template match');
  assert.equal(parseNucleiOutput(JSON.stringify({
    'template-id': 'external-target',
    'matched-at': 'https://example.org/elsewhere',
    info: { severity: 'high' },
  }), base).length, 0, 'do not import findings outside the target origin');

  const ffufFindings = parseFfufOutput(JSON.stringify({
    input: { FUZZ: 'admin' }, status: 401, length: 29, url: `${base}/admin`,
  }), base);
  assert.equal(ffufFindings.length, 1);
  assert.equal(ffufFindings[0].sev, 'info', 'path discovery is not asserted as a vulnerability');

  const behavior = compareBehavioralResponses(
    { status: 200, body: '<p>rsx-control-1</p>' },
    { status: 200, body: '<p><rsx-probe-1></p>' },
    'rsx-control-1',
    '<rsx-probe-1>',
  );
  assert.equal(behavior.normalizedBodiesEqual, true);
  assert.equal(behavior.probeMarkerReflectedRaw, true);
  assert.equal(behavior.bodyLengthDelta, 0);
  const encodedBehavior = compareBehavioralResponses(
    { status: 200, body: 'baseline' },
    { status: 200, body: '&lt;rsx-probe-1&gt;' },
    'rsx-control-1',
    '<rsx-probe-1>',
  );
  assert.equal(encodedBehavior.probeMarkerReflectedRaw, false, 'HTML-escaped reflection is not classified as raw markup');

  const fuzzerRequests = [];
  const fuzzerStopped = await runHeuristicFuzzer({
    targets: [`${base}/page`], enabled: true, profile: 'deep', emit: () => {},
    wait: async delay => assert.equal(delay, 550),
    request: async (url, options) => {
      fuzzerRequests.push({ url, options });
      return fuzzerRequests.length === 1
        ? { ok: true, status: 200, body: 'control page' }
        : { ok: true, status: 403, body: 'forbidden' };
    },
  });
  assert.equal(fuzzerStopped.tool.status, 'blocked');
  assert.equal(fuzzerRequests.length, 2, 'fuzzer must stop immediately on 403');
  assert.equal(fuzzerRequests[1].options.retry429, false, 'fuzzer must not retry rate-limited requests');
  assert.ok(fuzzerRequests.every(item => item.url.startsWith(base)), 'fuzzer must remain on the supplied same-origin seed');

  const detected = await runHeuristicFuzzer({
    targets: [`${base}/template`], enabled: true, profile: 'deep', emit: () => {}, wait: async () => {},
    request: async url => ({
      ok: true, status: 200,
      body: new URL(url).searchParams.get('__reasonix_probe') === '{{7*13}}' ? 'rendered 91' : 'plain response',
    }),
  });
  assert.equal(detected.tool.status, 'ok');
  assert.equal(detected.tool.findings.length, 1, 'only the evaluated arithmetic probe should produce a heuristic signal');
  assert.equal(detected.tool.findings[0].evidenceDetail.vulnerabilityType, 'possible-template-evaluation');
  assert.equal(detected.tool.findings[0].sev, 'info', 'heuristic signals must remain informational');

  const crawlRequests = [];
  const crawl = await runAutonomousCrawler('https://app.example/', 'deep', () => {}, {
    wait: async delay => assert.equal(delay, 300),
    request: async (url, options) => {
      crawlRequests.push({ url, options });
      const parsed = new URL(url);
      let body = '';
      let contentType = 'text/html';
      if (parsed.pathname === '/') body = `<a href="/page">page</a><a href="/private">robots denied</a><form action="/mutate" method="post"><input name="query"></form><script src="/app.js"></script>`;
      else if (parsed.pathname === '/robots.txt') { contentType = 'text/plain'; body = 'User-agent: *\nDisallow: /private\nSitemap: https://app.example/sitemap.xml'; }
      else if (parsed.pathname === '/sitemap.xml') { contentType = 'application/xml'; body = '<urlset><url><loc>https://app.example/docs</loc></url></urlset>'; }
      else if (parsed.pathname === '/app.js') { contentType = 'application/javascript'; body = `fetch('/api/v1/items?id=1'); fetch('/api/v1/items?access_token=not-for-export')`; }
      else if (parsed.pathname === '/api/v1/items') { contentType = 'application/json'; body = '{}'; }
      return {
        ok: true, status: 200, body,
        headers: {
          'content-type': contentType,
          ...(parsed.pathname === '/' ? { 'set-cookie': ['sid=super-secret-value; Path=/; Secure'] } : {}),
        },
      };
    },
  });
  assert.ok(crawlRequests.some(item => new URL(item.url).pathname === '/api/v1/items'));
  assert.ok(crawlRequests.some(item => new URL(item.url).pathname === '/docs'));
  assert.ok(!crawlRequests.some(item => ['/private', '/mutate'].includes(new URL(item.url).pathname)),
    'crawler must respect robots exclusions and never submit form actions');
  assert.ok(crawl.pipeline.formFields.some(field => field.name === 'query'));
  assert.match(JSON.stringify(crawl.tool.findings), /sid/u);
  assert.doesNotMatch(JSON.stringify(crawl.tool.findings), /super-secret-value|access_token=not-for-export/u);
  assert.ok(crawlRequests.every(item => new URL(item.url).origin === 'https://app.example'));
  assert.ok(crawlRequests.every(item => item.options.retry429 === false));

  let limitedRequests = 0;
  const limitedCrawl = await runAutonomousCrawler('https://limited.example/', 'quick', () => {}, {
    wait: async () => {},
    request: async () => { limitedRequests++; return { ok: true, status: 429, body: '', headers: {} }; },
  });
  assert.equal(limitedRequests, 1, 'crawler must stop at the first HTTP 429');
  assert.equal(limitedCrawl.tool.status, 'blocked');
} finally {
  await Promise.all([
    new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())),
    new Promise((resolve, reject) => proxy.close(error => error ? reject(error) : resolve())),
  ]);
}

console.log('authenticated requests, access-state classification, bounded 429 retry, and local proxy checks passed');
