import assert from 'node:assert/strict';
import http from 'node:http';
import {
  analyzeCookieSecurity,
  analyzeCorsPolicy,
  analyzeSecurityHeaders,
  apiEndpointExposure,
  findExternalAssetsWithoutSri,
  isAdminPanelResponse,
  isSoft404Response,
  req,
  runWithScanOptions,
  runAutonomousCrawler,
  sensitiveFileExposure,
} from './scan-server.mjs';

const appShell = '<!doctype html><html><head><title>Example app</title></head><body><div id="root"></div></body></html>';
assert.equal(isAdminPanelResponse(appShell, appShell), false, 'a catch-all SPA response is not an admin-panel finding');
assert.equal(isAdminPanelResponse('<title>Example app</title><div>Application</div>'), false);
assert.equal(isAdminPanelResponse(
  '<title>Admin Panel — Training Fixture</title><h1>Dashboard</h1>',
  appShell,
), true, 'a distinctive administrative heading is discoverable');
assert.equal(isAdminPanelResponse(
  '<title>Login</title><form><input type="password"></form>',
  appShell,
), true, 'a password form on a discovered administrative path is a signal');

const soft404Body = '<!doctype html><html><head><title>Not found</title></head><body><main><h1>Page unavailable</h1><p>The requested address could not be found.</p></main></body></html>';
const canaryBody = soft404Body.replace('</main>', '<p>Requested: /.well-known/reasonix-canary-123</p></main>');
const canary = { status: 200, body: canaryBody, url: 'https://example.test/.well-known/reasonix-canary-123' };
assert.equal(isSoft404Response(canaryBody, 200, canary, canary.url), true);
assert.equal(isSoft404Response(
  soft404Body.replace('</main>', '<p>Requested: /admin</p></main>'),
  200,
  canary,
  'https://example.test/admin',
), true, 'request-specific path echoes are normalized before comparing pages');
assert.equal(isSoft404Response(
  '<!doctype html><html><head><title>Admin Console</title></head><body><main><h1>Admin Console</h1><p>Manage users and settings.</p></main></body></html>',
  200,
  canary,
  'https://example.test/admin',
), false);
assert.equal(isSoft404Response(soft404Body, 404, canary, 'https://example.test/admin'), false,
  'a true not-found status is not classified as a soft-404 success');

assert.deepEqual(sensitiveFileExposure('/.env',
  'DB_PASSWORD=DEMO_ONLY_NOT_A_SECRET\nAPI_KEY=DEMO_ONLY_NOT_A_KEY\nJWT_SECRET=DEMO_ONLY_NOT_A_SECRET'),
{ severity: 'high', reason: 'Environment file contains secret-like configuration assignments.' });
assert.equal(sensitiveFileExposure('/.env', '<html><body>SPA fallback</body></html>'), null);
assert.deepEqual(sensitiveFileExposure('/backup.sql',
  '-- MySQL dump\nCREATE TABLE users (id int);\nINSERT INTO users VALUES (1);'),
{ severity: 'high', reason: 'Response contains database backup or dump signatures.' });
assert.deepEqual(sensitiveFileExposure('/config.php.bak', '$db_password = "not-a-real-secret";'),
{ severity: 'high', reason: 'Response contains secret-like configuration values.' });
assert.deepEqual(sensitiveFileExposure('/.git/HEAD', 'ref: refs/heads/main\n'),
{ severity: 'low', reason: 'Git repository metadata is publicly readable.' });
assert.equal(sensitiveFileExposure('/.htaccess', 'RewriteEngine On\n'), null,
  'ordinary web-server configuration is not automatically classified as sensitive');
assert.equal(sensitiveFileExposure('/server-status', '<html>generic SPA content</html>'), null);
assert.deepEqual(sensitiveFileExposure('/server-status', '<h1>Apache Server Status</h1>'),
{ severity: 'medium', reason: 'Apache server-status information is publicly readable.' });

assert.deepEqual(analyzeSecurityHeaders({}, false), {
  missing: ['content-security-policy', 'x-content-type-options', 'x-frame-options or CSP frame-ancestors', 'referrer-policy'],
  weakCsp: [],
  advisoryMissing: ['permissions-policy', 'cross-origin-opener-policy', 'cross-origin-embedder-policy'],
}, 'HSTS is not applicable over cleartext HTTP');
assert.deepEqual(analyzeSecurityHeaders({}, true).missing, [
  'strict-transport-security',
  'content-security-policy',
  'x-content-type-options',
  'x-frame-options or CSP frame-ancestors',
  'referrer-policy',
]);
assert.deepEqual(analyzeSecurityHeaders({
  'permissions-policy': 'camera=()',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-embedder-policy': 'require-corp',
}, false).advisoryMissing, []);
assert.deepEqual(analyzeSecurityHeaders({
  'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'none'",
  'content-type': 'text/html',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
}, false), {
  missing: [],
  weakCsp: ["script-src permits 'unsafe-inline'", "script-src permits 'unsafe-eval'"],
  advisoryMissing: ['permissions-policy', 'cross-origin-opener-policy', 'cross-origin-embedder-policy'],
});
assert.deepEqual(analyzeSecurityHeaders({
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
}, false).missing, []);
assert.deepEqual(analyzeSecurityHeaders({
  'content-security-policy': "default-src 'self' 'unsafe-inline'; script-src 'self' 'nonce-abcd'",
  'content-type': 'text/html',
}, false).weakCsp, [], 'unsafe-inline is ineffective when a nonce source is present');
assert.deepEqual(analyzeSecurityHeaders({
  'content-security-policy': "default-src 'self' 'unsafe-inline'",
  'content-type': 'text/html',
}, false).weakCsp, ["script-src permits 'unsafe-inline'"],
  'default-src fallback is considered when script-src is absent');
assert.deepEqual(analyzeSecurityHeaders({
  'content-type': 'application/json',
}, false).missing, ['x-content-type-options', 'referrer-policy'],
  'CSP and frame protections are not reported missing for non-HTML responses');

assert.deepEqual(apiEndpointExposure('/actuator/env', 'application/json',
  '{"activeProfiles":["test"],"propertySources":[]}'),
{ severity: 'medium', reason: 'Spring Boot environment endpoint returned a recognizable environment document.' });
assert.deepEqual(apiEndpointExposure('/swagger.json', 'application/json',
  '{"openapi":"3.0.0","paths":{}}'),
{ severity: 'info', reason: 'Public API documentation endpoint was confirmed; exposure alone does not prove a vulnerability.' });
assert.equal(apiEndpointExposure('/api/v1/', 'application/json', '{"items":[]}'), null,
  'generic API JSON responses are not classified as exposures');
assert.equal(apiEndpointExposure('/actuator/env', 'text/html', '<html>fallback</html>'), null,
  'HTML catch-all responses are not mistaken for an API endpoint');

assert.deepEqual(analyzeCookieSecurity({
  'set-cookie': [
    'sessionId=secret-value; Path=/; SameSite=Lax',
    'theme=dark; Path=/; Secure',
  ],
}, true), [
  { name: 'sessionId', missing: ['Secure', 'HttpOnly'] },
]);
assert.deepEqual(analyzeCookieSecurity({
  'set-cookie': 'sessionId=secret-value; Path=/; Secure; HttpOnly; SameSite=Strict',
}, true), [], 'secure and correctly attributed session cookies produce no finding');
assert.deepEqual(analyzeCookieSecurity({
  'set-cookie': 'sessionId=secret-value; Path=/',
}, false), [
  { name: 'sessionId', missing: ['HttpOnly', 'SameSite'] },
], 'Secure is not reported as missing on an HTTP response');

const testOrigin = 'https://reasonix-cors-check.invalid';
assert.deepEqual(analyzeCorsPolicy({
  'access-control-allow-origin': testOrigin,
  'access-control-allow-credentials': 'true',
  vary: 'Accept-Encoding, Origin',
}, testOrigin), {
  reflectedOrigin: true,
  allowCredentials: true,
  varyByOrigin: true,
  riskyReflection: true,
});
assert.equal(analyzeCorsPolicy({
  'access-control-allow-origin': '*',
  'access-control-allow-credentials': 'true',
}, testOrigin).riskyReflection, false, 'wildcard plus credentials is not treated as browser-usable reflection');
assert.equal(analyzeCorsPolicy({
  'Access-Control-Allow-Origin': 'null',
  'Access-Control-Allow-Credentials': 'true',
  Vary: 'Origin',
}, 'null').riskyReflection, true, 'credentialed access granted to null origins is flagged');
assert.equal(analyzeCorsPolicy({
  'access-control-allow-origin': testOrigin,
  'access-control-allow-credentials': 'false',
}, testOrigin).riskyReflection, false);
assert.equal(analyzeCorsPolicy({
  'access-control-allow-origin': 'https://trusted.example.test',
  'access-control-allow-credentials': 'true',
}, testOrigin).riskyReflection, false, 'a nonmatching explicit allowlist origin is not flagged');

assert.deepEqual(findExternalAssetsWithoutSri(`
  <script src="https://cdn.example.test/app.js"></script>
  <script src="https://cdn.example.test/secure.js" integrity="sha384-abc"></script>
  <link rel="stylesheet" href="https://styles.example.test/site.css">
  <link rel="stylesheet" href="/local.css">
  <link rel="preload" href="https://cdn.example.test/font.woff2">
`, 'https://app.example.test/'), [
  { tag: 'script', url: 'https://cdn.example.test/app.js' },
  { tag: 'link', url: 'https://styles.example.test/site.css' },
]);

let activeRequests = 0;
let maximumActiveRequests = 0;
const requestStartedAt = [];
const rateLimitServer = http.createServer((_request, response) => {
  activeRequests++;
  maximumActiveRequests = Math.max(maximumActiveRequests, activeRequests);
  requestStartedAt.push(Date.now());
  setTimeout(() => {
    activeRequests--;
    response.end('ok');
  }, 450);
});
await new Promise(resolve => rateLimitServer.listen(0, '127.0.0.1', resolve));
try {
  const origin = `http://127.0.0.1:${rateLimitServer.address().port}`;
  const pendingResponses = Array.from({ length: 7 }, () => req(`${origin}/health`, {}, 3000));
  const stallUntil = Date.now() + 700;
  while (Date.now() < stallUntil) {}
  const responses = await Promise.all(pendingResponses);
  assert.ok(responses.every(response => response.ok && response.status === 200));
  assert.ok(maximumActiveRequests <= 4, 'same-origin HTTP probes stay within the concurrency cap');
  for (let index = 1; index < requestStartedAt.length; index++) {
    assert.ok(requestStartedAt[index] - requestStartedAt[index - 1] >= 150,
      'same-origin HTTP probe starts are rate-limited');
  }
} finally {
  await new Promise((resolve, reject) => rateLimitServer.close(error => error ? reject(error) : resolve()));
}

let receivedCorsRequest;
const corsTestServer = http.createServer((request, response) => {
  receivedCorsRequest = request.headers;
  response.writeHead(200, {
    'Access-Control-Allow-Origin': request.headers.origin,
    'Access-Control-Allow-Credentials': 'true',
    Vary: 'Origin',
  });
  response.end('synthetic CORS test response');
});
await new Promise(resolve => corsTestServer.listen(0, '127.0.0.1', resolve));
try {
  const origin = `http://127.0.0.1:${corsTestServer.address().port}`;
  await runWithScanOptions({
    cookie: 'sessionId=synthetic-secret',
    authorization: 'Bearer synthetic-secret',
  }, async () => {
    const response = await req(origin, {
      headers: { Origin: testOrigin },
      omitScanHeaders: true,
    });
    assert.equal(response.status, 200);
  });
  assert.equal(receivedCorsRequest.origin, testOrigin);
  assert.equal(receivedCorsRequest.cookie, undefined, 'CORS probe must not send configured cookies');
  assert.equal(receivedCorsRequest.authorization, undefined, 'CORS probe must not send configured authorization');
} finally {
  await new Promise((resolve, reject) => corsTestServer.close(error => error ? reject(error) : resolve()));
}

const partialCrawl = await runAutonomousCrawler('https://example.test/', 'quick', () => {}, {
  request: async url => url.endsWith('/robots.txt')
    ? { ok: false, error: 'synthetic robots failure' }
    : { ok: true, status: 404, headers: {}, body: 'Not found', url },
  wait: async () => {},
});
assert.equal(partialCrawl.tool.status, 'partial', 'a failed crawl resource does not discard successful responses');
const failedCrawl = await runAutonomousCrawler('https://example.test/', 'quick', () => {}, {
  request: async () => { throw new Error('synthetic connection failure'); },
  wait: async () => {},
});
assert.equal(failedCrawl.tool.status, 'error', 'unexpected request failures are reported rather than crashing the crawl');

console.log('soft-404 calibration, CSP/headers, API endpoint signatures, crawler isolation, cookies, CORS, and SRI checks pass');
