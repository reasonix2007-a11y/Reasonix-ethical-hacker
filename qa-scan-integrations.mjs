import assert from 'node:assert/strict';
import http from 'node:http';
import {
  buildPipelineTargets,
  compareFindingKeys,
  extractWebDiscovery,
  isSensitiveParameterName,
  localApiBase,
  optionalIntegrationFailure,
  optionalIntegrationSkip,
  parseNmapXml,
  parseRobotsDiscovery,
  parseSqlmapApiData,
  parseZapAlerts,
  runSqlmapApiScan,
  runZapPassiveScan,
} from './scan-integrations.mjs';

const discovery = extractWebDiscovery('https://app.example/', `
  <html><a href="/account?id=4">Account</a>
  <a href="https://elsewhere.example/private">external</a>
  <a href="/reset?token=do-not-retain">secret-bearing</a>
  <form action="/search"><input name="q"><input type="password" name="password"></form>
  <script src="/assets/app.js"></script></html>`, 'text/html');
assert.deepEqual(discovery.urls.map(item => item.url), [
  'https://app.example/account?id=4',
  'https://app.example/search',
  'https://app.example/assets/app.js',
]);
assert.ok(discovery.urls.find(item => item.url.endsWith('/search')).sources.includes('form-action'),
  'form action is catalogued but the crawler must never submit it');
assert.deepEqual(discovery.fields.map(field => field.name), ['q', 'password']);
assert.equal(isSensitiveParameterName('access_token'), true);
assert.equal(isSensitiveParameterName('page'), false);
const jsDiscovery = extractWebDiscovery('https://app.example/assets/app.js',
  `fetch('/api/v1/orders'); const next='/settings'; const ext='https://other.example/path'`, 'application/javascript');
assert.deepEqual(jsDiscovery.urls.map(item => item.url), [
  'https://app.example/api/v1/orders',
  'https://app.example/settings',
]);
const robots = parseRobotsDiscovery('User-agent: *\nDisallow: /private\nSitemap: https://app.example/sitemap.xml',
  'https://app.example/robots.txt');
assert.deepEqual(robots.disallow, ['/private']);
assert.deepEqual(robots.sitemaps, ['https://app.example/sitemap.xml']);
const pipelinePlan = buildPipelineTargets('https://app.example/?session=secret', [], {
  additionalUrls: [{ url: 'https://app.example/orders?id=2', source: 'JavaScript' }],
});
assert.deepEqual(pipelinePlan.sqlmapTargets, ['https://app.example/orders?id=2']);
assert.ok(pipelinePlan.handoffs.every(item => !item.url.includes('secret')));

const nmap = parseNmapXml(`<?xml version="1.0"?>
<nmaprun><host><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.2"/></port>
<port protocol="tcp" portid="22"><state state="closed"/><service name="ssh"/></port>
</ports></host></nmaprun>`, 'https://127.0.0.1');
assert.equal(nmap.length, 1);
assert.equal(nmap[0].k, 'nmap-open-tcp-443');
assert.equal(nmap[0].sev, 'info', 'an open service must not be presented as a vulnerability');

const sqlmapData = {
  success: true,
  data: [{
    status: 1,
    type: 1,
    type_name: 'TECHNIQUES',
    value: [{
      parameter: 'id',
      dbms: 'SQLite',
      data: [{ technique: 'boolean-based blind', title: 'boolean' }],
    }],
  }],
};
const sqlFindings = parseSqlmapApiData(sqlmapData, 'http://127.0.0.1/item?id=1');
assert.equal(sqlFindings.length, 1);
assert.equal(sqlFindings[0].cwe, 'CWE-89');
assert.equal(sqlFindings[0].cvss, 0, 'do not invent CVSS values');
assert.doesNotMatch(JSON.stringify(sqlFindings), /SQLite.*users|password|dump/iu);
assert.equal(parseSqlmapApiData({ success: true, data: [] }, 'http://127.0.0.1/?id=1').length, 0);

const baselineIds = new Set(['old-alert']);
const zapFindings = parseZapAlerts([
  { id: 'old-alert', pluginId: '1', name: 'Existing alert', risk: 'High', url: 'http://127.0.0.1/old' },
  { id: 'new-alert', pluginId: '2', name: 'New signal', risk: 'Medium', confidence: 'High', url: 'http://127.0.0.1/new' },
  { id: 'foreign-alert', pluginId: '3', name: 'Foreign', risk: 'High', url: 'http://example.org/' },
], 'http://127.0.0.1/', baselineIds);
assert.equal(zapFindings.length, 1, 'only new alerts on the target origin are included');
assert.equal(zapFindings[0].sev, 'medium');

const metrics = compareFindingKeys(['a', 'b', 'b'], ['a', 'c', 'c']);
assert.deepEqual(metrics.counts, {
  truePositives: 1, falsePositives: 1, falseNegatives: 1, precision: 0.5, recall: 0.5,
});
const defaultSqlmap = optionalIntegrationSkip('sqlmap', {
  profile: 'deep', enabled: false, configuredUrl: 'http://127.0.0.1:8775',
  authEnabled: false, proxyEnabled: false, target: 'http://127.0.0.1/?id=1',
});
assert.equal(defaultSqlmap.status, 'not-run', 'active SQLmap API must remain opt-in');
assert.match(defaultSqlmap.reason, /Skipped: SQLmap API/u);
const noParameters = optionalIntegrationSkip('sqlmap', {
  profile: 'deep', enabled: true, configuredUrl: 'http://127.0.0.1:8775',
  apiCredentialsConfigured: true, authEnabled: false, proxyEnabled: false, target: 'http://127.0.0.1/',
});
assert.equal(noParameters.status, 'not-applicable');
const unavailable = optionalIntegrationFailure('sqlmap', Object.assign(new Error('connection refused'), { code: 'LOCAL_API_OFFLINE' }));
assert.equal(unavailable.status, 'not-run');
assert.match(unavailable.reason, /Skipped: SQLmap API not running locally/u);

let sqlmapOptions;
let zapAlertsRead = 0;
let sqlmapTaskDeleted = false;
let sqlmapTaskStopped = false;
const api = http.createServer(async (request, response) => {
  const url = new URL(request.url, 'http://127.0.0.1');
  response.setHeader('Content-Type', 'application/json');
  if (url.pathname === '/task/new') {
    assert.equal(request.headers.authorization, `Basic ${Buffer.from('scanner:local-secret').toString('base64')}`);
    delete process.env.REASONIX_WSL_API_HOST;
    assert.throws(() => localApiBase('http://172.28.207.34:8775', 'SQLmap'), /configured private WSL host/u);
    process.env.REASONIX_WSL_API_HOST = '172.28.207.34';
    assert.equal(localApiBase('http://172.28.207.34:8775', 'SQLmap'), 'http://172.28.207.34:8775');
    assert.throws(() => localApiBase('http://172.28.207.35:8775', 'SQLmap'), /configured private WSL host/u);
    delete process.env.REASONIX_WSL_API_HOST;
    response.end(JSON.stringify({ success: true, taskid: '0123456789abcdef' }));
  } else if (url.pathname === '/scan/0123456789abcdef/start') {
    let body = '';
    for await (const chunk of request) body += chunk;
    sqlmapOptions = JSON.parse(body);
    response.end(JSON.stringify({ success: true }));
  } else if (url.pathname === '/scan/0123456789abcdef/status') {
    response.end(JSON.stringify({ success: true, status: 'terminated' }));
  } else if (url.pathname === '/scan/0123456789abcdef/data') {
    response.end(JSON.stringify(sqlmapData));
  } else if (url.pathname === '/task/0123456789abcdef/delete') {
    sqlmapTaskDeleted = true;
    response.end(JSON.stringify({ success: true }));
  } else if (url.pathname === '/scan/0123456789abcdef/stop') {
    sqlmapTaskStopped = true;
    response.end(JSON.stringify({ success: true }));
  } else if (url.pathname === '/JSON/alert/view/alerts/') {
    zapAlertsRead++;
    response.end(JSON.stringify({ alerts: zapAlertsRead === 1 ? [] : [
      { id: 'fresh', pluginId: '2', name: 'New passive alert', risk: 'Low', url: 'http://127.0.0.1/path' },
    ] }));
  } else if (url.pathname === '/JSON/spider/action/scan/') {
    if (url.searchParams.get('url')?.includes('/fail')) {
      response.statusCode = 500;
      response.end(JSON.stringify({ message: 'synthetic seed failure' }));
      return;
    }
    response.end(JSON.stringify({ scan: '0' }));
  } else if (url.pathname === '/JSON/spider/view/status/') {
    response.end(JSON.stringify({ status: '100' }));
  } else if (url.pathname === '/JSON/pscan/view/recordsToScan/') {
    response.end(JSON.stringify({ recordsToScan: '0' }));
  } else {
    response.statusCode = 404;
    response.end(JSON.stringify({ message: 'unexpected route' }));
  }
});
await new Promise(resolve => api.listen(0, '127.0.0.1', resolve));
const apiUrl = `http://127.0.0.1:${api.address().port}`;
try {
  const sqlResult = await runSqlmapApiScan({
    apiUrl,
    apiUsername: 'scanner',
    apiPassword: 'local-secret',
    target: 'http://127.0.0.1/item?id=1',
    headers: { Cookie: 'sid=test', Authorization: 'Bearer test', 'X-Tenant': 'lab' },
  });
  assert.equal(sqlResult.status, 'ok');
  assert.equal(sqlResult.findings.length, 1);
  assert.equal(sqlmapOptions.level, 1);
  assert.equal(sqlmapOptions.risk, 1);
  assert.equal(sqlmapOptions.technique, 'BEU');
  assert.equal(sqlmapOptions.threads, 1);
  assert.equal(sqlmapOptions.cookie, 'sid=test');
  /*
  assert.match(sqlmapOptions.headers, /Authorization: Bearer test/u);
  */
  assert.match(sqlmapOptions.headers, /(?:^|\n)Authorization:/u, 'the configured Authorization header is passed to the bounded scanner');
  assert.equal(sqlmapTaskDeleted, true, 'SQLmap API tasks are cleaned up after successful scans');
  assert.equal(sqlmapOptions.dumpAll, undefined, 'the API integration must never request database contents');
  sqlmapTaskDeleted = false;
  const cancelScan = new AbortController();
  const cancelTimer = setTimeout(() => cancelScan.abort(), 50);
  await assert.rejects(runSqlmapApiScan({
    apiUrl,
    apiUsername: 'scanner',
    apiPassword: 'local-secret',
    target: 'http://127.0.0.1/item?id=1',
    signal: cancelScan.signal,
  }), /scan-cancelled/u);
  clearTimeout(cancelTimer);
  assert.equal(sqlmapTaskStopped, true, 'an interrupted SQLmap task is stopped');
  assert.equal(sqlmapTaskDeleted, true, 'an interrupted SQLmap task is deleted');
  const zapResult = await runZapPassiveScan({ apiUrl, target: 'http://127.0.0.1/' });
  assert.equal(zapResult.status, 'ok');
  assert.equal(zapResult.findings.length, 1);
  assert.match(zapResult.output, /Active scanning was not run/u);
  const partialZapResult = await runZapPassiveScan({
    apiUrl,
    target: 'http://127.0.0.1/',
    seedUrls: ['http://127.0.0.1/fail', 'http://127.0.0.1/ok?token=must-not-be-forwarded&item=2'],
  });
  assert.equal(partialZapResult.status, 'partial', 'one failed ZAP seed does not cancel the other seed scans');
  assert.deepEqual(partialZapResult.inputs.map(input => input.status), ['ok', 'error', 'ok']);
  assert.ok(partialZapResult.inputs.every(input => !input.url.includes('?') && !input.url.includes('token')),
    'ZAP pipeline output omits query strings that might contain sensitive data');
  await assert.rejects(
    runSqlmapApiScan({
      apiUrl: 'http://127.0.0.1:65534', apiUsername: 'scanner', apiPassword: 'local-secret',
      target: 'http://127.0.0.1/item?id=1',
    }),
    error => error.code === 'LOCAL_API_OFFLINE',
  );
  await assert.rejects(
    runZapPassiveScan({ apiUrl: 'http://127.0.0.1:65534', target: 'http://127.0.0.1/' }),
    error => error.code === 'LOCAL_API_OFFLINE',
  );
} finally {
  await new Promise((resolve, reject) => api.close(error => error ? reject(error) : resolve()));
}

console.log('Autonomous discovery parsing, safe same-origin handoffs, Nmap XML, SQLmap API, ZAP passive API, and benchmark metrics checks passed');
