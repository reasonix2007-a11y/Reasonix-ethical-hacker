const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);

export function localApiBase(value, label) {
  let url;
  try { url = new URL(String(value || '')); }
  catch { throw new Error(`${label} API URL is invalid.`); }
  const hostname = url.hostname.replace(/^\[|\]$/gu, '').toLowerCase();
  const configuredWslHost = String(process.env.REASONIX_WSL_API_HOST || '').toLowerCase();
  const trustedWslHost = configuredWslHost && hostname === configuredWslHost &&
    /^172\.(?:1[6-9]|2\d|3[01])\./u.test(hostname);
  if (url.protocol !== 'http:' || (!LOCAL_HOSTS.has(hostname) && !trustedWslHost) || url.username || url.password ||
      url.search || url.hash || url.pathname !== '/') {
    throw new Error(`${label} API must use loopback or the configured private WSL host.`);
  }
  return url.origin;
}

function apiUrl(base, route, apiKey) {
  const url = new URL(route, `${base}/`);
  if (apiKey) url.searchParams.set('apikey', apiKey);
  return url;
}

async function apiRequest(base, route, { apiKey = '', apiUsername = '', apiPassword = '', method = 'GET', body, signal, timeoutMs = 10000 } = {}) {
  const timeout = AbortSignal.timeout(timeoutMs);
  const signals = signal ? AbortSignal.any([signal, timeout]) : timeout;
  let response;
  try {
    response = await fetch(apiUrl(base, route, apiKey), {
      method,
      headers: {
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        ...(apiUsername && apiPassword ? { Authorization: `Basic ${Buffer.from(`${apiUsername}:${apiPassword}`).toString('base64')}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: signals,
    });
  } catch (error) {
    if (signal?.aborted) throw new Error('scan-cancelled');
    const causeCode = String(error?.cause?.code || '');
    if (['ECONNREFUSED', 'ECONNRESET', 'EHOSTUNREACH', 'ENETUNREACH'].includes(causeCode)) {
      const unavailable = new Error(`Optional API is not running locally or is unreachable (${causeCode}).`);
      unavailable.code = 'LOCAL_API_OFFLINE';
      throw unavailable;
    }
    throw error;
  }
  let data;
  try { data = await response.json(); }
  catch { throw new Error(`API returned non-JSON response (HTTP ${response.status}).`); }
  if (!response.ok || data?.success === false) {
    const reason = String(data?.message || data?.error || `HTTP ${response.status}`).slice(0, 400);
    throw new Error(`API request failed: ${reason}`);
  }
  return data;
}

function wait(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new Error('scan-cancelled'));
    const timer = setTimeout(finish, ms);
    function finish() {
      signal?.removeEventListener('abort', abort);
      resolve();
    }
    function abort() {
      clearTimeout(timer);
      signal?.removeEventListener('abort', abort);
      reject(new Error('scan-cancelled'));
    }
    signal?.addEventListener('abort', abort, { once: true });
  });
}

function targetUrl(value) {
  let target;
  try { target = new URL(String(value)); }
  catch { throw new Error('The scan target must be an absolute HTTP(S) URL.'); }
  if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password)
    throw new Error('The scan target must be an absolute HTTP(S) URL without embedded credentials.');
  return target;
}

export function createEvidenceObject({
  vulnerabilityType = 'unspecified',
  parameter = null,
  payload = null,
  responseExcerpt = null,
  dataExtracted = [],
  observations = [],
  source = null,
} = {}) {
  const redact = value => String(value).slice(0, 1000)
    .replace(/([?&](?:token|access_token|api[_-]?key|secret|password|session)=)[^&\s]*/giu, '$1[REDACTED]')
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/=-]+/giu, '$1[REDACTED]')
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu, '[REDACTED_EMAIL]')
    .replace(/\b(password|secret|token|api[_-]?key)\s*[:=]\s*["']?[^"'\s,;]+/giu, '$1=[REDACTED]');
  return {
    vulnerabilityType: redact(vulnerabilityType),
    parameter: parameter == null ? null : redact(parameter),
    payload: payload == null ? null : redact(payload),
    responseExcerpt: responseExcerpt == null ? null : redact(responseExcerpt),
    dataExtracted: dataExtracted.slice(0, 5).map(redact),
    observations: observations.slice(0, 12).map(redact),
    source: source == null ? null : redact(source),
  };
}

export function heuristicProbePayloads(marker) {
  return [
    { kind: 'ssti-arithmetic', parameterMode: 'value', payload: '{{7*13}}', expectedOutput: '91' },
    { kind: 'prototype-property-key', parameterMode: 'add-param', parameter: '__proto__[reasonixProbe]', payload: marker },
    { kind: 'deserialization-shape', parameterMode: 'value', payload: JSON.stringify({ type: 'ReasonixProbe', value: marker }) },
    { kind: 'unicode-boundary', parameterMode: 'value', payload: `✓${'x'.repeat(48)}${marker}` },
  ];
}

export function isSensitiveParameterName(name) {
  return /(?:token|secret|password|api[_-]?key|session|credential|auth|signature|csrf)/iu.test(String(name || ''));
}

export function extractWebDiscovery(base, body, contentType = '') {
  const origin = targetUrl(base).origin;
  const urls = new Map();
  const fields = [];
  const sourceText = String(body || '').slice(0, 200_000);
  const add = (raw, source) => {
    const value = String(raw || '').trim().replace(/&amp;/giu, '&');
    if (!value || /^(?:#|javascript:|data:|mailto:|tel:)/iu.test(value)) return;
    let url;
    try { url = new URL(value, base); } catch { return; }
    if (!['http:', 'https:'].includes(url.protocol) || url.origin !== origin || url.username || url.password) return;
    url.hash = '';
    if ([...url.searchParams.keys()].some(isSensitiveParameterName)) return;
    if (/\.(?:png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|mp[34]|pdf|zip|gz|rar|7z)(?:$|\?)/iu.test(url.pathname)) return;
    const href = url.href;
    if (!urls.has(href)) urls.set(href, new Set());
    urls.get(href).add(source);
  };
  if (/html|xhtml/iu.test(contentType) || /<\s*(?:html|a|form|script|input)\b/iu.test(sourceText)) {
    for (const match of sourceText.matchAll(/<(a|area|link|script|iframe|form)\b[^>]*>/giu)) {
      const tag = match[1].toLowerCase();
      const attributes = match[0];
      const value = attributes.match(/\b(?:href|src|action)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/iu);
      const raw = value?.[1] ?? value?.[2] ?? value?.[3];
      if (raw) add(raw, tag === 'script' ? 'script-src' : tag === 'form' ? 'form-action' : 'html-link');
    }
    for (const match of sourceText.matchAll(/<(input|select|textarea)\b[^>]*>/giu)) {
      const tag = match[1].toLowerCase();
      const attrs = match[0];
      const name = attrs.match(/\bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/iu);
      const fieldName = name?.[1] ?? name?.[2] ?? name?.[3];
      if (!fieldName) continue;
      const type = attrs.match(/\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/iu);
      fields.push({
        name: String(fieldName).slice(0, 120),
        type: String(type?.[1] ?? type?.[2] ?? type?.[3] ?? tag).slice(0, 40),
      });
      if (fields.length >= 100) break;
    }
  }
  if (/javascript|ecmascript/iu.test(contentType) || !/html|xhtml/iu.test(contentType)) {
    for (const match of sourceText.matchAll(/["'`](\/(?!\/)[^"'`\s<>]{1,250})["'`]/gu)) add(match[1], 'javascript-literal');
  }
  return {
    urls: [...urls].map(([url, sources]) => ({ url, sources: [...sources].slice(0, 5) })).slice(0, 200),
    fields: fields.slice(0, 100),
  };
}

export function parseRobotsDiscovery(body, base) {
  const urls = [];
  const disallow = [];
  let activeAgent = false;
  let groupHasRules = false;
  for (const rawLine of String(body || '').split(/\r?\n/u).slice(0, 1000)) {
    const line = rawLine.split('#', 1)[0].trim();
    const separator = line.indexOf(':');
    if (separator <= 0) continue;
    const key = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    if (key === 'user-agent') {
      if (groupHasRules) { activeAgent = false; groupHasRules = false; }
      if (value === '*' || /reasonix/iu.test(value)) activeAgent = true;
      continue;
    }
    if (key === 'disallow' && activeAgent && value.startsWith('/')) {
      disallow.push(value.slice(0, 300));
      groupHasRules = true;
    }
    if (key === 'sitemap' && value) {
      try {
        const url = new URL(value, base);
        if (url.origin === new URL(base).origin && ['http:', 'https:'].includes(url.protocol)) urls.push(url.href);
      } catch {}
    }
    if (activeAgent && !['user-agent', 'disallow', 'sitemap'].includes(key)) groupHasRules = true;
  }
  return { disallow: [...new Set(disallow)].slice(0, 100), sitemaps: [...new Set(urls)].slice(0, 10) };
}

export function analyzeHeuristicResponses(control, candidate, { probeMarker = '', expectedOutput = '' } = {}) {
  const controlBody = String(control?.body || '');
  const body = String(candidate?.body || '');
  const errorPattern = /(?:Traceback \(most recent call last\)|\b(?:TypeError|ReferenceError|SyntaxError|PDOException|UnhandledPromiseRejection)\b|SQLSTATE\[[A-Z0-9]+\]|Unhandled (?:exception|error)|Stack trace:)/iu;
  const newStackTrace = errorPattern.test(body) && !errorPattern.test(controlBody);
  const serverError = Number(candidate?.status) >= 500 && Number(control?.status) < 500;
  const templateEvaluated = Boolean(expectedOutput) && body.includes(expectedOutput) && !controlBody.includes(expectedOutput);
  const excludedAccessState = [401, 403, 429].includes(Number(candidate?.status));
  const threshold = Math.max(512, Math.floor(controlBody.length * 0.4));
  const sizeAnomaly = !excludedAccessState && Math.abs(body.length - controlBody.length) >= threshold &&
    controlBody.length > 0 && body.length > 0;
  const statusAnomaly = !excludedAccessState && Number(candidate?.status) !== Number(control?.status) &&
    Number(control?.status) >= 200 && Number(control?.status) < 400 &&
    Number(candidate?.status) >= 400;
  const signals = [];
  if (newStackTrace) signals.push('new-stack-trace');
  if (serverError) signals.push('unexpected-server-error');
  if (templateEvaluated) signals.push('template-expression-evaluated');
  if (sizeAnomaly) signals.push('large-response-size-delta');
  if (statusAnomaly) signals.push('unexpected-status-change');
  const markerIndex = probeMarker ? body.indexOf(probeMarker) : -1;
  const responseExcerpt = markerIndex >= 0
    ? body.slice(Math.max(0, markerIndex - 100), Math.min(body.length, markerIndex + probeMarker.length + 100))
    : body.slice(0, 220);
  return {
    anomalous: signals.length > 0,
    signals,
    controlStatus: Number(control?.status) || 0,
    probeStatus: Number(candidate?.status) || 0,
    controlLength: controlBody.length,
    probeLength: body.length,
    responseExcerpt,
    confidence: templateEvaluated || newStackTrace || serverError ? 'moderate-automated-signal' : 'low-automated-signal',
  };
}

export function parseNmapXml(xml, target = '') {
  const findings = [];
  const ports = String(xml || '').matchAll(/<port\b([^>]*)>([\s\S]*?)<\/port>/giu);
  const safeTarget = (() => { try { return new URL(target).hostname; } catch { return 'target'; } })();
  for (const match of ports) {
    const attrs = match[1];
    const block = match[2];
    const state = block.match(/<state\b[^>]*\bstate=["']([^"']+)["']/iu)?.[1];
    if (state !== 'open') continue;
    const protocol = attrs.match(/\bprotocol=["']([^"']+)["']/iu)?.[1] || 'tcp';
    const port = attrs.match(/\bportid=["'](\d+)["']/iu)?.[1];
    if (!port) continue;
    const service = block.match(/<service\b([^>]*)\/?>/iu)?.[1] || '';
    const name = service.match(/\bname=["']([^"']+)["']/iu)?.[1] || 'unknown';
    const product = service.match(/\bproduct=["']([^"']+)["']/iu)?.[1] || '';
    const version = service.match(/\bversion=["']([^"']+)["']/iu)?.[1] || '';
    const details = [product, version].filter(Boolean).join(' ');
    const observation = `Nmap state=open; service=${name}${details ? `; version=${details}` : ''}`;
    findings.push({
      k: `nmap-open-${protocol}-${port}`,
      sev: 'info',
      cwe: 'CWE-Unknown',
      cvss: 0,
      title: `Nmap observed open ${protocol}/${port} service`,
      desc: 'Network inventory observation from Nmap XML output; an open port alone is not a vulnerability.',
      fix: ['Confirm the service is expected and restrict exposure where it is not needed.'],
      ai: 'Service/version detection is an observation, not a confirmed security defect.',
      ep: `${safeTarget}:${port}/${protocol}`,
      evidence: [observation],
      evidenceDetail: createEvidenceObject({
        vulnerabilityType: 'open-service-inventory',
        observations: [observation],
        source: 'Nmap',
      }),
      real: true,
      source: 'Nmap',
    });
  }
  return findings;
}

export function parseSqlmapApiData(payload, target) {
  const origin = new URL(target).origin;
  if (!payload || payload.success !== true || !Array.isArray(payload.data)) return [];
  const findings = [];
  for (const entry of payload.data) {
    if (entry?.status !== 1 || (entry.type_name !== 'TECHNIQUES' && entry.type !== 1) || !Array.isArray(entry.value)) continue;
    for (const injection of entry.value) {
      if (!injection || typeof injection !== 'object' || !Array.isArray(injection.data) || !injection.data.length) continue;
      const parameter = String(injection.parameter || '').replace(/[^a-zA-Z0-9_.\[\]-]/gu, '').slice(0, 100);
      if (!parameter) continue;
      const techniques = injection.data.map(item => String(item?.technique || item?.title || '').trim())
        .filter(Boolean).slice(0, 8);
      const payloads = injection.data.map(item => String(item?.payload || '').trim()).filter(Boolean).slice(0, 3);
      const dbms = String(injection.dbms || '').replace(/[^a-zA-Z0-9_. -]/gu, '').slice(0, 80);
      const observations = [
        ...(dbms ? [`DBMS fingerprint: ${dbms}`] : []),
        ...(techniques.length ? [`Reported techniques: ${techniques.join(', ')}`] : []),
        'No database contents were requested or extracted.',
      ];
      const evidence = [
        `Parameter: ${parameter}`,
        ...observations,
      ];
      findings.push({
        k: `sql-injection-${new URL(target).pathname.toLowerCase().replace(/[^a-z0-9-]+/gu, '-')}-${parameter.toLowerCase()}`.slice(0, 120),
        sev: 'high',
        cwe: 'CWE-89',
        cvss: 0,
        title: `SQL injection signal confirmed by sqlmap in parameter "${parameter}"`,
        desc: 'sqlmap reported one or more successful injection techniques. Validate the request and response manually before treating the issue as confirmed.',
        fix: ['Use parameterized queries or prepared statements and validate input according to its expected type.'],
        ai: 'Automated injection evidence; no database contents were requested or extracted.',
        ep: `${origin}${new URL(target).pathname}?${encodeURIComponent(parameter)}=…`,
        evidence,
        evidenceDetail: createEvidenceObject({
          vulnerabilityType: 'SQL injection',
          parameter,
          payload: payloads.join('\n') || null,
          dataExtracted: [],
          observations,
          source: 'sqlmap API',
        }),
        real: true,
        source: 'sqlmap API',
      });
    }
  }
  return findings;
}

export function parseZapAlerts(alerts, target, baselineIds = new Set()) {
  const parsedTarget = new URL(target);
  const list = Array.isArray(alerts) ? alerts : [];
  const riskMap = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', informational: 'info', info: 'info' };
  const findings = [];
  for (const alert of list) {
    const alertUrl = String(alert?.url || '');
    let parsedAlert;
    try { parsedAlert = new URL(alertUrl); } catch { continue; }
    if (parsedAlert.origin !== parsedTarget.origin || baselineIds.has(String(alert?.id || ''))) continue;
    const name = String(alert?.name || alert?.alert || 'ZAP alert').slice(0, 180);
    const risk = String(alert?.risk || 'informational').toLowerCase();
    const evidence = [
      `OWASP ZAP passive alert: ${name}`,
      `Risk: ${risk}; confidence: ${String(alert?.confidence || 'unspecified').slice(0, 40)}`,
      `URL: ${parsedAlert.pathname.slice(0, 300)}`,
    ];
    if (alert?.param) evidence.push(`Parameter: ${String(alert.param).replace(/[^a-zA-Z0-9_.[\]-]/gu, '').slice(0, 100)}`);
    const parameter = alert?.param ? String(alert.param).replace(/[^a-zA-Z0-9_.[\]-]/gu, '').slice(0, 100) : null;
    findings.push({
      k: `zap-${String(alert?.pluginId || name).toLowerCase().replace(/[^a-z0-9-]+/gu, '-').slice(0, 80)}`,
      sev: riskMap[risk] || 'info',
      cwe: String(alert?.cweid || '').match(/^\d+$/u) ? `CWE-${alert.cweid}` : 'CWE-Unknown',
      cvss: 0,
      title: `OWASP ZAP signal: ${name}`,
      desc: String(alert?.description || 'Passive DAST alert; verify the response and application context manually.').slice(0, 1200),
      fix: alert?.solution ? [String(alert.solution).slice(0, 800)] : ['Review the alert evidence and remediation guidance in OWASP ZAP.'],
      ai: 'A newly observed passive-scan alert; automated evidence requires manual validation.',
      ep: `${parsedAlert.origin}${parsedAlert.pathname}`.slice(0, 500),
      evidence,
      evidenceDetail: createEvidenceObject({
        vulnerabilityType: name,
        parameter,
        observations: evidence,
        source: 'OWASP ZAP passive scan',
      }),
      real: true,
      source: 'OWASP ZAP passive scan',
    });
  }
  return findings;
}

export function compareFindingKeys(expectedKeys, observedKeys) {
  const expected = new Set(expectedKeys);
  const observed = new Set(observedKeys);
  const truePositives = [...observed].filter(key => expected.has(key));
  const falsePositives = [...observed].filter(key => !expected.has(key));
  const falseNegatives = [...expected].filter(key => !observed.has(key));
  const precision = observed.size ? truePositives.length / observed.size : (expected.size ? 0 : 1);
  const recall = expected.size ? truePositives.length / expected.size : 1;
  return {
    counts: {
      truePositives: truePositives.length,
      falsePositives: falsePositives.length,
      falseNegatives: falseNegatives.length,
      precision: Number(precision.toFixed(4)),
      recall: Number(recall.toFixed(4)),
    },
    truePositives,
    falsePositives,
    falseNegatives,
  };
}

export function optionalIntegrationSkip(id, { profile, enabled, configuredUrl, apiCredentialsConfigured, authEnabled, proxyEnabled, target }) {
  const name = id === 'sqlmap' ? 'SQLmap API' : 'OWASP ZAP API';
  let reason = '';
  let status = 'not-run';
  if (profile !== 'deep') reason = `${name} requires the Deep profile.`;
  else if (!enabled) reason = `${name} was not requested; opt-in is required.`;
  else if (!configuredUrl) reason = `${name} API is not configured locally.`;
  else if (id === 'sqlmap' && !apiCredentialsConfigured) reason = 'SQLmap API Basic Auth username/password are not configured.';
  else if (id === 'sqlmap' && !new URL(target).searchParams.size) {
    reason = 'SQLmap requires a URL with query parameters.';
    status = 'not-applicable';
  } else if (id === 'zap' && authEnabled) reason = 'ZAP authentication context is not configured; credentials were not sent to ZAP.';
  else if (id === 'zap' && proxyEnabled) reason = 'The selected proxy is not configured as ZAP upstream proxy; it was not used.';
  return reason ? { status, reason: `Skipped: ${name} — ${reason}` } : null;
}

export function optionalIntegrationFailure(id, error) {
  const name = id === 'sqlmap' ? 'SQLmap API' : 'OWASP ZAP API';
  const message = String(error?.message || error || 'Unknown API error').slice(0, 500);
  if (error?.code === 'LOCAL_API_OFFLINE') return { status: 'not-run', reason: `Skipped: ${name} not running locally — ${message}` };
  return { status: 'error', reason: `${name} failed: ${message}` };
}

export function buildPipelineTargets(target, findings = [], { maxSqlmap = 3, maxZap = 5, additionalUrls = [] } = {}) {
  const parsedTarget = targetUrl(target);
  const candidates = [
    { url: parsedTarget.href, source: 'user-supplied target' },
    ...additionalUrls.filter(item => typeof item?.url === 'string').map(item => ({
      url: item.url,
      source: String(item.source || item.sources?.[0] || 'autonomous crawler').slice(0, 80),
    })),
    ...findings.filter(finding => typeof finding?.ep === 'string').map(finding => ({
      url: finding.ep,
      source: String(finding.source || finding.k || 'scanner finding').slice(0, 80),
    })),
  ];
  const sameOrigin = [];
  const seen = new Set();
  let rejected = 0;
  for (const candidate of candidates) {
    let parsed;
    try { parsed = new URL(candidate.url, parsedTarget.origin); }
    catch { rejected++; continue; }
    if (parsed.origin !== parsedTarget.origin || !['http:', 'https:'].includes(parsed.protocol) ||
        parsed.username || parsed.password) {
      rejected++;
      continue;
    }
    for (const key of [...parsed.searchParams.keys()]) if (isSensitiveParameterName(key)) parsed.searchParams.delete(key);
    parsed.hash = '';
    if (seen.has(parsed.href)) {
      sameOrigin.find(item => item.url === parsed.href)?.sources.push(candidate.source);
      continue;
    }
    seen.add(parsed.href);
    sameOrigin.push({ url: parsed.href, sources: [candidate.source] });
  }
  const sqlmapTargets = sameOrigin.filter(item => {
    const params = [...new URL(item.url).searchParams.keys()];
    return params.length > 0 && params.some(key => !isSensitiveParameterName(key));
  }).slice(0, Math.max(0, maxSqlmap));
  const zapSeeds = sameOrigin.slice(0, Math.max(0, maxZap));
  return {
    sqlmapTargets: sqlmapTargets.map(item => item.url),
    zapSeeds: zapSeeds.map(item => item.url),
    handoffs: sameOrigin.slice(0, Math.max(maxSqlmap, maxZap)),
    rejected,
  };
}

export async function runSqlmapApiScan({
  apiUrl: configuredUrl,
  apiKey = '',
  apiUsername = '',
  apiPassword = '',
  target: rawTarget,
  headers = {},
  proxy = '',
  signal,
}) {
  const target = targetUrl(rawTarget);
  if (!apiUsername || !apiPassword) throw new Error('SQLmap API requires locally configured HTTP Basic Auth username and password.');
  if (![...target.searchParams.keys()].length) {
    return { status: 'not-applicable', reason: 'sqlmap API requires a URL with query parameters; no parameter was supplied.' };
  }
  const base = localApiBase(configuredUrl, 'sqlmap');
  const apiAuth = { apiKey, apiUsername, apiPassword, signal };
  const task = await apiRequest(base, '/task/new', apiAuth);
  const taskId = String(task?.taskid || '');
  if (!/^[a-f0-9]{16}$/iu.test(taskId)) throw new Error('sqlmap API did not return a valid task ID.');
  let result;
  let failure;
  let taskFinished = false;
  const cleanupErrors = [];
  try {
    const extraHeaders = Object.entries(headers).map(([name, value]) => `${name}: ${value}`).join('\n');
    const options = {
      url: target.href,
      batch: true,
      smart: true,
      level: 1,
      risk: 1,
      technique: 'BEU',
      threads: 1,
      timeout: 5,
      retries: 0,
      delay: 0.2,
      forms: false,
      crawl: 0,
      ...(headers.Cookie ? { cookie: headers.Cookie } : {}),
      ...(extraHeaders ? { headers: extraHeaders } : {}),
      ...(proxy ? { proxy } : {}),
    };
    const start = await apiRequest(base, `/scan/${taskId}/start`, { ...apiAuth, method: 'POST', body: options });
    if (start.success !== true) throw new Error(String(start.message || 'sqlmap API rejected the bounded scan.'));
    const deadline = Date.now() + 120_000;
    let status = 'running';
    while (Date.now() < deadline) {
      await wait(1500, signal);
      const state = await apiRequest(base, `/scan/${taskId}/status`, apiAuth);
      status = String(state.status || '').toLowerCase();
      if (status === 'terminated' || status === 'not running') {
        taskFinished = true;
        break;
      }
      if (status !== 'running') throw new Error(`sqlmap API returned unexpected status "${status}".`);
    }
    if (status === 'running') throw new Error('sqlmap API scan exceeded its 120-second limit.');
    const data = await apiRequest(base, `/scan/${taskId}/data`, apiAuth);
    const findings = parseSqlmapApiData(data, target.href);
    result = {
      status: 'ok',
      findings,
      output: `sqlmap API completed with ${findings.length} injection finding(s); bounded Boolean/Error/Union checks only, no data extraction.`,
    };
  } catch (error) {
    failure = error;
  }
  if (!taskFinished) {
    try { await apiRequest(base, `/scan/${taskId}/stop`, { ...apiAuth, signal: undefined }); }
    catch (error) { if (error?.code !== 'LOCAL_API_OFFLINE') cleanupErrors.push(`stop: ${String(error.message || error).slice(0, 200)}`); }
  }
  try { await apiRequest(base, `/task/${taskId}/delete`, { ...apiAuth, signal: undefined }); }
  catch (error) { cleanupErrors.push(`delete: ${String(error.message || error).slice(0, 200)}`); }
  if (failure) {
    if (cleanupErrors.length) failure.message = `${failure.message} Cleanup warning: ${cleanupErrors.join('; ')}.`;
    throw failure;
  }
  if (cleanupErrors.length) result.output += ` Task cleanup warning: ${cleanupErrors.join('; ')}.`;
  return result;
}

export async function runZapPassiveScan({ apiUrl: configuredUrl, apiKey = '', target: rawTarget, seedUrls = [], signal }) {
  const target = targetUrl(rawTarget);
  const base = localApiBase(configuredUrl, 'OWASP ZAP');
  const baselineResponse = await apiRequest(base, `/JSON/alert/view/alerts/?baseurl=${encodeURIComponent(target.origin)}&start=0&count=200`, { apiKey, signal });
  const baselineAlerts = baselineResponse.alerts;
  if (!Array.isArray(baselineAlerts)) throw new Error('OWASP ZAP API returned an invalid alert list.');
  const baselineIds = new Set(baselineAlerts.map(alert => String(alert?.id || '')).filter(Boolean));
  const seeds = [...new Set([target.href, ...seedUrls.map(value => String(value))])]
    .flatMap(value => {
      try {
        const seed = new URL(value);
        if (seed.origin !== target.origin || seed.username || seed.password) return [];
        for (const key of [...seed.searchParams.keys()]) if (isSensitiveParameterName(key)) seed.searchParams.delete(key);
        seed.hash = '';
        return [seed.href];
      } catch { return []; }
    }).slice(0, 5);
  const completedSeeds = new Set();
  const failedSeeds = [];
  const deadline = Date.now() + 120_000;
  for (const seed of seeds) {
    let scanId = '';
    let seedCompleted = false;
    try {
      const spider = await apiRequest(base, `/JSON/spider/action/scan/?url=${encodeURIComponent(seed)}&maxChildren=20&recurse=true&subtreeOnly=true`, { apiKey, signal });
      scanId = String(spider.scan || '');
      if (!/^\d{1,10}$/u.test(scanId)) throw new Error('OWASP ZAP did not return a valid spider scan ID.');
      let progress = 0;
      while (Date.now() < deadline) {
        await wait(1000, signal);
        const state = await apiRequest(base, `/JSON/spider/view/status/?scanId=${encodeURIComponent(scanId)}`, { apiKey, signal });
        progress = Number(state.status);
        if (!Number.isFinite(progress)) throw new Error('OWASP ZAP returned an invalid spider status.');
        if (progress >= 100) break;
      }
      if (progress < 100) throw new Error('OWASP ZAP spider exceeded its 120-second limit.');
      seedCompleted = true;
      completedSeeds.add(seed);
    } catch (error) {
      let reason = String(error.message || error).slice(0, 250);
      if (scanId && !seedCompleted) {
        try { await apiRequest(base, `/JSON/spider/action/stop/?scanId=${encodeURIComponent(scanId)}`, { apiKey }); }
        catch (cleanupError) {
          if (cleanupError?.code !== 'LOCAL_API_OFFLINE')
            reason += ` Stop request failed: ${String(cleanupError.message || cleanupError).slice(0, 150)}`;
        }
      }
      if (signal?.aborted) throw new Error('scan-cancelled');
      failedSeeds.push({ seed, reason: reason.slice(0, 400), code: error?.code });
      if (error?.code === 'LOCAL_API_OFFLINE') break;
    }
  }
  if (!completedSeeds.size && failedSeeds.length) {
    const failure = new Error(`OWASP ZAP failed for every seed: ${failedSeeds.slice(0, 3).map(item => item.reason).join('; ')}`);
    if (failedSeeds.every(item => item.code === 'LOCAL_API_OFFLINE')) failure.code = 'LOCAL_API_OFFLINE';
    throw failure;
  }
  const passiveDeadline = Date.now() + 30_000;
  let remaining = 0;
  while (Date.now() < passiveDeadline) {
    const queue = await apiRequest(base, '/JSON/pscan/view/recordsToScan/', { apiKey, signal });
    remaining = Number(queue.recordsToScan);
    if (!Number.isFinite(remaining)) throw new Error('OWASP ZAP returned an invalid passive-scan queue size.');
    if (remaining <= 0) break;
    await wait(1000, signal);
  }
  if (remaining > 0) throw new Error('OWASP ZAP passive-scan queue did not drain within 30 seconds.');
  const alertResponse = await apiRequest(base, `/JSON/alert/view/alerts/?baseurl=${encodeURIComponent(target.origin)}&start=0&count=200`, { apiKey, signal });
  const findings = parseZapAlerts(alertResponse.alerts, target.href, baselineIds);
  const inputs = seeds.map(seed => ({
    url: `${new URL(seed).origin}${new URL(seed).pathname}`,
    status: completedSeeds.has(seed) ? 'ok' : 'error',
    ...(!completedSeeds.has(seed) ? { reason: failedSeeds.find(item => item.seed === seed)?.reason || 'Not completed.' } : {}),
  }));
  return {
    status: failedSeeds.length ? 'partial' : 'ok',
    inputs,
    findings,
    output: `OWASP ZAP passive spider completed for ${completedSeeds.size}/${seeds.length} same-origin seed(s); ${findings.length} new alert(s) returned.${failedSeeds.length ? ` ${failedSeeds.length} seed(s) failed and were isolated.` : ''} Active scanning was not run.`,
  };
}
